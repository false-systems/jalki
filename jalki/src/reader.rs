use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use aya::maps::{MapData, PerCpuArray, RingBuf};
use aya::Ebpf;
use jalki_evidence::EvidenceRecord;
use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::enrich::{bind_record, RuntimeEnricher};
use crate::metrics::{Metrics, ProbeLabel};
use crate::probe::Probe;
use crate::sensitive_paths::SensitivePathMatcher;
use crate::store::EventStore;

const MAX_DRAIN_ITEMS: usize = 1024;

/// Per-probe drop counter, exposed for metrics.
pub struct ProbeStats {
    pub events_emitted: AtomicU64,
    pub events_dropped: AtomicU64,
    pub events_sampled_out: AtomicU64,
    pub parse_errors: AtomicU64,
    drop_observation: Mutex<DropObservation>,
}

#[derive(Clone, Copy, Default)]
struct DropObservation {
    total: u64,
    tracking_started_at_ns: u64,
    counter_polled_at_ns: u64,
}

impl Default for ProbeStats {
    fn default() -> Self {
        Self::new()
    }
}

impl ProbeStats {
    pub fn new() -> Self {
        Self {
            events_emitted: AtomicU64::new(0),
            events_dropped: AtomicU64::new(0),
            events_sampled_out: AtomicU64::new(0),
            parse_errors: AtomicU64::new(0),
            drop_observation: Mutex::new(DropObservation::default()),
        }
    }

    fn start_drop_tracking(&self, at_ns: u64) {
        let mut observation = self
            .drop_observation
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        observation.tracking_started_at_ns = at_ns;
        observation.counter_polled_at_ns = at_ns;
    }

    fn record_drop_poll(&self, total: u64, at_ns: u64) -> u64 {
        let mut observation = self
            .drop_observation
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let new_drops = total.wrapping_sub(observation.total);
        observation.total = total;
        observation.counter_polled_at_ns = at_ns;
        self.events_dropped.store(total, Ordering::Relaxed);
        new_drops
    }

    pub(crate) fn drop_observation(&self) -> (u64, u64, u64) {
        let observation = *self
            .drop_observation
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        (
            observation.total,
            observation.tracking_started_at_ns,
            observation.counter_polled_at_ns,
        )
    }
}

/// Drain a ring buffer and convert events to evidence records.
///
/// Runs as a blocking task (ring buffer polling is synchronous in aya).
/// Sends one batch per ring-buffer drain cycle through an mpsc channel.
// Reader setup is genuinely one cohesive bundle (probe, cluster, channel,
// stats, store, enricher, matcher). Threading it through a params struct —
// the shape `SinkLoop` uses in runtime.rs — would read better, but it is a
// call-site refactor and this commit exists to make CI green, not to move
// code. Tracked separately.
#[allow(clippy::too_many_arguments)]
pub fn spawn_reader(
    ebpf: &mut Ebpf,
    probe: Arc<dyn Probe>,
    cluster: String,
    tx: mpsc::Sender<Vec<EvidenceRecord>>,
    stats: Arc<ProbeStats>,
    metrics: Arc<Metrics>,
    store: Arc<EventStore>,
    enricher: Arc<dyn RuntimeEnricher>,
    sensitive_path_matcher: Arc<SensitivePathMatcher>,
) -> Result<ReaderStop> {
    let map_name = probe.ring_buffer_map().to_string();

    let map = ebpf
        .take_map(&map_name)
        .ok_or_else(|| anyhow::anyhow!("ring buffer map {map_name} not found"))?;
    let ring_buf: RingBuf<MapData> = map
        .try_into()
        .with_context(|| format!("{map_name} is not a RingBuf"))?;
    let drop_map_name = format!("{map_name}_DROPS");
    let drop_counts = ebpf
        .take_map(&drop_map_name)
        .ok_or_else(|| anyhow::anyhow!("ring buffer drop counter map {drop_map_name} not found"))?
        .try_into()
        .with_context(|| format!("{drop_map_name} is not a PerCpuArray"))?;
    let tracking_started_at_ns = monotonic_now_ns()?;
    stats.start_drop_tracking(tracking_started_at_ns);

    let probe_name = probe.name().to_string();
    let stop = ReaderStop::new();
    let stop_flag = stop.clone();

    tokio::task::spawn_blocking(move || {
        drain_loop(
            ring_buf,
            drop_counts,
            probe,
            &cluster,
            tx,
            stats,
            metrics,
            &probe_name,
            store,
            enricher,
            sensitive_path_matcher,
            stop_flag,
        );
    });

    Ok(stop)
}

/// Stop signal for a reader.
///
/// A flag rather than an `AbortHandle`, because the reader is a
/// `spawn_blocking` task: aborting one does nothing until it next yields, and
/// this one is inside a blocking `ring_buf.next()` / `thread::sleep` cycle. It
/// has to be asked to leave, and it checks between bounded drain batches.
///
/// Dropping this does *not* stop the reader; the registry owns it for as long
/// as the probe is attached.
#[derive(Clone, Debug)]
pub struct ReaderStop(Arc<AtomicBool>);

impl ReaderStop {
    fn new() -> Self {
        Self(Arc::new(AtomicBool::new(false)))
    }

    /// Ask the reader to finish its current poll and exit.
    pub fn stop(&self) {
        self.0.store(true, Ordering::Relaxed);
    }

    fn stopped(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
}

// Reader setup is genuinely one cohesive bundle (probe, cluster, channel,
// stats, store, enricher, matcher). Threading it through a params struct —
// the shape `SinkLoop` uses in runtime.rs — would read better, but it is a
// call-site refactor and this commit exists to make CI green, not to move
// code. Tracked separately.
#[allow(clippy::too_many_arguments)]
fn drain_loop(
    mut ring_buf: RingBuf<aya::maps::MapData>,
    drop_counts: PerCpuArray<MapData, u64>,
    probe: Arc<dyn Probe>,
    cluster: &str,
    tx: mpsc::Sender<Vec<EvidenceRecord>>,
    stats: Arc<ProbeStats>,
    metrics: Arc<Metrics>,
    probe_name: &str,
    store: Arc<EventStore>,
    enricher: Arc<dyn RuntimeEnricher>,
    sensitive_path_matcher: Arc<SensitivePathMatcher>,
    stop: ReaderStop,
) {
    let sample_rate = probe.sample_rate();
    let do_sampling = sample_rate < 1.0;
    // Simple deterministic sampling: use a counter modulo inverse-rate.
    // For 0.1 (10%), keep every 10th event. Avoids RNG overhead in the hot path.
    let sample_every = if do_sampling {
        (1.0 / sample_rate).round() as u64
    } else {
        1
    };
    let mut counter: u64 = 0;
    let mut last_drop_poll = std::time::Instant::now();
    let drop_metric_label = ProbeLabel {
        probe: probe_name.to_string(),
    };

    loop {
        // Checked before draining, so a detach cannot be delayed by a busy ring
        // buffer. Returning here drops `ring_buf`, which releases the map — the
        // reason detach can unload the program at all.
        if stop.stopped() {
            debug!(probe = probe_name, "reader stopping on request");
            return;
        }

        let mut records = Vec::new();

        let mut drained = 0;
        while drained < MAX_DRAIN_ITEMS {
            let Some(item) = ring_buf.next() else {
                break;
            };
            drained += 1;

            // Apply sampling before parsing — skip the conversion cost too.
            if do_sampling {
                counter = counter.wrapping_add(1);
                if !counter.is_multiple_of(sample_every) {
                    stats.events_sampled_out.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
            }

            let raw = item.as_ref();

            match probe.to_evidence(raw, cluster) {
                Ok(evidence) => {
                    for record in evidence.records {
                        if !record_matches_sensitive_paths(&record, sensitive_path_matcher.as_ref())
                        {
                            stats.events_sampled_out.fetch_add(1, Ordering::Relaxed);
                            continue;
                        }
                        let record = bind_record(record, enricher.as_ref());
                        // The local debug store keeps the lean occurrence shape used by
                        // IPC stream/watch. Durable sinks project D6 metadata later via
                        // EvidenceBatch::into_occurrences().
                        store.push(probe_name, record.occurrence.clone());
                        stats.events_emitted.fetch_add(1, Ordering::Relaxed);
                        records.push(record);
                    }
                }
                Err(e) => {
                    stats.parse_errors.fetch_add(1, Ordering::Relaxed);
                    warn!(probe = probe_name, error = %e, "failed to parse event");
                }
            }
        }

        if last_drop_poll.elapsed() >= std::time::Duration::from_secs(1) {
            match drop_counts.get(&0, 0) {
                Ok(values) => {
                    let total = values.iter().copied().fold(0, u64::wrapping_add);
                    let polled_at_ns = match monotonic_now_ns() {
                        Ok(value) => value,
                        Err(error) => {
                            warn!(probe = probe_name, %error, "failed to read monotonic clock");
                            return;
                        }
                    };
                    let new_drops = stats.record_drop_poll(total, polled_at_ns);
                    if new_drops > 0 {
                        metrics
                            .ring_buffer_drops
                            .get_or_create(&drop_metric_label)
                            .inc_by(new_drops);
                    }
                }
                Err(error) => {
                    warn!(probe = probe_name, %error, "failed to read ring buffer drop counter")
                }
            }
            last_drop_poll = std::time::Instant::now();
        }

        if !records.is_empty() && tx.blocking_send(records).is_err() {
            debug!(probe = probe_name, "sink channel closed, stopping reader");
            return;
        }

        if drained < MAX_DRAIN_ITEMS {
            // No events available — sleep briefly before polling again.
            // TODO: wire up epoll via ring_buf fd for zero-latency wakeup.
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
}

#[repr(C)]
struct Timespec {
    tv_sec: std::ffi::c_long,
    tv_nsec: std::ffi::c_long,
}

unsafe extern "C" {
    fn clock_gettime(clock_id: std::ffi::c_int, time: *mut Timespec) -> std::ffi::c_int;
}

/// Read the same Linux monotonic clock used by `bpf_ktime_get_ns`.
fn monotonic_now_ns() -> Result<u64> {
    const CLOCK_MONOTONIC: std::ffi::c_int = 1;
    let mut time = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `time` is a valid writable timespec and CLOCK_MONOTONIC is a
    // fixed Linux clock id.
    if unsafe { clock_gettime(CLOCK_MONOTONIC, &mut time) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let seconds =
        u64::try_from(time.tv_sec).context("monotonic clock returned negative seconds")?;
    let nanos = u64::try_from(time.tv_nsec).context("monotonic clock returned negative nanos")?;
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanos))
        .ok_or_else(|| anyhow::anyhow!("monotonic clock overflow"))
}

fn record_matches_sensitive_paths(
    record: &EvidenceRecord,
    sensitive_path_matcher: &SensitivePathMatcher,
) -> bool {
    if record.occurrence.occurrence_type.as_str() != "kernel.file.open" {
        return true;
    }

    record
        .occurrence
        .labels
        .get("resource_ref_id")
        .is_some_and(|path| sensitive_path_matcher.is_match(path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drop_observation_keeps_count_and_window_together() {
        let stats = ProbeStats::new();
        stats.start_drop_tracking(10);

        assert_eq!(stats.record_drop_poll(3, 20), 3);
        assert_eq!(stats.drop_observation(), (3, 10, 20));
        assert_eq!(stats.record_drop_poll(5, 30), 2);
        assert_eq!(stats.drop_observation(), (5, 10, 30));
    }

    #[test]
    fn monotonic_clock_advances_in_kernel_time_domain() {
        let first = monotonic_now_ns().expect("monotonic clock");
        let second = monotonic_now_ns().expect("monotonic clock");

        assert!(first > 0);
        assert!(second >= first);
    }
}

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::{Context, Result};
use aya::maps::{MapData, RingBuf};
use aya::Ebpf;
use jalki_evidence::EvidenceRecord;
use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::enrich::{bind_record, RuntimeEnricher};
use crate::probe::Probe;
use crate::sensitive_paths::SensitivePathMatcher;
use crate::store::EventStore;

/// Per-probe drop counter, exposed for metrics.
pub struct ProbeStats {
    pub events_emitted: AtomicU64,
    pub events_dropped: AtomicU64,
    pub events_sampled_out: AtomicU64,
    pub parse_errors: AtomicU64,
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
        }
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

    let probe_name = probe.name().to_string();
    let stop = ReaderStop::new();
    let stop_flag = stop.clone();

    tokio::task::spawn_blocking(move || {
        drain_loop(
            ring_buf,
            probe,
            &cluster,
            tx,
            stats,
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
/// has to be asked to leave, and it checks at the top of each poll — at most
/// one 10ms sleep away.
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
    probe: Arc<dyn Probe>,
    cluster: &str,
    tx: mpsc::Sender<Vec<EvidenceRecord>>,
    stats: Arc<ProbeStats>,
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

    loop {
        // Checked before draining, so a detach cannot be delayed by a busy ring
        // buffer. Returning here drops `ring_buf`, which releases the map — the
        // reason detach can unload the program at all.
        if stop.stopped() {
            debug!(probe = probe_name, "reader stopping on request");
            return;
        }

        let mut records = Vec::new();

        while let Some(item) = ring_buf.next() {
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

        if !records.is_empty() && tx.blocking_send(records).is_err() {
            debug!(probe = probe_name, "sink channel closed, stopping reader");
            return;
        }

        // No events available — sleep briefly before polling again.
        // TODO: wire up epoll via ring_buf fd for zero-latency wakeup.
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
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

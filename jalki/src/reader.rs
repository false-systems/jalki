use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use aya::maps::{MapData, PerCpuArray, RingBuf};
use aya::Ebpf;
use jalki_evidence::{EvidenceRecord, NormalizedEvidence};
use prometheus_client::metrics::counter::Counter;
use tracing::{debug, warn};

use crate::enrich::{bind_record, RuntimeEnricher};
use crate::metrics::{Metrics, ProbeLabel};
use crate::probe::Probe;
use crate::sensitive_paths::SensitivePathMatcher;
use crate::sink_queue::SinkQueueSender;
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
/// Offers one message per ring-buffer drain cycle to the sink queue, which
/// never blocks: a full queue refuses it as reported loss (jalki#97), so a
/// slow sink no longer backs the kernel ring buffer up behind this thread.
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
    tx: SinkQueueSender,
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
    tx: SinkQueueSender,
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
    let intake = RecordIntake::new(
        probe_name,
        stats.clone(),
        &metrics,
        store,
        enricher,
        sensitive_path_matcher,
    );

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
                Ok(evidence) => intake.admit(evidence, &mut records),
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

        // Refused and out-of-scope messages are already accounted for by the
        // queue; only a closed queue (the sink loop is gone) stops the reader.
        if !records.is_empty() && tx.try_send(records).is_err() {
            debug!(probe = probe_name, "sink queue closed, stopping reader");
            return;
        }

        if drained < MAX_DRAIN_ITEMS {
            // No events available — sleep briefly before polling again.
            // TODO: wire up epoll via ring_buf fd for zero-latency wakeup.
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
}

/// What the reader does with one decoded event: the sensitive-path gate,
/// runtime binding, the local store and the per-probe counters.
///
/// Split out of `drain_loop`, which needs a live ring buffer, so tests drive
/// the same code the daemon runs.
pub(crate) struct RecordIntake {
    probe_name: String,
    stats: Arc<ProbeStats>,
    /// This probe's `jalki_events_total` series, taken once: it exists (at 0)
    /// from attach, so `rate()` works from the first scrape, and the hot path
    /// is one atomic add rather than a family lookup per event.
    events_total: Counter,
    store: Arc<EventStore>,
    enricher: Arc<dyn RuntimeEnricher>,
    sensitive_path_matcher: Arc<SensitivePathMatcher>,
}

impl RecordIntake {
    pub(crate) fn new(
        probe_name: &str,
        stats: Arc<ProbeStats>,
        metrics: &Metrics,
        store: Arc<EventStore>,
        enricher: Arc<dyn RuntimeEnricher>,
        sensitive_path_matcher: Arc<SensitivePathMatcher>,
    ) -> Self {
        let events_total = metrics
            .events_total
            .get_or_create(&ProbeLabel {
                probe: probe_name.to_string(),
            })
            .clone();
        Self {
            probe_name: probe_name.to_string(),
            stats,
            events_total,
            store,
            enricher,
            sensitive_path_matcher,
        }
    }

    /// Gate, bind, store and count `evidence`, appending what passes to `out`.
    pub(crate) fn admit(&self, evidence: NormalizedEvidence, out: &mut Vec<EvidenceRecord>) {
        let mut emitted = 0u64;
        for record in evidence.records {
            if !record_matches_sensitive_paths(&record, self.sensitive_path_matcher.as_ref()) {
                self.stats
                    .events_sampled_out
                    .fetch_add(1, Ordering::Relaxed);
                continue;
            }
            let record = bind_record(record, self.enricher.as_ref());
            // The local debug store keeps the lean occurrence shape used by
            // IPC stream/watch. Durable sinks project D6 metadata later via
            // EvidenceBatch::into_occurrences().
            self.store.push(&self.probe_name, record.occurrence.clone());
            emitted += 1;
            out.push(record);
        }
        if emitted > 0 {
            // Same point, same number: the metric and `jalki status` agree.
            self.stats
                .events_emitted
                .fetch_add(emitted, Ordering::Relaxed);
            self.events_total.inc_by(emitted);
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

/// Userspace half of the sensitive-path gate. The kernel checks only each
/// pattern's coarse prefix (the bytes before the first wildcard, so
/// `/home/*/.ssh/` gates on `/home/`); this is where the whole pattern is
/// applied. Both file types go through it. `kernel.file.open_attempt` used to
/// skip it and shipped every failed open under `/home/` (jalki#97: 74% of all
/// events on a CI node).
fn record_matches_sensitive_paths(
    record: &EvidenceRecord,
    sensitive_path_matcher: &SensitivePathMatcher,
) -> bool {
    let labels = &record.occurrence.labels;
    // The label carrying the path differs by type: `kernel.file.open` has the
    // resolved identity in `resource_ref_id`; `open_attempt` has only what the
    // caller asked for, unresolved, in `requested_path`.
    let path_label = match record.occurrence.occurrence_type.as_str() {
        "kernel.file.open" => "resource_ref_id",
        "kernel.file.open_attempt" => {
            // A requested path is caller-controlled and cut at 255 bytes, so
            // padding (`/home/u/././…/.ssh/id_rsa`) can push the part the
            // pattern needs past the cut. The kernel's prefix already matched;
            // the full pattern cannot judge a string it cannot see, so keep it.
            if labels.get("path_truncated").map(String::as_str) == Some("true") {
                return true;
            }
            "requested_path"
        }
        _ => return true,
    };

    labels
        .get(path_label)
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

    // ── the userspace half of the sensitive-path gate (jalki#97 fix 2) ──────

    use jalki_evidence::{FileOpenEvent, HookKind, KernelEvent, ProbeMetadata};

    fn probe_meta(id: &str, function: &str) -> ProbeMetadata {
        ProbeMetadata {
            probe_id: id.into(),
            probe_version: "1".into(),
            probe_family: "file".into(),
            hook_kind: HookKind::Tracepoint,
            kernel_function: function.into(),
        }
    }

    fn file_event(path: &str, ret: i32, path_truncated: bool) -> FileOpenEvent {
        FileOpenEvent {
            observed_at_ns: 1,
            pid: 7,
            uid: 1001,
            cgroup_id: 9,
            ret,
            flags: 0,
            comm: "rustc".into(),
            path: path.into(),
            path_truncated,
        }
    }

    /// A failed open of `path`, as the file_open_attempt probe emits it.
    fn open_attempt(path: &str) -> EvidenceRecord {
        KernelEvent::FileOpenAttempt(file_event(path, -2, false))
            .normalize(probe_meta("file_open_attempt", "sys_exit_openat"), "prod")
            .records
            .remove(0)
    }

    fn file_open(path: &str) -> EvidenceRecord {
        KernelEvent::FileOpen(file_event(path, 0, false))
            .normalize(probe_meta("file_open", "security_file_open"), "prod")
            .records
            .remove(0)
    }

    fn sensitive(record: &EvidenceRecord) -> bool {
        record_matches_sensitive_paths(record, &SensitivePathMatcher::default_patterns())
    }

    /// The jalki#97 noise: the kernel gates `/home/*/.ssh/` on its coarse
    /// prefix `/home/`, so every failed open under a runner's work tree reached
    /// userspace, and userspace waved `open_attempt` through without the full
    /// pattern — 74% of all events on the CI node.
    #[test]
    fn open_attempt_outside_the_sensitive_patterns_is_dropped() {
        assert!(!sensitive(&open_attempt(
            "/home/runner/_work/x/target/libfoo.so"
        )));
        assert!(!sensitive(&open_attempt("/home/runner/.cache/sccache/x")));
    }

    /// Guards against over-correcting: what the patterns name is still kept.
    #[test]
    fn open_attempt_inside_the_sensitive_patterns_is_kept() {
        for path in [
            "/home/runner/.ssh/id_ed25519",
            "/root/.ssh/authorized_keys",
            "/etc/shadow",
            // The shadow backups (`shadow-`, `shadow.bak`) are the same
            // credentials; the default pattern is `/etc/shadow*` for that.
            "/etc/shadow-",
            "/var/run/secrets/kubernetes.io/serviceaccount/token",
            // `*` spans `/`, so a dot-dot detour still lands in the pattern.
            "/home/runner/../runner/.ssh/id_rsa",
        ] {
            assert!(sensitive(&open_attempt(path)), "{path} must be kept");
        }
    }

    /// Decided, not accidental: the `.ssh` directory itself is outside
    /// `/home/*/.ssh/` (the trailing `/` means "what is under it"), for failed
    /// opens exactly as for `kernel.file.open`. An operator who wants directory
    /// probes adds `/home/*/.ssh` explicitly.
    #[test]
    fn open_attempt_of_the_ssh_directory_itself_is_dropped() {
        assert!(!sensitive(&open_attempt("/home/runner/.ssh")));
    }

    /// The requested path is caller-controlled and cut at 255 bytes. Padding it
    /// with `./` pushes `.ssh/` past the cut, so the stored string can never
    /// match the full pattern even though the kernel's prefix did. A truncated
    /// attempt is kept: the full pattern cannot judge a string it cannot see.
    #[test]
    fn truncated_open_attempt_is_kept() {
        let mut path = format!("/home/runner/{}.ssh/id_rsa", "./".repeat(121));
        path.truncate(255);
        assert!(!path.contains("/.ssh/"), "precondition: the cut hides .ssh");
        let record = KernelEvent::FileOpenAttempt(file_event(&path, -2, true))
            .normalize(probe_meta("file_open_attempt", "sys_exit_openat"), "prod")
            .records
            .remove(0);
        assert!(sensitive(&record));
    }

    #[test]
    fn open_attempt_without_a_requested_path_is_dropped() {
        let mut record = open_attempt("/home/runner/.ssh/id_rsa");
        record.occurrence.labels.remove("requested_path");
        assert!(!sensitive(&record));
    }

    // ── jalki_events_total{probe} (jalki#97 fix 4) ──────────────────────────

    fn tcp_connect_evidence() -> NormalizedEvidence {
        KernelEvent::TcpConnect(jalki_evidence::TcpConnectEvent {
            observed_at_ns: 1,
            pid: 1,
            tid: 1,
            src_ip: "10.0.0.1".parse().expect("ip"),
            dst_ip: "10.0.0.2".parse().expect("ip"),
            src_port: 1234,
            dst_port: 443,
            addr_family: 2,
            ret: 0,
            cgroup_id: 1,
            comm: "curl".into(),
            netns: 0,
        })
        .normalize(probe_meta("tcp_connect", "tcp_connect"), "prod")
    }

    fn intake(probe: &str, metrics: &Metrics) -> (RecordIntake, Arc<ProbeStats>, Arc<EventStore>) {
        let stats = Arc::new(ProbeStats::new());
        let store = Arc::new(EventStore::new(16));
        let intake = RecordIntake::new(
            probe,
            stats.clone(),
            metrics,
            store.clone(),
            Arc::new(crate::enrich::NoopEnricher),
            Arc::new(SensitivePathMatcher::default_patterns()),
        );
        (intake, stats, store)
    }

    fn stored(store: &EventStore, probe: &str) -> usize {
        store
            .query(probe, &crate::store::EventFilter::default())
            .len()
    }

    /// Before jalki#97 the series was registered and never incremented, so a
    /// node drowning in failed opens could only be diagnosed with
    /// `kubectl exec … jalki status`.
    #[test]
    fn admitted_records_count_as_events_per_probe() {
        let metrics = Metrics::new();
        let (intake, stats, store) = intake("tcp_connect", &metrics);
        let mut out = Vec::new();
        for _ in 0..3 {
            intake.admit(tcp_connect_evidence(), &mut out);
        }

        assert_eq!(out.len(), 3);
        assert_eq!(stats.events_emitted.load(Ordering::Relaxed), 3);
        assert_eq!(stored(&store, "tcp_connect"), 3);
        let text = metrics.encode();
        assert!(
            text.contains("jalki_events_total{probe=\"tcp_connect\"} 3"),
            "{text}"
        );
    }

    /// What the path gate refuses is not an event: not stored, not counted,
    /// not sent on. (`events_sampled_out` counts it — a pre-existing misnomer.)
    #[test]
    fn path_filtered_records_are_not_events() {
        let metrics = Metrics::new();
        let (intake, stats, store) = intake("file_open_attempt", &metrics);
        let attempt = |path: &str| NormalizedEvidence::single(open_attempt(path));
        let mut out = Vec::new();

        intake.admit(attempt("/home/runner/_work/x/target/libfoo.so"), &mut out);
        assert!(out.is_empty());
        assert_eq!(stats.events_emitted.load(Ordering::Relaxed), 0);
        assert_eq!(stats.events_sampled_out.load(Ordering::Relaxed), 1);
        assert_eq!(stored(&store, "file_open_attempt"), 0);
        assert!(metrics
            .encode()
            .contains("jalki_events_total{probe=\"file_open_attempt\"} 0"));

        intake.admit(attempt("/home/runner/.ssh/id_rsa"), &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(stored(&store, "file_open_attempt"), 1);
        assert!(metrics
            .encode()
            .contains("jalki_events_total{probe=\"file_open_attempt\"} 1"));
    }

    /// Regression: `kernel.file.open` keeps matching on its resolved identity,
    /// and types that are not file evidence are not path-gated at all.
    #[test]
    fn file_open_still_matches_on_resource_ref_id() {
        assert!(sensitive(&file_open("/etc/shadow")));
        assert!(!sensitive(&file_open("/tmp/not-sensitive")));

        let connect = KernelEvent::TcpConnect(jalki_evidence::TcpConnectEvent {
            observed_at_ns: 1,
            pid: 1,
            tid: 1,
            src_ip: "10.0.0.1".parse().expect("ip"),
            dst_ip: "10.0.0.2".parse().expect("ip"),
            src_port: 1234,
            dst_port: 443,
            addr_family: 2,
            ret: 0,
            cgroup_id: 1,
            comm: "curl".into(),
            netns: 0,
        })
        .normalize(probe_meta("tcp_connect", "tcp_connect"), "prod")
        .records
        .remove(0);
        assert!(sensitive(&connect));
    }
}

//! The reader→sink queue, bounded by the bytes it holds (jalki#97).
//!
//! Each reader hands the sink loop one message per ring-buffer drain: up to
//! 1,024 records, about 3.5 MB of real memory. This used to be
//! `mpsc::channel(8192)`, bounded by message *count* and so unbounded in bytes;
//! the namespace scope ran only after it, and self-shedding could not see it.
//! Any in-scope burst faster than the sink grew RSS by ~13 MiB/s until the
//! kernel OOM-killed the agent, which loses everything held and reports
//! nothing (six memory deaths in 5.7 days on a CI node).
//!
//! [`SinkQueueSender::try_send`] never blocks and never waits. In order, it
//!
//! 1. counts records the Plane-B projection will drop for lacking a strong
//!    binding (`jalki_unbound_dropped_total`);
//! 2. applies the namespace scope, so out-of-scope evidence never takes memory
//!    (a scope, not a loss: no gap);
//! 3. measures the message's resident bytes ([`resident_bytes`]);
//! 4. reserves them against the budget, or refuses the message: its records
//!    are counted per probe (`jalki_sink_queue_dropped_total`) and reported as
//!    `jalki.agent.gap` evidence.
//!
//! **Refuse-newest, never evict.** What was accepted is delivered in order.
//! The shed order of ADR-0006 contract 5 (reliability before attribution) is
//! kept at admission instead: a message of only reliability evidence (TCP
//! close / retransmit) may fill three quarters of the budget, so it is refused
//! first and the last quarter stays for exec, connect and file evidence.
//!
//! **Loss reports travel the same queue.** Refusals are merged per cause into
//! one pending report, and at most one marker for it is ever queued; when the
//! receiver reaches the marker it takes every report merged so far. Sustained
//! overload therefore yields one gap per cause per pass through the queue, not
//! one per refused message. A gap's place in the stream is not evidence order:
//! it may arrive before evidence that was observed earlier than some of the
//! records it covers. Its `gap_start_ns`/`gap_end_ns` window is authoritative.
//!
//! **Memory pressure** (set by the sink loop from the cgroup ratio) shrinks the
//! budget to `pressure_max_bytes` (`max_bytes / 8`, at least 4 MiB): a flow the
//! sink keeps up with still passes, and build-up beyond it is refused with the
//! cause `sink_queue_memory_pressure`.
//!
//! Agent records (`jalki.agent.*`, e.g. ring-buffer gaps) are never scoped and
//! never refused: a loss report must not itself be lost, and their volume is
//! bounded by their producers. An empty queue always takes one message, even
//! one larger than the budget, so a small budget cannot stall delivery. The
//! queue therefore holds at most `max_bytes` plus one message, plus agent
//! records.

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;

use jalki_evidence::{
    gap_for_records, resident_bytes, EvidenceClass, EvidenceRecord, GapReport, UnboundReason,
};
use tokio::sync::mpsc;
use tracing::warn;

use crate::metrics::{Metrics, ProbeLabel, UnboundDropLabel};

/// Default budget: 128 MiB of estimated resident memory, about 39,000 bound
/// records or 70 s of delivery at 550 records/s.
pub const DEFAULT_QUEUE_MAX_BYTES: usize = 128 * 1024 * 1024;

/// The smallest pressure budget, so pressure never starves a flow the sink
/// keeps up with.
const PRESSURE_BUDGET_FLOOR: usize = 4 * 1024 * 1024;

/// The refusal WARN repeats at most this often.
const REFUSAL_WARN_INTERVAL_MS: u64 = 10_000;

/// Gap cause: the queue was at its budget.
pub const CAUSE_OVERFLOW: &str = "sink_queue_overflow";
/// Gap cause: the queue was at its pressure budget. Distinct from the retry
/// buffer's `memory_pressure` (ADR-0006 contract 6): that one gave up old,
/// buffered evidence; this one never accepted fresh evidence.
pub const CAUSE_MEMORY_PRESSURE: &str = "sink_queue_memory_pressure";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SinkQueueConfig {
    /// Budget in estimated resident bytes.
    pub max_bytes: usize,
    /// Budget while memory pressure is on.
    pub pressure_max_bytes: usize,
}

impl Default for SinkQueueConfig {
    fn default() -> Self {
        Self::new(DEFAULT_QUEUE_MAX_BYTES)
    }
}

impl SinkQueueConfig {
    /// A budget of `max_bytes`, with the pressure budget derived from it:
    /// `max_bytes / 8`, at least 4 MiB, never above `max_bytes`.
    pub fn new(max_bytes: usize) -> Self {
        Self {
            max_bytes,
            pressure_max_bytes: (max_bytes / 8).max(PRESSURE_BUDGET_FLOOR).min(max_bytes),
        }
    }

    /// `JALKI_QUEUE_MAX_BYTES`: a plain byte count, like `JALKI_RETRY_MAX_BYTES`.
    /// 0 is allowed and means "one message at a time".
    pub fn from_env() -> Self {
        Self::from_env_value(std::env::var("JALKI_QUEUE_MAX_BYTES").ok().as_deref())
    }

    fn from_env_value(raw: Option<&str>) -> Self {
        let Some(value) = raw.map(str::trim).filter(|v| !v.is_empty()) else {
            return Self::default();
        };
        match value.parse::<usize>() {
            Ok(max_bytes) => Self::new(max_bytes),
            Err(_) => {
                // Loud: the operator believes they set a budget, and silently
                // getting the default instead is how a limit gets mis-sized.
                warn!(
                    value,
                    default = DEFAULT_QUEUE_MAX_BYTES,
                    "JALKI_QUEUE_MAX_BYTES is not a plain byte count (e.g. 134217728); \
                     using the default"
                );
                Self::default()
            }
        }
    }
}

/// What [`SinkQueueSender::try_send`] did with a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    /// Queued for the sink loop.
    Admitted,
    /// Nothing left to queue once the namespace scope applied (or nothing was
    /// passed). A scope, not a loss: no gap.
    OutOfScope,
    /// The queue was full. Counted per probe and reported as gap evidence.
    Refused,
}

/// The sink loop is gone; nothing will deliver anything sent from here.
#[derive(Debug, thiserror::Error)]
#[error("sink queue closed")]
pub struct QueueClosed;

/// What [`SinkQueueReceiver::recv`] hands the sink loop.
#[derive(Debug)]
pub enum Received {
    Records(Vec<EvidenceRecord>),
    /// Loss reports for refused messages, at most one per cause.
    Gaps(Vec<GapReport>),
}

enum Queued {
    /// `bytes` is exactly what was reserved, so receipt releases the same.
    Records {
        records: Vec<EvidenceRecord>,
        bytes: usize,
    },
    /// "Take the pending loss reports." Holds no bytes; counts as a message.
    GapMarker,
}

/// Build the queue. `scope` is the namespace allow-list (`None`: deliver all).
pub fn channel(
    config: SinkQueueConfig,
    scope: Option<HashSet<String>>,
    metrics: Arc<Metrics>,
) -> (SinkQueueSender, SinkQueueReceiver) {
    let (tx, rx) = mpsc::unbounded_channel();
    metrics.sink_queue_max_bytes.set(gauge(config.max_bytes));
    // `Shared` holds no sender, so the receiver sees `None` once every
    // `SinkQueueSender` clone is dropped, exactly like a plain channel.
    let shared = Arc::new(Shared {
        max_bytes: config.max_bytes,
        pressure_max_bytes: config.pressure_max_bytes,
        bytes: AtomicUsize::new(0),
        messages: AtomicUsize::new(0),
        under_pressure: AtomicBool::new(false),
        scope,
        metrics,
        lost: Mutex::new(Lost::default()),
        started: Instant::now(),
        last_warn_ms: AtomicU64::new(0),
    });
    (
        SinkQueueSender {
            tx,
            shared: shared.clone(),
        },
        SinkQueueReceiver { rx, shared },
    )
}

/// The readers' end. Cheap to clone; never blocks.
#[derive(Clone)]
pub struct SinkQueueSender {
    tx: mpsc::UnboundedSender<Queued>,
    shared: Arc<Shared>,
}

impl SinkQueueSender {
    /// Scope, measure and admit `records`, or refuse them as reported loss.
    pub fn try_send(&self, mut records: Vec<EvidenceRecord>) -> Result<Admission, QueueClosed> {
        if self.tx.is_closed() {
            return Err(QueueClosed);
        }
        let shared = &self.shared;
        // Counted before the scope: with an allow-list an unbound record is
        // always out of scope, and it must still be counted once.
        record_unbound_drops(&shared.metrics, &records);
        if let Some(allow) = &shared.scope {
            records.retain(|record| record_in_namespace_scope(record, allow));
        }
        if records.is_empty() {
            return Ok(Admission::OutOfScope);
        }
        // A reader message is push-grown, so it can hold twice its records in
        // capacity, and `retain` leaves the capacity behind. Measured bytes
        // include slack (it is allocated), so give it back first.
        if records.capacity() > records.len() + records.len() / 4 {
            records.shrink_to_fit();
        }
        let bytes = resident_bytes(&records);
        match shared.reserve(bytes, admit_class(&records)) {
            Ok(()) => {
                if self.tx.send(Queued::Records { records, bytes }).is_err() {
                    shared.release(bytes);
                    return Err(QueueClosed);
                }
                Ok(Admission::Admitted)
            }
            Err(cause) => {
                self.refuse(cause, &records);
                Ok(Admission::Refused)
            }
        }
    }

    fn refuse(&self, cause: &'static str, records: &[EvidenceRecord]) {
        let shared = &self.shared;
        // A reader message is one probe's; split anyway, so a mixed message
        // cannot charge one probe for another's records.
        for run in records.chunk_by(|a, b| a.probe.probe_id == b.probe.probe_id) {
            if let Some(first) = run.first() {
                shared
                    .metrics
                    .sink_queue_dropped
                    .get_or_create(&ProbeLabel {
                        probe: first.probe.probe_id.clone(),
                    })
                    .inc_by(run.len() as u64);
            }
        }
        let report = gap_for_records(cause, records);
        let first_of_episode = {
            let mut lost = shared.lost();
            merge_by_cause(&mut lost.reports, report);
            !std::mem::replace(&mut lost.marker_queued, true)
        };
        if !first_of_episode {
            // A marker is already queued; the receiver takes this report with
            // it (the flag is cleared and the reports taken under one lock).
            return;
        }
        if shared.warn_due() {
            warn!(
                cause,
                queued_bytes = shared.bytes.load(Ordering::Relaxed),
                max_bytes = shared.max_bytes,
                pressure_max_bytes = shared.pressure_max_bytes,
                "reader→sink queue is full: new evidence is refused, counted in \
                 jalki_sink_queue_dropped_total and reported as jalki.agent.gap \
                 until the sink catches up (jalki#97; logged at most every 10 s)"
            );
        }
        shared.messages.fetch_add(1, Ordering::AcqRel);
        shared.metrics.sink_queue_messages.inc();
        if self.tx.send(Queued::GapMarker).is_err() {
            // The sink loop is gone; nothing will deliver the report.
            shared.messages.fetch_sub(1, Ordering::AcqRel);
            shared.metrics.sink_queue_messages.dec();
        }
    }

    pub fn queued_bytes(&self) -> usize {
        self.shared.bytes.load(Ordering::Acquire)
    }

    pub fn queued_messages(&self) -> usize {
        self.shared.messages.load(Ordering::Acquire)
    }
}

/// The sink loop's end.
pub struct SinkQueueReceiver {
    rx: mpsc::UnboundedReceiver<Queued>,
    shared: Arc<Shared>,
}

impl SinkQueueReceiver {
    /// The next message, or `None` once every sender is gone and the queue is
    /// empty.
    ///
    /// Cancel-safe, for `select!`: the only await is the inner channel's
    /// (itself cancel-safe), and everything after it runs without yielding, so
    /// a cancelled call has taken nothing. A marker whose reports were already
    /// taken by an earlier one carries nothing and is skipped.
    pub async fn recv(&mut self) -> Option<Received> {
        loop {
            match self.rx.recv().await? {
                Queued::Records { records, bytes } => {
                    self.shared.release(bytes);
                    return Some(Received::Records(records));
                }
                Queued::GapMarker => {
                    self.shared.release_marker();
                    let reports = self.shared.take_lost();
                    if !reports.is_empty() {
                        return Some(Received::Gaps(reports));
                    }
                }
            }
        }
    }

    pub fn queued_bytes(&self) -> usize {
        self.shared.bytes.load(Ordering::Acquire)
    }

    pub fn queued_messages(&self) -> usize {
        self.shared.messages.load(Ordering::Acquire)
    }

    pub fn pressure_max_bytes(&self) -> usize {
        self.shared.pressure_max_bytes
    }

    pub fn memory_pressure(&self) -> bool {
        self.shared.under_pressure.load(Ordering::Relaxed)
    }

    /// Hold the queue to its pressure budget (`true`) or release it. Returns
    /// whether the state changed, so the caller can log transitions only.
    pub fn set_memory_pressure(&self, on: bool) -> bool {
        let was = self.shared.under_pressure.swap(on, Ordering::Relaxed);
        self.shared
            .metrics
            .sink_queue_memory_pressure
            .set(i64::from(on));
        was != on
    }
}

struct Shared {
    max_bytes: usize,
    pressure_max_bytes: usize,
    /// Reserved bytes: the truth admission decides on.
    bytes: AtomicUsize,
    /// Queued messages, markers included.
    messages: AtomicUsize,
    under_pressure: AtomicBool,
    scope: Option<HashSet<String>>,
    metrics: Arc<Metrics>,
    /// Touched only on refusal and on receipt of a marker.
    lost: Mutex<Lost>,
    /// Rate limit for the refusal WARN: a small budget can cycle markers
    /// many times a second, and the metric and the gaps carry the counts.
    started: Instant,
    last_warn_ms: AtomicU64,
}

#[derive(Default)]
struct Lost {
    /// At most one report per cause.
    reports: Vec<GapReport>,
    /// A marker for `reports` is in the queue.
    marker_queued: bool,
}

/// Which limit a message is admitted against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Admit {
    /// Only `jalki.agent.*` records: always admitted.
    Agent,
    Attribution,
    /// Only reliability evidence: refused before the last quarter of the
    /// budget (ADR-0006 contract 5).
    Reliability,
}

fn admit_class(records: &[EvidenceRecord]) -> Admit {
    if records.iter().all(EvidenceRecord::is_agent_record) {
        Admit::Agent
    } else if records
        .iter()
        .all(|record| record.evidence_class() == EvidenceClass::Reliability)
    {
        Admit::Reliability
    } else {
        Admit::Attribution
    }
}

impl Shared {
    fn lost(&self) -> MutexGuard<'_, Lost> {
        self.lost
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Reserve `bytes`, or say which cause refuses them.
    ///
    /// A compare-and-swap loop, so concurrent readers cannot race past the
    /// budget: two that both see an empty queue both try to claim it, one
    /// wins, and the other re-checks against what the winner reserved.
    fn reserve(&self, bytes: usize, class: Admit) -> Result<(), &'static str> {
        let pressured = self.under_pressure.load(Ordering::Relaxed);
        let budget = if pressured {
            self.pressure_max_bytes
        } else {
            self.max_bytes
        };
        let limit = match class {
            Admit::Agent => usize::MAX,
            Admit::Attribution => budget,
            Admit::Reliability => budget - budget / 4,
        };
        let mut current = self.bytes.load(Ordering::Acquire);
        loop {
            // An empty queue takes one message whatever its size, or a small
            // budget (or pressure) could stall delivery outright.
            if current != 0 && current.saturating_add(bytes) > limit {
                return Err(if pressured {
                    CAUSE_MEMORY_PRESSURE
                } else {
                    CAUSE_OVERFLOW
                });
            }
            match self.bytes.compare_exchange_weak(
                current,
                current.saturating_add(bytes),
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(now) => current = now,
            }
        }
        // Counted before the send, so the receiver can never decrement first.
        // The gauges move by deltas rather than snapshots, which keeps them
        // consistent under concurrent writers.
        self.messages.fetch_add(1, Ordering::AcqRel);
        self.metrics.sink_queue_bytes.inc_by(gauge(bytes));
        self.metrics.sink_queue_messages.inc();
        Ok(())
    }

    /// True at most once per [`REFUSAL_WARN_INTERVAL_MS`], and on the first call.
    fn warn_due(&self) -> bool {
        let now = u64::try_from(self.started.elapsed().as_millis())
            .unwrap_or(u64::MAX)
            .saturating_add(REFUSAL_WARN_INTERVAL_MS);
        let last = self.last_warn_ms.load(Ordering::Relaxed);
        now.saturating_sub(last) >= REFUSAL_WARN_INTERVAL_MS
            && self
                .last_warn_ms
                .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
    }

    fn release(&self, bytes: usize) {
        self.bytes.fetch_sub(bytes, Ordering::AcqRel);
        self.messages.fetch_sub(1, Ordering::AcqRel);
        self.metrics.sink_queue_bytes.dec_by(gauge(bytes));
        self.metrics.sink_queue_messages.dec();
    }

    fn release_marker(&self) {
        self.messages.fetch_sub(1, Ordering::AcqRel);
        self.metrics.sink_queue_messages.dec();
    }

    /// Clear the marker flag and take the reports under ONE lock. A refusal
    /// after this sees no marker queued and sends a new one, so its report
    /// cannot be stranded; one before it is in what is taken here.
    fn take_lost(&self) -> Vec<GapReport> {
        let mut lost = self.lost();
        lost.marker_queued = false;
        std::mem::take(&mut lost.reports)
    }
}

/// Merge `gap` into the report with the same cause, or add it. Causes stay
/// apart (ADR-0006 contract 6): `GapReport::merge` across causes collapses
/// them to `multiple`.
pub(crate) fn merge_by_cause(reports: &mut Vec<GapReport>, gap: GapReport) {
    match reports.iter_mut().find(|report| report.cause == gap.cause) {
        Some(existing) => existing.merge(gap),
        None => reports.push(gap),
    }
}

fn gauge(bytes: usize) -> i64 {
    i64::try_from(bytes).unwrap_or(i64::MAX)
}

/// Source-side volume control: keep only evidence bound to an allowed
/// namespace. The agent's own records are never scoped out.
fn record_in_namespace_scope(record: &EvidenceRecord, allow: &HashSet<String>) -> bool {
    record.is_agent_record()
        || record
            .bound_namespace()
            .is_some_and(|namespace| allow.contains(namespace))
}

/// `jalki_unbound_dropped_total{reason}`: one increment per reason per
/// message rather than a family lookup per record.
fn record_unbound_drops(metrics: &Metrics, records: &[EvidenceRecord]) {
    let mut counts: Vec<(UnboundReason, u64)> = Vec::new();
    for reason in records
        .iter()
        .filter_map(EvidenceRecord::plane_b_drop_reason)
    {
        match counts.iter_mut().find(|(seen, _)| *seen == reason) {
            Some((_, n)) => *n += 1,
            None => counts.push((reason, 1)),
        }
    }
    for (reason, n) in counts {
        metrics
            .unbound_dropped_total
            .get_or_create(&UnboundDropLabel {
                reason: reason.as_str().into(),
            })
            .inc_by(n);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use false_protocol::Occurrence;
    use jalki_evidence::{
        BindingProvenance, HookKind, KernelEvent, ProbeMetadata, ProducerMetadata, RuntimeBinding,
        TcpCloseEvent, TcpConnectEvent,
    };

    fn meta(id: &str) -> ProbeMetadata {
        ProbeMetadata {
            probe_id: id.into(),
            probe_version: "1".into(),
            probe_family: "tcp".into(),
            hook_kind: HookKind::Fexit,
            kernel_function: id.into(),
        }
    }

    /// One unbound tcp_connect record, observed at `at`.
    fn connect_at(at: u64) -> Vec<EvidenceRecord> {
        KernelEvent::TcpConnect(TcpConnectEvent {
            observed_at_ns: at,
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
        .normalize(meta("tcp_connect"), "test")
        .records
    }

    fn connect() -> Vec<EvidenceRecord> {
        connect_at(1_000)
    }

    fn close() -> Vec<EvidenceRecord> {
        KernelEvent::TcpClose(TcpCloseEvent {
            observed_at_ns: 1_000,
            pid: 1,
            tid: 1,
            src_ip: "10.0.0.1".parse().expect("ip"),
            dst_ip: "10.0.0.2".parse().expect("ip"),
            src_port: 0,
            dst_port: 443,
            addr_family: 2,
            bytes_sent: 1,
            bytes_received: 2,
            duration_ns: 3,
            cgroup_id: 1,
            comm: "curl".into(),
            netns: 0,
        })
        .normalize(meta("tcp_close"), "test")
        .records
    }

    fn bound(namespace: &str) -> RuntimeBinding {
        RuntimeBinding::Bound {
            container_id: "c".into(),
            pod_uid: Some("p".into()),
            pod_name: Some("pod".into()),
            namespace: Some(namespace.into()),
            service_account: None,
            owner_kind: None,
            owner_name: None,
            owner_uid: None,
            provenance: BindingProvenance::Observed,
        }
    }

    fn connect_in(namespace: &str) -> Vec<EvidenceRecord> {
        connect()
            .into_iter()
            .map(|record| record.with_runtime_binding(bound(namespace)))
            .collect()
    }

    fn agent_gap() -> Vec<EvidenceRecord> {
        GapReport {
            cause: "ringbuffer_overflow".into(),
            affected_probes: vec!["kernel.tcp.connect".into()],
            dropped_records: 1,
            gap_start_ns: 10,
            gap_end_ns: 20,
            dropped_reliability: 0,
            dropped_attribution: 1,
        }
        .into_batch(ProducerMetadata::new("test", "node-1", "6.17.0"))
        .records
    }

    /// Budgets are sized in what one test message really costs, never a
    /// hard-coded number.
    fn unit() -> usize {
        resident_bytes(&connect())
    }

    fn queue(
        max_bytes: usize,
        scope: Option<&[&str]>,
    ) -> (SinkQueueSender, SinkQueueReceiver, Arc<Metrics>) {
        queue_with(
            SinkQueueConfig {
                max_bytes,
                pressure_max_bytes: max_bytes,
            },
            scope,
        )
    }

    fn queue_with(
        config: SinkQueueConfig,
        scope: Option<&[&str]>,
    ) -> (SinkQueueSender, SinkQueueReceiver, Arc<Metrics>) {
        let metrics = Arc::new(Metrics::new());
        let scope = scope.map(|names| names.iter().map(|n| n.to_string()).collect());
        let (tx, rx) = channel(config, scope, metrics.clone());
        (tx, rx, metrics)
    }

    fn send(tx: &SinkQueueSender, records: Vec<EvidenceRecord>) -> Admission {
        tx.try_send(records).expect("queue open")
    }

    /// Everything currently queued, without waiting for more.
    fn drain_now(rx: &mut SinkQueueReceiver) -> Vec<Received> {
        let mut out = Vec::new();
        while rx.queued_messages() > 0 {
            match rx.rx.try_recv() {
                Ok(Queued::Records { records, bytes }) => {
                    rx.shared.release(bytes);
                    out.push(Received::Records(records));
                }
                Ok(Queued::GapMarker) => {
                    rx.shared.release_marker();
                    let reports = rx.shared.take_lost();
                    if !reports.is_empty() {
                        out.push(Received::Gaps(reports));
                    }
                }
                Err(_) => break,
            }
        }
        out
    }

    fn gaps(received: &[Received]) -> Vec<GapReport> {
        received
            .iter()
            .filter_map(|r| match r {
                Received::Gaps(g) => Some(g.clone()),
                Received::Records(_) => None,
            })
            .flatten()
            .collect()
    }

    fn dropped(metrics: &Metrics, probe: &str) -> u64 {
        metrics
            .sink_queue_dropped
            .get_or_create(&ProbeLabel {
                probe: probe.into(),
            })
            .get()
    }

    /// The issue's scope test: an out-of-scope bound record never takes queue
    /// memory. Before jalki#97 the scope ran in the sink loop, after the
    /// channel had already held it.
    #[test]
    fn out_of_scope_evidence_never_enters_the_queue() {
        let (tx, _rx, _) = queue(DEFAULT_QUEUE_MAX_BYTES, Some(&["workloads"]));

        assert_eq!(send(&tx, connect_in("other")), Admission::OutOfScope);
        assert_eq!(tx.queued_messages(), 0);
        assert_eq!(tx.queued_bytes(), 0);

        assert_eq!(send(&tx, connect_in("workloads")), Admission::Admitted);
        assert_eq!(tx.queued_messages(), 1);
    }

    /// Pins that the scope judges the binding taken at read time: a record
    /// from a pod the cache had not seen yet is unbound, out of scope and
    /// counted as `cache_miss`, the same as before the scope moved here.
    #[test]
    fn scope_uses_the_read_time_binding() {
        let (tx, _rx, metrics) = queue(DEFAULT_QUEUE_MAX_BYTES, Some(&["workloads"]));
        let unbound = connect()
            .into_iter()
            .map(|r| {
                r.with_runtime_binding(RuntimeBinding::Unbound {
                    reason: UnboundReason::CacheMiss,
                })
            })
            .collect();

        assert_eq!(send(&tx, unbound), Admission::OutOfScope);
        assert!(metrics
            .encode()
            .contains("jalki_unbound_dropped_total_total{reason=\"cache_miss\"} 1"));
    }

    /// Loss reports are never scoped out and never refused (replaces
    /// `namespace_allowlist_never_discards_agent_gaps`).
    #[test]
    fn agent_gaps_pass_scope_and_budget() {
        let (tx, _rx, _) = queue(unit(), Some(&["workloads"]));
        assert_eq!(send(&tx, connect_in("workloads")), Admission::Admitted);
        assert_eq!(send(&tx, connect_in("workloads")), Admission::Refused);

        assert_eq!(send(&tx, agent_gap()), Admission::Admitted);
    }

    /// The core of fix 1: past the budget the queue refuses rather than grows.
    #[test]
    fn a_full_queue_refuses_instead_of_growing() {
        let budget = 10 * unit();
        let (tx, _rx, metrics) = queue(budget, None);

        let outcomes: Vec<_> = (0..50).map(|_| send(&tx, connect())).collect();

        let admitted = outcomes
            .iter()
            .filter(|o| **o == Admission::Admitted)
            .count();
        let refused = outcomes
            .iter()
            .filter(|o| **o == Admission::Refused)
            .count();
        assert_eq!((admitted, refused), (10, 40));
        assert!(tx.queued_bytes() <= budget);
        assert_eq!(dropped(&metrics, "tcp_connect"), 40);
        assert!(metrics
            .encode()
            .contains("jalki_sink_queue_dropped_total{probe=\"tcp_connect\"} 40"));
    }

    #[test]
    fn an_empty_queue_takes_one_oversized_message() {
        let (tx, mut rx, _) = queue(0, None);

        assert_eq!(send(&tx, connect()), Admission::Admitted);
        assert_eq!(send(&tx, connect()), Admission::Refused);
        drain_now(&mut rx);
        assert_eq!(send(&tx, connect()), Admission::Admitted);
    }

    /// 40 refusals are one marker and one gap, not 40 messages.
    #[test]
    fn refusals_coalesce_into_one_gap() {
        let (tx, mut rx, _) = queue(10 * unit(), None);
        let mut refused = 0;
        for i in 0..50u64 {
            if send(&tx, connect_at(1_000 + i)) == Admission::Refused {
                refused += 1;
            }
        }
        // A self-observability record carries no kernel time; it must not
        // drag the window back to 0.
        let mut parse_errors = vec![EvidenceRecord {
            observed_at_ns: 0,
            pid: 0,
            cgroup_id: 0,
            probe: meta("jalki_self"),
            occurrence: Occurrence::new("jalki/self", "jalki.probe.parse_errors"),
            binding: None,
        }];
        parse_errors.shrink_to_fit();
        assert_eq!(send(&tx, parse_errors), Admission::Refused);
        assert_eq!(refused, 40);
        assert_eq!(tx.queued_messages(), 10 + 1, "admitted + one marker");

        let received = drain_now(&mut rx);
        let gaps = gaps(&received);
        assert_eq!(gaps.len(), 1, "{gaps:?}");
        let gap = &gaps[0];
        assert_eq!(
            gap.cause, "sink_queue_overflow",
            "a wire contract: Vartio sees it"
        );
        assert_eq!(gap.dropped_records, 41);
        assert_eq!(gap.dropped_attribution, 41);
        assert_eq!(
            gap.affected_probes,
            vec![
                "kernel.tcp.connect".to_string(),
                "jalki.probe.parse_errors".to_string()
            ]
        );
        assert_eq!((gap.gap_start_ns, gap.gap_end_ns), (1_010, 1_049));
        assert!(
            matches!(received.last(), Some(Received::Gaps(_))),
            "the gap comes after what was queued before it"
        );
    }

    /// A refusal after the receiver took the reports queues a new marker; its
    /// report is never stranded behind a flag nobody will clear.
    #[test]
    fn a_refusal_after_the_gap_is_taken_is_reported_again() {
        let (tx, mut rx, _) = queue(unit(), None);
        assert_eq!(send(&tx, connect()), Admission::Admitted);
        assert_eq!(send(&tx, connect()), Admission::Refused);
        assert_eq!(gaps(&drain_now(&mut rx)).len(), 1);

        assert_eq!(send(&tx, connect()), Admission::Admitted);
        assert_eq!(send(&tx, connect()), Admission::Refused);
        assert_eq!(tx.queued_messages(), 2, "a second marker");
        let second = gaps(&drain_now(&mut rx));
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].dropped_records, 1);
    }

    #[test]
    fn queue_gauges_follow_admission_and_receipt() {
        let (tx, mut rx, metrics) = queue(10 * unit(), None);
        assert_eq!(metrics.sink_queue_max_bytes.get(), (10 * unit()) as i64);

        send(&tx, connect());
        send(&tx, connect());
        assert_eq!(metrics.sink_queue_messages.get(), 2);
        assert_eq!(metrics.sink_queue_bytes.get(), tx.queued_bytes() as i64);
        assert!(metrics.sink_queue_bytes.get() > 0);

        drain_now(&mut rx);
        assert_eq!(metrics.sink_queue_messages.get(), 0);
        assert_eq!(metrics.sink_queue_bytes.get(), 0);
        assert_eq!(tx.queued_bytes(), 0);
    }

    /// Pressure holds the queue to its pressure budget and reports the refusal
    /// under its own cause; clearing it restores the full budget.
    #[test]
    fn memory_pressure_holds_the_queue_to_its_pressure_budget() {
        let (tx, mut rx, metrics) = queue_with(
            SinkQueueConfig {
                max_bytes: 10 * unit(),
                pressure_max_bytes: 2 * unit(),
            },
            None,
        );
        assert!(rx.set_memory_pressure(true), "a transition");
        assert!(!rx.set_memory_pressure(true), "not a transition");
        assert_eq!(metrics.sink_queue_memory_pressure.get(), 1);

        assert_eq!(send(&tx, connect()), Admission::Admitted);
        assert_eq!(send(&tx, connect()), Admission::Admitted);
        assert_eq!(send(&tx, connect()), Admission::Refused);
        let gaps = gaps(&drain_now(&mut rx));
        assert_eq!(gaps.len(), 1);
        assert_eq!(
            gaps[0].cause, "sink_queue_memory_pressure",
            "its own cause, not the retry buffer's memory_pressure (ADR-0006 contract 6)"
        );

        rx.set_memory_pressure(false);
        assert_eq!(metrics.sink_queue_memory_pressure.get(), 0);
        for _ in 0..10 {
            assert_eq!(send(&tx, connect()), Admission::Admitted);
        }
    }

    /// Pressure is often not the queue's doing (page cache, allocator decay,
    /// the local store), and refusing evidence does not lower it. So it must
    /// not throttle a flow the sink keeps up with: with the default budget the
    /// pressure budget is 16 MiB, far above a few messages in flight while the
    /// loop is inside one append.
    #[test]
    fn memory_pressure_does_not_starve_a_steady_flow() {
        let (tx, rx, _) = queue_with(SinkQueueConfig::default(), None);
        rx.set_memory_pressure(true);

        for _ in 0..10 {
            assert_eq!(send(&tx, connect()), Admission::Admitted);
        }
    }

    #[test]
    fn the_pressure_budget_derives_from_the_budget() {
        assert_eq!(
            SinkQueueConfig::default().pressure_max_bytes,
            DEFAULT_QUEUE_MAX_BYTES / 8
        );
        assert_eq!(
            SinkQueueConfig::new(8 * 1024 * 1024).pressure_max_bytes,
            4 * 1024 * 1024,
            "never below the floor"
        );
        assert_eq!(
            SinkQueueConfig::new(1024).pressure_max_bytes,
            1024,
            "never above the budget"
        );
    }

    /// ADR-0006 contract 5 at admission: reliability evidence cannot take the
    /// last quarter of the budget, so it is refused before attribution.
    #[test]
    fn reliability_is_refused_before_attribution() {
        let close_unit = resident_bytes(&close());
        assert!(unit() <= 2 * close_unit, "precondition: comparable sizes");
        let (tx, _rx, metrics) = queue(8 * close_unit, None);

        // Bounded: a queue that never refuses must fail this, not exhaust
        // memory (which is what an unbounded queue does).
        let admitted = (0..100)
            .take_while(|_| send(&tx, close()) == Admission::Admitted)
            .count();
        assert_eq!(admitted, 6, "three quarters of eight");
        assert_eq!(dropped(&metrics, "tcp_close"), 1);

        assert_eq!(send(&tx, connect()), Admission::Admitted);
    }

    /// A small budget cycles markers fast; the WARN must not follow suit.
    #[test]
    fn the_refusal_warning_is_rate_limited() {
        let (_tx, rx, _) = queue(DEFAULT_QUEUE_MAX_BYTES, None);
        assert!(rx.shared.warn_due(), "the first refusal episode is logged");
        assert!(!rx.shared.warn_due(), "the next one inside 10 s is not");
    }

    #[test]
    fn a_closed_queue_says_so() {
        let (tx, rx, _) = queue(DEFAULT_QUEUE_MAX_BYTES, None);
        drop(rx);
        assert!(tx.try_send(connect()).is_err());
    }

    #[test]
    fn the_budget_comes_from_the_environment_as_plain_bytes() {
        assert_eq!(
            SinkQueueConfig::from_env_value(None),
            SinkQueueConfig::default()
        );
        assert_eq!(
            SinkQueueConfig::from_env_value(Some(" 1048576 ")).max_bytes,
            1_048_576
        );
        assert_eq!(
            SinkQueueConfig::from_env_value(Some("128Mi")),
            SinkQueueConfig::default(),
            "unparsable falls back (with a WARN)"
        );
        assert_eq!(SinkQueueConfig::from_env_value(Some("0")).max_bytes, 0);
    }

    /// The refusal bookkeeping under real contention: six reader threads
    /// against a draining receiver. Every refused record must come out as gap
    /// evidence exactly once, and the counters must return to zero.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_refusals_are_all_reported() {
        let (tx, mut rx, metrics) = queue(4 * unit(), None);
        let drainer = tokio::spawn(async move {
            let (mut records, mut gap_records) = (0usize, 0usize);
            while let Some(received) = rx.recv().await {
                match received {
                    Received::Records(r) => records += r.len(),
                    Received::Gaps(g) => {
                        gap_records += g.iter().map(|g| g.dropped_records).sum::<usize>()
                    }
                }
            }
            (records, gap_records, rx)
        });

        let threads: Vec<_> = (0..6)
            .map(|_| {
                let tx = tx.clone();
                std::thread::spawn(move || {
                    let (mut admitted, mut refused) = (0usize, 0usize);
                    for _ in 0..10_000 {
                        match tx.try_send(connect()) {
                            Ok(Admission::Admitted) => admitted += 1,
                            Ok(Admission::Refused) => refused += 1,
                            other => panic!("unexpected {other:?}"),
                        }
                    }
                    (admitted, refused)
                })
            })
            .collect();
        drop(tx);
        let (mut admitted, mut refused) = (0, 0);
        for thread in threads {
            let (a, r) = thread.join().expect("sender thread");
            admitted += a;
            refused += r;
        }
        let (records, gap_records, rx) = drainer.await.expect("drainer");

        assert!(refused > 0, "precondition: real contention");
        assert_eq!(records, admitted);
        assert_eq!(gap_records, refused, "every refusal reported exactly once");
        assert_eq!(dropped(&metrics, "tcp_connect"), refused as u64);
        assert!(rx.shared.lost().reports.is_empty(), "nothing stranded");
        assert_eq!(rx.queued_bytes(), 0);
        assert_eq!(rx.queued_messages(), 0);
        assert_eq!(metrics.sink_queue_bytes.get(), 0);
        assert_eq!(metrics.sink_queue_messages.get(), 0);
    }
}

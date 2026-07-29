use std::collections::VecDeque;

use false_protocol::{Occurrence, Severity};

use crate::{EvidenceBatch, EvidenceRecord, HookKind, ProbeMetadata, ProducerMetadata, SinkError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetryBufferConfig {
    pub max_records: usize,
    pub max_batches: usize,
    pub max_age_ms: u64,
    pub max_bytes: usize,
}

impl Default for RetryBufferConfig {
    fn default() -> Self {
        // Memory-sane baseline: the buffer holds evidence in RAM while a sink is
        // unavailable and sheds oldest (with gap evidence) past these bounds, so
        // they cap the process's memory under a downstream outage. The old
        // 1_000_000-record default was ~GBs — it OOMKilled the DaemonSet before
        // the cap ever engaged. ~100k records is a few hundred MB; size to the
        // deployment via `from_env`.
        Self {
            max_records: 100_000,
            max_batches: 2_048,
            max_age_ms: 300_000,
            // Records alone don't bound memory: 100k records at 1-3KB each is
            // 100-300MB — enough to OOM a 512Mi pod whose baseline is ~260Mi.
            // (Exactly the observed cascade: a Vartio outage fills the buffer,
            // the DaemonSet OOMs, 28-30 restarts per pod over 4 days.) The
            // byte budget is the binding constraint; the record cap remains as
            // a secondary guard for many-tiny-record shapes.
            max_bytes: 128 * 1024 * 1024,
        }
    }
}

impl RetryBufferConfig {
    /// Bounds from `JALKI_RETRY_MAX_{RECORDS,BATCHES,AGE_MS,BYTES}`, each falling back
    /// to the memory-sane default. These bound the daemon's memory while a
    /// downstream sink (e.g. Vartio) is unavailable — set them to the pod's
    /// memory limit so a transient outage sheds gap evidence instead of OOMing.
    pub fn from_env() -> Self {
        let d = Self::default();
        Self {
            max_records: env_parse("JALKI_RETRY_MAX_RECORDS", d.max_records),
            max_batches: env_parse("JALKI_RETRY_MAX_BATCHES", d.max_batches),
            max_age_ms: env_parse("JALKI_RETRY_MAX_AGE_MS", d.max_age_ms),
            max_bytes: env_parse("JALKI_RETRY_MAX_BYTES", d.max_bytes),
        }
    }
}

fn env_parse<T: std::str::FromStr>(key: &str, default: T) -> T {
    std::env::var(key)
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(default)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetryBackoffConfig {
    /// Ceiling for the first retry after a failure.
    pub base_ms: u64,
    /// Ceiling the doubling stops at.
    pub max_ms: u64,
}

impl Default for RetryBackoffConfig {
    fn default() -> Self {
        // 250ms first, doubling to a 30s ceiling: fast enough that a blip costs
        // no visible delivery latency, slow enough that a struggling sink is not
        // hammered. At the cap a single agent sends at most ~4 attempts/min.
        Self {
            base_ms: 250,
            max_ms: 30_000,
        }
    }
}

impl RetryBackoffConfig {
    /// `JALKI_RETRY_BACKOFF_{BASE_MS,MAX_MS}`, each falling back to the default.
    pub fn from_env() -> Self {
        let d = Self::default();
        Self {
            base_ms: env_parse("JALKI_RETRY_BACKOFF_BASE_MS", d.base_ms),
            max_ms: env_parse("JALKI_RETRY_BACKOFF_MAX_MS", d.max_ms),
        }
        .normalized()
    }

    /// A zero base would make the retry timer a busy loop, and a max below the
    /// base would make the "cap" tighten rather than widen the schedule. Both
    /// are operator typos rather than intentions, so clamp instead of trusting.
    fn normalized(self) -> Self {
        let base_ms = self.base_ms.max(1);
        Self {
            base_ms,
            max_ms: self.max_ms.max(base_ms),
        }
    }
}

/// Retry schedule for a sink that is refusing work: exponential, jittered, and
/// reset by success (jalki #39).
///
/// Before this, retries were driven only by the arrival of new evidence — so a
/// busy node hammered a struggling sink once per drain cycle, while a **quiet
/// node never retried at all** and its buffered evidence sat until some
/// unrelated event happened to arrive. Both halves are fixed by making the
/// cadence a property of the failure rather than of the traffic.
///
/// **Equal jitter**, not full jitter: the delay is `ceiling/2 + rand(0,
/// ceiling/2)`, so it keeps the herd-breaking property while retaining a hard
/// lower bound. That bound is the point — "attempt rate is bounded by the
/// backoff cap" is only provable if the draw cannot come back near zero, and a
/// DaemonSet means every node's agent is otherwise reconnecting to the same
/// Vartio at the same instant after an outage.
#[derive(Debug, Clone)]
pub struct RetryBackoff {
    config: RetryBackoffConfig,
    attempt: u32,
    jitter: Jitter,
}

impl RetryBackoff {
    pub fn new(config: RetryBackoffConfig) -> Self {
        Self {
            config: config.normalized(),
            attempt: 0,
            jitter: Jitter::new(),
        }
    }

    pub fn from_env() -> Self {
        Self::new(RetryBackoffConfig::from_env())
    }

    /// Consecutive failures since the last success. 0 means the next delay is
    /// the first one.
    pub fn attempt(&self) -> u32 {
        self.attempt
    }

    /// The un-jittered ceiling the next delay is drawn under: `base * 2^attempt`
    /// clamped to `max_ms`. Deterministic, so schedules can be asserted exactly.
    ///
    /// Saturating, not shifting: `base_ms.checked_shl(n)` looks like the obvious
    /// spelling and is wrong, because it only returns `None` when *n* exceeds
    /// the width — the value itself still wraps. `250u64.checked_shl(63)` is
    /// `Some(0)`, which would collapse the ceiling to zero and turn the retry
    /// timer into a busy loop after ~63 consecutive failures (about half an hour
    /// at the default cap — well inside a real outage).
    pub fn ceiling_ms(&self) -> u64 {
        1u64.checked_shl(self.attempt)
            .map(|factor| self.config.base_ms.saturating_mul(factor))
            .unwrap_or(u64::MAX)
            .min(self.config.max_ms)
    }

    /// Draw the next delay and count the failure.
    pub fn next_delay_ms(&mut self) -> u64 {
        let ceiling = self.ceiling_ms();
        self.attempt = self.attempt.saturating_add(1);
        let half = ceiling / 2;
        half + self.jitter.below(ceiling - half + 1)
    }

    /// A delivery succeeded: the next failure starts from `base_ms` again.
    pub fn reset(&mut self) {
        self.attempt = 0;
    }
}

/// Jitter without pulling in `rand`: a `RandomState` is seeded per process from
/// the OS, so hashing a counter under it gives a stream that differs between
/// pods — which is the whole point, since a synchronized DaemonSet is exactly
/// the herd being broken up.
#[derive(Debug, Clone)]
struct Jitter {
    state: std::collections::hash_map::RandomState,
    counter: u64,
}

impl Jitter {
    fn new() -> Self {
        Self {
            state: std::collections::hash_map::RandomState::new(),
            counter: 0,
        }
    }

    /// Uniform-ish draw in `[0, bound)`. `bound` is never 0 at the call site.
    fn below(&mut self, bound: u64) -> u64 {
        use std::hash::{BuildHasher, Hasher};
        self.counter = self.counter.wrapping_add(1);
        let mut hasher = self.state.build_hasher();
        hasher.write_u64(self.counter);
        hasher.finish() % bound.max(1)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GapReport {
    pub cause: String,
    pub dropped_records: usize,
    pub gap_start_ns: u64,
    pub gap_end_ns: u64,
}

impl GapReport {
    pub fn merge(&mut self, other: Self) {
        if self.cause != other.cause {
            self.cause = "multiple".into();
        }
        self.dropped_records = self.dropped_records.saturating_add(other.dropped_records);
        self.gap_start_ns = self.gap_start_ns.min(other.gap_start_ns);
        self.gap_end_ns = self.gap_end_ns.max(other.gap_end_ns);
    }

    pub fn into_batch(self, producer: ProducerMetadata) -> EvidenceBatch {
        let mut occ = Occurrence::new("jalki/agent", "jalki.agent.gap")
            .severity(Severity::Warning)
            .in_cluster(producer.cluster.clone());
        occ.labels.insert("cause".into(), self.cause);
        occ.labels
            .insert("dropped_records".into(), self.dropped_records.to_string());
        occ.labels
            .insert("gap_start_ns".into(), self.gap_start_ns.to_string());
        occ.labels
            .insert("gap_end_ns".into(), self.gap_end_ns.to_string());

        EvidenceBatch::new(
            producer,
            vec![EvidenceRecord {
                observed_at_ns: self.gap_end_ns,
                pid: 0,
                cgroup_id: 0,
                probe: ProbeMetadata {
                    probe_id: "jalki_agent".into(),
                    probe_version: "1".into(),
                    probe_family: "agent".into(),
                    hook_kind: HookKind::Fentry,
                    kernel_function: "jalki_agent_gap".into(),
                },
                occurrence: occ,
                binding: None,
            }],
        )
    }
}

#[derive(Debug, Clone)]
struct BufferedBatch {
    batch: EvidenceBatch,
    enqueued_at_ms: u64,
    approx_bytes: usize,
}

#[derive(Debug, Clone)]
pub struct RetryBuffer {
    config: RetryBufferConfig,
    batches: VecDeque<BufferedBatch>,
    records: usize,
    bytes: usize,
}

impl RetryBuffer {
    pub fn new(config: RetryBufferConfig) -> Self {
        Self {
            config,
            batches: VecDeque::new(),
            records: 0,
            bytes: 0,
        }
    }

    pub fn len_batches(&self) -> usize {
        self.batches.len()
    }

    pub fn len_records(&self) -> usize {
        self.records
    }

    pub fn len_bytes(&self) -> usize {
        self.bytes
    }

    pub fn is_empty(&self) -> bool {
        self.batches.is_empty()
    }

    pub fn enqueue(&mut self, batch: EvidenceBatch, now_ms: u64) -> Vec<GapReport> {
        let mut gaps = Vec::new();
        let approx_bytes = batch.approx_bytes();
        self.records += batch.len();
        self.bytes += approx_bytes;
        self.batches.push_back(BufferedBatch {
            batch,
            enqueued_at_ms: now_ms,
            approx_bytes,
        });

        while self.records > self.config.max_records
            || self.batches.len() > self.config.max_batches
            || self.bytes > self.config.max_bytes
        {
            if let Some(dropped) = self.pop_front() {
                gaps.push(gap_for_batch("retry_buffer_overflow", &dropped.batch));
            } else {
                break;
            }
        }

        gaps
    }

    pub fn drop_expired(&mut self, now_ms: u64) -> Vec<GapReport> {
        let mut gaps = Vec::new();
        loop {
            let expired = self
                .batches
                .front()
                .map(|b| now_ms.saturating_sub(b.enqueued_at_ms) > self.config.max_age_ms)
                .unwrap_or(false);
            if !expired {
                break;
            }
            if let Some(dropped) = self.pop_front() {
                gaps.push(gap_for_batch("retry_buffer_expired", &dropped.batch));
            }
        }
        gaps
    }

    pub fn front(&self) -> Option<&EvidenceBatch> {
        self.batches.front().map(|b| &b.batch)
    }

    pub fn pop_delivered(&mut self) -> Option<EvidenceBatch> {
        self.pop_front().map(|b| b.batch)
    }

    pub fn should_retry(error: &SinkError) -> bool {
        matches!(
            error,
            SinkError::Unavailable { .. }
                | SinkError::Timeout { .. }
                | SinkError::Backpressure { .. }
        )
    }

    fn pop_front(&mut self) -> Option<BufferedBatch> {
        let batch = self.batches.pop_front()?;
        self.records = self.records.saturating_sub(batch.batch.len());
        self.bytes = self.bytes.saturating_sub(batch.approx_bytes);
        Some(batch)
    }
}

fn gap_for_batch(cause: &str, batch: &EvidenceBatch) -> GapReport {
    GapReport {
        cause: cause.into(),
        dropped_records: batch.len(),
        gap_start_ns: batch.observed_at_min,
        gap_end_ns: batch.observed_at_max,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BindingProvenance, RuntimeBinding};
    fn producer() -> ProducerMetadata {
        ProducerMetadata::new("prod", "node-1", "6.17.0")
    }

    fn record(observed_at_ns: u64) -> EvidenceRecord {
        EvidenceRecord {
            observed_at_ns,
            pid: 0,
            cgroup_id: 0,
            probe: ProbeMetadata {
                probe_id: "tcp_connect".into(),
                probe_version: "1".into(),
                probe_family: "tcp".into(),
                hook_kind: HookKind::Fexit,
                kernel_function: "tcp_connect".into(),
            },
            occurrence: Occurrence::new("jalki/test", "kernel.test"),
            binding: Some(RuntimeBinding::Bound {
                container_id: "container-1".into(),
                pod_uid: Some("pod-1".into()),
                pod_name: Some("runner-1".into()),
                namespace: Some("default".into()),
                service_account: None,
                provenance: BindingProvenance::Observed,
            }),
        }
    }

    fn batch(times: &[u64]) -> EvidenceBatch {
        EvidenceBatch::new(producer(), times.iter().copied().map(record).collect())
    }

    #[test]
    fn retry_buffer_drops_oldest_and_emits_gap_on_overflow() {
        let mut buffer = RetryBuffer::new(RetryBufferConfig {
            max_records: 2,
            max_batches: 8,
            max_age_ms: 600_000,
            max_bytes: usize::MAX,
        });

        assert!(buffer.enqueue(batch(&[10, 20]), 0).is_empty());
        let gaps = buffer.enqueue(batch(&[30]), 1);

        assert_eq!(buffer.len_records(), 1);
        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0].cause, "retry_buffer_overflow");
        assert_eq!(gaps[0].dropped_records, 2);
        assert_eq!(gaps[0].gap_start_ns, 10);
        assert_eq!(gaps[0].gap_end_ns, 20);
    }

    #[test]
    fn retry_buffer_drops_expired_batches() {
        let mut buffer = RetryBuffer::new(RetryBufferConfig {
            max_records: 10,
            max_batches: 8,
            max_age_ms: 100,
            max_bytes: usize::MAX,
        });

        assert!(buffer.enqueue(batch(&[10]), 0).is_empty());
        assert!(buffer.drop_expired(100).is_empty());
        let gaps = buffer.drop_expired(101);

        assert!(buffer.is_empty());
        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0].cause, "retry_buffer_expired");
    }

    #[test]
    fn retry_policy_only_retries_transient_sink_errors() {
        assert!(RetryBuffer::should_retry(&SinkError::Backpressure {
            sink: "pipeline".into(),
            message: "slow".into(),
        }));
        assert!(RetryBuffer::should_retry(&SinkError::Unavailable {
            sink: "pipeline".into(),
            message: "down".into(),
        }));
        assert!(!RetryBuffer::should_retry(&SinkError::Unauthorized {
            sink: "pipeline".into(),
            message: "bad token".into(),
        }));
    }

    #[test]
    fn gap_batch_projects_to_plane_b_without_runtime_binding() {
        let gap = GapReport {
            cause: "retry_buffer_overflow".into(),
            dropped_records: 3,
            gap_start_ns: 10,
            gap_end_ns: 20,
        };

        let mut occurrences = gap.into_batch(producer()).into_plane_b_occurrences();
        let occ = occurrences.pop().unwrap();

        assert_eq!(occ.occurrence_type.as_str(), "jalki.agent.gap");
        assert_eq!(occ.severity, Severity::Info);
        assert_eq!(
            occ.labels.get("dropped_records").map(String::as_str),
            Some("3")
        );
    }

    #[test]
    fn retry_buffer_drops_oldest_on_byte_overflow() {
        // One record's estimate exceeds the tiny byte budget, so each newly
        // enqueued batch evicts the previous one — records/batches caps never
        // engage. This is the binding constraint for large-payload shapes.
        let mut buffer = RetryBuffer::new(RetryBufferConfig {
            max_records: 1_000,
            max_batches: 1_000,
            max_age_ms: 600_000,
            max_bytes: 1,
        });

        assert_eq!(
            buffer.enqueue(batch(&[10]), 0).len(),
            1,
            "over budget immediately"
        );
        assert!(buffer.is_empty());

        let gaps = buffer.enqueue(batch(&[20, 30]), 1);
        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0].cause, "retry_buffer_overflow");
        assert_eq!(gaps[0].dropped_records, 2);
        assert_eq!(buffer.len_bytes(), 0);
    }

    #[test]
    fn byte_accounting_tracks_enqueue_and_delivery() {
        let mut buffer = RetryBuffer::new(RetryBufferConfig::default());

        assert_eq!(buffer.len_bytes(), 0);
        buffer.enqueue(batch(&[10]), 0);
        let after_one = buffer.len_bytes();
        assert!(after_one > 0, "estimate must be non-zero");

        buffer.enqueue(batch(&[20]), 1);
        assert!(buffer.len_bytes() > after_one);

        buffer.pop_delivered();
        buffer.pop_delivered();
        assert_eq!(buffer.len_bytes(), 0, "delivery returns the budget");
    }

    #[test]
    fn gap_reports_merge_without_growing_the_retry_buffer() {
        let mut pending = GapReport {
            cause: "retry_buffer_overflow".into(),
            dropped_records: 2,
            gap_start_ns: 20,
            gap_end_ns: 30,
        };
        pending.merge(GapReport {
            cause: "retry_buffer_expired".into(),
            dropped_records: 3,
            gap_start_ns: 10,
            gap_end_ns: 40,
        });

        assert_eq!(pending.cause, "multiple");
        assert_eq!(pending.dropped_records, 5);
        assert_eq!(pending.gap_start_ns, 10);
        assert_eq!(pending.gap_end_ns, 40);
    }

    #[test]
    fn from_env_reads_byte_budget() {
        let key = "JALKI_RETRY_MAX_BYTES";
        // SAFETY: single-threaded test-local env mutation, restored below.
        unsafe { std::env::set_var(key, "4096") };
        assert_eq!(RetryBufferConfig::from_env().max_bytes, 4096);
        unsafe { std::env::remove_var(key) };
        assert_eq!(
            RetryBufferConfig::from_env().max_bytes,
            RetryBufferConfig::default().max_bytes
        );
    }

    #[test]
    fn default_config_is_memory_sane() {
        // Guards against a reintroduced GB-scale default (the OOM footgun).
        let d = RetryBufferConfig::default();
        assert!(
            d.max_records <= 200_000,
            "default too large: {}",
            d.max_records
        );
        assert!(
            d.max_bytes <= 256 * 1024 * 1024,
            "default byte budget too large for a 512Mi pod: {}",
            d.max_bytes
        );
    }

    #[test]
    fn from_env_reads_overrides_and_falls_back() {
        // Serialized via a unique key to avoid cross-test env races.
        let key = "JALKI_RETRY_MAX_RECORDS";
        // SAFETY: single-threaded test-local env mutation, restored below.
        unsafe { std::env::set_var(key, "1234") };
        assert_eq!(RetryBufferConfig::from_env().max_records, 1234);
        unsafe { std::env::set_var(key, "not-a-number") };
        assert_eq!(
            RetryBufferConfig::from_env().max_records,
            RetryBufferConfig::default().max_records,
            "garbage falls back to the default"
        );
        unsafe { std::env::remove_var(key) };
    }

    // ── RetryBackoff (jalki #39) ────────────────────────────────────────────

    fn backoff(base_ms: u64, max_ms: u64) -> RetryBackoff {
        RetryBackoff::new(RetryBackoffConfig { base_ms, max_ms })
    }

    #[test]
    fn ceiling_doubles_per_consecutive_failure_then_caps() {
        let mut b = backoff(250, 2_000);
        let mut ceilings = Vec::new();
        for _ in 0..6 {
            ceilings.push(b.ceiling_ms());
            b.next_delay_ms();
        }
        assert_eq!(
            ceilings,
            vec![250, 500, 1_000, 2_000, 2_000, 2_000],
            "exponential up to the cap, flat at it"
        );
    }

    #[test]
    fn every_delay_sits_inside_its_own_ceiling() {
        let mut b = backoff(250, 30_000);
        for _ in 0..64 {
            let ceiling = b.ceiling_ms();
            let delay = b.next_delay_ms();
            assert!(
                delay >= ceiling / 2 && delay <= ceiling,
                "equal jitter keeps the draw in [ceiling/2, ceiling]: \
                 got {delay} for ceiling {ceiling}"
            );
        }
    }

    #[test]
    fn the_cap_bounds_the_attempt_rate() {
        // The acceptance criterion this exists for: under a sustained outage the
        // RPC rate is a function of the cap, not of how much evidence arrives.
        let mut b = backoff(250, 30_000);
        for _ in 0..16 {
            b.next_delay_ms();
        }
        let steady: Vec<u64> = (0..32).map(|_| b.next_delay_ms()).collect();
        let attempts_per_minute = 60_000 / steady.iter().copied().max().unwrap();
        assert!(
            steady.iter().all(|d| *d >= 15_000),
            "a saturated backoff can never dip below half the cap: {steady:?}"
        );
        assert!(
            attempts_per_minute <= 2,
            "at the 30s cap a single agent stays at ~2 attempts/min, got {attempts_per_minute}"
        );
    }

    #[test]
    fn jitter_actually_varies_the_delay() {
        // Without this the schedule is a fixed ladder and every pod in the
        // DaemonSet reconnects to Vartio on the same tick.
        let mut b = backoff(1_000, 1_000);
        let draws: std::collections::BTreeSet<u64> = (0..32).map(|_| b.next_delay_ms()).collect();
        assert!(
            draws.len() > 1,
            "a constant delay is not jitter; drew {draws:?}"
        );
    }

    #[test]
    fn success_restarts_the_ladder() {
        let mut b = backoff(250, 30_000);
        for _ in 0..8 {
            b.next_delay_ms();
        }
        assert!(b.ceiling_ms() > 250, "precondition: the ladder climbed");

        b.reset();

        assert_eq!(b.attempt(), 0);
        assert_eq!(
            b.ceiling_ms(),
            250,
            "a delivered batch means the next outage starts from the bottom again"
        );
    }

    #[test]
    fn a_long_outage_never_collapses_the_ceiling() {
        // The ladder must be monotone: once it reaches the cap it stays there
        // for as long as the sink is down. Asserting only `delay <= cap` is not
        // enough — a ceiling that overflowed to 0 satisfies that too, and then
        // the retry timer fires immediately and spins. That is exactly what a
        // `base_ms.checked_shl(attempt)` implementation does at attempt 63,
        // roughly half an hour into an outage at the default cap.
        let mut b = backoff(250, 30_000);
        for attempt in 0..256 {
            let ceiling = b.ceiling_ms();
            assert!(
                ceiling >= 250,
                "ceiling collapsed below base at attempt {attempt}: {ceiling}"
            );
            let delay = b.next_delay_ms();
            assert!(
                (125..=30_000).contains(&delay),
                "delay escaped its bounds at attempt {attempt}: {delay}"
            );
        }
        assert_eq!(b.ceiling_ms(), 30_000, "and it is still pinned at the cap");
    }

    #[test]
    fn nonsense_config_is_clamped_rather_than_trusted() {
        let zero_base = backoff(0, 30_000);
        assert!(
            zero_base.ceiling_ms() >= 1,
            "a zero base would make the retry timer a busy loop"
        );

        let inverted = backoff(5_000, 100);
        assert_eq!(
            inverted.ceiling_ms(),
            5_000,
            "a max below the base must not tighten the schedule below its first step"
        );
    }
}

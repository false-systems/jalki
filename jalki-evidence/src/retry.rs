use std::collections::VecDeque;

use false_protocol::{Occurrence, Severity};

use crate::{
    EvidenceBatch, EvidenceClass, EvidenceRecord, HookKind, ProbeMetadata, ProducerMetadata,
    SinkError,
};

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

#[derive(Debug, Clone, PartialEq)]
pub struct DrainPaceConfig {
    pub max_bytes_per_sec: u64,
    pub max_batches_per_sec: u64,
    /// Rate multiplier applied on each backpressure signal (multiplicative
    /// decrease).
    pub backpressure_decrease: f64,
    /// Fraction of the full rate recovered per delivered batch (additive
    /// increase). Deliberately far smaller than the decrease: AIMD converges
    /// because it gives up rate fast and takes it back slowly.
    ///
    /// Per *batch* rather than per second, which makes recovery self-scaling:
    /// a heavily throttled pacer is sending fewer batches, so it also takes
    /// longer in wall-clock terms to earn its rate back.
    pub recovery_increase: f64,
    /// Floor, so a sustained-backpressure sink still makes progress instead of
    /// halving toward zero and stalling the drain forever.
    pub min_scale: f64,
}

impl Default for DrainPaceConfig {
    fn default() -> Self {
        // 2MiB/s drains a full 64Mi retry buffer in ~32s: fast enough that
        // recovery is not an outage of its own, slow enough that it is a ramp
        // rather than the burst that took Ahti from 0.24Gi to its 4Gi limit in
        // 90 minutes on 2026-07-28. Well above jälki's steady-state rate, so
        // ordinary delivery is untouched — this bounds *recovery*, not traffic.
        Self {
            max_bytes_per_sec: 2 * 1024 * 1024,
            max_batches_per_sec: 20,
            backpressure_decrease: 0.5,
            // 0.002 ⇒ ~375 batches from a halved-twice rate back to full.
            // At the 20 batch/s cap that is ~19s at full speed and ~75s while
            // still throttled. An earlier 0.02 recovered in ~2s on a busy
            // drain, which made the backpressure signal decorative.
            recovery_increase: 0.002,
            min_scale: 0.05,
        }
    }
}

impl DrainPaceConfig {
    /// `JALKI_DRAIN_MAX_{BYTES,BATCHES}_PER_SEC`, each falling back to the
    /// default.
    pub fn from_env() -> Self {
        let d = Self::default();
        Self {
            max_bytes_per_sec: env_parse("JALKI_DRAIN_MAX_BYTES_PER_SEC", d.max_bytes_per_sec)
                .max(1),
            max_batches_per_sec: env_parse(
                "JALKI_DRAIN_MAX_BATCHES_PER_SEC",
                d.max_batches_per_sec,
            )
            .max(1),
            ..d
        }
    }
}

/// What the pacer says about sending one more batch right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pace {
    Send,
    /// Nothing may be sent for this long.
    Wait {
        ms: u64,
    },
}

/// Rate limit for draining an outage backlog (jalki #40).
///
/// The flush loop used to hand the buffer to the sink as fast as it would take
/// it. That is the amplification step of the Jul 28-29 incident: Vartio came
/// back at 21:34, jälki's ~13h backlog drained at full speed, and Ahti went from
/// 0.24Gi to its 4Gi OOM limit inside 90 minutes. The outage was survivable;
/// the recovery was not. Vartio ADR-0009 contract 4: any client holding an
/// outage backlog drains it rate-bounded.
///
/// Two token buckets (bytes and batches) scaled by an AIMD factor, so a
/// `RESOURCE_EXHAUSTED`/`Backpressure` reply means *slow down* rather than
/// merely *try again shortly*. Client-side only — explicitly not a broker tier.
#[derive(Debug, Clone)]
pub struct DrainPacer {
    config: DrainPaceConfig,
    scale: f64,
    byte_tokens: f64,
    batch_tokens: f64,
    last_refill_ms: Option<u64>,
}

impl DrainPacer {
    pub fn new(config: DrainPaceConfig) -> Self {
        Self {
            byte_tokens: config.max_bytes_per_sec as f64,
            batch_tokens: config.max_batches_per_sec as f64,
            config,
            scale: 1.0,
            last_refill_ms: None,
        }
    }

    pub fn from_env() -> Self {
        Self::new(DrainPaceConfig::from_env())
    }

    /// Current fraction of the configured rate, after any backpressure.
    pub fn scale(&self) -> f64 {
        self.scale
    }

    fn rates(&self) -> (f64, f64) {
        (
            self.config.max_bytes_per_sec as f64 * self.scale,
            self.config.max_batches_per_sec as f64 * self.scale,
        )
    }

    fn refill(&mut self, now_ms: u64) {
        let last = self.last_refill_ms.unwrap_or(now_ms);
        let elapsed = now_ms.saturating_sub(last) as f64 / 1000.0;
        self.last_refill_ms = Some(now_ms);
        let (byte_rate, batch_rate) = self.rates();
        // One second of burst: enough that a healthy sink sees no added latency
        // per batch, not so much that a long idle period banks a flood.
        self.byte_tokens = (self.byte_tokens + elapsed * byte_rate).min(byte_rate.max(1.0));
        self.batch_tokens = (self.batch_tokens + elapsed * batch_rate).min(batch_rate.max(1.0));
    }

    /// May a batch of `bytes` go now? Consumes the tokens when it says `Send`.
    pub fn poll(&mut self, now_ms: u64, bytes: usize) -> Pace {
        self.refill(now_ms);
        let (byte_rate, batch_rate) = self.rates();

        // A batch larger than a whole second of budget can never accumulate
        // enough tokens. Let it through on a full bucket rather than deadlock
        // the drain — the bucket goes negative and the next batch simply waits
        // longer, so the average rate still holds.
        let bytes = bytes as f64;
        let affordable = bytes <= byte_rate.max(1.0);

        if self.batch_tokens >= 1.0 && (self.byte_tokens >= bytes || !affordable) {
            self.batch_tokens -= 1.0;
            self.byte_tokens -= bytes;
            return Pace::Send;
        }

        let byte_wait = if self.byte_tokens >= bytes {
            0.0
        } else {
            (bytes - self.byte_tokens) / byte_rate.max(f64::MIN_POSITIVE)
        };
        let batch_wait = if self.batch_tokens >= 1.0 {
            0.0
        } else {
            (1.0 - self.batch_tokens) / batch_rate.max(f64::MIN_POSITIVE)
        };
        let wait = byte_wait.max(batch_wait) * 1000.0;
        Pace::Wait {
            ms: wait.ceil().clamp(1.0, 60_000.0) as u64,
        }
    }

    /// The sink said it is overloaded: give up rate immediately.
    pub fn on_backpressure(&mut self) {
        self.scale = (self.scale * self.config.backpressure_decrease).max(self.config.min_scale);
    }

    /// A batch landed: take rate back, slowly.
    pub fn on_delivered(&mut self) {
        self.scale = (self.scale + self.config.recovery_increase).min(1.0);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GapReport {
    pub cause: String,
    pub dropped_records: usize,
    pub gap_start_ns: u64,
    pub gap_end_ns: u64,
    /// Records lost per class. "We dropped 4,000 tcp.close events" and "we
    /// dropped 3 execs" are the same number of bytes and completely different
    /// incidents — coverage downstream cannot tell them apart from a total.
    pub dropped_reliability: usize,
    pub dropped_attribution: usize,
}

impl GapReport {
    pub fn merge(&mut self, other: Self) {
        if self.cause != other.cause {
            self.cause = "multiple".into();
        }
        self.dropped_records = self.dropped_records.saturating_add(other.dropped_records);
        self.dropped_reliability = self
            .dropped_reliability
            .saturating_add(other.dropped_reliability);
        self.dropped_attribution = self
            .dropped_attribution
            .saturating_add(other.dropped_attribution);
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
        occ.labels.insert(
            "dropped_reliability".into(),
            self.dropped_reliability.to_string(),
        );
        occ.labels.insert(
            "dropped_attribution".into(),
            self.dropped_attribution.to_string(),
        );
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
    /// Class of every record in this batch. Batches are split by class on the
    /// way in, so this is exact rather than a summary — a mixed batch
    /// classified by its strongest member would make almost everything
    /// attribution and the shed order would do nothing.
    class: EvidenceClass,
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

        // Split by class before buffering. A drain cycle routinely mixes an
        // exec with tcp.close chatter, and a mixed batch can only be shed as a
        // unit — so without the split, shedding either drops attribution
        // evidence to get at telemetry, or (classifying conservatively) never
        // sheds anything early at all.
        for part in split_by_class(batch) {
            let approx_bytes = part.batch.approx_bytes();
            self.records += part.batch.len();
            self.bytes += approx_bytes;
            self.batches.push_back(BufferedBatch {
                batch: part.batch,
                enqueued_at_ms: now_ms,
                approx_bytes,
                class: part.class,
            });
        }

        while self.records > self.config.max_records
            || self.batches.len() > self.config.max_batches
            || self.bytes > self.config.max_bytes
        {
            match self.shed_one() {
                Some(dropped) => gaps.push(gap_for_shed(
                    "retry_buffer_overflow",
                    dropped.class,
                    &dropped.batch,
                )),
                None => break,
            }
        }

        gaps
    }

    /// Shed until at most `target_bytes` remain, reliability evidence first.
    ///
    /// The buffer's own bounds are a *budget*; this is a *reaction*. They are
    /// different questions: the budget asks "is this queue bigger than we
    /// planned for", and 64Mi of queue is fine right up until the rest of the
    /// process needs the room. Under real memory pressure the queue has to give
    /// ground even when it is inside its budget, because the alternative is the
    /// kernel taking the whole process and the entire backlog with it — and
    /// that loss produces no gap evidence at all (jalki #33).
    pub fn shed_to(&mut self, target_bytes: usize) -> Vec<GapReport> {
        let mut gaps = Vec::new();
        while self.bytes > target_bytes {
            match self.shed_one() {
                Some(dropped) => gaps.push(gap_for_shed(
                    "memory_pressure",
                    dropped.class,
                    &dropped.batch,
                )),
                None => break,
            }
        }
        gaps
    }

    /// Give up the least valuable batch: oldest reliability evidence if any is
    /// held, oldest attribution evidence only when nothing else remains
    /// (vartio ADR-0009 contract 5).
    ///
    /// Delivery order is untouched — `front()` is still strictly FIFO, because
    /// head-of-line ordering is what makes a drain reconstructible. Only the
    /// *shed* choice is class-aware.
    fn shed_one(&mut self) -> Option<BufferedBatch> {
        let victim = self
            .batches
            .iter()
            .position(|b| b.class == EvidenceClass::Reliability)
            .or(if self.batches.is_empty() {
                None
            } else {
                Some(0)
            })?;
        let dropped = self.batches.remove(victim)?;
        // Saturating, matching `pop_front` — the two are the only paths that
        // decrement, and they must not disagree about what happens if the
        // accounting ever drifts.
        self.records = self.records.saturating_sub(dropped.batch.len());
        self.bytes = self.bytes.saturating_sub(dropped.approx_bytes);
        Some(dropped)
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
                gaps.push(gap_for_shed(
                    "retry_buffer_expired",
                    dropped.class,
                    &dropped.batch,
                ));
            }
        }
        gaps
    }

    /// How long the oldest queued batch has been waiting, or `None` when the
    /// buffer is empty.
    ///
    /// Depth alone does not say how bad an outage is: a hundred batches queued
    /// a second ago is a blip, one batch queued twenty minutes ago is a sink
    /// that is gone. Age is what readiness and alerting key off (jalki #42).
    pub fn oldest_age_ms(&self, now_ms: u64) -> Option<u64> {
        self.batches
            .front()
            .map(|b| now_ms.saturating_sub(b.enqueued_at_ms))
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

/// Gap report for a batch lost whole — overflow, expiry, or a terminal sink
/// error. Public because the runtime needs the same construction for terminal
/// drops, and a second copy there is precisely how the per-class counts would
/// go stale (it already had one).
pub fn gap_for_batch(cause: &str, batch: &EvidenceBatch) -> GapReport {
    let mut reliability = 0;
    let mut attribution = 0;
    for record in &batch.records {
        match record.evidence_class() {
            EvidenceClass::Reliability => reliability += 1,
            EvidenceClass::Attribution => attribution += 1,
        }
    }
    GapReport {
        cause: cause.into(),
        dropped_records: batch.len(),
        gap_start_ns: batch.observed_at_min,
        gap_end_ns: batch.observed_at_max,
        dropped_reliability: reliability,
        dropped_attribution: attribution,
    }
}

/// Gap for a batch the buffer chose to shed; the class is already known, so it
/// does not need re-deriving per record.
fn gap_for_shed(cause: &str, class: EvidenceClass, batch: &EvidenceBatch) -> GapReport {
    let n = batch.len();
    GapReport {
        cause: cause.into(),
        dropped_records: n,
        gap_start_ns: batch.observed_at_min,
        gap_end_ns: batch.observed_at_max,
        dropped_reliability: match class {
            EvidenceClass::Reliability => n,
            EvidenceClass::Attribution => 0,
        },
        dropped_attribution: match class {
            EvidenceClass::Attribution => n,
            EvidenceClass::Reliability => 0,
        },
    }
}

struct ClassPart {
    batch: EvidenceBatch,
    class: EvidenceClass,
}

/// Partition a batch into per-class batches, preserving record order and
/// dropping empty parts. Idempotency keys are per-record
/// (`source:cluster:node:<occurrence id>`), so splitting is safe for dedup —
/// redelivery of either part is still a no-op downstream.
fn split_by_class(batch: EvidenceBatch) -> Vec<ClassPart> {
    let producer = batch.producer.clone();
    let mut reliability = Vec::new();
    let mut attribution = Vec::new();
    for record in batch.records {
        match record.evidence_class() {
            EvidenceClass::Reliability => reliability.push(record),
            EvidenceClass::Attribution => attribution.push(record),
        }
    }

    let mut parts = Vec::with_capacity(2);
    for (records, class) in [
        (reliability, EvidenceClass::Reliability),
        (attribution, EvidenceClass::Attribution),
    ] {
        if !records.is_empty() {
            parts.push(ClassPart {
                batch: EvidenceBatch::new(producer.clone(), records),
                class,
            });
        }
    }
    parts
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
                owner_kind: None,
                owner_name: None,
                owner_uid: None,
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
            dropped_reliability: 0,
            dropped_attribution: 0,
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
            dropped_reliability: 0,
            dropped_attribution: 0,
        };
        pending.merge(GapReport {
            cause: "retry_buffer_expired".into(),
            dropped_records: 3,
            gap_start_ns: 10,
            gap_end_ns: 40,
            dropped_reliability: 0,
            dropped_attribution: 0,
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

    // ── DrainPacer (jalki #40) ──────────────────────────────────────────────

    fn pacer(bytes_per_sec: u64, batches_per_sec: u64) -> DrainPacer {
        DrainPacer::new(DrainPaceConfig {
            max_bytes_per_sec: bytes_per_sec,
            max_batches_per_sec: batches_per_sec,
            ..DrainPaceConfig::default()
        })
    }

    /// Simulate a drain and report how many bytes actually went out per second
    /// of simulated time, honouring every wait the pacer asks for.
    fn drain_bytes_over(p: &mut DrainPacer, batch_bytes: usize, duration_ms: u64) -> u64 {
        let (mut now, mut sent) = (0u64, 0u64);
        while now < duration_ms {
            match p.poll(now, batch_bytes) {
                Pace::Send => {
                    sent += batch_bytes as u64;
                    p.on_delivered();
                }
                Pace::Wait { ms } => now += ms,
            }
        }
        sent
    }

    #[test]
    fn a_backlog_drains_at_the_configured_rate_not_line_rate() {
        // The incident in one assertion: unbounded, this sends everything at
        // once; bounded, ten seconds of drain is ten seconds of budget.
        let mut p = pacer(64 * 1024, 1_000);
        let sent = drain_bytes_over(&mut p, 4 * 1024, 10_000);
        let per_sec = sent / 10;
        assert!(
            per_sec <= 64 * 1024 + 64 * 1024 / 10,
            "drain exceeded the byte cap: {per_sec}/s against a 65536/s budget"
        );
        assert!(
            per_sec > 32 * 1024,
            "the cap must not throttle to a crawl: {per_sec}/s"
        );
    }

    #[test]
    fn the_batch_cap_bounds_rate_independently_of_size() {
        // Tiny batches cannot evade the limiter by staying under the byte cap.
        let mut p = pacer(u64::MAX / 2, 10);
        let (mut now, mut sends) = (0u64, 0);
        while now < 5_000 {
            match p.poll(now, 1) {
                Pace::Send => sends += 1,
                Pace::Wait { ms } => now += ms,
            }
        }
        // 10 from the initial full bucket (one second of burst, by design)
        // plus one per 100ms for 5s.
        assert!(
            (55..=61).contains(&sends),
            "expected ~60 = 10 burst + 50 paced over 5s at 10/s, got {sends}"
        );
    }

    #[test]
    fn backpressure_halves_the_rate_and_delivery_wins_it_back_slowly() {
        let mut p = pacer(1_000_000, 1_000);
        assert_eq!(p.scale(), 1.0);

        p.on_backpressure();
        assert!(
            (p.scale() - 0.5).abs() < f64::EPSILON,
            "RESOURCE_EXHAUSTED must halve the rate, got {}",
            p.scale()
        );

        p.on_backpressure();
        assert!(p.scale() < 0.3, "sustained backpressure keeps backing off");

        // Additive increase: recovery is deliberately much slower than the
        // decrease, which is what makes AIMD converge instead of oscillate.
        let after_backoff = p.scale();
        p.on_delivered();
        let gained = p.scale() - after_backoff;
        assert!(
            gained > 0.0 && gained < 0.1,
            "recovery must be gradual: +{gained}"
        );
    }

    #[test]
    fn backing_off_actually_slows_the_observed_drain() {
        // scale() moving is not the claim; throughput moving is.
        let full = drain_bytes_over(&mut pacer(64 * 1024, 1_000), 4 * 1024, 5_000);

        let mut throttled = pacer(64 * 1024, 1_000);
        throttled.on_backpressure();
        throttled.on_backpressure();
        let slowed = drain_bytes_over(&mut throttled, 4 * 1024, 5_000);

        assert!(
            slowed < full / 2,
            "a backed-off pacer must move measurably less data: {slowed} vs {full}. \
             If this regresses, suspect recovery_increase — recovering per batch \
             too quickly makes the backpressure signal decorative."
        );
    }

    #[test]
    fn the_rate_floor_keeps_a_hammered_drain_moving() {
        let mut p = pacer(64 * 1024, 1_000);
        for _ in 0..64 {
            p.on_backpressure();
        }
        assert!(p.scale() >= 0.05, "scale collapsed to {}", p.scale());
        assert!(
            drain_bytes_over(&mut p, 1_024, 30_000) > 0,
            "even a fully backed-off drain must make progress, or the backlog \
             never leaves and ages into gap evidence instead"
        );
    }

    #[test]
    fn an_oversized_batch_is_not_a_deadlock() {
        // A batch bigger than one second of budget can never accumulate enough
        // tokens. It must still go out — the bucket goes negative and the next
        // batch waits proportionally longer, so the average rate holds.
        let mut p = pacer(1_024, 1_000);
        let mut sent = false;
        let mut now = 0u64;
        for _ in 0..100 {
            match p.poll(now, 64 * 1024) {
                Pace::Send => {
                    sent = true;
                    break;
                }
                Pace::Wait { ms } => now += ms,
            }
        }
        assert!(sent, "an oversized batch stalled the drain forever");
    }

    #[test]
    fn a_healthy_sink_sees_no_added_latency_for_the_first_batch() {
        // The pacer bounds *recovery*, and must not tax ordinary delivery.
        let mut p = pacer(2 * 1024 * 1024, 20);
        assert_eq!(p.poll(0, 4 * 1024), Pace::Send);
    }

    // ── evidence-class-aware shedding (jalki #41) ───────────────────────────
    //
    // ADR-0009 contract 5: when a bounded buffer must drop, reliability
    // evidence sheds before attribution evidence, and the producer encodes the
    // order — that is this crate.

    fn classed_record(observed_at_ns: u64, occurrence_type: &str) -> EvidenceRecord {
        let mut r = record(observed_at_ns);
        r.occurrence = Occurrence::new("jalki/test", occurrence_type);
        r
    }

    fn exec(at: u64) -> EvidenceRecord {
        classed_record(at, "kernel.process.exec")
    }

    fn chatter(at: u64) -> EvidenceRecord {
        classed_record(at, "kernel.tcp.close")
    }

    fn classes_held(buffer: &RetryBuffer) -> (usize, usize) {
        let mut reliability = 0;
        let mut attribution = 0;
        for b in &buffer.batches {
            match b.class {
                EvidenceClass::Reliability => reliability += b.batch.len(),
                EvidenceClass::Attribution => attribution += b.batch.len(),
            }
        }
        (reliability, attribution)
    }

    #[test]
    fn classification_matches_vartios_importer() {
        // These four lists are the contract with Importer.Jalki. If Vartio
        // moves a type between them and this is not updated, jälki sheds
        // evidence Vartio treats as attribution-critical and the only symptom
        // is a chain that never forms.
        for t in [
            "kernel.process.exec",
            "kernel.tcp.connect",
            "kernel.file.open",
            "kernel.file.open_attempt",
        ] {
            assert_eq!(EvidenceClass::of(t), EvidenceClass::Attribution, "{t}");
        }
        for t in ["kernel.tcp.close", "kernel.tcp.retransmit"] {
            assert_eq!(EvidenceClass::of(t), EvidenceClass::Reliability, "{t}");
        }
        assert_eq!(
            EvidenceClass::of("kernel.something.new"),
            EvidenceClass::Attribution,
            "an unclassified type must be kept, not silently shed"
        );
    }

    #[test]
    fn a_mixed_batch_is_split_so_shedding_can_be_precise() {
        let mut buffer = RetryBuffer::new(RetryBufferConfig::default());
        buffer.enqueue(
            EvidenceBatch::new(producer(), vec![exec(1), chatter(2), chatter(3)]),
            0,
        );
        assert_eq!(
            buffer.len_batches(),
            2,
            "one batch in, one per class out — a mixed batch can only be shed \
             as a unit, so without the split the order cannot be honoured"
        );
        assert_eq!(classes_held(&buffer), (2, 1));
    }

    #[test]
    fn attribution_evidence_survives_while_any_telemetry_remains() {
        // The acceptance property. Overflow by batch count, feeding execs first
        // so a purely oldest-first policy would shed exactly the wrong ones.
        let mut buffer = RetryBuffer::new(RetryBufferConfig {
            max_batches: 4,
            ..RetryBufferConfig::default()
        });

        for i in 0..4 {
            buffer.enqueue(EvidenceBatch::new(producer(), vec![exec(i)]), 0);
        }
        for i in 0..8 {
            buffer.enqueue(EvidenceBatch::new(producer(), vec![chatter(100 + i)]), 0);
        }

        let (reliability, attribution) = classes_held(&buffer);
        assert_eq!(
            attribution, 4,
            "every exec must still be held: they were the oldest, and oldest-first \
             alone would have shed all four to make room for tcp.close chatter"
        );
        assert_eq!(reliability + attribution, 4, "the bound still holds");
    }

    #[test]
    fn attribution_evidence_sheds_only_when_nothing_else_is_left() {
        let mut buffer = RetryBuffer::new(RetryBufferConfig {
            max_batches: 2,
            ..RetryBufferConfig::default()
        });
        for i in 0..6 {
            buffer.enqueue(EvidenceBatch::new(producer(), vec![exec(i)]), 0);
        }
        assert_eq!(
            classes_held(&buffer),
            (0, 2),
            "with only attribution evidence held, the buffer still respects its \
             bound — the order is a preference, not an exemption"
        );
    }

    #[test]
    fn every_shed_still_produces_a_gap_and_names_the_class() {
        let mut buffer = RetryBuffer::new(RetryBufferConfig {
            max_batches: 1,
            ..RetryBufferConfig::default()
        });
        buffer.enqueue(
            EvidenceBatch::new(producer(), vec![chatter(1), chatter(2)]),
            0,
        );
        let gaps = buffer.enqueue(EvidenceBatch::new(producer(), vec![exec(3)]), 0);

        assert_eq!(gaps.len(), 1, "a shed is never silent");
        let gap = &gaps[0];
        assert_eq!(gap.cause, "retry_buffer_overflow");
        assert_eq!(gap.dropped_records, 2);
        assert_eq!(
            (gap.dropped_reliability, gap.dropped_attribution),
            (2, 0),
            "\"we dropped 4,000 tcp.close events\" and \"we dropped 3 execs\" are \
             the same byte count and completely different incidents"
        );
    }

    #[test]
    fn the_gap_occurrence_carries_the_class_split() {
        let gap = GapReport {
            cause: "retry_buffer_overflow".into(),
            dropped_records: 7,
            gap_start_ns: 1,
            gap_end_ns: 9,
            dropped_reliability: 5,
            dropped_attribution: 2,
        };
        let batch = gap.into_batch(producer());
        let labels = &batch.records[0].occurrence.labels;
        assert_eq!(
            labels.get("dropped_reliability").map(String::as_str),
            Some("5")
        );
        assert_eq!(
            labels.get("dropped_attribution").map(String::as_str),
            Some("2")
        );
    }

    #[test]
    fn delivery_order_stays_fifo_regardless_of_class() {
        // Only the *shed* choice is class-aware. Reordering delivery would make
        // a drain unreconstructible downstream, and #39/#40 both depend on
        // head-of-line order.
        let mut buffer = RetryBuffer::new(RetryBufferConfig::default());
        buffer.enqueue(EvidenceBatch::new(producer(), vec![chatter(1)]), 0);
        buffer.enqueue(EvidenceBatch::new(producer(), vec![exec(2)]), 0);
        assert_eq!(
            buffer.front().map(|b| b.records[0].observed_at_ns),
            Some(1),
            "the oldest batch is delivered first even though it is the one that \
             would be shed first"
        );
    }

    #[test]
    fn memory_pressure_sheds_telemetry_first() {
        // Same order as an overflow shed — pressure is a different trigger, not
        // a different policy. Losing an exec to save tcp.close chatter would be
        // the wrong trade under any trigger.
        let mut buffer = RetryBuffer::new(RetryBufferConfig::default());
        for i in 0..4 {
            buffer.enqueue(EvidenceBatch::new(producer(), vec![exec(i)]), 0);
        }
        for i in 0..4 {
            buffer.enqueue(EvidenceBatch::new(producer(), vec![chatter(100 + i)]), 0);
        }
        let full = buffer.len_bytes();

        // A modest reduction, satisfiable from telemetry alone.
        let gaps = buffer.shed_to(full * 9 / 10);

        assert!(!gaps.is_empty(), "shedding under pressure is never silent");
        assert!(buffer.len_bytes() <= full * 9 / 10);
        assert!(
            gaps.iter().all(|g| g.cause == "memory_pressure"),
            "the cause distinguishes this from an overflow, which is a different \
             operational story"
        );
        assert_eq!(
            gaps.iter().map(|g| g.dropped_attribution).sum::<usize>(),
            0,
            "attribution evidence must survive while telemetry is still there to give"
        );
    }

    #[test]
    fn deep_pressure_reaches_attribution_but_only_after_all_telemetry() {
        // The order is a preference, not an exemption: if the process is about
        // to be OOM-killed, keeping an exec is not worth losing every record.
        let mut buffer = RetryBuffer::new(RetryBufferConfig::default());
        for i in 0..4 {
            buffer.enqueue(EvidenceBatch::new(producer(), vec![exec(i)]), 0);
        }
        for i in 0..4 {
            buffer.enqueue(EvidenceBatch::new(producer(), vec![chatter(100 + i)]), 0);
        }

        let gaps = buffer.shed_to(0);
        assert!(buffer.is_empty());

        // Everything went, so ordering is the claim: no attribution record was
        // shed before the last reliability one.
        let first_attribution = gaps.iter().position(|g| g.dropped_attribution > 0);
        let last_reliability = gaps.iter().rposition(|g| g.dropped_reliability > 0);
        assert!(
            matches!((first_attribution, last_reliability), (Some(a), Some(r)) if a > r),
            "attribution evidence was shed before telemetry ran out: {gaps:#?}"
        );
    }

    #[test]
    fn shedding_to_zero_empties_the_buffer_and_reports_all_of_it() {
        let mut buffer = RetryBuffer::new(RetryBufferConfig::default());
        for i in 0..5 {
            buffer.enqueue(EvidenceBatch::new(producer(), vec![exec(i)]), 0);
        }
        let gaps = buffer.shed_to(0);
        assert!(buffer.is_empty());
        assert_eq!(
            gaps.iter().map(|g| g.dropped_records).sum::<usize>(),
            5,
            "every dropped record is accounted for, even when everything goes"
        );
    }

    #[test]
    fn shedding_below_the_current_size_is_a_no_op() {
        let mut buffer = RetryBuffer::new(RetryBufferConfig::default());
        buffer.enqueue(EvidenceBatch::new(producer(), vec![exec(1)]), 0);
        let before = buffer.len_bytes();
        assert!(buffer.shed_to(before + 1).is_empty());
        assert_eq!(buffer.len_bytes(), before);
    }
}

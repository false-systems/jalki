use std::collections::VecDeque;

use false_protocol::{Occurrence, Severity};

use crate::{EvidenceBatch, EvidenceRecord, HookKind, ProbeMetadata, ProducerMetadata, SinkError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetryBufferConfig {
    pub max_records: usize,
    pub max_batches: usize,
    pub max_age_ms: u64,
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
        }
    }
}

impl RetryBufferConfig {
    /// Bounds from `JALKI_RETRY_MAX_{RECORDS,BATCHES,AGE_MS}`, each falling back
    /// to the memory-sane default. These bound the daemon's memory while a
    /// downstream sink (e.g. Vartio) is unavailable — set them to the pod's
    /// memory limit so a transient outage sheds gap evidence instead of OOMing.
    pub fn from_env() -> Self {
        let d = Self::default();
        Self {
            max_records: env_parse("JALKI_RETRY_MAX_RECORDS", d.max_records),
            max_batches: env_parse("JALKI_RETRY_MAX_BATCHES", d.max_batches),
            max_age_ms: env_parse("JALKI_RETRY_MAX_AGE_MS", d.max_age_ms),
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
pub struct GapReport {
    pub cause: String,
    pub dropped_records: usize,
    pub gap_start_ns: u64,
    pub gap_end_ns: u64,
}

impl GapReport {
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
}

#[derive(Debug, Clone)]
pub struct RetryBuffer {
    config: RetryBufferConfig,
    batches: VecDeque<BufferedBatch>,
    records: usize,
}

impl RetryBuffer {
    pub fn new(config: RetryBufferConfig) -> Self {
        Self {
            config,
            batches: VecDeque::new(),
            records: 0,
        }
    }

    pub fn len_batches(&self) -> usize {
        self.batches.len()
    }

    pub fn len_records(&self) -> usize {
        self.records
    }

    pub fn is_empty(&self) -> bool {
        self.batches.is_empty()
    }

    pub fn enqueue(&mut self, batch: EvidenceBatch, now_ms: u64) -> Vec<GapReport> {
        let mut gaps = Vec::new();
        self.records += batch.len();
        self.batches.push_back(BufferedBatch {
            batch,
            enqueued_at_ms: now_ms,
        });

        while self.records > self.config.max_records || self.batches.len() > self.config.max_batches
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
    use std::collections::BTreeMap;

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
                namespace: Some("default".into()),
                service_account: None,
                labels: BTreeMap::new(),
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
    fn default_config_is_memory_sane() {
        // Guards against a reintroduced GB-scale default (the OOM footgun).
        let d = RetryBufferConfig::default();
        assert!(
            d.max_records <= 200_000,
            "default too large: {}",
            d.max_records
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
}

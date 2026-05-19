//! Evidence records, batches, and the producer/probe metadata model.
//!
//! ADR-0001 D5/D6: every record preserves observed-time separately from Ahti's
//! ingest-time, and carries producer / probe / kernel / node / cluster metadata.
//! Metadata is split by change cadence: fields constant for an agent process live
//! on the [`EvidenceBatch`]; fields constant per probe, plus the observed time,
//! live on each [`EvidenceRecord`]. A sink projects both onto the final record.

use false_protocol::Occurrence;

/// How a probe attaches to the kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookKind {
    Fentry,
    Fexit,
    Lsm,
}

impl HookKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            HookKind::Fentry => "fentry",
            HookKind::Fexit => "fexit",
            HookKind::Lsm => "lsm",
        }
    }
}

/// Metadata constant for the lifetime of an agent process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProducerMetadata {
    pub producer: String,
    pub producer_version: String,
    pub cluster: String,
    pub node_id: String,
    pub kernel_release: String,
}

impl ProducerMetadata {
    /// `producer` defaults to `"jalki"` and `producer_version` to the workspace
    /// version; the caller supplies the node/cluster/kernel identity. Fields are
    /// public, so the daemon may override the defaults when it knows better.
    pub fn new(
        cluster: impl Into<String>,
        node_id: impl Into<String>,
        kernel_release: impl Into<String>,
    ) -> Self {
        Self {
            producer: "jalki".into(),
            producer_version: env!("CARGO_PKG_VERSION").into(),
            cluster: cluster.into(),
            node_id: node_id.into(),
            kernel_release: kernel_release.into(),
        }
    }
}

/// Metadata constant for a given probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeMetadata {
    pub probe_id: String,
    pub probe_version: String,
    pub probe_family: String,
    pub hook_kind: HookKind,
    pub kernel_function: String,
}

/// A single normalized record, stamped with observed-time and probe metadata.
///
/// `observed_at_ns` is the kernel's monotonic timestamp (CLOCK_BOOTTIME-domain),
/// preserved verbatim. Wall-clock correlation and Ahti's ingest-time
/// (`Occurrence.received_at`) are added downstream; jälki never sets ingest-time.
#[derive(Debug, Clone)]
pub struct EvidenceRecord {
    pub observed_at_ns: u64,
    pub probe: ProbeMetadata,
    pub occurrence: Occurrence,
}

impl EvidenceRecord {
    /// Project into a single `Occurrence` carrying the full ADR-0001 D6 metadata
    /// set, with the agent-constant fields supplied by the batch's
    /// [`ProducerMetadata`].
    ///
    /// This is the contract a sink MUST go through: it folds the batch- and
    /// record-level metadata into the record so a downstream consumer that only
    /// sees the `Occurrence` still has producer / probe / kernel / node identity
    /// and the observed time. Forwarding `record.occurrence` directly would drop
    /// all of it. Until the Ahti record kinds land, these ride in `labels`; the
    /// sink projection (a later slice) maps them onto envelope/payload fields.
    /// `cluster` is omitted — it is already a first-class `Occurrence` field.
    pub fn into_occurrence_with_metadata(self, producer: &ProducerMetadata) -> Occurrence {
        let mut occ = self.occurrence;
        let labels = &mut occ.labels;
        labels.insert("producer".into(), producer.producer.clone());
        labels.insert("producer_version".into(), producer.producer_version.clone());
        labels.insert("node_id".into(), producer.node_id.clone());
        labels.insert("kernel_release".into(), producer.kernel_release.clone());
        labels.insert("probe_id".into(), self.probe.probe_id);
        labels.insert("probe_version".into(), self.probe.probe_version);
        labels.insert("probe_family".into(), self.probe.probe_family);
        labels.insert("hook_kind".into(), self.probe.hook_kind.as_str().into());
        labels.insert("kernel_function".into(), self.probe.kernel_function);
        labels.insert("observed_at_ns".into(), self.observed_at_ns.to_string());
        occ
    }
}

/// The records produced by normalizing one `KernelEvent`.
///
/// A `Vec` so a single event can yield multiple records (an occurrence plus,
/// later, `entity_version` / `relationship_claim`). The TCP probes currently
/// yield exactly one.
#[derive(Debug, Clone)]
pub struct NormalizedEvidence {
    pub records: Vec<EvidenceRecord>,
}

impl NormalizedEvidence {
    pub fn single(record: EvidenceRecord) -> Self {
        Self {
            records: vec![record],
        }
    }
}

/// A batch of records ready to hand to a sink.
#[derive(Debug, Clone)]
pub struct EvidenceBatch {
    pub batch_id: String,
    pub producer: ProducerMetadata,
    pub observed_at_min: u64,
    pub observed_at_max: u64,
    pub records: Vec<EvidenceRecord>,
}

impl EvidenceBatch {
    /// Build a batch, deriving the observed-time window from the records and
    /// generating a fresh batch id. An empty batch gets a zero window.
    pub fn new(producer: ProducerMetadata, records: Vec<EvidenceRecord>) -> Self {
        let (observed_at_min, observed_at_max) = records
            .iter()
            .map(|r| r.observed_at_ns)
            .fold(None, |acc: Option<(u64, u64)>, ts| match acc {
                None => Some((ts, ts)),
                Some((lo, hi)) => Some((lo.min(ts), hi.max(ts))),
            })
            .unwrap_or((0, 0));

        Self {
            batch_id: false_protocol::new_id().to_string(),
            producer,
            observed_at_min,
            observed_at_max,
            records,
        }
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Project every record into an `Occurrence` carrying full metadata, applying
    /// this batch's [`ProducerMetadata`] to each. Consumes the batch — this is the
    /// intended hand-off into a sink.
    pub fn into_occurrences(self) -> Vec<Occurrence> {
        let producer = self.producer;
        self.records
            .into_iter()
            .map(|r| r.into_occurrence_with_metadata(&producer))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(observed_at_ns: u64) -> EvidenceRecord {
        EvidenceRecord {
            observed_at_ns,
            probe: ProbeMetadata {
                probe_id: "tcp_retransmit".into(),
                probe_version: "1".into(),
                probe_family: "tcp".into(),
                hook_kind: HookKind::Fentry,
                kernel_function: "tcp_retransmit_skb".into(),
            },
            occurrence: Occurrence::new("jalki/test", "kernel.test"),
        }
    }

    #[test]
    fn producer_metadata_defaults_producer_and_version() {
        let p = ProducerMetadata::new("prod", "node-1", "6.17.0");
        assert_eq!(p.producer, "jalki");
        assert!(!p.producer_version.is_empty());
        assert_eq!(p.cluster, "prod");
        assert_eq!(p.node_id, "node-1");
        assert_eq!(p.kernel_release, "6.17.0");
    }

    #[test]
    fn batch_derives_observed_window_and_id() {
        let batch = EvidenceBatch::new(
            ProducerMetadata::new("prod", "node-1", "6.17.0"),
            vec![record(50), record(10), record(30)],
        );
        assert_eq!(batch.observed_at_min, 10);
        assert_eq!(batch.observed_at_max, 50);
        assert_eq!(batch.len(), 3);
        assert!(!batch.batch_id.is_empty());
    }

    #[test]
    fn record_carries_probe_metadata() {
        let r = record(7);
        assert_eq!(r.probe.probe_id, "tcp_retransmit");
        assert_eq!(r.probe.hook_kind, HookKind::Fentry);
        assert_eq!(r.probe.hook_kind.as_str(), "fentry");
        assert_eq!(r.observed_at_ns, 7);
    }

    #[test]
    fn empty_batch_has_zero_window() {
        let batch = EvidenceBatch::new(ProducerMetadata::new("c", "n", "k"), vec![]);
        assert!(batch.is_empty());
        assert_eq!((batch.observed_at_min, batch.observed_at_max), (0, 0));
    }

    #[test]
    fn projection_carries_full_d6_metadata() {
        let batch =
            EvidenceBatch::new(ProducerMetadata::new("prod", "node-1", "6.17.0"), vec![record(42)]);
        let occ = batch.into_occurrences().pop().unwrap();
        let get = |k: &str| occ.labels.get(k).map(String::as_str);

        // producer-constant fields, supplied by the batch
        assert_eq!(get("producer"), Some("jalki"));
        assert!(occ.labels.contains_key("producer_version"));
        assert_eq!(get("node_id"), Some("node-1"));
        assert_eq!(get("kernel_release"), Some("6.17.0"));
        // probe-constant fields, supplied by the record
        assert_eq!(get("probe_id"), Some("tcp_retransmit"));
        assert!(occ.labels.contains_key("probe_version"));
        assert_eq!(get("probe_family"), Some("tcp"));
        assert_eq!(get("hook_kind"), Some("fentry"));
        assert_eq!(get("kernel_function"), Some("tcp_retransmit_skb"));
        // observed time travels with the record
        assert_eq!(get("observed_at_ns"), Some("42"));
    }
}

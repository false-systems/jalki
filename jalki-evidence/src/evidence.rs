//! Evidence records, batches, and the producer/probe metadata model.
//!
//! ADR-0001 D5/D6: every record preserves observed-time separately from Ahti's
//! ingest-time, and carries producer / probe / kernel / node / cluster metadata.
//! Metadata is split by change cadence: fields constant for an agent process live
//! on the [`EvidenceBatch`]; fields constant per probe, plus the observed time,
//! live on each [`EvidenceRecord`]. A sink projects both onto the final record.

use std::collections::BTreeMap;

use false_protocol::{Occurrence, Severity};

/// Version of jälki's emitted-occurrence schema — the cross-team wire contract
/// with Polku and Vartio. Carried on every occurrence as the `schema_version`
/// label so a real shape change is a negotiated break, not a silent one. New
/// fields ride "present-but-zero" without a bump; only an incompatible change
/// bumps this. (See the "present-but-zero, never silently absent" doctrine.)
pub const SCHEMA_VERSION: &str = "1";

/// How a probe attaches to the kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookKind {
    Fentry,
    Fexit,
    Tracepoint,
    Lsm,
}

impl HookKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            HookKind::Fentry => "fentry",
            HookKind::Fexit => "fexit",
            HookKind::Tracepoint => "tracepoint",
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

/// Binding from a kernel event to the runtime object that caused it.
///
/// Plane B requires a strong binding (`pod_uid` or `container_id`) before an
/// event is forwarded to Vartio. Plane A may still retain unbound events for
/// local debugging.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeBinding {
    Bound {
        container_id: String,
        pod_uid: Option<String>,
        namespace: Option<String>,
        service_account: Option<String>,
        labels: BTreeMap<String, String>,
        provenance: BindingProvenance,
    },
    Unbound {
        reason: UnboundReason,
    },
}

impl RuntimeBinding {
    pub fn strong_binding(&self) -> bool {
        match self {
            RuntimeBinding::Bound {
                container_id,
                pod_uid,
                ..
            } => !container_id.is_empty() || pod_uid.as_deref().is_some_and(|v| !v.is_empty()),
            RuntimeBinding::Unbound { .. } => false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingProvenance {
    Observed,
    DerivedFromCache,
}

impl BindingProvenance {
    pub fn as_str(&self) -> &'static str {
        match self {
            BindingProvenance::Observed => "observed",
            BindingProvenance::DerivedFromCache => "derived",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum UnboundReason {
    HostProcess,
    CacheMiss,
    NoCgroup,
    Unknown,
}

impl UnboundReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            UnboundReason::HostProcess => "host_process",
            UnboundReason::CacheMiss => "cache_miss",
            UnboundReason::NoCgroup => "no_cgroup",
            UnboundReason::Unknown => "unknown",
        }
    }
}

/// A single normalized record, stamped with observed-time and probe metadata.
///
/// `observed_at_ns` is the kernel's monotonic timestamp (CLOCK_BOOTTIME-domain),
/// preserved verbatim. Wall-clock correlation and Ahti's ingest-time
/// (`Occurrence.received_at`) are added downstream; jälki never sets ingest-time.
#[derive(Debug, Clone)]
pub struct EvidenceRecord {
    pub observed_at_ns: u64,
    pub pid: u32,
    pub cgroup_id: u64,
    pub probe: ProbeMetadata,
    pub occurrence: Occurrence,
    pub binding: Option<RuntimeBinding>,
}

impl EvidenceRecord {
    pub fn with_runtime_binding(mut self, binding: RuntimeBinding) -> Self {
        self.binding = Some(binding);
        self
    }

    pub fn plane_b_drop_reason(&self) -> Option<UnboundReason> {
        if self.is_agent_record() {
            return None;
        }

        match self.binding.as_ref() {
            Some(binding) if binding.strong_binding() => None,
            Some(RuntimeBinding::Unbound { reason }) => Some(*reason),
            Some(RuntimeBinding::Bound { .. }) | None => Some(UnboundReason::Unknown),
        }
    }

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
    /// `cluster_id` is additive metadata; `Occurrence::cluster` remains the
    /// first-class cluster field for existing consumers. The two come from
    /// different sources — `cluster_id` from `ProducerMetadata` (the agent's
    /// cluster identity), `Occurrence::cluster` from the normalize-time cluster
    /// argument — so callers MUST source both from the same value (the daemon
    /// uses `Runtime.cluster` for both) to avoid divergence.
    pub fn into_occurrence_with_metadata(self, producer: &ProducerMetadata) -> Occurrence {
        let mut occ = self.occurrence;
        apply_runtime_binding(&mut occ, self.binding.as_ref());
        let labels = &mut occ.labels;
        labels.insert("producer".into(), producer.producer.clone());
        labels.insert("producer_version".into(), producer.producer_version.clone());
        labels.insert("cluster_id".into(), producer.cluster.clone());
        labels.insert("node_id".into(), producer.node_id.clone());
        labels.insert("kernel_release".into(), producer.kernel_release.clone());
        labels.insert("probe_id".into(), self.probe.probe_id);
        labels.insert("probe_version".into(), self.probe.probe_version);
        labels.insert("probe_family".into(), self.probe.probe_family);
        labels.insert("hook_kind".into(), self.probe.hook_kind.as_str().into());
        labels.insert("kernel_function".into(), self.probe.kernel_function);
        labels.insert("observed_at_ns".into(), self.observed_at_ns.to_string());
        labels.insert("schema_version".into(), SCHEMA_VERSION.into());
        occ
    }

    /// Project this record for the neutral Plane B path.
    ///
    /// Unlike Plane A, this projection refuses unbound evidence and strips local
    /// interpretation fields before the occurrence can be sent to Vartio.
    pub fn into_plane_b_occurrence(self, producer: &ProducerMetadata) -> Option<Occurrence> {
        if let Some(_reason) = self.plane_b_drop_reason() {
            return None;
        }

        let mut occ = self.into_occurrence_with_metadata(producer);
        neutralize_for_plane_b(&mut occ);
        Some(occ)
    }

    fn is_agent_record(&self) -> bool {
        self.occurrence
            .occurrence_type
            .as_str()
            .starts_with("jalki.agent.")
    }
}

fn apply_runtime_binding(occ: &mut Occurrence, binding: Option<&RuntimeBinding>) {
    match binding {
        Some(RuntimeBinding::Bound {
            container_id,
            pod_uid,
            namespace,
            service_account,
            labels,
            provenance,
        }) => {
            if !container_id.is_empty() {
                occ.labels
                    .insert("k8s_container_id".into(), container_id.clone());
                push_unique(
                    &mut occ.correlation_keys,
                    format!("k8s_container_id:{container_id}"),
                );
            }
            if let Some(pod_uid) = pod_uid.as_ref().filter(|v| !v.is_empty()) {
                occ.labels.insert("k8s_pod_uid".into(), pod_uid.clone());
                push_unique(&mut occ.correlation_keys, format!("k8s_pod_uid:{pod_uid}"));
            }
            if let Some(namespace) = namespace.as_ref().filter(|v| !v.is_empty()) {
                occ.namespace = Some(namespace.clone());
                occ.labels.insert("k8s_namespace".into(), namespace.clone());
                push_unique(
                    &mut occ.correlation_keys,
                    format!("k8s_namespace:{namespace}"),
                );
            }
            if let Some(service_account) = service_account.as_ref().filter(|v| !v.is_empty()) {
                occ.labels
                    .insert("k8s_service_account".into(), service_account.clone());
            }
            if let Some(run_id) = labels.get("actions.github.com/run-id") {
                occ.labels.insert("github_run_id".into(), run_id.clone());
                push_unique(&mut occ.correlation_keys, format!("github_run_id:{run_id}"));
            }
            occ.labels
                .insert("evidence_level".into(), provenance.as_str().into());
        }
        Some(RuntimeBinding::Unbound { reason }) => {
            occ.labels
                .insert("runtime_binding".into(), "unbound".into());
            occ.labels
                .insert("unbound_reason".into(), reason.as_str().into());
        }
        None => {}
    }
}

fn push_unique(values: &mut Vec<String>, value: String) {
    if !values.iter().any(|existing| existing == &value) {
        values.push(value);
    }
}

fn neutralize_for_plane_b(occ: &mut Occurrence) {
    occ.severity = Severity::Info;
    occ.error = None;
    occ.reasoning = None;
    occ.history = None;

    if let Some(network) = &occ.network_data {
        occ.labels
            .insert("resource_ref_kind".into(), "network_endpoint".into());
        occ.labels.insert(
            "resource_ref_id".into(),
            format!("{}:{}", network.dst_ip, network.dst_port),
        );
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

#[derive(Debug, Clone)]
pub struct PlaneBProjection {
    pub occurrences: Vec<Occurrence>,
    pub dropped_unbound: BTreeMap<UnboundReason, usize>,
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

    /// Project strongly bound, neutral Plane-B records only.
    pub fn into_plane_b_occurrences(self) -> Vec<Occurrence> {
        self.into_plane_b_projection().occurrences
    }

    pub fn into_plane_b_projection(self) -> PlaneBProjection {
        let producer = self.producer;
        let mut occurrences = Vec::new();
        let mut dropped_unbound = BTreeMap::new();

        for record in self.records {
            if let Some(reason) = record.plane_b_drop_reason() {
                *dropped_unbound.entry(reason).or_insert(0) += 1;
                continue;
            }
            if let Some(occurrence) = record.into_plane_b_occurrence(&producer) {
                occurrences.push(occurrence);
            }
        }

        PlaneBProjection {
            occurrences,
            dropped_unbound,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(observed_at_ns: u64) -> EvidenceRecord {
        EvidenceRecord {
            observed_at_ns,
            pid: 0,
            cgroup_id: 0,
            probe: ProbeMetadata {
                probe_id: "tcp_retransmit".into(),
                probe_version: "1".into(),
                probe_family: "tcp".into(),
                hook_kind: HookKind::Fentry,
                kernel_function: "tcp_retransmit_skb".into(),
            },
            occurrence: Occurrence::new("jalki/test", "kernel.test"),
            binding: None,
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
        let batch = EvidenceBatch::new(
            ProducerMetadata::new("prod", "node-1", "6.17.0"),
            vec![record(42)],
        );
        let occ = batch.into_occurrences().pop().unwrap();
        let get = |k: &str| occ.labels.get(k).map(String::as_str);

        // producer-constant fields, supplied by the batch
        assert_eq!(get("producer"), Some("jalki"));
        assert!(occ.labels.contains_key("producer_version"));
        assert_eq!(get("cluster_id"), Some("prod"));
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
        // schema version stamps every occurrence (the cross-team wire contract)
        assert_eq!(get("schema_version"), Some(SCHEMA_VERSION));
    }

    #[test]
    fn plane_b_projection_drops_unbound_records() {
        let batch = EvidenceBatch::new(
            ProducerMetadata::new("prod", "node-1", "6.17.0"),
            vec![record(42).with_runtime_binding(RuntimeBinding::Unbound {
                reason: UnboundReason::HostProcess,
            })],
        );

        assert!(batch.into_plane_b_occurrences().is_empty());
    }

    #[test]
    fn plane_b_projection_allows_agent_gap_without_binding() {
        let mut record = record(42);
        record.occurrence = Occurrence::new("jalki/agent", "jalki.agent.gap");

        let batch = EvidenceBatch::new(
            ProducerMetadata::new("prod", "node-1", "6.17.0"),
            vec![record],
        );
        let occ = batch.into_plane_b_occurrences().pop().unwrap();

        assert_eq!(occ.occurrence_type.as_str(), "jalki.agent.gap");
        assert_eq!(occ.severity, Severity::Info);
        assert!(occ.error.is_none());
    }

    #[test]
    fn plane_b_projection_adds_binding_and_strips_interpretation() {
        let mut labels = BTreeMap::new();
        labels.insert("actions.github.com/run-id".into(), "123456".into());
        let mut record = record(42).with_runtime_binding(RuntimeBinding::Bound {
            container_id: "container-1".into(),
            pod_uid: Some("pod-1".into()),
            namespace: Some("default".into()),
            service_account: Some("builder".into()),
            labels,
            provenance: BindingProvenance::Observed,
        });
        record.occurrence.severity = Severity::Critical;
        record.occurrence.error = Some(Default::default());

        let batch = EvidenceBatch::new(
            ProducerMetadata::new("prod", "node-1", "6.17.0"),
            vec![record],
        );
        let occ = batch.into_plane_b_occurrences().pop().unwrap();

        assert_eq!(occ.severity, Severity::Info);
        assert!(occ.error.is_none());
        assert_eq!(
            occ.labels.get("k8s_container_id").map(String::as_str),
            Some("container-1")
        );
        assert_eq!(
            occ.labels.get("k8s_pod_uid").map(String::as_str),
            Some("pod-1")
        );
        assert_eq!(
            occ.labels.get("github_run_id").map(String::as_str),
            Some("123456")
        );
        assert!(occ
            .correlation_keys
            .iter()
            .any(|key| key == "k8s_pod_uid:pod-1"));
    }
}

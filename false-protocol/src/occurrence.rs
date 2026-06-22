use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use ulid::Ulid;

use crate::blocks::*;
use crate::error::ProtocolError;
use crate::payloads::*;
use crate::types::*;

// === OccurrenceType ===

/// Hierarchical occurrence type: "domain.action" (e.g., "kernel.oom_kill").
///
/// Stored as a string for extensibility but has well-known constants.
/// Format: `^[a-z0-9]+\.[a-z0-9._]+$`
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct OccurrenceType(String);

impl OccurrenceType {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// Domain prefix (before the dot): "kernel" from "kernel.oom_kill"
    pub fn domain(&self) -> &str {
        self.0.split('.').next().unwrap_or("")
    }

    /// Action suffix (after the dot): "oom_kill" from "kernel.oom_kill"
    pub fn action(&self) -> &str {
        self.0.split_once('.').map_or("", |x| x.1)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Prefix-to-category mapping. Checked in order; first match wins.
/// Specific prefixes before general ones.
const CATEGORY_PREFIXES: &[(&str, OccurrenceCategory)] = &[
    ("kernel.oom", OccurrenceCategory::ResourceExhaustion),
    ("container.oom", OccurrenceCategory::ResourceExhaustion),
    (
        "node.memory_pressure",
        OccurrenceCategory::ResourceExhaustion,
    ),
    ("node.disk_pressure", OccurrenceCategory::ResourceExhaustion),
    ("node.cpu_pressure", OccurrenceCategory::ResourceExhaustion),
    ("pod.restart", OccurrenceCategory::Lifecycle),
    ("pod.scheduled", OccurrenceCategory::Lifecycle),
    ("pod.failed", OccurrenceCategory::Lifecycle),
    ("container.terminated", OccurrenceCategory::Lifecycle),
    ("container.started", OccurrenceCategory::Lifecycle),
    ("network.", OccurrenceCategory::Network),
    ("deployment.", OccurrenceCategory::ConfigChange),
    ("config.", OccurrenceCategory::ConfigChange),
    ("service.", OccurrenceCategory::ServiceDegradation),
    ("scheduling.", OccurrenceCategory::Scaling),
    ("node.not_ready", OccurrenceCategory::Scaling),
    ("hpa.", OccurrenceCategory::Scaling),
    ("security.", OccurrenceCategory::Security),
    ("policy.", OccurrenceCategory::Security),
    ("ahti.", OccurrenceCategory::SelfObservability),
];

impl OccurrenceType {
    /// Semantic category for this occurrence type.
    /// Uses prefix matching — new occurrence types from source tools
    /// get categorized automatically if they follow naming conventions.
    /// Returns None for types with no matching prefix.
    pub fn category(&self) -> Option<OccurrenceCategory> {
        let s = self.as_str();
        CATEGORY_PREFIXES
            .iter()
            .find(|(prefix, _)| s.starts_with(prefix))
            .map(|(_, cat)| *cat)
    }
}

// Well-known occurrence types
impl OccurrenceType {
    pub const KERNEL_OOM_KILL: &'static str = "kernel.oom_kill";
    pub const CONTAINER_TERMINATED: &'static str = "container.terminated";
    pub const CONTAINER_OOM_KILLED: &'static str = "container.oom_killed";
    pub const POD_RESTART: &'static str = "pod.restart";
    pub const POD_SCHEDULED: &'static str = "pod.scheduled";
    pub const POD_FAILED: &'static str = "pod.failed";
    pub const DEPLOYMENT_UPDATE: &'static str = "deployment.update";
    pub const DEPLOYMENT_ROLLBACK: &'static str = "deployment.rollback";
    pub const SERVICE_DISRUPTION: &'static str = "service.disruption";
    pub const SERVICE_ERROR: &'static str = "service.error";
    pub const SERVICE_TIMEOUT: &'static str = "service.timeout";
    pub const NETWORK_TIMEOUT: &'static str = "network.timeout";
    pub const NETWORK_LATENCY_SPIKE: &'static str = "network.latency_spike";
    pub const NODE_MEMORY_PRESSURE: &'static str = "node.memory_pressure";
    pub const NODE_DISK_PRESSURE: &'static str = "node.disk_pressure";
    pub const NODE_NOT_READY: &'static str = "node.not_ready";
    pub const CONFIG_CHANGED: &'static str = "config.changed";
    pub const SCHEDULING_FAILED: &'static str = "scheduling.failed";

    // Self-observability occurrence types
    pub const AHTI_INGEST_BACKPRESSURE: &'static str = "ahti.ingest.backpressure";
    pub const AHTI_ENRICHMENT_DEGRADED: &'static str = "ahti.enrichment.degraded";
    pub const AHTI_COMPACTION_STARTED: &'static str = "ahti.compaction.started";
    pub const AHTI_COMPACTION_COMPLETED: &'static str = "ahti.compaction.completed";
    pub const AHTI_EVICTION_COMPLETED: &'static str = "ahti.eviction.completed";
    pub const AHTI_LEARNING_PATTERN_DISCOVERED: &'static str = "ahti.learning.pattern_discovered";
    pub const AHTI_LEARNING_PHASE_TRANSITION: &'static str = "ahti.learning.phase_transition";
    pub const AHTI_QUERY_LATENCY_SPIKE: &'static str = "ahti.query.latency_spike";
    pub const AHTI_STORAGE_DISK_PRESSURE: &'static str = "ahti.storage.disk_pressure";
    pub const AHTI_CHECKPOINT_COMPLETED: &'static str = "ahti.checkpoint.completed";
}

// === Occurrence ===

/// The fundamental event type. All sources normalize to this.
///
/// Required fields: id, timestamp, source, occurrence_type, cluster.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Occurrence {
    pub id: Ulid,
    /// Producer-supplied event time. Advisory; causal ordering uses
    /// `received_at` when present.
    pub timestamp: DateTime<Utc>,
    /// Ingest moment set by Ahti at WAL append. Authoritative for causal ordering.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub received_at: Option<DateTime<Utc>>,
    pub source: String,

    #[serde(rename = "type")]
    pub occurrence_type: OccurrenceType,
    pub severity: Severity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome: Option<Outcome>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub correlation_keys: Vec<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<OccurrenceError>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reasoning: Option<OccurrenceReasoning>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub history: Option<OccurrenceHistory>,

    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub entity_ids: Vec<String>,

    pub cluster: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(skip_serializing_if = "HashMap::is_empty", default)]
    pub labels: HashMap<String, String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub span_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_span_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_us: Option<u64>,

    #[serde(default)]
    pub enrichment_state: EnrichmentState,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_data: Option<NetworkEventData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kernel_data: Option<KernelEventData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_data: Option<ContainerEventData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub k8s_data: Option<K8sEventData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_data: Option<ProcessEventData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scheduling_data: Option<SchedulingEventData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_data: Option<NodeEventData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_data: Option<ResourceEventData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub otel_data: Option<OtelEventData>,
}

// === Builder ===

impl Occurrence {
    /// Create a new Occurrence with required fields.
    /// Generates ULID, sets timestamp to now, defaults severity to Info.
    pub fn new(source: impl Into<String>, occurrence_type: impl Into<String>) -> Self {
        Self {
            id: Ulid::new(),
            timestamp: Utc::now(),
            received_at: None,
            source: source.into(),
            occurrence_type: OccurrenceType::new(occurrence_type),
            severity: Severity::Info,
            outcome: None,
            correlation_keys: Vec::new(),
            error: None,
            reasoning: None,
            history: None,
            entity_ids: Vec::new(),
            cluster: String::new(),
            namespace: None,
            labels: HashMap::new(),
            trace_id: None,
            span_id: None,
            parent_span_id: None,
            duration_us: None,
            enrichment_state: EnrichmentState::Raw,
            network_data: None,
            kernel_data: None,
            container_data: None,
            k8s_data: None,
            process_data: None,
            scheduling_data: None,
            node_data: None,
            resource_data: None,
            otel_data: None,
        }
    }

    /// Create a new Occurrence with an explicit timestamp (for deterministic testing).
    /// Uses `new_id_at` so the ULID embeds the given timestamp.
    /// Pre-epoch timestamps are clamped to epoch for ULID generation.
    pub fn new_at(
        source: impl Into<String>,
        occurrence_type: impl Into<String>,
        timestamp: DateTime<Utc>,
    ) -> Self {
        let millis = timestamp.timestamp_millis().max(0) as u64;
        let sys_time = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_millis(millis);
        Self {
            id: crate::new_id_at(sys_time),
            timestamp,
            ..Self::new(source, occurrence_type)
        }
    }

    pub fn severity(mut self, s: Severity) -> Self {
        self.severity = s;
        self
    }
    pub fn outcome(mut self, o: Outcome) -> Self {
        self.outcome = Some(o);
        self
    }
    pub fn in_cluster(mut self, c: impl Into<String>) -> Self {
        self.cluster = c.into();
        self
    }
    pub fn in_namespace(mut self, ns: impl Into<String>) -> Self {
        self.namespace = Some(ns.into());
        self
    }
    pub fn with_entities(mut self, ids: Vec<String>) -> Self {
        self.entity_ids = ids;
        self
    }
    /// Mark this occurrence as observed at `received_at`.
    pub fn with_received_at(mut self, received_at: DateTime<Utc>) -> Self {
        self.received_at = Some(received_at);
        self
    }
    pub fn with_error(mut self, e: OccurrenceError) -> Self {
        self.error = Some(e);
        self
    }
    pub fn with_reasoning(mut self, r: OccurrenceReasoning) -> Self {
        self.reasoning = Some(r);
        self
    }
    pub fn with_history(mut self, h: OccurrenceHistory) -> Self {
        self.history = Some(h);
        self
    }
    pub fn with_tracing(mut self, trace: String, span: String, parent: Option<String>) -> Self {
        self.trace_id = Some(trace);
        self.span_id = Some(span);
        self.parent_span_id = parent;
        self
    }

    /// Validate all invariants and return the Occurrence.
    pub fn build(self) -> Result<Self, ProtocolError> {
        self.validate()?;
        Ok(self)
    }
}

// === Validation ===

impl Occurrence {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.source.trim().is_empty() {
            return Err(ProtocolError::InvalidOccurrence(
                "source is required".into(),
            ));
        }
        if self.occurrence_type.as_str().trim().is_empty() {
            return Err(ProtocolError::InvalidOccurrence("type is required".into()));
        }
        if self.cluster.trim().is_empty() {
            return Err(ProtocolError::InvalidOccurrence(
                "cluster is required".into(),
            ));
        }

        // Max length guards — prevent oversized fields from consuming
        // unbounded memory in stores and indexes.
        const MAX_SHORT: usize = 256;
        const MAX_LABEL: usize = 1000;
        const MAX_LABELS: usize = 100;
        const MAX_ENTITY_IDS: usize = 100;

        if self.source.len() > MAX_SHORT {
            return Err(ProtocolError::InvalidOccurrence(format!(
                "source exceeds {MAX_SHORT} bytes"
            )));
        }
        if self.occurrence_type.as_str().len() > MAX_SHORT {
            return Err(ProtocolError::InvalidOccurrence(format!(
                "occurrence_type exceeds {MAX_SHORT} bytes"
            )));
        }
        if self.cluster.len() > MAX_SHORT {
            return Err(ProtocolError::InvalidOccurrence(format!(
                "cluster exceeds {MAX_SHORT} bytes"
            )));
        }
        if let Some(ref ns) = self.namespace {
            if ns.len() > MAX_SHORT {
                return Err(ProtocolError::InvalidOccurrence(format!(
                    "namespace exceeds {MAX_SHORT} bytes"
                )));
            }
        }
        if self.labels.len() > MAX_LABELS {
            return Err(ProtocolError::InvalidOccurrence(format!(
                "labels count {} exceeds {MAX_LABELS}",
                self.labels.len()
            )));
        }
        for (k, v) in &self.labels {
            if k.len() > MAX_LABEL {
                return Err(ProtocolError::InvalidOccurrence(format!(
                    "label key exceeds {MAX_LABEL} bytes"
                )));
            }
            if v.len() > MAX_LABEL {
                return Err(ProtocolError::InvalidOccurrence(format!(
                    "label value exceeds {MAX_LABEL} bytes"
                )));
            }
        }
        if self.entity_ids.len() > MAX_ENTITY_IDS {
            return Err(ProtocolError::InvalidOccurrence(format!(
                "entity_ids count {} exceeds {MAX_ENTITY_IDS}",
                self.entity_ids.len()
            )));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- OccurrenceType ---

    #[test]
    fn occurrence_type_domain_and_action() {
        let t = OccurrenceType::new("kernel.oom_kill");
        assert_eq!(t.domain(), "kernel");
        assert_eq!(t.action(), "oom_kill");
        assert_eq!(t.as_str(), "kernel.oom_kill");
    }

    #[test]
    fn occurrence_type_no_dot() {
        let t = OccurrenceType::new("nodot");
        assert_eq!(t.domain(), "nodot");
        assert_eq!(t.action(), "");
    }

    #[test]
    fn occurrence_type_nested_dots() {
        let t = OccurrenceType::new("network.latency.spike.detected");
        assert_eq!(t.domain(), "network");
        assert_eq!(t.action(), "latency.spike.detected");
    }

    #[test]
    fn occurrence_type_well_known_constants() {
        assert_eq!(OccurrenceType::KERNEL_OOM_KILL, "kernel.oom_kill");
        assert_eq!(OccurrenceType::CONTAINER_TERMINATED, "container.terminated");
        assert_eq!(OccurrenceType::POD_RESTART, "pod.restart");
        assert_eq!(OccurrenceType::SERVICE_DISRUPTION, "service.disruption");
        assert_eq!(OccurrenceType::SCHEDULING_FAILED, "scheduling.failed");
    }

    #[test]
    fn occurrence_type_serde_transparent() {
        let t = OccurrenceType::new("kernel.oom_kill");
        let json = serde_json::to_string(&t).unwrap();
        assert_eq!(json, "\"kernel.oom_kill\"");
        let back: OccurrenceType = serde_json::from_str(&json).unwrap();
        assert_eq!(back, t);
    }

    // --- OccurrenceCategory prefix matching ---

    #[test]
    fn category_resource_exhaustion() {
        assert_eq!(
            OccurrenceType::new("kernel.oom_kill").category(),
            Some(OccurrenceCategory::ResourceExhaustion)
        );
        assert_eq!(
            OccurrenceType::new("container.oom_killed").category(),
            Some(OccurrenceCategory::ResourceExhaustion)
        );
        assert_eq!(
            OccurrenceType::new("node.memory_pressure").category(),
            Some(OccurrenceCategory::ResourceExhaustion)
        );
        assert_eq!(
            OccurrenceType::new("node.disk_pressure").category(),
            Some(OccurrenceCategory::ResourceExhaustion)
        );
    }

    #[test]
    fn category_lifecycle() {
        assert_eq!(
            OccurrenceType::new("pod.restart").category(),
            Some(OccurrenceCategory::Lifecycle)
        );
        assert_eq!(
            OccurrenceType::new("container.terminated").category(),
            Some(OccurrenceCategory::Lifecycle)
        );
        assert_eq!(
            OccurrenceType::new("container.started").category(),
            Some(OccurrenceCategory::Lifecycle)
        );
    }

    #[test]
    fn category_network() {
        assert_eq!(
            OccurrenceType::new("network.timeout").category(),
            Some(OccurrenceCategory::Network)
        );
        assert_eq!(
            OccurrenceType::new("network.latency_spike").category(),
            Some(OccurrenceCategory::Network)
        );
    }

    #[test]
    fn category_config_change() {
        assert_eq!(
            OccurrenceType::new("deployment.update").category(),
            Some(OccurrenceCategory::ConfigChange)
        );
        assert_eq!(
            OccurrenceType::new("config.changed").category(),
            Some(OccurrenceCategory::ConfigChange)
        );
    }

    #[test]
    fn category_service_degradation() {
        assert_eq!(
            OccurrenceType::new("service.disruption").category(),
            Some(OccurrenceCategory::ServiceDegradation)
        );
        assert_eq!(
            OccurrenceType::new("service.error").category(),
            Some(OccurrenceCategory::ServiceDegradation)
        );
    }

    #[test]
    fn category_scaling() {
        assert_eq!(
            OccurrenceType::new("scheduling.failed").category(),
            Some(OccurrenceCategory::Scaling)
        );
        assert_eq!(
            OccurrenceType::new("node.not_ready").category(),
            Some(OccurrenceCategory::Scaling)
        );
        assert_eq!(
            OccurrenceType::new("hpa.scale_up").category(),
            Some(OccurrenceCategory::Scaling)
        );
    }

    #[test]
    fn category_security() {
        assert_eq!(
            OccurrenceType::new("security.policy_violation").category(),
            Some(OccurrenceCategory::Security)
        );
        assert_eq!(
            OccurrenceType::new("policy.denied").category(),
            Some(OccurrenceCategory::Security)
        );
    }

    #[test]
    fn category_self_observability() {
        assert_eq!(
            OccurrenceType::new("ahti.ingest.backpressure").category(),
            Some(OccurrenceCategory::SelfObservability)
        );
        assert_eq!(
            OccurrenceType::new("ahti.compaction.completed").category(),
            Some(OccurrenceCategory::SelfObservability)
        );
        assert_eq!(
            OccurrenceType::new("ahti.checkpoint.completed").category(),
            Some(OccurrenceCategory::SelfObservability)
        );
    }

    #[test]
    fn category_unknown_returns_none() {
        assert_eq!(OccurrenceType::new("database.deadlock").category(), None);
        assert_eq!(OccurrenceType::new("custom.event").category(), None);
        assert_eq!(OccurrenceType::new("nodot").category(), None);
    }

    #[test]
    fn category_prefix_specificity() {
        assert_eq!(
            OccurrenceType::new("node.memory_pressure").category(),
            Some(OccurrenceCategory::ResourceExhaustion)
        );
    }

    // --- Occurrence Builder ---

    #[test]
    fn builder_happy_path() {
        let occ = Occurrence::new("polku", OccurrenceType::KERNEL_OOM_KILL)
            .severity(Severity::Critical)
            .in_cluster("prod-us-east")
            .in_namespace("default")
            .build();
        assert!(occ.is_ok());
        let occ = occ.unwrap();
        assert_eq!(occ.source, "polku");
        assert_eq!(occ.occurrence_type.as_str(), "kernel.oom_kill");
        assert_eq!(occ.severity, Severity::Critical);
        assert_eq!(occ.cluster, "prod-us-east");
        assert_eq!(occ.namespace, Some("default".to_string()));
        assert_eq!(occ.enrichment_state, EnrichmentState::Raw);
        assert_eq!(occ.received_at, None);
    }

    #[test]
    fn with_received_at_sets_ingest_time() {
        let received_at = Utc::now();
        let occ = Occurrence::new("polku", OccurrenceType::KERNEL_OOM_KILL)
            .in_cluster("prod")
            .with_received_at(received_at);
        assert_eq!(occ.received_at, Some(received_at));
    }

    #[test]
    fn occurrence_backward_compat_missing_received_at() {
        let json = r#"{
            "id": "01ARZ3NDEKTSV4RRFFQ69G5FAV",
            "timestamp": "2024-01-01T00:00:00Z",
            "source": "tapio",
            "type": "kernel.oom_kill",
            "severity": "critical",
            "cluster": "prod"
        }"#;
        let occ: Occurrence = serde_json::from_str(json).unwrap();
        assert_eq!(occ.received_at, None);
    }

    #[test]
    fn builder_empty_source_fails() {
        let result = Occurrence::new("", OccurrenceType::POD_RESTART)
            .in_cluster("prod")
            .build();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("source is required"));
    }

    #[test]
    fn builder_whitespace_source_fails() {
        let result = Occurrence::new("  ", OccurrenceType::POD_RESTART)
            .in_cluster("prod")
            .build();
        assert!(result.is_err());
    }

    #[test]
    fn builder_empty_type_fails() {
        let result = Occurrence::new("polku", "").in_cluster("prod").build();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("type is required"));
    }

    #[test]
    fn builder_empty_cluster_fails() {
        let result = Occurrence::new("polku", OccurrenceType::POD_RESTART).build();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("cluster is required"));
    }

    #[test]
    fn builder_with_outcome() {
        let occ = Occurrence::new("polku", OccurrenceType::POD_RESTART)
            .in_cluster("prod")
            .outcome(Outcome::Failure)
            .build()
            .unwrap();
        assert_eq!(occ.outcome, Some(Outcome::Failure));
    }

    #[test]
    fn builder_with_entities() {
        let occ = Occurrence::new("polku", OccurrenceType::POD_RESTART)
            .in_cluster("prod")
            .with_entities(vec!["pod-1".into(), "node-1".into()])
            .build()
            .unwrap();
        assert_eq!(occ.entity_ids.len(), 2);
    }

    #[test]
    fn builder_with_tracing() {
        let occ = Occurrence::new("otel", "service.error")
            .in_cluster("prod")
            .with_tracing(
                "trace-123".into(),
                "span-456".into(),
                Some("span-000".into()),
            )
            .build()
            .unwrap();
        assert_eq!(occ.trace_id, Some("trace-123".to_string()));
        assert_eq!(occ.span_id, Some("span-456".to_string()));
        assert_eq!(occ.parent_span_id, Some("span-000".to_string()));
    }

    // --- Occurrence::new_at ---

    #[test]
    fn new_at_uses_provided_timestamp() {
        use chrono::TimeZone;
        let ts = Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 0).unwrap();
        let occ = Occurrence::new_at("tapio", "kernel.oom_kill", ts)
            .in_cluster("prod")
            .build()
            .unwrap();
        assert_eq!(occ.timestamp, ts);
        // ULID should embed the same millisecond timestamp
        assert_eq!(occ.id.timestamp_ms(), ts.timestamp_millis() as u64);
    }

    // --- FALSE Protocol Blocks ---

    #[test]
    fn occurrence_with_error_block() {
        let occ = Occurrence::new("polku", OccurrenceType::KERNEL_OOM_KILL)
            .in_cluster("prod")
            .with_error(OccurrenceError {
                code: "OOM_KILL".into(),
                what_failed: "Container memory allocation".into(),
                why_it_matters: Some("Pod will restart, potential cascade".into()),
                possible_causes: vec!["Memory leak".into(), "Undersized limits".into()],
                ..Default::default()
            })
            .build()
            .unwrap();
        let err = occ.error.unwrap();
        assert_eq!(err.code, "OOM_KILL");
        assert_eq!(err.possible_causes.len(), 2);
    }

    #[test]
    fn occurrence_with_reasoning_block() {
        let occ = Occurrence::new("ahti", "service.disruption")
            .in_cluster("prod")
            .with_reasoning(OccurrenceReasoning {
                summary: "OOM kill caused pod restart".into(),
                explanation: Some("Memory pressure triggered kernel OOM killer".into()),
                confidence: 0.87,
                steps: vec!["Detected OOM".into(), "Linked to pod restart".into()],
                root_cause: Some(CauseRef {
                    occurrence_id: "01ARZ3NDEKTSV4RRFFQ69G5FAV".into(),
                    cause_type: "kernel.oom_kill".into(),
                    summary: Some("OOM kill on node-1".into()),
                    confidence: Some(0.92),
                }),
                causal_chain: Vec::new(),
                patterns_matched: vec![PatternMatch {
                    pattern_id: "p-oom-restart".into(),
                    name: "OOM Kill → Pod Restart".into(),
                    confidence: 0.94,
                }],
                alternative_explanations: Vec::new(),
            })
            .build()
            .unwrap();
        let r = occ.reasoning.unwrap();
        assert_eq!(r.confidence, 0.87);
        assert!(r.root_cause.is_some());
        assert_eq!(r.patterns_matched.len(), 1);
    }

    #[test]
    fn occurrence_with_history_block() {
        let occ = Occurrence::new("portti", "deployment.update")
            .in_cluster("prod")
            .with_history(OccurrenceHistory {
                steps: vec![
                    HistoryStep {
                        description: "Image pulled".into(),
                        timestamp: Some("2024-01-01T00:00:00Z".into()),
                        duration_ms: Some(1200),
                        status: Some("success".into()),
                    },
                    HistoryStep {
                        description: "Container started".into(),
                        timestamp: None,
                        duration_ms: None,
                        status: Some("success".into()),
                    },
                ],
                duration_ms: Some(3400),
            })
            .build()
            .unwrap();
        let h = occ.history.unwrap();
        assert_eq!(h.steps.len(), 2);
        assert_eq!(h.duration_ms, Some(3400));
    }

    // --- Serde ---

    #[test]
    fn occurrence_serde_skips_none_fields() {
        let occ = Occurrence::new("polku", OccurrenceType::POD_RESTART)
            .in_cluster("prod")
            .build()
            .unwrap();
        let json = serde_json::to_string(&occ).unwrap();
        assert!(!json.contains("\"outcome\""));
        assert!(!json.contains("\"error\""));
        assert!(!json.contains("\"reasoning\""));
        assert!(!json.contains("\"history\""));
        assert!(!json.contains("\"namespace\""));
        assert!(!json.contains("\"trace_id\""));
        assert!(!json.contains("\"network_data\""));
    }

    #[test]
    fn occurrence_serde_roundtrip() {
        let occ = Occurrence::new("polku", OccurrenceType::KERNEL_OOM_KILL)
            .severity(Severity::Critical)
            .in_cluster("prod")
            .in_namespace("kube-system")
            .outcome(Outcome::Failure)
            .with_entities(vec!["pod-1".into()])
            .build()
            .unwrap();
        let json = serde_json::to_string(&occ).unwrap();
        let back: Occurrence = serde_json::from_str(&json).unwrap();
        assert_eq!(back.source, occ.source);
        assert_eq!(back.occurrence_type, occ.occurrence_type);
        assert_eq!(back.severity, occ.severity);
        assert_eq!(back.cluster, occ.cluster);
        assert_eq!(back.namespace, occ.namespace);
        assert_eq!(back.outcome, occ.outcome);
        assert_eq!(back.entity_ids, occ.entity_ids);
    }

    #[test]
    fn occurrence_type_field_renamed() {
        let occ = Occurrence::new("polku", "pod.restart")
            .in_cluster("prod")
            .build()
            .unwrap();
        let json = serde_json::to_string(&occ).unwrap();
        assert!(json.contains("\"type\":\"pod.restart\""));
    }

    // --- Typed Payloads ---

    #[test]
    fn occurrence_with_kernel_payload_roundtrip() {
        let occ = Occurrence::new("tapio", OccurrenceType::KERNEL_OOM_KILL)
            .severity(Severity::Critical)
            .in_cluster("prod")
            .build()
            .unwrap();
        let mut occ = occ;
        occ.kernel_data = Some(KernelEventData {
            event_type: "oom_kill".into(),
            pid: 42,
            command: "java".into(),
            oom_victim_pid: Some(99),
            oom_victim_comm: Some("java".into()),
            memory_requested: Some(2_147_483_648),
            signal: None,
            syscall_name: None,
        });

        let json = serde_json::to_string(&occ).unwrap();
        let back: Occurrence = serde_json::from_str(&json).unwrap();

        assert_eq!(back.source, "tapio");
        assert_eq!(
            back.occurrence_type.as_str(),
            OccurrenceType::KERNEL_OOM_KILL
        );
        let kd = back.kernel_data.unwrap();
        assert_eq!(kd.pid, 42);
        assert_eq!(kd.oom_victim_pid, Some(99));
        assert_eq!(kd.memory_requested, Some(2_147_483_648));
        assert!(back.network_data.is_none());
        assert!(back.container_data.is_none());
    }
}

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Debug,
    #[default]
    Info,
    Warning,
    Error,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Success,
    Failure,
    Timeout,
    InProgress,
    Unknown,
}

/// Enrichment progresses through these states.
/// Queryable at every stage — you just get different depth.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnrichmentState {
    #[default]
    Raw,
    EntityResolved,
    ContextEnriched,
    CausalityScored,
    FullyEnriched,
}

impl EnrichmentState {
    /// Returns the next state in the enrichment progression.
    /// FullyEnriched is absorbing — it maps to itself.
    pub fn next(self) -> EnrichmentState {
        match self {
            EnrichmentState::Raw => EnrichmentState::EntityResolved,
            EnrichmentState::EntityResolved => EnrichmentState::ContextEnriched,
            EnrichmentState::ContextEnriched => EnrichmentState::CausalityScored,
            EnrichmentState::CausalityScored => EnrichmentState::FullyEnriched,
            EnrichmentState::FullyEnriched => EnrichmentState::FullyEnriched,
        }
    }
}

/// Semantic categories for occurrence types.
/// Enables generalization across specific occurrence types.
/// Derived from OccurrenceType via prefix matching — not stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OccurrenceCategory {
    /// Resource exhaustion: OOM, disk pressure, CPU throttling
    ResourceExhaustion,
    /// Lifecycle events: pod start, stop, restart, scheduled
    Lifecycle,
    /// Network issues: timeouts, latency, connection failures
    Network,
    /// Configuration changes: deployment updates, config changes, rollbacks
    ConfigChange,
    /// Service degradation: errors, disruptions, SLO breaches
    ServiceDegradation,
    /// Scaling events: HPA triggers, node provisioning, scheduling failures
    Scaling,
    /// Security events: policy violations, access denials
    Security,
    /// Self-observability: Ahti diagnosing itself (ahti.* occurrence types)
    SelfObservability,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_default_is_info() {
        assert_eq!(Severity::default(), Severity::Info);
    }

    #[test]
    fn enrichment_state_default_is_raw() {
        assert_eq!(EnrichmentState::default(), EnrichmentState::Raw);
    }

    #[test]
    fn severity_serde_roundtrip() {
        let s = Severity::Critical;
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(json, "\"critical\"");
        let back: Severity = serde_json::from_str(&json).unwrap();
        assert_eq!(back, s);
    }

    #[test]
    fn outcome_serde_snake_case() {
        assert_eq!(
            serde_json::to_string(&Outcome::InProgress).unwrap(),
            "\"in_progress\""
        );
    }

    #[test]
    fn enrichment_state_serde_snake_case() {
        assert_eq!(
            serde_json::to_string(&EnrichmentState::EntityResolved).unwrap(),
            "\"entity_resolved\""
        );
        assert_eq!(
            serde_json::to_string(&EnrichmentState::CausalityScored).unwrap(),
            "\"causality_scored\""
        );
    }

    #[test]
    fn occurrence_category_serde_roundtrip() {
        let cat = OccurrenceCategory::ResourceExhaustion;
        let json = serde_json::to_string(&cat).unwrap();
        assert_eq!(json, "\"resource_exhaustion\"");
        let back: OccurrenceCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(back, cat);
    }

    #[test]
    fn occurrence_category_serde_all_variants() {
        let cases = [
            (
                OccurrenceCategory::ResourceExhaustion,
                "\"resource_exhaustion\"",
            ),
            (OccurrenceCategory::Lifecycle, "\"lifecycle\""),
            (OccurrenceCategory::Network, "\"network\""),
            (OccurrenceCategory::ConfigChange, "\"config_change\""),
            (
                OccurrenceCategory::ServiceDegradation,
                "\"service_degradation\"",
            ),
            (OccurrenceCategory::Scaling, "\"scaling\""),
            (OccurrenceCategory::Security, "\"security\""),
            (
                OccurrenceCategory::SelfObservability,
                "\"self_observability\"",
            ),
        ];
        for (cat, expected) in cases {
            assert_eq!(serde_json::to_string(&cat).unwrap(), expected);
        }
    }

    #[test]
    fn severity_orders_by_escalation() {
        assert!(Severity::Debug < Severity::Info);
        assert!(Severity::Info < Severity::Warning);
        assert!(Severity::Warning < Severity::Error);
        assert!(Severity::Error < Severity::Critical);
    }

    #[test]
    fn enrichment_state_next_advances_one_step() {
        assert_eq!(EnrichmentState::Raw.next(), EnrichmentState::EntityResolved);
        assert_eq!(
            EnrichmentState::EntityResolved.next(),
            EnrichmentState::ContextEnriched
        );
        assert_eq!(
            EnrichmentState::ContextEnriched.next(),
            EnrichmentState::CausalityScored
        );
        assert_eq!(
            EnrichmentState::CausalityScored.next(),
            EnrichmentState::FullyEnriched
        );
        assert_eq!(
            EnrichmentState::FullyEnriched.next(),
            EnrichmentState::FullyEnriched
        );
    }

    #[test]
    fn enrichment_state_orders_by_progression() {
        assert!(EnrichmentState::Raw < EnrichmentState::EntityResolved);
        assert!(EnrichmentState::EntityResolved < EnrichmentState::ContextEnriched);
        assert!(EnrichmentState::ContextEnriched < EnrichmentState::CausalityScored);
        assert!(EnrichmentState::CausalityScored < EnrichmentState::FullyEnriched);
    }
}

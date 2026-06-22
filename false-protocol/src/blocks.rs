use serde::{Deserialize, Serialize};

/// Structured error information (FALSE Protocol Error block).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OccurrenceError {
    pub code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stack: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cause: Option<String>,
    pub what_failed: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub why_it_matters: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub possible_causes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggested_fix: Option<String>,
}

/// Analysis information (FALSE Protocol Reasoning block).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OccurrenceReasoning {
    pub summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub explanation: Option<String>,
    pub confidence: f64,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub steps: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root_cause: Option<CauseRef>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub causal_chain: Vec<CauseRef>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub patterns_matched: Vec<PatternMatch>,

    /// Alternative causal explanations that were considered.
    /// Present only when multiple plausible causes exist.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub alternative_explanations: Vec<CauseRef>,
}

/// Reference to a causal occurrence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CauseRef {
    pub occurrence_id: String,
    #[serde(rename = "type")]
    pub cause_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f64>,
}

/// Record of a matched causality pattern.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternMatch {
    pub pattern_id: String,
    pub name: String,
    pub confidence: f64,
}

/// Lifecycle history (FALSE Protocol History block).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OccurrenceHistory {
    pub steps: Vec<HistoryStep>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryStep {
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn occurrence_error_default() {
        let err = OccurrenceError::default();
        assert_eq!(err.code, "");
        assert_eq!(err.what_failed, "");
        assert!(err.possible_causes.is_empty());
    }

    #[test]
    fn reasoning_with_alternative_explanations() {
        let reasoning = OccurrenceReasoning {
            summary: "OOM kill caused pod restart".into(),
            explanation: None,
            confidence: 0.87,
            steps: Vec::new(),
            root_cause: None,
            causal_chain: Vec::new(),
            patterns_matched: Vec::new(),
            alternative_explanations: vec![CauseRef {
                occurrence_id: "01ARZ3NDEKTSV4RRFFQ69G5FAV".into(),
                cause_type: "deployment.update".into(),
                summary: Some("Recent deployment to auth service".into()),
                confidence: Some(0.23),
            }],
        };
        let json = serde_json::to_string(&reasoning).unwrap();
        assert!(json.contains("\"alternative_explanations\""));
        let back: OccurrenceReasoning = serde_json::from_str(&json).unwrap();
        assert_eq!(back.alternative_explanations.len(), 1);
        assert_eq!(
            back.alternative_explanations[0].cause_type,
            "deployment.update"
        );
    }

    #[test]
    fn reasoning_skips_empty_alternative_explanations() {
        let reasoning = OccurrenceReasoning {
            summary: "test".into(),
            explanation: None,
            confidence: 0.5,
            steps: Vec::new(),
            root_cause: None,
            causal_chain: Vec::new(),
            patterns_matched: Vec::new(),
            alternative_explanations: Vec::new(),
        };
        let json = serde_json::to_string(&reasoning).unwrap();
        assert!(!json.contains("\"alternative_explanations\""));
    }
}

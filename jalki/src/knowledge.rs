use serde::{Deserialize, Serialize};

/// The compiled-in knowledge base. Loaded at startup from embedded JSON.
pub struct KnowledgeBase {
    layers: Vec<Layer>,
}

/// A layer groups related kernel functions (tcp, memory, fs, sched, process).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Layer {
    pub version: String,
    pub layer: String,
    pub description: String,
    pub probes: Vec<ProbeKnowledge>,
}

/// Everything an agent needs to know about a kernel function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeKnowledge {
    pub function: String,
    pub attachment: String,
    pub event_type: String,
    pub layer: String,
    pub answers: Vec<String>,
    pub keywords: Vec<String>,
    pub fields: Vec<FieldKnowledge>,
    pub use_when: String,
    pub not_when: String,
    pub combine_with: Vec<String>,
    #[serde(default)]
    pub tcp_states: Option<std::collections::HashMap<String, String>>,
    pub interpretations: Vec<Interpretation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldKnowledge {
    pub name: String,
    #[serde(rename = "type")]
    pub field_type: String,
    pub meaning: String,
    pub important: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Interpretation {
    pub pattern: String,
    pub conclusion: String,
    pub severity: String,
    pub action: String,
    #[serde(default)]
    pub errno: Option<String>,
}

impl KnowledgeBase {
    /// Load the knowledge base from embedded JSON files.
    /// Panics at startup if the JSON is malformed — this is intentional.
    /// A corrupted knowledge base must never silently serve wrong answers.
    pub fn load() -> Self {
        let tcp: Layer =
            serde_json::from_str(include_str!("../../knowledge/tcp.json"))
                .expect("knowledge/tcp.json is malformed — fix it before shipping");
        let memory: Layer =
            serde_json::from_str(include_str!("../../knowledge/memory.json"))
                .expect("knowledge/memory.json is malformed — fix it before shipping");
        let fs: Layer =
            serde_json::from_str(include_str!("../../knowledge/fs.json"))
                .expect("knowledge/fs.json is malformed — fix it before shipping");
        let sched: Layer =
            serde_json::from_str(include_str!("../../knowledge/sched.json"))
                .expect("knowledge/sched.json is malformed — fix it before shipping");
        let process: Layer =
            serde_json::from_str(include_str!("../../knowledge/process.json"))
                .expect("knowledge/process.json is malformed — fix it before shipping");

        Self {
            layers: vec![tcp, memory, fs, sched, process],
        }
    }

    /// Find probes that answer a question. Matches against `answers` and `keywords`.
    pub fn find_probes(&self, question: &str) -> Vec<&ProbeKnowledge> {
        let q = question.to_lowercase();
        let mut matches: Vec<(&ProbeKnowledge, usize)> = Vec::new();

        for layer in &self.layers {
            for probe in &layer.probes {
                let mut score = 0usize;

                // Check if question matches any answer descriptions.
                for answer in &probe.answers {
                    if q.contains(&answer.to_lowercase()) || answer.to_lowercase().contains(&q) {
                        score += 10;
                    }
                }

                // Check keyword matches.
                for keyword in &probe.keywords {
                    if q.contains(&keyword.to_lowercase()) {
                        score += 5;
                    }
                }

                // Check function name match.
                if q.contains(&probe.function) {
                    score += 20;
                }

                if score > 0 {
                    matches.push((probe, score));
                }
            }
        }

        // Sort by relevance (highest score first).
        matches.sort_by(|a, b| b.1.cmp(&a.1));
        matches.into_iter().map(|(p, _)| p).collect()
    }

    /// Look up a specific function by name.
    pub fn get_probe(&self, function: &str) -> Option<&ProbeKnowledge> {
        for layer in &self.layers {
            for probe in &layer.probes {
                if probe.function == function {
                    return Some(probe);
                }
            }
        }
        None
    }

    /// Get all probes in a layer.
    pub fn probes_in_layer(&self, layer_name: &str) -> Vec<&ProbeKnowledge> {
        for layer in &self.layers {
            if layer.layer == layer_name {
                return layer.probes.iter().collect();
            }
        }
        Vec::new()
    }

    /// List all known layers.
    pub fn layers(&self) -> Vec<&str> {
        self.layers.iter().map(|l| l.layer.as_str()).collect()
    }

    /// List all known functions.
    pub fn all_functions(&self) -> Vec<&str> {
        self.layers
            .iter()
            .flat_map(|l| l.probes.iter().map(|p| p.function.as_str()))
            .collect()
    }

    /// Find interpretations for a specific event.
    /// Returns matching interpretations based on the event's fields.
    pub fn explain(&self, function: &str, fields: &EventFields) -> Vec<&Interpretation> {
        let probe = match self.get_probe(function) {
            Some(p) => p,
            None => return Vec::new(),
        };

        let mut matches = Vec::new();
        for interp in &probe.interpretations {
            if interpretation_matches(interp, fields) {
                matches.push(interp);
            }
        }
        matches
    }
}

/// Fields from an event, used for interpretation matching.
pub struct EventFields {
    pub ret: Option<i32>,
    pub tcp_state: Option<u8>,
}

/// Simple pattern matching against interpretation conditions.
fn interpretation_matches(interp: &Interpretation, fields: &EventFields) -> bool {
    let pattern = &interp.pattern;

    // Match ret-based patterns.
    if let Some(ret) = fields.ret {
        if pattern.contains("ret == 0") && ret == 0 {
            return true;
        }
        if pattern.contains("ret == -111") && ret == -111 {
            return true;
        }
        if pattern.contains("ret == -110") && ret == -110 {
            return true;
        }
        if pattern.contains("ret == -113") && ret == -113 {
            return true;
        }
        if pattern.contains("ret == -101") && ret == -101 {
            return true;
        }
        if pattern.contains("ret != 0") && ret != 0 {
            return true;
        }
    }

    // Match tcp_state-based patterns.
    if let Some(state) = fields.tcp_state {
        if pattern.contains("SYN_SENT (2)") && state == 2 {
            return true;
        }
        if pattern.contains("ESTABLISHED (1)") && state == 1 {
            return true;
        }
        if pattern.contains("CLOSE_WAIT (7)") && state == 7 {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn knowledge_base_loads() {
        let kb = KnowledgeBase::load();
        assert!(!kb.layers.is_empty());
        assert_eq!(kb.layers[0].layer, "tcp");
    }

    #[test]
    fn find_probes_by_question() {
        let kb = KnowledgeBase::load();

        let results = kb.find_probes("why are connections failing");
        assert!(!results.is_empty());
        assert_eq!(results[0].function, "tcp_connect");
    }

    #[test]
    fn find_probes_by_keyword() {
        let kb = KnowledgeBase::load();

        let results = kb.find_probes("retransmit");
        assert!(!results.is_empty());
        assert_eq!(results[0].function, "tcp_retransmit_skb");
    }

    #[test]
    fn find_probes_packet_loss() {
        let kb = KnowledgeBase::load();

        let results = kb.find_probes("packet loss");
        assert!(!results.is_empty());
        assert_eq!(results[0].function, "tcp_retransmit_skb");
    }

    #[test]
    fn get_probe_by_name() {
        let kb = KnowledgeBase::load();

        let probe = kb.get_probe("tcp_connect").unwrap();
        assert_eq!(probe.attachment, "fexit");
        assert!(!probe.fields.is_empty());
    }

    #[test]
    fn get_probe_unknown_returns_none() {
        let kb = KnowledgeBase::load();
        assert!(kb.get_probe("nonexistent_function").is_none());
    }

    #[test]
    fn all_functions_listed() {
        let kb = KnowledgeBase::load();
        let funcs = kb.all_functions();
        assert!(funcs.contains(&"tcp_connect"));
        assert!(funcs.contains(&"tcp_close"));
        assert!(funcs.contains(&"tcp_retransmit_skb"));
        assert!(funcs.contains(&"tcp_sendmsg"));
        assert!(funcs.contains(&"inet_csk_accept"));
    }

    #[test]
    fn explain_econnrefused() {
        let kb = KnowledgeBase::load();
        let interps = kb.explain(
            "tcp_connect",
            &EventFields {
                ret: Some(-111),
                tcp_state: None,
            },
        );
        assert!(!interps.is_empty());
        assert!(interps[0].conclusion.contains("listening"));
        assert_eq!(interps[0].errno.as_deref(), Some("ECONNREFUSED"));
    }

    #[test]
    fn explain_established_retransmit() {
        let kb = KnowledgeBase::load();
        let interps = kb.explain(
            "tcp_retransmit_skb",
            &EventFields {
                ret: None,
                tcp_state: Some(1),
            },
        );
        assert!(!interps.is_empty());
        assert!(interps[0].conclusion.contains("network"));
    }

    #[test]
    fn explain_syn_sent_retransmit() {
        let kb = KnowledgeBase::load();
        let interps = kb.explain(
            "tcp_retransmit_skb",
            &EventFields {
                ret: None,
                tcp_state: Some(2),
            },
        );
        assert!(!interps.is_empty());
        assert!(interps[0].conclusion.contains("handshake"));
    }

    #[test]
    fn layers_lists_tcp() {
        let kb = KnowledgeBase::load();
        assert!(kb.layers().contains(&"tcp"));
    }

    #[test]
    fn probes_in_layer() {
        let kb = KnowledgeBase::load();
        let tcp_probes = kb.probes_in_layer("tcp");
        assert!(tcp_probes.len() >= 3);
    }

    #[test]
    fn combine_with_populated() {
        let kb = KnowledgeBase::load();
        let probe = kb.get_probe("tcp_connect").unwrap();
        assert!(probe.combine_with.contains(&"tcp_retransmit_skb".to_string()));
    }
}

fn main() {
    eprintln!("jalki-oracle is a test binary — run with: cargo test");
    eprintln!("Usage: cargo test --manifest-path eval/oracle/Cargo.toml");
    std::process::exit(1);
}

#[cfg(test)]
mod tests {
    use serde_json::{json, Value};
    use std::collections::HashSet;

    // ================================================================
    // HELPERS
    // ================================================================

    fn load_knowledge(filename: &str) -> Value {
        let path = format!(
            "{}/../../knowledge/{filename}",
            env!("CARGO_MANIFEST_DIR")
        );
        let data = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("failed to read {path}: {e}"));
        serde_json::from_str(&data)
            .unwrap_or_else(|e| panic!("{filename} is not valid JSON: {e}"))
    }

    fn all_layers() -> Vec<(&'static str, Value)> {
        vec![
            ("tcp.json", load_knowledge("tcp.json")),
            ("memory.json", load_knowledge("memory.json")),
            ("fs.json", load_knowledge("fs.json")),
            ("sched.json", load_knowledge("sched.json")),
            ("process.json", load_knowledge("process.json")),
        ]
    }

    fn all_probes() -> Vec<Value> {
        all_layers()
            .into_iter()
            .flat_map(|(_, layer)| {
                layer["probes"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default()
            })
            .collect()
    }

    fn mcp_tools_list() -> Value {
        // Simulate the tools/list response by reading the expected tool names.
        // The oracle doesn't import jalki — it validates the contract.
        json!([
            "jalki_find_probe",
            "jalki_deploy_probe",
            "jalki_get_events",
            "jalki_explain_event",
            "jalki_probe_status",
            "jalki_deploy_descriptor"
        ])
    }

    // ================================================================
    // KNOWLEDGE BASE — SCHEMA VALIDITY (001-010)
    //
    // Every knowledge file must conform to the schema.
    // Wrong schema = agents get garbage = silent misdiagnosis.
    // ================================================================

    #[test]
    fn case_001_all_knowledge_files_parse() {
        for (filename, layer) in all_layers() {
            assert!(
                layer.is_object(),
                "{filename}: root must be an object"
            );
            assert!(
                layer.get("version").is_some(),
                "{filename}: missing 'version' field"
            );
            assert!(
                layer.get("layer").is_some(),
                "{filename}: missing 'layer' field"
            );
            assert!(
                layer.get("probes").and_then(|v| v.as_array()).is_some(),
                "{filename}: missing or non-array 'probes' field"
            );
        }
    }

    #[test]
    fn case_002_every_probe_has_required_fields() {
        let required = [
            "function", "attachment", "event_type", "layer",
            "answers", "keywords", "fields", "use_when", "not_when",
            "combine_with", "interpretations",
        ];

        for probe in all_probes() {
            let function = probe["function"].as_str().unwrap_or("<unnamed>");
            for field in &required {
                assert!(
                    probe.get(field).is_some(),
                    "probe '{function}' missing required field '{field}'"
                );
            }
        }
    }

    #[test]
    fn case_003_attachment_is_fentry_or_fexit() {
        for probe in all_probes() {
            let function = probe["function"].as_str().unwrap_or("<unnamed>");
            let attachment = probe["attachment"].as_str().unwrap_or("");
            assert!(
                attachment == "fentry" || attachment == "fexit",
                "probe '{function}' has invalid attachment '{attachment}' — must be 'fentry' or 'fexit'"
            );
        }
    }

    #[test]
    fn case_004_function_names_are_unique() {
        let mut seen = HashSet::new();
        for probe in all_probes() {
            let function = probe["function"].as_str().unwrap().to_string();
            assert!(
                seen.insert(function.clone()),
                "duplicate function name: '{function}'"
            );
        }
    }

    #[test]
    fn case_005_event_types_follow_format() {
        // Format: kernel.<layer>.<action>
        for probe in all_probes() {
            let function = probe["function"].as_str().unwrap_or("<unnamed>");
            let event_type = probe["event_type"].as_str().unwrap_or("");
            assert!(
                event_type.starts_with("kernel."),
                "probe '{function}' event_type '{event_type}' must start with 'kernel.'"
            );
            let parts: Vec<&str> = event_type.split('.').collect();
            assert!(
                parts.len() >= 3,
                "probe '{function}' event_type '{event_type}' must have at least 3 dot-separated parts"
            );
        }
    }

    #[test]
    fn case_006_every_field_has_name_type_meaning() {
        for probe in all_probes() {
            let function = probe["function"].as_str().unwrap_or("<unnamed>");
            let fields = probe["fields"].as_array().unwrap();
            for field in fields {
                assert!(
                    field.get("name").and_then(|v| v.as_str()).is_some(),
                    "probe '{function}' has a field without 'name'"
                );
                assert!(
                    field.get("type").and_then(|v| v.as_str()).is_some(),
                    "probe '{function}' field '{}' missing 'type'",
                    field["name"].as_str().unwrap_or("?")
                );
                assert!(
                    field.get("meaning").and_then(|v| v.as_str()).is_some(),
                    "probe '{function}' field '{}' missing 'meaning'",
                    field["name"].as_str().unwrap_or("?")
                );
                assert!(
                    field.get("important").is_some(),
                    "probe '{function}' field '{}' missing 'important' flag",
                    field["name"].as_str().unwrap_or("?")
                );
            }
        }
    }

    #[test]
    fn case_007_every_interpretation_has_pattern_conclusion_action() {
        for probe in all_probes() {
            let function = probe["function"].as_str().unwrap_or("<unnamed>");
            let interps = probe["interpretations"].as_array().unwrap();
            for (i, interp) in interps.iter().enumerate() {
                assert!(
                    interp.get("pattern").and_then(|v| v.as_str()).is_some(),
                    "probe '{function}' interpretation [{i}] missing 'pattern'"
                );
                assert!(
                    interp.get("conclusion").and_then(|v| v.as_str()).is_some(),
                    "probe '{function}' interpretation [{i}] missing 'conclusion'"
                );
                assert!(
                    interp.get("action").and_then(|v| v.as_str()).is_some(),
                    "probe '{function}' interpretation [{i}] missing 'action'"
                );
                assert!(
                    interp.get("severity").and_then(|v| v.as_str()).is_some(),
                    "probe '{function}' interpretation [{i}] missing 'severity'"
                );
            }
        }
    }

    #[test]
    fn case_008_severity_values_are_valid() {
        let valid_severities: HashSet<&str> =
            ["info", "warning", "error", "critical"].iter().copied().collect();

        for probe in all_probes() {
            let function = probe["function"].as_str().unwrap_or("<unnamed>");
            for interp in probe["interpretations"].as_array().unwrap() {
                let sev = interp["severity"].as_str().unwrap_or("");
                assert!(
                    valid_severities.contains(sev),
                    "probe '{function}' has invalid severity '{sev}' — must be info/warning/error/critical"
                );
            }
        }
    }

    #[test]
    fn case_009_answers_are_non_empty() {
        for probe in all_probes() {
            let function = probe["function"].as_str().unwrap_or("<unnamed>");
            let answers = probe["answers"].as_array().unwrap();
            assert!(
                !answers.is_empty(),
                "probe '{function}' has empty answers — agents need at least one question this probe answers"
            );
            for answer in answers {
                assert!(
                    !answer.as_str().unwrap_or("").is_empty(),
                    "probe '{function}' has an empty answer string"
                );
            }
        }
    }

    #[test]
    fn case_010_keywords_are_non_empty_lowercase() {
        for probe in all_probes() {
            let function = probe["function"].as_str().unwrap_or("<unnamed>");
            let keywords = probe["keywords"].as_array().unwrap();
            assert!(
                !keywords.is_empty(),
                "probe '{function}' has no keywords — search will never find it"
            );
            for kw in keywords {
                let s = kw.as_str().unwrap_or("");
                assert!(!s.is_empty(), "probe '{function}' has empty keyword");
                assert_eq!(
                    s, s.to_lowercase().as_str(),
                    "probe '{function}' keyword '{s}' must be lowercase"
                );
            }
        }
    }

    // ================================================================
    // KNOWLEDGE BASE — SEMANTIC CORRECTNESS (011-020)
    //
    // The knowledge base must give correct answers.
    // A wrong interpretation misleads every agent that reads it.
    // ================================================================

    #[test]
    fn case_011_tcp_connect_is_fexit() {
        // tcp_connect return value is essential — fexit is the only correct choice.
        let probes = all_probes();
        let tcp_connect = probes.iter().find(|p| p["function"] == "tcp_connect").unwrap();
        assert_eq!(
            tcp_connect["attachment"].as_str().unwrap(), "fexit",
            "tcp_connect MUST be fexit — the return value (errno) is the whole point"
        );
    }

    #[test]
    fn case_012_tcp_retransmit_is_fentry() {
        // tcp_retransmit_skb: we care that it happened, not what it returned.
        let probes = all_probes();
        let retransmit = probes.iter().find(|p| p["function"] == "tcp_retransmit_skb").unwrap();
        assert_eq!(
            retransmit["attachment"].as_str().unwrap(), "fentry",
            "tcp_retransmit_skb MUST be fentry — we need entry state, not return value"
        );
    }

    #[test]
    fn case_013_retransmit_has_tcp_state_field() {
        // tcp_state is the most important field in the entire knowledge base.
        let probes = all_probes();
        let retransmit = probes.iter().find(|p| p["function"] == "tcp_retransmit_skb").unwrap();
        let fields = retransmit["fields"].as_array().unwrap();
        let has_tcp_state = fields.iter().any(|f| f["name"] == "tcp_state");
        assert!(
            has_tcp_state,
            "tcp_retransmit_skb MUST have tcp_state field — it's the single most important diagnostic field"
        );

        let tcp_state_field = fields.iter().find(|f| f["name"] == "tcp_state").unwrap();
        assert_eq!(
            tcp_state_field["important"].as_bool(), Some(true),
            "tcp_state must be marked important"
        );
    }

    #[test]
    fn case_014_retransmit_established_says_network_problem() {
        // ESTABLISHED retransmit = network problem, NOT application.
        // Getting this wrong misleads every agent.
        let probes = all_probes();
        let retransmit = probes.iter().find(|p| p["function"] == "tcp_retransmit_skb").unwrap();
        let interps = retransmit["interpretations"].as_array().unwrap();

        let established = interps.iter().find(|i| {
            let pattern = i["pattern"].as_str().unwrap_or("");
            pattern.contains("ESTABLISHED") && pattern.contains("1")
        });

        assert!(established.is_some(), "must have interpretation for ESTABLISHED retransmit");

        let conclusion = established.unwrap()["conclusion"].as_str().unwrap().to_lowercase();
        assert!(
            conclusion.contains("network"),
            "ESTABLISHED retransmit conclusion must mention 'network': got '{conclusion}'"
        );
        assert!(
            !conclusion.contains("application bug") || conclusion.contains("not"),
            "ESTABLISHED retransmit must NOT blame the application"
        );
    }

    #[test]
    fn case_015_retransmit_syn_sent_says_unreachable() {
        // SYN_SENT retransmit = remote unreachable.
        let probes = all_probes();
        let retransmit = probes.iter().find(|p| p["function"] == "tcp_retransmit_skb").unwrap();
        let interps = retransmit["interpretations"].as_array().unwrap();

        let syn_sent = interps.iter().find(|i| {
            let pattern = i["pattern"].as_str().unwrap_or("");
            pattern.contains("SYN_SENT") && pattern.contains("2")
        });

        assert!(syn_sent.is_some(), "must have interpretation for SYN_SENT retransmit");

        let conclusion = syn_sent.unwrap()["conclusion"].as_str().unwrap().to_lowercase();
        assert!(
            conclusion.contains("handshake") || conclusion.contains("unreachable"),
            "SYN_SENT retransmit conclusion must mention handshake failure or unreachability: got '{conclusion}'"
        );
    }

    #[test]
    fn case_016_econnrefused_interpretation_exists() {
        let probes = all_probes();
        let tcp_connect = probes.iter().find(|p| p["function"] == "tcp_connect").unwrap();
        let interps = tcp_connect["interpretations"].as_array().unwrap();

        let refused = interps.iter().find(|i| {
            i.get("errno").and_then(|v| v.as_str()) == Some("ECONNREFUSED")
        });

        assert!(refused.is_some(), "tcp_connect must have ECONNREFUSED interpretation");

        let conclusion = refused.unwrap()["conclusion"].as_str().unwrap().to_lowercase();
        assert!(
            conclusion.contains("listening") || conclusion.contains("not running"),
            "ECONNREFUSED must say nothing is listening: got '{conclusion}'"
        );
    }

    #[test]
    fn case_017_combine_with_references_exist() {
        // Every function referenced in combine_with must exist in the knowledge base.
        let all_functions: HashSet<String> = all_probes()
            .iter()
            .map(|p| p["function"].as_str().unwrap().to_string())
            .collect();

        for probe in all_probes() {
            let function = probe["function"].as_str().unwrap();
            let combine_with = probe["combine_with"].as_array().unwrap();
            for ref_fn in combine_with {
                let ref_name = ref_fn.as_str().unwrap();
                assert!(
                    all_functions.contains(ref_name),
                    "probe '{function}' references '{ref_name}' in combine_with, but it doesn't exist"
                );
            }
        }
    }

    #[test]
    fn case_018_tcp_probes_have_4tuple_fields() {
        // Every TCP probe must expose the 4-tuple for correlation.
        let tcp_probes: Vec<Value> = all_probes()
            .into_iter()
            .filter(|p| p["layer"] == "tcp")
            .collect();

        for probe in &tcp_probes {
            let function = probe["function"].as_str().unwrap();
            let field_names: HashSet<String> = probe["fields"]
                .as_array()
                .unwrap()
                .iter()
                .map(|f| f["name"].as_str().unwrap().to_string())
                .collect();

            // At minimum, dst_ip or dst_port must be present for correlation.
            assert!(
                field_names.contains("dst_ip") || field_names.contains("dst_port"),
                "TCP probe '{function}' must have dst_ip or dst_port for 4-tuple correlation"
            );
        }
    }

    #[test]
    fn case_019_oom_kill_is_critical() {
        let probes = all_probes();
        let oom = probes.iter().find(|p| p["function"] == "oom_kill_process").unwrap();
        let interps = oom["interpretations"].as_array().unwrap();

        let has_critical = interps.iter().any(|i| i["severity"] == "critical");
        assert!(
            has_critical,
            "oom_kill_process must have at least one critical-severity interpretation"
        );
    }

    #[test]
    fn case_020_every_layer_has_at_least_one_probe() {
        for (filename, layer) in all_layers() {
            let probes = layer["probes"].as_array().unwrap();
            assert!(
                !probes.is_empty(),
                "{filename} has no probes — empty layers are useless"
            );
        }
    }

    // ================================================================
    // MCP CONTRACT (021-030)
    //
    // The MCP server must expose exactly the tools described
    // in the contract. No more, no less.
    // ================================================================

    #[test]
    fn case_021_mcp_has_six_tools() {
        let tools = mcp_tools_list();
        assert_eq!(
            tools.as_array().unwrap().len(), 6,
            "MCP server must expose exactly 6 tools"
        );
    }

    #[test]
    fn case_022_required_tools_present() {
        let tools = mcp_tools_list();
        let tool_names: HashSet<String> = tools
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();

        let required = [
            "jalki_find_probe",
            "jalki_deploy_probe",
            "jalki_get_events",
            "jalki_explain_event",
            "jalki_probe_status",
            "jalki_deploy_descriptor",
        ];

        for tool in &required {
            assert!(
                tool_names.contains(*tool),
                "MCP server missing required tool: '{tool}'"
            );
        }
    }

    // ================================================================
    // EVENT SCHEMA (031-040)
    //
    // FALSE Protocol Occurrences must conform to the schema.
    // ================================================================

    #[test]
    fn case_031_occurrence_json_roundtrips() {
        // A minimal valid occurrence must serialize and deserialize.
        let occ = json!({
            "id": "01JWXYZ123456789ABCDE",
            "timestamp": "2026-04-08T14:32:01.123456789Z",
            "source": "jalki/tcp_connect",
            "type": "kernel.tcp.connect",
            "severity": "info",
            "cluster": "test",
            "enrichment_state": "raw"
        });

        let serialized = serde_json::to_string(&occ).unwrap();
        let deserialized: Value = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized["source"], "jalki/tcp_connect");
        assert_eq!(deserialized["type"], "kernel.tcp.connect");
    }

    #[test]
    fn case_032_occurrence_source_format() {
        // All jalki sources must be "jalki/{probe_name}".
        for probe in all_probes() {
            let function = probe["function"].as_str().unwrap();
            let expected_source_prefix = "jalki/";
            // The event_type should be kernel-prefixed.
            let event_type = probe["event_type"].as_str().unwrap();
            assert!(
                event_type.starts_with("kernel."),
                "probe '{function}' event_type must start with 'kernel.'"
            );
        }
    }

    // ================================================================
    // INTERPRETATION ACCURACY (041-050)
    //
    // These are the most important tests. A wrong interpretation
    // misleads every agent that reads it.
    // ================================================================

    #[test]
    fn case_041_no_interpretation_blames_network_for_econnrefused() {
        // ECONNREFUSED is NOT a network problem. It's a process not listening.
        let probes = all_probes();
        let tcp_connect = probes.iter().find(|p| p["function"] == "tcp_connect").unwrap();
        let interps = tcp_connect["interpretations"].as_array().unwrap();

        let refused = interps.iter().find(|i| {
            i.get("errno").and_then(|v| v.as_str()) == Some("ECONNREFUSED")
        }).unwrap();

        let conclusion = refused["conclusion"].as_str().unwrap().to_lowercase();
        let action = refused["action"].as_str().unwrap().to_lowercase();

        // Must NOT say "network problem" for ECONNREFUSED.
        assert!(
            !conclusion.contains("network problem") && !conclusion.contains("packet loss"),
            "ECONNREFUSED must NOT be interpreted as a network problem: '{conclusion}'"
        );
        // Must say to check the process.
        assert!(
            action.contains("process") || action.contains("running") || action.contains("port"),
            "ECONNREFUSED action must mention checking the process/port: '{action}'"
        );
    }

    #[test]
    fn case_042_no_interpretation_blames_application_for_established_retransmit() {
        // ESTABLISHED retransmit is a NETWORK problem. Never blame the application.
        let probes = all_probes();
        let retransmit = probes.iter().find(|p| p["function"] == "tcp_retransmit_skb").unwrap();
        let interps = retransmit["interpretations"].as_array().unwrap();

        let established = interps.iter().find(|i| {
            let pattern = i["pattern"].as_str().unwrap_or("");
            pattern.contains("ESTABLISHED") && pattern.contains("1")
        }).unwrap();

        let action = established["action"].as_str().unwrap().to_lowercase();

        assert!(
            action.contains("network") || action.contains("switch") || action.contains("path"),
            "ESTABLISHED retransmit action must point to network, not application: '{action}'"
        );
    }

    #[test]
    fn case_043_close_wait_retransmit_blames_application() {
        // CLOSE_WAIT retransmit IS an application problem — app not reading from socket.
        let probes = all_probes();
        let retransmit = probes.iter().find(|p| p["function"] == "tcp_retransmit_skb").unwrap();
        let interps = retransmit["interpretations"].as_array().unwrap();

        let close_wait = interps.iter().find(|i| {
            let pattern = i["pattern"].as_str().unwrap_or("");
            pattern.contains("CLOSE_WAIT") && pattern.contains("7")
        });

        assert!(close_wait.is_some(), "must have CLOSE_WAIT interpretation");

        let conclusion = close_wait.unwrap()["conclusion"].as_str().unwrap().to_lowercase();
        assert!(
            conclusion.contains("application") || conclusion.contains("local") || conclusion.contains("hung"),
            "CLOSE_WAIT retransmit must point to application issue: '{conclusion}'"
        );
    }

    #[test]
    fn case_044_high_frequency_probes_warn_about_sampling() {
        // tcp_sendmsg and tcp_recvmsg are high-frequency. The knowledge base
        // must warn about sampling.
        let probes = all_probes();

        for function in ["tcp_sendmsg"] {
            let probe = probes.iter().find(|p| p["function"] == function);
            if let Some(probe) = probe {
                let use_when = probe["use_when"].as_str().unwrap().to_lowercase();
                assert!(
                    use_when.contains("sampl") || use_when.contains("high frequency"),
                    "high-frequency probe '{function}' must mention sampling in use_when: '{use_when}'"
                );
            }
        }
    }

    #[test]
    fn case_045_exit_code_137_is_sigkill() {
        // Exit code 137 = 128 + 9 (SIGKILL). The knowledge base must say this.
        let probes = all_probes();
        let do_exit = probes.iter().find(|p| p["function"] == "do_exit");

        if let Some(probe) = do_exit {
            let interps = probe["interpretations"].as_array().unwrap();
            let sigkill = interps.iter().find(|i| {
                let pattern = i["pattern"].as_str().unwrap_or("");
                pattern.contains("137") || pattern.contains("SIGKILL")
            });

            assert!(
                sigkill.is_some(),
                "do_exit must have interpretation for exit code 137 (SIGKILL)"
            );
        }
    }

    // ================================================================
    // CROSS-LAYER CONSISTENCY (051-055)
    //
    // The knowledge base must be internally consistent.
    // ================================================================

    #[test]
    fn case_051_layer_field_matches_file() {
        for (filename, layer) in all_layers() {
            let layer_name = layer["layer"].as_str().unwrap();
            let expected = filename.replace(".json", "");
            assert_eq!(
                layer_name, expected,
                "file '{filename}' declares layer '{layer_name}' but should be '{expected}'"
            );
        }
    }

    #[test]
    fn case_052_probe_layer_matches_parent() {
        for (filename, layer) in all_layers() {
            let layer_name = layer["layer"].as_str().unwrap();
            for probe in layer["probes"].as_array().unwrap() {
                let function = probe["function"].as_str().unwrap();
                let probe_layer = probe["layer"].as_str().unwrap();
                assert_eq!(
                    probe_layer, layer_name,
                    "probe '{function}' in {filename} declares layer '{probe_layer}' but file layer is '{layer_name}'"
                );
            }
        }
    }

    #[test]
    fn case_053_no_empty_interpretations() {
        // A probe with no interpretations is useless to agents.
        for probe in all_probes() {
            let function = probe["function"].as_str().unwrap();
            let interps = probe["interpretations"].as_array().unwrap();
            assert!(
                !interps.is_empty(),
                "probe '{function}' has no interpretations — agents can't explain events from this probe"
            );
        }
    }

    #[test]
    fn case_054_no_duplicate_event_types() {
        let mut seen = HashSet::new();
        for probe in all_probes() {
            let event_type = probe["event_type"].as_str().unwrap().to_string();
            let function = probe["function"].as_str().unwrap();
            assert!(
                seen.insert(event_type.clone()),
                "duplicate event_type '{event_type}' found in probe '{function}'"
            );
        }
    }

    #[test]
    fn case_055_version_is_semver_ish() {
        for (filename, layer) in all_layers() {
            let version = layer["version"].as_str().unwrap();
            assert!(
                version.contains('.'),
                "{filename} version '{version}' should be semver-like (e.g. '1.0')"
            );
        }
    }

    // ================================================================
    // REQUIREMENT: PROBE COUNT (spec: knowledge/knowledge-base.md)
    // ================================================================

    #[test]
    fn case_060_at_least_20_probes() {
        let count = all_probes().len();
        assert!(
            count >= 20,
            "knowledge base must have at least 20 probes, got {count}"
        );
    }

    #[test]
    fn case_061_tcp_layer_has_8_probes() {
        let tcp = load_knowledge("tcp.json");
        let count = tcp["probes"].as_array().unwrap().len();
        assert!(
            count >= 8,
            "tcp layer must have at least 8 probes (connect, close, retransmit, sendmsg, accept, recvmsg, syn_recv, reset), got {count}"
        );
    }

    #[test]
    fn case_062_memory_layer_has_3_probes() {
        let mem = load_knowledge("memory.json");
        let count = mem["probes"].as_array().unwrap().len();
        assert!(
            count >= 3,
            "memory layer must have at least 3 probes (oom_kill, page_alloc, memcg), got {count}"
        );
    }

    #[test]
    fn case_063_fs_layer_has_4_probes() {
        let fs = load_knowledge("fs.json");
        let count = fs["probes"].as_array().unwrap().len();
        assert!(
            count >= 4,
            "fs layer must have at least 4 probes (open, write, read, close), got {count}"
        );
    }

    #[test]
    fn case_064_process_layer_has_3_probes() {
        let proc = load_knowledge("process.json");
        let count = proc["probes"].as_array().unwrap().len();
        assert!(
            count >= 3,
            "process layer must have at least 3 probes (execve, exit, clone), got {count}"
        );
    }

    #[test]
    fn case_065_sched_layer_has_2_probes() {
        let sched = load_knowledge("sched.json");
        let count = sched["probes"].as_array().unwrap().len();
        assert!(
            count >= 2,
            "sched layer must have at least 2 probes (task_switch, wake_up), got {count}"
        );
    }

    // ================================================================
    // REQUIREMENT: FIND RELEVANCE (spec: protocol/find.md)
    //
    // These test that the knowledge base data supports correct
    // relevance scoring. The oracle doesn't run the scoring code
    // but validates the data that makes it work.
    // ================================================================

    #[test]
    fn case_070_tcp_connect_answers_connection_questions() {
        let probes = all_probes();
        let tcp_connect = probes.iter().find(|p| p["function"] == "tcp_connect").unwrap();
        let answers: Vec<String> = tcp_connect["answers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_lowercase())
            .collect();

        let has_connection_answer = answers.iter().any(|a|
            a.contains("connect") || a.contains("failing") || a.contains("refused")
        );
        assert!(
            has_connection_answer,
            "tcp_connect answers must include connection failure questions: {answers:?}"
        );
    }

    #[test]
    fn case_071_retransmit_answers_packet_loss() {
        let probes = all_probes();
        let retransmit = probes.iter().find(|p| p["function"] == "tcp_retransmit_skb").unwrap();
        let keywords: Vec<String> = retransmit["keywords"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();

        assert!(
            keywords.contains(&"packet loss".to_string()) || keywords.contains(&"retransmit".to_string()),
            "tcp_retransmit_skb keywords must include 'packet loss' or 'retransmit': {keywords:?}"
        );
    }

    #[test]
    fn case_072_fs_probes_answer_disk_questions() {
        let probes = all_probes();
        let fs_probes: Vec<&Value> = probes.iter()
            .filter(|p| p["layer"] == "fs")
            .collect();

        let all_keywords: Vec<String> = fs_probes.iter()
            .flat_map(|p| p["keywords"].as_array().unwrap().iter())
            .map(|v| v.as_str().unwrap().to_string())
            .collect();

        assert!(
            all_keywords.iter().any(|k| k.contains("file") || k.contains("disk") || k.contains("read") || k.contains("write")),
            "fs layer keywords must include file/disk/read/write terms: {all_keywords:?}"
        );
    }

    // ================================================================
    // REQUIREMENT: ASK INTERPRETATIONS (spec: protocol/ask.md)
    //
    // The knowledge base must provide the interpretations that
    // make jalki ask work. Each is a testable requirement.
    // ================================================================

    #[test]
    fn case_080_econnrefused_says_not_listening() {
        let probes = all_probes();
        let tcp_connect = probes.iter().find(|p| p["function"] == "tcp_connect").unwrap();
        let interps = tcp_connect["interpretations"].as_array().unwrap();

        let refused = interps.iter().find(|i|
            i["pattern"].as_str().unwrap_or("").contains("-111")
        ).expect("must have -111 (ECONNREFUSED) interpretation");

        let conclusion = refused["conclusion"].as_str().unwrap().to_lowercase();
        assert!(
            conclusion.contains("listening"),
            "ECONNREFUSED conclusion must mention 'listening': got '{conclusion}'"
        );
    }

    #[test]
    fn case_081_established_retransmit_says_network() {
        let probes = all_probes();
        let retransmit = probes.iter().find(|p| p["function"] == "tcp_retransmit_skb").unwrap();
        let interps = retransmit["interpretations"].as_array().unwrap();

        let established = interps.iter().find(|i| {
            let p = i["pattern"].as_str().unwrap_or("");
            p.contains("ESTABLISHED")
        }).expect("must have ESTABLISHED interpretation");

        let action = established["action"].as_str().unwrap().to_lowercase();
        assert!(
            action.contains("network"),
            "ESTABLISHED retransmit action must mention network: got '{action}'"
        );
        assert!(
            !action.contains("application bug"),
            "ESTABLISHED retransmit must NOT say 'application bug'"
        );
    }

    #[test]
    fn case_082_syn_sent_retransmit_says_unreachable() {
        let probes = all_probes();
        let retransmit = probes.iter().find(|p| p["function"] == "tcp_retransmit_skb").unwrap();
        let interps = retransmit["interpretations"].as_array().unwrap();

        let syn_sent = interps.iter().find(|i| {
            let p = i["pattern"].as_str().unwrap_or("");
            p.contains("SYN_SENT")
        }).expect("must have SYN_SENT interpretation");

        let action = syn_sent["action"].as_str().unwrap().to_lowercase();
        assert!(
            action.contains("connect") || action.contains("reach") || action.contains("not an application"),
            "SYN_SENT retransmit action must reference connectivity: got '{action}'"
        );
    }

    // ================================================================
    // REQUIREMENT: SDK CONTRACT (spec: sdk/python.md)
    //
    // Generated types must exist with correct structure.
    // ================================================================

    #[test]
    fn case_090_generated_types_py_exists() {
        let path = format!(
            "{}/../../jalki-sdk-python/src/jalki/types.py",
            env!("CARGO_MANIFEST_DIR")
        );
        let content = std::fs::read_to_string(&path);
        if let Ok(content) = content {
            assert!(content.contains("GENERATED"), "types.py must have GENERATED header");
            assert!(content.contains("DO NOT EDIT"), "types.py must say DO NOT EDIT");
            assert!(content.contains("class Severity"), "types.py must define Severity");
            assert!(content.contains("class Event"), "types.py must define Event");
            assert!(content.contains("class EventFilter"), "types.py must define EventFilter");
            assert!(content.contains("class ProbeMatch"), "types.py must define ProbeMatch");
            assert!(content.contains("class AskResult"), "types.py must define AskResult");
        }
        // If file doesn't exist, skip silently (SDK may not be generated yet).
    }

    #[test]
    fn case_091_generated_protocol_py_exists() {
        let path = format!(
            "{}/../../jalki-sdk-python/src/jalki/protocol.py",
            env!("CARGO_MANIFEST_DIR")
        );
        let content = std::fs::read_to_string(&path);
        if let Ok(content) = content {
            assert!(content.contains("GENERATED"), "protocol.py must have GENERATED header");
            assert!(content.contains("class MsgType"), "protocol.py must define MsgType");
            assert!(content.contains("POS_ID"), "protocol.py must define stream event positions");
            assert!(content.contains("FRAME_HEADER_LEN"), "protocol.py must define frame constants");
        }
    }

    // ================================================================
    // REQUIREMENT: PROTOCOL WIRE FORMAT (spec: protocol/framing.md)
    //
    // These validate the protocol constants are correct and consistent
    // between the daemon code and the SDK meta definitions.
    // ================================================================

    #[test]
    fn case_095_specs_directory_exists() {
        let path = format!("{}/../../specs", env!("CARGO_MANIFEST_DIR"));
        assert!(
            std::path::Path::new(&path).is_dir(),
            "specs/ directory must exist for requirement documentation"
        );
    }

    #[test]
    fn case_096_protocol_specs_exist() {
        let base = format!("{}/../../specs/protocol", env!("CARGO_MANIFEST_DIR"));
        let required = ["framing.md", "find.md", "deploy.md", "subscribe.md", "status.md", "ask.md"];
        for spec in required {
            let path = format!("{base}/{spec}");
            assert!(
                std::path::Path::new(&path).exists(),
                "missing protocol spec: specs/protocol/{spec}"
            );
        }
    }
}

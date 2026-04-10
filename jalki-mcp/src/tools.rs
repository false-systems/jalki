use serde_json::{json, Value};

use jalki::ipc;
use jalki::knowledge::{EventFields, KnowledgeBase};

/// Shared state for the MCP server.
pub struct JalkiState {
    kb: KnowledgeBase,
}

impl JalkiState {
    pub fn new() -> Self {
        Self {
            kb: KnowledgeBase::load(),
        }
    }

    pub async fn handle(&self, method: &str, params: Option<Value>) -> Result<Value, String> {
        match method {
            "initialize" => self.handle_initialize(),
            "tools/list" => self.handle_tools_list(),
            "tools/call" => self.handle_tools_call(params).await,
            _ => Err(format!("unknown method: {method}")),
        }
    }

    fn handle_initialize(&self) -> Result<Value, String> {
        Ok(json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "tools": {}
            },
            "serverInfo": {
                "name": "jalki-mcp",
                "version": "0.1.0"
            }
        }))
    }

    fn handle_tools_list(&self) -> Result<Value, String> {
        Ok(json!({
            "tools": [
                {
                    "name": "jalki_find_probe",
                    "description": "Find which kernel probe answers your question. Always call this first — do not guess function names. Returns matching probes from the knowledge base ranked by relevance.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "question": {
                                "type": "string",
                                "description": "Natural language question about what you want to observe. Examples: 'why are connections failing', 'is the network dropping packets', 'which process is connecting to port 5432'"
                            }
                        },
                        "required": ["question"]
                    }
                },
                {
                    "name": "jalki_deploy_probe",
                    "description": "Attach a kernel probe by function name. The probe starts collecting events immediately. Use jalki_find_probe first to identify the right function.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "function": {
                                "type": "string",
                                "description": "Kernel function name, e.g. 'tcp_retransmit_skb', 'tcp_connect'"
                            },
                            "sample_rate": {
                                "type": "number",
                                "description": "Sampling rate 0.0-1.0. Default 1.0 (all events). Use 0.1 for high-frequency probes like tcp_sendmsg."
                            }
                        },
                        "required": ["function"]
                    }
                },
                {
                    "name": "jalki_get_events",
                    "description": "Retrieve collected events from an attached probe. Filter by IP, port, PID, or time window.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "probe_id": {
                                "type": "string",
                                "description": "Probe ID returned by jalki_deploy_probe"
                            },
                            "last_seconds": {
                                "type": "integer",
                                "description": "Only return events from the last N seconds. Default: 60"
                            },
                            "filter": {
                                "type": "object",
                                "properties": {
                                    "src_ip": { "type": "string" },
                                    "dst_ip": { "type": "string" },
                                    "src_port": { "type": "integer" },
                                    "dst_port": { "type": "integer" },
                                    "pid": { "type": "integer" },
                                    "command": { "type": "string" }
                                },
                                "description": "Filter events by network tuple, process, or command"
                            }
                        },
                        "required": ["probe_id"]
                    }
                },
                {
                    "name": "jalki_explain_event",
                    "description": "Interpret a kernel event using the knowledge base. Returns conclusion, severity, recommended action, and common misdiagnoses to avoid.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "function": {
                                "type": "string",
                                "description": "Kernel function that generated the event"
                            },
                            "ret": {
                                "type": "integer",
                                "description": "Return value (for fexit probes). Negative = errno."
                            },
                            "tcp_state": {
                                "type": "integer",
                                "description": "TCP state value (for tcp_retransmit_skb). 1=ESTABLISHED, 2=SYN_SENT, etc."
                            }
                        },
                        "required": ["function"]
                    }
                },
                {
                    "name": "jalki_probe_status",
                    "description": "List all attached probes with event counts, drop counts, and attachment time.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {}
                    }
                },
                {
                    "name": "jalki_deploy_descriptor",
                    "description": "Deploy a probe from a descriptor — the foundation for SDK-driven probe deployment. Specifies function, attachment type, fields, filter, and sampling.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "function": {
                                "type": "string",
                                "description": "Kernel function to hook"
                            },
                            "attachment": {
                                "type": "string",
                                "enum": ["fentry", "fexit"],
                                "description": "Hook type. Use fexit when you need the return value."
                            },
                            "fields": {
                                "type": "array",
                                "items": { "type": "string" },
                                "description": "Fields to extract from the event"
                            },
                            "filter": {
                                "type": "object",
                                "properties": {
                                    "dst_port": { "type": "integer" },
                                    "src_ip": { "type": "string" },
                                    "pid": { "type": "integer" },
                                    "command": { "type": "string" }
                                }
                            },
                            "sample_rate": {
                                "type": "number",
                                "description": "Sampling rate 0.0-1.0"
                            },
                            "event_type": {
                                "type": "string",
                                "description": "FALSE Protocol occurrence type"
                            }
                        },
                        "required": ["function", "attachment", "event_type"]
                    }
                }
            ]
        }))
    }

    async fn handle_tools_call(&self, params: Option<Value>) -> Result<Value, String> {
        let params = params.ok_or("missing params")?;
        let tool_name = params
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or("missing tool name")?;
        let args = params.get("arguments").cloned().unwrap_or(json!({}));

        let result = match tool_name {
            "jalki_find_probe" => self.tool_find_probe(args),
            "jalki_deploy_probe" => self.tool_deploy_probe(args).await,
            "jalki_get_events" => self.tool_get_events(args).await,
            "jalki_explain_event" => self.tool_explain_event(args),
            "jalki_probe_status" => self.tool_probe_status(args).await,
            "jalki_deploy_descriptor" => self.tool_deploy_descriptor(args).await,
            _ => Err(format!("unknown tool: {tool_name}")),
        };

        match result {
            Ok(content) => Ok(json!({
                "content": [{ "type": "text", "text": serde_json::to_string_pretty(&content).unwrap_or_default() }]
            })),
            Err(e) => Ok(json!({
                "content": [{ "type": "text", "text": e }],
                "isError": true
            })),
        }
    }

    // === Tool Implementations ===

    /// find_probe runs locally — the knowledge base is compiled into the MCP binary too.
    fn tool_find_probe(&self, args: Value) -> Result<Value, String> {
        let question = args
            .get("question")
            .and_then(|v| v.as_str())
            .ok_or("missing 'question' argument")?;

        let matches = self.kb.find_probes(question);

        let results: Vec<Value> = matches
            .iter()
            .take(5)
            .map(|probe| {
                json!({
                    "function": probe.function,
                    "attachment": probe.attachment,
                    "event_type": probe.event_type,
                    "why": probe.use_when,
                    "combine_with": probe.combine_with,
                    "fields": probe.fields.iter()
                        .filter(|f| f.important)
                        .map(|f| json!({ "name": f.name, "meaning": f.meaning }))
                        .collect::<Vec<_>>(),
                })
            })
            .collect();

        if results.is_empty() {
            return Ok(json!({
                "matches": [],
                "suggestion": "No matching probes found. Try broader keywords like 'connect', 'retransmit', 'send', 'accept'."
            }));
        }

        Ok(json!({ "matches": results }))
    }

    /// explain_event runs locally — pure knowledge base lookup, no daemon needed.
    fn tool_explain_event(&self, args: Value) -> Result<Value, String> {
        let function = args
            .get("function")
            .and_then(|v| v.as_str())
            .ok_or("missing 'function' argument")?;

        let fields = EventFields {
            ret: args.get("ret").and_then(|v| v.as_i64()).map(|v| v as i32),
            tcp_state: args.get("tcp_state").and_then(|v| v.as_u64()).map(|v| v as u8),
        };

        let interpretations = self.kb.explain(function, &fields);

        if interpretations.is_empty() {
            if let Some(probe) = self.kb.get_probe(function) {
                return Ok(json!({
                    "function": function,
                    "conclusion": "No specific interpretation matches these field values.",
                    "probe_info": {
                        "use_when": probe.use_when,
                        "combine_with": probe.combine_with,
                    }
                }));
            }
            return Err(format!("unknown function '{function}'"));
        }

        let best = &interpretations[0];
        Ok(json!({
            "function": function,
            "pattern": best.pattern,
            "conclusion": best.conclusion,
            "severity": best.severity,
            "action": best.action,
            "errno": best.errno,
        }))
    }

    /// deploy_probe forwards to the daemon via IPC.
    async fn tool_deploy_probe(&self, args: Value) -> Result<Value, String> {
        let function = args
            .get("function")
            .and_then(|v| v.as_str())
            .ok_or("missing 'function' argument")?;

        let sample_rate = args
            .get("sample_rate")
            .and_then(|v| v.as_f64())
            .unwrap_or(1.0);

        // Validate locally first.
        if self.kb.get_probe(function).is_none() {
            return Err(format!(
                "unknown function '{}'. Use jalki_find_probe to search the knowledge base.",
                function
            ));
        }

        let resp = ipc::call(
            "deploy_probe",
            json!({ "function": function, "sample_rate": sample_rate }),
        )
        .await
        .map_err(|e| format!("daemon connection failed: {e}"))?;

        if resp.ok {
            Ok(resp.result.unwrap_or(json!(null)))
        } else {
            Err(resp.error.unwrap_or_else(|| "unknown error".into()))
        }
    }

    /// get_events forwards to the daemon via IPC.
    async fn tool_get_events(&self, args: Value) -> Result<Value, String> {
        let resp = ipc::call("get_events", args)
            .await
            .map_err(|e| format!("daemon connection failed: {e}"))?;

        if resp.ok {
            Ok(resp.result.unwrap_or(json!(null)))
        } else {
            Err(resp.error.unwrap_or_else(|| "unknown error".into()))
        }
    }

    /// probe_status forwards to the daemon via IPC.
    async fn tool_probe_status(&self, _args: Value) -> Result<Value, String> {
        let resp = ipc::call("probe_status", json!({}))
            .await
            .map_err(|e| format!("daemon connection failed: {e}"))?;

        if resp.ok {
            Ok(resp.result.unwrap_or(json!(null)))
        } else {
            Err(resp.error.unwrap_or_else(|| "unknown error".into()))
        }
    }

    /// deploy_descriptor forwards to the daemon via IPC as a deploy_probe call.
    async fn tool_deploy_descriptor(&self, args: Value) -> Result<Value, String> {
        let function = args
            .get("function")
            .and_then(|v| v.as_str())
            .ok_or("missing 'function'")?;

        let attachment = args
            .get("attachment")
            .and_then(|v| v.as_str())
            .ok_or("missing 'attachment'")?;

        // Validate the descriptor against the knowledge base.
        if let Some(probe) = self.kb.get_probe(function) {
            if probe.attachment != attachment {
                return Err(format!(
                    "knowledge base recommends '{}' for {}, not '{}'",
                    probe.attachment, function, attachment
                ));
            }
        }

        let sample_rate = args
            .get("sample_rate")
            .and_then(|v| v.as_f64())
            .unwrap_or(1.0);

        let resp = ipc::call(
            "deploy_probe",
            json!({ "function": function, "sample_rate": sample_rate }),
        )
        .await
        .map_err(|e| format!("daemon connection failed: {e}"))?;

        if resp.ok {
            // Augment with descriptor metadata.
            let mut result = resp.result.unwrap_or(json!({}));
            if let Some(obj) = result.as_object_mut() {
                obj.insert("attachment".into(), json!(attachment));
                obj.insert(
                    "event_type".into(),
                    args.get("event_type").cloned().unwrap_or(json!(null)),
                );
            }
            Ok(result)
        } else {
            Err(resp.error.unwrap_or_else(|| "unknown error".into()))
        }
    }
}

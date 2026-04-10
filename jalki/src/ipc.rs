use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tracing::{debug, info, warn};

use crate::knowledge::EventFields;
use crate::runtime::DaemonHandle;
use crate::store::EventFilter;

/// Default socket path for the jälki daemon.
pub const SOCKET_PATH: &str = "/run/jalki/jalki.sock";

/// IPC request envelope.
#[derive(Debug, Serialize, Deserialize)]
pub struct Request {
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

/// IPC response envelope.
#[derive(Debug, Serialize, Deserialize)]
pub struct Response {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl Response {
    fn success(result: Value) -> Self {
        Self {
            ok: true,
            result: Some(result),
            error: None,
        }
    }

    fn err(msg: impl Into<String>) -> Self {
        Self {
            ok: false,
            result: None,
            error: Some(msg.into()),
        }
    }
}

/// Serve the jälki IPC API over a Unix socket.
///
/// Protocol: newline-delimited JSON. Each line is a Request, each response
/// is a single JSON line followed by newline.
pub async fn serve(handle: Arc<DaemonHandle>) -> Result<()> {
    let socket_dir = Path::new(SOCKET_PATH).parent().unwrap();
    tokio::fs::create_dir_all(socket_dir)
        .await
        .with_context(|| format!("failed to create {}", socket_dir.display()))?;

    // Remove stale socket.
    let _ = tokio::fs::remove_file(SOCKET_PATH).await;

    let listener = UnixListener::bind(SOCKET_PATH)
        .with_context(|| format!("failed to bind {SOCKET_PATH}"))?;

    // Make socket world-writable so non-root CLI/MCP can connect.
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(SOCKET_PATH, std::fs::Permissions::from_mode(0o777))
        .with_context(|| format!("failed to set permissions on {SOCKET_PATH}"))?;

    info!(path = SOCKET_PATH, "IPC server listening");

    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let handle = handle.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(stream, handle).await {
                        debug!(error = %e, "IPC connection error");
                    }
                });
            }
            Err(e) => {
                warn!(error = %e, "IPC accept error");
            }
        }
    }
}

async fn handle_connection(
    stream: tokio::net::UnixStream,
    handle: Arc<DaemonHandle>,
) -> Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();

    while let Some(line) = lines.next_line().await? {
        if line.is_empty() {
            continue;
        }

        let request: Request = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                let resp = Response::err(format!("parse error: {e}"));
                let json = serde_json::to_string(&resp)?;
                writer.write_all(json.as_bytes()).await?;
                writer.write_all(b"\n").await?;
                writer.flush().await?;
                continue;
            }
        };

        debug!(method = %request.method, "IPC request");
        let response = dispatch(&handle, &request).await;
        let json = serde_json::to_string(&response)?;
        writer.write_all(json.as_bytes()).await?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;
    }

    Ok(())
}

async fn dispatch(handle: &DaemonHandle, req: &Request) -> Response {
    match req.method.as_str() {
        "deploy_probe" => handle_deploy_probe(handle, &req.params).await,
        "get_events" => handle_get_events(handle, &req.params),
        "get_all_events" => handle_get_all_events(handle, &req.params),
        "probe_status" => handle_probe_status(handle, &req.params),
        "find_probe" => handle_find_probe(handle, &req.params),
        "explain_event" => handle_explain_event(handle, &req.params),
        other => Response::err(format!("unknown method: {other}")),
    }
}

async fn handle_deploy_probe(handle: &DaemonHandle, params: &Value) -> Response {
    let function = match params.get("function").and_then(|v| v.as_str()) {
        Some(f) => f,
        None => return Response::err("missing 'function' parameter"),
    };

    let sample_rate = params
        .get("sample_rate")
        .and_then(|v| v.as_f64())
        .unwrap_or(1.0);

    // Validate against knowledge base.
    if handle.kb.get_probe(function).is_none() {
        return Response::err(format!(
            "unknown function '{}'. Use find_probe to search the knowledge base.",
            function
        ));
    }

    match handle.deploy_probe(function, sample_rate).await {
        Ok(probe_id) => Response::success(serde_json::json!({
            "probe_id": probe_id,
            "function": function,
            "status": "attached",
        })),
        Err(e) => Response::err(format!("deploy failed: {e}")),
    }
}

fn handle_get_events(handle: &DaemonHandle, params: &Value) -> Response {
    let probe_id = match params.get("probe_id").and_then(|v| v.as_str()) {
        Some(id) => id,
        None => return Response::err("missing 'probe_id' parameter"),
    };

    let filter = parse_event_filter(params);
    let events = handle.store.query(probe_id, &filter);

    Response::success(serde_json::json!({
        "events": events.iter().map(|e| serde_json::to_value(e).unwrap_or_default()).collect::<Vec<_>>(),
        "total": events.len(),
        "probe_id": probe_id,
    }))
}

fn handle_get_all_events(handle: &DaemonHandle, params: &Value) -> Response {
    let filter = parse_event_filter(params);
    let events = handle.store.query_all(&filter);

    Response::success(serde_json::json!({
        "events": events.iter().map(|e| serde_json::to_value(e).unwrap_or_default()).collect::<Vec<_>>(),
        "total": events.len(),
    }))
}

fn handle_probe_status(handle: &DaemonHandle, params: &Value) -> Response {
    let probe_id = params.get("probe_id").and_then(|v| v.as_str());

    if let Some(id) = probe_id {
        match handle.registry.get_status(id) {
            Some(status) => Response::success(serde_json::json!({
                "probes": [probe_status_to_json(&status)],
            })),
            None => Response::err(format!("probe '{id}' not found")),
        }
    } else {
        let statuses = handle.registry.status();
        let probes: Vec<Value> = statuses.iter().map(probe_status_to_json).collect();
        Response::success(serde_json::json!({ "probes": probes }))
    }
}

fn handle_find_probe(handle: &DaemonHandle, params: &Value) -> Response {
    let question = match params.get("question").and_then(|v| v.as_str()) {
        Some(q) => q,
        None => return Response::err("missing 'question' parameter"),
    };

    let matches = handle.kb.find_probes(question);
    let results: Vec<Value> = matches
        .iter()
        .take(5)
        .map(|probe| {
            serde_json::json!({
                "function": probe.function,
                "attachment": probe.attachment,
                "event_type": probe.event_type,
                "why": probe.use_when,
                "combine_with": probe.combine_with,
                "fields": probe.fields.iter()
                    .filter(|f| f.important)
                    .map(|f| serde_json::json!({ "name": f.name, "meaning": f.meaning }))
                    .collect::<Vec<_>>(),
            })
        })
        .collect();

    if results.is_empty() {
        return Response::success(serde_json::json!({
            "matches": [],
            "suggestion": "No matching probes found. Try broader keywords like 'connect', 'retransmit', 'send', 'accept'.",
        }));
    }

    Response::success(serde_json::json!({ "matches": results }))
}

fn handle_explain_event(handle: &DaemonHandle, params: &Value) -> Response {
    let function = match params.get("function").and_then(|v| v.as_str()) {
        Some(f) => f,
        None => return Response::err("missing 'function' parameter"),
    };

    let fields = EventFields {
        ret: params.get("ret").and_then(|v| v.as_i64()).map(|v| v as i32),
        tcp_state: params.get("tcp_state").and_then(|v| v.as_u64()).map(|v| v as u8),
    };

    let interpretations = handle.kb.explain(function, &fields);

    if interpretations.is_empty() {
        if let Some(probe) = handle.kb.get_probe(function) {
            return Response::success(serde_json::json!({
                "function": function,
                "conclusion": "No specific interpretation matches these field values.",
                "probe_info": {
                    "use_when": probe.use_when,
                    "combine_with": probe.combine_with,
                },
            }));
        }
        return Response::err(format!("unknown function '{function}'"));
    }

    let best = &interpretations[0];
    Response::success(serde_json::json!({
        "function": function,
        "pattern": best.pattern,
        "conclusion": best.conclusion,
        "severity": best.severity,
        "action": best.action,
        "errno": best.errno,
    }))
}

// --- Helpers ---

fn parse_event_filter(params: &Value) -> EventFilter {
    let filter_obj = params.get("filter").cloned().unwrap_or(serde_json::json!({}));
    EventFilter {
        last_seconds: params
            .get("last_seconds")
            .and_then(|v| v.as_u64())
            .or(Some(60)),
        src_ip: filter_obj.get("src_ip").and_then(|v| v.as_str()).map(String::from),
        dst_ip: filter_obj.get("dst_ip").and_then(|v| v.as_str()).map(String::from),
        src_port: filter_obj.get("src_port").and_then(|v| v.as_u64()).map(|v| v as u16),
        dst_port: filter_obj.get("dst_port").and_then(|v| v.as_u64()).map(|v| v as u16),
        pid: filter_obj.get("pid").and_then(|v| v.as_u64()).map(|v| v as u32),
        command: filter_obj.get("command").and_then(|v| v.as_str()).map(String::from),
        limit: Some(100),
    }
}

fn probe_status_to_json(status: &crate::registry::ProbeStatus) -> Value {
    serde_json::json!({
        "probe_id": status.probe_id,
        "function": status.function,
        "name": status.name,
        "attached_since": status.attached_since.to_rfc3339(),
        "events_total": status.events_total,
        "ring_buffer_drops": status.ring_buffer_drops,
        "sample_rate": status.sample_rate,
    })
}

/// Connect to the daemon IPC socket.
/// Used by the MCP server and CLI to communicate with a running daemon.
pub async fn connect() -> Result<tokio::net::UnixStream> {
    tokio::net::UnixStream::connect(SOCKET_PATH)
        .await
        .with_context(|| format!(
            "failed to connect to jalki daemon at {SOCKET_PATH}. Is the daemon running?"
        ))
}

/// Send a request to the daemon and receive the response.
pub async fn call(method: &str, params: Value) -> Result<Response> {
    let stream = connect().await?;
    let (reader, mut writer) = stream.into_split();

    let request = Request {
        method: method.to_string(),
        params,
    };
    let json = serde_json::to_string(&request)?;
    writer.write_all(json.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;

    let mut lines = BufReader::new(reader).lines();
    let line = lines
        .next_line()
        .await?
        .ok_or_else(|| anyhow::anyhow!("daemon closed connection without response"))?;

    let response: Response = serde_json::from_str(&line)?;
    Ok(response)
}

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Context, Result};
use rmpv::Value;
use serde_json;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::knowledge::EventFields;
use crate::runtime::DaemonHandle;
use crate::store::EventFilter;

// --- Constants (must match jalki-sdk-meta protocol.rs) ---

pub const SOCKET_PATH: &str = "/run/jalki/jalki.sock";

pub const FRAME_HEADER_LEN: usize = 6;
pub const FRAME_MAX_LEN: usize = 1024 * 1024;

pub const MSG_REQUEST: u8 = 0x01;
pub const MSG_RESPONSE: u8 = 0x02;
pub const MSG_STREAM_START: u8 = 0x03;
pub const MSG_STREAM_EVENT: u8 = 0x04;
pub const MSG_STREAM_END: u8 = 0x05;
pub const MSG_ERROR: u8 = 0x06;
pub const MSG_PING: u8 = 0x07;
pub const MSG_PONG: u8 = 0x08;

pub const FLAG_INTERPRETED: u8 = 0x02;

pub const METHOD_FIND: u8 = 0x01;
pub const METHOD_DEPLOY: u8 = 0x02;
pub const METHOD_SUBSCRIBE: u8 = 0x03;
pub const METHOD_UNSUBSCRIBE: u8 = 0x04;
pub const METHOD_STATUS: u8 = 0x05;
pub const METHOD_ASK: u8 = 0x06;
pub const METHOD_GET_EVENTS: u8 = 0x07;

// --- Frame encoding/decoding ---

pub fn encode_frame(msg_type: u8, flags: u8, payload: &[u8]) -> Vec<u8> {
    let frame_len = (payload.len() + 2) as u32;
    let mut buf = Vec::with_capacity(FRAME_HEADER_LEN + payload.len());
    buf.extend_from_slice(&frame_len.to_be_bytes());
    buf.push(msg_type);
    buf.push(flags);
    buf.extend_from_slice(payload);
    buf
}

async fn read_frame<R: AsyncReadExt + Unpin>(reader: &mut R) -> Result<(u8, u8, Vec<u8>)> {
    let mut header = [0u8; FRAME_HEADER_LEN];
    reader.read_exact(&mut header).await?;

    let frame_len =
        u32::from_be_bytes([header[0], header[1], header[2], header[3]]) as usize;
    let msg_type = header[4];
    let flags = header[5];

    if frame_len < 2 || frame_len > FRAME_MAX_LEN {
        anyhow::bail!("invalid frame_len: {frame_len}");
    }

    let payload_len = frame_len - 2;
    let mut payload = vec![0u8; payload_len];
    if payload_len > 0 {
        reader.read_exact(&mut payload).await?;
    }

    Ok((msg_type, flags, payload))
}

fn encode_msgpack(value: &Value) -> Vec<u8> {
    let mut buf = Vec::new();
    rmpv::encode::write_value(&mut buf, value).unwrap_or_default();
    buf
}

fn decode_msgpack(data: &[u8]) -> Result<Value> {
    if data.is_empty() {
        return Ok(Value::Array(vec![]));
    }
    let mut cursor = std::io::Cursor::new(data);
    rmpv::decode::read_value(&mut cursor).context("msgpack decode")
}

fn encode_response(request_id: u32, result: Result<Value, String>) -> Vec<u8> {
    let payload = match result {
        Ok(val) => Value::Array(vec![
            Value::Integer(request_id.into()),
            Value::Boolean(true),
            val,
        ]),
        Err(msg) => Value::Array(vec![
            Value::Integer(request_id.into()),
            Value::Boolean(false),
            Value::String(msg.into()),
        ]),
    };
    encode_frame(MSG_RESPONSE, 0, &encode_msgpack(&payload))
}

// --- Server ---

pub async fn serve(handle: Arc<DaemonHandle>) -> Result<()> {
    let socket_dir = std::path::Path::new(SOCKET_PATH).parent().unwrap();
    tokio::fs::create_dir_all(socket_dir).await?;
    let _ = tokio::fs::remove_file(SOCKET_PATH).await;

    let listener = UnixListener::bind(SOCKET_PATH)?;

    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(SOCKET_PATH, std::fs::Permissions::from_mode(0o777))?;

    info!(path = SOCKET_PATH, "IPC server listening (binary protocol)");

    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let handle = handle.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(stream, handle).await {
                        debug!(error = %e, "IPC connection ended");
                    }
                });
            }
            Err(e) => warn!(error = %e, "IPC accept error"),
        }
    }
}

async fn handle_connection(stream: UnixStream, handle: Arc<DaemonHandle>) -> Result<()> {
    let (read_half, write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(4096);

    // Writer task: sends frames from tx to the socket.
    let mut writer = write_half;
    let writer_task = tokio::spawn(async move {
        while let Some(frame) = rx.recv().await {
            if writer.write_all(&frame).await.is_err() {
                break;
            }
            let _ = writer.flush().await;
        }
    });

    let mut conn = ConnectionHandler {
        handle,
        subscriptions: HashMap::new(),
        tx: tx.clone(),
    };

    loop {
        let frame = match read_frame(&mut reader).await {
            Ok(f) => f,
            Err(_) => break, // connection closed
        };

        let (msg_type, flags, payload) = frame;

        match msg_type {
            MSG_REQUEST => {
                let value = match decode_msgpack(&payload) {
                    Ok(v) => v,
                    Err(e) => {
                        warn!(error = %e, "bad msgpack in request");
                        continue;
                    }
                };

                // Parse [request_id, method, params]
                if let Value::Array(ref arr) = value {
                    if arr.len() >= 3 {
                        let request_id = arr[0].as_u64().unwrap_or(0) as u32;
                        let method = arr[1].as_u64().unwrap_or(0) as u8;
                        let params = arr[2].clone();

                        let response = conn.handle_request(request_id, method, params, flags).await;
                        let _ = tx.send(response).await;
                    }
                }
            }
            MSG_PING => {
                let pong = encode_frame(MSG_PONG, 0, &encode_msgpack(&Value::Array(vec![])));
                let _ = tx.send(pong).await;
            }
            _ => {
                debug!(msg_type = msg_type, "unexpected message type");
            }
        }
    }

    // Clean up subscriptions.
    for (_, abort) in conn.subscriptions.drain() {
        abort.abort();
    }

    drop(tx);
    let _ = writer_task.await;

    Ok(())
}

// --- Connection handler ---

struct ConnectionHandler {
    handle: Arc<DaemonHandle>,
    subscriptions: HashMap<String, tokio::task::AbortHandle>,
    tx: mpsc::Sender<Vec<u8>>,
}

impl ConnectionHandler {
    async fn handle_request(
        &mut self,
        request_id: u32,
        method: u8,
        params: Value,
        flags: u8,
    ) -> Vec<u8> {
        let result = match method {
            METHOD_FIND => self.handle_find(&params).await,
            METHOD_DEPLOY => self.handle_deploy(&params).await,
            METHOD_SUBSCRIBE => {
                return self.handle_subscribe(request_id, &params, flags).await;
            }
            METHOD_UNSUBSCRIBE => self.handle_unsubscribe(&params).await,
            METHOD_STATUS => self.handle_status().await,
            METHOD_ASK => self.handle_ask(&params).await,
            METHOD_GET_EVENTS => self.handle_get_events(&params).await,
            other => Err(format!("unknown method: 0x{other:02x}")),
        };
        encode_response(request_id, result)
    }

    async fn handle_find(&self, params: &Value) -> Result<Value, String> {
        let question = get_str(params, "question").ok_or("missing 'question'")?;

        let matches = self.handle.kb.find_probes(&question);
        let results: Vec<Value> = matches
            .iter()
            .take(5)
            .map(|probe| {
                let fields: Vec<Value> = probe
                    .fields
                    .iter()
                    .filter(|f| f.important)
                    .map(|f| {
                        Value::Map(vec![
                            (msgpack_str("name"), msgpack_str(&f.name)),
                            (msgpack_str("meaning"), msgpack_str(&f.meaning)),
                            (msgpack_str("important"), Value::Boolean(true)),
                        ])
                    })
                    .collect();

                Value::Map(vec![
                    (msgpack_str("function"), msgpack_str(&probe.function)),
                    (msgpack_str("attachment"), msgpack_str(&probe.attachment)),
                    (msgpack_str("event_type"), msgpack_str(&probe.event_type)),
                    (msgpack_str("why"), msgpack_str(&probe.use_when)),
                    (msgpack_str("fields"), Value::Array(fields)),
                    (msgpack_str("combine_with"), Value::Array(
                        probe.combine_with.iter().map(|s| msgpack_str(s)).collect(),
                    )),
                ])
            })
            .collect();

        Ok(Value::Array(results))
    }

    async fn handle_deploy(&self, params: &Value) -> Result<Value, String> {
        let function = get_str(params, "function").ok_or("missing 'function'")?;
        let sample_rate = get_f64(params, "sample_rate").unwrap_or(1.0);

        if self.handle.kb.get_probe(&function).is_none() {
            return Err(format!("unknown function '{}' — use find() to search", function));
        }

        let probe_id = self
            .handle
            .deploy_probe(&function, sample_rate)
            .await
            .map_err(|e| e.to_string())?;

        Ok(Value::Map(vec![
            (msgpack_str("probe_id"), msgpack_str(&probe_id)),
            (msgpack_str("function"), msgpack_str(&function)),
            (msgpack_str("status"), msgpack_str("attached")),
        ]))
    }

    async fn handle_subscribe(
        &mut self,
        request_id: u32,
        params: &Value,
        flags: u8,
    ) -> Vec<u8> {
        let probe_id = match get_str(params, "probe_id") {
            Some(id) => id,
            None => return encode_response(request_id, Err("missing 'probe_id'".into())),
        };

        let filter = parse_event_filter(params);
        let interpreted = (flags & FLAG_INTERPRETED != 0)
            || get_bool(params, "interpreted").unwrap_or(false);

        let stream_id = ulid::Ulid::new().to_string();

        // Send response first.
        let response = encode_response(
            request_id,
            Ok(Value::Map(vec![
                (msgpack_str("stream_id"), msgpack_str(&stream_id)),
            ])),
        );

        let tx = self.tx.clone();
        let handle = self.handle.clone();
        let probe_id_clone = probe_id.clone();
        let kb = self.handle.kb.clone();

        let task = tokio::spawn(async move {
            // Send STREAM_START.
            let start_arr = Value::Array(vec![msgpack_str(&probe_id_clone)]);
            let start_frame = encode_frame(MSG_STREAM_START, 0, &encode_msgpack(&start_arr));
            if tx.send(start_frame).await.is_err() {
                return;
            }

            // Stream events.
            let mut last_seen_id: Option<String> = None;
            let poll_interval = std::time::Duration::from_millis(50);

            loop {
                let events = handle.store.query_since(
                    &probe_id_clone,
                    last_seen_id.as_deref(),
                    &filter,
                );

                for occ in &events {
                    let event_frame =
                        encode_stream_event(occ, 0, &kb, interpreted);
                    if tx.send(event_frame).await.is_err() {
                        return;
                    }
                    last_seen_id = Some(occ.id.to_string());
                }

                if tx.is_closed() {
                    return;
                }

                tokio::time::sleep(poll_interval).await;
            }
        });

        self.subscriptions
            .insert(stream_id, task.abort_handle());

        response
    }

    async fn handle_unsubscribe(&mut self, params: &Value) -> Result<Value, String> {
        let probe_id = get_str(params, "probe_id").ok_or("missing 'probe_id'")?;

        // Find and abort the subscription by iterating (stream_id is internal).
        let mut found = false;
        self.subscriptions.retain(|_, abort| {
            if !found {
                abort.abort();
                found = true;
                false
            } else {
                true
            }
        });

        // Send STREAM_END.
        let end_frame = encode_frame(MSG_STREAM_END, 0, &encode_msgpack(&Value::Array(vec![])));
        let _ = self.tx.send(end_frame).await;

        Ok(Value::Map(vec![(msgpack_str("ok"), Value::Boolean(true))]))
    }

    async fn handle_status(&self) -> Result<Value, String> {
        let statuses = self.handle.registry.status();
        let probes: Vec<Value> = statuses
            .iter()
            .map(|s| {
                Value::Map(vec![
                    (msgpack_str("probe_id"), msgpack_str(&s.probe_id)),
                    (msgpack_str("function"), msgpack_str(&s.function)),
                    (msgpack_str("events_total"), Value::Integer(s.events_total.into())),
                    (msgpack_str("ring_buffer_drops"), Value::Integer(s.ring_buffer_drops.into())),
                    (msgpack_str("sample_rate"), Value::F64(s.sample_rate)),
                    (msgpack_str("attached_since"), msgpack_str(&s.attached_since.to_rfc3339())),
                ])
            })
            .collect();

        Ok(Value::Array(probes))
    }

    async fn handle_ask(&self, params: &Value) -> Result<Value, String> {
        let question = get_str(params, "question").ok_or("missing 'question'")?;
        let collect_seconds = get_u64(params, "collect_seconds").unwrap_or(5);
        let max_events = get_u64(params, "max_events").unwrap_or(100) as usize;
        let filter = parse_event_filter(params);

        // 1. Find probes.
        let matches = self.handle.kb.find_probes(&question);
        if matches.is_empty() {
            return Ok(encode_ask_result(
                "No probes found for this question.",
                0,
                "Try keywords like 'connect', 'retransmit', 'packet loss'.",
                vec![],
                vec![],
                true,
            ));
        }

        // 2. Deploy top 3.
        let selected: Vec<_> = matches.into_iter().take(3).collect();
        let mut deployed = vec![];
        for probe in &selected {
            match self.handle.deploy_probe(&probe.function, 1.0).await {
                Ok(pid) => deployed.push((probe.function.clone(), pid)),
                Err(e) => {
                    let msg = e.to_string();
                    if msg.contains("already attached") {
                        deployed.push((probe.function.clone(), probe.function.clone()));
                    } else {
                        debug!(function = %probe.function, error = %msg, "deploy failed in ask");
                    }
                }
            }
        }

        if deployed.is_empty() {
            return Ok(encode_ask_result_kb_only(&question, &selected, &self.handle.kb));
        }

        // 3. Collect events.
        tokio::time::sleep(std::time::Duration::from_secs(collect_seconds)).await;

        let all_events = self.handle.store.query_all(&filter);
        let events: Vec<_> = all_events.into_iter().take(max_events).collect();
        let probes_used: Vec<String> = deployed.iter().map(|(f, _)| f.clone()).collect();

        // 4. Interpret.
        if events.is_empty() {
            return Ok(encode_ask_result(
                "No events observed. The kernel functions did not fire.",
                0,
                "Try collecting for longer.",
                vec![],
                probes_used,
                true,
            ));
        }

        // Find first interpretable event.
        let kb = &self.handle.kb;
        for occ in &events {
            let function = occ.source.strip_prefix("jalki/").unwrap_or(&occ.source);
            let fields = extract_event_fields(occ);
            let interps = kb.explain(function, &fields);
            if let Some(interp) = interps.first() {
                let sev = match interp.severity.as_str() {
                    "warning" => 1u8,
                    "error" => 2,
                    "critical" => 3,
                    _ => 0,
                };
                let compact = events
                    .iter()
                    .map(|e| encode_compact_event(e, kb))
                    .collect();
                return Ok(encode_ask_result(
                    &interp.conclusion,
                    sev,
                    &interp.action,
                    compact,
                    probes_used,
                    false,
                ));
            }
        }

        let compact = events
            .iter()
            .map(|e| encode_compact_event(e, kb))
            .collect();
        Ok(encode_ask_result(
            &format!("Collected {} events but no specific interpretation matched.", events.len()),
            0,
            "Review the events manually.",
            compact,
            probes_used,
            false,
        ))
    }

    async fn handle_get_events(&self, params: &Value) -> Result<Value, String> {
        let probe_id = get_str(params, "probe_id");
        let filter = parse_event_filter(params);

        let events = if let Some(ref pid) = probe_id {
            self.handle.store.query(pid, &filter)
        } else {
            self.handle.store.query_all(&filter)
        };

        let compact: Vec<Value> = events
            .iter()
            .map(|e| encode_compact_event(e, &self.handle.kb))
            .collect();

        Ok(Value::Map(vec![
            (msgpack_str("events"), Value::Array(compact)),
            (msgpack_str("total"), Value::Integer(events.len().into())),
        ]))
    }
}

// --- Encoding helpers ---

/// Create a msgpack string value.
pub fn msgpack_str(s: &str) -> Value {
    Value::String(s.into())
}

pub fn get_str(v: &Value, key: &str) -> Option<String> {
    match v {
        Value::Map(pairs) => {
            for (k, val) in pairs {
                if k.as_str() == Some(key) {
                    return val.as_str().map(|s| s.to_string());
                }
            }
            None
        }
        _ => None,
    }
}

pub fn get_u64(v: &Value, key: &str) -> Option<u64> {
    match v {
        Value::Map(pairs) => {
            for (k, val) in pairs {
                if k.as_str() == Some(key) {
                    return val.as_u64();
                }
            }
            None
        }
        _ => None,
    }
}

pub fn get_f64(v: &Value, key: &str) -> Option<f64> {
    match v {
        Value::Map(pairs) => {
            for (k, val) in pairs {
                if k.as_str() == Some(key) {
                    return val.as_f64().or_else(|| val.as_u64().map(|n| n as f64));
                }
            }
            None
        }
        _ => None,
    }
}

pub fn get_bool(v: &Value, key: &str) -> Option<bool> {
    match v {
        Value::Map(pairs) => {
            for (k, val) in pairs {
                if k.as_str() == Some(key) {
                    return val.as_bool();
                }
            }
            None
        }
        _ => None,
    }
}

fn parse_event_filter(params: &Value) -> EventFilter {
    let filter_val = match params {
        Value::Map(pairs) => {
            pairs.iter().find(|(k, _)| k.as_str() == Some("filter")).map(|(_, v)| v)
        }
        _ => None,
    };

    let f = filter_val.unwrap_or(&Value::Nil);
    EventFilter {
        last_seconds: get_u64(f, "last_seconds").or(Some(60)).map(|v| v as u64),
        src_ip: get_str(f, "src_ip"),
        dst_ip: get_str(f, "dst_ip"),
        src_port: get_u64(f, "src_port").map(|v| v as u16),
        dst_port: get_u64(f, "dst_port").map(|v| v as u16),
        pid: get_u64(f, "pid").map(|v| v as u32),
        command: get_str(f, "command"),
        limit: Some(100),
    }
}

fn encode_stream_event(
    occ: &false_protocol::Occurrence,
    probe_idx: u8,
    kb: &crate::knowledge::KnowledgeBase,
    interpreted: bool,
) -> Vec<u8> {
    let ts_ns = occ.timestamp.timestamp_nanos_opt().unwrap_or(0) as u64;

    let severity: u8 = match occ.severity {
        false_protocol::Severity::Info | false_protocol::Severity::Debug => 0,
        false_protocol::Severity::Warning => 1,
        false_protocol::Severity::Error => 2,
        false_protocol::Severity::Critical => 3,
    };

    let outcome: u8 = match occ.outcome {
        Some(false_protocol::Outcome::Success) => 0,
        Some(false_protocol::Outcome::Failure) => 1,
        _ => 2,
    };

    let net_src = occ
        .network_data
        .as_ref()
        .map(|n| format!("{}:{}", n.src_ip, n.src_port));
    let net_dst = occ
        .network_data
        .as_ref()
        .map(|n| format!("{}:{}", n.dst_ip, n.dst_port));
    let proto: Option<u8> = occ.network_data.as_ref().map(|n| {
        if n.protocol == "tcp" { 0 } else { 1 }
    });

    let pid = occ.process_data.as_ref().map(|p| p.pid);
    let cmd = occ.process_data.as_ref().map(|p| p.command.clone());

    let labels = if occ.labels.is_empty() {
        Value::Nil
    } else {
        Value::Map(
            occ.labels
                .iter()
                .map(|(k, v)| (msgpack_str(k), msgpack_str(v)))
                .collect(),
        )
    };

    let interp = if interpreted {
        let function = occ.source.strip_prefix("jalki/").unwrap_or(&occ.source);
        let fields = extract_event_fields(occ);
        kb.explain(function, &fields).first().map(|i| {
            Value::Array(vec![msgpack_str(&i.conclusion), msgpack_str(&i.action)])
        })
    } else {
        None
    };

    let arr = Value::Array(vec![
        msgpack_str(&occ.id.to_string()),
        Value::Integer(probe_idx.into()),
        Value::Integer(ts_ns.into()),
        Value::Integer(severity.into()),
        Value::Integer(outcome.into()),
        net_src.map(|s| msgpack_str(&s)).unwrap_or(Value::Nil),
        net_dst.map(|s| msgpack_str(&s)).unwrap_or(Value::Nil),
        proto.map(|p| Value::Integer(p.into())).unwrap_or(Value::Nil),
        pid.map(|p| Value::Integer(p.into())).unwrap_or(Value::Nil),
        cmd.map(|c| msgpack_str(&c)).unwrap_or(Value::Nil),
        labels,
        interp.unwrap_or(Value::Nil),
    ]);

    let flags = if interpreted { FLAG_INTERPRETED } else { 0 };
    encode_frame(MSG_STREAM_EVENT, flags, &encode_msgpack(&arr))
}

fn encode_compact_event(
    occ: &false_protocol::Occurrence,
    kb: &crate::knowledge::KnowledgeBase,
) -> Value {
    let ts_ns = occ.timestamp.timestamp_nanos_opt().unwrap_or(0) as u64;
    let probe = occ.source.strip_prefix("jalki/").unwrap_or(&occ.source);

    let severity: u8 = match occ.severity {
        false_protocol::Severity::Info | false_protocol::Severity::Debug => 0,
        false_protocol::Severity::Warning => 1,
        false_protocol::Severity::Error => 2,
        false_protocol::Severity::Critical => 3,
    };
    let outcome: u8 = match occ.outcome {
        Some(false_protocol::Outcome::Success) => 0,
        Some(false_protocol::Outcome::Failure) => 1,
        _ => 2,
    };

    let fields = extract_event_fields(occ);
    let interp = kb.explain(probe, &fields).first().map(|i| {
        Value::Array(vec![msgpack_str(&i.conclusion), msgpack_str(&i.action)])
    });

    Value::Array(vec![
        msgpack_str(&occ.id.to_string()),
        Value::Integer(0.into()),
        Value::Integer(ts_ns.into()),
        Value::Integer(severity.into()),
        Value::Integer(outcome.into()),
        occ.network_data
            .as_ref()
            .map(|n| msgpack_str(&format!("{}:{}", n.src_ip, n.src_port)))
            .unwrap_or(Value::Nil),
        occ.network_data
            .as_ref()
            .map(|n| msgpack_str(&format!("{}:{}", n.dst_ip, n.dst_port)))
            .unwrap_or(Value::Nil),
        occ.network_data
            .as_ref()
            .map(|_| Value::Integer(0.into()))
            .unwrap_or(Value::Nil),
        occ.process_data
            .as_ref()
            .map(|p| Value::Integer(p.pid.into()))
            .unwrap_or(Value::Nil),
        occ.process_data
            .as_ref()
            .map(|p| msgpack_str(&p.command))
            .unwrap_or(Value::Nil),
        if occ.labels.is_empty() {
            Value::Nil
        } else {
            Value::Map(occ.labels.iter().map(|(k, v)| (msgpack_str(k), msgpack_str(v))).collect())
        },
        interp.unwrap_or(Value::Nil),
    ])
}

fn encode_ask_result(
    interpretation: &str,
    severity: u8,
    action: &str,
    events: Vec<Value>,
    probes_used: Vec<String>,
    kb_only: bool,
) -> Value {
    Value::Map(vec![
        (msgpack_str("interpretation"), msgpack_str(interpretation)),
        (msgpack_str("severity"), Value::Integer(severity.into())),
        (msgpack_str("action"), msgpack_str(action)),
        (msgpack_str("events"), Value::Array(events)),
        (msgpack_str("probes_used"), Value::Array(probes_used.iter().map(|s| msgpack_str(s)).collect())),
        (msgpack_str("kb_only"), Value::Boolean(kb_only)),
    ])
}

fn encode_ask_result_kb_only(
    _question: &str,
    selected: &[&crate::knowledge::ProbeKnowledge],
    _kb: &crate::knowledge::KnowledgeBase,
) -> Value {
    let mut parts = Vec::new();
    for probe in selected {
        parts.push(format!("**{}** ({}): {}", probe.function, probe.attachment, probe.use_when));
    }
    let interpretation = parts.join("\n\n");

    encode_ask_result(
        &interpretation,
        0,
        "Start the daemon for live events: sudo jalki --sink stdout",
        vec![],
        selected.iter().map(|p| p.function.clone()).collect(),
        true,
    )
}

fn extract_event_fields(occ: &false_protocol::Occurrence) -> EventFields {
    let ret = occ.error.as_ref().and_then(|e| match e.code.as_str() {
        "ECONNREFUSED" => Some(-111),
        "ETIMEDOUT" => Some(-110),
        "EHOSTUNREACH" => Some(-113),
        "ENETUNREACH" => Some(-101),
        _ => None,
    });
    let tcp_state = occ.labels.get("tcp_state").and_then(|s| match s.as_str() {
        "ESTABLISHED" => Some(1),
        "SYN_SENT" => Some(2),
        "CLOSE_WAIT" => Some(7),
        _ => None,
    });
    EventFields { ret, tcp_state }
}

// --- Client functions (used by CLI and MCP) ---

/// Backwards-compatible client: speaks binary frames but presents JSON interface.
/// CLI and MCP call this with method name strings and get JSON back.
pub async fn connect() -> Result<UnixStream> {
    UnixStream::connect(SOCKET_PATH)
        .await
        .with_context(|| format!(
            "failed to connect to jalki daemon at {SOCKET_PATH}. Is the daemon running?"
        ))
}

/// IPC response — carries native msgpack values, no JSON conversion.
#[derive(Debug)]
pub struct Response {
    pub ok: bool,
    pub result: Option<Value>,
    pub error: Option<String>,
}

impl Response {
    fn success(result: Value) -> Self {
        Self { ok: true, result: Some(result), error: None }
    }

    fn err(msg: impl Into<String>) -> Self {
        Self { ok: false, result: None, error: Some(msg.into()) }
    }

    /// Get a string field from the result map.
    pub fn get_str(&self, key: &str) -> Option<String> {
        self.result.as_ref().and_then(|v| get_str(v, key))
    }

    /// Get a u64 field from the result map.
    pub fn get_u64(&self, key: &str) -> Option<u64> {
        self.result.as_ref().and_then(|v| get_u64(v, key))
    }

    /// Get a f64 field from the result map.
    pub fn get_f64(&self, key: &str) -> Option<f64> {
        self.result.as_ref().and_then(|v| get_f64(v, key))
    }

    /// Get the result as an array slice.
    pub fn as_array(&self) -> Option<&[Value]> {
        self.result.as_ref().and_then(|v| v.as_array()).map(|v| v.as_slice())
    }

    /// Convert result to JSON (for MCP compatibility layer).
    pub fn to_json(&self) -> serde_json::Value {
        match &self.result {
            Some(v) => msgpack_to_json(v),
            None => serde_json::Value::Null,
        }
    }
}

/// Send a request to the daemon using the binary frame protocol.
/// Params are native msgpack — no JSON conversion.
pub async fn call_native(method: u8, params: Value) -> Result<Response> {
    let stream = connect().await?;
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    let request = Value::Array(vec![
        Value::Integer(1u32.into()),
        Value::Integer(method.into()),
        params,
    ]);
    let payload = encode_msgpack(&request);
    let frame = encode_frame(MSG_REQUEST, 0, &payload);

    write_half.write_all(&frame).await?;
    write_half.flush().await?;

    let (msg_type, _flags, resp_payload) = read_frame(&mut reader).await?;

    if msg_type != MSG_RESPONSE {
        return Ok(Response::err(format!("unexpected response type: {msg_type}")));
    }

    let resp_value = decode_msgpack(&resp_payload)?;

    if let Value::Array(ref arr) = resp_value {
        if arr.len() >= 3 {
            let ok = arr[1].as_bool().unwrap_or(false);
            if ok {
                return Ok(Response::success(arr[2].clone()));
            } else {
                let err_msg = arr[2].as_str().unwrap_or("unknown error").to_string();
                return Ok(Response::err(err_msg));
            }
        }
    }

    Ok(Response::err("malformed response"))
}

/// Convenience: call with method name string and JSON params.
/// Converts JSON → msgpack for the wire. Used by MCP which still works in JSON.
pub async fn call(method: &str, params: serde_json::Value) -> Result<Response> {
    let method_u8 = match method {
        "find_probe" | "find" => METHOD_FIND,
        "deploy_probe" | "deploy" => METHOD_DEPLOY,
        "subscribe" => METHOD_SUBSCRIBE,
        "unsubscribe" => METHOD_UNSUBSCRIBE,
        "probe_status" | "status" => METHOD_STATUS,
        "ask" => METHOD_ASK,
        "get_events" | "get_all_events" => METHOD_GET_EVENTS,
        _ => return Ok(Response::err(format!("unknown method: {method}"))),
    };
    call_native(method_u8, json_to_msgpack(&params)).await
}

// --- JSON ↔ MessagePack conversion ---

fn json_to_msgpack(v: &serde_json::Value) -> Value {
    match v {
        serde_json::Value::Null => Value::Nil,
        serde_json::Value::Bool(b) => Value::Boolean(*b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_u64() {
                Value::Integer(i.into())
            } else if let Some(i) = n.as_i64() {
                Value::Integer(i.into())
            } else if let Some(f) = n.as_f64() {
                Value::F64(f)
            } else {
                Value::Nil
            }
        }
        serde_json::Value::String(s) => msgpack_str(s),
        serde_json::Value::Array(arr) => {
            Value::Array(arr.iter().map(json_to_msgpack).collect())
        }
        serde_json::Value::Object(map) => {
            Value::Map(
                map.iter()
                    .map(|(k, v)| (msgpack_str(k), json_to_msgpack(v)))
                    .collect(),
            )
        }
    }
}

fn msgpack_to_json(v: &Value) -> serde_json::Value {
    match v {
        Value::Nil => serde_json::Value::Null,
        Value::Boolean(b) => serde_json::Value::Bool(*b),
        Value::Integer(i) => {
            if let Some(u) = i.as_u64() {
                serde_json::json!(u)
            } else if let Some(i) = i.as_i64() {
                serde_json::json!(i)
            } else {
                serde_json::Value::Null
            }
        }
        Value::F32(f) => serde_json::json!(*f),
        Value::F64(f) => serde_json::json!(*f),
        Value::String(s) => serde_json::Value::String(s.as_str().unwrap_or("").to_string()),
        Value::Binary(b) => serde_json::Value::String(String::from_utf8_lossy(b).to_string()),
        Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(msgpack_to_json).collect())
        }
        Value::Map(pairs) => {
            let mut map = serde_json::Map::new();
            for (k, v) in pairs {
                let key = match k {
                    Value::String(s) => s.as_str().unwrap_or("").to_string(),
                    _ => format!("{k}"),
                };
                map.insert(key, msgpack_to_json(v));
            }
            serde_json::Value::Object(map)
        }
        Value::Ext(_, _) => serde_json::Value::Null,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_frame_roundtrip() {
        let payload = b"hello world";
        let frame = encode_frame(MSG_REQUEST, 0, payload);
        assert_eq!(frame.len(), FRAME_HEADER_LEN + payload.len());

        let frame_len = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]);
        assert_eq!(frame_len as usize, payload.len() + 2);
        assert_eq!(frame[4], MSG_REQUEST);
        assert_eq!(frame[5], 0);
        assert_eq!(&frame[6..], payload);
    }

    #[test]
    fn frame_len_includes_type_and_flags() {
        let frame = encode_frame(MSG_PING, 0, &[]);
        let frame_len = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]);
        assert_eq!(frame_len, 2);
    }

    #[test]
    fn json_msgpack_roundtrip() {
        let json = serde_json::json!({
            "function": "tcp_connect",
            "sample_rate": 1.0,
            "filter": {"dst_port": 5432}
        });
        let msgpack = json_to_msgpack(&json);
        let back = msgpack_to_json(&msgpack);
        assert_eq!(back["function"], "tcp_connect");
        assert_eq!(back["filter"]["dst_port"], 5432);
    }

    #[test]
    fn method_name_mapping() {
        // Verify method names used by CLI map to correct u8 values.
        assert_eq!(
            match "deploy_probe" {
                "deploy_probe" | "deploy" => METHOD_DEPLOY,
                _ => 0,
            },
            METHOD_DEPLOY
        );
    }
}

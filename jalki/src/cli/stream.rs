use anyhow::Result;
use rmpv::Value;

use jalki::ipc::{self, msgpack_str, METHOD_DEPLOY, METHOD_GET_EVENTS};

/// `jalki stream [function]`
///
/// Poll events from the daemon and print ndjson continuously.
pub async fn run(function: Option<&str>) -> Result<()> {
    if let Some(func) = function {
        let params = Value::Map(vec![
            (msgpack_str("function"), msgpack_str(func)),
            (msgpack_str("sample_rate"), Value::F64(1.0)),
        ]);

        let resp = ipc::call_native(METHOD_DEPLOY, params).await;

        match resp {
            Ok(r) if r.ok => {
                eprintln!("Attached {}", func);
            }
            Ok(r) => {
                let err = r.error.unwrap_or_default();
                if !err.contains("already attached") {
                    eprintln!("Warning: {}", err);
                }
            }
            Err(e) => {
                anyhow::bail!(
                    "Cannot connect to jalki daemon: {e}\n\
                     Start the daemon first: sudo jalki --sink stdout"
                );
            }
        }
    }

    eprintln!("Streaming events (ctrl+c to stop)...");

    let mut last_seen = chrono::Utc::now();
    let poll_interval = std::time::Duration::from_millis(500);

    loop {
        let resp = ipc::call_native(
            METHOD_GET_EVENTS,
            Value::Map(vec![
                (msgpack_str("last_seconds"), Value::Integer(2.into())),
            ]),
        )
        .await?;

        if resp.ok {
            let json = resp.to_json();
            if let Some(events) = json.get("events").and_then(|v| v.as_array()) {
                for event in events {
                    if let Some(ts) = event.get("timestamp").and_then(|v| v.as_str()) {
                        if let Ok(t) = chrono::DateTime::parse_from_rfc3339(ts) {
                            let t_utc = t.with_timezone(&chrono::Utc);
                            if t_utc <= last_seen {
                                continue;
                            }
                            last_seen = t_utc;
                        }
                    }
                    if let Ok(json) = serde_json::to_string(event) {
                        println!("{}", json);
                    }
                }
            }
        }

        tokio::time::sleep(poll_interval).await;
    }
}

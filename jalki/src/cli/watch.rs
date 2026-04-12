use anyhow::Result;
use rmpv::Value;

use jalki::ipc::{self, vs, METHOD_DEPLOY, METHOD_STATUS};

/// `jalki watch tcp_connect --seconds 10 --dst-port 5432`
pub async fn run(
    function: &str,
    seconds: u64,
    dst_port: Option<u16>,
    dst_ip: Option<String>,
    pid: Option<u32>,
) -> Result<()> {
    let params = Value::Map(vec![
        (vs("function"), vs(function)),
        (vs("sample_rate"), Value::F64(1.0)),
    ]);

    let resp = ipc::call_native(METHOD_DEPLOY, params).await;

    let probe_id = match resp {
        Ok(r) if r.ok => {
            let id = r.get_str("probe_id").unwrap_or_else(|| function.into());
            eprintln!("Attached {} → {}", function, id);
            id
        }
        Ok(r) => {
            let err = r.error.unwrap_or_default();
            if err.contains("already attached") {
                eprintln!("{} already attached, collecting...", function);
                function.to_string()
            } else {
                anyhow::bail!("deploy failed: {}", err);
            }
        }
        Err(e) => {
            anyhow::bail!(
                "Cannot connect to jalki daemon: {e}\n\
                 Start the daemon first: sudo jalki --emit stdout"
            );
        }
    };

    eprintln!("Collecting for {}s...", seconds);
    tokio::time::sleep(std::time::Duration::from_secs(seconds)).await;

    // Build filter params.
    let mut filter_pairs = vec![];
    if let Some(p) = dst_port {
        filter_pairs.push((vs("dst_port"), Value::Integer(p.into())));
    }
    if let Some(ref ip) = dst_ip {
        filter_pairs.push((vs("dst_ip"), vs(ip)));
    }
    if let Some(p) = pid {
        filter_pairs.push((vs("pid"), Value::Integer(p.into())));
    }

    let status_resp = ipc::call_native(
        METHOD_STATUS,
        Value::Map(vec![
            (vs("probe_id"), vs(&probe_id)),
            (vs("last_seconds"), Value::Integer((seconds + 1).into())),
            (vs("filter"), Value::Map(filter_pairs)),
        ]),
    )
    .await?;

    if !status_resp.ok {
        anyhow::bail!("status failed: {}", status_resp.error.unwrap_or_default());
    }

    // Status returns array of probes — print events from the store via the result.
    let probes = status_resp.as_array().cloned().unwrap_or_default();
    eprintln!("{} probes reporting.", probes.len());

    // For watch, we re-query events via get_all_events (legacy compat via call).
    // The native approach would be subscribe+stream, but for one-shot collection
    // the simpler path is to query the EventStore.
    let events_resp = ipc::call(
        "get_all_events",
        serde_json::json!({ "last_seconds": seconds + 1 }),
    )
    .await?;

    if events_resp.ok {
        let json = events_resp.to_json();
        if let Some(events) = json.get("events").and_then(|v| v.as_array()) {
            eprintln!("{} events collected.", events.len());
            println!();
            for event in events {
                if let Ok(json) = serde_json::to_string(event) {
                    println!("{}", json);
                }
            }
        }
    }

    Ok(())
}

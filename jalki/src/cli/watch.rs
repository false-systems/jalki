use anyhow::Result;
use rmpv::Value;

use jalki::ipc::{self, msgpack_str, METHOD_DEPLOY, METHOD_GET_EVENTS};

/// `jalki watch tcp_connect --seconds 10 --dst-port 5432`
pub async fn run(
    function: &str,
    seconds: u64,
    dst_port: Option<u16>,
    dst_ip: Option<String>,
    pid: Option<u32>,
) -> Result<()> {
    let params = Value::Map(vec![
        (msgpack_str("function"), msgpack_str(function)),
        (msgpack_str("sample_rate"), Value::F64(1.0)),
    ]);

    let resp = ipc::call_native(METHOD_DEPLOY, params).await;

    let _probe_id = match resp {
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
                 Start the daemon first: sudo jalki --sink stdout"
            );
        }
    };

    eprintln!("Collecting for {}s...", seconds);
    tokio::time::sleep(std::time::Duration::from_secs(seconds)).await;

    // Build filter.
    let mut filter_pairs = vec![];
    if let Some(p) = dst_port {
        filter_pairs.push((msgpack_str("dst_port"), Value::Integer(p.into())));
    }
    if let Some(ref ip) = dst_ip {
        filter_pairs.push((msgpack_str("dst_ip"), msgpack_str(ip)));
    }
    if let Some(p) = pid {
        filter_pairs.push((msgpack_str("pid"), Value::Integer(p.into())));
    }

    let events_resp = ipc::call_native(
        METHOD_GET_EVENTS,
        Value::Map(vec![
            (msgpack_str("last_seconds"), Value::Integer((seconds + 1).into())),
            (msgpack_str("filter"), Value::Map(filter_pairs)),
        ]),
    )
    .await?;

    if !events_resp.ok {
        anyhow::bail!("get_events failed: {}", events_resp.error.unwrap_or_default());
    }

    let json = events_resp.to_json();
    let events = json.get("events").and_then(|v| v.as_array()).cloned().unwrap_or_default();

    eprintln!("{} events collected.", events.len());
    println!();

    for event in &events {
        if let Ok(json) = serde_json::to_string(event) {
            println!("{}", json);
        }
    }

    Ok(())
}

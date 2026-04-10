use anyhow::Result;
use serde_json::json;

use jalki::ipc;

/// `jalki watch tcp_connect --seconds 10 --dst-port 5432`
///
/// Deploy a probe, collect events for N seconds, print results.
pub async fn run(
    function: &str,
    seconds: u64,
    dst_port: Option<u16>,
    dst_ip: Option<String>,
    pid: Option<u32>,
) -> Result<()> {
    // Deploy probe via daemon.
    let resp = ipc::call(
        "deploy_probe",
        json!({ "function": function, "sample_rate": 1.0 }),
    )
    .await;

    let probe_id = match resp {
        Ok(r) if r.ok => {
            let id = r
                .result
                .as_ref()
                .and_then(|v| v.get("probe_id"))
                .and_then(|v| v.as_str())
                .unwrap_or(function)
                .to_string();
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

    // Build filter.
    let mut filter = json!({});
    if let Some(p) = dst_port {
        filter["dst_port"] = json!(p);
    }
    if let Some(ref ip) = dst_ip {
        filter["dst_ip"] = json!(ip);
    }
    if let Some(p) = pid {
        filter["pid"] = json!(p);
    }

    let resp = ipc::call(
        "get_events",
        json!({
            "probe_id": probe_id,
            "last_seconds": seconds + 1,
            "filter": filter,
        }),
    )
    .await?;

    if !resp.ok {
        anyhow::bail!("get_events failed: {}", resp.error.unwrap_or_default());
    }

    let events = resp
        .result
        .as_ref()
        .and_then(|v| v.get("events"))
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    eprintln!("{} events collected.", events.len());
    println!();

    for event in &events {
        if let Ok(json) = serde_json::to_string(event) {
            println!("{}", json);
        }
    }

    Ok(())
}

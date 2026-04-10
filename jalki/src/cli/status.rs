use anyhow::Result;
use serde_json::json;

use jalki::ipc;

/// `jalki status`
///
/// Show status of all attached probes on the running daemon.
pub async fn run() -> Result<()> {
    let resp = ipc::call("probe_status", json!({})).await;

    match resp {
        Ok(r) if r.ok => {
            let probes = r
                .result
                .as_ref()
                .and_then(|v| v.get("probes"))
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();

            if probes.is_empty() {
                println!("No probes attached.");
                return Ok(());
            }

            println!(
                "{:<12} {:<24} {:<10} {:<10} {:<8}",
                "PROBE_ID", "FUNCTION", "EVENTS", "DROPS", "RATE"
            );
            for p in &probes {
                println!(
                    "{:<12} {:<24} {:<10} {:<10} {:<8}",
                    p.get("probe_id").and_then(|v| v.as_str()).unwrap_or("-"),
                    p.get("function").and_then(|v| v.as_str()).unwrap_or("-"),
                    p.get("events_total").and_then(|v| v.as_u64()).unwrap_or(0),
                    p.get("ring_buffer_drops")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0),
                    p.get("sample_rate").and_then(|v| v.as_f64()).unwrap_or(1.0),
                );
            }
        }
        Ok(r) => {
            eprintln!(
                "Error: {}",
                r.error.unwrap_or_else(|| "unknown".into())
            );
        }
        Err(e) => {
            eprintln!(
                "Cannot connect to jalki daemon: {e}\n\
                 Start the daemon first: sudo jalki --emit stdout"
            );
        }
    }

    Ok(())
}

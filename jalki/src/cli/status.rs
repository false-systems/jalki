use anyhow::Result;
use rmpv::Value;

use jalki::ipc::{self, METHOD_STATUS};

/// `jalki status`
pub async fn run() -> Result<()> {
    let resp = ipc::call_native(METHOD_STATUS, Value::Map(vec![])).await;

    match resp {
        Ok(r) if r.ok => {
            let probes = r.as_array().map(|s| s.to_vec()).unwrap_or_default();

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
                    ipc::get_str(p, "probe_id").unwrap_or_else(|| "-".into()),
                    ipc::get_str(p, "function").unwrap_or_else(|| "-".into()),
                    ipc::get_u64(p, "events_total").unwrap_or(0),
                    ipc::get_u64(p, "ring_buffer_drops").unwrap_or(0),
                    ipc::get_f64(p, "sample_rate").unwrap_or(1.0),
                );
            }
        }
        Ok(r) => {
            eprintln!("Error: {}", r.error.unwrap_or_else(|| "unknown".into()));
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

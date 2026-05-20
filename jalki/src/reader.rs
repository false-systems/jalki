use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::{Context, Result};
use aya::maps::{MapData, RingBuf};
use aya::Ebpf;
use jalki_evidence::EvidenceRecord;
use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::probe::Probe;
use crate::store::EventStore;

/// Per-probe drop counter, exposed for metrics.
pub struct ProbeStats {
    pub events_emitted: AtomicU64,
    pub events_dropped: AtomicU64,
    pub events_sampled_out: AtomicU64,
    pub parse_errors: AtomicU64,
}

impl ProbeStats {
    pub fn new() -> Self {
        Self {
            events_emitted: AtomicU64::new(0),
            events_dropped: AtomicU64::new(0),
            events_sampled_out: AtomicU64::new(0),
            parse_errors: AtomicU64::new(0),
        }
    }
}

/// Drain a ring buffer and convert events to evidence records.
///
/// Runs as a blocking task (ring buffer polling is synchronous in aya).
/// Sends one batch per ring-buffer drain cycle through an mpsc channel.
pub fn spawn_reader(
    ebpf: &mut Ebpf,
    probe: Arc<dyn Probe>,
    cluster: String,
    tx: mpsc::Sender<Vec<EvidenceRecord>>,
    stats: Arc<ProbeStats>,
    store: Arc<EventStore>,
) -> Result<()> {
    let map_name = probe.ring_buffer_map().to_string();

    let map = ebpf
        .take_map(&map_name)
        .ok_or_else(|| anyhow::anyhow!("ring buffer map {map_name} not found"))?;
    let ring_buf: RingBuf<MapData> = map
        .try_into()
        .with_context(|| format!("{map_name} is not a RingBuf"))?;

    let probe_name = probe.name().to_string();

    tokio::task::spawn_blocking(move || {
        drain_loop(ring_buf, probe, &cluster, tx, stats, &probe_name, store);
    });

    Ok(())
}

fn drain_loop(
    mut ring_buf: RingBuf<aya::maps::MapData>,
    probe: Arc<dyn Probe>,
    cluster: &str,
    tx: mpsc::Sender<Vec<EvidenceRecord>>,
    stats: Arc<ProbeStats>,
    probe_name: &str,
    store: Arc<EventStore>,
) {
    let sample_rate = probe.sample_rate();
    let do_sampling = sample_rate < 1.0;
    // Simple deterministic sampling: use a counter modulo inverse-rate.
    // For 0.1 (10%), keep every 10th event. Avoids RNG overhead in the hot path.
    let sample_every = if do_sampling {
        (1.0 / sample_rate).round() as u64
    } else {
        1
    };
    let mut counter: u64 = 0;

    loop {
        let mut records = Vec::new();

        while let Some(item) = ring_buf.next() {
            // Apply sampling before parsing — skip the conversion cost too.
            if do_sampling {
                counter = counter.wrapping_add(1);
                if counter % sample_every != 0 {
                    stats.events_sampled_out.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
            }

            let raw = item.as_ref();

            match probe.to_evidence(raw, cluster) {
                Ok(evidence) => {
                    for record in evidence.records {
                        store.push(probe_name, record.occurrence.clone());
                        stats.events_emitted.fetch_add(1, Ordering::Relaxed);
                        records.push(record);
                    }
                }
                Err(e) => {
                    stats.parse_errors.fetch_add(1, Ordering::Relaxed);
                    warn!(probe = probe_name, error = %e, "failed to parse event");
                }
            }
        }

        if !records.is_empty() && tx.blocking_send(records).is_err() {
            debug!(probe = probe_name, "sink channel closed, stopping reader");
            return;
        }

        // No events available — sleep briefly before polling again.
        // TODO: wire up epoll via ring_buf fd for zero-latency wakeup.
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

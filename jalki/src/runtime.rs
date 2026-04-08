use std::path::Path;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use anyhow::Result;
use false_protocol::{Occurrence, Severity};
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use crate::emitter::Emitter;
use crate::loader;
use crate::metrics::{EmitterLabel, Metrics};
use crate::probe::Probe;
use crate::reader::{self, ProbeStats};

/// Builder for configuring and running jälki.
pub struct Runtime {
    probes: Vec<Arc<dyn Probe>>,
    emitters: Vec<Box<dyn Emitter>>,
    ebpf_path: String,
    cluster: String,
}

impl Runtime {
    pub fn new(ebpf_path: impl Into<String>) -> Self {
        Self {
            probes: Vec::new(),
            emitters: Vec::new(),
            ebpf_path: ebpf_path.into(),
            cluster: hostname::get()
                .ok()
                .and_then(|h| h.into_string().ok())
                .unwrap_or_else(|| "unknown".into()),
        }
    }

    pub fn cluster(mut self, cluster: impl Into<String>) -> Self {
        self.cluster = cluster.into();
        self
    }

    pub fn attach(mut self, probe: impl Probe) -> Self {
        self.probes.push(Arc::new(probe));
        self
    }

    pub fn emit_to(mut self, emitter: impl Emitter + 'static) -> Self {
        self.emitters.push(Box::new(emitter));
        self
    }

    /// Run the jälki daemon: load eBPF, attach probes, drain events, emit.
    pub async fn run(self) -> Result<()> {
        let metrics = Arc::new(Metrics::new());

        info!(
            probes = self.probes.len(),
            emitters = self.emitters.len(),
            cluster = %self.cluster,
            "starting jalki"
        );

        // Load and attach eBPF programs — driven by probe metadata.
        let mut ebpf = loader::load_and_attach(Path::new(&self.ebpf_path), &self.probes)?;

        // Channel: readers → emit loop.
        let (tx, mut rx) = mpsc::channel::<Occurrence>(8192);

        // Spawn a reader for each probe.
        let mut stats_map: Vec<(String, Arc<ProbeStats>)> = Vec::new();
        for probe in &self.probes {
            let stats = Arc::new(ProbeStats::new());
            reader::spawn_reader(
                &mut ebpf,
                probe.clone(),
                self.cluster.clone(),
                tx.clone(),
                stats.clone(),
            )?;
            stats_map.push((probe.name().to_string(), stats));
        }

        // Spawn self-observability: periodically emit drops/errors as Occurrences.
        let stats_tx = tx.clone();
        let stats_cluster = self.cluster.clone();
        let stats_for_task = stats_map.clone();
        tokio::spawn(async move {
            emit_self_observability(stats_for_task, stats_tx, &stats_cluster).await;
        });

        // Drop the original sender so the channel closes when all readers stop.
        drop(tx);

        // Emit loop: batch events and send to all emitters.
        let emitters = self.emitters;
        let metrics_clone = metrics.clone();

        let emit_handle = tokio::spawn(async move {
            let mut batch = Vec::with_capacity(128);

            loop {
                match rx.recv().await {
                    Some(occ) => batch.push(occ),
                    None => break,
                }

                while batch.len() < 128 {
                    match rx.try_recv() {
                        Ok(occ) => batch.push(occ),
                        Err(_) => break,
                    }
                }

                for emitter in &emitters {
                    if let Err(e) = emitter.emit(&batch).await {
                        error!(emitter = emitter.name(), error = %e, "emit failed");
                        metrics_clone
                            .emit_errors
                            .get_or_create(&EmitterLabel {
                                emitter: emitter.name().into(),
                            })
                            .inc();
                    }
                }

                batch.clear();
            }

            info!("emit loop finished");
        });

        // Spawn metrics server.
        let _metrics_handle = {
            let metrics = metrics.clone();
            tokio::spawn(async move {
                if let Err(e) = serve_metrics(metrics).await {
                    error!(error = %e, "metrics server failed");
                }
            })
        };

        emit_handle.await?;
        Ok(())
    }
}

/// Periodically check probe stats and emit self-observability Occurrences.
///
/// If AHTI sees a gap in events and doesn't know jälki dropped them,
/// it will misdiagnose. These events close that gap.
async fn emit_self_observability(
    stats_map: Vec<(String, Arc<ProbeStats>)>,
    tx: mpsc::Sender<Occurrence>,
    cluster: &str,
) {
    let mut prev_dropped: Vec<u64> = vec![0; stats_map.len()];
    let mut prev_errors: Vec<u64> = vec![0; stats_map.len()];

    let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));

    loop {
        interval.tick().await;

        for (i, (probe_name, stats)) in stats_map.iter().enumerate() {
            let dropped = stats.events_dropped.load(Ordering::Relaxed);
            let errors = stats.parse_errors.load(Ordering::Relaxed);

            let new_drops = dropped - prev_dropped[i];
            let new_errors = errors - prev_errors[i];

            if new_drops > 0 {
                warn!(probe = %probe_name, dropped = new_drops, "ring buffer drops detected");
                let occ = Occurrence::new("jalki/self", "jalki.probe.events_dropped")
                    .severity(Severity::Warning)
                    .in_cluster(cluster);
                // Best-effort — if the channel is full, we can't do anything about it.
                let _ = tx.try_send(occ);
            }

            if new_errors > 0 {
                warn!(probe = %probe_name, errors = new_errors, "parse errors detected");
                let occ = Occurrence::new("jalki/self", "jalki.probe.parse_errors")
                    .severity(Severity::Warning)
                    .in_cluster(cluster);
                let _ = tx.try_send(occ);
            }

            prev_dropped[i] = dropped;
            prev_errors[i] = errors;
        }
    }
}

/// Serve Prometheus metrics on :9090/metrics.
async fn serve_metrics(metrics: Arc<Metrics>) -> Result<()> {
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("0.0.0.0:9090").await?;
    info!("metrics server listening on :9090");

    loop {
        let (mut stream, _) = listener.accept().await?;
        let body = metrics.encode();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = stream.write_all(response.as_bytes()).await;
    }
}

/// Convenience function matching the design doc's API.
pub async fn run<F>(configure: F) -> Result<()>
where
    F: FnOnce(Runtime) -> Runtime,
{
    let ebpf_path = std::env::var("JALKI_EBPF_PATH")
        .unwrap_or_else(|_| "jalki-ebpf/target/bpfel-unknown-none/release/jalki-ebpf".into());

    let runtime = Runtime::new(ebpf_path);
    let runtime = configure(runtime);
    runtime.run().await
}

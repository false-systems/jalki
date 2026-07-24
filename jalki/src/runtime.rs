use std::collections::HashSet;
use std::path::Path;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result};
use aya::{Btf, Ebpf};
use false_protocol::{Occurrence, Severity};
use jalki_evidence::{
    EvidenceBatch, EvidenceRecord, EvidenceSink, GapReport, HookKind, ProbeMetadata,
    ProducerMetadata, RetryBuffer, RetryBufferConfig, SinkError,
};
use tokio::sync::{mpsc, Mutex};
use tracing::{error, info, warn};

use crate::enrich::{NoopEnricher, RuntimeEnricher};
use crate::knowledge::KnowledgeBase;
use crate::loader;
use crate::metrics::{Metrics, SinkLabel, UnboundDropLabel};
use crate::probe::Probe;
use crate::probes::generated::GeneratedProbeReader;
use crate::probes::{
    file_open::FileOpen, process_exec::ProcessExec, tcp_close::TcpClose, tcp_connect::TcpConnect,
    tcp_retransmit::TcpRetransmit,
};
use crate::reader::{self, ProbeStats};
use crate::registry::ProbeRegistry;
use crate::sensitive_paths;
use crate::store::EventStore;

/// Builder for configuring and running jälki.
pub struct Runtime {
    probes: Vec<Arc<dyn Probe>>,
    sink: Option<Box<dyn EvidenceSink>>,
    ebpf_path: String,
    cluster: String,
    enricher: Arc<dyn RuntimeEnricher>,
    sensitive_paths: Vec<String>,
    /// When set, only evidence bound to one of these Kubernetes namespaces is
    /// delivered to the sink — the source-side volume control that keeps jälki
    /// from shipping the whole-node firehose. `None` = deliver all (bound)
    /// evidence. Applies to the evidence-sink path only; the local CLI/IPC
    /// query surface still sees everything.
    namespace_allowlist: Option<HashSet<String>>,
}

impl Runtime {
    pub fn new(ebpf_path: impl Into<String>) -> Self {
        Self {
            probes: Vec::new(),
            sink: None,
            ebpf_path: ebpf_path.into(),
            cluster: hostname::get()
                .ok()
                .and_then(|h| h.into_string().ok())
                .unwrap_or_else(|| "unknown".into()),
            enricher: Arc::new(NoopEnricher),
            sensitive_paths: sensitive_paths::default_sensitive_paths(),
            namespace_allowlist: None,
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

    pub fn sink_to(mut self, sink: Box<dyn EvidenceSink>) -> Self {
        self.sink = Some(sink);
        self
    }

    pub fn enrich_with(mut self, enricher: Arc<dyn RuntimeEnricher>) -> Self {
        self.enricher = enricher;
        self
    }

    pub fn sensitive_paths(mut self, sensitive_paths: Vec<String>) -> Self {
        self.sensitive_paths = sensitive_paths;
        self
    }

    /// Restrict sink delivery to evidence bound to these Kubernetes namespaces.
    /// Empty = no restriction (deliver all bound evidence). This is the
    /// source-side volume control (mirrors the tetragon-adapter's namespace
    /// allow-list); it scopes only the sink path, not the local CLI query view.
    pub fn namespace_allowlist(mut self, namespaces: Vec<String>) -> Self {
        let set: HashSet<String> = namespaces
            .into_iter()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        self.namespace_allowlist = (!set.is_empty()).then_some(set);
        self
    }

    /// Run the jälki daemon: load eBPF, attach probes, drain events, emit.
    ///
    /// Returns a `DaemonHandle` for runtime operations (IPC, CLI).
    /// The daemon runs until the returned future completes.
    pub async fn run(self) -> Result<()> {
        let metrics = Arc::new(Metrics::new());
        let store = Arc::new(EventStore::new(10_000));
        let registry = Arc::new(ProbeRegistry::new());
        let kb = Arc::new(KnowledgeBase::load());

        info!(
            probes = self.probes.len(),
            sink = self.sink.as_ref().map(|s| s.name()).unwrap_or("stdout"),
            cluster = %self.cluster,
            "starting jalki"
        );

        // Load and attach eBPF programs — driven by probe metadata.
        let mut ebpf = loader::load_and_attach(
            Path::new(&self.ebpf_path),
            &self.probes,
            &self.sensitive_paths,
        )?;

        // Load BTF for runtime probe attachment.
        let btf = Btf::from_sys_fs().context("failed to load BTF from /sys/kernel/btf/vmlinux")?;
        let btf_data = jalki_codegen::btf::BtfData::from_sys_fs()
            .context("failed to parse BTF for codegen")?;

        let producer = producer_metadata(&self.cluster);
        let sensitive_path_matcher = Arc::new(sensitive_paths::SensitivePathMatcher::new(
            self.sensitive_paths.clone(),
        ));

        // Channel: readers → sink loop.
        let (tx, mut rx) = mpsc::channel::<Vec<EvidenceRecord>>(8192);

        // Spawn a reader for each probe, register in the registry.
        let mut stats_map: Vec<(String, Arc<ProbeStats>)> = Vec::new();
        for probe in &self.probes {
            let stats = Arc::new(ProbeStats::new());
            reader::spawn_reader(
                &mut ebpf,
                probe.clone(),
                self.cluster.clone(),
                tx.clone(),
                stats.clone(),
                store.clone(),
                self.enricher.clone(),
                sensitive_path_matcher.clone(),
            )?;
            registry.register_startup_probe(probe.clone(), stats.clone());
            stats_map.push((probe.name().to_string(), stats));
        }

        // Build the daemon handle for IPC and CLI.
        let handle = Arc::new(DaemonHandle {
            ebpf: Mutex::new(ebpf),
            btf,
            btf_data,
            registry: registry.clone(),
            store: store.clone(),
            kb: kb.clone(),
            tx: tx.clone(),
            cluster: self.cluster.clone(),
            enricher: self.enricher.clone(),
            sensitive_path_matcher: sensitive_path_matcher.clone(),
        });

        // Spawn self-observability: periodically emit drops/errors as evidence.
        let stats_tx = tx.clone();
        let stats_cluster = self.cluster.clone();
        let stats_for_task = stats_map.clone();
        tokio::spawn(async move {
            emit_self_observability(stats_for_task, stats_tx, &stats_cluster).await;
        });

        // Spawn IPC server.
        let ipc_handle = handle.clone();
        tokio::spawn(async move {
            if let Err(e) = crate::ipc::serve(ipc_handle).await {
                error!(error = %e, "IPC server failed");
            }
        });

        // Drop the original sender so the channel closes when all readers stop.
        drop(tx);

        // Sink loop: one EvidenceBatch per ring-buffer drain cycle, with a
        // bounded retry buffer for transient downstream failures.
        let sink = self
            .sink
            .unwrap_or_else(|| Box::new(jalki_evidence::StdoutSink::new()));
        let metrics_clone = metrics.clone();
        let producer_for_sink = producer.clone();
        let enricher_for_metrics = self.enricher.clone();
        let namespace_allowlist = self.namespace_allowlist.clone();

        let sink_handle = tokio::spawn(async move {
            let retry_config = RetryBufferConfig::from_env();
            info!(
                max_records = retry_config.max_records,
                max_batches = retry_config.max_batches,
                max_age_ms = retry_config.max_age_ms,
                max_bytes = retry_config.max_bytes,
                "retry buffer bounded (sheds oldest as gap evidence past these; \
                 tune via JALKI_RETRY_MAX_{{RECORDS,BATCHES,AGE_MS,BYTES}})"
            );
            match &namespace_allowlist {
                Some(ns) => info!(
                    namespaces = ?ns,
                    "namespace allow-list active: only bound evidence in these \
                     namespaces is delivered to the sink"
                ),
                None => info!(
                    "no namespace allow-list: delivering all bound evidence \
                     (set JALKI_NAMESPACES to scope the whole-node firehose)"
                ),
            }
            let mut retry_buffer = RetryBuffer::new(retry_config);
            let mut pending_gap = None;
            let retry_clock_start = Instant::now();
            while let Some(mut records) = rx.recv().await {
                if records.is_empty() {
                    continue;
                }

                record_unbound_drops(&metrics_clone, &records);
                refresh_binding_cache_metrics(&metrics_clone, enricher_for_metrics.as_ref());

                // Source-side volume control: keep only evidence bound to an
                // allowed namespace. Out-of-scope namespaces are deliberately
                // not observed here (a scope, not a loss — no gap evidence),
                // mirroring the tetragon-adapter's namespace filter.
                if let Some(allow) = &namespace_allowlist {
                    let before = records.len();
                    records.retain(|r| r.bound_namespace().is_some_and(|ns| allow.contains(ns)));
                    let dropped = before - records.len();
                    if dropped > 0 {
                        tracing::debug!(dropped, "records filtered by namespace allow-list");
                    }
                    if records.is_empty() {
                        continue;
                    }
                }

                let now_ms = elapsed_ms(retry_clock_start);
                merge_gaps(&mut pending_gap, retry_buffer.drop_expired(now_ms));

                let batch = EvidenceBatch::new(producer_for_sink.clone(), records);
                if retry_buffer.is_empty() && pending_gap.is_none() {
                    match sink.append_batch(batch.clone()).await {
                        Ok(_) => continue,
                        Err(err) if RetryBuffer::should_retry(&err) => {
                            record_sink_error(&metrics_clone, sink.name());
                            merge_gaps(&mut pending_gap, retry_buffer.enqueue(batch, now_ms));
                            warn!(
                                sink = sink.name(),
                                error = %err,
                                queued_batches = retry_buffer.len_batches(),
                                queued_records = retry_buffer.len_records(),
                                queued_bytes = retry_buffer.len_bytes(),
                                "evidence sink append failed; retrying later"
                            );
                            continue;
                        }
                        Err(err) => {
                            record_sink_error(&metrics_clone, sink.name());
                            error!(
                                sink = sink.name(),
                                error = %err,
                                "evidence sink append failed permanently; dropping batch"
                            );
                            merge_gap(
                                &mut pending_gap,
                                gap_for_batch(terminal_gap_cause(&err), &batch),
                            );
                        }
                    }
                } else {
                    merge_gaps(&mut pending_gap, retry_buffer.enqueue(batch, now_ms));
                }

                flush_retry_buffer(
                    sink.as_ref(),
                    &mut retry_buffer,
                    &mut pending_gap,
                    &metrics_clone,
                    &producer_for_sink,
                )
                .await;
            }

            while !retry_buffer.is_empty() || pending_gap.is_some() {
                let before = (retry_buffer.len_batches(), pending_gap.is_some());
                flush_retry_buffer(
                    sink.as_ref(),
                    &mut retry_buffer,
                    &mut pending_gap,
                    &metrics_clone,
                    &producer_for_sink,
                )
                .await;
                if (retry_buffer.len_batches(), pending_gap.is_some()) == before {
                    break;
                }
            }

            info!("sink loop finished");
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

        sink_handle.await?;
        Ok(())
    }
}

/// Handle for runtime operations against a running jälki daemon.
///
/// Shared across IPC server, MCP, and CLI. All methods are safe to call
/// concurrently — the Ebpf object is protected by a Mutex.
pub struct DaemonHandle {
    ebpf: Mutex<Ebpf>,
    btf: Btf,
    btf_data: jalki_codegen::btf::BtfData,
    pub registry: Arc<ProbeRegistry>,
    pub store: Arc<EventStore>,
    pub kb: Arc<KnowledgeBase>,
    tx: mpsc::Sender<Vec<EvidenceRecord>>,
    pub cluster: String,
    enricher: Arc<dyn RuntimeEnricher>,
    sensitive_path_matcher: Arc<sensitive_paths::SensitivePathMatcher>,
}

impl DaemonHandle {
    /// Deploy a probe by kernel function name at runtime.
    ///
    /// Fast path: pre-compiled probes (tcp_connect, tcp_close, tcp_retransmit_skb).
    /// Slow path: codegen — generate BPF bytecode from BTF at runtime.
    pub async fn deploy_probe(&self, function: &str, _sample_rate: f64) -> Result<String> {
        // Fast path: pre-compiled probes.
        let pre_compiled: Option<Arc<dyn Probe>> = match function {
            "sched_process_exec" | "process_exec" => Some(Arc::new(ProcessExec::new())),
            "tcp_connect" => Some(Arc::new(TcpConnect::new())),
            "tcp_close" => Some(Arc::new(TcpClose::new())),
            "tcp_retransmit_skb" => Some(Arc::new(TcpRetransmit::new())),
            "security_file_open" | "file_open" => Some(Arc::new(FileOpen::new())),
            _ => None,
        };

        if let Some(probe) = pre_compiled {
            let mut ebpf = self.ebpf.lock().await;
            let probe_id = self.registry.attach(
                probe,
                &mut ebpf,
                &self.btf,
                &self.cluster,
                self.tx.clone(),
                &self.store,
                self.enricher.clone(),
                self.sensitive_path_matcher.clone(),
            )?;
            return Ok(probe_id.to_string());
        }

        // Slow path: codegen.
        info!(function = function, "generating probe via codegen");
        self.deploy_codegen(function).await
    }

    /// Generate and deploy a probe for any kernel function using codegen.
    async fn deploy_codegen(&self, function: &str) -> Result<String> {
        // Determine attachment type from knowledge base, default to fentry.
        let (attachment, event_type, fields) = match self.kb.get_probe(function) {
            Some(probe_info) => {
                let attach = match probe_info.attachment.as_str() {
                    "fexit" => jalki_codegen::program::AttachType::Fexit,
                    _ => jalki_codegen::program::AttachType::Fentry,
                };
                let fields: Vec<String> = probe_info
                    .fields
                    .iter()
                    .filter(|f| f.important)
                    .map(|f| f.name.clone())
                    .collect();
                (attach, probe_info.event_type.clone(), fields)
            }
            None => {
                // No KB entry — generate a minimal probe with basic fields.
                // Try fexit first (gives return value).
                let attach = jalki_codegen::program::AttachType::Fentry;
                let event_type = format!("kernel.{}", function.replace('_', "."));
                let fields = vec!["comm".to_string()];
                (attach, event_type, fields)
            }
        };

        // Map KB field names to BTF paths.
        let btf_fields = map_kb_fields_to_btf(function, &fields, &self.btf_data);

        let spec = jalki_codegen::program::ProbeSpec {
            function: function.to_string(),
            attachment,
            fields: btf_fields,
            event_type: event_type.clone(),
        };

        let generated = jalki_codegen::generate(&spec, &self.btf_data)
            .with_context(|| format!("codegen failed for {function}"))?;

        info!(
            function = function,
            event_size = generated.event_size,
            instructions = generated.spec.fields.len(),
            "probe generated"
        );

        // Load the generated ELF.
        let mut gen_ebpf = Ebpf::load(&generated.elf_bytes)
            .with_context(|| format!("failed to load generated ELF for {function}"))?;

        // Populate PID filter.
        crate::filter::populate_pid_filter(&mut gen_ebpf)?;

        // Create the probe reader.
        // Find the program name — it's the only text section symbol.
        let prog_name = format!("jalki_codegen_{function}");
        let probe = Arc::new(GeneratedProbeReader::new(
            spec,
            generated.field_layout,
            generated.event_size,
            generated.map_name,
            prog_name.clone(),
        ));

        // Attach via BTF.
        let probe_id = self.registry.attach(
            probe,
            &mut gen_ebpf,
            &self.btf,
            &self.cluster,
            self.tx.clone(),
            &self.store,
            self.enricher.clone(),
            self.sensitive_path_matcher.clone(),
        )?;

        // Keep the generated Ebpf object alive (it owns the loaded programs).
        // TODO: Store in a Vec<Ebpf> on DaemonHandle to prevent drop.
        // For now, leak it — this is correct but not ideal.
        std::mem::forget(gen_ebpf);

        Ok(probe_id.to_string())
    }
}

fn producer_metadata(cluster: &str) -> ProducerMetadata {
    let node_id = hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_else(|| "unknown".into());
    let kernel_release = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".into());
    ProducerMetadata::new(cluster, node_id, kernel_release)
}

async fn flush_retry_buffer(
    sink: &dyn EvidenceSink,
    retry_buffer: &mut RetryBuffer,
    pending_gap: &mut Option<GapReport>,
    metrics: &Metrics,
    producer: &ProducerMetadata,
) {
    if let Some(gap) = pending_gap.take() {
        match sink
            .append_batch(gap.clone().into_batch(producer.clone()))
            .await
        {
            Ok(_) => {}
            Err(err) if RetryBuffer::should_retry(&err) => {
                record_sink_error(metrics, sink.name());
                warn!(
                    sink = sink.name(),
                    error = %err,
                    "gap evidence delivery failed; retrying later"
                );
                *pending_gap = Some(gap);
                return;
            }
            Err(err) => {
                record_sink_error(metrics, sink.name());
                error!(
                    sink = sink.name(),
                    error = %err,
                    "gap evidence delivery failed permanently"
                );
            }
        }
    }

    while let Some(batch) = retry_buffer.front().cloned() {
        match sink.append_batch(batch).await {
            Ok(_) => {
                retry_buffer.pop_delivered();
            }
            Err(err) if RetryBuffer::should_retry(&err) => {
                record_sink_error(metrics, sink.name());
                warn!(
                    sink = sink.name(),
                    error = %err,
                    queued_batches = retry_buffer.len_batches(),
                    queued_records = retry_buffer.len_records(),
                    queued_bytes = retry_buffer.len_bytes(),
                    "evidence sink append failed; retrying later"
                );
                break;
            }
            Err(err) => {
                record_sink_error(metrics, sink.name());
                error!(
                    sink = sink.name(),
                    error = %err,
                    "evidence sink append failed permanently; dropping batch"
                );
                let dropped = retry_buffer.pop_delivered();
                if let Some(dropped) = dropped {
                    merge_gap(
                        pending_gap,
                        gap_for_batch(terminal_gap_cause(&err), &dropped),
                    );
                }
                break;
            }
        }
    }
}

fn merge_gaps(pending: &mut Option<GapReport>, gaps: impl IntoIterator<Item = GapReport>) {
    for gap in gaps {
        merge_gap(pending, gap);
    }
}

fn merge_gap(pending: &mut Option<GapReport>, gap: GapReport) {
    match pending {
        Some(existing) => existing.merge(gap),
        None => *pending = Some(gap),
    }
}

fn gap_for_batch(cause: &str, batch: &EvidenceBatch) -> GapReport {
    GapReport {
        cause: cause.into(),
        dropped_records: batch.len(),
        gap_start_ns: batch.observed_at_min,
        gap_end_ns: batch.observed_at_max,
    }
}

fn record_sink_error(metrics: &Metrics, sink: &str) {
    metrics
        .sink_errors
        .get_or_create(&SinkLabel { sink: sink.into() })
        .inc();
}

fn record_unbound_drops(metrics: &Metrics, records: &[EvidenceRecord]) {
    for record in records {
        if let Some(reason) = record.plane_b_drop_reason() {
            metrics
                .unbound_dropped_total
                .get_or_create(&UnboundDropLabel {
                    reason: reason.as_str().into(),
                })
                .inc();
        }
    }
}

fn refresh_binding_cache_metrics(metrics: &Metrics, enricher: &dyn RuntimeEnricher) {
    if let Some(stats) = enricher.binding_cache_stats() {
        metrics.binding_cache_entries.set(stats.entries as i64);
        metrics.binding_cache_hit_ratio.set(stats.hit_ratio);
    }
}

fn terminal_gap_cause(error: &SinkError) -> &'static str {
    match error {
        SinkError::InvalidRecord { .. } => "sink_invalid_record",
        SinkError::Rejected { .. } => "sink_rejected",
        SinkError::Unauthorized { .. } => "sink_unauthorized",
        SinkError::Misconfigured { .. } => "sink_misconfigured",
        SinkError::PartialFailure { .. } => "sink_partial_failure",
        SinkError::Unsupported { .. } => "sink_unsupported",
        SinkError::Unavailable { .. }
        | SinkError::Timeout { .. }
        | SinkError::Backpressure { .. } => "sink_retryable_failure",
    }
}

fn elapsed_ms(start: Instant) -> u64 {
    start.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
}

/// Map knowledge base field names to BTF field paths.
///
/// KB fields like "src_ip", "dst_port" are human-friendly.
/// BTF needs "sk.__sk_common.skc_rcv_saddr", etc.
fn map_kb_fields_to_btf(
    function: &str,
    kb_fields: &[String],
    btf_data: &jalki_codegen::btf::BtfData,
) -> Vec<String> {
    let mut result = Vec::new();

    // Check if the function's first param is a sock pointer.
    let has_sock = btf_data
        .resolve_function(function)
        .ok()
        .and_then(|sig| sig.params.first().cloned())
        .map(|p| p.name == "sk")
        .unwrap_or(false);

    for field in kb_fields {
        match field.as_str() {
            "src_ip" if has_sock => result.push("sk.__sk_common.skc_rcv_saddr".into()),
            "dst_ip" if has_sock => result.push("sk.__sk_common.skc_daddr".into()),
            "src_port" if has_sock => result.push("sk.__sk_common.skc_num".into()),
            "dst_port" if has_sock => result.push("sk.__sk_common.skc_dport".into()),
            "tcp_state" if has_sock => result.push("sk.__sk_common.skc_state".into()),
            "pid" | "tid" | "timestamp_ns" => {} // always included in header
            "command" | "comm" => result.push("comm".into()),
            "ret" => result.push("ret".into()),
            // Pass through anything that looks like a BTF path already.
            other if other.contains('.') => result.push(other.to_string()),
            _ => {
                // Unknown field — try "comm" as a safe default.
                // Don't add unknown fields that would cause codegen to fail.
            }
        }
    }

    // Always include comm if not already present.
    if !result.iter().any(|f| f == "comm") {
        result.push("comm".into());
    }

    result
}

/// Periodically check probe stats and emit self-observability Occurrences.
///
/// If AHTI sees a gap in events and doesn't know jälki dropped them,
/// it will misdiagnose. These events close that gap.
async fn emit_self_observability(
    stats_map: Vec<(String, Arc<ProbeStats>)>,
    tx: mpsc::Sender<Vec<EvidenceRecord>>,
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
                let _ = tx.try_send(vec![self_observability_record(occ)]);
            }

            if new_errors > 0 {
                warn!(probe = %probe_name, errors = new_errors, "parse errors detected");
                let occ = Occurrence::new("jalki/self", "jalki.probe.parse_errors")
                    .severity(Severity::Warning)
                    .in_cluster(cluster);
                let _ = tx.try_send(vec![self_observability_record(occ)]);
            }

            prev_dropped[i] = dropped;
            prev_errors[i] = errors;
        }
    }
}

fn self_observability_record(occurrence: Occurrence) -> EvidenceRecord {
    EvidenceRecord {
        observed_at_ns: 0,
        pid: 0,
        cgroup_id: 0,
        probe: ProbeMetadata {
            probe_id: "jalki_self".into(),
            probe_version: "1".into(),
            probe_family: "agent".into(),
            hook_kind: HookKind::Fentry,
            kernel_function: "jalki_self_observability".into(),
        },
        occurrence,
        binding: None,
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

use std::collections::HashSet;
use std::path::Path;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use aya::{Btf, Ebpf};
use false_protocol::{Occurrence, Severity};
use jalki_evidence::{
    EvidenceBatch, EvidenceRecord, EvidenceSink, GapReport, HookKind, ProbeMetadata,
    ProducerMetadata, RetryBackoff, RetryBackoffConfig, RetryBuffer, RetryBufferConfig, SinkError,
};
use tokio::sync::{mpsc, Mutex};
use tokio::time::Instant as Deadline;
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
    /// source-side volume control; it scopes only the sink path, not the local
    /// CLI query view.
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
        let (tx, rx) = mpsc::channel::<Vec<EvidenceRecord>>(8192);

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
        let backoff_config = RetryBackoffConfig::from_env();
        info!(
            base_ms = backoff_config.base_ms,
            max_ms = backoff_config.max_ms,
            "sink retries are timer-driven and jittered, independent of event \
             arrival (tune via JALKI_RETRY_BACKOFF_{{BASE_MS,MAX_MS}})"
        );

        let sink_handle = tokio::spawn(run_sink_loop(SinkLoop {
            rx,
            sink,
            metrics: metrics_clone,
            producer: producer_for_sink,
            enricher: enricher_for_metrics,
            namespace_allowlist,
            retry_config,
            backoff_config,
        }));

        // Spawn metrics server.
        let _metrics_handle = {
            let metrics = metrics.clone();
            tokio::spawn(async move {
                if let Err(e) = serve_metrics(metrics).await {
                    error!(error = %e, "metrics server failed");
                }
            })
        };

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

/// Inputs for [`run_sink_loop`]. A struct rather than eight positional
/// arguments, and separate from `Runtime` so the loop can be driven directly by
/// tests — the daemon itself cannot be, because loading eBPF needs a kernel.
pub(crate) struct SinkLoop {
    pub rx: mpsc::Receiver<Vec<EvidenceRecord>>,
    pub sink: Box<dyn EvidenceSink>,
    pub metrics: Arc<Metrics>,
    pub producer: ProducerMetadata,
    pub enricher: Arc<dyn RuntimeEnricher>,
    pub namespace_allowlist: Option<HashSet<String>>,
    pub retry_config: RetryBufferConfig,
    pub backoff_config: RetryBackoffConfig,
}

/// One `EvidenceBatch` per ring-buffer drain cycle, with a bounded retry buffer
/// for transient downstream failures and a timer that owns the retry cadence.
pub(crate) async fn run_sink_loop(loop_state: SinkLoop) {
    let SinkLoop {
        mut rx,
        sink,
        metrics: metrics_clone,
        producer: producer_for_sink,
        enricher: enricher_for_metrics,
        namespace_allowlist,
        retry_config,
        backoff_config,
    } = loop_state;

    let mut retry_buffer = RetryBuffer::new(retry_config);
    let mut backoff = RetryBackoff::new(backoff_config);
    let mut pending_gaps = PendingGaps::default();
    let retry_clock_start = Instant::now();
    // Absolute deadline of the next retry sweep; `None` means there is
    // no backlog and the timer arm stays disabled, so an idle agent
    // costs nothing. Absolute rather than a duration because `select!`
    // rebuilds the sleep on every iteration — a relative delay would be
    // pushed back by each arriving batch and, on a busy node, never
    // fire.
    let mut next_retry: Option<Deadline> = None;

    loop {
        // `select!` constructs *every* branch's future before consulting
        // the preconditions (verified: a disabled arm's expression still
        // runs), so this has to be safe to build with no backlog. The
        // `if` below is what stops the arm from ever firing then; the
        // far-future value is only there to have something to construct.
        let retry_at = next_retry.unwrap_or_else(|| Deadline::now() + IDLE_PARK);

        // No `biased;` — deliberately. `select!` picks randomly among ready
        // branches, which is the only thing keeping the retry arm alive on a
        // node where `rx.recv()` is *always* ready. Adding `biased;` to
        // prioritise fresh evidence would starve the timer and put us straight
        // back to the traffic-coupled retries this issue is about.
        tokio::select! {
            maybe_records = rx.recv() => {
                let Some(mut records) = maybe_records else { break };
                if records.is_empty() {
                    continue;
                }

                record_unbound_drops(&metrics_clone, &records);
                refresh_binding_cache_metrics(&metrics_clone, enricher_for_metrics.as_ref());

                // Source-side volume control: keep only evidence bound to an
                // allowed namespace. Out-of-scope namespaces are deliberately
                // not observed here (a scope, not a loss — no gap evidence).
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
                pending_gaps.extend(retry_buffer.drop_expired(now_ms));

                let batch = EvidenceBatch::new(producer_for_sink.clone(), records);
                if retry_buffer.is_empty() && pending_gaps.is_empty() {
                    // Nothing queued, so the sink is presumed working:
                    // deliver inline and keep the latency.
                    match sink.append_batch(batch.clone()).await {
                        Ok(_) => {
                            backoff.reset();
                        }
                        Err(err) if RetryBuffer::should_retry(&err) => {
                            record_sink_error(&metrics_clone, sink.name());
                            pending_gaps.extend(retry_buffer.enqueue(batch, now_ms));
                            warn!(
                                sink = sink.name(),
                                error = %err,
                                queued_batches = retry_buffer.len_batches(),
                                queued_records = retry_buffer.len_records(),
                                queued_bytes = retry_buffer.len_bytes(),
                                "evidence sink append failed; retrying later"
                            );
                        }
                        Err(err) => {
                            record_sink_error(&metrics_clone, sink.name());
                            error!(
                                sink = sink.name(),
                                error = %err,
                                "evidence sink append failed permanently; dropping batch"
                            );
                            pending_gaps.merge(gap_for_batch(terminal_gap_cause(&err), &batch));
                        }
                    }
                } else {
                    // A backlog exists, so the sink is known to be
                    // refusing work: queue behind it and let the timer
                    // decide when to try again. Retrying here is what
                    // used to hammer a struggling sink once per drain
                    // cycle, and what tied a quiet node's retries to
                    // traffic it wasn't receiving (jalki #39).
                    pending_gaps.extend(retry_buffer.enqueue(batch, now_ms));
                }

                publish_backlog_metrics(&metrics_clone, &retry_buffer, now_ms);
                next_retry = schedule_retry(
                    next_retry,
                    &mut backoff,
                    has_backlog(&retry_buffer, &pending_gaps),
                    sink.name(),
                );
            }

            _ = tokio::time::sleep_until(retry_at), if next_retry.is_some() => {
                let now_ms = elapsed_ms(retry_clock_start);
                // Age out the buffer on the timer too: on a quiet node
                // nothing else calls this, so expired batches would
                // otherwise sit past max_age_ms without becoming gaps.
                pending_gaps.extend(retry_buffer.drop_expired(now_ms));

                let before = backlog_len(&retry_buffer, &pending_gaps);
                flush_retry_buffer(
                    sink.as_ref(),
                    &mut retry_buffer,
                    &mut pending_gaps,
                    &metrics_clone,
                    &producer_for_sink,
                )
                .await;

                // Any batch accepted means the sink is taking work
                // again, so start the next outage from the bottom of
                // the ladder rather than wherever this one ended.
                if backlog_len(&retry_buffer, &pending_gaps) < before {
                    backoff.reset();
                }
                publish_backlog_metrics(&metrics_clone, &retry_buffer, now_ms);
                next_retry = schedule_retry(
                    None,
                    &mut backoff,
                    has_backlog(&retry_buffer, &pending_gaps),
                    sink.name(),
                );
            }
        }
    }

    while !retry_buffer.is_empty() || !pending_gaps.is_empty() {
        let before = (retry_buffer.len_batches(), pending_gaps.len());
        flush_retry_buffer(
            sink.as_ref(),
            &mut retry_buffer,
            &mut pending_gaps,
            &metrics_clone,
            &producer_for_sink,
        )
        .await;
        publish_backlog_metrics(&metrics_clone, &retry_buffer, elapsed_ms(retry_clock_start));
        if (retry_buffer.len_batches(), pending_gaps.len()) == before {
            break;
        }
    }

    if !retry_buffer.is_empty() || !pending_gaps.is_empty() {
        // The sink is still refusing at shutdown, so this evidence dies with
        // the process. It is a real loss and it gets said out loud — silence
        // here would be indistinguishable from a clean drain (ADR-0009
        // contract 6). Surviving a restart needs the spill-to-disk half of
        // #33; this is the honesty half.
        error!(
            sink = sink.name(),
            lost_batches = retry_buffer.len_batches(),
            lost_records = retry_buffer.len_records(),
            lost_bytes = retry_buffer.len_bytes(),
            pending_gap_reports = pending_gaps.len(),
            "sink loop exiting with an undeliverable backlog; this evidence is lost"
        );
    }

    info!("sink loop finished");
}

/// How far out to park the retry timer when there is no backlog. Never elapses
/// in practice — the arm is disabled — it just gives `select!` a deadline to
/// construct.
const IDLE_PARK: Duration = Duration::from_secs(3600);

fn has_backlog(retry_buffer: &RetryBuffer, pending_gaps: &PendingGaps) -> bool {
    !retry_buffer.is_empty() || !pending_gaps.is_empty()
}

fn backlog_len(retry_buffer: &RetryBuffer, pending_gaps: &PendingGaps) -> usize {
    retry_buffer.len_batches() + pending_gaps.len()
}

/// Decide when the backlog gets its next attempt.
///
/// Passing `Some(deadline)` as `current` keeps an already-scheduled attempt
/// rather than pushing it out — otherwise arriving evidence would postpone the
/// retry it is queueing behind, which is the traffic-coupling jalki #39 exists
/// to remove.
fn schedule_retry(
    current: Option<Deadline>,
    backoff: &mut RetryBackoff,
    backlog: bool,
    sink_name: &str,
) -> Option<Deadline> {
    if !backlog {
        backoff.reset();
        return None;
    }
    if let Some(deadline) = current {
        return Some(deadline);
    }
    let delay_ms = backoff.next_delay_ms();
    info!(
        sink = sink_name,
        delay_ms,
        attempt = backoff.attempt(),
        "backlog queued; next sink retry scheduled"
    );
    Some(Deadline::now() + Duration::from_millis(delay_ms))
}

async fn flush_retry_buffer(
    sink: &dyn EvidenceSink,
    retry_buffer: &mut RetryBuffer,
    pending_gaps: &mut PendingGaps,
    metrics: &Metrics,
    producer: &ProducerMetadata,
) {
    while let Some(batch) = pending_gaps.front(producer) {
        match sink.append_batch(batch).await {
            Ok(_) => pending_gaps.pop_front(),
            Err(err) if RetryBuffer::should_retry(&err) => {
                record_sink_error(metrics, sink.name());
                warn!(
                    sink = sink.name(),
                    error = %err,
                    "gap evidence delivery failed; retrying later"
                );
                return;
            }
            Err(err) => {
                record_sink_error(metrics, sink.name());
                error!(
                    sink = sink.name(),
                    error = %err,
                    "gap evidence delivery failed permanently"
                );
                pending_gaps.pop_front();
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
                    pending_gaps.merge(gap_for_batch(terminal_gap_cause(&err), &dropped));
                }
                break;
            }
        }
    }
}

#[derive(Default)]
struct PendingGaps {
    in_flight: Option<EvidenceBatch>,
    queued: Option<GapReport>,
}

impl PendingGaps {
    fn merge(&mut self, gap: GapReport) {
        match &mut self.queued {
            Some(existing) => existing.merge(gap),
            None => self.queued = Some(gap),
        }
    }

    fn extend(&mut self, gaps: impl IntoIterator<Item = GapReport>) {
        for gap in gaps {
            self.merge(gap);
        }
    }

    fn front(&mut self, producer: &ProducerMetadata) -> Option<EvidenceBatch> {
        if self.in_flight.is_none() {
            self.in_flight = self
                .queued
                .take()
                .map(|gap| gap.into_batch(producer.clone()));
        }
        self.in_flight.clone()
    }

    fn pop_front(&mut self) {
        self.in_flight = None;
    }

    fn is_empty(&self) -> bool {
        self.in_flight.is_none() && self.queued.is_none()
    }

    fn len(&self) -> usize {
        usize::from(self.in_flight.is_some()) + usize::from(self.queued.is_some())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_gap_retries_keep_the_same_ids() {
        let producer = ProducerMetadata::new("test", "node-1", "6.17.0");
        let mut pending = PendingGaps::default();
        pending.merge(GapReport {
            cause: "retry_buffer_overflow".into(),
            dropped_records: 1,
            gap_start_ns: 10,
            gap_end_ns: 20,
        });

        let first = pending.front(&producer).expect("pending gap");
        let retry = pending.front(&producer).expect("same pending gap");

        assert_eq!(retry.batch_id, first.batch_id);
        assert_eq!(
            retry.records[0].occurrence.id,
            first.records[0].occurrence.id
        );
    }

    // ── sink loop retry cadence (jalki #39) ─────────────────────────────────
    //
    // Driven on tokio's paused clock: `advance` fires the retry timer without
    // the tests taking the wall-clock time the schedule describes, and — more
    // importantly — makes "did it retry on its own?" a deterministic question
    // rather than a sleep-and-hope.

    use jalki_evidence::{AppendResult, Checkpoint, HealthStatus, KernelEvent, TcpConnectEvent};
    use std::sync::atomic::{AtomicBool, AtomicUsize};
    use std::sync::Mutex as StdMutex;

    /// A sink whose availability the test controls, counting every attempt.
    struct ControlledSink {
        up: Arc<AtomicBool>,
        attempts: Arc<AtomicUsize>,
        delivered: Arc<StdMutex<Vec<String>>>,
    }

    #[async_trait::async_trait]
    impl EvidenceSink for ControlledSink {
        fn name(&self) -> &str {
            "controlled"
        }

        async fn append_batch(&self, batch: EvidenceBatch) -> Result<AppendResult, SinkError> {
            self.attempts.fetch_add(1, Ordering::SeqCst);
            if !self.up.load(Ordering::SeqCst) {
                return Err(SinkError::Unavailable {
                    sink: "controlled".into(),
                    message: "test sink is down".into(),
                });
            }
            let n = batch.len();
            self.delivered.lock().unwrap().push(batch.batch_id.clone());
            Ok(AppendResult {
                accepted_count: n,
                rejected_count: 0,
                sink_name: "controlled".into(),
                watermark: Some(Checkpoint {
                    value: batch.batch_id,
                }),
                warnings: Vec::new(),
            })
        }

        async fn health(&self) -> HealthStatus {
            HealthStatus::Healthy
        }
    }

    struct Harness {
        tx: mpsc::Sender<Vec<EvidenceRecord>>,
        up: Arc<AtomicBool>,
        attempts: Arc<AtomicUsize>,
        delivered: Arc<StdMutex<Vec<String>>>,
        metrics: Arc<Metrics>,
        handle: tokio::task::JoinHandle<()>,
    }

    fn spawn_loop(backoff_config: RetryBackoffConfig) -> Harness {
        let (tx, rx) = mpsc::channel::<Vec<EvidenceRecord>>(64);
        let up = Arc::new(AtomicBool::new(false));
        let attempts = Arc::new(AtomicUsize::new(0));
        let delivered = Arc::new(StdMutex::new(Vec::new()));
        let metrics = Arc::new(Metrics::new());
        let handle = tokio::spawn(run_sink_loop(SinkLoop {
            rx,
            sink: Box::new(ControlledSink {
                up: up.clone(),
                attempts: attempts.clone(),
                delivered: delivered.clone(),
            }),
            metrics: metrics.clone(),
            producer: ProducerMetadata::new("test", "node-1", "6.17.0"),
            enricher: Arc::new(NoopEnricher),
            namespace_allowlist: None,
            retry_config: RetryBufferConfig::default(),
            backoff_config,
        }));
        Harness {
            tx,
            up,
            attempts,
            delivered,
            metrics,
            handle,
        }
    }

    /// Let the loop consume whatever is queued. On a paused clock nothing else
    /// advances the scheduler, so a single `yield_now` only gets one batch
    /// through — a count sampled too early reads as "throttled" when it really
    /// means "not delivered yet".
    async fn drain(h: &Harness) {
        for _ in 0..2_000 {
            if h.tx.capacity() == h.tx.max_capacity() {
                break;
            }
            tokio::task::yield_now().await;
        }
        for _ in 0..64 {
            tokio::task::yield_now().await;
        }
    }

    fn one_record() -> Vec<EvidenceRecord> {
        let event = KernelEvent::TcpConnect(TcpConnectEvent {
            observed_at_ns: 1_000,
            pid: 1,
            tid: 1,
            src_ip: "10.0.0.1".parse().unwrap(),
            dst_ip: "10.0.0.2".parse().unwrap(),
            src_port: 1234,
            dst_port: 443,
            addr_family: 2,
            ret: 0,
            cgroup_id: 1,
            comm: "test".into(),
            netns: 0,
        });
        event
            .normalize(
                ProbeMetadata {
                    probe_id: "tcp_connect".into(),
                    probe_version: "1".into(),
                    probe_family: "tcp".into(),
                    hook_kind: HookKind::Fexit,
                    kernel_function: "tcp_connect".into(),
                },
                "test",
            )
            .records
    }

    /// Acceptance criterion 1: buffered evidence is retried on the backoff
    /// schedule with **zero** further events. Before #39 the retry only ran
    /// inside the `rx.recv()` arm, so a node that went quiet during an outage
    /// held its evidence until some unrelated event arrived — possibly never.
    #[tokio::test(start_paused = true)]
    async fn a_quiet_node_retries_without_any_new_events() {
        let h = spawn_loop(RetryBackoffConfig {
            base_ms: 100,
            max_ms: 400,
        });

        // One batch against a down sink: attempted inline, then buffered.
        h.tx.send(one_record()).await.unwrap();
        tokio::time::advance(Duration::from_millis(10)).await;
        let after_first = h.attempts.load(Ordering::SeqCst);
        assert_eq!(after_first, 1, "the inline attempt still happens");

        // Nothing is sent from here on. The timer alone must drive retries.
        tokio::time::advance(Duration::from_secs(5)).await;
        tokio::task::yield_now().await;
        let retried = h.attempts.load(Ordering::SeqCst);
        assert!(
            retried > after_first,
            "a quiet node must still retry: attempts stuck at {retried}"
        );

        // And when the sink returns, the held evidence lands — still with no
        // new events to trigger it.
        h.up.store(true, Ordering::SeqCst);
        tokio::time::advance(Duration::from_secs(5)).await;
        tokio::task::yield_now().await;
        assert_eq!(
            h.delivered.lock().unwrap().len(),
            1,
            "buffered batch delivers once the sink recovers"
        );

        drop(h.tx);
        let _ = h.handle.await;
    }

    /// Acceptance criterion 2: under load against a down sink, the attempt rate
    /// follows the backoff cap, not the event rate. Before #39 every arriving
    /// batch triggered a flush, so a busy node hammered a struggling sink.
    #[tokio::test(start_paused = true)]
    async fn attempt_rate_follows_the_cap_not_the_event_rate() {
        let h = spawn_loop(RetryBackoffConfig {
            base_ms: 1_000,
            max_ms: 1_000,
        });

        // 200 batches against a down sink, all inside one backoff window.
        for _ in 0..200 {
            h.tx.send(one_record()).await.unwrap();
        }
        drain(&h).await;

        let attempts = h.attempts.load(Ordering::SeqCst);
        assert!(
            attempts <= 2,
            "200 batches inside one backoff window must not become 200 RPCs; got {attempts}"
        );

        // Without this the assertion above is satisfied just as well by a loop
        // that never consumed the channel — which is exactly how an earlier
        // version of this test passed against the pre-#39 code it was meant to
        // fail against. Delivering all 200 proves they were really ingested and
        // held, so the low attempt count means throttling and not backlog.
        h.up.store(true, Ordering::SeqCst);
        tokio::time::advance(Duration::from_secs(5)).await;
        drain(&h).await;
        assert_eq!(
            h.delivered.lock().unwrap().len(),
            200,
            "every batch was buffered while the sink was down"
        );

        drop(h.tx);
        let _ = h.handle.await;
    }

    /// The ladder is reset by success, so a second outage starts fast rather
    /// than inheriting the first one's cap.
    #[tokio::test(start_paused = true)]
    async fn delivery_resets_the_ladder_for_the_next_outage() {
        let h = spawn_loop(RetryBackoffConfig {
            base_ms: 100,
            max_ms: 10_000,
        });

        // Climb the ladder against a down sink, then let it drain.
        h.tx.send(one_record()).await.unwrap();
        tokio::time::advance(Duration::from_secs(30)).await;
        tokio::task::yield_now().await;
        h.up.store(true, Ordering::SeqCst);
        tokio::time::advance(Duration::from_secs(30)).await;
        tokio::task::yield_now().await;
        assert_eq!(
            h.delivered.lock().unwrap().len(),
            1,
            "precondition: drained"
        );

        // Second outage: the first retry must come at ~base, not at the cap the
        // previous outage climbed to.
        h.up.store(false, Ordering::SeqCst);
        h.tx.send(one_record()).await.unwrap();
        tokio::time::advance(Duration::from_millis(10)).await;
        tokio::task::yield_now().await;
        let before = h.attempts.load(Ordering::SeqCst);

        tokio::time::advance(Duration::from_millis(500)).await;
        tokio::task::yield_now().await;
        assert!(
            h.attempts.load(Ordering::SeqCst) > before,
            "a reset ladder retries within ~base_ms; it waited longer"
        );

        drop(h.tx);
        let _ = h.handle.await;
    }

    /// An idle agent with no backlog must not wake up at all — the timer arm is
    /// disabled, not merely parked far out.
    #[tokio::test(start_paused = true)]
    async fn an_idle_loop_makes_no_attempts() {
        let h = spawn_loop(RetryBackoffConfig::default());
        h.up.store(true, Ordering::SeqCst);

        tokio::time::advance(Duration::from_secs(3_600)).await;
        tokio::task::yield_now().await;

        assert_eq!(
            h.attempts.load(Ordering::SeqCst),
            0,
            "no evidence and no backlog means no RPCs"
        );

        drop(h.tx);
        let _ = h.handle.await;
    }

    // ── observability surface (jalki #42) ───────────────────────────────────

    #[test]
    fn request_paths_are_parsed_and_query_strings_stripped() {
        assert_eq!(
            request_path(b"GET /readyz HTTP/1.1\r\nHost: x\r\n\r\n").as_deref(),
            Some("/readyz")
        );
        assert_eq!(
            request_path(b"GET /metrics?debug=1 HTTP/1.1\r\n").as_deref(),
            Some("/metrics"),
            "kube-prometheus appends params; they must not turn into a 404"
        );
        assert_eq!(request_path(b"").as_deref(), None);
        assert_eq!(request_path(b"garbage\r\n").as_deref(), None);
    }

    /// Serve one request against a real socket and return (status line, body).
    async fn probe_request(metrics: &Arc<Metrics>, path: &str, max_age: u64) -> (String, String) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let m = metrics.clone();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let _ = handle_observability_request(stream, &m, max_age).await;
        });

        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        client
            .write_all(format!("GET {path} HTTP/1.1\r\nHost: t\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut raw = String::new();
        client.read_to_string(&mut raw).await.unwrap();
        let (head, body) = raw.split_once("\r\n\r\n").unwrap_or((raw.as_str(), ""));
        (
            head.lines().next().unwrap_or("").to_string(),
            body.to_string(),
        )
    }

    /// The contract vartio ADR-0009 insists on: liveness must never consult a
    /// dependency. A `/healthz` that went red during a Vartio outage would have
    /// the kubelet restart the agent — destroying the buffered evidence the
    /// outage is precisely when we need — and turn one incident into the crash
    /// loop this whole milestone exists to break.
    #[tokio::test]
    async fn healthz_ignores_the_backlog_entirely() {
        let metrics = Arc::new(Metrics::new());
        metrics.retry_queued_batches.set(9_999);
        metrics.retry_oldest_age_seconds.set(86_400.0);

        let (status, body) = probe_request(&metrics, "/healthz", 60).await;
        assert!(
            status.contains("200"),
            "a day-old backlog must not make the process look dead: {status}"
        );
        assert_eq!(body, "ok\n");
    }

    #[tokio::test]
    async fn readyz_is_ok_while_evidence_is_flowing() {
        let metrics = Arc::new(Metrics::new());
        let (status, body) = probe_request(&metrics, "/readyz", 60).await;
        assert!(status.contains("200"), "{status}");
        assert!(body.contains("status=ok"), "{body}");
    }

    /// A quiet node has nothing to deliver, which is not an outage. Readiness
    /// keys off backlog age rather than sink health precisely so these two stay
    /// distinguishable — `HealthStatus::Degraded` covers both.
    #[tokio::test]
    async fn readyz_is_ok_for_a_brief_backlog() {
        let metrics = Arc::new(Metrics::new());
        metrics.retry_queued_batches.set(120);
        metrics.retry_oldest_age_seconds.set(2.0);

        let (status, _) = probe_request(&metrics, "/readyz", 60).await;
        assert!(
            status.contains("200"),
            "a blip the backoff clears in under a second must not flap the probe: {status}"
        );
    }

    #[tokio::test]
    async fn readyz_goes_notready_once_the_backlog_is_stale() {
        let metrics = Arc::new(Metrics::new());
        metrics.retry_queued_batches.set(3);
        metrics.retry_queued_records.set(42);
        metrics.retry_oldest_age_seconds.set(120.0);

        let (status, body) = probe_request(&metrics, "/readyz", 60).await;
        assert!(
            status.contains("503"),
            "holding undeliverable evidence for 2 minutes is NotReady: {status}"
        );
        assert!(body.contains("status=stalled"), "{body}");
        assert!(
            body.contains("queued_records=42"),
            "the body has to say why, not just fail: {body}"
        );
    }

    #[tokio::test]
    async fn metrics_still_served_and_unknown_paths_404() {
        let metrics = Arc::new(Metrics::new());
        let (status, body) = probe_request(&metrics, "/metrics", 60).await;
        assert!(status.contains("200"), "{status}");
        assert!(body.contains("jalki_retry_queued_bytes"), "{body}");

        // The old server answered metrics to literally any request, so a probe
        // pointed at a typo'd path would have passed while measuring nothing.
        let (status, _) = probe_request(&metrics, "/healthzz", 60).await;
        assert!(status.contains("404"), "{status}");
    }

    #[tokio::test(start_paused = true)]
    async fn the_loop_publishes_backlog_gauges() {
        let h = spawn_loop(RetryBackoffConfig {
            base_ms: 60_000,
            max_ms: 60_000,
        });
        h.tx.send(one_record()).await.unwrap();
        drain(&h).await;

        assert!(
            h.metrics.retry_queued_batches.get() > 0,
            "a batch held for a down sink must be visible as a gauge, not only in a log line"
        );
        assert!(h.metrics.retry_queued_records.get() > 0);
        assert!(h.metrics.retry_queued_bytes.get() > 0);

        h.up.store(true, Ordering::SeqCst);
        tokio::time::advance(Duration::from_secs(120)).await;
        drain(&h).await;
        assert_eq!(
            h.metrics.retry_queued_batches.get(),
            0,
            "and must fall back to zero once delivered, or /readyz stays stuck"
        );
        assert_eq!(h.metrics.retry_oldest_age_seconds.get(), 0.0);

        drop(h.tx);
        let _ = h.handle.await;
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
/// A queued batch older than this makes the agent NotReady: it is holding
/// evidence it cannot deliver. Well above the backoff cap so an ordinary blip —
/// which #39 clears in well under a second — never flaps the probe.
const DEFAULT_READY_MAX_BACKLOG_AGE_SECS: u64 = 60;

fn ready_max_backlog_age_secs() -> u64 {
    std::env::var("JALKI_READY_MAX_BACKLOG_AGE_SECS")
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(DEFAULT_READY_MAX_BACKLOG_AGE_SECS)
}

/// Serves `/metrics`, `/healthz` and `/readyz` on :9090 (jalki #42).
///
/// Deliberately split, and the split is the point (vartio ADR-0009 rejects
/// sink-health-fed liveness probes):
///
/// - `/healthz` — **process alive only**. It must never consult the sink. A
///   liveness probe that fails during a downstream outage tells the kubelet to
///   restart the agent, which destroys the buffered evidence the outage is
///   exactly when we need, and turns one incident into a crash loop.
/// - `/readyz` — reports whether evidence is *flowing*. NotReady is a visible,
///   alertable, harmless state for a DaemonSet with no Service in front of it.
///
/// Readiness keys off backlog **age**, not the sink's `health()`. Two reasons:
/// `HealthStatus::Degraded` is overloaded (it covers "never exercised", a
/// transport error, and permanent per-item rejects alike), and a node whose
/// namespaces are simply quiet has nothing to deliver — reporting it NotReady
/// would be indistinguishable from a real outage. "Holding undeliverable
/// evidence for more than a minute" is the condition an operator actually
/// wants.
async fn serve_metrics(metrics: Arc<Metrics>) -> Result<()> {
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("0.0.0.0:9090").await?;
    let max_backlog_age = ready_max_backlog_age_secs();
    info!(
        ready_max_backlog_age_secs = max_backlog_age,
        "observability server listening on :9090 (/metrics, /healthz, /readyz)"
    );

    loop {
        let (stream, _) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(e) => {
                // A per-connection accept error (fd exhaustion, a peer that
                // vanished) used to propagate out of this function and take the
                // whole server with it — silently removing the probe surface
                // the kubelet is about to depend on.
                warn!(error = %e, "observability server accept failed; continuing");
                continue;
            }
        };
        let metrics = metrics.clone();
        // Per connection: a serial loop lets one slow scraper block every
        // subsequent request, and once probes point here that is a restart.
        tokio::spawn(async move {
            if let Err(e) = handle_observability_request(stream, &metrics, max_backlog_age).await {
                tracing::debug!(error = %e, "observability request failed");
            }
        });
    }
}

async fn handle_observability_request(
    mut stream: tokio::net::TcpStream,
    metrics: &Metrics,
    max_backlog_age_secs: u64,
) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Enough for a request line plus headers from any probe or scraper; a peer
    // that sends more, or nothing, must not pin the task forever.
    let mut buf = [0u8; 2048];
    let read = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
        .await
        .context("timed out reading request")??;
    let path = request_path(&buf[..read]);

    let (status, content_type, body) = match path.as_deref() {
        Some("/metrics") => (
            "200 OK",
            "text/plain; version=0.0.4; charset=utf-8",
            metrics.encode(),
        ),
        // No sink call, no buffer inspection, no dependency of any kind: if
        // this task is scheduled to answer, the process is alive, and that is
        // the entire claim.
        Some("/healthz") => ("200 OK", "text/plain; charset=utf-8", "ok\n".to_string()),
        Some("/readyz") => {
            let age = metrics.retry_oldest_age_seconds.get();
            let batches = metrics.retry_queued_batches.get();
            let stalled = age > max_backlog_age_secs as f64;
            let body = format!(
                "queued_batches={batches}\nqueued_records={}\nqueued_bytes={}\n\
                 oldest_age_seconds={age:.1}\nmax_backlog_age_seconds={max_backlog_age_secs}\n\
                 status={}\n",
                metrics.retry_queued_records.get(),
                metrics.retry_queued_bytes.get(),
                if stalled { "stalled" } else { "ok" },
            );
            let status = if stalled {
                "503 Service Unavailable"
            } else {
                "200 OK"
            };
            (status, "text/plain; charset=utf-8", body)
        }
        _ => (
            "404 Not Found",
            "text/plain; charset=utf-8",
            "not found\n".to_string(),
        ),
    };

    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len(),
    );
    stream.write_all(response.as_bytes()).await?;
    let _ = stream.shutdown().await;
    Ok(())
}

/// Path from an HTTP request line (`GET /readyz HTTP/1.1`), query string
/// stripped. `None` for anything that isn't one.
fn request_path(raw: &[u8]) -> Option<String> {
    let line = std::str::from_utf8(raw).ok()?.lines().next()?;
    let mut parts = line.split_whitespace();
    let _method = parts.next()?;
    let target = parts.next()?;
    Some(target.split('?').next().unwrap_or(target).to_string())
}

/// Publish retry-buffer state so `/readyz` and Prometheus can see it. Called
/// wherever the buffer changes — the loop is the only writer.
fn publish_backlog_metrics(metrics: &Metrics, retry_buffer: &RetryBuffer, now_ms: u64) {
    metrics
        .retry_queued_batches
        .set(retry_buffer.len_batches() as i64);
    metrics
        .retry_queued_records
        .set(retry_buffer.len_records() as i64);
    metrics
        .retry_queued_bytes
        .set(retry_buffer.len_bytes() as i64);
    metrics.retry_oldest_age_seconds.set(
        retry_buffer
            .oldest_age_ms(now_ms)
            .map(|ms| ms as f64 / 1000.0)
            .unwrap_or(0.0),
    );
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

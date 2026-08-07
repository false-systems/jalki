use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use aya::{Btf, Ebpf};
use false_protocol::{Occurrence, Severity};
use jalki_evidence::{
    gap_for_batch, DrainPaceConfig, DrainPacer, EvidenceBatch, EvidenceClass, EvidenceRecord,
    EvidenceSink, GapReport, HookKind, MemoryPressure, Pace, ProbeMetadata, ProducerMetadata,
    RetryBackoff, RetryBackoffConfig, RetryBuffer, RetryBufferConfig, SinkError, Spool,
    SpoolConfig,
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
        for probe in &self.probes {
            let stats = Arc::new(ProbeStats::new());
            reader::spawn_reader(
                &mut ebpf,
                probe.clone(),
                self.cluster.clone(),
                tx.clone(),
                stats.clone(),
                metrics.clone(),
                store.clone(),
                self.enricher.clone(),
                sensitive_path_matcher.clone(),
            )?;
            registry.register_startup_probe(probe.clone(), stats.clone());
        }

        // Build the daemon handle for IPC and CLI.
        let handle = Arc::new(DaemonHandle {
            ebpf: Mutex::new(ebpf),
            btf,
            btf_data,
            registry: registry.clone(),
            metrics: metrics.clone(),
            store: store.clone(),
            kb: kb.clone(),
            tx: tx.clone(),
            cluster: self.cluster.clone(),
            enricher: self.enricher.clone(),
            sensitive_path_matcher: sensitive_path_matcher.clone(),
            generated_probes: Mutex::new(HashMap::new()),
        });

        // Spawn self-observability: periodically emit drops/errors as evidence.
        let stats_tx = tx.clone();
        let stats_registry = registry.clone();
        let stats_producer = producer.clone();
        tokio::spawn(async move {
            emit_self_observability(stats_registry, stats_tx, &stats_producer).await;
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
        let pace_config = DrainPaceConfig::from_env();
        info!(
            max_bytes_per_sec = pace_config.max_bytes_per_sec,
            max_batches_per_sec = pace_config.max_batches_per_sec,
            "post-outage backlog drains are rate-bounded and back off on sink \
             backpressure (tune via JALKI_DRAIN_MAX_{{BYTES,BATCHES}}_PER_SEC)"
        );
        let pace_config = DrainPaceConfig::from_env();
        info!(
            max_bytes_per_sec = pace_config.max_bytes_per_sec,
            max_batches_per_sec = pace_config.max_batches_per_sec,
            "post-outage backlog drains are rate-bounded and back off on sink \
             backpressure (tune via JALKI_DRAIN_MAX_{{BYTES,BATCHES}}_PER_SEC)"
        );
        let declared_limit = std::env::var("JALKI_MEMORY_LIMIT_BYTES")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok());
        let memory_pressure = MemoryPressure::detect(
            Path::new(
                &std::env::var("JALKI_CGROUP_ROOT").unwrap_or_else(|_| "/sys/fs/cgroup".into()),
            ),
            declared_limit,
        );
        match &memory_pressure {
            Some(p) => info!(
                limit_bytes = p.limit_bytes(),
                source = ?p.source(),
                watermark = memory_high_watermark(),
                "self-shedding armed: buffered evidence is given up before the \
                 kernel OOM-kills the agent (an OOM loses the whole backlog and \
                 reports nothing)"
            ),
            // Loud, because the failure mode is silent: jälki mounts the host
            // cgroupfs, so an unresolved limit reads as the node root — which
            // is unbounded, and would look like endless headroom.
            None => warn!(
                "self-shedding OFF: could not establish this agent's memory limit. \
                 Set JALKI_MEMORY_LIMIT_BYTES (downward API: resources.limits.memory)"
            ),
        }
        let spool = spool_from_env();
        match &spool {
            Some(s) => info!(
                path = %s.path().display(),
                existing_bytes = s.bytes(),
                "backlog spool armed: buffered evidence survives a restart"
            ),
            None => info!(
                "backlog spool OFF (set JALKI_SPOOL_PATH): an OOM or restart \
                 during a sink outage loses whatever is buffered"
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
            pace_config,
            memory_pressure,
            spool,
        }));

        // The observability server runs on its OWN thread and its own
        // single-threaded runtime, not as a task on the main one.
        //
        // `/healthz` answers "is this process alive", and a liveness probe acts
        // on the answer by killing the process. That makes it the one endpoint
        // that must never be affected by how busy the process is — and as a
        // task among others it was: during a Vartio outage the probe timed out
        // (`context deadline exceeded ... while awaiting headers`, 1s budget)
        // and the kubelet killed an agent that was healthy and correctly
        // buffering. Consulting no dependency is not enough if the answer
        // cannot be delivered (jalki #67).
        //
        // A dedicated thread means the health surface is answerable whenever
        // the process exists, which is exactly the claim it makes.
        let _metrics_thread = {
            let metrics = metrics.clone();
            std::thread::Builder::new()
                .name("jalki-observability".into())
                .spawn(move || {
                    let rt = match tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                    {
                        Ok(rt) => rt,
                        Err(e) => {
                            error!(error = %e, "observability runtime failed to start");
                            return;
                        }
                    };
                    if let Err(e) = rt.block_on(serve_metrics(metrics)) {
                        error!(error = %e, "observability server failed");
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
    metrics: Arc<Metrics>,
    pub store: Arc<EventStore>,
    pub kb: Arc<KnowledgeBase>,
    tx: mpsc::Sender<Vec<EvidenceRecord>>,
    pub cluster: String,
    enricher: Arc<dyn RuntimeEnricher>,
    sensitive_path_matcher: Arc<sensitive_paths::SensitivePathMatcher>,
    /// BPF objects for runtime-generated probes, keyed by kernel function.
    ///
    /// Owned rather than forgotten. `deploy_codegen` used to end in
    /// `std::mem::forget(gen_ebpf)` to keep the loaded programs alive, which
    /// kept them alive by *leaking* them: programs and maps stayed resident
    /// with no owner and no way to unload them, one per distinct function
    /// deployed over IPC/MCP, for the life of the process (#19).
    ///
    /// Holding them here means they are released when the handle drops, and —
    /// more to the point — that a detach path has something to release. There
    /// is no detach path yet; that is the other half of #19's acceptance and
    /// needs its own change.
    generated_probes: Mutex<HashMap<String, Ebpf>>,
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
                self.metrics.clone(),
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

    /// Detach a runtime-deployed probe and unload its BPF programs.
    ///
    /// Two steps, and both are required. `registry.detach` stops the reader,
    /// which owns the `RingBuf` — the map cannot be released while it lives.
    /// Dropping the generated `Ebpf` then unloads the programs and maps.
    ///
    /// Before #59 the second step was impossible: `deploy_codegen` ended in
    /// `std::mem::forget`, so nothing owned the object and nothing could ever
    /// release it. That is why this issue's acceptance criteria were
    /// unsatisfiable rather than merely unimplemented.
    ///
    /// Unknown probe id is a no-op: the caller asked for a state that already
    /// holds, so retries are safe.
    pub async fn detach_probe(&self, probe_id: &str) -> Result<bool> {
        let Some(name) = self.registry.detach(probe_id)? else {
            return Ok(false);
        };

        // The registry keys probes by id, the generated objects by kernel
        // function, and the probe's name is the function for codegen probes.
        // A startup probe never reaches here — `registry.detach` refuses it.
        if let Some(ebpf) = self.generated_probes.lock().await.remove(&name) {
            drop(ebpf);
            info!(
                probe_id = %probe_id,
                function = %name,
                "unloaded generated BPF programs"
            );
        }
        Ok(true)
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
            self.metrics.clone(),
            &self.store,
            self.enricher.clone(),
            self.sensitive_path_matcher.clone(),
        )?;

        // Take ownership of the generated object; it owns the loaded programs
        // and maps, so it has to outlive the probe. Previously this was
        // `std::mem::forget`, which achieved that by leaking (#19).
        //
        // Note the ordering: `registry.attach` above refuses a probe whose name
        // is already attached, and its `?` drops `gen_ebpf` normally — so a
        // rejected redeploy already unloaded correctly. Only successful deploys
        // reached the forget, which is why the leak was one object per distinct
        // function rather than one per call.
        if let Some(previous) = self
            .generated_probes
            .lock()
            .await
            .insert(function.to_string(), gen_ebpf)
        {
            // Unreachable while the registry rejects duplicate names; if that
            // guarantee ever changes, drop the old object rather than silently
            // replacing it and leaking again.
            warn!(
                function = function,
                "replaced an existing generated probe; unloading the previous BPF object"
            );
            drop(previous);
        }

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
    pub pace_config: DrainPaceConfig,
    /// `None` when the agent could not establish its own memory limit — the
    /// feature is off, and the startup log says so rather than leaving it to
    /// look like permanent headroom.
    pub memory_pressure: Option<MemoryPressure>,
    /// `None` when no spool location is usable — delivery works without it,
    /// just without surviving a restart.
    pub spool: Option<Spool>,
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
        pace_config,
        memory_pressure,
        mut spool,
    } = loop_state;
    let memory_high_watermark = memory_high_watermark();
    // Transition tracker for "at ceiling, nothing to shed" (jalki#76) — owned
    // by the sink loop so the WARN fires once per episode, not per tick.
    let mut ceiling = CeilingState::default();

    let mut retry_buffer = RetryBuffer::new(retry_config);
    let mut backoff = RetryBackoff::new(backoff_config);
    let mut pacer = DrainPacer::new(pace_config);

    let mut pending_gaps = PendingGaps::default();

    // Anything a previous process was still holding. This runs before the first
    // event is taken, so replayed evidence keeps its place at the head of the
    // queue rather than landing behind whatever arrives next.
    if let Some(spool) = &mut spool {
        let (batches, report) = Spool::replay(spool.path());
        if report.batches > 0 || report.torn_tail_bytes > 0 {
            info!(
                batches = report.batches,
                records = report.records,
                torn_tail_bytes = report.torn_tail_bytes,
                "recovered spooled evidence from a previous run"
            );
        }
        if report.torn_tail_bytes > 0 {
            // Expected — the process was killed mid-write, which is the whole
            // scenario — but it is still lost evidence and gets a gap.
            warn!(
                torn_tail_bytes = report.torn_tail_bytes,
                "spool tail was incomplete; those bytes are lost"
            );
        }
        for batch in batches {
            pending_gaps.extend(retry_buffer.enqueue(batch, 0));
        }
        // Rewrite from what actually made it into the buffer: replay may have
        // over-filled it, and the shed that followed must not be re-replayed on
        // the next restart.
        spool.compact(retry_buffer.iter_batches());
    }
    let retry_clock_start = Deadline::now();
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
                    records.retain(|record| record_in_namespace_scope(record, allow));
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

                if let Some(pressure) = &memory_pressure {
                    shed_under_memory_pressure(
                        pressure,
                        memory_high_watermark,
                        &mut retry_buffer,
                        &mut pending_gaps,
                        &metrics_clone,
                        &mut ceiling,
                    );
                }
                sync_spool(&mut spool, &retry_buffer, &metrics_clone);
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
                let outcome = flush_retry_buffer(
                    sink.as_ref(),
                    &mut retry_buffer,
                    &mut pending_gaps,
                    &metrics_clone,
                    &producer_for_sink,
                    &mut pacer,
                    now_ms,
                )
                .await;

                // Any batch accepted means the sink is taking work
                // again, so start the next outage from the bottom of
                // the ladder rather than wherever this one ended.
                if backlog_len(&retry_buffer, &pending_gaps) < before {
                    backoff.reset();
                }
                if let Some(pressure) = &memory_pressure {
                    shed_under_memory_pressure(
                        pressure,
                        memory_high_watermark,
                        &mut retry_buffer,
                        &mut pending_gaps,
                        &metrics_clone,
                        &mut ceiling,
                    );
                }
                sync_spool(&mut spool, &retry_buffer, &metrics_clone);
                publish_backlog_metrics(&metrics_clone, &retry_buffer, now_ms);

                next_retry = match outcome {
                    // Rate-limited, not refused. Come back when the pacer
                    // allows, rather than climbing the failure ladder —
                    // treating "going slowly on purpose" as an outage would
                    // stretch a paced drain out exponentially.
                    DrainOutcome::Paced { wait_ms } => {
                        Some(Deadline::now() + Duration::from_millis(wait_ms))
                    }
                    DrainOutcome::SinkRefused | DrainOutcome::Empty => schedule_retry(
                        None,
                        &mut backoff,
                        has_backlog(&retry_buffer, &pending_gaps),
                        sink.name(),
                    ),
                };
            }
        }
    }

    while !retry_buffer.is_empty() || !pending_gaps.is_empty() {
        let before = (retry_buffer.len_batches(), pending_gaps.len());
        // Shutdown honours the pace too — a process exiting is no reason to
        // hand a recovering sink everything at once — but bounded, so a slow
        // pace cannot hold the daemon open indefinitely.
        if let DrainOutcome::Paced { wait_ms } = flush_retry_buffer(
            sink.as_ref(),
            &mut retry_buffer,
            &mut pending_gaps,
            &metrics_clone,
            &producer_for_sink,
            &mut pacer,
            elapsed_ms(retry_clock_start),
        )
        .await
        {
            tokio::time::sleep(Duration::from_millis(wait_ms.min(1_000))).await;
            continue;
        }
        publish_backlog_metrics(&metrics_clone, &retry_buffer, elapsed_ms(retry_clock_start));
        if (retry_buffer.len_batches(), pending_gaps.len()) == before {
            break;
        }
    }

    sync_spool(&mut spool, &retry_buffer, &metrics_clone);

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
            spooled = spool.as_ref().map(|s| s.bytes()).unwrap_or(0),
            "sink loop exiting with an undeliverable backlog"
        );
        if spool.is_none() {
            error!("no spool configured, so that backlog is lost with this process");
        }
    }

    info!("sink loop finished");
}

/// Rewrite the spool to match the buffer.
///
/// Compaction rather than an append/cursor scheme. The buffer is small and
/// bounded, so rewriting is cheap, and "the file is exactly what is still
/// undelivered" is an invariant that cannot drift — whereas an offset into an
/// append log has to stay correct across shedding, expiry and partial drains,
/// each of which is a chance to replay evidence twice or lose it.
fn sync_spool(spool: &mut Option<Spool>, retry_buffer: &RetryBuffer, metrics: &Metrics) {
    let Some(s) = spool else { return };
    if s.is_disabled() {
        return;
    }
    s.compact(retry_buffer.iter_batches());
    metrics.spool_bytes.set(s.bytes() as i64);
    if let Some(reason) = s.disabled_reason() {
        // Once, on the transition: delivery continues without a spool, but an
        // operator should not have to infer that from a missing file.
        warn!(
            error = reason,
            "backlog spool failed and is now off; evidence no longer survives a restart"
        );
    }
}

/// Open the on-disk backlog if a location is configured.
///
/// Off unless `JALKI_SPOOL_PATH` is set: it needs a writable volume, and
/// silently writing into the container's ephemeral root would be worse than
/// not spooling at all — it fills the node's ephemeral storage and gets the
/// pod evicted, which is the failure being avoided, reached differently.
fn spool_from_env() -> Option<Spool> {
    let path = std::env::var("JALKI_SPOOL_PATH").ok()?;
    let max_bytes = std::env::var("JALKI_SPOOL_MAX_BYTES")
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(256 * 1024 * 1024);
    Spool::open(SpoolConfig {
        path: PathBuf::from(path),
        max_bytes,
    })
}

/// Shed the retry buffer once the cgroup passes this fraction of its limit.
/// 0.8 leaves room for the shed itself to be observed and for the working set
/// to spike while it happens.
const DEFAULT_MEMORY_HIGH_WATERMARK: f64 = 0.8;

/// Shed down to this fraction of the buffer's current size when it triggers.
/// Shedding a slice rather than everything keeps a brief spike from costing the
/// whole backlog.
const MEMORY_SHED_FRACTION: f64 = 0.5;

fn memory_high_watermark() -> f64 {
    std::env::var("JALKI_MEMORY_HIGH_WATERMARK")
        .ok()
        .and_then(|v| v.trim().parse::<f64>().ok())
        .filter(|v| *v > 0.0 && *v <= 1.0)
        .unwrap_or(DEFAULT_MEMORY_HIGH_WATERMARK)
}

/// Tracks the state "at the memory ceiling with nothing meaningful to shed",
/// so it is logged on TRANSITION rather than every sink-loop tick, and
/// exported continuously as `jalki_memory_ceiling_no_shed`.
///
/// This state existed for 3+ hours before the 2026-08-07 OOM (jalki#76) and
/// was reconstructable only by joining three metrics after the kill: the
/// working set sat at 71% of the limit while the retry buffer held ~20MB.
/// Shedding governs buffered evidence; when the growth is the process's own
/// working set — allocator retention, cache growth — shedding structurally
/// cannot help. ADR-0010 applies to the agent itself: absence of headroom the
/// agent can do anything about must be reported, not inferred.
#[derive(Default)]
struct CeilingState {
    active: bool,
}

impl CeilingState {
    /// `doomed` is precise, not a heuristic: even shedding the ENTIRE buffer
    /// (freeing at most `len_bytes`) could not bring the ratio back under the
    /// watermark. On 2026-08-07: ratio 0.98, buffer 20MB/1Gi ≈ 0.02 →
    /// 0.96 ≥ 0.8, doomed. A healthy pressure spike with 300MB buffered:
    /// 0.85 − 0.29 = 0.56 < 0.8 — shedding works, not doomed.
    fn observe(&mut self, doomed: bool, ratio: f64, pressure: &MemoryPressure, metrics: &Metrics) {
        metrics.memory_ceiling_no_shed.set(i64::from(doomed));
        if doomed && !self.active {
            warn!(
                memory_ratio = ratio,
                limit_bytes = pressure.limit_bytes(),
                "at the memory ceiling with nothing meaningful to shed: the \
                 growth is the process working set, not buffered evidence, and \
                 shedding cannot prevent an OOM from here (jalki#76). If this \
                 persists the limit is undersized for the workload or the \
                 allocator is retaining churn"
            );
        } else if !doomed && self.active {
            info!(
                memory_ratio = ratio,
                "memory ceiling cleared; headroom is back under the agent's control"
            );
        }
        self.active = doomed;
    }
}

/// Give back buffer memory before the kernel takes the process.
///
/// An OOM kill loses the entire backlog *and* produces no gap evidence — the
/// one loss the pipeline cannot describe afterwards. Shedding deliberately
/// costs the same records and says so.
fn shed_under_memory_pressure(
    pressure: &MemoryPressure,
    high_watermark: f64,
    retry_buffer: &mut RetryBuffer,
    pending_gaps: &mut PendingGaps,
    metrics: &Metrics,
    ceiling: &mut CeilingState,
) {
    let Some(ratio) = pressure.ratio() else {
        return;
    };
    metrics.memory_usage_ratio.set(ratio);

    // Report the structural state BEFORE the early returns below: the empty-
    // buffer return on the next line is exactly the silent path the 2026-08-07
    // OOM took, and it must not stay silent.
    let buffer_fraction = retry_buffer.len_bytes() as f64 / pressure.limit_bytes() as f64;
    let doomed = ratio >= high_watermark && (ratio - buffer_fraction) >= high_watermark;
    ceiling.observe(doomed, ratio, pressure, metrics);

    if ratio < high_watermark || retry_buffer.is_empty() {
        return;
    }

    let before = retry_buffer.len_bytes();
    let target = (before as f64 * MEMORY_SHED_FRACTION) as usize;
    let gaps = retry_buffer.shed_to(target);
    if gaps.is_empty() {
        return;
    }

    let dropped: usize = gaps.iter().map(|g| g.dropped_records).sum();
    warn!(
        memory_ratio = ratio,
        limit_bytes = pressure.limit_bytes(),
        dropped_records = dropped,
        freed_bytes = before.saturating_sub(retry_buffer.len_bytes()),
        "shedding buffered evidence under memory pressure; an OOM kill would \
         have cost the whole backlog and reported nothing"
    );
    pending_gaps.extend(gaps);
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

/// What a drain pass ended on, so the loop knows when to come back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DrainOutcome {
    /// Nothing left to send.
    Empty,
    /// Backlog remains and the pacer says wait — the sink is fine, we are
    /// deliberately going slower.
    Paced { wait_ms: u64 },
    /// The sink refused; the backoff ladder owns the next attempt.
    SinkRefused,
}

/// Drain as much of the backlog as the pacer currently permits, then return.
///
/// It returns rather than looping to empty for two reasons. The rate limit is
/// the headline one (jalki #40): draining at line rate is what took Ahti from
/// 0.24Gi to its 4Gi OOM limit in 90 minutes once Vartio came back. The other
/// is that a flush which loops until empty holds the `select!` loop for the
/// whole drain, so `rx.recv()` is never polled, the channel fills, and the ring
/// buffer readers start dropping fresh evidence — losing new events to pay for
/// old ones.
async fn flush_retry_buffer(
    sink: &dyn EvidenceSink,
    retry_buffer: &mut RetryBuffer,
    pending_gaps: &mut PendingGaps,
    metrics: &Metrics,
    producer: &ProducerMetadata,
    pacer: &mut DrainPacer,
    now_ms: u64,
) -> DrainOutcome {
    while let Some(batch) = pending_gaps.front(producer) {
        // Gap reports are tiny and describe evidence already lost; pace them
        // with everything else so they cannot themselves become a burst.
        if let Pace::Wait { ms } = pacer.poll(now_ms, batch.approx_bytes()) {
            return DrainOutcome::Paced { wait_ms: ms };
        }
        match sink.append_batch(batch).await {
            Ok(_) => {
                pacer.on_delivered();
                pending_gaps.pop_front();
            }
            Err(err) => {
                let retriable = RetryBuffer::should_retry(&err);
                if matches!(err, SinkError::Backpressure { .. }) {
                    pacer.on_backpressure();
                }
                record_sink_error(metrics, sink.name());
                if retriable {
                    warn!(
                        sink = sink.name(),
                        error = %err,
                        drain_scale = pacer.scale(),
                        "gap evidence delivery failed; retrying later"
                    );
                    return DrainOutcome::SinkRefused;
                }
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
        if let Pace::Wait { ms } = pacer.poll(now_ms, batch.approx_bytes()) {
            return DrainOutcome::Paced { wait_ms: ms };
        }
        match sink.append_batch(batch).await {
            Ok(_) => {
                pacer.on_delivered();
                retry_buffer.pop_delivered();
            }
            Err(err) => {
                let retriable = RetryBuffer::should_retry(&err);
                // ADR-0009 contract 1: RESOURCE_EXHAUSTED means *slow down*,
                // not merely *try again shortly*. Without this the sink's only
                // way to shed load is to keep refusing, and we keep asking at
                // the same rate.
                if matches!(err, SinkError::Backpressure { .. }) {
                    pacer.on_backpressure();
                    warn!(
                        sink = sink.name(),
                        drain_scale = pacer.scale(),
                        "sink signalled backpressure; halving the drain rate"
                    );
                }
                record_sink_error(metrics, sink.name());
                if retriable {
                    warn!(
                        sink = sink.name(),
                        error = %err,
                        queued_batches = retry_buffer.len_batches(),
                        queued_records = retry_buffer.len_records(),
                        queued_bytes = retry_buffer.len_bytes(),
                        "evidence sink append failed; retrying later"
                    );
                    return DrainOutcome::SinkRefused;
                }
                error!(
                    sink = sink.name(),
                    error = %err,
                    "evidence sink append failed permanently; dropping batch"
                );
                if let Some(dropped) = retry_buffer.pop_delivered() {
                    pending_gaps.merge(gap_for_batch(terminal_gap_cause(&err), &dropped));
                }
                return DrainOutcome::SinkRefused;
            }
        }
    }

    DrainOutcome::Empty
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

fn record_sink_error(metrics: &Metrics, sink: &str) {
    metrics
        .sink_errors
        .get_or_create(&SinkLabel { sink: sink.into() })
        .inc();
}

fn record_in_namespace_scope(record: &EvidenceRecord, allow: &HashSet<String>) -> bool {
    record.occurrence.occurrence_type.as_str() == "jalki.agent.gap"
        || record
            .bound_namespace()
            .is_some_and(|namespace| allow.contains(namespace))
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

/// Loop clock, on tokio's timebase rather than `std::time::Instant`.
///
/// Identical in production — tokio's clock *is* the system clock unless paused.
/// It matters for tests: the retry deadline already runs on tokio's clock, so a
/// std-based `now_ms` meant the buffer's age and the drain pacer's token
/// buckets stood still while the retry timer advanced. Under `start_paused`
/// that stalls a paced drain outright, and it made `max_age_ms` expiry
/// untestable.
fn elapsed_ms(start: Deadline) -> u64 {
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
    registry: Arc<ProbeRegistry>,
    tx: mpsc::Sender<Vec<EvidenceRecord>>,
    producer: &ProducerMetadata,
) {
    let mut previous: HashMap<String, (u64, u64, u64)> = HashMap::new();

    let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));

    loop {
        interval.tick().await;

        let snapshots = registry.observability_stats();
        let attached_ids: HashSet<_> = snapshots.iter().map(|(id, ..)| id.clone()).collect();
        previous.retain(|id, _| attached_ids.contains(id));

        for (probe_id, probe_name, occurrence_type, stats) in snapshots {
            let errors = stats.parse_errors.load(Ordering::Relaxed);
            let (dropped, tracking_started_at_ns, counter_polled_at_ns) = stats.drop_observation();
            let (new_drops, new_errors, previous_poll_at_ns) = update_probe_counters(
                &mut previous,
                &probe_id,
                dropped,
                errors,
                tracking_started_at_ns,
                counter_polled_at_ns,
            );

            if new_drops > 0 {
                warn!(probe = %probe_name, dropped = new_drops, "ring buffer drops detected");
                if tx
                    .send(ring_buffer_gap_records(
                        producer,
                        &occurrence_type,
                        new_drops,
                        previous_poll_at_ns,
                        counter_polled_at_ns,
                    ))
                    .await
                    .is_err()
                {
                    return;
                }
            }

            if new_errors > 0 {
                warn!(probe = %probe_name, errors = new_errors, "parse errors detected");
                let occ = Occurrence::new("jalki/self", "jalki.probe.parse_errors")
                    .severity(Severity::Warning)
                    .in_cluster(producer.cluster.clone());
                if tx.send(vec![self_observability_record(occ)]).await.is_err() {
                    return;
                }
            }
        }
    }
}

fn counter_delta(current: u64, previous: u64) -> u64 {
    current.checked_sub(previous).unwrap_or(current)
}

fn update_probe_counters(
    previous: &mut HashMap<String, (u64, u64, u64)>,
    probe_id: &str,
    dropped: u64,
    errors: u64,
    tracking_started_at_ns: u64,
    counter_polled_at_ns: u64,
) -> (u64, u64, u64) {
    let (prev_dropped, prev_errors, previous_poll_at_ns) = previous
        .get(probe_id)
        .copied()
        .unwrap_or((0, 0, tracking_started_at_ns));
    previous.insert(probe_id.to_owned(), (dropped, errors, counter_polled_at_ns));
    (
        counter_delta(dropped, prev_dropped),
        counter_delta(errors, prev_errors),
        previous_poll_at_ns,
    )
}

fn ring_buffer_gap_records(
    producer: &ProducerMetadata,
    occurrence_type: &str,
    dropped_records: u64,
    gap_start_ns: u64,
    gap_end_ns: u64,
) -> Vec<EvidenceRecord> {
    let dropped_records = usize::try_from(dropped_records).unwrap_or(usize::MAX);
    let class = EvidenceClass::of(occurrence_type);
    let batch = GapReport {
        cause: "ringbuffer_overflow".into(),
        affected_probes: vec![occurrence_type.into()],
        dropped_records,
        gap_start_ns,
        gap_end_ns,
        dropped_reliability: if class == EvidenceClass::Reliability {
            dropped_records
        } else {
            0
        },
        dropped_attribution: if class == EvidenceClass::Attribution {
            dropped_records
        } else {
            0
        },
    }
    .into_batch(producer.clone());
    batch.records
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
    use tokio::io::AsyncWriteExt;

    let raw = tokio::time::timeout(REQUEST_READ_TIMEOUT, read_request_line(&mut stream))
        .await
        .context("timed out reading request")??;
    let path = request_path(&raw);

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

/// Overall budget for receiving a request, not a per-read one: a peer that
/// dribbles a byte at a time must not pin the task indefinitely.
const REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Enough for a request line plus any probe's or scraper's headers. A peer that
/// sends more just gets answered on what arrived first.
const MAX_REQUEST_BYTES: usize = 2048;

/// Read until the end of the HTTP request line.
///
/// A single `read()` is **not** enough, and the failure it produces is nasty:
/// TCP may split `GET /healthz HTTP/1.1\r\n` across segments, and the kubelet's
/// probe reaches this over the pod network rather than loopback. A short read
/// yields a truncated path like `/healt`, which routes to 404, which fails the
/// liveness probe, which restarts the agent — the exact outcome the probe was
/// added to prevent.
async fn read_request_line(stream: &mut tokio::net::TcpStream) -> Result<Vec<u8>> {
    use tokio::io::AsyncReadExt;

    let mut buf = Vec::with_capacity(256);
    let mut chunk = [0u8; 512];
    while !buf.contains(&b'\n') && buf.len() < MAX_REQUEST_BYTES {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            break; // peer closed; answer on what we have
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    Ok(buf)
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

#[cfg(test)]
mod tests {
    use super::*;
    use jalki_evidence::{Spool, SpoolConfig};

    #[test]
    fn pending_gap_retries_keep_the_same_ids() {
        let producer = ProducerMetadata::new("test", "node-1", "6.17.0");
        let mut pending = PendingGaps::default();
        pending.merge(GapReport {
            cause: "retry_buffer_overflow".into(),
            affected_probes: vec!["kernel.process.exec".into()],
            dropped_records: 1,
            gap_start_ns: 10,
            gap_end_ns: 20,
            dropped_reliability: 0,
            dropped_attribution: 1,
        });

        let first = pending.front(&producer).expect("pending gap");
        let retry = pending.front(&producer).expect("same pending gap");

        assert_eq!(retry.batch_id, first.batch_id);
        assert_eq!(
            retry.records[0].occurrence.id,
            first.records[0].occurrence.id
        );
    }

    #[test]
    fn ring_buffer_loss_becomes_gap_evidence() {
        let producer = ProducerMetadata::new("test", "node-1", "6.17.0");
        let records = ring_buffer_gap_records(&producer, "kernel.tcp.connect", 7, 10, 20);
        let gap = &records[0].occurrence;

        assert_eq!(gap.occurrence_type.as_str(), "jalki.agent.gap");
        assert_eq!(
            gap.labels.get("cause").map(String::as_str),
            Some("ringbuffer_overflow")
        );
        assert_eq!(
            gap.labels.get("dropped_records").map(String::as_str),
            Some("7")
        );
        assert_eq!(
            gap.labels.get("affected_probes").map(String::as_str),
            Some("[\"kernel.tcp.connect\"]")
        );
        assert_eq!(
            gap.labels.get("dropped_attribution").map(String::as_str),
            Some("7")
        );
        assert_eq!(
            gap.labels.get("gap_start_ns").map(String::as_str),
            Some("10")
        );
        assert_eq!(gap.labels.get("gap_end_ns").map(String::as_str), Some("20"));

        let reliability = ring_buffer_gap_records(&producer, "kernel.tcp.close", 3, 30, 40);
        assert_eq!(
            reliability[0]
                .occurrence
                .labels
                .get("dropped_reliability")
                .map(String::as_str),
            Some("3")
        );
    }

    #[test]
    fn reset_probe_counters_start_a_new_history() {
        assert_eq!(counter_delta(3, 10), 3);
        assert_eq!(counter_delta(12, 10), 2);
    }

    #[test]
    fn redeployed_probe_uses_its_new_instance_history() {
        let mut previous = HashMap::from([("probe_001".into(), (3, 0, 10))]);

        let first = update_probe_counters(&mut previous, "probe_002", 7, 0, 20, 30);
        let second = update_probe_counters(&mut previous, "probe_002", 9, 0, 20, 40);

        assert_eq!(first, (7, 0, 20));
        assert_eq!(second, (2, 0, 30));
    }

    #[test]
    fn namespace_allowlist_never_discards_agent_gaps() {
        let producer = ProducerMetadata::new("test", "node-1", "6.17.0");
        let record = ring_buffer_gap_records(&producer, "kernel.tcp.connect", 1, 10, 20)
            .into_iter()
            .next()
            .expect("gap record");
        let allow = HashSet::from(["workloads".to_string()]);

        assert!(record_in_namespace_scope(&record, &allow));
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
        /// When set, the sink accepts nothing and answers Backpressure — the
        /// RESOURCE_EXHAUSTED case, distinct from being down.
        overloaded: Arc<AtomicBool>,
        /// Per-append cost. A real sink is not instant, and without this the
        /// difference between "drains a slice and yields" and "drains to empty
        /// while nothing else runs" is invisible on a paused clock.
        append_cost: Duration,
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
            if !self.append_cost.is_zero() {
                tokio::time::sleep(self.append_cost).await;
            }
            if self.overloaded.load(Ordering::SeqCst) {
                return Err(SinkError::Backpressure {
                    sink: "controlled".into(),
                    message: "test sink is overloaded".into(),
                });
            }
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
        overloaded: Arc<AtomicBool>,
        attempts: Arc<AtomicUsize>,
        delivered: Arc<StdMutex<Vec<String>>>,
        metrics: Arc<Metrics>,
        handle: tokio::task::JoinHandle<()>,
    }

    fn spawn_loop(backoff_config: RetryBackoffConfig) -> Harness {
        spawn_loop_paced(
            backoff_config,
            DrainPaceConfig {
                max_bytes_per_sec: u64::MAX / 4,
                max_batches_per_sec: u64::MAX / 4,
                ..DrainPaceConfig::default()
            },
        )
    }

    fn spawn_loop_paced(
        backoff_config: RetryBackoffConfig,
        pace_config: DrainPaceConfig,
    ) -> Harness {
        spawn_loop_full(backoff_config, pace_config, Duration::ZERO)
    }

    fn spawn_loop_full(
        backoff_config: RetryBackoffConfig,
        pace_config: DrainPaceConfig,
        append_cost: Duration,
    ) -> Harness {
        let (tx, rx) = mpsc::channel::<Vec<EvidenceRecord>>(64);
        let up = Arc::new(AtomicBool::new(false));
        let overloaded = Arc::new(AtomicBool::new(false));
        let attempts = Arc::new(AtomicUsize::new(0));
        let delivered = Arc::new(StdMutex::new(Vec::new()));
        let metrics = Arc::new(Metrics::new());
        let handle = tokio::spawn(run_sink_loop(SinkLoop {
            rx,
            sink: Box::new(ControlledSink {
                up: up.clone(),
                overloaded: overloaded.clone(),
                append_cost,
                attempts: attempts.clone(),
                delivered: delivered.clone(),
            }),
            metrics: metrics.clone(),
            producer: ProducerMetadata::new("test", "node-1", "6.17.0"),
            enricher: Arc::new(NoopEnricher),
            namespace_allowlist: None,
            retry_config: RetryBufferConfig::default(),
            backoff_config,
            pace_config,
            memory_pressure: None,
            spool: None,
        }));
        Harness {
            tx,
            up,
            overloaded,
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

    /// Advance the paused clock in slices, letting the loop run between them.
    /// A paced drain needs many timer ticks — each pass sends what its tokens
    /// allow and reschedules — so a single large `advance` only ever fires the
    /// first one.
    async fn advance_draining(h: &Harness, total: Duration, step: Duration) {
        let mut elapsed = Duration::ZERO;
        while elapsed < total {
            tokio::time::advance(step).await;
            drain(h).await;
            elapsed += step;
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
    /// A single `read()` is not guaranteed to return the whole request line.
    /// Split across segments, the old handler saw `GET /healt` and answered
    /// 404 — a failed liveness probe, i.e. a restart. Feed it deliberately
    /// fragmented, the way a real network can.
    #[tokio::test]
    async fn a_request_split_across_packets_still_routes() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let metrics = Arc::new(Metrics::new());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let m = metrics.clone();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let _ = handle_observability_request(stream, &m, 60).await;
        });

        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        for piece in ["GET /he", "alt", "hz HTTP/1.1\r\n", "Host: t\r\n\r\n"] {
            client.write_all(piece.as_bytes()).await.unwrap();
            client.flush().await.unwrap();
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let mut raw = String::new();
        client.read_to_string(&mut raw).await.unwrap();
        assert!(
            raw.starts_with("HTTP/1.1 200"),
            "a fragmented /healthz must not 404 into a pod restart: {raw:?}"
        );
    }

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
    // ── paced drain (jalki #40) ─────────────────────────────────────────────
    //
    // The amplification step of the Jul 28-29 incident: Vartio returned at
    // 21:34, jälki's backlog drained at line rate, and Ahti went 0.24Gi → its
    // 4Gi OOM limit inside 90 minutes. The outage was survivable; the recovery
    // was not.

    /// The headline criterion: a recovering sink is fed at the configured rate,
    /// not as fast as it will accept.
    #[tokio::test(start_paused = true)]
    async fn a_recovered_sink_is_not_handed_the_whole_backlog_at_once() {
        let h = spawn_loop_paced(
            RetryBackoffConfig {
                base_ms: 10,
                max_ms: 10,
            },
            DrainPaceConfig {
                max_bytes_per_sec: 4 * 1024,
                max_batches_per_sec: 4,
                ..DrainPaceConfig::default()
            },
        );

        // Build a backlog against a down sink.
        for _ in 0..60 {
            h.tx.send(one_record()).await.unwrap();
        }
        drain(&h).await;
        assert!(
            h.metrics.retry_queued_batches.get() >= 50,
            "precondition: a backlog"
        );

        // Sink returns. Give it one second of simulated time.
        h.up.store(true, Ordering::SeqCst);
        tokio::time::advance(Duration::from_secs(1)).await;
        drain(&h).await;

        let delivered = h.delivered.lock().unwrap().len();
        assert!(
            delivered <= 12,
            "one second at 4 batches/s (plus a one-second burst) must not \
             deliver the whole backlog; got {delivered}"
        );
        assert!(delivered > 0, "but it must make progress; got {delivered}");

        // And it does finish, given time — pacing slows recovery, never stalls it.
        advance_draining(&h, Duration::from_secs(60), Duration::from_millis(250)).await;
        assert_eq!(
            h.metrics.retry_queued_batches.get(),
            0,
            "a paced drain still completes"
        );

        drop(h.tx);
        let _ = h.handle.await;
    }

    /// ADR-0009 contract 1: RESOURCE_EXHAUSTED means *slow down*, not merely
    /// *try again shortly*. Asserted comparatively — two identical drains, one
    /// preceded by an overload episode — because "scale() changed" is a claim
    /// about a field, while "less data moved" is a claim about behaviour.
    #[tokio::test(start_paused = true)]
    async fn backpressure_from_the_sink_slows_the_later_drain() {
        async fn delivered_after(overload: bool) -> usize {
            let h = spawn_loop_paced(
                RetryBackoffConfig {
                    base_ms: 10,
                    max_ms: 10,
                },
                DrainPaceConfig {
                    max_bytes_per_sec: 64 * 1024,
                    max_batches_per_sec: 64,
                    ..DrainPaceConfig::default()
                },
            );
            for _ in 0..200 {
                h.tx.send(one_record()).await.unwrap();
            }
            drain(&h).await;

            if overload {
                h.overloaded.store(true, Ordering::SeqCst);
                advance_draining(&h, Duration::from_secs(1), Duration::from_millis(50)).await;
                h.overloaded.store(false, Ordering::SeqCst);
            }

            h.up.store(true, Ordering::SeqCst);
            advance_draining(&h, Duration::from_secs(2), Duration::from_millis(50)).await;
            let n = h.delivered.lock().unwrap().len();
            drop(h.tx);
            let _ = h.handle.await;
            n
        }

        let baseline = delivered_after(false).await;
        let after_backpressure = delivered_after(true).await;

        assert!(
            after_backpressure * 2 < baseline,
            "a sink that answered RESOURCE_EXHAUSTED must be fed more slowly \
             afterwards: {after_backpressure} delivered vs {baseline} without \
             the overload episode"
        );
    }

    /// Regression guard, **not** a proof of interleaving — say so plainly,
    /// because the name it deserves is the one it cannot earn.
    ///
    /// The property that matters is that a flush must not monopolise the
    /// `select!` loop: one that runs to empty leaves `rx.recv()` unpolled for
    /// the whole drain, the channel fills, and the ring-buffer readers start
    /// dropping — losing new events to pay for old ones. The implementation has
    /// that property (the pacer returns after a slice).
    ///
    /// This test does not establish it. Verified by removing both pacer gates:
    /// it still passes, because the fresh evidence lands while the loop is at a
    /// select decision point rather than inside a flush, and `select!` then
    /// picks the channel branch immediately regardless of how long a flush
    /// would have run.
    ///
    /// The property is proved instead by
    /// `one_flush_returns_while_the_backlog_still_has_work`, which tests the
    /// mechanism rather than the symptom: a flush that hands back control with
    /// work outstanding is *why* the loop can yield, and that is directly
    /// observable with no scheduler races involved (#53).
    ///
    /// What this one holds on its own: a drain under a slow sink delivers the
    /// backlog *and* everything that arrived during it, losing nothing.
    #[tokio::test(start_paused = true)]
    async fn a_slow_drain_loses_neither_the_backlog_nor_what_arrives_during_it() {
        let h = spawn_loop_full(
            RetryBackoffConfig {
                base_ms: 10,
                max_ms: 10,
            },
            DrainPaceConfig {
                max_bytes_per_sec: 8 * 1024,
                max_batches_per_sec: 8,
                ..DrainPaceConfig::default()
            },
            // A real sink is not instant. 20ms x 60 batches is 1.2s of drain
            // that an unpaced flush would hold the loop for in one go.
            Duration::from_millis(20),
        );

        for _ in 0..60 {
            h.tx.send(one_record()).await.unwrap();
        }
        drain(&h).await;
        h.up.store(true, Ordering::SeqCst);

        // Kick the drain off, then post fresh evidence into the middle of it.
        tokio::time::advance(Duration::from_millis(100)).await;
        tokio::task::yield_now().await;
        for _ in 0..8 {
            h.tx.send(one_record()).await.unwrap();
        }

        let filled = h.tx.capacity();
        let mut waited = Duration::ZERO;
        while h.tx.capacity() == filled && waited < Duration::from_secs(30) {
            tokio::time::advance(Duration::from_millis(10)).await;
            tokio::task::yield_now().await;
            waited += Duration::from_millis(10);
        }
        assert!(
            h.tx.capacity() > filled,
            "the loop never came back for the fresh evidence"
        );

        advance_draining(&h, Duration::from_secs(60), Duration::from_millis(100)).await;
        assert_eq!(
            h.delivered.lock().unwrap().len(),
            68,
            "backlog and the evidence that arrived during it all land"
        );

        drop(h.tx);
        let _ = h.handle.await;
    }

    // ── the drain yields (jalki #53) ────────────────────────────────────────

    /// A drain must hand the loop back before the buffer is empty, so
    /// `rx.recv()` gets polled and the channel does not fill — otherwise jälki
    /// drops *fresh* evidence to pay for delivering old evidence.
    ///
    /// #40 tried to prove this at the loop level and could not: the fresh
    /// evidence lands while the loop sits at a `select!` decision point rather
    /// than inside a flush, so `select!` takes the channel branch immediately
    /// whether or not a flush would have run long. Three framings all passed
    /// against an unpaced build (issue #53).
    ///
    /// This tests the mechanism instead of the symptom. "The flush returns
    /// while work remains" is the whole reason the loop can yield, and it is
    /// directly observable — no scheduler races involved. The loop-level
    /// consequence follows structurally: a flush that returns means another
    /// `select!` iteration, and `select!` polls `rx`.
    #[tokio::test(start_paused = true)]
    async fn one_flush_returns_while_the_backlog_still_has_work() {
        let producer = ProducerMetadata::new("test", "node-1", "6.17.0");
        let metrics = Arc::new(Metrics::new());
        let sink = ControlledSink {
            up: Arc::new(AtomicBool::new(true)),
            overloaded: Arc::new(AtomicBool::new(false)),
            attempts: Arc::new(AtomicUsize::new(0)),
            delivered: Arc::new(StdMutex::new(Vec::new())),
            append_cost: Duration::ZERO,
        };
        let attempts = sink.attempts.clone();

        let mut retry_buffer = RetryBuffer::new(RetryBufferConfig::default());
        let mut pending_gaps = PendingGaps::default();
        for _ in 0..200 {
            retry_buffer.enqueue(EvidenceBatch::new(producer.clone(), one_record()), 0);
        }
        let queued_before = retry_buffer.len_batches();
        assert!(queued_before >= 200, "precondition: a real backlog");

        // 5 batches/second, so one second of burst is 5 batches.
        let mut pacer = DrainPacer::new(DrainPaceConfig {
            max_bytes_per_sec: u64::MAX / 4,
            max_batches_per_sec: 5,
            ..DrainPaceConfig::default()
        });

        let outcome = flush_retry_buffer(
            &sink,
            &mut retry_buffer,
            &mut pending_gaps,
            &metrics,
            &producer,
            &mut pacer,
            0,
        )
        .await;

        assert!(
            matches!(outcome, DrainOutcome::Paced { .. }),
            "the flush must hand back control with work outstanding, got {outcome:?}"
        );
        assert!(
            !retry_buffer.is_empty(),
            "an unpaced flush drains to empty in one call and never yields —              that is the bug this pins"
        );
        let sent = attempts.load(Ordering::SeqCst);
        assert!(
            sent <= 6,
            "one slice is one second of budget, not the whole backlog: sent {sent} of {queued_before}"
        );
        assert!(sent > 0, "but it must make progress, or the drain stalls");
    }

    /// And the slices compose: repeated flushes still finish the backlog.
    /// Bounding each call is only correct if the total still converges.
    #[tokio::test(start_paused = true)]
    async fn repeated_slices_still_finish_the_backlog() {
        let producer = ProducerMetadata::new("test", "node-1", "6.17.0");
        let metrics = Arc::new(Metrics::new());
        let sink = ControlledSink {
            up: Arc::new(AtomicBool::new(true)),
            overloaded: Arc::new(AtomicBool::new(false)),
            attempts: Arc::new(AtomicUsize::new(0)),
            delivered: Arc::new(StdMutex::new(Vec::new())),
            append_cost: Duration::ZERO,
        };
        let delivered = sink.delivered.clone();

        let mut retry_buffer = RetryBuffer::new(RetryBufferConfig::default());
        let mut pending_gaps = PendingGaps::default();
        for _ in 0..40 {
            retry_buffer.enqueue(EvidenceBatch::new(producer.clone(), one_record()), 0);
        }
        let mut pacer = DrainPacer::new(DrainPaceConfig {
            max_bytes_per_sec: u64::MAX / 4,
            max_batches_per_sec: 5,
            ..DrainPaceConfig::default()
        });

        let mut now_ms = 0;
        let mut slices = 0;
        while !retry_buffer.is_empty() && slices < 100 {
            if let DrainOutcome::Paced { wait_ms } = flush_retry_buffer(
                &sink,
                &mut retry_buffer,
                &mut pending_gaps,
                &metrics,
                &producer,
                &mut pacer,
                now_ms,
            )
            .await
            {
                now_ms += wait_ms;
            }
            slices += 1;
        }

        assert!(
            retry_buffer.is_empty(),
            "the backlog drains, just not at once"
        );
        assert!(
            slices > 1,
            "if one slice emptied it, the bound is not doing anything"
        );
        assert_eq!(delivered.lock().unwrap().len(), 40, "and nothing is lost");
    }

    // ── self-shedding under memory pressure (jalki #33) ─────────────────────

    fn fake_cgroup(name: &str, current: u64, max: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("jalki-rt-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("memory.current"), format!("{current}\n")).unwrap();
        std::fs::write(dir.join("memory.max"), format!("{max}\n")).unwrap();
        dir
    }

    /// The whole point: an OOM kill costs the entire backlog *and* reports
    /// nothing, which is the one loss the pipeline cannot describe afterwards.
    /// Shedding deliberately costs some of the same records and says so.
    #[test]
    fn pressure_above_the_watermark_sheds_and_reports() {
        let producer = ProducerMetadata::new("test", "node-1", "6.17.0");
        let metrics = Metrics::new();
        let mut buffer = RetryBuffer::new(RetryBufferConfig::default());
        let mut gaps = PendingGaps::default();
        for _ in 0..20 {
            buffer.enqueue(EvidenceBatch::new(producer.clone(), one_record()), 0);
        }
        let before = buffer.len_bytes();

        // 900Mi of a 1Gi limit.
        let dir = fake_cgroup("high", 943_718_400, "1073741824");
        let pressure = MemoryPressure::at(&dir, None).expect("detected");

        shed_under_memory_pressure(
            &pressure,
            0.8,
            &mut buffer,
            &mut gaps,
            &metrics,
            &mut CeilingState::default(),
        );

        assert!(buffer.len_bytes() < before, "it gave memory back");
        assert!(!gaps.is_empty(), "and the loss is reported, not silent");
        assert!(
            metrics.memory_usage_ratio.get() > 0.8,
            "the ratio is exported so an operator can see it coming"
        );
    }

    #[test]
    fn pressure_below_the_watermark_keeps_the_backlog() {
        let producer = ProducerMetadata::new("test", "node-1", "6.17.0");
        let metrics = Metrics::new();
        let mut buffer = RetryBuffer::new(RetryBufferConfig::default());
        let mut gaps = PendingGaps::default();
        for _ in 0..20 {
            buffer.enqueue(EvidenceBatch::new(producer.clone(), one_record()), 0);
        }
        let before = buffer.len_bytes();

        // 300Mi of 1Gi — comfortable. Buffered evidence is the thing we are
        // trying to deliver; shedding it early would be self-defeating.
        let dir = fake_cgroup("low", 314_572_800, "1073741824");
        let pressure = MemoryPressure::at(&dir, None).expect("detected");

        shed_under_memory_pressure(
            &pressure,
            0.8,
            &mut buffer,
            &mut gaps,
            &metrics,
            &mut CeilingState::default(),
        );

        assert_eq!(
            buffer.len_bytes(),
            before,
            "nothing shed under normal usage"
        );
        assert!(gaps.is_empty());
        assert!(
            metrics.memory_usage_ratio.get() > 0.0,
            "but it is still measured"
        );
    }

    /// The 2026-08-07 OOM state (jalki#76): at the ceiling with a buffer too
    /// small for shedding to matter. Before this, the function returned
    /// silently — three hours of a reportable state, reported nowhere.
    #[test]
    fn ceiling_with_nothing_to_shed_is_reported() {
        let metrics = Metrics::new();
        let mut buffer = RetryBuffer::new(RetryBufferConfig::default());
        let mut gaps = PendingGaps::default();
        let mut ceiling = CeilingState::default();

        // 980Mi of 1Gi, empty buffer — the exact silent path from the incident.
        let dir = fake_cgroup("doomed", 1_027_604_480, "1073741824");
        let pressure = MemoryPressure::at(&dir, None).expect("detected");

        shed_under_memory_pressure(
            &pressure,
            0.8,
            &mut buffer,
            &mut gaps,
            &metrics,
            &mut ceiling,
        );

        assert_eq!(
            metrics.memory_ceiling_no_shed.get(),
            1,
            "the state is exported"
        );
        assert!(ceiling.active, "and tracked for transition logging");
        assert!(
            gaps.is_empty(),
            "nothing was shed — there was nothing to shed"
        );
    }

    /// Same ratio with a heavy buffer is NOT the doomed state: shedding can
    /// bring the ratio back under the watermark, and does.
    #[test]
    fn ceiling_with_a_real_buffer_is_not_doomed() {
        let producer = ProducerMetadata::new("test", "node-1", "6.17.0");
        let metrics = Metrics::new();
        let mut buffer = RetryBuffer::new(RetryBufferConfig::default());
        let mut gaps = PendingGaps::default();
        let mut ceiling = CeilingState::default();
        for _ in 0..20 {
            buffer.enqueue(EvidenceBatch::new(producer.clone(), one_record()), 0);
        }

        // 900Mi of a limit chosen so the buffer is a large fraction of it:
        // shedding everything would land well below the watermark.
        let limit = (buffer.len_bytes() as u64) * 4;
        let current = (limit as f64 * 0.9) as u64;
        let dir = fake_cgroup("shed-works", current, &limit.to_string());
        let pressure = MemoryPressure::at(&dir, None).expect("detected");

        shed_under_memory_pressure(
            &pressure,
            0.8,
            &mut buffer,
            &mut gaps,
            &metrics,
            &mut ceiling,
        );

        assert_eq!(
            metrics.memory_ceiling_no_shed.get(),
            0,
            "shedding can still help here"
        );
        assert!(!ceiling.active);
        assert!(!gaps.is_empty(), "and it did shed");
    }

    /// The gauge must come back down when pressure clears — a latched 1 would
    /// be its own false alarm.
    #[test]
    fn ceiling_state_clears_on_recovery() {
        let metrics = Metrics::new();
        let mut buffer = RetryBuffer::new(RetryBufferConfig::default());
        let mut gaps = PendingGaps::default();
        let mut ceiling = CeilingState::default();

        let dir = fake_cgroup("recover-high", 1_027_604_480, "1073741824");
        let pressure = MemoryPressure::at(&dir, None).expect("detected");
        shed_under_memory_pressure(
            &pressure,
            0.8,
            &mut buffer,
            &mut gaps,
            &metrics,
            &mut ceiling,
        );
        assert_eq!(metrics.memory_ceiling_no_shed.get(), 1);

        // Pressure drops (the allocator gave pages back, or the limit grew).
        std::fs::write(dir.join("memory.current"), "314572800\n").unwrap();
        shed_under_memory_pressure(
            &pressure,
            0.8,
            &mut buffer,
            &mut gaps,
            &metrics,
            &mut ceiling,
        );
        assert_eq!(
            metrics.memory_ceiling_no_shed.get(),
            0,
            "cleared, not latched"
        );
        assert!(!ceiling.active);
    }

    // ── the backlog outlives the process (jalki #33) ────────────────────────

    fn spool_at(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("jalki-loop-spool-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("backlog.spool")
    }

    fn spool_loop(path: &std::path::Path) -> Harness {
        let (tx, rx) = mpsc::channel::<Vec<EvidenceRecord>>(64);
        let up = Arc::new(AtomicBool::new(false));
        let overloaded = Arc::new(AtomicBool::new(false));
        let attempts = Arc::new(AtomicUsize::new(0));
        let delivered = Arc::new(StdMutex::new(Vec::new()));
        let metrics = Arc::new(Metrics::new());
        let handle = tokio::spawn(run_sink_loop(SinkLoop {
            rx,
            sink: Box::new(ControlledSink {
                up: up.clone(),
                overloaded: overloaded.clone(),
                attempts: attempts.clone(),
                delivered: delivered.clone(),
                append_cost: Duration::ZERO,
            }),
            metrics: metrics.clone(),
            producer: ProducerMetadata::new("test", "node-1", "6.17.0"),
            enricher: Arc::new(NoopEnricher),
            namespace_allowlist: None,
            retry_config: RetryBufferConfig::default(),
            backoff_config: RetryBackoffConfig {
                base_ms: 10,
                max_ms: 10,
            },
            pace_config: DrainPaceConfig {
                max_bytes_per_sec: u64::MAX / 4,
                max_batches_per_sec: u64::MAX / 4,
                ..DrainPaceConfig::default()
            },
            memory_pressure: None,
            spool: Spool::open(SpoolConfig {
                path: path.to_path_buf(),
                max_bytes: 16 * 1024 * 1024,
            }),
        }));
        Harness {
            tx,
            up,
            overloaded,
            attempts,
            delivered,
            metrics,
            handle,
        }
    }

    /// #33's outstanding acceptance criterion since it was filed: restart
    /// mid-outage and the evidence buffered before the restart still gets
    /// delivered. Until now an OOM kill during an outage destroyed exactly the
    /// evidence that outage produced.
    #[tokio::test(start_paused = true)]
    async fn evidence_buffered_before_a_restart_is_delivered_after_it() {
        let path = spool_at("restart");

        // First process: sink is down, evidence accumulates, process ends.
        {
            let h = spool_loop(&path);
            for _ in 0..6 {
                h.tx.send(one_record()).await.unwrap();
            }
            drain(&h).await;
            assert!(
                h.metrics.spool_bytes.get() > 0,
                "the backlog reached disk while the sink was down"
            );
            assert!(
                h.delivered.lock().unwrap().is_empty(),
                "nothing got through"
            );
            drop(h.tx);
            let _ = h.handle.await;
        }

        // Second process: same spool, sink is back.
        {
            let h = spool_loop(&path);
            h.up.store(true, Ordering::SeqCst);
            h.tx.send(one_record()).await.unwrap();
            advance_draining(&h, Duration::from_secs(5), Duration::from_millis(100)).await;

            assert_eq!(
                h.delivered.lock().unwrap().len(),
                7,
                "all six recovered batches, plus the new one"
            );
            drop(h.tx);
            let _ = h.handle.await;
        }

        // And nothing is left to replay a third time.
        let (remaining, _) = Spool::replay(&path);
        assert!(
            remaining.is_empty(),
            "delivered evidence must not be re-delivered on the next restart"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_delivered_backlog_leaves_nothing_on_disk() {
        let path = spool_at("drains");
        let h = spool_loop(&path);
        h.up.store(true, Ordering::SeqCst);
        for _ in 0..5 {
            h.tx.send(one_record()).await.unwrap();
        }
        advance_draining(&h, Duration::from_secs(5), Duration::from_millis(100)).await;

        assert_eq!(h.delivered.lock().unwrap().len(), 5);
        assert_eq!(
            h.metrics.spool_bytes.get(),
            0,
            "a healthy sink leaves no disk residue to replay"
        );

        drop(h.tx);
        let _ = h.handle.await;
    }
}

use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use jalki_enrich::BindingCache;
use jalki_evidence::{CompositeSink, EvidenceSink, FileSink, StdoutSink};
use tracing_subscriber::EnvFilter;

use jalki::enrich::CachedEnricher;
use jalki::kube_watch;
use jalki::probes::{
    file_open::FileOpen, file_open_attempt::FileOpenAttempt, process_exec::ProcessExec,
    tcp_close::TcpClose, tcp_connect::TcpConnect, tcp_retransmit::TcpRetransmit,
};
use jalki::runtime::Runtime;
use jalki::sensitive_paths;

mod cli;

#[derive(Parser)]
#[command(
    name = "jalki",
    about = "Programmable fentry/fexit framework for Linux"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// Path to the compiled eBPF object.
    #[arg(
        long,
        env = "JALKI_EBPF_PATH",
        default_value = "jalki-ebpf/target/bpfel-unknown-none/release/jalki-ebpf",
        global = true
    )]
    ebpf_path: String,

    /// Primary evidence sink: "stdout", "file", "vartio", or a file path.
    #[arg(
        long,
        alias = "emit",
        env = "JALKI_SINK",
        default_value = "stdout",
        global = true
    )]
    sink: String,

    /// Additional best-effort evidence sink: "stdout", "file", "vartio", or a file path.
    #[arg(long, env = "JALKI_ALSO_SINK", global = true)]
    also_sink: Vec<String>,

    /// Vartio source-ingress gRPC endpoint for `--sink vartio`
    /// (e.g. http://vartio.vartio.svc:50061).
    #[arg(long, env = "JALKI_VARTIO_ENDPOINT", global = true)]
    vartio_endpoint: Option<String>,

    /// Adapter identity reported to Vartio for `--sink vartio`.
    #[arg(
        long,
        env = "JALKI_VARTIO_ADAPTER_ID",
        default_value = "jalki",
        global = true
    )]
    vartio_adapter_id: String,

    /// Cluster name for FALSE Protocol Occurrences.
    #[arg(long, env = "JALKI_CLUSTER", global = true)]
    cluster: Option<String>,

    /// Enable Kubernetes pod/container enrichment for Plane-B evidence.
    #[arg(long, env = "JALKI_K8S_ENRICHMENT", global = true)]
    k8s_enrichment: bool,

    /// Namespace allow-list for sink delivery. Repeatable; comma-separated
    /// values accepted. When set, only evidence bound to one of these
    /// Kubernetes namespaces reaches the sink — the source-side volume control
    /// that keeps jälki from shipping the whole-node firehose. Empty = deliver
    /// all bound evidence. The local CLI query surface is unaffected.
    #[arg(long = "namespace", env = "JALKI_NAMESPACES", value_delimiter = ',', global = true)]
    namespaces: Vec<String>,

    /// Kubernetes node name for pod watches. Defaults to the host name.
    #[arg(long, env = "JALKI_NODE_NAME", global = true)]
    node_name: Option<String>,

    /// cgroup filesystem root used to resolve cgroup_id to container id.
    #[arg(
        long,
        env = "JALKI_CGROUP_ROOT",
        default_value = "/sys/fs/cgroup",
        global = true
    )]
    cgroup_root: String,

    /// Sensitive path pattern for kernel.file.open capture. Repeatable; comma-separated values are accepted.
    #[arg(
        long,
        env = "JALKI_SENSITIVE_PATHS",
        value_delimiter = ',',
        global = true
    )]
    sensitive_path: Vec<String>,
}

#[derive(Subcommand)]
enum Command {
    /// Ask a question about kernel behavior — the killer feature.
    ///
    /// Searches the knowledge base, auto-attaches relevant probes,
    /// collects events, interprets them, and returns an answer.
    Ask {
        /// The question to ask the kernel.
        question: Vec<String>,

        /// How many seconds to collect events before answering.
        #[arg(long, default_value = "5")]
        collect_seconds: u64,
    },

    /// Watch kernel events for a specific probe (one-shot collection).
    Watch {
        /// Kernel function to watch.
        function: String,

        /// How many seconds to collect.
        #[arg(long, default_value = "10")]
        seconds: u64,

        /// Filter: destination port.
        #[arg(long)]
        dst_port: Option<u16>,

        /// Filter: destination IP.
        #[arg(long)]
        dst_ip: Option<String>,

        /// Filter: process ID.
        #[arg(long)]
        pid: Option<u32>,
    },

    /// Stream live events as ndjson.
    Stream {
        /// Kernel function to stream. If omitted, streams all attached probes.
        function: Option<String>,
    },

    /// List available kernel probes from the knowledge base.
    List {
        /// Filter by layer (tcp, memory, fs, sched, process).
        #[arg(long)]
        layer: Option<String>,
    },

    /// Show status of attached probes on the running daemon.
    Status,
}

#[tokio::main]
async fn main() -> Result<()> {
    // rustls 0.23 requires exactly one process-level crypto provider; the dep
    // tree (kube rustls-tls) compiles rustls without one, which panics at the
    // first TLS use (e.g. the k8s-enrichment client). Install ring up front —
    // Err just means another component already installed one, which is fine.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cli = Cli::parse();

    match &cli.command {
        // Subcommands use minimal logging (stderr).
        Some(_) => {
            tracing_subscriber::fmt()
                .with_env_filter(
                    EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn")),
                )
                .with_writer(std::io::stderr)
                .init();
        }
        // Daemon mode uses full logging.
        None => {
            tracing_subscriber::fmt()
                .with_env_filter(EnvFilter::from_default_env())
                .init();
        }
    }

    match cli.command {
        Some(Command::Ask {
            question,
            collect_seconds,
        }) => {
            let q = question.join(" ");
            cli::ask::run(&q, collect_seconds).await
        }
        Some(Command::Watch {
            function,
            seconds,
            dst_port,
            dst_ip,
            pid,
        }) => cli::watch::run(&function, seconds, dst_port, dst_ip, pid).await,
        Some(Command::Stream { function }) => cli::stream::run(function.as_deref()).await,
        Some(Command::List { layer }) => {
            cli::list::run(layer.as_deref());
            Ok(())
        }
        Some(Command::Status) => cli::status::run().await,
        None => run_daemon(cli).await,
    }
}

async fn run_daemon(cli: Cli) -> Result<()> {
    let mut runtime = Runtime::new(&cli.ebpf_path)
        .attach(ProcessExec::new())
        .attach(FileOpen::new())
        .attach(FileOpenAttempt::new())
        .attach(TcpConnect::new())
        .attach(TcpClose::new())
        .attach(TcpRetransmit::new())
        .sensitive_paths(sensitive_paths::parse_sensitive_paths(&cli.sensitive_path))
        .namespace_allowlist(cli.namespaces.clone());

    if let Some(cluster) = cli.cluster.clone() {
        runtime = runtime.cluster(cluster);
    }

    if cli.k8s_enrichment {
        runtime = configure_k8s_enrichment(runtime, &cli).await?;
    }

    let sink = build_sink(&cli).await?;
    runtime = runtime.sink_to(sink);

    runtime.run().await
}

async fn configure_k8s_enrichment(mut runtime: Runtime, cli: &Cli) -> Result<Runtime> {
    let node_name = cli.node_name.clone().unwrap_or_else(default_node_name);
    let cache = Arc::new(RwLock::new(BindingCache::new()));
    let enricher = Arc::new(CachedEnricher::new(&cli.cgroup_root, cache.clone()));
    runtime = runtime.enrich_with(enricher);

    let client = kube::Client::try_default()
        .await
        .context("failed to create Kubernetes client for jalki pod enrichment")?;
    tokio::spawn(async move {
        if let Err(err) = kube_watch::run_pod_binding_watcher(client, node_name, cache).await {
            tracing::error!(error = %err, "Kubernetes pod binding watcher stopped");
        }
    });

    Ok(runtime)
}

fn default_node_name() -> String {
    hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_else(|| "unknown".into())
}

async fn build_sink(cli: &Cli) -> Result<Box<dyn EvidenceSink>> {
    let primary = sink_from_spec(&cli.sink, cli).await?;
    if cli.also_sink.is_empty() {
        Ok(primary)
    } else {
        let mut secondaries = Vec::with_capacity(cli.also_sink.len());
        for spec in &cli.also_sink {
            secondaries.push(sink_from_spec(spec, cli).await?);
        }
        Ok(Box::new(CompositeSink::new(primary, secondaries)))
    }
}

async fn sink_from_spec(spec: &str, cli: &Cli) -> Result<Box<dyn EvidenceSink>> {
    Ok(match spec {
        "stdout" => Box::new(StdoutSink::new()),
        "file" => Box::new(FileSink::new(PathBuf::from("jalki-events.ndjson"))),
        "vartio" => Box::new(build_vartio_sink(cli).await?),
        other => Box::new(FileSink::new(PathBuf::from(other))),
    })
}

/// The ADR-0003/0004 Plane-B transport. Endpoint + adapter id come from flags
/// or env; the ingress bearer token (ADR-0004 D1-a) comes from
/// `VARTIO_INGRESS_TOKEN` only — env from a Secret, never argv, never logged.
async fn build_vartio_sink(cli: &Cli) -> Result<jalki_vartio_sink::VartioSink> {
    let endpoint = cli
        .vartio_endpoint
        .clone()
        .context("--sink vartio requires --vartio-endpoint (or JALKI_VARTIO_ENDPOINT)")?;
    let mut cfg =
        jalki_vartio_sink::VartioSinkConfig::new(endpoint, cli.vartio_adapter_id.clone());
    if let Ok(token) = std::env::var("VARTIO_INGRESS_TOKEN") {
        cfg = cfg.with_ingress_token(token);
    }
    // ADR-0005 §4: the file family ships only when the receiving importer
    // accepts it; the flag decouples jälki's deploy from Vartio's.
    let file_types = std::env::var("JALKI_VARTIO_FILE_TYPES")
        .map(|v| matches!(v.trim(), "1" | "true"))
        .unwrap_or(false);
    cfg = cfg.with_file_types(file_types);
    jalki_vartio_sink::VartioSink::connect(cfg)
        .await
        .map_err(|e| anyhow::anyhow!("vartio sink connect failed: {e}"))
}

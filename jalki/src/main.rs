use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use jalki_evidence::{CompositeSink, EvidenceSink, FileSink, StdoutSink};
use tracing_subscriber::EnvFilter;

use jalki::probes::{tcp_close::TcpClose, tcp_connect::TcpConnect, tcp_retransmit::TcpRetransmit};
use jalki::runtime::Runtime;

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

    /// Primary evidence sink: "stdout", "file", or a file path.
    #[arg(
        long,
        alias = "emit",
        env = "JALKI_SINK",
        default_value = "stdout",
        global = true
    )]
    sink: String,

    /// Additional best-effort evidence sink: "stdout", "file", or a file path.
    #[arg(long, env = "JALKI_ALSO_SINK", global = true)]
    also_sink: Vec<String>,

    /// Cluster name for FALSE Protocol Occurrences.
    #[arg(long, env = "JALKI_CLUSTER", global = true)]
    cluster: Option<String>,
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
        .attach(TcpConnect::new())
        .attach(TcpClose::new())
        .attach(TcpRetransmit::new());

    if let Some(cluster) = cli.cluster {
        runtime = runtime.cluster(cluster);
    }

    let sink = build_sink(&cli.sink, &cli.also_sink);
    runtime = runtime.sink_to(sink);

    runtime.run().await
}

fn build_sink(primary: &str, secondaries: &[String]) -> Box<dyn EvidenceSink> {
    let primary = sink_from_spec(primary);
    if secondaries.is_empty() {
        primary
    } else {
        let secondaries = secondaries
            .iter()
            .map(|spec| sink_from_spec(spec))
            .collect();
        Box::new(CompositeSink::new(primary, secondaries))
    }
}

fn sink_from_spec(spec: &str) -> Box<dyn EvidenceSink> {
    match spec {
        "stdout" => Box::new(StdoutSink::new()),
        "file" => Box::new(FileSink::new(PathBuf::from("jalki-events.ndjson"))),
        other => Box::new(FileSink::new(PathBuf::from(other))),
    }
}

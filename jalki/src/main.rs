use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use tracing_subscriber::EnvFilter;

use jalki::emit::{file::FileEmitter, grpc::GrpcEmitter, stdout::StdoutEmitter};
use jalki::probes::{tcp_close::TcpClose, tcp_connect::TcpConnect, tcp_retransmit::TcpRetransmit};
use jalki::runtime::Runtime;

#[derive(Parser)]
#[command(name = "jalki", about = "Programmable fentry/fexit framework for Linux")]
struct Cli {
    /// Path to the compiled eBPF object.
    #[arg(long, env = "JALKI_EBPF_PATH",
        default_value = "jalki-ebpf/target/bpfel-unknown-none/release/jalki-ebpf")]
    ebpf_path: String,

    /// Emit destination: "stdout", "grpc://<endpoint>", or a file path.
    #[arg(long, env = "JALKI_EMIT", default_value = "stdout")]
    emit: Vec<String>,

    /// Cluster name for FALSE Protocol Occurrences.
    #[arg(long, env = "JALKI_CLUSTER")]
    cluster: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    let mut runtime = Runtime::new(&cli.ebpf_path)
        .attach(TcpConnect::new())
        .attach(TcpClose::new())
        .attach(TcpRetransmit::new());

    if let Some(cluster) = cli.cluster {
        runtime = runtime.cluster(cluster);
    }

    for dest in &cli.emit {
        if dest == "stdout" {
            runtime = runtime.emit_to(StdoutEmitter::new());
        } else if let Some(endpoint) = dest.strip_prefix("grpc://") {
            runtime = runtime.emit_to(GrpcEmitter::new(endpoint));
        } else {
            runtime = runtime.emit_to(FileEmitter::new(PathBuf::from(dest)));
        }
    }

    runtime.run().await
}

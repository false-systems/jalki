//! Compile the vendored Vartio source-ingress contract.
//!
//! Source of truth: `vartio/apps/vartio_runtime/proto/source_ingress.proto`
//! (Vartio owns the contract; producers vendor a copy — polku #158 Q2). We build
//! the client for the sink and the server for the in-crate test receiver. CI
//! without `protoc` falls back to the checked-in generated file under `src/proto/`.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto/source_ingress.proto");
    println!("cargo:rerun-if-env-changed=PROTOC");

    if !protoc_available() {
        println!("cargo:warning=protoc not found, using pre-generated source_ingress proto");
        return Ok(());
    }

    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .out_dir("src/proto")
        .compile_protos(&["proto/source_ingress.proto"], &["proto"])?;

    Ok(())
}

fn protoc_available() -> bool {
    let protoc = std::env::var_os("PROTOC").unwrap_or_else(|| "protoc".into());
    std::process::Command::new(protoc)
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

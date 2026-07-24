use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "jalki-sdk-codegen",
    about = "Generate jälki SDK foundation from meta"
)]
struct Cli {
    /// Target language: python, go, elixir, typescript
    #[arg(long)]
    lang: String,
    /// Output directory for generated files
    #[arg(long)]
    out: PathBuf,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let target: Box<dyn jalki_sdk_meta::codegen::CodegenTarget> = match cli.lang.as_str() {
        "python" => Box::new(jalki_sdk_meta::codegen::python::PythonTarget),
        "go" => Box::new(jalki_sdk_meta::codegen::go::GoTarget),
        "elixir" => Box::new(jalki_sdk_meta::codegen::elixir::ElixirTarget),
        "typescript" => Box::new(jalki_sdk_meta::codegen::typescript::TypescriptTarget),
        other => anyhow::bail!("unknown language: {other}"),
    };

    std::fs::create_dir_all(&cli.out)?;
    target.write(&cli.out)?;

    println!(
        "generated {} SDK foundation to {}",
        cli.lang,
        cli.out.display()
    );

    Ok(())
}

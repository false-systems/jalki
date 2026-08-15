use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use aya::programs::{FEntry, FExit, TracePoint};
use aya::{Btf, Ebpf};
use tracing::{info, warn};

use crate::filter;
use crate::probe::{Attachment, Probe};
use crate::sensitive_paths;

/// Load the eBPF object and attach probes described by their trait metadata.
///
/// The loader is probe-agnostic. It reads `program_name()` and `attachments()`
/// from each probe to find and attach the right eBPF programs. No hardcoded
/// program names — add a new probe, implement the trait, it just works.
pub fn load_and_attach(
    ebpf_path: &Path,
    probes: &[Arc<dyn Probe>],
    sensitive_paths: &[String],
) -> Result<Ebpf> {
    let data = std::fs::read(ebpf_path)
        .with_context(|| format!("failed to read eBPF object at {}", ebpf_path.display()))?;

    let mut ebpf = Ebpf::load(&data).context("failed to load eBPF programs")?;

    // Initialize aya-log for eBPF-side logging.
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        warn!("eBPF logger init failed (non-fatal): {e}");
    }

    // Populate self-filter before attaching probes.
    filter::populate_pid_filter(&mut ebpf)?;
    sensitive_paths::populate_sensitive_prefixes(&mut ebpf, sensitive_paths)?;
    // Verify the file.open probe's struct file offsets against kernel BTF
    // (warns loudly on mismatch; the eBPF probe uses the compiled constants).
    crate::file_offsets::check_file_offsets();
    // Resolve task_struct offsets from BTF so process.exec can populate ppid.
    crate::file_offsets::populate_task_offsets(&mut ebpf)?;

    let btf = Btf::from_sys_fs().context("failed to load BTF from /sys/kernel/btf/vmlinux")?;

    // Attach each probe based on its metadata. PER-PROBE fault tolerance:
    // a probe that fails to load or attach is skipped with the full error,
    // never fatal to the daemon. The first external deployment (an amd64 VM,
    // 2026-08-15) proved why: its kernel's verifier rejected the
    // security_file_open program over a helper type-signature difference
    // ("R1 is of type file but path is expected"), and one unverifiable
    // probe took down all six — on a customer kernel we do not control.
    // Degrading per-probe is also what the runtime-evidence contract
    // requires (vartio-runtime-evidence-v1.md §5 collector_integrity:
    // capability state is a reported fact, not a startup precondition).
    // Only zero attached probes is fatal — a collector observing nothing
    // has no reason to run.
    let mut attached = 0;
    let mut skipped: Vec<&str> = Vec::new();
    for probe in probes {
        let prog_name = probe.program_name();
        let mut probe_ok = true;
        for attachment in probe.attachments() {
            let result = match attachment {
                Attachment::Fentry { function } => {
                    attach_fentry(&mut ebpf, prog_name, function, &btf)
                }
                Attachment::Fexit { function } => {
                    attach_fexit(&mut ebpf, prog_name, function, &btf)
                }
                Attachment::Tracepoint {
                    program,
                    category,
                    name,
                } => attach_tracepoint(&mut ebpf, program, category, name),
            };
            match result {
                Ok(()) => attached += 1,
                Err(e) => {
                    probe_ok = false;
                    warn!(
                        probe = probe.name(),
                        error = format!("{e:#}"),
                        "probe failed to load/attach on this kernel; continuing without it — its evidence type will be ABSENT, which downstream must treat as no-coverage, not no-events"
                    );
                }
            }
        }
        if !probe_ok {
            skipped.push(probe.name());
        }
    }

    if attached == 0 {
        anyhow::bail!("no probe could attach on this kernel — refusing to run a collector that observes nothing");
    }
    if skipped.is_empty() {
        info!(count = attached, "all probes attached");
    } else {
        warn!(
            count = attached,
            skipped = skipped.join(","),
            "started DEGRADED: some probes are not attached on this kernel"
        );
    }
    Ok(ebpf)
}

fn attach_fentry(ebpf: &mut Ebpf, prog_name: &str, fn_name: &str, btf: &Btf) -> Result<()> {
    let prog: &mut FEntry = ebpf
        .program_mut(prog_name)
        .ok_or_else(|| anyhow::anyhow!("program {prog_name} not found in eBPF object"))?
        .try_into()
        .context("program is not an fentry")?;
    prog.load(fn_name, btf)
        .with_context(|| format!("failed to load fentry/{fn_name} (program {prog_name})"))?;
    prog.attach()
        .with_context(|| format!("failed to attach fentry/{fn_name}"))?;
    info!("attached fentry/{fn_name}");
    Ok(())
}

fn attach_fexit(ebpf: &mut Ebpf, prog_name: &str, fn_name: &str, btf: &Btf) -> Result<()> {
    let prog: &mut FExit = ebpf
        .program_mut(prog_name)
        .ok_or_else(|| anyhow::anyhow!("program {prog_name} not found in eBPF object"))?
        .try_into()
        .context("program is not an fexit")?;
    prog.load(fn_name, btf)
        .with_context(|| format!("failed to load fexit/{fn_name} (program {prog_name})"))?;
    prog.attach()
        .with_context(|| format!("failed to attach fexit/{fn_name}"))?;
    info!("attached fexit/{fn_name}");
    Ok(())
}

fn attach_tracepoint(ebpf: &mut Ebpf, prog_name: &str, category: &str, name: &str) -> Result<()> {
    let prog: &mut TracePoint = ebpf
        .program_mut(prog_name)
        .ok_or_else(|| anyhow::anyhow!("program {prog_name} not found in eBPF object"))?
        .try_into()
        .context("program is not a tracepoint")?;
    prog.load()
        .with_context(|| format!("failed to load tracepoint/{category}/{name}"))?;
    prog.attach(category, name)
        .with_context(|| format!("failed to attach tracepoint/{category}/{name}"))?;
    info!("attached tracepoint/{category}/{name}");
    Ok(())
}

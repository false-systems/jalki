use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use aya::programs::{FEntry, FExit};
use aya::{Btf, Ebpf};
use tracing::{info, warn};

use crate::filter;
use crate::probe::{Attachment, Probe};

/// Load the eBPF object and attach probes described by their trait metadata.
///
/// The loader is probe-agnostic. It reads `program_name()` and `attachments()`
/// from each probe to find and attach the right eBPF programs. No hardcoded
/// program names — add a new probe, implement the trait, it just works.
pub fn load_and_attach(ebpf_path: &Path, probes: &[Arc<dyn Probe>]) -> Result<Ebpf> {
    let data = std::fs::read(ebpf_path)
        .with_context(|| format!("failed to read eBPF object at {}", ebpf_path.display()))?;

    let mut ebpf = Ebpf::load(&data).context("failed to load eBPF programs")?;

    // Initialize aya-log for eBPF-side logging.
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        warn!("eBPF logger init failed (non-fatal): {e}");
    }

    // Populate self-filter before attaching probes.
    filter::populate_pid_filter(&mut ebpf)?;

    let btf = Btf::from_sys_fs().context("failed to load BTF from /sys/kernel/btf/vmlinux")?;

    // Attach each probe based on its metadata.
    let mut attached = 0;
    for probe in probes {
        let prog_name = probe.program_name();
        for attachment in probe.attachments() {
            match attachment {
                Attachment::Fentry { function } => {
                    attach_fentry(&mut ebpf, prog_name, function, &btf)
                        .with_context(|| format!("probe '{}' failed to attach", probe.name()))?;
                }
                Attachment::Fexit { function } => {
                    attach_fexit(&mut ebpf, prog_name, function, &btf)
                        .with_context(|| format!("probe '{}' failed to attach", probe.name()))?;
                }
            }
            attached += 1;
        }
    }

    info!(count = attached, "all probes attached");
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

//! Verify the file.open probe's `struct file` offsets against the running kernel.
//!
//! `bpf_d_path` needs a verifier-known `struct path *`, which requires a
//! compile-time-constant offset (a runtime offset is rejected by the verifier),
//! and this aya version exposes no CO-RE field relocation — so the eBPF probe
//! uses the constants in `jalki_common`. A wrong constant doesn't crash: it makes
//! `bpf_d_path` fail and the event is dropped, so file.open goes *silently*
//! absent. This guard resolves the real offsets from `/sys/kernel/btf/vmlinux` at
//! startup and logs loudly on mismatch, turning that silence into a clear signal.

use anyhow::{Context, Result};
use aya::maps::Array;
use aya::Ebpf;
use jalki_common::{FILE_F_FLAGS_OFFSET, FILE_F_PATH_OFFSET};
use tracing::{error, info, warn};

/// Resolve `struct file` offsets from BTF and compare to the compiled constants.
///
/// Never fatal: on a mismatch or when BTF is unavailable it logs and returns.
pub fn check_file_offsets() {
    match resolve() {
        Ok((f_path, f_flags)) => {
            let mut mismatch = false;
            if f_path != FILE_F_PATH_OFFSET {
                mismatch = true;
                error!(
                    btf = f_path,
                    compiled = FILE_F_PATH_OFFSET,
                    "struct file.f_path offset disagrees with the compiled file.open probe constant; \
                     bpf_d_path will fail on this kernel and file.open evidence will be silently absent. \
                     Rebuild jalki-ebpf with the correct offset (or wait for CO-RE support)."
                );
            }
            if f_flags != FILE_F_FLAGS_OFFSET {
                mismatch = true;
                warn!(
                    btf = f_flags,
                    compiled = FILE_F_FLAGS_OFFSET,
                    "struct file.f_flags offset disagrees with the compiled file.open probe constant; \
                     file.open `flags` will be inaccurate on this kernel."
                );
            }
            if !mismatch {
                info!(
                    f_path,
                    f_flags, "verified file.open struct file offsets against kernel BTF"
                );
            }
        }
        Err(e) => {
            warn!(
                error = %e,
                f_path = FILE_F_PATH_OFFSET,
                f_flags = FILE_F_FLAGS_OFFSET,
                "could not verify file.open struct file offsets against BTF; using compiled constants \
                 (may be wrong on this kernel)"
            );
        }
    }
}

fn resolve() -> Result<(u32, u32), String> {
    let btf = jalki_codegen::btf::BtfData::from_sys_fs().map_err(|e| format!("load BTF: {e}"))?;
    let file_id = btf
        .struct_by_name("file")
        .ok_or_else(|| "struct file not found in BTF".to_string())?;
    let f_path = btf
        .field_offset(file_id, "f_path")
        .map_err(|e| format!("resolve file.f_path: {e}"))?;
    let f_flags = btf
        .field_offset(file_id, "f_flags")
        .map_err(|e| format!("resolve file.f_flags: {e}"))?;
    Ok((f_path, f_flags))
}

/// Resolve `task_struct.{real_parent, tgid}` offsets from BTF into the
/// `TASK_OFFSETS` map, so the exec probe can read `current->real_parent->tgid`
/// for ppid. Unlike `bpf_d_path`, those reads go through `bpf_probe_read_kernel`,
/// which accepts a runtime offset — so BTF-driven offsets are verifier-safe here.
///
/// Never fatal: if BTF resolution fails the map stays zero and the probe leaves
/// ppid = 0 (omitted) rather than read a guessed offset.
pub fn populate_task_offsets(ebpf: &mut Ebpf) -> Result<()> {
    let mut map: Array<_, u32> = ebpf
        .map_mut("TASK_OFFSETS")
        .ok_or_else(|| anyhow::anyhow!("TASK_OFFSETS map not found"))?
        .try_into()
        .context("TASK_OFFSETS is not an Array")?;

    match resolve_task_offsets() {
        Ok((real_parent, tgid)) => {
            map.set(0, real_parent, 0).context("set real_parent offset")?;
            map.set(1, tgid, 0).context("set tgid offset")?;
            info!(
                real_parent,
                tgid, "resolved task_struct offsets from BTF (process.exec ppid enabled)"
            );
        }
        Err(e) => {
            warn!(
                error = %e,
                "could not resolve task_struct offsets from BTF; process.exec ppid will be omitted"
            );
        }
    }
    Ok(())
}

fn resolve_task_offsets() -> Result<(u32, u32), String> {
    let btf = jalki_codegen::btf::BtfData::from_sys_fs().map_err(|e| format!("load BTF: {e}"))?;
    let task_id = btf
        .struct_by_name("task_struct")
        .ok_or_else(|| "struct task_struct not found in BTF".to_string())?;
    let real_parent = btf
        .field_offset(task_id, "real_parent")
        .map_err(|e| format!("resolve task_struct.real_parent: {e}"))?;
    let tgid = btf
        .field_offset(task_id, "tgid")
        .map_err(|e| format!("resolve task_struct.tgid: {e}"))?;
    Ok((real_parent, tgid))
}

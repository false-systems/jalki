//! Verify the file.open probe's `struct file` offsets against the running kernel.
//!
//! `bpf_d_path` needs a verifier-known `struct path *`, which requires a
//! compile-time-constant offset (a runtime offset is rejected by the verifier),
//! and this aya version exposes no CO-RE field relocation — so the eBPF probe
//! uses the constants in `jalki_common`. A wrong constant doesn't crash: it makes
//! `bpf_d_path` fail and the event is dropped, so file.open goes *silently*
//! absent. This guard resolves the real offsets from `/sys/kernel/btf/vmlinux` at
//! startup and logs loudly on mismatch, turning that silence into a clear signal.

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

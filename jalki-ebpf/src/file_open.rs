use aya_ebpf::bindings::path;
use aya_ebpf::helpers::{
    bpf_get_current_cgroup_id, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns,
    bpf_probe_read_kernel,
};
use aya_ebpf::programs::FExitContext;

use jalki_common::{
    FileOpenEvent, FILE_F_FLAGS_OFFSET, FILE_F_PATH_OFFSET, FILE_OPEN_PATH_LEN,
    MAX_SENSITIVE_PREFIXES,
};

use crate::{is_self_filtered, FILE_OPEN_EVENTS, FILE_OPEN_SCRATCH, SENSITIVE_PREFIXES};

// `struct file` field offsets (f_path for bpf_d_path, f_flags) are compile-time
// constants shared from `jalki_common` and verified against kernel BTF at load
// by `jalki::file_offsets`. They must be constant: `bpf_d_path` requires a
// verifier-known `struct path *`, which a runtime offset cannot provide.

/// Handle fexit/security_file_open.
///
/// security_file_open(struct file *file) -> int
///
/// fexit args: arg(0) = file, arg(1) = return value.
pub fn handle(ctx: &FExitContext) -> i32 {
    match try_handle(ctx) {
        Ok(_) => 0,
        Err(_) => 0,
    }
}

#[inline(always)]
fn try_handle(ctx: &FExitContext) -> Result<(), i64> {
    if is_self_filtered() {
        return Ok(());
    }

    let file: u64 = unsafe { ctx.arg(0) };
    if file == 0 {
        return Ok(());
    }
    let ret: i32 = unsafe { ctx.arg(1) };

    let scratch = FILE_OPEN_SCRATCH.get_ptr_mut(0).ok_or(1i64)?;

    // SAFETY: `scratch` points at this CPU's map value. The program owns it for
    // the duration of this invocation and writes a plain-old-data event into it.
    let event = unsafe { &mut *scratch };
    *event = FileOpenEvent {
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        pid: (bpf_get_current_pid_tgid() >> 32) as u32,
        uid: bpf_get_current_uid_gid() as u32,
        // SAFETY: helper reads the current task's cgroup id and does not
        // dereference program-provided pointers.
        cgroup_id: unsafe { bpf_get_current_cgroup_id() },
        ret,
        flags: read_file_flags(file),
        comm: aya_ebpf::helpers::bpf_get_current_comm().unwrap_or([0u8; 16]),
        path: [0u8; FILE_OPEN_PATH_LEN],
    };

    let file_path = (file as *mut u8).wrapping_add(FILE_F_PATH_OFFSET as usize) as *mut path;
    let path_len = unsafe {
        aya_ebpf::helpers::gen::bpf_d_path(
            file_path,
            event.path.as_mut_ptr() as *mut _,
            FILE_OPEN_PATH_LEN as u32,
        )
    };

    if path_len <= 0 {
        return Ok(());
    }

    if !matches_sensitive_prefix(&event.path) {
        return Ok(());
    }

    // Best-effort ring buffer output — drop silently if full. Reader-side stats
    // surface ring buffer drops as agent gap evidence.
    let _ = FILE_OPEN_EVENTS.output(event, 0);

    Ok(())
}

#[inline(always)]
fn read_file_flags(file: u64) -> u32 {
    unsafe {
        bpf_probe_read_kernel((file as *const u8).add(FILE_F_FLAGS_OFFSET as usize) as *const u32)
    }
    .unwrap_or(0)
}

#[inline(always)]
fn matches_sensitive_prefix(path: &[u8; FILE_OPEN_PATH_LEN]) -> bool {
    let mut index = 0;
    while index < MAX_SENSITIVE_PREFIXES {
        if let Some(prefix) = SENSITIVE_PREFIXES.get(index) {
            if prefix.len == 0 {
                index += 1;
                continue;
            }
            if prefix_matches(path, &prefix.bytes, prefix.len as usize) {
                return true;
            }
        }
        index += 1;
    }
    false
}

#[inline(always)]
fn prefix_matches(path: &[u8; FILE_OPEN_PATH_LEN], prefix: &[u8; 128], prefix_len: usize) -> bool {
    if prefix_len == 0 || prefix_len > 128 || prefix_len > FILE_OPEN_PATH_LEN {
        return false;
    }

    let mut i = 0;
    while i < 128 {
        if i >= prefix_len {
            return true;
        }
        let path_byte = unsafe { *path.as_ptr().add(i) };
        let prefix_byte = unsafe { *prefix.as_ptr().add(i) };
        if path_byte != prefix_byte {
            return false;
        }
        i += 1;
    }

    true
}

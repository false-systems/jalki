use aya_ebpf::helpers::{
    bpf_get_current_cgroup_id, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns,
    bpf_probe_read_user_str_bytes,
};
use aya_ebpf::programs::TracePointContext;

use jalki_common::{FileOpenEvent, FILE_OPEN_PATH_LEN};

use crate::file_open::matches_sensitive_prefix;
use crate::{
    is_self_filtered, ENTER_PATH_SCRATCH, IN_FLIGHT_OPENS, OPEN_ATTEMPT_EVENTS, OPEN_ATTEMPT_SCRATCH,
};

/// sys_enter_open{at,at2} layout: __syscall_nr@8, dfd@16, filename@24.
const SYS_ENTER_FILENAME_OFFSET: usize = 24;
/// sys_exit_open{at,at2} layout: __syscall_nr@8, ret@16.
const SYS_EXIT_RET_OFFSET: usize = 16;

/// sys_enter_openat / sys_enter_openat2: stash the user-requested path if it is
/// an absolute, watched sensitive path. Gating here bounds the in-flight map and
/// the ring buffer.
pub fn handle_enter(ctx: &TracePointContext) -> i32 {
    let _ = try_enter(ctx);
    0
}

#[inline(always)]
fn try_enter(ctx: &TracePointContext) -> Result<(), i64> {
    if is_self_filtered() {
        return Ok(());
    }

    let filename_ptr: u64 = unsafe { ctx.read_at(SYS_ENTER_FILENAME_OFFSET) }.unwrap_or(0);
    if filename_ptr == 0 {
        return Ok(());
    }

    let scratch = ENTER_PATH_SCRATCH.get_ptr_mut(0).ok_or(1i64)?;
    // SAFETY: per-CPU scratch owned for the duration of this invocation.
    let buf = unsafe { &mut *scratch };
    *buf = [0u8; FILE_OPEN_PATH_LEN];
    if unsafe { bpf_probe_read_user_str_bytes(filename_ptr as *const u8, buf) }.is_err() {
        return Ok(());
    }

    // v0.1: absolute-path matching only. Relative / AT_FDCWD paths are a
    // documented no-match — the sensitive patterns and in-kernel gate are
    // built around absolute paths.
    if buf[0] != b'/' {
        return Ok(());
    }
    if !matches_sensitive_prefix(buf) {
        return Ok(());
    }

    let key = bpf_get_current_pid_tgid();
    let _ = IN_FLIGHT_OPENS.insert(&key, buf, 0);
    Ok(())
}

/// sys_exit_openat / sys_exit_openat2: if this open's path was stashed at enter,
/// emit a failed-open attempt on a negative return, then clear the entry.
pub fn handle_exit(ctx: &TracePointContext) -> i32 {
    let _ = try_exit(ctx);
    0
}

#[inline(always)]
fn try_exit(ctx: &TracePointContext) -> Result<(), i64> {
    let key = bpf_get_current_pid_tgid();

    // Copy the stashed path out before any map mutation.
    // SAFETY: map read; `*p` copies the value, ending the borrow immediately.
    let path = match unsafe { IN_FLIGHT_OPENS.get(&key) } {
        Some(p) => *p,
        None => return Ok(()),
    };

    let ret: i64 = unsafe { ctx.read_at(SYS_EXIT_RET_OFFSET) }.unwrap_or(0);

    // Emit only on failure; a successful open is covered by kernel.file.open.
    if ret < 0 {
        let scratch = OPEN_ATTEMPT_SCRATCH.get_ptr_mut(0).ok_or(1i64)?;
        // SAFETY: per-CPU scratch owned for the duration of this invocation.
        let event = unsafe { &mut *scratch };
        *event = FileOpenEvent {
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            pid: (key >> 32) as u32,
            uid: bpf_get_current_uid_gid() as u32,
            // SAFETY: helper reads the current task's cgroup id; no program
            // pointer is dereferenced.
            cgroup_id: unsafe { bpf_get_current_cgroup_id() },
            ret: ret as i32,
            flags: 0,
            comm: aya_ebpf::helpers::bpf_get_current_comm().unwrap_or([0u8; 16]),
            path,
        };
        let _ = OPEN_ATTEMPT_EVENTS.output(event, 0);
    }

    let _ = IN_FLIGHT_OPENS.remove(&key);
    Ok(())
}

use aya_ebpf::helpers::{
    bpf_get_current_cgroup_id, bpf_get_current_pid_tgid, bpf_get_current_task,
    bpf_get_current_uid_gid, bpf_ktime_get_ns, bpf_probe_read_kernel,
    bpf_probe_read_kernel_str_bytes,
};
use aya_ebpf::programs::TracePointContext;
use aya_ebpf::EbpfContext;

use jalki_common::ProcessExecEvent;

use crate::{
    count_ring_buffer_drop, is_self_filtered, PROCESS_EXEC_EVENTS, PROCESS_EXEC_EVENTS_DROPS,
    TASK_OFFSETS,
};

/// sched_process_exec tracepoint payload offsets after the common trace header.
///
/// Linux tracepoint format:
///   __data_loc char[] filename; offset: 8; size: 4
const SCHED_EXEC_FILENAME_LOC_OFFSET: usize = 8;

/// Handle tracepoint/sched/sched_process_exec.
///
/// This tracepoint fires only after a successful exec. It provides filename as
/// tracepoint payload data, avoiding fragile reads from struct linux_binprm.
pub fn handle(ctx: &TracePointContext) -> i32 {
    match try_handle(ctx) {
        Ok(_) => 0,
        Err(_) => 0,
    }
}

#[inline(always)]
fn try_handle(ctx: &TracePointContext) -> Result<(), i64> {
    if is_self_filtered() {
        return Ok(());
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let host_tgid = (pid_tgid >> 32) as u32;
    let host_tid = pid_tgid as u32;
    let uid_gid = bpf_get_current_uid_gid();
    let uid = uid_gid as u32;
    let gid = (uid_gid >> 32) as u32;
    let comm = aya_ebpf::helpers::bpf_get_current_comm().unwrap_or([0u8; 16]);

    let mut event = ProcessExecEvent {
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        pid: host_tgid,
        ppid: read_ppid(),
        uid,
        gid,
        // SAFETY: helper reads the current task's cgroup id and does not
        // dereference pointers supplied by the program.
        cgroup_id: unsafe { bpf_get_current_cgroup_id() },
        ret: 0,
        tid: host_tid,
        comm,
        filename: [0u8; jalki_common::PROCESS_EXEC_FILENAME_LEN],
        // argv is intentionally not captured. Userspace may replace this with
        // a source-side argv digest later; raw argv must never leave the agent.
        argv_hash: [0u8; 32],
        leader_start_boottime_ns: read_leader_start_boottime_ns(),
    };

    let filename_loc: u32 = unsafe { ctx.read_at(SCHED_EXEC_FILENAME_LOC_OFFSET) }.unwrap_or(0);
    let filename_offset = (filename_loc & 0xffff) as usize;

    if filename_offset != 0 {
        let _ = unsafe {
            bpf_probe_read_kernel_str_bytes(
                ctx.as_ptr().add(filename_offset) as *const u8,
                &mut event.filename,
            )
        };
    }

    if PROCESS_EXEC_EVENTS.output(&event, 0).is_err() {
        count_ring_buffer_drop(&PROCESS_EXEC_EVENTS_DROPS);
    }

    Ok(())
}

/// Read the thread-group leader's boot-based process start identity.
#[inline(always)]
fn read_leader_start_boottime_ns() -> u64 {
    let group_leader_off = TASK_OFFSETS.get(2).copied().unwrap_or(0);
    let start_boottime_off = TASK_OFFSETS.get(3).copied().unwrap_or(0);
    if group_leader_off == 0 || start_boottime_off == 0 {
        return 0;
    }
    // SAFETY: the helper supplies the current task pointer; subsequent reads
    // use BTF-resolved offsets and bpf_probe_read_kernel.
    let task = unsafe { bpf_get_current_task() };
    if task == 0 {
        return 0;
    }
    let leader: u64 = match unsafe {
        bpf_probe_read_kernel((task as *const u8).add(group_leader_off as usize) as *const u64)
    } {
        Ok(value) if value != 0 => value,
        _ => return 0,
    };
    unsafe {
        bpf_probe_read_kernel(
            (leader as *const u8).add(start_boottime_off as usize) as *const u64,
        )
    }
    .unwrap_or(0)
}

/// Best-effort parent pid via `current->real_parent->tgid`.
///
/// Offsets come from the BTF-resolved `TASK_OFFSETS` map (index 0 = real_parent,
/// 1 = tgid). `bpf_probe_read_kernel` tolerates a runtime offset (unlike
/// `bpf_d_path`), so this is portable across kernels. If BTF resolution was
/// unavailable the offsets are 0 and we return 0 — ppid is omitted rather than
/// read from a guessed offset (present-but-zero).
#[inline(always)]
fn read_ppid() -> u32 {
    let real_parent_off = TASK_OFFSETS.get(0).copied().unwrap_or(0);
    let tgid_off = TASK_OFFSETS.get(1).copied().unwrap_or(0);
    if real_parent_off == 0 || tgid_off == 0 {
        return 0;
    }
    // SAFETY: helper returns the current task pointer; no program-supplied
    // pointer is dereferenced by the helper itself.
    let task = unsafe { bpf_get_current_task() };
    if task == 0 {
        return 0;
    }
    let parent: u64 = match unsafe {
        bpf_probe_read_kernel((task as *const u8).add(real_parent_off as usize) as *const u64)
    } {
        Ok(p) if p != 0 => p,
        _ => return 0,
    };
    unsafe { bpf_probe_read_kernel((parent as *const u8).add(tgid_off as usize) as *const u32) }
        .unwrap_or(0)
}

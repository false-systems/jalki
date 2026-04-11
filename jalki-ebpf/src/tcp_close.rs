use aya_ebpf::helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_kernel};
use aya_ebpf::programs::FExitContext;

use jalki_common::TcpCloseEvent;

use crate::{is_self_filtered, TCP_CLOSE_EVENTS};

/// Handle fexit/tcp_close.
///
/// tcp_close(struct sock *sk, long timeout) -> void
///
/// At fexit we read bytes sent/received from sock fields.
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

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;

    // arg0: struct sock *sk
    let sk: u64 = unsafe { ctx.arg(0) };

    // Read 4-tuple from __sk_common.
    // offset 0: skc_daddr, offset 4: skc_rcv_saddr
    //
    // Known issue: skc_num (src_port, offset 14) is cleared by the kernel
    // before tcp_close returns, so fexit always reads 0. This is correct
    // kernel behavior. Use tcp_connect event's src_port to correlate.
    let dst_addr: u32 =
        unsafe { bpf_probe_read_kernel((sk as *const u8).add(0) as *const u32) }.map_err(|e| e as i64)?;
    let src_addr: u32 =
        unsafe { bpf_probe_read_kernel((sk as *const u8).add(4) as *const u32) }.map_err(|e| e as i64)?;
    let dst_port: u16 =
        unsafe { bpf_probe_read_kernel((sk as *const u8).add(12) as *const u16) }.map_err(|e| e as i64)?;
    let src_port: u16 =
        unsafe { bpf_probe_read_kernel((sk as *const u8).add(14) as *const u16) }.map_err(|e| e as i64)?;

    // v0.1: bytes_sent/received require reading tcp_sock fields whose offsets
    // vary across kernel versions. Proper implementation needs BTF-based CO-RE
    // field access (aya doesn't support this for struct fields yet) or a
    // runtime offset lookup via pahole/BTF. Emitting 0 is honest — don't
    // pretend to have data we can't reliably read.
    let bytes_sent: u64 = 0;
    let bytes_received: u64 = 0;

    // v0.1: duration requires stashing the connection start timestamp in a
    // BPF hashmap keyed by socket pointer at fentry/tcp_connect, then reading
    // it here at fexit/tcp_close. Not implemented yet.
    let duration_ns: u64 = 0;

    let netns: u32 = 0;

    let comm = aya_ebpf::helpers::bpf_get_current_comm().unwrap_or([0u8; 16]);

    let event = TcpCloseEvent {
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        pid,
        tid,
        src_addr,
        dst_addr,
        src_port,
        dst_port,
        bytes_sent,
        bytes_received,
        duration_ns,
        comm,
        netns,
        _pad: 0,
    };

    let _ = TCP_CLOSE_EVENTS.output(&event, 0);

    Ok(())
}

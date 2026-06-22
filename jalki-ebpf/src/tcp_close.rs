use aya_ebpf::helpers::{
    bpf_get_current_cgroup_id, bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_kernel,
};
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

    // Read address family + src/dst addresses (IPv4 or IPv6).
    let (addr_family, src_addr, dst_addr) = crate::read_addrs(sk);

    // Ports: skc_dport at offset 12, skc_num at offset 14.
    // Known issue: skc_num is cleared before tcp_close fexit fires.
    let dst_port: u16 = unsafe { bpf_probe_read_kernel((sk as *const u8).add(12) as *const u16) }
        .map_err(|e| e as i64)?;
    let src_port: u16 = unsafe { bpf_probe_read_kernel((sk as *const u8).add(14) as *const u16) }
        .map_err(|e| e as i64)?;

    // Read bytes_sent/received from tcp_sock.
    // struct sock *sk can be cast to struct tcp_sock * — tcp_sock embeds sock.
    // Offsets verified via BTF on kernel 6.19.9 (Fedora 43):
    //   tcp_sock.bytes_sent:    offset 1608
    //   tcp_sock.bytes_received: offset 1808
    // These offsets WILL differ on other kernel versions.
    // TODO: pass offsets via BPF map populated at load time from BTF.
    let bytes_sent: u64 =
        unsafe { bpf_probe_read_kernel((sk as *const u8).add(1608) as *const u64) }.unwrap_or(0);
    let bytes_received: u64 =
        unsafe { bpf_probe_read_kernel((sk as *const u8).add(1808) as *const u64) }.unwrap_or(0);

    // v0.1: duration requires stashing the connection start timestamp in a
    // BPF hashmap keyed by socket pointer at fentry/tcp_connect, then reading
    // it here at fexit/tcp_close. Not implemented yet.
    let duration_ns: u64 = 0;

    let netns: u32 = crate::read_netns(sk);

    let comm = aya_ebpf::helpers::bpf_get_current_comm().unwrap_or([0u8; 16]);

    let event = TcpCloseEvent {
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        pid,
        tid,
        src_addr,
        dst_addr,
        src_port,
        dst_port,
        addr_family,
        _pad1: 0,
        bytes_sent,
        bytes_received,
        duration_ns,
        // SAFETY: helper reads the current task's cgroup id and does not
        // dereference program-provided pointers.
        cgroup_id: unsafe { bpf_get_current_cgroup_id() },
        comm,
        netns,
        _pad2: 0,
    };

    let _ = TCP_CLOSE_EVENTS.output(&event, 0);

    Ok(())
}

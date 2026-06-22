use aya_ebpf::helpers::{
    bpf_get_current_cgroup_id, bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_kernel,
};
use aya_ebpf::programs::FExitContext;

use jalki_common::TcpConnectEvent;

use crate::{is_self_filtered, TCP_CONNECT_EVENTS};

/// Handle fexit/tcp_connect.
///
/// tcp_connect(struct sock *sk) -> int
///
/// fexit args: arg(0) = sk, arg(1) = return value.
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
    // arg1: return value (fexit provides ret after all params)
    let ret: i32 = unsafe { ctx.arg(1) };

    // Read address family + src/dst addresses (IPv4 or IPv6).
    let (addr_family, src_addr, dst_addr) = crate::read_addrs(sk);

    // Ports: skc_dport at offset 12, skc_num at offset 14.
    let dst_port: u16 = unsafe { bpf_probe_read_kernel((sk as *const u8).add(12) as *const u16) }
        .map_err(|e| e as i64)?;
    let src_port: u16 = unsafe { bpf_probe_read_kernel((sk as *const u8).add(14) as *const u16) }
        .map_err(|e| e as i64)?;

    let netns: u32 = crate::read_netns(sk);

    let comm = aya_ebpf::helpers::bpf_get_current_comm().unwrap_or([0u8; 16]);

    let event = TcpConnectEvent {
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        pid,
        tid,
        src_addr,
        dst_addr,
        src_port,
        dst_port,
        addr_family,
        _pad1: 0,
        ret,
        // SAFETY: helper reads the current task's cgroup id and does not
        // dereference program-provided pointers.
        cgroup_id: unsafe { bpf_get_current_cgroup_id() },
        comm,
        netns,
        _pad2: 0,
    };

    // Best-effort ring buffer output — drop silently if full.
    let _ = TCP_CONNECT_EVENTS.output(&event, 0);

    Ok(())
}

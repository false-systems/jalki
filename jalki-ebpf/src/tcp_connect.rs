use aya_ebpf::helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_kernel};
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

    // Read sock fields via bpf_probe_read_kernel.
    // struct sock starts with __sk_common:
    //   offset 0: skc_daddr (__be32) — destination address
    //   offset 4: skc_rcv_saddr (__be32) — source address
    //   offset 12: skc_dport (__be16) — destination port (network order)
    //   offset 14: skc_num (__u16) — source port (host order)
    //   offset 18: skc_state (u8) — TCP state
    // Verified via pahole on kernel 6.19.9.
    let dst_addr: u32 =
        unsafe { bpf_probe_read_kernel((sk as *const u8).add(0) as *const u32) }.map_err(|e| e as i64)?;
    let src_addr: u32 =
        unsafe { bpf_probe_read_kernel((sk as *const u8).add(4) as *const u32) }.map_err(|e| e as i64)?;
    let dst_port: u16 =
        unsafe { bpf_probe_read_kernel((sk as *const u8).add(12) as *const u16) }.map_err(|e| e as i64)?;
    let src_port: u16 =
        unsafe { bpf_probe_read_kernel((sk as *const u8).add(14) as *const u16) }.map_err(|e| e as i64)?;

    // Network namespace inode: sk.__sk_common.skc_net (pointer to net) → ns.inum
    // For v0.1, set to 0 — proper netns reading requires BTF-aware offset walking.
    let netns: u32 = 0;

    let comm = aya_ebpf::helpers::bpf_get_current_comm().unwrap_or([0u8; 16]);

    let event = TcpConnectEvent {
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        pid,
        tid,
        src_addr,
        dst_addr,
        src_port,
        dst_port,
        ret,
        comm,
        netns,
        _pad: 0,
    };

    // Best-effort ring buffer output — drop silently if full.
    let _ = TCP_CONNECT_EVENTS.output(&event, 0);

    Ok(())
}

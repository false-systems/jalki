use aya_ebpf::helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_kernel};
use aya_ebpf::programs::FEntryContext;

use jalki_common::TcpRetransmitEvent;

use crate::{is_self_filtered, TCP_RETRANSMIT_EVENTS};

/// Handle fentry/tcp_retransmit_skb.
///
/// tcp_retransmit_skb(struct sock *sk, struct sk_buff *skb, int segs)
///
/// At fentry we get the socket that is retransmitting. This is a reliability
/// signal — high retransmit rates indicate network-layer problems.
pub fn handle(ctx: &FEntryContext) -> i32 {
    match try_handle(ctx) {
        Ok(_) => 0,
        Err(_) => 0,
    }
}

#[inline(always)]
fn try_handle(ctx: &FEntryContext) -> Result<(), i64> {
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

    let dst_port: u16 =
        unsafe { bpf_probe_read_kernel((sk as *const u8).add(12) as *const u16) }.map_err(|e| e as i64)?;
    let src_port: u16 =
        unsafe { bpf_probe_read_kernel((sk as *const u8).add(14) as *const u16) }.map_err(|e| e as i64)?;

    // TCP state: __sk_common.skc_state (offset 18, u8).
    let state: u8 =
        unsafe { bpf_probe_read_kernel((sk as *const u8).add(18) as *const u8) }.unwrap_or(0);

    let netns: u32 = crate::read_netns(sk);

    let comm = aya_ebpf::helpers::bpf_get_current_comm().unwrap_or([0u8; 16]);

    let event = TcpRetransmitEvent {
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        pid,
        tid,
        src_addr,
        dst_addr,
        src_port,
        dst_port,
        addr_family,
        state,
        _pad1: 0,
        comm,
        netns,
        _pad2: 0,
    };

    let _ = TCP_RETRANSMIT_EVENTS.output(&event, 0);

    Ok(())
}

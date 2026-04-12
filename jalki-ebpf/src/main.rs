#![no_std]
#![no_main]

mod tcp_connect;
mod tcp_close;
mod tcp_retransmit;

use aya_ebpf::macros::{fentry, fexit, map};
use aya_ebpf::maps::{HashMap, RingBuf};
use aya_ebpf::programs::FEntryContext;
use aya_ebpf::programs::FExitContext;

// === BPF Maps ===

/// Self-filter: PIDs to exclude from all probe output.
/// Populated by userspace with jalki's own PID + children.
#[map]
static PID_FILTER: HashMap<u32, u8> = HashMap::with_max_entries(64, 0);

/// Ring buffer for TcpConnectEvent (fexit/tcp_connect).
#[map]
static TCP_CONNECT_EVENTS: RingBuf = RingBuf::with_byte_size(4 * 1024 * 1024, 0);

/// Ring buffer for TcpCloseEvent (fexit/tcp_close).
#[map]
static TCP_CLOSE_EVENTS: RingBuf = RingBuf::with_byte_size(4 * 1024 * 1024, 0);

/// Ring buffer for TcpRetransmitEvent (fentry/tcp_retransmit_skb).
#[map]
static TCP_RETRANSMIT_EVENTS: RingBuf = RingBuf::with_byte_size(4 * 1024 * 1024, 0);

// === Probe Entrypoints ===

#[fexit(function = "tcp_connect")]
pub fn jalki_tcp_connect(ctx: FExitContext) -> i32 {
    tcp_connect::handle(&ctx)
}

#[fexit(function = "tcp_close")]
pub fn jalki_tcp_close(ctx: FExitContext) -> i32 {
    tcp_close::handle(&ctx)
}

#[fentry(function = "tcp_retransmit_skb")]
pub fn jalki_tcp_retransmit(ctx: FEntryContext) -> i32 {
    tcp_retransmit::handle(&ctx)
}

// === Shared Helpers ===

/// Check if the current PID is in the self-filter map.
#[inline(always)]
pub fn is_self_filtered() -> bool {
    let pid = (aya_ebpf::helpers::bpf_get_current_pid_tgid() >> 32) as u32;
    unsafe { PID_FILTER.get(&pid).is_some() }
}

/// Read network namespace inode from a sock pointer.
///
/// Chain: sk.__sk_common.skc_net (offset 48) → struct net *
///        net->ns (offset 152) → struct ns_common
///        ns_common.inum (offset 24) → u32
///
/// Offsets verified via BTF on kernel 6.19.9 (Fedora 43).
#[inline(always)]
pub fn read_netns(sk: u64) -> u32 {
    // Read skc_net pointer.
    let net_ptr: u64 = match unsafe {
        aya_ebpf::helpers::bpf_probe_read_kernel(
            (sk as *const u8).add(48) as *const u64,
        )
    } {
        Ok(v) => v,
        Err(_) => return 0,
    };

    if net_ptr == 0 {
        return 0;
    }

    // Read ns.inum: net + 152 (ns offset) + 24 (inum offset) = net + 176.
    match unsafe {
        aya_ebpf::helpers::bpf_probe_read_kernel(
            (net_ptr as *const u8).add(176) as *const u32,
        )
    } {
        Ok(v) => v,
        Err(_) => 0,
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

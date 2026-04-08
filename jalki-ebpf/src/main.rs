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

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

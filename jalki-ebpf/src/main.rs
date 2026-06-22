#![no_std]
#![no_main]

mod process_exec;
mod tcp_close;
mod tcp_connect;
mod tcp_retransmit;

use aya_ebpf::macros::{fentry, fexit, map, tracepoint};
use aya_ebpf::maps::{HashMap, RingBuf};
use aya_ebpf::programs::FEntryContext;
use aya_ebpf::programs::FExitContext;
use aya_ebpf::programs::TracePointContext;

// === BPF Maps ===

/// Self-filter: PIDs to exclude from all probe output.
/// Populated by userspace with jalki's own PID + children.
#[map]
static PID_FILTER: HashMap<u32, u8> = HashMap::with_max_entries(64, 0);

/// Ring buffer for TcpConnectEvent (fexit/tcp_connect).
#[map]
static TCP_CONNECT_EVENTS: RingBuf = RingBuf::with_byte_size(4 * 1024 * 1024, 0);

/// Ring buffer for ProcessExecEvent (tracepoint/sched_process_exec).
#[map]
static PROCESS_EXEC_EVENTS: RingBuf = RingBuf::with_byte_size(4 * 1024 * 1024, 0);

/// Ring buffer for TcpCloseEvent (fexit/tcp_close).
#[map]
static TCP_CLOSE_EVENTS: RingBuf = RingBuf::with_byte_size(4 * 1024 * 1024, 0);

/// Ring buffer for TcpRetransmitEvent (fentry/tcp_retransmit_skb).
#[map]
static TCP_RETRANSMIT_EVENTS: RingBuf = RingBuf::with_byte_size(4 * 1024 * 1024, 0);

// === Probe Entrypoints ===

#[tracepoint(category = "sched", name = "sched_process_exec")]
pub fn jalki_process_exec(ctx: TracePointContext) -> i32 {
    process_exec::handle(&ctx)
}

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

/// Read address family and src/dst addresses from a sock pointer.
///
/// For AF_INET (2): reads skc_daddr (4 bytes at offset 0) and skc_rcv_saddr (offset 4).
///   Stored in first 4 bytes of the 16-byte output, rest zeroed.
/// For AF_INET6 (10): reads skc_v6_daddr (16 bytes at offset 56) and skc_v6_rcv_saddr (offset 72).
///
/// Returns (addr_family, src_addr, dst_addr).
#[inline(always)]
pub fn read_addrs(sk: u64) -> (u16, [u8; 16], [u8; 16]) {
    let family: u16 = unsafe {
        aya_ebpf::helpers::bpf_probe_read_kernel((sk as *const u8).add(16) as *const u16)
    }
    .unwrap_or(2); // default to AF_INET

    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];

    if family == 10 {
        // AF_INET6: read 16-byte addresses.
        // skc_v6_daddr at offset 56, skc_v6_rcv_saddr at offset 72.
        if let Ok(v) = unsafe {
            aya_ebpf::helpers::bpf_probe_read_kernel((sk as *const u8).add(56) as *const [u8; 16])
        } {
            dst = v;
        }
        if let Ok(v) = unsafe {
            aya_ebpf::helpers::bpf_probe_read_kernel((sk as *const u8).add(72) as *const [u8; 16])
        } {
            src = v;
        }
    } else {
        // AF_INET: read 4-byte addresses into first 4 bytes.
        // skc_daddr at offset 0, skc_rcv_saddr at offset 4.
        if let Ok(v) = unsafe {
            aya_ebpf::helpers::bpf_probe_read_kernel((sk as *const u8).add(0) as *const [u8; 4])
        } {
            dst[..4].copy_from_slice(&v);
        }
        if let Ok(v) = unsafe {
            aya_ebpf::helpers::bpf_probe_read_kernel((sk as *const u8).add(4) as *const [u8; 4])
        } {
            src[..4].copy_from_slice(&v);
        }
    }

    (family, src, dst)
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
        aya_ebpf::helpers::bpf_probe_read_kernel((sk as *const u8).add(48) as *const u64)
    } {
        Ok(v) => v,
        Err(_) => return 0,
    };

    if net_ptr == 0 {
        return 0;
    }

    // Read ns.inum: net + 152 (ns offset) + 24 (inum offset) = net + 176.
    match unsafe {
        aya_ebpf::helpers::bpf_probe_read_kernel((net_ptr as *const u8).add(176) as *const u32)
    } {
        Ok(v) => v,
        Err(_) => 0,
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

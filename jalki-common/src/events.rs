/// Address family constants.
pub const AF_INET: u16 = 2;
pub const AF_INET6: u16 = 10;

/// Event emitted by the tcp_connect fexit probe.
///
/// Captures a TCP connection attempt: 4-tuple, return code, process info.
/// Supports both IPv4 and IPv6 — check `addr_family` to distinguish.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct TcpConnectEvent {
    pub timestamp_ns: u64,
    pub pid: u32,
    pub tid: u32,
    pub src_addr: [u8; 16],
    pub dst_addr: [u8; 16],
    pub src_port: u16,
    pub dst_port: u16,
    pub addr_family: u16,
    pub _pad1: u16,
    pub ret: i32,
    pub comm: [u8; 16],
    pub netns: u32,
    pub _pad2: u32,
}

/// Event emitted by the tcp_close fexit probe.
///
/// Captures connection lifetime and byte counts.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct TcpCloseEvent {
    pub timestamp_ns: u64,
    pub pid: u32,
    pub tid: u32,
    pub src_addr: [u8; 16],
    pub dst_addr: [u8; 16],
    pub src_port: u16,
    pub dst_port: u16,
    pub addr_family: u16,
    pub _pad1: u16,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub duration_ns: u64,
    pub comm: [u8; 16],
    pub netns: u32,
    pub _pad2: u32,
}

/// Event emitted by the tcp_retransmit_skb fentry probe.
///
/// Indicates a TCP retransmission — a reliability signal.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct TcpRetransmitEvent {
    pub timestamp_ns: u64,
    pub pid: u32,
    pub tid: u32,
    pub src_addr: [u8; 16],
    pub dst_addr: [u8; 16],
    pub src_port: u16,
    pub dst_port: u16,
    pub addr_family: u16,
    pub state: u8,
    pub _pad1: u8,
    pub comm: [u8; 16],
    pub netns: u32,
    pub _pad2: u32,
}

/// Maximum number of PIDs in the self-filter map.
pub const MAX_FILTERED_PIDS: u32 = 64;

/// Ring buffer size for low-frequency probes (4 MB).
pub const RING_BUF_LOW_FREQ: u32 = 4 * 1024 * 1024;

/// Ring buffer size for high-frequency probes (64 MB).
pub const RING_BUF_HIGH_FREQ: u32 = 64 * 1024 * 1024;

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for TcpConnectEvent {}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for TcpCloseEvent {}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for TcpRetransmitEvent {}

impl TcpConnectEvent {
    /// Read the process name as a UTF-8 string (truncated at first null).
    pub fn comm_str(&self) -> &str {
        let len = self.comm.iter().position(|&b| b == 0).unwrap_or(16);
        core::str::from_utf8(&self.comm[..len]).unwrap_or("")
    }
}

impl TcpCloseEvent {
    pub fn comm_str(&self) -> &str {
        let len = self.comm.iter().position(|&b| b == 0).unwrap_or(16);
        core::str::from_utf8(&self.comm[..len]).unwrap_or("")
    }
}

impl TcpRetransmitEvent {
    pub fn comm_str(&self) -> &str {
        let len = self.comm.iter().position(|&b| b == 0).unwrap_or(16);
        core::str::from_utf8(&self.comm[..len]).unwrap_or("")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem;

    #[test]
    fn tcp_connect_event_size() {
        // Must be stable for BPF ring buffer reads.
        // v0.2: 88 bytes (was 56 — added 16-byte addrs + addr_family).
        assert_eq!(mem::size_of::<TcpConnectEvent>(), 88);
    }

    #[test]
    fn tcp_close_event_size() {
        // v0.2: 104 bytes (was 80 — added 16-byte addrs + addr_family).
        assert_eq!(mem::size_of::<TcpCloseEvent>(), 104);
    }

    #[test]
    fn tcp_retransmit_event_size() {
        // v0.2: 80 bytes (was 56 — added 16-byte addrs + addr_family).
        assert_eq!(mem::size_of::<TcpRetransmitEvent>(), 80);
    }

    #[test]
    fn comm_str_null_terminated() {
        let mut evt = unsafe { mem::zeroed::<TcpConnectEvent>() };
        evt.comm[0] = b'n';
        evt.comm[1] = b'g';
        evt.comm[2] = b'i';
        evt.comm[3] = b'n';
        evt.comm[4] = b'x';
        assert_eq!(evt.comm_str(), "nginx");
    }

    #[test]
    fn comm_str_full_buffer() {
        let mut evt = unsafe { mem::zeroed::<TcpConnectEvent>() };
        evt.comm = *b"0123456789abcdef";
        assert_eq!(evt.comm_str(), "0123456789abcdef");
    }
}

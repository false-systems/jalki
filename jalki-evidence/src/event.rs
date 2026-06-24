//! Typed, ergonomic kernel events.
//!
//! These sit between the raw `#[repr(C)]` ABI structs in `jalki-common` (which
//! mirror the bytes the eBPF programs write) and the FALSE Protocol records that
//! leave the agent. Decoding (raw bytes -> typed event) lives here; normalization
//! (typed event -> records) lives in [`crate::normalize`]. The two are separate so
//! each can be tested in isolation, and so this crate stays free of `aya` and
//! compiles on hosts where the kernel layer cannot.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use jalki_common::{
    FileOpenEvent as RawFileOpen, ProcessExecEvent as RawProcessExec, TcpCloseEvent as RawTcpClose,
    TcpConnectEvent as RawTcpConnect, TcpRetransmitEvent as RawTcpRetransmit, AF_INET6,
};
use thiserror::Error;

/// Failure to decode raw ring-buffer bytes into a typed event.
///
/// Mirrors `jalki::probe::ProbeError` so the daemon can map one to the other
/// with a trivial `From` impl.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum DecodeError {
    #[error("event too short: expected {expected} bytes, got {actual}")]
    TooShort { expected: usize, actual: usize },

    #[error("invalid event data: {0}")]
    Invalid(String),
}

/// A decoded kernel event, regardless of which probe produced it.
///
/// This is the unifying type the reader, batching, and correlation layers thread
/// through. Each variant can be decoded from raw bytes and normalized to a FALSE
/// Protocol `Occurrence`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KernelEvent {
    ProcessExec(ProcessExecEvent),
    FileOpen(FileOpenEvent),
    TcpConnect(TcpConnectEvent),
    TcpClose(TcpCloseEvent),
    TcpRetransmit(TcpRetransmitEvent),
}

impl KernelEvent {
    /// The kernel's monotonic observation time, in nanoseconds.
    pub fn observed_at_ns(&self) -> u64 {
        match self {
            KernelEvent::ProcessExec(e) => e.observed_at_ns,
            KernelEvent::FileOpen(e) => e.observed_at_ns,
            KernelEvent::TcpConnect(e) => e.observed_at_ns,
            KernelEvent::TcpClose(e) => e.observed_at_ns,
            KernelEvent::TcpRetransmit(e) => e.observed_at_ns,
        }
    }

    pub fn pid(&self) -> u32 {
        match self {
            KernelEvent::ProcessExec(e) => e.pid,
            KernelEvent::FileOpen(e) => e.pid,
            KernelEvent::TcpConnect(e) => e.pid,
            KernelEvent::TcpClose(e) => e.pid,
            KernelEvent::TcpRetransmit(e) => e.pid,
        }
    }

    pub fn cgroup_id(&self) -> u64 {
        match self {
            KernelEvent::ProcessExec(e) => e.cgroup_id,
            KernelEvent::FileOpen(e) => e.cgroup_id,
            KernelEvent::TcpConnect(e) => e.cgroup_id,
            KernelEvent::TcpClose(e) => e.cgroup_id,
            KernelEvent::TcpRetransmit(e) => e.cgroup_id,
        }
    }
}

/// A sensitive file open observed via security_file_open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileOpenEvent {
    pub observed_at_ns: u64,
    pub pid: u32,
    pub uid: u32,
    pub cgroup_id: u64,
    pub ret: i32,
    pub flags: u32,
    pub comm: String,
    pub path: String,
    pub path_truncated: bool,
}

impl FileOpenEvent {
    pub fn from_bytes(raw: &[u8]) -> Result<Self, DecodeError> {
        let raw = read_raw::<RawFileOpen>(raw)?;
        Ok(Self {
            observed_at_ns: raw.timestamp_ns,
            pid: raw.pid,
            uid: raw.uid,
            cgroup_id: raw.cgroup_id,
            ret: raw.ret,
            flags: raw.flags,
            comm: raw.comm_str().to_string(),
            path: raw.path_str().to_string(),
            path_truncated: raw.path_truncated(),
        })
    }

    /// Whether the open was allowed by the kernel/LSM hook.
    pub fn succeeded(&self) -> bool {
        self.ret == 0
    }
}

/// A successful process exec observed via sched_process_exec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessExecEvent {
    pub observed_at_ns: u64,
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub cgroup_id: u64,
    pub ret: i32,
    pub comm: String,
    pub filename: String,
    pub argv_hash: [u8; 32],
}

impl ProcessExecEvent {
    pub fn from_bytes(raw: &[u8]) -> Result<Self, DecodeError> {
        let raw = read_raw::<RawProcessExec>(raw)?;
        Ok(Self {
            observed_at_ns: raw.timestamp_ns,
            pid: raw.pid,
            ppid: raw.ppid,
            uid: raw.uid,
            gid: raw.gid,
            cgroup_id: raw.cgroup_id,
            ret: raw.ret,
            comm: raw.comm_str().to_string(),
            filename: raw.filename_str().to_string(),
            argv_hash: raw.argv_hash,
        })
    }

    /// Whether exec completed successfully (kernel returned 0).
    pub fn succeeded(&self) -> bool {
        self.ret == 0
    }
}

/// TCP connection state, as carried by the kernel `sk_state` byte.
///
/// `Unknown(n)` preserves the raw value for any state jälki does not name; its
/// label is `"UNKNOWN"`, matching the original probe behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    Established,
    SynSent,
    SynRecv,
    FinWait1,
    FinWait2,
    TimeWait,
    Close,
    CloseWait,
    LastAck,
    Listen,
    Closing,
    Unknown(u8),
}

impl TcpState {
    pub fn from_u8(value: u8) -> Self {
        match value {
            1 => TcpState::Established,
            2 => TcpState::SynSent,
            3 => TcpState::SynRecv,
            4 => TcpState::FinWait1,
            5 => TcpState::FinWait2,
            6 => TcpState::TimeWait,
            7 => TcpState::Close,
            8 => TcpState::CloseWait,
            9 => TcpState::LastAck,
            10 => TcpState::Listen,
            11 => TcpState::Closing,
            other => TcpState::Unknown(other),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            TcpState::Established => "ESTABLISHED",
            TcpState::SynSent => "SYN_SENT",
            TcpState::SynRecv => "SYN_RECV",
            TcpState::FinWait1 => "FIN_WAIT1",
            TcpState::FinWait2 => "FIN_WAIT2",
            TcpState::TimeWait => "TIME_WAIT",
            TcpState::Close => "CLOSE",
            TcpState::CloseWait => "CLOSE_WAIT",
            TcpState::LastAck => "LAST_ACK",
            TcpState::Listen => "LISTEN",
            TcpState::Closing => "CLOSING",
            TcpState::Unknown(_) => "UNKNOWN",
        }
    }
}

/// A TCP connection attempt (`tcp_connect` fexit).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpConnectEvent {
    pub observed_at_ns: u64,
    pub pid: u32,
    pub tid: u32,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub addr_family: u16,
    /// Kernel return value: 0 on success, negative errno on failure.
    pub ret: i32,
    pub cgroup_id: u64,
    pub comm: String,
    pub netns: u32,
}

impl TcpConnectEvent {
    pub fn from_bytes(raw: &[u8]) -> Result<Self, DecodeError> {
        let raw = read_raw::<RawTcpConnect>(raw)?;
        Ok(Self {
            observed_at_ns: raw.timestamp_ns,
            pid: raw.pid,
            tid: raw.tid,
            src_ip: ip_from(&raw.src_addr, raw.addr_family),
            dst_ip: ip_from(&raw.dst_addr, raw.addr_family),
            src_port: raw.src_port,
            dst_port: u16::from_be(raw.dst_port),
            addr_family: raw.addr_family,
            ret: raw.ret,
            cgroup_id: raw.cgroup_id,
            comm: raw.comm_str().to_string(),
            netns: raw.netns,
        })
    }

    /// Whether the connect succeeded (kernel returned 0).
    pub fn succeeded(&self) -> bool {
        self.ret == 0
    }
}

/// A closed TCP connection (`tcp_close` fexit).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpCloseEvent {
    pub observed_at_ns: u64,
    pub pid: u32,
    pub tid: u32,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub addr_family: u16,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub duration_ns: u64,
    pub cgroup_id: u64,
    pub comm: String,
    pub netns: u32,
}

impl TcpCloseEvent {
    pub fn from_bytes(raw: &[u8]) -> Result<Self, DecodeError> {
        let raw = read_raw::<RawTcpClose>(raw)?;
        Ok(Self {
            observed_at_ns: raw.timestamp_ns,
            pid: raw.pid,
            tid: raw.tid,
            src_ip: ip_from(&raw.src_addr, raw.addr_family),
            dst_ip: ip_from(&raw.dst_addr, raw.addr_family),
            src_port: raw.src_port,
            dst_port: u16::from_be(raw.dst_port),
            addr_family: raw.addr_family,
            bytes_sent: raw.bytes_sent,
            bytes_received: raw.bytes_received,
            duration_ns: raw.duration_ns,
            cgroup_id: raw.cgroup_id,
            comm: raw.comm_str().to_string(),
            netns: raw.netns,
        })
    }
}

/// A TCP retransmission (`tcp_retransmit_skb` fentry).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpRetransmitEvent {
    pub observed_at_ns: u64,
    pub pid: u32,
    pub tid: u32,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub addr_family: u16,
    pub state: TcpState,
    pub cgroup_id: u64,
    pub comm: String,
    pub netns: u32,
}

impl TcpRetransmitEvent {
    pub fn from_bytes(raw: &[u8]) -> Result<Self, DecodeError> {
        let raw = read_raw::<RawTcpRetransmit>(raw)?;
        Ok(Self {
            observed_at_ns: raw.timestamp_ns,
            pid: raw.pid,
            tid: raw.tid,
            src_ip: ip_from(&raw.src_addr, raw.addr_family),
            dst_ip: ip_from(&raw.dst_addr, raw.addr_family),
            src_port: raw.src_port,
            dst_port: u16::from_be(raw.dst_port),
            addr_family: raw.addr_family,
            state: TcpState::from_u8(raw.state),
            cgroup_id: raw.cgroup_id,
            comm: raw.comm_str().to_string(),
            netns: raw.netns,
        })
    }
}

/// Read a `#[repr(C)]` ABI struct out of a length-checked byte slice.
///
/// The bytes come from a `Vec<u8>` (alignment 1), so `read_unaligned` is required;
/// a plain pointer cast would be UB on stricter targets.
fn read_raw<T: Copy>(raw: &[u8]) -> Result<T, DecodeError> {
    let expected = core::mem::size_of::<T>();
    if raw.len() < expected {
        return Err(DecodeError::TooShort {
            expected,
            actual: raw.len(),
        });
    }
    // SAFETY: length checked above. T is one of the `jalki-common` event structs:
    // `#[repr(C)]`, `Copy`, and composed solely of integers and byte arrays, so
    // every bit pattern is a valid value. `read_unaligned` tolerates the slice's
    // alignment.
    Ok(unsafe { core::ptr::read_unaligned(raw.as_ptr() as *const T) })
}

/// Build an `IpAddr` from the kernel's `[u8; 16]` address + family.
///
/// AF_INET6 uses all 16 bytes; anything else (AF_INET or unset) takes the first 4
/// as an IPv4 address. The `Display` of the resulting `IpAddr` is byte-identical
/// to jälki's previous string formatting.
fn ip_from(raw: &[u8; 16], family: u16) -> IpAddr {
    if family == AF_INET6 {
        IpAddr::V6(Ipv6Addr::from(*raw))
    } else {
        IpAddr::V4(Ipv4Addr::from([raw[0], raw[1], raw[2], raw[3]]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jalki_common::{
        FileOpenEvent as RawFileOpen, ProcessExecEvent as RawExec, TcpCloseEvent as RawClose,
        TcpConnectEvent as RawConnect, TcpRetransmitEvent as RawRetransmit,
    };

    fn raw_bytes<T: Copy>(value: &T) -> Vec<u8> {
        let ptr = value as *const T as *const u8;
        unsafe { std::slice::from_raw_parts(ptr, core::mem::size_of::<T>()) }.to_vec()
    }

    fn v4(addr: [u8; 4]) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[..4].copy_from_slice(&addr);
        out
    }

    fn comm16(s: &str) -> [u8; 16] {
        let mut out = [0u8; 16];
        let b = s.as_bytes();
        let len = b.len().min(16);
        out[..len].copy_from_slice(&b[..len]);
        out
    }

    fn filename(s: &str) -> [u8; jalki_common::PROCESS_EXEC_FILENAME_LEN] {
        let mut out = [0u8; jalki_common::PROCESS_EXEC_FILENAME_LEN];
        let b = s.as_bytes();
        let len = b.len().min(out.len());
        out[..len].copy_from_slice(&b[..len]);
        out
    }

    fn path(s: &str) -> [u8; jalki_common::FILE_OPEN_PATH_LEN] {
        let mut out = [0u8; jalki_common::FILE_OPEN_PATH_LEN];
        let b = s.as_bytes();
        let len = b.len().min(out.len());
        out[..len].copy_from_slice(&b[..len]);
        out
    }

    #[test]
    fn decode_file_open_round_trip() {
        let raw = RawFileOpen {
            timestamp_ns: 123,
            pid: 456,
            uid: 1000,
            cgroup_id: 789,
            ret: -13,
            flags: 42,
            comm: comm16("cat"),
            path: path("/etc/shadow"),
        };

        let decoded = FileOpenEvent::from_bytes(&raw_bytes(&raw)).unwrap();

        assert_eq!(decoded.observed_at_ns, 123);
        assert_eq!(decoded.pid, 456);
        assert_eq!(decoded.uid, 1000);
        assert_eq!(decoded.cgroup_id, 789);
        assert_eq!(decoded.ret, -13);
        assert_eq!(decoded.flags, 42);
        assert_eq!(decoded.comm, "cat");
        assert_eq!(decoded.path, "/etc/shadow");
        assert!(!decoded.path_truncated);
    }

    #[test]
    fn decode_file_open_marks_full_path_buffer_truncated() {
        let raw = RawFileOpen {
            timestamp_ns: 123,
            pid: 456,
            uid: 1000,
            cgroup_id: 789,
            ret: 0,
            flags: 42,
            comm: comm16("cat"),
            path: [b'a'; jalki_common::FILE_OPEN_PATH_LEN],
        };

        let decoded = FileOpenEvent::from_bytes(&raw_bytes(&raw)).unwrap();

        assert!(decoded.path_truncated);
    }

    #[test]
    fn decode_file_open_too_short() {
        let err = FileOpenEvent::from_bytes(&[0u8; 8]).unwrap_err();

        assert!(matches!(
            err,
            DecodeError::TooShort {
                expected: 304,
                actual: 8
            }
        ));
    }

    #[test]
    fn decode_process_exec_preserves_hash_not_argv() {
        let raw = RawExec {
            timestamp_ns: 4,
            pid: 42,
            ppid: 7,
            uid: 1000,
            gid: 1000,
            cgroup_id: 99,
            ret: 0,
            _pad1: 0,
            comm: comm16("true"),
            filename: filename("/bin/true"),
            argv_hash: [0xabu8; 32],
        };
        let ev = ProcessExecEvent::from_bytes(&raw_bytes(&raw)).unwrap();
        assert_eq!(ev.pid, 42);
        assert_eq!(ev.ppid, 7);
        assert_eq!(ev.uid, 1000);
        assert_eq!(ev.gid, 1000);
        assert_eq!(ev.cgroup_id, 99);
        assert_eq!(ev.filename, "/bin/true");
        assert_eq!(ev.argv_hash, [0xabu8; 32]);
        assert!(ev.succeeded());
    }

    #[test]
    fn decode_connect_parses_4tuple_and_byteorder() {
        let raw = RawConnect {
            timestamp_ns: 1_000_000_000,
            pid: 1234,
            tid: 1234,
            src_addr: v4([10, 0, 0, 1]),
            dst_addr: v4([10, 0, 0, 2]),
            src_port: 54321,
            dst_port: 8080u16.to_be(),
            addr_family: 2,
            _pad1: 0,
            ret: 0,
            cgroup_id: 42,
            comm: comm16("nginx"),
            netns: 0,
            _pad2: 0,
        };
        let ev = TcpConnectEvent::from_bytes(&raw_bytes(&raw)).unwrap();

        assert_eq!(ev.src_ip.to_string(), "10.0.0.1");
        assert_eq!(ev.dst_ip.to_string(), "10.0.0.2");
        // src_port host-order, dst_port byte-swapped from network order.
        assert_eq!(ev.src_port, 54321);
        assert_eq!(ev.dst_port, 8080);
        assert_eq!(ev.cgroup_id, 42);
        assert_eq!(ev.comm, "nginx");
        assert!(ev.succeeded());
    }

    #[test]
    fn decode_connect_failure_keeps_errno() {
        let raw = RawConnect {
            timestamp_ns: 1,
            pid: 1,
            tid: 1,
            src_addr: v4([1, 1, 1, 1]),
            dst_addr: v4([2, 2, 2, 2]),
            src_port: 1,
            dst_port: 443u16.to_be(),
            addr_family: 2,
            _pad1: 0,
            ret: -111,
            cgroup_id: 0,
            comm: comm16("curl"),
            netns: 0,
            _pad2: 0,
        };
        let ev = TcpConnectEvent::from_bytes(&raw_bytes(&raw)).unwrap();
        assert!(!ev.succeeded());
        assert_eq!(ev.ret, -111);
    }

    #[test]
    fn decode_close_keeps_byte_counts_and_duration() {
        let raw = RawClose {
            timestamp_ns: 2_000_000_000,
            pid: 5678,
            tid: 5678,
            src_addr: v4([10, 0, 0, 1]),
            dst_addr: v4([10, 0, 0, 2]),
            src_port: 54321,
            dst_port: 8080u16.to_be(),
            addr_family: 2,
            _pad1: 0,
            bytes_sent: 1024,
            bytes_received: 2048,
            duration_ns: 5_000_000,
            cgroup_id: 43,
            comm: comm16("nginx"),
            netns: 0,
            _pad2: 0,
        };
        let ev = TcpCloseEvent::from_bytes(&raw_bytes(&raw)).unwrap();
        assert_eq!(ev.bytes_sent, 1024);
        assert_eq!(ev.bytes_received, 2048);
        assert_eq!(ev.duration_ns, 5_000_000);
        assert_eq!(ev.cgroup_id, 43);
    }

    #[test]
    fn decode_retransmit_maps_state() {
        let raw = RawRetransmit {
            timestamp_ns: 3,
            pid: 9999,
            tid: 9999,
            src_addr: v4([10, 0, 0, 1]),
            dst_addr: v4([10, 0, 0, 2]),
            src_port: 100,
            dst_port: 80u16.to_be(),
            addr_family: 2,
            state: 1,
            _pad1: 0,
            _pad2: 0,
            cgroup_id: 44,
            comm: comm16("app"),
            netns: 0,
            _pad3: 0,
        };
        let ev = TcpRetransmitEvent::from_bytes(&raw_bytes(&raw)).unwrap();
        assert_eq!(ev.state, TcpState::Established);
        assert_eq!(ev.state.as_str(), "ESTABLISHED");
        assert_eq!(ev.cgroup_id, 44);
    }

    #[test]
    fn decode_too_short_is_reported() {
        let err = TcpConnectEvent::from_bytes(&[0u8; 8]).unwrap_err();
        assert!(matches!(err, DecodeError::TooShort { .. }));
    }

    #[test]
    fn tcp_state_unknown_for_unnamed_values() {
        assert_eq!(TcpState::from_u8(0).as_str(), "UNKNOWN");
        assert_eq!(TcpState::from_u8(12).as_str(), "UNKNOWN");
        assert_eq!(TcpState::from_u8(255).as_str(), "UNKNOWN");
        assert_eq!(TcpState::from_u8(2), TcpState::SynSent);
    }

    #[test]
    fn ipv6_family_uses_all_sixteen_bytes() {
        let mut addr = [0u8; 16];
        addr[15] = 1; // ::1
        let raw = RawConnect {
            timestamp_ns: 1,
            pid: 1,
            tid: 1,
            src_addr: addr,
            dst_addr: addr,
            src_port: 1,
            dst_port: 1u16.to_be(),
            addr_family: AF_INET6,
            _pad1: 0,
            ret: 0,
            cgroup_id: 0,
            comm: comm16("app"),
            netns: 0,
            _pad2: 0,
        };
        let ev = TcpConnectEvent::from_bytes(&raw_bytes(&raw)).unwrap();
        assert_eq!(ev.src_ip.to_string(), "::1");
    }
}

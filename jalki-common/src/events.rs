/// Address family constants.
pub const AF_INET: u16 = 2;
pub const AF_INET6: u16 = 10;

/// Maximum executable path bytes captured for process.exec.
pub const PROCESS_EXEC_FILENAME_LEN: usize = 256;

/// Maximum path bytes captured for file.open.
pub const FILE_OPEN_PATH_LEN: usize = 256;

/// Maximum sensitive path prefixes accepted by the in-kernel file.open gate.
pub const MAX_SENSITIVE_PREFIXES: u32 = 16;

/// Maximum prefix bytes in the in-kernel sensitive path gate.
pub const SENSITIVE_PREFIX_LEN: usize = 128;

/// One configured sensitive path prefix for the in-kernel file.open gate.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct SensitivePrefix {
    pub len: u32,
    pub _pad1: u32,
    pub bytes: [u8; SENSITIVE_PREFIX_LEN],
}

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
    pub cgroup_id: u64,
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
    pub cgroup_id: u64,
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
    pub _pad2: u32,
    pub cgroup_id: u64,
    pub comm: [u8; 16],
    pub netns: u32,
    pub _pad3: u32,
}

/// Event emitted by the sched_process_exec tracepoint probe.
///
/// Captures exec identity and result. argv is never carried raw; the fixed
/// hash slot is reserved for a source-side SHA-256 digest.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct ProcessExecEvent {
    pub timestamp_ns: u64,
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub cgroup_id: u64,
    pub ret: i32,
    pub _pad1: u32,
    pub comm: [u8; 16],
    pub filename: [u8; PROCESS_EXEC_FILENAME_LEN],
    pub argv_hash: [u8; 32],
}

/// Event emitted by the security_file_open fexit probe.
///
/// Captures sensitive-path opens only. `ret` is the LSM hook return value:
/// 0 means allowed, negative errno means denied.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct FileOpenEvent {
    pub timestamp_ns: u64,
    pub pid: u32,
    pub uid: u32,
    pub cgroup_id: u64,
    pub ret: i32,
    pub flags: u32,
    pub comm: [u8; 16],
    pub path: [u8; FILE_OPEN_PATH_LEN],
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

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for ProcessExecEvent {}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for FileOpenEvent {}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for SensitivePrefix {}

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

impl ProcessExecEvent {
    pub fn comm_str(&self) -> &str {
        nul_terminated_str(&self.comm)
    }

    pub fn filename_str(&self) -> &str {
        nul_terminated_str(&self.filename)
    }
}

impl FileOpenEvent {
    pub fn comm_str(&self) -> &str {
        nul_terminated_str(&self.comm)
    }

    pub fn path_str(&self) -> &str {
        nul_terminated_str(&self.path)
    }

    pub fn path_truncated(&self) -> bool {
        !self.path.iter().any(|&b| b == 0)
    }
}

impl SensitivePrefix {
    pub const fn empty() -> Self {
        Self {
            len: 0,
            _pad1: 0,
            bytes: [0u8; SENSITIVE_PREFIX_LEN],
        }
    }
}

fn nul_terminated_str(buf: &[u8]) -> &str {
    let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    core::str::from_utf8(&buf[..len]).unwrap_or("")
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem;

    #[test]
    fn tcp_connect_event_size() {
        // Must be stable for BPF ring buffer reads.
        // v0.3: 96 bytes (added cgroup_id for runtime binding).
        assert_eq!(mem::size_of::<TcpConnectEvent>(), 96);
    }

    #[test]
    fn tcp_close_event_size() {
        // v0.3: 112 bytes (added cgroup_id for runtime binding).
        assert_eq!(mem::size_of::<TcpCloseEvent>(), 112);
    }

    #[test]
    fn tcp_retransmit_event_size() {
        // v0.3: 96 bytes (added cgroup_id for runtime binding).
        assert_eq!(mem::size_of::<TcpRetransmitEvent>(), 96);
    }

    #[test]
    fn process_exec_event_size() {
        // Stable for BPF ring buffer reads.
        assert_eq!(mem::size_of::<ProcessExecEvent>(), 344);
    }

    #[test]
    fn file_open_event_size() {
        // Stable for BPF ring buffer reads.
        assert_eq!(mem::size_of::<FileOpenEvent>(), 304);
    }

    #[test]
    fn sensitive_prefix_size() {
        assert_eq!(mem::size_of::<SensitivePrefix>(), 136);
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

    #[test]
    fn process_exec_filename_str() {
        let mut evt = unsafe { mem::zeroed::<ProcessExecEvent>() };
        evt.filename[..9].copy_from_slice(b"/bin/true");
        assert_eq!(evt.filename_str(), "/bin/true");
    }

    #[test]
    fn file_open_path_str() {
        let mut evt = unsafe { mem::zeroed::<FileOpenEvent>() };
        evt.path[..11].copy_from_slice(b"/etc/shadow");
        assert_eq!(evt.path_str(), "/etc/shadow");
    }
}

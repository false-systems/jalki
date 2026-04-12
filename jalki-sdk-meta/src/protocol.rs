/// Wire message types.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MsgType {
    Request = 0x01,
    Response = 0x02,
    StreamStart = 0x03,
    StreamEvent = 0x04,
    StreamEnd = 0x05,
    Error = 0x06,
    Ping = 0x07,
    Pong = 0x08,
}

/// RPC methods.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Find = 0x01,
    Deploy = 0x02,
    Subscribe = 0x03,
    Unsubscribe = 0x04,
    Status = 0x05,
    Ask = 0x06,
}

/// Frame flags.
pub struct Flags;
impl Flags {
    /// Payload is zstd-compressed.
    pub const COMPRESSED: u8 = 0x01;
    /// Stream events include interpretation inline.
    pub const INTERPRETED: u8 = 0x02;
    /// Stream events are full FALSE Protocol JSON.
    pub const FULL_PROTOCOL: u8 = 0x04;
}

/// Frame layout:
/// [frame_len: u32 big-endian][msg_type: u8][flags: u8][payload: msgpack]
/// frame_len includes msg_type and flags bytes.
pub const FRAME_HEADER_LEN: usize = 6; // 4 (len) + 1 (type) + 1 (flags)
pub const FRAME_MAX_LEN: usize = 1024 * 1024; // 1MB

/// STREAM_EVENT wire positions (positional MessagePack array).
/// No field names on wire — SDK maps positions to struct fields.
pub const POS_ID: usize = 0; // str (ULID)
pub const POS_PROBE_IDX: usize = 1; // u8 — index into probe name table from STREAM_START
pub const POS_TS: usize = 2; // u64 nanoseconds
pub const POS_SEVERITY: usize = 3; // u8 (Severity enum)
pub const POS_OUTCOME: usize = 4; // u8 (Outcome enum)
pub const POS_NET_SRC: usize = 5; // str|nil "ip:port"
pub const POS_NET_DST: usize = 6; // str|nil "ip:port"
pub const POS_PROTO: usize = 7; // u8|nil (Proto enum)
pub const POS_PID: usize = 8; // u32|nil
pub const POS_CMD: usize = 9; // str|nil
pub const POS_LABELS: usize = 10; // map|nil
pub const POS_INTERP: usize = 11; // [str, str]|nil — [conclusion, action]

/// REQUEST payload: [request_id: u32, method: u8, params: msgpack_value]
/// RESPONSE payload: [request_id: u32, ok: bool, result_or_error: msgpack_value]
/// STREAM_START payload: [probe_names: [str]] — probe name table
/// STREAM_END payload: [] — empty
/// ERROR payload: [code: str, message: str]
/// PING/PONG payload: [] — empty

pub const KEEPALIVE_INTERVAL_SECS: u64 = 30;
pub const KEEPALIVE_TIMEOUT_SECS: u64 = 5;
pub const REQUEST_TIMEOUT_SECS: u64 = 30;
pub const RECONNECT_BASE_MS: u64 = 100;
pub const RECONNECT_MAX_MS: u64 = 5000;

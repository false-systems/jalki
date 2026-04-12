use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Compact SDK event — NOT a full FALSE Protocol Occurrence.
/// Designed for minimal token cost when consumed by AI agents.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    /// ULID as string — sortable, unique identifier
    pub id: String,
    /// Unix nanoseconds — NOT ISO string
    pub ts: u64,
    /// Short probe name e.g. "tcp_connect" NOT "jalki/tcp_connect"
    pub probe: String,
    pub severity: Severity,
    pub outcome: Outcome,
    /// Present only for network probes
    pub net: Option<NetData>,
    /// Present only when process info available
    #[serde(rename = "proc")]
    pub proc_data: Option<ProcData>,
    /// Probe-specific labels e.g. {"tcp_state": "ESTABLISHED"}
    pub labels: Option<HashMap<String, String>>,
    /// Present only when stream(interpreted=true) or ask()
    pub interp: Option<Interpretation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetData {
    /// Combined "ip:port" e.g. "10.0.0.1:54321"
    pub src: String,
    /// Combined "ip:port" e.g. "10.0.0.2:5432"
    pub dst: String,
    pub proto: Proto,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcData {
    pub pid: u32,
    pub cmd: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Interpretation {
    pub conclusion: String,
    pub action: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EventFilter {
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub pid: Option<u32>,
    pub command: Option<String>,
    pub last_seconds: Option<u32>,
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeMatch {
    pub function: String,
    pub attachment: Attachment,
    pub event_type: String,
    pub why: String,
    pub fields: Vec<FieldInfo>,
    pub combine_with: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldInfo {
    pub name: String,
    pub meaning: String,
    pub important: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeHandle {
    pub probe_id: String,
    pub function: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AskResult {
    pub interpretation: String,
    pub severity: Severity,
    pub action: String,
    pub events: Vec<Event>,
    pub probes_used: Vec<String>,
    /// True if result came from KB only (no daemon running)
    pub kb_only: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum Severity {
    Info = 0,
    Warning = 1,
    Error = 2,
    Critical = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum Outcome {
    Success = 0,
    Failure = 1,
    Unknown = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum Proto {
    Tcp = 0,
    Udp = 1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Attachment {
    Fentry,
    Fexit,
}

/// Ask options
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AskOptions {
    pub collect_seconds: Option<u64>,
    pub max_events: Option<u32>,
    pub filter: Option<EventFilter>,
}

/// Deploy options
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DeployOptions {
    pub sample_rate: Option<f64>,
    pub filter: Option<EventFilter>,
}

/// Stream options
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StreamOptions {
    pub filter: Option<EventFilter>,
    pub interpreted: Option<bool>,
}

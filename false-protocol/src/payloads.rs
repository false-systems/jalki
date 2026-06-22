use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkEventData {
    pub protocol: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub direction: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns_query: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_status_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_sent: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_received: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rtt_baseline_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rtt_current_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retransmit_count: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelEventData {
    pub event_type: String,
    pub pid: u32,
    pub command: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oom_victim_pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oom_victim_comm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_requested: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signal: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub syscall_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerEventData {
    pub container_id: String,
    pub container_name: String,
    pub image: String,
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub restart_count: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_usage: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_usage: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct K8sEventData {
    pub resource_type: String,
    pub resource_name: String,
    pub namespace: String,
    pub reason: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replicas: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ready_replicas: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessEventData {
    pub pid: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ppid: Option<u32>,
    pub command: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub args: Option<String>,
    pub uid: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchedulingEventData {
    pub pod_uid: String,
    pub attempts: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nodes_failed: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nodes_total: Option<i32>,
    #[serde(skip_serializing_if = "HashMap::is_empty", default)]
    pub failure_reasons: HashMap<String, i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeEventData {
    pub node_name: String,
    pub condition: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_capacity: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_capacity: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_allocated: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_allocated: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceEventData {
    pub resource_id: String,
    pub resource_type: String,
    pub provider: String,
    pub region: String,
    pub account: String,
    pub status: String,
    #[serde(skip_serializing_if = "HashMap::is_empty", default)]
    pub tags: HashMap<String, String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub changes: Vec<ResourceChange>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceChange {
    pub field: String,
    pub old_value: String,
    pub new_value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtelEventData {
    pub service_name: String,
    pub operation_name: String,
    pub span_kind: String,
    pub status_code: String,
    pub duration_ms: f64,
    #[serde(skip_serializing_if = "HashMap::is_empty", default)]
    pub attributes: HashMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_event_data_serde_roundtrip() {
        let data = KernelEventData {
            event_type: "oom_kill".into(),
            pid: 1234,
            command: "java".into(),
            oom_victim_pid: Some(5678),
            oom_victim_comm: Some("java".into()),
            memory_requested: Some(1_073_741_824),
            signal: None,
            syscall_name: None,
        };
        let json = serde_json::to_string(&data).unwrap();
        let back: KernelEventData = serde_json::from_str(&json).unwrap();
        assert_eq!(back.event_type, "oom_kill");
        assert_eq!(back.pid, 1234);
        assert_eq!(back.oom_victim_pid, Some(5678));
        assert!(!json.contains("\"signal\""));
    }

    #[test]
    fn network_event_data_serde_roundtrip() {
        let data = NetworkEventData {
            protocol: "tcp".into(),
            src_ip: "10.0.0.1".into(),
            dst_ip: "10.0.0.2".into(),
            src_port: 8080,
            dst_port: 443,
            direction: "egress".into(),
            dns_query: None,
            http_method: Some("GET".into()),
            http_path: Some("/api/health".into()),
            http_status_code: Some(200),
            latency_ms: Some(42.5),
            bytes_sent: Some(512),
            bytes_received: Some(1024),
            rtt_baseline_ms: None,
            rtt_current_ms: None,
            retransmit_count: None,
        };
        let json = serde_json::to_string(&data).unwrap();
        let back: NetworkEventData = serde_json::from_str(&json).unwrap();
        assert_eq!(back.protocol, "tcp");
        assert_eq!(back.src_port, 8080);
        assert_eq!(back.http_status_code, Some(200));
    }
}

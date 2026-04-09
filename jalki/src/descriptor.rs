use serde::{Deserialize, Serialize};

use crate::probe::Attachment;

/// Declarative probe definition — the wire format for SDK-driven probe deployment.
///
/// An agent or SDK generates this descriptor. The daemon matches it against
/// pre-compiled eBPF programs and activates the right one. In v0.3, the daemon
/// will generate BPF bytecode directly from this descriptor + BTF.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeDescriptor {
    /// Kernel function to hook.
    pub function: String,

    /// fentry or fexit.
    pub attachment: String,

    /// Which fields to extract from the event.
    pub fields: Vec<String>,

    /// Kernel-side filter — events not matching are dropped before ring buffer.
    #[serde(default)]
    pub filter: Option<ProbeFilter>,

    /// Sampling rate: 1.0 = all events, 0.1 = 10%.
    #[serde(default = "default_sample_rate")]
    pub sample_rate: f64,

    /// FALSE Protocol occurrence type string.
    pub event_type: String,
}

fn default_sample_rate() -> f64 {
    1.0
}

/// Kernel-side event filter.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProbeFilter {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dst_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
}

impl ProbeDescriptor {
    /// Convert the attachment string to the Probe trait's Attachment enum.
    pub fn to_attachment(&self) -> Attachment {
        let function = Box::leak(self.function.clone().into_boxed_str());
        match self.attachment.as_str() {
            "fentry" => Attachment::Fentry { function },
            "fexit" => Attachment::Fexit { function },
            _ => Attachment::Fentry { function }, // default to fentry
        }
    }

    /// Map a function name to the pre-compiled eBPF program name.
    /// Returns None if no pre-compiled program exists for this function.
    pub fn program_name(&self) -> Option<&'static str> {
        match self.function.as_str() {
            "tcp_connect" => Some("jalki_tcp_connect"),
            "tcp_close" => Some("jalki_tcp_close"),
            "tcp_retransmit_skb" => Some("jalki_tcp_retransmit"),
            // Future pre-compiled probes go here.
            // When codegen lands (v0.3), this becomes a fallback.
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_descriptor() {
        let json = r#"{
            "function": "tcp_connect",
            "attachment": "fexit",
            "fields": ["src_ip", "dst_ip", "ret"],
            "filter": { "dst_port": 5432 },
            "sample_rate": 1.0,
            "event_type": "kernel.tcp.connect"
        }"#;
        let desc: ProbeDescriptor = serde_json::from_str(json).unwrap();
        assert_eq!(desc.function, "tcp_connect");
        assert_eq!(desc.filter.unwrap().dst_port, Some(5432));
    }

    #[test]
    fn program_name_mapping() {
        let desc = ProbeDescriptor {
            function: "tcp_connect".into(),
            attachment: "fexit".into(),
            fields: vec![],
            filter: None,
            sample_rate: 1.0,
            event_type: "kernel.tcp.connect".into(),
        };
        assert_eq!(desc.program_name(), Some("jalki_tcp_connect"));
    }

    #[test]
    fn unknown_function_returns_none() {
        let desc = ProbeDescriptor {
            function: "some_random_function".into(),
            attachment: "fentry".into(),
            fields: vec![],
            filter: None,
            sample_rate: 1.0,
            event_type: "kernel.custom".into(),
        };
        assert!(desc.program_name().is_none());
    }

    #[test]
    fn default_sample_rate() {
        let json = r#"{
            "function": "tcp_connect",
            "attachment": "fexit",
            "fields": [],
            "event_type": "kernel.tcp.connect"
        }"#;
        let desc: ProbeDescriptor = serde_json::from_str(json).unwrap();
        assert_eq!(desc.sample_rate, 1.0);
    }
}

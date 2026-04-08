use std::net::Ipv4Addr;

use false_protocol::{NetworkEventData, Occurrence, Outcome, ProcessEventData, Severity};
use jalki_common::TcpRetransmitEvent;

use crate::probe::{Attachment, Probe, ProbeError};

pub struct TcpRetransmit {
    attachments: Vec<Attachment>,
}

impl TcpRetransmit {
    pub fn new() -> Self {
        Self {
            attachments: vec![Attachment::Fentry {
                function: "tcp_retransmit_skb",
            }],
        }
    }
}

impl Probe for TcpRetransmit {
    fn attachments(&self) -> &[Attachment] {
        &self.attachments
    }

    fn name(&self) -> &str {
        "tcp_retransmit"
    }

    fn program_name(&self) -> &str {
        "jalki_tcp_retransmit"
    }

    fn ring_buffer_map(&self) -> &str {
        "TCP_RETRANSMIT_EVENTS"
    }

    fn to_occurrence(&self, raw: &[u8], cluster: &str) -> Result<Occurrence, ProbeError> {
        let expected = std::mem::size_of::<TcpRetransmitEvent>();
        if raw.len() < expected {
            return Err(ProbeError::TooShort {
                expected,
                actual: raw.len(),
            });
        }

        let event: &TcpRetransmitEvent =
            unsafe { &*(raw.as_ptr() as *const TcpRetransmitEvent) };

        let src_ip = Ipv4Addr::from(u32::from_be(event.src_addr));
        let dst_ip = Ipv4Addr::from(u32::from_be(event.dst_addr));
        let src_port = event.src_port;
        let dst_port = u16::from_be(event.dst_port);
        let comm = event.comm_str().to_string();
        let conn_id = format!("{src_ip}:{src_port}->{dst_ip}:{dst_port}");

        let mut occ = Occurrence::new("jalki/tcp_retransmit", "kernel.tcp.retransmit")
            .severity(Severity::Warning)
            .outcome(Outcome::Failure)
            .in_cluster(cluster)
            .with_entities(vec![
                format!("process:{}", event.pid),
                format!("connection:{conn_id}"),
            ]);

        occ.network_data = Some(NetworkEventData {
            protocol: "tcp".into(),
            src_ip: src_ip.to_string(),
            dst_ip: dst_ip.to_string(),
            src_port,
            dst_port,
            direction: "egress".into(),
            dns_query: None,
            http_method: None,
            http_path: None,
            http_status_code: None,
            latency_ms: None,
            bytes_sent: None,
            bytes_received: None,
            rtt_baseline_ms: None,
            rtt_current_ms: None,
            retransmit_count: None,
        });

        occ.process_data = Some(ProcessEventData {
            pid: event.pid,
            ppid: None,
            command: comm,
            args: None,
            uid: 0,
            exit_code: None,
        });

        occ.labels
            .insert("tcp_state".into(), tcp_state_name(event.state).into());

        occ.correlation_keys = vec![conn_id];

        Ok(occ)
    }
}

fn tcp_state_name(state: u8) -> &'static str {
    match state {
        1 => "ESTABLISHED",
        2 => "SYN_SENT",
        3 => "SYN_RECV",
        4 => "FIN_WAIT1",
        5 => "FIN_WAIT2",
        6 => "TIME_WAIT",
        7 => "CLOSE",
        8 => "CLOSE_WAIT",
        9 => "LAST_ACK",
        10 => "LISTEN",
        11 => "CLOSING",
        _ => "UNKNOWN",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use false_protocol::Severity;

    fn make_event(
        src: [u8; 4], dst: [u8; 4],
        src_port: u16, dst_port: u16,
        state: u8, comm: &str,
    ) -> Vec<u8> {
        let mut event = TcpRetransmitEvent {
            timestamp_ns: 3_000_000_000,
            pid: 9999,
            tid: 9999,
            src_addr: u32::from_ne_bytes(src),
            dst_addr: u32::from_ne_bytes(dst),
            src_port,
            dst_port: dst_port.to_be(),
            state,
            _pad1: [0; 3],
            comm: [0u8; 16],
            netns: 0,
            _pad2: 0,
        };
        let comm_bytes = comm.as_bytes();
        let len = comm_bytes.len().min(16);
        event.comm[..len].copy_from_slice(&comm_bytes[..len]);

        let ptr = &event as *const TcpRetransmitEvent as *const u8;
        unsafe { std::slice::from_raw_parts(ptr, std::mem::size_of::<TcpRetransmitEvent>()) }.to_vec()
    }

    #[test]
    fn retransmit_is_always_warning() {
        let probe = TcpRetransmit::new();
        let raw = make_event([10, 0, 0, 1], [10, 0, 0, 2], 54321, 8080, 1, "nginx");
        let occ = probe.to_occurrence(&raw, "prod").unwrap();

        assert_eq!(occ.severity, Severity::Warning);
        assert_eq!(occ.outcome, Some(Outcome::Failure));
        assert_eq!(occ.occurrence_type.as_str(), "kernel.tcp.retransmit");
    }

    #[test]
    fn tcp_state_label_established() {
        let probe = TcpRetransmit::new();
        let raw = make_event([10, 0, 0, 1], [10, 0, 0, 2], 100, 80, 1, "app");
        let occ = probe.to_occurrence(&raw, "test").unwrap();

        assert_eq!(occ.labels.get("tcp_state"), Some(&"ESTABLISHED".to_string()));
    }

    #[test]
    fn tcp_state_label_syn_sent() {
        let probe = TcpRetransmit::new();
        let raw = make_event([10, 0, 0, 1], [10, 0, 0, 2], 100, 80, 2, "app");
        let occ = probe.to_occurrence(&raw, "test").unwrap();

        assert_eq!(occ.labels.get("tcp_state"), Some(&"SYN_SENT".to_string()));
    }

    #[test]
    fn tcp_state_label_unknown() {
        let probe = TcpRetransmit::new();
        let raw = make_event([10, 0, 0, 1], [10, 0, 0, 2], 100, 80, 255, "app");
        let occ = probe.to_occurrence(&raw, "test").unwrap();

        assert_eq!(occ.labels.get("tcp_state"), Some(&"UNKNOWN".to_string()));
    }

    #[test]
    fn correlation_key_same_format_as_connect() {
        let probe = TcpRetransmit::new();
        let raw = make_event([172, 16, 0, 1], [172, 16, 0, 2], 12345, 443, 1, "curl");
        let occ = probe.to_occurrence(&raw, "test").unwrap();

        assert_eq!(occ.correlation_keys, vec!["172.16.0.1:12345->172.16.0.2:443"]);
    }

    #[test]
    fn too_short() {
        let probe = TcpRetransmit::new();
        let err = probe.to_occurrence(&[0u8; 8], "test").unwrap_err();
        assert!(matches!(err, ProbeError::TooShort { .. }));
    }

    #[test]
    fn tcp_state_name_all_known() {
        assert_eq!(tcp_state_name(1), "ESTABLISHED");
        assert_eq!(tcp_state_name(2), "SYN_SENT");
        assert_eq!(tcp_state_name(3), "SYN_RECV");
        assert_eq!(tcp_state_name(4), "FIN_WAIT1");
        assert_eq!(tcp_state_name(5), "FIN_WAIT2");
        assert_eq!(tcp_state_name(6), "TIME_WAIT");
        assert_eq!(tcp_state_name(7), "CLOSE");
        assert_eq!(tcp_state_name(8), "CLOSE_WAIT");
        assert_eq!(tcp_state_name(9), "LAST_ACK");
        assert_eq!(tcp_state_name(10), "LISTEN");
        assert_eq!(tcp_state_name(11), "CLOSING");
        assert_eq!(tcp_state_name(0), "UNKNOWN");
        assert_eq!(tcp_state_name(12), "UNKNOWN");
    }
}

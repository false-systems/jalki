use false_protocol::{
    NetworkEventData, Occurrence, OccurrenceError, Outcome, ProcessEventData, Severity,
};
use jalki_common::TcpConnectEvent;

use crate::addr::format_addr;
use crate::probe::{Attachment, Probe, ProbeError};

pub struct TcpConnect {
    attachments: Vec<Attachment>,
}

impl TcpConnect {
    pub fn new() -> Self {
        Self {
            attachments: vec![Attachment::Fexit {
                function: "tcp_connect",
            }],
        }
    }
}

impl Probe for TcpConnect {
    fn attachments(&self) -> &[Attachment] {
        &self.attachments
    }

    fn name(&self) -> &str {
        "tcp_connect"
    }

    fn program_name(&self) -> &str {
        "jalki_tcp_connect"
    }

    fn ring_buffer_map(&self) -> &str {
        "TCP_CONNECT_EVENTS"
    }

    fn to_occurrence(&self, raw: &[u8], cluster: &str) -> Result<Occurrence, ProbeError> {
        let expected = std::mem::size_of::<TcpConnectEvent>();
        if raw.len() < expected {
            return Err(ProbeError::TooShort {
                expected,
                actual: raw.len(),
            });
        }

        let event: &TcpConnectEvent = unsafe { &*(raw.as_ptr() as *const TcpConnectEvent) };

        let src_ip = format_addr(&event.src_addr, event.addr_family);
        let dst_ip = format_addr(&event.dst_addr, event.addr_family);
        let src_port = event.src_port;
        let dst_port = u16::from_be(event.dst_port);
        let comm = event.comm_str().to_string();
        let success = event.ret == 0;

        let severity = if success {
            Severity::Info
        } else {
            Severity::Warning
        };
        let outcome = if success {
            Outcome::Success
        } else {
            Outcome::Failure
        };

        let conn_id = format!("{src_ip}:{src_port}->{dst_ip}:{dst_port}");

        let mut occ = Occurrence::new("jalki/tcp_connect", "kernel.tcp.connect")
            .severity(severity)
            .outcome(outcome)
            .in_cluster(cluster)
            .with_entities(vec![
                format!("process:{}", event.pid),
                format!("connection:{conn_id}"),
            ]);

        occ.network_data = Some(NetworkEventData {
            protocol: "tcp".into(),
            src_ip: src_ip.clone(),
            dst_ip: dst_ip.clone(),
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
            command: comm.clone(),
            args: None,
            uid: 0,
            exit_code: None,
        });

        if !success {
            occ.error = Some(OccurrenceError {
                code: errno_name(event.ret),
                what_failed: format!(
                    "TCP connect from {comm} (pid {}) to {dst_ip}:{dst_port}",
                    event.pid
                ),
                why_it_matters: Some(
                    "Connection failure may indicate backend unreachability".into(),
                ),
                possible_causes: vec![
                    "Destination host unreachable".into(),
                    "Port not listening".into(),
                    "Firewall blocking connection".into(),
                ],
                ..Default::default()
            });
        }

        // Correlation key: 4-tuple for joining with tcp_close and tcp_retransmit.
        occ.correlation_keys = vec![conn_id];

        Ok(occ)
    }
}

fn errno_name(ret: i32) -> String {
    match -ret {
        111 => "ECONNREFUSED".into(),
        110 => "ETIMEDOUT".into(),
        113 => "EHOSTUNREACH".into(),
        101 => "ENETUNREACH".into(),
        _ => format!("E{}", -ret),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use false_protocol::Severity;

    /// Build a raw event as the kernel would produce it.
    fn make_event(src: [u8; 4], dst: [u8; 4], src_port: u16, dst_port: u16, ret: i32, comm: &str) -> Vec<u8> {
        let mut src_addr = [0u8; 16];
        src_addr[..4].copy_from_slice(&src);
        let mut dst_addr = [0u8; 16];
        dst_addr[..4].copy_from_slice(&dst);

        let mut event = TcpConnectEvent {
            timestamp_ns: 1_000_000_000,
            pid: 1234,
            tid: 1234,
            src_addr,
            dst_addr,
            src_port,
            dst_port: dst_port.to_be(),
            addr_family: 2, // AF_INET
            _pad1: 0,
            ret,
            comm: [0u8; 16],
            netns: 0,
            _pad2: 0,
        };
        let comm_bytes = comm.as_bytes();
        let len = comm_bytes.len().min(16);
        event.comm[..len].copy_from_slice(&comm_bytes[..len]);

        let ptr = &event as *const TcpConnectEvent as *const u8;
        unsafe { std::slice::from_raw_parts(ptr, std::mem::size_of::<TcpConnectEvent>()) }.to_vec()
    }

    #[test]
    fn successful_connect() {
        let probe = TcpConnect::new();
        let raw = make_event([10, 0, 0, 1], [10, 0, 0, 2], 54321, 8080, 0, "nginx");
        let occ = probe.to_occurrence(&raw, "test-cluster").unwrap();

        assert_eq!(occ.source, "jalki/tcp_connect");
        assert_eq!(occ.occurrence_type.as_str(), "kernel.tcp.connect");
        assert_eq!(occ.severity, Severity::Info);
        assert_eq!(occ.outcome, Some(Outcome::Success));
        assert_eq!(occ.cluster, "test-cluster");
        assert!(occ.error.is_none());

        let net = occ.network_data.unwrap();
        assert_eq!(net.src_ip, "10.0.0.1");
        assert_eq!(net.dst_ip, "10.0.0.2");
        assert_eq!(net.src_port, 54321);
        assert_eq!(net.dst_port, 8080);
        assert_eq!(net.protocol, "tcp");

        let proc = occ.process_data.unwrap();
        assert_eq!(proc.pid, 1234);
        assert_eq!(proc.command, "nginx");

        assert_eq!(occ.correlation_keys, vec!["10.0.0.1:54321->10.0.0.2:8080"]);
    }

    #[test]
    fn failed_connect_econnrefused() {
        let probe = TcpConnect::new();
        // ret = -111 is ECONNREFUSED
        let raw = make_event([192, 168, 1, 100], [192, 168, 1, 1], 40000, 443, -111, "curl");
        let occ = probe.to_occurrence(&raw, "prod").unwrap();

        assert_eq!(occ.severity, Severity::Warning);
        assert_eq!(occ.outcome, Some(Outcome::Failure));

        let err = occ.error.unwrap();
        assert_eq!(err.code, "ECONNREFUSED");
        assert!(err.what_failed.contains("curl"));
        assert!(err.what_failed.contains("192.168.1.1:443"));
    }

    #[test]
    fn failed_connect_etimedout() {
        let probe = TcpConnect::new();
        let raw = make_event([10, 0, 0, 1], [10, 0, 0, 2], 12345, 80, -110, "wget");
        let occ = probe.to_occurrence(&raw, "staging").unwrap();

        let err = occ.error.unwrap();
        assert_eq!(err.code, "ETIMEDOUT");
    }

    #[test]
    fn failed_connect_unknown_errno() {
        let probe = TcpConnect::new();
        let raw = make_event([10, 0, 0, 1], [10, 0, 0, 2], 12345, 80, -99, "app");
        let occ = probe.to_occurrence(&raw, "test").unwrap();

        let err = occ.error.unwrap();
        assert_eq!(err.code, "E99");
    }

    #[test]
    fn too_short_buffer() {
        let probe = TcpConnect::new();
        let raw = vec![0u8; 10];
        let err = probe.to_occurrence(&raw, "test").unwrap_err();
        match err {
            ProbeError::TooShort { expected, actual } => {
                assert_eq!(expected, std::mem::size_of::<TcpConnectEvent>());
                assert_eq!(actual, 10);
            }
            _ => panic!("expected TooShort error"),
        }
    }

    #[test]
    fn entity_ids_populated() {
        let probe = TcpConnect::new();
        let raw = make_event([10, 0, 0, 1], [10, 0, 0, 2], 54321, 8080, 0, "app");
        let occ = probe.to_occurrence(&raw, "test").unwrap();

        assert!(occ.entity_ids.iter().any(|e| e == "process:1234"));
        assert!(occ.entity_ids.iter().any(|e| e.starts_with("connection:")));
    }

    #[test]
    fn errno_name_mapping() {
        assert_eq!(errno_name(-111), "ECONNREFUSED");
        assert_eq!(errno_name(-110), "ETIMEDOUT");
        assert_eq!(errno_name(-113), "EHOSTUNREACH");
        assert_eq!(errno_name(-101), "ENETUNREACH");
        assert_eq!(errno_name(-42), "E42");
    }
}

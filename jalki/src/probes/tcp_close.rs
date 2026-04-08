use std::net::Ipv4Addr;

use false_protocol::{NetworkEventData, Occurrence, Outcome, ProcessEventData, Severity};
use jalki_common::TcpCloseEvent;

use crate::probe::{Attachment, Probe, ProbeError};

pub struct TcpClose {
    attachments: Vec<Attachment>,
}

impl TcpClose {
    pub fn new() -> Self {
        Self {
            attachments: vec![Attachment::Fexit {
                function: "tcp_close",
            }],
        }
    }
}

impl Probe for TcpClose {
    fn attachments(&self) -> &[Attachment] {
        &self.attachments
    }

    fn name(&self) -> &str {
        "tcp_close"
    }

    fn program_name(&self) -> &str {
        "jalki_tcp_close"
    }

    fn ring_buffer_map(&self) -> &str {
        "TCP_CLOSE_EVENTS"
    }

    fn to_occurrence(&self, raw: &[u8], cluster: &str) -> Result<Occurrence, ProbeError> {
        let expected = std::mem::size_of::<TcpCloseEvent>();
        if raw.len() < expected {
            return Err(ProbeError::TooShort {
                expected,
                actual: raw.len(),
            });
        }

        let event: &TcpCloseEvent = unsafe { &*(raw.as_ptr() as *const TcpCloseEvent) };

        let src_ip = Ipv4Addr::from(u32::from_be(event.src_addr));
        let dst_ip = Ipv4Addr::from(u32::from_be(event.dst_addr));
        let src_port = event.src_port;
        let dst_port = u16::from_be(event.dst_port);
        let comm = event.comm_str().to_string();
        let conn_id = format!("{src_ip}:{src_port}->{dst_ip}:{dst_port}");

        let mut occ = Occurrence::new("jalki/tcp_close", "kernel.tcp.close")
            .severity(Severity::Info)
            .outcome(Outcome::Success)
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
            bytes_sent: Some(event.bytes_sent),
            bytes_received: Some(event.bytes_received),
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

        if event.duration_ns > 0 {
            occ.duration_us = Some(event.duration_ns / 1000);
        }

        occ.correlation_keys = vec![conn_id];

        Ok(occ)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use false_protocol::Severity;

    fn make_event(
        src: [u8; 4], dst: [u8; 4],
        src_port: u16, dst_port: u16,
        bytes_sent: u64, bytes_received: u64,
        duration_ns: u64,
        comm: &str,
    ) -> Vec<u8> {
        let mut event = TcpCloseEvent {
            timestamp_ns: 2_000_000_000,
            pid: 5678,
            tid: 5678,
            src_addr: u32::from_ne_bytes(src),
            dst_addr: u32::from_ne_bytes(dst),
            src_port,
            dst_port: dst_port.to_be(),
            bytes_sent,
            bytes_received,
            duration_ns,
            comm: [0u8; 16],
            netns: 0,
            _pad: 0,
        };
        let comm_bytes = comm.as_bytes();
        let len = comm_bytes.len().min(16);
        event.comm[..len].copy_from_slice(&comm_bytes[..len]);

        let ptr = &event as *const TcpCloseEvent as *const u8;
        unsafe { std::slice::from_raw_parts(ptr, std::mem::size_of::<TcpCloseEvent>()) }.to_vec()
    }

    #[test]
    fn basic_close_event() {
        let probe = TcpClose::new();
        let raw = make_event([10, 0, 0, 1], [10, 0, 0, 2], 54321, 8080, 1024, 2048, 0, "nginx");
        let occ = probe.to_occurrence(&raw, "prod").unwrap();

        assert_eq!(occ.source, "jalki/tcp_close");
        assert_eq!(occ.occurrence_type.as_str(), "kernel.tcp.close");
        assert_eq!(occ.severity, Severity::Info);
        assert_eq!(occ.outcome, Some(Outcome::Success));
        assert!(occ.error.is_none());

        let net = occ.network_data.unwrap();
        assert_eq!(net.src_ip, "10.0.0.1");
        assert_eq!(net.dst_ip, "10.0.0.2");
        assert_eq!(net.bytes_sent, Some(1024));
        assert_eq!(net.bytes_received, Some(2048));
    }

    #[test]
    fn duration_converted_to_microseconds() {
        let probe = TcpClose::new();
        let raw = make_event([10, 0, 0, 1], [10, 0, 0, 2], 100, 80, 0, 0, 5_000_000, "app");
        let occ = probe.to_occurrence(&raw, "test").unwrap();

        assert_eq!(occ.duration_us, Some(5000));
    }

    #[test]
    fn zero_duration_omitted() {
        let probe = TcpClose::new();
        let raw = make_event([10, 0, 0, 1], [10, 0, 0, 2], 100, 80, 0, 0, 0, "app");
        let occ = probe.to_occurrence(&raw, "test").unwrap();

        assert!(occ.duration_us.is_none());
    }

    #[test]
    fn too_short() {
        let probe = TcpClose::new();
        let err = probe.to_occurrence(&[0u8; 4], "test").unwrap_err();
        assert!(matches!(err, ProbeError::TooShort { .. }));
    }

    #[test]
    fn correlation_key_matches_connect() {
        let probe = TcpClose::new();
        let raw = make_event([10, 0, 0, 1], [10, 0, 0, 2], 54321, 8080, 0, 0, 0, "app");
        let occ = probe.to_occurrence(&raw, "test").unwrap();

        // Must use same format as tcp_connect for 4-tuple join.
        assert_eq!(occ.correlation_keys, vec!["10.0.0.1:54321->10.0.0.2:8080"]);
    }
}

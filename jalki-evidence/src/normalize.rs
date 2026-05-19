//! Normalization: typed [`KernelEvent`] -> FALSE Protocol records.
//!
//! For now each event maps to a single `Occurrence`, reproducing exactly what the
//! per-probe `to_occurrence` methods produced before this layer existed. The
//! richer multi-record `NormalizedEvidence` shape (occurrence + entity_version +
//! relationship_claim) arrives in a later slice; keeping this faithful means the
//! existing daemon output and oracle expectations are unchanged.

use false_protocol::{NetworkEventData, Occurrence, OccurrenceError, Outcome, ProcessEventData, Severity};

use crate::event::{KernelEvent, TcpCloseEvent, TcpConnectEvent, TcpRetransmitEvent};

impl KernelEvent {
    /// Convert to a FALSE Protocol `Occurrence`.
    pub fn to_occurrence(&self, cluster: &str) -> Occurrence {
        match self {
            KernelEvent::TcpConnect(e) => e.to_occurrence(cluster),
            KernelEvent::TcpClose(e) => e.to_occurrence(cluster),
            KernelEvent::TcpRetransmit(e) => e.to_occurrence(cluster),
        }
    }
}

impl TcpConnectEvent {
    pub fn to_occurrence(&self, cluster: &str) -> Occurrence {
        let src_ip = self.src_ip.to_string();
        let dst_ip = self.dst_ip.to_string();
        let conn_id = format!("{src_ip}:{}->{dst_ip}:{}", self.src_port, self.dst_port);
        let success = self.succeeded();

        let severity = if success { Severity::Info } else { Severity::Warning };
        let outcome = if success { Outcome::Success } else { Outcome::Failure };

        let mut occ = Occurrence::new("jalki/tcp_connect", "kernel.tcp.connect")
            .severity(severity)
            .outcome(outcome)
            .in_cluster(cluster)
            .with_entities(vec![
                format!("process:{}", self.pid),
                format!("connection:{conn_id}"),
            ]);

        occ.network_data = Some(NetworkEventData {
            protocol: "tcp".into(),
            src_ip: src_ip.clone(),
            dst_ip: dst_ip.clone(),
            src_port: self.src_port,
            dst_port: self.dst_port,
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
            pid: self.pid,
            ppid: None,
            command: self.comm.clone(),
            args: None,
            uid: 0,
            exit_code: None,
        });

        if !success {
            occ.error = Some(OccurrenceError {
                code: errno_name(self.ret),
                what_failed: format!(
                    "TCP connect from {} (pid {}) to {dst_ip}:{}",
                    self.comm, self.pid, self.dst_port
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

        occ.correlation_keys = vec![conn_id];
        occ
    }
}

impl TcpCloseEvent {
    pub fn to_occurrence(&self, cluster: &str) -> Occurrence {
        let src_ip = self.src_ip.to_string();
        let dst_ip = self.dst_ip.to_string();
        let conn_id = format!("{src_ip}:{}->{dst_ip}:{}", self.src_port, self.dst_port);

        let mut occ = Occurrence::new("jalki/tcp_close", "kernel.tcp.close")
            .severity(Severity::Info)
            .outcome(Outcome::Success)
            .in_cluster(cluster)
            .with_entities(vec![
                format!("process:{}", self.pid),
                format!("connection:{conn_id}"),
            ]);

        occ.network_data = Some(NetworkEventData {
            protocol: "tcp".into(),
            src_ip: src_ip.clone(),
            dst_ip: dst_ip.clone(),
            src_port: self.src_port,
            dst_port: self.dst_port,
            direction: "egress".into(),
            dns_query: None,
            http_method: None,
            http_path: None,
            http_status_code: None,
            latency_ms: None,
            bytes_sent: Some(self.bytes_sent),
            bytes_received: Some(self.bytes_received),
            rtt_baseline_ms: None,
            rtt_current_ms: None,
            retransmit_count: None,
        });

        occ.process_data = Some(ProcessEventData {
            pid: self.pid,
            ppid: None,
            command: self.comm.clone(),
            args: None,
            uid: 0,
            exit_code: None,
        });

        if self.duration_ns > 0 {
            occ.duration_us = Some(self.duration_ns / 1000);
        }

        occ.correlation_keys = vec![conn_id];
        occ
    }
}

impl TcpRetransmitEvent {
    pub fn to_occurrence(&self, cluster: &str) -> Occurrence {
        let src_ip = self.src_ip.to_string();
        let dst_ip = self.dst_ip.to_string();
        let conn_id = format!("{src_ip}:{}->{dst_ip}:{}", self.src_port, self.dst_port);

        let mut occ = Occurrence::new("jalki/tcp_retransmit", "kernel.tcp.retransmit")
            .severity(Severity::Warning)
            .outcome(Outcome::Failure)
            .in_cluster(cluster)
            .with_entities(vec![
                format!("process:{}", self.pid),
                format!("connection:{conn_id}"),
            ]);

        occ.network_data = Some(NetworkEventData {
            protocol: "tcp".into(),
            src_ip: src_ip.clone(),
            dst_ip: dst_ip.clone(),
            src_port: self.src_port,
            dst_port: self.dst_port,
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
            pid: self.pid,
            ppid: None,
            command: self.comm.clone(),
            args: None,
            uid: 0,
            exit_code: None,
        });

        occ.labels
            .insert("tcp_state".into(), self.state.as_str().into());

        occ.correlation_keys = vec![conn_id];
        occ
    }
}

/// Map a kernel errno (negative return) to its symbolic name.
pub fn errno_name(ret: i32) -> String {
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
    use crate::event::TcpState;
    use std::net::{IpAddr, Ipv4Addr};

    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn connect(ret: i32) -> TcpConnectEvent {
        TcpConnectEvent {
            observed_at_ns: 1,
            pid: 1234,
            tid: 1234,
            src_ip: ip(10, 0, 0, 1),
            dst_ip: ip(10, 0, 0, 2),
            src_port: 54321,
            dst_port: 8080,
            addr_family: 2,
            ret,
            comm: "nginx".into(),
            netns: 0,
        }
    }

    #[test]
    fn connect_success_is_info() {
        let occ = connect(0).to_occurrence("test-cluster");
        assert_eq!(occ.source, "jalki/tcp_connect");
        assert_eq!(occ.occurrence_type.as_str(), "kernel.tcp.connect");
        assert_eq!(occ.severity, Severity::Info);
        assert_eq!(occ.outcome, Some(Outcome::Success));
        assert_eq!(occ.cluster, "test-cluster");
        assert!(occ.error.is_none());

        let net = occ.network_data.unwrap();
        assert_eq!(net.src_ip, "10.0.0.1");
        assert_eq!(net.dst_port, 8080);
        assert_eq!(occ.correlation_keys, vec!["10.0.0.1:54321->10.0.0.2:8080"]);
        assert!(occ.entity_ids.iter().any(|e| e == "process:1234"));
    }

    #[test]
    fn connect_failure_sets_errno_and_error_block() {
        let mut e = connect(-111);
        e.dst_ip = ip(192, 168, 1, 1);
        e.dst_port = 443;
        e.comm = "curl".into();
        let occ = e.to_occurrence("prod");

        assert_eq!(occ.severity, Severity::Warning);
        assert_eq!(occ.outcome, Some(Outcome::Failure));
        let err = occ.error.unwrap();
        assert_eq!(err.code, "ECONNREFUSED");
        assert!(err.what_failed.contains("curl"));
        assert!(err.what_failed.contains("192.168.1.1:443"));
    }

    #[test]
    fn close_carries_bytes_and_duration() {
        let e = TcpCloseEvent {
            observed_at_ns: 1,
            pid: 5678,
            tid: 5678,
            src_ip: ip(10, 0, 0, 1),
            dst_ip: ip(10, 0, 0, 2),
            src_port: 54321,
            dst_port: 8080,
            addr_family: 2,
            bytes_sent: 1024,
            bytes_received: 2048,
            duration_ns: 5_000_000,
            comm: "nginx".into(),
            netns: 0,
        };
        let occ = e.to_occurrence("prod");
        let net = occ.network_data.unwrap();
        assert_eq!(net.bytes_sent, Some(1024));
        assert_eq!(net.bytes_received, Some(2048));
        assert_eq!(occ.duration_us, Some(5000));
    }

    #[test]
    fn close_zero_duration_omitted() {
        let mut e = TcpCloseEvent {
            observed_at_ns: 1,
            pid: 1,
            tid: 1,
            src_ip: ip(10, 0, 0, 1),
            dst_ip: ip(10, 0, 0, 2),
            src_port: 1,
            dst_port: 2,
            addr_family: 2,
            bytes_sent: 0,
            bytes_received: 0,
            duration_ns: 0,
            comm: "app".into(),
            netns: 0,
        };
        e.duration_ns = 0;
        let occ = e.to_occurrence("test");
        assert!(occ.duration_us.is_none());
    }

    #[test]
    fn retransmit_is_warning_with_state_label() {
        let e = TcpRetransmitEvent {
            observed_at_ns: 1,
            pid: 9999,
            tid: 9999,
            src_ip: ip(172, 16, 0, 1),
            dst_ip: ip(172, 16, 0, 2),
            src_port: 12345,
            dst_port: 443,
            addr_family: 2,
            state: TcpState::Established,
            comm: "curl".into(),
            netns: 0,
        };
        let occ = e.to_occurrence("test");
        assert_eq!(occ.severity, Severity::Warning);
        assert_eq!(occ.outcome, Some(Outcome::Failure));
        assert_eq!(occ.occurrence_type.as_str(), "kernel.tcp.retransmit");
        assert_eq!(occ.labels.get("tcp_state"), Some(&"ESTABLISHED".to_string()));
        assert_eq!(occ.correlation_keys, vec!["172.16.0.1:12345->172.16.0.2:443"]);
    }

    #[test]
    fn kernel_event_enum_dispatches() {
        let occ = KernelEvent::TcpConnect(connect(0)).to_occurrence("c");
        assert_eq!(occ.occurrence_type.as_str(), "kernel.tcp.connect");
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

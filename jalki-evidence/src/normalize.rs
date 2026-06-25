//! Normalization: typed [`KernelEvent`] -> FALSE Protocol records.
//!
//! For now each event maps to a single `Occurrence`, reproducing exactly what the
//! per-probe `to_occurrence` methods produced before this layer existed. The
//! richer multi-record `NormalizedEvidence` shape (occurrence + entity_version +
//! relationship_claim) arrives in a later slice; keeping this faithful means the
//! existing daemon output and oracle expectations are unchanged.

use false_protocol::{
    NetworkEventData, Occurrence, OccurrenceError, Outcome, ProcessEventData, Severity,
};

use crate::event::{
    FileOpenEvent, KernelEvent, ProcessExecEvent, TcpCloseEvent, TcpConnectEvent,
    TcpRetransmitEvent,
};
use crate::evidence::{EvidenceRecord, NormalizedEvidence, ProbeMetadata};

impl KernelEvent {
    /// Convert to a FALSE Protocol `Occurrence`.
    pub fn to_occurrence(&self, cluster: &str) -> Occurrence {
        match self {
            KernelEvent::ProcessExec(e) => e.to_occurrence(cluster),
            KernelEvent::FileOpen(e) => e.to_occurrence(cluster),
            KernelEvent::TcpConnect(e) => e.to_occurrence(cluster),
            KernelEvent::TcpClose(e) => e.to_occurrence(cluster),
            KernelEvent::TcpRetransmit(e) => e.to_occurrence(cluster),
        }
    }

    /// Normalize into stamped evidence records.
    ///
    /// Today each event yields a single occurrence record; the `Vec` shape leaves
    /// room for `entity_version` / `relationship_claim` records once those land.
    pub fn normalize(&self, probe: ProbeMetadata, cluster: &str) -> NormalizedEvidence {
        NormalizedEvidence::single(EvidenceRecord {
            observed_at_ns: self.observed_at_ns(),
            pid: self.pid(),
            cgroup_id: self.cgroup_id(),
            probe,
            occurrence: self.to_occurrence(cluster),
            binding: None,
        })
    }
}

impl FileOpenEvent {
    pub fn to_occurrence(&self, cluster: &str) -> Occurrence {
        let success = self.succeeded();
        let outcome = if success {
            Outcome::Success
        } else {
            Outcome::Failure
        };
        let result = if success { "allowed" } else { "denied" };

        let mut occ = Occurrence::new("jalki/file_open", "kernel.file.open")
            .severity(Severity::Info)
            .outcome(outcome)
            .in_cluster(cluster)
            .with_entities(vec![
                format!("process:{}", self.pid),
                format!("file:{}", self.path),
            ]);

        occ.process_data = Some(ProcessEventData {
            pid: self.pid,
            ppid: None,
            command: self.comm.clone(),
            args: None,
            uid: self.uid,
            exit_code: None,
        });

        occ.labels.insert("result".into(), result.into());
        occ.labels.insert("flags".into(), self.flags.to_string());
        occ.labels
            .insert("cgroup_id".into(), self.cgroup_id.to_string());
        occ.labels.insert("resource_ref_kind".into(), "file".into());
        occ.labels
            .insert("resource_ref_id".into(), self.path.clone());
        if self.path_truncated {
            occ.labels.insert("path_truncated".into(), "true".into());
        }

        occ.correlation_keys = vec![format!("process:{}", self.pid)];
        occ
    }
}

impl ProcessExecEvent {
    pub fn to_occurrence(&self, cluster: &str) -> Occurrence {
        let success = self.succeeded();
        let outcome = if success {
            Outcome::Success
        } else {
            Outcome::Failure
        };

        let mut occ = Occurrence::new("jalki/process_exec", "kernel.process.exec")
            .severity(Severity::Info)
            .outcome(outcome)
            .in_cluster(cluster)
            .with_entities(vec![
                format!("process:{}", self.pid),
                format!("executable:{}", self.filename),
            ]);

        occ.process_data = Some(ProcessEventData {
            pid: self.pid,
            ppid: (self.ppid != 0).then_some(self.ppid),
            command: self.filename.clone(),
            args: None,
            uid: self.uid,
            exit_code: if success { None } else { Some(self.ret) },
        });

        occ.labels
            .insert("cgroup_id".into(), self.cgroup_id.to_string());
        occ.labels.insert("gid".into(), self.gid.to_string());
        occ.labels
            .insert("resource_ref_kind".into(), "executable".into());
        occ.labels
            .insert("resource_ref_id".into(), self.filename.clone());
        occ.labels.insert(
            "argv_hash".into(),
            format!("sha256:{}", hex32(&self.argv_hash)),
        );

        occ.correlation_keys = vec![format!("process:{}", self.pid)];
        occ
    }
}

impl TcpConnectEvent {
    pub fn to_occurrence(&self, cluster: &str) -> Occurrence {
        let src_ip = self.src_ip.to_string();
        let dst_ip = self.dst_ip.to_string();
        let conn_id = format!("{src_ip}:{}->{dst_ip}:{}", self.src_port, self.dst_port);
        let success = self.succeeded();

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
        occ.labels
            .insert("cgroup_id".into(), self.cgroup_id.to_string());
        occ.labels.insert("netns".into(), self.netns.to_string());

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
        occ.labels
            .insert("cgroup_id".into(), self.cgroup_id.to_string());
        occ.labels.insert("netns".into(), self.netns.to_string());

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
            .insert("cgroup_id".into(), self.cgroup_id.to_string());
        occ.labels.insert("netns".into(), self.netns.to_string());

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

fn hex32(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
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
            cgroup_id: 42,
            comm: "nginx".into(),
            netns: 0,
        }
    }

    fn exec_event(ret: i32) -> ProcessExecEvent {
        ProcessExecEvent {
            observed_at_ns: 4,
            pid: 42,
            ppid: 7,
            uid: 1000,
            gid: 1000,
            cgroup_id: 99,
            ret,
            comm: "true".into(),
            filename: "/bin/true".into(),
            argv_hash: [0xabu8; 32],
        }
    }

    fn file_open(ret: i32) -> FileOpenEvent {
        FileOpenEvent {
            observed_at_ns: 5,
            pid: 4242,
            uid: 1000,
            cgroup_id: 77,
            ret,
            flags: 0,
            comm: "cat".into(),
            path: "/var/run/secrets/kubernetes.io/serviceaccount/token".into(),
            path_truncated: false,
        }
    }

    #[test]
    fn exec_success_is_neutral_and_redacted() {
        let occ = exec_event(0).to_occurrence("prod");
        assert_eq!(occ.source, "jalki/process_exec");
        assert_eq!(occ.occurrence_type.as_str(), "kernel.process.exec");
        assert_eq!(occ.severity, Severity::Info);
        assert_eq!(occ.outcome, Some(Outcome::Success));
        assert!(occ.error.is_none());
        let proc = occ.process_data.unwrap();
        assert_eq!(proc.pid, 42);
        assert_eq!(proc.ppid, Some(7));
        assert_eq!(proc.command, "/bin/true");
        assert!(proc.args.is_none());
        assert_eq!(
            occ.labels.get("argv_hash"),
            Some(&format!("sha256:{}", "ab".repeat(32)))
        );
        assert_eq!(
            occ.labels.get("resource_ref_kind"),
            Some(&"executable".to_string())
        );
        assert_eq!(
            occ.labels.get("resource_ref_id"),
            Some(&"/bin/true".to_string())
        );
    }

    #[test]
    fn exec_omits_unresolved_parent_pid() {
        let mut event = exec_event(0);
        event.ppid = 0;

        let occ = event.to_occurrence("prod");

        assert_eq!(occ.process_data.unwrap().ppid, None);
    }

    #[test]
    fn exec_failure_sets_outcome_without_interpretation() {
        let occ = exec_event(-13).to_occurrence("prod");
        assert_eq!(occ.outcome, Some(Outcome::Failure));
        assert!(occ.error.is_none());
        assert_eq!(occ.process_data.unwrap().exit_code, Some(-13));
    }

    #[test]
    fn file_open_occurrence_is_neutral() {
        let occ = file_open(0).to_occurrence("prod");

        assert_eq!(occ.source, "jalki/file_open");
        assert_eq!(occ.occurrence_type.as_str(), "kernel.file.open");
        assert_eq!(occ.severity, Severity::Info);
        assert_eq!(occ.outcome, Some(Outcome::Success));
        assert!(occ.error.is_none());
        assert_eq!(occ.labels.get("result"), Some(&"allowed".to_string()));
        assert_eq!(occ.labels.get("cgroup_id"), Some(&"77".to_string()));
        assert_eq!(
            occ.labels.get("resource_ref_kind"),
            Some(&"file".to_string())
        );
        assert_eq!(
            occ.labels.get("resource_ref_id"),
            Some(&"/var/run/secrets/kubernetes.io/serviceaccount/token".to_string())
        );
        assert_eq!(occ.process_data.unwrap().command, "cat");
    }

    #[test]
    fn file_open_marks_truncated_paths() {
        let mut event = file_open(0);
        event.path_truncated = true;

        let occ = event.to_occurrence("prod");

        assert_eq!(
            occ.labels.get("path_truncated"),
            Some(&"true".to_string())
        );
    }

    #[test]
    fn file_open_denied_sets_result_denied() {
        let occ = file_open(-13).to_occurrence("prod");

        assert_eq!(occ.severity, Severity::Info);
        assert_eq!(occ.outcome, Some(Outcome::Failure));
        assert!(occ.error.is_none());
        assert_eq!(occ.labels.get("result"), Some(&"denied".to_string()));
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
        assert_eq!(occ.labels.get("cgroup_id"), Some(&"42".to_string()));

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
            cgroup_id: 43,
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
            cgroup_id: 43,
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
            cgroup_id: 44,
            comm: "curl".into(),
            netns: 0,
        };
        let occ = e.to_occurrence("test");
        assert_eq!(occ.severity, Severity::Warning);
        assert_eq!(occ.outcome, Some(Outcome::Failure));
        assert_eq!(occ.occurrence_type.as_str(), "kernel.tcp.retransmit");
        assert_eq!(
            occ.labels.get("tcp_state"),
            Some(&"ESTABLISHED".to_string())
        );
        assert_eq!(occ.labels.get("cgroup_id"), Some(&"44".to_string()));
        assert_eq!(
            occ.correlation_keys,
            vec!["172.16.0.1:12345->172.16.0.2:443"]
        );
    }

    #[test]
    fn kernel_event_enum_dispatches() {
        let occ = KernelEvent::TcpConnect(connect(0)).to_occurrence("c");
        assert_eq!(occ.occurrence_type.as_str(), "kernel.tcp.connect");

        let occ = KernelEvent::FileOpen(file_open(0)).to_occurrence("c");
        assert_eq!(occ.occurrence_type.as_str(), "kernel.file.open");
    }

    #[test]
    fn errno_name_mapping() {
        assert_eq!(errno_name(-111), "ECONNREFUSED");
        assert_eq!(errno_name(-110), "ETIMEDOUT");
        assert_eq!(errno_name(-113), "EHOSTUNREACH");
        assert_eq!(errno_name(-101), "ENETUNREACH");
        assert_eq!(errno_name(-42), "E42");
    }

    #[test]
    fn normalize_stamps_probe_metadata_and_observed_time() {
        use crate::evidence::HookKind;

        let event = TcpRetransmitEvent {
            observed_at_ns: 123_456_789,
            pid: 9999,
            tid: 9999,
            src_ip: ip(10, 0, 0, 1),
            dst_ip: ip(10, 0, 0, 2),
            src_port: 12345,
            dst_port: 443,
            addr_family: 2,
            state: TcpState::Established,
            cgroup_id: 44,
            comm: "curl".into(),
            netns: 0,
        };
        let probe = ProbeMetadata {
            probe_id: "tcp_retransmit".into(),
            probe_version: "1".into(),
            probe_family: "tcp".into(),
            hook_kind: HookKind::Fentry,
            kernel_function: "tcp_retransmit_skb".into(),
        };

        let norm = KernelEvent::TcpRetransmit(event).normalize(probe, "prod");

        assert_eq!(norm.records.len(), 1);
        let r = &norm.records[0];
        assert_eq!(r.observed_at_ns, 123_456_789);
        assert_eq!(r.probe.probe_id, "tcp_retransmit");
        assert_eq!(r.probe.kernel_function, "tcp_retransmit_skb");
        assert_eq!(r.pid, 9999);
        assert_eq!(r.cgroup_id, 44);
        assert_eq!(
            r.occurrence.occurrence_type.as_str(),
            "kernel.tcp.retransmit"
        );
        // jälki never sets Ahti's ingest-time.
        assert!(r.occurrence.received_at.is_none());
    }
}

use false_protocol::Occurrence;
use jalki_evidence::TcpRetransmitEvent;

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
        // Decode (raw -> typed) and normalize (typed -> Occurrence) both live in
        // jalki-evidence; the probe only owns kernel attachment metadata.
        Ok(TcpRetransmitEvent::from_bytes(raw)?.to_occurrence(cluster))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jalki_common::TcpRetransmitEvent as RawEvent;

    fn raw_retransmit(state: u8) -> Vec<u8> {
        let mut src_addr = [0u8; 16];
        src_addr[..4].copy_from_slice(&[172, 16, 0, 1]);
        let mut dst_addr = [0u8; 16];
        dst_addr[..4].copy_from_slice(&[172, 16, 0, 2]);
        let mut comm = [0u8; 16];
        comm[..4].copy_from_slice(b"curl");

        let event = RawEvent {
            timestamp_ns: 3_000_000_000,
            pid: 9999,
            tid: 9999,
            src_addr,
            dst_addr,
            src_port: 12345,
            dst_port: 443u16.to_be(),
            addr_family: 2,
            state,
            _pad1: 0,
            comm,
            netns: 0,
            _pad2: 0,
        };
        let ptr = &event as *const RawEvent as *const u8;
        unsafe { std::slice::from_raw_parts(ptr, std::mem::size_of::<RawEvent>()) }.to_vec()
    }

    #[test]
    fn delegates_to_evidence_normalizer() {
        let occ = TcpRetransmit::new()
            .to_occurrence(&raw_retransmit(1), "prod")
            .unwrap();
        assert_eq!(occ.source, "jalki/tcp_retransmit");
        assert_eq!(occ.occurrence_type.as_str(), "kernel.tcp.retransmit");
        assert_eq!(occ.labels.get("tcp_state"), Some(&"ESTABLISHED".to_string()));
        assert_eq!(occ.correlation_keys, vec!["172.16.0.1:12345->172.16.0.2:443"]);
    }

    #[test]
    fn too_short_maps_to_probe_error() {
        let err = TcpRetransmit::new()
            .to_occurrence(&[0u8; 8], "prod")
            .unwrap_err();
        assert!(matches!(err, ProbeError::TooShort { .. }));
    }
}

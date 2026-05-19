use false_protocol::Occurrence;
use jalki_evidence::TcpConnectEvent;

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
        // Decode (raw -> typed) and normalize (typed -> Occurrence) both live in
        // jalki-evidence; the probe only owns kernel attachment metadata.
        Ok(TcpConnectEvent::from_bytes(raw)?.to_occurrence(cluster))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jalki_common::TcpConnectEvent as RawEvent;

    fn raw_connect() -> Vec<u8> {
        let mut src_addr = [0u8; 16];
        src_addr[..4].copy_from_slice(&[10, 0, 0, 1]);
        let mut dst_addr = [0u8; 16];
        dst_addr[..4].copy_from_slice(&[10, 0, 0, 2]);
        let mut comm = [0u8; 16];
        comm[..5].copy_from_slice(b"nginx");

        let event = RawEvent {
            timestamp_ns: 1_000_000_000,
            pid: 1234,
            tid: 1234,
            src_addr,
            dst_addr,
            src_port: 54321,
            dst_port: 8080u16.to_be(),
            addr_family: 2,
            _pad1: 0,
            ret: 0,
            comm,
            netns: 0,
            _pad2: 0,
        };
        let ptr = &event as *const RawEvent as *const u8;
        unsafe { std::slice::from_raw_parts(ptr, std::mem::size_of::<RawEvent>()) }.to_vec()
    }

    #[test]
    fn delegates_to_evidence_normalizer() {
        let occ = TcpConnect::new()
            .to_occurrence(&raw_connect(), "prod")
            .unwrap();
        assert_eq!(occ.source, "jalki/tcp_connect");
        assert_eq!(occ.occurrence_type.as_str(), "kernel.tcp.connect");
        assert_eq!(occ.network_data.unwrap().dst_port, 8080);
    }

    #[test]
    fn too_short_maps_to_probe_error() {
        let err = TcpConnect::new().to_occurrence(&[0u8; 8], "prod").unwrap_err();
        assert!(matches!(err, ProbeError::TooShort { .. }));
    }
}

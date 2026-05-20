use jalki_evidence::{KernelEvent, TcpCloseEvent};

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

    fn decode_event(&self, raw: &[u8]) -> Result<KernelEvent, ProbeError> {
        Ok(KernelEvent::TcpClose(TcpCloseEvent::from_bytes(raw)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jalki_common::TcpCloseEvent as RawEvent;

    fn raw_close(duration_ns: u64) -> Vec<u8> {
        let mut src_addr = [0u8; 16];
        src_addr[..4].copy_from_slice(&[10, 0, 0, 1]);
        let mut dst_addr = [0u8; 16];
        dst_addr[..4].copy_from_slice(&[10, 0, 0, 2]);
        let mut comm = [0u8; 16];
        comm[..5].copy_from_slice(b"nginx");

        let event = RawEvent {
            timestamp_ns: 2_000_000_000,
            pid: 5678,
            tid: 5678,
            src_addr,
            dst_addr,
            src_port: 54321,
            dst_port: 8080u16.to_be(),
            addr_family: 2,
            _pad1: 0,
            bytes_sent: 1024,
            bytes_received: 2048,
            duration_ns,
            comm,
            netns: 0,
            _pad2: 0,
        };
        let ptr = &event as *const RawEvent as *const u8;
        unsafe { std::slice::from_raw_parts(ptr, std::mem::size_of::<RawEvent>()) }.to_vec()
    }

    #[test]
    fn delegates_to_evidence_normalizer() {
        let occ = TcpClose::new()
            .to_evidence(&raw_close(5_000_000), "prod")
            .unwrap();
        let occ = occ.records.into_iter().next().unwrap().occurrence;
        assert_eq!(occ.source, "jalki/tcp_close");
        assert_eq!(occ.occurrence_type.as_str(), "kernel.tcp.close");
        assert_eq!(occ.network_data.unwrap().bytes_sent, Some(1024));
        assert_eq!(occ.duration_us, Some(5000));
    }

    #[test]
    fn too_short_maps_to_probe_error() {
        let err = TcpClose::new().to_evidence(&[0u8; 4], "prod").unwrap_err();
        assert!(matches!(err, ProbeError::TooShort { .. }));
    }
}

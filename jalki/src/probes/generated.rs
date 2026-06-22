use std::net::Ipv4Addr;

use false_protocol::{NetworkEventData, Occurrence, ProcessEventData, Severity};
use jalki_codegen::btf::FieldType;
use jalki_codegen::program::{AttachType, FieldLayout, ProbeSpec};
use jalki_evidence::{EvidenceRecord, KernelEvent, NormalizedEvidence};

use crate::probe::{Attachment, Probe, ProbeError};

/// A dynamically generated probe that uses field layout metadata
/// to deserialize raw ring buffer events into FALSE Protocol Occurrences.
pub struct GeneratedProbeReader {
    spec: ProbeSpec,
    layout: Vec<FieldLayout>,
    event_size: usize,
    map_name: String,
    program_name: String,
    attachments: Vec<Attachment>,
}

impl GeneratedProbeReader {
    pub fn new(
        spec: ProbeSpec,
        layout: Vec<FieldLayout>,
        event_size: usize,
        map_name: String,
        program_name: String,
    ) -> Self {
        let attachments = vec![match spec.attachment {
            AttachType::Fentry => Attachment::Fentry {
                function: Box::leak(spec.function.clone().into_boxed_str()),
            },
            AttachType::Fexit => Attachment::Fexit {
                function: Box::leak(spec.function.clone().into_boxed_str()),
            },
        }];

        Self {
            spec,
            layout,
            event_size,
            map_name,
            program_name,
            attachments,
        }
    }

    fn read_u8(raw: &[u8], offset: usize) -> u8 {
        if offset < raw.len() {
            raw[offset]
        } else {
            0
        }
    }

    fn read_u16(raw: &[u8], offset: usize) -> u16 {
        if offset + 2 <= raw.len() {
            u16::from_le_bytes([raw[offset], raw[offset + 1]])
        } else {
            0
        }
    }

    fn read_u32(raw: &[u8], offset: usize) -> u32 {
        if offset + 4 <= raw.len() {
            u32::from_le_bytes([
                raw[offset],
                raw[offset + 1],
                raw[offset + 2],
                raw[offset + 3],
            ])
        } else {
            0
        }
    }

    fn read_i32(raw: &[u8], offset: usize) -> i32 {
        if offset + 4 <= raw.len() {
            i32::from_le_bytes([
                raw[offset],
                raw[offset + 1],
                raw[offset + 2],
                raw[offset + 3],
            ])
        } else {
            0
        }
    }

    fn read_u64(raw: &[u8], offset: usize) -> u64 {
        if offset + 8 <= raw.len() {
            u64::from_le_bytes([
                raw[offset],
                raw[offset + 1],
                raw[offset + 2],
                raw[offset + 3],
                raw[offset + 4],
                raw[offset + 5],
                raw[offset + 6],
                raw[offset + 7],
            ])
        } else {
            0
        }
    }

    fn read_comm(raw: &[u8], offset: usize) -> String {
        if offset + 16 <= raw.len() {
            let bytes = &raw[offset..offset + 16];
            let end = bytes.iter().position(|&b| b == 0).unwrap_or(16);
            String::from_utf8_lossy(&bytes[..end]).to_string()
        } else {
            String::new()
        }
    }
}

impl Probe for GeneratedProbeReader {
    fn attachments(&self) -> &[Attachment] {
        &self.attachments
    }

    fn name(&self) -> &str {
        &self.spec.function
    }

    fn program_name(&self) -> &str {
        &self.program_name
    }

    fn ring_buffer_map(&self) -> &str {
        &self.map_name
    }

    fn decode_event(&self, _raw: &[u8]) -> Result<KernelEvent, ProbeError> {
        Err(ProbeError::InvalidData(
            "generated probes produce normalized evidence directly".into(),
        ))
    }

    fn to_evidence(&self, raw: &[u8], cluster: &str) -> Result<NormalizedEvidence, ProbeError> {
        if raw.len() < self.event_size {
            return Err(ProbeError::TooShort {
                expected: self.event_size,
                actual: raw.len(),
            });
        }

        // Header is always: timestamp_ns(u64), pid(u32), tid(u32)
        let observed_at_ns = Self::read_u64(raw, 0);
        let pid = Self::read_u32(raw, 8);
        let source = format!("jalki/{}", self.spec.function);

        let mut occ = Occurrence::new(&source, &self.spec.event_type)
            .severity(Severity::Info)
            .in_cluster(cluster)
            .with_entities(vec![format!("process:{pid}")]);

        // Extract known field patterns into structured data.
        let mut src_ip: Option<String> = None;
        let mut dst_ip: Option<String> = None;
        let mut src_port: Option<u16> = None;
        let mut dst_port: Option<u16> = None;
        let mut comm: Option<String> = None;
        let mut ret: Option<i32> = None;

        for field in &self.layout {
            match field.name.as_str() {
                "pid" | "tid" | "timestamp_ns" => continue, // already in header
                "comm" => {
                    comm = Some(Self::read_comm(raw, field.offset));
                }
                "ret" => {
                    ret = Some(Self::read_i32(raw, field.offset));
                }
                name if name.contains("skc_rcv_saddr") || name.contains("src_addr") => {
                    let addr = Self::read_u32(raw, field.offset);
                    src_ip = Some(Ipv4Addr::from(u32::from_be(addr)).to_string());
                }
                name if name.contains("skc_daddr") || name.contains("dst_addr") => {
                    let addr = Self::read_u32(raw, field.offset);
                    dst_ip = Some(Ipv4Addr::from(u32::from_be(addr)).to_string());
                }
                name if name.contains("skc_num") || name.contains("src_port") => {
                    src_port = Some(Self::read_u16(raw, field.offset));
                }
                name if name.contains("skc_dport") || name.contains("dst_port") => {
                    dst_port = Some(u16::from_be(Self::read_u16(raw, field.offset)));
                }
                _ => {
                    // Store as a label for fields we don't have special handling for.
                    let val = match field.field_type {
                        FieldType::U8 => Self::read_u8(raw, field.offset).to_string(),
                        FieldType::U16 => Self::read_u16(raw, field.offset).to_string(),
                        FieldType::U32 => Self::read_u32(raw, field.offset).to_string(),
                        FieldType::U64 => Self::read_u64(raw, field.offset).to_string(),
                        FieldType::I32 => Self::read_i32(raw, field.offset).to_string(),
                        FieldType::I64 => (Self::read_u64(raw, field.offset) as i64).to_string(),
                    };
                    // Add as entity for now — labels would be better but Occurrence may not have a labels field.
                    occ.entity_ids.push(format!("{}:{}", field.name, val));
                }
            }
        }

        // Build network_data if we have any network fields.
        if src_ip.is_some() || dst_ip.is_some() {
            occ.network_data = Some(NetworkEventData {
                protocol: "tcp".into(),
                src_ip: src_ip.unwrap_or_default(),
                dst_ip: dst_ip.unwrap_or_default(),
                src_port: src_port.unwrap_or(0),
                dst_port: dst_port.unwrap_or(0),
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

            // Correlation key.
            let s_ip = occ
                .network_data
                .as_ref()
                .map(|n| n.src_ip.as_str())
                .unwrap_or("?");
            let d_ip = occ
                .network_data
                .as_ref()
                .map(|n| n.dst_ip.as_str())
                .unwrap_or("?");
            let s_port = src_port.unwrap_or(0);
            let d_port = dst_port.unwrap_or(0);
            occ.correlation_keys = vec![format!("{s_ip}:{s_port}->{d_ip}:{d_port}")];
        }

        // Build process_data.
        if let Some(ref cmd) = comm {
            occ.process_data = Some(ProcessEventData {
                pid,
                ppid: None,
                command: cmd.clone(),
                args: None,
                uid: 0,
                exit_code: None,
            });
        }

        // Handle return value for fexit probes.
        if let Some(r) = ret {
            if r == 0 {
                occ.outcome = Some(false_protocol::Outcome::Success);
            } else {
                occ.outcome = Some(false_protocol::Outcome::Failure);
                occ.severity = Severity::Warning;
            }
        }

        Ok(NormalizedEvidence::single(EvidenceRecord {
            observed_at_ns,
            probe: self.probe_metadata(),
            occurrence: occ,
            binding: None,
        }))
    }
}

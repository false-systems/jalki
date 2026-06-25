use jalki_evidence::{FileOpenEvent, KernelEvent};

use crate::probe::{Attachment, Probe, ProbeError};

pub struct FileOpen {
    attachments: Vec<Attachment>,
}

impl FileOpen {
    pub fn new() -> Self {
        Self {
            attachments: vec![Attachment::Fexit {
                function: "security_file_open",
            }],
        }
    }
}

impl Probe for FileOpen {
    fn attachments(&self) -> &[Attachment] {
        &self.attachments
    }

    fn name(&self) -> &str {
        "file_open"
    }

    fn program_name(&self) -> &str {
        "jalki_file_open"
    }

    fn ring_buffer_map(&self) -> &str {
        "FILE_OPEN_EVENTS"
    }

    fn decode_event(&self, raw: &[u8]) -> Result<KernelEvent, ProbeError> {
        Ok(KernelEvent::FileOpen(FileOpenEvent::from_bytes(raw)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jalki_common::FileOpenEvent as RawEvent;

    fn raw_file_open() -> Vec<u8> {
        let mut comm = [0u8; 16];
        comm[..3].copy_from_slice(b"cat");
        let mut path = [0u8; jalki_common::FILE_OPEN_PATH_LEN];
        path[..11].copy_from_slice(b"/etc/shadow");

        let event = RawEvent {
            timestamp_ns: 1_000_000_000,
            pid: 1234,
            uid: 1000,
            cgroup_id: 42,
            ret: 0,
            flags: 0,
            comm,
            path,
        };
        let ptr = &event as *const RawEvent as *const u8;
        unsafe { std::slice::from_raw_parts(ptr, std::mem::size_of::<RawEvent>()) }.to_vec()
    }

    #[test]
    fn delegates_to_evidence_normalizer() {
        let occ = FileOpen::new()
            .to_evidence(&raw_file_open(), "prod")
            .unwrap();
        let occ = occ.records.into_iter().next().unwrap().occurrence;
        assert_eq!(occ.source, "jalki/file_open");
        assert_eq!(occ.occurrence_type.as_str(), "kernel.file.open");
        assert_eq!(
            occ.labels.get("resource_ref_id").map(String::as_str),
            Some("/etc/shadow")
        );
    }

    #[test]
    fn too_short_maps_to_probe_error() {
        let err = FileOpen::new().to_evidence(&[0u8; 8], "prod").unwrap_err();
        assert!(matches!(err, ProbeError::TooShort { .. }));
    }
}

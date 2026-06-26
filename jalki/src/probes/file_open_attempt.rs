use jalki_evidence::{FileOpenEvent, KernelEvent};

use crate::probe::{Attachment, Probe, ProbeError};

/// `kernel.file.open_attempt` — FAILED opens of watched sensitive paths.
///
/// Multi-program probe: the two `sys_enter_open{at,at2}` programs stash the
/// requested path; the two `sys_exit_open{at,at2}` programs read the errno and
/// emit on failure. All four share an in-flight map (in eBPF) and one ring
/// buffer (`OPEN_ATTEMPT_EVENTS`). Each attachment carries its own program name,
/// which is why `Attachment::Tracepoint` is per-attachment.
pub struct FileOpenAttempt {
    attachments: Vec<Attachment>,
}

impl FileOpenAttempt {
    pub fn new() -> Self {
        Self {
            attachments: vec![
                Attachment::Tracepoint {
                    program: "jalki_sys_enter_openat",
                    category: "syscalls",
                    name: "sys_enter_openat",
                },
                Attachment::Tracepoint {
                    program: "jalki_sys_exit_openat",
                    category: "syscalls",
                    name: "sys_exit_openat",
                },
                Attachment::Tracepoint {
                    program: "jalki_sys_enter_openat2",
                    category: "syscalls",
                    name: "sys_enter_openat2",
                },
                Attachment::Tracepoint {
                    program: "jalki_sys_exit_openat2",
                    category: "syscalls",
                    name: "sys_exit_openat2",
                },
            ],
        }
    }
}

impl Probe for FileOpenAttempt {
    fn attachments(&self) -> &[Attachment] {
        &self.attachments
    }

    fn name(&self) -> &str {
        "file_open_attempt"
    }

    // Unused for attachment: every Tracepoint attachment carries its own program
    // name. Present only to satisfy the trait.
    fn program_name(&self) -> &str {
        "jalki_sys_exit_openat"
    }

    fn ring_buffer_map(&self) -> &str {
        "OPEN_ATTEMPT_EVENTS"
    }

    fn decode_event(&self, raw: &[u8]) -> Result<KernelEvent, ProbeError> {
        Ok(KernelEvent::FileOpenAttempt(FileOpenEvent::from_bytes(raw)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jalki_common::FileOpenEvent as RawEvent;

    fn raw_attempt() -> Vec<u8> {
        let mut comm = [0u8; 16];
        comm[..3].copy_from_slice(b"cat");
        let mut path = [0u8; jalki_common::FILE_OPEN_PATH_LEN];
        let p = b"/var/run/secrets/missing";
        path[..p.len()].copy_from_slice(p);
        let event = RawEvent {
            timestamp_ns: 1,
            pid: 7,
            uid: 0,
            cgroup_id: 9,
            ret: -2, // ENOENT
            flags: 0,
            comm,
            path,
        };
        let ptr = &event as *const RawEvent as *const u8;
        unsafe { std::slice::from_raw_parts(ptr, std::mem::size_of::<RawEvent>()) }.to_vec()
    }

    #[test]
    fn decodes_to_open_attempt_occurrence() {
        let evidence = FileOpenAttempt::new()
            .to_evidence(&raw_attempt(), "prod")
            .unwrap();
        let occ = evidence.records.into_iter().next().unwrap().occurrence;
        assert_eq!(occ.occurrence_type.as_str(), "kernel.file.open_attempt");
        assert_eq!(
            occ.labels.get("requested_path").map(String::as_str),
            Some("/var/run/secrets/missing")
        );
        assert_eq!(occ.labels.get("result").map(String::as_str), Some("failed"));
        // never claims a resolved file identity
        assert!(occ.labels.get("resource_ref_id").is_none());
    }

    #[test]
    fn too_short_maps_to_probe_error() {
        let err = FileOpenAttempt::new()
            .to_evidence(&[0u8; 8], "prod")
            .unwrap_err();
        assert!(matches!(err, ProbeError::TooShort { .. }));
    }
}

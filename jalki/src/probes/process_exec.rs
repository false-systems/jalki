use jalki_evidence::{KernelEvent, ProcessExecEvent};

use crate::probe::{Attachment, Probe, ProbeError};

pub struct ProcessExec {
    attachments: Vec<Attachment>,
}

impl ProcessExec {
    pub fn new() -> Self {
        Self {
            attachments: vec![Attachment::Tracepoint {
                program: "jalki_process_exec",
                category: "sched",
                name: "sched_process_exec",
            }],
        }
    }
}

impl Probe for ProcessExec {
    fn attachments(&self) -> &[Attachment] {
        &self.attachments
    }

    fn name(&self) -> &str {
        "process_exec"
    }

    fn program_name(&self) -> &str {
        "jalki_process_exec"
    }

    fn ring_buffer_map(&self) -> &str {
        "PROCESS_EXEC_EVENTS"
    }

    fn decode_event(&self, raw: &[u8]) -> Result<KernelEvent, ProbeError> {
        Ok(KernelEvent::ProcessExec(ProcessExecEvent::from_bytes(raw)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jalki_common::ProcessExecEvent as RawEvent;

    fn raw_exec() -> Vec<u8> {
        let mut comm = [0u8; 16];
        comm[..4].copy_from_slice(b"true");
        let mut filename = [0u8; jalki_common::PROCESS_EXEC_FILENAME_LEN];
        filename[..9].copy_from_slice(b"/bin/true");

        let event = RawEvent {
            timestamp_ns: 1_000_000_000,
            pid: 1234,
            ppid: 1,
            uid: 1000,
            gid: 1000,
            cgroup_id: 42,
            ret: 0,
            _pad1: 0,
            comm,
            filename,
            argv_hash: [0xabu8; 32],
        };
        let ptr = &event as *const RawEvent as *const u8;
        unsafe { std::slice::from_raw_parts(ptr, std::mem::size_of::<RawEvent>()) }.to_vec()
    }

    #[test]
    fn delegates_to_evidence_normalizer() {
        let occ = ProcessExec::new().to_evidence(&raw_exec(), "prod").unwrap();
        let occ = occ.records.into_iter().next().unwrap().occurrence;
        assert_eq!(occ.source, "jalki/process_exec");
        assert_eq!(occ.occurrence_type.as_str(), "kernel.process.exec");
        assert_eq!(occ.process_data.unwrap().command, "/bin/true");
        assert!(occ.labels.contains_key("argv_hash"));
    }

    #[test]
    fn too_short_maps_to_probe_error() {
        let err = ProcessExec::new()
            .to_evidence(&[0u8; 8], "prod")
            .unwrap_err();
        assert!(matches!(err, ProbeError::TooShort { .. }));
    }
}

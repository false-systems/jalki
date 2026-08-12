//! Canonical Linux process-lifetime identity shared by Jälki evidence.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const RUNTIME_SUBJECT_CANONICALIZATION_VERSION: u16 = 1;
pub const RUNTIME_SUBJECT_IDENTITY_METHOD: &str = "task_start_boottime_btf_v1";

const DOMAIN: &[u8] = b"false-systems/runtime-subject/v1\0";

/// A Linux thread-group lifetime. Pod, container, and cgroup are relationships,
/// not components of this identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeSubjectV1 {
    pub runtime_subject_id: String,
    pub node_identity: String,
    pub boot_id: String,
    pub host_tgid: u32,
    pub leader_start_boottime_ns: u64,
    pub canonicalization_version: u16,
    pub identity_method: String,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RuntimeSubjectError {
    #[error("node identity must be non-empty and have no surrounding whitespace")]
    InvalidNodeIdentity,
    #[error("boot id must be a canonical UUID")]
    InvalidBootId,
    #[error("host tgid must be non-zero")]
    InvalidHostTgid,
    #[error("leader start_boottime must be non-zero")]
    InvalidLeaderStart,
}

impl RuntimeSubjectV1 {
    pub fn new(
        node_identity: impl Into<String>,
        boot_id: impl Into<String>,
        host_tgid: u32,
        leader_start_boottime_ns: u64,
    ) -> Result<Self, RuntimeSubjectError> {
        let node_identity = node_identity.into();
        if node_identity.is_empty() || node_identity.trim() != node_identity {
            return Err(RuntimeSubjectError::InvalidNodeIdentity);
        }
        let boot_id = canonical_boot_id(&boot_id.into())?;
        if host_tgid == 0 {
            return Err(RuntimeSubjectError::InvalidHostTgid);
        }
        if leader_start_boottime_ns == 0 {
            return Err(RuntimeSubjectError::InvalidLeaderStart);
        }

        let mut hasher = Sha256::new();
        hasher.update(DOMAIN);
        update_field(&mut hasher, node_identity.as_bytes());
        update_field(&mut hasher, boot_id.as_bytes());
        update_field(&mut hasher, &host_tgid.to_be_bytes());
        update_field(&mut hasher, &leader_start_boottime_ns.to_be_bytes());
        update_field(
            &mut hasher,
            &RUNTIME_SUBJECT_CANONICALIZATION_VERSION.to_be_bytes(),
        );

        Ok(Self {
            runtime_subject_id: format!("sha256:{:x}", hasher.finalize()),
            node_identity,
            boot_id,
            host_tgid,
            leader_start_boottime_ns,
            canonicalization_version: RUNTIME_SUBJECT_CANONICALIZATION_VERSION,
            identity_method: RUNTIME_SUBJECT_IDENTITY_METHOD.into(),
        })
    }
}

fn update_field(hasher: &mut Sha256, field: &[u8]) {
    hasher.update((field.len() as u64).to_be_bytes());
    hasher.update(field);
}

fn canonical_boot_id(value: &str) -> Result<String, RuntimeSubjectError> {
    let bytes = value.as_bytes();
    if bytes.len() != 36
        || bytes.iter().enumerate().any(|(index, byte)| match index {
            8 | 13 | 18 | 23 => *byte != b'-',
            _ => !byte.is_ascii_hexdigit(),
        })
    {
        return Err(RuntimeSubjectError::InvalidBootId);
    }
    Ok(value.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_is_reproducible_and_unambiguous() {
        let subject = RuntimeSubjectV1::new(
            "k8s-node-uid:8f01",
            "550E8400-E29B-41D4-A716-446655440000",
            4217,
            657_653_680_687_218,
        )
        .expect("valid subject");
        let different_boundary = RuntimeSubjectV1::new(
            "k8s-node-uid:8f014",
            "550e8400-e29b-41d4-a716-446655440000",
            217,
            657_653_680_687_218,
        )
        .expect("valid subject");

        assert_eq!(subject.boot_id, "550e8400-e29b-41d4-a716-446655440000");
        assert_eq!(
            subject.runtime_subject_id,
            "sha256:cc574f4ae29b49d1ff4a9f0df3c162faa73b2375aa5ae73c0fbf2a15e9516a3f"
        );
        assert_ne!(
            subject.runtime_subject_id,
            different_boundary.runtime_subject_id
        );
    }
}

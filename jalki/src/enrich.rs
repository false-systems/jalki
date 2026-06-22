use std::sync::{Arc, RwLock};

use jalki_enrich::{resolve_container_ref_from_cgroupfs, BindingCache};
use jalki_evidence::{BindingProvenance, EvidenceRecord, RuntimeBinding, UnboundReason};

/// Runtime binding resolver used by readers before records reach sinks.
pub trait RuntimeEnricher: Send + Sync + 'static {
    fn resolve(&self, cgroup_id: u64, pid: u32) -> RuntimeBinding;
}

/// Default resolver for environments without Kubernetes/CRI binding configured.
pub struct NoopEnricher;

impl RuntimeEnricher for NoopEnricher {
    fn resolve(&self, cgroup_id: u64, _pid: u32) -> RuntimeBinding {
        if cgroup_id == 0 {
            RuntimeBinding::Unbound {
                reason: UnboundReason::NoCgroup,
            }
        } else {
            RuntimeBinding::Unbound {
                reason: UnboundReason::CacheMiss,
            }
        }
    }
}

/// Cache-backed resolver that can bind records once pod/container metadata has
/// been loaded by a watcher.
pub struct CachedEnricher {
    cgroup_root: String,
    cache: Arc<RwLock<BindingCache>>,
}

impl CachedEnricher {
    pub fn new(cgroup_root: impl Into<String>, cache: Arc<RwLock<BindingCache>>) -> Self {
        Self {
            cgroup_root: cgroup_root.into(),
            cache,
        }
    }
}

impl RuntimeEnricher for CachedEnricher {
    fn resolve(&self, cgroup_id: u64, _pid: u32) -> RuntimeBinding {
        if cgroup_id == 0 {
            return RuntimeBinding::Unbound {
                reason: UnboundReason::NoCgroup,
            };
        }

        let container = match resolve_container_ref_from_cgroupfs(&self.cgroup_root, cgroup_id) {
            Ok(container) => container,
            Err(_) => {
                return RuntimeBinding::Unbound {
                    reason: UnboundReason::CacheMiss,
                }
            }
        };

        self.cache
            .read()
            .map(|cache| {
                cache
                    .bind_container(&container.id, BindingProvenance::Observed)
                    .into_runtime_binding()
            })
            .unwrap_or(RuntimeBinding::Unbound {
                reason: UnboundReason::CacheMiss,
            })
    }
}

pub fn bind_record(record: EvidenceRecord, enricher: &dyn RuntimeEnricher) -> EvidenceRecord {
    let cgroup_id = record
        .occurrence
        .labels
        .get("cgroup_id")
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0);
    let pid = record
        .occurrence
        .process_data
        .as_ref()
        .map(|process| process.pid)
        .unwrap_or(0);

    record.with_runtime_binding(enricher.resolve(cgroup_id, pid))
}

#[cfg(test)]
mod tests {
    use false_protocol::Occurrence;
    use jalki_evidence::{EvidenceRecord, HookKind, ProbeMetadata};

    use super::*;

    fn record(cgroup_id: Option<u64>) -> EvidenceRecord {
        let mut occurrence = Occurrence::new("jalki/test", "kernel.test");
        if let Some(cgroup_id) = cgroup_id {
            occurrence
                .labels
                .insert("cgroup_id".into(), cgroup_id.to_string());
        }

        EvidenceRecord {
            observed_at_ns: 1,
            probe: ProbeMetadata {
                probe_id: "test".into(),
                probe_version: "1".into(),
                probe_family: "test".into(),
                hook_kind: HookKind::Fentry,
                kernel_function: "test".into(),
            },
            occurrence,
            binding: None,
        }
    }

    #[test]
    fn noop_enricher_marks_missing_cgroup_as_no_cgroup() {
        let record = bind_record(record(None), &NoopEnricher);

        assert_eq!(
            record.binding,
            Some(RuntimeBinding::Unbound {
                reason: UnboundReason::NoCgroup
            })
        );
    }

    #[test]
    fn noop_enricher_marks_present_cgroup_as_cache_miss() {
        let record = bind_record(record(Some(42)), &NoopEnricher);

        assert_eq!(
            record.binding,
            Some(RuntimeBinding::Unbound {
                reason: UnboundReason::CacheMiss
            })
        );
    }
}

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use jalki_enrich::{
    resolve_container_ref_from_cgroupfs, resolve_container_ref_from_procfs, BindingCache,
    ContainerRef, ResolveCgroupError,
};
use jalki_evidence::{BindingProvenance, EvidenceRecord, RuntimeBinding, UnboundReason};

const CGROUP_FALLBACK_MEMO_MAX: usize = 8192;

/// Runtime binding resolver used by readers before records reach sinks.
pub trait RuntimeEnricher: Send + Sync + 'static {
    fn resolve(&self, cgroup_id: u64, pid: u32) -> RuntimeBinding;

    fn binding_cache_stats(&self) -> Option<BindingCacheStats> {
        None
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BindingCacheStats {
    pub entries: usize,
    pub hit_ratio: f64,
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
    proc_root: String,
    cache: Arc<RwLock<BindingCache>>,
    cgroup_memo: RwLock<HashMap<u64, Option<ContainerRef>>>,
}

impl CachedEnricher {
    pub fn new(cgroup_root: impl Into<String>, cache: Arc<RwLock<BindingCache>>) -> Self {
        Self::with_roots(cgroup_root, "/proc", cache)
    }

    pub fn with_roots(
        cgroup_root: impl Into<String>,
        proc_root: impl Into<String>,
        cache: Arc<RwLock<BindingCache>>,
    ) -> Self {
        Self {
            cgroup_root: cgroup_root.into(),
            proc_root: proc_root.into(),
            cache,
            cgroup_memo: RwLock::new(HashMap::new()),
        }
    }
}

impl RuntimeEnricher for CachedEnricher {
    fn resolve(&self, cgroup_id: u64, pid: u32) -> RuntimeBinding {
        if cgroup_id == 0 {
            return RuntimeBinding::Unbound {
                reason: UnboundReason::NoCgroup,
            };
        }

        if let Ok(container) = resolve_container_ref_from_procfs(&self.proc_root, pid) {
            return self.bind_container(&container, BindingProvenance::Observed);
        }

        let container = match self.resolve_from_cgroupfs_fallback(cgroup_id) {
            Ok(Some(container)) => container,
            Ok(None) => {
                return RuntimeBinding::Unbound {
                    reason: UnboundReason::HostProcess,
                };
            }
            Err(reason) => {
                return RuntimeBinding::Unbound { reason };
            }
        };

        self.bind_container(&container, BindingProvenance::DerivedFromCache)
    }

    fn binding_cache_stats(&self) -> Option<BindingCacheStats> {
        self.cache.read().ok().map(|cache| BindingCacheStats {
            entries: cache.len(),
            hit_ratio: cache.hit_ratio(),
        })
    }
}

impl CachedEnricher {
    fn resolve_from_cgroupfs_fallback(
        &self,
        cgroup_id: u64,
    ) -> Result<Option<ContainerRef>, UnboundReason> {
        if let Ok(memo) = self.cgroup_memo.read() {
            if let Some(container) = memo.get(&cgroup_id) {
                return Ok(container.clone());
            }
        }

        let resolved = match resolve_container_ref_from_cgroupfs(&self.cgroup_root, cgroup_id) {
            Ok(container) => Some(container),
            Err(ResolveCgroupError::Unbound { .. }) => None,
            Err(_) => {
                return Err(UnboundReason::CacheMiss);
            }
        };

        if let Ok(mut memo) = self.cgroup_memo.write() {
            if memo.len() >= CGROUP_FALLBACK_MEMO_MAX {
                memo.clear();
            }
            memo.insert(cgroup_id, resolved.clone());
        }
        Ok(resolved)
    }

    fn bind_container(
        &self,
        container: &ContainerRef,
        provenance: BindingProvenance,
    ) -> RuntimeBinding {
        self.cache
            .read()
            .map(|cache| {
                cache
                    .bind_container(&container.id, provenance)
                    .into_runtime_binding()
            })
            .unwrap_or(RuntimeBinding::Unbound {
                reason: UnboundReason::CacheMiss,
            })
    }
}

pub fn bind_record(record: EvidenceRecord, enricher: &dyn RuntimeEnricher) -> EvidenceRecord {
    let binding = enricher.resolve(record.cgroup_id, record.pid);
    record.with_runtime_binding(binding)
}

#[cfg(test)]
mod tests {
    use false_protocol::Occurrence;
    use jalki_evidence::{EvidenceRecord, HookKind, ProbeMetadata};
    use std::collections::BTreeMap;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    const ID: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn record(cgroup_id: u64) -> EvidenceRecord {
        EvidenceRecord {
            observed_at_ns: 1,
            pid: 123,
            cgroup_id,
            probe: ProbeMetadata {
                probe_id: "test".into(),
                probe_version: "1".into(),
                probe_family: "test".into(),
                hook_kind: HookKind::Fentry,
                kernel_function: "test".into(),
            },
            occurrence: Occurrence::new("jalki/test", "kernel.test"),
            binding: None,
        }
    }

    fn temp_root() -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "jalki-enrich-runtime-test-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn metadata() -> jalki_enrich::PodMetadata {
        jalki_enrich::PodMetadata {
            pod_uid: "pod-1".into(),
            namespace: "default".into(),
            service_account: Some("builder".into()),
            labels: BTreeMap::new(),
        }
    }

    #[test]
    fn noop_enricher_marks_missing_cgroup_as_no_cgroup() {
        let record = bind_record(record(0), &NoopEnricher);

        assert_eq!(
            record.binding,
            Some(RuntimeBinding::Unbound {
                reason: UnboundReason::NoCgroup
            })
        );
    }

    #[test]
    fn noop_enricher_marks_present_cgroup_as_cache_miss() {
        let record = bind_record(record(42), &NoopEnricher);

        assert_eq!(
            record.binding,
            Some(RuntimeBinding::Unbound {
                reason: UnboundReason::CacheMiss
            })
        );
    }

    #[test]
    fn bind_record_uses_typed_cgroup_id_not_labels() {
        let mut record = record(0);
        record
            .occurrence
            .labels
            .insert("cgroup_id".into(), "42".into());

        let record = bind_record(record, &NoopEnricher);

        assert_eq!(
            record.binding,
            Some(RuntimeBinding::Unbound {
                reason: UnboundReason::NoCgroup
            })
        );
    }

    #[test]
    fn cached_enricher_prefers_procfs_fast_path() {
        let proc_root = temp_root();
        let cgroup_root = temp_root();
        let proc_dir = proc_root.join("123");
        fs::create_dir_all(&proc_dir).unwrap();
        fs::write(
            proc_dir.join("cgroup"),
            format!("0::/kubepods.slice/pod123/cri-containerd-{ID}.scope\n"),
        )
        .unwrap();

        let mut cache = BindingCache::new();
        cache.upsert(ID, metadata());
        let enricher = CachedEnricher::with_roots(
            cgroup_root.to_string_lossy(),
            proc_root.to_string_lossy(),
            Arc::new(RwLock::new(cache)),
        );

        let binding = enricher.resolve(999, 123);

        assert!(matches!(
            binding,
            RuntimeBinding::Bound {
                provenance: BindingProvenance::Observed,
                ..
            }
        ));
        fs::remove_dir_all(proc_root).unwrap();
        fs::remove_dir_all(cgroup_root).unwrap();
    }
}

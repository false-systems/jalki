//! Runtime binding helpers for Plane-B evidence.
//!
//! This crate is deliberately aya-free and kube-free. It owns the deterministic
//! pieces that can be tested on any host: parsing cgroup/container identifiers
//! and converting resolved pod/container metadata into `RuntimeBinding`.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use jalki_evidence::{BindingProvenance, RuntimeBinding, UnboundReason};
use thiserror::Error;

const CONTAINER_ID_LEN: usize = 64;
const ARC_RUN_ID_LABEL: &str = "actions.github.com/run-id";
const DEFAULT_BINDING_CACHE_MAX_CONTAINERS: usize = 100_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerRuntime {
    Containerd,
    Crio,
    Docker,
}

impl ContainerRuntime {
    pub fn as_str(&self) -> &'static str {
        match self {
            ContainerRuntime::Containerd => "containerd",
            ContainerRuntime::Crio => "cri-o",
            ContainerRuntime::Docker => "docker",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerRef {
    pub runtime: ContainerRuntime,
    pub id: String,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ParseContainerError {
    #[error("no container id in cgroup path")]
    NoContainerId,
    #[error("invalid container id in cgroup path: {0}")]
    InvalidContainerId(String),
}

#[derive(Debug, Error)]
pub enum ResolveCgroupError {
    #[error("failed to scan cgroupfs at {path}: {source}")]
    Io { path: PathBuf, source: io::Error },
    #[error("no cgroup directory with inode {0}")]
    NotFound(u64),
    #[error("cgroup inode {inode} matched {path}, but no container id was present: {source}")]
    Unbound {
        inode: u64,
        path: PathBuf,
        source: ParseContainerError,
    },
}

#[derive(Debug, Error)]
pub enum ResolveProcCgroupError {
    #[error("invalid pid 0 for proc cgroup lookup")]
    InvalidPid,
    #[error("failed to read proc cgroup file at {path}: {source}")]
    Io { path: PathBuf, source: io::Error },
    #[error("no cgroup path in {0}")]
    NoCgroupPath(PathBuf),
    #[error("no container id was present in {path}: {source}")]
    Unbound {
        path: PathBuf,
        source: ParseContainerError,
    },
}

/// Parse a container id out of common cgroup path forms.
///
/// Supported examples:
///
/// - `.../cri-containerd-<64hex>.scope`
/// - `.../crio-<64hex>.scope`
/// - `.../docker-<64hex>.scope`
/// - `.../docker/<64hex>`
pub fn parse_container_ref(path: &str) -> Result<ContainerRef, ParseContainerError> {
    for segment in path.rsplit('/') {
        let segment = segment.trim();
        if segment.is_empty() {
            continue;
        }

        for (prefix, runtime) in [
            ("cri-containerd-", ContainerRuntime::Containerd),
            ("crio-", ContainerRuntime::Crio),
            ("docker-", ContainerRuntime::Docker),
        ] {
            if let Some(rest) = segment.strip_prefix(prefix) {
                let id = rest.strip_suffix(".scope").unwrap_or(rest);
                return validate_container_id(id, runtime);
            }
        }

        if is_container_id(segment) {
            let runtime = if path.contains("/docker/") {
                ContainerRuntime::Docker
            } else {
                ContainerRuntime::Containerd
            };
            return Ok(ContainerRef {
                runtime,
                id: segment.to_ascii_lowercase(),
            });
        }
    }

    Err(ParseContainerError::NoContainerId)
}

/// Resolve a container id through `/proc/<pid>/cgroup`.
///
/// This is the hot-path resolver for live events because it reads one small
/// file for the event's process instead of scanning cgroupfs by inode.
pub fn resolve_container_ref_from_procfs(
    proc_root: impl AsRef<Path>,
    pid: u32,
) -> Result<ContainerRef, ResolveProcCgroupError> {
    if pid == 0 {
        return Err(ResolveProcCgroupError::InvalidPid);
    }

    let path = proc_root.as_ref().join(pid.to_string()).join("cgroup");
    let contents = fs::read_to_string(&path).map_err(|source| ResolveProcCgroupError::Io {
        path: path.clone(),
        source,
    })?;

    let mut saw_path = false;
    let mut first_error = None;
    for line in contents.lines() {
        if let Some((_, cgroup_path)) = line.rsplit_once(':') {
            if cgroup_path.is_empty() {
                continue;
            }
            saw_path = true;
            match parse_container_ref(cgroup_path) {
                Ok(container) => return Ok(container),
                Err(source) if first_error.is_none() => first_error = Some(source),
                Err(_) => {}
            }
        }
    }

    if let Some(source) = first_error {
        Err(ResolveProcCgroupError::Unbound { path, source })
    } else if saw_path {
        Err(ResolveProcCgroupError::Unbound {
            path,
            source: ParseContainerError::NoContainerId,
        })
    } else {
        Err(ResolveProcCgroupError::NoCgroupPath(path))
    }
}

/// Resolve a kernel `bpf_get_current_cgroup_id()` value through cgroupfs.
///
/// Linux exposes the cgroup id as the cgroup directory inode. This scans a root
/// such as `/sys/fs/cgroup`, finds the matching directory, then parses the
/// container runtime id from its path.
pub fn resolve_container_ref_from_cgroupfs(
    root: impl AsRef<Path>,
    cgroup_id: u64,
) -> Result<ContainerRef, ResolveCgroupError> {
    let root = root.as_ref();
    let matched = find_dir_by_inode(root, cgroup_id)?;
    match parse_container_ref(&matched.to_string_lossy()) {
        Ok(container) => Ok(container),
        Err(source) => Err(ResolveCgroupError::Unbound {
            inode: cgroup_id,
            path: matched,
            source,
        }),
    }
}

fn find_dir_by_inode(root: &Path, inode: u64) -> Result<PathBuf, ResolveCgroupError> {
    let metadata = fs::metadata(root).map_err(|source| ResolveCgroupError::Io {
        path: root.to_path_buf(),
        source,
    })?;
    if metadata.ino() == inode {
        return Ok(root.to_path_buf());
    }

    let entries = fs::read_dir(root).map_err(|source| ResolveCgroupError::Io {
        path: root.to_path_buf(),
        source,
    })?;

    for entry in entries {
        let entry = entry.map_err(|source| ResolveCgroupError::Io {
            path: root.to_path_buf(),
            source,
        })?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(|source| ResolveCgroupError::Io {
            path: path.clone(),
            source,
        })?;
        if !file_type.is_dir() {
            continue;
        }

        match find_dir_by_inode(&path, inode) {
            Ok(found) => return Ok(found),
            Err(ResolveCgroupError::NotFound(_)) => {}
            Err(err) => return Err(err),
        }
    }

    Err(ResolveCgroupError::NotFound(inode))
}

fn validate_container_id(
    id: &str,
    runtime: ContainerRuntime,
) -> Result<ContainerRef, ParseContainerError> {
    if !is_container_id(id) {
        return Err(ParseContainerError::InvalidContainerId(id.into()));
    }

    Ok(ContainerRef {
        runtime,
        id: id.to_ascii_lowercase(),
    })
}

fn is_container_id(value: &str) -> bool {
    value.len() == CONTAINER_ID_LEN && value.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Normalize Kubernetes `containerID` values such as
/// `containerd://<id>` and `docker://<id>`.
pub fn parse_k8s_container_id(value: &str) -> Result<ContainerRef, ParseContainerError> {
    let (runtime, id) = match value.split_once("://") {
        Some(("containerd", id)) => (ContainerRuntime::Containerd, id),
        Some(("cri-o", id)) | Some(("crio", id)) => (ContainerRuntime::Crio, id),
        Some(("docker", id)) => (ContainerRuntime::Docker, id),
        Some((_, id)) => (ContainerRuntime::Containerd, id),
        None => (ContainerRuntime::Containerd, value),
    };

    validate_container_id(id, runtime)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PodMetadata {
    pub pod_uid: String,
    pub namespace: String,
    pub service_account: Option<String>,
    pub labels: BTreeMap<String, String>,
}

impl PodMetadata {
    pub fn github_run_id(&self) -> Option<&str> {
        self.labels.get(ARC_RUN_ID_LABEL).map(String::as_str)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerStatusSnapshot {
    pub container_id: String,
}

impl ContainerStatusSnapshot {
    pub fn new(container_id: impl Into<String>) -> Self {
        Self {
            container_id: container_id.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PodSnapshot {
    pub pod_uid: String,
    pub namespace: String,
    pub service_account: Option<String>,
    pub labels: BTreeMap<String, String>,
    pub containers: Vec<ContainerStatusSnapshot>,
}

impl PodSnapshot {
    pub fn metadata(&self) -> PodMetadata {
        PodMetadata {
            pod_uid: self.pod_uid.clone(),
            namespace: self.namespace.clone(),
            service_account: self.service_account.clone(),
            labels: self.labels.clone(),
        }
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CacheUpdate {
    pub upserted: usize,
    pub removed: usize,
    pub ignored: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Binding {
    Bound {
        container_id: String,
        metadata: PodMetadata,
        provenance: BindingProvenance,
    },
    Unbound {
        reason: UnboundReason,
    },
}

impl Binding {
    pub fn into_runtime_binding(self) -> RuntimeBinding {
        match self {
            Binding::Bound {
                container_id,
                metadata,
                provenance,
            } => RuntimeBinding::Bound {
                container_id,
                pod_uid: Some(metadata.pod_uid),
                namespace: Some(metadata.namespace),
                service_account: metadata.service_account,
                labels: metadata.labels,
                provenance,
            },
            Binding::Unbound { reason } => RuntimeBinding::Unbound { reason },
        }
    }
}

#[derive(Debug)]
pub struct BindingCache {
    by_container_id: HashMap<String, PodMetadata>,
    by_pod_uid: HashMap<String, Vec<String>>,
    insertion_order: VecDeque<String>,
    max_containers: usize,
    hits: AtomicU64,
    misses: AtomicU64,
}

impl BindingCache {
    pub fn new() -> Self {
        Self::with_max_containers(DEFAULT_BINDING_CACHE_MAX_CONTAINERS)
    }

    pub fn with_max_containers(max_containers: usize) -> Self {
        Self {
            by_container_id: HashMap::new(),
            by_pod_uid: HashMap::new(),
            insertion_order: VecDeque::new(),
            max_containers,
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }

    pub fn upsert(&mut self, container_id: impl Into<String>, metadata: PodMetadata) {
        self.insert_container(container_id.into(), metadata);
        self.evict_to_capacity();
    }

    pub fn remove(&mut self, container_id: &str) -> Option<PodMetadata> {
        let container_id = container_id.to_ascii_lowercase();
        let removed = self.by_container_id.remove(&container_id);
        if removed.is_some() {
            self.remove_from_pod_index(&container_id);
            // Purge from the FIFO index too, or it accumulates tombstones for
            // every removed container even while `by_container_id` stays bounded.
            self.insertion_order.retain(|id| id != &container_id);
        }
        removed
    }

    pub fn apply_pod_snapshot(&mut self, pod: PodSnapshot) -> CacheUpdate {
        let mut update = self.remove_pod(&pod.pod_uid);
        let metadata = pod.metadata();
        let mut container_ids = Vec::new();

        for container in pod.containers {
            match parse_k8s_container_id(&container.container_id) {
                Ok(container_ref) => {
                    self.insert_container(container_ref.id.clone(), metadata.clone());
                    container_ids.push(container_ref.id);
                    update.upserted += 1;
                }
                Err(_) => {
                    update.ignored += 1;
                }
            }
        }

        if !container_ids.is_empty() {
            self.by_pod_uid.insert(pod.pod_uid, container_ids);
        }
        update.removed += self.evict_to_capacity();

        update
    }

    pub fn remove_pod(&mut self, pod_uid: &str) -> CacheUpdate {
        let mut update = CacheUpdate::default();
        if let Some(container_ids) = self.by_pod_uid.remove(pod_uid) {
            for container_id in &container_ids {
                if self.by_container_id.remove(container_id).is_some() {
                    update.removed += 1;
                }
            }
            // Purge removed ids from the FIFO index so it cannot grow unbounded
            // under churn that stays under the capacity cap.
            self.insertion_order
                .retain(|id| !container_ids.contains(id));
        }
        update
    }

    pub fn bind_container(&self, container_id: &str, provenance: BindingProvenance) -> Binding {
        match self.by_container_id.get(&container_id.to_ascii_lowercase()) {
            Some(metadata) => {
                self.hits.fetch_add(1, Ordering::Relaxed);
                Binding::Bound {
                    container_id: container_id.to_ascii_lowercase(),
                    metadata: metadata.clone(),
                    provenance,
                }
            }
            None => {
                self.misses.fetch_add(1, Ordering::Relaxed);
                Binding::Unbound {
                    reason: UnboundReason::CacheMiss,
                }
            }
        }
    }

    pub fn len(&self) -> usize {
        self.by_container_id.len()
    }

    pub fn pod_count(&self) -> usize {
        self.by_pod_uid.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_container_id.is_empty()
    }

    pub fn max_containers(&self) -> usize {
        self.max_containers
    }

    pub fn hit_count(&self) -> u64 {
        self.hits.load(Ordering::Relaxed)
    }

    pub fn miss_count(&self) -> u64 {
        self.misses.load(Ordering::Relaxed)
    }

    pub fn hit_ratio(&self) -> f64 {
        let hits = self.hit_count();
        let total = hits + self.miss_count();
        if total == 0 {
            0.0
        } else {
            hits as f64 / total as f64
        }
    }

    fn insert_container(&mut self, container_id: String, metadata: PodMetadata) {
        let container_id = container_id.to_ascii_lowercase();
        let is_new = !self.by_container_id.contains_key(&container_id);
        self.by_container_id.insert(container_id.clone(), metadata);
        if is_new {
            self.insertion_order.push_back(container_id);
        }
    }

    fn evict_to_capacity(&mut self) -> usize {
        if self.max_containers == 0 {
            let removed = self.by_container_id.len();
            self.by_container_id.clear();
            self.by_pod_uid.clear();
            self.insertion_order.clear();
            return removed;
        }

        let mut removed = 0;
        while self.by_container_id.len() > self.max_containers {
            let Some(container_id) = self.insertion_order.pop_front() else {
                break;
            };
            if self.by_container_id.remove(&container_id).is_some() {
                self.remove_from_pod_index(&container_id);
                removed += 1;
            }
        }
        removed
    }

    fn remove_from_pod_index(&mut self, container_id: &str) {
        let mut empty_pods = Vec::new();
        for (pod_uid, container_ids) in &mut self.by_pod_uid {
            container_ids.retain(|id| id != container_id);
            if container_ids.is_empty() {
                empty_pods.push(pod_uid.clone());
            }
        }
        for pod_uid in empty_pods {
            self.by_pod_uid.remove(&pod_uid);
        }
    }
}

impl Default for BindingCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    const ID: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const UPPER_ID: &str = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";

    fn metadata() -> PodMetadata {
        let mut labels = BTreeMap::new();
        labels.insert(ARC_RUN_ID_LABEL.into(), "987654321".into());
        PodMetadata {
            pod_uid: "pod-uid-1".into(),
            namespace: "default".into(),
            service_account: Some("builder".into()),
            labels,
        }
    }

    fn pod_snapshot() -> PodSnapshot {
        let mut labels = BTreeMap::new();
        labels.insert(ARC_RUN_ID_LABEL.into(), "987654321".into());
        PodSnapshot {
            pod_uid: "pod-uid-1".into(),
            namespace: "default".into(),
            service_account: Some("builder".into()),
            labels,
            containers: vec![ContainerStatusSnapshot::new(format!("containerd://{ID}"))],
        }
    }

    fn temp_root() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("jalki-enrich-test-{}-{nanos}", std::process::id()));
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn parses_containerd_systemd_scope() {
        let path = format!("/kubepods.slice/kubepods-burstable.slice/cri-containerd-{ID}.scope");
        let parsed = parse_container_ref(&path).unwrap();

        assert_eq!(parsed.runtime, ContainerRuntime::Containerd);
        assert_eq!(parsed.id, ID);
    }

    #[test]
    fn parses_crio_systemd_scope() {
        let path = format!("/kubepods.slice/crio-{ID}.scope");
        let parsed = parse_container_ref(&path).unwrap();

        assert_eq!(parsed.runtime, ContainerRuntime::Crio);
        assert_eq!(parsed.id, ID);
    }

    #[test]
    fn parses_docker_cgroupfs_path() {
        let path = format!("/kubepods/besteffort/pod123/docker/{UPPER_ID}");
        let parsed = parse_container_ref(&path).unwrap();

        assert_eq!(parsed.runtime, ContainerRuntime::Docker);
        assert_eq!(parsed.id, ID);
    }

    #[test]
    fn host_process_yields_no_container_id() {
        let err = parse_container_ref("/user.slice/user-501.slice/session-2.scope").unwrap_err();

        assert_eq!(err, ParseContainerError::NoContainerId);
    }

    #[test]
    fn malformed_container_id_is_rejected() {
        let err = parse_container_ref("/kubepods.slice/cri-containerd-not-a-container.scope")
            .unwrap_err();

        assert!(matches!(err, ParseContainerError::InvalidContainerId(_)));
    }

    #[test]
    fn parses_k8s_container_id_uri() {
        let parsed = parse_k8s_container_id(&format!("containerd://{ID}")).unwrap();

        assert_eq!(parsed.runtime, ContainerRuntime::Containerd);
        assert_eq!(parsed.id, ID);
    }

    #[test]
    fn resolves_cgroup_inode_to_container_id() {
        let root = temp_root();
        let cgroup_path = root.join(format!("kubepods.slice/pod123/cri-containerd-{ID}.scope"));
        fs::create_dir_all(&cgroup_path).unwrap();
        let inode = fs::metadata(&cgroup_path).unwrap().ino();

        let resolved = resolve_container_ref_from_cgroupfs(&root, inode).unwrap();

        assert_eq!(resolved.runtime, ContainerRuntime::Containerd);
        assert_eq!(resolved.id, ID);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn resolves_proc_cgroup_to_container_id() {
        let root = temp_root();
        let proc_dir = root.join("1234");
        fs::create_dir_all(&proc_dir).unwrap();
        fs::write(
            proc_dir.join("cgroup"),
            format!("0::/kubepods.slice/pod123/cri-containerd-{ID}.scope\n"),
        )
        .unwrap();

        let resolved = resolve_container_ref_from_procfs(&root, 1234).unwrap();

        assert_eq!(resolved.runtime, ContainerRuntime::Containerd);
        assert_eq!(resolved.id, ID);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn proc_cgroup_scans_all_controller_lines() {
        let root = temp_root();
        let proc_dir = root.join("1234");
        fs::create_dir_all(&proc_dir).unwrap();
        fs::write(
            proc_dir.join("cgroup"),
            format!("8:cpu:/user.slice/session.scope\n2:memory:/docker/{ID}\n"),
        )
        .unwrap();

        let resolved = resolve_container_ref_from_procfs(&root, 1234).unwrap();

        assert_eq!(resolved.runtime, ContainerRuntime::Docker);
        assert_eq!(resolved.id, ID);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn unresolved_cgroup_inode_is_not_found() {
        let root = temp_root();
        let err = resolve_container_ref_from_cgroupfs(&root, u64::MAX).unwrap_err();

        assert!(matches!(err, ResolveCgroupError::NotFound(_)));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn binding_cache_returns_runtime_binding_with_arc_label() {
        let mut cache = BindingCache::new();
        cache.upsert(ID, metadata());

        let binding = cache
            .bind_container(ID, BindingProvenance::Observed)
            .into_runtime_binding();

        let RuntimeBinding::Bound {
            pod_uid,
            namespace,
            service_account,
            labels,
            provenance,
            ..
        } = binding
        else {
            panic!("expected bound runtime binding");
        };

        assert_eq!(pod_uid.as_deref(), Some("pod-uid-1"));
        assert_eq!(namespace.as_deref(), Some("default"));
        assert_eq!(service_account.as_deref(), Some("builder"));
        assert_eq!(
            labels.get(ARC_RUN_ID_LABEL).map(String::as_str),
            Some("987654321")
        );
        assert_eq!(provenance, BindingProvenance::Observed);
    }

    #[test]
    fn binding_cache_miss_is_unbound() {
        let cache = BindingCache::new();
        let binding = cache.bind_container(ID, BindingProvenance::Observed);

        assert_eq!(
            binding,
            Binding::Unbound {
                reason: UnboundReason::CacheMiss
            }
        );
        assert_eq!(cache.miss_count(), 1);
    }

    #[test]
    fn binding_cache_records_hits_and_hit_ratio() {
        let mut cache = BindingCache::new();
        cache.upsert(ID, metadata());

        assert!(matches!(
            cache.bind_container(ID, BindingProvenance::Observed),
            Binding::Bound { .. }
        ));
        assert!(matches!(
            cache.bind_container(UPPER_ID, BindingProvenance::Observed),
            Binding::Bound { .. }
        ));
        assert!(matches!(
            cache.bind_container(
                "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
                BindingProvenance::Observed
            ),
            Binding::Unbound { .. }
        ));

        assert_eq!(cache.hit_count(), 2);
        assert_eq!(cache.miss_count(), 1);
        assert!((cache.hit_ratio() - (2.0 / 3.0)).abs() < f64::EPSILON);
    }

    #[test]
    fn binding_cache_evicts_oldest_entry_when_bounded() {
        let mut cache = BindingCache::with_max_containers(1);
        let new_id = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

        cache.upsert(ID, metadata());
        cache.upsert(new_id, metadata());

        assert_eq!(cache.len(), 1);
        assert_eq!(cache.max_containers(), 1);
        assert!(matches!(
            cache.bind_container(ID, BindingProvenance::Observed),
            Binding::Unbound {
                reason: UnboundReason::CacheMiss
            }
        ));
        assert!(matches!(
            cache.bind_container(new_id, BindingProvenance::Observed),
            Binding::Bound { .. }
        ));
    }

    #[test]
    fn pod_snapshot_upserts_container_binding() {
        let mut cache = BindingCache::new();

        let update = cache.apply_pod_snapshot(pod_snapshot());

        assert_eq!(
            update,
            CacheUpdate {
                upserted: 1,
                removed: 0,
                ignored: 0,
            }
        );
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.pod_count(), 1);
        let binding = cache.bind_container(ID, BindingProvenance::Observed);
        assert!(matches!(binding, Binding::Bound { .. }));
    }

    #[test]
    fn pod_snapshot_replaces_old_container_ids_for_same_pod() {
        let mut cache = BindingCache::new();
        cache.apply_pod_snapshot(pod_snapshot());

        let new_id = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let mut pod = pod_snapshot();
        pod.containers = vec![ContainerStatusSnapshot::new(format!(
            "containerd://{new_id}"
        ))];
        let update = cache.apply_pod_snapshot(pod);

        assert_eq!(update.upserted, 1);
        assert_eq!(update.removed, 1);
        assert!(matches!(
            cache.bind_container(ID, BindingProvenance::Observed),
            Binding::Unbound {
                reason: UnboundReason::CacheMiss
            }
        ));
        assert!(matches!(
            cache.bind_container(new_id, BindingProvenance::Observed),
            Binding::Bound { .. }
        ));
    }

    #[test]
    fn pod_delete_removes_all_container_bindings() {
        let mut cache = BindingCache::new();
        cache.apply_pod_snapshot(pod_snapshot());

        let update = cache.remove_pod("pod-uid-1");

        assert_eq!(update.removed, 1);
        assert!(cache.is_empty());
        assert_eq!(cache.pod_count(), 0);
        // The FIFO index must not keep a tombstone for the removed container.
        assert_eq!(cache.insertion_order.len(), 0);
    }

    #[test]
    fn remove_purges_insertion_order() {
        let mut cache = BindingCache::new();
        cache.upsert(ID, metadata());
        assert_eq!(cache.insertion_order.len(), 1);

        cache.remove(ID);

        assert!(cache.is_empty());
        assert_eq!(cache.insertion_order.len(), 0);
    }

    #[test]
    fn churn_under_cap_does_not_leak_insertion_order() {
        // Add + remove the same pod's container repeatedly, always staying under
        // the capacity cap. Without purging on removal the FIFO index would grow
        // one tombstone per cycle (the bug this guards against).
        let mut cache = BindingCache::with_max_containers(1024);
        for _ in 0..100 {
            cache.apply_pod_snapshot(pod_snapshot());
            cache.remove_pod("pod-uid-1");
        }

        assert!(cache.is_empty());
        assert_eq!(cache.insertion_order.len(), 0);
    }

    #[test]
    fn pod_snapshot_ignores_malformed_container_ids() {
        let mut cache = BindingCache::new();
        let mut pod = pod_snapshot();
        pod.containers = vec![ContainerStatusSnapshot::new("containerd://not-a-container")];

        let update = cache.apply_pod_snapshot(pod);

        assert_eq!(update.ignored, 1);
        assert!(cache.is_empty());
    }
}

use std::collections::HashSet;
use std::sync::{Arc, RwLock};

use anyhow::Result;
use futures::StreamExt;
use k8s_openapi::api::core::v1::{ContainerStatus, Pod};
use kube::runtime::watcher::{watcher, Config, Event};
use kube::{Api, Client, ResourceExt};
use tracing::{debug, info, warn};

use jalki_enrich::{BindingCache, ContainerStatusSnapshot, PodSnapshot, WorkloadOwner};

/// Watch pods assigned to one node and keep the runtime binding cache current.
pub async fn run_pod_binding_watcher(
    client: Client,
    node_name: String,
    cache: Arc<RwLock<BindingCache>>,
) -> Result<()> {
    let pods: Api<Pod> = Api::all(client);
    let config = Config::default().fields(&format!("spec.nodeName={node_name}"));
    let mut stream = watcher(pods, config).boxed();
    let mut known_pods: HashSet<String> = HashSet::new();
    let mut init_seen: Option<HashSet<String>> = None;

    info!(node = %node_name, "starting pod binding watcher");

    while let Some(event) = stream.next().await {
        match event {
            Ok(Event::Init) => {
                init_seen = Some(HashSet::new());
                debug!(node = %node_name, "pod watcher init started");
            }
            Ok(Event::InitApply(pod)) => {
                if let Some(uid) = apply_pod_to_cache(&pod, &cache)? {
                    if let Some(seen) = init_seen.as_mut() {
                        seen.insert(uid.clone());
                    }
                    known_pods.insert(uid);
                }
            }
            Ok(Event::InitDone) => {
                if let Some(seen) = init_seen.take() {
                    let stale: Vec<_> = known_pods.difference(&seen).cloned().collect();
                    for uid in stale {
                        remove_pod_from_cache(&uid, &cache)?;
                        known_pods.remove(&uid);
                    }
                    debug!(node = %node_name, pods = known_pods.len(), "pod watcher init completed");
                }
            }
            Ok(Event::Apply(pod)) => {
                if let Some(uid) = apply_pod_to_cache(&pod, &cache)? {
                    known_pods.insert(uid);
                }
            }
            Ok(Event::Delete(pod)) => {
                if let Some(uid) = pod.metadata.uid.as_deref() {
                    remove_pod_from_cache(uid, &cache)?;
                    known_pods.remove(uid);
                }
            }
            Err(err) => {
                warn!(node = %node_name, error = %err, "pod watcher error; kube runtime will retry");
            }
        }
    }

    Ok(())
}

fn apply_pod_to_cache(pod: &Pod, cache: &Arc<RwLock<BindingCache>>) -> Result<Option<String>> {
    let Some(snapshot) = pod_to_snapshot(pod) else {
        return Ok(None);
    };
    let uid = snapshot.pod_uid.clone();

    let update = cache
        .write()
        .map_err(|_| anyhow::anyhow!("binding cache lock poisoned"))?
        .apply_pod_snapshot(snapshot);

    debug!(
        pod_uid = %uid,
        upserted = update.upserted,
        removed = update.removed,
        ignored = update.ignored,
        "applied pod snapshot to binding cache"
    );

    Ok(Some(uid))
}

fn remove_pod_from_cache(uid: &str, cache: &Arc<RwLock<BindingCache>>) -> Result<()> {
    let update = cache
        .write()
        .map_err(|_| anyhow::anyhow!("binding cache lock poisoned"))?
        .remove_pod(uid);
    debug!(pod_uid = %uid, removed = update.removed, "removed pod from binding cache");
    Ok(())
}

pub fn pod_to_snapshot(pod: &Pod) -> Option<PodSnapshot> {
    let pod_uid = pod.metadata.uid.clone()?;
    let pod_name = pod.metadata.name.clone()?;
    let namespace = pod.namespace()?;
    let service_account = pod
        .spec
        .as_ref()
        .and_then(|spec| spec.service_account_name.clone());
    let mut containers = Vec::new();

    if let Some(status) = &pod.status {
        collect_container_statuses(&mut containers, status.container_statuses.as_deref());
        collect_container_statuses(&mut containers, status.init_container_statuses.as_deref());
        collect_container_statuses(
            &mut containers,
            status.ephemeral_container_statuses.as_deref(),
        );
    }

    Some(PodSnapshot {
        pod_uid,
        pod_name,
        namespace,
        service_account,
        owner: controlling_owner(pod),
        containers,
    })
}

/// The owner marked `controller: true`, not simply the first reference.
///
/// A pod may carry several `ownerReferences` but at most one controller, and
/// only that one is the workload that manages it. Taking `[0]` happens to be
/// right in the common single-reference case and quietly wrong the moment
/// anything else adds a reference — the kind of bug that shows up as evidence
/// attributed to the wrong workload rather than as an error.
fn controlling_owner(pod: &Pod) -> Option<WorkloadOwner> {
    let owner = pod
        .metadata
        .owner_references
        .as_ref()?
        .iter()
        .find(|r| r.controller.unwrap_or(false))?;
    if owner.kind.is_empty() || owner.name.is_empty() || owner.uid.is_empty() {
        return None;
    }
    Some(WorkloadOwner {
        kind: owner.kind.clone(),
        name: owner.name.clone(),
        uid: owner.uid.clone(),
    })
}

fn collect_container_statuses(
    out: &mut Vec<ContainerStatusSnapshot>,
    statuses: Option<&[ContainerStatus]>,
) {
    let Some(statuses) = statuses else {
        return;
    };

    out.extend(
        statuses
            .iter()
            .filter_map(|status| status.container_id.as_ref())
            .cloned()
            .map(ContainerStatusSnapshot::new),
    );
}

#[cfg(test)]
mod tests {
    use k8s_openapi::api::core::v1::{ContainerStatus, PodSpec, PodStatus};
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

    use super::*;

    const ID: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn container_status(container_id: &str) -> ContainerStatus {
        ContainerStatus {
            container_id: Some(container_id.into()),
            name: "app".into(),
            ..Default::default()
        }
    }

    fn pod() -> Pod {
        Pod {
            metadata: ObjectMeta {
                uid: Some("pod-uid-1".into()),
                name: Some("runner-1".into()),
                namespace: Some("default".into()),
                ..Default::default()
            },
            spec: Some(PodSpec {
                service_account_name: Some("builder".into()),
                ..Default::default()
            }),
            status: Some(PodStatus {
                container_statuses: Some(vec![container_status(&format!("containerd://{ID}"))]),
                ..Default::default()
            }),
        }
    }

    #[test]
    fn pod_to_snapshot_extracts_binding_fields() {
        let snapshot = pod_to_snapshot(&pod()).unwrap();

        assert_eq!(snapshot.pod_uid, "pod-uid-1");
        assert_eq!(snapshot.pod_name, "runner-1");
        assert_eq!(snapshot.namespace, "default");
        assert_eq!(snapshot.service_account.as_deref(), Some("builder"));
        assert_eq!(snapshot.containers.len(), 1);
        assert_eq!(
            snapshot.containers[0].container_id,
            format!("containerd://{ID}")
        );
    }

    #[test]
    fn pod_without_uid_is_ignored() {
        let mut pod = pod();
        pod.metadata.uid = None;

        assert!(pod_to_snapshot(&pod).is_none());
    }

    /// A pod may carry several `ownerReferences` but at most one controller.
    /// Taking `[0]` is right by luck in the common case and wrong the moment
    /// anything else adds a reference — and it fails as evidence attributed to
    /// the wrong workload, not as an error.
    #[test]
    fn the_controlling_owner_is_chosen_not_the_first_reference() {
        let mut pod = Pod::default();
        pod.metadata.uid = Some("pod-uid-1".into());
        pod.metadata.name = Some("runner-abc123".into());
        pod.metadata.namespace = Some("arc-runners".into());
        pod.metadata.owner_references = Some(vec![
            owner_ref("SomethingElse", "decorator", "uid-not-this", Some(false)),
            owner_ref("ReplicaSet", "runner-5f9c", "uid-rs-1", Some(true)),
        ]);

        let snapshot = pod_to_snapshot(&pod).expect("snapshot");
        let owner = snapshot.owner.expect("controlling owner");
        assert_eq!(owner.kind, "ReplicaSet");
        assert_eq!(owner.name, "runner-5f9c");
        assert_eq!(owner.uid, "uid-rs-1");
    }

    #[test]
    fn a_pod_with_no_controller_has_no_owner() {
        // A bare pod — kubectl run, a static pod — is owned by nobody, and
        // inventing an owner for it would be worse than reporting none.
        let mut pod = Pod::default();
        pod.metadata.uid = Some("pod-uid-2".into());
        pod.metadata.name = Some("adhoc".into());
        pod.metadata.namespace = Some("workloads".into());
        assert!(pod_to_snapshot(&pod).expect("snapshot").owner.is_none());

        pod.metadata.owner_references =
            Some(vec![owner_ref("ReplicaSet", "rs", "uid", Some(false))]);
        assert!(
            pod_to_snapshot(&pod).expect("snapshot").owner.is_none(),
            "a non-controller reference is not the owning workload"
        );
    }

    #[test]
    fn an_incomplete_owner_reference_is_dropped() {
        // Half an identity is worse than none: it would bind evidence to a
        // workload that cannot be looked up.
        let mut pod = Pod::default();
        pod.metadata.uid = Some("pod-uid-3".into());
        pod.metadata.name = Some("p".into());
        pod.metadata.namespace = Some("workloads".into());
        pod.metadata.owner_references = Some(vec![owner_ref("ReplicaSet", "rs", "", Some(true))]);
        assert!(pod_to_snapshot(&pod).expect("snapshot").owner.is_none());
    }

    #[test]
    fn the_owner_reaches_the_runtime_binding() {
        let mut pod = Pod::default();
        pod.metadata.uid = Some("pod-uid-4".into());
        pod.metadata.name = Some("runner-abc123".into());
        pod.metadata.namespace = Some("arc-runners".into());
        pod.metadata.owner_references = Some(vec![owner_ref(
            "DaemonSet",
            "jalki",
            "uid-ds-1",
            Some(true),
        )]);

        let binding = jalki_enrich::Binding::Bound {
            container_id: "containerd://abc".into(),
            metadata: pod_to_snapshot(&pod).expect("snapshot").metadata(),
            provenance: jalki_evidence::BindingProvenance::Observed,
        }
        .into_runtime_binding();

        match binding {
            jalki_evidence::RuntimeBinding::Bound {
                owner_kind,
                owner_name,
                owner_uid,
                ..
            } => {
                assert_eq!(owner_kind.as_deref(), Some("DaemonSet"));
                assert_eq!(owner_name.as_deref(), Some("jalki"));
                assert_eq!(owner_uid.as_deref(), Some("uid-ds-1"));
            }
            other => panic!("expected Bound, got {other:?}"),
        }
    }

    fn owner_ref(
        kind: &str,
        name: &str,
        uid: &str,
        controller: Option<bool>,
    ) -> k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference {
        k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference {
            api_version: "apps/v1".into(),
            kind: kind.into(),
            name: name.into(),
            uid: uid.into(),
            controller,
            block_owner_deletion: None,
        }
    }
}

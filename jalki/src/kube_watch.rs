use std::collections::HashSet;
use std::sync::{Arc, RwLock};

use anyhow::Result;
use futures::StreamExt;
use k8s_openapi::api::core::v1::{ContainerStatus, Pod};
use kube::runtime::watcher::{watcher, Config, Event};
use kube::{Api, Client, ResourceExt};
use tracing::{debug, info, warn};

use jalki_enrich::{BindingCache, ContainerStatusSnapshot, PodSnapshot};

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
    let namespace = pod.namespace()?;
    let labels = pod.labels().clone();
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
        namespace,
        service_account,
        labels,
        containers,
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
    use std::collections::BTreeMap;

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
        let mut labels = BTreeMap::new();
        labels.insert("actions.github.com/run-id".into(), "123456".into());
        Pod {
            metadata: ObjectMeta {
                uid: Some("pod-uid-1".into()),
                namespace: Some("default".into()),
                labels: Some(labels),
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
        assert_eq!(snapshot.namespace, "default");
        assert_eq!(snapshot.service_account.as_deref(), Some("builder"));
        assert_eq!(
            snapshot
                .labels
                .get("actions.github.com/run-id")
                .map(String::as_str),
            Some("123456")
        );
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
}

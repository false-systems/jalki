//! ADR-0004 D2-a: project a Plane-B [`Occurrence`] into Vartio's **native
//! runtime map** — the wire shape `Importer.Jalki` consumes.
//!
//! The importer reads jälki evidence as native event data plus runtime binding
//! at the **top level** of the item payload, not as a FALSE/Ahti Occurrence
//! wrapper. Plane-B neutrality (ADR-0002 §D4) survives as *content*: nothing
//! here adds interpretation — fields are re-homed, never invented. The
//! authoritative key names are Vartio's `fixtures/jalki/*.json` fixtures
//! (`occurrence_type`, `destination_ip`/`destination_port`, numeric
//! `kernel_time_ns`, string `cgroup_id`, …).
//!
//! Field sources, by occurrence anatomy:
//! - identity/time: `id` → `event_id`, `timestamp` → `observed_at` +
//!   `agent_recv_time`, label `observed_at_ns` → numeric `kernel_time_ns`
//! - binding labels: `k8s_pod_uid` → `pod_uid`, `k8s_container_id` →
//!   `container_id`, `k8s_namespace`, `k8s_service_account` →
//!   `service_account`, `github_run_id`, `evidence_level`
//! - process block: `pid`, `ppid`, `command` → `comm`, `uid`; labels `gid`
//!   (numeric) and `argv_hash`; `exe` from the `resource_ref_id` label when
//!   `resource_ref_kind == "executable"`
//! - network block: `protocol`, `source_ip`/`source_port`,
//!   `destination_ip`/`destination_port`; label `tcp_state`
//! - outcome → `state` (`success`/`failure`/…)

use false_protocol::Occurrence;
use serde_json::{json, Map, Value};

/// Straight label→key copies (label name, native key).
const LABEL_KEYS: &[(&str, &str)] = &[
    ("node_id", "node_id"),
    ("k8s_pod_uid", "pod_uid"),
    ("k8s_container_id", "container_id"),
    ("k8s_namespace", "k8s_namespace"),
    ("k8s_service_account", "service_account"),
    ("github_run_id", "github_run_id"),
    ("cgroup_id", "cgroup_id"),
    ("argv_hash", "argv_hash"),
    ("tcp_state", "tcp_state"),
    ("cluster_id", "cluster_id"),
    ("kernel_release", "kernel_release"),
    ("evidence_level", "evidence_level"),
];

/// Build the native runtime map for one Plane-B occurrence.
pub fn native_runtime_item(occ: &Occurrence) -> Map<String, Value> {
    let mut item = Map::new();

    item.insert(
        "occurrence_type".into(),
        json!(occ.occurrence_type.as_str()),
    );
    item.insert("event_id".into(), json!(occ.id.to_string()));

    let ts = occ.timestamp.to_rfc3339();
    item.insert("observed_at".into(), json!(ts));
    item.insert("agent_recv_time".into(), json!(ts));

    let labels = &occ.labels;
    if let Some(ns) = labels
        .get("observed_at_ns")
        .and_then(|v| v.parse::<u64>().ok())
    {
        item.insert("kernel_time_ns".into(), json!(ns));
    }
    for (label, key) in LABEL_KEYS {
        if let Some(value) = labels.get(*label) {
            item.insert((*key).into(), json!(value));
        }
    }
    if let Some(gid) = labels.get("gid").and_then(|v| v.parse::<u64>().ok()) {
        item.insert("gid".into(), json!(gid));
    }
    if labels.get("resource_ref_kind").map(String::as_str) == Some("executable") {
        if let Some(exe) = labels.get("resource_ref_id") {
            item.insert("exe".into(), json!(exe));
        }
    }

    // File family (ADR-0005). `path` is asserted ONLY for a resolved file
    // identity (`kernel.file.open`); an attempt's user-requested string rides
    // `requested_path` + `path_resolution=unresolved`, never `path`.
    if labels.get("resource_ref_kind").map(String::as_str) == Some("file") {
        if let Some(path) = labels.get("resource_ref_id") {
            item.insert("path".into(), json!(path));
        }
    }
    for key in ["requested_path", "path_resolution", "coverage", "flags"] {
        if let Some(value) = labels.get(key) {
            item.insert(key.into(), json!(value));
        }
    }
    if labels.get("path_truncated").map(String::as_str) == Some("true") {
        item.insert("path_truncated".into(), json!(true));
    }
    // Wire errno is the positive number (`tcp_close_errno.json` convention);
    // the `errno_num` label is the raw negative kernel return.
    if let Some(errno) = labels
        .get("errno_num")
        .and_then(|v| v.parse::<i64>().ok())
        .filter(|ret| *ret < 0)
    {
        item.insert("errno".into(), json!(-errno));
    }

    if let Some(process) = &occ.process_data {
        item.insert("pid".into(), json!(process.pid));
        if let Some(ppid) = process.ppid {
            item.insert("ppid".into(), json!(ppid));
        }
        item.insert("comm".into(), json!(process.command));
        item.insert("uid".into(), json!(process.uid));
    }

    if let Some(network) = &occ.network_data {
        item.insert("protocol".into(), json!(network.protocol));
        item.insert("source_ip".into(), json!(network.src_ip));
        item.insert("source_port".into(), json!(network.src_port));
        item.insert("destination_ip".into(), json!(network.dst_ip));
        item.insert("destination_port".into(), json!(network.dst_port));
        if let Some(count) = network.retransmit_count {
            item.insert("count".into(), json!(count));
        }
    }

    if let Some(outcome) = &occ.outcome {
        if let Ok(state) = serde_json::to_value(outcome) {
            item.insert("state".into(), state);
        }
    }

    item
}

#[cfg(test)]
mod tests {
    use super::*;
    use false_protocol::{NetworkEventData, Outcome, ProcessEventData};

    fn base_occ(occurrence_type: &str) -> Occurrence {
        let mut occ = Occurrence::new("jalki", occurrence_type);
        for (k, v) in [
            ("node_id", "node-vox"),
            ("cluster_id", "cluster-1"),
            ("observed_at_ns", "657653680687218"),
            ("k8s_pod_uid", "pod-uid-1"),
            ("k8s_container_id", "containerd://abc"),
            ("k8s_namespace", "workloads"),
            ("cgroup_id", "913488225941"),
        ] {
            occ.labels.insert(k.into(), v.into());
        }
        occ
    }

    #[test]
    fn tcp_connect_projects_to_the_fixture_shape() {
        let mut occ = base_occ("kernel.tcp.connect");
        occ.outcome = Some(Outcome::Success);
        occ.network_data = Some(NetworkEventData {
            protocol: "tcp".into(),
            src_ip: "10.244.3.21".into(),
            dst_ip: "10.42.7.19".into(),
            src_port: 41822,
            dst_port: 443,
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
        occ.process_data = Some(ProcessEventData {
            pid: 4242,
            ppid: None,
            command: "kubectl".into(),
            args: None,
            uid: 0,
            exit_code: None,
        });

        let m = native_runtime_item(&occ);
        assert_eq!(m["occurrence_type"], "kernel.tcp.connect");
        assert_eq!(m["node_id"], "node-vox");
        assert_eq!(m["kernel_time_ns"], 657653680687218u64);
        assert_eq!(m["pod_uid"], "pod-uid-1");
        assert_eq!(m["container_id"], "containerd://abc");
        assert_eq!(m["pid"], 4242);
        assert_eq!(m["comm"], "kubectl");
        assert_eq!(m["protocol"], "tcp");
        assert_eq!(m["destination_ip"], "10.42.7.19");
        assert_eq!(m["destination_port"], 443);
        assert_eq!(m["state"], "success");
        assert!(m.contains_key("event_id") && m.contains_key("agent_recv_time"));
        // native shape: binding is top-level, no occurrence wrapper remains
        assert!(!m.contains_key("labels") && !m.contains_key("reasoning"));
    }

    #[test]
    fn exec_carries_exe_gid_and_argv_hash() {
        let mut occ = base_occ("kernel.process.exec");
        occ.labels.insert("gid".into(), "1001".into());
        occ.labels
            .insert("argv_hash".into(), "sha256:6cdb1f73c8f42df8".into());
        occ.labels
            .insert("resource_ref_kind".into(), "executable".into());
        occ.labels
            .insert("resource_ref_id".into(), "/usr/local/bin/kubectl".into());
        occ.process_data = Some(ProcessEventData {
            pid: 1707354,
            ppid: Some(1707001),
            command: "kubectl".into(),
            args: None,
            uid: 1001,
            exit_code: None,
        });

        let m = native_runtime_item(&occ);
        assert_eq!(m["exe"], "/usr/local/bin/kubectl");
        assert_eq!(m["gid"], 1001);
        assert_eq!(m["argv_hash"], "sha256:6cdb1f73c8f42df8");
        assert_eq!(m["ppid"], 1707001);
        assert_eq!(m["uid"], 1001);
    }

    #[test]
    fn file_open_projects_resolved_path_coverage_and_errno() {
        let mut occ = base_occ("kernel.file.open");
        occ.outcome = Some(Outcome::Failure);
        for (k, v) in [
            ("resource_ref_kind", "file"),
            ("resource_ref_id", "/etc/shadow"),
            ("coverage", "lsm_gated"),
            ("flags", "32768"),
            ("result", "denied"),
            ("errno_num", "-13"), // EACCES, raw negative kernel ret
        ] {
            occ.labels.insert(k.into(), v.into());
        }
        occ.process_data = Some(ProcessEventData {
            pid: 4242,
            ppid: None,
            command: "cat".into(),
            args: None,
            uid: 1001,
            exit_code: None,
        });

        let m = native_runtime_item(&occ);
        assert_eq!(m["path"], "/etc/shadow");
        assert_eq!(m["coverage"], "lsm_gated");
        assert_eq!(m["flags"], "32768");
        assert_eq!(m["errno"], 13, "wire errno is positive (fixture convention)");
        assert_eq!(m["state"], "failure");
        assert!(!m.contains_key("requested_path"));
        assert!(!m.contains_key("exe"), "a file ref is not an exe");
    }

    #[test]
    fn open_attempt_projects_requested_path_never_path() {
        let mut occ = base_occ("kernel.file.open_attempt");
        occ.outcome = Some(Outcome::Failure);
        for (k, v) in [
            ("requested_path", "/var/run/secrets/missing"),
            ("path_resolution", "unresolved"),
            ("path_truncated", "true"),
            ("errno_num", "-2"), // ENOENT
        ] {
            occ.labels.insert(k.into(), v.into());
        }
        occ.process_data = Some(ProcessEventData {
            pid: 7,
            ppid: None,
            command: "cat".into(),
            args: None,
            uid: 0,
            exit_code: None,
        });

        let m = native_runtime_item(&occ);
        assert_eq!(m["requested_path"], "/var/run/secrets/missing");
        assert_eq!(m["path_resolution"], "unresolved");
        assert_eq!(m["path_truncated"], true);
        assert_eq!(m["errno"], 2);
        // The unresolved string must never be asserted as a file identity.
        assert!(!m.contains_key("path"));
    }

    #[test]
    fn non_executable_resource_ref_is_not_exe() {
        let mut occ = base_occ("kernel.tcp.connect");
        occ.labels
            .insert("resource_ref_kind".into(), "network_endpoint".into());
        occ.labels
            .insert("resource_ref_id".into(), "10.42.7.19:443".into());
        let m = native_runtime_item(&occ);
        assert!(!m.contains_key("exe"));
    }
}

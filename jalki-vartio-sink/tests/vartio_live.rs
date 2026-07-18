//! LIVE integration test — jälki `VartioSink` against a *real* Vartio
//! `SourceIngress.ReceiveBatch` server (not the in-crate mock).
//!
//! Gated on env, like vartio's own `:live_ahti` tests, so it never runs in CI:
//!   VARTIO_LIVE_ENDPOINT=http://127.0.0.1:50061 \
//!   VARTIO_LIVE_TOKEN=live-test-token \
//!   cargo test -p jalki-vartio-sink --test vartio_live -- --nocapture
//!
//! When either var is unset, the tests return early (pass) so a plain
//! `cargo test` is unaffected.

use std::collections::BTreeMap;

use jalki_evidence::{
    BindingProvenance, EvidenceBatch, EvidenceRecord, EvidenceSink, HookKind, KernelEvent,
    ProbeMetadata, ProducerMetadata, RuntimeBinding, SinkError, TcpConnectEvent,
};
use jalki_vartio_sink::{VartioSink, VartioSinkConfig};

fn live_env() -> Option<(String, String)> {
    match (
        std::env::var("VARTIO_LIVE_ENDPOINT"),
        std::env::var("VARTIO_LIVE_TOKEN"),
    ) {
        (Ok(e), Ok(t)) if !e.is_empty() && !t.is_empty() => Some((e, t)),
        _ => {
            eprintln!("SKIP: set VARTIO_LIVE_ENDPOINT + VARTIO_LIVE_TOKEN to run the live test");
            None
        }
    }
}

fn producer() -> ProducerMetadata {
    ProducerMetadata::new("cluster-live", "node-vox", "6.19-live")
}

fn probe() -> ProbeMetadata {
    ProbeMetadata {
        probe_id: "tcp_connect".to_string(),
        probe_version: "1".to_string(),
        probe_family: "tcp".to_string(),
        hook_kind: HookKind::Fexit,
        kernel_function: "tcp_connect".to_string(),
    }
}

/// Real capture-path record: TcpConnect event → normalize → bind. What the
/// daemon would actually ship.
fn bound_record() -> EvidenceRecord {
    let event = KernelEvent::TcpConnect(TcpConnectEvent {
        observed_at_ns: 657_653_680_687_218,
        pid: 4242,
        tid: 4242,
        src_ip: "10.244.3.21".parse().unwrap(),
        dst_ip: "10.42.7.19".parse().unwrap(),
        src_port: 41822,
        dst_port: 443,
        addr_family: 2,
        ret: 0,
        cgroup_id: 77,
        comm: "kubectl".to_string(),
        netns: 4_026_531_993,
    });
    let mut normalized = event.normalize(probe(), "cluster-live");
    normalized
        .records
        .remove(0)
        .with_runtime_binding(RuntimeBinding::Bound {
            container_id: "containerd://abc".to_string(),
            pod_uid: Some("pod-uid-live-1".to_string()),
            namespace: Some("workloads".to_string()),
            service_account: None,
            labels: BTreeMap::new(),
            provenance: BindingProvenance::Observed,
        })
}

/// ADR-0004 D1 regression: a sink with *no* token must be refused by the real,
/// fail-closed ingress as a terminal auth failure.
#[tokio::test]
async fn live_tokenless_sink_is_unauthenticated() {
    let Some((endpoint, _token)) = live_env() else {
        return;
    };
    let sink = VartioSink::connect(VartioSinkConfig::new(endpoint, "jalki-live-1"))
        .await
        .expect("connect");
    let err = sink
        .append_batch(EvidenceBatch::new(producer(), vec![bound_record()]))
        .await
        .expect_err("tokenless sink must be refused by the fail-closed ingress");
    eprintln!("LIVE tokenless result: {err:?}");
    assert!(
        matches!(err, SinkError::Unauthorized { .. }),
        "expected Unauthorized from the real ingress, got {err:?}"
    );
}

/// The ADR-0004 config surface end-to-end: token on the wire (D1-a) + native
/// runtime-map payload (D2-a) → the real importer ACCEPTS the item.
#[tokio::test]
async fn live_configured_sink_delivers_and_is_accepted() {
    let Some((endpoint, token)) = live_env() else {
        return;
    };
    let cfg = VartioSinkConfig::new(endpoint, "jalki-live-1").with_ingress_token(token);
    let sink = VartioSink::connect(cfg).await.expect("connect");

    let record = bound_record();
    let result = sink
        .append_batch(EvidenceBatch::new(producer(), vec![record.clone()]))
        .await
        .expect("the real ingress accepts an authenticated native-map item");
    eprintln!("LIVE configured-sink result: {result:?}");
    assert_eq!(result.accepted_count, 1, "item accepted end-to-end");
    assert_eq!(result.rejected_count, 0);

    // Idempotent replay: the *same* record (same idempotency key) re-sent must
    // settle as a duplicate, which the sink counts as delivered with a visible
    // warning — never a reject.
    let replay = sink
        .append_batch(EvidenceBatch::new(producer(), vec![record]))
        .await
        .expect("replay settles");
    eprintln!("LIVE replay result: {replay:?}");
    assert_eq!(replay.accepted_count, 1, "duplicate counts as delivered");
    assert_eq!(replay.rejected_count, 0, "replay is never a reject");
    assert!(
        replay.warnings.iter().any(|w| w.contains("duplicate")),
        "duplicate split is visible: {:?}",
        replay.warnings
    );
}

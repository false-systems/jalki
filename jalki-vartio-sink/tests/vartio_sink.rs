//! Integration tests: drive `VartioSink` over real gRPC against an in-crate
//! `SourceIngress` test receiver. Verifies the wire contract, all-or-retry,
//! fail-fast identity, the Plane-B boundary, and the ADR-0004 config surface
//! (bearer auth + native payload shape).

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use jalki_evidence::{
    AppendResult, BindingProvenance, EvidenceBatch, EvidenceRecord, EvidenceSink, GapReport,
    HookKind, KernelEvent, ProbeMetadata, ProducerMetadata, RetryBuffer, RuntimeBinding, SinkError,
    TcpConnectEvent, UnboundReason,
};
use jalki_vartio_sink::proto::source_ingress_server::{SourceIngress, SourceIngressServer};
use jalki_vartio_sink::proto::{
    ProviderEvidenceBatch, ReasonSummary, ReceiveBatchResponse, RejectReason,
};
use jalki_vartio_sink::{VartioSink, VartioSinkConfig};
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::Server;
use tonic::{Request, Response, Status};

#[derive(Clone)]
struct TestReceiver {
    received: Arc<Mutex<Vec<ProviderEvidenceBatch>>>,
    auth_headers: Arc<Mutex<Vec<Option<String>>>>,
    retryable: bool,
    duplicates: u32,
    rejected: u32,
}

#[tonic::async_trait]
impl SourceIngress for TestReceiver {
    async fn receive_batch(
        &self,
        req: Request<ProviderEvidenceBatch>,
    ) -> Result<Response<ReceiveBatchResponse>, Status> {
        let auth = req
            .metadata()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .map(String::from);
        self.auth_headers.lock().unwrap().push(auth);

        let batch = req.into_inner();
        let n = batch.items.len() as u32;
        let batch_id = batch.batch_id.clone();
        self.received.lock().unwrap().push(batch);
        let duplicates = self.duplicates.min(n);
        let rejected = self.rejected.min(n - duplicates);
        let error_summaries = if !self.retryable && rejected > 0 {
            vec![ReasonSummary {
                reason: RejectReason::ValidationFailed as i32,
                count: rejected,
            }]
        } else {
            vec![]
        };
        Ok(Response::new(ReceiveBatchResponse {
            batch_id,
            accepted_count: if self.retryable {
                0
            } else {
                n - duplicates - rejected
            },
            duplicate_count: if self.retryable { 0 } else { duplicates },
            rejected_count: if self.retryable { 0 } else { rejected },
            items: vec![],
            error_summaries,
            retryable: self.retryable,
        }))
    }
}

struct ReceiverHandle {
    endpoint: String,
    received: Arc<Mutex<Vec<ProviderEvidenceBatch>>>,
    auth_headers: Arc<Mutex<Vec<Option<String>>>>,
}

async fn spawn_receiver(retryable: bool, duplicates: u32, rejected: u32) -> ReceiverHandle {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    serve_receiver(listener, retryable, duplicates, rejected)
}

/// Reserve an ephemeral port and release it, yielding an address nothing is
/// listening on — a sink's target that is *down*, without waiting on a timeout.
async fn reserved_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    addr
}

/// Bring a receiver up on a previously reserved address — used to let a sink
/// meet its target *after* it has already failed against it.
async fn spawn_receiver_at(addr: SocketAddr, retryable: bool) -> ReceiverHandle {
    let listener = TcpListener::bind(addr)
        .await
        .expect("reserved port is free to rebind");
    serve_receiver(listener, retryable, 0, 0)
}

fn serve_receiver(
    listener: TcpListener,
    retryable: bool,
    duplicates: u32,
    rejected: u32,
) -> ReceiverHandle {
    let received = Arc::new(Mutex::new(Vec::new()));
    let auth_headers = Arc::new(Mutex::new(Vec::new()));
    let receiver = TestReceiver {
        received: received.clone(),
        auth_headers: auth_headers.clone(),
        retryable,
        duplicates,
        rejected,
    };
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        Server::builder()
            .add_service(SourceIngressServer::new(receiver))
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .unwrap();
    });
    ReceiverHandle {
        endpoint: format!("http://{addr}"),
        received,
        auth_headers,
    }
}

/// Connect is lazy (jalki #38), so this no longer has to poll until the test
/// receiver is up — construction cannot fail on a reachable-or-not endpoint,
/// only on a malformed one.
async fn connect_cfg(cfg: VartioSinkConfig) -> VartioSink {
    VartioSink::connect(cfg)
        .await
        .expect("construction must succeed for a well-formed endpoint")
}

async fn connect(endpoint: String) -> VartioSink {
    connect_cfg(VartioSinkConfig::new(endpoint, "jalki-adapter-1")).await
}

fn producer() -> ProducerMetadata {
    ProducerMetadata::new("cluster-1", "node-vox", "6.19-test")
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

/// A record produced by the *real* normalize path (TcpConnect → Occurrence),
/// then bound — so the native wire projection carries genuine runtime fields.
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
    let mut normalized = event.normalize(probe(), "cluster-1");
    normalized
        .records
        .remove(0)
        .with_runtime_binding(RuntimeBinding::Bound {
            container_id: "containerd://abc".to_string(),
            pod_uid: Some("pod-uid-1".to_string()),
            pod_name: Some("runner-1".to_string()),
            namespace: Some("workloads".to_string()),
            service_account: None,
            owner_kind: None,
            owner_name: None,
            owner_uid: None,
            provenance: BindingProvenance::Observed,
        })
}

fn unbound_record() -> EvidenceRecord {
    let occurrence = false_protocol::Occurrence::new("jalki", "kernel.tcp.connect");
    EvidenceRecord {
        observed_at_ns: 1_000_000,
        pid: 1,
        cgroup_id: 0,
        probe: probe(),
        occurrence,
        binding: None,
    }
    .with_runtime_binding(RuntimeBinding::Unbound {
        reason: UnboundReason::HostProcess,
    })
}

#[tokio::test]
async fn delivers_a_bound_batch_with_the_wire_contract() {
    let rx = spawn_receiver(false, 0, 0).await;
    let sink = connect(rx.endpoint.clone()).await;

    let batch = EvidenceBatch::new(producer(), vec![bound_record(), bound_record()]);
    let batch_id = batch.batch_id.clone();
    let result = sink.append_batch(batch).await.expect("accepted");
    assert_eq!(result.accepted_count, 2);
    assert_eq!(result.rejected_count, 0);
    assert_eq!(result.watermark.unwrap().value, batch_id);

    let batches = rx.received.lock().unwrap();
    assert_eq!(batches.len(), 1);
    let wire = &batches[0];
    assert_eq!(wire.source_key, "jalki");
    assert_eq!(wire.provider, "jalki");
    assert_eq!(wire.namespace, "vartio-jalki");
    assert_eq!(wire.adapter_id, "jalki-adapter-1");
    assert_eq!(wire.cluster_id, "cluster-1");
    assert_eq!(wire.node_id, "node-vox");
    assert_eq!(wire.items.len(), 2);

    let item = &wire.items[0];
    assert_eq!(item.occurrence_type, "kernel.tcp.connect");
    assert!(
        item.idempotency_key
            .starts_with("jalki:cluster-1:node-vox:"),
        "source-scoped idempotency key, got {}",
        item.idempotency_key
    );
    // ADR-0004 D2-a: the payload is the native runtime map — binding and
    // runtime fields top-level, no FALSE Occurrence wrapper, no interpretation.
    let payload: serde_json::Value = serde_json::from_slice(&item.payload).unwrap();
    assert_eq!(payload["occurrence_type"], "kernel.tcp.connect");
    assert_eq!(payload["pod_uid"], "pod-uid-1");
    assert_eq!(payload["pod_name"], "runner-1");
    assert_eq!(payload["container_id"], "containerd://abc");
    assert_eq!(payload["k8s_namespace"], "workloads");
    assert_eq!(payload["node_id"], "node-vox");
    assert_eq!(payload["pid"], 4242);
    assert_eq!(payload["comm"], "kubectl");
    assert_eq!(payload["protocol"], "tcp");
    assert_eq!(payload["destination_ip"], "10.42.7.19");
    assert_eq!(payload["destination_port"], 443);
    assert_eq!(payload["kernel_time_ns"], 657_653_680_687_218u64);
    assert!(payload.get("event_id").is_some());
    assert!(payload.get("agent_recv_time").is_some());
    assert!(
        payload.get("labels").is_none() && payload.get("reasoning").is_none(),
        "native shape carries no occurrence wrapper or interpretation"
    );
    // No token configured — nothing rides the authorization header.
    assert_eq!(rx.auth_headers.lock().unwrap().as_slice(), &[None]);
}

#[tokio::test]
async fn bearer_token_rides_the_authorization_header() {
    let rx = spawn_receiver(false, 0, 0).await;
    let cfg = VartioSinkConfig::new(rx.endpoint.clone(), "jalki-adapter-1")
        .with_ingress_token("live-test-token");
    let sink = connect_cfg(cfg).await;

    sink.append_batch(EvidenceBatch::new(producer(), vec![bound_record()]))
        .await
        .expect("accepted");

    assert_eq!(
        rx.auth_headers.lock().unwrap().as_slice(),
        &[Some("Bearer live-test-token".to_string())],
        "ADR-0004 D1-a: the configured token is presented as a bearer credential"
    );
}

/// A record whose occurrence type the importer does not accept — a probe the
/// daemon could capture but the `vartio-jalki` contract does not cover.
fn unsupported_type_record() -> EvidenceRecord {
    let occurrence = false_protocol::Occurrence::new("jalki", "kernel.sched.switch");
    EvidenceRecord {
        observed_at_ns: 1_000_000,
        pid: 4242,
        cgroup_id: 77,
        probe: probe(),
        occurrence,
        binding: None,
    }
    .with_runtime_binding(RuntimeBinding::Bound {
        container_id: "containerd://abc".to_string(),
        pod_uid: Some("pod-uid-1".to_string()),
        pod_name: Some("runner-1".to_string()),
        namespace: Some("workloads".to_string()),
        service_account: None,
        owner_kind: None,
        owner_name: None,
        owner_uid: None,
        provenance: BindingProvenance::Observed,
    })
}

#[tokio::test]
async fn importer_unsupported_types_are_dropped_with_a_warning() {
    let rx = spawn_receiver(false, 0, 0).await;
    let sink = connect(rx.endpoint.clone()).await;

    // One supported (tcp.connect) + one unsupported (sched.switch) — only the
    // supported one crosses the wire; the drop is a visible warning, not a
    // reject and not silent.
    let result = sink
        .append_batch(EvidenceBatch::new(
            producer(),
            vec![bound_record(), unsupported_type_record()],
        ))
        .await
        .expect("accepted");
    assert_eq!(
        result.accepted_count, 1,
        "only the supported type delivered"
    );
    assert_eq!(
        result.rejected_count, 0,
        "unsupported is dropped, not rejected"
    );
    assert!(
        result
            .warnings
            .iter()
            .any(|w| w.contains("unsupported-by-importer") && w.contains("kernel.sched.switch")),
        "the drop is visible: {:?}",
        result.warnings
    );

    let batches = rx.received.lock().unwrap();
    assert_eq!(batches[0].items.len(), 1, "only 1 item on the wire");
    assert_eq!(batches[0].items[0].occurrence_type, "kernel.tcp.connect");
}

#[tokio::test]
async fn agent_gap_crosses_the_wire_without_runtime_binding() {
    let rx = spawn_receiver(false, 0, 0).await;
    let sink = connect(rx.endpoint.clone()).await;
    let batch = GapReport {
        cause: "ringbuffer_overflow".into(),
        affected_probes: vec!["kernel.tcp.connect".into()],
        dropped_records: 7,
        dropped_reliability: 0,
        dropped_attribution: 7,
        gap_start_ns: 10,
        gap_end_ns: 20,
    }
    .into_batch(producer());
    let result = sink.append_batch(batch).await.expect("accepted");
    assert_eq!(result.accepted_count, 1);

    let batches = rx.received.lock().unwrap();
    let item = &batches[0].items[0];
    assert_eq!(item.occurrence_type, "jalki.agent.gap");
    let payload: serde_json::Value = serde_json::from_slice(&item.payload).unwrap();
    assert_eq!(payload["cause"], "ringbuffer_overflow");
    assert_eq!(payload["dropped_records"], 7);
    assert_eq!(payload["dropped_reliability"], 0);
    assert_eq!(payload["dropped_attribution"], 7);
    assert_eq!(payload["gap_start_ns"], 10);
    assert_eq!(payload["gap_end_ns"], 20);
    assert_eq!(
        payload["affected_probes"],
        serde_json::json!(["kernel.tcp.connect"])
    );
    assert!(payload.get("event_id").is_some());
    assert!(payload.get("node_id").is_some());
    assert!(payload.get("cluster_id").is_some());
    assert!(payload.get("pod_uid").is_none());
    assert!(payload.get("container_id").is_none());
}

/// A bound `kernel.file.open_attempt` record — importer-supported, but gated
/// behind `send_file_types` (ADR-0005 §4).
fn file_family_record() -> EvidenceRecord {
    let occurrence = false_protocol::Occurrence::new("jalki", "kernel.file.open_attempt");
    EvidenceRecord {
        observed_at_ns: 2_000_000,
        pid: 7,
        cgroup_id: 77,
        probe: probe(),
        occurrence,
        binding: None,
    }
    .with_runtime_binding(RuntimeBinding::Bound {
        container_id: "containerd://abc".to_string(),
        pod_uid: Some("pod-uid-1".to_string()),
        pod_name: Some("runner-1".to_string()),
        namespace: Some("workloads".to_string()),
        service_account: None,
        owner_kind: None,
        owner_name: None,
        owner_uid: None,
        provenance: BindingProvenance::Observed,
    })
}

#[tokio::test]
async fn file_family_is_gated_off_by_default_with_a_config_warning() {
    let rx = spawn_receiver(false, 0, 0).await;
    let sink = connect(rx.endpoint.clone()).await;

    let result = sink
        .append_batch(EvidenceBatch::new(
            producer(),
            vec![bound_record(), file_family_record()],
        ))
        .await
        .expect("accepted");
    assert_eq!(result.accepted_count, 1, "only the tcp record delivered");
    assert!(
        result.warnings.iter().any(|w| w.contains("gated off")
            && w.contains("JALKI_VARTIO_FILE_TYPES")
            && w.contains("kernel.file.open_attempt")),
        "the gate drop is visible and names the remedy: {:?}",
        result.warnings
    );

    let batches = rx.received.lock().unwrap();
    assert_eq!(batches[0].items.len(), 1);
    assert_eq!(batches[0].items[0].occurrence_type, "kernel.tcp.connect");
}

#[tokio::test]
async fn file_family_is_delivered_when_enabled() {
    let rx = spawn_receiver(false, 0, 0).await;
    let cfg = VartioSinkConfig::new(rx.endpoint.clone(), "jalki-adapter-1").with_file_types(true);
    let sink = connect_cfg(cfg).await;

    let result = sink
        .append_batch(EvidenceBatch::new(producer(), vec![file_family_record()]))
        .await
        .expect("accepted");
    assert_eq!(result.accepted_count, 1);
    assert!(
        result.warnings.iter().all(|w| !w.contains("gated off")),
        "no gate warning when enabled: {:?}",
        result.warnings
    );

    let batches = rx.received.lock().unwrap();
    assert_eq!(
        batches[0].items[0].occurrence_type,
        "kernel.file.open_attempt"
    );
}

#[tokio::test]
async fn duplicates_count_as_accepted_with_a_warning() {
    let rx = spawn_receiver(false, 1, 0).await;
    let sink = connect(rx.endpoint.clone()).await;

    let result = sink
        .append_batch(EvidenceBatch::new(
            producer(),
            vec![bound_record(), bound_record()],
        ))
        .await
        .expect("accepted");
    assert_eq!(result.accepted_count, 2, "duplicate is a delivered record");
    assert!(
        result.warnings.iter().any(|w| w.contains("duplicate")),
        "duplicate split surfaces in warnings: {:?}",
        result.warnings
    );
}

#[tokio::test]
async fn batch_retryable_surfaces_as_retryable_sink_error() {
    let rx = spawn_receiver(true, 0, 0).await;
    let sink = connect(rx.endpoint.clone()).await;

    let err = sink
        .append_batch(EvidenceBatch::new(producer(), vec![bound_record()]))
        .await
        .unwrap_err();
    assert!(
        matches!(err, SinkError::Unavailable { .. }),
        "all-or-retry: expected Unavailable, got {err:?}"
    );
}

#[tokio::test]
async fn empty_identity_is_refused_before_the_wire() {
    let rx = spawn_receiver(false, 0, 0).await;
    let sink = connect(rx.endpoint.clone()).await;

    let bad_producer = ProducerMetadata::new("", "node-vox", "6.19-test");
    let err = sink
        .append_batch(EvidenceBatch::new(bad_producer, vec![bound_record()]))
        .await
        .unwrap_err();
    assert!(
        matches!(err, SinkError::Misconfigured { .. }),
        "expected Misconfigured, got {err:?}"
    );
    assert!(
        rx.received.lock().unwrap().is_empty(),
        "nothing crossed the wire"
    );
}

#[tokio::test]
async fn unbound_only_batch_is_a_local_noop_with_visible_drops() {
    let rx = spawn_receiver(false, 0, 0).await;
    let sink = connect(rx.endpoint.clone()).await;

    let result = sink
        .append_batch(EvidenceBatch::new(producer(), vec![unbound_record()]))
        .await
        .expect("local no-op");
    assert_eq!(result.accepted_count, 0);
    assert!(
        result.warnings.iter().any(|w| w.contains("unbound")),
        "drop is visible: {:?}",
        result.warnings
    );
    assert!(
        rx.received.lock().unwrap().is_empty(),
        "unbound evidence never leaves the node"
    );
}

#[tokio::test]
async fn permanent_rejects_fail_the_batch_as_partial_failure() {
    let rx = spawn_receiver(false, 0, 1).await;
    let sink = connect(rx.endpoint.clone()).await;

    let err = sink
        .append_batch(EvidenceBatch::new(
            producer(),
            vec![bound_record(), bound_record()],
        ))
        .await
        .unwrap_err();
    assert!(
        !RetryBuffer::should_retry(&err),
        "permanent rejects must be terminal so the runtime records the drop, got {err:?}"
    );
    match err {
        SinkError::PartialFailure {
            accepted_count,
            rejected_count,
            message,
            ..
        } => {
            assert_eq!(accepted_count, 1);
            assert_eq!(rejected_count, 1);
            assert!(
                message.contains("reason="),
                "reject reasons surface in the error: {message}"
            );
        }
        other => panic!("expected PartialFailure, got {other:?}"),
    }
}

// ── jalki #38: a sink that is down at *startup* is a value, not a crash ──────
//
// Mid-run outages were always graceful (retryable error → RetryBuffer). Startup
// was not: one eager dial, and its failure propagated to a process exit, so any
// restart during a Vartio outage — OOM, drain, rollout — became a crash loop
// with kubelet backoff as the only retry. These pin the two paths together.

/// A config aimed at an address with no listener. The short timeout means a
/// genuine hang fails the test rather than stalling it; a refused connection
/// returns immediately anyway.
fn down_cfg(addr: SocketAddr) -> VartioSinkConfig {
    let mut cfg = VartioSinkConfig::new(format!("http://{addr}"), "jalki-adapter-1");
    cfg.timeout = Duration::from_secs(2);
    cfg
}

/// What the runtime sink loop does with a retryable error, condensed: hold the
/// batch and re-offer it until the sink takes it.
async fn retry_until_delivered(sink: &VartioSink, batch: EvidenceBatch) -> AppendResult {
    for _ in 0..40 {
        match sink.append_batch(batch.clone()).await {
            Ok(result) => return result,
            Err(err) => {
                assert!(
                    RetryBuffer::should_retry(&err),
                    "a returning sink must never produce a terminal error: {err:?}"
                );
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
    panic!("sink never recovered after the receiver came back");
}

#[tokio::test]
async fn construction_succeeds_while_the_sink_is_down() {
    let addr = reserved_addr().await;
    let result = VartioSink::connect(down_cfg(addr)).await;
    assert!(
        result.is_ok(),
        "startup must survive a sink outage, got {:?}",
        result.err()
    );
}

#[tokio::test]
async fn a_sink_that_has_never_connected_does_not_claim_health() {
    let addr = reserved_addr().await;
    let sink = VartioSink::connect(down_cfg(addr)).await.unwrap();
    assert!(
        !sink.health().await.is_healthy(),
        "lazy connect proves nothing at construction, so health must not claim it does"
    );
}

#[tokio::test]
async fn first_append_against_a_down_sink_is_retryable_not_terminal() {
    let addr = reserved_addr().await;
    let sink = VartioSink::connect(down_cfg(addr)).await.unwrap();

    let err = sink
        .append_batch(EvidenceBatch::new(producer(), vec![bound_record()]))
        .await
        .unwrap_err();
    assert!(
        RetryBuffer::should_retry(&err),
        "a startup outage must reach the retry buffer, not drop the batch: {err:?}"
    );
}

/// The acceptance criterion: start with the sink down, hold the evidence, and
/// deliver it when the sink returns.
#[tokio::test]
async fn evidence_survives_a_startup_outage_and_lands_when_vartio_returns() {
    let addr = reserved_addr().await;
    let sink = VartioSink::connect(down_cfg(addr)).await.unwrap();
    let batch = EvidenceBatch::new(producer(), vec![bound_record()]);

    let err = sink.append_batch(batch.clone()).await.unwrap_err();
    assert!(
        RetryBuffer::should_retry(&err),
        "expected the batch to be held, got {err:?}"
    );

    // Vartio comes back at the address jälki was already pointed at.
    let rx = spawn_receiver_at(addr, false).await;

    let result = retry_until_delivered(&sink, batch).await;
    assert_eq!(result.accepted_count, 1, "the held batch is delivered");
    assert!(
        sink.health().await.is_healthy(),
        "a settled batch is what earns the healthy claim"
    );
    assert_eq!(
        rx.received.lock().unwrap().len(),
        1,
        "delivered exactly once"
    );
}

#[tokio::test]
async fn misconfiguration_still_fails_fast() {
    for (label, endpoint) in [("empty", ""), ("unparseable", "not a uri at all")] {
        let result = VartioSink::connect(VartioSinkConfig::new(endpoint, "jalki-adapter-1")).await;
        match result {
            Err(SinkError::Misconfigured { .. }) => {}
            Err(other) => panic!(
                "{label} endpoint: no retry fixes a bad endpoint, so it must be \
                 Misconfigured — got {other:?}"
            ),
            Ok(_) => panic!("{label} endpoint must be refused at construction"),
        }
    }
}

/// jalki #44: workload lineage has to survive the whole path — binding →
/// occurrence labels → Plane-B projection → native wire map — or Vartio's
/// runtime-corroboration Lane 2 has nothing to join on.
#[tokio::test]
async fn workload_owner_rides_the_wire() {
    let rx = spawn_receiver(false, 0, 0).await;
    let sink = connect(rx.endpoint.clone()).await;

    let record = bound_record().with_runtime_binding(RuntimeBinding::Bound {
        container_id: "containerd://abc".to_string(),
        pod_uid: Some("pod-uid-1".to_string()),
        pod_name: Some("runner-abc123".to_string()),
        namespace: Some("arc-runners".to_string()),
        service_account: None,
        owner_kind: Some("ReplicaSet".to_string()),
        owner_name: Some("runner-5f9c".to_string()),
        owner_uid: Some("uid-rs-1".to_string()),
        provenance: BindingProvenance::Observed,
    });

    sink.append_batch(EvidenceBatch::new(producer(), vec![record]))
        .await
        .expect("delivered");

    let batches = rx.received.lock().unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&batches[0].items[0].payload).unwrap();
    assert_eq!(payload["owner_kind"], "ReplicaSet");
    assert_eq!(payload["owner_name"], "runner-5f9c");
    assert_eq!(
        payload["owner_uid"], "uid-rs-1",
        "the uid is the identity that outlives the pod; without it a runtime \
         hop can only ever name an instance"
    );
}

/// A pod with no controller must not acquire an invented owner on the way out.
#[tokio::test]
async fn an_unowned_pod_ships_no_owner_fields() {
    let rx = spawn_receiver(false, 0, 0).await;
    let sink = connect(rx.endpoint.clone()).await;

    sink.append_batch(EvidenceBatch::new(producer(), vec![bound_record()]))
        .await
        .expect("delivered");

    let batches = rx.received.lock().unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&batches[0].items[0].payload).unwrap();
    for key in ["owner_kind", "owner_name", "owner_uid"] {
        assert!(
            payload.get(key).is_none(),
            "{key} must be absent, not empty: {payload}"
        );
    }
}

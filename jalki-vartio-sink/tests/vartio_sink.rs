//! Integration tests: drive `VartioSink` over real gRPC against an in-crate
//! `SourceIngress` test receiver (ported from polku #159). Verifies the wire
//! contract, all-or-retry, fail-fast identity, the Plane-B boundary, and the
//! ADR-0004 config surface (bearer auth + native payload shape).

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use jalki_evidence::{
    BindingProvenance, EvidenceBatch, EvidenceRecord, EvidenceSink, HookKind, KernelEvent,
    ProbeMetadata, ProducerMetadata, RetryBuffer, RuntimeBinding, SinkError, TcpConnectEvent,
    UnboundReason,
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
    let received = Arc::new(Mutex::new(Vec::new()));
    let auth_headers = Arc::new(Mutex::new(Vec::new()));
    let receiver = TestReceiver {
        received: received.clone(),
        auth_headers: auth_headers.clone(),
        retryable,
        duplicates,
        rejected,
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
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

async fn connect_cfg(cfg: VartioSinkConfig) -> VartioSink {
    for _ in 0..40 {
        if let Ok(s) = VartioSink::connect(cfg.clone()).await {
            return s;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("could not connect to test receiver");
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
            namespace: Some("workloads".to_string()),
            service_account: None,
            labels: BTreeMap::new(),
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

/// A record whose occurrence type the importer does not accept
/// (`kernel.file.open`) — the daemon captures these but Vartio rejects them.
fn unsupported_type_record() -> EvidenceRecord {
    let occurrence = false_protocol::Occurrence::new("jalki", "kernel.file.open");
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
        namespace: Some("workloads".to_string()),
        service_account: None,
        labels: BTreeMap::new(),
        provenance: BindingProvenance::Observed,
    })
}

#[tokio::test]
async fn importer_unsupported_types_are_dropped_with_a_warning() {
    let rx = spawn_receiver(false, 0, 0).await;
    let sink = connect(rx.endpoint.clone()).await;

    // One supported (tcp.connect) + one unsupported (file.open) — only the
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
            .any(|w| w.contains("unsupported-by-importer") && w.contains("kernel.file.open")),
        "the drop is visible: {:?}",
        result.warnings
    );

    let batches = rx.received.lock().unwrap();
    assert_eq!(batches[0].items.len(), 1, "only 1 item on the wire");
    assert_eq!(batches[0].items[0].occurrence_type, "kernel.tcp.connect");
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

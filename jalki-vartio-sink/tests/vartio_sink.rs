//! Integration tests: drive `VartioSink` over real gRPC against an in-crate
//! `SourceIngress` test receiver (ported from polku #159). Verifies the wire
//! contract, all-or-retry, fail-fast identity, and the Plane-B boundary.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use jalki_evidence::{
    BindingProvenance, EvidenceBatch, EvidenceRecord, EvidenceSink, HookKind, ProbeMetadata,
    ProducerMetadata, RetryBuffer, RuntimeBinding, SinkError, UnboundReason,
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

async fn spawn_receiver(
    retryable: bool,
    duplicates: u32,
    rejected: u32,
) -> (String, Arc<Mutex<Vec<ProviderEvidenceBatch>>>) {
    let received = Arc::new(Mutex::new(Vec::new()));
    let receiver = TestReceiver {
        received: received.clone(),
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
    (format!("http://{addr}"), received)
}

async fn connect(endpoint: String) -> VartioSink {
    let cfg = VartioSinkConfig::new(endpoint, "jalki-adapter-1");
    for _ in 0..40 {
        if let Ok(s) = VartioSink::connect(cfg.clone()).await {
            return s;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("could not connect to test receiver");
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

fn bound_record() -> EvidenceRecord {
    let occurrence = false_protocol::Occurrence::new("jalki", "kernel.tcp.connect");
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
    let (endpoint, received) = spawn_receiver(false, 0, 0).await;
    let sink = connect(endpoint).await;

    let batch = EvidenceBatch::new(producer(), vec![bound_record(), bound_record()]);
    let batch_id = batch.batch_id.clone();
    let result = sink.append_batch(batch).await.expect("accepted");
    assert_eq!(result.accepted_count, 2);
    assert_eq!(result.rejected_count, 0);
    assert_eq!(result.watermark.unwrap().value, batch_id);

    let batches = received.lock().unwrap();
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
    // payload is the neutral Plane-B occurrence: parses, typed, uninterpreted
    let payload: serde_json::Value = serde_json::from_slice(&item.payload).unwrap();
    assert_eq!(payload["type"], "kernel.tcp.connect"); // serde renames occurrence_type
    assert!(
        payload
            .get("reasoning")
            .map(|v| v.is_null())
            .unwrap_or(true),
        "plane-B payload must carry no interpretation"
    );
}

#[tokio::test]
async fn duplicates_count_as_accepted_with_a_warning() {
    let (endpoint, _received) = spawn_receiver(false, 1, 0).await;
    let sink = connect(endpoint).await;

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
    let (endpoint, _received) = spawn_receiver(true, 0, 0).await;
    let sink = connect(endpoint).await;

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
    let (endpoint, received) = spawn_receiver(false, 0, 0).await;
    let sink = connect(endpoint).await;

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
        received.lock().unwrap().is_empty(),
        "nothing crossed the wire"
    );
}

#[tokio::test]
async fn unbound_only_batch_is_a_local_noop_with_visible_drops() {
    let (endpoint, received) = spawn_receiver(false, 0, 0).await;
    let sink = connect(endpoint).await;

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
        received.lock().unwrap().is_empty(),
        "unbound evidence never leaves the node"
    );
}

#[tokio::test]
async fn permanent_rejects_fail_the_batch_as_partial_failure() {
    let (endpoint, _received) = spawn_receiver(false, 0, 1).await;
    let sink = connect(endpoint).await;

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

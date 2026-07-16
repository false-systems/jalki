//! `VartioSink` — the Plane-B transport (ADR-0003).
//!
//! An [`EvidenceSink`] that delivers jälki evidence to Vartio's
//! `SourceIngress.ReceiveBatch` over gRPC. Ported from polku #159's
//! `VartioEmitter` (all-or-retry, source-scoped idempotency, in-crate test
//! receiver), adapted to jälki's seams:
//!
//! - **Plane-B projection at the door**: `EvidenceBatch::into_plane_b_projection`
//!   supplies neutral, strongly-bound occurrences (ADR-0002 §D4/§D5). Unbound
//!   drops never leave the node; they surface in `AppendResult::warnings`.
//! - **all-or-retry**: a transport failure or a batch-level `retryable` response
//!   returns a *retryable* [`SinkError`] so the runtime sink loop retries the
//!   whole batch; accepted/duplicate items replay safely because the per-item
//!   `idempotency_key` is stable (`source:cluster:node:<occurrence id>`).
//! - **permanent rejects fail the batch** (jalki #22 review): a settled
//!   response with `rejected_count > 0` returns the terminal
//!   [`SinkError::PartialFailure`] (matching `PipelineSink`), so the runtime
//!   sink loop records the drop as gap evidence instead of counting the batch
//!   as delivered.
//! - **fail-fast identity** (polku #159 review): a batch whose producer carries
//!   an empty cluster or node identity is refused as `Misconfigured` — the sink
//!   never emits `jalki:::…` idempotency keys.
//! - **bounded-and-lossy is the caller's policy** (ADR-0003 §D3): this sink
//!   classifies errors as retryable/terminal; the retry budget and the visible
//!   drop live in the runtime sink loop, not here.

pub mod proto {
    #![allow(clippy::all)]
    #![allow(missing_docs)]
    include!("proto/vartio.source_ingress.v1.rs");
}

use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use jalki_evidence::{
    AppendResult, Checkpoint, EvidenceBatch, EvidenceSink, HealthStatus, SinkError,
};
use tonic::transport::{Channel, Endpoint};
use tonic::Request;

use proto::source_ingress_client::SourceIngressClient;
use proto::{ProviderEvidenceBatch, ProviderEvidenceItem};

pub const SINK_NAME: &str = "vartio";

/// Static identity + target for the Vartio ingress lane. Cluster/node identity
/// rides on each `EvidenceBatch`'s `ProducerMetadata`, not here.
#[derive(Debug, Clone)]
pub struct VartioSinkConfig {
    /// Vartio source-ingress gRPC endpoint, e.g. `http://vartio:50061`.
    pub endpoint: String,
    /// Registry source key + provider (`jalki`) and the importer namespace.
    pub source_key: String,
    pub provider: String,
    pub namespace: String,
    /// Identity of this adapter instance (per-deployment).
    pub adapter_id: String,
    pub timeout: Duration,
}

impl VartioSinkConfig {
    pub fn new(endpoint: impl Into<String>, adapter_id: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            source_key: "jalki".to_string(),
            provider: "jalki".to_string(),
            namespace: "vartio-jalki".to_string(),
            adapter_id: adapter_id.into(),
            timeout: Duration::from_secs(10),
        }
    }

    fn validate(&self) -> Result<(), SinkError> {
        for (field, value) in [
            ("endpoint", &self.endpoint),
            ("adapter_id", &self.adapter_id),
        ] {
            if value.is_empty() {
                return Err(SinkError::Misconfigured {
                    sink: SINK_NAME.to_string(),
                    message: format!("{field} must not be empty"),
                });
            }
        }
        Ok(())
    }
}

/// gRPC client for Vartio's `SourceIngress`. Plaintext/bearer is the dev
/// posture; mTLS is the production hardening point (`connect` is the seam).
pub struct VartioSink {
    client: SourceIngressClient<Channel>,
    cfg: VartioSinkConfig,
    health: Mutex<HealthStatus>,
}

impl VartioSink {
    pub async fn connect(cfg: VartioSinkConfig) -> Result<Self, SinkError> {
        cfg.validate()?;
        let channel = Endpoint::try_from(cfg.endpoint.clone())
            .map_err(|e| SinkError::Misconfigured {
                sink: SINK_NAME.to_string(),
                message: format!("invalid endpoint {}: {e}", cfg.endpoint),
            })?
            .timeout(cfg.timeout)
            .connect()
            .await
            .map_err(|e| SinkError::Unavailable {
                sink: SINK_NAME.to_string(),
                message: e.to_string(),
            })?;
        Ok(Self {
            client: SourceIngressClient::new(channel),
            cfg,
            health: Mutex::new(HealthStatus::Healthy),
        })
    }

    fn set_health(&self, status: HealthStatus) {
        if let Ok(mut h) = self.health.lock() {
            *h = status;
        }
    }

    fn idempotency_key(&self, cluster: &str, node: &str, occurrence_id: &str) -> String {
        format!(
            "{}:{}:{}:{}",
            self.cfg.source_key, cluster, node, occurrence_id
        )
    }
}

#[async_trait]
impl EvidenceSink for VartioSink {
    fn name(&self) -> &str {
        SINK_NAME
    }

    async fn append_batch(&self, batch: EvidenceBatch) -> Result<AppendResult, SinkError> {
        // fail-fast identity (polku #159 review): never emit `jalki:::…` keys.
        let producer = batch.producer.clone();
        if producer.cluster.is_empty() || producer.node_id.is_empty() {
            return Err(SinkError::Misconfigured {
                sink: SINK_NAME.to_string(),
                message: "producer cluster/node identity is empty; refusing to emit unscoped idempotency keys".to_string(),
            });
        }

        let batch_id = batch.batch_id.clone();
        let projection = batch.into_plane_b_projection();

        let mut warnings: Vec<String> = projection
            .dropped_unbound
            .iter()
            .map(|(reason, n)| {
                format!(
                    "dropped {n} unbound record(s) at source: {}",
                    reason.as_str()
                )
            })
            .collect();

        if projection.occurrences.is_empty() {
            // Nothing bound to deliver — a local no-op, never a wire call.
            let mut result = AppendResult::accepted(SINK_NAME, 0);
            result.warnings = warnings;
            return Ok(result);
        }

        let mut items = Vec::with_capacity(projection.occurrences.len());
        for occ in &projection.occurrences {
            let observed_at = prost_types::Timestamp {
                seconds: occ.timestamp.timestamp(),
                nanos: occ.timestamp.timestamp_subsec_nanos().min(999_999_999) as i32,
            };
            let payload = serde_json::to_vec(occ).map_err(|e| SinkError::InvalidRecord {
                sink: SINK_NAME.to_string(),
                message: e.to_string(),
            })?;
            items.push(ProviderEvidenceItem {
                idempotency_key: self.idempotency_key(
                    &producer.cluster,
                    &producer.node_id,
                    &occ.id.to_string(),
                ),
                occurrence_type: occ.occurrence_type.as_str().to_string(),
                observed_at: Some(observed_at),
                payload,
                metadata: Vec::new(),
                trust_context: Vec::new(),
            });
        }
        let item_count = items.len();

        let wire_batch = ProviderEvidenceBatch {
            source_key: self.cfg.source_key.clone(),
            provider: self.cfg.provider.clone(),
            namespace: self.cfg.namespace.clone(),
            batch_id: batch_id.clone(),
            adapter_id: self.cfg.adapter_id.clone(),
            cluster_id: producer.cluster.clone(),
            node_id: producer.node_id.clone(),
            ingested_at: Some(prost_types::Timestamp::from(std::time::SystemTime::now())),
            items,
        };

        let response = self
            .client
            .clone()
            .receive_batch(Request::new(wire_batch))
            .await
            .map_err(|status| {
                let err = classify_status(&status);
                self.set_health(HealthStatus::Degraded {
                    reason: format!("receive_batch: {}", status.message()),
                });
                err
            })?
            .into_inner();

        if response.retryable {
            // all-or-retry: the whole batch is retried by the caller;
            // accepted/duplicate items are idempotent no-ops on redelivery.
            self.set_health(HealthStatus::Degraded {
                reason: format!("batch {} retryable item failures", response.batch_id),
            });
            return Err(SinkError::Unavailable {
                sink: SINK_NAME.to_string(),
                message: format!(
                    "batch {} has retryable item failures (accepted={} duplicate={} rejected={})",
                    response.batch_id,
                    response.accepted_count,
                    response.duplicate_count,
                    response.rejected_count
                ),
            });
        }

        if response.rejected_count > 0 {
            // Permanent rejects must fail the batch (match `PipelineSink`):
            // the runtime sink loop counts any `Ok` as delivered and records
            // gap evidence only on `Err`, so an `Ok` here would be silent
            // loss (ADR-0002 §D7). `PartialFailure` is terminal in the loop —
            // the batch drops once, visibly.
            let mut message = format!(
                "batch {} permanently rejected {} item(s) (accepted={} duplicate={})",
                response.batch_id,
                response.rejected_count,
                response.accepted_count,
                response.duplicate_count
            );
            for summary in &response.error_summaries {
                message.push_str(&format!(
                    "; reason={} count={}",
                    summary.reason, summary.count
                ));
            }
            self.set_health(HealthStatus::Degraded {
                reason: format!("batch {} permanent item rejects", response.batch_id),
            });
            return Err(SinkError::PartialFailure {
                sink: SINK_NAME.to_string(),
                accepted_count: (response.accepted_count + response.duplicate_count) as usize,
                rejected_count: response.rejected_count as usize,
                message,
            });
        }

        if response.duplicate_count > 0 {
            warnings.push(format!(
                "{} duplicate item(s) (idempotent no-op)",
                response.duplicate_count
            ));
        }

        self.set_health(HealthStatus::Healthy);
        tracing::debug!(
            sink = SINK_NAME,
            batch_id = %response.batch_id,
            sent = item_count,
            accepted = response.accepted_count,
            duplicate = response.duplicate_count,
            rejected = response.rejected_count,
            "vartio batch settled"
        );

        Ok(AppendResult {
            // A duplicate is a delivered record (idempotent no-op), so it counts
            // as accepted for durability purposes; the warning records the split.
            accepted_count: (response.accepted_count + response.duplicate_count) as usize,
            rejected_count: response.rejected_count as usize,
            sink_name: SINK_NAME.to_string(),
            watermark: Some(Checkpoint { value: batch_id }),
            warnings,
        })
    }

    async fn health(&self) -> HealthStatus {
        self.health
            .lock()
            .map(|h| h.clone())
            .unwrap_or(HealthStatus::Degraded {
                reason: "health lock poisoned".to_string(),
            })
    }
}

/// Map a gRPC status onto the retryable/terminal split `SinkError` encodes.
/// Auth and malformed-request failures are terminal; everything else retries.
fn classify_status(status: &tonic::Status) -> SinkError {
    use tonic::Code;
    let sink = SINK_NAME.to_string();
    let message = status.message().to_string();
    match status.code() {
        Code::Unauthenticated | Code::PermissionDenied => SinkError::Unauthorized { sink, message },
        Code::InvalidArgument | Code::FailedPrecondition => SinkError::Rejected { sink, message },
        Code::ResourceExhausted => SinkError::Backpressure { sink, message },
        Code::DeadlineExceeded => SinkError::Timeout { sink, message },
        _ => SinkError::Unavailable { sink, message },
    }
}

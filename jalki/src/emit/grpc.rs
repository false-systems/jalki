use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use false_protocol::Occurrence;
use tokio::sync::Mutex;
use tonic::transport::Channel;
use tracing::{debug, info, warn};

use crate::emitter::{EmitError, Emitter, HealthStatus};

/// Emits Occurrences to a POLKU-compatible gRPC endpoint.
///
/// Sends batches of JSON-encoded occurrences over a unary gRPC call.
/// Reconnects automatically on failure. Never blocks the emit loop.
pub struct GrpcEmitter {
    endpoint: String,
    channel: Arc<Mutex<Option<Channel>>>,
    consecutive_failures: AtomicU32,
}

impl GrpcEmitter {
    pub fn new(endpoint: impl Into<String>) -> Self {
        let endpoint = endpoint.into();
        info!(endpoint = %endpoint, "gRPC emitter configured");
        Self {
            endpoint,
            channel: Arc::new(Mutex::new(None)),
            consecutive_failures: AtomicU32::new(0),
        }
    }

    async fn get_or_connect(&self) -> Result<Channel, EmitError> {
        let mut guard = self.channel.lock().await;
        if let Some(ref ch) = *guard {
            return Ok(ch.clone());
        }

        let uri = if self.endpoint.starts_with("http") {
            self.endpoint.clone()
        } else {
            format!("http://{}", self.endpoint)
        };

        debug!(uri = %uri, "connecting to POLKU");

        let channel = Channel::from_shared(uri.clone())
            .map_err(|e| EmitError::Failed {
                destination: self.endpoint.clone(),
                source: anyhow::anyhow!("invalid endpoint: {e}"),
            })?
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(10))
            .connect()
            .await
            .map_err(|e| EmitError::Failed {
                destination: self.endpoint.clone(),
                source: anyhow::anyhow!("connect failed: {e}"),
            })?;

        info!(endpoint = %self.endpoint, "connected to POLKU");
        *guard = Some(channel.clone());
        Ok(channel)
    }

    async fn reset_channel(&self) {
        let mut guard = self.channel.lock().await;
        *guard = None;
    }
}

#[async_trait]
impl Emitter for GrpcEmitter {
    fn name(&self) -> &str {
        "grpc"
    }

    async fn emit(&self, occurrences: &[Occurrence]) -> Result<(), EmitError> {
        if occurrences.is_empty() {
            return Ok(());
        }

        let channel = self.get_or_connect().await?;

        // Serialize occurrences as JSON array.
        let json_bytes = serde_json::to_vec(occurrences).map_err(|e| EmitError::Failed {
            destination: self.endpoint.clone(),
            source: anyhow::anyhow!("serialize failed: {e}"),
        })?;

        // Send as a unary gRPC call to polku.v1.OccurrenceService/Emit.
        // We construct the request manually using tonic's low-level API.
        let mut client = tonic::client::Grpc::new(channel);
        client.ready().await.map_err(|e| {
            self.consecutive_failures.fetch_add(1, Ordering::Relaxed);
            EmitError::Failed {
                destination: self.endpoint.clone(),
                source: anyhow::anyhow!("channel not ready: {e}"),
            }
        })?;

        let request = tonic::Request::new(EmitRequest {
            occurrences_json: json_bytes,
            count: occurrences.len() as u32,
        });

        let path = tonic::codegen::http::uri::PathAndQuery::from_static(
            "/polku.v1.OccurrenceService/Emit",
        );

        let codec = JsonCodec::default();

        let result = client
            .unary(request, path, codec)
            .await;

        match result {
            Ok(_response) => {
                self.consecutive_failures.store(0, Ordering::Relaxed);
                debug!(count = occurrences.len(), "emitted to POLKU");
                Ok(())
            }
            Err(status) => {
                let failures = self.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;
                if failures >= 3 {
                    warn!(
                        endpoint = %self.endpoint,
                        failures = failures,
                        "POLKU connection degraded, resetting"
                    );
                    self.reset_channel().await;
                }
                Err(EmitError::Failed {
                    destination: self.endpoint.clone(),
                    source: anyhow::anyhow!("gRPC emit failed: {status}"),
                })
            }
        }
    }

    async fn health(&self) -> HealthStatus {
        let failures = self.consecutive_failures.load(Ordering::Relaxed);
        match failures {
            0 => HealthStatus::Healthy,
            1..=2 => HealthStatus::Degraded,
            _ => HealthStatus::Unhealthy,
        }
    }
}

// --- Minimal gRPC codec for raw JSON bytes ---

/// Request message for polku.v1.OccurrenceService/Emit.
#[derive(Clone)]
struct EmitRequest {
    occurrences_json: Vec<u8>,
    count: u32,
}

/// Response message.
#[derive(Clone, Default)]
struct EmitResponse {
    _accepted: u32,
}

/// A minimal codec that sends/receives raw bytes without protobuf.
/// Uses a simple framing: 4-byte length prefix + JSON body.
#[derive(Debug, Clone, Default)]
struct JsonCodec;

impl tonic::codec::Codec for JsonCodec {
    type Encode = EmitRequest;
    type Decode = EmitResponse;
    type Encoder = JsonEncoder;
    type Decoder = JsonDecoder;

    fn encoder(&mut self) -> Self::Encoder {
        JsonEncoder
    }

    fn decoder(&mut self) -> Self::Decoder {
        JsonDecoder
    }
}

#[derive(Debug, Clone)]
struct JsonEncoder;

impl tonic::codec::Encoder for JsonEncoder {
    type Item = EmitRequest;
    type Error = tonic::Status;

    fn encode(
        &mut self,
        item: Self::Item,
        dst: &mut tonic::codec::EncodeBuf<'_>,
    ) -> Result<(), Self::Error> {
        // Simple framing: just write the JSON bytes.
        // The gRPC framing (length-prefix) is handled by tonic.
        use bytes::BufMut;
        dst.put_slice(&item.occurrences_json);
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct JsonDecoder;

impl tonic::codec::Decoder for JsonDecoder {
    type Item = EmitResponse;
    type Error = tonic::Status;

    fn decode(
        &mut self,
        _src: &mut tonic::codec::DecodeBuf<'_>,
    ) -> Result<Option<Self::Item>, Self::Error> {
        // We don't need to parse the response for now.
        Ok(Some(EmitResponse::default()))
    }
}

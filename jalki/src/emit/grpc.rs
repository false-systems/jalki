use async_trait::async_trait;
use false_protocol::Occurrence;

use crate::emitter::{EmitError, Emitter, HealthStatus};

/// Emits Occurrences to a POLKU-compatible gRPC endpoint.
///
/// NOT IMPLEMENTED. Will fail loudly on every emit call.
/// Full POLKU integration requires the POLKU proto definitions.
pub struct GrpcEmitter {
    endpoint: String,
}

impl GrpcEmitter {
    pub fn new(endpoint: impl Into<String>) -> Self {
        let endpoint = endpoint.into();
        tracing::warn!(
            endpoint = %endpoint,
            "gRPC emitter is not yet implemented — all emit calls will fail"
        );
        Self { endpoint }
    }
}

#[async_trait]
impl Emitter for GrpcEmitter {
    fn name(&self) -> &str {
        "grpc"
    }

    async fn emit(&self, _occurrences: &[Occurrence]) -> Result<(), EmitError> {
        Err(EmitError::Failed {
            destination: format!("grpc://{}", self.endpoint),
            source: anyhow::anyhow!(
                "gRPC emitter not implemented — use stdout or file emitter for v0.1"
            ),
        })
    }

    async fn health(&self) -> HealthStatus {
        HealthStatus::Unhealthy
    }
}

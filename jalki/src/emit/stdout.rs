use async_trait::async_trait;
use false_protocol::Occurrence;

use crate::emitter::{EmitError, Emitter, HealthStatus};

/// Emits Occurrences as newline-delimited JSON to stdout.
pub struct StdoutEmitter;

impl StdoutEmitter {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Emitter for StdoutEmitter {
    fn name(&self) -> &str {
        "stdout"
    }

    async fn emit(&self, occurrences: &[Occurrence]) -> Result<(), EmitError> {
        for occ in occurrences {
            let json = serde_json::to_string(occ).map_err(|e| EmitError::Failed {
                destination: "stdout".into(),
                source: e.into(),
            })?;
            println!("{json}");
        }
        Ok(())
    }

    async fn health(&self) -> HealthStatus {
        HealthStatus::Healthy
    }
}

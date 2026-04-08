use false_protocol::Occurrence;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EmitError {
    #[error("emit to {destination} failed: {source}")]
    Failed {
        destination: String,
        #[source]
        source: anyhow::Error,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

/// Pluggable output destination for Occurrences.
#[async_trait::async_trait]
pub trait Emitter: Send + Sync {
    fn name(&self) -> &str;

    async fn emit(&self, occurrences: &[Occurrence]) -> Result<(), EmitError>;

    async fn health(&self) -> HealthStatus;
}

// async_trait is used via manual desugaring to avoid the extra dependency.
// We'll use a simpler approach: Box<dyn Future> returns.

/// Re-export for convenience — callers don't need to import async_trait themselves.
pub use HealthStatus as EmitterHealth;

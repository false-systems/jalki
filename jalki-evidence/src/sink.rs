//! Evidence sinks and local sink implementations.
//!
//! Sinks are the only durable-output seam in ADR-0001. They accept
//! [`EvidenceBatch`] so observed-time and producer/probe metadata are projected
//! before serialization or forwarding.

use std::path::{Path, PathBuf};
#[cfg(test)]
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use thiserror::Error;
use tokio::io::AsyncWriteExt;
use tracing::warn;

use crate::EvidenceBatch;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppendResult {
    pub accepted_count: usize,
    pub rejected_count: usize,
    pub sink_name: String,
    pub watermark: Option<Checkpoint>,
    pub warnings: Vec<String>,
}

impl AppendResult {
    pub fn accepted(sink_name: impl Into<String>, accepted_count: usize) -> Self {
        Self {
            accepted_count,
            rejected_count: 0,
            sink_name: sink_name.into(),
            watermark: None,
            warnings: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HealthStatus {
    Healthy,
    Degraded { reason: String },
    Unhealthy { reason: String },
}

impl HealthStatus {
    pub fn is_healthy(&self) -> bool {
        matches!(self, HealthStatus::Healthy)
    }
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum SinkError {
    #[error("sink {sink} unavailable: {message}")]
    Unavailable { sink: String, message: String },

    #[error("sink {sink} timed out: {message}")]
    Timeout { sink: String, message: String },

    #[error("sink {sink} rejected invalid record: {message}")]
    InvalidRecord { sink: String, message: String },

    #[error("sink {sink} rejected batch: {message}")]
    Rejected { sink: String, message: String },

    #[error("sink {sink} is under backpressure: {message}")]
    Backpressure { sink: String, message: String },

    #[error("sink {sink} unauthorized: {message}")]
    Unauthorized { sink: String, message: String },

    #[error("sink {sink} misconfigured: {message}")]
    Misconfigured { sink: String, message: String },

    #[error("sink {sink} partially failed: accepted {accepted_count}, rejected {rejected_count}: {message}")]
    PartialFailure {
        sink: String,
        accepted_count: usize,
        rejected_count: usize,
        message: String,
    },

    #[error("sink {sink} unsupported: {message}")]
    Unsupported { sink: String, message: String },
}

impl SinkError {
    pub fn sink_name(&self) -> &str {
        match self {
            SinkError::Unavailable { sink, .. }
            | SinkError::Timeout { sink, .. }
            | SinkError::InvalidRecord { sink, .. }
            | SinkError::Rejected { sink, .. }
            | SinkError::Backpressure { sink, .. }
            | SinkError::Unauthorized { sink, .. }
            | SinkError::Misconfigured { sink, .. }
            | SinkError::PartialFailure { sink, .. }
            | SinkError::Unsupported { sink, .. } => sink,
        }
    }
}

#[async_trait]
pub trait EvidenceSink: Send + Sync {
    fn name(&self) -> &str;

    async fn append_batch(&self, batch: EvidenceBatch) -> Result<AppendResult, SinkError>;

    async fn health(&self) -> HealthStatus;
}

fn encode_ndjson(batch: EvidenceBatch, sink_name: &str) -> Result<(Vec<u8>, usize), SinkError> {
    let occurrences = batch.into_occurrences();
    let count = occurrences.len();
    let mut bytes = Vec::new();

    for occ in occurrences {
        let json = serde_json::to_vec(&occ).map_err(|e| SinkError::InvalidRecord {
            sink: sink_name.into(),
            message: e.to_string(),
        })?;
        bytes.extend_from_slice(&json);
        bytes.push(b'\n');
    }

    Ok((bytes, count))
}

/// Emits batches as newline-delimited JSON to stdout.
pub struct StdoutSink;

impl StdoutSink {
    pub fn new() -> Self {
        Self
    }

    #[doc(hidden)]
    pub fn encode_batch_for_test(batch: EvidenceBatch) -> Result<Vec<u8>, SinkError> {
        encode_ndjson(batch, "stdout").map(|(bytes, _)| bytes)
    }
}

impl Default for StdoutSink {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl EvidenceSink for StdoutSink {
    fn name(&self) -> &str {
        "stdout"
    }

    async fn append_batch(&self, batch: EvidenceBatch) -> Result<AppendResult, SinkError> {
        let (bytes, count) = encode_ndjson(batch, self.name())?;
        let mut stdout = tokio::io::stdout();
        stdout
            .write_all(&bytes)
            .await
            .map_err(|e| SinkError::Unavailable {
                sink: self.name().into(),
                message: e.to_string(),
            })?;
        stdout.flush().await.map_err(|e| SinkError::Unavailable {
            sink: self.name().into(),
            message: e.to_string(),
        })?;
        Ok(AppendResult::accepted(self.name(), count))
    }

    async fn health(&self) -> HealthStatus {
        HealthStatus::Healthy
    }
}

/// Emits batches as newline-delimited JSON to a file.
pub struct FileSink {
    path: PathBuf,
}

impl FileSink {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[async_trait]
impl EvidenceSink for FileSink {
    fn name(&self) -> &str {
        "file"
    }

    async fn append_batch(&self, batch: EvidenceBatch) -> Result<AppendResult, SinkError> {
        let (bytes, count) = encode_ndjson(batch, self.name())?;
        let mut file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .await
            .map_err(|e| SinkError::Unavailable {
                sink: self.path.display().to_string(),
                message: e.to_string(),
            })?;

        file.write_all(&bytes)
            .await
            .map_err(|e| SinkError::Unavailable {
                sink: self.path.display().to_string(),
                message: e.to_string(),
            })?;

        Ok(AppendResult::accepted(self.name(), count))
    }

    async fn health(&self) -> HealthStatus {
        match tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .await
        {
            Ok(_) => HealthStatus::Healthy,
            Err(e) => HealthStatus::Unhealthy {
                reason: e.to_string(),
            },
        }
    }
}

/// Fan-out sink with a required primary and best-effort secondaries.
pub struct CompositeSink {
    primary: Box<dyn EvidenceSink>,
    secondaries: Vec<Box<dyn EvidenceSink>>,
}

impl CompositeSink {
    pub fn new(primary: Box<dyn EvidenceSink>, secondaries: Vec<Box<dyn EvidenceSink>>) -> Self {
        Self {
            primary,
            secondaries,
        }
    }
}

#[async_trait]
impl EvidenceSink for CompositeSink {
    fn name(&self) -> &str {
        "composite"
    }

    async fn append_batch(&self, batch: EvidenceBatch) -> Result<AppendResult, SinkError> {
        if self.secondaries.is_empty() {
            let mut result = self.primary.append_batch(batch).await?;
            result.sink_name = self.name().into();
            return Ok(result);
        }

        let mut result = self.primary.append_batch(batch.clone()).await?;
        result.sink_name = self.name().into();

        for secondary in &self.secondaries {
            if let Err(err) = secondary.append_batch(batch.clone()).await {
                let warning = format!("secondary sink {} failed: {err}", secondary.name());
                warn!(
                    sink = secondary.name(),
                    error = %err,
                    "secondary evidence sink failed"
                );
                result.warnings.push(warning);
            }
        }

        Ok(result)
    }

    async fn health(&self) -> HealthStatus {
        let primary = self.primary.health().await;
        let mut secondary_warnings = Vec::new();

        for secondary in &self.secondaries {
            let health = secondary.health().await;
            if !health.is_healthy() {
                secondary_warnings.push(format!("{}: {health:?}", secondary.name()));
            }
        }

        match primary {
            HealthStatus::Healthy if secondary_warnings.is_empty() => HealthStatus::Healthy,
            HealthStatus::Healthy => HealthStatus::Degraded {
                reason: format!(
                    "secondary sinks degraded: {}",
                    secondary_warnings.join("; ")
                ),
            },
            HealthStatus::Degraded { reason } => HealthStatus::Degraded {
                reason: format!("primary degraded: {reason}"),
            },
            HealthStatus::Unhealthy { reason } => HealthStatus::Unhealthy {
                reason: format!("primary unhealthy: {reason}"),
            },
        }
    }
}

#[cfg(test)]
#[derive(Clone)]
pub struct FakeSink {
    name: String,
    batches: Arc<Mutex<Vec<EvidenceBatch>>>,
    failure: Arc<Mutex<Option<SinkError>>>,
}

#[cfg(test)]
impl FakeSink {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            batches: Arc::new(Mutex::new(Vec::new())),
            failure: Arc::new(Mutex::new(None)),
        }
    }

    pub fn with_failure(name: impl Into<String>, failure: SinkError) -> Self {
        let sink = Self::new(name);
        sink.set_failure(Some(failure));
        sink
    }

    pub fn set_failure(&self, failure: Option<SinkError>) {
        if let Ok(mut guard) = self.failure.lock() {
            *guard = failure;
        }
    }

    pub fn batches(&self) -> Vec<EvidenceBatch> {
        self.batches
            .lock()
            .map(|guard| guard.clone())
            .unwrap_or_default()
    }
}

#[cfg(test)]
#[async_trait]
impl EvidenceSink for FakeSink {
    fn name(&self) -> &str {
        &self.name
    }

    async fn append_batch(&self, batch: EvidenceBatch) -> Result<AppendResult, SinkError> {
        let failure = self.failure.lock().ok().and_then(|guard| guard.clone());
        if let Some(err) = failure {
            return Err(err);
        }

        let count = batch.len();
        if let Ok(mut guard) = self.batches.lock() {
            guard.push(batch);
        }
        Ok(AppendResult::accepted(self.name(), count))
    }

    async fn health(&self) -> HealthStatus {
        if self
            .failure
            .lock()
            .ok()
            .and_then(|guard| guard.clone())
            .is_some()
        {
            HealthStatus::Unhealthy {
                reason: "configured failure".into(),
            }
        } else {
            HealthStatus::Healthy
        }
    }
}

#[cfg(test)]
mod tests {
    use false_protocol::Occurrence;

    use crate::{EvidenceRecord, HookKind, ProbeMetadata, ProducerMetadata};

    use super::*;

    fn record(observed_at_ns: u64) -> EvidenceRecord {
        EvidenceRecord {
            observed_at_ns,
            probe: ProbeMetadata {
                probe_id: "tcp_connect".into(),
                probe_version: "1".into(),
                probe_family: "tcp".into(),
                hook_kind: HookKind::Fexit,
                kernel_function: "tcp_connect".into(),
            },
            occurrence: Occurrence::new("jalki/tcp_connect", "kernel.tcp.connect")
                .in_cluster("prod"),
        }
    }

    fn batch() -> EvidenceBatch {
        EvidenceBatch::new(
            ProducerMetadata::new("prod", "node-1", "6.17.0"),
            vec![record(123)],
        )
    }

    fn variant_names() -> Vec<&'static str> {
        vec![
            "Unavailable",
            "Timeout",
            "InvalidRecord",
            "Rejected",
            "Backpressure",
            "Unauthorized",
            "Misconfigured",
            "PartialFailure",
            "Unsupported",
        ]
    }

    #[test]
    fn sink_error_variants_are_distinct() {
        let errors = vec![
            SinkError::Unavailable {
                sink: "s".into(),
                message: "m".into(),
            },
            SinkError::Timeout {
                sink: "s".into(),
                message: "m".into(),
            },
            SinkError::InvalidRecord {
                sink: "s".into(),
                message: "m".into(),
            },
            SinkError::Rejected {
                sink: "s".into(),
                message: "m".into(),
            },
            SinkError::Backpressure {
                sink: "s".into(),
                message: "m".into(),
            },
            SinkError::Unauthorized {
                sink: "s".into(),
                message: "m".into(),
            },
            SinkError::Misconfigured {
                sink: "s".into(),
                message: "m".into(),
            },
            SinkError::PartialFailure {
                sink: "s".into(),
                accepted_count: 1,
                rejected_count: 1,
                message: "m".into(),
            },
            SinkError::Unsupported {
                sink: "s".into(),
                message: "m".into(),
            },
        ];

        let labels: Vec<_> = errors
            .iter()
            .map(|err| match err {
                SinkError::Unavailable { .. } => "Unavailable",
                SinkError::Timeout { .. } => "Timeout",
                SinkError::InvalidRecord { .. } => "InvalidRecord",
                SinkError::Rejected { .. } => "Rejected",
                SinkError::Backpressure { .. } => "Backpressure",
                SinkError::Unauthorized { .. } => "Unauthorized",
                SinkError::Misconfigured { .. } => "Misconfigured",
                SinkError::PartialFailure { .. } => "PartialFailure",
                SinkError::Unsupported { .. } => "Unsupported",
            })
            .collect();

        assert_eq!(labels, variant_names());
    }

    #[test]
    fn stdout_sink_emits_deterministic_ndjson() {
        let bytes = StdoutSink::encode_batch_for_test(batch()).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        let lines: Vec<_> = text.lines().collect();
        assert_eq!(lines.len(), 1);
        let value: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(value["source"], "jalki/tcp_connect");
        assert_eq!(value["type"], "kernel.tcp.connect");
        assert_eq!(value["cluster"], "prod");
        assert_eq!(value["labels"]["producer"], "jalki");
        assert_eq!(value["labels"]["probe_id"], "tcp_connect");
    }

    #[tokio::test]
    async fn file_sink_writes_valid_ndjson() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("events.ndjson");
        let sink = FileSink::new(&path);

        let result = sink.append_batch(batch()).await.unwrap();
        assert_eq!(result.accepted_count, 1);

        let text = tokio::fs::read_to_string(path).await.unwrap();
        let lines: Vec<_> = text.lines().collect();
        assert_eq!(lines.len(), 1);
        let value: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(value["labels"]["kernel_function"], "tcp_connect");
    }

    #[tokio::test]
    async fn fake_sink_receives_batch_with_projected_metadata() {
        let sink = FakeSink::new("fake");
        sink.append_batch(batch()).await.unwrap();

        let mut batches = sink.batches();
        assert_eq!(batches.len(), 1);
        let occ = batches.remove(0).into_occurrences().pop().unwrap();
        assert_eq!(
            occ.labels.get("producer").map(String::as_str),
            Some("jalki")
        );
        assert_eq!(
            occ.labels.get("cluster_id").map(String::as_str),
            Some("prod")
        );
        assert_eq!(
            occ.labels.get("node_id").map(String::as_str),
            Some("node-1")
        );
        assert_eq!(
            occ.labels.get("kernel_release").map(String::as_str),
            Some("6.17.0")
        );
        assert_eq!(
            occ.labels.get("probe_id").map(String::as_str),
            Some("tcp_connect")
        );
        assert_eq!(
            occ.labels.get("hook_kind").map(String::as_str),
            Some("fexit")
        );
        assert_eq!(
            occ.labels.get("observed_at_ns").map(String::as_str),
            Some("123")
        );
    }

    #[tokio::test]
    async fn composite_primary_failure_propagates_and_skips_secondaries() {
        let primary_error = SinkError::Unavailable {
            sink: "primary".into(),
            message: "down".into(),
        };
        let primary = FakeSink::with_failure("primary", primary_error.clone());
        let secondary = FakeSink::new("secondary");
        let secondary_handle = secondary.clone();
        let composite = CompositeSink::new(Box::new(primary), vec![Box::new(secondary)]);

        let err = composite.append_batch(batch()).await.unwrap_err();
        assert_eq!(err, primary_error);
        assert!(secondary_handle.batches().is_empty());
    }

    #[tokio::test]
    async fn composite_secondary_failure_is_warning() {
        let primary = FakeSink::new("primary");
        let primary_handle = primary.clone();
        let secondary_error = SinkError::Rejected {
            sink: "secondary".into(),
            message: "bad".into(),
        };
        let secondary = FakeSink::with_failure("secondary", secondary_error);
        let secondary_handle = secondary.clone();
        let composite = CompositeSink::new(Box::new(primary), vec![Box::new(secondary)]);

        let result = composite.append_batch(batch()).await.unwrap();
        assert_eq!(result.accepted_count, 1);
        assert_eq!(result.warnings.len(), 1);
        assert!(result.warnings[0].contains("secondary"));
        assert_eq!(primary_handle.batches().len(), 1);
        assert!(secondary_handle.batches().is_empty());
    }

    #[tokio::test]
    async fn composite_success_reaches_every_sink() {
        let primary = FakeSink::new("primary");
        let secondary_a = FakeSink::new("secondary-a");
        let secondary_b = FakeSink::new("secondary-b");
        let primary_handle = primary.clone();
        let secondary_a_handle = secondary_a.clone();
        let secondary_b_handle = secondary_b.clone();
        let composite = CompositeSink::new(
            Box::new(primary),
            vec![Box::new(secondary_a), Box::new(secondary_b)],
        );

        let result = composite.append_batch(batch()).await.unwrap();
        assert_eq!(result.accepted_count, 1);
        assert!(result.warnings.is_empty());
        assert_eq!(primary_handle.batches().len(), 1);
        assert_eq!(secondary_a_handle.batches().len(), 1);
        assert_eq!(secondary_b_handle.batches().len(), 1);
    }
}

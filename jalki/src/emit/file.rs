use std::path::PathBuf;

use async_trait::async_trait;
use false_protocol::Occurrence;
use tokio::io::AsyncWriteExt;

use crate::emitter::{EmitError, Emitter, HealthStatus};

/// Emits Occurrences as newline-delimited JSON to a file.
pub struct FileEmitter {
    path: PathBuf,
}

impl FileEmitter {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

#[async_trait]
impl Emitter for FileEmitter {
    fn name(&self) -> &str {
        "file"
    }

    async fn emit(&self, occurrences: &[Occurrence]) -> Result<(), EmitError> {
        let mut file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .await
            .map_err(|e| EmitError::Failed {
                destination: self.path.display().to_string(),
                source: e.into(),
            })?;

        for occ in occurrences {
            let mut json = serde_json::to_string(occ).map_err(|e| EmitError::Failed {
                destination: self.path.display().to_string(),
                source: e.into(),
            })?;
            json.push('\n');
            file.write_all(json.as_bytes())
                .await
                .map_err(|e| EmitError::Failed {
                    destination: self.path.display().to_string(),
                    source: e.into(),
                })?;
        }

        Ok(())
    }

    async fn health(&self) -> HealthStatus {
        // Check if we can open the file for writing.
        match tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .await
        {
            Ok(_) => HealthStatus::Healthy,
            Err(_) => HealthStatus::Unhealthy,
        }
    }
}

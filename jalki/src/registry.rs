use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use anyhow::{Context, Result};
use aya::programs::{FEntry, FExit};
use aya::{Btf, Ebpf};
use chrono::{DateTime, Utc};
use false_protocol::Occurrence;
use tokio::sync::mpsc;
use tracing::info;

use crate::probe::{Attachment, Probe};
use crate::reader::{self, ProbeStats};
use crate::store::EventStore;

/// Unique identifier for an attached probe instance.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProbeId(String);

impl ProbeId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ProbeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Status of a single attached probe.
#[derive(Debug, Clone)]
pub struct ProbeStatus {
    pub probe_id: String,
    pub function: String,
    pub name: String,
    pub attached_since: DateTime<Utc>,
    pub events_total: u64,
    pub ring_buffer_drops: u64,
    pub sample_rate: f64,
}

struct AttachedProbe {
    probe: Arc<dyn Probe>,
    attached_since: DateTime<Utc>,
    stats: Arc<ProbeStats>,
}

/// Registry of attached probes. Supports runtime attachment and detachment.
///
/// The eBPF object contains all compiled probes. At startup, only configured
/// probes attach. At runtime, any probe in the object can be activated by name.
pub struct ProbeRegistry {
    attached: RwLock<HashMap<String, AttachedProbe>>,
    next_id: AtomicU64,
}

impl ProbeRegistry {
    pub fn new() -> Self {
        Self {
            attached: RwLock::new(HashMap::new()),
            next_id: AtomicU64::new(1),
        }
    }

    /// Attach a probe at runtime. Loads the eBPF program, starts the reader,
    /// and begins flowing events into the store and emit channel.
    pub fn attach(
        &self,
        probe: Arc<dyn Probe>,
        ebpf: &mut Ebpf,
        btf: &Btf,
        cluster: &str,
        tx: mpsc::Sender<Occurrence>,
        _store: &Arc<EventStore>,
    ) -> Result<ProbeId> {
        let function = probe.attachments().first()
            .map(|a| match a {
                Attachment::Fentry { function } | Attachment::Fexit { function } => *function,
            })
            .unwrap_or("unknown");

        // Check if already attached.
        {
            let attached = self.attached.read().unwrap();
            if attached.values().any(|a| a.probe.name() == probe.name()) {
                anyhow::bail!("probe '{}' is already attached", probe.name());
            }
        }

        // Attach the eBPF program.
        let prog_name = probe.program_name();
        for attachment in probe.attachments() {
            match attachment {
                Attachment::Fentry { function } => {
                    let prog: &mut FEntry = ebpf
                        .program_mut(prog_name)
                        .ok_or_else(|| anyhow::anyhow!("program {prog_name} not found"))?
                        .try_into()
                        .context("not an fentry")?;
                    prog.load(function, btf)
                        .with_context(|| format!("failed to load fentry/{function}"))?;
                    prog.attach()
                        .with_context(|| format!("failed to attach fentry/{function}"))?;
                }
                Attachment::Fexit { function } => {
                    let prog: &mut FExit = ebpf
                        .program_mut(prog_name)
                        .ok_or_else(|| anyhow::anyhow!("program {prog_name} not found"))?
                        .try_into()
                        .context("not an fexit")?;
                    prog.load(function, btf)
                        .with_context(|| format!("failed to load fexit/{function}"))?;
                    prog.attach()
                        .with_context(|| format!("failed to attach fexit/{function}"))?;
                }
            }
        }

        // Start the reader.
        let stats = Arc::new(ProbeStats::new());
        reader::spawn_reader(
            ebpf,
            probe.clone(),
            cluster.to_string(),
            tx,
            stats.clone(),
        )?;

        let id_num = self.next_id.fetch_add(1, Ordering::Relaxed);
        let probe_id = format!("probe_{:03}", id_num);

        info!(
            probe_id = %probe_id,
            function = function,
            name = probe.name(),
            "probe attached at runtime"
        );

        let entry = AttachedProbe {
            probe,
            attached_since: Utc::now(),
            stats,
        };

        self.attached.write().unwrap().insert(probe_id.clone(), entry);
        Ok(ProbeId(probe_id))
    }

    /// Register a probe that was attached at startup (by the loader).
    pub fn register_startup_probe(&self, probe: Arc<dyn Probe>, stats: Arc<ProbeStats>) -> ProbeId {
        let id_num = self.next_id.fetch_add(1, Ordering::Relaxed);
        let probe_id = format!("probe_{:03}", id_num);

        let entry = AttachedProbe {
            probe,
            attached_since: Utc::now(),
            stats,
        };

        self.attached.write().unwrap().insert(probe_id.clone(), entry);
        ProbeId(probe_id)
    }

    /// Check if a probe for a given function is already attached.
    pub fn is_attached(&self, function: &str) -> bool {
        let attached = self.attached.read().unwrap();
        attached.values().any(|a| {
            a.probe.attachments().iter().any(|att| match att {
                Attachment::Fentry { function: f } | Attachment::Fexit { function: f } => *f == function,
            })
        })
    }

    /// Get status of all attached probes.
    pub fn status(&self) -> Vec<ProbeStatus> {
        let attached = self.attached.read().unwrap();
        attached
            .iter()
            .map(|(id, entry)| {
                let function = entry.probe.attachments().first()
                    .map(|a| match a {
                        Attachment::Fentry { function } | Attachment::Fexit { function } => function.to_string(),
                    })
                    .unwrap_or_default();

                ProbeStatus {
                    probe_id: id.clone(),
                    function,
                    name: entry.probe.name().to_string(),
                    attached_since: entry.attached_since,
                    events_total: entry.stats.events_emitted.load(Ordering::Relaxed),
                    ring_buffer_drops: entry.stats.events_dropped.load(Ordering::Relaxed),
                    sample_rate: entry.probe.sample_rate(),
                }
            })
            .collect()
    }

    /// Get status by probe ID.
    pub fn get_status(&self, probe_id: &str) -> Option<ProbeStatus> {
        self.status().into_iter().find(|s| s.probe_id == probe_id)
    }
}

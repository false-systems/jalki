use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use anyhow::{Context, Result};
use aya::programs::{FEntry, FExit, TracePoint};
use aya::{Btf, Ebpf};
use chrono::{DateTime, Utc};
use jalki_evidence::EvidenceRecord;
use tokio::sync::mpsc;
use tracing::info;

use crate::enrich::RuntimeEnricher;
use crate::metrics::Metrics;
use crate::probe::{Attachment, Probe};
use crate::reader::{self, ProbeStats, ReaderStop};
use crate::sensitive_paths::SensitivePathMatcher;
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
    /// `None` for startup probes: they are attached by the loader from the
    /// shared eBPF object, so stopping one reader would not release anything —
    /// the object stays alive for the others. Only runtime-generated probes own
    /// their object and can therefore be genuinely unloaded (#19).
    stop: Option<ReaderStop>,
}

/// Registry of attached probes, with runtime attach and detach.
///
/// Detach applies only to runtime-generated probes. Startup probes share the
/// daemon's single eBPF object, so there is nothing to release by stopping one
/// reader and detaching one would only blind a producer lane (#19).
///
/// The eBPF object contains all compiled probes. At startup, only configured
/// probes attach. At runtime, any probe in the object can be activated by name.
pub struct ProbeRegistry {
    attached: RwLock<HashMap<String, AttachedProbe>>,
    next_id: AtomicU64,
}

impl Default for ProbeRegistry {
    fn default() -> Self {
        Self::new()
    }
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
    // Reader setup is genuinely one cohesive bundle (probe, cluster, channel,
    // stats, store, enricher, matcher). Threading it through a params struct —
    // the shape `SinkLoop` uses in runtime.rs — would read better, but it is a
    // call-site refactor and this commit exists to make CI green, not to move
    // code. Tracked separately.
    #[allow(clippy::too_many_arguments)]
    pub fn attach(
        &self,
        probe: Arc<dyn Probe>,
        ebpf: &mut Ebpf,
        btf: &Btf,
        cluster: &str,
        tx: mpsc::Sender<Vec<EvidenceRecord>>,
        metrics: Arc<Metrics>,
        store: &Arc<EventStore>,
        enricher: Arc<dyn RuntimeEnricher>,
        sensitive_path_matcher: Arc<SensitivePathMatcher>,
    ) -> Result<ProbeId> {
        let function = probe
            .attachments()
            .first()
            .map(|a| match a {
                Attachment::Fentry { function } | Attachment::Fexit { function } => *function,
                Attachment::Tracepoint { name, .. } => *name,
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
                Attachment::Tracepoint {
                    program,
                    category,
                    name,
                } => {
                    let prog: &mut TracePoint = ebpf
                        .program_mut(program)
                        .ok_or_else(|| anyhow::anyhow!("program {program} not found"))?
                        .try_into()
                        .context("not a tracepoint")?;
                    prog.load()
                        .with_context(|| format!("failed to load tracepoint/{category}/{name}"))?;
                    prog.attach(category, name).with_context(|| {
                        format!("failed to attach tracepoint/{category}/{name}")
                    })?;
                }
            }
        }

        // Start the reader.
        let stats = Arc::new(ProbeStats::new());
        let stop = reader::spawn_reader(
            ebpf,
            probe.clone(),
            cluster.to_string(),
            tx,
            stats.clone(),
            metrics,
            store.clone(),
            enricher,
            sensitive_path_matcher,
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
            stop: Some(stop),
        };

        self.attached
            .write()
            .unwrap()
            .insert(probe_id.clone(), entry);
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
            stop: None,
        };

        self.attached
            .write()
            .unwrap()
            .insert(probe_id.clone(), entry);
        ProbeId(probe_id)
    }

    /// Check if a probe for a given function is already attached.
    /// Detach a runtime-attached probe: stop its reader and forget it.
    ///
    /// Returns the probe name so the caller can log what went, and
    /// `Ok(None)` for an unknown id — detaching something already gone is the
    /// state the caller asked for, so it is a no-op rather than an error.
    ///
    /// Refuses a startup probe. Those share the daemon's single eBPF object,
    /// so stopping one reader would release nothing and would silently blind a
    /// producer lane that the deployment expects to be running. Undoing the
    /// startup set is a restart, not a runtime operation.
    ///
    /// Stopping the reader is what makes unloading possible: the reader owns
    /// the `RingBuf`, and the map it borrows cannot be released while it lives.
    /// The caller drops the generated `Ebpf` afterwards, which unloads the
    /// programs.
    pub fn detach(&self, probe_id: &str) -> Result<Option<String>> {
        let mut attached = self.attached.write().unwrap();
        let Some(entry) = attached.get(probe_id) else {
            return Ok(None);
        };
        let Some(stop) = entry.stop.clone() else {
            anyhow::bail!(
                "probe '{probe_id}' was attached at startup and shares the daemon's \
                 eBPF object; it cannot be detached at runtime"
            );
        };
        stop.stop();
        let name = attached
            .remove(probe_id)
            .map(|e| e.probe.name().to_string())
            .unwrap_or_default();
        info!(probe_id = %probe_id, name = %name, "probe detached at runtime");
        Ok(Some(name))
    }

    pub fn is_attached(&self, function: &str) -> bool {
        let attached = self.attached.read().unwrap();
        attached.values().any(|a| {
            a.probe.attachments().iter().any(|att| match att {
                Attachment::Fentry { function: f } | Attachment::Fexit { function: f } => {
                    *f == function
                }
                Attachment::Tracepoint { name, .. } => *name == function,
            })
        })
    }

    /// Get status of all attached probes.
    pub fn status(&self) -> Vec<ProbeStatus> {
        let attached = self.attached.read().unwrap();
        attached
            .iter()
            .map(|(id, entry)| {
                let function = entry
                    .probe
                    .attachments()
                    .first()
                    .map(|a| match a {
                        Attachment::Fentry { function } | Attachment::Fexit { function } => {
                            function.to_string()
                        }
                        Attachment::Tracepoint { name, .. } => name.to_string(),
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

    pub(crate) fn observability_stats(&self) -> Vec<(String, Arc<ProbeStats>)> {
        self.attached
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .values()
            .map(|entry| (entry.probe.name().to_string(), entry.stats.clone()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A startup probe shares the daemon's single eBPF object, so stopping its
    /// reader releases nothing — it would just blind a producer lane the
    /// deployment expects to be running, with no way to get it back short of a
    /// restart. Refusing is the honest answer.
    #[test]
    fn a_startup_probe_cannot_be_detached() {
        let registry = ProbeRegistry::new();
        let stats = Arc::new(ProbeStats::new());
        let id = registry.register_startup_probe(
            Arc::new(crate::probes::tcp_connect::TcpConnect::new()),
            stats,
        );

        let err = registry
            .detach(id.as_str())
            .expect_err("must refuse, not silently succeed");
        assert!(
            err.to_string().contains("attached at startup"),
            "the refusal must say why: {err}"
        );
        assert!(
            registry.get_status(id.as_str()).is_some(),
            "and the probe must still be attached after the refusal"
        );
    }

    /// Detaching something already gone leaves the caller in the state they
    /// asked for, so it is a no-op. That makes a retry after a partial failure
    /// safe, which matters because the caller cannot easily tell the two apart.
    #[test]
    fn detaching_an_unknown_probe_is_a_no_op() {
        let registry = ProbeRegistry::new();
        assert_eq!(registry.detach("probe_999").unwrap(), None);
    }
}

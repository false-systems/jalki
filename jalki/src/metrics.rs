use prometheus_client::encoding::text::encode;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;
use std::sync::atomic::AtomicU64;

/// Label for per-probe metrics.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct ProbeLabel {
    pub probe: String,
}

impl prometheus_client::encoding::EncodeLabelSet for ProbeLabel {
    fn encode(
        &self,
        mut encoder: prometheus_client::encoding::LabelSetEncoder<'_>,
    ) -> Result<(), std::fmt::Error> {
        use prometheus_client::encoding::EncodeLabelValue;
        let mut label = encoder.encode_label();
        let mut key = label.encode_label_key()?;
        prometheus_client::encoding::EncodeLabelKey::encode(&"probe", &mut key)?;
        let mut value = key.encode_label_value()?;
        self.probe.encode(&mut value)?;
        value.finish()
    }
}

/// Label for per-sink metrics.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct SinkLabel {
    pub sink: String,
}

/// Label for unbound records dropped from the neutral Plane-B projection.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct UnboundDropLabel {
    pub reason: String,
}

impl prometheus_client::encoding::EncodeLabelSet for UnboundDropLabel {
    fn encode(
        &self,
        mut encoder: prometheus_client::encoding::LabelSetEncoder<'_>,
    ) -> Result<(), std::fmt::Error> {
        use prometheus_client::encoding::EncodeLabelValue;
        let mut label = encoder.encode_label();
        let mut key = label.encode_label_key()?;
        prometheus_client::encoding::EncodeLabelKey::encode(&"reason", &mut key)?;
        let mut value = key.encode_label_value()?;
        self.reason.encode(&mut value)?;
        value.finish()
    }
}

impl prometheus_client::encoding::EncodeLabelSet for SinkLabel {
    fn encode(
        &self,
        mut encoder: prometheus_client::encoding::LabelSetEncoder<'_>,
    ) -> Result<(), std::fmt::Error> {
        use prometheus_client::encoding::EncodeLabelValue;
        let mut label = encoder.encode_label();
        let mut key = label.encode_label_key()?;
        prometheus_client::encoding::EncodeLabelKey::encode(&"sink", &mut key)?;
        let mut value = key.encode_label_value()?;
        self.sink.encode(&mut value)?;
        value.finish()
    }
}

pub struct Metrics {
    pub registry: Registry,
    pub events_total: Family<ProbeLabel, Counter>,
    pub ring_buffer_drops: Family<ProbeLabel, Counter>,
    pub attach_errors: Family<ProbeLabel, Counter>,
    pub sink_errors: Family<SinkLabel, Counter>,
    pub unbound_dropped_total: Family<UnboundDropLabel, Counter>,
    pub binding_cache_entries: Gauge,
    pub binding_cache_hit_ratio: Gauge<f64, AtomicU64>,
    /// Retry-buffer depth and age (jalki #42). Before these, buffer state was
    /// visible only in log lines, so "is this agent holding evidence it cannot
    /// deliver?" was not a question Prometheus could answer or alert on — and
    /// during the Jul 28-29 incident the only failure signal jälki gave was
    /// process exit.
    pub retry_queued_batches: Gauge,
    pub retry_queued_records: Gauge,
    pub retry_queued_bytes: Gauge,
    /// Age of the oldest queued batch. The one to alert on: depth says how much
    /// is waiting, age says whether anything is moving.
    pub retry_oldest_age_seconds: Gauge<f64, AtomicU64>,
    /// Fraction of the pod's memory limit in use (jalki #33). Stays 0 when the
    /// agent could not resolve its own cgroup, which is a real state and not
    /// the same as "no pressure" — the startup log says which.
    pub memory_usage_ratio: Gauge<f64, AtomicU64>,
    /// Bytes of backlog currently on disk (jalki #33). 0 means either nothing
    /// buffered or no spool — `/readyz` and the log distinguish them.
    pub spool_bytes: Gauge,
    /// 1 while memory sits at/above the shed watermark AND shedding the entire
    /// retry buffer could not bring it back under — the state that preceded
    /// the 2026-08-07 OOM (jalki#76): working set at 71% of the limit with
    /// ~20MB buffered. Shedding governs buffered evidence; when the growth is
    /// the process's own working set, shedding structurally cannot help, and
    /// that must be a first-class signal rather than something reconstructed
    /// from three metrics after the kill.
    pub memory_ceiling_no_shed: Gauge,
    /// The reader→sink queue (jalki#97): estimated resident bytes and
    /// messages waiting for the sink loop. Updated by the queue itself, so
    /// they stay live while the loop is parked inside a slow append.
    pub sink_queue_bytes: Gauge,
    pub sink_queue_messages: Gauge,
    /// The configured budget (`JALKI_QUEUE_MAX_BYTES`), so a fill ratio needs
    /// no knowledge of the environment.
    pub sink_queue_max_bytes: Gauge,
    /// 1 while memory pressure holds the queue to its smaller pressure budget
    /// (`max_bytes / 8`, at least 4 MiB): refusals then happen far below
    /// `sink_queue_max_bytes`, and this says why.
    pub sink_queue_memory_pressure: Gauge,
    /// Records the queue refused, per probe. Each refusal is also reported as
    /// `jalki.agent.gap` evidence; this is the off-node copy to alert on.
    pub sink_queue_dropped: Family<ProbeLabel, Counter>,
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

impl Metrics {
    pub fn new() -> Self {
        let mut registry = Registry::default();

        // Registered without the `_total` suffix: prometheus-client appends
        // it to every counter, so this is scraped as `jalki_events_total`.
        // (Registered as `jalki_events_total` it was `_total_total`, and never
        // had a sample — nothing incremented it before jalki#97.)
        let events_total = Family::<ProbeLabel, Counter>::default();
        registry.register(
            "jalki_events",
            "Records captured per probe: past the sensitive-path gate and into \
             the local store, before the namespace scope (the count `jalki \
             status` shows as events_total)",
            events_total.clone(),
        );

        let ring_buffer_drops = Family::<ProbeLabel, Counter>::default();
        registry.register(
            "jalki_ring_buffer_drops",
            "Events dropped due to full ring buffer per probe",
            ring_buffer_drops.clone(),
        );

        let attach_errors = Family::<ProbeLabel, Counter>::default();
        registry.register(
            "jalki_attach_errors",
            "Failed probe attachments",
            attach_errors.clone(),
        );

        let sink_errors = Family::<SinkLabel, Counter>::default();
        registry.register(
            "jalki_sink_errors",
            "Append failures per evidence sink",
            sink_errors.clone(),
        );

        let unbound_dropped_total = Family::<UnboundDropLabel, Counter>::default();
        registry.register(
            "jalki_unbound_dropped_total",
            "Plane B records dropped because runtime binding was missing or weak",
            unbound_dropped_total.clone(),
        );

        let binding_cache_entries = Gauge::default();
        registry.register(
            "jalki_binding_cache_entries",
            "Current number of cached runtime container bindings",
            binding_cache_entries.clone(),
        );

        let binding_cache_hit_ratio = Gauge::<f64, AtomicU64>::default();
        registry.register(
            "jalki_binding_cache_hit_ratio",
            "Runtime binding cache hit ratio since process start",
            binding_cache_hit_ratio.clone(),
        );

        let retry_queued_batches = Gauge::default();
        registry.register(
            "jalki_retry_queued_batches",
            "Evidence batches held in the retry buffer awaiting delivery",
            retry_queued_batches.clone(),
        );

        let retry_queued_records = Gauge::default();
        registry.register(
            "jalki_retry_queued_records",
            "Evidence records held in the retry buffer awaiting delivery",
            retry_queued_records.clone(),
        );

        let retry_queued_bytes = Gauge::default();
        registry.register(
            "jalki_retry_queued_bytes",
            "Approximate bytes held in the retry buffer (the bound that keeps a \
             sink outage from OOMing the agent)",
            retry_queued_bytes.clone(),
        );

        let retry_oldest_age_seconds = Gauge::<f64, AtomicU64>::default();
        registry.register(
            "jalki_retry_oldest_age_seconds",
            "Age of the oldest batch in the retry buffer; 0 when empty",
            retry_oldest_age_seconds.clone(),
        );

        let spool_bytes = Gauge::default();
        registry.register(
            "jalki_spool_bytes",
            "Bytes of undelivered evidence persisted to disk",
            spool_bytes.clone(),
        );

        let memory_ceiling_no_shed = Gauge::default();
        registry.register(
            "jalki_memory_ceiling_no_shed",
            "1 while memory is at/above the shed watermark and neither shedding \
             the whole retry buffer nor draining the reader→sink queue to its \
             pressure budget could bring it back below it — growth is the \
             process working set, not buffered evidence (jalki#76)",
            memory_ceiling_no_shed.clone(),
        );

        let memory_usage_ratio = Gauge::<f64, AtomicU64>::default();
        registry.register(
            "jalki_memory_usage_ratio",
            "Fraction of the pod memory limit in use; 0 when the cgroup limit \
             could not be resolved",
            memory_usage_ratio.clone(),
        );

        let sink_queue_bytes = Gauge::default();
        registry.register(
            "jalki_sink_queue_bytes",
            "Estimated resident bytes of evidence waiting in the reader→sink \
             queue (bounded by JALKI_QUEUE_MAX_BYTES)",
            sink_queue_bytes.clone(),
        );

        let sink_queue_messages = Gauge::default();
        registry.register(
            "jalki_sink_queue_messages",
            "Messages waiting in the reader→sink queue, including a pending gap \
             marker",
            sink_queue_messages.clone(),
        );

        let sink_queue_max_bytes = Gauge::default();
        registry.register(
            "jalki_sink_queue_max_bytes",
            "Configured budget of the reader→sink queue (JALKI_QUEUE_MAX_BYTES)",
            sink_queue_max_bytes.clone(),
        );

        let sink_queue_memory_pressure = Gauge::default();
        registry.register(
            "jalki_sink_queue_memory_pressure",
            "1 while memory pressure holds the reader→sink queue to its smaller \
             pressure budget (max_bytes / 8, at least 4 MiB)",
            sink_queue_memory_pressure.clone(),
        );

        // Exposed as `jalki_sink_queue_dropped_total` (the client appends the
        // suffix).
        let sink_queue_dropped = Family::<ProbeLabel, Counter>::default();
        registry.register(
            "jalki_sink_queue_dropped",
            "Records the reader→sink queue refused because it was full, per \
             probe; each refusal is also reported as jalki.agent.gap evidence",
            sink_queue_dropped.clone(),
        );

        Self {
            registry,
            events_total,
            ring_buffer_drops,
            attach_errors,
            sink_errors,
            unbound_dropped_total,
            binding_cache_entries,
            binding_cache_hit_ratio,
            retry_queued_batches,
            retry_queued_records,
            retry_queued_bytes,
            retry_oldest_age_seconds,
            memory_usage_ratio,
            spool_bytes,
            memory_ceiling_no_shed,
            sink_queue_bytes,
            sink_queue_messages,
            sink_queue_max_bytes,
            sink_queue_memory_pressure,
            sink_queue_dropped,
        }
    }

    /// Encode all metrics as Prometheus text format.
    pub fn encode(&self) -> String {
        let mut buf = String::new();
        let _ = encode(&mut buf, &self.registry);
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// prometheus-client appends `_total` to every counter it exposes, so a
    /// counter registered as `jalki_events_total` is scraped as
    /// `jalki_events_total_total` — not the name the docs and the alerts use.
    #[test]
    fn events_total_is_exposed_under_its_documented_name() {
        let metrics = Metrics::new();
        metrics
            .events_total
            .get_or_create(&ProbeLabel {
                probe: "tcp_connect".into(),
            })
            .inc_by(3);

        let text = metrics.encode();
        assert!(
            text.contains("jalki_events_total{probe=\"tcp_connect\"} 3"),
            "{text}"
        );
        assert!(!text.contains("jalki_events_total_total"), "{text}");
    }
}

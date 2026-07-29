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
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

impl Metrics {
    pub fn new() -> Self {
        let mut registry = Registry::default();

        let events_total = Family::<ProbeLabel, Counter>::default();
        registry.register(
            "jalki_events_total",
            "Total events emitted per probe",
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
        }
    }

    /// Encode all metrics as Prometheus text format.
    pub fn encode(&self) -> String {
        let mut buf = String::new();
        let _ = encode(&mut buf, &self.registry);
        buf
    }
}

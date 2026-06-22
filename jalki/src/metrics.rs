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

        Self {
            registry,
            events_total,
            ring_buffer_drops,
            attach_errors,
            sink_errors,
            unbound_dropped_total,
            binding_cache_entries,
            binding_cache_hit_ratio,
        }
    }

    /// Encode all metrics as Prometheus text format.
    pub fn encode(&self) -> String {
        let mut buf = String::new();
        let _ = encode(&mut buf, &self.registry);
        buf
    }
}

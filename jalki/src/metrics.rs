use prometheus_client::encoding::text::encode;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::registry::Registry;

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

        Self {
            registry,
            events_total,
            ring_buffer_drops,
            attach_errors,
            sink_errors,
        }
    }

    /// Encode all metrics as Prometheus text format.
    pub fn encode(&self) -> String {
        let mut buf = String::new();
        let _ = encode(&mut buf, &self.registry);
        buf
    }
}

use jalki_evidence::{HookKind, KernelEvent, NormalizedEvidence, ProbeMetadata};
use thiserror::Error;

/// Error from probe event conversion.
#[derive(Debug, Error)]
pub enum ProbeError {
    #[error("event too short: expected {expected} bytes, got {actual}")]
    TooShort { expected: usize, actual: usize },

    #[error("invalid event data: {0}")]
    InvalidData(String),
}

impl From<jalki_evidence::DecodeError> for ProbeError {
    fn from(err: jalki_evidence::DecodeError) -> Self {
        match err {
            jalki_evidence::DecodeError::TooShort { expected, actual } => {
                ProbeError::TooShort { expected, actual }
            }
            jalki_evidence::DecodeError::Invalid(msg) => ProbeError::InvalidData(msg),
        }
    }
}

/// How a probe attaches to a kernel function.
#[derive(Debug, Clone)]
pub enum Attachment {
    Fentry { function: &'static str },
    Fexit { function: &'static str },
}

impl Attachment {
    pub fn hook_kind(&self) -> HookKind {
        match self {
            Attachment::Fentry { .. } => HookKind::Fentry,
            Attachment::Fexit { .. } => HookKind::Fexit,
        }
    }

    pub fn function(&self) -> &'static str {
        match self {
            Attachment::Fentry { function } | Attachment::Fexit { function } => function,
        }
    }
}

/// A kernel probe that converts raw ring buffer events to FALSE Protocol Occurrences.
///
/// This is the core abstraction. Implement this trait to observe any kernel function.
/// jälki handles eBPF loading, BTF attachment, ring buffer management, self-filtering,
/// and emission. You just describe what to observe and how to interpret it.
pub trait Probe: Send + Sync + 'static {
    /// Kernel function(s) this probe attaches to.
    fn attachments(&self) -> &[Attachment];

    /// Name used in metrics, logging, and the event `source` field.
    fn name(&self) -> &str;

    /// eBPF program name in the ELF object.
    ///
    /// This must match the function name annotated with `#[fentry]`/`#[fexit]`
    /// in the jalki-ebpf crate. The loader uses this to find and attach the program.
    fn program_name(&self) -> &str;

    /// Name of the BPF ring buffer map for this probe.
    ///
    /// Must match the `#[map]` name in the eBPF program.
    fn ring_buffer_map(&self) -> &str;

    /// Probe version carried in emitted evidence metadata.
    fn probe_version(&self) -> &str {
        "1"
    }

    /// Probe family carried in emitted evidence metadata.
    fn family(&self) -> &str {
        match self.name().split('_').next() {
            Some(family) if !family.is_empty() => family,
            _ => self.name(),
        }
    }

    /// Decode raw ring buffer bytes to a typed kernel event.
    fn decode_event(&self, raw: &[u8]) -> Result<KernelEvent, ProbeError>;

    /// Metadata constant for records produced by this probe.
    fn probe_metadata(&self) -> ProbeMetadata {
        let attachment = self.attachments().first();
        ProbeMetadata {
            probe_id: self.name().into(),
            probe_version: self.probe_version().into(),
            probe_family: self.family().into(),
            hook_kind: attachment
                .map(Attachment::hook_kind)
                .unwrap_or(HookKind::Fentry),
            kernel_function: attachment
                .map(Attachment::function)
                .unwrap_or("unknown")
                .into(),
        }
    }

    /// Convert raw ring buffer bytes to normalized evidence records.
    fn to_evidence(&self, raw: &[u8], cluster: &str) -> Result<NormalizedEvidence, ProbeError> {
        let event = self.decode_event(raw)?;
        Ok(event.normalize(self.probe_metadata(), cluster))
    }

    /// Sampling rate: 1.0 = all events, 0.1 = 10%.
    /// Applied in the reader — events below the threshold are dropped before
    /// reaching the emit pipeline.
    fn sample_rate(&self) -> f64 {
        1.0
    }
}

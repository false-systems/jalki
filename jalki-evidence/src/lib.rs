//! Typed kernel-event model and FALSE Protocol normalization for jälki.
//!
//! The pipeline is: raw ring-buffer bytes -> [`KernelEvent`] (decode) -> FALSE
//! Protocol records (normalize). This crate owns the middle, typed representation
//! and the conversion to records. It deliberately carries no `aya` dependency, so
//! it compiles and tests on hosts where the kernel layer cannot build.
//!
//! See `docs/jalki/adr/0001-evidence-sinks-and-probe-intelligence.md` (decision D3).

pub mod event;
pub mod evidence;
pub mod normalize;
pub mod retry;
pub mod sink;

pub use event::{
    DecodeError, KernelEvent, ProcessExecEvent, TcpCloseEvent, TcpConnectEvent, TcpRetransmitEvent,
    TcpState,
};
pub use evidence::{
    BindingProvenance, EvidenceBatch, EvidenceRecord, HookKind, NormalizedEvidence, ProbeMetadata,
    ProducerMetadata, RuntimeBinding, UnboundReason,
};
pub use normalize::errno_name;
pub use retry::{GapReport, RetryBuffer, RetryBufferConfig};
pub use sink::{
    AppendResult, Checkpoint, CompositeSink, EvidenceSink, FileSink, HealthStatus, PipelineClient,
    PipelineError, PipelineResponse, PipelineSink, SinkError, StdoutSink,
};

/// BPF probe codegen — generate fentry/fexit programs at runtime from BTF.
///
/// Given a probe descriptor (function name, attachment type, fields to extract),
/// generates valid BPF bytecode as an ELF loadable by aya. No C, no clang,
/// no pre-compiled eBPF object needed.
///
/// ```text
/// ProbeSpec → BTF resolution → BPF instructions → ELF → aya::Ebpf::load()
/// ```
pub mod btf;
pub mod elf;
pub mod error;
pub mod insn;
pub mod program;

use btf::BtfData;
use error::CodegenError;
use program::{AttachType, ProbeSpec};

/// Ring buffer size for generated probes (4 MB).
const DEFAULT_RINGBUF_SIZE: u32 = 4 * 1024 * 1024;

/// A fully generated probe — ELF bytes + metadata for the reader.
#[derive(Debug)]
pub struct GeneratedProbe {
    /// Raw BPF ELF bytes, loadable by `aya::Ebpf::load()`.
    pub elf_bytes: Vec<u8>,
    /// Ring buffer map name in the ELF.
    pub map_name: String,
    /// Size of each event in bytes.
    pub event_size: usize,
    /// Field layout for deserializing raw events back to Occurrences.
    pub field_layout: Vec<program::FieldLayout>,
    /// The probe spec that was used to generate this.
    pub spec: ProbeSpec,
}

/// Generate a complete BPF probe from a spec.
///
/// The returned `GeneratedProbe` contains ELF bytes loadable by aya,
/// plus the metadata needed to deserialize events from the ring buffer.
pub fn generate(spec: &ProbeSpec, btf: &BtfData) -> Result<GeneratedProbe, CodegenError> {
    let program = program::generate(spec, btf)?;

    let elf_bytes = elf::generate_elf(
        &spec.function,
        spec.attachment,
        &program.instructions,
        &program.relocations,
        &program.map_name,
        DEFAULT_RINGBUF_SIZE,
    )?;

    Ok(GeneratedProbe {
        elf_bytes,
        map_name: program.map_name,
        event_size: program.event_size,
        field_layout: program.field_layout,
        spec: spec.clone(),
    })
}

/// Convenience: generate from simple parameters.
pub fn generate_for_function(
    btf: &BtfData,
    function: &str,
    attachment: &str,
    fields: &[String],
    event_type: &str,
) -> Result<GeneratedProbe, CodegenError> {
    let attach_type = match attachment {
        "fentry" => AttachType::Fentry,
        "fexit" => AttachType::Fexit,
        other => return Err(CodegenError::BtfType(format!("unknown attachment: {other}"))),
    };

    let spec = ProbeSpec {
        function: function.to_string(),
        attachment: attach_type,
        fields: fields.to_vec(),
        event_type: event_type.to_string(),
    };

    generate(&spec, btf)
}

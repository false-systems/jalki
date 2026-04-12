/// Generate a valid BPF ELF that aya can load.
///
/// Uses the `object` crate's write module to construct a minimal ELF with:
/// - Program section (fentry/<fn> or fexit/<fn>)
/// - Map definitions (PID_FILTER hash + ring buffer)
/// - License section ("GPL")
/// - Relocations for map FD references
use object::write::{Object, Symbol, SymbolSection};
use object::{Architecture, BinaryFormat, Endianness, SectionKind, SymbolFlags, SymbolKind, SymbolScope};

use crate::error::CodegenError;
use crate::insn::{encode, BpfInsn};
use crate::program::{AttachType, MAP_IDX_PID_FILTER, MAP_IDX_RINGBUF};

/// BPF map definition struct (legacy format — 20 bytes).
/// Matches the kernel's `struct bpf_map_def`.
#[repr(C)]
struct BpfMapDef {
    map_type: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    map_flags: u32,
}

const BPF_MAP_TYPE_HASH: u32 = 1;
const BPF_MAP_TYPE_RINGBUF: u32 = 27;

/// Relocation type for BPF 64-bit immediate (map fd).
const R_BPF_64_64: u32 = 1;

/// Generate a loadable BPF ELF from instructions and metadata.
pub fn generate_elf(
    function: &str,
    attach_type: AttachType,
    instructions: &[BpfInsn],
    relocations: &[(usize, usize)], // (insn_offset, map_index)
    ringbuf_map_name: &str,
    ringbuf_size: u32,
) -> Result<Vec<u8>, CodegenError> {
    let mut obj = Object::new(BinaryFormat::Elf, Architecture::Bpf, Endianness::Little);

    // === Maps section ===
    // Define PID_FILTER and the ring buffer as legacy bpf_map_def entries
    // in a "maps" section. Each map is a named subsection.

    let pid_filter_def = BpfMapDef {
        map_type: BPF_MAP_TYPE_HASH,
        key_size: 4,
        value_size: 1,
        max_entries: 64,
        map_flags: 0,
    };

    let ringbuf_def = BpfMapDef {
        map_type: BPF_MAP_TYPE_RINGBUF,
        key_size: 0,
        value_size: 0,
        max_entries: ringbuf_size,
        map_flags: 0,
    };

    // Write maps as individual sections: maps/PID_FILTER, maps/<ringbuf>
    let pid_filter_data = unsafe {
        std::slice::from_raw_parts(
            &pid_filter_def as *const BpfMapDef as *const u8,
            std::mem::size_of::<BpfMapDef>(),
        )
    };
    let pid_filter_section_name = "maps/PID_FILTER".to_string();
    let pid_filter_section = obj.add_section(
        Vec::new(),
        pid_filter_section_name.as_bytes().to_vec(),
        SectionKind::Data,
    );
    obj.set_section_data(pid_filter_section, pid_filter_data, 4);

    // Add symbol for PID_FILTER map.
    let pid_filter_sym = obj.add_symbol(Symbol {
        name: b"PID_FILTER".to_vec(),
        value: 0,
        size: std::mem::size_of::<BpfMapDef>() as u64,
        kind: SymbolKind::Data,
        scope: SymbolScope::Linkage,
        weak: false,
        section: SymbolSection::Section(pid_filter_section),
        flags: SymbolFlags::None,
    });

    let ringbuf_data = unsafe {
        std::slice::from_raw_parts(
            &ringbuf_def as *const BpfMapDef as *const u8,
            std::mem::size_of::<BpfMapDef>(),
        )
    };
    let ringbuf_section_name = format!("maps/{ringbuf_map_name}");
    let ringbuf_section = obj.add_section(
        Vec::new(),
        ringbuf_section_name.as_bytes().to_vec(),
        SectionKind::Data,
    );
    obj.set_section_data(ringbuf_section, ringbuf_data, 4);

    let ringbuf_sym = obj.add_symbol(Symbol {
        name: ringbuf_map_name.as_bytes().to_vec(),
        value: 0,
        size: std::mem::size_of::<BpfMapDef>() as u64,
        kind: SymbolKind::Data,
        scope: SymbolScope::Linkage,
        weak: false,
        section: SymbolSection::Section(ringbuf_section),
        flags: SymbolFlags::None,
    });

    // === License section ===
    let license_section = obj.add_section(
        Vec::new(),
        b"license".to_vec(),
        SectionKind::Data,
    );
    obj.set_section_data(license_section, b"GPL\0", 1);

    // === Program section ===
    let section_name = match attach_type {
        AttachType::Fentry => format!("fentry/{function}"),
        AttachType::Fexit => format!("fexit/{function}"),
    };
    let prog_section = obj.add_section(
        Vec::new(),
        section_name.as_bytes().to_vec(),
        SectionKind::Text,
    );
    let prog_data = encode(instructions);
    obj.set_section_data(prog_section, &prog_data, 8);

    // Add a function symbol for the program.
    let prog_sym_name = format!("jalki_codegen_{function}");
    obj.add_symbol(Symbol {
        name: prog_sym_name.as_bytes().to_vec(),
        value: 0,
        size: prog_data.len() as u64,
        kind: SymbolKind::Text,
        scope: SymbolScope::Linkage,
        weak: false,
        section: SymbolSection::Section(prog_section),
        flags: SymbolFlags::None,
    });

    // === Relocations ===
    // Each relocation points a ld_map_fd instruction to the right map symbol.
    for &(insn_offset, map_index) in relocations {
        let target_sym = match map_index {
            MAP_IDX_PID_FILTER => pid_filter_sym,
            MAP_IDX_RINGBUF => ringbuf_sym,
            _ => return Err(CodegenError::Elf(format!("unknown map index {map_index}"))),
        };

        let byte_offset = insn_offset as u64 * 8; // each instruction is 8 bytes

        obj.add_relocation(
            prog_section,
            object::write::Relocation {
                offset: byte_offset,
                symbol: target_sym,
                addend: 0,
                flags: object::RelocationFlags::Elf {
                    r_type: R_BPF_64_64,
                },
            },
        )
        .map_err(|e| CodegenError::Elf(format!("add relocation: {e}")))?;
    }

    // === Write ELF ===
    obj.write().map_err(|e| CodegenError::Elf(format!("write ELF: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::insn::{self, R0};

    #[test]
    fn generate_minimal_elf() {
        // Simplest possible BPF program: mov r0, 0; exit
        let insns = vec![insn::mov64_imm(R0, 0), insn::exit()];

        let elf = generate_elf(
            "tcp_connect",
            AttachType::Fexit,
            &insns,
            &[], // no relocations
            "TEST_EVENTS",
            4 * 1024 * 1024,
        )
        .expect("should generate ELF");

        // Should be a valid ELF.
        assert!(elf.len() > 64); // at least an ELF header
        assert_eq!(&elf[0..4], b"\x7fELF"); // ELF magic
    }
}

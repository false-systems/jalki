/// Program builder — generate BPF instruction sequences for probe descriptors.
///
/// Given a ProbeDescriptor and BTF metadata, generates a complete BPF program
/// that reads the requested fields from kernel function arguments, writes them
/// to a ring buffer, and handles self-filtering.
use crate::btf::{BtfData, FieldType, PointeeKind};
use crate::error::CodegenError;
use crate::insn::*;

/// Maximum BPF stack size.
const MAX_STACK: usize = 512;

/// Map index for PID_FILTER in the generated ELF.
pub const MAP_IDX_PID_FILTER: usize = 0;
/// Map index for the ring buffer in the generated ELF.
pub const MAP_IDX_RINGBUF: usize = 1;

/// Layout of a single field in the generated event struct.
#[derive(Debug, Clone)]
pub struct FieldLayout {
    pub name: String,
    pub offset: usize,
    pub size: usize,
    pub field_type: FieldType,
}

/// A generated BPF probe — instructions + metadata.
#[derive(Debug)]
pub struct GeneratedProgram {
    /// BPF instructions for the probe.
    pub instructions: Vec<BpfInsn>,
    /// Offsets (in instructions, not bytes) where map FD relocations are needed.
    /// Each entry is (instruction_offset, map_index).
    pub relocations: Vec<(usize, usize)>,
    /// Layout of the event struct written to the ring buffer.
    pub field_layout: Vec<FieldLayout>,
    /// Total event size in bytes.
    pub event_size: usize,
    /// Ring buffer map name.
    pub map_name: String,
}

/// Descriptor for what the generated probe should do.
#[derive(Debug, Clone)]
pub struct ProbeSpec {
    /// Kernel function to hook.
    pub function: String,
    /// fentry or fexit.
    pub attachment: AttachType,
    /// Fields to extract. Each is a "param.field.path" string.
    /// Special names: "pid", "tid", "timestamp_ns", "comm", "ret".
    pub fields: Vec<String>,
    /// Event type for FALSE Protocol.
    pub event_type: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachType {
    Fentry,
    Fexit,
}

/// Generate a BPF program from a probe spec using BTF.
pub fn generate(spec: &ProbeSpec, btf: &BtfData) -> Result<GeneratedProgram, CodegenError> {
    let sig = btf.resolve_function(&spec.function)?;

    // Plan the event layout — figure out what fields we're emitting and their sizes.
    let mut layout = Vec::new();
    let mut offset = 0usize;

    // Always start with: timestamp_ns (u64), pid (u32), tid (u32)
    layout.push(FieldLayout {
        name: "timestamp_ns".into(),
        offset,
        size: 8,
        field_type: FieldType::U64,
    });
    offset += 8;

    layout.push(FieldLayout {
        name: "pid".into(),
        offset,
        size: 4,
        field_type: FieldType::U32,
    });
    offset += 4;

    layout.push(FieldLayout {
        name: "tid".into(),
        offset,
        size: 4,
        field_type: FieldType::U32,
    });
    offset += 4;

    // Resolve requested fields.
    let mut field_reads: Vec<FieldRead> = Vec::new();

    for field_name in &spec.fields {
        match field_name.as_str() {
            "pid" | "tid" | "timestamp_ns" => continue, // already in header
            "comm" => {
                layout.push(FieldLayout {
                    name: "comm".into(),
                    offset,
                    size: 16,
                    field_type: FieldType::U8, // byte array, not a scalar
                });
                field_reads.push(FieldRead::Comm { event_offset: offset });
                offset += 16;
            }
            "ret" => {
                if spec.attachment != AttachType::Fexit {
                    return Err(CodegenError::BtfType(
                        "ret is only available for fexit probes".into(),
                    ));
                }
                layout.push(FieldLayout {
                    name: "ret".into(),
                    offset,
                    size: 4,
                    field_type: FieldType::I32,
                });
                field_reads.push(FieldRead::ReturnValue {
                    event_offset: offset,
                    arg_index: sig.params.len() as u32, // ret is last arg in fexit
                });
                offset += 4;
            }
            other => {
                // Parse "param.field.path" — first component is the param name.
                let (param_name, field_path) = match other.split_once('.') {
                    Some((p, f)) => (p, Some(f)),
                    None => (other, None),
                };

                // Find the param index.
                let (param_idx, param) = sig
                    .params
                    .iter()
                    .enumerate()
                    .find(|(_, p)| p.name == param_name)
                    .ok_or_else(|| CodegenError::FieldNotFound {
                        struct_name: spec.function.clone(),
                        field: param_name.to_string(),
                    })?;

                if let Some(path) = field_path {
                    // Pointer dereference + field access.
                    let struct_type_id = match btf.pointer_pointee(param.type_id) {
                        PointeeKind::Struct { type_id, .. } => type_id,
                        _ => {
                            return Err(CodegenError::BtfType(format!(
                                "param '{}' is not a pointer to struct",
                                param_name
                            )));
                        }
                    };

                    let resolved = btf.resolve_field_offset(struct_type_id, path)?;

                    layout.push(FieldLayout {
                        name: other.to_string(),
                        offset,
                        size: resolved.size,
                        field_type: resolved.field_type,
                    });
                    field_reads.push(FieldRead::ProbeReadKernel {
                        event_offset: offset,
                        arg_index: param_idx as u32,
                        struct_offset: resolved.offset_bytes,
                        size: resolved.size,
                        field_type: resolved.field_type,
                    });
                    offset += resolved.size;
                } else {
                    // Direct param value (scalar).
                    let size = btf.type_size(param.type_id);
                    let field_type = match size {
                        1 => FieldType::U8,
                        2 => FieldType::U16,
                        4 => FieldType::U32,
                        8 => FieldType::U64,
                        _ => {
                            return Err(CodegenError::UnsupportedType(format!(
                                "param {param_name} has unsupported size {size}"
                            )));
                        }
                    };

                    layout.push(FieldLayout {
                        name: other.to_string(),
                        offset,
                        size,
                        field_type,
                    });
                    field_reads.push(FieldRead::DirectArg {
                        event_offset: offset,
                        arg_index: param_idx as u32,
                        size,
                    });
                    offset += size;
                }
            }
        }
    }

    // Align event size to 8 bytes.
    let event_size = (offset + 7) & !7;

    // Check stack budget: event + 4 bytes for PID lookup key.
    let stack_needed = event_size + 4;
    if stack_needed > MAX_STACK {
        return Err(CodegenError::StackOverflow { size: stack_needed });
    }

    // Generate instructions.
    let mut insns = Vec::new();
    let mut relocs = Vec::new();

    // Stack layout:
    //   [fp - event_size .. fp - 0]  = unused (top)
    //   [fp - event_size - 4 .. fp - event_size] = PID key (u32)
    //   Actually, let's put the event at the bottom:
    //   [fp - 4] = PID key (u32)
    //   [fp - 4 - event_size .. fp - 4] = event struct
    let pid_key_off: i32 = -4;
    let event_base_off: i32 = -(4 + event_size as i32);

    // === Self-filter ===
    // r6 = bpf_get_current_pid_tgid()
    insns.push(call(BPF_FUNC_GET_CURRENT_PID_TGID));
    insns.push(mov64_reg(R6, R0)); // r6 = pid_tgid (preserved across calls)

    // pid = r6 >> 32
    insns.push(mov64_reg(R1, R6));
    insns.push(rsh64_imm(R1, 32));

    // Store pid to stack for map lookup.
    insns.push(stx_w(R10, R1, pid_key_off as i16));

    // r1 = PID_FILTER map fd (relocation)
    let map_fd_offset = insns.len();
    let map_fd_insns = ld_map_fd(R1);
    insns.push(map_fd_insns[0]);
    insns.push(map_fd_insns[1]);
    relocs.push((map_fd_offset, MAP_IDX_PID_FILTER));

    // r2 = &pid_key (on stack)
    insns.push(mov64_reg(R2, R10));
    insns.push(add64_imm(R2, pid_key_off as i32));

    // r0 = bpf_map_lookup_elem(r1, r2)
    insns.push(call(BPF_FUNC_MAP_LOOKUP_ELEM));

    // if r0 != NULL, this is our own PID — exit
    insns.push(jne_imm(R0, 0, 2)); // skip 2 insns to exit
    insns.push(ja(1)); // jump over the exit
    // exit path:
    insns.push(mov64_imm(R0, 0));
    // We need a jump target. Let me restructure:
    // Actually, simpler:
    // if r0 == 0 goto +1  (not filtered)
    // exit
    // (continue)

    // Let me redo this more cleanly.
    let self_filter_start = insns.len() - 4; // back up
    insns.truncate(self_filter_start);

    // r0 = bpf_map_lookup_elem(PID_FILTER, &pid)
    // Redo: load map fd, set args, call
    let map_fd_offset = insns.len();
    let map_fd_insns = ld_map_fd(R1);
    insns.push(map_fd_insns[0]);
    insns.push(map_fd_insns[1]);
    relocs.clear();
    relocs.push((map_fd_offset, MAP_IDX_PID_FILTER));

    insns.push(mov64_reg(R2, R10));
    insns.push(add64_imm(R2, pid_key_off as i32));
    insns.push(call(BPF_FUNC_MAP_LOOKUP_ELEM));

    // if r0 != 0 (found in filter): exit
    insns.push(jeq_imm(R0, 0, 2)); // if r0 == 0 skip 2 to continue
    insns.push(mov64_imm(R0, 0));
    insns.push(exit());

    // === Zero-init event on stack ===
    // Write zeros to the event area. Do it in 8-byte chunks.
    let mut zero_off = event_base_off as i16;
    let mut remaining = event_size;
    while remaining >= 8 {
        insns.push(st_dw(R10, zero_off, 0));
        zero_off += 8;
        remaining -= 8;
    }
    while remaining >= 4 {
        insns.push(st_w(R10, zero_off, 0));
        zero_off += 4;
        remaining -= 4;
    }

    // === Fill header: timestamp_ns, pid, tid ===
    // timestamp_ns = bpf_ktime_get_ns()
    insns.push(call(BPF_FUNC_KTIME_GET_NS));
    insns.push(stx_dw(R10, R0, event_base_off as i16)); // event[0] = timestamp

    // pid = r6 >> 32, tid = r6 & 0xffffffff
    insns.push(mov64_reg(R1, R6));
    insns.push(rsh64_imm(R1, 32));
    insns.push(stx_w(R10, R1, (event_base_off + 8) as i16)); // event[8] = pid

    insns.push(mov64_reg(R1, R6));
    insns.push(and32_imm(R1, -1)); // lower 32 bits
    insns.push(stx_w(R10, R1, (event_base_off + 12) as i16)); // event[12] = tid

    // === Fill requested fields ===
    // Save ctx pointer in r7 (callee-saved).
    // For fentry/fexit tracing programs, ctx is passed in r1.
    // We need it saved before the first helper call — but we already called helpers above.
    // Actually, we need to save r1 (ctx) at the very start. Let me restructure.

    // The issue: r1 (ctx) is clobbered by the first call. We need to save it.
    // Insert at the beginning: mov r7, r1 (save ctx)
    insns.insert(0, mov64_reg(R7, R1));
    // Adjust all relocation offsets by 1.
    for (off, _) in &mut relocs {
        *off += 1;
    }

    // Now r7 = ctx. For fentry/fexit tracing programs, ctx->args[n] is at offset n*8.
    for read in &field_reads {
        match read {
            FieldRead::Comm { event_offset } => {
                // bpf_get_current_comm(&event[offset], 16)
                insns.push(mov64_reg(R1, R10));
                insns.push(add64_imm(R1, event_base_off + *event_offset as i32));
                insns.push(mov64_imm(R2, 16));
                insns.push(call(BPF_FUNC_GET_CURRENT_COMM));
            }
            FieldRead::ReturnValue {
                event_offset,
                arg_index,
            } => {
                // For fexit: ret is ctx->args[n_params]
                let ctx_off = (*arg_index as i16) * 8;
                insns.push(ldx_dw(R1, R7, ctx_off));
                insns.push(stx_w(R10, R1, (event_base_off + *event_offset as i32) as i16));
            }
            FieldRead::DirectArg {
                event_offset,
                arg_index,
                size,
            } => {
                let ctx_off = (*arg_index as i16) * 8;
                insns.push(ldx_dw(R1, R7, ctx_off));
                match size {
                    8 => insns.push(stx_dw(R10, R1, (event_base_off + *event_offset as i32) as i16)),
                    4 => insns.push(stx_w(R10, R1, (event_base_off + *event_offset as i32) as i16)),
                    2 => insns.push(stx_h(R10, R1, (event_base_off + *event_offset as i32) as i16)),
                    1 => insns.push(stx_b(R10, R1, (event_base_off + *event_offset as i32) as i16)),
                    _ => return Err(CodegenError::UnsupportedType(format!("{size}-byte direct"))),
                }
            }
            FieldRead::ProbeReadKernel {
                event_offset,
                arg_index,
                struct_offset,
                size,
                ..
            } => {
                // r1 = &event[event_offset] (dst)
                insns.push(mov64_reg(R1, R10));
                insns.push(add64_imm(R1, event_base_off as i32 + *event_offset as i32));
                // r2 = size
                insns.push(mov64_imm(R2, *size as i32));
                // r3 = ctx->args[arg_index] + struct_offset (src)
                let ctx_off = (*arg_index as i16) * 8;
                insns.push(ldx_dw(R3, R7, ctx_off));
                insns.push(add64_imm(R3, *struct_offset as i32));
                // bpf_probe_read_kernel(dst, size, src)
                insns.push(call(BPF_FUNC_PROBE_READ_KERNEL));
            }
        }
    }

    // === Ring buffer output ===
    // r1 = RINGBUF map fd (relocation)
    let ringbuf_reloc_off = insns.len();
    let rb_insns = ld_map_fd(R1);
    insns.push(rb_insns[0]);
    insns.push(rb_insns[1]);
    relocs.push((ringbuf_reloc_off, MAP_IDX_RINGBUF));

    // r2 = &event (on stack)
    insns.push(mov64_reg(R2, R10));
    insns.push(add64_imm(R2, event_base_off as i32));
    // r3 = event_size
    insns.push(mov64_imm(R3, event_size as i32));
    // r4 = flags (0)
    insns.push(mov64_imm(R4, 0));
    // bpf_ringbuf_output(map, data, size, flags)
    insns.push(call(BPF_FUNC_RINGBUF_OUTPUT));

    // === Exit ===
    insns.push(mov64_imm(R0, 0));
    insns.push(exit());

    // Check program size.
    if insns.len() > 4096 {
        return Err(CodegenError::ProgramTooLarge {
            size: insns.len(),
            max: 4096,
        });
    }

    let map_name = format!("{}_EVENTS", spec.function.to_uppercase().replace("_SKB", ""));

    Ok(GeneratedProgram {
        instructions: insns,
        relocations: relocs,
        field_layout: layout,
        event_size,
        map_name,
    })
}

/// Internal representation of a field read operation.
enum FieldRead {
    /// bpf_get_current_comm into event.
    Comm { event_offset: usize },
    /// Read return value from ctx (fexit only).
    ReturnValue { event_offset: usize, arg_index: u32 },
    /// Read scalar arg directly from ctx.
    DirectArg {
        event_offset: usize,
        arg_index: u32,
        size: usize,
    },
    /// bpf_probe_read_kernel from a pointer arg + struct offset.
    ProbeReadKernel {
        event_offset: usize,
        arg_index: u32,
        struct_offset: u32,
        size: usize,
        field_type: FieldType,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load_btf() -> Option<BtfData> {
        BtfData::from_sys_fs().ok()
    }

    #[test]
    fn generate_tcp_connect_probe() {
        let btf = match load_btf() {
            Some(b) => b,
            None => return,
        };

        let spec = ProbeSpec {
            function: "tcp_connect".into(),
            attachment: AttachType::Fexit,
            fields: vec![
                "sk.__sk_common.skc_daddr".into(),
                "sk.__sk_common.skc_rcv_saddr".into(),
                "sk.__sk_common.skc_dport".into(),
                "sk.__sk_common.skc_num".into(),
                "ret".into(),
                "comm".into(),
            ],
            event_type: "kernel.tcp.connect".into(),
        };

        let program = generate(&spec, &btf).expect("should generate");

        // Should have instructions.
        assert!(!program.instructions.is_empty());
        // Should have 2 map relocations (PID_FILTER + RINGBUF).
        assert_eq!(program.relocations.len(), 2);
        // Field layout should include header + requested fields.
        assert!(program.field_layout.len() >= 6); // timestamp, pid, tid, + requested
        // Event size should be > 0 and aligned to 8.
        assert!(program.event_size > 0);
        assert_eq!(program.event_size % 8, 0);
    }

    #[test]
    fn generate_simple_fentry() {
        let btf = match load_btf() {
            Some(b) => b,
            None => return,
        };

        let spec = ProbeSpec {
            function: "tcp_retransmit_skb".into(),
            attachment: AttachType::Fentry,
            fields: vec!["comm".into()],
            event_type: "kernel.tcp.retransmit".into(),
        };

        let program = generate(&spec, &btf).expect("should generate");
        assert!(!program.instructions.is_empty());
    }

    #[test]
    fn ret_on_fentry_errors() {
        let btf = match load_btf() {
            Some(b) => b,
            None => return,
        };

        let spec = ProbeSpec {
            function: "tcp_retransmit_skb".into(),
            attachment: AttachType::Fentry,
            fields: vec!["ret".into()],
            event_type: "test".into(),
        };

        assert!(generate(&spec, &btf).is_err());
    }
}

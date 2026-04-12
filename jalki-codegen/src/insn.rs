/// BPF instruction encoding.
///
/// Each BPF instruction is 8 bytes. The `ld_map_fd` pseudo-instruction
/// is 16 bytes (two consecutive instructions).
///
/// Reference: linux/bpf.h, linux/bpf_common.h

/// A single 8-byte BPF instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct BpfInsn {
    /// Opcode.
    pub code: u8,
    /// dst_reg:4 | src_reg:4 (little-endian packed).
    pub regs: u8,
    /// Signed offset.
    pub off: i16,
    /// Signed immediate.
    pub imm: i32,
}

impl BpfInsn {
    pub fn new(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> Self {
        Self {
            code,
            regs: (src << 4) | (dst & 0xf),
            off,
            imm,
        }
    }

    /// Encode to 8 raw bytes (little-endian).
    pub fn to_bytes(self) -> [u8; 8] {
        let mut out = [0u8; 8];
        out[0] = self.code;
        out[1] = self.regs;
        out[2..4].copy_from_slice(&self.off.to_le_bytes());
        out[4..8].copy_from_slice(&self.imm.to_le_bytes());
        out
    }
}

// --- Opcode components ---

// Classes
const BPF_LD: u8 = 0x00;
const BPF_LDX: u8 = 0x01;
const BPF_ST: u8 = 0x02;
const BPF_STX: u8 = 0x03;
const BPF_ALU: u8 = 0x04;
const BPF_JMP: u8 = 0x05;
const BPF_ALU64: u8 = 0x07;

// Sizes
const BPF_W: u8 = 0x00; // 32-bit
const BPF_H: u8 = 0x08; // 16-bit
const BPF_B: u8 = 0x10; // 8-bit
const BPF_DW: u8 = 0x18; // 64-bit

// Modes
const BPF_IMM: u8 = 0x00;
const BPF_MEM: u8 = 0x60;

// ALU operations
const BPF_MOV: u8 = 0xb0;
const BPF_ADD: u8 = 0x00;
const BPF_RSH: u8 = 0x70;
const BPF_AND: u8 = 0x50;

// Sources
const BPF_K: u8 = 0x00; // immediate
const BPF_X: u8 = 0x08; // register

// Jump ops
const BPF_JA: u8 = 0x00;
const BPF_JEQ: u8 = 0x10;
const BPF_JNE: u8 = 0x50;
const BPF_EXIT: u8 = 0x90;
const BPF_CALL: u8 = 0x80;

/// Pseudo map fd source register for `ld_map_fd`.
const BPF_PSEUDO_MAP_FD: u8 = 1;

// --- Registers ---

pub const R0: u8 = 0; // return value
pub const R1: u8 = 1; // arg1 / scratch
pub const R2: u8 = 2; // arg2 / scratch
pub const R3: u8 = 3; // arg3 / scratch
pub const R4: u8 = 4; // arg4 / scratch
pub const R5: u8 = 5; // arg5 / scratch
pub const R6: u8 = 6; // callee-saved
pub const R7: u8 = 7; // callee-saved
pub const R8: u8 = 8; // callee-saved
pub const R9: u8 = 9; // callee-saved
pub const R10: u8 = 10; // stack pointer (read-only)

// --- BPF helper function IDs ---

pub const BPF_FUNC_MAP_LOOKUP_ELEM: i32 = 1;
pub const BPF_FUNC_KTIME_GET_NS: i32 = 5;
pub const BPF_FUNC_GET_CURRENT_PID_TGID: i32 = 14;
pub const BPF_FUNC_GET_CURRENT_COMM: i32 = 16;
pub const BPF_FUNC_PROBE_READ_KERNEL: i32 = 113;
pub const BPF_FUNC_RINGBUF_OUTPUT: i32 = 130;

// --- Instruction constructors ---

/// `dst = imm` (64-bit mov immediate).
pub fn mov64_imm(dst: u8, imm: i32) -> BpfInsn {
    BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, dst, 0, 0, imm)
}

/// `dst = src` (64-bit mov register).
pub fn mov64_reg(dst: u8, src: u8) -> BpfInsn {
    BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_X, dst, src, 0, 0)
}

/// `dst += imm` (64-bit add immediate).
pub fn add64_imm(dst: u8, imm: i32) -> BpfInsn {
    BpfInsn::new(BPF_ALU64 | BPF_ADD | BPF_K, dst, 0, 0, imm)
}

/// `dst >>= imm` (64-bit right shift immediate).
pub fn rsh64_imm(dst: u8, imm: i32) -> BpfInsn {
    BpfInsn::new(BPF_ALU64 | BPF_RSH | BPF_K, dst, 0, 0, imm)
}

/// `dst &= imm` (32-bit AND immediate — ALU32).
pub fn and32_imm(dst: u8, imm: i32) -> BpfInsn {
    BpfInsn::new(BPF_ALU | BPF_AND | BPF_K, dst, 0, 0, imm)
}

/// Load 64-bit from memory: `dst = *(u64 *)(src + off)`.
pub fn ldx_dw(dst: u8, src: u8, off: i16) -> BpfInsn {
    BpfInsn::new(BPF_LDX | BPF_MEM | BPF_DW, dst, src, off, 0)
}

/// Load 32-bit from memory: `dst = *(u32 *)(src + off)`.
pub fn ldx_w(dst: u8, src: u8, off: i16) -> BpfInsn {
    BpfInsn::new(BPF_LDX | BPF_MEM | BPF_W, dst, src, off, 0)
}

/// Load 16-bit from memory: `dst = *(u16 *)(src + off)`.
pub fn ldx_h(dst: u8, src: u8, off: i16) -> BpfInsn {
    BpfInsn::new(BPF_LDX | BPF_MEM | BPF_H, dst, src, off, 0)
}

/// Load 8-bit from memory: `dst = *(u8 *)(src + off)`.
pub fn ldx_b(dst: u8, src: u8, off: i16) -> BpfInsn {
    BpfInsn::new(BPF_LDX | BPF_MEM | BPF_B, dst, src, off, 0)
}

/// Store 64-bit to memory: `*(u64 *)(dst + off) = src`.
pub fn stx_dw(dst: u8, src: u8, off: i16) -> BpfInsn {
    BpfInsn::new(BPF_STX | BPF_MEM | BPF_DW, dst, src, off, 0)
}

/// Store 32-bit to memory: `*(u32 *)(dst + off) = src`.
pub fn stx_w(dst: u8, src: u8, off: i16) -> BpfInsn {
    BpfInsn::new(BPF_STX | BPF_MEM | BPF_W, dst, src, off, 0)
}

/// Store 16-bit to memory: `*(u16 *)(dst + off) = src`.
pub fn stx_h(dst: u8, src: u8, off: i16) -> BpfInsn {
    BpfInsn::new(BPF_STX | BPF_MEM | BPF_H, dst, src, off, 0)
}

/// Store 8-bit to memory: `*(u8 *)(dst + off) = src`.
pub fn stx_b(dst: u8, src: u8, off: i16) -> BpfInsn {
    BpfInsn::new(BPF_STX | BPF_MEM | BPF_B, dst, src, off, 0)
}

/// Store 32-bit immediate to memory: `*(u32 *)(dst + off) = imm`.
pub fn st_w(dst: u8, off: i16, imm: i32) -> BpfInsn {
    BpfInsn::new(BPF_ST | BPF_MEM | BPF_W, dst, 0, off, imm)
}

/// Store 64-bit immediate (0) to memory: `*(u64 *)(dst + off) = 0`.
pub fn st_dw(dst: u8, off: i16, imm: i32) -> BpfInsn {
    BpfInsn::new(BPF_ST | BPF_MEM | BPF_DW, dst, 0, off, imm)
}

/// Call BPF helper function.
pub fn call(helper_id: i32) -> BpfInsn {
    BpfInsn::new(BPF_JMP | BPF_CALL, 0, 0, 0, helper_id)
}

/// Unconditional jump: `goto +off`.
pub fn ja(off: i16) -> BpfInsn {
    BpfInsn::new(BPF_JMP | BPF_JA, 0, 0, off, 0)
}

/// Jump if equal to immediate: `if dst == imm goto +off`.
pub fn jeq_imm(dst: u8, imm: i32, off: i16) -> BpfInsn {
    BpfInsn::new(BPF_JMP | BPF_JEQ | BPF_K, dst, 0, off, imm)
}

/// Jump if not equal to immediate: `if dst != imm goto +off`.
pub fn jne_imm(dst: u8, imm: i32, off: i16) -> BpfInsn {
    BpfInsn::new(BPF_JMP | BPF_JNE | BPF_K, dst, 0, off, imm)
}

/// Exit program: `return r0`.
pub fn exit() -> BpfInsn {
    BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0)
}

/// Load 64-bit map FD pseudo-instruction (2 instructions, 16 bytes).
///
/// This is a `BPF_LD | BPF_DW | BPF_IMM` with `src_reg = BPF_PSEUDO_MAP_FD`.
/// aya resolves the map FD via ELF relocations at load time.
/// The `imm` here is a placeholder — the actual map index is set via relocation.
pub fn ld_map_fd(dst: u8) -> [BpfInsn; 2] {
    [
        BpfInsn::new(BPF_LD | BPF_DW | BPF_IMM, dst, BPF_PSEUDO_MAP_FD, 0, 0),
        // Second half of the 16-byte imm64 instruction — always zero for map fd.
        BpfInsn::new(0, 0, 0, 0, 0),
    ]
}

/// Encode a sequence of instructions to bytes.
pub fn encode(insns: &[BpfInsn]) -> Vec<u8> {
    let mut out = Vec::with_capacity(insns.len() * 8);
    for insn in insns {
        out.extend_from_slice(&insn.to_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insn_size_is_8_bytes() {
        assert_eq!(std::mem::size_of::<BpfInsn>(), 8);
    }

    #[test]
    fn mov64_imm_encoding() {
        let insn = mov64_imm(R0, 0);
        let bytes = insn.to_bytes();
        // code = BPF_ALU64 | BPF_MOV | BPF_K = 0x07 | 0xb0 | 0x00 = 0xb7
        assert_eq!(bytes[0], 0xb7);
        // regs: src=0, dst=0
        assert_eq!(bytes[1], 0x00);
    }

    #[test]
    fn mov64_reg_encoding() {
        let insn = mov64_reg(R1, R6);
        let bytes = insn.to_bytes();
        // code = BPF_ALU64 | BPF_MOV | BPF_X = 0x07 | 0xb0 | 0x08 = 0xbf
        assert_eq!(bytes[0], 0xbf);
        // regs: src=6, dst=1 → (6 << 4) | 1 = 0x61
        assert_eq!(bytes[1], 0x61);
    }

    #[test]
    fn call_helper_encoding() {
        let insn = call(BPF_FUNC_GET_CURRENT_PID_TGID);
        let bytes = insn.to_bytes();
        // code = BPF_JMP | BPF_CALL = 0x05 | 0x80 = 0x85
        assert_eq!(bytes[0], 0x85);
        assert_eq!(i32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]), 14);
    }

    #[test]
    fn exit_encoding() {
        let insn = exit();
        let bytes = insn.to_bytes();
        // code = BPF_JMP | BPF_EXIT = 0x05 | 0x90 = 0x95
        assert_eq!(bytes[0], 0x95);
    }

    #[test]
    fn ld_map_fd_is_two_insns() {
        let insns = ld_map_fd(R1);
        assert_eq!(insns.len(), 2);
        // First instruction: BPF_LD | BPF_DW | BPF_IMM = 0x00 | 0x18 | 0x00 = 0x18
        assert_eq!(insns[0].code, 0x18);
        // src_reg = BPF_PSEUDO_MAP_FD = 1, dst = 1 → regs = (1 << 4) | 1 = 0x11
        assert_eq!(insns[0].regs, 0x11);
    }

    #[test]
    fn encode_sequence() {
        let insns = vec![mov64_imm(R0, 0), exit()];
        let bytes = encode(&insns);
        assert_eq!(bytes.len(), 16);
    }

    #[test]
    fn ldx_dw_encoding() {
        // Load ctx->args[0]: ldx_dw(R6, R1, 0)
        let insn = ldx_dw(R6, R1, 0);
        let bytes = insn.to_bytes();
        // code = BPF_LDX | BPF_MEM | BPF_DW = 0x01 | 0x60 | 0x18 = 0x79
        assert_eq!(bytes[0], 0x79);
    }

    #[test]
    fn stx_w_encoding() {
        let insn = stx_w(R10, R1, -4);
        let bytes = insn.to_bytes();
        // code = BPF_STX | BPF_MEM | BPF_W = 0x03 | 0x60 | 0x00 = 0x63
        assert_eq!(bytes[0], 0x63);
        // off = -4
        assert_eq!(i16::from_le_bytes([bytes[2], bytes[3]]), -4);
    }
}

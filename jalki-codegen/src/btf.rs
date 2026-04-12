/// BTF type resolution — parse /sys/kernel/btf/vmlinux directly.
///
/// aya's Btf methods are `pub(crate)`, so we parse BTF ourselves.
/// The format is simple: header + type section + string section.
use std::collections::HashMap;

use crate::error::CodegenError;

// --- BTF binary format ---

const BTF_MAGIC: u16 = 0xEB9F;

const BTF_KIND_INT: u32 = 1;
const BTF_KIND_PTR: u32 = 2;
const BTF_KIND_STRUCT: u32 = 4;
const BTF_KIND_UNION: u32 = 5;
const BTF_KIND_ENUM: u32 = 6;
const BTF_KIND_TYPEDEF: u32 = 8;
const BTF_KIND_VOLATILE: u32 = 9;
const BTF_KIND_CONST: u32 = 10;
const BTF_KIND_RESTRICT: u32 = 11;
const BTF_KIND_FUNC: u32 = 12;
const BTF_KIND_FUNC_PROTO: u32 = 13;
const BTF_KIND_ENUM64: u32 = 19;

/// Parsed BTF data.
pub struct BtfData {
    types: Vec<BtfTypeEntry>,
    strings: Vec<u8>,
    /// name → type_id index for fast lookup.
    func_index: HashMap<String, u32>,
    struct_index: HashMap<String, u32>,
}

#[derive(Debug, Clone)]
struct BtfTypeEntry {
    name_off: u32,
    kind: u32,
    vlen: u32,
    size_or_type: u32,
    extra: TypeExtra,
}

#[derive(Debug, Clone)]
enum TypeExtra {
    None,
    Members(Vec<BtfMember>),
    Params(Vec<BtfParam>),
    IntData(u32),
}

#[derive(Debug, Clone)]
struct BtfMember {
    name_off: u32,
    type_id: u32,
    offset_bits: u32,
}

#[derive(Debug, Clone)]
struct BtfParam {
    name_off: u32,
    type_id: u32,
}

// --- Public types ---

#[derive(Debug, Clone)]
pub struct FunctionSignature {
    pub name: String,
    pub params: Vec<FunctionParam>,
    pub return_type_id: u32,
}

#[derive(Debug, Clone)]
pub struct FunctionParam {
    pub name: String,
    pub type_id: u32,
}

#[derive(Debug, Clone)]
pub struct ResolvedField {
    pub name: String,
    pub offset_bytes: u32,
    pub size: usize,
    pub field_type: FieldType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldType {
    U8,
    U16,
    U32,
    U64,
    I32,
    I64,
}

impl FieldType {
    pub fn size(self) -> usize {
        match self {
            FieldType::U8 => 1,
            FieldType::U16 => 2,
            FieldType::U32 | FieldType::I32 => 4,
            FieldType::U64 | FieldType::I64 => 8,
        }
    }
}

/// What kind of type a pointer points to.
#[derive(Debug, Clone)]
pub enum PointeeKind {
    Struct { name: String, type_id: u32 },
    Other,
}

impl BtfData {
    /// Load and parse BTF from /sys/kernel/btf/vmlinux.
    pub fn from_sys_fs() -> Result<Self, CodegenError> {
        let data = std::fs::read("/sys/kernel/btf/vmlinux")
            .map_err(|e| CodegenError::BtfType(format!("read vmlinux BTF: {e}")))?;
        Self::parse(&data)
    }

    /// Parse raw BTF bytes.
    pub fn parse(data: &[u8]) -> Result<Self, CodegenError> {
        if data.len() < 24 {
            return Err(CodegenError::BtfType("BTF too short".into()));
        }

        let magic = u16::from_le_bytes([data[0], data[1]]);
        if magic != BTF_MAGIC {
            return Err(CodegenError::BtfType(format!("bad BTF magic: {magic:#x}")));
        }

        let hdr_len = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;
        let type_off = u32::from_le_bytes([data[8], data[9], data[10], data[11]]) as usize;
        let type_len = u32::from_le_bytes([data[12], data[13], data[14], data[15]]) as usize;
        let str_off = u32::from_le_bytes([data[16], data[17], data[18], data[19]]) as usize;
        let str_len = u32::from_le_bytes([data[20], data[21], data[22], data[23]]) as usize;

        let type_data = &data[hdr_len + type_off..hdr_len + type_off + type_len];
        let str_data = data[hdr_len + str_off..hdr_len + str_off + str_len].to_vec();

        let types = parse_types(type_data)?;

        // Build lookup indexes.
        let mut func_index = HashMap::new();
        let mut struct_index = HashMap::new();

        for (i, ty) in types.iter().enumerate() {
            let type_id = (i + 1) as u32; // BTF type IDs are 1-based
            let name = string_at(&str_data, ty.name_off);
            if !name.is_empty() {
                match ty.kind {
                    BTF_KIND_FUNC => {
                        func_index.insert(name.to_string(), type_id);
                    }
                    BTF_KIND_STRUCT => {
                        struct_index.insert(name.to_string(), type_id);
                    }
                    _ => {}
                }
            }
        }

        Ok(Self {
            types,
            strings: str_data,
            func_index,
            struct_index,
        })
    }

    fn get_type(&self, type_id: u32) -> Option<&BtfTypeEntry> {
        if type_id == 0 {
            return None;
        }
        self.types.get((type_id - 1) as usize)
    }

    fn type_name(&self, type_id: u32) -> &str {
        match self.get_type(type_id) {
            Some(ty) => string_at(&self.strings, ty.name_off),
            None => "",
        }
    }

    /// Resolve a kernel function's signature.
    pub fn resolve_function(&self, function: &str) -> Result<FunctionSignature, CodegenError> {
        let &func_id = self
            .func_index
            .get(function)
            .ok_or_else(|| CodegenError::FunctionNotFound(function.to_string()))?;

        let func_type = self
            .get_type(func_id)
            .ok_or_else(|| CodegenError::BtfType("func type missing".into()))?;

        if func_type.kind != BTF_KIND_FUNC {
            return Err(CodegenError::BtfType(format!("{function} is not a function")));
        }

        // Func points to a FuncProto.
        let proto_id = func_type.size_or_type;
        let proto = self
            .get_type(proto_id)
            .ok_or_else(|| CodegenError::BtfType("func proto missing".into()))?;

        if proto.kind != BTF_KIND_FUNC_PROTO {
            return Err(CodegenError::BtfType("expected FuncProto".into()));
        }

        let params = match &proto.extra {
            TypeExtra::Params(params) => params
                .iter()
                .map(|p| FunctionParam {
                    name: string_at(&self.strings, p.name_off).to_string(),
                    type_id: p.type_id,
                })
                .collect(),
            _ => Vec::new(),
        };

        Ok(FunctionSignature {
            name: function.to_string(),
            params,
            return_type_id: proto.size_or_type,
        })
    }

    /// Resolve a field's offset within a struct.
    /// `field_path` is dot-separated: `__sk_common.skc_daddr`.
    ///
    /// Handles anonymous struct/union members by searching recursively
    /// into members with empty names.
    pub fn resolve_field_offset(
        &self,
        struct_type_id: u32,
        field_path: &str,
    ) -> Result<ResolvedField, CodegenError> {
        let parts: Vec<&str> = field_path.split('.').collect();
        let mut current_id = struct_type_id;
        let mut total_offset: u32 = 0;

        for (i, part) in parts.iter().enumerate() {
            let (member_type_id, member_offset) =
                self.find_member_recursive(current_id, part)?;

            total_offset += member_offset;

            if i == parts.len() - 1 {
                let size = self.type_size(member_type_id);
                let field_type = size_to_field_type(size)?;
                return Ok(ResolvedField {
                    name: field_path.to_string(),
                    offset_bytes: total_offset,
                    size,
                    field_type,
                });
            } else {
                current_id = member_type_id;
            }
        }

        Err(CodegenError::BtfType("empty field path".into()))
    }

    /// Find a named member in a struct, recursing into anonymous members.
    fn find_member_recursive(
        &self,
        type_id: u32,
        field_name: &str,
    ) -> Result<(u32, u32), CodegenError> {
        let resolved_id = self.resolve_through_modifiers(type_id);
        let ty = self
            .get_type(resolved_id)
            .ok_or_else(|| CodegenError::BtfType(format!("type {resolved_id} missing")))?;

        let members = match &ty.extra {
            TypeExtra::Members(m) => m,
            _ => {
                return Err(CodegenError::BtfType(format!(
                    "type {} is not a struct/union",
                    self.type_name(resolved_id)
                )));
            }
        };

        // First: try direct match.
        for member in members {
            let name = string_at(&self.strings, member.name_off);
            if name == field_name {
                return Ok((member.type_id, member.offset_bits / 8));
            }
        }

        // Second: recurse into anonymous members (empty name).
        for member in members {
            let name = string_at(&self.strings, member.name_off);
            if name.is_empty() {
                let anon_offset = member.offset_bits / 8;
                if let Ok((found_type, inner_offset)) =
                    self.find_member_recursive(member.type_id, field_name)
                {
                    return Ok((found_type, anon_offset + inner_offset));
                }
            }
        }

        Err(CodegenError::FieldNotFound {
            struct_name: self.type_name(resolved_id).to_string(),
            field: field_name.to_string(),
        })
    }

    /// Get the size of a BTF type in bytes.
    pub fn type_size(&self, type_id: u32) -> usize {
        let ty = match self.get_type(type_id) {
            Some(t) => t,
            None => return 0,
        };

        match ty.kind {
            BTF_KIND_INT => {
                if let TypeExtra::IntData(data) = ty.extra {
                    // BTF_INT_BITS is in bits 0-7 of the int data.
                    (data & 0xff) as usize / 8
                } else {
                    ty.size_or_type as usize
                }
            }
            BTF_KIND_STRUCT | BTF_KIND_UNION | BTF_KIND_ENUM | BTF_KIND_ENUM64 => {
                ty.size_or_type as usize
            }
            BTF_KIND_PTR => 8,
            BTF_KIND_TYPEDEF | BTF_KIND_VOLATILE | BTF_KIND_CONST | BTF_KIND_RESTRICT
            | 18 /* TYPE_TAG */ => {
                self.type_size(ty.size_or_type)
            }
            16 /* FLOAT */ => ty.size_or_type as usize,
            _ => 0,
        }
    }

    /// Resolve what a pointer type points to.
    pub fn pointer_pointee(&self, type_id: u32) -> PointeeKind {
        let ty = match self.get_type(type_id) {
            Some(t) => t,
            None => return PointeeKind::Other,
        };

        if ty.kind != BTF_KIND_PTR {
            return PointeeKind::Other;
        }

        let pointee_id = self.resolve_through_modifiers(ty.size_or_type);
        let pointee = match self.get_type(pointee_id) {
            Some(t) => t,
            None => return PointeeKind::Other,
        };

        if pointee.kind == BTF_KIND_STRUCT {
            let name = string_at(&self.strings, pointee.name_off).to_string();
            PointeeKind::Struct {
                name,
                type_id: pointee_id,
            }
        } else {
            PointeeKind::Other
        }
    }

    /// Look up a struct by name, return its type ID.
    pub fn struct_by_name(&self, name: &str) -> Option<u32> {
        self.struct_index.get(name).copied()
    }

    /// Follow typedef/const/volatile/restrict chains.
    fn resolve_through_modifiers(&self, mut type_id: u32) -> u32 {
        for _ in 0..32 {
            // depth limit
            let ty = match self.get_type(type_id) {
                Some(t) => t,
                None => return type_id,
            };
            match ty.kind {
                BTF_KIND_TYPEDEF | BTF_KIND_VOLATILE | BTF_KIND_CONST | BTF_KIND_RESTRICT
                | 18 /* TYPE_TAG */ => {
                    type_id = ty.size_or_type;
                }
                _ => return type_id,
            }
        }
        type_id
    }
}

// --- Parsing ---

fn parse_types(data: &[u8]) -> Result<Vec<BtfTypeEntry>, CodegenError> {
    let mut types = Vec::new();
    let mut offset = 0;

    while offset + 12 <= data.len() {
        let name_off = u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]]);
        let info = u32::from_le_bytes([data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7]]);
        let size_or_type = u32::from_le_bytes([data[offset + 8], data[offset + 9], data[offset + 10], data[offset + 11]]);

        let kind = (info >> 24) & 0x1f;
        let vlen = info & 0xffff;

        offset += 12;

        // Each BTF kind has a specific amount of extra data after the 12-byte header.
        // Getting this wrong misaligns all subsequent types.
        let extra = match kind {
            0 => TypeExtra::None,                    // UNKN
            BTF_KIND_INT => {                        // 1: +4 bytes
                if offset + 4 > data.len() {
                    return Err(CodegenError::BtfType("truncated INT".into()));
                }
                let int_data = u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]]);
                offset += 4;
                TypeExtra::IntData(int_data)
            }
            BTF_KIND_PTR => TypeExtra::None,         // 2: no extra
            3 => {                                   // ARRAY: +12 bytes (3 x u32)
                offset += 12;
                TypeExtra::None
            }
            BTF_KIND_STRUCT | BTF_KIND_UNION => {    // 4, 5: +vlen*12 (members)
                let mut members = Vec::with_capacity(vlen as usize);
                for _ in 0..vlen {
                    if offset + 12 > data.len() {
                        return Err(CodegenError::BtfType("truncated member".into()));
                    }
                    let mn = u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]]);
                    let mt = u32::from_le_bytes([data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7]]);
                    let mo = u32::from_le_bytes([data[offset + 8], data[offset + 9], data[offset + 10], data[offset + 11]]);
                    offset += 12;
                    members.push(BtfMember {
                        name_off: mn,
                        type_id: mt,
                        offset_bits: mo,
                    });
                }
                TypeExtra::Members(members)
            }
            BTF_KIND_ENUM => {                       // 6: +vlen*8 (name_off + val)
                offset += vlen as usize * 8;
                TypeExtra::None
            }
            7 => TypeExtra::None,                    // FWD: no extra
            BTF_KIND_TYPEDEF | BTF_KIND_VOLATILE
            | BTF_KIND_CONST | BTF_KIND_RESTRICT => { // 8-11: no extra
                TypeExtra::None
            }
            BTF_KIND_FUNC => TypeExtra::None,        // 12: no extra
            BTF_KIND_FUNC_PROTO => {                 // 13: +vlen*8 (params)
                let mut params = Vec::with_capacity(vlen as usize);
                for _ in 0..vlen {
                    if offset + 8 > data.len() {
                        return Err(CodegenError::BtfType("truncated param".into()));
                    }
                    let pn = u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]]);
                    let pt = u32::from_le_bytes([data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7]]);
                    offset += 8;
                    params.push(BtfParam {
                        name_off: pn,
                        type_id: pt,
                    });
                }
                TypeExtra::Params(params)
            }
            14 => {                                  // VAR: +4 bytes
                offset += 4;
                TypeExtra::None
            }
            15 => {                                  // DATASEC: +vlen*12
                offset += vlen as usize * 12;
                TypeExtra::None
            }
            16 => TypeExtra::None,                   // FLOAT: no extra
            17 => {                                  // DECL_TAG: +4 bytes
                offset += 4;
                TypeExtra::None
            }
            18 => TypeExtra::None,                   // TYPE_TAG: no extra
            BTF_KIND_ENUM64 => {                     // 19: +vlen*12
                offset += vlen as usize * 12;
                TypeExtra::None
            }
            _ => TypeExtra::None,                    // Unknown future kinds — no extra (best effort)
        };

        types.push(BtfTypeEntry {
            name_off,
            kind,
            vlen,
            size_or_type,
            extra,
        });
    }

    Ok(types)
}

fn string_at(strings: &[u8], offset: u32) -> &str {
    let start = offset as usize;
    if start >= strings.len() {
        return "";
    }
    let end = strings[start..]
        .iter()
        .position(|&b| b == 0)
        .map(|p| start + p)
        .unwrap_or(strings.len());
    std::str::from_utf8(&strings[start..end]).unwrap_or("")
}

fn size_to_field_type(size: usize) -> Result<FieldType, CodegenError> {
    match size {
        1 => Ok(FieldType::U8),
        2 => Ok(FieldType::U16),
        4 => Ok(FieldType::U32),
        8 => Ok(FieldType::U64),
        _ => Err(CodegenError::UnsupportedType(format!("{size}-byte field"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load_btf() -> Option<BtfData> {
        BtfData::from_sys_fs().ok()
    }

    #[test]
    fn parse_vmlinux_btf() {
        let btf = match load_btf() {
            Some(b) => b,
            None => return,
        };
        assert!(!btf.types.is_empty());
        assert!(!btf.func_index.is_empty());
        assert!(!btf.struct_index.is_empty());
    }

    #[test]
    fn resolve_tcp_connect() {
        let btf = match load_btf() {
            Some(b) => b,
            None => return,
        };

        let sig = btf.resolve_function("tcp_connect").expect("should resolve");
        assert_eq!(sig.name, "tcp_connect");
        assert!(!sig.params.is_empty());
        assert_eq!(sig.params[0].name, "sk");
    }

    #[test]
    fn resolve_sock_skc_daddr() {
        let btf = match load_btf() {
            Some(b) => b,
            None => return,
        };

        let sock_id = btf.struct_by_name("sock").expect("sock struct");
        let field = btf
            .resolve_field_offset(sock_id, "__sk_common.skc_daddr")
            .expect("skc_daddr");

        assert_eq!(field.offset_bytes, 0);
        assert_eq!(field.size, 4);
    }

    #[test]
    fn resolve_sock_skc_num() {
        let btf = match load_btf() {
            Some(b) => b,
            None => return,
        };

        let sock_id = btf.struct_by_name("sock").expect("sock struct");
        let field = btf
            .resolve_field_offset(sock_id, "__sk_common.skc_num")
            .expect("skc_num");

        assert_eq!(field.offset_bytes, 14);
        assert_eq!(field.size, 2);
    }

    #[test]
    fn resolve_inet_csk_accept() {
        let btf = match load_btf() {
            Some(b) => b,
            None => return,
        };

        let sig = btf.resolve_function("inet_csk_accept").expect("should exist");
        assert!(!sig.params.is_empty());
    }

    #[test]
    fn unknown_function_errors() {
        let btf = match load_btf() {
            Some(b) => b,
            None => return,
        };

        assert!(btf.resolve_function("definitely_not_a_function").is_err());
    }
}

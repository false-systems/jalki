use thiserror::Error;

#[derive(Debug, Error)]
pub enum CodegenError {
    #[error("BTF function '{0}' not found in /sys/kernel/btf/vmlinux")]
    FunctionNotFound(String),

    #[error("BTF struct '{0}' not found")]
    StructNotFound(String),

    #[error("field '{field}' not found in struct '{struct_name}'")]
    FieldNotFound {
        struct_name: String,
        field: String,
    },

    #[error("BTF type error: {0}")]
    BtfType(String),

    #[error("unsupported field type: {0}")]
    UnsupportedType(String),

    #[error("ELF generation failed: {0}")]
    Elf(String),

    #[error("program too large: {size} instructions (max {max})")]
    ProgramTooLarge { size: usize, max: usize },

    #[error("stack overflow: {size} bytes (max 512)")]
    StackOverflow { size: usize },
}

use super::CodegenTarget;

pub struct TypescriptTarget;

impl CodegenTarget for TypescriptTarget {
    fn language(&self) -> &'static str {
        "typescript"
    }

    fn types_filename(&self) -> &'static str {
        "types.ts"
    }

    fn protocol_filename(&self) -> &'static str {
        "protocol.ts"
    }

    fn generate_types(&self) -> String {
        "// GENERATED STUB — jalki-sdk-meta TypeScript codegen not yet implemented\n".into()
    }

    fn generate_protocol(&self) -> String {
        "// GENERATED STUB — jalki-sdk-meta TypeScript codegen not yet implemented\n".into()
    }
}

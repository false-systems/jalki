use super::CodegenTarget;

pub struct GoTarget;

impl CodegenTarget for GoTarget {
    fn language(&self) -> &'static str {
        "go"
    }

    fn types_filename(&self) -> &'static str {
        "types.go"
    }

    fn protocol_filename(&self) -> &'static str {
        "protocol.go"
    }

    fn generate_types(&self) -> String {
        "// GENERATED STUB — jalki-sdk-meta Go codegen not yet implemented\npackage jalki\n".into()
    }

    fn generate_protocol(&self) -> String {
        "// GENERATED STUB — jalki-sdk-meta Go codegen not yet implemented\npackage jalki\n".into()
    }
}

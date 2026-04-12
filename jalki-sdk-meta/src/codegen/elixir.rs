use super::CodegenTarget;

pub struct ElixirTarget;

impl CodegenTarget for ElixirTarget {
    fn language(&self) -> &'static str {
        "elixir"
    }

    fn types_filename(&self) -> &'static str {
        "types.ex"
    }

    fn protocol_filename(&self) -> &'static str {
        "protocol.ex"
    }

    fn generate_types(&self) -> String {
        "# GENERATED STUB — jalki-sdk-meta Elixir codegen not yet implemented\n".into()
    }

    fn generate_protocol(&self) -> String {
        "# GENERATED STUB — jalki-sdk-meta Elixir codegen not yet implemented\n".into()
    }
}

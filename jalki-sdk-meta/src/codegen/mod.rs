use anyhow::Result;
use std::path::Path;

pub mod elixir;
pub mod go;
pub mod python;
pub mod typescript;

pub trait CodegenTarget {
    fn language(&self) -> &'static str;
    /// Generate types file — Event, ProbeMatch, AskResult, EventFilter, enums.
    fn generate_types(&self) -> String;
    /// Generate protocol file — message types, frame constants, wire positions.
    fn generate_protocol(&self) -> String;
    /// Write both files to the output directory.
    fn write(&self, out_dir: &Path) -> Result<()> {
        let types = self.generate_types();
        let protocol = self.generate_protocol();
        std::fs::write(out_dir.join(self.types_filename()), &types)?;
        std::fs::write(out_dir.join(self.protocol_filename()), &protocol)?;
        Ok(())
    }
    fn types_filename(&self) -> &'static str;
    fn protocol_filename(&self) -> &'static str;
}

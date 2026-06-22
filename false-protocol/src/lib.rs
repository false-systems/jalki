pub mod blocks;
pub mod error;
pub mod occurrence;
pub mod payloads;
pub mod types;

pub use blocks::*;
pub use error::ProtocolError;
pub use occurrence::*;
pub use payloads::*;
pub use types::*;

use ulid::Ulid;

/// Generate a new ULID for the current time.
pub fn new_id() -> Ulid {
    Ulid::new()
}

/// Generate a ULID with a specific timestamp (for testing/DST).
pub fn new_id_at(timestamp: std::time::SystemTime) -> Ulid {
    Ulid::from_datetime(timestamp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_id_generates_unique_ids() {
        let a = new_id();
        let b = new_id();
        assert_ne!(a, b);
    }

    #[test]
    fn new_id_at_uses_provided_timestamp() {
        use std::time::{Duration, SystemTime};
        let t = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let id = new_id_at(t);
        let ms = id.timestamp_ms();
        assert_eq!(ms, 1_700_000_000_000);
    }
}

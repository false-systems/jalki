use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("occurrence validation failed: {0}")]
    InvalidOccurrence(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_messages() {
        let err = ProtocolError::InvalidOccurrence("source is required".into());
        assert_eq!(
            err.to_string(),
            "occurrence validation failed: source is required"
        );
    }

    #[test]
    fn error_is_std_error() {
        let err: Box<dyn std::error::Error> =
            Box::new(ProtocolError::InvalidOccurrence("test".into()));
        assert!(err.to_string().contains("test"));
    }
}

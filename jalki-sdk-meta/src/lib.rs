/// Source of truth for jälki SDK types, wire protocol, and conformance tests.
///
/// Every SDK in every language generates its foundation from this crate.
/// Change types here → regenerate → all SDKs update. No drift.
pub mod codegen;
pub mod conformance;
pub mod protocol;
pub mod types;

#[cfg(test)]
mod tests {
    use super::*;
    use codegen::CodegenTarget;

    #[test]
    fn all_conformance_cases_have_unique_ids() {
        let mut seen = std::collections::HashSet::new();
        for case in conformance::CASES {
            assert!(
                seen.insert(case.id),
                "duplicate conformance case id: {}",
                case.id
            );
        }
    }

    #[test]
    fn daemon_free_cases_exist() {
        let free = conformance::CASES
            .iter()
            .filter(|c| !c.requires_daemon)
            .count();
        assert!(free >= 3, "need at least 3 daemon-free conformance cases");
    }

    #[test]
    fn python_codegen_generates_types() {
        let target = codegen::python::PythonTarget;
        let types = target.generate_types();
        assert!(types.contains("class Severity"), "missing Severity enum");
        assert!(types.contains("class Event"), "missing Event dataclass");
        assert!(types.contains("class EventFilter"), "missing EventFilter");
        assert!(types.contains("DO NOT EDIT"), "missing generated header");
    }

    #[test]
    fn python_codegen_generates_protocol() {
        let target = codegen::python::PythonTarget;
        let proto = target.generate_protocol();
        assert!(proto.contains("class MsgType"), "missing MsgType");
        assert!(proto.contains("POS_ID"), "missing stream event positions");
        assert!(proto.contains("DO NOT EDIT"), "missing generated header");
    }

    #[test]
    fn severity_repr_values() {
        assert_eq!(types::Severity::Info as u8, 0);
        assert_eq!(types::Severity::Warning as u8, 1);
        assert_eq!(types::Severity::Error as u8, 2);
        assert_eq!(types::Severity::Critical as u8, 3);
    }

    #[test]
    fn proto_positions_are_contiguous() {
        assert_eq!(protocol::POS_ID, 0);
        assert_eq!(protocol::POS_INTERP, 11);
    }

    #[test]
    fn conformance_case_count() {
        assert_eq!(conformance::CASES.len(), 9);
    }
}

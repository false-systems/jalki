//! Conformance test cases — defined once, executed in every SDK language.

/// A conformance test case.
#[derive(Debug)]
pub struct ConformanceCase {
    pub id: &'static str,
    pub description: &'static str,
    /// If true, test requires a running jälki daemon.
    pub requires_daemon: bool,
    pub input: ConformanceInput,
    pub expected: ConformanceExpected,
}

#[derive(Debug)]
pub enum ConformanceInput {
    Find {
        question: &'static str,
    },
    Deploy {
        function: &'static str,
    },
    Stream {
        function: &'static str,
        collect_ms: u64,
    },
    StreamWithFilter {
        function: &'static str,
        dst_port: u16,
        collect_ms: u64,
    },
    Ask {
        question: &'static str,
    },
}

#[derive(Debug)]
pub enum ConformanceExpected {
    FindResult {
        first_function: &'static str,
        min_results: usize,
    },
    Handle {
        has_probe_id: bool,
    },
    Events {
        /// 0 = "zero or more" (stream may be quiet in CI)
        min_count: usize,
        /// All returned events must have these fields non-null
        fields_present: &'static [&'static str],
    },
    AskResult {
        has_interpretation: bool,
        has_action: bool,
    },
    EventShape {
        /// These fields must be present on every event
        has_field: &'static [&'static str],
        /// These fields must NOT be present (FALSE Protocol bloat)
        no_field: &'static [&'static str],
    },
    FilteredEvents {
        /// All returned events must match this dst_port
        dst_port: u16,
    },
}

pub const CASES: &[ConformanceCase] = &[
    ConformanceCase {
        id: "find_tcp_connect",
        description: "find returns tcp_connect for connection failure question",
        requires_daemon: false,
        input: ConformanceInput::Find {
            question: "why are connections failing",
        },
        expected: ConformanceExpected::FindResult {
            first_function: "tcp_connect",
            min_results: 1,
        },
    },
    ConformanceCase {
        id: "find_retransmit",
        description: "find returns tcp_retransmit_skb for packet loss question",
        requires_daemon: false,
        input: ConformanceInput::Find {
            question: "packet loss",
        },
        expected: ConformanceExpected::FindResult {
            first_function: "tcp_retransmit_skb",
            min_results: 1,
        },
    },
    ConformanceCase {
        id: "find_no_daemon",
        description: "find works without any daemon running",
        requires_daemon: false,
        input: ConformanceInput::Find {
            question: "connection refused",
        },
        expected: ConformanceExpected::FindResult {
            first_function: "tcp_connect",
            min_results: 1,
        },
    },
    ConformanceCase {
        id: "deploy_returns_handle",
        description: "deploy returns handle with non-empty probe_id",
        requires_daemon: true,
        input: ConformanceInput::Deploy {
            function: "tcp_connect",
        },
        expected: ConformanceExpected::Handle { has_probe_id: true },
    },
    ConformanceCase {
        id: "stream_required_fields",
        description: "stream events have id, ts, probe, severity, outcome",
        requires_daemon: true,
        input: ConformanceInput::Stream {
            function: "tcp_connect",
            collect_ms: 2000,
        },
        expected: ConformanceExpected::Events {
            min_count: 0,
            fields_present: &["id", "ts", "probe", "severity", "outcome"],
        },
    },
    ConformanceCase {
        id: "compact_no_false_protocol_fields",
        description: "events must not contain full FALSE Protocol fields",
        requires_daemon: true,
        input: ConformanceInput::Stream {
            function: "tcp_connect",
            collect_ms: 1000,
        },
        expected: ConformanceExpected::EventShape {
            has_field: &["id", "ts", "probe", "severity", "outcome"],
            no_field: &[
                "source",
                "enrichment_state",
                "entity_ids",
                "correlation_keys",
                "occurrence_type",
            ],
        },
    },
    ConformanceCase {
        id: "filter_server_side",
        description: "filter is applied server-side — non-matching events never arrive",
        requires_daemon: true,
        input: ConformanceInput::StreamWithFilter {
            function: "tcp_connect",
            dst_port: 9999,
            collect_ms: 2000,
        },
        expected: ConformanceExpected::FilteredEvents { dst_port: 9999 },
    },
    ConformanceCase {
        id: "ask_with_daemon",
        description: "ask returns non-empty interpretation and action",
        requires_daemon: true,
        input: ConformanceInput::Ask {
            question: "why are connections failing",
        },
        expected: ConformanceExpected::AskResult {
            has_interpretation: true,
            has_action: true,
        },
    },
    ConformanceCase {
        id: "ask_fallback_no_daemon",
        description: "ask falls back to KB when daemon not running, still returns result",
        requires_daemon: false,
        input: ConformanceInput::Ask {
            question: "why are connections failing",
        },
        expected: ConformanceExpected::AskResult {
            has_interpretation: true,
            has_action: true,
        },
    },
];

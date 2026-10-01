//! Resident-memory estimate for evidence records (jalki#97).
//!
//! A bounded in-memory queue is bounded only if it counts what its contents
//! really hold. [`EvidenceBatch::approx_bytes`](crate::EvidenceBatch::approx_bytes)
//! estimates *encoded* size: it serializes every occurrence to JSON, reads
//! 0.32-0.36x of a record's real memory, and costs about 0.9 ms per 1,024
//! records, which is the wrong unit and too slow for a reader thread. This
//! walks the allocations a record owns instead: about 14 ns a record, within a
//! few bytes of a counting allocator. `tests/resident_bytes.rs` pins it to
//! ±5% for every record shape the daemon emits.
//!
//! It counts requested bytes, not the allocator's size classes (jemalloc rounds
//! up by roughly another 10%). Every heap-owning field has to be walked here;
//! one that is missed shows up in the calibration test.

// Capacities are the point of this module, so `&String` / `&Vec` parameters
// are deliberate: `&str` / `&[T]` would hide exactly what is being measured.
#![allow(clippy::ptr_arg)]

use std::collections::HashMap;
use std::mem::size_of;

use false_protocol::{
    CauseRef, ContainerEventData, HistoryStep, K8sEventData, KernelEventData, NetworkEventData,
    NodeEventData, Occurrence, OccurrenceError, OccurrenceHistory, OccurrenceReasoning,
    OtelEventData, PatternMatch, ProcessEventData, ResourceChange, ResourceEventData,
    SchedulingEventData,
};

use crate::evidence::{EvidenceRecord, ProbeMetadata, RuntimeBinding};

/// Resident bytes of one message of records: the Vec's whole allocation
/// (`capacity × size_of::<EvidenceRecord>()`, because unused capacity is
/// allocated memory too) plus the heap every record owns.
pub fn resident_bytes(records: &Vec<EvidenceRecord>) -> usize {
    records.iter().map(EvidenceRecord::heap_bytes).fold(
        records
            .capacity()
            .saturating_mul(size_of::<EvidenceRecord>()),
        usize::saturating_add,
    )
}

impl EvidenceRecord {
    /// Heap this record owns beyond its inline `size_of` (2,560 bytes): the
    /// occurrence's strings, label table and payloads, the probe metadata and
    /// the runtime binding.
    pub fn heap_bytes(&self) -> usize {
        probe_heap(&self.probe)
            + self.binding.as_ref().map_or(0, binding_heap)
            + occurrence_heap(&self.occurrence)
    }
}

fn s(value: &String) -> usize {
    value.capacity()
}

fn os(value: &Option<String>) -> usize {
    value.as_ref().map_or(0, String::capacity)
}

fn vec_of<T>(values: &Vec<T>, each: impl Fn(&T) -> usize) -> usize {
    values.capacity() * size_of::<T>() + values.iter().map(each).sum::<usize>()
}

fn strings(values: &Vec<String>) -> usize {
    vec_of(values, String::capacity)
}

/// Control bytes hashbrown adds past the last bucket (one SIMD group).
const HASH_GROUP_WIDTH: usize = 16;

fn map_of<K, V>(map: &HashMap<K, V>, each: impl Fn(&K, &V) -> usize) -> usize {
    let capacity = map.capacity();
    if capacity == 0 {
        return 0;
    }
    // hashbrown keeps buckets at a power of two loaded to at most 7/8 (4 or 8
    // buckets below that), with one control byte per bucket.
    let buckets = (capacity.saturating_mul(8) / 7).next_power_of_two();
    buckets * (size_of::<(K, V)>() + 1)
        + HASH_GROUP_WIDTH
        + map.iter().map(|(k, v)| each(k, v)).sum::<usize>()
}

fn string_map(map: &HashMap<String, String>) -> usize {
    map_of(map, |k, v| k.capacity() + v.capacity())
}

fn probe_heap(probe: &ProbeMetadata) -> usize {
    s(&probe.probe_id)
        + s(&probe.probe_version)
        + s(&probe.probe_family)
        + s(&probe.kernel_function)
}

fn binding_heap(binding: &RuntimeBinding) -> usize {
    match binding {
        RuntimeBinding::Bound {
            container_id,
            pod_uid,
            pod_name,
            namespace,
            service_account,
            owner_kind,
            owner_name,
            owner_uid,
            provenance: _,
        } => {
            s(container_id)
                + os(pod_uid)
                + os(pod_name)
                + os(namespace)
                + os(service_account)
                + os(owner_kind)
                + os(owner_name)
                + os(owner_uid)
        }
        RuntimeBinding::Unbound { .. } => 0,
    }
}

fn occurrence_heap(occ: &Occurrence) -> usize {
    s(&occ.source)
        // A private `String`; its length is exact for the types built from a
        // `&str`, which is every type jälki emits.
        + occ.occurrence_type.as_str().len()
        + strings(&occ.correlation_keys)
        + occ.error.as_ref().map_or(0, error_heap)
        + occ.reasoning.as_ref().map_or(0, reasoning_heap)
        + occ.history.as_ref().map_or(0, history_heap)
        + strings(&occ.entity_ids)
        + s(&occ.cluster)
        + os(&occ.namespace)
        + string_map(&occ.labels)
        + os(&occ.trace_id)
        + os(&occ.span_id)
        + os(&occ.parent_span_id)
        + occ.network_data.as_ref().map_or(0, network_heap)
        + occ.kernel_data.as_ref().map_or(0, kernel_heap)
        + occ.container_data.as_ref().map_or(0, container_heap)
        + occ.k8s_data.as_ref().map_or(0, k8s_heap)
        + occ.process_data.as_ref().map_or(0, process_heap)
        + occ.scheduling_data.as_ref().map_or(0, scheduling_heap)
        + occ.node_data.as_ref().map_or(0, node_heap)
        + occ.resource_data.as_ref().map_or(0, resource_heap)
        + occ.otel_data.as_ref().map_or(0, otel_heap)
}

fn error_heap(e: &OccurrenceError) -> usize {
    s(&e.code)
        + os(&e.message)
        + os(&e.stack)
        + os(&e.cause)
        + s(&e.what_failed)
        + os(&e.why_it_matters)
        + strings(&e.possible_causes)
        + os(&e.suggested_fix)
}

fn cause_ref_heap(c: &CauseRef) -> usize {
    s(&c.occurrence_id) + s(&c.cause_type) + os(&c.summary)
}

fn reasoning_heap(r: &OccurrenceReasoning) -> usize {
    s(&r.summary)
        + os(&r.explanation)
        + strings(&r.steps)
        + r.root_cause.as_ref().map_or(0, cause_ref_heap)
        + vec_of(&r.causal_chain, cause_ref_heap)
        + vec_of(&r.patterns_matched, |p: &PatternMatch| {
            s(&p.pattern_id) + s(&p.name)
        })
        + vec_of(&r.alternative_explanations, cause_ref_heap)
}

fn history_heap(h: &OccurrenceHistory) -> usize {
    vec_of(&h.steps, |step: &HistoryStep| {
        s(&step.description) + os(&step.timestamp) + os(&step.status)
    })
}

fn network_heap(n: &NetworkEventData) -> usize {
    s(&n.protocol)
        + s(&n.src_ip)
        + s(&n.dst_ip)
        + s(&n.direction)
        + os(&n.dns_query)
        + os(&n.http_method)
        + os(&n.http_path)
}

fn kernel_heap(k: &KernelEventData) -> usize {
    s(&k.event_type) + s(&k.command) + os(&k.oom_victim_comm) + os(&k.syscall_name)
}

fn container_heap(c: &ContainerEventData) -> usize {
    s(&c.container_id) + s(&c.container_name) + s(&c.image) + s(&c.state)
}

fn k8s_heap(k: &K8sEventData) -> usize {
    s(&k.resource_type) + s(&k.resource_name) + s(&k.namespace) + s(&k.reason) + s(&k.message)
}

fn process_heap(p: &ProcessEventData) -> usize {
    s(&p.command) + os(&p.args)
}

fn scheduling_heap(d: &SchedulingEventData) -> usize {
    s(&d.pod_uid) + map_of(&d.failure_reasons, |k, _| k.capacity())
}

fn node_heap(n: &NodeEventData) -> usize {
    s(&n.node_name) + s(&n.condition) + s(&n.status) + os(&n.reason)
}

fn resource_heap(r: &ResourceEventData) -> usize {
    s(&r.resource_id)
        + s(&r.resource_type)
        + s(&r.provider)
        + s(&r.region)
        + s(&r.account)
        + s(&r.status)
        + string_map(&r.tags)
        + vec_of(&r.changes, |c: &ResourceChange| {
            s(&c.field) + s(&c.old_value) + s(&c.new_value)
        })
}

fn otel_heap(o: &OtelEventData) -> usize {
    s(&o.service_name)
        + s(&o.operation_name)
        + s(&o.span_kind)
        + s(&o.status_code)
        + string_map(&o.attributes)
        + os(&o.error_message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{HookKind, KernelEvent, TcpConnectEvent};

    fn record() -> EvidenceRecord {
        KernelEvent::TcpConnect(TcpConnectEvent {
            observed_at_ns: 1,
            pid: 1,
            tid: 1,
            src_ip: "10.0.0.1".parse().expect("ip"),
            dst_ip: "10.0.0.2".parse().expect("ip"),
            src_port: 1234,
            dst_port: 443,
            addr_family: 2,
            ret: 0,
            cgroup_id: 1,
            comm: "curl".into(),
            netns: 0,
        })
        .normalize(
            ProbeMetadata {
                probe_id: "tcp_connect".into(),
                probe_version: "1".into(),
                probe_family: "tcp".into(),
                hook_kind: HookKind::Fexit,
                kernel_function: "tcp_connect".into(),
            },
            "prod",
        )
        .records
        .remove(0)
    }

    /// A reader message is a push-grown Vec: 520 records sit in capacity
    /// 1,024, and the empty slots are allocated memory a budget has to see.
    #[test]
    fn resident_bytes_counts_capacity_slack() {
        let mut records = Vec::with_capacity(1024);
        records.push(record());

        assert!(resident_bytes(&records) >= 1024 * size_of::<EvidenceRecord>());
        records.shrink_to_fit();
        assert!(resident_bytes(&records) < 2 * size_of::<EvidenceRecord>());
    }

    #[test]
    fn heap_bytes_follows_what_the_record_owns() {
        let small = record();
        let mut large = record();
        large
            .occurrence
            .labels
            .insert("requested_path".into(), "x".repeat(4096));

        assert!(small.heap_bytes() > 0);
        assert!(large.heap_bytes() >= small.heap_bytes() + 4096);
    }
}

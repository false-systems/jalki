//! Calibrates `resident_bytes` against what the allocator really hands out.
//!
//! Its own test binary, because it installs a counting global allocator, and a
//! single `#[test]`, so no other test allocates while one is being measured.
//! The bound it holds is the one the reader→sink queue budget (jalki#97)
//! depends on: an estimate that drifts low lets the queue hold more than
//! `JALKI_QUEUE_MAX_BYTES` says, which is the OOM the budget exists to stop.
//! A heap-owning field the estimator does not walk shows up here.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicIsize, Ordering};

use false_protocol::{NetworkEventData, Occurrence, Outcome, ProcessEventData, Severity};
use jalki_evidence::{
    resident_bytes, BindingProvenance, EvidenceRecord, FileOpenEvent, GapReport, HookKind,
    KernelEvent, ProbeMetadata, ProcessExecEvent, ProducerMetadata, RuntimeBinding, TcpCloseEvent,
    TcpConnectEvent,
};

struct Counting;

static NET: AtomicIsize = AtomicIsize::new(0);

// SAFETY: every method forwards to `System` with the caller's own arguments
// and only adds bookkeeping, so it upholds exactly `System`'s contract.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        NET.fetch_add(layout.size() as isize, Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        NET.fetch_sub(layout.size() as isize, Ordering::Relaxed);
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        NET.fetch_add(
            new_size as isize - layout.size() as isize,
            Ordering::Relaxed,
        );
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

fn meta(probe_id: &str, function: &str) -> ProbeMetadata {
    ProbeMetadata {
        probe_id: probe_id.into(),
        probe_version: "1".into(),
        probe_family: "test".into(),
        hook_kind: HookKind::Fexit,
        kernel_function: function.into(),
    }
}

fn bound() -> RuntimeBinding {
    RuntimeBinding::Bound {
        container_id: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
        pod_uid: Some("12345678-1234-1234-1234-123456789012".into()),
        pod_name: Some("runner-abcde-xyz12".into()),
        namespace: Some("arc-runners".into()),
        service_account: Some("runner".into()),
        owner_kind: Some("EphemeralRunner".into()),
        owner_name: Some("runner-abcde".into()),
        owner_uid: Some("87654321-4321-4321-4321-210987654321".into()),
        provenance: BindingProvenance::Observed,
    }
}

fn first(event: KernelEvent, meta: ProbeMetadata) -> EvidenceRecord {
    event.normalize(meta, "prod").records.remove(0)
}

fn open_attempt(path: String, path_truncated: bool) -> EvidenceRecord {
    first(
        KernelEvent::FileOpenAttempt(FileOpenEvent {
            observed_at_ns: 1,
            pid: 7,
            uid: 1001,
            cgroup_id: 9,
            ret: -2,
            flags: 0,
            comm: "rustc".into(),
            path,
            path_truncated,
        }),
        meta("file_open_attempt", "sys_exit_openat"),
    )
}

fn tcp_connect(ret: i32) -> EvidenceRecord {
    first(
        KernelEvent::TcpConnect(TcpConnectEvent {
            observed_at_ns: 1,
            pid: 1,
            tid: 1,
            src_ip: "10.0.0.1".parse().expect("ip"),
            dst_ip: "10.0.0.2".parse().expect("ip"),
            src_port: 1234,
            dst_port: 443,
            addr_family: 2,
            ret,
            cgroup_id: 1,
            comm: "curl".into(),
            netns: 0,
        }),
        meta("tcp_connect", "tcp_connect"),
    )
}

/// The shape `GeneratedProbeReader` builds for a codegen probe: one entity id
/// per captured field and every network string set.
fn codegen_shaped() -> EvidenceRecord {
    let mut occ = Occurrence::new("jalki/codegen", "kernel.tcp.sendmsg")
        .severity(Severity::Info)
        .outcome(Outcome::Success)
        .in_cluster("prod");
    occ.entity_ids = (0..8).map(|i| format!("field_{i}:value-{i}")).collect();
    occ.network_data = Some(NetworkEventData {
        protocol: "tcp".into(),
        src_ip: "10.0.0.1".into(),
        dst_ip: "10.0.0.2".into(),
        src_port: 1234,
        dst_port: 443,
        direction: "outbound".into(),
        dns_query: Some("example.internal".into()),
        http_method: Some("POST".into()),
        http_path: Some("/v1/evidence/append".into()),
        http_status_code: None,
        latency_ms: None,
        bytes_sent: Some(1),
        bytes_received: Some(2),
        rtt_baseline_ms: None,
        rtt_current_ms: None,
        retransmit_count: None,
    });
    occ.process_data = Some(ProcessEventData {
        pid: 1,
        ppid: None,
        command: "curl".into(),
        args: None,
        uid: None,
        exit_code: None,
    });
    occ.labels.insert("ret".into(), "0".into());
    EvidenceRecord {
        observed_at_ns: 1,
        pid: 1,
        cgroup_id: 1,
        probe: meta("tcp_sendmsg", "tcp_sendmsg"),
        occurrence: occ,
        binding: Some(bound()),
    }
}

/// Real bytes allocated to hold `n` clones of `record` in one Vec, against the
/// estimate for that Vec.
fn ratio(record: &EvidenceRecord) -> (usize, usize) {
    const N: usize = 512;
    let before = NET.load(Ordering::Relaxed);
    let records: Vec<EvidenceRecord> = (0..N).map(|_| record.clone()).collect();
    let real = (NET.load(Ordering::Relaxed) - before) as usize;
    let estimate = resident_bytes(&records);
    drop(records);
    (estimate, real)
}

#[test]
fn estimate_tracks_real_heap() {
    let shapes: Vec<(&str, EvidenceRecord)> = vec![
        (
            "open_attempt, bound",
            open_attempt(
                "/home/runner/_work/x/target/debug/deps/libfoo-0123456789abcdef.so".into(),
                false,
            )
            .with_runtime_binding(bound()),
        ),
        (
            "open_attempt, 255-byte path",
            open_attempt(format!("/{}", "a".repeat(254)), true).with_runtime_binding(bound()),
        ),
        ("tcp_connect, unbound", tcp_connect(0)),
        (
            "tcp_connect, failed (error block), bound",
            tcp_connect(-111).with_runtime_binding(bound()),
        ),
        (
            "tcp_close, bound",
            first(
                KernelEvent::TcpClose(TcpCloseEvent {
                    observed_at_ns: 1,
                    pid: 1,
                    tid: 1,
                    src_ip: "10.0.0.1".parse().expect("ip"),
                    dst_ip: "10.0.0.2".parse().expect("ip"),
                    src_port: 0,
                    dst_port: 443,
                    addr_family: 2,
                    bytes_sent: 10,
                    bytes_received: 20,
                    duration_ns: 30,
                    cgroup_id: 1,
                    comm: "curl".into(),
                    netns: 0,
                }),
                meta("tcp_close", "tcp_close"),
            )
            .with_runtime_binding(bound()),
        ),
        (
            "process_exec, bound",
            first(
                KernelEvent::ProcessExec(ProcessExecEvent {
                    observed_at_ns: 1,
                    pid: 1,
                    tid: 1,
                    ppid: 1,
                    uid: 0,
                    gid: 0,
                    cgroup_id: 1,
                    ret: 0,
                    comm: "bash".into(),
                    filename: "/usr/bin/bash".into(),
                    argv_hash: [7; 32],
                    leader_start_boottime_ns: 5,
                }),
                meta("process_exec", "sched_process_exec"),
            )
            .with_runtime_binding(bound()),
        ),
        (
            "jalki.agent.gap",
            GapReport {
                cause: "sink_queue_overflow".into(),
                affected_probes: vec!["kernel.tcp.connect".into(), "kernel.file.open".into()],
                dropped_records: 4_979,
                gap_start_ns: 10,
                gap_end_ns: 20,
                dropped_reliability: 0,
                dropped_attribution: 4_979,
            }
            .into_batch(ProducerMetadata::new("prod", "node-1", "6.17.0"))
            .records
            .remove(0),
        ),
        ("codegen-shaped", codegen_shaped()),
    ];

    let mut report = String::new();
    let mut bad = Vec::new();
    for (name, record) in &shapes {
        let (estimate, real) = ratio(record);
        let r = estimate as f64 / real as f64;
        report.push_str(&format!(
            "{name}: estimate {estimate} / real {real} = {r:.3}\n"
        ));
        // The estimate reads within 0.5% of the allocator for every shape;
        // ±5% still catches a missed field the size of the failed-connect
        // error block (about 6% of that record), where ±10% would not.
        if !(0.95..=1.05).contains(&r) {
            bad.push(*name);
        }
    }
    println!("{report}");
    assert!(bad.is_empty(), "outside ±5% for {bad:?}:\n{report}");
}

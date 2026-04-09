use std::collections::HashMap;
use std::sync::RwLock;

use chrono::Utc;
use false_protocol::Occurrence;

/// In-memory ring buffer of recent Occurrences, per probe.
///
/// Thread-safe via RwLock. Readers don't block each other.
/// Writers acquire exclusive access briefly to push one event.
pub struct EventStore {
    capacity: usize,
    buffers: RwLock<HashMap<String, ProbeBuffer>>,
}

struct ProbeBuffer {
    events: Vec<Occurrence>,
    head: usize,
    count: usize,
}

impl ProbeBuffer {
    fn new(capacity: usize) -> Self {
        Self {
            events: Vec::with_capacity(capacity),
            head: 0,
            count: 0,
        }
    }

    fn push(&mut self, occ: Occurrence) {
        if self.events.len() < self.events.capacity() {
            self.events.push(occ);
            self.count += 1;
        } else {
            self.events[self.head] = occ;
            self.head = (self.head + 1) % self.events.capacity();
            self.count += 1;
        }
    }

    /// Iterate events in insertion order (oldest first).
    fn iter(&self) -> impl Iterator<Item = &Occurrence> {
        let cap = self.events.len();
        let start = if self.count >= cap { self.head } else { 0 };
        let len = self.events.len();
        (0..len).map(move |i| &self.events[(start + i) % cap])
    }
}

/// Filter for querying the event store.
#[derive(Debug, Default, Clone)]
pub struct EventFilter {
    pub last_seconds: Option<u64>,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub pid: Option<u32>,
    pub command: Option<String>,
    pub limit: Option<usize>,
}

impl EventStore {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            buffers: RwLock::new(HashMap::new()),
        }
    }

    /// Push an occurrence into the probe's ring buffer.
    pub fn push(&self, probe_name: &str, occurrence: Occurrence) {
        let mut buffers = self.buffers.write().unwrap();
        let buffer = buffers
            .entry(probe_name.to_string())
            .or_insert_with(|| ProbeBuffer::new(self.capacity));
        buffer.push(occurrence);
    }

    /// Query events for a specific probe.
    pub fn query(&self, probe_name: &str, filter: &EventFilter) -> Vec<Occurrence> {
        let buffers = self.buffers.read().unwrap();
        let buffer = match buffers.get(probe_name) {
            Some(b) => b,
            None => return Vec::new(),
        };
        filter_events(buffer.iter(), filter)
    }

    /// Query events across all probes.
    pub fn query_all(&self, filter: &EventFilter) -> Vec<Occurrence> {
        let buffers = self.buffers.read().unwrap();
        let mut results = Vec::new();
        for buffer in buffers.values() {
            results.extend(filter_events(buffer.iter(), filter));
        }
        // Sort by timestamp, most recent first.
        results.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        let limit = filter.limit.unwrap_or(100);
        results.truncate(limit);
        results
    }

    /// List probe names that have events.
    pub fn probe_names(&self) -> Vec<String> {
        let buffers = self.buffers.read().unwrap();
        buffers.keys().cloned().collect()
    }
}

fn filter_events<'a>(
    events: impl Iterator<Item = &'a Occurrence>,
    filter: &EventFilter,
) -> Vec<Occurrence> {
    let now = Utc::now();
    let limit = filter.limit.unwrap_or(100);

    events
        .filter(|occ| {
            if let Some(secs) = filter.last_seconds {
                let cutoff = now - chrono::Duration::seconds(secs as i64);
                if occ.timestamp < cutoff {
                    return false;
                }
            }
            if let Some(ref src_ip) = filter.src_ip {
                if let Some(ref net) = occ.network_data {
                    if &net.src_ip != src_ip {
                        return false;
                    }
                } else {
                    return false;
                }
            }
            if let Some(ref dst_ip) = filter.dst_ip {
                if let Some(ref net) = occ.network_data {
                    if &net.dst_ip != dst_ip {
                        return false;
                    }
                } else {
                    return false;
                }
            }
            if let Some(src_port) = filter.src_port {
                if let Some(ref net) = occ.network_data {
                    if net.src_port != src_port {
                        return false;
                    }
                } else {
                    return false;
                }
            }
            if let Some(dst_port) = filter.dst_port {
                if let Some(ref net) = occ.network_data {
                    if net.dst_port != dst_port {
                        return false;
                    }
                } else {
                    return false;
                }
            }
            if let Some(pid) = filter.pid {
                if let Some(ref proc_data) = occ.process_data {
                    if proc_data.pid != pid {
                        return false;
                    }
                } else {
                    return false;
                }
            }
            if let Some(ref command) = filter.command {
                if let Some(ref proc_data) = occ.process_data {
                    if &proc_data.command != command {
                        return false;
                    }
                } else {
                    return false;
                }
            }
            true
        })
        .take(limit)
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use false_protocol::{NetworkEventData, Occurrence, ProcessEventData, Severity};

    fn make_occ(src_ip: &str, dst_ip: &str, dst_port: u16, pid: u32, cmd: &str) -> Occurrence {
        let mut occ = Occurrence::new("jalki/test", "kernel.tcp.connect")
            .severity(Severity::Info)
            .in_cluster("test");
        occ.network_data = Some(NetworkEventData {
            protocol: "tcp".into(),
            src_ip: src_ip.into(),
            dst_ip: dst_ip.into(),
            src_port: 12345,
            dst_port,
            direction: "egress".into(),
            dns_query: None,
            http_method: None,
            http_path: None,
            http_status_code: None,
            latency_ms: None,
            bytes_sent: None,
            bytes_received: None,
            rtt_baseline_ms: None,
            rtt_current_ms: None,
            retransmit_count: None,
        });
        occ.process_data = Some(ProcessEventData {
            pid,
            ppid: None,
            command: cmd.into(),
            args: None,
            uid: 0,
            exit_code: None,
        });
        occ
    }

    #[test]
    fn push_and_query() {
        let store = EventStore::new(100);
        store.push("tcp_connect", make_occ("10.0.0.1", "10.0.0.2", 8080, 1234, "nginx"));
        store.push("tcp_connect", make_occ("10.0.0.1", "10.0.0.3", 5432, 1234, "nginx"));

        let results = store.query("tcp_connect", &EventFilter::default());
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn filter_by_dst_port() {
        let store = EventStore::new(100);
        store.push("tcp_connect", make_occ("10.0.0.1", "10.0.0.2", 8080, 1, "a"));
        store.push("tcp_connect", make_occ("10.0.0.1", "10.0.0.2", 5432, 2, "b"));
        store.push("tcp_connect", make_occ("10.0.0.1", "10.0.0.2", 5432, 3, "c"));

        let results = store.query(
            "tcp_connect",
            &EventFilter {
                dst_port: Some(5432),
                ..Default::default()
            },
        );
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn filter_by_pid() {
        let store = EventStore::new(100);
        store.push("tcp_connect", make_occ("10.0.0.1", "10.0.0.2", 80, 100, "nginx"));
        store.push("tcp_connect", make_occ("10.0.0.1", "10.0.0.2", 80, 200, "curl"));

        let results = store.query(
            "tcp_connect",
            &EventFilter {
                pid: Some(100),
                ..Default::default()
            },
        );
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn ring_buffer_wraps() {
        let store = EventStore::new(3);
        store.push("p", make_occ("1", "2", 80, 1, "a"));
        store.push("p", make_occ("1", "2", 80, 2, "b"));
        store.push("p", make_occ("1", "2", 80, 3, "c"));
        store.push("p", make_occ("1", "2", 80, 4, "d")); // wraps, evicts pid=1

        let results = store.query("p", &EventFilter::default());
        assert_eq!(results.len(), 3);
        // Oldest should be pid=2 (pid=1 was evicted).
        let pids: Vec<u32> = results.iter().map(|o| o.process_data.as_ref().unwrap().pid).collect();
        assert_eq!(pids, vec![2, 3, 4]);
    }

    #[test]
    fn query_unknown_probe() {
        let store = EventStore::new(100);
        let results = store.query("nonexistent", &EventFilter::default());
        assert!(results.is_empty());
    }

    #[test]
    fn limit_results() {
        let store = EventStore::new(100);
        for i in 0..50 {
            store.push("p", make_occ("1", "2", 80, i, "a"));
        }
        let results = store.query(
            "p",
            &EventFilter {
                limit: Some(10),
                ..Default::default()
            },
        );
        assert_eq!(results.len(), 10);
    }
}

//! On-disk backlog so an outage's evidence survives a restart (jalki #33).
//!
//! The retry buffer is RAM. That means it does not survive the thing it exists
//! to protect against: an OOM kill during a sink outage destroys exactly the
//! evidence the outage produced, and a rollout or drain does the same. #60
//! made the agent shed *before* the kernel intervenes; this makes what it is
//! still holding outlive a restart.
//!
//! Deliberately not a database. An append-only file of length-prefixed JSON
//! frames, rewritten whole when it is compacted. Records are small, the file is
//! bounded, and the failure this guards against is losing everything — so
//! simplicity that is obviously correct beats efficiency that is not.
//!
//! **A torn tail is expected, not exceptional.** The process is killed
//! mid-write by definition of the scenario, so replay stops at the first frame
//! that does not parse and reports how many bytes it abandoned. Refusing to
//! load a spool because its last frame is short would throw away every intact
//! frame before it, which is the loss we are preventing.

use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use crate::EvidenceBatch;

/// Frames larger than this are refused on read: a corrupt length prefix would
/// otherwise ask us to allocate an arbitrary amount.
const MAX_FRAME_BYTES: u32 = 64 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpoolConfig {
    pub path: PathBuf,
    /// Stop appending past this. Disk is not free — an `emptyDir` counts
    /// against the node's ephemeral storage, and filling it evicts the pod,
    /// which is the failure we are trying to avoid, achieved differently.
    pub max_bytes: u64,
}

/// What replay found. Returned rather than logged internally so the caller
/// decides how loud to be — and so "we abandoned a torn tail" cannot be
/// silent.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ReplayReport {
    pub batches: usize,
    pub records: usize,
    /// Bytes after the last intact frame, discarded. Non-zero means the process
    /// died mid-write, which is the normal case for this feature.
    pub torn_tail_bytes: u64,
}

pub struct Spool {
    config: SpoolConfig,
    bytes: u64,
    /// Set when a write fails. The spool then stops trying: a full or
    /// read-only disk must degrade to "no spool" rather than to an error on
    /// every batch, because delivery must keep working without it.
    disabled: Option<String>,
}

impl Spool {
    /// Open (creating the parent directory if needed), returning `None` if the
    /// location is unusable. A spool is an improvement, never a prerequisite.
    pub fn open(config: SpoolConfig) -> Option<Self> {
        if let Some(parent) = config.path.parent() {
            std::fs::create_dir_all(parent).ok()?;
        }
        let bytes = std::fs::metadata(&config.path)
            .map(|m| m.len())
            .unwrap_or(0);
        Some(Self {
            config,
            bytes,
            disabled: None,
        })
    }

    pub fn path(&self) -> &Path {
        &self.config.path
    }

    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    pub fn is_disabled(&self) -> bool {
        self.disabled.is_some()
    }

    pub fn disabled_reason(&self) -> Option<&str> {
        self.disabled.as_deref()
    }

    /// Append one batch. Over budget or after a write failure this is a no-op:
    /// the in-memory buffer remains the source of truth, and its own bounds
    /// still apply.
    pub fn append(&mut self, batch: &EvidenceBatch) -> bool {
        if self.disabled.is_some() || self.bytes >= self.config.max_bytes {
            return false;
        }
        match self.try_append(batch) {
            Ok(written) => {
                self.bytes += written;
                true
            }
            Err(e) => {
                self.disabled = Some(e.to_string());
                false
            }
        }
    }

    fn try_append(&mut self, batch: &EvidenceBatch) -> std::io::Result<u64> {
        let body = serde_json::to_vec(batch)?;
        let len = u32::try_from(body.len()).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "batch exceeds frame size")
        })?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.config.path)?;
        file.write_all(&len.to_be_bytes())?;
        file.write_all(&body)?;
        // Not fsync per append: the scenario is a killed process, whose page
        // cache the kernel still flushes, and fsyncing every batch during an
        // outage would trade the problem for a slower one. A lost tail is
        // handled by design.
        Ok(4 + body.len() as u64)
    }

    /// Read everything intact, stopping at the first frame that does not parse.
    pub fn replay(path: &Path) -> (Vec<EvidenceBatch>, ReplayReport) {
        let mut report = ReplayReport::default();
        let mut batches = Vec::new();
        let Ok(file) = File::open(path) else {
            return (batches, report);
        };
        let total = file.metadata().map(|m| m.len()).unwrap_or(0);
        let mut reader = BufReader::new(file);
        let mut consumed: u64 = 0;

        loop {
            let mut len_buf = [0u8; 4];
            if reader.read_exact(&mut len_buf).is_err() {
                break;
            }
            let len = u32::from_be_bytes(len_buf);
            if len == 0 || len > MAX_FRAME_BYTES {
                break;
            }
            let mut body = vec![0u8; len as usize];
            if reader.read_exact(&mut body).is_err() {
                break;
            }
            let Ok(batch) = serde_json::from_slice::<EvidenceBatch>(&body) else {
                break;
            };
            report.records += batch.len();
            batches.push(batch);
            consumed += 4 + len as u64;
        }

        report.batches = batches.len();
        report.torn_tail_bytes = total.saturating_sub(consumed);
        (batches, report)
    }

    /// Replace the spool with exactly `batches`, so it reflects what is still
    /// undelivered.
    ///
    /// Write-to-temp-and-rename, because a compaction interrupted halfway would
    /// otherwise leave a file that is neither the old contents nor the new —
    /// and this runs at exactly the moments the process is most likely to die.
    pub fn compact<'a>(&mut self, batches: impl Iterator<Item = &'a EvidenceBatch>) -> bool {
        if self.disabled.is_some() {
            return false;
        }
        match self.try_compact(batches) {
            Ok(bytes) => {
                self.bytes = bytes;
                true
            }
            Err(e) => {
                self.disabled = Some(e.to_string());
                false
            }
        }
    }

    fn try_compact<'a>(
        &mut self,
        batches: impl Iterator<Item = &'a EvidenceBatch>,
    ) -> std::io::Result<u64> {
        let tmp = self.config.path.with_extension("compacting");
        let mut bytes = 0u64;
        {
            let mut writer = BufWriter::new(File::create(&tmp)?);
            for batch in batches {
                let body = serde_json::to_vec(batch)?;
                let Ok(len) = u32::try_from(body.len()) else {
                    continue;
                };
                writer.write_all(&len.to_be_bytes())?;
                writer.write_all(&body)?;
                bytes += 4 + body.len() as u64;
            }
            writer.flush()?;
            // Durable before the rename: a rename that lands while the contents
            // are still in cache would publish an empty file as the truth.
            writer.get_ref().sync_all()?;
        }
        std::fs::rename(&tmp, &self.config.path)?;
        Ok(bytes)
    }

    /// Forget everything; the backlog is delivered.
    pub fn clear(&mut self) -> bool {
        self.compact(std::iter::empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        BindingProvenance, EvidenceRecord, HookKind, ProbeMetadata, ProducerMetadata,
        RuntimeBinding,
    };
    use false_protocol::Occurrence;
    use std::sync::atomic::{AtomicU32, Ordering};

    static SEQ: AtomicU32 = AtomicU32::new(0);

    fn scratch(name: &str) -> PathBuf {
        let n = SEQ.fetch_add(1, Ordering::SeqCst);
        let dir =
            std::env::temp_dir().join(format!("jalki-spool-{name}-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("backlog.spool")
    }

    fn producer() -> ProducerMetadata {
        ProducerMetadata::new("cluster-1", "node-1", "6.17.0")
    }

    fn batch(n: usize) -> EvidenceBatch {
        let records = (0..n)
            .map(|i| EvidenceRecord {
                observed_at_ns: 1_000 + i as u64,
                pid: 42,
                cgroup_id: 7,
                probe: ProbeMetadata {
                    probe_id: "tcp_connect".into(),
                    probe_version: "1".into(),
                    probe_family: "tcp".into(),
                    hook_kind: HookKind::Fexit,
                    kernel_function: "tcp_connect".into(),
                },
                occurrence: Occurrence::new("jalki", "kernel.tcp.connect"),
                binding: Some(RuntimeBinding::Bound {
                    container_id: "containerd://abc".into(),
                    pod_uid: Some("pod-1".into()),
                    pod_name: Some("runner-1".into()),
                    namespace: Some("workloads".into()),
                    service_account: None,
                    owner_kind: Some("ReplicaSet".into()),
                    owner_name: Some("runner-5f9c".into()),
                    owner_uid: Some("uid-rs-1".into()),
                    provenance: BindingProvenance::Observed,
                }),
            })
            .collect();
        EvidenceBatch::new(producer(), records)
    }

    fn cfg(path: PathBuf, max_bytes: u64) -> SpoolConfig {
        SpoolConfig { path, max_bytes }
    }

    /// The acceptance criterion #33 has had open since it was filed: a restart
    /// mid-outage still delivers what was already spooled.
    #[test]
    fn a_backlog_survives_the_process_that_wrote_it() {
        let path = scratch("survives");
        {
            let mut spool = Spool::open(cfg(path.clone(), 1 << 20)).unwrap();
            for _ in 0..5 {
                assert!(spool.append(&batch(3)));
            }
        } // process dies here

        let (batches, report) = Spool::replay(&path);
        assert_eq!(report.batches, 5);
        assert_eq!(report.records, 15);
        assert_eq!(report.torn_tail_bytes, 0);
        assert_eq!(batches.len(), 5);
        assert_eq!(batches[0].len(), 3);
    }

    #[test]
    fn the_binding_survives_the_round_trip() {
        // The whole value of spooled evidence is that it is still attributable.
        // A backlog that replays without its pod and workload identity is
        // bytes, not evidence.
        let path = scratch("binding");
        let mut spool = Spool::open(cfg(path.clone(), 1 << 20)).unwrap();
        spool.append(&batch(1));

        let (batches, _) = Spool::replay(&path);
        match batches[0].records[0].binding.as_ref().unwrap() {
            RuntimeBinding::Bound {
                pod_uid, owner_uid, ..
            } => {
                assert_eq!(pod_uid.as_deref(), Some("pod-1"));
                assert_eq!(owner_uid.as_deref(), Some("uid-rs-1"));
            }
            other => panic!("binding lost in the round trip: {other:?}"),
        }
    }

    /// The process is killed mid-write by definition of the scenario, so a
    /// torn tail is the normal case. Refusing the whole file because its last
    /// frame is short would discard every intact frame before it — the exact
    /// loss this feature exists to prevent.
    #[test]
    fn a_torn_tail_costs_only_the_torn_frame() {
        let path = scratch("torn");
        {
            let mut spool = Spool::open(cfg(path.clone(), 1 << 20)).unwrap();
            for _ in 0..4 {
                spool.append(&batch(2));
            }
        }
        // Simulate a kill partway through the fifth frame.
        let mut raw = std::fs::read(&path).unwrap();
        let intact = raw.len();
        raw.extend_from_slice(&1_000u32.to_be_bytes());
        raw.extend_from_slice(b"{\"partial\":");
        std::fs::write(&path, &raw).unwrap();

        let (batches, report) = Spool::replay(&path);
        assert_eq!(report.batches, 4, "every intact frame is recovered");
        assert_eq!(report.records, 8);
        assert_eq!(
            report.torn_tail_bytes,
            (raw.len() - intact) as u64,
            "and the abandoned bytes are reported, not swallowed"
        );
        assert_eq!(batches.len(), 4);
    }

    #[test]
    fn a_corrupt_length_prefix_cannot_ask_for_an_arbitrary_allocation() {
        let path = scratch("corrupt-len");
        std::fs::write(&path, u32::MAX.to_be_bytes()).unwrap();
        let (batches, report) = Spool::replay(&path);
        assert!(batches.is_empty());
        assert_eq!(report.torn_tail_bytes, 4);
    }

    #[test]
    fn the_spool_stops_at_its_byte_budget() {
        // emptyDir counts against node ephemeral storage; filling it evicts the
        // pod, which is the failure we are avoiding, arrived at differently.
        let path = scratch("budget");
        let mut spool = Spool::open(cfg(path.clone(), 512)).unwrap();
        let mut appended = 0;
        for _ in 0..50 {
            if spool.append(&batch(1)) {
                appended += 1;
            }
        }
        assert!(appended > 0, "it accepts something");
        assert!(appended < 50, "but not everything");
        assert!(
            std::fs::metadata(&path).unwrap().len() < 512 + 4096,
            "and the file stays near its budget"
        );
    }

    #[test]
    fn compaction_leaves_only_what_is_still_undelivered() {
        let path = scratch("compact");
        let mut spool = Spool::open(cfg(path.clone(), 1 << 20)).unwrap();
        for _ in 0..6 {
            spool.append(&batch(1));
        }
        let keep = [batch(1), batch(1)];

        assert!(spool.compact(keep.iter()));

        let (batches, report) = Spool::replay(&path);
        assert_eq!(batches.len(), 2, "delivered batches are not replayed twice");
        assert_eq!(report.torn_tail_bytes, 0);
        assert_eq!(spool.bytes(), std::fs::metadata(&path).unwrap().len());
    }

    #[test]
    fn an_interrupted_compaction_cannot_publish_a_half_file() {
        // Compaction runs exactly when the process is most likely to die, so
        // the temp file must never be the live one until it is complete.
        let path = scratch("atomic");
        let mut spool = Spool::open(cfg(path.clone(), 1 << 20)).unwrap();
        spool.append(&batch(1));
        spool.compact([batch(1), batch(1)].iter());

        assert!(
            !path.with_extension("compacting").exists(),
            "the temp file is renamed, never left behind"
        );
        let (batches, _) = Spool::replay(&path);
        assert_eq!(batches.len(), 2);
    }

    #[test]
    fn clearing_drops_everything() {
        let path = scratch("clear");
        let mut spool = Spool::open(cfg(path.clone(), 1 << 20)).unwrap();
        spool.append(&batch(1));
        assert!(spool.clear());
        assert_eq!(Spool::replay(&path).0.len(), 0);
        assert_eq!(spool.bytes(), 0);
    }

    #[test]
    fn replaying_a_spool_that_was_never_written_is_not_an_error() {
        let (batches, report) = Spool::replay(&scratch("absent"));
        assert!(batches.is_empty());
        assert_eq!(report, ReplayReport::default());
    }

    /// Delivery must keep working without a spool. A full or read-only disk
    /// degrades to "no spool", not to an error on every batch.
    #[test]
    fn an_unwritable_spool_disables_itself_instead_of_failing_every_append() {
        let dir = scratch("unwritable");
        let blocked = dir.parent().unwrap().join("not-a-dir");
        std::fs::write(&blocked, b"x").unwrap();
        let spool = Spool::open(cfg(blocked.join("child.spool"), 1 << 20));
        // create_dir_all under a regular file fails, so open declines outright.
        assert!(
            spool.is_none(),
            "an unusable location yields no spool at all"
        );

        // And a spool that becomes unwritable later stops trying.
        let path = scratch("goes-bad");
        let mut s = Spool::open(cfg(path.clone(), 1 << 20)).unwrap();
        assert!(s.append(&batch(1)));
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
        assert!(!s.append(&batch(1)), "the failed append is reported");
        assert!(s.is_disabled());
        assert!(s.disabled_reason().is_some());
        assert!(!s.append(&batch(1)), "and it does not keep retrying");
    }
}

//! Self-imposed memory pressure sensing (jalki #33).
//!
//! An evidence collector that waits for the kernel to OOM-kill it loses the
//! backlog it was holding — precisely during the incident the evidence is for.
//! Reading our own cgroup lets the agent shed deliberately, with gap evidence,
//! before the kernel sheds the whole process without any.
//!
//! **Resolving "our own" cgroup is the hard part**, and getting it wrong is
//! worse than not having the feature: jälki mounts the *host's*
//! `/sys/fs/cgroup`, so the obvious `/sys/fs/cgroup/memory.max` is the node
//! root, whose limit is unbounded. A naive reading would put the ratio near
//! zero forever and quietly promise a safety net that never fires.

use std::path::{Path, PathBuf};

/// Where the limit came from — worth logging, because "we are watching the
/// wrong cgroup" and "we are watching the right one" produce the same-shaped
/// number.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LimitSource {
    /// `memory.max` in our own cgroup.
    Cgroup(PathBuf),
    /// `JALKI_MEMORY_LIMIT_BYTES`, which the DaemonSet feeds from the pod's
    /// declared limit via the downward API. Needed because a container that
    /// bind-mounts the host hierarchy cannot always find its own leaf.
    DeclaredLimit,
}

#[derive(Debug, Clone)]
pub struct MemoryPressure {
    current_path: PathBuf,
    limit_bytes: u64,
    source: LimitSource,
}

impl MemoryPressure {
    /// Resolve our cgroup beneath `cgroup_root`, then read its limit.
    ///
    /// Returns `None` when neither a cgroup limit nor a declared one can be
    /// established — the caller must say so and carry on without the feature
    /// rather than assume headroom.
    pub fn detect(cgroup_root: &Path, declared_limit: Option<u64>) -> Option<Self> {
        Self::at(&own_cgroup_dir(cgroup_root), declared_limit)
    }

    /// Read a specific cgroup directory, skipping resolution.
    ///
    /// Split out because `detect` consults the real `/proc/self/cgroup`, which
    /// makes it a function of the host: it resolves to `/` inside one container
    /// and to `/actions_job/…` on a CI runner, so a test pointed at a synthetic
    /// directory passes in one and fails in the other. Resolution and reading
    /// are separate questions and now have separate entry points.
    pub fn at(cgroup_dir: &Path, declared_limit: Option<u64>) -> Option<Self> {
        let own = cgroup_dir.to_path_buf();
        let current_path = own.join("memory.current");
        if !current_path.exists() {
            return None;
        }

        // A cgroup limit wins when it is a real number. `max` means unbounded,
        // which in practice means we resolved to the host root — treat it as
        // "not our limit" rather than "no pressure possible".
        if let Some(bytes) = read_limit(&own.join("memory.max")) {
            return Some(Self {
                current_path,
                limit_bytes: bytes,
                source: LimitSource::Cgroup(own),
            });
        }

        declared_limit.filter(|b| *b > 0).map(|bytes| Self {
            current_path,
            limit_bytes: bytes,
            source: LimitSource::DeclaredLimit,
        })
    }

    pub fn limit_bytes(&self) -> u64 {
        self.limit_bytes
    }

    pub fn source(&self) -> &LimitSource {
        &self.source
    }

    /// Fraction of the limit currently in use, or `None` if the file went away
    /// (cgroup removed under us, which is a shutdown race, not an error).
    pub fn ratio(&self) -> Option<f64> {
        let current = read_u64(&self.current_path)?;
        Some(current as f64 / self.limit_bytes as f64)
    }
}

/// Our own cgroup directory beneath `cgroup_root`.
///
/// `/proc/self/cgroup` on cgroup v2 is a single `0::<path>` line. Inside a
/// cgroup namespace that path is `/` — which is correct relative to the
/// container's own view, and wrong when the mount is the host's. Both resolve
/// to `cgroup_root` here; the caller distinguishes them by whether the limit
/// read back is bounded.
fn own_cgroup_dir(cgroup_root: &Path) -> PathBuf {
    let Ok(content) = std::fs::read_to_string("/proc/self/cgroup") else {
        return cgroup_root.to_path_buf();
    };
    for line in content.lines() {
        if let Some(path) = line.strip_prefix("0::") {
            let rel = path.trim().trim_start_matches('/');
            return if rel.is_empty() {
                cgroup_root.to_path_buf()
            } else {
                cgroup_root.join(rel)
            };
        }
    }
    cgroup_root.to_path_buf()
}

/// `memory.max` is either a byte count or the literal `max`.
fn read_limit(path: &Path) -> Option<u64> {
    let raw = std::fs::read_to_string(path).ok()?;
    let raw = raw.trim();
    if raw == "max" {
        return None;
    }
    raw.parse().ok()
}

fn read_u64(path: &Path) -> Option<u64> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("jalki-cgroup-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_bounded_cgroup_limit_is_used() {
        let dir = scratch("bounded");
        fs::write(dir.join("memory.current"), "536870912\n").unwrap();
        fs::write(dir.join("memory.max"), "1073741824\n").unwrap();

        let p = MemoryPressure::at(&dir, None).expect("detected");
        assert_eq!(p.limit_bytes(), 1_073_741_824);
        assert!(matches!(p.source(), LimitSource::Cgroup(_)));
        assert!((p.ratio().unwrap() - 0.5).abs() < 1e-9);
    }

    /// The case that makes this feature dangerous if handled naively. jälki
    /// bind-mounts the host's cgroupfs, so an unresolved path lands on the node
    /// root, whose `memory.max` is `max`. Believing it would peg the ratio near
    /// zero and promise a safety net that never fires.
    #[test]
    fn an_unbounded_limit_is_refused_rather_than_treated_as_headroom() {
        let dir = scratch("unbounded");
        fs::write(dir.join("memory.current"), "536870912\n").unwrap();
        fs::write(dir.join("memory.max"), "max\n").unwrap();

        assert!(
            MemoryPressure::at(&dir, None).is_none(),
            "an unbounded limit means we are not looking at our own cgroup"
        );
    }

    #[test]
    fn the_declared_limit_rescues_an_unbounded_cgroup() {
        let dir = scratch("declared");
        fs::write(dir.join("memory.current"), "805306368\n").unwrap();
        fs::write(dir.join("memory.max"), "max\n").unwrap();

        let p = MemoryPressure::at(&dir, Some(1_073_741_824)).expect("detected");
        assert_eq!(*p.source(), LimitSource::DeclaredLimit);
        assert!((p.ratio().unwrap() - 0.75).abs() < 1e-9);
    }

    #[test]
    fn a_zero_declared_limit_is_not_a_limit() {
        let dir = scratch("zero");
        fs::write(dir.join("memory.current"), "1\n").unwrap();
        fs::write(dir.join("memory.max"), "max\n").unwrap();
        assert!(
            MemoryPressure::at(&dir, Some(0)).is_none(),
            "dividing by zero would report infinite pressure and shed everything"
        );
    }

    #[test]
    fn no_cgroup_files_means_no_feature() {
        let dir = scratch("missing");
        assert!(MemoryPressure::at(&dir, Some(1024)).is_none());
    }

    #[test]
    fn a_cgroup_removed_under_us_is_not_an_error() {
        let dir = scratch("vanishing");
        fs::write(dir.join("memory.current"), "10\n").unwrap();
        fs::write(dir.join("memory.max"), "100\n").unwrap();
        let p = MemoryPressure::at(&dir, None).expect("detected");

        fs::remove_file(dir.join("memory.current")).unwrap();
        assert!(
            p.ratio().is_none(),
            "shutdown races must read as unknown, not as zero pressure"
        );
    }
}

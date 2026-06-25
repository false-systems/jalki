use anyhow::{Context, Result};
use aya::maps::Array;
use aya::Ebpf;
use jalki_common::{SensitivePrefix, MAX_SENSITIVE_PREFIXES, SENSITIVE_PREFIX_LEN};
use tracing::{info, warn};

/// Default sensitive-path patterns.
///
/// Each pattern's *coarse prefix* (the bytes before its first wildcard) is the
/// in-kernel gate. Patterns whose wildcard appears early — e.g. `/proc/*/environ`
/// gates on only `/proc/`, which matches a huge volume of opens that then have to
/// be dropped by the userspace matcher — are intentionally **not** shipped by
/// default. Operators can add them explicitly via `--sensitive-path` /
/// `JALKI_SENSITIVE_PATHS` when the extra ring-buffer traffic is acceptable.
pub const DEFAULT_SENSITIVE_PATHS: &[&str] = &[
    "/var/run/secrets/",
    "/run/secrets/",
    "/etc/shadow",
    "/etc/kubernetes/",
    "/root/.ssh/",
    "/home/*/.ssh/",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SensitivePathMatcher {
    patterns: Vec<String>,
}

impl SensitivePathMatcher {
    pub fn new(patterns: Vec<String>) -> Self {
        Self { patterns }
    }

    pub fn default_patterns() -> Self {
        Self::new(default_sensitive_paths())
    }

    pub fn is_match(&self, path: &str) -> bool {
        self.patterns
            .iter()
            .any(|pattern| pattern_matches(pattern, path))
    }

    pub fn patterns(&self) -> &[String] {
        &self.patterns
    }
}

fn pattern_matches(pattern: &str, path: &str) -> bool {
    let has_glob = pattern.as_bytes().iter().any(|b| matches!(b, b'*' | b'?' | b'['));
    if !has_glob && pattern.ends_with('/') {
        return path.starts_with(pattern);
    }

    if has_glob && pattern.ends_with('/') {
        let mut prefix_pattern = String::with_capacity(pattern.len() + 1);
        prefix_pattern.push_str(pattern);
        prefix_pattern.push('*');
        return glob_match(prefix_pattern.as_bytes(), path.as_bytes());
    }

    glob_match(pattern.as_bytes(), path.as_bytes())
}

pub fn default_sensitive_paths() -> Vec<String> {
    DEFAULT_SENSITIVE_PATHS
        .iter()
        .map(|value| (*value).to_string())
        .collect()
}

pub fn parse_sensitive_paths(values: &[String]) -> Vec<String> {
    let mut paths = Vec::new();
    for value in values {
        for part in value.split(',') {
            let part = part.trim();
            if !part.is_empty() {
                paths.push(part.to_string());
            }
        }
    }
    if paths.is_empty() {
        default_sensitive_paths()
    } else {
        paths
    }
}

pub fn populate_sensitive_prefixes(ebpf: &mut Ebpf, patterns: &[String]) -> Result<()> {
    let mut map: Array<_, SensitivePrefix> = ebpf
        .map_mut("SENSITIVE_PREFIXES")
        .ok_or_else(|| anyhow::anyhow!("SENSITIVE_PREFIXES map not found"))?
        .try_into()
        .context("SENSITIVE_PREFIXES is not an Array")?;

    for index in 0..MAX_SENSITIVE_PREFIXES {
        map.set(index, SensitivePrefix::empty(), 0)
            .with_context(|| format!("failed to clear sensitive prefix slot {index}"))?;
    }

    let mut inserted = 0;
    for pattern in patterns.iter().take(MAX_SENSITIVE_PREFIXES as usize) {
        let prefix = coarse_prefix(pattern);
        if prefix.is_empty() {
            continue;
        }
        let entry = sensitive_prefix(prefix);
        map.set(inserted, entry, 0)
            .with_context(|| format!("failed to insert sensitive prefix {prefix}"))?;
        inserted += 1;
    }

    if patterns.len() > MAX_SENSITIVE_PREFIXES as usize {
        warn!(
            configured = patterns.len(),
            max = MAX_SENSITIVE_PREFIXES,
            "ignoring extra sensitive path patterns"
        );
    }
    info!(count = inserted, "loaded sensitive file-open prefixes");
    Ok(())
}

fn sensitive_prefix(prefix: &str) -> SensitivePrefix {
    let bytes = prefix.as_bytes();
    let len = bytes.len().min(SENSITIVE_PREFIX_LEN);
    let mut entry = SensitivePrefix::empty();
    entry.len = len as u32;
    entry.bytes[..len].copy_from_slice(&bytes[..len]);
    entry
}

fn coarse_prefix(pattern: &str) -> &str {
    let wildcard = pattern.find(['*', '?', '[']).unwrap_or(pattern.len());
    let prefix = &pattern[..wildcard];
    if prefix.is_empty() {
        "/"
    } else {
        prefix
    }
}

/// Wildcard match supporting `*` (matches any run, including empty) and `?`
/// (matches one byte); every other byte is literal.
///
/// Iterative star-backtracking: O(pattern·value) worst case, no recursion and no
/// exponential blowup. Patterns are operator-configured and small today; this
/// keeps the matcher robust even if untrusted/larger patterns are ever wired in.
fn glob_match(pattern: &[u8], value: &[u8]) -> bool {
    let (mut p, mut v) = (0usize, 0usize);
    // Position of the most recent `*` in the pattern, and the value index it was
    // matched against, so a mismatch can let that `*` absorb one more byte.
    let mut star: Option<usize> = None;
    let mut star_v = 0usize;

    while v < value.len() {
        if p < pattern.len() && (pattern[p] == b'?' || pattern[p] == value[v]) {
            p += 1;
            v += 1;
        } else if p < pattern.len() && pattern[p] == b'*' {
            star = Some(p);
            star_v = v;
            p += 1;
        } else if let Some(sp) = star {
            p = sp + 1;
            star_v += 1;
            v = star_v;
        } else {
            return false;
        }
    }

    // Consume any trailing `*`s; the pattern matches iff it is fully consumed.
    while p < pattern.len() && pattern[p] == b'*' {
        p += 1;
    }
    p == pattern.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_path_matches() {
        let matcher = SensitivePathMatcher::default_patterns();

        assert!(matcher.is_match("/var/run/secrets/kubernetes.io/serviceaccount/token"));
    }

    #[test]
    fn unrelated_path_does_not_match() {
        let matcher = SensitivePathMatcher::default_patterns();

        assert!(!matcher.is_match("/tmp/not-sensitive"));
    }

    #[test]
    fn default_patterns_match_home_ssh_not_proc() {
        let matcher = SensitivePathMatcher::default_patterns();

        assert!(matcher.is_match("/home/runner/.ssh/id_rsa"));
        // /proc/*/environ is intentionally not a default (weak coarse-prefix gate).
        assert!(!matcher.is_match("/proc/123/environ"));
    }

    #[test]
    fn explicit_glob_patterns_match() {
        let matcher = SensitivePathMatcher::new(vec![
            "/proc/*/environ".to_string(),
            "/home/*/.ssh/".to_string(),
        ]);

        assert!(matcher.is_match("/proc/123/environ"));
        assert!(matcher.is_match("/home/runner/.ssh/id_rsa"));
        assert!(!matcher.is_match("/proc/123/cmdline"));
    }

    #[test]
    fn parse_accepts_repeated_and_comma_separated_values() {
        let values = vec!["/a,/b".to_string(), " /c ".to_string()];

        assert_eq!(parse_sensitive_paths(&values), vec!["/a", "/b", "/c"]);
    }
}

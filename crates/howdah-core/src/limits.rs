//! Resource limits and the critical-limit checks that stop PHP2Shell-shaped
//! uploads (very many parts/files/headers) before the backend allocates
//! per-part memory.
//!
//! Zero policy: a limit of 0 is rejected by [`Limits::validate`] (called from
//! `Config::from_toml`), because 0 would silently block every multipart body.
//! There is no "unlimited" value; set a large number instead.

use serde::Deserialize;

use crate::multipart::{Event, MultipartState};

/// Resource limits applied to multipart bodies.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Limits {
    /// Maximum number of parts in one body.
    pub max_parts: usize,
    /// Maximum number of file parts in one body.
    pub max_files: usize,
    /// Maximum number of header lines in a single part.
    pub max_part_headers: usize,
    /// Maximum bytes (name + value) of a single part header.
    pub max_part_header_bytes: usize,
    /// Maximum bytes of a form field name.
    pub max_field_name_bytes: usize,
    /// Maximum bytes of an uploaded filename.
    pub max_filename_bytes: usize,
    /// Maximum bytes of any single part body / running parse total.
    pub max_parse_memory_bytes: usize,
}

impl Limits {
    /// Starting values; tuned against the false-positive corpus in Task 12.
    pub fn defaults() -> Limits {
        Limits {
            // PHP's own max_input_vars is 1000; real forms rarely exceed a few
            // hundred fields. 2000 leaves headroom, yet PHP2Shell uses tens of
            // thousands of parts.
            max_parts: 2000,
            // No legitimate form uploads hundreds of files at once.
            max_files: 200,
            // Browsers send 1-3 headers per part (Content-Disposition, Content-Type).
            max_part_headers: 16,
            // Typical header is <200 bytes; 8 KiB tolerates long UTF-8 filenames.
            max_part_header_bytes: 8 * 1024,
            // Field names are identifiers/array keys; 1 KiB is very generous.
            max_field_name_bytes: 1024,
            // Filesystems cap names at 255 bytes; 512 allows encoded forms.
            max_filename_bytes: 512,
            // 256 MiB: above any sane single part, below host memory exhaustion.
            max_parse_memory_bytes: 256 * 1024 * 1024,
        }
    }

    /// Reject configurations that would block everything (any limit of 0).
    pub fn validate(&self) -> Result<(), String> {
        let fields = [
            ("max_parts", self.max_parts),
            ("max_files", self.max_files),
            ("max_part_headers", self.max_part_headers),
            ("max_part_header_bytes", self.max_part_header_bytes),
            ("max_field_name_bytes", self.max_field_name_bytes),
            ("max_filename_bytes", self.max_filename_bytes),
            ("max_parse_memory_bytes", self.max_parse_memory_bytes),
        ];
        for (name, v) in fields {
            if v == 0 {
                return Err(format!("limits.{name} must be greater than 0"));
            }
        }
        Ok(())
    }

    /// Check the analyzer state (counters, not only `ev`) against the limits.
    /// Call after feeding; robust even if a mid-chunk error dropped events.
    pub fn check(&self, state: &MultipartState, ev: &Event) -> Option<LimitHit> {
        let crit = |rule, detail: String| {
            Some(LimitHit { rule, severity: Severity::Critical, detail })
        };
        if state.parts() > self.max_parts as u64 {
            return crit(
                RuleId::MaxParts,
                format!("{} parts exceeds limit {}", state.parts(), self.max_parts),
            );
        }
        if state.files() > self.max_files as u64 {
            return crit(
                RuleId::MaxFiles,
                format!("{} files exceeds limit {}", state.files(), self.max_files),
            );
        }
        if state.headers_in_current_part() as u64 > self.max_part_headers as u64 {
            return crit(
                RuleId::MaxPartHeaders,
                format!(
                    "{} headers in one part exceeds limit {}",
                    state.headers_in_current_part(),
                    self.max_part_headers
                ),
            );
        }
        match ev {
            Event::PartHeader { name_len, value_len }
                if name_len.saturating_add(*value_len) > self.max_part_header_bytes =>
            {
                crit(
                    RuleId::MaxPartHeaderBytes,
                    format!("part header of {} bytes exceeds limit", name_len + value_len),
                )
            }
            Event::FieldStart { name_len } if *name_len > self.max_field_name_bytes => crit(
                RuleId::MaxFieldNameLen,
                format!("field name of {name_len} bytes exceeds limit"),
            ),
            Event::FileStart { filename_len } if *filename_len > self.max_filename_bytes => crit(
                RuleId::MaxFilenameLen,
                format!("filename of {filename_len} bytes exceeds limit"),
            ),
            Event::PartData { len } if *len > self.max_parse_memory_bytes as u64 => crit(
                RuleId::ParseMemoryBudget,
                format!("part of {len} bytes exceeds budget"),
            ),
            _ => None,
        }
    }

    /// Check the running total of fed body bytes against the memory budget.
    /// PartData arrives only at PartEnd, so callers count chunk lengths.
    pub fn check_fed_bytes(&self, total_fed: u64) -> Option<LimitHit> {
        (total_fed > self.max_parse_memory_bytes as u64).then(|| LimitHit {
            rule: RuleId::ParseMemoryBudget,
            severity: Severity::Critical,
            detail: format!("{total_fed} body bytes exceeds budget"),
        })
    }
}

impl Default for Limits {
    fn default() -> Self {
        Limits::defaults()
    }
}

/// Identifier of a detection rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleId {
    MaxParts,
    MaxFiles,
    MaxPartHeaders,
    MaxPartHeaderBytes,
    MaxFieldNameLen,
    MaxFilenameLen,
    ParseMemoryBudget,
    MalformedMultipart,
    UploadProgressAbuse,
    SelfTest,
}

impl RuleId {
    /// Default severity of a rule. Malformed multipart is Standard: a strict
    /// parser disagreeing with an unusual legit client must not block by default.
    pub fn severity(self) -> Severity {
        match self {
            RuleId::MalformedMultipart | RuleId::UploadProgressAbuse | RuleId::SelfTest => {
                Severity::Standard
            }
            _ => Severity::Critical,
        }
    }
}

/// How severe a rule's finding is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Severity {
    Critical,
    Standard,
}

/// A limit violation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LimitHit {
    pub rule: RuleId,
    pub severity: Severity,
    pub detail: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feed(limits: &Limits, body: &[u8]) -> Option<LimitHit> {
        let mut st = MultipartState::new(b"B");
        let evs = st.feed(body).unwrap_or_default();
        for ev in &evs {
            if let Some(h) = limits.check(&st, ev) {
                return Some(h);
            }
        }
        None
    }

    fn part(name: &str) -> String {
        format!("--B\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\nv\r\n")
    }

    fn small() -> Limits {
        Limits { max_parts: 3, max_files: 1, max_part_headers: 2, ..Limits::defaults() }
    }

    #[test]
    fn within_limits_is_none() {
        let b = format!("{}{}--B--\r\n", part("a"), part("b"));
        assert_eq!(feed(&small(), b.as_bytes()), None);
    }

    #[test]
    fn too_many_parts_critical() {
        let b = format!("{}{}{}{}--B--\r\n", part("a"), part("b"), part("c"), part("d"));
        let h = feed(&small(), b.as_bytes()).unwrap();
        assert_eq!((h.rule, h.severity), (RuleId::MaxParts, Severity::Critical));
    }

    #[test]
    fn exactly_max_parts_ok() {
        let b = format!("{}{}{}--B--\r\n", part("a"), part("b"), part("c"));
        assert_eq!(feed(&small(), b.as_bytes()), None);
    }

    #[test]
    fn too_many_files_critical() {
        let f = |n: &str| {
            format!("--B\r\nContent-Disposition: form-data; name=\"f\"; filename=\"{n}\"\r\n\r\nx\r\n")
        };
        let b = format!("{}{}--B--\r\n", f("a"), f("b"));
        let h = feed(&small(), b.as_bytes()).unwrap();
        assert_eq!((h.rule, h.severity), (RuleId::MaxFiles, Severity::Critical));
    }

    #[test]
    fn too_many_headers_critical() {
        let b = "--B\r\nContent-Disposition: form-data; name=\"a\"\r\nX-1: a\r\nX-2: b\r\n\r\nv\r\n--B--\r\n";
        let h = feed(&small(), b.as_bytes()).unwrap();
        assert_eq!((h.rule, h.severity), (RuleId::MaxPartHeaders, Severity::Critical));
    }

    #[test]
    fn long_filename_and_field_name() {
        let l = Limits { max_filename_bytes: 4, max_field_name_bytes: 3, ..Limits::defaults() };
        let b = "--B\r\nContent-Disposition: form-data; name=\"f\"; filename=\"abcdefgh\"\r\n\r\nx\r\n--B--\r\n";
        assert_eq!(feed(&l, b.as_bytes()).unwrap().rule, RuleId::MaxFilenameLen);
        let b = "--B\r\nContent-Disposition: form-data; name=\"abcdef\"\r\n\r\nx\r\n--B--\r\n";
        assert_eq!(feed(&l, b.as_bytes()).unwrap().rule, RuleId::MaxFieldNameLen);
    }

    #[test]
    fn header_bytes_and_memory_budget() {
        let l = Limits { max_part_header_bytes: 10, ..Limits::defaults() };
        assert_eq!(feed(&l, part("a").as_bytes()).unwrap().rule, RuleId::MaxPartHeaderBytes);
        let l = Limits { max_parse_memory_bytes: 3, ..Limits::defaults() };
        let b = "--B\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nlonger\r\n--B--\r\n";
        assert_eq!(feed(&l, b.as_bytes()).unwrap().rule, RuleId::ParseMemoryBudget);
        assert!(l.check_fed_bytes(4).is_some());
        assert!(l.check_fed_bytes(3).is_none());
    }

    #[test]
    fn counters_fire_even_if_event_is_unrelated() {
        let mut st = MultipartState::new(b"B");
        st.feed(format!("{}{}{}{}", part("a"), part("b"), part("c"), part("d")).as_bytes())
            .unwrap();
        let h = small().check(&st, &Event::PartEnd).unwrap();
        assert_eq!(h.rule, RuleId::MaxParts);
    }

    #[test]
    fn php2shell_shape_blocked_by_defaults() {
        let body: String = (0..5000).map(|i| part(&format!("f{i}"))).collect();
        let h = feed(&Limits::defaults(), body.as_bytes()).unwrap();
        assert_eq!((h.rule, h.severity), (RuleId::MaxParts, Severity::Critical));
        assert_eq!(feed(&Limits::defaults(), part("ok").as_bytes()), None);
    }

    #[test]
    fn rule_severities() {
        assert_eq!(RuleId::MalformedMultipart.severity(), Severity::Standard);
        assert_eq!(RuleId::MaxParts.severity(), Severity::Critical);
        assert_eq!(RuleId::MaxFiles.severity(), Severity::Critical);
        assert_eq!(RuleId::MaxPartHeaders.severity(), Severity::Critical);
    }

    #[test]
    fn zero_limits_rejected() {
        assert!(Limits::defaults().validate().is_ok());
        let l = Limits { max_parts: 0, ..Limits::defaults() };
        assert!(l.validate().unwrap_err().contains("max_parts"));
    }
}

//! Resource limits and the critical-limit checks that stop PHP2Shell-shaped
//! uploads (very many parts/files/headers) before the backend allocates
//! per-part memory.
//!
//! Zero policy: a limit of 0 is rejected by [`Limits::validate`] (called from
//! `Config::from_toml`), because 0 would silently block every multipart body.
//! There is no "unlimited" value; set a large number instead. A `Limits`
//! built by hand (bypassing `from_toml`) can still contain zeros; `check` then
//! blocks everything but never panics.

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
    /// Maximum number of header lines in any single part.
    pub max_part_headers: usize,
    /// Maximum bytes (name + value) of any single part header.
    pub max_part_header_bytes: usize,
    /// Maximum bytes of a form field name.
    pub max_field_name_bytes: usize,
    /// Maximum bytes of an uploaded filename.
    pub max_filename_bytes: usize,
    /// Backstop on the TOTAL body bytes Howdah will process for one request
    /// (also bounds any single part). Set it above your PHP `post_max_size`
    /// (PHP default 8 MiB) so it never fires before PHP's own limit on normal
    /// uploads; the 256 MiB default is far above typical `post_max_size`.
    pub max_parse_memory_bytes: usize,
}

impl Limits {
    /// Default limits, VALIDATED by the Task-12 cross-version gate (not merely
    /// starting points). Measured on a stock box (memory_limit=128M,
    /// post_max_size=8M) across PHP 5.6/7.3/8.4:
    ///
    /// * On stock config PHP's OWN caps (max_file_uploads=20, max_input_vars=1000)
    ///   hold the shaped flood's peak worker RSS flat at ~20-33 MiB and, on PHP
    ///   8.x, gate the rfc1867 callback entirely -- so the flood is already
    ///   contained and there is nothing for Howdah to block.
    /// * The real exposure is a box with those caps RAISED. There the callback
    ///   fires unbounded and, within the stock 8 MiB post body, the undefended
    ///   flood drives peak RSS to ~127 MiB (8.4) / ~173 MiB (5.6) -- a genuine
    ///   memory-exhaustion DoS. With these defaults Howdah BLOCKS every such
    ///   flood (max_files at 201, max_parts at 2001), holding defended peak to
    ///   ~28-56 MiB, well under 128M.
    /// * The attack needs ~90000 parts to approach 128M -- ~45x more than
    ///   max_parts -- so the count-based critical limits fire with a huge margin
    ///   and no lowering is warranted. The full false-positive corpus (a 500-field
    ///   form, a 15-file gallery, deep nested arrays, the strict-parser cases)
    ///   produces zero blocks at these values. See lab/integration/matrix.sh and
    ///   docs/coverage-data.md.
    pub fn defaults() -> Limits {
        Limits {
            // Stock PHP max_input_vars is 1000, so a stock-config form can carry
            // at most 1000 fields: 2000 never false-positives there, yet a raised-
            // cap flood (the threat) needs tens of thousands of parts to exhaust
            // memory, so max_parts fires ~45x before 128M. See the doc-comment above.
            max_parts: 2000,
            // No legitimate form uploads hundreds of files at once; a raised
            // max_file_uploads flood is capped here before the per-file temp-file
            // allocation (the dominant cost: 127 MiB undefended -> 36 MiB blocked).
            max_files: 200,
            // Browsers send 1-3 headers per part (Content-Disposition, Content-Type).
            max_part_headers: 16,
            // Typical header is <200 bytes; 8 KiB tolerates long UTF-8 filenames.
            max_part_header_bytes: 8 * 1024,
            // Field names are identifiers/array keys; 1 KiB is very generous.
            max_field_name_bytes: 1024,
            // Filesystems cap names at 255 bytes; 512 allows encoded forms.
            max_filename_bytes: 512,
            // 256 MiB total body: well above PHP's default post_max_size (8 MiB)
            // and common raised values, below host memory exhaustion.
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

    /// Check the analyzer state against the limits.
    ///
    /// Every decision reads state counters / high-water marks, never `ev`
    /// (kept for API stability), so enforcement holds whenever this runs:
    /// after a multi-part chunk, or after an error dropped that call's events.
    pub fn check(&self, state: &MultipartState, _ev: &Event) -> Option<LimitHit> {
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
        let hdrs = state.max_headers_in_any_part();
        if hdrs as u64 > self.max_part_headers as u64 {
            return crit(
                RuleId::MaxPartHeaders,
                format!("{hdrs} headers in one part exceeds limit {}", self.max_part_headers),
            );
        }
        let hb = state.max_header_bytes_seen();
        if hb > self.max_part_header_bytes {
            return crit(
                RuleId::MaxPartHeaderBytes,
                format!("part header of {hb} bytes exceeds limit {}", self.max_part_header_bytes),
            );
        }
        let fnl = state.max_field_name_seen();
        if fnl > self.max_field_name_bytes {
            return crit(
                RuleId::MaxFieldNameLen,
                format!("field name of {fnl} bytes exceeds limit {}", self.max_field_name_bytes),
            );
        }
        let fl = state.max_filename_seen();
        if fl > self.max_filename_bytes {
            return crit(
                RuleId::MaxFilenameLen,
                format!("filename of {fl} bytes exceeds limit {}", self.max_filename_bytes),
            );
        }
        self.check_fed_bytes(state.max_part_data_seen().max(state.total_fed_bytes()))
    }

    /// Check a byte total against `max_parse_memory_bytes` (total body bytes
    /// processed). `check` already applies this using the state's totals.
    pub fn check_fed_bytes(&self, total_fed: u64) -> Option<LimitHit> {
        (total_fed > self.max_parse_memory_bytes as u64).then(|| LimitHit {
            rule: RuleId::ParseMemoryBudget,
            severity: Severity::Critical,
            detail: format!("{total_fed} body bytes exceeds budget {}", self.max_parse_memory_bytes),
        })
    }
}

impl Default for Limits {
    fn default() -> Self {
        Limits::defaults()
    }
}

/// The fixed, benign self-test marker: a multipart FIELD NAME. Any request
/// carrying a part with exactly this name produces one `SelfTest` Log event
/// (never a block), so a sysadmin can prove Howdah is live in the web SAPI.
/// The name starts and ends with `__` and contains `howdah_selftest`, so it
/// cannot collide with a real form field. Matching is exact (case-sensitive).
///
/// The core analyzer is fed only name LENGTHS, so the glue (which sees real
/// names via the rfc1867 callback) matches with [`is_selftest_name`] and then
/// reports it through the core's `howdah_selftest` entrypoint.
pub const SELFTEST_FIELD: &[u8] = b"__howdah_selftest__";

/// Does this field name equal the self-test marker?
pub fn is_selftest_name(name: &[u8]) -> bool {
    name == SELFTEST_FIELD
}

/// The hit recorded for the self-test marker (always `Standard`, never critical).
pub fn selftest_hit() -> LimitHit {
    LimitHit {
        rule: RuleId::SelfTest,
        severity: RuleId::SelfTest.severity(),
        detail: "howdah self-test marker".to_string(),
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

    /// Feed the whole body in one chunk (parse errors fail the test), then
    /// check once, as a caller would after a multi-part chunk.
    fn feed(limits: &Limits, body: &[u8]) -> Option<LimitHit> {
        let mut st = MultipartState::new(b"B");
        st.feed(body).expect("test body must parse");
        limits.check(&st, &Event::BodyEnd)
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

    const FLOOD: &str =
        "--B\r\nContent-Disposition: form-data; name=\"a\"\r\nX-1: a\r\nX-2: b\r\n\r\nv\r\n";

    #[test]
    fn too_many_headers_critical() {
        let b = format!("{FLOOD}--B--\r\n");
        let h = feed(&small(), b.as_bytes()).unwrap();
        assert_eq!((h.rule, h.severity), (RuleId::MaxPartHeaders, Severity::Critical));
    }

    #[test]
    fn header_flood_followed_by_normal_part_in_one_chunk_still_fires() {
        let b = format!("{FLOOD}{}--B--\r\n", part("ok"));
        let h = feed(&small(), b.as_bytes()).unwrap();
        assert_eq!(h.rule, RuleId::MaxPartHeaders);
    }

    #[test]
    fn long_filename_followed_by_normal_part_still_fires() {
        let l = Limits { max_filename_bytes: 4, ..Limits::defaults() };
        let b = format!(
            "--B\r\nContent-Disposition: form-data; name=\"f\"; filename=\"abcdefgh\"\r\n\r\nx\r\n{}--B--\r\n",
            part("ok")
        );
        assert_eq!(feed(&l, b.as_bytes()).unwrap().rule, RuleId::MaxFilenameLen);
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
    fn default_budget_allows_normal_upload() {
        let l = Limits::defaults();
        assert!(l.check_fed_bytes(8 * 1024 * 1024).is_none());
    }

    #[test]
    fn fires_from_state_after_mid_chunk_error_dropped_events() {
        let l = Limits { max_filename_bytes: 4, ..Limits::defaults() };
        let mut st = MultipartState::new(b"B");
        // Valid file part with a long filename, then garbage after a delimiter:
        // feed errors and returns no events at all.
        let body = "--B\r\nContent-Disposition: form-data; name=\"f\"; filename=\"abcdefgh\"\r\n\r\nx\r\n--Bzzz";
        assert!(st.feed(body.as_bytes()).is_err());
        assert_eq!(l.check(&st, &Event::PartEnd).unwrap().rule, RuleId::MaxFilenameLen);
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
    fn selftest_marker_is_exact_and_never_ordinary() {
        assert!(is_selftest_name(b"__howdah_selftest__"));
        for n in ["", "a", "username", "file", "howdah_selftest", "__howdah_selftest_",
                  "__HOWDAH_SELFTEST__", "__howdah_selftest__x", "x__howdah_selftest__"] {
            assert!(!is_selftest_name(n.as_bytes()), "{n}");
        }
    }

    #[test]
    fn selftest_is_standard_and_logs_in_detect_never_critical() {
        use crate::config::Mode;
        use crate::rules::{decide, Action};
        let h = selftest_hit();
        assert_eq!((h.rule, h.severity), (RuleId::SelfTest, Severity::Standard));
        let none = std::collections::BTreeMap::new();
        assert_eq!(decide(Some(&h), Mode::Detect, &none), Action::Log);
    }

    #[test]
    fn limit_checks_never_report_selftest() {
        // The limit checks can never yield SelfTest; the real "never matches
        // ordinary traffic" guarantee is the exact-name match (see
        // selftest_marker_is_exact_and_never_ordinary) plus the integration
        // normal-form check.
        assert_eq!(feed(&Limits::defaults(), part("ok").as_bytes()), None);
        let body: String = (0..5000).map(|i| part(&format!("f{i}"))).collect();
        assert_ne!(feed(&Limits::defaults(), body.as_bytes()).unwrap().rule, RuleId::SelfTest);
    }

    #[test]
    fn zero_limits_rejected() {
        assert!(Limits::defaults().validate().is_ok());
        let l = Limits { max_parts: 0, ..Limits::defaults() };
        assert!(l.validate().unwrap_err().contains("max_parts"));
    }

    #[test]
    fn hand_built_zero_limits_block_without_panic() {
        let l = Limits { max_parts: 0, ..Limits::defaults() };
        let b = format!("{}--B--\r\n", part("a"));
        assert_eq!(feed(&l, b.as_bytes()).unwrap().rule, RuleId::MaxParts);
    }
}

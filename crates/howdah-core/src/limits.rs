//! Resource limits and the limit checks that stop resource-exhaustion shapes
//! before PHP allocates for them:
//!   * multipart bodies — very many parts/files, oversized part headers/names
//!     (the PHP2Shell shape), checked while the body is parsed;
//!   * request inputs — too many GET/POST/cookie variables (hash-collision /
//!     variable floods), over-deep array nesting, oversized keys;
//!   * request headers — too many headers, or an oversized header line.
//!
//! Zero policy: a limit of 0 is rejected by [`Limits::validate`] (called from
//! `Config::from_toml`), because 0 would silently block every request.
//! There is no "unlimited" value; set a large number instead. A `Limits`
//! built by hand (bypassing `from_toml`) can still contain zeros; `check` then
//! blocks everything but never panics.

use serde::{Deserialize, Serialize};

use crate::input::InputState;
use crate::multipart::{Event, MultipartState};

/// Resource limits applied to multipart bodies.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
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
    /// Maximum number of request input variables (GET/POST/cookie names).
    pub max_input_vars: usize,
    /// Maximum array nesting depth of any one variable name (`a[b][c]` = 2).
    pub max_input_nesting_depth: usize,
    /// Maximum bytes of any single variable name or array key.
    pub max_input_key_bytes: usize,
    /// Maximum number of request headers.
    pub max_request_headers: usize,
    /// Maximum bytes (name + value) of any single request header.
    pub max_request_header_bytes: usize,
    /// Maximum summed array-nesting levels across all variable/field/file names
    /// in one request (gap C, §4.4). File names are weighted (they build several
    /// metadata arrays). Bounds the total array-building cost, which a flood of
    /// deeply- or widely-nested names drives up regardless of any one depth.
    pub max_nesting_levels: usize,
    /// Override (bytes) for the §4.5 parse-memory ceiling. `0` (the default)
    /// means AUTOMATIC: the ceiling is the request's live `memory_limit / 4`, or
    /// [`FALLBACK_CEILING_BYTES`] when `memory_limit = -1`. A non-zero value
    /// pins the ceiling regardless of `memory_limit`. Unlike the other limits,
    /// `0` is a valid value (it selects the automatic ceiling), so `validate`
    /// does not reject it.
    pub memory_ceiling_bytes: usize,
}

/// §4.5 cost of one array-nesting level in the parse-memory estimate (bytes).
/// A Zend array (HashTable + initial buckets) is on this order. Provisional;
/// the Task-8 RSS calibration pins it.
pub const COST_PER_LEVEL_BYTES: u64 = 384;

/// §4.5 cost multiplier per buffered non-file byte. 2, not 1: while PHP reads a
/// field it holds the growing read buffer AND, once complete, the registered
/// copy, so the peak is roughly twice the value's size. Conservative (blocks a
/// touch earlier, nearer the real peak). Provisional; Task-8 RSS calibrated.
pub const COST_PER_NONFILE_BYTE: u64 = 2;

/// §4.5 fallback ceiling (bytes) when `memory_limit = -1` (no limit). The
/// advisory names `-1` as a partial mitigation; Howdah keeps working there with
/// a fixed, measured ceiling. Provisional; Task-8 calibrated.
pub const FALLBACK_CEILING_BYTES: u64 = 64 * 1024 * 1024;

impl Limits {
    /// Default limits, VALIDATED by the Task-12 cross-version gate (not merely
    /// starting points). Measured on a stock box (memory_limit=128M,
    /// post_max_size=8M) across PHP 5.6/7.3/8.4 against a part/field-flood SHAPE
    /// (structure only; this is NOT CVE-2026-109618's session.upload_progress
    /// header-parsing path, which was not reproduced -- see docs/coverage-data.md):
    ///
    /// * For that flood shape on stock config, PHP's OWN caps (max_file_uploads=20,
    ///   max_input_vars=1000) hold peak worker RSS flat at ~20-33 MiB and, on PHP
    ///   8.x, gate the rfc1867 callback entirely -- so this shape is already
    ///   contained and there is nothing for Howdah to add (no claim is made about
    ///   the CVE's header-parsing path on stock config).
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
            // Kept at 2000 after the Task-9 cross-version matrix + corpus: zero
            // false positives at this value on every SAPI/version run.
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
            // Double stock PHP max_input_vars (1000), so stock-config forms never
            // trip it. Confirmed by the Task-9 corpus: a legitimate 1500-field
            // form is zero-block at this value (a hash-collision / variable flood
            // is var-dropped + logged well before the symbol table is stressed).
            max_input_vars: 2000,
            // Real forms nest a handful of levels (the legit corpus peaks at 5);
            // 64 is far beyond legitimate use yet well below depths that stress
            // recursive array handling. Zero-block on the corpus.
            max_input_nesting_depth: 64,
            // Same generous bound as field names: keys are identifiers.
            max_input_key_bytes: 1024,
            // Browsers send ~10-30 headers and proxies add a few more; 200 is far
            // beyond legitimate use. Confirmed by the corpus: a 50-header request
            // is zero-block at this value.
            max_request_headers: 200,
            // 16 KiB tolerates large cookies and auth tokens in one header line
            // (servers commonly cap a header line at 8-16 KiB).
            max_request_header_bytes: 16384,
            // Summed, file-weighted nesting levels. Stock PHP caps vars at 1000
            // and files at 20; a legitimate form nests a handful of levels, so a
            // few thousand total levels is far above benign use yet well below
            // the counts a trigger-(3)/gap-C flood needs to stress array
            // building. Provisional; the Task-8 corpus + RSS calibration pins it.
            max_nesting_levels: 10000,
            // 0 = automatic: the §4.5 ceiling is memory_limit / 4 (or the
            // FALLBACK when memory_limit = -1). Operators rarely override this.
            memory_ceiling_bytes: 0,
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
            ("max_input_vars", self.max_input_vars),
            ("max_input_nesting_depth", self.max_input_nesting_depth),
            ("max_input_key_bytes", self.max_input_key_bytes),
            ("max_request_headers", self.max_request_headers),
            ("max_request_header_bytes", self.max_request_header_bytes),
            ("max_nesting_levels", self.max_nesting_levels),
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

    /// Check request input-shape high-water marks against the limits, in
    /// field order (var count, nesting depth, key bytes, header count, header
    /// bytes); first hit wins.
    pub fn check_input(&self, st: &InputState) -> Option<LimitHit> {
        let hit = |rule: RuleId, detail: String| {
            Some(LimitHit { rule, severity: rule.severity(), detail })
        };
        if st.vars() > self.max_input_vars as u64 {
            return hit(
                RuleId::MaxInputVars,
                format!("{} input variables exceeds limit {}", st.vars(), self.max_input_vars),
            );
        }
        if st.max_depth() > self.max_input_nesting_depth {
            return hit(
                RuleId::MaxInputNestingDepth,
                format!(
                    "array nesting depth {} exceeds limit {}",
                    st.max_depth(),
                    self.max_input_nesting_depth
                ),
            );
        }
        if st.max_key_bytes() > self.max_input_key_bytes {
            return hit(
                RuleId::MaxInputKeyBytes,
                format!(
                    "input key of {} bytes exceeds limit {}",
                    st.max_key_bytes(),
                    self.max_input_key_bytes
                ),
            );
        }
        if st.headers() > self.max_request_headers as u64 {
            return hit(
                RuleId::MaxRequestHeaders,
                format!("{} request headers exceeds limit {}", st.headers(), self.max_request_headers),
            );
        }
        if st.max_header_bytes() > self.max_request_header_bytes {
            return hit(
                RuleId::MaxRequestHeaderBytes,
                format!(
                    "request header of {} bytes exceeds limit {}",
                    st.max_header_bytes(),
                    self.max_request_header_bytes
                ),
            );
        }
        if st.total_levels() > self.max_nesting_levels as u64 {
            return hit(
                RuleId::NestingBudget,
                format!(
                    "summed nesting levels {} exceeds limit {}",
                    st.total_levels(),
                    self.max_nesting_levels
                ),
            );
        }
        None
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

    /// Gap B (§4.3): the bytes actually read for a multipart body exceed PHP's
    /// effective `post_max_size`. `post_max_size <= 0` means unlimited (PHP's `0`
    /// / `-1`): the check is off and §4.5 still bounds memory. Unlike
    /// `max_parse_memory_bytes` (Howdah's own fixed backstop), this limit is
    /// PHP's own INI value, read per request by the glue.
    pub fn check_post_bytes(&self, total_read: u64, post_max_size: i64) -> Option<LimitHit> {
        if post_max_size <= 0 {
            return None;
        }
        (total_read > post_max_size as u64).then(|| LimitHit {
            rule: RuleId::PostTooLarge,
            severity: Severity::Critical,
            detail: format!("{total_read} body bytes exceeds post_max_size {post_max_size}"),
        })
    }

    /// §4.5: the ceiling for the parse-memory estimate, in bytes. The
    /// `memory_ceiling_bytes` override wins; otherwise the request's live
    /// `memory_limit / 4` (leaving the rest for the application); otherwise
    /// (`memory_limit <= 0`, i.e. unlimited) [`FALLBACK_CEILING_BYTES`].
    pub fn memory_ceiling(&self, memory_limit: i64) -> u64 {
        if self.memory_ceiling_bytes > 0 {
            self.memory_ceiling_bytes as u64
        } else if memory_limit > 0 {
            (memory_limit as u64) / 4
        } else {
            FALLBACK_CEILING_BYTES
        }
    }

    /// §4.5: the estimate of parser-held memory for this request — summed
    /// nesting levels (gap C, file-weighted) times the per-level cost, plus the
    /// buffered non-file field bytes (gap B). Per-part header floods are bounded
    /// exactly by gap A, so no header term is added here (it would only add
    /// false-positive risk on benign multi-part forms).
    pub fn memory_estimate(total_levels: u64, nonfile_bytes: u64) -> u64 {
        total_levels
            .saturating_mul(COST_PER_LEVEL_BYTES)
            .saturating_add(nonfile_bytes.saturating_mul(COST_PER_NONFILE_BYTE))
    }

    /// §4.5: block (Critical) when the estimate passes the ceiling.
    pub fn check_memory_estimate(&self, total_levels: u64, nonfile_bytes: u64, memory_limit: i64) -> Option<LimitHit> {
        let estimate = Self::memory_estimate(total_levels, nonfile_bytes);
        let ceiling = self.memory_ceiling(memory_limit);
        (estimate > ceiling).then(|| LimitHit {
            rule: RuleId::ParseMemoryEstimate,
            severity: Severity::Critical,
            detail: format!("parse-memory estimate {estimate} bytes exceeds ceiling {ceiling}"),
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
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
    MaxInputVars,
    MaxInputNestingDepth,
    MaxInputKeyBytes,
    MaxRequestHeaders,
    MaxRequestHeaderBytes,
    SqlInjection,
    PathTraversal,
    CommandInjection,
    /// The query string has the shape of php-cgi command-line arguments (CVE-2012-1823,
    /// CVE-2024-4577). Standard, Layer 2; unlike the other Layer 2 classes it blocks by
    /// default (`[inspect] cgi_arg`), because an `=`-less option-shaped query is not
    /// something an application sends. See `crate::inspect::cgi_arg_injection`.
    CgiArgInjection,
    CommandExec,
    Include,
    Eval,
    Unserialize,
    Phar,
    Ssrf,
    UploadExec,
    UnexpectedBinary,
    UnexpectedEgress,
    PhpWrite,
    MailInjection,
    PregEval,
    CreateFunction,
    AssertString,
    DangerousCallback,
    Xxe,
    TlsVerify,
    /// PHP ran out of memory while the engine was parsing/handling the request
    /// (the PHP2Shell out-of-memory backstop; see `crate::oom`). Critical,
    /// Layer 1. Not produced by any limit check: the glue's `zend_error_cb`
    /// hook reports it directly.
    OutOfMemory,
    /// A fatal error struck during request startup, before the half-built
    /// request state could be used (the other backstop trigger). Critical,
    /// Layer 1. Also reported directly by the glue, never by a limit check.
    StartupFatal,
    /// The multipart body read more bytes than PHP's effective `post_max_size`
    /// (gap B, §4.3): backports upstream's `fill_buffer` check, enforced from the
    /// byte stream the read_post wrapper sees. Critical, Layer 1.
    PostTooLarge,
    /// Summed array-nesting levels across all variable/field/file names exceeded
    /// `max_nesting_levels` (gap C, §4.4): memory grows with the total number of
    /// array levels, not any one depth. Critical, Layer 1.
    NestingBudget,
    /// The per-request estimate of the memory PHP's parser will hold (summed
    /// nesting levels + buffered non-file field bytes) passed the ceiling derived
    /// from the request's live `memory_limit` (§4.5). Critical, Layer 1.
    ParseMemoryEstimate,
    /// A poisoning-class bailout fatal (an uncaught `Error`, a parse/compile
    /// error, a failed `require`, `max_execution_time`) struck during the script
    /// on an unpatched engine, and the recycle facet (§4.7) ended the worker
    /// after the request delivered its 500 — before it could serve another and
    /// hit the CVE-2026-109619 consumer window. Critical, Layer 1. Reported
    /// directly by the glue's `zend_error_cb` hook, never by a limit check.
    FatalRecycle,
}

impl RuleId {
    /// Default severity of a rule. Malformed multipart is Standard: a strict
    /// parser disagreeing with an unusual legit client must not block by default.
    pub fn severity(self) -> Severity {
        match self {
            RuleId::MalformedMultipart
            | RuleId::UploadProgressAbuse
            | RuleId::SelfTest
            | RuleId::MaxInputKeyBytes
            | RuleId::MaxRequestHeaders
            | RuleId::MaxRequestHeaderBytes
            | RuleId::SqlInjection
            | RuleId::PathTraversal
            | RuleId::CommandInjection
            | RuleId::CgiArgInjection
            | RuleId::CommandExec
            | RuleId::Include
            | RuleId::Eval
            | RuleId::Unserialize
            | RuleId::Phar
            | RuleId::Ssrf
            | RuleId::UploadExec
            | RuleId::UnexpectedBinary
            | RuleId::UnexpectedEgress
            | RuleId::PhpWrite
            | RuleId::MailInjection
            | RuleId::PregEval
            | RuleId::CreateFunction
            | RuleId::AssertString
            | RuleId::DangerousCallback
            | RuleId::Xxe
            | RuleId::TlsVerify => Severity::Standard,
            _ => Severity::Critical,
        }
    }
}

/// Every rule, in declaration order. The config editor builds its `[rules]`
/// section from this (names come from `RuleId`'s serde spelling, severities
/// from [`RuleId::severity`]), so it can never offer a rule the core rejects
/// or miss one it accepts. `rule_catalog_covers_every_variant` fails to
/// compile when a variant is added here but not to the list.
pub fn rule_catalog() -> &'static [RuleId] {
    const ALL: [RuleId; 42] = [
        RuleId::MaxParts,
        RuleId::MaxFiles,
        RuleId::MaxPartHeaders,
        RuleId::MaxPartHeaderBytes,
        RuleId::MaxFieldNameLen,
        RuleId::MaxFilenameLen,
        RuleId::ParseMemoryBudget,
        RuleId::MalformedMultipart,
        RuleId::UploadProgressAbuse,
        RuleId::SelfTest,
        RuleId::MaxInputVars,
        RuleId::MaxInputNestingDepth,
        RuleId::MaxInputKeyBytes,
        RuleId::MaxRequestHeaders,
        RuleId::MaxRequestHeaderBytes,
        RuleId::SqlInjection,
        RuleId::PathTraversal,
        RuleId::CommandInjection,
        RuleId::CgiArgInjection,
        RuleId::CommandExec,
        RuleId::Include,
        RuleId::Eval,
        RuleId::Unserialize,
        RuleId::Phar,
        RuleId::Ssrf,
        RuleId::UploadExec,
        RuleId::UnexpectedBinary,
        RuleId::UnexpectedEgress,
        RuleId::PhpWrite,
        RuleId::MailInjection,
        RuleId::PregEval,
        RuleId::CreateFunction,
        RuleId::AssertString,
        RuleId::DangerousCallback,
        RuleId::Xxe,
        RuleId::TlsVerify,
        RuleId::OutOfMemory,
        RuleId::StartupFatal,
        RuleId::PostTooLarge,
        RuleId::NestingBudget,
        RuleId::ParseMemoryEstimate,
        RuleId::FatalRecycle,
    ];
    &ALL
}

/// How severe a rule's finding is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
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
    fn memory_estimate_ceiling_scales_with_memory_limit() {
        let l = Limits::defaults(); // memory_ceiling_bytes = 0 (auto)
        let mb = 1024 * 1024;
        // 20 MiB of non-file bytes -> estimate 40 MiB (x2): over the 32 MiB
        // ceiling at memory_limit = 128M, but under the 128 MiB ceiling at 512M.
        let nonfile = 20 * mb;
        let h = l.check_memory_estimate(0, nonfile, 128 * mb as i64).unwrap();
        assert_eq!((h.rule, h.severity), (RuleId::ParseMemoryEstimate, Severity::Critical));
        assert!(l.check_memory_estimate(0, nonfile, 512 * mb as i64).is_none());
        // memory_limit = -1 (no limit) uses the fixed fallback ceiling; non-file
        // bytes count x2, so half the ceiling of bytes is the edge.
        assert!(l.check_memory_estimate(0, FALLBACK_CEILING_BYTES / 2 + 1, -1).is_some());
        assert!(l.check_memory_estimate(0, FALLBACK_CEILING_BYTES / 2, -1).is_none());
        // Nesting levels contribute COST_PER_LEVEL_BYTES each.
        let levels_over = (32 * mb / COST_PER_LEVEL_BYTES) + 1;
        assert!(l.check_memory_estimate(levels_over, 0, 128 * mb as i64).is_some());
        // An explicit override pins the ceiling regardless of memory_limit.
        let l2 = Limits { memory_ceiling_bytes: 10 * mb as usize, ..Limits::defaults() };
        assert!(l2.check_memory_estimate(0, 11 * mb, 512 * mb as i64).is_some());
    }

    #[test]
    fn nesting_budget_sums_levels_across_names() {
        use crate::input::{InputState, FILE_NAME_WEIGHT};
        let l = Limits { max_nesting_levels: 10, ..Limits::defaults() };
        let mut s = InputState::new();
        for _ in 0..10 {
            s.note_var(b"a");
        } // 10 * 1 = 10, at the limit
        assert!(l.check_input(&s).is_none());
        s.note_var(b"a"); // 11 > 10
        let h = l.check_input(&s).unwrap();
        assert_eq!((h.rule, h.severity), (RuleId::NestingBudget, Severity::Critical));
        // A single file name weighs FILE_NAME_WEIGHT.
        let l = Limits { max_nesting_levels: FILE_NAME_WEIGHT as usize, ..Limits::defaults() };
        let mut s = InputState::new();
        s.note_name(b"f", true);
        assert!(l.check_input(&s).is_none());
        s.note_name(b"g", true);
        assert_eq!(l.check_input(&s).unwrap().rule, RuleId::NestingBudget);
    }

    #[test]
    fn post_too_large_vs_effective_post_max_size() {
        let l = Limits::defaults();
        // Over PHP's post_max_size -> Critical PostTooLarge.
        let h = l.check_post_bytes(8 * 1024 * 1024 + 1, 8 * 1024 * 1024).unwrap();
        assert_eq!((h.rule, h.severity), (RuleId::PostTooLarge, Severity::Critical));
        // Exactly at the limit, or under, is fine.
        assert!(l.check_post_bytes(8 * 1024 * 1024, 8 * 1024 * 1024).is_none());
        // 0 / negative post_max_size = unlimited -> never fires (gap B off).
        assert!(l.check_post_bytes(u64::MAX, 0).is_none());
        assert!(l.check_post_bytes(u64::MAX, -1).is_none());
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
    fn phar_ssrf_rules_standard_and_serde() {
        assert_eq!(RuleId::Phar.severity(), Severity::Standard);
        assert_eq!(RuleId::Ssrf.severity(), Severity::Standard);
        assert_eq!(serde_json::from_str::<RuleId>("\"phar\"").unwrap(), RuleId::Phar);
        assert_eq!(serde_json::from_str::<RuleId>("\"ssrf\"").unwrap(), RuleId::Ssrf);
    }

    #[test]
    fn rule_catalog_covers_every_variant() {
        let all = rule_catalog();
        // Exhaustive match: adding a RuleId variant without listing it in
        // rule_catalog() fails here at compile time.
        for r in all {
            match r {
                RuleId::MaxParts
                | RuleId::MaxFiles
                | RuleId::MaxPartHeaders
                | RuleId::MaxPartHeaderBytes
                | RuleId::MaxFieldNameLen
                | RuleId::MaxFilenameLen
                | RuleId::ParseMemoryBudget
                | RuleId::MalformedMultipart
                | RuleId::UploadProgressAbuse
                | RuleId::SelfTest
                | RuleId::MaxInputVars
                | RuleId::MaxInputNestingDepth
                | RuleId::MaxInputKeyBytes
                | RuleId::MaxRequestHeaders
                | RuleId::MaxRequestHeaderBytes
                | RuleId::SqlInjection
                | RuleId::PathTraversal
                | RuleId::CommandInjection
                | RuleId::CgiArgInjection
                | RuleId::CommandExec
                | RuleId::Include
                | RuleId::Eval
                | RuleId::Unserialize
                | RuleId::Phar
                | RuleId::Ssrf
                | RuleId::UploadExec
                | RuleId::UnexpectedBinary
                | RuleId::UnexpectedEgress
                | RuleId::PhpWrite
                | RuleId::MailInjection
                | RuleId::PregEval
                | RuleId::CreateFunction
                | RuleId::AssertString
                | RuleId::DangerousCallback
                | RuleId::Xxe
                | RuleId::TlsVerify
                | RuleId::OutOfMemory
                | RuleId::StartupFatal
                | RuleId::PostTooLarge
                | RuleId::NestingBudget
                | RuleId::ParseMemoryEstimate
                | RuleId::FatalRecycle => {}
            }
        }
        assert_eq!(rule_catalog().len(), 42);
        let mut sorted = all.to_vec();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), all.len(), "duplicate in rule_catalog");
        assert_eq!(all[0], RuleId::MaxParts);
        assert_eq!(serde_json::to_string(&RuleId::MaxParts).unwrap(), "\"max_parts\"");
        assert_eq!(serde_json::to_string(&Severity::Critical).unwrap(), "\"critical\"");
    }

    #[test]
    fn rule_severities() {
        assert_eq!(RuleId::MalformedMultipart.severity(), Severity::Standard);
        assert_eq!(RuleId::SqlInjection.severity(), Severity::Standard);
        assert_eq!(RuleId::PathTraversal.severity(), Severity::Standard);
        assert_eq!(RuleId::CommandInjection.severity(), Severity::Standard);
        assert_eq!(RuleId::CgiArgInjection.severity(), Severity::Standard);
        assert_eq!(serde_json::to_string(&RuleId::CgiArgInjection).unwrap(), "\"cgi_arg_injection\"");
        assert_eq!(RuleId::CommandExec.severity(), Severity::Standard);
        assert_eq!(RuleId::Include.severity(), Severity::Standard);
        assert_eq!(RuleId::Eval.severity(), Severity::Standard);
        assert_eq!(RuleId::Unserialize.severity(), Severity::Standard);
        assert_eq!(RuleId::UploadExec.severity(), Severity::Standard);
        assert_eq!(RuleId::UnexpectedBinary.severity(), Severity::Standard);
        assert_eq!(RuleId::UnexpectedEgress.severity(), Severity::Standard);
        assert_eq!(RuleId::PhpWrite.severity(), Severity::Standard);
        for r in [
            RuleId::MailInjection,
            RuleId::PregEval,
            RuleId::CreateFunction,
            RuleId::AssertString,
            RuleId::DangerousCallback,
            RuleId::Xxe,
            RuleId::TlsVerify,
        ] {
            assert_eq!(r.severity(), Severity::Standard, "{r:?}");
        }
        assert_eq!(serde_json::to_string(&RuleId::DangerousCallback).unwrap(), "\"dangerous_callback\"");
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

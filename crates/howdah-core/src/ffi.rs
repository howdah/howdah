//! Panic-safe C ABI over the core. The PHP extension calls only this.
//!
//! Safety contract:
//! * Every `extern "C"` entry point runs its body inside `catch_unwind`; a
//!   panic never unwinds into the caller. On a caught panic `feed` and
//!   `request_end` return 0 (Allow, fail-open: Howdah must never take PHP down)
//!   and a "panic caught" log line is stashed for `howdah_take_log_line`.
//! * Ownership: `howdah_init` returns a heap `howdah_ctx*` owned by the caller;
//!   release it exactly once with `howdah_free`. `howdah_take_log_line` returns
//!   a heap C string owned by the caller; release it exactly once with
//!   `howdah_free_str` (never `free()`). All input pointers are borrowed for the
//!   duration of the call only (data is copied). NULL pointers are tolerated
//!   everywhere (NULL ctx = no-op / Allow / NULL; NULL data with len 0 = empty).
//! * BUILD REQUIREMENT: this crate and the consuming cdylib/extension MUST be
//!   built with `panic = "unwind"` (set in the workspace profiles). Under
//!   `panic = "abort"` every `catch_unwind` is a no-op and a panic aborts PHP.
//! * Every non-null pointer + `len` pair must satisfy `len <= isize::MAX` and
//!   be valid for reads of `len` bytes (`slice::from_raw_parts` contract).
//! * A ctx must not be used from two threads at once (PHP workers each own one).
#![allow(non_camel_case_types)]

use std::ffi::{c_char, CString};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::{Config, Mode};
use crate::exceptions::{EventFacts, Exceptions, Match};
use crate::input::InputState;
use crate::inspect::{class_rule, scan, InspectClass, Source};
use crate::limits::{LimitHit, RuleId, Severity};
use crate::log::{log_line, new_request_id, EventRecord};
use crate::multipart::{Event, MultipartState};
use crate::rules::{decide, Action};
use crate::sinks::ssrf::{
    classify_ip, decode_literal_ip, denied_scheme, host_allowed, parse_host, resolve_pin_entry, HostForm, IpRepr,
    SchemeCtx,
};
use crate::sinks::{command_allowed, include_allowed, legacy, phar_allowed, unserialize_classes, SinkId};

/// Action codes returned over the ABI. Pinned: Allow=0, Log=1, Block=2.
pub const HOWDAH_ALLOW: i32 = 0;
pub const HOWDAH_LOG: i32 = 1;
pub const HOWDAH_BLOCK: i32 = 2;

/// Part kinds for `howdah_part`: a plain form field, or a file upload.
pub const HOWDAH_PART_FIELD: i32 = 0;
pub const HOWDAH_PART_FILE: i32 = 1;

/// Whether the read_post scanner must STOP the body (truncate, return EOF) when
/// this rule blocks. True for the unbounded-growth guards, where letting PHP
/// keep reading would buffer an unbounded body: gap B (`post_too_large`), the
/// raw-byte budget (`parse_memory_budget`), the §4.5 estimate
/// (`parse_memory_estimate`), and the per-part header flood (`max_part_headers`/
/// `max_part_header_bytes`, gap A — the scanner is the only enforcer and the
/// headers grow per part). False for the bounded COUNT limits `max_parts` /
/// `max_files` (and name-length rules): the parsed-event counter blocks those
/// and `deliver_startup_refusal` drains the bounded body for a clean 403, so
/// truncating them only resets the FastCGI client.
fn rule_stops_the_read(rule: RuleId) -> bool {
    matches!(
        rule,
        RuleId::PostTooLarge
            | RuleId::ParseMemoryBudget
            | RuleId::ParseMemoryEstimate
            | RuleId::MaxPartHeaders
            | RuleId::MaxPartHeaderBytes
    )
}

/// Input sources for `howdah_inspect_value`.
pub const HOWDAH_SRC_GET: i32 = 0;
pub const HOWDAH_SRC_POST: i32 = 1;
pub const HOWDAH_SRC_COOKIE: i32 = 2;
pub const HOWDAH_SRC_PATH: i32 = 3;
/// The raw query string as the SAPI reports it (`request_info.query_string`),
/// for the php-cgi argument-injection rule only. Not budgeted: the scan is one
/// bounded pass and a flood of ordinary variables must not be able to exhaust a
/// budget ahead of it.
pub const HOWDAH_SRC_QUERY: i32 = 4;

// Layer-3 sink ids (howdah_sink_check).
pub const HOWDAH_SINK_COMMAND_EXEC: i32 = 0;
pub const HOWDAH_SINK_INCLUDE: i32 = 1;
pub const HOWDAH_SINK_EVAL: i32 = 2;
pub const HOWDAH_SINK_UNSERIALIZE: i32 = 3;
pub const HOWDAH_SINK_PHAR: i32 = 4;
pub const HOWDAH_SINK_SSRF: i32 = 5;
// Legacy-era sinks (1.5). Mirrored in howdah_sink.h.
pub const HOWDAH_SINK_MAIL: i32 = 6;
pub const HOWDAH_SINK_PREG_EVAL: i32 = 7;
pub const HOWDAH_SINK_CREATE_FUNCTION: i32 = 8;
pub const HOWDAH_SINK_ASSERT: i32 = 9;
pub const HOWDAH_SINK_CALLBACK: i32 = 10;
pub const HOWDAH_SINK_XML: i32 = 11;
pub const HOWDAH_SINK_TLS: i32 = 12;

// SSRF event kinds (`howdah_sink_check_ssrf_kind_at`). RANGE is the original
// check-time reserved-range verdict; REBIND judges the address a connection
// uses (resolve-at-connect); REDIRECT judges a curl 3xx hop's target.
pub const HOWDAH_SSRF_KIND_RANGE: i32 = 0;
pub const HOWDAH_SSRF_KIND_REBIND: i32 = 1;
pub const HOWDAH_SSRF_KIND_REDIRECT: i32 = 2;

// SSRF armed-mask bits (`howdah_ssrf_armed_mask`): which parts of the SSRF
// hardening the C shim must run. PIN / PROTOCOLS say the rebind / scheme knob is
// `block`, i.e. the shim may also change the curl handle's options; in `detect`
// the shim only observes.
pub const HOWDAH_SSRF_ARM_RANGE: i32 = 1;
pub const HOWDAH_SSRF_ARM_REBIND: i32 = 2;
pub const HOWDAH_SSRF_ARM_SCHEME: i32 = 4;
pub const HOWDAH_SSRF_ARM_REDIRECT: i32 = 8;
pub const HOWDAH_SSRF_ARM_PIN: i32 = 16;
pub const HOWDAH_SSRF_ARM_PROTOCOLS: i32 = 32;

// Where a URL was seen, for the egress-scheme denial (`howdah_sink_ssrf_scheme_at`).
pub const HOWDAH_SSRF_VIA_STREAM: i32 = 0;
pub const HOWDAH_SSRF_VIA_CURL: i32 = 1;

// File-op classes for `howdah_sink_check_open_at` (the T4 file-open firewall;
// the reusable foundation T5 extends with delete/rename ops). Mirrored in
// howdah_sink.h.
/// A read-open: fopen (read mode), file_get_contents, readfile.
pub const HOWDAH_FILE_OP_READ: i32 = 0;
/// A write-open: fopen (write/append/create mode).
pub const HOWDAH_FILE_OP_WRITE: i32 = 1;
/// A delete: unlink / rmdir (T5 delete guard).
pub const HOWDAH_FILE_OP_DELETE: i32 = 2;
/// The SOURCE operand of rename (T5 delete guard: moving wp-config.php away).
pub const HOWDAH_FILE_OP_MOVE_SRC: i32 = 3;

// `is_write_mode` codes for `howdah_behavior_check_php_write(_at)`.
/// A read-mode open: never a php_write finding.
pub const HOWDAH_WRITE_READ: i32 = 0;
/// file_put_contents / write-mode fopen / rename / copy target.
pub const HOWDAH_WRITE_PLAIN: i32 = 1;
/// move_uploaded_file target (the always-on upload tier).
pub const HOWDAH_WRITE_UPLOAD: i32 = 2;

/// Action code from `howdah_sink_check_xml`: the dangerous call is neutralized
/// by removing the dangerous libxml flags from its options argument (the glue
/// then runs the original call with the rewritten flags) instead of refusing
/// it. Logged as `block`. Never returned by any other entry point.
pub const HOWDAH_STRIP: i32 = 3;
/// `howdah_sink_check_xml` `caps` bit: the glue can rewrite the options
/// argument, so a block may strip the flags instead of refusing the call.
pub const HOWDAH_XML_CAN_STRIP: i32 = 1;
/// `howdah_sink_check_xml` `caps` bit: the libxml in use is older than 2.9.0,
/// which resolves external entities whatever the flags say.
pub const HOWDAH_XML_ENGINE_IGNORES_FLAGS: i32 = 2;
/// The dangerous `LIBXML_*` option bits (`NOENT|DTDLOAD|DTDATTR|DTDVALID`) the
/// glue clears on a `HOWDAH_STRIP`. Mirrored in `howdah_sink.h`.
pub const HOWDAH_XML_DANGEROUS_FLAGS: i64 = 30;

// Layer-4 behavior facets (howdah_behavior_armed).
pub const HOWDAH_BEHAVIOR_EXEC_DIR: i32 = 0;
pub const HOWDAH_BEHAVIOR_BINARY: i32 = 1;
pub const HOWDAH_BEHAVIOR_EGRESS: i32 = 2;
pub const HOWDAH_BEHAVIOR_PHP_WRITE: i32 = 3;
/// The enforced-by-default upload-write guard (`move_uploaded_file` only).
pub const HOWDAH_BEHAVIOR_UPLOAD_WRITE: i32 = 4;
/// The enforced-by-default delete guard (`unlink`/`rmdir`/`rename` source).
pub const HOWDAH_BEHAVIOR_DELETE: i32 = 5;
/// The opt-in secret-read guard (read-open sinks).
pub const HOWDAH_BEHAVIOR_SECRET_READ: i32 = 6;

fn code(a: Action) -> i32 {
    match a {
        Action::Allow | Action::Excepted => HOWDAH_ALLOW,
        Action::Log => HOWDAH_LOG,
        Action::Block => HOWDAH_BLOCK,
    }
}

fn rank(a: Action) -> u8 {
    match a {
        Action::Allow | Action::Excepted => 0,
        Action::Log => 1,
        Action::Block => 2,
    }
}

/// A 32-byte SHA-256 handed over the ABI (`sha256`/`sha256_len`): only an
/// exact 32-byte buffer is accepted; anything else means "no hash".
///
/// # Safety
/// `p` must be NULL or valid for `len` readable bytes.
unsafe fn copy_sha(p: *const u8, len: usize) -> Option<[u8; 32]> {
    if p.is_null() || len != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(std::slice::from_raw_parts(p, 32));
    Some(out)
}

/// Borrow `len` bytes at `p` as a str-ish script path (lossy), or `None` for
/// NULL / empty.
///
/// # Safety
/// `p` must be NULL or valid for `len` readable bytes.
unsafe fn copy_script(p: *const c_char, len: usize) -> Option<String> {
    if p.is_null() || len == 0 {
        None
    } else {
        Some(copy_str(p, len))
    }
}

/// Request metadata for logging. Pointers are borrowed for the call only;
/// any may be NULL (len ignored then).
#[repr(C)]
pub struct RequestMeta {
    pub client_ip: *const c_char,
    pub client_ip_len: usize,
    pub method: *const c_char,
    pub method_len: usize,
    pub uri: *const c_char,
    pub uri_len: usize,
}

#[derive(Default)]
struct Meta {
    client_ip: String,
    method: String,
    uri: String,
}

/// Opaque context: config plus per-request state.
pub struct howdah_ctx {
    config: Config,
    state: Option<MultipartState>,
    /// The §4.2 byte-stream scanner, fed the RAW body by the read_post wrapper
    /// and framed on the request's real boundary. Independent of `state` (the
    /// parsed-event counter): it only ever ADDS blocks, so a desync here can
    /// never switch the structural limits off (design §4.2, fail closed).
    /// `None` until `howdah_scan_post_begin` sees a multipart boundary.
    post_scan: Option<MultipartState>,
    /// PHP's effective `post_max_size` for this request (bytes; `<= 0` =
    /// unlimited → gap B off). Set by `howdah_scan_post_begin`.
    post_max_size: i64,
    /// PHP's effective `memory_limit` for this request (bytes; `-1` = no limit →
    /// §4.5 uses a fixed fallback ceiling). Set by `howdah_scan_post_begin`.
    memory_limit: i64,
    /// True once the read_post byte-scanner hit an UNBOUNDED-growth limit (see
    /// [`rule_stops_the_read`]) — continuing to read would buffer an unbounded
    /// body, so it must be truncated (the wrapper returns EOF). It alone drives
    /// that EOF. A BOUNDED count limit (`max_parts`/`max_files`), even one the
    /// scanner detects itself, must NOT truncate: the parsed-event counter
    /// blocks it and `deliver_startup_refusal` drains the bounded body for a
    /// clean 403; truncating there leaves the FastCGI body unread and resets the
    /// client. Reset by `scan_post_begin`.
    post_scan_blocked: bool,
    request_id: String,
    meta: Meta,
    worst: Action,
    log: Option<String>,
    /// True while the only stashed line is the self_test marker (a real hit replaces it).
    selftest_only: bool,
    /// Per-request input-shape counters (vars, headers); reset in `request_begin`.
    input: InputState,
    /// Layer-2 per-request aggregate scan budget; reset in `request_begin`.
    inspect_values: usize,
    inspect_bytes: usize,
    /// Layer-3 per-hit sink line; dedicated slot, never shares `log`/`worst`.
    sink_log: Option<String>,
    /// Compiled `[[exceptions]]` (empty when none configured).
    exceptions: Exceptions,
    /// Write matched exceptions as `excepted` events.
    exceptions_log: bool,
    /// Runtime `session.save_path` for the poisonable-local-target firewall
    /// (empty when the glue has not set it). Scanned, never logged.
    session_save_path: String,
    /// Runtime `error_log` for the poisonable-local-target firewall (empty when
    /// unset / logging to SAPI). Scanned, never logged.
    error_log: String,
}

fn describe(r: RuleId) -> &'static str {
    match r {
        RuleId::MaxParts => "multipart part count exceeds limit",
        RuleId::MaxFiles => "multipart file count exceeds limit",
        RuleId::MaxPartHeaders => "too many headers in one part",
        RuleId::MaxPartHeaderBytes => "part header too large",
        RuleId::MaxFieldNameLen => "field name too long",
        RuleId::MaxFilenameLen => "filename too long",
        RuleId::ParseMemoryBudget => "body exceeds parse memory budget",
        RuleId::MalformedMultipart => "malformed or truncated multipart body",
        RuleId::UploadProgressAbuse => "upload progress abuse",
        RuleId::SelfTest => "self test",
        RuleId::MaxInputVars => "too many input variables",
        RuleId::MaxInputNestingDepth => "input array nesting too deep",
        RuleId::MaxInputKeyBytes => "input variable key too long",
        RuleId::MaxRequestHeaders => "too many request headers",
        RuleId::MaxRequestHeaderBytes => "request header too large",
        RuleId::SqlInjection => "possible SQL injection in request input",
        RuleId::PathTraversal => "possible path traversal in request input",
        RuleId::CommandInjection => "possible command injection in request input",
        RuleId::CgiArgInjection => "query string shaped like php-cgi command-line arguments",
        RuleId::CommandExec => "command execution sink called with a disallowed command",
        RuleId::Include => "file include sink called with a disallowed path",
        RuleId::Eval => "eval sink invoked",
        RuleId::Unserialize => "unserialize sink invoked on untrusted data",
        RuleId::Phar => "phar:// stream wrapper access outside the allowlist",
        RuleId::Ssrf => "outbound request to a disallowed destination",
        RuleId::IncludeWrapper => "include/require of a non-file wrapper or a poisonable local target",
        RuleId::FileOpen => "file-open sink called with a dangerous wrapper or a poisonable local target",
        RuleId::UploadExec => "possible executable or server-side code in an uploaded file",
        RuleId::UnexpectedBinary => "unexpected binary executed following an upload",
        RuleId::UnexpectedEgress => "possible unexpected outbound connection",
        RuleId::PhpWrite => "executable or handler-config file written to disk",
        RuleId::FileDelete => "sensitive file deleted or moved away",
        RuleId::SecretRead => "secret file read",
        RuleId::MailInjection => "mail() called with an unsafe sendmail option or header injection",
        RuleId::PregEval => "preg pattern with the /e modifier",
        RuleId::CreateFunction => "create_function invoked",
        RuleId::AssertString => "assert() evaluating a string as code",
        RuleId::DangerousCallback => "string callback naming a command or code execution function",
        RuleId::Xxe => "XML external entity or entity bomb parsed with a dangerous libxml flag",
        RuleId::TlsVerify => "curl TLS certificate verification disabled",
        RuleId::OutOfMemory => "worker ended on out-of-memory",
        RuleId::StartupFatal => "fatal error during request startup",
        RuleId::FatalRecycle => "worker recycled after a poisoning-class fatal",
        RuleId::PostTooLarge => "request body exceeds post_max_size",
        RuleId::NestingBudget => "too many array-nesting levels across request inputs",
        RuleId::ParseMemoryEstimate => "estimated parse memory exceeds the memory_limit-based ceiling",
    }
}

/// Current UTC time as Unix epoch milliseconds, decimal string. The core has no
/// clock of its own; this stamps every stashed log record so emitted JSON lines
/// always carry a real timestamp.
fn now() -> String {
    // wasm32-unknown-unknown has no wall clock (SystemTime::now panics); the
    // browser demo does not need a real timestamp.
    #[cfg(target_arch = "wasm32")]
    {
        return "0".to_string();
    }
    #[allow(unreachable_code)]
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
        .to_string()
}

/// Copy `len` bytes at `p` (lossy UTF-8). NULL or zero len gives "".
///
/// # Safety
/// `p` must be NULL or valid for `len` readable bytes.
unsafe fn copy_str(p: *const c_char, len: usize) -> String {
    if p.is_null() || len == 0 {
        return String::new();
    }
    String::from_utf8_lossy(std::slice::from_raw_parts(p as *const u8, len)).into_owned()
}

impl howdah_ctx {
    fn new(config: Config) -> Self {
        // The config was validated by `from_toml`, so this cannot fail; a
        // hand-built config with bad entries simply gets no exceptions.
        let exceptions = Exceptions::compile(&config.exceptions).unwrap_or_default();
        let exceptions_log = config.exceptions_log;
        howdah_ctx {
            config,
            state: None,
            post_scan: None,
            post_max_size: 0,
            memory_limit: -1,
            post_scan_blocked: false,
            request_id: new_request_id(),
            meta: Meta::default(),
            worst: Action::Allow,
            log: None,
            selftest_only: false,
            input: InputState::new(),
            inspect_values: 0,
            inspect_bytes: 0,
            sink_log: None,
            exceptions,
            exceptions_log,
            session_save_path: String::new(),
            error_log: String::new(),
        }
    }

    /// Build a log record for `rule`/`action` with this request's metadata.
    fn record(&self, rule: RuleId, action: Action, reason: String) -> String {
        log_line(&EventRecord {
            ts: now(),
            request_id: self.request_id.clone(),
            rule,
            action,
            client_ip: self.meta.client_ip.clone(),
            method: self.meta.method.clone(),
            uri: self.meta.uri.clone(),
            reason,
        })
    }

    /// Does an exception turn `rule` off for this event? `script`, `sha` and
    /// `param` are whatever the calling layer knows (see the design, §3).
    fn excepted(
        &self,
        rule: RuleId,
        script: Option<&str>,
        sha: Option<&[u8; 32]>,
        param: Option<&[u8]>,
    ) -> Option<Match> {
        if self.exceptions.is_empty() {
            return None;
        }
        self.exceptions.matches(&EventFacts {
            rule,
            script,
            script_sha256: sha,
            param,
            uri: &self.meta.uri,
            client_ip: &self.meta.client_ip,
        })
    }

    /// An excepted Layer 1/2 finding: with `exceptions_log`, use the
    /// per-request slot like the self-test marker does (only when nothing
    /// else is pending; a later real hit replaces it). `worst` is untouched.
    fn note_excepted_request(&mut self, rule: RuleId, m: &Match) {
        if self.exceptions_log && self.log.is_none() && self.worst == Action::Allow {
            self.selftest_only = true;
            self.log = Some(self.record(rule, Action::Excepted, m.log_reason()));
        }
    }

    /// An excepted Layer 3/4 call: with `exceptions_log`, one line in the
    /// per-call sink slot.
    fn note_excepted_sink(&mut self, rule: RuleId, m: &Match) {
        if self.exceptions_log {
            self.sink_log = Some(self.record(rule, Action::Excepted, m.log_reason()));
        }
    }

    fn stash(&mut self, rule: RuleId, action: Action, reason: &str) {
        let rec = EventRecord {
            ts: now(),
            request_id: self.request_id.clone(),
            rule,
            action,
            client_ip: self.meta.client_ip.clone(),
            method: self.meta.method.clone(),
            uri: self.meta.uri.clone(),
            reason: reason.to_string(),
        };
        self.log = Some(log_line(&rec));
    }

    /// Fold a hit into the sticky worst action; log only on escalation. A
    /// Standard hit that an exception covers (URI / client facets; Layer 1
    /// knows no script or parameter) is dropped here, before the mode is
    /// applied. Critical hits never consult the exceptions.
    fn apply(&mut self, hit: Option<&LimitHit>) -> Action {
        if let Some(h) = hit {
            if h.severity == Severity::Standard {
                if let Some(m) = self.excepted(h.rule, None, None, None) {
                    self.note_excepted_request(h.rule, &m);
                    return Action::Allow;
                }
            }
        }
        let a = decide(hit, self.config.mode, &self.config.rule_modes);
        self.fold(hit, a, None);
        a
    }

    /// Fold an already-resolved action into the sticky worst action; log only
    /// on escalation. `reason` overrides the rule's generic description.
    fn fold(&mut self, hit: Option<&LimitHit>, a: Action, reason: Option<&str>) {
        // A real hit always replaces a pending self_test-only line.
        if rank(a) > rank(self.worst) || (self.selftest_only && a != Action::Allow && hit.is_some()) {
            self.selftest_only = false;
            self.worst = a;
            if let Some(h) = hit {
                self.stash(h.rule, a, reason.unwrap_or_else(|| describe(h.rule)));
            }
        }
    }

    /// Like `apply`, but resolved against an explicit mode and override map
    /// (Layer 2 uses its own independent mode, not the global one).
    fn apply_with_mode(
        &mut self,
        hit: &LimitHit,
        mode: crate::config::Mode,
        overrides: &std::collections::BTreeMap<RuleId, crate::config::Mode>,
        reason: &str,
    ) -> Action {
        let a = decide(Some(hit), mode, overrides);
        self.fold(Some(hit), a, Some(reason));
        a
    }

    /// Scan one request value (Layer 2). The value is inspected, never logged;
    /// only the (truncated) variable name appears in the reason. Returns the
    /// action for THIS value (the caller decides what to do with it).
    fn inspect_value(&mut self, source: Source, name: &[u8], val: &[u8]) -> Action {
        #[cfg(test)]
        if tests::FORCE_PANIC.with(|f| f.get()) {
            panic!("injected test panic");
        }
        let ins = &self.config.inspect;
        if !ins.enabled {
            return Action::Allow;
        }
        let limits = ins.limits;
        if self.inspect_values >= limits.max_values || self.inspect_bytes >= limits.max_total_bytes {
            return Action::Allow;
        }
        self.inspect_values += 1;
        self.inspect_bytes = self.inspect_bytes.saturating_add(val.len().min(limits.max_value_bytes));

        let Some(class) = scan(val, source, &limits) else {
            return Action::Allow;
        };
        if !self.config.inspect.class_enabled(class) {
            return Action::Allow;
        }
        let mode = self.config.inspect.effective_mode(self.config.mode);
        // Off is absolute: no rule_modes override may re-arm the layer.
        if mode == crate::config::Mode::Off {
            return Action::Allow;
        }
        let overrides = self.config.inspect.rule_modes.clone();
        let rule = class_rule(class);
        // Scoped exception: by parameter name, URI or client (never script:
        // Layer 2 runs before any script is known).
        if let Some(m) = self.excepted(rule, None, None, Some(name)) {
            self.note_excepted_request(rule, &m);
            return Action::Allow;
        }
        let class_name = match class {
            InspectClass::SqlInjection => "sql_injection",
            InspectClass::PathTraversal => "path_traversal",
            InspectClass::CommandInjection => "command_injection",
        };
        let src_name = match source {
            Source::Get => "get",
            Source::Post => "post",
            Source::Cookie => "cookie",
            Source::Path => "path",
        };
        let n = &name[..name.len().min(64)];
        let reason = format!("{class_name} pattern in {src_name} variable '{}'", String::from_utf8_lossy(n));
        let hit = LimitHit { rule, severity: Severity::Standard, detail: reason.clone() };
        self.apply_with_mode(&hit, mode, &overrides, &reason)
    }

    /// Layer-2 php-cgi argument-injection check on the raw query string
    /// (CVE-2012-1823, CVE-2024-4577). The query is scanned, never logged: the
    /// reason is a fixed string. Not subject to the per-request value/byte
    /// budgets of `inspect_value`, so a flood of ordinary variables cannot
    /// exhaust a budget before it runs. Its mode is `[inspect] cgi_arg` (default
    /// `block`, whatever the global `detect`/`block`), see
    /// `InspectConfig::cgi_arg_mode`.
    fn inspect_query(&mut self, query: &[u8]) -> Action {
        #[cfg(test)]
        if tests::FORCE_PANIC.with(|f| f.get()) {
            panic!("injected test panic");
        }
        let ins = &self.config.inspect;
        let mode = ins.cgi_arg_mode(self.config.mode);
        if mode == crate::config::Mode::Off {
            return Action::Allow;
        }
        if !crate::inspect::cgi_arg_injection(query, ins.limits.max_total_bytes) {
            return Action::Allow;
        }
        let rule = RuleId::CgiArgInjection;
        // Scoped exception: URI or client facets (the "parameter" is the query
        // string itself; a `param` facet is matched against that pseudo-name).
        if let Some(m) = self.excepted(rule, None, None, Some(&b"QUERY_STRING"[..])) {
            self.note_excepted_request(rule, &m);
            return Action::Allow;
        }
        let reason = "php-cgi argument-injection pattern in query string".to_string();
        let hit = LimitHit { rule, severity: Severity::Standard, detail: reason.clone() };
        self.apply_with_mode(&hit, mode, &std::collections::BTreeMap::new(), &reason)
    }

    /// Stash a firewall hit (shared by the include and open paths): honor a
    /// scoped exception, resolve the action from the rule's own mode (block →
    /// Block, else Log), and record the line. `reason` carries only a
    /// scheme/category label and the construct name — never the target content.
    fn emit_firewall(
        &mut self,
        rule: RuleId,
        mode: Mode,
        reason: String,
        script: Option<&str>,
        sha: Option<&[u8; 32]>,
    ) -> Action {
        if let Some(m) = self.excepted(rule, script, sha, None) {
            self.note_excepted_sink(rule, &m);
            return Action::Allow;
        }
        let action = if mode == Mode::Block { Action::Block } else { Action::Log };
        self.sink_log = Some(self.record(rule, action, reason));
        action
    }

    /// Layer-3 include/require firewall (T4): classify the resolved target's
    /// stream-wrapper scheme (`wrapper`, default block), then flag a poisonable
    /// local target (`poison`, default block), then the legacy `allow_paths`
    /// check (inherits `sinks.mode`). First hit wins. The target is scanned,
    /// never logged. `arg` is the fully resolved include target the hook saw.
    fn include_firewall_check(
        &mut self,
        name: &[u8],
        arg: &[u8],
        script: Option<&str>,
        sha: Option<&[u8; 32]>,
    ) -> Action {
        use crate::sinks::wrapper::{classify_poison, classify_scheme};
        let global = self.config.mode;
        let n = String::from_utf8_lossy(&name[..name.len().min(64)]).into_owned();
        let decision: Option<(RuleId, Mode, String)> = (|| {
            let sinks = &self.config.sinks;
            let wmode = sinks.include_wrapper_mode(global);
            let pmode = sinks.include_poison_mode(global);
            let imode = sinks.effective_mode(SinkId::Include, global);
            let cls = classify_scheme(arg);
            if wmode != Mode::Off && cls.blocks_include() {
                return Some((RuleId::IncludeWrapper, wmode, format!("include of {} wrapper refused via {n}", cls.as_label())));
            }
            if pmode != Mode::Off {
                if let Some(kind) =
                    classify_poison(arg, self.session_save_path.as_bytes(), self.error_log.as_bytes())
                {
                    return Some((RuleId::IncludeWrapper, pmode, format!("include of poisonable local target ({}) via {n}", kind.as_label())));
                }
            }
            if imode != Mode::Off
                && !sinks.include.allow_paths.is_empty()
                && !include_allowed(arg, &sinks.include.allow_paths)
            {
                return Some((RuleId::Include, imode, format!("include path outside allowlist via {n}")));
            }
            None
        })();
        match decision {
            Some((rule, mode, reason)) => self.emit_firewall(rule, mode, reason, script, sha),
            None => Action::Allow,
        }
    }

    /// The file-op hub (T4 firewall + T5 guards). `op` is a `HOWDAH_FILE_OP_*`
    /// class:
    ///
    /// * `DELETE` (unlink/rmdir) and `MOVE_SRC` (rename's source): the Layer-4
    ///   delete guard only (`file_delete`).
    /// * `READ`/`WRITE` opens (fopen/file_get_contents/readfile/file): the T3/T4
    ///   Layer-3 firewall (dangerous wrapper, poisonable local target; remote is
    ///   the SSRF sink's job), then for `READ` the Layer-4 secret-read guard.
    ///
    /// `script_raw`/`line` are the calling PHP script and line (origin; empty/0
    /// when unknown); they are only turned into text on a hit. The target is
    /// scanned, never logged; a Layer-4 line names a path CATEGORY and the origin.
    fn open_check(
        &mut self,
        name: &[u8],
        target: &[u8],
        op: i32,
        script_raw: &[u8],
        line: u32,
        sha: Option<&[u8; 32]>,
    ) -> Action {
        let script_str = std::str::from_utf8(script_raw).unwrap_or("");
        let script = (!script_str.is_empty()).then_some(script_str);
        if op == HOWDAH_FILE_OP_DELETE || op == HOWDAH_FILE_OP_MOVE_SRC {
            return self.file_guard(name, target, op, script_str, line, script, sha);
        }
        let act = self.open_firewall(name, target, script, sha);
        if act != Action::Allow || op != HOWDAH_FILE_OP_READ {
            return act;
        }
        self.file_guard(name, target, op, script_str, line, script, sha)
    }

    /// The Layer-4 file guards that classify a path argument: the delete guard
    /// (`DELETE`/`MOVE_SRC`) and the secret-read guard (`READ`). Cheap early-out
    /// when the guard's own mode is off.
    #[allow(clippy::too_many_arguments)]
    fn file_guard(
        &mut self,
        name: &[u8],
        target: &[u8],
        op: i32,
        file: &str,
        line: u32,
        script: Option<&str>,
        sha: Option<&[u8; 32]>,
    ) -> Action {
        let b = &self.config.behavior;
        let armed = if op == HOWDAH_FILE_OP_READ {
            b.secret_read != Mode::Off
        } else {
            b.delete_guard != Mode::Off
        };
        if !armed {
            return Action::Allow;
        }
        let Ok(t) = std::str::from_utf8(target) else {
            return Action::Allow; // a non-UTF-8 path is never one of the named secrets
        };
        // The guarded function's name (a short ASCII constant); no allocation.
        let n = std::str::from_utf8(&name[..name.len().min(32)]).unwrap_or("?");
        let origin = crate::behavior::Origin { file, line };
        if op == HOWDAH_FILE_OP_READ {
            self.behavior_check(|cfg| crate::behavior::secret_read_hit(origin, n, t, cfg), script, sha)
        } else {
            let is_move = op == HOWDAH_FILE_OP_MOVE_SRC;
            self.behavior_check(|cfg| crate::behavior::delete_hit(origin, n, t, is_move, cfg), script, sha)
        }
    }

    /// Layer-3 file-open firewall (T4): a file-open sink (fopen/
    /// file_get_contents/readfile) called with a dangerous wrapper
    /// (`php://filter`/`data:`/`expect://`; remote is the SSRF sink's job) or a
    /// poisonable local target. The verdict does not depend on the read/write
    /// class. Target scanned, never logged.
    fn open_firewall(
        &mut self,
        name: &[u8],
        target: &[u8],
        script: Option<&str>,
        sha: Option<&[u8; 32]>,
    ) -> Action {
        use crate::sinks::wrapper::{classify_poison, classify_scheme};
        let global = self.config.mode;
        let n = String::from_utf8_lossy(&name[..name.len().min(64)]).into_owned();
        let decision: Option<(RuleId, Mode, String)> = (|| {
            let sinks = &self.config.sinks;
            let wmode = sinks.include_wrapper_mode(global);
            let pmode = sinks.include_poison_mode(global);
            let cls = classify_scheme(target);
            if wmode != Mode::Off && cls.blocks_open() {
                return Some((RuleId::FileOpen, wmode, format!("open of {} wrapper refused via {n}", cls.as_label())));
            }
            if pmode != Mode::Off {
                if let Some(kind) =
                    classify_poison(target, self.session_save_path.as_bytes(), self.error_log.as_bytes())
                {
                    return Some((RuleId::FileOpen, pmode, format!("open of poisonable local target ({}) via {n}", kind.as_label())));
                }
            }
            None
        })();
        match decision {
            Some((rule, mode, reason)) => self.emit_firewall(rule, mode, reason, script, sha),
            None => Action::Allow,
        }
    }

    /// Layer-3 sink check. `arg` is scanned, never logged. Independent of
    /// `worst`/`log`: a hit goes only to `sink_log`. All sinks honor block;
    /// include/eval block is enforced by the C opcode handler (PHP 7.0+); PHP
    /// 5.x has no such handler and uses a compile-time swap instead.
    fn sink_check(
        &mut self,
        sink: SinkId,
        name: &[u8],
        arg: &[u8],
        script: Option<&str>,
        sha: Option<&[u8; 32]>,
    ) -> Action {
        #[cfg(test)]
        if tests::FORCE_PANIC.with(|f| f.get()) {
            panic!("injected test panic");
        }
        // Include/require goes through the T4 firewall (wrapper scheme + poison
        // local target, each with its own default-block mode), which also runs
        // the legacy allow_paths check. Its modes are independent of the
        // include sink's `effective_mode`, so it must not pass through the gate
        // below.
        if sink == SinkId::Include {
            return self.include_firewall_check(name, arg, script, sha);
        }
        let mode = self.config.sinks.effective_mode(sink, self.config.mode);
        if mode == Mode::Off {
            return Action::Allow;
        }
        let sinks = &self.config.sinks;
        let n = String::from_utf8_lossy(&name[..name.len().min(64)]).into_owned();
        let (rule, matched): (RuleId, Option<String>) = match sink {
            SinkId::CommandExec => (
                RuleId::CommandExec,
                (!command_allowed(arg, &sinks.command_exec.allow))
                    .then(|| format!("non-allowlisted command via {n}")),
            ),
            SinkId::Include => (
                RuleId::Include,
                (!sinks.include.allow_paths.is_empty() && !include_allowed(arg, &sinks.include.allow_paths))
                    .then(|| format!("include path outside allowlist via {n}")),
            ),
            SinkId::Eval => (RuleId::Eval, Some(format!("dynamic code evaluation via {n}"))),
            // Never log the path: only the guarded function name.
            SinkId::Phar => (
                RuleId::Phar,
                (!phar_allowed(arg, &sinks.phar.allow_paths))
                    .then(|| format!("phar stream access outside allowlist via {n}")),
            ),
            // SSRF has its own entry point (howdah_sink_check_ssrf).
            SinkId::Ssrf => (RuleId::Ssrf, None),
            // mail has its own entry point (howdah_sink_check_mail).
            SinkId::Mail => (RuleId::MailInjection, None),
            SinkId::PregEval => (
                RuleId::PregEval,
                legacy::preg_pattern_has_e(arg).then(|| format!("{} via {n}", legacy::REASON_PREG_EVAL)),
            ),
            SinkId::CreateFunction => {
                (RuleId::CreateFunction, Some(format!("dynamic code evaluation via {n}")))
            }
            SinkId::Assert => {
                (RuleId::AssertString, Some(format!("string assertion evaluated as code via {n}")))
            }
            // The callback NAME is a function identifier from a fixed list,
            // never the data the callback would receive.
            SinkId::Callback => (
                RuleId::DangerousCallback,
                legacy::dangerous_callback(arg).map(|cb| format!("dangerous callback '{cb}' via {n}")),
            ),
            // xml has its own entry point (howdah_sink_check_xml): the verdict
            // needs the call's libxml flags, which this one-argument path lacks.
            SinkId::Xml => (RuleId::Xxe, None),
            // `arg` is the option token the shim passes ("verifypeer" /
            // "verifyhost"), not user data.
            SinkId::Tls => (RuleId::TlsVerify, legacy::tls_reason(arg).map(|r| format!("{r} via {n}"))),
            SinkId::Unserialize => {
                let scan = unserialize_classes(arg);
                let allow = &sinks.unserialize.allow_classes;
                let bad = scan.classes.iter().find(|c| !allow.contains(c));
                let m = if scan.capped {
                    Some(format!("unserialize via {n}: too many classes to enumerate (fail closed)"))
                } else {
                    bad.map(|c| format!("unserialize via {n}: class '{c}' not allowlisted"))
                };
                (RuleId::Unserialize, m)
            }
        };
        let Some(reason) = matched else {
            return Action::Allow;
        };
        // Scoped exception (script / hash / URI / client): the sink is not
        // checked for this script. Decided after the finding, before the mode.
        if let Some(m) = self.excepted(rule, script, sha, None) {
            self.note_excepted_sink(rule, &m);
            return Action::Allow;
        }
        // tls is detect-only in this release: a block mode is logged as log.
        let action = match mode {
            Mode::Block if sink != SinkId::Tls => Action::Block,
            _ => Action::Log,
        };
        self.sink_log = Some(self.record(rule, action, reason));
        action
    }

    /// Layer-3 `xxe` check for an XML string about to be parsed with libxml
    /// option mask `flags`. Flag-aware: nothing happens unless a dangerous
    /// flag (`LIBXML_NOENT`/`DTDLOAD`/`DTDATTR`/`DTDVALID`) coincides with
    /// an external entity or an entity bomb in `doc`; a bare DOCTYPE or a bare
    /// external DTD (SAML, SVG, XHTML, Office XML) is never an attack. `caps`
    /// is `HOWDAH_XML_CAN_STRIP` | `HOWDAH_XML_ENGINE_IGNORES_FLAGS` bits from
    /// the glue. In block mode an attack is neutralized by removing the
    /// dangerous flags when the glue can rewrite them (and the engine honours
    /// them), else by refusing the call. A bare external DTD, fetched because
    /// of `DTDLOAD`/`DTDATTR`, only ever logs. The document is scanned, never
    /// logged. Returns the action and whether the caller should strip.
    fn sink_check_xml(
        &mut self,
        name: &[u8],
        doc: &[u8],
        flags: i64,
        caps: i32,
        script: Option<&str>,
        sha: Option<&[u8; 32]>,
    ) -> (Action, bool) {
        #[cfg(test)]
        if tests::FORCE_PANIC.with(|f| f.get()) {
            panic!("injected test panic");
        }
        let mode = self.config.sinks.effective_mode(SinkId::Xml, self.config.mode);
        if mode == Mode::Off {
            return (Action::Allow, false);
        }
        let legacy_engine = caps & HOWDAH_XML_ENGINE_IGNORES_FLAGS != 0;
        let Some(hit) = legacy::xml_flag_aware_hit(doc, flags, legacy_engine) else {
            return (Action::Allow, false);
        };
        let rule = RuleId::Xxe;
        if let Some(m) = self.excepted(rule, script, sha, None) {
            self.note_excepted_sink(rule, &m);
            return (Action::Allow, false);
        }
        let n = String::from_utf8_lossy(&name[..name.len().min(64)]).into_owned();
        let what = format!("{} ({}) via {n}", hit.reason, legacy::xml_flag_names(flags, legacy_engine));
        let (action, strip, reason) = match mode {
            Mode::Block if hit.is_attack() => {
                let strip = caps & HOWDAH_XML_CAN_STRIP != 0
                    && !legacy_engine
                    && flags & legacy::XML_DANGEROUS_FLAGS != 0;
                let how = if strip { "dangerous flags removed, parse continued" } else { "call refused" };
                (Action::Block, strip, format!("{what}; {how}"))
            }
            _ => (Action::Log, false, what),
        };
        self.sink_log = Some(self.record(rule, action, reason));
        (action, strip)
    }

    /// `mail()` check: the 4th (headers) and 5th (additional_parameters)
    /// arguments, each possibly absent. Scanned, never logged.
    fn sink_check_mail(&mut self, headers: &[u8], params: &[u8]) -> Action {
        #[cfg(test)]
        if tests::FORCE_PANIC.with(|f| f.get()) {
            panic!("injected test panic");
        }
        let mode = self.config.sinks.effective_mode(SinkId::Mail, self.config.mode);
        if mode == Mode::Off {
            return Action::Allow;
        }
        let reason = match (legacy::mail_params_hit(params), legacy::mail_headers_hit(headers)) {
            (Some(r), _) | (None, Some(r)) => r,
            (None, None) => return Action::Allow,
        };
        let action = match mode {
            Mode::Block => Action::Block,
            _ => Action::Log,
        };
        let rec = EventRecord {
            ts: now(),
            request_id: self.request_id.clone(),
            rule: RuleId::MailInjection,
            action,
            client_ip: self.meta.client_ip.clone(),
            method: self.meta.method.clone(),
            uri: self.meta.uri.clone(),
            reason: reason.to_string(),
        };
        self.sink_log = Some(log_line(&rec));
        action
    }

    /// Layer-4 behavior check. Reuses `sink_log`. `hit` runs the classifier
    /// against the config; the target is never logged (the classifier's
    /// detail is a dir/host/basename only). `script` is the executing file
    /// (the caller for binary/egress/php-write, the file itself for exec-dir).
    fn behavior_check(
        &mut self,
        hit: impl FnOnce(&crate::config::BehaviorConfig) -> Option<crate::behavior::BehaviorHit>,
        script: Option<&str>,
        sha: Option<&[u8; 32]>,
    ) -> Action {
        #[cfg(test)]
        if tests::FORCE_PANIC.with(|f| f.get()) {
            panic!("injected test panic");
        }
        let mode = self.config.behavior.effective_mode(self.config.mode);
        if mode == Mode::Off {
            return Action::Allow;
        }
        let Some(crate::behavior::BehaviorHit { rule, detail, mode: own }) = hit(&self.config.behavior) else {
            return Action::Allow;
        };
        // The file guards carry their own mode (enforced by default); the other
        // facets follow the section mode. The section mode already gated Off above.
        let mode = own.unwrap_or(mode);
        if let Some(m) = self.excepted(rule, script, sha, None) {
            self.note_excepted_sink(rule, &m);
            return Action::Allow;
        }
        // Observe is propose-only: never block, and mark the line as a proposal.
        let observe = self.config.behavior.observe;
        let action = match mode {
            Mode::Block if !observe => Action::Block,
            _ => Action::Log,
        };
        let rec = EventRecord {
            ts: now(),
            request_id: self.request_id.clone(),
            rule,
            action,
            client_ip: self.meta.client_ip.clone(),
            method: self.meta.method.clone(),
            uri: self.meta.uri.clone(),
            reason: if observe { format!("proposed: {detail}") } else { detail },
        };
        self.sink_log = Some(log_line(&rec));
        action
    }

    /// Original check-time SSRF verdict (kind RANGE).
    fn sink_check_ssrf(
        &mut self,
        scheme: &[u8],
        host: &[u8],
        port: u16,
        recs: &[u8],
        script: Option<&str>,
        sha: Option<&[u8; 32]>,
    ) -> Action {
        self.sink_check_ssrf_kind(HOWDAH_SSRF_KIND_RANGE, scheme, host, port, recs, script, sha)
    }

    /// SSRF check; `recs` is a multiple of 17 bytes (see `howdah_sink_check_ssrf`).
    /// `kind` picks the mode that governs the verdict and the wording of the
    /// reason: RANGE the original `[sinks.ssrf] mode`, REBIND the connect-time
    /// `rebind` knob (the addresses are those the connection resolved to or used),
    /// REDIRECT the `redirect` knob (the addresses are a 3xx hop's target).
    #[allow(clippy::too_many_arguments)]
    fn sink_check_ssrf_kind(
        &mut self,
        kind: i32,
        scheme: &[u8],
        host: &[u8],
        port: u16,
        recs: &[u8],
        script: Option<&str>,
        sha: Option<&[u8; 32]>,
    ) -> Action {
        #[cfg(test)]
        if tests::FORCE_PANIC.with(|f| f.get()) {
            panic!("injected test panic");
        }
        let mode = match kind {
            HOWDAH_SSRF_KIND_REBIND => self.config.sinks.ssrf_rebind_mode(self.config.mode),
            HOWDAH_SSRF_KIND_REDIRECT => self.config.sinks.ssrf_redirect_mode(self.config.mode),
            _ => self.config.sinks.effective_mode(SinkId::Ssrf, self.config.mode),
        };
        if mode == Mode::Off {
            return Action::Allow;
        }
        let literal = decode_literal_ip(host);
        let mut resolved: Vec<IpRepr> = Vec::new();
        #[allow(unknown_lints, clippy::chunks_exact_to_as_chunks)] // as_chunks needs Rust 1.88+
        for r in recs.chunks_exact(17) {
            let Ok(r): Result<&[u8; 17], _> = r.try_into() else { continue };
            match r[0] {
                4 => resolved.push(IpRepr::V4([r[1], r[2], r[3], r[4]])),
                6 => {
                    let mut a = [0u8; 16];
                    a.copy_from_slice(&r[1..17]);
                    resolved.push(IpRepr::V6(a));
                }
                _ => {}
            }
        }
        if host_allowed(host, &resolved, literal, &self.config.sinks.ssrf.allow_hosts) {
            return Action::Allow;
        }
        let hit = literal
            .into_iter()
            .chain(resolved.iter().copied())
            .find_map(|ip| classify_ip(ip).map(|c| (ip, c)));
        let Some((ip, class)) = hit else {
            return Action::Allow;
        };
        let ip_s = match ip {
            IpRepr::V4(a) => std::net::Ipv4Addr::from(a).to_string(),
            IpRepr::V6(a) => std::net::Ipv6Addr::from(a).to_string(),
        };
        let clip = |b: &[u8]| -> String {
            String::from_utf8_lossy(&b[..b.len().min(255)])
                .chars()
                .filter(|c| !c.is_control())
                .collect()
        };
        // Defense in depth: log only the bare host. Cut at the first
        // /, ? or #, then drop userinfo.
        let bare_host = {
            let h = clip(host);
            // Cut first (an '@' in path/query is not userinfo), then take the
            // text after the LAST '@' of the authority (userinfo may hold '@').
            let end = h.find(['/', '?', '#']).unwrap_or(h.len());
            let auth = &h[..end];
            auth.rsplit_once('@').map_or(auth, |(_, host)| host).to_string()
        };
        let lead = match kind {
            HOWDAH_SSRF_KIND_REBIND => "ssrf rebind via",
            HOWDAH_SSRF_KIND_REDIRECT => "ssrf redirect via",
            _ => "ssrf via",
        };
        let reason = format!(
            "{lead} {}: host={} port={} ip={} class={}",
            clip(scheme),
            bare_host,
            port,
            ip_s,
            class.as_str()
        );
        if let Some(m) = self.excepted(RuleId::Ssrf, script, sha, None) {
            self.note_excepted_sink(RuleId::Ssrf, &m);
            return Action::Allow;
        }
        let action = if mode == Mode::Block { Action::Block } else { Action::Log };
        self.sink_log = Some(self.record(RuleId::Ssrf, action, reason));
        action
    }

    /// A host too long to resolve (>256 bytes; DNS max is 253) is never
    /// legitimate and can hide a zero-padded numeric IP, so it is treated as
    /// suspicious per the effective mode. The host bytes are never logged.
    fn sink_ssrf_oversize(&mut self, script: Option<&str>, sha: Option<&[u8; 32]>) -> Action {
        self.sink_ssrf_oversize_kind(HOWDAH_SSRF_KIND_RANGE, script, sha)
    }

    /// [`Ctx::sink_ssrf_oversize`] for an SSRF event `kind`: the same verdict,
    /// governed by the kind's own mode (a redirect hop with an oversize host is
    /// judged by `redirect`, not by the range `mode`).
    fn sink_ssrf_oversize_kind(&mut self, kind: i32, script: Option<&str>, sha: Option<&[u8; 32]>) -> Action {
        let mode = match kind {
            HOWDAH_SSRF_KIND_REBIND => self.config.sinks.ssrf_rebind_mode(self.config.mode),
            HOWDAH_SSRF_KIND_REDIRECT => self.config.sinks.ssrf_redirect_mode(self.config.mode),
            _ => self.config.sinks.effective_mode(SinkId::Ssrf, self.config.mode),
        };
        if mode == Mode::Off {
            return Action::Allow;
        }
        if let Some(m) = self.excepted(RuleId::Ssrf, script, sha, None) {
            self.note_excepted_sink(RuleId::Ssrf, &m);
            return Action::Allow;
        }
        let action = if mode == Mode::Block { Action::Block } else { Action::Log };
        let lead = if kind == HOWDAH_SSRF_KIND_REDIRECT { "ssrf redirect" } else { "ssrf" };
        self.sink_log = Some(self.record(
            RuleId::Ssrf,
            action,
            format!("{lead}: oversize host (>256 bytes), not resolvable - treated as suspicious"),
        ));
        action
    }

    /// Egress-scheme denial (`[sinks.ssrf] scheme`). `via` is `HOWDAH_SSRF_VIA_*`.
    /// Only the scheme CATEGORY is logged, never the URL. `[[exceptions]]`
    /// `rule = "ssrf"` applies; `allow_hosts` does not (it names destinations,
    /// this is a protocol policy).
    fn sink_ssrf_scheme(
        &mut self,
        via: i32,
        url: &[u8],
        script: Option<&str>,
        sha: Option<&[u8; 32]>,
    ) -> Action {
        #[cfg(test)]
        if tests::FORCE_PANIC.with(|f| f.get()) {
            panic!("injected test panic");
        }
        let mode = self.config.sinks.ssrf_scheme_mode(self.config.mode);
        if mode == Mode::Off {
            return Action::Allow;
        }
        let (ctx, name) = if via == HOWDAH_SSRF_VIA_CURL {
            (SchemeCtx::Curl, "curl")
        } else {
            (SchemeCtx::Stream, "stream")
        };
        let Some(label) = denied_scheme(url, ctx) else {
            return Action::Allow;
        };
        if let Some(m) = self.excepted(RuleId::Ssrf, script, sha, None) {
            self.note_excepted_sink(RuleId::Ssrf, &m);
            return Action::Allow;
        }
        let action = if mode == Mode::Block { Action::Block } else { Action::Log };
        self.sink_log = Some(self.record(
            RuleId::Ssrf,
            action,
            format!("ssrf scheme via {name}: scheme={label} is not http/https"),
        ));
        action
    }

    /// Record the self-test marker: always a Log event, NEVER a block. A
    /// Standard hit would block in `mode = block`, so clamp Block to Log. Off
    /// (global or per-rule) stays silent. Never masks an already-decided Block.
    fn selftest(&mut self) {
        let hit = crate::limits::selftest_hit();
        let a = decide(Some(&hit), self.config.mode, &self.config.rule_modes);
        // Only when nothing else was flagged: never displace, suppress or
        // downgrade a real detection. A later real hit replaces this line.
        // (Any client can trigger one self_test line per request by sending
        // the marker; low risk, by design.)
        if a == Action::Allow || self.worst != Action::Allow {
            return;
        }
        self.selftest_only = true;
        self.worst = Action::Log;
        self.stash(RuleId::SelfTest, Action::Log, describe(RuleId::SelfTest));
    }

    fn malformed(&mut self) {
        let hit = LimitHit {
            rule: RuleId::MalformedMultipart,
            severity: Severity::Standard,
            detail: String::new(),
        };
        self.apply(Some(&hit));
    }

    fn feed(&mut self, chunk: &[u8]) -> Action {
        #[cfg(test)]
        if tests::FORCE_PANIC.with(|f| f.get()) {
            panic!("injected test panic");
        }
        if self.worst == Action::Block {
            return self.worst; // already blocked: stop parsing hostile input
        }
        let Some(state) = self.state.as_mut() else {
            return self.worst; // no request in progress: fail-open
        };
        let res = state.feed(chunk);
        let limits = &self.config.limits;
        let mut hits: Vec<Option<LimitHit>> = Vec::new();
        match &res {
            Ok(events) => {
                for ev in events {
                    hits.push(limits.check(state, ev));
                }
                if events.is_empty() {
                    hits.push(limits.check(state, &Event::PartEnd));
                }
            }
            // Events from a failing call are dropped; check counters anyway.
            Err(_) => hits.push(limits.check(state, &Event::PartEnd)),
        }
        hits.push(limits.check_fed_bytes(state.total_fed_bytes()));
        for h in hits {
            self.apply(h.as_ref());
        }
        if res.is_err() {
            self.malformed();
        }
        self.worst
    }

    fn end(&mut self) -> Action {
        #[cfg(test)]
        if tests::FORCE_PANIC.with(|f| f.get()) {
            panic!("injected test panic");
        }
        let truncated = match self.state.as_mut() {
            Some(state) => state.finish().is_err(),
            None => false,
        };
        if truncated {
            self.malformed();
        }
        self.worst
    }

    /// §4.2: arm the byte-stream scanner on the request's real boundary, taken
    /// from `content_type`. A non-multipart type or an absent boundary leaves the
    /// scanner off (fail open; the parsed-event counter still enforces the
    /// structural limits).
    fn scan_post_begin(&mut self, content_type: &[u8], post_max_size: i64, memory_limit: i64) {
        self.post_scan = crate::boundary::extract(content_type).map(|b| MultipartState::new(&b));
        self.post_max_size = post_max_size;
        self.memory_limit = memory_limit;
        self.post_scan_blocked = false;
    }

    /// §4.2: feed `chunk` raw body bytes to the byte-stream scanner and fold any
    /// limit hit into the sticky worst. Mirrors `feed`, but on `self.post_scan`,
    /// so the exact per-part header counts (and, later, byte/estimate checks) run
    /// independently of the parsed-event counter. A feed error is a malformed
    /// body (over-counts, never under-counts).
    fn scan_post(&mut self, chunk: &[u8]) -> Action {
        #[cfg(test)]
        if tests::FORCE_PANIC.with(|f| f.get()) {
            panic!("injected test panic");
        }
        // The scanner's return drives the read_post wrapper's EOF: it stops the
        // body ONLY on an unbounded-growth limit (see `rule_stops_the_read`),
        // never for a bounded count limit — even one the scanner detects itself.
        // A bounded body that trips `max_parts`/`max_files` must drain so
        // `deliver_startup_refusal` can answer with a clean 403; truncating it
        // leaves the FastCGI body unread and resets the client.
        if self.post_scan_blocked {
            return Action::Block; // scanner already stopped the body; stay stopped
        }
        let pms = self.post_max_size;
        let Some(state) = self.post_scan.as_mut() else {
            return Action::Allow; // not multipart / no boundary: never truncate
        };
        let res = state.feed(chunk);
        let limits = &self.config.limits;
        let mut hits: Vec<Option<LimitHit>> = Vec::new();
        match &res {
            Ok(events) => {
                for ev in events {
                    hits.push(limits.check(state, ev));
                }
                if events.is_empty() {
                    hits.push(limits.check(state, &Event::PartEnd));
                }
            }
            Err(_) => hits.push(limits.check(state, &Event::PartEnd)),
        }
        hits.push(limits.check_fed_bytes(state.total_fed_bytes()));
        // Gap B (§4.3): bytes actually read vs PHP's effective post_max_size.
        hits.push(limits.check_post_bytes(state.total_fed_bytes(), pms));
        // Every hit folds into `worst` (verdict + fail-closed), but only an
        // UNBOUNDED-growth limit stops the body: a bounded one (max_parts, etc.)
        // the scanner also detects must still drain for a clean 403.
        let mut scanner_block = false;
        for h in hits {
            let stops_read = h.as_ref().is_some_and(|x| rule_stops_the_read(x.rule));
            scanner_block |= self.apply(h.as_ref()) == Action::Block && stops_read;
        }
        // A scanner parse error is NOT a block: PHP's rfc1867 accepts shapes this
        // strict scanner rejects (LF-only line endings, header folding, a
        // non-`form-data` disposition, a part with no Content-Disposition), and
        // blocking them would refuse bodies PHP serves. On an error the scanner
        // just stops advancing — its high-water counts so far still hold and the
        // independent parsed-event counter remains the floor (over-count, never
        // under-count; §4.2). `MalformedMultipart` is deliberately not raised.
        // §4.5: the buffered non-file bytes may have grown; re-check the estimate.
        scanner_block |= self.apply_memory_estimate() == Action::Block;
        if scanner_block {
            self.post_scan_blocked = true;
        }
        if self.post_scan_blocked {
            Action::Block
        } else {
            Action::Allow
        }
    }

    /// §4.5: fold the parse-memory estimate (summed nesting levels from the input
    /// paths + buffered non-file field bytes from the byte scanner) against the
    /// live-`memory_limit` ceiling. Called whenever either input grows.
    fn apply_memory_estimate(&mut self) -> Action {
        let levels = self.input.total_levels();
        let nonfile = self.post_scan.as_ref().map(|s| s.total_nonfile_bytes()).unwrap_or(0);
        let hit = self.config.limits.check_memory_estimate(levels, nonfile, self.memory_limit);
        self.apply(hit.as_ref())
    }

    /// One already-parsed multipart part (the PHP glue's `FORMDATA` /
    /// `FILE_START`). Counting happens in `MultipartState::note_part` and does
    /// not depend on any byte parsing, so part data can never suppress it.
    fn part(&mut self, kind: i32, name_len: usize, filename_len: usize) -> Action {
        #[cfg(test)]
        if tests::FORCE_PANIC.with(|f| f.get()) {
            panic!("injected test panic");
        }
        if self.worst == Action::Block {
            return self.worst; // already blocked: every further part is refused
        }
        let Some(state) = self.state.as_mut() else {
            return self.worst; // no request in progress: fail-open
        };
        let filename = (kind == HOWDAH_PART_FILE).then_some(filename_len);
        state.note_part(name_len, filename);
        let hit = self.config.limits.check(state, &Event::PartStart);
        self.apply(hit.as_ref());
        self.worst
    }

    /// `len` bytes of part data (a `FORMDATA` value or a `FILE_DATA` chunk).
    fn part_data(&mut self, len: usize) -> Action {
        #[cfg(test)]
        if tests::FORCE_PANIC.with(|f| f.get()) {
            panic!("injected test panic");
        }
        if self.worst == Action::Block {
            return self.worst;
        }
        let Some(state) = self.state.as_mut() else {
            return self.worst;
        };
        state.note_data(len as u64);
        let hit = self.config.limits.check(state, &Event::PartData { len: len as u64 });
        self.apply(hit.as_ref());
        self.worst
    }

    fn input_var(&mut self, name: &[u8]) -> Action {
        #[cfg(test)]
        if tests::FORCE_PANIC.with(|f| f.get()) {
            panic!("injected test panic");
        }
        self.input.note_var(name);
        let hit = self.config.limits.check_input(&self.input);
        self.apply(hit.as_ref());
        self.apply_memory_estimate(); // §4.5: nesting levels just grew
        self.worst
    }

    /// Feed one multipart FORMDATA/FILE_START name into the gap-C nesting budget
    /// (the part is already counted by `MultipartState`; this only adds its
    /// array levels). The name is inspected for `[` depth, never logged.
    fn note_name(&mut self, name: &[u8], is_file: bool) -> Action {
        #[cfg(test)]
        if tests::FORCE_PANIC.with(|f| f.get()) {
            panic!("injected test panic");
        }
        self.input.note_name(name, is_file);
        let hit = self.config.limits.check_input(&self.input);
        self.apply(hit.as_ref());
        self.apply_memory_estimate(); // §4.5: nesting levels just grew
        self.worst
    }

    fn request_header(&mut self, name_len: usize, value_len: usize) -> Action {
        #[cfg(test)]
        if tests::FORCE_PANIC.with(|f| f.get()) {
            panic!("injected test panic");
        }
        self.input.note_header(name_len, value_len);
        let hit = self.config.limits.check_input(&self.input);
        self.apply(hit.as_ref());
        self.worst
    }

    fn panic_note(&mut self) {
        // Best effort; must not itself unwind out of the boundary.
        // Do not clobber an already-stashed real Log/Block line.
        if self.log.is_some() {
            return;
        }
        let _ = catch_unwind(AssertUnwindSafe(|| {
            self.stash(RuleId::SelfTest, Action::Log, "internal panic caught at FFI boundary; failed open");
        }));
    }
}

/// Must never unwind: the stderr write ignores errors (`eprintln!` would panic
/// on EIO/EPIPE) and the whole body is itself guarded.
///
/// # Safety
/// `ctx` must be NULL or a live howdah_ctx.
unsafe fn report_panic(ctx: *mut howdah_ctx) {
    use std::io::Write;
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let _ = writeln!(
            std::io::stderr(),
            "howdah: panic caught at FFI boundary; failing open (Allow)"
        );
        if !ctx.is_null() {
            (*ctx).panic_note();
        }
    }));
}

/// Create a context from TOML config. Invalid, non-UTF-8 or NULL config falls
/// back to safe defaults. Never returns NULL (barring allocation failure).
/// Caller owns the result; release with `howdah_free`.
///
/// # Safety
/// `toml` must be NULL or valid for `len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn howdah_init(toml: *const c_char, len: usize) -> *mut howdah_ctx {
    let cfg = catch_unwind(AssertUnwindSafe(|| {
        if toml.is_null() {
            return Config::safe_defaults();
        }
        let s = copy_str(toml, len);
        Config::from_toml(&s).unwrap_or_else(|_| Config::safe_defaults())
    }))
    .unwrap_or_else(|_| Config::safe_defaults());
    let ctx = catch_unwind(AssertUnwindSafe(|| howdah_ctx::new(cfg)))
        .unwrap_or_else(|_| howdah_ctx::new(Config::safe_defaults()));
    Box::into_raw(Box::new(ctx))
}

/// Begin a new request: resets state, new request id, copies `meta`.
///
/// # Safety
/// `ctx` NULL or live; `boundary` NULL or valid for `len` bytes; `meta` NULL
/// or a valid RequestMeta whose pointers are each NULL or valid for their len.
#[no_mangle]
pub unsafe extern "C" fn howdah_request_begin(
    ctx: *mut howdah_ctx,
    boundary: *const c_char,
    len: usize,
    meta: *const RequestMeta,
) {
    if ctx.is_null() {
        return;
    }
    let r = catch_unwind(AssertUnwindSafe(|| {
        let c = &mut *ctx;
        let b = if boundary.is_null() || len == 0 {
            Vec::new()
        } else {
            std::slice::from_raw_parts(boundary as *const u8, len).to_vec()
        };
        c.state = Some(MultipartState::new(&b));
        c.post_scan = None; // set by howdah_scan_post_begin once the boundary is known
        c.post_max_size = 0;
        c.memory_limit = -1;
        c.request_id = new_request_id();
        c.worst = Action::Allow;
        c.log = None;
        c.selftest_only = false;
        c.input = InputState::new();
        c.inspect_values = 0;
        c.inspect_bytes = 0;
        c.sink_log = None;
        c.meta = match meta.as_ref() {
            Some(m) => Meta {
                client_ip: copy_str(m.client_ip, m.client_ip_len),
                method: copy_str(m.method, m.method_len),
                uri: copy_str(m.uri, m.uri_len),
            },
            None => Meta::default(),
        };
    }));
    if r.is_err() {
        report_panic(ctx);
    }
}

/// Feed a body chunk; returns the most severe action so far this request
/// (0 Allow, 1 Log, 2 Block). Panic or NULL ctx returns 0.
///
/// # Safety
/// `ctx` NULL or live; `chunk` NULL or valid for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn howdah_feed(ctx: *mut howdah_ctx, chunk: *const c_char, len: usize) -> i32 {
    if ctx.is_null() {
        return HOWDAH_ALLOW;
    }
    let r = catch_unwind(AssertUnwindSafe(|| {
        let data: &[u8] = if chunk.is_null() || len == 0 {
            &[]
        } else {
            std::slice::from_raw_parts(chunk as *const u8, len)
        };
        code((*ctx).feed(data))
    }));
    r.unwrap_or_else(|_| {
        report_panic(ctx);
        HOWDAH_ALLOW
    })
}

/// §4.2: arm the byte-stream scanner from the request's `Content-Type` (the real
/// boundary is extracted here). Call once per request before `howdah_scan_post`,
/// when the SAPI reports a `multipart/form-data` body. A non-multipart type or an
/// absent boundary leaves the scanner off. NULL ctx / panic is a no-op.
///
/// `post_max_size` and `memory_limit` are PHP's effective INI values for this
/// request in bytes (`post_max_size <= 0` = unlimited → gap B off;
/// `memory_limit = -1` = no limit → §4.5 fallback ceiling).
///
/// # Safety
/// `ctx` NULL or live; `content_type` NULL or valid for `ct_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn howdah_scan_post_begin(
    ctx: *mut howdah_ctx,
    content_type: *const c_char,
    ct_len: usize,
    post_max_size: i64,
    memory_limit: i64,
) {
    if ctx.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let ct: &[u8] = if content_type.is_null() || ct_len == 0 {
            &[]
        } else {
            std::slice::from_raw_parts(content_type as *const u8, ct_len)
        };
        (*ctx).scan_post_begin(ct, post_max_size, memory_limit);
    }));
}

/// §4.2: feed `len` raw body bytes (as the `read_post` wrapper reads them) to the
/// byte-stream scanner. Returns the most severe action so far (0 Allow / 1 Log /
/// 2 Block); `Block` tells the wrapper to stop reading. The bytes are scanned for
/// framing only, never logged. NULL ctx, a scanner that was never armed, or a
/// panic returns 0 (fail open).
///
/// # Safety
/// `ctx` NULL or live; `buf` NULL or valid for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn howdah_scan_post(ctx: *mut howdah_ctx, buf: *const c_char, len: usize) -> i32 {
    if ctx.is_null() {
        return HOWDAH_ALLOW;
    }
    let r = catch_unwind(AssertUnwindSafe(|| {
        let data: &[u8] = if buf.is_null() || len == 0 {
            &[]
        } else {
            std::slice::from_raw_parts(buf as *const u8, len)
        };
        code((*ctx).scan_post(data))
    }));
    r.unwrap_or_else(|_| {
        report_panic(ctx);
        HOWDAH_ALLOW
    })
}

/// Signal end of body: detects a truncated body (MalformedMultipart) and
/// returns the final action code. Panic or NULL ctx returns 0.
///
/// # Safety
/// `ctx` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn howdah_request_end(ctx: *mut howdah_ctx) -> i32 {
    if ctx.is_null() {
        return HOWDAH_ALLOW;
    }
    let r = catch_unwind(AssertUnwindSafe(|| code((*ctx).end())));
    r.unwrap_or_else(|_| {
        report_panic(ctx);
        HOWDAH_ALLOW
    })
}

/// Report one already-parsed multipart part: `kind` is `HOWDAH_PART_FIELD` or
/// `HOWDAH_PART_FILE`; `name_len` is the form field name's byte length and
/// `filename_len` the upload filename's (ignored for a field). This is how the
/// PHP glue reports parts: PHP hands it parsed events, never request bytes, so
/// nothing in the part data can influence the count. Returns the most severe
/// action so far (0 Allow, 1 Log, 2 Block); `Block` for a part means the
/// caller must not let PHP allocate it. Panic or NULL ctx returns 0.
///
/// # Safety
/// `ctx` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn howdah_part(
    ctx: *mut howdah_ctx,
    kind: i32,
    name_len: usize,
    filename_len: usize,
) -> i32 {
    if ctx.is_null() {
        return HOWDAH_ALLOW;
    }
    let r = catch_unwind(AssertUnwindSafe(|| code((*ctx).part(kind, name_len, filename_len))));
    r.unwrap_or_else(|_| {
        report_panic(ctx);
        HOWDAH_ALLOW
    })
}

/// Report `len` bytes of data for the current part (a field value or one file
/// chunk). Only the length is used, so the bytes are not passed. Returns the
/// most severe action so far. Panic or NULL ctx returns 0.
///
/// # Safety
/// `ctx` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn howdah_part_data(ctx: *mut howdah_ctx, len: usize) -> i32 {
    if ctx.is_null() {
        return HOWDAH_ALLOW;
    }
    let r = catch_unwind(AssertUnwindSafe(|| code((*ctx).part_data(len))));
    r.unwrap_or_else(|_| {
        report_panic(ctx);
        HOWDAH_ALLOW
    })
}

/// Record one request variable name (GET/POST/COOKIE key) and run the
/// input-shape checks. The name is inspected, never logged. Returns the most
/// severe action so far this request (0 Allow, 1 Log, 2 Block). Panic or NULL
/// ctx returns 0.
///
/// # Safety
/// `ctx` NULL or live; `name` NULL or valid for `name_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn howdah_input_var(ctx: *mut howdah_ctx, name: *const c_char, name_len: usize) -> i32 {
    if ctx.is_null() {
        return HOWDAH_ALLOW;
    }
    let r = catch_unwind(AssertUnwindSafe(|| {
        let bytes: &[u8] = if name.is_null() || name_len == 0 {
            &[]
        } else {
            std::slice::from_raw_parts(name as *const u8, name_len)
        };
        code((*ctx).input_var(bytes))
    }));
    r.unwrap_or_else(|_| {
        report_panic(ctx);
        HOWDAH_ALLOW
    })
}

/// Feed one multipart FORMDATA/FILE_START name into the gap-C nesting budget
/// (§4.4). `is_file` is non-zero for a FILE_START name (weighted higher). The
/// part itself is counted by `howdah_part`; this only adds its array levels. The
/// name is inspected for `[` depth, never logged. Returns the most severe action
/// so far (0 Allow, 1 Log, 2 Block). Panic or NULL ctx returns 0.
///
/// # Safety
/// `ctx` NULL or live; `name` NULL or valid for `name_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn howdah_note_name(
    ctx: *mut howdah_ctx,
    name: *const c_char,
    name_len: usize,
    is_file: i32,
) -> i32 {
    if ctx.is_null() {
        return HOWDAH_ALLOW;
    }
    let r = catch_unwind(AssertUnwindSafe(|| {
        let bytes: &[u8] = if name.is_null() || name_len == 0 {
            &[]
        } else {
            std::slice::from_raw_parts(name as *const u8, name_len)
        };
        code((*ctx).note_name(bytes, is_file != 0))
    }));
    r.unwrap_or_else(|_| {
        report_panic(ctx);
        HOWDAH_ALLOW
    })
}

/// Inspect one request value (Layer 2). `source` is a `HOWDAH_SRC_*` code.
/// The value is scanned binary-safe and NEVER logged; the log carries only the
/// class, source and (truncated) variable name. Resolved against the
/// independent `[inspect]` mode, so a global `block` never arms blocking here.
/// Returns the action for this value (0 Allow, 1 Log, 2 Block); it never drops
/// the variable. NULL ctx, unknown source or panic returns 0.
///
/// `HOWDAH_SRC_QUERY` is different: `val` is the raw query string, `name` is
/// ignored, and the check is the php-cgi argument-injection rule, whose mode is
/// `[inspect] cgi_arg` (default `block`, independent of the global mode and of
/// `[inspect] mode`) and which is exempt from the per-request scan budgets.
///
/// # Safety
/// `ctx` NULL or live; `name`/`val` NULL or valid for their lengths.
#[no_mangle]
pub unsafe extern "C" fn howdah_inspect_value(
    ctx: *mut howdah_ctx,
    source: i32,
    name: *const c_char,
    name_len: usize,
    val: *const c_char,
    val_len: usize,
) -> i32 {
    if ctx.is_null() {
        return HOWDAH_ALLOW;
    }
    // `None` is the raw query string (the php-cgi argument-injection rule); the
    // rest are the budgeted per-variable scans.
    let src = match source {
        HOWDAH_SRC_GET => Some(Source::Get),
        HOWDAH_SRC_POST => Some(Source::Post),
        HOWDAH_SRC_COOKIE => Some(Source::Cookie),
        HOWDAH_SRC_PATH => Some(Source::Path),
        HOWDAH_SRC_QUERY => None,
        _ => return HOWDAH_ALLOW,
    };
    let r = catch_unwind(AssertUnwindSafe(|| {
        let n: &[u8] = if name.is_null() || name_len == 0 {
            &[]
        } else {
            std::slice::from_raw_parts(name as *const u8, name_len)
        };
        let v: &[u8] = if val.is_null() || val_len == 0 {
            &[]
        } else {
            std::slice::from_raw_parts(val as *const u8, val_len)
        };
        code(match src {
            Some(s) => (*ctx).inspect_value(s, n, v),
            None => (*ctx).inspect_query(v),
        })
    }));
    r.unwrap_or_else(|_| {
        report_panic(ctx);
        HOWDAH_ALLOW
    })
}

/// Record one request header by LENGTHS ONLY (names and values never cross the
/// ABI) and run the header count/size checks. Returns the most severe action so
/// far this request (0 Allow, 1 Log, 2 Block). Panic or NULL ctx returns 0.
///
/// # Safety
/// `ctx` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn howdah_request_header(ctx: *mut howdah_ctx, name_len: usize, value_len: usize) -> i32 {
    if ctx.is_null() {
        return HOWDAH_ALLOW;
    }
    let r = catch_unwind(AssertUnwindSafe(|| code((*ctx).request_header(name_len, value_len))));
    r.unwrap_or_else(|_| {
        report_panic(ctx);
        HOWDAH_ALLOW
    })
}

/// Take the pending JSON log line (single line, no newline), or NULL if none.
/// Caller owns the string; free with `howdah_free_str`.
///
/// # Safety
/// `ctx` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn howdah_take_log_line(ctx: *mut howdah_ctx) -> *mut c_char {
    if ctx.is_null() {
        return std::ptr::null_mut();
    }
    catch_unwind(AssertUnwindSafe(|| match (*ctx).log.take() {
        Some(s) => CString::new(s.replace('\0', ""))
            .map(|c| c.into_raw())
            .unwrap_or(std::ptr::null_mut()),
        None => std::ptr::null_mut(),
    }))
    .unwrap_or(std::ptr::null_mut())
}

/// Layer-3 sink check: `sink` is a `HOWDAH_SINK_*` id, `name` the guarded
/// function/construct, `arg` the sink argument (binary-safe; scanned, never
/// logged). Returns 0 Allow / 1 Log / 2 Block. NULL ctx, unknown sink or panic
/// returns 0 (fail-open: a sink-check bug must never neutralize a legitimate
/// call). A hit is retrievable with `howdah_take_sink_log_line`.
///
/// # Safety
/// `ctx` NULL or live; `name`/`arg` NULL or valid for their lengths.
#[no_mangle]
pub unsafe extern "C" fn howdah_sink_check(
    ctx: *mut howdah_ctx,
    sink: i32,
    name: *const c_char,
    name_len: usize,
    arg: *const c_char,
    arg_len: usize,
) -> i32 {
    if ctx.is_null() {
        return HOWDAH_ALLOW;
    }
    let id = match sink {
        HOWDAH_SINK_COMMAND_EXEC => SinkId::CommandExec,
        HOWDAH_SINK_INCLUDE => SinkId::Include,
        HOWDAH_SINK_EVAL => SinkId::Eval,
        HOWDAH_SINK_UNSERIALIZE => SinkId::Unserialize,
        HOWDAH_SINK_PHAR => SinkId::Phar,
        HOWDAH_SINK_PREG_EVAL => SinkId::PregEval,
        HOWDAH_SINK_CREATE_FUNCTION => SinkId::CreateFunction,
        HOWDAH_SINK_ASSERT => SinkId::Assert,
        HOWDAH_SINK_CALLBACK => SinkId::Callback,
        HOWDAH_SINK_XML => SinkId::Xml,
        HOWDAH_SINK_TLS => SinkId::Tls,
        _ => return HOWDAH_ALLOW,
    };
    let r = catch_unwind(AssertUnwindSafe(|| {
        let n: &[u8] = if name.is_null() || name_len == 0 {
            &[]
        } else {
            std::slice::from_raw_parts(name as *const u8, name_len)
        };
        let a: &[u8] = if arg.is_null() || arg_len == 0 {
            &[]
        } else {
            std::slice::from_raw_parts(arg as *const u8, arg_len)
        };
        code((*ctx).sink_check(id, n, a, None, None))
    }));
    r.unwrap_or_else(|_| {
        report_panic(ctx);
        HOWDAH_ALLOW
    })
}

/// 1 iff the given Layer-4 facet (`HOWDAH_BEHAVIOR_*`) is armed; NULL ctx,
/// unknown facet or panic is 0.
///
/// # Safety
/// `ctx` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn howdah_behavior_armed(ctx: *mut howdah_ctx, facet: i32) -> i32 {
    if ctx.is_null() {
        return 0;
    }
    catch_unwind(AssertUnwindSafe(|| {
        let c = &*ctx;
        let b = &c.config.behavior;
        if b.effective_mode(c.config.mode) == Mode::Off {
            return 0;
        }
        let scoped = b.observe || !b.deny_exec_dirs.is_empty();
        i32::from(match facet {
            HOWDAH_BEHAVIOR_EXEC_DIR => !b.deny_exec_dirs.is_empty(),
            HOWDAH_BEHAVIOR_BINARY => scoped || !b.allow_exec_binaries.is_empty(),
            HOWDAH_BEHAVIOR_EGRESS => scoped || !b.allow_egress_hosts.is_empty(),
            HOWDAH_BEHAVIOR_PHP_WRITE => b.deny_php_writes,
            HOWDAH_BEHAVIOR_UPLOAD_WRITE => b.upload_write != Mode::Off,
            HOWDAH_BEHAVIOR_DELETE => b.delete_guard != Mode::Off,
            HOWDAH_BEHAVIOR_SECRET_READ => b.secret_read != Mode::Off,
            _ => false,
        })
    }))
    .unwrap_or(0)
}

/// 1 iff the behavior egress facet is armed (for the widened SSRF hook).
///
/// # Safety
/// `ctx` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn howdah_behavior_egress_active(ctx: *mut howdah_ctx) -> i32 {
    howdah_behavior_armed(ctx, HOWDAH_BEHAVIOR_EGRESS)
}

/// Layer-4: script about to execute at realpath `path`. 0/1/2; fail-open.
///
/// # Safety
/// `ctx` NULL or live; `path` NULL or valid for `path_len`.
#[no_mangle]
pub unsafe extern "C" fn howdah_behavior_check_exec_dir(
    ctx: *mut howdah_ctx,
    path: *const c_char,
    path_len: usize,
) -> i32 {
    if ctx.is_null() {
        return HOWDAH_ALLOW;
    }
    catch_unwind(AssertUnwindSafe(|| {
        let p = copy_str(path, path_len);
        code((*ctx).behavior_check(|cfg| crate::behavior::exec_dir_hit(&p, cfg), None, None))
    }))
    .unwrap_or_else(|_| {
        report_panic(ctx);
        HOWDAH_ALLOW
    })
}

/// Layer-4: caller spawning program `prog`. 0/1/2; fail-open.
///
/// # Safety
/// `ctx` NULL or live; pointers NULL or valid for their lengths.
#[no_mangle]
pub unsafe extern "C" fn howdah_behavior_check_binary(
    ctx: *mut howdah_ctx,
    caller: *const c_char,
    caller_len: usize,
    prog: *const c_char,
    prog_len: usize,
) -> i32 {
    if ctx.is_null() {
        return HOWDAH_ALLOW;
    }
    catch_unwind(AssertUnwindSafe(|| {
        let c = copy_str(caller, caller_len);
        let p = copy_str(prog, prog_len);
        code((*ctx).behavior_check(|cfg| crate::behavior::binary_hit(&c, &p, cfg), None, None))
    }))
    .unwrap_or_else(|_| {
        report_panic(ctx);
        HOWDAH_ALLOW
    })
}

/// Layer-4: caller connecting out to `host`. 0/1/2; fail-open.
///
/// # Safety
/// `ctx` NULL or live; pointers NULL or valid for their lengths.
#[no_mangle]
pub unsafe extern "C" fn howdah_behavior_check_egress(
    ctx: *mut howdah_ctx,
    caller: *const c_char,
    caller_len: usize,
    host: *const c_char,
    host_len: usize,
) -> i32 {
    if ctx.is_null() {
        return HOWDAH_ALLOW;
    }
    catch_unwind(AssertUnwindSafe(|| {
        let c = copy_str(caller, caller_len);
        let h = copy_str(host, host_len);
        code((*ctx).behavior_check(|cfg| crate::behavior::egress_hit(&c, &h, cfg), None, None))
    }))
    .unwrap_or_else(|_| {
        report_panic(ctx);
        HOWDAH_ALLOW
    })
}

/// Layer-4: caller opening `target`; `is_write_mode` non-zero for write modes.
/// 0/1/2; fail-open.
///
/// # Safety
/// `ctx` NULL or live; pointers NULL or valid for their lengths.
#[no_mangle]
pub unsafe extern "C" fn howdah_behavior_check_php_write(
    ctx: *mut howdah_ctx,
    caller: *const c_char,
    caller_len: usize,
    target: *const c_char,
    target_len: usize,
    is_write_mode: i32,
) -> i32 {
    if ctx.is_null() {
        return HOWDAH_ALLOW;
    }
    catch_unwind(AssertUnwindSafe(|| {
        let c = copy_str(caller, caller_len);
        let t = copy_str(target, target_len);
        let op = crate::behavior::WriteOp::from_code(is_write_mode);
        let org = crate::behavior::Origin { file: &c, line: 0 };
        code((*ctx).behavior_check(|cfg| crate::behavior::php_write_hit(org, &t, op, cfg), None, None))
    }))
    .unwrap_or_else(|_| {
        report_panic(ctx);
        HOWDAH_ALLOW
    })
}

/// 1 iff SSRF guarding is armed (effective mode != off); NULL ctx or panic is
/// 0. Never stashes a log line. Lets the shim skip DNS work when disarmed.
///
/// # Safety
/// `ctx` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn howdah_sink_ssrf_armed(ctx: *mut howdah_ctx) -> i32 {
    if ctx.is_null() {
        return 0;
    }
    catch_unwind(AssertUnwindSafe(|| {
        let c = &*ctx;
        i32::from(c.config.sinks.effective_mode(SinkId::Ssrf, c.config.mode) != Mode::Off)
    }))
    .unwrap_or(0)
}

/// 1 iff the given sink (`HOWDAH_SINK_*`) is armed (effective mode != off);
/// NULL ctx, unknown sink or panic is 0. Never stashes a log line. Used by the
/// glue to decide, once per process, whether to install the phar/ssrf hooks.
///
/// # Safety
/// `ctx` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn howdah_sink_armed(ctx: *mut howdah_ctx, sink: i32) -> i32 {
    if ctx.is_null() {
        return 0;
    }
    let id = match sink {
        HOWDAH_SINK_COMMAND_EXEC => SinkId::CommandExec,
        HOWDAH_SINK_INCLUDE => SinkId::Include,
        HOWDAH_SINK_EVAL => SinkId::Eval,
        HOWDAH_SINK_UNSERIALIZE => SinkId::Unserialize,
        HOWDAH_SINK_PHAR => SinkId::Phar,
        HOWDAH_SINK_SSRF => SinkId::Ssrf,
        HOWDAH_SINK_MAIL => SinkId::Mail,
        HOWDAH_SINK_PREG_EVAL => SinkId::PregEval,
        HOWDAH_SINK_CREATE_FUNCTION => SinkId::CreateFunction,
        HOWDAH_SINK_ASSERT => SinkId::Assert,
        HOWDAH_SINK_CALLBACK => SinkId::Callback,
        HOWDAH_SINK_XML => SinkId::Xml,
        HOWDAH_SINK_TLS => SinkId::Tls,
        _ => return 0,
    };
    catch_unwind(AssertUnwindSafe(|| {
        let c = &*ctx;
        i32::from(c.config.sinks.effective_mode(id, c.config.mode) != Mode::Off)
    }))
    .unwrap_or(0)
}

/// SSRF decision for one intercepted outbound call. `ips` points to
/// `ips_count` fixed 17-byte records `[family (4|6)][16 address bytes]` (a v4
/// uses the first 4). Returns 0 Allow / 1 Log / 2 Block; NULL ctx, malformed
/// input or panic is 0 (fail-open). The log line carries scheme/host/port/
/// matched-ip/class only (in `reason`), never userinfo/path/query.
///
/// # Safety
/// `ctx` NULL or live; each pointer NULL or valid for its length (`ips`: 17 *
/// `ips_count` bytes).
#[no_mangle]
pub unsafe extern "C" fn howdah_sink_check_ssrf(
    ctx: *mut howdah_ctx,
    scheme: *const c_char,
    scheme_len: usize,
    host: *const c_char,
    host_len: usize,
    port: u16,
    ips: *const u8,
    ips_count: usize,
) -> i32 {
    if ctx.is_null() {
        return HOWDAH_ALLOW;
    }
    let r = catch_unwind(AssertUnwindSafe(|| {
        let sl = |p: *const c_char, n: usize| -> &[u8] {
            if p.is_null() || n == 0 {
                &[]
            } else {
                std::slice::from_raw_parts(p as *const u8, n)
            }
        };
        let recs: &[u8] = if ips.is_null() || ips_count == 0 {
            &[]
        } else {
            match ips_count.checked_mul(17) {
                Some(total) if total <= (1 << 24) => std::slice::from_raw_parts(ips, total),
                _ => return HOWDAH_ALLOW,
            }
        };
        code((*ctx).sink_check_ssrf(sl(scheme, scheme_len), sl(host, host_len), port, recs, None, None))
    }));
    r.unwrap_or_else(|_| {
        report_panic(ctx);
        HOWDAH_ALLOW
    })
}

/// SSRF parse seam: parse the target of an intercepted outbound call so the C
/// shim never parses URLs itself. `scheme_required != 0` selects
/// `HostForm::SchemeRequired` (URL-only sinks), else `BareHostOk` (fsockopen,
/// curl); `scheme_required == 2` is `SchemeRequired` for a redirect `Location`
/// value, where a leading `//` (scheme-relative) is read as `http://` and a
/// plain relative reference is a skip. Returns 2 when the host parsed but is longer than `out_host_cap`
/// (suspicious: nothing is written; call `howdah_sink_ssrf_oversize`). Returns 1 ("act") after writing the clean host (no userinfo/brackets/
/// port, lowercased) to `out_host`, its length to `*out_host_len` and the port
/// (0 if none) to `*out_port`. Returns 0 ("skip") for a non-network target
/// (local path, `unix://`, no scheme when required), any NULL argument, or a
/// panic: fail-open, the call is chained. Return codes: 0 = skip (not a network
/// target), 1 = host written, 2 = oversize (host longer than the buffer; the
/// caller treats it as suspicious via `howdah_sink_ssrf_oversize`).
///
/// # Safety
/// `input` NULL or valid for `input_len` bytes; `out_host` NULL or writable for
/// `out_host_cap` bytes; `out_host_len` / `out_port` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn howdah_ssrf_prepare(
    input: *const u8,
    input_len: usize,
    scheme_required: i32,
    out_host: *mut u8,
    out_host_cap: usize,
    out_host_len: *mut usize,
    out_port: *mut u16,
) -> i32 {
    if input.is_null() || out_host.is_null() || out_host_len.is_null() || out_port.is_null() {
        return 0;
    }
    catch_unwind(AssertUnwindSafe(|| {
        let form = if scheme_required != 0 { HostForm::SchemeRequired } else { HostForm::BareHostOk };
        let raw = std::slice::from_raw_parts(input, input_len);
        // 2 = a redirect `Location` value: an absolute URL or a scheme-relative
        // `//host/..` (which libcurl resolves against the current scheme). A plain
        // relative reference stays on the same host: not a new target.
        let scheme_relative;
        let raw = if scheme_required == 2 && raw.trim_ascii_start().starts_with(b"//") {
            scheme_relative = [b"http:".as_slice(), raw.trim_ascii_start()].concat();
            &scheme_relative[..]
        } else {
            raw
        };
        let Some(h) = parse_host(raw, form) else {
            return 0;
        };
        if h.name.len() > out_host_cap {
            return 2; // oversize: suspicious, see howdah_sink_ssrf_oversize
        }
        std::ptr::copy_nonoverlapping(h.name.as_ptr(), out_host, h.name.len());
        *out_host_len = h.name.len();
        *out_port = h.port.unwrap_or(0);
        1
    }))
    .unwrap_or(0)
}

/// Verdict for an oversize (>cap) SSRF host, called when `howdah_ssrf_prepare`
/// returned 2. 0 Allow (off) / 1 Log / 2 Block per the effective SSRF mode;
/// stashes a log line with no host bytes. NULL ctx or panic is 0.
///
/// # Safety
/// `ctx` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn howdah_sink_ssrf_oversize(ctx: *mut howdah_ctx) -> i32 {
    if ctx.is_null() {
        return HOWDAH_ALLOW;
    }
    let r = catch_unwind(AssertUnwindSafe(|| code((*ctx).sink_ssrf_oversize(None, None))));
    r.unwrap_or(HOWDAH_ALLOW)
}

/// Take the pending sink log line, or NULL if none. Same ownership contract as
/// `howdah_take_log_line`; free with `howdah_free_str`.
///
/// # Safety
/// `ctx` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn howdah_take_sink_log_line(ctx: *mut howdah_ctx) -> *mut c_char {
    if ctx.is_null() {
        return std::ptr::null_mut();
    }
    catch_unwind(AssertUnwindSafe(|| match (*ctx).sink_log.take() {
        Some(s) => CString::new(s.replace('\0', ""))
            .map(|c| c.into_raw())
            .unwrap_or(std::ptr::null_mut()),
        None => std::ptr::null_mut(),
    }))
    .unwrap_or(std::ptr::null_mut())
}

/// Report that the request carried the self-test marker (see
/// `limits::SELFTEST_FIELD`): stashes one `self_test` Log line, never a block.
/// Returns the resulting action code (Log=1; 0 if Howdah is off, the ctx is
/// NULL or a panic occurred; 2 if the request was already blocked).
///
/// # Safety
/// `ctx` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn howdah_selftest(ctx: *mut howdah_ctx) -> i32 {
    if ctx.is_null() {
        return HOWDAH_ALLOW;
    }
    let r = catch_unwind(AssertUnwindSafe(|| {
        (*ctx).selftest();
        code((*ctx).worst)
    }));
    r.unwrap_or_else(|_| {
        report_panic(ctx);
        code((*ctx).worst)
    })
}

/// Free a string from `howdah_take_log_line`. NULL is a no-op.
///
/// # Safety
/// `s` must be NULL or a pointer returned by `howdah_take_log_line`, freed once.
#[no_mangle]
pub unsafe extern "C" fn howdah_free_str(s: *mut c_char) {
    if !s.is_null() {
        let _ = catch_unwind(AssertUnwindSafe(|| drop(CString::from_raw(s))));
    }
}

/// Free a context. NULL is a no-op.
///
/// # Safety
/// `ctx` must be NULL or from `howdah_init`, freed once.
#[no_mangle]
pub unsafe extern "C" fn howdah_free(ctx: *mut howdah_ctx) {
    if !ctx.is_null() {
        let _ = catch_unwind(AssertUnwindSafe(|| drop(Box::from_raw(ctx))));
    }
}

/// 1 iff Layer 2 can return Block for at least one class: the `[inspect]`
/// effective mode is not off AND (it is `block`, or a `[inspect.rule_modes]`
/// override is `block`). Mirrors the decision `howdah_inspect_value` makes,
/// so the glue can decide per process whether to force `$_SERVER` at RINIT
/// and refuse before the script. A global `block` never arms it. NULL ctx or
/// panic is 0. Never stashes a log line.
///
/// # Safety
/// `ctx` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn howdah_inspect_armed(ctx: *mut howdah_ctx) -> i32 {
    if ctx.is_null() {
        return 0;
    }
    catch_unwind(AssertUnwindSafe(|| {
        let c = &*ctx;
        let ins = &c.config.inspect;
        let mode = ins.effective_mode(c.config.mode);
        if mode == Mode::Off {
            return 0;
        }
        i32::from(mode == Mode::Block || ins.rule_modes.values().any(|m| *m == Mode::Block))
    }))
    .unwrap_or(0)
}

/// The context's parsed `[log]` table (a copy). Rust-only, not part of the C
/// ABI: the glue reads it once at startup to set up the log destination and
/// hook. A NULL ctx or a caught panic gives the defaults, matching the safe
/// defaults an unparseable config falls back to.
///
/// # Safety
/// `ctx` NULL or live.
pub unsafe fn howdah_log_config(ctx: *const howdah_ctx) -> crate::config::LogConfig {
    if ctx.is_null() {
        return crate::config::LogConfig::default();
    }
    catch_unwind(AssertUnwindSafe(|| (*ctx).config.log.clone())).unwrap_or_default()
}

// ---- scoped [[exceptions]] --------------------------------------------------
//
// The `_at` entry points below are the originals plus the executing script
// (and an optional 32-byte SHA-256 of its bytes) so `script` / `script_sha256`
// facets can match. The originals stay and behave as before.

/// Set the request's client IP when it is still empty (the CLI built-in
/// server has no `sapi_getenv`, so the glue hands over the `REMOTE_ADDR`
/// variable it sees in the input filter instead). A non-empty IP already set
/// by `howdah_request_begin` is kept. NULL ctx or panic is a no-op.
///
/// # Safety
/// `ctx` NULL or live; `ip` NULL or valid for `ip_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn howdah_request_client_ip(ctx: *mut howdah_ctx, ip: *const c_char, ip_len: usize) {
    if ctx.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let c = &mut *ctx;
        if c.meta.client_ip.is_empty() {
            let v = copy_str(ip, ip_len.min(64));
            if !v.is_empty() && v.chars().all(|ch| ch.is_ascii_hexdigit() || matches!(ch, '.' | ':')) {
                c.meta.client_ip = v;
            }
        }
    }));
}

/// Number of `[[exceptions]]` entries active in this context (0 for NULL /
/// panic). For `php --ri howdah`.
///
/// # Safety
/// `ctx` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn howdah_exceptions_count(ctx: *mut howdah_ctx) -> i32 {
    if ctx.is_null() {
        return 0;
    }
    catch_unwind(AssertUnwindSafe(|| (*ctx).exceptions.len().min(i32::MAX as usize) as i32)).unwrap_or(0)
}

/// 1 iff the context's config has `exceptions_log = true`; 0 otherwise, for
/// NULL and on panic. For the startup summary line.
///
/// # Safety
/// `ctx` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn howdah_exceptions_log(ctx: *mut howdah_ctx) -> i32 {
    if ctx.is_null() {
        return 0;
    }
    catch_unwind(AssertUnwindSafe(|| i32::from((*ctx).exceptions_log))).unwrap_or(0)
}

/// 1 iff the context's config has `oom_exit = true` (the default); 0 otherwise,
/// for NULL and on panic. Read by the glue at MINIT to decide whether to install
/// the out-of-memory backstop (`zend_error_cb` hook). A NULL ctx or a caught
/// panic yields 0 (do not install: the fail-open direction — no behavior change).
///
/// # Safety
/// `ctx` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn howdah_oom_exit(ctx: *mut howdah_ctx) -> i32 {
    if ctx.is_null() {
        return 0;
    }
    catch_unwind(AssertUnwindSafe(|| i32::from((*ctx).config.oom_exit))).unwrap_or(0)
}

/// 1 iff the config ARMS the out-of-memory backstop: `oom_exit` is on AND the
/// global mode is not `off`. A global `off` disables every layer (the backstop
/// included), matching `[rules] decide` and the sink/inspect/behavior layers;
/// `detect` keeps it armed, since it is a Critical fail-stop that cannot be
/// "detected only". 0 for NULL and on panic. The glue applies the SAPI and
/// patched-engine gates on top of this.
///
/// # Safety
/// `ctx` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn howdah_oom_armed(ctx: *mut howdah_ctx) -> i32 {
    if ctx.is_null() {
        return 0;
    }
    catch_unwind(AssertUnwindSafe(|| {
        let c = &*ctx;
        i32::from(c.config.oom_exit && c.config.mode != Mode::Off)
    }))
    .unwrap_or(0)
}

/// 1 iff the context's config has `recycle_on_fatal = true` (the §4.7 recycle
/// facet opt-in); 0 otherwise, for NULL and on panic. Read by the glue at MINIT
/// for the phpinfo row. Off by default. See [`howdah_recycle_armed`].
///
/// # Safety
/// `ctx` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn howdah_recycle_on_fatal(ctx: *mut howdah_ctx) -> i32 {
    if ctx.is_null() {
        return 0;
    }
    catch_unwind(AssertUnwindSafe(|| i32::from((*ctx).config.recycle_on_fatal))).unwrap_or(0)
}

/// 1 iff the config ARMS the §4.7 recycle facet: `recycle_on_fatal` is on AND
/// the global mode is not `off` (a global `off` disables every layer, this one
/// included; `detect` keeps it armed, like the OOM backstop). The glue applies
/// the SAPI and patched-engine gates on top of this, and chooses observe vs
/// enforce from [`howdah_recycle_observe`]. 0 for NULL and on panic (do not arm
/// — the fail-open direction).
///
/// # Safety
/// `ctx` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn howdah_recycle_armed(ctx: *mut howdah_ctx) -> i32 {
    if ctx.is_null() {
        return 0;
    }
    catch_unwind(AssertUnwindSafe(|| {
        let c = &*ctx;
        i32::from(c.config.recycle_on_fatal && c.config.mode != Mode::Off)
    }))
    .unwrap_or(0)
}

/// 1 iff the config has `recycle_observe = true`: the §4.7 facet logs a
/// "would-recycle" event but does NOT exit, so an operator can size their
/// uncaught-fatal rate before enforcing. Only meaningful when the facet is
/// armed. 0 (enforce) for NULL and on panic.
///
/// # Safety
/// `ctx` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn howdah_recycle_observe(ctx: *mut howdah_ctx) -> i32 {
    if ctx.is_null() {
        return 0;
    }
    catch_unwind(AssertUnwindSafe(|| i32::from((*ctx).config.recycle_observe))).unwrap_or(0)
}

/// 1 iff some exception has a `script_sha256` facet that could apply to
/// `script` (so the glue should hash the file); else 0. NULL / panic is 0.
///
/// # Safety
/// `ctx` NULL or live; `script` NULL or valid for `script_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn howdah_exceptions_want_hash(
    ctx: *mut howdah_ctx,
    script: *const c_char,
    script_len: usize,
) -> i32 {
    if ctx.is_null() {
        return 0;
    }
    catch_unwind(AssertUnwindSafe(|| {
        if (*ctx).exceptions.is_empty() || script.is_null() || script_len == 0 {
            return 0; // nothing to hash for: no copy, no walk
        }
        let s = copy_str(script, script_len);
        i32::from((*ctx).exceptions.want_hash(&s))
    }))
    .unwrap_or(0)
}

/// `howdah_sink_check` plus the executing script (as PHP reports it) and an
/// optional SHA-256 (`sha256_len` must be 32, else ignored).
///
/// # Safety
/// `ctx` NULL or live; every pointer NULL or valid for its length.
#[no_mangle]
pub unsafe extern "C" fn howdah_sink_check_at(
    ctx: *mut howdah_ctx,
    sink: i32,
    name: *const c_char,
    name_len: usize,
    arg: *const c_char,
    arg_len: usize,
    script: *const c_char,
    script_len: usize,
    sha256: *const u8,
    sha256_len: usize,
) -> i32 {
    if ctx.is_null() {
        return HOWDAH_ALLOW;
    }
    let id = match sink {
        HOWDAH_SINK_COMMAND_EXEC => SinkId::CommandExec,
        HOWDAH_SINK_INCLUDE => SinkId::Include,
        HOWDAH_SINK_EVAL => SinkId::Eval,
        HOWDAH_SINK_UNSERIALIZE => SinkId::Unserialize,
        HOWDAH_SINK_PHAR => SinkId::Phar,
        // Legacy-era sinks (1.5) route through here too (the glue calls the
        // `_at` variant for every one-argument sink).
        HOWDAH_SINK_PREG_EVAL => SinkId::PregEval,
        HOWDAH_SINK_CREATE_FUNCTION => SinkId::CreateFunction,
        HOWDAH_SINK_ASSERT => SinkId::Assert,
        HOWDAH_SINK_CALLBACK => SinkId::Callback,
        HOWDAH_SINK_XML => SinkId::Xml,
        HOWDAH_SINK_TLS => SinkId::Tls,
        _ => return HOWDAH_ALLOW,
    };
    let r = catch_unwind(AssertUnwindSafe(|| {
        let n: &[u8] = if name.is_null() || name_len == 0 {
            &[]
        } else {
            std::slice::from_raw_parts(name as *const u8, name_len)
        };
        let a: &[u8] = if arg.is_null() || arg_len == 0 {
            &[]
        } else {
            std::slice::from_raw_parts(arg as *const u8, arg_len)
        };
        let s = copy_script(script, script_len);
        let h = copy_sha(sha256, sha256_len);
        code((*ctx).sink_check(id, n, a, s.as_deref(), h.as_ref()))
    }));
    r.unwrap_or_else(|_| {
        report_panic(ctx);
        HOWDAH_ALLOW
    })
}

/// Store the runtime `session.save_path` and `error_log` for the include/open
/// poisonable-local-target firewall (the glue reads them from PHP's ini). An
/// empty value (NULL / 0 len) clears the slot, so that category simply does not
/// fire. NULL ctx or panic is a no-op. Scanned, never logged.
///
/// # Safety
/// `ctx` NULL or live; each pointer NULL or valid for its length.
#[no_mangle]
pub unsafe extern "C" fn howdah_set_runtime_paths(
    ctx: *mut howdah_ctx,
    session: *const c_char,
    session_len: usize,
    error_log: *const c_char,
    error_log_len: usize,
) {
    if ctx.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| {
        (*ctx).session_save_path = copy_str(session, session_len);
        (*ctx).error_log = copy_str(error_log, error_log_len);
    }));
}

/// 1 iff the file-op hub is armed: the include/open wrapper-or-poison firewall
/// (either mode not off), or a T5 guard that shares it (the delete guard or the
/// secret-read guard). The glue reads this once per process to decide whether to
/// install the file-op trampolines; NULL ctx or panic is 0.
///
/// # Safety
/// `ctx` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn howdah_sink_open_armed(ctx: *mut howdah_ctx) -> i32 {
    if ctx.is_null() {
        return 0;
    }
    catch_unwind(AssertUnwindSafe(|| {
        let c = &*ctx;
        let g = c.config.mode;
        let b = &c.config.behavior;
        i32::from(
            c.config.sinks.include_wrapper_mode(g) != Mode::Off
                || c.config.sinks.include_poison_mode(g) != Mode::Off
                // T5: the delete (unlink/rmdir) and secret-read guards share the
                // file-op hub, so arming either arms the hub.
                || b.delete_guard_mode(g) != Mode::Off
                || b.secret_read_mode(g) != Mode::Off,
        )
    }))
    .unwrap_or(0)
}

/// File-op hub check: the T4 file-open firewall for fopen / file_get_contents /
/// readfile, plus the T5 Layer-4 guards (delete for unlink/rmdir/rename-source,
/// secret-read for read opens). `name` is the guarded function, `target` the
/// path/URL argument (scanned, never logged), `op` a `HOWDAH_FILE_OP_*` class,
/// `script`/`line` the calling PHP script and line (logged on a Layer-4 hit and
/// matched by `[[exceptions]]` `script` facets), `sha256` as the other `_at`
/// entry points. Returns 0 Allow / 1 Log / 2 Block; NULL ctx or panic is 0
/// (fail-open). A hit is retrievable with `howdah_take_sink_log_line`.
///
/// # Safety
/// `ctx` NULL or live; every pointer NULL or valid for its length.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn howdah_sink_check_open_at(
    ctx: *mut howdah_ctx,
    name: *const c_char,
    name_len: usize,
    target: *const c_char,
    target_len: usize,
    op: i32,
    script: *const c_char,
    script_len: usize,
    sha256: *const u8,
    sha256_len: usize,
    line: u32,
) -> i32 {
    if ctx.is_null() {
        return HOWDAH_ALLOW;
    }
    let r = catch_unwind(AssertUnwindSafe(|| {
        let slice = |p: *const c_char, n: usize| -> &[u8] {
            if p.is_null() || n == 0 {
                &[]
            } else {
                std::slice::from_raw_parts(p as *const u8, n)
            }
        };
        let h = copy_sha(sha256, sha256_len);
        code((*ctx).open_check(
            slice(name, name_len),
            slice(target, target_len),
            op,
            slice(script, script_len),
            line,
            h.as_ref(),
        ))
    }));
    r.unwrap_or_else(|_| {
        report_panic(ctx);
        HOWDAH_ALLOW
    })
}

/// `howdah_sink_check_ssrf` plus the executing script and optional SHA-256.
///
/// # Safety
/// As `howdah_sink_check_ssrf`; `script`/`sha256` NULL or valid for their lengths.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn howdah_sink_check_ssrf_at(
    ctx: *mut howdah_ctx,
    scheme: *const c_char,
    scheme_len: usize,
    host: *const c_char,
    host_len: usize,
    port: u16,
    ips: *const u8,
    ips_count: usize,
    script: *const c_char,
    script_len: usize,
    sha256: *const u8,
    sha256_len: usize,
) -> i32 {
    if ctx.is_null() {
        return HOWDAH_ALLOW;
    }
    let r = catch_unwind(AssertUnwindSafe(|| {
        let sl = |p: *const c_char, n: usize| -> &[u8] {
            if p.is_null() || n == 0 {
                &[]
            } else {
                std::slice::from_raw_parts(p as *const u8, n)
            }
        };
        let recs: &[u8] = if ips.is_null() || ips_count == 0 {
            &[]
        } else {
            match ips_count.checked_mul(17) {
                Some(total) if total <= (1 << 24) => std::slice::from_raw_parts(ips, total),
                _ => return HOWDAH_ALLOW,
            }
        };
        let s = copy_script(script, script_len);
        let h = copy_sha(sha256, sha256_len);
        code((*ctx).sink_check_ssrf(
            sl(scheme, scheme_len),
            sl(host, host_len),
            port,
            recs,
            s.as_deref(),
            h.as_ref(),
        ))
    }));
    r.unwrap_or_else(|_| {
        report_panic(ctx);
        HOWDAH_ALLOW
    })
}

/// `howdah_sink_ssrf_oversize` plus the executing script and optional SHA-256.
///
/// # Safety
/// `ctx` NULL or live; pointers NULL or valid for their lengths.
#[no_mangle]
pub unsafe extern "C" fn howdah_sink_ssrf_oversize_at(
    ctx: *mut howdah_ctx,
    script: *const c_char,
    script_len: usize,
    sha256: *const u8,
    sha256_len: usize,
) -> i32 {
    if ctx.is_null() {
        return HOWDAH_ALLOW;
    }
    catch_unwind(AssertUnwindSafe(|| {
        let s = copy_script(script, script_len);
        let h = copy_sha(sha256, sha256_len);
        code((*ctx).sink_ssrf_oversize(s.as_deref(), h.as_ref()))
    }))
    .unwrap_or(HOWDAH_ALLOW)
}

/// `howdah_sink_ssrf_oversize_at` for an SSRF event `kind` (`HOWDAH_SSRF_KIND_*`):
/// a redirect hop whose host is longer than the resolver buffer is judged by the
/// `redirect` mode, not the range `mode`. 0 Allow / 1 Log / 2 Block; NULL ctx or
/// a panic is 0. The host bytes are never logged.
///
/// # Safety
/// `ctx` NULL or live; pointers NULL or valid for their lengths.
#[no_mangle]
pub unsafe extern "C" fn howdah_sink_ssrf_oversize_kind_at(
    ctx: *mut howdah_ctx,
    kind: i32,
    script: *const c_char,
    script_len: usize,
    sha256: *const u8,
    sha256_len: usize,
) -> i32 {
    if ctx.is_null() {
        return HOWDAH_ALLOW;
    }
    catch_unwind(AssertUnwindSafe(|| {
        let s = copy_script(script, script_len);
        let h = copy_sha(sha256, sha256_len);
        code((*ctx).sink_ssrf_oversize_kind(kind, s.as_deref(), h.as_ref()))
    }))
    .unwrap_or(HOWDAH_ALLOW)
}

/// Which parts of the SSRF hardening are armed, as a `HOWDAH_SSRF_ARM_*` mask
/// (0 = nothing: the shim chains with zero overhead). RANGE is the original
/// `[sinks.ssrf] mode`; REBIND / SCHEME / REDIRECT are the three hardening
/// knobs; PIN and PROTOCOLS add that the rebind / scheme knob is `block` (the
/// shim may then also set `CURLOPT_RESOLVE` / `CURLOPT_PROTOCOLS`). NULL ctx or
/// a panic is 0. Never stashes a log line.
///
/// # Safety
/// `ctx` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn howdah_ssrf_armed_mask(ctx: *mut howdah_ctx) -> i32 {
    if ctx.is_null() {
        return 0;
    }
    catch_unwind(AssertUnwindSafe(|| {
        let c = &*ctx;
        let sinks = &c.config.sinks;
        let mut m = 0;
        if sinks.effective_mode(SinkId::Ssrf, c.config.mode) != Mode::Off {
            m |= HOWDAH_SSRF_ARM_RANGE;
        }
        match sinks.ssrf_rebind_mode(c.config.mode) {
            Mode::Off => {}
            Mode::Detect => m |= HOWDAH_SSRF_ARM_REBIND,
            Mode::Block => m |= HOWDAH_SSRF_ARM_REBIND | HOWDAH_SSRF_ARM_PIN,
        }
        match sinks.ssrf_scheme_mode(c.config.mode) {
            Mode::Off => {}
            Mode::Detect => m |= HOWDAH_SSRF_ARM_SCHEME,
            Mode::Block => m |= HOWDAH_SSRF_ARM_SCHEME | HOWDAH_SSRF_ARM_PROTOCOLS,
        }
        if sinks.ssrf_redirect_mode(c.config.mode) != Mode::Off {
            m |= HOWDAH_SSRF_ARM_REDIRECT;
        }
        m
    }))
    .unwrap_or(0)
}

/// SSRF verdict of a given kind (`HOWDAH_SSRF_KIND_*`) plus the executing
/// script and optional SHA-256: the connect-time (REBIND) and redirect-hop
/// (REDIRECT) variants of `howdah_sink_check_ssrf_at`. `ips` is `ips_count` x
/// 17-byte records. 0 Allow / 1 Log / 2 Block; NULL ctx, malformed input or a
/// panic is 0 (fail-open).
///
/// # Safety
/// As `howdah_sink_check_ssrf_at`.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn howdah_sink_check_ssrf_kind_at(
    ctx: *mut howdah_ctx,
    kind: i32,
    scheme: *const c_char,
    scheme_len: usize,
    host: *const c_char,
    host_len: usize,
    port: u16,
    ips: *const u8,
    ips_count: usize,
    script: *const c_char,
    script_len: usize,
    sha256: *const u8,
    sha256_len: usize,
) -> i32 {
    if ctx.is_null() {
        return HOWDAH_ALLOW;
    }
    let r = catch_unwind(AssertUnwindSafe(|| {
        let sl = |p: *const c_char, n: usize| -> &[u8] {
            if p.is_null() || n == 0 {
                &[]
            } else {
                std::slice::from_raw_parts(p as *const u8, n)
            }
        };
        let recs: &[u8] = if ips.is_null() || ips_count == 0 {
            &[]
        } else {
            match ips_count.checked_mul(17) {
                Some(total) if total <= (1 << 24) => std::slice::from_raw_parts(ips, total),
                _ => return HOWDAH_ALLOW,
            }
        };
        let s = copy_script(script, script_len);
        let h = copy_sha(sha256, sha256_len);
        code((*ctx).sink_check_ssrf_kind(
            kind,
            sl(scheme, scheme_len),
            sl(host, host_len),
            port,
            recs,
            s.as_deref(),
            h.as_ref(),
        ))
    }));
    r.unwrap_or_else(|_| {
        report_panic(ctx);
        HOWDAH_ALLOW
    })
}

/// Egress-scheme verdict for a URL (`via`: `HOWDAH_SSRF_VIA_STREAM` /
/// `HOWDAH_SSRF_VIA_CURL`) plus the executing script and optional SHA-256. 0
/// Allow / 1 Log / 2 Block per `[sinks.ssrf] scheme`; the log line carries the
/// scheme category only. NULL ctx or a panic is 0.
///
/// # Safety
/// `ctx` NULL or live; pointers NULL or valid for their lengths.
#[no_mangle]
pub unsafe extern "C" fn howdah_sink_ssrf_scheme_at(
    ctx: *mut howdah_ctx,
    via: i32,
    url: *const c_char,
    url_len: usize,
    script: *const c_char,
    script_len: usize,
    sha256: *const u8,
    sha256_len: usize,
) -> i32 {
    if ctx.is_null() || url.is_null() {
        return HOWDAH_ALLOW;
    }
    let r = catch_unwind(AssertUnwindSafe(|| {
        let u = std::slice::from_raw_parts(url as *const u8, url_len);
        let s = copy_script(script, script_len);
        let h = copy_sha(sha256, sha256_len);
        code((*ctx).sink_ssrf_scheme(via, u, s.as_deref(), h.as_ref()))
    }));
    r.unwrap_or_else(|_| {
        report_panic(ctx);
        HOWDAH_ALLOW
    })
}

/// Build the `CURLOPT_RESOLVE` entry that pins `input`'s hostname (an HTTP(S) or
/// scheme-less curl URL) to the validated IPv4 addresses in `recs`
/// (`recs_count` x 17-byte records), writing `host:port:ip[,ip...]` (no NUL) to
/// `out`. `multi != 0` allows a comma list (libcurl 7.59+), else only the first
/// address is pinned. Returns the byte count written, or 0 when there is
/// nothing safe to pin (literal-IP host, non-HTTP(S) URL, IPv6-only/unresolved
/// host, odd host spelling, or `out_cap` too small). NULL arguments or a panic
/// is 0. Pure: no ctx, no logging.
///
/// # Safety
/// `input` valid for `input_len`; `recs` NULL or valid for `recs_count * 17`
/// bytes; `out` writable for `out_cap` bytes.
#[no_mangle]
pub unsafe extern "C" fn howdah_ssrf_pin_entry(
    input: *const u8,
    input_len: usize,
    recs: *const u8,
    recs_count: usize,
    multi: i32,
    out: *mut u8,
    out_cap: usize,
) -> usize {
    if input.is_null() || out.is_null() {
        return 0;
    }
    catch_unwind(AssertUnwindSafe(|| {
        let r: &[u8] = if recs.is_null() || recs_count == 0 {
            &[]
        } else {
            match recs_count.checked_mul(17) {
                Some(total) if total <= (1 << 24) => std::slice::from_raw_parts(recs, total),
                _ => return 0,
            }
        };
        let Some(e) = resolve_pin_entry(std::slice::from_raw_parts(input, input_len), r, multi != 0) else {
            return 0;
        };
        if e.len() > out_cap {
            return 0;
        }
        std::ptr::copy_nonoverlapping(e.as_ptr(), out, e.len());
        e.len()
    }))
    .unwrap_or(0)
}

/// `howdah_behavior_check_exec_dir` plus an optional SHA-256 of the file at
/// `path` (the executing script for this check is the file itself).
///
/// # Safety
/// `ctx` NULL or live; pointers NULL or valid for their lengths.
#[no_mangle]
pub unsafe extern "C" fn howdah_behavior_check_exec_dir_at(
    ctx: *mut howdah_ctx,
    path: *const c_char,
    path_len: usize,
    sha256: *const u8,
    sha256_len: usize,
) -> i32 {
    if ctx.is_null() {
        return HOWDAH_ALLOW;
    }
    catch_unwind(AssertUnwindSafe(|| {
        let p = copy_str(path, path_len);
        let h = copy_sha(sha256, sha256_len);
        let s = (!p.is_empty()).then_some(p.as_str());
        code((*ctx).behavior_check(|cfg| crate::behavior::exec_dir_hit(&p, cfg), s, h.as_ref()))
    }))
    .unwrap_or_else(|_| {
        report_panic(ctx);
        HOWDAH_ALLOW
    })
}

/// `howdah_behavior_check_binary` plus an optional SHA-256 of `caller`.
///
/// # Safety
/// `ctx` NULL or live; pointers NULL or valid for their lengths.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn howdah_behavior_check_binary_at(
    ctx: *mut howdah_ctx,
    caller: *const c_char,
    caller_len: usize,
    prog: *const c_char,
    prog_len: usize,
    sha256: *const u8,
    sha256_len: usize,
) -> i32 {
    if ctx.is_null() {
        return HOWDAH_ALLOW;
    }
    catch_unwind(AssertUnwindSafe(|| {
        let c = copy_str(caller, caller_len);
        let p = copy_str(prog, prog_len);
        let h = copy_sha(sha256, sha256_len);
        let s = (!c.is_empty()).then_some(c.as_str());
        code((*ctx).behavior_check(|cfg| crate::behavior::binary_hit(&c, &p, cfg), s, h.as_ref()))
    }))
    .unwrap_or_else(|_| {
        report_panic(ctx);
        HOWDAH_ALLOW
    })
}

/// `howdah_behavior_check_egress` plus an optional SHA-256 of `caller`.
///
/// # Safety
/// `ctx` NULL or live; pointers NULL or valid for their lengths.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn howdah_behavior_check_egress_at(
    ctx: *mut howdah_ctx,
    caller: *const c_char,
    caller_len: usize,
    host: *const c_char,
    host_len: usize,
    sha256: *const u8,
    sha256_len: usize,
) -> i32 {
    if ctx.is_null() {
        return HOWDAH_ALLOW;
    }
    catch_unwind(AssertUnwindSafe(|| {
        let c = copy_str(caller, caller_len);
        let hst = copy_str(host, host_len);
        let h = copy_sha(sha256, sha256_len);
        let s = (!c.is_empty()).then_some(c.as_str());
        code((*ctx).behavior_check(|cfg| crate::behavior::egress_hit(&c, &hst, cfg), s, h.as_ref()))
    }))
    .unwrap_or_else(|_| {
        report_panic(ctx);
        HOWDAH_ALLOW
    })
}

/// `howdah_behavior_check_php_write` plus an optional SHA-256 of `caller` and the
/// `line` of the call in `caller` (0 = unknown; logged as `file:line`).
///
/// # Safety
/// `ctx` NULL or live; pointers NULL or valid for their lengths.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn howdah_behavior_check_php_write_at(
    ctx: *mut howdah_ctx,
    caller: *const c_char,
    caller_len: usize,
    target: *const c_char,
    target_len: usize,
    is_write_mode: i32,
    sha256: *const u8,
    sha256_len: usize,
    line: u32,
) -> i32 {
    if ctx.is_null() {
        return HOWDAH_ALLOW;
    }
    catch_unwind(AssertUnwindSafe(|| {
        let c = copy_str(caller, caller_len);
        let t = copy_str(target, target_len);
        let h = copy_sha(sha256, sha256_len);
        let s = (!c.is_empty()).then_some(c.as_str());
        let op = crate::behavior::WriteOp::from_code(is_write_mode);
        let org = crate::behavior::Origin { file: &c, line };
        code((*ctx).behavior_check(
            |cfg| crate::behavior::php_write_hit(org, &t, op, cfg),
            s,
            h.as_ref(),
        ))
    }))
    .unwrap_or_else(|_| {
        report_panic(ctx);
        HOWDAH_ALLOW
    })
}

// ---- include/eval hook selection (`[sinks] hook`; JIT compatibility) -------
// Appended after the [[exceptions]] `_at` entry points (append-only file).

// Mechanism half of `howdah_sink_hook_plan` (low nibble).
/// Install nothing (nothing armed needs the hook; JIT stays on).
pub const HOWDAH_HOOK_PLAN_NONE: i32 = 0;
/// Install the `ZEND_INCLUDE_OR_EVAL` user opcode handler.
pub const HOWDAH_HOOK_PLAN_OPCODE: i32 = 1;
/// Install the `zend_compile_file`/`zend_compile_string` pointer swap.
pub const HOWDAH_HOOK_PLAN_COMPILE: i32 = 2;
// Reason half (`plan >> 4`), for the phpinfo row.
pub const HOWDAH_HOOK_WHY_CONFIGURED: i32 = 0;
pub const HOWDAH_HOOK_WHY_EVAL_ONLY: i32 = 1;
pub const HOWDAH_HOOK_WHY_INCLUDE_ALLOW_PATHS: i32 = 2;
pub const HOWDAH_HOOK_WHY_DENY_EXEC_DIRS: i32 = 3;
pub const HOWDAH_HOOK_WHY_INCLUDE_FIREWALL: i32 = 4;

/// The startup plan for the include/eval hook: `mechanism | (reason << 4)`
/// with the `HOWDAH_HOOK_PLAN_*` / `HOWDAH_HOOK_WHY_*` codes. Mechanism
/// `NONE` means nothing armed needs the hook (the Layer-3 `eval`/`include`
/// verdict combined with Layer 4's `deny_exec_dirs`, which the plan takes
/// from `howdah_behavior_armed`); otherwise what `[sinks] hook` resolves to
/// (`auto`, the default: compile when only eval needs it, opcode when include
/// has `allow_paths` or `deny_exec_dirs` is set). NULL ctx or panic is `NONE`
/// (install nothing: the fail-open direction for a startup decision that only
/// adds visibility). Never stashes a log line. The only hook-selection export;
/// the glue reads nothing else for this decision.
///
/// # Safety
/// `ctx` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn howdah_sink_hook_plan(ctx: *mut howdah_ctx) -> i32 {
    use crate::config::{HookReason, SinkHook};
    if ctx.is_null() {
        return HOWDAH_HOOK_PLAN_NONE;
    }
    let l4 = howdah_behavior_armed(ctx, HOWDAH_BEHAVIOR_EXEC_DIR) != 0;
    catch_unwind(AssertUnwindSafe(|| {
        let c = &*ctx;
        match c.config.sinks.include_eval_hook_plan(c.config.mode, l4) {
            None => HOWDAH_HOOK_PLAN_NONE,
            Some((mech, why)) => {
                let m = match mech {
                    SinkHook::Compile => HOWDAH_HOOK_PLAN_COMPILE,
                    SinkHook::Opcode | SinkHook::Auto => HOWDAH_HOOK_PLAN_OPCODE,
                };
                let w = match why {
                    HookReason::Configured => HOWDAH_HOOK_WHY_CONFIGURED,
                    HookReason::EvalOnly => HOWDAH_HOOK_WHY_EVAL_ONLY,
                    HookReason::IncludeAllowPaths => HOWDAH_HOOK_WHY_INCLUDE_ALLOW_PATHS,
                    HookReason::DenyExecDirs => HOWDAH_HOOK_WHY_DENY_EXEC_DIRS,
                    HookReason::IncludeFirewall => HOWDAH_HOOK_WHY_INCLUDE_FIREWALL,
                };
                m | (w << 4)
            }
        }
    }))
    .unwrap_or(HOWDAH_HOOK_PLAN_NONE)
}

// ---- legacy-era sinks (1.5) -----------------------------------------------

/// `mail()` sink check. `headers` is the 4th argument when it is a string
/// (NULL/0 otherwise), `params` the 5th. Both are scanned, never logged.
/// Returns 0 Allow / 1 Log / 2 Block; NULL ctx or panic is 0 (fail-open). A
/// hit is retrievable with `howdah_take_sink_log_line`.
///
/// # Safety
/// `ctx` NULL or live; `headers`/`params` NULL or valid for their lengths.
#[no_mangle]
pub unsafe extern "C" fn howdah_sink_check_mail(
    ctx: *mut howdah_ctx,
    headers: *const c_char,
    headers_len: usize,
    params: *const c_char,
    params_len: usize,
) -> i32 {
    if ctx.is_null() {
        return HOWDAH_ALLOW;
    }
    let r = catch_unwind(AssertUnwindSafe(|| {
        let sl = |p: *const c_char, n: usize| -> &[u8] {
            if p.is_null() || n == 0 {
                &[]
            } else {
                std::slice::from_raw_parts(p as *const u8, n)
            }
        };
        code((*ctx).sink_check_mail(sl(headers, headers_len), sl(params, params_len)))
    }));
    r.unwrap_or_else(|_| {
        report_panic(ctx);
        HOWDAH_ALLOW
    })
}

/// XML sink check (`xxe`), flag-aware: `doc` is the XML string about to be
/// parsed (`simplexml_load_string`, `DOMDocument::loadXML`, `new
/// SimpleXMLElement`, `XMLReader::XML`), `flags` the libxml option mask the call
/// passes (0 when absent), `caps` a `HOWDAH_XML_*` bit set, `script`/`sha256` the
/// executing script for `[[exceptions]]`. Scanned, never logged. Returns 0
/// Allow / 1 Log / 2 Block, or 3 (`HOWDAH_STRIP`) to neutralize by removing
/// the dangerous flags from the options argument and continuing; a strip is
/// logged as `block`. Nothing fires without a dangerous flag AND an external
/// entity (or entity bomb) together. NULL ctx or panic is 0 (fail-open). A hit
/// is retrievable with `howdah_take_sink_log_line`.
///
/// # Safety
/// `ctx` NULL or live; every pointer NULL or valid for its length.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn howdah_sink_check_xml(
    ctx: *mut howdah_ctx,
    name: *const c_char,
    name_len: usize,
    doc: *const c_char,
    doc_len: usize,
    flags: i64,
    caps: i32,
    script: *const c_char,
    script_len: usize,
    sha256: *const u8,
    sha256_len: usize,
) -> i32 {
    if ctx.is_null() {
        return HOWDAH_ALLOW;
    }
    let r = catch_unwind(AssertUnwindSafe(|| {
        let sl = |p: *const c_char, n: usize| -> &[u8] {
            if p.is_null() || n == 0 {
                &[]
            } else {
                std::slice::from_raw_parts(p as *const u8, n)
            }
        };
        let s = copy_script(script, script_len);
        let h = copy_sha(sha256, sha256_len);
        let (action, strip) =
            (*ctx).sink_check_xml(sl(name, name_len), sl(doc, doc_len), flags, caps, s.as_deref(), h.as_ref());
        if strip {
            HOWDAH_STRIP
        } else {
            code(action)
        }
    }));
    r.unwrap_or_else(|_| {
        report_panic(ctx);
        HOWDAH_ALLOW
    })
}

/// 1 iff `[sinks.xml] external_entities = "deny"` is in force (set, global
/// mode not off, sinks enabled); the glue then turns libxml's external
/// entity loader off at every request start. NULL ctx or panic is 0.
///
/// # Safety
/// `ctx` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn howdah_sink_xml_deny_external_entities(ctx: *mut howdah_ctx) -> i32 {
    if ctx.is_null() {
        return 0;
    }
    catch_unwind(AssertUnwindSafe(|| {
        let c = &*ctx;
        i32::from(c.config.sinks.xml_deny_external_entities(c.config.mode))
    }))
    .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::ffi::CStr;

    thread_local! {
        pub(super) static FORCE_PANIC: Cell<bool> = const { Cell::new(false) };
    }

    const BODY: &[u8] = b"--B\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nx\r\n--B--\r\n";

    fn init(toml: &str) -> *mut howdah_ctx {
        unsafe { howdah_init(toml.as_ptr() as *const c_char, toml.len()) }
    }
    fn begin(c: *mut howdah_ctx) {
        let (ip, m, u) = ("1.2.3.4", "POST", "/up");
        let meta = RequestMeta {
            client_ip: ip.as_ptr() as _,
            client_ip_len: ip.len(),
            method: m.as_ptr() as _,
            method_len: m.len(),
            uri: u.as_ptr() as _,
            uri_len: u.len(),
        };
        unsafe { howdah_request_begin(c, b"B".as_ptr() as _, 1, &meta) };
    }
    fn feed(c: *mut howdah_ctx, b: &[u8]) -> i32 {
        unsafe { howdah_feed(c, b.as_ptr() as _, b.len()) }
    }
    fn take(c: *mut howdah_ctx) -> Option<String> {
        unsafe {
            let p = howdah_take_log_line(c);
            if p.is_null() {
                return None;
            }
            let s = CStr::from_ptr(p).to_string_lossy().into_owned();
            howdah_free_str(p);
            Some(s)
        }
    }

    #[test]
    fn selftest_logs_in_detect_and_never_blocks_even_in_block_mode() {
        for mode in ["detect", "block"] {
            let c = init(&format!("mode = \"{mode}\""));
            begin(c);
            feed(c, BODY);
            assert_eq!(unsafe { howdah_selftest(c) }, HOWDAH_LOG, "{mode}");
            let line = take(c).expect("self_test line");
            assert!(line.contains("\"rule\":\"self_test\""), "{line}");
            assert!(line.contains("\"action\":\"log\""), "{line}");
            assert_eq!(unsafe { howdah_request_end(c) }, HOWDAH_LOG);
            unsafe { howdah_free(c) };
        }
    }

    #[test]
    fn selftest_silent_when_off_and_null_safe() {
        let c = init("mode = \"off\"");
        begin(c);
        assert_eq!(unsafe { howdah_selftest(c) }, HOWDAH_ALLOW);
        assert!(take(c).is_none());
        unsafe { howdah_free(c) };
        assert_eq!(unsafe { howdah_selftest(std::ptr::null_mut()) }, HOWDAH_ALLOW);
    }

    #[test]
    fn selftest_then_real_standard_hit_logs_the_real_rule() {
        let c = init("mode = \"detect\"");
        begin(c);
        feed(c, BODY);
        assert_eq!(unsafe { howdah_selftest(c) }, HOWDAH_LOG);
        // Malformed continuation (garbage after a delimiter) then truncation.
        feed(c, b"--Bzzz");
        unsafe { howdah_request_end(c) };
        let line = take(c).unwrap();
        assert!(line.contains("malformed_multipart"), "{line}");
        assert!(!line.contains("self_test"), "{line}");
        unsafe { howdah_free(c) };
    }

    #[test]
    fn selftest_after_real_log_hit_preserves_it() {
        let c = init("mode = \"detect\"");
        begin(c);
        feed(c, b"--B\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nx");
        unsafe { howdah_request_end(c) }; // truncated -> malformed Log
        unsafe { howdah_selftest(c) };
        let line = take(c).unwrap();
        assert!(line.contains("malformed_multipart"), "{line}");
        unsafe { howdah_free(c) };
    }

    #[test]
    fn selftest_does_not_mask_a_block() {
        let c = init("mode = \"detect\"\n[limits]\nmax_parts = 1");
        begin(c);
        let two = b"--B\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nx\r\n--B\r\nContent-Disposition: form-data; name=\"b\"\r\n\r\nx\r\n";
        assert_eq!(feed(c, two), HOWDAH_BLOCK);
        assert_eq!(unsafe { howdah_selftest(c) }, HOWDAH_BLOCK);
        assert!(take(c).unwrap().contains("max_parts"));
        unsafe { howdah_free(c) };
    }

    #[test]
    fn action_codes_pinned() {
        assert_eq!(code(Action::Allow), 0);
        assert_eq!(code(Action::Log), 1);
        assert_eq!(code(Action::Block), 2);
    }

    #[test]
    fn clean_body_allows() {
        let c = init("");
        begin(c);
        assert_eq!(feed(c, BODY), 0);
        assert_eq!(unsafe { howdah_request_end(c) }, 0);
        assert!(take(c).is_none());
        unsafe { howdah_free(c) };
    }

    #[test]
    fn critical_limit_blocks_and_logs_json() {
        let c = init("[limits]\nmax_parts = 1\n");
        begin(c);
        let body = b"--B\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nx\r\n--B\r\nContent-Disposition: form-data; name=\"b\"\r\n\r\ny\r\n--B--\r\n";
        assert_eq!(feed(c, body), 2);
        let line = take(c).expect("log line");
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["action"], "block");
        assert_eq!(v["rule"], "max_parts");
        assert_eq!(v["client_ip"], "1.2.3.4");
        assert_eq!(v["uri"], "/up");
        let rid = unsafe { (*c).request_id.clone() };
        assert_eq!(v["request_id"].as_str().unwrap(), rid);
        assert!(take(c).is_none(), "line is taken once");
        assert_eq!(feed(c, b"more"), 2, "block is sticky");
        begin(c);
        assert_ne!(unsafe { (*c).request_id.clone() }, rid);
        assert_eq!(feed(c, BODY), 0, "new request resets");
        unsafe { howdah_free(c) };
    }

    #[test]
    fn malformed_is_standard_so_blocks_only_in_block_mode() {
        let bad = b"--B\r\nnot a header line\r\n\r\nx";
        let c = init("mode = \"detect\"\n");
        begin(c);
        assert_eq!(feed(c, bad), 1);
        assert!(take(c).unwrap().contains("malformed_multipart"));
        unsafe { howdah_free(c) };
        let c = init("mode = \"block\"\n");
        begin(c);
        assert_eq!(feed(c, bad), 2);
        unsafe { howdah_free(c) };
    }

    #[test]
    fn truncated_body_detected_at_request_end() {
        let c = init("");
        begin(c);
        assert_eq!(feed(c, &BODY[..BODY.len() - 8]), 0);
        assert_eq!(unsafe { howdah_request_end(c) }, 2);
        assert!(take(c).unwrap().contains("malformed_multipart"));
        unsafe { howdah_free(c) };
    }

    #[test]
    fn invalid_toml_falls_back_to_safe_defaults() {
        for c in [init("this is = = not toml"), unsafe { howdah_init(std::ptr::null(), 0) }] {
            assert!(!c.is_null());
            unsafe { assert!((*c).config == Config::safe_defaults()) };
            begin(c);
            assert_eq!(feed(c, BODY), 0);
            unsafe { howdah_free(c) };
        }
    }

    #[test]
    fn panic_is_caught_and_fails_open() {
        let c = init("");
        begin(c);
        FORCE_PANIC.with(|f| f.set(true));
        assert_eq!(feed(c, BODY), 0);
        assert_eq!(unsafe { howdah_request_end(c) }, 0);
        FORCE_PANIC.with(|f| f.set(false));
        let line = take(c).expect("panic noted in log");
        assert!(line.contains("panic caught"));
        begin(c);
        assert_eq!(feed(c, BODY), 0, "ctx usable after a caught panic");
        unsafe { howdah_free(c) };
    }

    #[test]
    fn input_var_flood_blocks_and_logs_json() {
        let c = init("[limits]\nmax_input_vars = 2\n");
        begin(c);
        for n in ["a", "b", "c"] {
            unsafe { howdah_input_var(c, n.as_ptr() as _, n.len()) };
        }
        let line = take(c).unwrap();
        assert!(line.contains("\"rule\":\"max_input_vars\""), "{line}");
        assert!(line.contains("\"action\":\"block\""), "{line}");
        unsafe { howdah_free(c) };
    }

    #[test]
    fn new_entrypoints_null_and_panic_safe() {
        assert_eq!(unsafe { howdah_input_var(std::ptr::null_mut(), std::ptr::null(), 0) }, 0);
        assert_eq!(unsafe { howdah_request_header(std::ptr::null_mut(), 0, 0) }, 0);
        let c = init("");
        begin(c);
        FORCE_PANIC.with(|f| f.set(true));
        assert_eq!(unsafe { howdah_input_var(c, b"a".as_ptr() as _, 1) }, 0);
        assert_eq!(unsafe { howdah_request_header(c, 1, 1) }, 0);
        FORCE_PANIC.with(|f| f.set(false));
        unsafe { howdah_free(c) };
    }

    #[test]
    fn part_entrypoints_null_and_panic_safe() {
        unsafe {
            assert_eq!(howdah_part(std::ptr::null_mut(), HOWDAH_PART_FILE, 1, 1), 0);
            assert_eq!(howdah_part_data(std::ptr::null_mut(), 1), 0);
            // No request begun: fail-open, no state touched.
            let c = init("");
            assert_eq!(howdah_part(c, HOWDAH_PART_FILE, 1, 1), 0);
            assert_eq!(howdah_part_data(c, 1), 0);
            // A panic inside is caught and fails open, and the ctx stays usable.
            howdah_request_begin(c, std::ptr::null(), 0, std::ptr::null());
            FORCE_PANIC.with(|f| f.set(true));
            assert_eq!(howdah_part(c, HOWDAH_PART_FILE, 1, 1), 0);
            assert_eq!(howdah_part_data(c, 1), 0);
            FORCE_PANIC.with(|f| f.set(false));
            assert!(take(c).expect("panic noted").contains("panic caught"));
            for i in 0..300 {
                howdah_part(c, HOWDAH_PART_FILE, 1, 1);
                assert!(i < 200 || howdah_part(c, HOWDAH_PART_FILE, 1, 1) == 2, "part {i}");
            }
            howdah_free(c);
        }
    }

    fn inspect(c: *mut howdah_ctx, src: i32, name: &str, val: &[u8]) -> i32 {
        unsafe { howdah_inspect_value(c, src, name.as_ptr() as _, name.len(), val.as_ptr() as _, val.len()) }
    }

    #[test]
    fn inspect_logs_under_global_block_when_inspect_detect() {
        let c = init("mode = \"block\"");
        begin(c);
        assert_eq!(inspect(c, HOWDAH_SRC_GET, "q", b"' OR 1=1 --"), HOWDAH_LOG);
        let line = take(c).expect("log line");
        assert!(line.contains("\"rule\":\"sql_injection\""), "{line}");
        assert!(line.contains("\"action\":\"log\""), "{line}");
        assert!(line.contains("sql_injection pattern in get variable 'q'"), "{line}");
        unsafe { howdah_free(c) };
    }

    #[test]
    fn inspect_blocks_only_when_inspect_mode_block() {
        let c = init("[inspect]\nmode = \"block\"");
        begin(c);
        assert_eq!(inspect(c, HOWDAH_SRC_GET, "q", b"' OR 1=1 --"), HOWDAH_BLOCK);
        let line = take(c).expect("log line");
        assert!(line.contains("\"action\":\"block\""), "{line}");
        unsafe { howdah_free(c) };
    }

    #[test]
    fn inspect_log_omits_value() {
        let c = init("");
        begin(c);
        inspect(c, HOWDAH_SRC_POST, "q", b"' OR 1=1 --");
        let line = take(c).expect("log line");
        assert!(line.contains('q') && line.contains("sql_injection"), "{line}");
        assert!(!line.contains("OR 1=1") && !line.contains("1=1"), "{line}");
        unsafe { howdah_free(c) };
    }

    #[test]
    fn inspect_disabled_is_allow() {
        let c = init("[inspect]\nenabled = false");
        begin(c);
        assert_eq!(inspect(c, HOWDAH_SRC_GET, "q", b"' OR 1=1 --"), HOWDAH_ALLOW);
        assert!(take(c).is_none());
        unsafe { howdah_free(c) };
    }

    #[test]
    fn aggregate_budget_caps_total_scan() {
        let c = init("[inspect.limits]\nmax_values = 3");
        begin(c);
        for _ in 0..3 {
            assert_eq!(inspect(c, HOWDAH_SRC_GET, "a", b"hello"), HOWDAH_ALLOW);
        }
        assert_eq!(inspect(c, HOWDAH_SRC_GET, "q", b"' OR 1=1 --"), HOWDAH_ALLOW);
        assert!(take(c).is_none());
        // a new request resets the budget
        begin(c);
        assert_eq!(inspect(c, HOWDAH_SRC_GET, "q", b"' OR 1=1 --"), HOWDAH_LOG);
        unsafe { howdah_free(c) };
    }

    #[test]
    fn global_off_silences_inspect() {
        let c = init("mode = \"off\"");
        begin(c);
        assert_eq!(inspect(c, HOWDAH_SRC_GET, "q", b"' OR 1=1 --"), HOWDAH_ALLOW);
        assert!(take(c).is_none());
        unsafe { howdah_free(c) };
    }

    const CGI_POC: &[u8] = b"%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input";

    fn query(c: *mut howdah_ctx, q: &[u8]) -> i32 {
        unsafe { howdah_inspect_value(c, HOWDAH_SRC_QUERY, std::ptr::null(), 0, q.as_ptr() as _, q.len()) }
    }

    #[test]
    fn cgi_arg_blocks_by_default_in_every_global_mode() {
        // Default global mode is block; the shipped ini default is detect. The
        // other Layer 2 rules only log in both.
        for cfg in ["", "mode = \"block\"", "mode = \"detect\""] {
            let c = init(cfg);
            begin(c);
            assert_eq!(inspect(c, HOWDAH_SRC_GET, "q", b"' OR 1=1 --"), HOWDAH_LOG, "{cfg}");
            unsafe { howdah_request_end(c) };
            take(c);
            begin(c);
            assert_eq!(query(c, CGI_POC), HOWDAH_BLOCK, "{cfg}");
            assert_eq!(query(c, b"-d+allow_url_include%3d1+-d+auto_prepend_file%3dphp://input"), HOWDAH_BLOCK);
            unsafe { howdah_free(c) };
        }
    }

    #[test]
    fn cgi_arg_benign_query_is_allowed_and_logs_nothing() {
        let c = init("");
        begin(c);
        for q in [&b""[..], b"q=search&page=2", b"hello+world", b"-1", b"garc%C3%ADa", b"dGVzdA%3D%3D"] {
            assert_eq!(query(c, q), HOWDAH_ALLOW, "{}", String::from_utf8_lossy(q));
        }
        assert!(take(c).is_none());
        unsafe { howdah_free(c) };
    }

    #[test]
    fn cgi_arg_log_omits_the_query() {
        let c = init("");
        begin(c);
        assert_eq!(query(c, CGI_POC), HOWDAH_BLOCK);
        let line = take(c).expect("log line");
        assert!(line.contains("\"rule\":\"cgi_arg_injection\""), "{line}");
        assert!(line.contains("\"action\":\"block\"") && line.contains("\"layer\":2"), "{line}");
        for leak in ["allow_url_include", "auto_prepend_file", "php://input", "%AD", "%3d"] {
            assert!(!line.contains(leak), "{leak} leaked: {line}");
        }
        unsafe { howdah_free(c) };
    }

    #[test]
    fn cgi_arg_observe_disable_and_master_switches() {
        let detect = init("[inspect]\ncgi_arg = \"detect\"");
        begin(detect);
        assert_eq!(query(detect, CGI_POC), HOWDAH_LOG);
        assert!(take(detect).unwrap().contains("\"action\":\"log\""));
        unsafe { howdah_free(detect) };
        for cfg in [
            "[inspect]\ncgi_arg = \"off\"",
            "[inspect]\nenabled = false",
            "mode = \"off\"",
            "mode = \"off\"\n[inspect.rule_modes]\ncgi_arg_injection = \"block\"",
        ] {
            let c = init(cfg);
            begin(c);
            assert_eq!(query(c, CGI_POC), HOWDAH_ALLOW, "{cfg}");
            assert!(take(c).is_none(), "{cfg}");
            unsafe { howdah_free(c) };
        }
        // The per-class table can also raise an observe-only key back to block.
        let c = init("[inspect]\ncgi_arg = \"detect\"\n[inspect.rule_modes]\ncgi_arg_injection = \"block\"");
        begin(c);
        assert_eq!(query(c, CGI_POC), HOWDAH_BLOCK);
        unsafe { howdah_free(c) };
    }

    #[test]
    fn cgi_arg_is_not_starved_by_the_value_budget() {
        // 2000-variable budget spent on ordinary values, then the attack query.
        let c = init("[inspect.limits]\nmax_values = 3");
        begin(c);
        for _ in 0..5 {
            inspect(c, HOWDAH_SRC_GET, "a", b"hello");
        }
        assert_eq!(inspect(c, HOWDAH_SRC_GET, "q", b"' OR 1=1 --"), HOWDAH_ALLOW, "budget is spent");
        assert_eq!(query(c, CGI_POC), HOWDAH_BLOCK, "the query check is not budgeted");
        unsafe { howdah_free(c) };
    }

    #[test]
    fn cgi_arg_null_ctx_and_panic_are_allow() {
        assert_eq!(unsafe { howdah_inspect_value(std::ptr::null_mut(), HOWDAH_SRC_QUERY, std::ptr::null(), 0, CGI_POC.as_ptr() as _, CGI_POC.len()) }, 0);
        let c = init("");
        begin(c);
        assert_eq!(unsafe { howdah_inspect_value(c, HOWDAH_SRC_QUERY, std::ptr::null(), 0, std::ptr::null(), 0) }, HOWDAH_ALLOW);
        // A panic inside the check is caught and fails open; the ctx stays usable.
        FORCE_PANIC.with(|f| f.set(true));
        assert_eq!(query(c, CGI_POC), HOWDAH_ALLOW);
        FORCE_PANIC.with(|f| f.set(false));
        assert!(take(c).expect("panic noted").contains("panic caught"));
        begin(c);
        assert_eq!(query(c, CGI_POC), HOWDAH_BLOCK, "ctx usable after a caught panic");
        unsafe { howdah_free(c) };
    }

    #[test]
    fn cgi_arg_scoped_exception_by_client_and_uri() {
        // begin() sets client 1.2.3.4 and uri /up.
        let c = init("[[exceptions]]\nrule = \"inspect.cgi_arg_injection\"\nclient_cidr = \"1.2.3.0/24\"\nreason = \"scanner\"\n");
        begin(c);
        assert_eq!(query(c, CGI_POC), HOWDAH_ALLOW);
        unsafe { howdah_free(c) };
        let c = init("[[exceptions]]\nrule = \"inspect.cgi_arg_injection\"\nclient_cidr = \"9.9.9.0/24\"\nreason = \"other\"\n");
        begin(c);
        assert_eq!(query(c, CGI_POC), HOWDAH_BLOCK);
        unsafe { howdah_free(c) };
    }

    #[test]
    fn global_off_overrides_inspect_rule_modes() {
        let c = init("mode = \"off\"\n[inspect.rule_modes]\nsql_injection = \"block\"");
        begin(c);
        assert_eq!(inspect(c, HOWDAH_SRC_GET, "q", b"' OR 1=1 --"), HOWDAH_ALLOW);
        assert!(take(c).is_none());
        unsafe { howdah_free(c) };
    }

    #[test]
    fn inspect_unknown_source_and_null_are_allow() {
        assert_eq!(unsafe { howdah_inspect_value(std::ptr::null_mut(), 0, std::ptr::null(), 0, std::ptr::null(), 0) }, 0);
        let c = init("");
        begin(c);
        assert_eq!(inspect(c, 99, "q", b"' OR 1=1 --"), HOWDAH_ALLOW);
        assert_eq!(unsafe { howdah_inspect_value(c, 0, std::ptr::null(), 0, std::ptr::null(), 0) }, HOWDAH_ALLOW);
        unsafe { howdah_free(c) };
    }

    fn sink(c: *mut howdah_ctx, id: i32, name: &str, arg: &[u8]) -> i32 {
        unsafe { howdah_sink_check(c, id, name.as_ptr() as _, name.len(), arg.as_ptr() as _, arg.len()) }
    }
    fn take_sink(c: *mut howdah_ctx) -> Option<String> {
        unsafe {
            let p = howdah_take_sink_log_line(c);
            if p.is_null() {
                return None;
            }
            let s = CStr::from_ptr(p).to_string_lossy().into_owned();
            howdah_free_str(p);
            Some(s)
        }
    }

    #[test]
    fn sink_logs_under_global_block_when_sinks_detect() {
        let c = init("mode = \"block\"");
        begin(c);
        assert_eq!(sink(c, HOWDAH_SINK_COMMAND_EXEC, "system", b"id"), HOWDAH_LOG);
        let line = take_sink(c).expect("sink line");
        assert!(line.contains("\"rule\":\"command_exec\""), "{line}");
        assert!(line.contains("\"action\":\"log\""), "{line}");
        assert!(line.contains("system"), "{line}");
        assert!(take(c).is_none(), "layer-1/2 slot untouched");
        unsafe { howdah_free(c) };
    }

    #[test]
    fn sink_blocks_only_when_sink_mode_block() {
        let c = init("[sinks.command_exec]\nmode=\"block\"");
        begin(c);
        assert_eq!(sink(c, HOWDAH_SINK_COMMAND_EXEC, "system", b"id"), HOWDAH_BLOCK);
        let line = take_sink(c).expect("sink line");
        assert!(line.contains("\"action\":\"block\""), "{line}");
        unsafe { howdah_free(c) };
    }

    #[test]
    fn command_allow_silences() {
        let c = init("[sinks.command_exec]\nmode=\"block\"\nallow=[\"id\"]");
        begin(c);
        assert_eq!(sink(c, HOWDAH_SINK_COMMAND_EXEC, "system", b"id"), HOWDAH_ALLOW);
        assert!(take_sink(c).is_none());
        unsafe { howdah_free(c) };
    }

    #[test]
    fn sink_log_omits_argument() {
        let c = init("");
        begin(c);
        sink(c, HOWDAH_SINK_COMMAND_EXEC, "system", b"cat /etc/shadow");
        let line = take_sink(c).expect("sink line");
        assert!(line.contains("system") && line.contains("command_exec"), "{line}");
        assert!(!line.contains("shadow") && !line.contains("/etc/"), "{line}");
        unsafe { howdah_free(c) };
    }

    #[test]
    fn multiple_sink_hits_each_emit() {
        let c = init("[limits]\nmax_input_vars = 2\n");
        begin(c);
        for n in ["a", "b", "c"] {
            unsafe { howdah_input_var(c, n.as_ptr() as _, n.len()) };
        }
        for (i, a) in [&b"id"[..], b"ls", b"whoami"].iter().enumerate() {
            assert_eq!(sink(c, HOWDAH_SINK_COMMAND_EXEC, "system", a), HOWDAH_LOG, "{i}");
            assert!(take_sink(c).is_some(), "hit {i} dropped");
            assert!(take_sink(c).is_none());
        }
        let l1 = take(c).expect("layer-1 line survives sink hits");
        assert!(l1.contains("max_input_vars"), "{l1}");
        unsafe { howdah_free(c) };
    }

    #[test]
    fn sink_log_reset_on_request_begin() {
        let c = init("");
        begin(c);
        sink(c, HOWDAH_SINK_COMMAND_EXEC, "system", b"id");
        begin(c);
        assert!(take_sink(c).is_none());
        unsafe { howdah_free(c) };
    }

    #[test]
    fn unserialize_off_by_default_is_allow() {
        let c = init("");
        begin(c);
        assert_eq!(sink(c, HOWDAH_SINK_UNSERIALIZE, "unserialize", b"O:8:\"stdClass\":0:{}"), HOWDAH_ALLOW);
        assert!(take_sink(c).is_none());
        unsafe { howdah_free(c) };
    }

    #[test]
    fn unserialize_class_logged_unless_allowed() {
        let c = init("[sinks.unserialize]\nmode=\"block\"\nallow_classes=[\"Good\"]");
        begin(c);
        assert_eq!(sink(c, HOWDAH_SINK_UNSERIALIZE, "unserialize", b"O:4:\"Good\":0:{}"), HOWDAH_ALLOW);
        assert_eq!(sink(c, HOWDAH_SINK_UNSERIALIZE, "unserialize", b"a:1:{i:0;i:1;}"), HOWDAH_ALLOW);
        assert_eq!(sink(c, HOWDAH_SINK_UNSERIALIZE, "unserialize", b"O:3:\"Bad\":0:{}"), HOWDAH_BLOCK);
        let line = take_sink(c).expect("line");
        assert!(line.contains("Bad") && line.contains("\"rule\":\"unserialize\""), "{line}");
        unsafe { howdah_free(c) };
    }

    #[test]
    fn include_eval_block_when_armed() {
        // include/eval honor block (enforced by the C opcode handler on PHP 7+);
        // the core returns Block and never logs the path/code (the arg).
        let c = init("[sinks.include]\nmode=\"block\"\nallow_paths=[\"/var/www/app\"]");
        begin(c);
        assert_eq!(sink(c, HOWDAH_SINK_INCLUDE, "include", b"/etc/passwd"), HOWDAH_BLOCK);
        let line = take_sink(c).expect("line");
        assert!(line.contains("\"action\":\"block\"") && line.contains("\"rule\":\"include\""), "{line}");
        assert!(!line.contains("passwd"), "{line}");
        unsafe { howdah_free(c) };
        let c = init("[sinks.eval]\nmode=\"block\"");
        begin(c);
        assert_eq!(sink(c, HOWDAH_SINK_EVAL, "eval", b"1"), HOWDAH_BLOCK);
        assert!(take_sink(c).unwrap().contains("\"action\":\"block\""));
        unsafe { howdah_free(c) };
    }

    #[test]
    fn include_detect_logs_not_block() {
        let c = init("[sinks.include]\nallow_paths=[\"/var/www/app\"]");
        begin(c);
        assert_eq!(sink(c, HOWDAH_SINK_INCLUDE, "include", b"/etc/passwd"), HOWDAH_LOG);
        assert!(take_sink(c).unwrap().contains("\"action\":\"log\""));
        unsafe { howdah_free(c) };
    }

    #[test]
    fn include_inert_without_allow_paths() {
        let c = init("");
        begin(c);
        assert_eq!(sink(c, HOWDAH_SINK_INCLUDE, "include", b"/etc/passwd"), HOWDAH_ALLOW);
        assert!(take_sink(c).is_none());
        unsafe { howdah_free(c) };
    }

    // ---- T4 include/open wrapper-scheme firewall ------------------------------

    fn open(c: *mut howdah_ctx, name: &str, target: &[u8], op: i32) -> i32 {
        unsafe {
            howdah_sink_check_open_at(
                c,
                name.as_ptr() as *const c_char,
                name.len(),
                target.as_ptr() as *const c_char,
                target.len(),
                op,
                std::ptr::null(),
                0,
                std::ptr::null(),
                0,
                0,
            )
        }
    }

    /// `open` with a calling script and line (origin attribution).
    fn open_from(c: *mut howdah_ctx, name: &str, target: &[u8], op: i32, script: &str, line: u32) -> i32 {
        unsafe {
            howdah_sink_check_open_at(
                c,
                name.as_ptr() as *const c_char,
                name.len(),
                target.as_ptr() as *const c_char,
                target.len(),
                op,
                script.as_ptr() as *const c_char,
                script.len(),
                std::ptr::null(),
                0,
                line,
            )
        }
    }

    #[test]
    fn include_wrapper_firewall_blocks_by_default() {
        // On by default (shipped detect), independent of the include sink mode.
        let c = init("mode = \"detect\"");
        begin(c);
        for target in [
            &b"php://filter/convert.base64-encode/resource=/etc/passwd"[..],
            b"php://input",
            b"data://text/plain;base64,PD9waHA=",
            b"expect://id",
            b"http://evil.example/shell.txt",
            b"ftp://evil.example/x",
        ] {
            assert_eq!(sink(c, HOWDAH_SINK_INCLUDE, "include", target), HOWDAH_BLOCK, "{:?}", String::from_utf8_lossy(target));
            let line = take_sink(c).expect("line");
            assert!(line.contains("\"rule\":\"include_wrapper\"") && line.contains("\"action\":\"block\""), "{line}");
            // The target content never appears; only a scheme label.
            assert!(!line.contains("passwd") && !line.contains("evil.example") && !line.contains("PD9waHA"), "{line}");
        }
        // A plain template / config path is never blocked.
        assert_eq!(sink(c, HOWDAH_SINK_INCLUDE, "include", b"templates/header.php"), HOWDAH_ALLOW);
        assert_eq!(sink(c, HOWDAH_SINK_INCLUDE, "include", b"/var/www/app/config.php"), HOWDAH_ALLOW);
        unsafe { howdah_free(c) };
    }

    #[test]
    fn include_poison_firewall_blocks_proc_and_session() {
        let c = init("mode = \"detect\"");
        begin(c);
        unsafe {
            let s = "/var/lib/php/sessions";
            let e = "/var/log/php_errors.log";
            howdah_set_runtime_paths(c, s.as_ptr() as *const c_char, s.len(), e.as_ptr() as *const c_char, e.len());
        }
        for target in [
            &b"/proc/self/environ"[..],
            b"/var/lib/php/sessions/sess_abc",
            b"/var/log/php_errors.log",
        ] {
            assert_eq!(sink(c, HOWDAH_SINK_INCLUDE, "include", target), HOWDAH_BLOCK, "{:?}", String::from_utf8_lossy(target));
            let line = take_sink(c).expect("line");
            assert!(line.contains("\"rule\":\"include_wrapper\"") && line.contains("poisonable"), "{line}");
        }
        unsafe { howdah_free(c) };
    }

    #[test]
    fn open_firewall_is_tight() {
        let c = init("mode = \"detect\"");
        begin(c);
        // Blocked: the dangerous wrappers.
        for t in [&b"php://filter/resource=/etc/passwd"[..], b"data://text/plain;base64,x", b"expect://id"] {
            assert_eq!(open(c, "fopen", t, HOWDAH_FILE_OP_READ), HOWDAH_BLOCK, "{:?}", String::from_utf8_lossy(t));
            let line = take_sink(c).expect("line");
            assert!(line.contains("\"rule\":\"file_open\"") && line.contains("\"action\":\"block\""), "{line}");
        }
        // Allowed: legitimate open targets (php://input is read-the-body; remote
        // is the SSRF sink's job; php://temp is benign).
        for t in [&b"php://input"[..], b"php://temp", b"https://api.example/x.json", b"/var/www/app/data.json"] {
            assert_eq!(open(c, "file_get_contents", t, HOWDAH_FILE_OP_READ), HOWDAH_ALLOW, "{:?}", String::from_utf8_lossy(t));
            assert!(take_sink(c).is_none());
        }
        unsafe { howdah_free(c) };
    }

    #[test]
    fn open_firewall_poison_proc() {
        let c = init("mode = \"detect\"");
        begin(c);
        assert_eq!(open(c, "readfile", b"/proc/self/environ", HOWDAH_FILE_OP_READ), HOWDAH_BLOCK);
        assert!(take_sink(c).unwrap().contains("\"rule\":\"file_open\""));
        unsafe { howdah_free(c) };
    }

    #[test]
    fn firewall_off_disables_both() {
        // The hub also serves the T5 delete / secret-read guards, so those are
        // switched off too for "nothing armed".
        let c = init("[sinks.include]\nwrapper = \"off\"\npoison = \"off\"\n[behavior]\ndelete_guard = \"off\"");
        begin(c);
        assert_eq!(sink(c, HOWDAH_SINK_INCLUDE, "include", b"php://filter/resource=x"), HOWDAH_ALLOW);
        assert_eq!(open(c, "fopen", b"php://filter/resource=x", HOWDAH_FILE_OP_READ), HOWDAH_ALLOW);
        assert_eq!(unsafe { howdah_sink_open_armed(c) }, 0);
        unsafe { howdah_free(c) };
        // Armed by default.
        let c = init("mode = \"detect\"");
        assert_eq!(unsafe { howdah_sink_open_armed(c) }, 1);
        unsafe { howdah_free(c) };
    }

    // ---- T5 delete / secret-read / upload-write guards ------------------------

    const WP_PLUGIN: &str = "/var/www/html/wp-content/plugins/x/x.php";

    #[test]
    fn delete_guard_blocks_by_default_and_logs_origin_not_target() {
        // Shipped posture: global detect, [behavior] untouched -> the guard blocks.
        let c = init("mode = \"detect\"");
        begin(c);
        for (name, target, op) in [
            ("unlink", &b"/var/www/html/wp-config.php"[..], HOWDAH_FILE_OP_DELETE),
            ("unlink", b"/var/www/html/.env", HOWDAH_FILE_OP_DELETE),
            ("unlink", b"/var/www/html/uploads/../../../../etc/cron.d/x", HOWDAH_FILE_OP_DELETE),
            ("rmdir", b"/var/www/html/../../../../etc/ssl", HOWDAH_FILE_OP_DELETE),
            ("rename", b"/var/www/html/wp-config.php", HOWDAH_FILE_OP_MOVE_SRC),
        ] {
            assert_eq!(open_from(c, name, target, op, WP_PLUGIN, 42), HOWDAH_BLOCK, "{name} {:?}", String::from_utf8_lossy(target));
            let line = take_sink(c).expect("line");
            assert!(line.contains("\"rule\":\"file_delete\"") && line.contains("\"action\":\"block\"") && line.contains("\"layer\":4"), "{line}");
            assert!(line.contains(&format!("{name} ")) && line.contains("x.php:42"), "origin/function missing: {line}");
            assert!(!line.contains("wp-config.php\"") && !line.contains("/etc/") && !line.contains(".env"), "target leaked: {line}");
        }
        unsafe { howdah_free(c) };
    }

    #[test]
    fn delete_guard_benign_corpus_allows() {
        let c = init("mode = \"detect\"");
        begin(c);
        for t in [
            &b"/tmp/phpAbC123"[..],
            b"/var/lib/php/sessions/sess_x",
            b"/var/www/html/wp-content/cache/x.html",
            b"/var/www/html/wp-content/uploads/2026/10/a.jpg",
            b"/var/www/html/wp-content/upgrade/tmp",
            b"/var/www/app/storage/framework/views/a.php",
            b"/var/www/app/.env.example",
            b"/var/www/html/.maintenance",
            b"/var/www/shared/../releases/1/cache/x",
        ] {
            assert_eq!(open_from(c, "unlink", t, HOWDAH_FILE_OP_DELETE, WP_PLUGIN, 1), HOWDAH_ALLOW, "{:?}", String::from_utf8_lossy(t));
            assert_eq!(open_from(c, "rmdir", t, HOWDAH_FILE_OP_DELETE, WP_PLUGIN, 1), HOWDAH_ALLOW);
            assert!(take_sink(c).is_none());
        }
        // rename SOURCE: ordinary renames (including a .env.production -> .env deploy) pass.
        for t in [&b"/var/www/app/.env.production"[..], b"/var/www/html/cache/a.tmp", b"/var/www/html/uploads/a.jpg"] {
            assert_eq!(open_from(c, "rename", t, HOWDAH_FILE_OP_MOVE_SRC, WP_PLUGIN, 1), HOWDAH_ALLOW);
        }
        // The T3/T4 firewall behaviour is unchanged for the read/write ops.
        assert_eq!(open(c, "fopen", b"/var/www/html/data.json", HOWDAH_FILE_OP_READ), HOWDAH_ALLOW);
        assert_eq!(open(c, "fopen", b"/var/www/html/.env", HOWDAH_FILE_OP_READ), HOWDAH_ALLOW); // secret_read is off
        assert!(take_sink(c).is_none());
        unsafe { howdah_free(c) };
    }

    #[test]
    fn delete_guard_modes_observe_exceptions_and_master_switches() {
        let target = b"/var/www/html/wp-config.php";
        let run = |toml: &str| {
            let c = init(toml);
            begin(c);
            let a = open_from(c, "unlink", target, HOWDAH_FILE_OP_DELETE, "/var/www/migrate/installer.php", 3);
            let l = take_sink(c);
            unsafe { howdah_free(c) };
            (a, l)
        };
        assert_eq!(run("[behavior]\ndelete_guard = \"detect\"").0, HOWDAH_LOG);
        assert_eq!(run("[behavior]\ndelete_guard = \"off\"").0, HOWDAH_ALLOW);
        // Independent of the (log-only by default) section mode.
        assert_eq!(run("[behavior]\nmode = \"detect\"").0, HOWDAH_BLOCK);
        // observe is propose-only: never a block, line marked proposed.
        let (a, l) = run("[behavior]\nobserve = true");
        assert_eq!(a, HOWDAH_LOG);
        assert!(l.unwrap().contains("proposed:"));
        // Layer-4 master switches.
        assert_eq!(run("mode = \"off\"").0, HOWDAH_ALLOW);
        assert_eq!(run("[behavior]\nenabled = false").0, HOWDAH_ALLOW);
        assert_eq!(run("[behavior]\nmode = \"off\"").0, HOWDAH_ALLOW);
        // A scoped exception on the executing script lets a migration tool through.
        let ex = "[[exceptions]]\nrule = \"behavior.file_delete\"\nscript = \"/var/www/migrate/**\"\nreason = \"migration installer\"\n";
        assert_eq!(run(ex).0, HOWDAH_ALLOW);
        // ... but not a different script.
        let c = init(ex);
        begin(c);
        assert_eq!(open_from(c, "unlink", target, HOWDAH_FILE_OP_DELETE, WP_PLUGIN, 3), HOWDAH_BLOCK);
        unsafe { howdah_free(c) };
    }

    #[test]
    fn secret_read_is_off_by_default_and_opt_in() {
        let target = b"/var/www/html/.env";
        let read = |toml: &str| {
            let c = init(toml);
            begin(c);
            let a = open_from(c, "file_get_contents", target, HOWDAH_FILE_OP_READ, WP_PLUGIN, 9);
            let l = take_sink(c);
            unsafe { howdah_free(c) };
            (a, l)
        };
        assert_eq!(read("").0, HOWDAH_ALLOW);
        assert_eq!(read("[behavior]\nmode = \"block\"").0, HOWDAH_ALLOW); // still off
        let (a, l) = read("[behavior]\nsecret_read = \"detect\"");
        assert_eq!(a, HOWDAH_LOG);
        let l = l.unwrap();
        assert!(l.contains("\"rule\":\"secret_read\"") && l.contains("\"layer\":4") && l.contains("\"action\":\"log\""), "{l}");
        assert!(l.contains("file_get_contents reads a dotenv file at /var/www/html/wp-content/plugins/x/x.php:9"), "{l}");
        assert_eq!(read("[behavior]\nsecret_read = \"block\"").0, HOWDAH_BLOCK);
        // observe downgrades even an explicit block.
        assert_eq!(read("[behavior]\nsecret_read = \"block\"\nobserve = true").0, HOWDAH_LOG);
        assert_eq!(read("mode = \"off\"\n[behavior]\nsecret_read = \"block\"").0, HOWDAH_ALLOW);
        // A write-mode open of .env is not a read.
        let c = init("[behavior]\nsecret_read = \"block\"");
        begin(c);
        assert_eq!(open(c, "fopen", target, HOWDAH_FILE_OP_WRITE), HOWDAH_ALLOW);
        // The firewall wins (and logs file_open) when both would fire.
        assert_eq!(open(c, "fopen", b"/proc/self/environ", HOWDAH_FILE_OP_READ), HOWDAH_BLOCK);
        assert!(take_sink(c).unwrap().contains("file_open"));
        unsafe { howdah_free(c) };
    }

    #[test]
    fn behavior_armed_facets_for_the_file_guards() {
        let armed = |toml: &str, f: i32| {
            let c = init(toml);
            let r = unsafe { howdah_behavior_armed(c, f) };
            unsafe { howdah_free(c) };
            r
        };
        // Defaults: upload-write and delete on, secret-read off, scoped write off.
        assert_eq!(armed("", HOWDAH_BEHAVIOR_UPLOAD_WRITE), 1);
        assert_eq!(armed("", HOWDAH_BEHAVIOR_DELETE), 1);
        assert_eq!(armed("", HOWDAH_BEHAVIOR_SECRET_READ), 0);
        assert_eq!(armed("", HOWDAH_BEHAVIOR_PHP_WRITE), 0);
        assert_eq!(armed("[behavior]\nsecret_read = \"detect\"", HOWDAH_BEHAVIOR_SECRET_READ), 1);
        assert_eq!(armed("[behavior]\ndelete_guard = \"off\"", HOWDAH_BEHAVIOR_DELETE), 0);
        assert_eq!(armed("[behavior]\nupload_write = \"off\"", HOWDAH_BEHAVIOR_UPLOAD_WRITE), 0);
        assert_eq!(armed("mode = \"off\"", HOWDAH_BEHAVIOR_DELETE), 0);
    }

    #[test]
    fn upload_write_guard_blocks_by_default_without_config() {
        let c = init("mode = \"detect\"");
        begin(c);
        let call = |caller: &str, target: &str, mode: i32| unsafe {
            howdah_behavior_check_php_write_at(
                c,
                caller.as_ptr() as _,
                caller.len(),
                target.as_ptr() as _,
                target.len(),
                mode,
                std::ptr::null(),
                0,
                77,
            )
        };
        let up = "/var/www/html/upload.php";
        for t in ["/var/www/html/uploads/s.php", "/var/www/html/uploads/.htaccess", "/var/www/html/uploads/.user.ini", "/x/s.phtml", "/x/s.phar", "/x/web.config"] {
            assert_eq!(call(up, t, HOWDAH_WRITE_UPLOAD), HOWDAH_BLOCK, "{t}");
            let line = take_sink(c).expect("line");
            assert!(line.contains("\"rule\":\"php_write\"") && line.contains("\"action\":\"block\"") && line.contains("upload.php:77"), "{line}");
            assert!(!line.contains("uploads") && !line.contains(".htaccess") && !line.contains("s.php\""), "target leaked: {line}");
        }
        // Benign uploads and every plain write sink (no scoped tier) are allowed.
        for t in ["/x/a.jpg", "/x/a.pdf", "/x/a.txt", "/x/a.json", "/x/a.zip", "/x/a.inc"] {
            assert_eq!(call(up, t, HOWDAH_WRITE_UPLOAD), HOWDAH_ALLOW, "{t}");
        }
        for t in ["/x/s.php", "/x/.htaccess", "/x/.user.ini"] {
            assert_eq!(call(up, t, HOWDAH_WRITE_PLAIN), HOWDAH_ALLOW, "{t}");
            assert_eq!(call(up, t, HOWDAH_WRITE_READ), HOWDAH_ALLOW, "{t}");
        }
        assert!(take_sink(c).is_none());
        unsafe { howdah_free(c) };
        // Switchable.
        let c = init("[behavior]\nupload_write = \"off\"");
        begin(c);
        assert_eq!(
            unsafe { howdah_behavior_check_php_write(c, "/a.php".as_ptr() as _, 6, "/x/s.php".as_ptr() as _, 8, HOWDAH_WRITE_UPLOAD) },
            HOWDAH_ALLOW
        );
        unsafe { howdah_free(c) };
        let c = init("[behavior]\nupload_write = \"detect\"");
        begin(c);
        assert_eq!(
            unsafe { howdah_behavior_check_php_write(c, "/a.php".as_ptr() as _, 6, "/x/s.php".as_ptr() as _, 8, HOWDAH_WRITE_UPLOAD) },
            HOWDAH_LOG
        );
        unsafe { howdah_free(c) };
    }

    #[test]
    fn unserialize_capped_fails_closed() {
        let c = init("[sinks.unserialize]\nmode=\"block\"\nallow_classes=[\"A\"]");
        begin(c);
        let payload = "O:1:\"A\":0:{}".repeat(70);
        assert_eq!(sink(c, HOWDAH_SINK_UNSERIALIZE, "unserialize", payload.as_bytes()), HOWDAH_BLOCK);
        assert!(take_sink(c).is_some());
        unsafe { howdah_free(c) };
    }

    #[test]
    fn global_off_silences_sinks() {
        let c = init("mode = \"off\"\n[sinks.command_exec]\nmode=\"block\"");
        begin(c);
        assert_eq!(sink(c, HOWDAH_SINK_COMMAND_EXEC, "system", b"id"), HOWDAH_ALLOW);
        assert!(take_sink(c).is_none());
        unsafe { howdah_free(c) };
    }

    #[test]
    fn sink_check_panic_fails_open() {
        let c = init("[sinks.command_exec]\nmode=\"block\"");
        begin(c);
        FORCE_PANIC.with(|f| f.set(true));
        assert_eq!(sink(c, HOWDAH_SINK_COMMAND_EXEC, "system", b"id"), HOWDAH_ALLOW);
        FORCE_PANIC.with(|f| f.set(false));
        unsafe { howdah_free(c) };
    }

    #[test]
    fn sink_unknown_id_and_null_are_allow() {
        assert_eq!(unsafe { howdah_sink_check(std::ptr::null_mut(), 0, std::ptr::null(), 0, std::ptr::null(), 0) }, 0);
        assert!(unsafe { howdah_take_sink_log_line(std::ptr::null_mut()) }.is_null());
        let c = init("");
        begin(c);
        assert_eq!(sink(c, 99, "x", b"id"), HOWDAH_ALLOW);
        assert_eq!(sink(c, -1, "x", b"id"), HOWDAH_ALLOW);
        assert_eq!(unsafe { howdah_sink_check(c, 0, std::ptr::null(), 0, std::ptr::null(), 0) }, HOWDAH_LOG);
        unsafe { howdah_free(c) };
    }

    fn ssrf_armed(c: *mut howdah_ctx) -> i32 {
        unsafe { howdah_sink_ssrf_armed(c) }
    }
    fn rec4(a: [u8; 4]) -> [u8; 17] {
        let mut r = [0u8; 17];
        r[0] = 4;
        r[1..5].copy_from_slice(&a);
        r
    }
    fn ssrf(c: *mut howdah_ctx, host: &str, ips: &[[u8; 17]]) -> i32 {
        let flat: Vec<u8> = ips.iter().flatten().copied().collect();
        let s = "http";
        unsafe {
            howdah_sink_check_ssrf(c, s.as_ptr() as _, s.len(), host.as_ptr() as _, host.len(), 80, flat.as_ptr(), ips.len())
        }
    }

    #[test]
    fn ssrf_prepare_act_writes_host_and_port() {
        let u = b"http://user:pw@Example.COM:8080/p?q=1";
        let (mut buf, mut n, mut port) = ([0u8; 64], 0usize, 0u16);
        let r = unsafe { howdah_ssrf_prepare(u.as_ptr(), u.len(), 1, buf.as_mut_ptr(), 64, &mut n, &mut port) };
        assert_eq!(r, 1);
        assert_eq!(&buf[..n], b"example.com");
        assert_eq!(port, 8080);
        // bare host ok when scheme not required; no port -> 0
        let b = b"10.0.0.5";
        let r = unsafe { howdah_ssrf_prepare(b.as_ptr(), b.len(), 0, buf.as_mut_ptr(), 64, &mut n, &mut port) };
        assert_eq!((r, &buf[..n], port), (1, &b"10.0.0.5"[..], 0));
    }

    #[test]
    fn ssrf_prepare_redirect_location_forms() {
        let (mut buf, mut n, mut port) = ([0u8; 64], 0usize, 0u16);
        let mut go = |loc: &str| -> (i32, String) {
            let r = unsafe {
                howdah_ssrf_prepare(loc.as_ptr(), loc.len(), 2, buf.as_mut_ptr(), 64, &mut n, &mut port)
            };
            (r, String::from_utf8_lossy(&buf[..n]).into_owned())
        };
        // Absolute and scheme-relative Locations are new targets.
        assert_eq!(go("http://169.254.169.254/latest/meta-data"), (1, "169.254.169.254".into()));
        assert_eq!(go("//127.0.0.1:8080/x"), (1, "127.0.0.1".into()));
        assert_eq!(go("  //Evil.example/x").0, 1);
        // A relative reference stays on the current host: not a target.
        for rel in ["/admin", "admin", "../x", "?q=1", "#f", ""] {
            assert_eq!(go(rel).0, 0, "{rel:?}");
        }
        // Unknown schemes are the scheme knob's job, not a network target here.
        assert_eq!(go("dict://127.0.0.1:11211/x").0, 0);
    }

    #[test]
    fn ssrf_armed_mask_reflects_knobs() {
        let mask = |toml: &str| {
            let c = init(toml);
            let m = unsafe { howdah_ssrf_armed_mask(c) };
            unsafe { howdah_free(c) };
            m
        };
        // Off by default, and a global block arms nothing.
        assert_eq!(mask(""), 0);
        assert_eq!(mask("mode=\"block\""), 0);
        assert_eq!(mask("[sinks.ssrf]\nmode=\"detect\""), HOWDAH_SSRF_ARM_RANGE);
        // Each knob is independent of `mode` and of the others.
        assert_eq!(mask("[sinks.ssrf]\nrebind=\"detect\""), HOWDAH_SSRF_ARM_REBIND);
        assert_eq!(
            mask("[sinks.ssrf]\nrebind=\"block\""),
            HOWDAH_SSRF_ARM_REBIND | HOWDAH_SSRF_ARM_PIN
        );
        assert_eq!(mask("[sinks.ssrf]\nscheme=\"detect\""), HOWDAH_SSRF_ARM_SCHEME);
        assert_eq!(
            mask("[sinks.ssrf]\nscheme=\"block\""),
            HOWDAH_SSRF_ARM_SCHEME | HOWDAH_SSRF_ARM_PROTOCOLS
        );
        assert_eq!(mask("[sinks.ssrf]\nredirect=\"detect\""), HOWDAH_SSRF_ARM_REDIRECT);
        assert_eq!(mask("[sinks.ssrf]\nredirect=\"block\""), HOWDAH_SSRF_ARM_REDIRECT);
        assert_eq!(
            mask("[sinks.ssrf]\nmode=\"block\"\nrebind=\"block\"\nscheme=\"block\"\nredirect=\"block\""),
            HOWDAH_SSRF_ARM_RANGE
                | HOWDAH_SSRF_ARM_REBIND
                | HOWDAH_SSRF_ARM_PIN
                | HOWDAH_SSRF_ARM_SCHEME
                | HOWDAH_SSRF_ARM_PROTOCOLS
                | HOWDAH_SSRF_ARM_REDIRECT
        );
        // A global off and `enabled = false` silence every knob.
        let all = "[sinks.ssrf]\nmode=\"block\"\nrebind=\"block\"\nscheme=\"block\"\nredirect=\"block\"";
        assert_eq!(mask(&format!("mode=\"off\"\n{all}")), 0);
        assert_eq!(mask(&format!("[sinks]\nenabled=false\n{}", all.trim_start_matches("[sinks.ssrf]\n"))), 0);
        assert_eq!(unsafe { howdah_ssrf_armed_mask(std::ptr::null_mut()) }, 0);
    }

    fn ssrf_kind(c: *mut howdah_ctx, kind: i32, via: &str, host: &str, ips: &[[u8; 17]]) -> i32 {
        let flat: Vec<u8> = ips.iter().flatten().copied().collect();
        unsafe {
            howdah_sink_check_ssrf_kind_at(
                c,
                kind,
                via.as_ptr() as _,
                via.len(),
                host.as_ptr() as _,
                host.len(),
                80,
                flat.as_ptr(),
                ips.len(),
                std::ptr::null(),
                0,
                std::ptr::null(),
                0,
            )
        }
    }

    #[test]
    fn ssrf_rebind_judges_the_connected_address() {
        let c = init("[sinks.ssrf]\nrebind=\"block\"");
        begin(c);
        // The host name looks public, but the address the connection used is loopback.
        assert_eq!(
            ssrf_kind(c, HOWDAH_SSRF_KIND_REBIND, "curl-connect", "rebind.example", &[rec4([127, 0, 0, 1])]),
            HOWDAH_BLOCK
        );
        let line = take_sink(c).expect("line");
        assert!(line.contains("\"rule\":\"ssrf\"") && line.contains("\"action\":\"block\""), "{line}");
        assert!(
            line.contains("ssrf rebind via curl-connect: host=rebind.example port=80 ip=127.0.0.1 class=loopback"),
            "{line}"
        );
        // A public connected address is fine; so is metadata only via the knob's own class.
        assert_eq!(
            ssrf_kind(c, HOWDAH_SSRF_KIND_REBIND, "curl-connect", "ok.example", &[rec4([93, 184, 216, 34])]),
            HOWDAH_ALLOW
        );
        assert!(take_sink(c).is_none());
        assert_eq!(
            ssrf_kind(c, HOWDAH_SSRF_KIND_REBIND, "tcp", "x.example", &[rec4([169, 254, 169, 254])]),
            HOWDAH_BLOCK
        );
        assert!(take_sink(c).expect("line").contains("class=metadata"));
        // allow_hosts still wins (the operator vouched for the destination).
        unsafe { howdah_free(c) };
        let c = init("[sinks.ssrf]\nrebind=\"block\"\nallow_hosts=[\"internal.example\",\"10.0.0.0/8\"]");
        begin(c);
        assert_eq!(
            ssrf_kind(c, HOWDAH_SSRF_KIND_REBIND, "tcp", "internal.example", &[rec4([127, 0, 0, 1])]),
            HOWDAH_ALLOW
        );
        assert_eq!(
            ssrf_kind(c, HOWDAH_SSRF_KIND_REBIND, "tcp", "other.example", &[rec4([10, 1, 2, 3])]),
            HOWDAH_ALLOW
        );
        assert_eq!(
            ssrf_kind(c, HOWDAH_SSRF_KIND_REBIND, "tcp", "other.example", &[rec4([192, 168, 1, 1])]),
            HOWDAH_BLOCK
        );
        unsafe { howdah_free(c) };
        // detect logs and allows; off is silent.
        let c = init("[sinks.ssrf]\nrebind=\"detect\"");
        begin(c);
        assert_eq!(
            ssrf_kind(c, HOWDAH_SSRF_KIND_REBIND, "curl-connect", "h.example", &[rec4([127, 0, 0, 1])]),
            HOWDAH_LOG
        );
        assert!(take_sink(c).expect("line").contains("\"action\":\"log\""));
        unsafe { howdah_free(c) };
        let c = init("[sinks.ssrf]\nmode=\"block\"");
        begin(c);
        assert_eq!(
            ssrf_kind(c, HOWDAH_SSRF_KIND_REBIND, "curl-connect", "h.example", &[rec4([127, 0, 0, 1])]),
            HOWDAH_ALLOW,
            "rebind is its own knob: `mode` alone does not arm it"
        );
        assert!(take_sink(c).is_none());
        unsafe { howdah_free(c) };
    }

    #[test]
    fn ssrf_redirect_judges_the_hop_target() {
        let c = init("[sinks.ssrf]\nredirect=\"block\"");
        begin(c);
        assert_eq!(
            ssrf_kind(c, HOWDAH_SSRF_KIND_REDIRECT, "http", "169.254.169.254", &[]),
            HOWDAH_BLOCK,
            "a literal metadata hop needs no resolved address"
        );
        let line = take_sink(c).expect("line");
        assert!(line.contains("ssrf redirect via http: host=169.254.169.254 port=80 ip=169.254.169.254 class=metadata"), "{line}");
        assert_eq!(
            ssrf_kind(c, HOWDAH_SSRF_KIND_REDIRECT, "https", "evil.example", &[rec4([10, 0, 0, 5])]),
            HOWDAH_BLOCK
        );
        assert_eq!(
            ssrf_kind(c, HOWDAH_SSRF_KIND_REDIRECT, "https", "cdn.example", &[rec4([93, 184, 216, 34])]),
            HOWDAH_ALLOW
        );
        // An allowlisted hop target is untouched.
        unsafe { howdah_free(c) };
        let c = init("[sinks.ssrf]\nredirect=\"detect\"\nallow_hosts=[\"localhost\"]");
        begin(c);
        assert_eq!(
            ssrf_kind(c, HOWDAH_SSRF_KIND_REDIRECT, "http", "localhost", &[rec4([127, 0, 0, 1])]),
            HOWDAH_ALLOW
        );
        assert_eq!(
            ssrf_kind(c, HOWDAH_SSRF_KIND_REDIRECT, "http", "127.0.0.1", &[]),
            HOWDAH_LOG
        );
        unsafe { howdah_free(c) };
    }

    fn ssrf_scheme(c: *mut howdah_ctx, via: i32, url: &str) -> i32 {
        unsafe {
            howdah_sink_ssrf_scheme_at(c, via, url.as_ptr() as _, url.len(), std::ptr::null(), 0, std::ptr::null(), 0)
        }
    }

    #[test]
    fn ssrf_scheme_denies_non_http_and_logs_only_the_category() {
        let c = init("[sinks.ssrf]\nscheme=\"block\"");
        begin(c);
        for (u, label) in [
            ("gopher://127.0.0.1:6379/_SECRETCMD", "gopher"),
            ("dict://127.0.0.1:11211/SECRETCMD", "dict"),
            ("file:///etc/SECRETFILE", "file"),
            ("ldap://127.0.0.1/SECRETCMD", "ldap"),
            ("tftp://127.0.0.1/SECRETCMD", "tftp"),
        ] {
            assert_eq!(ssrf_scheme(c, HOWDAH_SSRF_VIA_CURL, u), HOWDAH_BLOCK, "{u}");
            let line = take_sink(c).expect("line");
            assert!(line.contains("\"rule\":\"ssrf\"") && line.contains("\"action\":\"block\""), "{line}");
            assert!(line.contains(&format!("ssrf scheme via curl: scheme={label}")), "{line}");
            assert!(!line.contains("SECRET") && !line.contains("127.0.0.1") && !line.contains("//"), "leaked: {line}");
        }
        for ok in ["http://127.0.0.1/", "https://example.com/x", "example.com/x", "localhost:8080"] {
            assert_eq!(ssrf_scheme(c, HOWDAH_SSRF_VIA_CURL, ok), HOWDAH_ALLOW, "{ok}");
        }
        // Stream functions: only the remote wrappers; local wrappers and phar are untouched.
        assert_eq!(ssrf_scheme(c, HOWDAH_SSRF_VIA_STREAM, "ftp://127.0.0.1/x"), HOWDAH_BLOCK);
        assert!(take_sink(c).expect("line").contains("ssrf scheme via stream: scheme=ftp"));
        for ok in ["file:///etc/hostname", "php://temp", "data://text/plain,hi", "phar:///x.phar/y", "http://h/"] {
            assert_eq!(ssrf_scheme(c, HOWDAH_SSRF_VIA_STREAM, ok), HOWDAH_ALLOW, "{ok}");
        }
        assert!(take_sink(c).is_none());
        unsafe { howdah_free(c) };
        // detect logs, off is silent, and the range `mode` does not arm it.
        let c = init("[sinks.ssrf]\nscheme=\"detect\"");
        begin(c);
        assert_eq!(ssrf_scheme(c, HOWDAH_SSRF_VIA_CURL, "gopher://h/"), HOWDAH_LOG);
        assert!(take_sink(c).expect("line").contains("\"action\":\"log\""));
        unsafe { howdah_free(c) };
        let c = init("[sinks.ssrf]\nmode=\"block\"");
        begin(c);
        assert_eq!(ssrf_scheme(c, HOWDAH_SSRF_VIA_CURL, "gopher://h/"), HOWDAH_ALLOW);
        assert!(take_sink(c).is_none());
        unsafe { howdah_free(c) };
        assert_eq!(ssrf_scheme(std::ptr::null_mut(), HOWDAH_SSRF_VIA_CURL, "gopher://h/"), HOWDAH_ALLOW);
    }

    #[test]
    fn ssrf_scheme_honours_exceptions_and_fails_open_on_panic() {
        let toml = "[sinks.ssrf]\nscheme=\"block\"\n[[exceptions]]\nrule=\"ssrf\"\nscript=\"/app/trusted.php\"\nreason=\"partner ftp\"";
        let c = init(toml);
        begin(c);
        let (url, s) = ("ftp://partner.example/x", "/app/trusted.php");
        let r = |script: &str| unsafe {
            howdah_sink_ssrf_scheme_at(
                c,
                HOWDAH_SSRF_VIA_CURL,
                url.as_ptr() as _,
                url.len(),
                script.as_ptr() as _,
                script.len(),
                std::ptr::null(),
                0,
            )
        };
        assert_eq!(r(s), HOWDAH_ALLOW, "excepted script");
        assert_eq!(r("/app/other.php"), HOWDAH_BLOCK, "any other script");
        FORCE_PANIC.with(|f| f.set(true));
        assert_eq!(ssrf_scheme(c, HOWDAH_SSRF_VIA_CURL, "gopher://h/"), HOWDAH_ALLOW);
        FORCE_PANIC.with(|f| f.set(false));
        unsafe { howdah_free(c) };
    }

    #[test]
    fn ssrf_pin_entry_ffi_roundtrip() {
        let recs = [rec4([93, 184, 216, 34]), rec4([93, 184, 216, 35])].concat();
        let url = b"https://Example.com:8443/x?y=1";
        let mut out = [0u8; 64];
        let n = unsafe { howdah_ssrf_pin_entry(url.as_ptr(), url.len(), recs.as_ptr(), 2, 1, out.as_mut_ptr(), out.len()) };
        assert_eq!(&out[..n], b"example.com:8443:93.184.216.34,93.184.216.35");
        let n = unsafe { howdah_ssrf_pin_entry(url.as_ptr(), url.len(), recs.as_ptr(), 2, 0, out.as_mut_ptr(), out.len()) };
        assert_eq!(&out[..n], b"example.com:8443:93.184.216.34");
        // Too small a buffer, a literal host, NULLs: nothing.
        assert_eq!(unsafe { howdah_ssrf_pin_entry(url.as_ptr(), url.len(), recs.as_ptr(), 2, 0, out.as_mut_ptr(), 8) }, 0);
        let lit = b"http://127.0.0.1/";
        assert_eq!(unsafe { howdah_ssrf_pin_entry(lit.as_ptr(), lit.len(), recs.as_ptr(), 2, 0, out.as_mut_ptr(), 64) }, 0);
        assert_eq!(unsafe { howdah_ssrf_pin_entry(std::ptr::null(), 0, std::ptr::null(), 0, 0, out.as_mut_ptr(), 64) }, 0);
    }

    #[test]
    fn ssrf_oversize_follows_mode() {
        let c = init("[sinks.ssrf]\nmode=\"block\"");
        begin(c);
        assert_eq!(unsafe { howdah_sink_ssrf_oversize(c) }, HOWDAH_BLOCK);
        let l = unsafe { howdah_take_sink_log_line(c) };
        assert!(!l.is_null());
        let s = unsafe { std::ffi::CStr::from_ptr(l) }.to_string_lossy().into_owned();
        assert!(s.contains("oversize host") && s.contains("ssrf"), "{s}");
        unsafe { howdah_free_str(l) };
        unsafe { howdah_free(c) };
        let c = init("[sinks.ssrf]\nmode=\"detect\"");
        begin(c);
        assert_eq!(unsafe { howdah_sink_ssrf_oversize(c) }, 1);
        unsafe { howdah_free(c) };
        let c = init("");
        begin(c);
        assert_eq!(unsafe { howdah_sink_ssrf_oversize(c) }, HOWDAH_ALLOW);
        unsafe { howdah_free(c) };
        assert_eq!(unsafe { howdah_sink_ssrf_oversize(std::ptr::null_mut()) }, 0);
    }

    #[test]
    fn ssrf_prepare_skips() {
        let (mut buf, mut n, mut port) = ([0u8; 8], 0usize, 0u16);
        let mut run = |i: &[u8], f: i32| unsafe {
            howdah_ssrf_prepare(i.as_ptr(), i.len(), f, buf.as_mut_ptr(), 8, &mut n, &mut port)
        };
        assert_eq!(run(b"/etc/passwd", 1), 0); // local path
        assert_eq!(run(b"unix:///var/run/x.sock", 0), 0);
        assert_eq!(run(b"example.com", 1), 0); // no scheme when required
        assert_eq!(run(b"http://averyveryverylonghost.example/", 1), 2); // oversize, not skip
        let r = unsafe {
            howdah_ssrf_prepare(std::ptr::null(), 0, 1, std::ptr::null_mut(), 0, std::ptr::null_mut(), std::ptr::null_mut())
        };
        assert_eq!(r, 0);
    }

    #[test]
    fn phar_arm_block_no_path_in_log() {
        let c = init("[sinks.phar]\nmode=\"block\"\nallow_paths=[\"/srv/app\"]");
        begin(c);
        assert_eq!(sink(c, HOWDAH_SINK_PHAR, "file_get_contents", b"phar:///tmp/secret/evil.phar/x"), HOWDAH_BLOCK);
        let line = take_sink(c).expect("line");
        assert!(line.contains("\"rule\":\"phar\""), "{line}");
        assert!(line.contains("\"action\":\"block\""), "{line}");
        assert!(!line.contains("secret") && !line.contains("evil"), "{line}");
        assert_eq!(sink(c, HOWDAH_SINK_PHAR, "f", b"phar:///srv/app/a.phar"), HOWDAH_ALLOW);
        assert!(take_sink(c).is_none());
        unsafe { howdah_free(c) };
    }

    #[test]
    fn phar_default_off_allows() {
        let c = init("");
        begin(c);
        assert_eq!(sink(c, HOWDAH_SINK_PHAR, "f", b"phar:///tmp/x.phar"), HOWDAH_ALLOW);
        assert!(take_sink(c).is_none());
        unsafe { howdah_free(c) };
    }

    #[test]
    fn ssrf_armed_reflects_mode() {
        let c = init("");
        assert_eq!(ssrf_armed(c), 0);
        unsafe { howdah_free(c) };
        let c = init("[sinks.ssrf]\nmode=\"detect\"");
        assert_eq!(ssrf_armed(c), 1);
        assert!(take_sink(c).is_none());
        unsafe { howdah_free(c) };
        let c = init("mode=\"off\"\n[sinks.ssrf]\nmode=\"block\"");
        assert_eq!(ssrf_armed(c), 0);
        unsafe { howdah_free(c) };
    }

    #[test]
    fn behavior_ffi_smoke() {
        let p = "/u/x.php";
        let exec = |c: *mut howdah_ctx| unsafe { howdah_behavior_check_exec_dir(c, p.as_ptr() as _, p.len()) };
        let c = init("[behavior]\ndeny_exec_dirs=[\"/u\"]");
        assert_eq!(exec(c), HOWDAH_LOG);
        let line = take_sink(c).unwrap();
        assert!(line.contains("upload_exec") || line.contains("UploadExec"), "{line}");
        assert!(!line.contains("x.php"));
        unsafe { howdah_free(c) };
        let c = init("[behavior]\nmode=\"block\"\ndeny_exec_dirs=[\"/u\"]");
        assert_eq!(exec(c), HOWDAH_BLOCK);
        assert!(take_sink(c).is_some());
        unsafe { howdah_free(c) };
        let c = init("[behavior]\nmode=\"block\"\ndeny_exec_dirs=[\"/u\"]");
        let o = "/safe/x.php";
        assert_eq!(unsafe { howdah_behavior_check_exec_dir(c, o.as_ptr() as _, o.len()) }, HOWDAH_ALLOW);
        assert!(take_sink(c).is_none());
        unsafe { howdah_free(c) };
        assert_eq!(unsafe { howdah_behavior_check_exec_dir(std::ptr::null_mut(), p.as_ptr() as _, p.len()) }, 0);
    }

    #[test]
    fn behavior_observe_never_blocks_and_proposes() {
        let p = "/u/x.php";
        let c = init("[behavior]\nobserve=true\nmode=\"block\"\ndeny_exec_dirs=[\"/u\"]");
        assert_eq!(unsafe { howdah_behavior_check_exec_dir(c, p.as_ptr() as _, p.len()) }, HOWDAH_LOG);
        let line = take_sink(c).unwrap();
        assert!(line.contains("proposed"), "{line}");
        assert!(!line.contains("x.php"));
        unsafe { howdah_free(c) };
        let c = init("[behavior]\nobserve=true\nallow_exec_binaries=[]");
        let (caller, prog) = ("/var/www/a.php", "/usr/bin/gs");
        let r = unsafe { howdah_behavior_check_binary(c, caller.as_ptr() as _, caller.len(), prog.as_ptr() as _, prog.len()) };
        assert_eq!(r, HOWDAH_LOG);
        assert!(take_sink(c).unwrap().contains("proposed"));
        unsafe { howdah_free(c) };
        let c = init("[behavior]\nmode=\"block\"\ndeny_exec_dirs=[\"/u\"]");
        assert_eq!(unsafe { howdah_behavior_check_exec_dir(c, p.as_ptr() as _, p.len()) }, HOWDAH_BLOCK);
        assert!(!take_sink(c).unwrap().contains("proposed"));
        unsafe { howdah_free(c) };
    }

    #[test]
    fn behavior_ffi_other_checks_and_armed() {
        let c = init(
            "[behavior]\nmode=\"block\"\ndeny_exec_dirs=[\"/u\"]\nallow_exec_binaries=[\"git\"]\nallow_egress_hosts=[\"ok.example\"]\ndeny_php_writes=true",
        );
        let (caller, prog, host, tgt) = ("/u/a.php", "/bin/nc", "evil.example", "/u/w.php");
        unsafe {
            assert_eq!(howdah_behavior_check_binary(c, caller.as_ptr() as _, caller.len(), prog.as_ptr() as _, prog.len()), HOWDAH_BLOCK);
            assert_eq!(howdah_behavior_check_egress(c, caller.as_ptr() as _, caller.len(), host.as_ptr() as _, host.len()), HOWDAH_BLOCK);
            assert_eq!(howdah_behavior_check_php_write(c, caller.as_ptr() as _, caller.len(), tgt.as_ptr() as _, tgt.len(), 1), HOWDAH_BLOCK);
            assert_eq!(howdah_behavior_check_php_write(c, caller.as_ptr() as _, caller.len(), tgt.as_ptr() as _, tgt.len(), 0), HOWDAH_ALLOW);
            for f in 0..4 {
                assert_eq!(howdah_behavior_armed(c, f), 1);
            }
            assert_eq!(howdah_behavior_egress_active(c), 1);
            assert_eq!(howdah_behavior_armed(c, 99), 0);
            assert_eq!(howdah_behavior_armed(std::ptr::null_mut(), 0), 0);
            howdah_free(c);
        }
        let c = init("");
        unsafe {
            for f in 0..4 {
                assert_eq!(howdah_behavior_armed(c, f), 0);
            }
            assert_eq!(howdah_behavior_egress_active(c), 0);
            howdah_free(c);
        }
        let c = init("mode=\"off\"\n[behavior]\ndeny_exec_dirs=[\"/u\"]");
        unsafe {
            assert_eq!(howdah_behavior_armed(c, HOWDAH_BEHAVIOR_EXEC_DIR), 0);
            howdah_free(c);
        }
    }

    #[test]
    fn behavior_ffi_panic_fails_open() {
        let c = init("[behavior]\nmode=\"block\"\ndeny_exec_dirs=[\"/u\"]");
        FORCE_PANIC.with(|f| f.set(true));
        let p = "/u/x.php";
        let r = unsafe { howdah_behavior_check_exec_dir(c, p.as_ptr() as _, p.len()) };
        FORCE_PANIC.with(|f| f.set(false));
        assert_eq!(r, HOWDAH_ALLOW);
        unsafe { howdah_free(c) };
    }

    #[test]
    fn sink_armed_per_sink() {
        let c = init("");
        unsafe {
            assert_eq!(howdah_sink_armed(c, HOWDAH_SINK_PHAR), 0);
            assert_eq!(howdah_sink_armed(c, HOWDAH_SINK_SSRF), 0);
            howdah_free(c);
        }
        let c = init("[sinks.phar]\nmode=\"detect\"");
        unsafe {
            assert_eq!(howdah_sink_armed(c, HOWDAH_SINK_PHAR), 1);
            assert_eq!(howdah_sink_armed(c, HOWDAH_SINK_SSRF), 0);
            assert_eq!(howdah_sink_armed(c, 99), 0);
            howdah_free(c);
            assert_eq!(howdah_sink_armed(std::ptr::null_mut(), HOWDAH_SINK_PHAR), 0);
        }
    }

    #[test]
    fn ssrf_armed_null_ctx_zero() {
        assert_eq!(ssrf_armed(std::ptr::null_mut()), 0);
    }

    #[test]
    fn ssrf_loopback_blocks_when_block() {
        let c = init("[sinks.ssrf]\nmode=\"block\"");
        begin(c);
        assert_eq!(ssrf(c, "evil.example", &[rec4([127, 0, 0, 1])]), HOWDAH_BLOCK);
        assert!(take_sink(c).unwrap().contains("\"action\":\"block\""));
        assert_eq!(ssrf(c, "ok.example", &[rec4([8, 8, 8, 8])]), HOWDAH_ALLOW);
        assert!(take_sink(c).is_none());
        let mut v6 = [0u8; 17];
        v6[0] = 6;
        v6[16] = 1;
        assert_eq!(ssrf(c, "v6.example", &[v6]), HOWDAH_BLOCK);
        assert!(take_sink(c).unwrap().contains("ip=::1"));
        unsafe { howdah_free(c) };
    }

    #[test]
    fn ssrf_literal_only_no_resolve() {
        let c = init("[sinks.ssrf]\nmode=\"block\"");
        begin(c);
        assert_eq!(ssrf(c, "2130706433", &[]), HOWDAH_BLOCK);
        assert!(take_sink(c).unwrap().contains("class=loopback"));
        unsafe { howdah_free(c) };
    }

    #[test]
    fn ssrf_allow_host_allows() {
        let c = init("[sinks.ssrf]\nmode=\"block\"\nallow_hosts=[\"internal.example\",\"10.0.0.0/8\"]");
        begin(c);
        assert_eq!(ssrf(c, "internal.example", &[rec4([127, 0, 0, 1])]), HOWDAH_ALLOW);
        assert_eq!(ssrf(c, "other.example", &[rec4([10, 1, 2, 3])]), HOWDAH_ALLOW);
        assert!(take_sink(c).is_none());
        assert_eq!(ssrf(c, "other.example", &[rec4([192, 168, 1, 1])]), HOWDAH_BLOCK);
        unsafe { howdah_free(c) };
    }

    #[test]
    fn ssrf_reason_has_class_not_url() {
        let c = init("[sinks.ssrf]\nmode=\"detect\"");
        begin(c);
        assert_eq!(ssrf(c, "user:pw@127.0.0.1/admin?token=secret", &[rec4([127, 0, 0, 1])]), HOWDAH_LOG);
        let line = take_sink(c).unwrap();
        assert!(line.contains("\"rule\":\"ssrf\""), "{line}");
        assert!(line.contains("class=loopback") && line.contains("host=127.0.0.1 port=80 ip=127.0.0.1"), "{line}");
        for bad in ["@", "user", "pw", "/admin", "?", "secret"] {
            assert!(!line.contains(bad), "leaked {bad:?}: {line}");
        }
        unsafe { howdah_free(c) };
    }

    #[test]
    fn ssrf_log_host_cut_before_userinfo_strip() {
        let c = init("[sinks.ssrf]\nmode=\"detect\"");
        begin(c);
        let cases = [
            ("evilhost/path?x=a@b.com", "host=evilhost port=80"),
            ("example.com/cb?email=a@b.com", "host=example.com port=80"),
            ("u:p@ss@host", "host=host port=80"),
            ("user:pw@127.0.0.1/admin?token=secret", "host=127.0.0.1 port=80"),
            ("[::1]:80", "host=[::1]:80 port=80"),
        ];
        for (h, want) in cases {
            assert_eq!(ssrf(c, h, &[rec4([127, 0, 0, 1])]), HOWDAH_LOG, "{h}");
            let line = take_sink(c).unwrap();
            assert!(line.contains(want), "{h}: {line}");
            for bad in ["b.com", "@", "ss@", "u:p"] {
                assert!(!line.contains(bad), "{h} leaked {bad:?}: {line}");
            }
        }
        unsafe { howdah_free(c) };
    }

    #[test]
    fn ssrf_resolve_failure_fails_open() {
        let c = init("[sinks.ssrf]\nmode=\"block\"");
        begin(c);
        assert_eq!(ssrf(c, "nonexistent.example", &[]), HOWDAH_ALLOW);
        assert!(take_sink(c).is_none());
        unsafe { howdah_free(c) };
    }

    #[test]
    fn panic_in_check_fails_open() {
        let c = init("[sinks.ssrf]\nmode=\"block\"");
        begin(c);
        FORCE_PANIC.with(|f| f.set(true));
        assert_eq!(ssrf(c, "2130706433", &[]), HOWDAH_ALLOW);
        FORCE_PANIC.with(|f| f.set(false));
        unsafe { howdah_free(c) };
    }

    #[test]
    fn null_ctx_guarded() {
        let n = std::ptr::null();
        assert_eq!(unsafe { howdah_sink_check_ssrf(std::ptr::null_mut(), n, 0, n, 0, 0, std::ptr::null(), 0) }, HOWDAH_ALLOW);
        let c = init("[sinks.ssrf]\nmode=\"block\"");
        begin(c);
        assert_eq!(unsafe { howdah_sink_check_ssrf(c, n, 0, n, 0, 0, std::ptr::null(), 5) }, HOWDAH_ALLOW);
        unsafe { howdah_free(c) };
    }

    #[test]
    fn log_config_accessor() {
        use crate::config::LogDestination;
        assert_eq!(unsafe { howdah_log_config(std::ptr::null()) }, crate::config::LogConfig::default());
        let c = init("[log]\ndestination = \"syslog\"\nsyslog_ident = \"shop\"\nexec = \"/usr/local/bin/h\"");
        let l = unsafe { howdah_log_config(c) };
        assert_eq!(l.destination(), LogDestination::Syslog);
        assert_eq!(l.ident(), "shop");
        assert_eq!(l.exec.as_deref(), Some("/usr/local/bin/h"));
        unsafe { howdah_free(c) };
        // A config the core rejects falls back to safe defaults, [log] included.
        let c = init("[log]\nexec = \"relative\"");
        assert_eq!(unsafe { howdah_log_config(c) }, crate::config::LogConfig::default());
        unsafe { howdah_free(c) };
    }

    #[test]
    fn sink_hook_plan_follows_config() {
        assert_eq!(unsafe { howdah_sink_hook_plan(std::ptr::null_mut()) }, HOWDAH_HOOK_PLAN_NONE);
        // Shipped defaults: the include firewall is on -> the hook is needed;
        // auto picks compile (firewall + eval are compile-covered), JIT stays on.
        let c = init("");
        assert_eq!(unsafe { howdah_sink_hook_plan(c) }, HOWDAH_HOOK_PLAN_COMPILE | (HOWDAH_HOOK_WHY_INCLUDE_FIREWALL << 4));
        unsafe { howdah_free(c) };
        let c = init("[sinks]\nhook = \"compile\"");
        assert_eq!(unsafe { howdah_sink_hook_plan(c) }, HOWDAH_HOOK_PLAN_COMPILE | (HOWDAH_HOOK_WHY_CONFIGURED << 4));
        unsafe { howdah_free(c) };
        let c = init("[sinks]\nhook = \"opcode\"");
        assert_eq!(unsafe { howdah_sink_hook_plan(c) }, HOWDAH_HOOK_PLAN_OPCODE | (HOWDAH_HOOK_WHY_CONFIGURED << 4));
        unsafe { howdah_free(c) };
        // include allow_paths flips auto to opcode.
        let c = init("[sinks.include]\nallow_paths = [\"/srv/app\"]");
        assert_eq!(unsafe { howdah_sink_hook_plan(c) }, HOWDAH_HOOK_PLAN_OPCODE | (HOWDAH_HOOK_WHY_INCLUDE_ALLOW_PATHS << 4));
        unsafe { howdah_free(c) };
        // Layer 4 deny_exec_dirs flips auto to opcode even with sinks disabled.
        let c = init("[sinks]\nenabled = false\n[behavior]\ndeny_exec_dirs = [\"/var/www/uploads\"]");
        assert_eq!(unsafe { howdah_sink_hook_plan(c) }, HOWDAH_HOOK_PLAN_OPCODE | (HOWDAH_HOOK_WHY_DENY_EXEC_DIRS << 4));
        unsafe { howdah_free(c) };
        // eval off but the firewall is on by default -> still compile.
        let c = init("[sinks.eval]\nmode = \"off\"");
        assert_eq!(unsafe { howdah_sink_hook_plan(c) }, HOWDAH_HOOK_PLAN_COMPILE | (HOWDAH_HOOK_WHY_INCLUDE_FIREWALL << 4));
        unsafe { howdah_free(c) };
        // Nothing armed (firewall + eval off), or global off / disabled: NONE.
        for toml in [
            "[sinks.include]\nwrapper = \"off\"\npoison = \"off\"\n[sinks.eval]\nmode = \"off\"",
            "[sinks]\nenabled = false",
            "mode = \"off\"\n[behavior]\ndeny_exec_dirs = [\"/x\"]",
        ] {
            let c = init(toml);
            assert_eq!(unsafe { howdah_sink_hook_plan(c) }, HOWDAH_HOOK_PLAN_NONE, "{toml}");
            unsafe { howdah_free(c) };
        }
    }

    fn mail(c: *mut howdah_ctx, headers: &[u8], params: &[u8]) -> i32 {
        unsafe {
            howdah_sink_check_mail(
                c,
                headers.as_ptr() as _,
                headers.len(),
                params.as_ptr() as _,
                params.len(),
            )
        }
    }

    #[test]
    fn legacy_sinks_log_by_default_block_when_armed_and_never_log_the_argument() {
        // Shipped defaults: every legacy sink inherits detect.
        let c = init("");
        begin(c);
        assert_eq!(mail(c, b"From: a@b.c", b"-fa@b.c"), HOWDAH_ALLOW);
        assert!(take_sink(c).is_none());
        assert_eq!(mail(c, b"From: a@b.c", b"-Oqueue=/tmp/SECRETDIR"), HOWDAH_LOG);
        let l = take_sink(c).unwrap();
        assert!(l.contains("\"rule\":\"mail_injection\"") && l.contains("\"layer\":3"), "{l}");
        assert!(!l.contains("SECRETDIR") && !l.contains("-O"), "{l}");
        assert_eq!(mail(c, b"X: 1\r\n\r\nSECRETBODY", b""), HOWDAH_LOG);
        assert!(!take_sink(c).unwrap().contains("SECRETBODY"));
        assert_eq!(sink(c, HOWDAH_SINK_PREG_EVAL, "preg_replace", b"/SECRETPAT/e"), HOWDAH_LOG);
        let l = take_sink(c).unwrap();
        assert!(l.contains("\"rule\":\"preg_eval\"") && !l.contains("SECRETPAT"), "{l}");
        assert_eq!(sink(c, HOWDAH_SINK_PREG_EVAL, "preg_replace", b"/x/i"), HOWDAH_ALLOW);
        assert_eq!(sink(c, HOWDAH_SINK_CREATE_FUNCTION, "create_function", b"return SECRETCODE;"), HOWDAH_LOG);
        let l = take_sink(c).unwrap();
        assert!(l.contains("\"rule\":\"create_function\"") && !l.contains("SECRETCODE"), "{l}");
        assert_eq!(sink(c, HOWDAH_SINK_ASSERT, "assert", b"SECRETEXPR"), HOWDAH_LOG);
        assert!(take_sink(c).unwrap().contains("\"rule\":\"assert_string\""));
        assert_eq!(sink(c, HOWDAH_SINK_CALLBACK, "array_map", b"system"), HOWDAH_LOG);
        let l = take_sink(c).unwrap();
        assert!(l.contains("\"rule\":\"dangerous_callback\"") && l.contains("'system' via array_map"), "{l}");
        assert_eq!(sink(c, HOWDAH_SINK_CALLBACK, "array_map", b"trim"), HOWDAH_ALLOW);
        assert!(take_sink(c).is_none());
        // xml has its own flag-aware entry point (xml_check below); the
        // one-argument path never reports it.
        assert_eq!(
            sink(c, HOWDAH_SINK_XML, "simplexml_load_string", b"<!DOCTYPE r [<!ENTITY x SYSTEM \"file:///SECRETPATH\">]><r/>"),
            HOWDAH_ALLOW
        );
        assert!(take_sink(c).is_none());
        assert_eq!(sink(c, HOWDAH_SINK_TLS, "curl_setopt", b"verifypeer"), HOWDAH_LOG);
        let l = take_sink(c).unwrap();
        assert!(l.contains("\"rule\":\"tls_verify\"") && l.contains("VERIFYPEER"), "{l}");
        assert_eq!(sink(c, HOWDAH_SINK_TLS, "curl_setopt", b"other"), HOWDAH_ALLOW);
        unsafe { howdah_free(c) };

        // Armed: block, except tls which is detect-only (clamped to log).
        let c = init("[sinks]\nmode=\"block\"");
        begin(c);
        assert_eq!(mail(c, b"", b"-X/tmp/f"), HOWDAH_BLOCK);
        assert!(take_sink(c).unwrap().contains("\"action\":\"block\""));
        assert_eq!(sink(c, HOWDAH_SINK_PREG_EVAL, "preg_replace", b"/a/e"), HOWDAH_BLOCK);
        assert_eq!(sink(c, HOWDAH_SINK_CREATE_FUNCTION, "create_function", b"1;"), HOWDAH_BLOCK);
        assert_eq!(sink(c, HOWDAH_SINK_ASSERT, "assert", b"1"), HOWDAH_BLOCK);
        assert_eq!(sink(c, HOWDAH_SINK_CALLBACK, "call_user_func", b"\\exec"), HOWDAH_BLOCK);
        assert_eq!(sink(c, HOWDAH_SINK_TLS, "curl_setopt_array", b"verifyhost"), HOWDAH_LOG);
        let l = take_sink(c).unwrap();
        assert!(l.contains("\"action\":\"log\"") && l.contains("VERIFYHOST"), "{l}");
        unsafe { howdah_free(c) };

        // Per-sink off and global off: silent; armed flags follow.
        let c = init("[sinks.callback]\nmode=\"off\"");
        begin(c);
        assert_eq!(sink(c, HOWDAH_SINK_CALLBACK, "array_map", b"system"), HOWDAH_ALLOW);
        assert!(take_sink(c).is_none());
        unsafe {
            assert_eq!(howdah_sink_armed(c, HOWDAH_SINK_CALLBACK), 0);
            assert_eq!(howdah_sink_armed(c, HOWDAH_SINK_MAIL), 1);
            assert_eq!(howdah_sink_armed(c, HOWDAH_SINK_TLS), 1);
            assert_eq!(howdah_sink_xml_deny_external_entities(c), 0);
            howdah_free(c);
        }
        let c = init("mode=\"off\"\n[sinks.xml]\nexternal_entities=\"deny\"");
        begin(c);
        assert_eq!(mail(c, b"", b"-X/tmp/f"), HOWDAH_ALLOW);
        unsafe {
            assert_eq!(howdah_sink_xml_deny_external_entities(c), 0);
            howdah_free(c);
        }
        let c = init("[sinks.xml]\nexternal_entities=\"deny\"");
        unsafe {
            assert_eq!(howdah_sink_xml_deny_external_entities(c), 1);
            assert_eq!(howdah_sink_xml_deny_external_entities(std::ptr::null_mut()), 0);
            assert_eq!(howdah_sink_check_mail(std::ptr::null_mut(), std::ptr::null(), 0, std::ptr::null(), 0), HOWDAH_ALLOW);
            assert_eq!(howdah_sink_check_mail(c, std::ptr::null(), 0, std::ptr::null(), 0), HOWDAH_ALLOW);
            howdah_free(c);
        }
    }

    fn xml_check(c: *mut howdah_ctx, name: &str, doc: &[u8], flags: i64, caps: i32) -> i32 {
        unsafe {
            howdah_sink_check_xml(
                c,
                name.as_ptr() as _,
                name.len(),
                doc.as_ptr() as _,
                doc.len(),
                flags,
                caps,
                std::ptr::null(),
                0,
                std::ptr::null(),
                0,
            )
        }
    }

    const XXE_DOC: &[u8] =
        b"<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY x SYSTEM \"file:///SECRETPATH\">]><r>&x;</r>";
    const SVG_DOC: &[u8] = b"<?xml version=\"1.0\"?><!DOCTYPE svg PUBLIC \"-//W3C//DTD SVG 1.1//EN\" \"http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd\"><svg/>";

    #[test]
    fn xxe_blocks_only_a_dangerous_flag_with_an_external_entity_by_default() {
        // Shipped config: no [sinks] section at all, global detect. The xxe rule
        // still enforces (like cgi_arg_injection), and only on flag AND entity.
        let c = init("");
        begin(c);
        let strip = HOWDAH_XML_CAN_STRIP;
        // dangerous flag + external entity: stripped (block), logged as block,
        // document never logged, flags named from a fixed vocabulary.
        assert_eq!(xml_check(c, "simplexml_load_string", XXE_DOC, 2, strip), HOWDAH_STRIP);
        let l = take_sink(c).unwrap();
        assert!(l.contains("\"rule\":\"xxe\"") && l.contains("\"layer\":3"), "{l}");
        assert!(l.contains("\"action\":\"block\"") && l.contains("LIBXML_NOENT"), "{l}");
        assert!(l.contains("dangerous flags removed, parse continued"), "{l}");
        assert!(!l.contains("SECRETPATH") && !l.contains("passwd"), "{l}");
        // every dangerous flag, and combinations
        for f in [4, 8, 16, 2 | 4, 14, 30, 2 | 16384, 2 | 1 << 19] {
            assert_eq!(xml_check(c, "DOMDocument::loadXML", XXE_DOC, f, strip), HOWDAH_STRIP, "flags {f}");
            assert!(take_sink(c).is_some());
        }
        // no dangerous flag: silent, whatever the document
        for f in [0, 1, 32, 64, 256, 1024, 2048, 16384, 1 << 19] {
            assert_eq!(xml_check(c, "simplexml_load_string", XXE_DOC, f, strip), HOWDAH_ALLOW, "flags {f}");
            assert!(take_sink(c).is_none());
        }
        // A bare DOCTYPE / SAML / SVG / Office-style document: never blocked
        // under any flags; a bare external DTD logs only when a flag fetches it.
        for f in [0, 2, 4, 8, 16, 30, 31] {
            for doc in [
                &b"<!DOCTYPE html><html/>"[..],
                b"<?xml version=\"1.0\"?><samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"/>",
                b"<?xml version=\"1.0\"?><!DOCTYPE r [<!ELEMENT r ANY><!ENTITY co \"ACME\">]><r>&co;</r>",
                SVG_DOC,
            ] {
                let a = xml_check(c, "DOMDocument::loadXML", doc, f, strip);
                assert!(a == HOWDAH_ALLOW || a == HOWDAH_LOG, "flags {f}: {a}");
                let line = take_sink(c);
                assert_eq!(a == HOWDAH_LOG, line.is_some());
                if let Some(line) = line {
                    assert!(f & 12 != 0 && line.contains("external DTD") && line.contains("\"action\":\"log\""), "{line}");
                }
            }
        }
        // Without the strip capability a block refuses the call.
        assert_eq!(xml_check(c, "simplexml_load_string", XXE_DOC, 2, 0), HOWDAH_BLOCK);
        assert!(take_sink(c).unwrap().contains("call refused"));
        // libxml before 2.9 resolves entities whatever the flags: flags 0 is
        // not a pass, and the flags cannot be stripped, so the call is refused.
        let old = HOWDAH_XML_CAN_STRIP | HOWDAH_XML_ENGINE_IGNORES_FLAGS;
        assert_eq!(xml_check(c, "simplexml_load_string", XXE_DOC, 0, old), HOWDAH_BLOCK);
        let l = take_sink(c).unwrap();
        assert!(l.contains("before 2.9") && l.contains("call refused") && !l.contains("SECRETPATH"), "{l}");
        assert_eq!(xml_check(c, "simplexml_load_string", b"<r/>", 0, old), HOWDAH_ALLOW);
        // an entity bomb is the same class
        let mut bomb = String::from("<!DOCTYPE l [<!ENTITY a0 \"lol\">");
        for k in 1..=9 {
            bomb.push_str(&format!("<!ENTITY a{k} \"{}\">", format!("&a{};", k - 1).repeat(10)));
        }
        bomb.push_str("]><l>&a9;</l>");
        assert_eq!(xml_check(c, "simplexml_load_string", bomb.as_bytes(), 2, strip), HOWDAH_STRIP);
        assert!(take_sink(c).unwrap().contains("expand past 1 MiB"));
        assert_eq!(xml_check(c, "simplexml_load_string", bomb.as_bytes(), 0, strip), HOWDAH_ALLOW);
        unsafe { howdah_free(c) };

        // Shipped howdah.mode = detect and an explicit [sinks] detect do not
        // soften it; sinks off does not either (own knob); global off does.
        let c = init("[sinks]\nmode=\"detect\"");
        begin(c);
        assert_eq!(xml_check(c, "simplexml_load_string", XXE_DOC, 2, strip), HOWDAH_STRIP);
        unsafe { howdah_free(c) };
        let c = init("mode=\"off\"");
        begin(c);
        assert_eq!(xml_check(c, "simplexml_load_string", XXE_DOC, 2, strip), HOWDAH_ALLOW);
        assert!(take_sink(c).is_none());
        unsafe { howdah_free(c) };
        let c = init("[sinks]\nenabled=false");
        begin(c);
        assert_eq!(xml_check(c, "simplexml_load_string", XXE_DOC, 2, strip), HOWDAH_ALLOW);
        unsafe { howdah_free(c) };

        // [sinks.xml] mode: detect logs and leaves the call alone; off is silent.
        let c = init("[sinks.xml]\nmode=\"detect\"");
        begin(c);
        assert_eq!(xml_check(c, "simplexml_load_string", XXE_DOC, 2, strip), HOWDAH_LOG);
        let l = take_sink(c).unwrap();
        assert!(l.contains("\"action\":\"log\"") && !l.contains("removed") && !l.contains("refused"), "{l}");
        unsafe { howdah_free(c) };
        let c = init("[sinks.xml]\nmode=\"off\"");
        begin(c);
        assert_eq!(xml_check(c, "simplexml_load_string", XXE_DOC, 2, strip), HOWDAH_ALLOW);
        assert!(take_sink(c).is_none());
        unsafe {
            assert_eq!(howdah_sink_armed(c, HOWDAH_SINK_XML), 0);
            howdah_free(c);
        }
        // Armed by default (so the glue installs the hooks with no config).
        let c = init("");
        unsafe {
            assert_eq!(howdah_sink_armed(c, HOWDAH_SINK_XML), 1);
            assert_eq!(
                howdah_sink_check_xml(std::ptr::null_mut(), std::ptr::null(), 0, std::ptr::null(), 0, 2, 1, std::ptr::null(), 0, std::ptr::null(), 0),
                HOWDAH_ALLOW
            );
            howdah_free(c);
        }
    }

    #[test]
    fn xml_dangerous_flags_mirror_the_scanner() {
        assert_eq!(HOWDAH_XML_DANGEROUS_FLAGS, legacy::XML_DANGEROUS_FLAGS);
        assert_eq!(HOWDAH_XML_DANGEROUS_FLAGS, 2 | 4 | 8 | 16); // NOENT|DTDLOAD|DTDATTR|DTDVALID
    }

    #[test]
    fn xxe_script_exception_silences_the_rule() {
        let c = init("[[exceptions]]\nrule = \"sinks.xxe\"\nscript = \"/srv/app/dom.php\"\nreason = \"trusted local DocBook build\"");
        begin(c);
        let at = |script: &str| unsafe {
            howdah_sink_check_xml(
                c,
                b"DOMDocument::loadXML".as_ptr() as _,
                20,
                XXE_DOC.as_ptr() as _,
                XXE_DOC.len(),
                2,
                HOWDAH_XML_CAN_STRIP,
                script.as_ptr() as _,
                script.len(),
                std::ptr::null(),
                0,
            )
        };
        assert_eq!(at("/srv/app/dom.php"), HOWDAH_ALLOW);
        assert_eq!(at("/srv/app/other.php"), HOWDAH_STRIP);
        unsafe { howdah_free(c) };
    }

    /// The ext glue routes every one-argument sink through the `_at` entry
    /// point (exceptions-aware), which has its own sink-id map: each legacy
    /// id must be known there too (the lab caught `array_map('system')`
    /// falling through to ALLOW when only the original map was extended).
    #[test]
    fn legacy_sink_ids_are_known_to_the_at_entry_point() {
        let c = init("");
        begin(c);
        let at = |id: i32, name: &str, arg: &[u8]| unsafe {
            howdah_sink_check_at(
                c,
                id,
                name.as_ptr() as _,
                name.len(),
                arg.as_ptr() as _,
                arg.len(),
                std::ptr::null(),
                0,
                std::ptr::null(),
                0,
            )
        };
        for (id, name, arg, rule) in [
            (HOWDAH_SINK_PREG_EVAL, "preg_replace", &b"/a/e"[..], "preg_eval"),
            (HOWDAH_SINK_CREATE_FUNCTION, "create_function", b"1;", "create_function"),
            (HOWDAH_SINK_ASSERT, "assert", b"1", "assert_string"),
            (HOWDAH_SINK_CALLBACK, "array_map", b"system", "dangerous_callback"),
            (HOWDAH_SINK_TLS, "curl_setopt", b"verifypeer", "tls_verify"),
        ] {
            assert_eq!(at(id, name, arg), HOWDAH_LOG, "{rule} via _at");
            let l = take_sink(c).unwrap_or_else(|| panic!("{rule}: no line via _at"));
            assert!(l.contains(&format!("\"rule\":\"{rule}\"")), "{l}");
        }
        // Benign arguments stay silent through the same path.
        assert_eq!(at(HOWDAH_SINK_CALLBACK, "array_map", b"trim"), HOWDAH_ALLOW);
        assert!(take_sink(c).is_none());
        unsafe { howdah_free(c) };
    }

    #[test]
    fn null_args_are_safe() {
        unsafe {
            howdah_request_begin(std::ptr::null_mut(), std::ptr::null(), 0, std::ptr::null());
            assert_eq!(howdah_feed(std::ptr::null_mut(), std::ptr::null(), 5), 0);
            assert_eq!(howdah_request_end(std::ptr::null_mut()), 0);
            assert!(howdah_take_log_line(std::ptr::null_mut()).is_null());
            howdah_free_str(std::ptr::null_mut());
            howdah_free(std::ptr::null_mut());
            let c = howdah_init(std::ptr::null(), 0);
            howdah_request_begin(c, std::ptr::null(), 0, std::ptr::null());
            assert_eq!(howdah_feed(c, std::ptr::null(), 0), 0);
            howdah_free(c);
        }
    }

    // ---- scoped [[exceptions]] ------------------------------------------------

    fn sink_at(c: *mut howdah_ctx, id: i32, name: &str, arg: &[u8], script: &str, sha: Option<&[u8; 32]>) -> i32 {
        unsafe {
            howdah_sink_check_at(
                c,
                id,
                name.as_ptr() as _,
                name.len(),
                arg.as_ptr() as _,
                arg.len(),
                script.as_ptr() as _,
                script.len(),
                sha.map_or(std::ptr::null(), |h| h.as_ptr()),
                sha.map_or(0, |_| 32),
            )
        }
    }
    fn begin_from(c: *mut howdah_ctx, ip: &str, uri: &str) {
        let m = "GET";
        let meta = RequestMeta {
            client_ip: ip.as_ptr() as _,
            client_ip_len: ip.len(),
            method: m.as_ptr() as _,
            method_len: m.len(),
            uri: uri.as_ptr() as _,
            uri_len: uri.len(),
        };
        unsafe { howdah_request_begin(c, std::ptr::null(), 0, &meta) };
    }

    const EXC_SINK: &str = "mode = \"detect\"\n[sinks]\nmode = \"block\"\n\
        [[exceptions]]\nrule = \"sinks.command_exec\"\nscript = \"/var/www/cron.php\"\nreason = \"cron mailer\"\n";

    #[test]
    fn sink_exception_by_script_silences_only_that_script() {
        let c = init(EXC_SINK);
        begin(c);
        assert_eq!(unsafe { howdah_exceptions_count(c) }, 1);
        // Matching script: allowed, no line.
        assert_eq!(sink_at(c, HOWDAH_SINK_COMMAND_EXEC, "system", b"id", "/var/www/cron.php", None), HOWDAH_ALLOW);
        assert!(take_sink(c).is_none());
        // Another script: blocked and logged.
        assert_eq!(sink_at(c, HOWDAH_SINK_COMMAND_EXEC, "system", b"id", "/var/www/other.php", None), HOWDAH_BLOCK);
        let line = take_sink(c).unwrap();
        assert!(line.contains("\"rule\":\"command_exec\"") && line.contains("\"action\":\"block\""), "{line}");
        // Same script, a different sink: not covered.
        assert_eq!(sink_at(c, HOWDAH_SINK_EVAL, "eval", b"1;", "/var/www/cron.php", None), HOWDAH_BLOCK);
        assert!(take_sink(c).is_some());
        // The script-less entry point cannot match a script facet.
        assert_eq!(sink(c, HOWDAH_SINK_COMMAND_EXEC, "system", b"id"), HOWDAH_BLOCK);
        unsafe { howdah_free(c) };
    }

    #[test]
    fn sink_exception_by_hash_and_want_hash_gate() {
        let body = b"<?php system('true');";
        let d = crate::exceptions::sha256::digest(body);
        let hex = crate::exceptions::sha256::hex(&d);
        let toml = format!(
            "mode = \"detect\"\n[sinks]\nmode = \"block\"\n[[exceptions]]\nrule = \"command_exec\"\nscript_sha256 = \"{hex}\"\nreason = \"pinned\"\n"
        );
        let c = init(&toml);
        begin(c);
        let p = "/srv/x.php";
        assert_eq!(unsafe { howdah_exceptions_want_hash(c, p.as_ptr() as _, p.len()) }, 1);
        assert_eq!(sink_at(c, HOWDAH_SINK_COMMAND_EXEC, "system", b"true", p, Some(&d)), HOWDAH_ALLOW);
        let other = crate::exceptions::sha256::digest(b"<?php system('false');");
        assert_eq!(sink_at(c, HOWDAH_SINK_COMMAND_EXEC, "system", b"true", p, Some(&other)), HOWDAH_BLOCK);
        assert_eq!(sink_at(c, HOWDAH_SINK_COMMAND_EXEC, "system", b"true", p, None), HOWDAH_BLOCK);
        unsafe { howdah_free(c) };
        // No hash facet anywhere: the gate says no.
        let c = init(EXC_SINK);
        assert_eq!(unsafe { howdah_exceptions_want_hash(c, p.as_ptr() as _, p.len()) }, 0);
        unsafe { howdah_free(c) };
        assert_eq!(unsafe { howdah_exceptions_want_hash(std::ptr::null_mut(), p.as_ptr() as _, p.len()) }, 0);
    }

    #[test]
    fn sink_exception_never_widens_allowlist_or_arms_anything() {
        // Exception present but the call comes from another script: the
        // allowlist still decides; an exception never changes it.
        let c = init(EXC_SINK);
        begin(c);
        assert_eq!(sink_at(c, HOWDAH_SINK_COMMAND_EXEC, "system", b"id", "/var/www/other.php", None), HOWDAH_BLOCK);
        unsafe { howdah_free(c) };
        // Sink off: an exception cannot arm it.
        let c = init("mode = \"detect\"\n[sinks]\nmode = \"off\"\n[[exceptions]]\nrule = \"sinks\"\nscript = \"/a.php\"\nreason = \"x\"\n");
        begin(c);
        assert_eq!(sink_at(c, HOWDAH_SINK_COMMAND_EXEC, "system", b"id", "/b.php", None), HOWDAH_ALLOW);
        assert!(take_sink(c).is_none());
        unsafe { howdah_free(c) };
    }

    #[test]
    fn exceptions_log_writes_excepted_line_for_sink() {
        let c = init(&format!("exceptions_log = true\n{EXC_SINK}"));
        begin(c);
        assert_eq!(sink_at(c, HOWDAH_SINK_COMMAND_EXEC, "system", b"id", "/var/www/cron.php", None), HOWDAH_ALLOW);
        let line = take_sink(c).expect("excepted line");
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["action"], "excepted");
        assert_eq!(v["rule"], "command_exec");
        assert_eq!(v["reason"], "exception #0 (sinks.command_exec): cron mailer");
        assert!(!line.contains("\"id\""), "argument leaked: {line}");
        unsafe { howdah_free(c) };
    }

    const EXC_L2: &str = "mode = \"detect\"\n[inspect]\nmode = \"block\"\n\
        [[exceptions]]\nrule = \"inspect.sql_injection\"\nparam = \"q\"\nreason = \"editors\"\n";

    #[test]
    fn layer2_param_exception_silences_one_rule_for_one_param() {
        let c = init(EXC_L2);
        begin(c);
        let sqli = b"' OR 1=1 --";
        assert_eq!(inspect(c, HOWDAH_SRC_GET, "q", sqli), HOWDAH_ALLOW);
        assert_eq!(inspect(c, HOWDAH_SRC_POST, "q", sqli), HOWDAH_ALLOW);
        assert!(take(c).is_none());
        // Another parameter: blocked.
        assert_eq!(inspect(c, HOWDAH_SRC_GET, "other", sqli), HOWDAH_BLOCK);
        let line = take(c).unwrap();
        assert!(line.contains("sql_injection") && line.contains("\"action\":\"block\""), "{line}");
        unsafe { howdah_free(c) };
        // Same parameter, another class: still caught.
        let c = init(EXC_L2);
        begin(c);
        assert_eq!(inspect(c, HOWDAH_SRC_GET, "q", b"../../etc/passwd"), HOWDAH_BLOCK);
        assert!(take(c).unwrap().contains("path_traversal"));
        unsafe { howdah_free(c) };
    }

    #[test]
    fn layer2_param_prefix_uri_and_cidr_facets() {
        let toml = "mode = \"detect\"\n[inspect]\nmode = \"block\"\n\
            [[exceptions]]\nrule = \"inspect\"\nparam_prefix = \"jform[\"\nuri_prefix = \"/administrator/\"\nclient_cidr = \"10.0.0.0/8\"\nreason = \"joomla admin\"\n";
        let c = init(toml);
        let sqli = b"' OR 1=1 --";
        begin_from(c, "10.1.1.1", "/administrator/index.php");
        assert_eq!(inspect(c, HOWDAH_SRC_POST, "jform[articletext]", sqli), HOWDAH_ALLOW);
        assert_eq!(inspect(c, HOWDAH_SRC_POST, "other", sqli), HOWDAH_BLOCK);
        begin_from(c, "10.1.1.1", "/index.php");
        assert_eq!(inspect(c, HOWDAH_SRC_POST, "jform[articletext]", sqli), HOWDAH_BLOCK);
        begin_from(c, "192.0.2.1", "/administrator/index.php");
        assert_eq!(inspect(c, HOWDAH_SRC_POST, "jform[articletext]", sqli), HOWDAH_BLOCK);
        unsafe { howdah_free(c) };
    }

    #[test]
    fn layer2_excepted_line_uses_request_slot_once_and_yields_to_real_hit() {
        let c = init(&format!("exceptions_log = true\n{EXC_L2}"));
        // No multipart boundary: a plain GET request.
        begin_from(c, "1.2.3.4", "/up");
        let sqli = b"' OR 1=1 --";
        assert_eq!(inspect(c, HOWDAH_SRC_GET, "q", sqli), HOWDAH_ALLOW);
        assert_eq!(inspect(c, HOWDAH_SRC_GET, "q", sqli), HOWDAH_ALLOW);
        assert_eq!(unsafe { howdah_request_end(c) }, HOWDAH_ALLOW);
        let line = take(c).unwrap();
        assert!(line.contains("\"action\":\"excepted\"") && line.contains("sql_injection"), "{line}");
        assert!(take(c).is_none(), "one line per request");
        begin_from(c, "1.2.3.4", "/up");
        assert_eq!(inspect(c, HOWDAH_SRC_GET, "q", sqli), HOWDAH_ALLOW);
        assert_eq!(inspect(c, HOWDAH_SRC_GET, "other", sqli), HOWDAH_BLOCK);
        let line = take(c).unwrap();
        assert!(line.contains("\"action\":\"block\""), "real hit replaces excepted: {line}");
        unsafe { howdah_free(c) };
    }

    #[test]
    fn layer1_standard_exception_by_client_cidr() {
        let toml = "mode = \"block\"\n[limits]\nmax_input_key_bytes = 4\n\
            [[exceptions]]\nrule = \"max_input_key_bytes\"\nclient_cidr = \"127.0.0.0/8\"\nreason = \"local tooling\"\n";
        let c = init(toml);
        begin_from(c, "127.0.0.1", "/x");
        let name = b"a_very_long_key";
        assert_eq!(unsafe { howdah_input_var(c, name.as_ptr() as _, name.len()) }, HOWDAH_ALLOW);
        assert_eq!(unsafe { howdah_request_end(c) }, HOWDAH_ALLOW);
        assert!(take(c).is_none());
        begin_from(c, "203.0.113.9", "/x");
        assert_eq!(unsafe { howdah_input_var(c, name.as_ptr() as _, name.len()) }, HOWDAH_BLOCK);
        assert!(take(c).unwrap().contains("max_input_key_bytes"));
        unsafe { howdah_free(c) };
    }

    #[test]
    fn layer1_critical_is_never_excepted_even_by_layer_selector() {
        // `limits` as a layer compiles (it covers the Standard rules) and the
        // Critical flood limit still blocks for a matching client.
        let toml = "mode = \"detect\"\n[limits]\nmax_parts = 1\n\
            [[exceptions]]\nrule = \"limits\"\nclient_cidr = \"1.2.3.0/24\"\nreason = \"x\"\n";
        let c = init(toml);
        begin(c);
        let two = b"--B\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nx\r\n--B\r\nContent-Disposition: form-data; name=\"b\"\r\n\r\nx\r\n--B--\r\n";
        assert_eq!(feed(c, two), HOWDAH_BLOCK);
        assert!(take(c).unwrap().contains("max_parts"));
        unsafe { howdah_free(c) };
        // And a direct Critical selector never loads: safe defaults instead.
        let c = init("[[exceptions]]\nrule = \"max_parts\"\nuri_prefix = \"/\"\nreason = \"x\"");
        assert_eq!(unsafe { howdah_exceptions_count(c) }, 0);
        unsafe { howdah_free(c) };
    }

    #[test]
    fn request_client_ip_fills_only_when_empty() {
        let c = init("mode = \"detect\"");
        begin_from(c, "", "/x");
        let ip = "127.0.0.1";
        unsafe { howdah_request_client_ip(c, ip.as_ptr() as _, ip.len()) };
        let bogus = "<script>";
        unsafe { howdah_request_client_ip(c, bogus.as_ptr() as _, bogus.len()) };
        assert_eq!(unsafe { (*c).meta.client_ip.as_str() }, "127.0.0.1");
        begin_from(c, "10.0.0.1", "/x");
        unsafe { howdah_request_client_ip(c, ip.as_ptr() as _, ip.len()) };
        assert_eq!(unsafe { (*c).meta.client_ip.as_str() }, "10.0.0.1");
        begin_from(c, "", "/x");
        unsafe { howdah_request_client_ip(c, bogus.as_ptr() as _, bogus.len()) };
        assert_eq!(unsafe { (*c).meta.client_ip.as_str() }, "");
        unsafe { howdah_request_client_ip(std::ptr::null_mut(), ip.as_ptr() as _, ip.len()) };
        unsafe { howdah_free(c) };
    }

    #[test]
    fn behavior_exception_by_script_glob_and_at_entry_points() {
        let toml = "mode = \"detect\"\n[behavior]\nmode = \"block\"\ndeny_php_writes = true\ndeny_exec_dirs = [\"/var/www/uploads\"]\n\
            [[exceptions]]\nrule = \"behavior.php_write\"\nscript = \"/var/www/app/**\"\nreason = \"template compiler\"\n";
        let c = init(toml);
        begin(c);
        let target = "/var/www/uploads/x.php";
        let call = |caller: &str| unsafe {
            howdah_behavior_check_php_write_at(
                c,
                caller.as_ptr() as _,
                caller.len(),
                target.as_ptr() as _,
                target.len(),
                1,
                std::ptr::null(),
                0,
                0,
            )
        };
        assert_eq!(call("/var/www/app/compile.php"), HOWDAH_ALLOW);
        assert!(take_sink(c).is_none());
        assert_eq!(call("/var/www/other/x.php"), HOWDAH_BLOCK);
        assert!(take_sink(c).unwrap().contains("php_write"));
        // upload_exec is not covered by a php_write exception.
        let p = "/var/www/uploads/shell.php";
        assert_eq!(
            unsafe { howdah_behavior_check_exec_dir_at(c, p.as_ptr() as _, p.len(), std::ptr::null(), 0) },
            HOWDAH_BLOCK
        );
        // binary / egress _at variants behave like the originals with no exception.
        let prog = "xmrig";
        let caller = "/var/www/uploads/shell.php";
        assert_eq!(
            unsafe {
                howdah_behavior_check_binary_at(c, caller.as_ptr() as _, caller.len(), prog.as_ptr() as _, prog.len(), std::ptr::null(), 0)
            },
            HOWDAH_BLOCK
        );
        let host = "evil.test";
        assert_eq!(
            unsafe {
                howdah_behavior_check_egress_at(c, caller.as_ptr() as _, caller.len(), host.as_ptr() as _, host.len(), std::ptr::null(), 0)
            },
            HOWDAH_BLOCK
        );
        unsafe { howdah_free(c) };
    }

    #[test]
    fn ssrf_at_entry_points_honour_script_exception() {
        let toml = "mode = \"detect\"\n[sinks.ssrf]\nmode = \"block\"\n\
            [[exceptions]]\nrule = \"ssrf\"\nscript = \"/var/www/fetch.php\"\nreason = \"internal api\"\n";
        let c = init(toml);
        begin(c);
        let (sch, host) = ("http", "127.0.0.1");
        let call = |script: &str| unsafe {
            howdah_sink_check_ssrf_at(
                c,
                sch.as_ptr() as _,
                sch.len(),
                host.as_ptr() as _,
                host.len(),
                80,
                std::ptr::null(),
                0,
                script.as_ptr() as _,
                script.len(),
                std::ptr::null(),
                0,
            )
        };
        assert_eq!(call("/var/www/fetch.php"), HOWDAH_ALLOW);
        assert!(take_sink(c).is_none());
        assert_eq!(call("/var/www/other.php"), HOWDAH_BLOCK);
        assert!(take_sink(c).unwrap().contains("ssrf"));
        let s = "/var/www/fetch.php";
        assert_eq!(unsafe { howdah_sink_ssrf_oversize_at(c, s.as_ptr() as _, s.len(), std::ptr::null(), 0) }, HOWDAH_ALLOW);
        let o = "/var/www/other.php";
        assert_eq!(unsafe { howdah_sink_ssrf_oversize_at(c, o.as_ptr() as _, o.len(), std::ptr::null(), 0) }, HOWDAH_BLOCK);
        unsafe { howdah_free(c) };
    }

    #[test]
    fn no_exceptions_means_byte_identical_behaviour() {
        // The script-aware entry points with no [[exceptions]] give the same
        // verdicts and lines as the originals.
        let c = init("mode = \"detect\"\n[sinks]\nmode = \"block\"");
        begin(c);
        assert_eq!(sink_at(c, HOWDAH_SINK_COMMAND_EXEC, "system", b"id", "/a.php", None), HOWDAH_BLOCK);
        let a = take_sink(c).unwrap();
        assert_eq!(sink(c, HOWDAH_SINK_COMMAND_EXEC, "system", b"id"), HOWDAH_BLOCK);
        let b = take_sink(c).unwrap();
        let strip = |s: &str| -> serde_json::Value {
            let mut v: serde_json::Value = serde_json::from_str(s).unwrap();
            v.as_object_mut().unwrap().remove("ts");
            v
        };
        assert_eq!(strip(&a), strip(&b));
        assert_eq!(unsafe { howdah_exceptions_count(c) }, 0);
        unsafe { howdah_free(c) };
    }

    // ---- howdah_inspect_armed: "can Layer 2 return Block for some class?" ----

    fn inspect_armed(toml: &str) -> i32 {
        let c = init(toml);
        let r = unsafe { howdah_inspect_armed(c) };
        unsafe { howdah_free(c) };
        r
    }

    #[test]
    fn inspect_armed_follows_the_inspect_mode_not_the_global_mode() {
        assert_eq!(inspect_armed(""), 0, "default: detect, log-only");
        assert_eq!(inspect_armed("mode = \"block\""), 0, "a global block never arms Layer 2");
        assert_eq!(inspect_armed("[inspect]\nmode = \"block\""), 1);
        assert_eq!(inspect_armed("mode = \"detect\"\n[inspect]\nmode = \"block\""), 1);
    }

    #[test]
    fn inspect_armed_by_one_class_override() {
        assert_eq!(inspect_armed("[inspect.rule_modes]\nsql_injection = \"block\""), 1);
        assert_eq!(inspect_armed("[inspect.rule_modes]\nsql_injection = \"detect\""), 0);
    }

    #[test]
    fn inspect_armed_is_off_when_layer_or_global_is_off() {
        assert_eq!(inspect_armed("[inspect]\nenabled = false\nmode = \"block\""), 0);
        assert_eq!(inspect_armed("mode = \"off\"\n[inspect]\nmode = \"block\""), 0);
        assert_eq!(
            inspect_armed("[inspect]\nmode = \"off\"\n[inspect.rule_modes]\nsql_injection = \"block\""),
            0,
            "an explicit inspect off is absolute; no override re-arms it"
        );
        assert_eq!(unsafe { howdah_inspect_armed(std::ptr::null_mut()) }, 0);
    }

    // ---- howdah_oom_exit: the out-of-memory backstop toggle -------------------

    #[test]
    fn oom_exit_getter() {
        let on = init(""); // defaults -> oom_exit true
        assert_eq!(unsafe { howdah_oom_exit(on) }, 1);
        let off = init("oom_exit = false\n");
        assert_eq!(unsafe { howdah_oom_exit(off) }, 0);
        assert_eq!(unsafe { howdah_oom_exit(std::ptr::null_mut()) }, 0);
        unsafe {
            howdah_free(on);
            howdah_free(off);
        }
    }

    #[test]
    fn oom_armed_honors_oom_exit_and_mode() {
        // Default (mode block, oom_exit true) -> armed.
        let a = init("");
        assert_eq!(unsafe { howdah_oom_armed(a) }, 1);
        // detect keeps it armed (Critical fail-stop).
        let d = init("mode = \"detect\"\n");
        assert_eq!(unsafe { howdah_oom_armed(d) }, 1);
        // A global off disables it, even with oom_exit on (the default).
        let off = init("mode = \"off\"\n");
        assert_eq!(unsafe { howdah_oom_armed(off) }, 0);
        assert_eq!(unsafe { howdah_oom_exit(off) }, 1, "oom_exit itself is still on");
        // oom_exit = false disables it regardless of mode.
        let no = init("mode = \"block\"\noom_exit = false\n");
        assert_eq!(unsafe { howdah_oom_armed(no) }, 0);
        assert_eq!(unsafe { howdah_oom_armed(std::ptr::null_mut()) }, 0);
        unsafe {
            howdah_free(a);
            howdah_free(d);
            howdah_free(off);
            howdah_free(no);
        }
    }

    // ---- howdah_recycle_*: the §4.7 recycle facet toggles ---------------------

    #[test]
    fn recycle_on_fatal_getter_defaults_off() {
        let def = init(""); // off by default
        assert_eq!(unsafe { howdah_recycle_on_fatal(def) }, 0);
        let on = init("recycle_on_fatal = true\n");
        assert_eq!(unsafe { howdah_recycle_on_fatal(on) }, 1);
        assert_eq!(unsafe { howdah_recycle_on_fatal(std::ptr::null_mut()) }, 0);
        unsafe {
            howdah_free(def);
            howdah_free(on);
        }
    }

    #[test]
    fn recycle_armed_honors_key_and_mode() {
        // Off by default -> not armed.
        let def = init("");
        assert_eq!(unsafe { howdah_recycle_armed(def) }, 0);
        // On, block mode -> armed.
        let on = init("recycle_on_fatal = true\n");
        assert_eq!(unsafe { howdah_recycle_armed(on) }, 1);
        // detect keeps it armed (Critical fail-stop).
        let d = init("mode = \"detect\"\nrecycle_on_fatal = true\n");
        assert_eq!(unsafe { howdah_recycle_armed(d) }, 1);
        // A global off disables it even with the key on.
        let off = init("mode = \"off\"\nrecycle_on_fatal = true\n");
        assert_eq!(unsafe { howdah_recycle_armed(off) }, 0);
        assert_eq!(unsafe { howdah_recycle_on_fatal(off) }, 1, "key itself is still on");
        assert_eq!(unsafe { howdah_recycle_armed(std::ptr::null_mut()) }, 0);
        unsafe {
            howdah_free(def);
            howdah_free(on);
            howdah_free(d);
            howdah_free(off);
        }
    }

    #[test]
    fn recycle_observe_getter_defaults_enforce() {
        let enforce = init("recycle_on_fatal = true\n"); // observe off -> enforce
        assert_eq!(unsafe { howdah_recycle_observe(enforce) }, 0);
        let observe = init("recycle_on_fatal = true\nrecycle_observe = true\n");
        assert_eq!(unsafe { howdah_recycle_observe(observe) }, 1);
        assert_eq!(unsafe { howdah_recycle_observe(std::ptr::null_mut()) }, 0);
        unsafe {
            howdah_free(enforce);
            howdah_free(observe);
        }
    }

    // ---- howdah_scan_post: the §4.2 byte-stream scanner (gap A exact) --------

    unsafe fn scan_line(ctx: *mut howdah_ctx) -> String {
        let p = howdah_take_log_line(ctx);
        if p.is_null() {
            return String::new();
        }
        let s = std::ffi::CStr::from_ptr(p).to_string_lossy().into_owned();
        howdah_free_str(p);
        s
    }

    fn header_flood_body() -> String {
        let mut body = String::from("--B\r\nContent-Disposition: form-data; name=\"a\"\r\n");
        for i in 0..50 {
            body.push_str(&format!("X-{i}: v\r\n"));
        }
        body.push_str("\r\nvalue\r\n--B--\r\n");
        body
    }

    #[test]
    fn scan_post_counts_every_header_from_bytes() {
        // The parsed-event path sees only PHP's one Content-Disposition; the byte
        // scanner sees all 50 header lines and trips max_part_headers (gap A).
        let ctx = init(""); // defaults: mode block, max_part_headers = 16
        let ct = b"multipart/form-data; boundary=B";
        let body = header_flood_body();
        unsafe {
            howdah_scan_post_begin(ctx, ct.as_ptr() as *const c_char, ct.len(), 0, -1);
            let a = howdah_scan_post(ctx, body.as_ptr() as *const c_char, body.len());
            assert_eq!(a, HOWDAH_BLOCK);
            assert!(scan_line(ctx).contains("max_part_headers"));
            howdah_free(ctx);
        }
    }

    #[test]
    fn scan_post_allows_a_benign_part_with_extra_headers() {
        let ctx = init("");
        let ct = b"multipart/form-data; boundary=B";
        let body = "--B\r\nContent-Disposition: form-data; name=\"a\"\r\nContent-Type: text/plain\r\nContent-Transfer-Encoding: binary\r\n\r\nvalue\r\n--B--\r\n";
        unsafe {
            howdah_scan_post_begin(ctx, ct.as_ptr() as *const c_char, ct.len(), 0, -1);
            assert_eq!(howdah_scan_post(ctx, body.as_ptr() as *const c_char, body.len()), HOWDAH_ALLOW);
            howdah_free(ctx);
        }
    }

    #[test]
    fn scan_post_is_resumable_across_arbitrary_chunk_splits() {
        let ctx = init("");
        let ct = b"multipart/form-data; boundary=B";
        let body = header_flood_body();
        unsafe {
            howdah_scan_post_begin(ctx, ct.as_ptr() as *const c_char, ct.len(), 0, -1);
            let mut worst = HOWDAH_ALLOW;
            for ch in body.as_bytes().chunks(7) {
                worst = worst.max(howdah_scan_post(ctx, ch.as_ptr() as *const c_char, ch.len()));
            }
            assert_eq!(worst, HOWDAH_BLOCK);
            howdah_free(ctx);
        }
    }

    #[test]
    fn scan_post_trips_post_too_large_over_effective_post_max_size() {
        // A benign single field whose read bytes exceed a low post_max_size (100)
        // → gap B PostTooLarge, even though no structural limit is near.
        let ctx = init("");
        let ct = b"multipart/form-data; boundary=B";
        let mut body = String::from("--B\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n");
        body.push_str(&"x".repeat(500));
        body.push_str("\r\n--B--\r\n");
        unsafe {
            howdah_scan_post_begin(ctx, ct.as_ptr() as *const c_char, ct.len(), 100, 134217728);
            let a = howdah_scan_post(ctx, body.as_ptr() as *const c_char, body.len());
            assert_eq!(a, HOWDAH_BLOCK);
            assert!(scan_line(ctx).contains("post_too_large"));
            howdah_free(ctx);
        }
        // With post_max_size unlimited (0) the same body is allowed by gap B.
        let ctx = init("");
        let mut body = String::from("--B\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n");
        body.push_str(&"x".repeat(500));
        body.push_str("\r\n--B--\r\n");
        unsafe {
            howdah_scan_post_begin(ctx, ct.as_ptr() as *const c_char, ct.len(), 0, 134217728);
            assert_eq!(howdah_scan_post(ctx, body.as_ptr() as *const c_char, body.len()), HOWDAH_ALLOW);
            howdah_free(ctx);
        }
    }

    #[test]
    fn scan_post_block_is_sticky_never_cleared() {
        // §4.2: once blocked, the scanner never lowers the verdict on later bytes.
        let ctx = init("");
        let ct = b"multipart/form-data; boundary=B";
        let flood = header_flood_body();
        let benign = "--B\r\nContent-Disposition: form-data; name=\"ok\"\r\n\r\nv\r\n--B--\r\n";
        unsafe {
            howdah_scan_post_begin(ctx, ct.as_ptr() as *const c_char, ct.len(), 0, -1);
            assert_eq!(howdah_scan_post(ctx, flood.as_ptr() as *const c_char, flood.len()), HOWDAH_BLOCK);
            // More (benign) bytes cannot clear the block.
            assert_eq!(howdah_scan_post(ctx, benign.as_ptr() as *const c_char, benign.len()), HOWDAH_BLOCK);
            howdah_free(ctx);
        }
    }

    #[test]
    fn scan_post_does_not_block_lf_only_body_php_accepts() {
        // M1: PHP's rfc1867 accepts LF-only line endings; the strict scanner
        // errors internally but must NOT escalate to a block (no false positive).
        let ctx = init("");
        let ct = b"multipart/form-data; boundary=B";
        let lf = "--B\nContent-Disposition: form-data; name=\"a\"\n\nv\n--B--\n";
        unsafe {
            howdah_scan_post_begin(ctx, ct.as_ptr() as *const c_char, ct.len(), 0, -1);
            assert_eq!(howdah_scan_post(ctx, lf.as_ptr() as *const c_char, lf.len()), HOWDAH_ALLOW);
            assert!(scan_line(ctx).is_empty(), "no block/malformed line for an LF-only body");
            howdah_free(ctx);
        }
    }

    #[test]
    fn scan_post_off_when_not_multipart() {
        let ctx = init("");
        let ct = b"application/x-www-form-urlencoded";
        let body = header_flood_body();
        unsafe {
            howdah_scan_post_begin(ctx, ct.as_ptr() as *const c_char, ct.len(), 0, -1);
            assert_eq!(howdah_scan_post(ctx, body.as_ptr() as *const c_char, body.len()), HOWDAH_ALLOW);
            howdah_free(ctx);
        }
    }

    #[test]
    fn scan_post_truncates_only_on_unbounded_growth_limits() {
        // Regression (1.6.0 docker smoke): the read_post scanner stops the body
        // (returns EOF) only for an UNBOUNDED-growth limit. A bounded limit the
        // scanner detects itself (max_parts here) must still record the verdict
        // (fail-closed) but NOT truncate — rfc1867 drains the bounded body and
        // `deliver_startup_refusal` sends a clean 403; truncating leaves the
        // FastCGI body unread and resets the client.
        let ct = b"multipart/form-data; boundary=B";
        unsafe {
            // Bounded: the scanner's OWN max_parts (3 parts, limit 1) blocks the
            // request but does NOT stop the body.
            let ctx = init("[limits]\nmax_parts = 1\n");
            howdah_scan_post_begin(ctx, ct.as_ptr() as *const c_char, ct.len(), 0, -1);
            let three = b"--B\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nx\r\n--B\r\nContent-Disposition: form-data; name=\"b\"\r\n\r\ny\r\n--B\r\nContent-Disposition: form-data; name=\"c\"\r\n\r\nz\r\n--B--\r\n";
            assert_eq!(
                howdah_scan_post(ctx, three.as_ptr() as *const c_char, three.len()),
                HOWDAH_ALLOW,
                "the scanner's own max_parts is bounded; it must not truncate the body"
            );
            assert!(scan_line(ctx).contains("max_parts"), "but the verdict is still recorded (fail-closed)");
            howdah_free(ctx);

            // Unbounded: gap B (post_too_large) MUST stop the body.
            let ctx = init("");
            let mut big = String::from("--B\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n");
            big.push_str(&"x".repeat(500));
            big.push_str("\r\n--B--\r\n");
            howdah_scan_post_begin(ctx, ct.as_ptr() as *const c_char, ct.len(), 100, 134217728);
            assert_eq!(
                howdah_scan_post(ctx, big.as_ptr() as *const c_char, big.len()),
                HOWDAH_BLOCK,
                "post_too_large is unbounded; it must stop the body"
            );
            howdah_free(ctx);
        }
    }
}

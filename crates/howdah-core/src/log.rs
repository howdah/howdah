//! Privacy-preserving JSON event log: one JSON line per security event.
//!
//! `EventRecord` deliberately has no field for request bodies, cookies or
//! Authorization headers, so they cannot be logged by construction.
//!
//! The line format is a versioned contract (see `docs/log-schema.md` and
//! `docs/howdah-event.schema.json`). Schema 2 is the eight 1.x fields
//! unchanged plus `schema`, `layer` and `version`, all derived from the build
//! and the rule id, never from the request. Adding a field does not bump
//! `schema`; removing, renaming or retyping one does.

use crate::limits::RuleId;
use crate::rules::Action;

/// Version of the event line format. 1 was the unversioned 1.0 to 1.4.0 line.
pub const SCHEMA_VERSION: u32 = 2;

/// Every key of a schema-2 event line, in documentation order.
pub const EVENT_FIELDS: [&str; 11] = [
    "schema", "version", "ts", "request_id", "layer", "rule", "action", "client_ip", "method", "uri",
    "reason",
];

/// The protection layer a rule belongs to: 1 = request-shape limits
/// (multipart, input shape, request headers, and the self-test marker),
/// 2 = input inspection, 3 = sink hardening, 4 = after-breach behaviour.
/// Exhaustive on purpose: a new `RuleId` variant does not compile until it is
/// given a layer.
pub fn rule_layer(r: RuleId) -> u8 {
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
        | RuleId::OutOfMemory
        | RuleId::StartupFatal
        | RuleId::FatalRecycle
        | RuleId::PostTooLarge
        | RuleId::NestingBudget
        | RuleId::ParseMemoryEstimate => 1,
        RuleId::SqlInjection | RuleId::PathTraversal | RuleId::CommandInjection | RuleId::CgiArgInjection => 2,
        RuleId::CommandExec
        | RuleId::Include
        | RuleId::Eval
        | RuleId::Unserialize
        | RuleId::Phar
        | RuleId::Ssrf
        | RuleId::IncludeWrapper
        | RuleId::FileOpen
        | RuleId::MailInjection
        | RuleId::PregEval
        | RuleId::CreateFunction
        | RuleId::AssertString
        | RuleId::DangerousCallback
        | RuleId::Xxe
        | RuleId::TlsVerify => 3,
        RuleId::UploadExec | RuleId::UnexpectedBinary | RuleId::UnexpectedEgress
        | RuleId::PhpWrite
        | RuleId::FileDelete
        | RuleId::SecretRead => 4,
    }
}

/// One security event. Exactly these fields (plus the derived `schema`,
/// `layer` and `version`) are ever logged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventRecord {
    /// UTC timestamp, Unix epoch milliseconds, as a decimal string. The FFI
    /// layer stamps it from the system clock at the moment the record is built
    /// (the core has no clock of its own otherwise).
    pub ts: String,
    pub request_id: String,
    pub rule: RuleId,
    pub action: Action,
    pub client_ip: String,
    pub method: String,
    pub uri: String,
    pub reason: String,
}

fn rule_name(r: RuleId) -> &'static str {
    match r {
        RuleId::MaxParts => "max_parts",
        RuleId::MaxFiles => "max_files",
        RuleId::MaxPartHeaders => "max_part_headers",
        RuleId::MaxPartHeaderBytes => "max_part_header_bytes",
        RuleId::MaxFieldNameLen => "max_field_name_len",
        RuleId::MaxFilenameLen => "max_filename_len",
        RuleId::ParseMemoryBudget => "parse_memory_budget",
        RuleId::MalformedMultipart => "malformed_multipart",
        RuleId::UploadProgressAbuse => "upload_progress_abuse",
        RuleId::SelfTest => "self_test",
        RuleId::MaxInputVars => "max_input_vars",
        RuleId::MaxInputNestingDepth => "max_input_nesting_depth",
        RuleId::MaxInputKeyBytes => "max_input_key_bytes",
        RuleId::MaxRequestHeaders => "max_request_headers",
        RuleId::MaxRequestHeaderBytes => "max_request_header_bytes",
        RuleId::SqlInjection => "sql_injection",
        RuleId::PathTraversal => "path_traversal",
        RuleId::CommandInjection => "command_injection",
        RuleId::CgiArgInjection => "cgi_arg_injection",
        RuleId::CommandExec => "command_exec",
        RuleId::Include => "include",
        RuleId::Eval => "eval",
        RuleId::Phar => "phar",
        RuleId::Ssrf => "ssrf",
        RuleId::IncludeWrapper => "include_wrapper",
        RuleId::FileOpen => "file_open",
        RuleId::Unserialize => "unserialize",
        RuleId::UploadExec => "upload_exec",
        RuleId::UnexpectedBinary => "unexpected_binary",
        RuleId::UnexpectedEgress => "unexpected_egress",
        RuleId::PhpWrite => "php_write",
        RuleId::FileDelete => "file_delete",
        RuleId::SecretRead => "secret_read",
        RuleId::MailInjection => "mail_injection",
        RuleId::PregEval => "preg_eval",
        RuleId::CreateFunction => "create_function",
        RuleId::AssertString => "assert_string",
        RuleId::DangerousCallback => "dangerous_callback",
        RuleId::Xxe => "xxe",
        RuleId::TlsVerify => "tls_verify",
        RuleId::OutOfMemory => "out_of_memory",
        RuleId::StartupFatal => "startup_fatal",
        RuleId::FatalRecycle => "fatal_recycle",
        RuleId::PostTooLarge => "post_too_large",
        RuleId::NestingBudget => "nesting_budget",
        RuleId::ParseMemoryEstimate => "parse_memory_estimate",
    }
}

fn action_name(a: Action) -> &'static str {
    match a {
        Action::Allow => "allow",
        Action::Log => "log",
        Action::Block => "block",
        Action::Excepted => "excepted",
    }
}

/// Serialize a record as a single line of JSON (no trailing newline).
/// serde_json escapes control characters, so the output never contains a
/// raw newline. Keys come out in alphabetical order (serde_json's default
/// map); consumers must not depend on key order.
pub fn log_line(rec: &EventRecord) -> String {
    let v = serde_json::json!({
        "schema": SCHEMA_VERSION,
        "version": env!("CARGO_PKG_VERSION"),
        "layer": rule_layer(rec.rule),
        "ts": rec.ts.clone(),
        "request_id": rec.request_id,
        "rule": rule_name(rec.rule),
        "action": action_name(rec.action),
        "client_ip": rec.client_ip,
        "method": rec.method,
        "uri": rec.uri,
        "reason": rec.reason,
    });
    // Serializing a Value with string keys cannot fail; fall back to `{}`.
    serde_json::to_string(&v).unwrap_or_else(|_| "{}".to_string())
}

/// A fixed-capacity, allocation-free line writer, for building one event line on
/// the stack where the allocator must not be called: the out-of-memory backstop
/// (a genuine system OOM cannot allocate) and the recycle facet (a
/// `max_execution_time` fatal on PHP <= 7.0 reaches `zend_error_cb` from the
/// SIGPROF handler, where `malloc` is not async-signal-safe). Silently refuses
/// to overflow; the caller checks `ok`.
struct LineBuf<'a> {
    out: &'a mut [u8],
    pos: usize,
    ok: bool,
}

impl<'a> LineBuf<'a> {
    fn new(out: &'a mut [u8]) -> Self {
        LineBuf { out, pos: 0, ok: true }
    }
    fn raw(&mut self, b: &[u8]) {
        if self.ok && self.pos + b.len() <= self.out.len() {
            self.out[self.pos..self.pos + b.len()].copy_from_slice(b);
            self.pos += b.len();
        } else {
            self.ok = false;
        }
    }
    /// A JSON string value's bytes: `"` and `\` are backslash-escaped and
    /// control bytes (< 0x20) are dropped, so the result is always valid JSON.
    fn json(&mut self, s: &str) {
        for &b in s.as_bytes() {
            match b {
                b'"' => self.raw(b"\\\""),
                b'\\' => self.raw(b"\\\\"),
                0..=0x1f => {}
                _ => self.raw(&[b]),
            }
        }
    }
    fn uint(&mut self, mut n: u64) {
        if n == 0 {
            self.raw(b"0");
            return;
        }
        let mut tmp = [0u8; 20];
        let mut i = tmp.len();
        while n > 0 {
            i -= 1;
            tmp[i] = b'0' + (n % 10) as u8;
            n /= 10;
        }
        self.raw(&tmp[i..]);
    }
}

/// Write one schema-2 event line — byte-for-byte what [`log_line`] produces —
/// into `out` with NO allocation, for the OOM / signal-context paths. Returns
/// the byte length, or 0 if it does not fit (the caller then writes nothing).
/// `ts`, `request_id` and `reason` are the only dynamic values and are
/// JSON-escaped here; `client_ip`/`method`/`uri` are always empty on these
/// paths. Keys are emitted in the sorted order `serde_json` uses.
pub fn write_event_line(
    out: &mut [u8],
    rule: RuleId,
    action: Action,
    ts: &str,
    request_id: &str,
    reason: &str,
) -> usize {
    let mut b = LineBuf::new(out);
    b.raw(b"{\"action\":\"");
    b.json(action_name(action));
    b.raw(b"\",\"client_ip\":\"\",\"layer\":");
    b.uint(rule_layer(rule) as u64);
    b.raw(b",\"method\":\"\",\"reason\":\"");
    b.json(reason);
    b.raw(b"\",\"request_id\":\"");
    b.json(request_id);
    b.raw(b"\",\"rule\":\"");
    b.json(rule_name(rule));
    b.raw(b"\",\"schema\":");
    b.uint(SCHEMA_VERSION as u64);
    b.raw(b",\"ts\":\"");
    b.json(ts);
    b.raw(b"\",\"uri\":\"\",\"version\":\"");
    b.json(env!("CARGO_PKG_VERSION"));
    b.raw(b"\"}");
    if b.ok {
        b.pos
    } else {
        0
    }
}

/// Generate a request id: a process-wide monotonic counter (unique within the
/// process) followed by 16 hex chars of a keyed hash (makes ids unguessable
/// across restarts). Alphanumeric only, so it is safe in URLs and headers.
///
/// The hash also takes the process id and the clock. php-fpm and Apache
/// prefork fork their workers from a parent that already loaded Howdah, so
/// every worker starts with the same counter and the same hash keys; without
/// the pid and time, workers handed out the same ids (seen in the lab, three
/// FPM workers, one id), and a recycled pid would repeat them later.
pub fn new_request_id() -> String {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut h = RandomState::new().build_hasher();
    h.write_u64(n);
    // wasm32-unknown-unknown has no pid and no clock (both panic there); the
    // browser demo never forks.
    #[cfg(not(target_arch = "wasm32"))]
    {
        h.write_u32(std::process::id());
        if let Ok(d) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            h.write_u128(d.as_nanos());
        }
    }
    format!("{:x}{:016x}", n, h.finish())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn rec() -> EventRecord {
        EventRecord {
            ts: "1700000000000".to_string(),
            request_id: new_request_id(),
            rule: RuleId::MaxParts,
            action: Action::Block,
            client_ip: "203.0.113.7".into(),
            method: "POST".into(),
            uri: "/upload.php?a=1\n\"x\"".into(),
            reason: "too many\nparts".into(),
        }
    }

    #[test]
    fn write_event_line_matches_log_line() {
        // The no-alloc builder must be byte-for-byte what serde produces, for a
        // clean (control-free) OOM/recycle reason — the realistic shape.
        for (rule, action, reason) in [
            (RuleId::OutOfMemory, Action::Block, "worker ended on PHP out-of-memory at /var/www/x.php:42"),
            (RuleId::FatalRecycle, Action::Block, "worker recycled after a poisoning-class fatal (CVE-2026-109619)"),
            (RuleId::StartupFatal, Action::Log, "would recycle the worker"),
        ] {
            let r = EventRecord {
                ts: "1792864974141".to_string(),
                request_id: "o42".to_string(),
                rule,
                action,
                client_ip: String::new(),
                method: String::new(),
                uri: String::new(),
                reason: reason.to_string(),
            };
            let want = log_line(&r);
            let mut buf = [0u8; 1024];
            let n = write_event_line(&mut buf, rule, action, &r.ts, &r.request_id, reason);
            assert_eq!(std::str::from_utf8(&buf[..n]).unwrap(), want, "{rule:?}");
        }
        // Escaping: a quote and backslash survive as valid JSON; control dropped.
        let mut buf = [0u8; 256];
        let n = write_event_line(&mut buf, RuleId::OutOfMemory, Action::Block, "1", "id", "a\"b\\c\x01d");
        let v: serde_json::Value = serde_json::from_str(std::str::from_utf8(&buf[..n]).unwrap()).unwrap();
        assert_eq!(v["reason"], "a\"b\\cd");
        // Overflow: a buffer too small writes nothing (0), never a partial line.
        let mut small = [0u8; 8];
        assert_eq!(write_event_line(&mut small, RuleId::OutOfMemory, Action::Block, "1", "i", "r"), 0);
    }

    #[test]
    fn rule_name_phar_ssrf() {
        assert_eq!(rule_name(RuleId::Phar), "phar");
        assert_eq!(rule_name(RuleId::Ssrf), "ssrf");
    }

    #[test]
    fn layer3_rule_names_are_snake_case() {
        assert_eq!(rule_name(RuleId::CommandExec), "command_exec");
        assert_eq!(rule_name(RuleId::Include), "include");
        assert_eq!(rule_name(RuleId::Eval), "eval");
        assert_eq!(rule_name(RuleId::Unserialize), "unserialize");
    }

    #[test]
    fn layer2_rule_names_are_snake_case() {
        assert_eq!(rule_name(RuleId::SqlInjection), "sql_injection");
        assert_eq!(rule_name(RuleId::PathTraversal), "path_traversal");
        assert_eq!(rule_name(RuleId::CommandInjection), "command_injection");
    }

    /// Schema v2: the eight v1 fields (same names, same JSON types) plus
    /// `schema`, `layer` and `version`. Nothing else.
    #[test]
    fn single_line_json_with_exact_fields() {
        let line = log_line(&rec());
        assert!(!line.contains('\n') && !line.contains('\r'));
        let v: serde_json::Value = serde_json::from_str(&line).expect("valid json");
        let keys: HashSet<&str> = v.as_object().unwrap().keys().map(|k| k.as_str()).collect();
        let want: HashSet<&str> = EVENT_FIELDS.iter().copied().collect();
        assert_eq!(keys, want);
        assert_eq!(EVENT_FIELDS.len(), 11);
        // The v1 fields keep their names and their JSON type (all strings).
        for k in ["ts", "request_id", "rule", "action", "client_ip", "method", "uri", "reason"] {
            assert!(v[k].is_string(), "{k} must stay a string");
        }
        assert_eq!(v["rule"], "max_parts");
        assert_eq!(v["action"], "block");
        assert_eq!(v["ts"], "1700000000000");
        assert_eq!(v["reason"], "too many\nparts");
        // v2 additions.
        assert_eq!(v["schema"], 2);
        assert!(v["schema"].is_u64());
        assert_eq!(v["layer"], 1);
        assert!(v["layer"].is_u64());
        assert_eq!(v["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(SCHEMA_VERSION, 2);
    }

    /// Every rule has a layer, listed here explicitly. `rule_catalog()` is
    /// compile-checked to hold every `RuleId` variant (see limits.rs) and
    /// `rule_layer` is an exhaustive match, so a new rule cannot ship without
    /// a layer: it fails to compile in `rule_layer`, then fails here until
    /// this table names it.
    #[test]
    fn every_rule_has_a_layer() {
        use crate::limits::rule_catalog;
        let want: &[(RuleId, u8)] = &[
            (RuleId::MaxParts, 1),
            (RuleId::MaxFiles, 1),
            (RuleId::MaxPartHeaders, 1),
            (RuleId::MaxPartHeaderBytes, 1),
            (RuleId::MaxFieldNameLen, 1),
            (RuleId::MaxFilenameLen, 1),
            (RuleId::ParseMemoryBudget, 1),
            (RuleId::MalformedMultipart, 1),
            (RuleId::UploadProgressAbuse, 1),
            (RuleId::SelfTest, 1),
            (RuleId::MaxInputVars, 1),
            (RuleId::MaxInputNestingDepth, 1),
            (RuleId::MaxInputKeyBytes, 1),
            (RuleId::MaxRequestHeaders, 1),
            (RuleId::MaxRequestHeaderBytes, 1),
            (RuleId::SqlInjection, 2),
            (RuleId::PathTraversal, 2),
            (RuleId::CommandInjection, 2),
            (RuleId::CgiArgInjection, 2),
            (RuleId::CommandExec, 3),
            (RuleId::Include, 3),
            (RuleId::Eval, 3),
            (RuleId::Unserialize, 3),
            (RuleId::Phar, 3),
            (RuleId::Ssrf, 3),
            (RuleId::IncludeWrapper, 3),
            (RuleId::FileOpen, 3),
            (RuleId::UploadExec, 4),
            (RuleId::UnexpectedBinary, 4),
            (RuleId::UnexpectedEgress, 4),
            (RuleId::PhpWrite, 4),
            (RuleId::FileDelete, 4),
            (RuleId::SecretRead, 4),
            (RuleId::MailInjection, 3),
            (RuleId::PregEval, 3),
            (RuleId::CreateFunction, 3),
            (RuleId::AssertString, 3),
            (RuleId::DangerousCallback, 3),
            (RuleId::Xxe, 3),
            (RuleId::TlsVerify, 3),
            (RuleId::OutOfMemory, 1),
            (RuleId::StartupFatal, 1),
            (RuleId::FatalRecycle, 1),
            (RuleId::PostTooLarge, 1),
            (RuleId::NestingBudget, 1),
            (RuleId::ParseMemoryEstimate, 1),
        ];
        assert_eq!(rule_catalog().len(), 46);
        assert_eq!(want.len(), rule_catalog().len(), "layer table and rule_catalog differ");
        for r in rule_catalog() {
            let w = want.iter().find(|(x, _)| x == r).unwrap_or_else(|| panic!("{r:?} has no layer in this table")).1;
            assert_eq!(rule_layer(*r), w, "{r:?}");
            let mut e = rec();
            e.rule = *r;
            let v: serde_json::Value = serde_json::from_str(&log_line(&e)).unwrap();
            assert_eq!(v["layer"], w, "{r:?} line");
            assert_eq!(v["rule"], rule_name(*r));
        }
    }

    #[test]
    fn excepted_action_name() {
        let mut r = rec();
        r.action = Action::Excepted;
        let v: serde_json::Value = serde_json::from_str(&log_line(&r)).unwrap();
        assert_eq!(v["action"], "excepted");
    }

    #[test]
    fn all_actions_and_rules_serialize() {
        for a in [Action::Allow, Action::Log, Action::Block, Action::Excepted] {
            let mut r = rec();
            r.action = a;
            r.rule = RuleId::SelfTest;
            let v: serde_json::Value = serde_json::from_str(&log_line(&r)).unwrap();
            assert!(v["action"].is_string());
            assert_eq!(v["rule"], "self_test");
        }
    }

    /// Simulates a request carrying sensitive data; only the allowed
    /// metadata is copied into the record, and none of it leaks.
    #[test]
    fn privacy_cookie_body_auth_never_logged() {
        struct Req {
            method: &'static str,
            uri: &'static str,
            ip: &'static str,
            cookie: &'static str,
            authorization: &'static str,
            body: &'static str,
        }
        let req = Req {
            method: "POST",
            uri: "/login.php",
            ip: "198.51.100.2",
            cookie: "PHPSESSID=SECRETCOOKIEVALUE",
            authorization: "Bearer SECRETAUTHTOKEN",
            body: "password=SECRETBODYPASSWORD",
        };
        let r = EventRecord {
            ts: "1".to_string(),
            request_id: new_request_id(),
            rule: RuleId::MalformedMultipart,
            action: Action::Log,
            client_ip: req.ip.into(),
            method: req.method.into(),
            uri: req.uri.into(),
            reason: "malformed".into(),
        };
        let line = log_line(&r);
        assert!(line.contains("/login.php"));
        for s in [req.cookie, req.authorization, req.body, "SECRET", "PHPSESSID", "Bearer"] {
            assert!(!line.contains(s), "leaked {s}");
        }
        for k in ["cookie", "authorization", "body", "password"] {
            assert!(!line.to_lowercase().contains(k), "key {k} present");
        }
        // Schema v2 fields carry only constants derived from the build and
        // the rule id: never anything from the request.
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        let keys: HashSet<&str> = v.as_object().unwrap().keys().map(|k| k.as_str()).collect();
        assert_eq!(keys, EVENT_FIELDS.iter().copied().collect::<HashSet<&str>>());
        assert_eq!(v["schema"], SCHEMA_VERSION);
        assert_eq!(v["layer"], 1);
        assert_eq!(v["version"], env!("CARGO_PKG_VERSION"));
        for k in ["schema", "layer", "version"] {
            let s = v[k].to_string();
            for secret in [req.cookie, req.authorization, req.body, req.ip, req.uri, req.method] {
                assert!(!s.contains(secret), "{k} carries request data");
            }
        }
    }

    #[test]
    fn request_ids_unique_and_safe() {
        let ids: Vec<String> = (0..10_000).map(|_| new_request_id()).collect();
        let set: HashSet<&String> = ids.iter().collect();
        assert_eq!(set.len(), ids.len());
        for id in &ids {
            assert!(!id.is_empty() && id.len() <= 64);
            assert!(id.chars().all(|c| c.is_ascii_alphanumeric()), "unsafe id {id}");
        }
    }

    #[test]
    fn request_ids_unique_across_threads() {
        let hs: Vec<_> = (0..4)
            .map(|_| {
                std::thread::spawn(|| (0..2_000).map(|_| new_request_id()).collect::<Vec<_>>())
            })
            .collect();
        let mut set = HashSet::new();
        for h in hs {
            for id in h.join().unwrap() {
                assert!(set.insert(id));
            }
        }
    }
}

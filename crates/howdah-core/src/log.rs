//! Privacy-preserving JSON event log: one JSON line per security event.
//!
//! `EventRecord` deliberately has no field for request bodies, cookies or
//! Authorization headers, so they cannot be logged by construction.

use crate::limits::RuleId;
use crate::rules::Action;

/// One security event. Exactly these fields are ever logged.
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
        RuleId::CgiArgInjection => "cgi_arg_injection",
    }
}

fn action_name(a: Action) -> &'static str {
    match a {
        Action::Allow => "allow",
        Action::Log => "log",
        Action::Block => "block",
    }
}

/// Serialize a record as a single line of JSON (no trailing newline).
/// serde_json escapes control characters, so the output never contains a
/// raw newline.
pub fn log_line(rec: &EventRecord) -> String {
    let v = serde_json::json!({
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

/// Generate a request id: a process-wide monotonic counter (guarantees
/// uniqueness) followed by 16 hex chars of per-process-random hash (makes
/// ids unguessable across restarts). Alphanumeric only, so it is safe in
/// URLs and headers.
pub fn new_request_id() -> String {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut h = RandomState::new().build_hasher();
    h.write_u64(n);
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
    fn single_line_json_with_exact_fields() {
        let line = log_line(&rec());
        assert!(!line.contains('\n') && !line.contains('\r'));
        let v: serde_json::Value = serde_json::from_str(&line).expect("valid json");
        let keys: HashSet<&str> = v.as_object().unwrap().keys().map(|k| k.as_str()).collect();
        let want: HashSet<&str> =
            ["ts", "request_id", "rule", "action", "client_ip", "method", "uri", "reason"]
                .into_iter()
                .collect();
        assert_eq!(keys, want);
        assert_eq!(v["rule"], "max_parts");
        assert_eq!(v["action"], "block");
        assert_eq!(v["ts"], "1700000000000");
        assert!(v["ts"].is_string());
        assert_eq!(v["reason"], "too many\nparts");
    }

    #[test]
    fn all_actions_and_rules_serialize() {
        for a in [Action::Allow, Action::Log, Action::Block] {
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

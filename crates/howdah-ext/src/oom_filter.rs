//! The out-of-memory backstop's Rust side: classify the fatal PHP reported,
//! log one shape-only event, and tell the C shim (`oom_hook.c`) whether to end
//! the worker. Installed from MINIT only on web SAPIs, only on unpatched PHP,
//! only when the backstop is armed — `oom_exit` on and mode not off (see
//! `module::minit`).
//!
//! Why logging from here is sound: hitting `memory_limit` exhausts only the
//! Zend heap, so Rust's system-malloc log path still works. A genuine
//! system-malloc failure makes Rust abort — still a fail-stop, the same outcome
//! the backstop is after. We never read the half-built SAPI request state (no
//! client IP / method / URI), so the event carries only the rule, a fixed
//! reason, and the error's own `file:line` (the script location, which Layers
//! 3/4 already log); the fresh request id plus the timestamp identify it.

use std::ffi::{c_char, c_int};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::time::{SystemTime, UNIX_EPOCH};

use howdah_core::log::{log_line, new_request_id, EventRecord};
use howdah_core::oom::classify_fatal;
use howdah_core::rules::Action;
use howdah_core::RuleId;

use crate::response;

/// `HowdahOomDecide`: 1 = end the worker (after logging), 0 = chain to the prior
/// `zend_error_cb`. A NULL/empty `msg`, a non-matching error, or any panic
/// returns 0 (fail-open — the classifier is a trivial prefix match that cannot
/// realistically panic, and Howdah must never end a worker on a surprise).
///
/// # Safety
/// `msg`/`file` are NULL or valid for their lengths for the duration of the call.
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn decide(
    error_type: c_int,
    msg: *const c_char,
    msg_len: usize,
    during_startup: c_int,
    file: *const c_char,
    file_len: usize,
    line: u32,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        let bytes: &[u8] = if msg.is_null() || msg_len == 0 {
            &[]
        } else {
            std::slice::from_raw_parts(msg as *const u8, msg_len)
        };
        let Some(rule) = classify_fatal(error_type, bytes, during_startup != 0) else {
            return 0;
        };
        let base = match rule {
            RuleId::OutOfMemory => {
                "worker ended on PHP out-of-memory before the half-built request state could be used"
            }
            _ => "worker ended on a fatal error during request startup before the half-built request state could be used",
        };
        // Append the error's own location (the script path + line). This is the
        // same kind of value Layers 3/4 log (an executing-file path), never
        // request content, and it is the operator's only locus now that the
        // worker exits before PHP writes its own "exhausted in X on line N" line.
        let reason = match loc(file, file_len, line) {
            Some(l) => format!("{base} at {l}"),
            None => base.to_string(),
        };
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0)
            .to_string();
        let out = log_line(&EventRecord {
            ts,
            request_id: new_request_id(),
            rule,
            action: Action::Block,
            client_ip: String::new(),
            method: String::new(),
            uri: String::new(),
            reason,
        });
        response::write_log_line(&out);
        1
    }))
    .unwrap_or(0)
}

/// `<file>:<line>` for the reason, or `None` when PHP gave no file (e.g. an
/// out-of-memory with no active script). The file path is lossy-decoded and
/// control characters are dropped so it stays a single clean log token.
///
/// # Safety
/// `file` is NULL or valid for `file_len` bytes.
unsafe fn loc(file: *const c_char, file_len: usize, line: u32) -> Option<String> {
    if file.is_null() || file_len == 0 {
        return None;
    }
    let raw = std::slice::from_raw_parts(file as *const u8, file_len);
    let path: String = String::from_utf8_lossy(raw).chars().filter(|c| !c.is_control()).collect();
    if path.is_empty() {
        return None;
    }
    Some(format!("{path}:{line}"))
}

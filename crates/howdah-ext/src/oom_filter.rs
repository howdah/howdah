//! The out-of-memory backstop's Rust side: classify the fatal PHP reported,
//! log one shape-only event, and tell the C shim (`oom_hook.c`) whether to end
//! the worker. Installed from MINIT only on web SAPIs, only on unpatched PHP,
//! only when `oom_exit` is on (see `module::minit`).
//!
//! Why logging from here is sound: hitting `memory_limit` exhausts only the
//! Zend heap, so Rust's system-malloc log path still works. A genuine
//! system-malloc failure makes Rust abort — still a fail-stop, the same outcome
//! the backstop is after. We never read the half-built SAPI request state (no
//! client IP / method / URI), so the event carries only the rule and a fixed
//! reason; the fresh request id plus the timestamp identify it.

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
/// `msg` is NULL or valid for `msg_len` bytes for the duration of the call.
pub unsafe extern "C" fn decide(
    error_type: c_int,
    msg: *const c_char,
    msg_len: usize,
    during_startup: c_int,
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
        let reason = match rule {
            RuleId::OutOfMemory => {
                "worker ended on PHP out-of-memory before the half-built request state could be used"
            }
            _ => "worker ended on a fatal error during request startup before the half-built request state could be used",
        };
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0)
            .to_string();
        let line = log_line(&EventRecord {
            ts,
            request_id: new_request_id(),
            rule,
            action: Action::Block,
            client_ip: String::new(),
            method: String::new(),
            uri: String::new(),
            reason: reason.to_string(),
        });
        response::write_log_line(&line);
        1
    }))
    .unwrap_or(0)
}

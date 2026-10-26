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
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use howdah_core::log::{log_line, new_request_id, EventRecord};
use howdah_core::oom::{classify_fatal, FatalAction};
use howdah_core::rules::Action;
use howdah_core::RuleId;

use crate::response;

/// Return codes for the `decide` callback (the C shim `oom_hook.c` acts on them):
/// 0 = chain to the prior `zend_error_cb`; 1 = end the worker NOW (`_exit`
/// before the longjmp); 2 = mark the worker tainted (the C shim `_exit`s it at
/// `post_deactivate`, after this request delivers its 500) and chain.
const CHAIN: c_int = 0;
const EXIT_NOW: c_int = 1;
const RECYCLE_AFTER: c_int = 2;

/// Process-static arming, set once at MINIT by `module::install_oom_backstop`
/// (the glue has already applied the web-SAPI + unpatched-engine gates). The
/// `zend_error_cb` hook is a no-op until these are set, and both default to the
/// safe/off direction so a decide call that somehow races startup never exits.
///
/// `OOM_EXIT_ARMED`: the §4.6 backstop is on, so an [`FatalAction::ExitNow`]
/// (out-of-memory any phase, or a startup-window fatal) ends the worker.
static OOM_EXIT_ARMED: AtomicBool = AtomicBool::new(false);
/// `RECYCLE_MODE`: the §4.7 facet — 0 off, 1 observe (log a would-recycle, do
/// not exit), 2 enforce (recycle after teardown).
static RECYCLE_MODE: AtomicU8 = AtomicU8::new(0);
pub const RECYCLE_OFF: u8 = 0;
pub const RECYCLE_OBSERVE: u8 = 1;
pub const RECYCLE_ENFORCE: u8 = 2;
/// `RECYCLE_IMMEDIATE`: on a SAPI that does NOT flush the response before
/// `post_deactivate`, recycle-after would drop the 500 just as an immediate
/// exit does, so we take the guaranteed-safe immediate `_exit` on the enforce
/// path (safety over a response that isn't preserved anyway; design §4.7). Set
/// per SAPI from the lab flush-ordering finding.
static RECYCLE_IMMEDIATE: AtomicBool = AtomicBool::new(false);

/// Set the error-cb arming. `oom_exit` arms the §4.6 immediate exit; `mode` is
/// one of [`RECYCLE_OFF`]/[`RECYCLE_OBSERVE`]/[`RECYCLE_ENFORCE`]; `immediate`
/// forces the enforce path to exit now (the SAPI drops the response regardless).
pub fn set_arm(oom_exit: bool, mode: u8, immediate: bool) {
    OOM_EXIT_ARMED.store(oom_exit, Ordering::Relaxed);
    RECYCLE_MODE.store(mode, Ordering::Relaxed);
    RECYCLE_IMMEDIATE.store(immediate, Ordering::Relaxed);
}

/// `HowdahOomDecide`: tell the C shim what to do about one PHP error (see the
/// return-code constants). A NULL/empty `msg`, a non-matching error, an unarmed
/// outcome, or any panic returns [`CHAIN`] (fail-open — the classifier is a
/// trivial match that cannot realistically panic, and Howdah must never end a
/// worker on a surprise).
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
        match classify_fatal(error_type, bytes, during_startup != 0) {
            FatalAction::ExitNow(rule) => {
                if !OOM_EXIT_ARMED.load(Ordering::Relaxed) {
                    return CHAIN;
                }
                let base = match rule {
                    RuleId::OutOfMemory => {
                        "worker ended on PHP out-of-memory before the half-built request state could be used"
                    }
                    _ => "worker ended on a fatal error during request startup before the half-built request state could be used",
                };
                emit(rule, Action::Block, base, file, file_len, line);
                EXIT_NOW
            }
            FatalAction::RecycleAfter(rule) => match RECYCLE_MODE.load(Ordering::Relaxed) {
                RECYCLE_ENFORCE => {
                    emit(
                        rule,
                        Action::Block,
                        "worker recycled after a poisoning-class fatal before it could serve another request (CVE-2026-109619)",
                        file,
                        file_len,
                        line,
                    );
                    // On a SAPI that drops the 500 anyway, take the immediate
                    // exit (same client outcome, guaranteed fail-stop).
                    if RECYCLE_IMMEDIATE.load(Ordering::Relaxed) {
                        EXIT_NOW
                    } else {
                        RECYCLE_AFTER
                    }
                }
                RECYCLE_OBSERVE => {
                    // Observe: record a would-recycle event (action: log), do NOT
                    // taint the worker and do NOT exit — PHP handles the fatal
                    // normally so the operator can size their fatal rate first.
                    emit(
                        rule,
                        Action::Log,
                        "would recycle the worker after a poisoning-class fatal (observe mode; set recycle_observe = false to enforce)",
                        file,
                        file_len,
                        line,
                    );
                    CHAIN
                }
                _ => CHAIN,
            },
            FatalAction::None => CHAIN,
        }
    }))
    .unwrap_or(CHAIN)
}

/// Write one shape-only Howdah event line. Carries only the rule, the action, a
/// fixed reason, and the error's own `file:line` (the script location, the same
/// kind of value Layers 3/4 log) — never request content. Appending the
/// location is the operator's only locus when the worker exits before PHP writes
/// its own "... in X on line N".
///
/// # Safety
/// `file` is NULL or valid for `file_len` bytes.
unsafe fn emit(rule: RuleId, action: Action, base: &str, file: *const c_char, file_len: usize, line: u32) {
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
        action,
        client_ip: String::new(),
        method: String::new(),
        uri: String::new(),
        reason,
    });
    response::write_log_line(&out);
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

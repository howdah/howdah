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
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, AtomicU8, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use howdah_core::log::write_event_line;
use howdah_core::oom::{classify_fatal, FatalAction};
use howdah_core::rules::Action;
use howdah_core::RuleId;

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

/// The fd the backstop's event line is written to. Captured at MINIT from the
/// log destination (an append fd on the log file, or stderr for syslog/stderr),
/// so the write on the OOM / signal-context path is a single `write(2)` with no
/// `open`, no allocation. Defaults to stderr until set.
static OOM_LOG_FD: AtomicI32 = AtomicI32::new(libc::STDERR_FILENO);

/// Set the fd the backstop writes its event line to (MINIT only). A negative fd
/// falls back to stderr.
pub fn set_log_fd(fd: i32) {
    OOM_LOG_FD.store(if fd >= 0 { fd } else { libc::STDERR_FILENO }, Ordering::Relaxed);
}

/// Per-process event counter for the backstop's request id (the keyed-hash id
/// would allocate, and this path has no response to correlate against).
static OOM_SEQ: AtomicU64 = AtomicU64::new(0);

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

/// Append `b` to `buf` at `pos` (truncating if full); return the new position.
fn push(buf: &mut [u8], pos: usize, b: &[u8]) -> usize {
    let take = b.len().min(buf.len().saturating_sub(pos));
    buf[pos..pos + take].copy_from_slice(&b[..take]);
    pos + take
}

/// Write `n` as decimal into `buf` and return the byte length (0-length guard:
/// `0` writes "0"). No allocation.
fn uint_len(buf: &mut [u8], mut n: u64) -> usize {
    if n == 0 {
        return push(buf, 0, b"0");
    }
    let mut tmp = [0u8; 20];
    let mut i = tmp.len();
    while n > 0 {
        i -= 1;
        tmp[i] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    push(buf, 0, &tmp[i..])
}

/// Build the reason — `<base>` or `<base> at <file>:<line>` — into `buf`, with
/// no allocation. The file is logged only when it is an absolute path (F10),
/// restricted to printable ASCII (so the result is valid UTF-8 and one clean
/// token) and capped at 256 bytes; `"`/`\` are left for `write_event_line` to
/// escape.
///
/// # Safety
/// `file` is NULL or valid for `file_len` bytes.
unsafe fn build_reason<'a>(buf: &'a mut [u8], base: &str, file: *const c_char, file_len: usize, line: u32) -> &'a str {
    let mut p = push(buf, 0, base.as_bytes());
    if !file.is_null() && file_len > 0 {
        let raw = std::slice::from_raw_parts(file as *const u8, file_len);
        if raw.first() == Some(&b'/') {
            p = push(buf, p, b" at ");
            let mut copied = 0usize;
            for &c in raw {
                if copied >= 256 {
                    break;
                }
                if (0x20..=0x7e).contains(&c) {
                    p = push(buf, p, &[c]);
                    copied += 1;
                }
            }
            let mut nb = [0u8; 20];
            let nl = uint_len(&mut nb, line as u64);
            p = push(buf, p, b":");
            p = push(buf, p, &nb[..nl]);
        }
    }
    // Every appended byte is ASCII (base is ASCII; file is printable-ASCII only).
    std::str::from_utf8_unchecked(&buf[..p])
}

/// Write one shape-only event line for the backstop / recycle facet,
/// ALLOCATION-FREE and async-signal-safe. A genuine system out-of-memory cannot
/// call the allocator, and a `max_execution_time` fatal on PHP <= 7.0 reaches
/// `zend_error_cb` from the SIGPROF handler where `malloc` can deadlock; so the
/// line is built entirely on the stack and written with one `write(2)` to the
/// fd captured at MINIT (or stderr). Best effort — a short write or a closed fd
/// is ignored — so the `_exit` that follows always runs. Carries only the rule,
/// action, a fixed reason and the error's own `file:line`; never request content.
///
/// # Safety
/// `file` is NULL or valid for `file_len` bytes.
unsafe fn emit(rule: RuleId, action: Action, base: &str, file: *const c_char, file_len: usize, line: u32) {
    let ms = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0);
    let mut tsb = [0u8; 20];
    let tsl = uint_len(&mut tsb, ms);
    let ts = std::str::from_utf8_unchecked(&tsb[..tsl]);
    // request id: 'o' + a process counter (unique within the process).
    let mut idb = [0u8; 24];
    idb[0] = b'o';
    let idl = uint_len(&mut idb[1..], OOM_SEQ.fetch_add(1, Ordering::Relaxed));
    let id = std::str::from_utf8_unchecked(&idb[..1 + idl]);
    let mut rb = [0u8; 384];
    let reason = build_reason(&mut rb, base, file, file_len, line);
    let mut lb = [0u8; 768];
    let n = write_event_line(&mut lb, rule, action, ts, id, reason);
    if n > 0 && n < lb.len() {
        lb[n] = b'\n';
        let fd = OOM_LOG_FD.load(Ordering::Relaxed);
        let _ = libc::write(fd, lb.as_ptr() as *const libc::c_void, n + 1);
    }
}

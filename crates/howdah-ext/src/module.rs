//! Module registration and lifecycle: `get_module`, MINIT/MSHUTDOWN, the three
//! ini entries, and `phpinfo()`/`php --ri` surfacing. All process-global state
//! lives here. Workers are NTS (single-threaded per process), so the
//! `static mut` globals are never touched concurrently.

use std::ffi::{c_char, c_int, c_uint, c_void, CStr, CString};
use std::mem::size_of;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};

use howdah_core::ffi as core;
use howdah_sys as sys;

use crate::input_filter;
use crate::logsink;
use crate::refusal::{Deferred, Delivery, Verdict};
use crate::response;
use crate::rfc1867;

/// The prior `php_rfc1867_callback` (e.g. ext/session's upload-progress hook).
pub(crate) type Prior =
    Option<unsafe extern "C" fn(c_uint, *mut c_void, *mut *mut c_void) -> c_int>;

// ---- process-global state (NTS: no concurrent access) -----------------------
pub(crate) static mut CTX: *mut core::howdah_ctx = ptr::null_mut();
pub(crate) static mut PRIOR: Prior = None;
/// The prior `sapi_module.input_filter` (PHP's own var filter, or another
/// extension's). Saved at MINIT, chained by `input_filter::filter`, restored at
/// MSHUTDOWN.
pub(crate) static mut PRIOR_INPUT_FILTER: input_filter::InputFilter = None;
/// Unified per-request lifecycle (NTS: process-global, no concurrency, like
/// `FEEDER`/`BLOCKED`). The first glue hook to fire in a request (multipart
/// START or the input_filter — which runs before RINIT) begins the core
/// request via `maybe_begin`; RSHUTDOWN ends it. `ENDED` guards against the
/// multipart END path and RSHUTDOWN both ending the same request.
pub(crate) static mut BEGUN: bool = false;
pub(crate) static mut ENDED: bool = false;
/// True once the multipart (rfc1867) path has begun this request. The input
/// filter then skips `PARSE_POST` variables (they ARE the multipart fields,
/// already counted by the part limits — double-counting them would both
/// mis-attribute a flood and diverge from 0.1). GET/COOKIE on a multipart
/// request are still counted.
pub(crate) static mut MULTIPART: bool = false;
/// Resolved log destination + `[log] exec` hook (set at MINIT; `None` before
/// that, when `response::write_log_line` falls back to stderr).
pub(crate) static mut LOG: Option<logsink::Settings> = None;
/// The request's deferred refusal (see `refusal.rs` and the 2026-10-24
/// refusal-path design). A verdict decided during `php_request_startup()` is
/// recorded here and delivered at the end of RINIT; reset by
/// `clear_request_state`.
pub(crate) static mut DEFERRED: Deferred = Deferred::new();
/// Process-static: Layer 2 can block (computed once at first RINIT). When set,
/// RINIT materialises `$_SERVER` so the path and header values are scanned
/// before the script, and an armed class refuses before execution.
static INSPECT_ARMED: AtomicBool = AtomicBool::new(false);
static mut MODULE_NUMBER: c_int = 0;
/// For the info table: (mode, config path, log destination, hook) as displayed.
static mut DISP_MODE: Option<CString> = None;
static mut DISP_CONFIG: Option<CString> = None;
static mut DISP_LOG: Option<CString> = None;
static mut DISP_CONFIG_STATUS: Option<CString> = None;
/// For the info table: `N configured, M rejected` ([[exceptions]]).
static mut DISP_EXCEPTIONS: Option<CString> = None;
static mut DISP_HOOK: Option<CString> = None;

const SUCCESS: c_int = 0;

// ---- the zend_module_entry --------------------------------------------------

/// A fully-zeroed module entry (all fields are POD: null ptrs / `None` / 0),
/// used as the base before `get_module` fills in the live fields. The layout is
/// identical across the PHP 5/7/8 headers measured, so one literal serves all.
const EMPTY_MODULE: sys::zend_module_entry = sys::zend_module_entry {
    size: 0,
    zend_api: 0,
    zend_debug: 0,
    zts: 0,
    ini_entry: ptr::null(),
    deps: ptr::null(),
    name: ptr::null(),
    functions: ptr::null(),
    module_startup_func: None,
    module_shutdown_func: None,
    request_startup_func: None,
    request_shutdown_func: None,
    info_func: None,
    version: ptr::null(),
    globals_size: 0,
    globals_ptr: ptr::null_mut(),
    globals_ctor: None,
    globals_dtor: None,
    post_deactivate_func: None,
    module_started: 0,
    type_: 0,
    handle: ptr::null_mut(),
    module_number: 0,
    build_id: ptr::null(),
};

static mut MODULE: sys::zend_module_entry = EMPTY_MODULE;

const NAME: &[u8] = b"howdah\0";
const VERSION: &[u8] = concat!(env!("CARGO_PKG_VERSION"), "\0").as_bytes();

/// PHP's dynamic loader calls this to obtain the module entry. Called once,
/// before MINIT. We fill the entry (including the per-generation `build_id`,
/// taken from the C header via the howdah-sys shim so the ABI check passes) and
/// return a stable pointer to it.
///
/// # Safety
/// Called by the PHP loader exactly once per process.
#[no_mangle]
pub unsafe extern "C" fn get_module() -> *mut sys::zend_module_entry {
    let m = sys::zend_module_entry {
        size: size_of::<sys::zend_module_entry>() as u16,
        zend_api: sys::ZEND_MODULE_API_NO,
        zend_debug: sys::ZEND_DEBUG as u8,
        zts: sys::USING_ZTS as u8,
        name: NAME.as_ptr() as *const c_char,
        module_startup_func: Some(minit),
        module_shutdown_func: Some(mshutdown),
        request_startup_func: Some(rinit),
        request_shutdown_func: Some(rshutdown),
        info_func: Some(minfo),
        version: VERSION.as_ptr() as *const c_char,
        type_: 1, // MODULE_PERSISTENT
        build_id: sys::howdah_sys_build_id(),
        ..EMPTY_MODULE
    };
    let slot = ptr::addr_of_mut!(MODULE);
    slot.write(m);
    slot
}

// ---- unified per-request lifecycle -----------------------------------------

/// Open the core request exactly once per PHP request, regardless of which glue
/// hook fires first (the multipart START, or the input_filter which runs before
/// RINIT). Builds the RequestMeta from the SAPI globals with our fixed internal
/// boundary. Idempotent: later callers in the same request see `BEGUN` and skip,
/// so the multipart and input paths share one ctx / request id. `BEGUN` is
/// cleared in RSHUTDOWN (never in RINIT — the input_filter fires before RINIT,
/// so resetting there would erase counts; see the Task-1 findings).
///
/// # Safety
/// Called from the glue hooks during an active request; `CTX` is live.
pub(crate) unsafe fn maybe_begin() {
    if *ptr::addr_of!(BEGUN) {
        return;
    }
    // Latch BEGUN *before* any call that can re-enter the glue. `remote_addr`
    // below calls `sapi_getenv`, and under php-fpm (unlike the CLI server)
    // `sapi_getenv` registers the server variable through `sapi_module.input_filter`
    // — i.e. back into our own `input_filter::filter`, which calls `maybe_begin`
    // again. Setting the guard here makes that re-entrant call return immediately,
    // breaking what is otherwise unbounded recursion (a stack-overflow SIGSEGV on
    // every fpm request). The subsequent `request_begin` resets the per-request
    // input state, so anything a re-entrant filter call might count is discarded.
    BEGUN = true;

    let ri = (*ptr::addr_of!(sys::sapi_globals)).request_info;
    let method = rfc1867::cbytes(ri.request_method);
    let uri_full = rfc1867::cbytes(ri.request_uri);
    let uri = strip_query(&uri_full); // path only: query strings can carry secrets
    let ip = remote_addr();

    let meta = core::RequestMeta {
        client_ip: ip.as_ptr() as *const c_char,
        client_ip_len: ip.len(),
        method: method.as_ptr() as *const c_char,
        method_len: method.len(),
        uri: uri.as_ptr() as *const c_char,
        uri_len: uri.len(),
    };
    // No boundary: the glue never feeds request bytes. Parts are reported with
    // `howdah_part` / `howdah_part_data` from the parsed events PHP hands us.
    core::howdah_request_begin(CTX, ptr::null(), 0, &meta);
    // ip/method/uri outlive this call's request_begin, which copies them.
    // (BEGUN was latched at the top, before the re-entrant sapi_getenv.)
}

/// Request shutdown (RSHUTDOWN): the unified end-of-request. Runs after every
/// request. If the request was begun (by either glue hook) and NOT already
/// ended (by the multipart END path, or by the RINIT refusal), end the core
/// request, write any pending log line, and — if the input path latched a
/// block (or the core's final verdict is Block) — emit the block response.
/// This is the "post-hoc refuse": it only still applies to a block first seen
/// AFTER RINIT (today: a request-header flood whose `$_SERVER` the script
/// built lazily), because anything latched before RINIT is refused there,
/// before the script. We do NOT `zend_bailout` here: by RSHUTDOWN the script
/// has run, so this response/status is best-effort. Always reset the
/// lifecycle flags + input latch for the next request.
///
/// # Safety
/// Called by PHP once per request at shutdown.
unsafe extern "C" fn rshutdown(_type: c_int, _module_number: c_int) -> c_int {
    // NB: on a multipart request whose body is clean but where only a GET/COOKIE
    // variable tripped an input block, the multipart END path has already set
    // ENDED (and written any log line), so this guard is false and the
    // input-path 403 is intentionally skipped here — the var-drop in the
    // input_filter is the actual mitigation, and the log line is still written.
    if *ptr::addr_of!(BEGUN) && !*ptr::addr_of!(ENDED) {
        // Nothing to close: the core request was begun without a boundary, so
        // request_end has no framing to find truncated (input-only requests
        // and hard-aborted multipart requests alike).
        let end_action = core::howdah_request_end(CTX);
        let line = rfc1867::take_log_line();
        if let Some(l) = line.as_deref() {
            response::write_log_line(l);
        }
        // One response per request: a refusal already delivered at RINIT (the
        // Layer-4 exec-dir verdict leaves the core request open) never gets a
        // second body here.
        let already = (*ptr::addr_of!(DEFERRED)).delivered();
        if !already
            && (*ptr::addr_of!(input_filter::INPUT_BLOCKED) || end_action == core::HOWDAH_BLOCK)
        {
            let (rule, request_id) = line.as_deref().map(rfc1867::parse_line).unwrap_or_default();
            let status = if rule.is_empty() { 403 } else { response::status_for_rule(&rule) };
            // Best-effort: headers may already be sent; emit_block never bails.
            let _ = catch_unwind(AssertUnwindSafe(|| response::emit_block(status, &request_id)));
        }
    }
    clear_request_state();
    SUCCESS
}

/// First-RINIT, process-once install of the phar + ssrf hooks. Deferred past
/// MINIT because on distro builds curl/phar are shared extensions that load
/// AFTER howdah; by first RINIT every module has registered. Config is
/// process-static, so a sink whose effective mode is Off installs nothing (true
/// zero overhead; both default Off).
///
/// # Safety
/// Called by PHP at request startup (NTS: single-threaded).
unsafe extern "C" fn rinit(_type: c_int, _module_number: c_int) -> c_int {
    // Defensive: a compile swap left armed by a request whose RSHUTDOWN never
    // ran (another module bailing out of startup) must not refuse this one.
    sys::howdah_refuse_disarm();
    static INSTALLED: AtomicBool = AtomicBool::new(false);
    if !INSTALLED.swap(true, Ordering::Relaxed) && !CTX.is_null() {
        let _ = catch_unwind(AssertUnwindSafe(|| {
            INSPECT_ARMED.store(core::howdah_inspect_armed(CTX) != 0, Ordering::Relaxed);
            if core::howdah_sink_armed(CTX, core::HOWDAH_SINK_PHAR) != 0 {
                sys::howdah_install_phar_hook(crate::sink_filter::decide);
            }
            // SSRF trampolines: install when the L3 SSRF sink is armed OR the L4
            // behavior egress / php-write facet is armed. Egress-only operation
            // (SSRF off) needs these trampolines, and `ssrf_filter::armed` is
            // widened to keep the C `g_armed` short-circuit open for it. The
            // SSRF install is ALSO what swaps `fopen`, whose php-write branch
            // (gated on behavior_armed(PHP_WRITE)) is the only way php-write-only
            // mode sees `fopen($p,'w')` — so a PHP_WRITE-armed config must reach
            // here too. This runs BEFORE the behavior install below so fopen is
            // swapped before the php-write callback goes live. In php-write-only
            // mode `ssrf_filter::armed` still returns 0 (ssrf+egress off), so the
            // fopen SSRF branch short-circuits before any DNS/block work; only
            // the php-write branch activates.
            if core::howdah_sink_armed(CTX, core::HOWDAH_SINK_SSRF) != 0
                || core::howdah_behavior_egress_active(CTX) != 0
                || core::howdah_behavior_armed(CTX, core::HOWDAH_BEHAVIOR_PHP_WRITE) != 0
            {
                sys::howdah_install_ssrf_hooks(
                    crate::ssrf_filter::decide,
                    crate::ssrf_filter::armed,
                );
            }
            // Layer-4 behavior glue: install once if ANY facet is armed. This
            // sets the five callbacks and swaps the php-write sinks
            // (file_put_contents/move_uploaded_file/rename); the exec-dir and
            // binary in-hook checks live in the command-exec / compile-file /
            // opcode-handler hooks already installed at MINIT.
            if core::howdah_behavior_armed(CTX, core::HOWDAH_BEHAVIOR_EXEC_DIR) != 0
                || core::howdah_behavior_armed(CTX, core::HOWDAH_BEHAVIOR_BINARY) != 0
                || core::howdah_behavior_armed(CTX, core::HOWDAH_BEHAVIOR_EGRESS) != 0
                || core::howdah_behavior_armed(CTX, core::HOWDAH_BEHAVIOR_PHP_WRITE) != 0
            {
                sys::howdah_install_behavior_hooks(
                    crate::behavior_filter::armed,
                    crate::behavior_filter::exec_dir,
                    crate::behavior_filter::binary,
                    crate::behavior_filter::egress,
                    crate::behavior_filter::php_write,
                );
            }
        }));
    }
    // Layer 2 armed: build `$_SERVER` now (a no-op unless auto_globals_jit
    // deferred it) so REQUEST_URI/PATH_INFO and the HTTP_* headers pass through
    // the chained input_filter BEFORE the script, and a hit latches INPUT_BLOCKED
    // in time for the refusal below. Costs one $_SERVER build per request on
    // apps that never read it; not paid by the default (log-only) install.
    if INSPECT_ARMED.load(Ordering::Relaxed) {
        let _ = catch_unwind(AssertUnwindSafe(|| sys::howdah_force_server_global()));
    }
    // Layer-4 main-script exec-dir check: the primary, opcache-independent
    // control. Runs every request, BEFORE the script executes, and records a
    // 403 if the main script resolves under a denied exec dir.
    main_script_exec_dir_check();
    // The earliest legal point for a response: deliver whatever startup
    // recorded (multipart flood, exec-dir, input/header/Layer-2 block) and
    // keep the script from running. No longjmp anywhere on this path.
    deliver_startup_refusal();
    SUCCESS
}

/// Layer-4 RINIT main-script exec-dir check. When the EXEC_DIR facet is armed,
/// read the main script path from the SAPI (`request_info.path_translated`,
/// NUL-terminated; NULL when the SAPI supplies no main script path. The CLI does set it, so a CLI main script is checked too) and ask the core whether it falls under
/// a denied exec dir. On BLOCK, record the refusal; `deliver_startup_refusal`
/// sends it at the end of RINIT, before the script runs. Fully fail-open
/// (panic -> no action).
///
/// # Safety
/// Called from `rinit` during request startup; `CTX` is live when set.
unsafe fn main_script_exec_dir_check() {
    let decision =
        catch_unwind(AssertUnwindSafe(|| exec_dir_decision())).unwrap_or(None);
    if let Some((status, request_id)) = decision {
        refuse(status, request_id);
    }
}

/// A hook decided to refuse the request. While PHP is inside
/// `php_request_startup()` (the multipart callback, RINIT) the verdict is only
/// recorded: a `zend_bailout` there unwinds to the SAPI's startup-failure
/// path, which under php-fpm is a forced close and `exit(70)` (see the
/// 2026-10-24 refusal-path design). `deliver_startup_refusal` sends it at the
/// end of RINIT. A verdict that arrives during execution (no hook does this
/// today) takes the old emit-and-bailout path, which is legal there.
///
/// # Safety
/// Called from the glue hooks during an active request.
pub(crate) unsafe fn refuse(status: c_int, request_id: String) {
    let during_startup = sys::howdah_during_request_startup() != 0;
    let verdict = Verdict { status, request_id };
    let delivery = catch_unwind(AssertUnwindSafe(|| {
        (*ptr::addr_of_mut!(DEFERRED)).refuse(verdict, during_startup)
    }));
    if let Ok(Delivery::Now(v)) = delivery {
        // Past startup: emit + longjmp, with the verdict's String dropped
        // inside emit_and_bail before the bailout (nothing else is live here).
        rfc1867::emit_and_bail(v.status, v.request_id);
    }
}

/// End of RINIT: send the recorded refusal (or one derived from a block the
/// input path latched before RINIT), then arm the per-request compile swap so
/// the main script never runs. The request then ends normally through
/// RSHUTDOWN and the worker survives. Every step is panic-guarded; a failure
/// means "no refusal delivered" (fail-open), never a crash.
///
/// # Safety
/// Called from `rinit`; `CTX` is live when set.
unsafe fn deliver_startup_refusal() {
    let verdict = catch_unwind(AssertUnwindSafe(|| startup_verdict())).unwrap_or(None);
    if let Some(v) = verdict {
        let _ = catch_unwind(AssertUnwindSafe(|| response::emit_block(v.status, &v.request_id)));
        sys::howdah_refuse_arm();
    }
}

/// The verdict to deliver at RINIT, if any: a recorded one (multipart END,
/// exec-dir) wins; otherwise a block latched by the input path before RINIT
/// (Layer 1 input-shape / header rules, an armed Layer 2 class) ends the core
/// request now, writes its log line and maps rule -> status, exactly as
/// RSHUTDOWN would have done after the script.
unsafe fn startup_verdict() -> Option<Verdict> {
    let d = &mut *ptr::addr_of_mut!(DEFERRED);
    if let Some(v) = d.take_at_rinit() {
        return Some(v);
    }
    if d.delivered()
        || CTX.is_null()
        || !*ptr::addr_of!(input_filter::INPUT_BLOCKED)
        || !*ptr::addr_of!(BEGUN)
        || *ptr::addr_of!(ENDED)
    {
        return None;
    }
    ENDED = true;
    let _ = core::howdah_request_end(CTX);
    let line = rfc1867::take_log_line();
    if let Some(l) = line.as_deref() {
        response::write_log_line(l);
    }
    let (rule, request_id) = line.as_deref().map(rfc1867::parse_line).unwrap_or_default();
    let status = if rule.is_empty() { 403 } else { response::status_for_rule(&rule) };
    d.mark_delivered();
    Some(Verdict { status, request_id })
}

/// Compute the main-script exec-dir verdict. Returns `Some((status, request_id))`
/// when the request must be refused, else `None`. All heap-owned values are
/// dropped before returning, so the caller's `emit_and_bail` longjmp is clean.
unsafe fn exec_dir_decision() -> Option<(c_int, String)> {
    if CTX.is_null() || core::howdah_behavior_armed(CTX, core::HOWDAH_BEHAVIOR_EXEC_DIR) == 0 {
        return None;
    }
    let ri = (*ptr::addr_of!(sys::sapi_globals)).request_info;
    let pt = ri.path_translated;
    if pt.is_null() {
        return None; // SAPI supplied no main script path (the CLI does set one)
    }
    let plen = CStr::from_ptr(pt).to_bytes().len();
    if plen == 0 {
        return None;
    }
    maybe_begin();
    // The main script is the executing file for this check; a hash facet
    // (`script_sha256`) is served the same way as at the sink hooks.
    let sha = crate::origin::sha_for(std::slice::from_raw_parts(pt as *const u8, plen));
    let (sp, sl) = crate::origin::sha_args(&sha);
    let action = core::howdah_behavior_check_exec_dir_at(CTX, pt as *const c_char, plen, sp, sl);
    // Take + write the stashed log line (behavior reuses the core's sink_log).
    let line = {
        let p = core::howdah_take_sink_log_line(CTX);
        if p.is_null() {
            None
        } else {
            let s = CStr::from_ptr(p).to_string_lossy().into_owned();
            core::howdah_free_str(p);
            Some(s)
        }
    };
    if let Some(l) = line.as_deref() {
        response::write_log_line(l);
    }
    if action != core::HOWDAH_BLOCK {
        return None;
    }
    let (rule, request_id) = line.as_deref().map(rfc1867::parse_line).unwrap_or_default();
    let status = if rule.is_empty() {
        403
    } else {
        response::status_for_rule(&rule)
    };
    // rule + line drop here, before the tuple (carrying only request_id) returns.
    Some((status, request_id))
}

/// Reset the per-request lifecycle flags for the next request. Runs at the end
/// of RSHUTDOWN AND — via [`rfc1867::emit_and_bail`] — immediately before a
/// bailout refusal. The second call site is load-bearing: `zend_bailout` is a
/// longjmp that, on some SAPIs (the CLI built-in server, confirmed across
/// 5.4–8.4), returns straight to the SAPI's request loop and SKIPS our
/// RSHUTDOWN. Were `BEGUN` left set, the next request's `maybe_begin` would
/// no-op, the core request would never be re-opened, and every subsequent
/// request on that worker would reuse this request's already-ended state —
/// emitting a stale 403 with no fresh log line. Resetting here makes a skipped
/// RSHUTDOWN harmless; when RSHUTDOWN does run it simply resets again (idempotent).
///
/// It also calls `howdah_ssrf_request_reset()`, so both the normal RSHUTDOWN
/// path and the `emit_and_bail` path clear the per-request SSRF handle map and
/// resolution cache.
///
/// # Safety
/// Single-threaded (NTS) request teardown; the statics are request-local.
pub(crate) unsafe fn clear_request_state() {
    BEGUN = false;
    ENDED = false;
    MULTIPART = false;
    input_filter::INPUT_BLOCKED = false;
    // The deferred refusal is request-local too. Its only heap value (a
    // pending request id) is `None` on the bailout path by construction (a
    // verdict is delivered Now only when nothing is pending), so this reset
    // leaves nothing heap-owned alive across a `bail()`.
    (*ptr::addr_of_mut!(DEFERRED)).reset();
    // Restore `zend_compile_file` if this request's refusal swapped it.
    sys::howdah_refuse_disarm();
    // Drop the C-owned SSRF curl handle map + resolution cache (FPM workers
    // persist; a bailout can skip RSHUTDOWN). Idempotent; a no-op when the ssrf
    // hooks were never installed.
    sys::howdah_ssrf_request_reset();
}

/// Everything up to the first `?` (log the path, never the query string).
fn strip_query(uri: &[u8]) -> Vec<u8> {
    match uri.iter().position(|&b| b == b'?') {
        Some(i) => uri[..i].to_vec(),
        None => uri.to_vec(),
    }
}

/// Best-effort client IP from the SAPI environment.
unsafe fn remote_addr() -> Vec<u8> {
    let key = b"REMOTE_ADDR\0";
    let p = sys::sapi_getenv(key.as_ptr() as _, key.len() - 1);
    if p.is_null() {
        Vec::new()
    } else {
        CStr::from_ptr(p).to_bytes().to_vec()
    }
}

// ---- ini entries ------------------------------------------------------------

/// Wrapper so an array of ini defs (which contains raw pointers) can be a
/// `static`. Safe: read-only, single-threaded registration. php5 registers the
/// older runtime `zend_ini_entry`; php7/php8 the `zend_ini_entry_def`.
#[cfg(not(feature = "php5"))]
struct IniDefs([sys::zend_ini_entry_def; 4]);
#[cfg(feature = "php5")]
struct IniDefs([sys::zend_ini_entry; 4]);
unsafe impl Sync for IniDefs {}

#[cfg(not(feature = "php5"))]
const fn def(name: &'static [u8], value: &'static [u8]) -> sys::zend_ini_entry_def {
    sys::zend_ini_entry_def {
        name: name.as_ptr() as *const c_char,
        on_modify: None,
        mh_arg1: ptr::null_mut(),
        mh_arg2: ptr::null_mut(),
        mh_arg3: ptr::null_mut(),
        value: value.as_ptr() as *const c_char,
        displayer: None,
        // `as _`: the width of these fields varies by PHP generation
        // (name_length is u32 on 7.0-7.2, u16 on 7.3+), so let the compiler
        // infer the field's actual type per generation.
        value_length: (value.len() - 1) as _, // strlen (drop trailing NUL)
        name_length: (name.len() - 1) as _,
        modifiable: 7, // ZEND_INI_ALL (SYSTEM|PERDIR|USER)
    }
}

#[cfg(not(feature = "php5"))]
static INI: IniDefs = IniDefs([
    def(b"howdah.mode\0", b"block\0"),
    def(b"howdah.config\0", b"\0"),
    def(b"howdah.log\0", b"\0"),
    // terminating sentinel (name == NULL)
    sys::zend_ini_entry_def {
        name: ptr::null(),
        on_modify: None,
        mh_arg1: ptr::null_mut(),
        mh_arg2: ptr::null_mut(),
        mh_arg3: ptr::null_mut(),
        value: ptr::null(),
        displayer: None,
        value_length: 0,
        name_length: 0,
        modifiable: 0,
    },
]);

// --- php5 uses the older runtime `zend_ini_entry` for registration ----------
#[cfg(feature = "php5")]
const fn def(name: &'static [u8], value: &'static [u8]) -> sys::zend_ini_entry {
    sys::zend_ini_entry {
        module_number: 0,
        modifiable: 7, // ZEND_INI_ALL
        name: name.as_ptr() as *mut c_char,
        name_length: name.len() as _, // php5 hash keys include the NUL
        on_modify: None,
        mh_arg1: ptr::null_mut(),
        mh_arg2: ptr::null_mut(),
        mh_arg3: ptr::null_mut(),
        value: value.as_ptr() as *mut c_char,
        value_length: (value.len() - 1) as _,
        orig_value: ptr::null_mut(),
        orig_value_length: 0,
        orig_modifiable: 0,
        modified: 0,
        displayer: None,
    }
}

#[cfg(feature = "php5")]
static INI: IniDefs = IniDefs([
    def(b"howdah.mode\0", b"block\0"),
    def(b"howdah.config\0", b"\0"),
    def(b"howdah.log\0", b"\0"),
    sys::zend_ini_entry {
        module_number: 0,
        modifiable: 0,
        name: ptr::null_mut(),
        name_length: 0,
        on_modify: None,
        mh_arg1: ptr::null_mut(),
        mh_arg2: ptr::null_mut(),
        mh_arg3: ptr::null_mut(),
        value: ptr::null_mut(),
        value_length: 0,
        orig_value: ptr::null_mut(),
        orig_value_length: 0,
        orig_modifiable: 0,
        modified: 0,
        displayer: None,
    },
]);

#[cfg(feature = "php5")]
unsafe fn register_ini(module_number: c_int) {
    sys::zend_register_ini_entries(INI.0.as_ptr(), module_number);
}

/// Read a registered ini string by name (name includes a trailing NUL).
/// Returns `None` when unset or empty.
unsafe fn ini_string(name: &[u8]) -> Option<String> {
    #[cfg(not(feature = "php5"))]
    let nlen = name.len() - 1; // php7/php8: strlen, no NUL
    #[cfg(feature = "php5")]
    let nlen = name.len(); // php5 hash keys include the NUL
    let p = sys::zend_ini_string(name.as_ptr() as _, nlen as _, 0);
    if p.is_null() {
        return None;
    }
    let s = CStr::from_ptr(p).to_string_lossy().into_owned();
    (!s.is_empty()).then_some(s)
}

// ---- MINIT / MSHUTDOWN / MINFO ---------------------------------------------

/// Module startup (once per process). Registers ini entries, loads the core
/// config from the ini-configured TOML path, sets the log destination, and
/// chains the multipart callback. Never fails open-endedly: a bad/missing
/// config yields the core's safe defaults; nothing here may take PHP down.
///
/// # Safety
/// Called by PHP once at module startup.
unsafe extern "C" fn minit(_type: c_int, module_number: c_int) -> c_int {
    MODULE_NUMBER = module_number;
    register_ini(module_number);

    let cfg_path = ini_string(b"howdah.config\0");
    let log = ini_string(b"howdah.log\0");
    let ini_mode = ini_string(b"howdah.mode\0");

    // Config precedence:
    //  * A howdah.config FILE, when present, is authoritative — its own `mode`
    //    wins over the howdah.mode ini (and limits/rules come from it).
    //  * With NO config file (the shipped path: howdah.mode set, howdah.config
    //    empty), synthesize the core config from the ini so howdah.mode actually
    //    takes effect — otherwise off/detect would silently become Block. The
    //    howdah.log destination is carried into the synthesized config too, as
    //    [log] path; the glue's log wiring (LOG below) resolves the effective
    //    destination either way, with the ini path winning over [log] path.
    // Fail-safe: genuinely broken/unreadable config still yields the core's safe
    // defaults (Block) — we fail toward protection, never toward Off.
    let mode_disp;
    let mut config_status = String::from("ok");
    // `[[exceptions]]` counts for the info table: (configured, rejected), a
    // lenient second pass over the file text (`None` when it is not TOML).
    let mut exc_report: Option<(usize, usize)> = Some((0, 0));
    let ctx = match cfg_path.as_deref().and_then(read_file) {
        Some(bytes) => {
            // A file that does not parse is NOT silent: one startup line in the
            // SAPI error log and an INVALID row in phpinfo(). The fallback is
            // block unless the file's top-level `on_invalid_config = "off"`.
            let plan = crate::ini_config::plan_file_config(&bytes);
            exc_report = std::str::from_utf8(&bytes).ok().and_then(howdah_core::Config::exceptions_report);
            let eff = match &plan.invalid {
                Some(inv) => {
                    let path = cfg_path.as_deref().unwrap_or("");
                    let c = cstring(&inv.startup_message(path));
                    sys::howdah_sys_log_err(c.as_ptr());
                    config_status = inv.status();
                    format!("{} (fallback: howdah.config is invalid)", inv.fallback)
                }
                None => format!(
                    "(set by howdah.config file: {})",
                    cfg_path.as_deref().unwrap_or("")
                ),
            };
            mode_disp = eff;
            core::howdah_init(plan.init_toml.as_ptr() as *const c_char, plan.init_toml.len())
        }
        None => {
            // No config file: resolve howdah.mode (note PHP maps bareword
            // off/no/false/none -> "" -> None => Off; unset keeps the registered
            // default "block") and synthesize a core config so the ini mode
            // actually takes effect.
            config_status = if cfg_path.is_some() {
                "UNREADABLE (using howdah.mode)".to_string()
            } else {
                "n/a (no howdah.config file)".to_string()
            };
            let choice = crate::ini_config::resolve_mode(ini_mode.as_deref());
            let toml = crate::ini_config::synth_config(choice.toml_mode(), log.as_deref());
            mode_disp = choice.display().to_string();
            core::howdah_init(toml.as_ptr() as *const c_char, toml.len())
        }
    };
    CTX = ctx;

    // Log destination + hook (glue-level: this is what actually writes the
    // log line). `[log] destination` picks file/syslog/stderr; for a file the
    // howdah.log ini path wins over `[log] path`. Nothing is opened here: the
    // file is opened per event and the syslog socket on first use, in the
    // worker, after any fork.
    let settings = catch_unwind(AssertUnwindSafe(|| {
        logsink::Settings::resolve(log.as_deref(), &core::howdah_log_config(ctx))
    }))
    .unwrap_or_else(|_| logsink::Settings::resolve(log.as_deref(), &Default::default()));
    DISP_LOG = Some(cstring(&settings.describe()));
    DISP_HOOK = settings.describe_hook().map(|h| cstring(&h));
    LOG = Some(settings);

    // Display strings for `php --ri howdah` / phpinfo(): reflect the EFFECTIVE
    // config source, so the Mode row never disagrees with real behavior.
    DISP_MODE = Some(cstring(&mode_disp));
    DISP_CONFIG = Some(cstring(cfg_path.as_deref().unwrap_or("(none; mode from howdah.mode ini)")));
    DISP_CONFIG_STATUS = Some(cstring(&config_status));

    // `[[exceptions]]`: the info row, and one startup line in the SAPI error
    // log when any are active (the once-per-process config summary; matched
    // exceptions are otherwise silent unless `exceptions_log = true`).
    let active = core::howdah_exceptions_count(ctx).max(0) as usize;
    // Zero-cost when unused: the glue consults the origin/hash paths only
    // when at least one exception is loaded (see `origin::ACTIVE`).
    crate::origin::ACTIVE = active > 0;
    DISP_EXCEPTIONS = Some(cstring(&match exc_report {
        Some((_, rejected)) => format!("{active} configured, {rejected} rejected"),
        None => format!("{active} configured, n/a rejected (config does not parse)"),
    }));
    if active > 0 {
        let msg = format!(
            "Howdah: {active} exception(s) active from '{}'; exceptions_log = {}",
            cfg_path.as_deref().unwrap_or(""),
            if exceptions_log_on(ctx) { "on" } else { "off" }
        );
        let c = cstring(&msg);
        sys::howdah_sys_log_err(c.as_ptr());
    }

    // Chain the multipart callback: save whatever is installed (e.g. session
    // upload-progress) and install ours above it.
    PRIOR = ptr::addr_of!(sys::php_rfc1867_callback).read();
    let slot = ptr::addr_of_mut!(sys::php_rfc1867_callback);
    slot.write(Some(rfc1867::callback));

    // Chain the input_filter the same way: save the current filter (PHP's own,
    // or another extension's) and install ours above it. Ours counts
    // GET/POST/COOKIE variables through the core, then always chains the prior
    // filter and returns its verdict (so PHP's filtering is unaffected).
    PRIOR_INPUT_FILTER = (*ptr::addr_of!(sys::sapi_module)).input_filter;
    (*ptr::addr_of_mut!(sys::sapi_module)).input_filter = Some(input_filter::filter);

    // Layer 3: install the function-table sink hooks (process-global; no
    // MSHUTDOWN restore, like the other installs).
    sys::howdah_install_sink_hooks(crate::sink_filter::decide);

    SUCCESS
}

#[cfg(not(feature = "php5"))]
unsafe fn register_ini(module_number: c_int) {
    sys::zend_register_ini_entries(INI.0.as_ptr(), module_number);
}

/// Module shutdown: restore the prior callback, release the core context, and
/// unregister ini entries.
///
/// # Safety
/// Called by PHP once at module shutdown.
unsafe extern "C" fn mshutdown(_type: c_int, _module_number: c_int) -> c_int {
    let slot = ptr::addr_of_mut!(sys::php_rfc1867_callback);
    slot.write(PRIOR);
    PRIOR = None;
    // Restore the prior input_filter.
    (*ptr::addr_of_mut!(sys::sapi_module)).input_filter = PRIOR_INPUT_FILTER;
    PRIOR_INPUT_FILTER = None;
    core::howdah_free(CTX);
    CTX = ptr::null_mut();
    sys::zend_unregister_ini_entries(MODULE_NUMBER);
    SUCCESS
}

/// phpinfo() / `php --ri howdah` table.
///
/// # Safety
/// Called by PHP with the module entry.
unsafe extern "C" fn minfo(_module: *mut sys::zend_module_entry) {
    sys::php_info_print_table_start();
    row(b"Howdah\0", b"enabled\0");
    row(b"Version\0", VERSION);
    if let Some(m) = (*ptr::addr_of!(DISP_MODE)).as_ref() {
        row(b"Mode\0", m.as_bytes_with_nul());
    }
    if let Some(c) = (*ptr::addr_of!(DISP_CONFIG)).as_ref() {
        row(b"Rules file (howdah.config)\0", c.as_bytes_with_nul());
    }
    if let Some(s) = (*ptr::addr_of!(DISP_CONFIG_STATUS)).as_ref() {
        row(b"Config status\0", s.as_bytes_with_nul());
    }
    if let Some(e) = (*ptr::addr_of!(DISP_EXCEPTIONS)).as_ref() {
        row(b"Exceptions ([[exceptions]])\0", e.as_bytes_with_nul());
    }
    if let Some(l) = (*ptr::addr_of!(DISP_LOG)).as_ref() {
        row(b"Log destination\0", l.as_bytes_with_nul());
    }
    if let Some(h) = (*ptr::addr_of!(DISP_HOOK)).as_ref() {
        row(b"Log hook ([log] exec)\0", h.as_bytes_with_nul());
    }
    row(b"Log schema\0", cstring(&howdah_core::log::SCHEMA_VERSION.to_string()).as_bytes_with_nul());
    row(
        b"Panic guard (catch_unwind active)\0",
        if crate::panic_unwinds() { b"yes\0" } else { b"NO - UNSAFE BUILD\0" },
    );
    row(
        b"Layer-1 limits\0",
        b"multipart, input-shape, request-header\0",
    );
    sys::php_info_print_table_end();

    // Read-only ini-risk report. Reads current values, changes none.
    let _ = catch_unwind(AssertUnwindSafe(|| risky_ini_section()));
}

/// "Risky ini settings": only flagged settings; an empty list says so.
unsafe fn risky_ini_section() {
    let sapi = {
        let p = (*ptr::addr_of!(sys::sapi_module)).name;
        if p.is_null() { String::new() } else { CStr::from_ptr(p).to_string_lossy().into_owned() }
    };
    let get = |n: &str| {
        let mut b = n.as_bytes().to_vec();
        b.push(0);
        ini_string(&b)
    };
    let dir_mode = |p: &str| {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(p).ok().filter(|m| m.is_dir()).map(|m| m.permissions().mode())
    };
    let findings = crate::ini_risk::evaluate(&crate::ini_risk::Env { sapi: &sapi, get: &get, dir_mode: &dir_mode });
    sys::php_info_print_table_start();
    sys::php_info_print_table_header(2, b"Risky ini settings\0".as_ptr() as *const c_char, b"(read-only; Howdah changes none)\0".as_ptr() as *const c_char);
    if findings.is_empty() {
        row(b"Flagged\0", b"none flagged\0");
    }
    for f in &findings {
        let k = cstring(f.setting);
        let v = cstring(&f.row_value());
        sys::php_info_print_table_row(2, k.as_ptr(), v.as_ptr());
    }
    sys::php_info_print_table_end();
}

unsafe fn row(k: &[u8], v: &[u8]) {
    sys::php_info_print_table_row(2, k.as_ptr() as *const c_char, v.as_ptr() as *const c_char);
}

// ---- helpers ----------------------------------------------------------------

fn cstring(s: &str) -> CString {
    CString::new(s).unwrap_or_default()
}

/// Whether the context's config has `exceptions_log = true` (for the startup
/// summary line). Read through the Rust-only accessor, fail-closed to "off".
unsafe fn exceptions_log_on(ctx: *mut core::howdah_ctx) -> bool {
    catch_unwind(AssertUnwindSafe(|| core::howdah_exceptions_log(ctx) != 0)).unwrap_or(false)
}

/// Read a whole file; `None` (with a loud stderr note) on any error, so a
/// missing/unreadable config never takes PHP down.
fn read_file(path: &str) -> Option<Vec<u8>> {
    match std::fs::read(path) {
        Ok(b) => Some(b),
        Err(e) => {
            response::loud_error(&format!("cannot read howdah.config '{path}': {e}"));
            None
        }
    }
}

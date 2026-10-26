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
use crate::oom_filter;
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
/// RINIT materialises `$_SERVER` so the request path (`REQUEST_URI`,
/// `PATH_INFO`) is scanned and the `HTTP_*` headers are counted before the
/// script (Layer 2 never scans header values), and an armed class refuses
/// before execution.
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
/// The include/eval hook actually installed at MINIT (phpinfo row).
static mut DISP_INCLUDE_HOOK: Option<CString> = None;
/// The legacy sinks actually installed at first RINIT (phpinfo row).
static mut DISP_LEGACY: Option<CString> = None;
/// The out-of-memory backstop state decided at MINIT (phpinfo row).
static mut DISP_OOM: Option<CString> = None;
/// The §4.7 recycle-facet state decided at MINIT (phpinfo row).
static mut DISP_RECYCLE: Option<CString> = None;
/// `[sinks.xml] external_entities = "deny"` in force (decided once).
static mut XML_DENY: bool = false;

const SUCCESS: c_int = 0;
/// Zend's `FAILURE` (-1): what MINIT returns to refuse the load.
const FAILURE: c_int = -1;

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
        post_deactivate_func: Some(post_deactivate),
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

    // Layer 2, php-cgi argument injection: judge the raw query string once, as
    // soon as the core request exists, so the verdict is in the request's worst
    // action before ANY other hook (the multipart END path included) ends it.
    // Fail-open; the string is read by the core and never logged.
    let _ = catch_unwind(AssertUnwindSafe(|| input_filter::inspect_query_string()));
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
    // A previous request whose RSHUTDOWN never ran (a startup failure after our
    // RINIT, or another module bailing out of its RSHUTDOWN) leaves the
    // request-local state stale: BEGUN/ENDED/INPUT_BLOCKED and the compile swap,
    // and DEFERRED.delivered, which would make this request's refusal
    // `Ignored` silently. `delivered` can only be true at RINIT entry for that
    // reason (every delivery happens at or after RINIT), so it is the sound
    // signal to reset everything. Otherwise just make sure no swap is armed.
    if (*ptr::addr_of!(DEFERRED)).delivered() {
        clear_request_state();
    } else {
        sys::howdah_refuse_disarm();
    }
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
            // The T4 file-open firewall (include/open wrapper scheme + poison)
            // is on by default. fopen / file_get_contents are swapped by the
            // SSRF install, and their firewall branch self-gates on the file
            // decide callback, so a firewall-armed config must reach the SSRF
            // install too.
            let open_armed = core::howdah_sink_open_armed(CTX) != 0;
            // The T6 SSRF hardening knobs (rebind / scheme / redirect) are
            // independent of the range `mode`, so any armed bit installs too.
            if core::howdah_sink_armed(CTX, core::HOWDAH_SINK_SSRF) != 0
                || core::howdah_ssrf_armed_mask(CTX) != 0
                || core::howdah_behavior_egress_active(CTX) != 0
                || core::howdah_behavior_armed(CTX, core::HOWDAH_BEHAVIOR_PHP_WRITE) != 0
                || open_armed
            {
                sys::howdah_install_ssrf_hooks(
                    crate::ssrf_filter::decide,
                    crate::ssrf_filter::armed,
                );
            }
            // File-op hub: swap readfile/file (and unlink/rmdir when the T5
            // delete guard is armed) and set the shared file decide callback
            // (which lights up the fopen / file_get_contents / rename branches).
            // `open_armed` already covers the delete and secret-read guards.
            // Stash the runtime session.save_path / error_log for the poison
            // check; empty values simply leave that category inert.
            let delete_armed = core::howdah_behavior_armed(CTX, core::HOWDAH_BEHAVIOR_DELETE) != 0;
            if open_armed {
                sys::howdah_install_file_hooks(
                    crate::file_filter::decide,
                    if delete_armed { sys::HOWDAH_FILE_HOOK_DELETE } else { 0 },
                );
                let session = ini_string(b"session.save_path\0").unwrap_or_default();
                let error_log = ini_string(b"error_log\0").unwrap_or_default();
                core::howdah_set_runtime_paths(
                    CTX,
                    session.as_ptr() as *const c_char,
                    session.len(),
                    error_log.as_ptr() as *const c_char,
                    error_log.len(),
                );
            }
            // Layer-4 behavior glue: install once if ANY facet is armed. This
            // sets the five callbacks and swaps only the write/rename sinks an
            // armed facet needs: file_put_contents/copy for the scoped
            // deny_php_writes tier, move_uploaded_file for it or the (default-on)
            // upload-write guard, rename for it or the delete guard's source
            // check. The exec-dir and binary in-hook checks live in the
            // command-exec / compile-file / opcode-handler hooks already
            // installed at MINIT.
            let write_armed = core::howdah_behavior_armed(CTX, core::HOWDAH_BEHAVIOR_PHP_WRITE) != 0;
            let upload_armed = core::howdah_behavior_armed(CTX, core::HOWDAH_BEHAVIOR_UPLOAD_WRITE) != 0;
            if core::howdah_behavior_armed(CTX, core::HOWDAH_BEHAVIOR_EXEC_DIR) != 0
                || core::howdah_behavior_armed(CTX, core::HOWDAH_BEHAVIOR_BINARY) != 0
                || core::howdah_behavior_armed(CTX, core::HOWDAH_BEHAVIOR_EGRESS) != 0
                || write_armed
                || upload_armed
                || delete_armed
            {
                let mut swap = 0;
                if write_armed {
                    swap |= sys::HOWDAH_BHV_SWAP_GENERIC;
                }
                if upload_armed {
                    swap |= sys::HOWDAH_BHV_SWAP_UPLOAD;
                }
                if delete_armed {
                    swap |= sys::HOWDAH_BHV_SWAP_RENAME_SRC;
                }
                sys::howdah_install_behavior_hooks(
                    crate::behavior_filter::armed,
                    crate::behavior_filter::exec_dir,
                    crate::behavior_filter::binary,
                    crate::behavior_filter::egress,
                    crate::behavior_filter::php_write,
                    swap,
                );
            }
            // Legacy-era sinks (mail, preg_eval, create_function, assert,
            // callback, xml, tls): swap only the armed ones, and only the
            // functions this PHP has. After the SSRF install so the tls hook
            // on curl_setopt chains onto the SSRF trampoline (either order
            // works; this one is fixed so the chain is predictable).
            let armed = crate::legacy_filter::armed_mask(CTX);
            let installed = if armed != 0 {
                sys::howdah_install_legacy_hooks(
                    crate::sink_filter::decide,
                    crate::legacy_filter::mail_decide,
                    crate::legacy_filter::xml_decide,
                    armed,
                )
            } else {
                0
            };
            DISP_LEGACY = Some(cstring(&crate::legacy_filter::describe(armed, installed)));
            XML_DENY = core::howdah_sink_xml_deny_external_entities(CTX) != 0;
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
    // `[sinks.xml] external_entities = "deny"`: ext/libxml re-enables its
    // loader at every request start, so the toggle is re-applied per request
    // (after libxml's RINIT, which runs before ours). Fail-open: a panic or a
    // missing function leaves libxml alone.
    if *ptr::addr_of!(XML_DENY) {
        let _ = catch_unwind(AssertUnwindSafe(|| sys::howdah_xml_deny_external_entities()));
    }
    // Layer 2, php-cgi argument injection (CVE-2012-1823, CVE-2024-4577): the
    // query string is judged when the core request begins (`maybe_begin`). A
    // query that produced no input variable (`?-s`, `?%ADd+...` all do, but a
    // lone `?` or `?&` does not) would never have begun it, so begin here when
    // there is a query to judge. Idempotent; on by default (`[inspect] cgi_arg`),
    // so the cost is one bounded scan of a short string per request that has one.
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if !CTX.is_null() && input_filter::has_query_string() {
            maybe_begin();
        }
    }));
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
        // The body went out through ub_write; drop every output handler that
        // request startup started (output_handler = ob_gzhandler, zlib output
        // compression) so none of them adds Content-Encoding at shutdown,
        // after our headers, and warns "headers already sent".
        sys::howdah_sys_output_discard_all();
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

/// `post_deactivate_func`: `zend_post_deactivate_modules()` runs this
/// UNCONDITIONALLY at request shutdown, even when RSHUTDOWN was skipped — a
/// startup failure before `modules_activated` (a `max_input_time` fatal on a
/// slow upload, PHP's own OOM) skips every RSHUTDOWN. php-fpm then exits the
/// worker, but mod_php and the CLI server survive; without this, the next
/// request on that worker would inherit a stale scanner arm / stop latch /
/// `BEGUN`, since the body is read before RINIT could reset them. Clearing here
/// makes a skipped RSHUTDOWN harmless (and closes the long-standing `BEGUN`
/// staleness too). Idempotent with the RSHUTDOWN reset.
///
/// # Safety
/// Called by PHP once per request at shutdown (NTS).
unsafe extern "C" fn post_deactivate() -> c_int {
    let _ = catch_unwind(AssertUnwindSafe(|| clear_request_state()));
    // §4.7 recycle facet: if this request raised a poisoning-class fatal while
    // the facet was enforcing, the error-cb marked the worker tainted. Now that
    // request teardown is done (PHP has rendered and, on SAPIs that flush here,
    // delivered its 500), end the worker so it never serves another request on
    // the state CVE-2026-109619 leaves behind. `_exit(0)` from the C shim; a
    // no-op when nothing tainted the worker. Runs unconditionally at shutdown,
    // so a skipped RSHUTDOWN still reaches it. MUST be last.
    sys::howdah_oom_recycle_if_tainted();
    SUCCESS
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
    // §4.1: clear the read_post scanner's per-request arm + stop latch.
    crate::post_scan::reset();
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
unsafe extern "C" fn minit(type_: c_int, module_number: c_int) -> c_int {
    // Refuse a dl()'d load (MODULE_TEMPORARY). Howdah swaps function-table
    // handlers, compile pointers and (on 7.0+) an opcode handler for the life
    // of the process; a module unloaded at request end would leave every one
    // of them dangling. php.ini `extension=howdah.so` is the only supported
    // way in. One clear line in the SAPI error log, then FAILURE (PHP reports
    // the dl() as failed and continues).
    if type_ == sys::MODULE_TEMPORARY as c_int {
        let c = cstring(
            "howdah: refusing to load via dl(): Howdah installs process-wide hooks and must be \
             loaded from php.ini (extension=howdah.so), then php-fpm/Apache restarted",
        );
        sys::howdah_sys_log_err(c.as_ptr());
        return FAILURE;
    }
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

    // §4.1: wrap sapi_module.read_post so the raw body passes through the
    // byte-stream scanner before PHP parses it (gaps A/B + the §4.5 estimate).
    // Process-global; armed per request by the scanner only for multipart, a
    // no-op otherwise. Restored at MSHUTDOWN.
    sys::howdah_install_read_post_hook(crate::post_scan::decide);

    // Layer 3: install the function-table sink hooks (process-global; no
    // MSHUTDOWN restore, like the other installs).
    sys::howdah_install_sink_hooks(crate::sink_filter::decide);

    // T6: the SSRF redirect / scheme guard is a PHP-callable internal function.
    // It is registered HERE, at startup, and only when one of those knobs is
    // armed (PHP 7.x interns the name of a function registered later in the
    // request's own string table, which dangles after the request).
    if core::howdah_ssrf_armed_mask(CTX) & (core::HOWDAH_SSRF_ARM_REDIRECT | core::HOWDAH_SSRF_ARM_SCHEME) != 0 {
        sys::howdah_register_ssrf_guard_fn();
    }

    // The include/eval hook is a STARTUP decision (config is read once, here):
    // the core's plan says whether anything armed needs it (eval on, include
    // on with an allowlist, or Layer-4 deny_exec_dirs) and which mechanism
    // `[sinks] hook` resolves to (`auto`: compile when only eval needs it,
    // opcode when include has allow_paths or deny_exec_dirs is set). With
    // nothing armed no handler is installed and OPcache JIT stays on; changing
    // these keys needs an FPM/Apache restart, as for every other key.
    let plan = catch_unwind(AssertUnwindSafe(|| core::howdah_sink_hook_plan(CTX)))
        .unwrap_or(core::HOWDAH_HOOK_PLAN_NONE);
    let mechanism = match plan & 0xF {
        core::HOWDAH_HOOK_PLAN_OPCODE => 1,
        core::HOWDAH_HOOK_PLAN_COMPILE => 2,
        _ => 0,
    };
    let installed = catch_unwind(AssertUnwindSafe(|| sys::howdah_install_include_eval_hook(mechanism)))
        .unwrap_or(0);
    // Read once: the row wording and the startup line both depend on whether
    // php.ini actually has the JIT on (OPcache absent or jit off -> no claim
    // that PHP "disabled" anything).
    let jit_on = sys::howdah_jit_enabled_in_ini() != 0;
    DISP_INCLUDE_HOOK = Some(cstring(&include_hook_label(installed, plan >> 4, jit_on)));
    if installed == 1 && jit_on {
        let c = cstring(JIT_STARTUP_LINE);
        sys::howdah_sys_log_err(c.as_ptr());
    }

    // Out-of-memory backstop (§4.6): save+chain `zend_error_cb` so an
    // out-of-memory fatal — or any fatal during request startup — ends the
    // worker before code runs on the half-built request state (PHP2Shell,
    // CVE-2026-109618/109619). Armed only on web SAPIs, only on an unpatched
    // engine (the `memory_hard_limit_percent` ini directive is absent), and only
    // when `oom_exit` is on (the default). All three gates are process-static,
    // read once here. Fail-open: a panic leaves `zend_error_cb` untouched.
    let _ = catch_unwind(AssertUnwindSafe(|| install_oom_backstop()));

    SUCCESS
}

/// Decide the OOM-backstop (§4.6) and recycle-facet (§4.7) gates, arm the shared
/// `zend_error_cb` decide path, install the hook when either is armed, and set
/// both phpinfo rows. Web SAPIs only; unpatched engine only (upstream's fix
/// registers `memory_hard_limit_percent`). The backstop wants `oom_exit` on (the
/// default); the recycle facet wants `recycle_on_fatal` on (off by default).
///
/// # Safety
/// Called from `minit` once per process; `CTX` is set.
unsafe fn install_oom_backstop() {
    let sapi = {
        let p = (*ptr::addr_of!(sys::sapi_module)).name;
        if p.is_null() { String::new() } else { CStr::from_ptr(p).to_string_lossy().into_owned() }
    };
    let ctx_null = CTX.is_null();
    // `exit_on` is the raw config bit; `armed_cfg` also requires mode != off, so
    // a global `mode = off` (or the `on_invalid_config = "off"` fallback)
    // disables the backstop like every other layer. `detect` keeps it armed.
    let exit_on = !ctx_null && core::howdah_oom_exit(CTX) != 0;
    let oom_armed_cfg = !ctx_null && core::howdah_oom_armed(CTX) != 0;
    let recycle_on = !ctx_null && core::howdah_recycle_on_fatal(CTX) != 0;
    let recycle_armed_cfg = !ctx_null && core::howdah_recycle_armed(CTX) != 0;
    let recycle_observe = !ctx_null && core::howdah_recycle_observe(CTX) != 0;
    let patched = sys::howdah_memory_hard_limit_percent_exists() != 0;
    let web = is_backstop_sapi(&sapi);

    // Effective, after the SAPI + patched-engine gates.
    let oom_exit_armed = oom_armed_cfg && web && !patched;
    let recycle_mode = if recycle_armed_cfg && web && !patched {
        if recycle_observe { oom_filter::RECYCLE_OBSERVE } else { oom_filter::RECYCLE_ENFORCE }
    } else {
        oom_filter::RECYCLE_OFF
    };
    // On a SAPI that drops the response before `post_deactivate`, enforce takes
    // the immediate exit (the 500 is lost either way; see §4.7 and the lab).
    let recycle_immediate = sapi_recycle_immediate(&sapi);

    oom_filter::set_arm(oom_exit_armed, recycle_mode, recycle_immediate);
    if oom_exit_armed || recycle_mode != oom_filter::RECYCLE_OFF {
        sys::howdah_install_oom_hook(crate::oom_filter::decide);
    }
    DISP_OOM = Some(cstring(&oom_backstop_label(ctx_null, exit_on, oom_armed_cfg, &sapi, web, patched)));
    DISP_RECYCLE = Some(cstring(&recycle_facet_label(
        ctx_null, recycle_on, recycle_armed_cfg, recycle_observe, &sapi, web, patched, recycle_immediate,
    )));
}

/// Web SAPIs the out-of-memory backstop runs on. Off on cli / cli-server.
fn is_backstop_sapi(name: &str) -> bool {
    matches!(name, "apache2handler" | "fpm-fcgi" | "cgi-fcgi" | "litespeed")
}

/// Whether the §4.7 recycle facet must `_exit` immediately (from the
/// `zend_error_cb`, before PHP's bailout longjmp) instead of recycling after
/// teardown. The spec (§4.7) keeps recycle-after only where the response is
/// flushed to the client BEFORE `post_deactivate`; on any SAPI where it isn't,
/// the producing request's 500 is dropped under recycle-after just as under an
/// immediate exit, so the simpler, guaranteed-safe immediate fail-stop is used
/// ("safety over the preserved error page").
///
/// Measured empirically by `lab/integration/recycle.sh`: **every tested web SAPI
/// finalizes the response AFTER `post_deactivate`**, so none preserves the 500.
///
/// * **FastCGI (`fpm-fcgi`, `cgi-fcgi`):** php-fpm sends the `FCGI_END_REQUEST`
///   record only after `php_request_shutdown` returns (in its main loop), i.e.
///   after `zend_post_deactivate_modules` runs our `post_deactivate`. Exiting
///   there closes the FastCGI socket before `END_REQUEST`, so nginx answers 502
///   (lab: producing request = 502).
/// * **Apache mod_php (`apache2handler`):** mod_php finalizes the response (the
///   output-filter flush + connection close) only after the handler returns,
///   which is after `post_deactivate`; exiting there resets the client
///   connection (lab: producing request = no response / 000).
/// * **LiteSpeed (`litespeed`):** untested here; defaulted to the immediate
///   fail-stop (the safe direction) until the lab covers it.
///
/// The recycle-after code path (the tainted flag + the `post_deactivate` exit)
/// is retained and is selected automatically for any SAPI that DOES flush before
/// teardown; none of the supported web SAPIs do, so enforce currently resolves
/// to an immediate exit on all of them, while still fully closing the
/// CVE-2026-109619 window (the worker never serves the consumer request).
fn sapi_recycle_immediate(name: &str) -> bool {
    matches!(name, "fpm-fcgi" | "cgi-fcgi" | "apache2handler" | "litespeed")
}

/// The `OOM backstop (oom_exit)` phpinfo row: armed, or the specific reason not.
fn oom_backstop_label(ctx_null: bool, exit_on: bool, armed_cfg: bool, sapi: &str, web: bool, patched: bool) -> String {
    if ctx_null {
        return "off (core unavailable)".to_string();
    }
    if !exit_on {
        return "off (oom_exit = false)".to_string();
    }
    if !armed_cfg {
        // oom_exit is on, so the only remaining config reason is a global off.
        return "off (mode = off)".to_string();
    }
    if !web {
        return format!("off (non-web SAPI: {sapi})");
    }
    if patched {
        return "off (patched PHP: memory_hard_limit_percent present)".to_string();
    }
    format!("armed (ends the worker on out-of-memory; SAPI {sapi})")
}

/// The `Recycle after fatal (recycle_on_fatal)` phpinfo row: armed (and in which
/// mode and delivery strategy), or the specific reason not. Off by default.
#[allow(clippy::too_many_arguments)]
fn recycle_facet_label(
    ctx_null: bool,
    recycle_on: bool,
    armed_cfg: bool,
    observe: bool,
    sapi: &str,
    web: bool,
    patched: bool,
    immediate: bool,
) -> String {
    if ctx_null {
        return "off (core unavailable)".to_string();
    }
    if !recycle_on {
        return "off (recycle_on_fatal = false)".to_string();
    }
    if !armed_cfg {
        // recycle_on_fatal is on, so the only remaining config reason is a global off.
        return "off (mode = off)".to_string();
    }
    if !web {
        return format!("off (non-web SAPI: {sapi})");
    }
    if patched {
        return "off (patched PHP: memory_hard_limit_percent present)".to_string();
    }
    if observe {
        return format!("armed (observe: logs a would-recycle, does not exit; SAPI {sapi})");
    }
    let how = if immediate {
        "immediate _exit (this SAPI drops the response before teardown)"
    } else {
        "recycle after teardown (the request keeps its 500)"
    };
    format!("armed (enforce: {how}; SAPI {sapi})")
}

/// The `Include/eval hook` phpinfo row: what the shim reported installed, and
/// why the plan chose it (`HOWDAH_HOOK_WHY_*`). The JIT parentheticals apply
/// to PHP 8.0+ only (there is no JIT before); "JIT disabled by PHP" is said
/// only when php.ini has the JIT on (`jit_on`), otherwise the opcode handler
/// is described as incompatible with it.
fn include_hook_label(installed: c_int, why: i32, jit_on: bool) -> String {
    let php8 = sys::PHP_VERSION_ID >= 80000;
    let mech = match (installed, php8) {
        (1, true) if jit_on => "opcode handler (JIT disabled by PHP",
        (1, true) => "opcode handler (incompatible with OPcache JIT",
        (1, false) => "opcode handler (",
        (2, true) => "compile pointer (JIT compatible",
        (2, false) => "compile pointer (",
        _ => return "none".to_string(),
    };
    let why = match why {
        core::HOWDAH_HOOK_WHY_EVAL_ONLY => "auto: eval only",
        core::HOWDAH_HOOK_WHY_INCLUDE_ALLOW_PATHS => "auto: include allow_paths set",
        core::HOWDAH_HOOK_WHY_DENY_EXEC_DIRS => "auto: deny_exec_dirs set",
        core::HOWDAH_HOOK_WHY_INCLUDE_FIREWALL => "auto: include firewall on",
        _ => "configured",
    };
    let sep = if mech.ends_with('(') { "" } else { "; " };
    format!("{mech}{sep}{why})")
}

/// One startup line, written when the operator has OPcache JIT on in php.ini
/// and the opcode handler is what got installed: PHP is about to turn JIT off
/// and this names the key that keeps it on.
const JIT_STARTUP_LINE: &str = "howdah: OPcache JIT is enabled in php.ini and the include/eval guard \
    uses the opcode handler (chosen because [sinks.include] allow_paths or [behavior] deny_exec_dirs \
    is set, or [sinks] hook = \"opcode\"), so PHP will turn JIT off for this process. To keep JIT on, \
    set [sinks] hook = \"compile\" in howdah.config (an include served from a warm opcache is then \
    not re-inspected; eval is still fully covered), then restart php-fpm/Apache.";

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
    // Restore the prior zend_error_cb if the OOM backstop swapped it (no-op
    // otherwise). Before freeing the ctx, though the handler needs no ctx.
    sys::howdah_uninstall_oom_hook();
    // Restore the prior sapi_module.read_post (§4.1 wrapper).
    sys::howdah_uninstall_read_post_hook();
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
    if let Some(h) = (*ptr::addr_of!(DISP_INCLUDE_HOOK)).as_ref() {
        row(b"Include/eval hook\0", h.as_bytes_with_nul());
    }
    if let Some(l) = (*ptr::addr_of!(DISP_LEGACY)).as_ref() {
        row(b"Layer-3 legacy sinks\0", l.as_bytes_with_nul());
    }
    if let Some(o) = (*ptr::addr_of!(DISP_OOM)).as_ref() {
        row(b"OOM backstop (oom_exit)\0", o.as_bytes_with_nul());
    }
    if let Some(r) = (*ptr::addr_of!(DISP_RECYCLE)).as_ref() {
        row(b"Recycle after fatal (recycle_on_fatal)\0", r.as_bytes_with_nul());
    }
    if *ptr::addr_of!(XML_DENY) {
        row(b"XML external entities\0", b"denied ([sinks.xml] external_entities)\0");
    }
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

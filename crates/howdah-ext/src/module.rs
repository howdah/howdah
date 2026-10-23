//! Module registration and lifecycle: `get_module`, MINIT/MSHUTDOWN, the three
//! ini entries, and `phpinfo()`/`php --ri` surfacing. All process-global state
//! lives here. Workers are NTS (single-threaded per process), so the
//! `static mut` globals are never touched concurrently.

use std::ffi::{c_char, c_int, c_uint, c_void, CStr, CString};
use std::mem::size_of;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;

use howdah_core::ffi as core;
use howdah_sys as sys;

use crate::feeder;
use crate::input_filter;
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
/// mis-attribute a flood and diverge from 0.1), and RSHUTDOWN leaves the
/// (real, frame-fed) multipart state to its own truncation detection rather
/// than force-closing it. GET/COOKIE on a multipart request are still counted.
pub(crate) static mut MULTIPART: bool = false;
/// Log destination file; `None` => stderr fallback.
pub(crate) static mut LOG_PATH: Option<CString> = None;
static mut MODULE_NUMBER: c_int = 0;
/// For the info table: (mode, config path, log path) as displayed.
static mut DISP_MODE: Option<CString> = None;
static mut DISP_CONFIG: Option<CString> = None;
static mut DISP_LOG: Option<CString> = None;

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
        request_startup_func: None,
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
    core::howdah_request_begin(
        CTX,
        feeder::INTERNAL_BOUNDARY.as_ptr() as *const c_char,
        feeder::INTERNAL_BOUNDARY.len(),
        &meta,
    );
    // ip/method/uri outlive this call's request_begin, which copies them.
    // (BEGUN was latched at the top, before the re-entrant sapi_getenv.)
}

/// Request shutdown (RSHUTDOWN): the unified end-of-request. Runs after every
/// request. If the request was begun (by either glue hook) and NOT already
/// ended by the multipart END path, end the core request, write any pending log
/// line, and — if the input path latched a block (or the core's final verdict
/// is Block) — emit the block response. We do NOT `zend_bailout` here: the
/// input_filter already dropped the offending variables (the real DoS
/// mitigation), and by RSHUTDOWN the script has run, so this response/status is
/// best-effort. Always reset the lifecycle flags + input latch for the next
/// request.
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
        // Input-only request (no multipart body): close the synthetic multipart
        // state cleanly so request_end's truncation check does not false-positive
        // on a never-fed state. Mirrors rfc1867::end_request's closing feed. A
        // real multipart request reaches RSHUTDOWN unended only on a hard abort;
        // leave its partially-fed state to genuine truncation detection.
        if !*ptr::addr_of!(MULTIPART) {
            let closing = feeder::Feeder::new().closing();
            core::howdah_feed(CTX, closing.as_ptr() as *const c_char, closing.len());
        }
        let end_action = core::howdah_request_end(CTX);
        let line = rfc1867::take_log_line();
        if let Some(l) = line.as_deref() {
            response::write_log_line(l);
        }
        if *ptr::addr_of!(input_filter::INPUT_BLOCKED) || end_action == core::HOWDAH_BLOCK {
            let (rule, request_id) = line.as_deref().map(rfc1867::parse_line).unwrap_or_default();
            let status = if rule.is_empty() { 403 } else { response::status_for_rule(&rule) };
            // Best-effort: headers may already be sent; emit_block never bails.
            let _ = catch_unwind(AssertUnwindSafe(|| response::emit_block(status, &request_id)));
        }
    }
    clear_request_state();
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
/// # Safety
/// Single-threaded (NTS) request teardown; the statics are request-local.
pub(crate) unsafe fn clear_request_state() {
    BEGUN = false;
    ENDED = false;
    MULTIPART = false;
    input_filter::INPUT_BLOCKED = false;
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
    //    howdah.log destination is carried into the synthesized config too, but
    //    the glue's own log wiring (LOG_PATH below) is what actually writes, and
    //    is set unconditionally regardless of this branch.
    // Fail-safe: genuinely broken/unreadable config still yields the core's safe
    // defaults (Block) — we fail toward protection, never toward Off.
    let mode_disp;
    let ctx = match cfg_path.as_deref().and_then(read_file) {
        Some(bytes) => {
            mode_disp = format!(
                "(set by howdah.config file: {})",
                cfg_path.as_deref().unwrap_or("")
            );
            core::howdah_init(bytes.as_ptr() as *const c_char, bytes.len())
        }
        None => {
            // No config file: resolve howdah.mode (note PHP maps bareword
            // off/no/false/none -> "" -> None => Off; unset keeps the registered
            // default "block") and synthesize a core config so the ini mode
            // actually takes effect.
            let choice = crate::ini_config::resolve_mode(ini_mode.as_deref());
            let toml = crate::ini_config::synth_config(choice.toml_mode(), log.as_deref());
            mode_disp = choice.display().to_string();
            core::howdah_init(toml.as_ptr() as *const c_char, toml.len())
        }
    };
    CTX = ctx;

    // Log destination (glue-level: this is what actually writes the log line).
    LOG_PATH = log.clone().map(|p| CString::new(p).unwrap_or_default());

    // Display strings for `php --ri howdah` / phpinfo(): reflect the EFFECTIVE
    // config source, so the Mode row never disagrees with real behavior.
    DISP_MODE = Some(cstring(&mode_disp));
    DISP_CONFIG = Some(cstring(cfg_path.as_deref().unwrap_or("(none; mode from howdah.mode ini)")));
    DISP_LOG = Some(cstring(log.as_deref().unwrap_or("(stderr)")));

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
    if let Some(l) = (*ptr::addr_of!(DISP_LOG)).as_ref() {
        row(b"Log (howdah.log)\0", l.as_bytes_with_nul());
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
}

unsafe fn row(k: &[u8], v: &[u8]) {
    sys::php_info_print_table_row(2, k.as_ptr() as *const c_char, v.as_ptr() as *const c_char);
}

// ---- helpers ----------------------------------------------------------------

fn cstring(s: &str) -> CString {
    CString::new(s).unwrap_or_default()
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

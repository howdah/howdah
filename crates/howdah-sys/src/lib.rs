//! Raw bindings to the PHP/Zend C symbols the Howdah extension glue needs.
//!
//! PHP's internal layout differs across PHP 5 / 7 / 8, so the bindings are
//! generated at build time (bindgen, into `OUT_DIR`) against the headers of
//! the PHP selected by the `php5` / `php7` / `php8` cargo feature.
//!
//! With no `phpN` feature this crate is empty and its build script is a
//! no-op, so the default workspace build needs no PHP headers.

#![cfg(any(feature = "php5", feature = "php7", feature = "php8"))]
#![allow(non_upper_case_globals, non_camel_case_types, non_snake_case)]
#![allow(unknown_lints, unnecessary_transmutes)]
#![allow(clippy::all, improper_ctypes, dead_code)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

extern "C" {
    /// `ZEND_MODULE_BUILD_ID` from the compiled-against PHP headers (via
    /// `shim.c`): the per-generation ABI tag the loader checks. Points at a
    /// static C string literal; never freed.
    pub fn howdah_sys_build_id() -> *const ::std::ffi::c_char;

    /// Write one line to the SAPI error log (`php_log_err`, see `shim.c`).
    pub fn howdah_sys_log_err(msg: *const ::std::ffi::c_char);

    /// The executing PHP script's path (`zend_get_executed_filename()`, the
    /// Layer-4 origin capture in `sink_hook.c`), exported so the glue can hand
    /// it to the core for `[[exceptions]]` `script` facets. Engine-owned
    /// string; never freed. PHP returns a bracketed placeholder (not a path)
    /// when nothing is executing.
    pub fn howdah_sys_current_script() -> *const ::std::ffi::c_char;

    /// Install the Layer-3 function-table sink hooks (see `sink_hook.c`). Call
    /// once at MINIT. `cb` decides each intercepted call, returning the action
    /// code (0 ALLOW / 1 LOG / 2 BLOCK); on BLOCK the C trampoline neutralizes
    /// the call (returns false without invoking the original).
    pub fn howdah_install_sink_hooks(cb: HowdahSinkDecide);

    /// Proxy the `phar://` stream wrapper's ops (see `phar_hook.c`). Returns 1 if
    /// phar was found and proxied, 0 if phar is not registered (honest no-op).
    /// Each op passes the full `phar://...` URL to `cb`; on BLOCK it returns the
    /// missing-file sentinel without calling phar.
    pub fn howdah_install_phar_hook(cb: HowdahSinkDecide) -> ::std::ffi::c_int;

    /// Install the SSRF egress trampolines (see `ssrf_hook.c`): URL sinks,
    /// socket openers and the curl handle->URL map. `armed` gates all DNS work;
    /// `decide` is the Rust verdict. Call once at MINIT.
    pub fn howdah_install_ssrf_hooks(decide: HowdahSsrfDecide, armed: HowdahSsrfArmed);

    /// Clear the C-owned per-request curl handle->URL map and resolution cache.
    /// Called from the ext's `clear_request_state` (RSHUTDOWN and bailout paths).
    pub fn howdah_ssrf_request_reset();

    /// Install the Layer-4 behavior glue: set the five behavior callbacks AND
    /// swap `file_put_contents`/`move_uploaded_file`/`rename` onto their
    /// php-write trampolines (fopen is already swapped by the SSRF install, so
    /// its php-write branch goes live once these callbacks are set). Call once at
    /// first RINIT, AFTER `howdah_install_ssrf_hooks` (same first-RINIT install
    /// as the phar/ssrf hooks, for shared-extension load order). Parameter order mirrors
    /// `howdah_install_behavior_hooks` in `howdah_sink.h` exactly. A NULL
    /// callback leaves that facet unguarded (fail-open).
    pub fn howdah_install_behavior_hooks(
        armed: HowdahBehaviorArmed,
        exec_dir: HowdahBehaviorExecDir,
        binary: HowdahBehaviorBinary,
        egress: HowdahBehaviorEgress,
        php_write: HowdahBehaviorPhpWrite,
    );

    /// Deferred refusal (see `refuse_hook.c`): swap `zend_compile_file` for
    /// the rest of this request so the main script (and auto_prepend/append)
    /// compile to NULL and never run. No longjmp. Idempotent per request.
    pub fn howdah_refuse_arm();

    /// Restore the compile function saved by `howdah_refuse_arm`. No-op when
    /// not armed. Called from the ext's `clear_request_state` (RSHUTDOWN).
    pub fn howdah_refuse_disarm();

    /// 1 while PHP is inside `php_request_startup()` (`PG(during_request_startup)`):
    /// a `zend_bailout` there is fatal under php-fpm (exit 70), so a refusal
    /// decided then is recorded for RINIT instead.
    pub fn howdah_during_request_startup() -> ::std::ffi::c_int;

    /// Build `$_SERVER` now if `auto_globals_jit` deferred it, so its variables
    /// pass through the chained `input_filter` before the script. No-op when it
    /// already exists.
    pub fn howdah_force_server_global();

    /// `php_output_discard_all()`: drop every active output handler. Called
    /// right after the refusal body went out, so a handler started at request
    /// startup (`output_handler = ob_gzhandler`) cannot add headers later and
    /// warn "headers already sent".
    pub fn howdah_sys_output_discard_all();
}

extern "C" {
    /// Verdict for an oversize SSRF host (`howdah_ssrf_prepare` returned 2); used
    /// by `ssrf_hook.c`. Implemented in howdah-core. 0 allow / 1 log / 2 block.
    pub fn howdah_sink_ssrf_oversize(ctx: *mut ::std::ffi::c_void) -> ::std::ffi::c_int;
}

/// `howdah_sink_ssrf_armed`-shaped callback: 1 iff SSRF guarding is armed.
pub type HowdahSsrfArmed = unsafe extern "C" fn(ctx: *mut ::std::ffi::c_void) -> ::std::ffi::c_int;

/// `howdah_sink_check_ssrf`-shaped callback. `ips` is `ips_count` x 17-byte
/// records `[family 4|6][16 addr bytes]`. Returns 0 ALLOW / 1 LOG / 2 BLOCK.
pub type HowdahSsrfDecide = unsafe extern "C" fn(
    ctx: *mut ::std::ffi::c_void,
    scheme: *const ::std::ffi::c_char,
    scheme_len: usize,
    host: *const ::std::ffi::c_char,
    host_len: usize,
    port: u16,
    ips: *const u8,
    ips_count: usize,
) -> ::std::ffi::c_int;

/// The glue decision callback the C sink trampolines invoke. `sink` is a
/// `HOWDAH_SINK_*` code, `name` the intercepted function name, `arg` its first
/// string argument (never logged by the core). Returns 0 ALLOW / 1 LOG / 2 BLOCK.
pub type HowdahSinkDecide = unsafe extern "C" fn(
    sink: ::std::ffi::c_int,
    name: *const ::std::ffi::c_char,
    name_len: usize,
    arg: *const ::std::ffi::c_char,
    arg_len: usize,
) -> ::std::ffi::c_int;

// ---- Layer-4 behavior glue callbacks ---------------------------------------
// Mirror the `howdah_behavior_*_t` typedefs in `howdah_sink.h` (and the matching
// `howdah_behavior_check_*` / `howdah_behavior_armed` FFI in howdah-core). `ctx`
// is always NULL (the ext glue uses its own CTX and writes the log line). Return
// code is 0 ALLOW / 1 LOG / 2 BLOCK (armed: 1 iff the facet is armed).

/// `howdah_behavior_armed_t`: 1 iff the given `HOWDAH_BEHAVIOR_*` facet is armed.
pub type HowdahBehaviorArmed = unsafe extern "C" fn(
    ctx: *mut ::std::ffi::c_void,
    facet: ::std::ffi::c_int,
) -> ::std::ffi::c_int;

/// `howdah_behavior_exec_dir_t`: script about to execute at `path`.
pub type HowdahBehaviorExecDir = unsafe extern "C" fn(
    ctx: *mut ::std::ffi::c_void,
    path: *const ::std::ffi::c_char,
    path_len: usize,
) -> ::std::ffi::c_int;

/// `howdah_behavior_binary_t`: `caller` spawning program `prog`.
pub type HowdahBehaviorBinary = unsafe extern "C" fn(
    ctx: *mut ::std::ffi::c_void,
    caller: *const ::std::ffi::c_char,
    caller_len: usize,
    prog: *const ::std::ffi::c_char,
    prog_len: usize,
) -> ::std::ffi::c_int;

/// `howdah_behavior_egress_t`: `caller` connecting out to `host`.
pub type HowdahBehaviorEgress = unsafe extern "C" fn(
    ctx: *mut ::std::ffi::c_void,
    caller: *const ::std::ffi::c_char,
    caller_len: usize,
    host: *const ::std::ffi::c_char,
    host_len: usize,
) -> ::std::ffi::c_int;

/// `howdah_behavior_php_write_t`: `caller` opening `target`; `is_write_mode`
/// non-zero for write modes.
pub type HowdahBehaviorPhpWrite = unsafe extern "C" fn(
    ctx: *mut ::std::ffi::c_void,
    caller: *const ::std::ffi::c_char,
    caller_len: usize,
    target: *const ::std::ffi::c_char,
    target_len: usize,
    is_write_mode: ::std::ffi::c_int,
) -> ::std::ffi::c_int;

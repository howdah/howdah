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
    /// the call (returns false without invoking the original). Does NOT install
    /// the include/eval hook: see `howdah_install_include_eval_hook`.
    pub fn howdah_install_sink_hooks(cb: HowdahSinkDecide);

    /// Install the include/require/eval hook, once, at MINIT after
    /// `howdah_install_sink_hooks`. `mechanism`: 0 nothing, 1 the
    /// `ZEND_INCLUDE_OR_EVAL` user opcode handler (PHP 7.0+; turns OPcache JIT
    /// off), 2 the `zend_compile_file`/`zend_compile_string` pointer swap
    /// (JIT-compatible; a warm-opcache include is not re-inspected). On PHP
    /// 5.x, 1 is mapped to 2. Returns what was actually installed (0/1/2).
    pub fn howdah_install_include_eval_hook(mechanism: ::std::ffi::c_int) -> ::std::ffi::c_int;

    /// 1 iff OPcache is loaded and the parsed php.ini says its JIT is on
    /// (PHP 8.0+; always 0 before). Read from the raw ini hash, since opcache's
    /// ini entries are not yet registered when module MINIT runs. Advisory:
    /// drives one startup log line.
    pub fn howdah_jit_enabled_in_ini() -> ::std::ffi::c_int;

    /// Install the legacy-era sink swaps named by `mask` (`HOWDAH_LEGACY_*`
    /// bits; see `legacy_hook.c`). Call once at first RINIT. `cb` is the
    /// one-argument decide callback, `mail_cb` the two-argument `mail()` one,
    /// `xml_cb` the flag-aware XML one.
    /// Returns the mask of sinks actually installed (a function missing on
    /// this PHP is skipped).
    pub fn howdah_install_legacy_hooks(
        cb: HowdahSinkDecide,
        mail_cb: HowdahMailDecide,
        xml_cb: HowdahXmlDecide,
        mask: ::std::ffi::c_int,
    ) -> ::std::ffi::c_int;

    /// `[sinks.xml] external_entities = "deny"`: turn libxml's external
    /// entity loader off for the current request (PHP's own
    /// `libxml_disable_entity_loader(true)`, through the function table, with
    /// error_reporting at 0 so PHP 8's deprecation is not logged per request).
    /// Call at every RINIT. Returns 1 when the call was made, 0 when the
    /// function does not exist.
    pub fn howdah_xml_deny_external_entities() -> ::std::ffi::c_int;

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

    /// Install the T4 file-op foundation (see `file_hook.c`): set the shared
    /// file-op decide callback and swap the read-open sinks file_hook.c owns
    /// (`readfile`). fopen / file_get_contents are swapped by
    /// `howdah_install_ssrf_hooks` and call the firewall check once the callback
    /// is set, so a file-firewall-armed config must ALSO reach
    /// `howdah_install_ssrf_hooks`. Call once at first RINIT when the firewall is
    /// armed. Idempotent; a NULL callback leaves the firewall disarmed.
    pub fn howdah_install_file_hooks(decide: HowdahFileDecide);

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

    /// Install the out-of-memory backstop (see `oom_hook.c`): save and chain
    /// `zend_error_cb`, so an out-of-memory fatal (or any fatal during request
    /// startup) ends the worker via `_exit()` before PHP longjmps, after `cb`
    /// logs the event. Call once at MINIT, only when armed (web SAPI, unpatched
    /// engine, `oom_exit` on). `cb` returns 1 to end the worker, 0 to chain.
    pub fn howdah_install_oom_hook(cb: HowdahOomDecide);

    /// Restore the `zend_error_cb` saved by `howdah_install_oom_hook`. No-op when
    /// not installed. Called from MSHUTDOWN, before the core ctx is freed.
    pub fn howdah_uninstall_oom_hook();

    /// §4.7 recycle facet: `_exit(0)` the worker iff a poisoning-class script
    /// fatal tainted it this request (the decide callback returned 2). Called
    /// from the ext's `post_deactivate` AFTER request teardown, so PHP has
    /// rendered and (on SAPIs that flush before teardown) delivered its 500.
    /// A no-op when the worker was not tainted; allocates nothing.
    pub fn howdah_oom_recycle_if_tainted();

    /// 1 iff the `memory_hard_limit_percent` ini directive is registered at
    /// runtime: upstream's out-of-memory fix (8.2.35/8.3.36/8.4.27/8.5.12) adds
    /// it, so its presence means the backstop should stay off (the engine
    /// already handles out-of-memory safely). Catches distro backports.
    pub fn howdah_memory_hard_limit_percent_exists() -> ::std::ffi::c_int;

    /// Install the §4.1 raw-body hook (see `read_post_hook.c`): wrap
    /// `sapi_module.read_post` so the raw body passes through `cb` (which feeds
    /// the byte-stream scanner) before PHP parses it. `cb` returns 1 to stop the
    /// body (Block) or 0 to continue. Call once at MINIT.
    pub fn howdah_install_read_post_hook(cb: HowdahReadPostDecide);

    /// Restore the `sapi_module.read_post` saved by `howdah_install_read_post_hook`.
    /// No-op when not installed. Called from MSHUTDOWN.
    pub fn howdah_uninstall_read_post_hook();

    /// Clear the per-request "stop reading" latch. Called by the glue at request
    /// begin so a block in one request does not wedge the next request's reads
    /// on a persistent fpm/Apache worker.
    pub fn howdah_read_post_reset();

    /// PHP's effective PARSED `memory_limit` for this request in bytes
    /// (`PG(memory_limit)`; `-1` = no limit). Not `zend_ini_long`, which would
    /// misread the `128M` shorthand.
    pub fn howdah_memory_limit() -> i64;

    /// PHP's effective PARSED `post_max_size` for this request in bytes
    /// (`SG(post_max_size)`; `0` = unlimited).
    pub fn howdah_post_max_size() -> i64;

    /// The request's `Content-Type` (`SG(request_info).content_type`;
    /// NUL-terminated, or NULL). Engine-owned; never freed.
    pub fn howdah_request_content_type() -> *const ::std::ffi::c_char;

    /// 1 iff PHP resolved this request's body as `multipart/form-data` (its
    /// `post_entry` is the multipart reader). The glue arms the byte scanner only
    /// then, so PUT / `php://input` / urlencoded bodies — which PHP does not
    /// parse as multipart and where gaps A/B do not exist — are never scanned.
    pub fn howdah_is_multipart_post() -> ::std::ffi::c_int;

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

/// Legacy sink install mask bits (mirror `HOWDAH_LEGACY_*` in `howdah_sink.h`).
pub const HOWDAH_LEGACY_MAIL: ::std::ffi::c_int = 1;
pub const HOWDAH_LEGACY_PREG_EVAL: ::std::ffi::c_int = 2;
pub const HOWDAH_LEGACY_CREATE_FUNCTION: ::std::ffi::c_int = 4;
pub const HOWDAH_LEGACY_ASSERT: ::std::ffi::c_int = 8;
pub const HOWDAH_LEGACY_CALLBACK: ::std::ffi::c_int = 16;
pub const HOWDAH_LEGACY_XML: ::std::ffi::c_int = 32;
pub const HOWDAH_LEGACY_TLS: ::std::ffi::c_int = 64;

/// The `mail()` decide callback: 4th argument (headers) and 5th
/// (additional_parameters), either NULL/0 when absent or not a string.
/// Returns 0 ALLOW / 1 LOG / 2 BLOCK.
pub type HowdahMailDecide = unsafe extern "C" fn(
    headers: *const ::std::ffi::c_char,
    headers_len: usize,
    params: *const ::std::ffi::c_char,
    params_len: usize,
) -> ::std::ffi::c_int;

/// The XML-string decide callback: the guarded function name, the document, the
/// libxml option mask the call passes and a `HOWDAH_XML_*` capability set.
/// Returns 0 ALLOW / 1 LOG / 2 BLOCK / 3 STRIP (remove the dangerous flags and
/// run the call).
pub type HowdahXmlDecide = unsafe extern "C" fn(
    name: *const ::std::ffi::c_char,
    name_len: usize,
    doc: *const ::std::ffi::c_char,
    doc_len: usize,
    flags: i64,
    caps: ::std::ffi::c_int,
) -> ::std::ffi::c_int;

/// `howdah_sink_ssrf_armed`-shaped callback: 1 iff SSRF guarding is armed.
pub type HowdahSsrfArmed = unsafe extern "C" fn(ctx: *mut ::std::ffi::c_void) -> ::std::ffi::c_int;

/// The §4.1 read_post decide callback (see `read_post_hook.c`). Given the body
/// bytes just read (`buf`/`len`), returns 1 to STOP the body (the byte-stream
/// scanner decided Block) or 0 to continue reading.
pub type HowdahReadPostDecide = unsafe extern "C" fn(
    buf: *const ::std::ffi::c_char,
    len: usize,
) -> ::std::ffi::c_int;

/// The out-of-memory backstop's decide callback (see `oom_hook.c`). `error_type`
/// is PHP's `E_*` code, `msg` the rendered message (8.x) or `format` string
/// (5.x/7.x) for `msg_len` bytes, `during_startup` 1 inside `php_request_startup`,
/// and `file`/`file_len`/`line` the error's location (script path + line, for
/// the logged reason; `file` may be NULL). Returns 0 to chain to the prior
/// handler, 1 to end the worker NOW (the §4.6 backstop), or 2 to mark the worker
/// tainted and chain (the §4.7 recycle facet — the C shim `_exit`s it at the
/// ext's `post_deactivate`, after this request delivers its 500).
pub type HowdahOomDecide = unsafe extern "C" fn(
    error_type: ::std::ffi::c_int,
    msg: *const ::std::ffi::c_char,
    msg_len: usize,
    during_startup: ::std::ffi::c_int,
    file: *const ::std::ffi::c_char,
    file_len: usize,
    line: u32,
) -> ::std::ffi::c_int;

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

/// The T4 file-op decide callback the file-open trampolines invoke (mirrors
/// `howdah_file_decide_t` in `howdah_sink.h`). `name` is the guarded function,
/// `target` its path/URL argument (never logged by the core), `op` a
/// `HOWDAH_FILE_OP_*` code. Returns 0 ALLOW / 1 LOG / 2 BLOCK.
pub type HowdahFileDecide = unsafe extern "C" fn(
    name: *const ::std::ffi::c_char,
    name_len: usize,
    target: *const ::std::ffi::c_char,
    target_len: usize,
    op: ::std::ffi::c_int,
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

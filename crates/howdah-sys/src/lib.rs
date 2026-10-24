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

//! Layer-4 behavior glue: the five callbacks the C trampolines (command-exec in
//! `sink_hook.c`, egress + php-write in `ssrf_hook.c`) invoke once
//! `howdah_install_behavior_hooks` has set them. Mirrors `ssrf_filter`: the
//! C-passed `ctx` is always NULL (the shim never sets it), so `module::CTX` is
//! used, and the glue also writes the core's pre-built log line (which carries
//! no argument values). Fail-open everywhere (NULL CTX / panic -> ALLOW, or 0
//! for `armed`).

use std::ffi::{c_char, c_int, c_void, CStr};
use std::panic::{catch_unwind, AssertUnwindSafe};

use howdah_core::ffi as core;

use crate::{module, response};

/// Take the pending sink-log line (behavior reuses the core's `sink_log` slot),
/// write it, free it. Same helper shape as `ssrf_filter::flush_log_line`.
unsafe fn flush_log_line() {
    let p = core::howdah_take_sink_log_line(module::CTX);
    if !p.is_null() {
        let line = CStr::from_ptr(p).to_string_lossy().into_owned();
        core::howdah_free_str(p);
        response::write_log_line(&line);
    }
}

/// `howdah_behavior_armed_t`: 1 iff the `HOWDAH_BEHAVIOR_*` `facet` is armed;
/// fail-open 0. Used by the C trampolines to skip per-call work when disarmed.
///
/// # Safety
/// Invoked by the C trampolines.
pub(crate) unsafe extern "C" fn armed(_ctx: *mut c_void, facet: c_int) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        if module::CTX.is_null() {
            return 0;
        }
        core::howdah_behavior_armed(module::CTX, facet)
    }))
    .unwrap_or(0)
}

/// `howdah_behavior_exec_dir_t`: an included file is about to compile at `path`.
/// 0 ALLOW / 1 LOG / 2 BLOCK; fail-open ALLOW.
///
/// # Safety
/// Invoked by the C trampolines; `path` valid for `path_len`.
pub(crate) unsafe extern "C" fn exec_dir(
    _ctx: *mut c_void,
    path: *const c_char,
    path_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        if module::CTX.is_null() {
            return core::HOWDAH_ALLOW;
        }
        module::maybe_begin();
        let action = core::howdah_behavior_check_exec_dir(module::CTX, path, path_len);
        flush_log_line();
        action
    }))
    .unwrap_or(core::HOWDAH_ALLOW)
}

/// `howdah_behavior_binary_t`: `caller` is spawning program `prog`.
/// 0 ALLOW / 1 LOG / 2 BLOCK; fail-open ALLOW.
///
/// # Safety
/// Invoked by the C trampolines; pointers valid for their lengths.
pub(crate) unsafe extern "C" fn binary(
    _ctx: *mut c_void,
    caller: *const c_char,
    caller_len: usize,
    prog: *const c_char,
    prog_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        if module::CTX.is_null() {
            return core::HOWDAH_ALLOW;
        }
        module::maybe_begin();
        let action =
            core::howdah_behavior_check_binary(module::CTX, caller, caller_len, prog, prog_len);
        flush_log_line();
        action
    }))
    .unwrap_or(core::HOWDAH_ALLOW)
}

/// `howdah_behavior_egress_t`: `caller` is connecting out to `host`. Invoked by
/// C on every resolved URL whenever the egress callback pointer is set; the core
/// gates on the behavior effective mode and returns ALLOW cheaply when the facet
/// is off, so there is nothing to short-circuit here. 0 ALLOW / 1 LOG / 2 BLOCK;
/// fail-open ALLOW.
///
/// # Safety
/// Invoked by the C trampolines; pointers valid for their lengths.
pub(crate) unsafe extern "C" fn egress(
    _ctx: *mut c_void,
    caller: *const c_char,
    caller_len: usize,
    host: *const c_char,
    host_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        if module::CTX.is_null() {
            return core::HOWDAH_ALLOW;
        }
        module::maybe_begin();
        let action =
            core::howdah_behavior_check_egress(module::CTX, caller, caller_len, host, host_len);
        flush_log_line();
        action
    }))
    .unwrap_or(core::HOWDAH_ALLOW)
}

/// `howdah_behavior_php_write_t`: `caller` is opening `target`; `is_write_mode`
/// non-zero for write modes. 0 ALLOW / 1 LOG / 2 BLOCK; fail-open ALLOW.
///
/// # Safety
/// Invoked by the C trampolines; pointers valid for their lengths.
pub(crate) unsafe extern "C" fn php_write(
    _ctx: *mut c_void,
    caller: *const c_char,
    caller_len: usize,
    target: *const c_char,
    target_len: usize,
    is_write_mode: c_int,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        if module::CTX.is_null() {
            return core::HOWDAH_ALLOW;
        }
        module::maybe_begin();
        let action = core::howdah_behavior_check_php_write(
            module::CTX,
            caller,
            caller_len,
            target,
            target_len,
            is_write_mode,
        );
        flush_log_line();
        action
    }))
    .unwrap_or(core::HOWDAH_ALLOW)
}

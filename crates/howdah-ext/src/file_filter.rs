//! File-op hub glue: the `decide` callback the C file-op trampolines in howdah-sys
//! `file_hook.c` (readfile, file, unlink, rmdir) and the fopen /
//! file_get_contents / rename trampolines in `ssrf_hook.c` invoke per
//! intercepted call. Thin bridge — the wrapper-scheme / poisonable-target policy
//! (T4, Layer 3) and the delete / secret-read guards (T5, Layer 4) live in
//! howdah-core. Mirrors `sink_filter` / `ssrf_filter`: `module::CTX` is used and
//! the executing script (and its SHA-256 when an exception asks) is passed for
//! `[[exceptions]]` `script` facets. Fail-open: a glue panic never neutralizes a
//! legitimate call.
use std::ffi::{c_char, c_int, CStr};
use std::panic::{catch_unwind, AssertUnwindSafe};

use howdah_core::ffi as core;
use howdah_sys as sys;

use crate::{module, origin, response};

/// The calling script and line (the Layer-4 origin) as the engine reports them:
/// `zend_get_executed_filename()` / `zend_get_executed_lineno()` inside the
/// intercepted call. Ungated (unlike `origin::current_script`, which is empty
/// without `[[exceptions]]`) because the T5 guards LOG the call site. Borrowed
/// from the engine, no copy; a non-path placeholder (`[no active file]`) is
/// dropped like `origin::current_script` does.
///
/// # Safety
/// Must be called from a PHP hook with the engine initialised; the slice is
/// valid only for the duration of the call.
unsafe fn call_site<'a>() -> (&'a [u8], u32) {
    let p = sys::howdah_sys_current_script();
    let file: &[u8] = if p.is_null() {
        &[]
    } else {
        let b = CStr::from_ptr(p).to_bytes();
        if b.first() == Some(&b'/') {
            b
        } else {
            &[]
        }
    };
    (file, sys::howdah_sys_current_line())
}

/// `howdah_file_decide_t`: 0 ALLOW / 1 LOG / 2 BLOCK. On BLOCK the C
/// neutralizes the call (RETVAL_FALSE).
///
/// # Safety
/// Invoked by the C trampolines mid-call; `name`/`target` valid for their lens.
pub(crate) unsafe extern "C" fn decide(
    name: *const c_char,
    name_len: usize,
    target: *const c_char,
    target_len: usize,
    op: c_int,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        if module::CTX.is_null() {
            return core::HOWDAH_ALLOW;
        }
        module::maybe_begin();
        let (script, line) = call_site();
        let sha = origin::sha_for(script);
        let (sp, sl) = origin::sha_args(&sha);
        let action = core::howdah_sink_check_open_at(
            module::CTX,
            name,
            name_len,
            target,
            target_len,
            op,
            script.as_ptr() as *const c_char,
            script.len(),
            sp,
            sl,
            line,
        );
        let p = core::howdah_take_sink_log_line(module::CTX);
        if !p.is_null() {
            let line = CStr::from_ptr(p).to_string_lossy().into_owned();
            core::howdah_free_str(p);
            response::write_log_line(&line);
        }
        action
    }))
    .unwrap_or(core::HOWDAH_ALLOW) // fail-open: never neutralize on a glue bug
}

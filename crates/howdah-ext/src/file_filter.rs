//! Layer-3 file-open firewall glue (T4): the `decide` callback the C file-op
//! trampolines in howdah-sys `file_hook.c` (readfile) and the fopen /
//! file_get_contents trampolines in `ssrf_hook.c` invoke per intercepted call.
//! Thin bridge — the wrapper-scheme and poisonable-local-target policy lives in
//! howdah-core. Mirrors `sink_filter` / `ssrf_filter`: `module::CTX` is used and
//! the executing script (and its SHA-256 when an exception asks) is passed for
//! `[[exceptions]]` `script` facets. Fail-open: a glue panic never neutralizes a
//! legitimate call.
use std::ffi::{c_char, c_int, CStr};
use std::panic::{catch_unwind, AssertUnwindSafe};

use howdah_core::ffi as core;

use crate::{module, origin, response};

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
        let script = origin::current_script();
        let sha = origin::sha_for(&script);
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

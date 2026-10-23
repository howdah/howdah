//! Layer-3 sink-hook glue: the decision callback the C trampolines in
//! howdah-sys `sink_hook.c` invoke per intercepted call. Thin bridge —
//! the policy lives in howdah-core. Fail-open: a glue panic never neutralizes
//! a legitimate call.
use std::ffi::{c_char, c_int, CStr};
use std::panic::{catch_unwind, AssertUnwindSafe};

use howdah_core::ffi as core;

use crate::{module, response};

/// Installed as the sink-decision callback by MINIT. Returns the action code
/// (0 ALLOW / 1 LOG / 2 BLOCK); on BLOCK the C neutralizes the call.
///
/// # Safety
/// Invoked by the C sink trampolines mid-call; `name`/`arg` valid for their lens.
pub(crate) unsafe extern "C" fn decide(
    sink: c_int,
    name: *const c_char,
    name_len: usize,
    arg: *const c_char,
    arg_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        // Defense in depth: if there is no live core context (e.g. a trampoline
        // fires after MSHUTDOWN freed+nulled CTX), chain the call unguarded. The
        // core entry points are null-safe too, but guarding here makes it local.
        if module::CTX.is_null() {
            return core::HOWDAH_ALLOW;
        }
        module::maybe_begin();
        let action = core::howdah_sink_check(module::CTX, sink, name, name_len, arg, arg_len);
        // Emit this hit's line immediately (per-hit, at the call site), then
        // return the action so the C side chains (ALLOW/LOG) or neutralizes (BLOCK).
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

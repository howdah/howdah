//! The out-of-memory backstop's classifier (pure; host-tested).
//!
//! PHP's out-of-memory handling longjmps out of the current operation. On an
//! unpatched engine that can leave request state half-built, which later code
//! reads (PHP2Shell, CVE-2026-109618/109619). The glue installs a
//! `zend_error_cb` hook and asks this function, for each error PHP raises,
//! whether Howdah must end the worker before anything runs on that state.
//!
//! The decision is a pure function of the error type, the error message (the
//! rendered `zend_string` on PHP 8.x, or the `format` string on 5.x/7.x, which
//! still carries its `%`-specifiers — the prefixes we match precede any of
//! them), and whether PHP is still inside request startup.

use crate::limits::RuleId;

// PHP error-type bit flags (`Zend/zend_errors.h`), stable across 5.4–8.5.
pub const E_ERROR: i32 = 1;
pub const E_WARNING: i32 = 2;
pub const E_PARSE: i32 = 4;
pub const E_NOTICE: i32 = 8;
pub const E_CORE_ERROR: i32 = 16;
pub const E_COMPILE_ERROR: i32 = 64;
pub const E_USER_ERROR: i32 = 256;
pub const E_RECOVERABLE_ERROR: i32 = 4096;

/// The error types that bail out (longjmp) in PHP. `E_RECOVERABLE_ERROR` is
/// catchable and deliberately excluded.
const FATAL_MASK: i32 = E_ERROR | E_CORE_ERROR | E_COMPILE_ERROR | E_USER_ERROR | E_PARSE;

/// Message prefixes PHP uses for an out-of-memory fatal.
const OOM_PREFIXES: [&[u8]; 2] = [b"Allowed memory size of", b"Out of memory"];

fn is_fatal(error_type: i32) -> bool {
    error_type & FATAL_MASK != 0
}

/// What the backstop/recycle machinery must do about one PHP error. A pure
/// function of the error; the glue decides whether each outcome is *armed*
/// (`oom_exit` for [`FatalAction::ExitNow`], `recycle_on_fatal` for
/// [`FatalAction::RecycleAfter`]) before acting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FatalAction {
    /// Let PHP handle the error normally (chain to the prior `zend_error_cb`).
    None,
    /// End the worker NOW, before PHP longjmps (§4.6): an out-of-memory fatal
    /// (any phase), or any bailout-fatal during request startup. The producing
    /// request's connection drops; a fresh worker serves the next one.
    ExitNow(RuleId),
    /// Recycle the worker AFTER this request's teardown (§4.7): a non-OOM
    /// bailout-fatal during the script — an uncaught `Error`, a parse/compile
    /// error, a failed `require`, `max_execution_time`. The producing request
    /// still renders and delivers its own 500 (the consumer of
    /// CVE-2026-109619 runs only on a *later* request on the same worker); the
    /// worker then `_exit`s before serving another.
    RecycleAfter(RuleId),
}

/// Classify one PHP error for the backstop and the recycle facet.
///
/// * A bailout-fatal whose message starts with an out-of-memory prefix →
///   [`FatalAction::ExitNow`]`(`[`RuleId::OutOfMemory`]`)` (regardless of phase —
///   OOM is the primary danger).
/// * Any other bailout-fatal raised while PHP is still in request startup →
///   [`FatalAction::ExitNow`]`(`[`RuleId::StartupFatal`]`)` (the
///   CVE-2026-109619 startup window).
/// * A bailout-fatal during the script (not out-of-memory, not startup) →
///   [`FatalAction::RecycleAfter`]`(`[`RuleId::FatalRecycle`]`)` (the remaining
///   CVE-2026-109619 producer).
/// * Anything else (warnings, notices, catchable errors) → [`FatalAction::None`].
pub fn classify_fatal(error_type: i32, message: &[u8], during_startup: bool) -> FatalAction {
    // Only a true engine out-of-memory counts, and PHP always raises that as
    // `E_ERROR` (zend_mm_safe_error -> zend_error_noreturn(E_ERROR, ...)). A
    // script-controlled `E_USER_ERROR` (or any other fatal type) whose message
    // merely starts with an out-of-memory prefix must NOT end the worker — on
    // PHP 8.x `trigger_error($attacker_msg, E_USER_ERROR)` hands us the rendered
    // message, which would otherwise be a remote worker-recycle and a false
    // `out_of_memory` event. The `& E_ERROR` test ignores any flag bits (e.g.
    // `E_DONT_BAIL`) the engine ORs onto the type.
    if (error_type & E_ERROR) != 0 && OOM_PREFIXES.iter().any(|p| message.starts_with(p)) {
        return FatalAction::ExitNow(RuleId::OutOfMemory);
    }
    if is_fatal(error_type) {
        // A non-OOM bailout-fatal: exit now if it struck during request startup
        // (the §4.6 window), otherwise it is a script-phase poisoning-class
        // fatal the recycle facet (§4.7) closes after the request delivers its
        // 500. Non-fatal types (warnings/notices) fall through to `None`.
        if during_startup {
            return FatalAction::ExitNow(RuleId::StartupFatal);
        }
        return FatalAction::RecycleAfter(RuleId::FatalRecycle);
    }
    FatalAction::None
}

#[cfg(test)]
mod tests {
    use super::*;

    use FatalAction::{ExitNow, None as FaNone, RecycleAfter};

    // ---- §4.6 exit-now: out-of-memory, any phase (unchanged byte-for-byte) ----

    #[test]
    fn oom_format_prefix_5x_7x_is_out_of_memory() {
        // 5.x/7.x hand the FORMAT string (with %zu still in it).
        let f = b"Allowed memory size of %zu bytes exhausted (tried to allocate %zu bytes)";
        assert_eq!(classify_fatal(E_ERROR, f, false), ExitNow(RuleId::OutOfMemory));
    }
    #[test]
    fn oom_rendered_message_8x_is_out_of_memory() {
        let m = b"Allowed memory size of 2097152 bytes exhausted (tried to allocate 40 bytes)";
        assert_eq!(classify_fatal(E_ERROR, m, false), ExitNow(RuleId::OutOfMemory));
    }
    #[test]
    fn out_of_memory_literal_is_out_of_memory() {
        assert_eq!(classify_fatal(E_ERROR, b"Out of memory", false), ExitNow(RuleId::OutOfMemory));
    }
    #[test]
    fn oom_wins_even_during_startup() {
        assert_eq!(classify_fatal(E_ERROR, b"Out of memory", true), ExitNow(RuleId::OutOfMemory));
    }

    // ---- §4.6 exit-now: any fatal during request startup ----------------------

    #[test]
    fn any_fatal_during_startup_is_exit_now_startup_fatal() {
        for t in [E_ERROR, E_CORE_ERROR, E_COMPILE_ERROR, E_PARSE, E_USER_ERROR] {
            assert_eq!(
                classify_fatal(t, b"Uncaught Error: boom", true),
                ExitNow(RuleId::StartupFatal),
                "type {t}"
            );
        }
    }

    // ---- §4.7 recycle-after: a non-OOM bailout fatal during the script --------
    // Each producer the advisory names (other than OOM and the startup window)
    // raises a bailout fatal through zend_error_cb and must classify as
    // RecycleAfter(FatalRecycle).

    #[test]
    fn uncaught_error_script_phase_is_recycle_after() {
        // An uncaught Error/Exception surfaces as E_ERROR "Uncaught ...".
        assert_eq!(
            classify_fatal(E_ERROR, b"Uncaught Error: Call to undefined function boom()", false),
            RecycleAfter(RuleId::FatalRecycle)
        );
    }
    #[test]
    fn parse_or_compile_error_is_recycle_after() {
        assert_eq!(
            classify_fatal(E_PARSE, b"syntax error, unexpected end of file", false),
            RecycleAfter(RuleId::FatalRecycle)
        );
        assert_eq!(
            classify_fatal(E_COMPILE_ERROR, b"Cannot redeclare foo()", false),
            RecycleAfter(RuleId::FatalRecycle)
        );
    }
    #[test]
    fn failed_require_is_recycle_after() {
        // A failed `require` is a compile/E_ERROR fatal naming the missing file.
        assert_eq!(
            classify_fatal(E_COMPILE_ERROR, b"require(): Failed opening required 'missing.php'", false),
            RecycleAfter(RuleId::FatalRecycle)
        );
        assert_eq!(
            classify_fatal(E_ERROR, b"Failed opening required 'missing.php' (include_path='.')", false),
            RecycleAfter(RuleId::FatalRecycle)
        );
    }
    #[test]
    fn max_execution_time_is_recycle_after() {
        // max_execution_time is an E_ERROR "Maximum execution time ... exceeded".
        assert_eq!(
            classify_fatal(E_ERROR, b"Maximum execution time of 30 seconds exceeded", false),
            RecycleAfter(RuleId::FatalRecycle)
        );
    }
    #[test]
    fn user_error_script_phase_is_recycle_after() {
        // trigger_error(..., E_USER_ERROR) in the script also bails out.
        assert_eq!(
            classify_fatal(E_USER_ERROR, b"fatal from the app", false),
            RecycleAfter(RuleId::FatalRecycle)
        );
    }

    // ---- regressions: the §4.6 boundaries stay exactly where they were --------

    #[test]
    fn oom_stays_exit_now_never_recycle() {
        // OOM must never degrade to recycle-after, in any phase.
        assert_eq!(classify_fatal(E_ERROR, b"Out of memory", false), ExitNow(RuleId::OutOfMemory));
        assert_eq!(classify_fatal(E_ERROR, b"Allowed memory size of 1 bytes exhausted", true), ExitNow(RuleId::OutOfMemory));
    }
    #[test]
    fn startup_fatal_stays_exit_now_never_recycle() {
        // The same fatal that recycles in the script must still EXIT during startup.
        assert_eq!(classify_fatal(E_ERROR, b"Uncaught Error: boom", true), ExitNow(RuleId::StartupFatal));
        assert_eq!(classify_fatal(E_PARSE, b"syntax error", true), ExitNow(RuleId::StartupFatal));
    }
    #[test]
    fn script_controlled_user_error_with_oom_prefix_is_not_oom() {
        // trigger_error("Allowed memory size of ...", E_USER_ERROR) on PHP 8.x
        // must NOT be treated as a real out-of-memory: only E_ERROR counts. It is
        // still a script-phase bailout fatal, so it recycles, not exits.
        assert_eq!(
            classify_fatal(E_USER_ERROR, b"Allowed memory size of 999 bytes exhausted", false),
            RecycleAfter(RuleId::FatalRecycle)
        );
        assert_eq!(classify_fatal(E_USER_ERROR, b"Out of memory, ha", false), RecycleAfter(RuleId::FatalRecycle));
        // E_ERROR with a flag bit (e.g. E_DONT_BAIL) still classifies as OOM exit.
        assert_eq!(classify_fatal(E_ERROR | 0x8000, b"Out of memory", false), ExitNow(RuleId::OutOfMemory));
    }
    #[test]
    fn warning_never_matches_even_during_startup() {
        // OOM is always raised as a bailout fatal (E_ERROR); a non-fatal type
        // carrying an OOM-looking message is not treated as OOM, and a warning is
        // never fatal so it neither exits nor recycles.
        assert_eq!(classify_fatal(E_WARNING, b"Allowed memory size of ...", true), FaNone);
        assert_eq!(classify_fatal(E_WARNING, b"undefined index", true), FaNone);
        assert_eq!(classify_fatal(E_WARNING, b"undefined index", false), FaNone);
        assert_eq!(classify_fatal(E_NOTICE, b"undefined var", false), FaNone);
        // Catchable, not a bailout.
        assert_eq!(classify_fatal(E_RECOVERABLE_ERROR, b"boom", true), FaNone);
        assert_eq!(classify_fatal(E_RECOVERABLE_ERROR, b"boom", false), FaNone);
    }
    #[test]
    fn empty_or_unrelated_fatal_message_still_classifies_by_type() {
        // An E_ERROR with an unrelated message is still a bailout fatal: it
        // recycles in the script, exits during startup. Only the OOM prefix and
        // the startup phase change the outcome; the message content otherwise
        // does not gate anything (we never inspect request content).
        assert_eq!(classify_fatal(E_ERROR, b"", false), RecycleAfter(RuleId::FatalRecycle));
        assert_eq!(classify_fatal(E_ERROR, b"Division by zero", false), RecycleAfter(RuleId::FatalRecycle));
        assert_eq!(classify_fatal(E_ERROR, b"", true), ExitNow(RuleId::StartupFatal));
    }
    #[test]
    fn new_rules_are_critical_layer1() {
        use crate::limits::Severity;
        use crate::log::rule_layer;
        for r in [RuleId::OutOfMemory, RuleId::StartupFatal, RuleId::FatalRecycle] {
            assert_eq!(r.severity(), Severity::Critical);
            assert_eq!(rule_layer(r), 1);
        }
    }
}

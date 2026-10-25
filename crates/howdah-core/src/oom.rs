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

/// Classify one PHP error for the backstop. Returns the rule the worker should
/// be ended on, or `None` to let PHP handle the error normally.
///
/// * A bailout-fatal whose message starts with an out-of-memory prefix →
///   [`RuleId::OutOfMemory`] (regardless of phase — OOM is the primary danger).
/// * Any other bailout-fatal raised while PHP is still in request startup →
///   [`RuleId::StartupFatal`] (the CVE-2026-109619 window).
/// * Anything else (warnings, notices, catchable errors, ordinary script-phase
///   fatals) → `None`.
pub fn classify_fatal(error_type: i32, message: &[u8], during_startup: bool) -> Option<RuleId> {
    if is_fatal(error_type) && OOM_PREFIXES.iter().any(|p| message.starts_with(p)) {
        return Some(RuleId::OutOfMemory);
    }
    if during_startup && is_fatal(error_type) {
        return Some(RuleId::StartupFatal);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oom_format_prefix_5x_7x_is_out_of_memory() {
        // 5.x/7.x hand the FORMAT string (with %zu still in it).
        let f = b"Allowed memory size of %zu bytes exhausted (tried to allocate %zu bytes)";
        assert_eq!(classify_fatal(E_ERROR, f, false), Some(RuleId::OutOfMemory));
    }
    #[test]
    fn oom_rendered_message_8x_is_out_of_memory() {
        let m = b"Allowed memory size of 2097152 bytes exhausted (tried to allocate 40 bytes)";
        assert_eq!(classify_fatal(E_ERROR, m, false), Some(RuleId::OutOfMemory));
    }
    #[test]
    fn out_of_memory_literal_is_out_of_memory() {
        assert_eq!(classify_fatal(E_ERROR, b"Out of memory", false), Some(RuleId::OutOfMemory));
    }
    #[test]
    fn oom_wins_even_during_startup() {
        assert_eq!(classify_fatal(E_ERROR, b"Out of memory", true), Some(RuleId::OutOfMemory));
    }
    #[test]
    fn any_fatal_during_startup_is_startup_fatal() {
        for t in [E_ERROR, E_CORE_ERROR, E_COMPILE_ERROR, E_PARSE, E_USER_ERROR] {
            assert_eq!(
                classify_fatal(t, b"Uncaught Error: boom", true),
                Some(RuleId::StartupFatal),
                "type {t}"
            );
        }
    }
    #[test]
    fn script_phase_non_oom_fatal_does_not_match() {
        assert_eq!(classify_fatal(E_ERROR, b"Uncaught Error: boom", false), None);
    }
    #[test]
    fn warning_never_matches_even_during_startup() {
        // OOM is always raised as a bailout fatal (E_ERROR); a non-fatal type
        // carrying an OOM-looking message is not treated as OOM.
        assert_eq!(classify_fatal(E_WARNING, b"Allowed memory size of ...", true), None);
        assert_eq!(classify_fatal(E_WARNING, b"undefined index", true), None);
        assert_eq!(classify_fatal(E_NOTICE, b"undefined var", false), None);
        // Catchable, not a bailout.
        assert_eq!(classify_fatal(E_RECOVERABLE_ERROR, b"boom", true), None);
    }
    #[test]
    fn empty_or_unrelated_message_is_none() {
        assert_eq!(classify_fatal(E_ERROR, b"", false), None);
        assert_eq!(classify_fatal(E_ERROR, b"Division by zero", false), None);
    }
    #[test]
    fn new_rules_are_critical_layer1() {
        use crate::limits::Severity;
        use crate::log::rule_layer;
        for r in [RuleId::OutOfMemory, RuleId::StartupFatal] {
            assert_eq!(r.severity(), Severity::Critical);
            assert_eq!(rule_layer(r), 1);
        }
    }
}

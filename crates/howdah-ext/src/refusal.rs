//! Deferred refusal: *when* a refusal may be delivered.
//!
//! A refusal decided while PHP is still inside `php_request_startup()` (the
//! multipart callback runs from `php_hash_environment`, the Layer 4 main-script
//! check from RINIT) must not `zend_bailout()`: the whole startup runs inside
//! one `zend_try`, a longjmp there makes `php_request_startup()` return
//! FAILURE, and php-fpm answers that with a forced close and `exit(70)` (see
//! `docs/superpowers/specs/2026-10-24-howdah-refusal-path-design.md`). So the
//! verdict is recorded here and delivered at the end of our RINIT, where a
//! response is legal and the script can be suppressed without a longjmp.
//!
//! Pure Rust so the state machine is host-tested; the PHP glue (`module.rs`)
//! supplies the phase from PHP's own `PG(during_request_startup)` flag.

use std::ffi::c_int;

/// What the refusal says to the client: the HTTP status and the request id
/// that also appears in the log line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub status: c_int,
    pub request_id: String,
}

/// Where a just-decided refusal goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Delivery {
    /// Recorded; the caller returns normally and RINIT delivers it.
    Deferred,
    /// PHP is past startup: the caller delivers it on the spot (a bailout is
    /// legal during execution). Carries the verdict back.
    Now(Verdict),
    /// A verdict was already recorded or delivered this request; this one is
    /// dropped (first verdict wins, one response per request).
    Ignored,
}

/// One request's refusal state. Reset at the end of every request.
#[derive(Debug, Default)]
pub struct Deferred {
    pending: Option<Verdict>,
    delivered: bool,
}

impl Deferred {
    /// The empty state, usable in a `static`.
    pub const fn new() -> Self {
        Deferred { pending: None, delivered: false }
    }

    /// A hook decided to refuse. `during_startup` is PHP's
    /// `PG(during_request_startup)`.
    pub fn refuse(&mut self, verdict: Verdict, during_startup: bool) -> Delivery {
        if self.delivered || self.pending.is_some() {
            return Delivery::Ignored;
        }
        if during_startup {
            self.pending = Some(verdict);
            Delivery::Deferred
        } else {
            self.delivered = true;
            Delivery::Now(verdict)
        }
    }

    /// End of RINIT: the first legal point for a response. Hands out the
    /// recorded verdict exactly once and marks the request refused.
    pub fn take_at_rinit(&mut self) -> Option<Verdict> {
        let v = self.pending.take()?;
        self.delivered = true;
        Some(v)
    }

    /// Mark a verdict derived at RINIT itself (the input path latched a block
    /// before RINIT) as delivered, so nothing else responds this request.
    pub fn mark_delivered(&mut self) {
        self.delivered = true;
    }

    /// True once a response has gone out (or is about to) this request.
    pub fn delivered(&self) -> bool {
        self.delivered
    }

    /// A verdict is recorded and still waiting for RINIT.
    pub fn is_pending(&self) -> bool {
        self.pending.is_some()
    }

    /// End of request.
    pub fn reset(&mut self) {
        self.pending = None;
        self.delivered = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(status: c_int, id: &str) -> Verdict {
        Verdict { status, request_id: id.to_string() }
    }

    #[test]
    fn startup_verdict_is_deferred_and_delivered_once_at_rinit() {
        let mut d = Deferred::default();
        assert_eq!(d.refuse(v(403, "a"), true), Delivery::Deferred);
        assert!(d.is_pending());
        assert!(!d.delivered());
        assert_eq!(d.take_at_rinit(), Some(v(403, "a")));
        assert!(d.delivered());
        assert!(!d.is_pending());
        assert_eq!(d.take_at_rinit(), None, "exactly once");
    }

    #[test]
    fn execution_verdict_is_delivered_now() {
        let mut d = Deferred::default();
        assert_eq!(d.refuse(v(413, "b"), false), Delivery::Now(v(413, "b")));
        assert!(d.delivered());
        assert_eq!(d.take_at_rinit(), None);
    }

    #[test]
    fn first_verdict_wins() {
        let mut d = Deferred::default();
        assert_eq!(d.refuse(v(413, "first"), true), Delivery::Deferred);
        assert_eq!(d.refuse(v(403, "second"), true), Delivery::Ignored);
        assert_eq!(d.refuse(v(403, "third"), false), Delivery::Ignored);
        assert_eq!(d.take_at_rinit(), Some(v(413, "first")));
    }

    #[test]
    fn nothing_after_delivery_in_the_same_request() {
        let mut d = Deferred::default();
        d.refuse(v(403, "a"), true);
        d.take_at_rinit();
        assert_eq!(d.refuse(v(403, "late"), false), Delivery::Ignored);
        let mut e = Deferred::default();
        e.mark_delivered();
        assert_eq!(e.refuse(v(403, "late"), true), Delivery::Ignored);
        assert_eq!(e.take_at_rinit(), None);
    }

    #[test]
    fn reset_clears_everything_for_the_next_request() {
        let mut d = Deferred::default();
        d.refuse(v(403, "a"), true);
        d.reset();
        assert!(!d.is_pending() && !d.delivered());
        assert_eq!(d.take_at_rinit(), None);
        d.refuse(v(403, "b"), false);
        d.reset();
        assert_eq!(d.refuse(v(403, "c"), true), Delivery::Deferred);
    }

    #[test]
    fn no_verdict_means_nothing_at_rinit() {
        let mut d = Deferred::default();
        assert_eq!(d.take_at_rinit(), None);
        assert!(!d.delivered());
    }
}

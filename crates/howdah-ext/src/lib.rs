//! The Howdah PHP extension (`howdah.so`): a `cdylib` that registers Howdah at
//! module startup, chains PHP's multipart (`rfc1867`) callback, feeds request
//! structure to the pure-Rust core through its C ABI, and refuses an abusive
//! upload before PHP materialises per-part memory (the PHP2Shell defence).
//!
//! All `unsafe` and all PHP/Zend contact lives in this crate. The core stays
//! pure Rust; this glue translates between PHP's world and the core's C ABI.
//!
//! # Build requirement (carry-forward #2)
//! The core's FFI safety rests on `catch_unwind`, which is a no-op under
//! `panic = "abort"`. This cdylib MUST be built with `panic = "unwind"` (set in
//! the workspace dev+release profiles). `panic_unwinds` below is a runtime
//! self-check proving a panic is actually caught, surfaced in `phpinfo()`.
//!
//! With no `phpN` feature only the pure [`ini_config`] is compiled
//! (host-testable, no PHP headers needed); the PHP glue is feature-gated. The
//! glue's use of the core ABI is exercised on the host by
//! `tests/multipart_events.rs`, which drives the same calls the glue makes.

pub mod ini_config;

#[cfg(any(feature = "php5", feature = "php7", feature = "php8"))]
mod input_filter;
#[cfg(any(feature = "php5", feature = "php7", feature = "php8"))]
mod module;
#[cfg(any(feature = "php5", feature = "php7", feature = "php8"))]
mod response;
#[cfg(any(feature = "php5", feature = "php7", feature = "php8"))]
mod rfc1867;
#[cfg(any(feature = "php5", feature = "php7", feature = "php8"))]
mod sink_filter;
#[cfg(any(feature = "php5", feature = "php7", feature = "php8"))]
mod ssrf_filter;

/// Belt-and-suspenders (carry-forward #2): confirm at runtime that this binary
/// actually catches panics (i.e. was built `panic = "unwind"`). Returns true
/// when a panic was caught. Used in the `phpinfo()` table so an operator can
/// see the guarantee holds on the deployed build.
pub fn panic_unwinds() -> bool {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {})); // silence the panic message
    let caught = std::panic::catch_unwind(|| panic!("howdah self-check")).is_err();
    std::panic::set_hook(prev);
    caught
}

#[cfg(test)]
mod tests {
    #[test]
    fn panics_are_caught_on_this_build() {
        // If this ever fails, the crate was built panic="abort" and the FFI
        // boundary's catch_unwind would be a no-op — a hard safety violation.
        assert!(super::panic_unwinds());
    }
}

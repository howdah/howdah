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
}

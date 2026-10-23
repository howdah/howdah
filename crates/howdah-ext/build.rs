//! Version-gates the one `input_filter` signature difference bindgen can't
//! fold into a `phpN` feature.
//!
//! The chained `sapi_module.input_filter`'s `var` parameter is `char *` before
//! PHP 8.1 and `const char *` from 8.1 onward (Task-1 spike finding). That
//! boundary falls INSIDE the `php8` feature (8.0 is still `char *`), so a plain
//! `#[cfg(feature = "php8")]` cannot express it. We ask `php-config` for the
//! exact `PHP_VERSION_ID` and emit `cfg(howdah_input_filter_const)` when it is
//! >= 8.1.0, so `input_filter.rs` can pick the matching pointer type and the
//! handler's `extern "C"` signature matches `sys::`'s generated field type on
//! every generation (the in-container compiler enforces the match).
//!
//! With no `phpN` feature this does nothing (plain host `cargo build`/`test`).

#[cfg(any(feature = "php5", feature = "php7", feature = "php8"))]
fn main() {
    use std::{env, process::Command};

    println!("cargo:rerun-if-env-changed=PHP_CONFIG");
    // Declare the cfg so a build on any generation stays warning-clean.
    println!("cargo::rustc-check-cfg=cfg(howdah_input_filter_const)");

    let php_config = env::var("PHP_CONFIG").unwrap_or_else(|_| "php-config".into());
    let out = Command::new(&php_config)
        .arg("--vernum")
        .output()
        .unwrap_or_else(|e| panic!("cannot run `{php_config} --vernum` (set PHP_CONFIG): {e}"));
    assert!(out.status.success(), "`{php_config} --vernum` failed");
    let vernum: u32 = String::from_utf8(out.stdout)
        .expect("php-config --vernum output not UTF-8")
        .trim()
        .parse()
        .expect("php-config --vernum not an integer");

    // `const char *var` from PHP 8.1.0 (80100); `char *var` before it.
    if vernum >= 80100 {
        println!("cargo:rustc-cfg=howdah_input_filter_const");
    }
}

#[cfg(not(any(feature = "php5", feature = "php7", feature = "php8")))]
fn main() {}

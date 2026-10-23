//! Version-gates the one `input_filter` signature difference bindgen can't
//! fold into a `phpN` feature.
//!
//! The chained `sapi_module.input_filter`'s `var` parameter is `char *` before
//! PHP 8.0 and `const char *` from 8.0 onward (the SAPI constification landed
//! for 8.0.0; proven by the per-minor release build failing to compile on 8.0
//! with the `char *` type). That boundary falls INSIDE the `php8` feature (it
//! splits 7.x from 8.x), so a plain `#[cfg(feature = "php8")]` almost expresses
//! it — but we gate on the exact version so a future pre-8.0 `php8`-style build
//! can't be miscompiled. We ask `php-config` for the exact `PHP_VERSION_ID` and
//! emit `cfg(howdah_input_filter_const)` when it is 8.0.0 or newer, so
//! `input_filter.rs` can pick the matching pointer type and
//! the handler's `extern "C"` signature matches `sys::`'s generated field type
//! on every generation (the in-container compiler enforces the match).
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

    // `const char *var` from PHP 8.0.0 (80000); `char *var` before it.
    if vernum >= 80000 {
        println!("cargo:rustc-cfg=howdah_input_filter_const");
    }
}

#[cfg(not(any(feature = "php5", feature = "php7", feature = "php8")))]
fn main() {}

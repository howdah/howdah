//! Generates PHP bindings with bindgen when a `phpN` feature is active.
//!
//! BUILD HYGIENE: with no `phpN` feature this script does nothing (and
//! bindgen is not even compiled: it is an optional dependency), so a plain
//! `cargo build` / `cargo test` on a host without PHP headers is unaffected.
//!
//! Headers come from `php-config --includes`; set `PHP_CONFIG` to point at a
//! specific php-config binary.

#[cfg(any(feature = "php5", feature = "php7", feature = "php8"))]
fn main() {
    use std::{env, path::PathBuf, process::Command};

    println!("cargo:rerun-if-env-changed=PHP_CONFIG");
    println!("cargo:rerun-if-changed=wrapper.h");

    let n = ["PHP5", "PHP7", "PHP8"]
        .iter()
        .filter(|f| env::var_os(format!("CARGO_FEATURE_{f}")).is_some())
        .count();
    assert!(n == 1, "enable exactly one of the php5/php7/php8 features");

    let php_config = env::var("PHP_CONFIG").unwrap_or_else(|_| "php-config".into());
    let out = Command::new(&php_config)
        .arg("--includes")
        .output()
        .unwrap_or_else(|e| panic!("cannot run `{php_config} --includes` (set PHP_CONFIG): {e}"));
    assert!(out.status.success(), "`{php_config} --includes` failed");
    let includes = String::from_utf8(out.stdout).expect("php-config output not UTF-8");

    // Compile the C shim (ZEND_MODULE_BUILD_ID) against the same headers.
    println!("cargo:rerun-if-changed=shim.c");
    println!("cargo:rerun-if-changed=sink_hook.c");
    println!("cargo:rerun-if-changed=phar_hook.c");
    println!("cargo:rerun-if-changed=ssrf_hook.c");
    println!("cargo:rerun-if-changed=refuse_hook.c");
    println!("cargo:rerun-if-changed=howdah_sink.h");
    let mut shim = cc::Build::new();
    shim.file("shim.c")
        .file("sink_hook.c")
        .file("phar_hook.c")
        .file("ssrf_hook.c")
        .file("refuse_hook.c")
        .warnings(false);
    for inc in includes.split_whitespace() {
        if let Some(dir) = inc.strip_prefix("-I") {
            shim.include(dir);
        }
    }
    shim.compile("howdah_sys_shim");

    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        .clang_args(includes.split_whitespace())
        .layout_tests(false)
        .generate_comments(false)
        // rfc1867 hook + events.
        .allowlist_var("php_rfc1867_callback")
        .allowlist_var("MULTIPART_EVENT_.*")
        .allowlist_type("multipart_event_.*|php_rfc1867_.*")
        .allowlist_function("php_rfc1867_.*|rfc1867_.*")
        // Module startup machinery.
        .allowlist_type("_?zend_module_entry|_?zend_function_entry|zend_ini_entry|_?zend_ini_entry|_?zend_ini_entry_def")
        .allowlist_function("zend_register_ini_entries|zend_unregister_ini_entries|zend_parse_parameters|php_info_print_table_.*")
        // Reading registered ini entries, and request termination.
        .allowlist_function("zend_ini_string|zend_ini_long|_?zend_bailout")
        // SAPI.
        .allowlist_type("_?sapi_module_struct|sapi_request_info|_?sapi_globals_struct|_?sapi_header_struct|sapi_header_line")
        .allowlist_var("sapi_module|sapi_globals")
        .allowlist_function("sapi_.*")
        // input_filter `arg` discriminants (PARSE_GET/POST/COOKIE/SERVER).
        .allowlist_var("PARSE_.*")
        // Module-entry constants the glue must fill in (macros; absent ones are ignored).
        .allowlist_var("ZEND_MODULE_API_NO|ZEND_MODULE_BUILD_ID|PHP_VERSION_ID|ZEND_DEBUG|USING_ZTS|PHP_API_VERSION")
        .generate()
        .expect("bindgen failed on PHP headers");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap()).join("bindings.rs");
    bindings.write_to_file(out_path).expect("writing bindings.rs");
}

#[cfg(not(any(feature = "php5", feature = "php7", feature = "php8")))]
fn main() {}

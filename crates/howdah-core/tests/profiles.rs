//! The shipped application profiles (`profiles/*.toml`) must load with the
//! real parser, give every exception a reason, and arm nothing.

use std::path::PathBuf;

use howdah_core::{Config, Mode};

fn profiles_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../profiles")
}

fn profiles() -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = std::fs::read_dir(profiles_dir())
        .expect("profiles/ directory")
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().is_some_and(|x| x == "toml"))
        .map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            let text = std::fs::read_to_string(e.path()).unwrap();
            (name, text)
        })
        .collect();
    out.sort();
    out
}

#[test]
fn the_six_profiles_exist() {
    let names: Vec<String> = profiles().into_iter().map(|(n, _)| n).collect();
    assert_eq!(
        names,
        ["drupal7.toml", "joomla.toml", "magento1.toml", "magento2.toml", "prestashop16.toml", "wordpress.toml"]
    );
}

#[test]
fn every_profile_parses_with_the_real_core() {
    for (name, text) in profiles() {
        let c = Config::from_toml(&text).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert!(!c.exceptions.is_empty(), "{name}: no exceptions");
        assert_eq!(Config::exceptions_report(&text), Some((c.exceptions.len(), 0)), "{name}");
    }
}

#[test]
fn every_exception_has_a_reason_and_a_docroot_placeholder_where_it_names_a_script() {
    for (name, text) in profiles() {
        let c = Config::from_toml(&text).unwrap();
        for (i, e) in c.exceptions.iter().enumerate() {
            let r = e.reason.as_deref().unwrap_or("");
            assert!(r.len() >= 20, "{name} exceptions[{i}]: reason too short: {r:?}");
            if let Some(s) = &e.script {
                assert!(s.starts_with("/var/www/html/"), "{name} exceptions[{i}].script {s:?} must use the /var/www/html placeholder");
            }
        }
    }
}

#[test]
fn profiles_arm_nothing() {
    use howdah_core::sinks::SinkId;
    for (name, text) in profiles() {
        let c = Config::from_toml(&text).unwrap();
        assert_eq!(c.mode, Mode::Detect, "{name}: top-level mode");
        assert_ne!(c.inspect.effective_mode(c.mode), Mode::Block, "{name}: inspect");
        assert_ne!(c.behavior.effective_mode(c.mode), Mode::Block, "{name}: behavior");
        for s in [SinkId::CommandExec, SinkId::Include, SinkId::Eval, SinkId::Unserialize, SinkId::Phar, SinkId::Ssrf] {
            assert_ne!(c.sinks.effective_mode(s, c.mode), Mode::Block, "{name}: sink {s:?}");
        }
        for (r, m) in &c.rule_modes {
            assert_ne!(*m, Mode::Block, "{name}: [rules] {r:?}");
        }
        assert!(c.behavior.deny_exec_dirs.is_empty(), "{name}: deny_exec_dirs must stay a commented suggestion");
        assert!(!c.behavior.deny_php_writes, "{name}: deny_php_writes must stay a commented suggestion");
        assert!(!text.contains("mode = \"block\"") && !text.contains("mode=\"block\""), "{name}: a block mode in the text");
    }
}

#[test]
fn profiles_say_they_are_starting_points() {
    for (name, text) in profiles() {
        assert!(text.contains("STARTING POINT"), "{name}");
        assert!(text.contains("never applied automatically"), "{name}");
        assert!(text.contains("docs/exceptions.md"), "{name}");
    }
}

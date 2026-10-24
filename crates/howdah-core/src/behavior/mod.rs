//! Layer 4 (after a breach): pure classification of post-compromise behavior.
//!
//! Every function here is sandbox-pure: no filesystem access. All incoming
//! paths must already be absolute, resolved realpaths (the C extension
//! resolves them); matching is lexical on `/` boundaries. A hit's `detail`
//! names only a directory, host, or binary basename -- never an argument,
//! payload, or file content.

use crate::config::BehaviorConfig;
use crate::limits::RuleId;
use crate::sinks::ssrf::{decode_literal_ip, host_allowed};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BehaviorHit {
    pub rule: RuleId,
    pub detail: String,
}

/// Boundary-correct prefix test: `path` equals `dir` or lies beneath it.
/// Both must be absolute (relative or empty entries never match). Trailing
/// slashes on `dir` are ignored, so a bare `/` (or `//`) means "everything
/// under root". Inputs are trusted to be resolved; `..` is not interpreted
/// (paths are matched by their literal text).
pub fn path_under(path: &str, dir: &str) -> bool {
    if !dir.starts_with('/') || !path.starts_with('/') {
        return false;
    }
    let d = dir.trim_end_matches('/');
    if d.is_empty() {
        return true;
    }
    match path.strip_prefix(d) {
        Some(rest) => rest.is_empty() || rest.starts_with('/'),
        None => false,
    }
}

/// True for `.php`, `.php5`, `.phtml`, `.phar` (case-insensitive).
pub fn has_php_ext(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    match name.rfind('.') {
        Some(i) => {
            let ext = &name[i + 1..];
            ["php", "php5", "phtml", "phar"]
                .iter()
                .any(|e| ext.eq_ignore_ascii_case(e))
        }
        None => false,
    }
}

fn under_any<'a>(path: &str, dirs: &'a [String]) -> Option<&'a str> {
    dirs.iter()
        .map(String::as_str)
        .find(|d| path_under(path, d))
}

fn basename(p: &str) -> &str {
    p.rsplit('/').next().unwrap_or(p)
}

/// `UploadExec`: the executing script lives under a `deny_exec_dirs` entry.
pub fn exec_dir_hit(script_realpath: &str, cfg: &BehaviorConfig) -> Option<BehaviorHit> {
    under_any(script_realpath, &cfg.deny_exec_dirs).map(|d| BehaviorHit {
        rule: RuleId::UploadExec,
        detail: d.to_string(),
    })
}

/// Exec/egress facets are active when observing, when an allowlist is
/// configured, or when the caller runs from a denied-exec directory.
fn facet_active(caller: &str, allowlist: &[String], cfg: &BehaviorConfig) -> bool {
    cfg.observe || !allowlist.is_empty() || under_any(caller, &cfg.deny_exec_dirs).is_some()
}

/// `UnexpectedBinary`: active exec facet and the program not allow-listed.
///
/// PHP's exec family passes the WHOLE command line (program + arguments) as
/// one string, so matching and logging operate ONLY on the program TOKEN --
/// the first whitespace-delimited field. An allowlist entry matches the full
/// token (e.g. `/usr/bin/convert` or `convert`) or, for entries without a `/`,
/// the token's basename. `detail` is the token basename ALONE (e.g. `convert`,
/// `php`): argument values and paths beyond the first field are never logged.
pub fn binary_hit(
    caller_realpath: &str,
    program: &str,
    cfg: &BehaviorConfig,
) -> Option<BehaviorHit> {
    if !facet_active(caller_realpath, &cfg.allow_exec_binaries, cfg) {
        return None;
    }
    let token = program.split_whitespace().next().unwrap_or("");
    let base = basename(token);
    let allowed = cfg
        .allow_exec_binaries
        .iter()
        .any(|e| !e.is_empty() && (e == token || (!e.contains('/') && e == base)));
    if allowed {
        return None;
    }
    Some(BehaviorHit {
        rule: RuleId::UnexpectedBinary,
        detail: base.to_string(),
    })
}

/// `UnexpectedEgress`: active egress facet and `host` not allow-listed
/// (hostname, literal IP, or CIDR, via the ssrf matcher).
pub fn egress_hit(caller_realpath: &str, host: &str, cfg: &BehaviorConfig) -> Option<BehaviorHit> {
    if !facet_active(caller_realpath, &cfg.allow_egress_hosts, cfg) {
        return None;
    }
    let allowed = host_allowed(
        host.as_bytes(),
        &[],
        decode_literal_ip(host.as_bytes()),
        &cfg.allow_egress_hosts,
    );
    if allowed {
        return None;
    }
    Some(BehaviorHit {
        rule: RuleId::UnexpectedEgress,
        detail: host.to_string(),
    })
}

/// `PhpWrite`: write-mode open of a PHP-extension file, scoped to
/// `deny_exec_dirs` (target or caller under one). With no `deny_exec_dirs`
/// it scopes to nothing and never fires; the operator must name the
/// writable directories.
pub fn php_write_hit(
    caller_realpath: &str,
    target_path: &str,
    is_write_mode: bool,
    cfg: &BehaviorConfig,
) -> Option<BehaviorHit> {
    if !cfg.deny_php_writes || !is_write_mode || !has_php_ext(target_path) {
        return None;
    }
    let dir = under_any(target_path, &cfg.deny_exec_dirs)
        .or_else(|| under_any(caller_realpath, &cfg.deny_exec_dirs))?;
    Some(BehaviorHit {
        rule: RuleId::PhpWrite,
        detail: dir.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> BehaviorConfig {
        BehaviorConfig::default()
    }
    fn v(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn shell_under_uploads_is_upload_exec() {
        let mut c = cfg();
        c.deny_exec_dirs = v(&["/var/www/uploads"]);
        let h = exec_dir_hit("/var/www/uploads/a/shell.php", &c).unwrap();
        assert_eq!(h.rule, RuleId::UploadExec);
        assert_eq!(h.detail, "/var/www/uploads");
    }

    #[test]
    fn sibling_prefix_not_flagged() {
        let mut c = cfg();
        c.deny_exec_dirs = v(&["/var/www/uploads"]);
        assert!(exec_dir_hit("/var/www/uploadsX/a.php", &c).is_none());
        assert!(path_under("/var/www/uploads/x.php", "/var/www/uploads/"));
        assert!(!path_under("/var/www/uploadsX/x.php", "/var/www/uploads"));
        assert!(path_under("/var/www/uploads", "/var/www/uploads"));
    }

    #[test]
    fn bare_root_denies_all_without_misfire() {
        assert!(path_under("/anything/x.php", "/"));
        assert!(path_under("/anything/x.php", "//"));
        assert!(!path_under("relative/x.php", "/"));
        assert!(!path_under("/a/x.php", ""));
        assert!(!path_under("/a/x.php", "relative"));
    }

    #[test]
    fn binary_allowlist() {
        let mut c = cfg();
        c.allow_exec_binaries = v(&["gs", "/usr/bin/convert"]);
        let h = binary_hit("/var/www/app/i.php", "/usr/bin/xmrig", &c).unwrap();
        assert_eq!(h.rule, RuleId::UnexpectedBinary);
        assert_eq!(h.detail, "xmrig");
        assert!(binary_hit("/var/www/app/i.php", "/usr/bin/gs", &c).is_none());
        assert!(binary_hit("/var/www/app/i.php", "gs", &c).is_none());
        assert!(binary_hit("/var/www/app/i.php", "/usr/bin/convert", &c).is_none());
        assert!(binary_hit("/var/www/app/i.php", "/opt/convert", &c).is_some());
    }

    #[test]
    fn binary_command_with_args_matches_by_name_and_leaks_nothing() {
        let uploads = "/var/www/uploads/x.php";
        let mut c = cfg();
        c.allow_exec_binaries = v(&["convert"]);
        // Allowed by name even though arg1 carries the whole command line.
        assert!(binary_hit(uploads, "convert in.jpg /out/thumb.png", &c).is_none());
        // Empty allowlist but active via observe: fires, detail is basename only.
        let mut c2 = cfg();
        c2.observe = true;
        let h = binary_hit(uploads, "convert in.jpg /out/thumb.png", &c2).unwrap();
        assert_eq!(h.detail, "convert");
        assert!(!h.detail.contains("in.jpg"));
        assert!(!h.detail.contains("thumb.png"));
        assert!(!h.detail.contains("/out"));
    }

    #[test]
    fn binary_absolute_token_with_args_no_path_leak() {
        let uploads = "/var/www/uploads/x.php";
        let mut c = cfg();
        c.allow_exec_binaries = v(&["php"]);
        assert!(binary_hit(
            uploads,
            "/usr/bin/php /var/www/secret/cron-token-ABC.php",
            &c
        )
        .is_none());
        let mut c2 = cfg();
        c2.observe = true;
        let h = binary_hit(
            uploads,
            "/usr/bin/php /var/www/secret/cron-token-ABC.php",
            &c2,
        )
        .unwrap();
        assert_eq!(h.detail, "php");
        assert!(!h.detail.contains("cron-token-ABC"));
    }

    #[test]
    fn binary_inactive_facet_is_none() {
        assert!(binary_hit("/var/www/app/i.php", "xmrig", &cfg()).is_none());
        let mut c = cfg();
        c.observe = true;
        assert!(binary_hit("/var/www/app/i.php", "xmrig", &c).is_some());
        let mut c = cfg();
        c.deny_exec_dirs = v(&["/var/www/uploads"]);
        assert!(binary_hit("/var/www/uploads/s.php", "id", &c).is_some());
    }

    #[test]
    fn egress() {
        let mut c = cfg();
        c.allow_egress_hosts = v(&["api.example.com", "10.0.0.0/8"]);
        let h = egress_hit("/var/www/app/i.php", "evil.test", &c).unwrap();
        assert_eq!(h.rule, RuleId::UnexpectedEgress);
        assert_eq!(h.detail, "evil.test");
        assert!(egress_hit("/var/www/app/i.php", "api.example.com", &c).is_none());
        assert!(egress_hit("/var/www/app/i.php", "10.1.2.3", &c).is_none());
        assert!(egress_hit("/var/www/app/i.php", "8.8.8.8", &c).is_some());
        assert!(egress_hit("/x.php", "evil.test", &cfg()).is_none());
    }

    #[test]
    fn php_write_blade_guard_and_scoping() {
        let mut c = cfg();
        c.deny_php_writes = true;
        let caller = "/var/www/app/index.php";
        let blade = "/var/www/app/storage/framework/views/x.php";
        assert!(php_write_hit(caller, blade, true, &c).is_none());
        c.deny_exec_dirs = v(&["/var/www/uploads"]);
        assert!(php_write_hit(caller, blade, true, &c).is_none());
        let h = php_write_hit(caller, "/var/www/uploads/s.PHP", true, &c).unwrap();
        assert_eq!(h.rule, RuleId::PhpWrite);
        // Caller under a denied dir writing elsewhere also fires.
        assert!(php_write_hit("/var/www/uploads/s.php", blade, true, &c).is_some());
        // Non-PHP extension ignored.
        assert!(php_write_hit(caller, "/var/www/uploads/a.txt", true, &c).is_none());
        // Disabled flag.
        c.deny_php_writes = false;
        assert!(php_write_hit(caller, "/var/www/uploads/s.php", true, &c).is_none());
    }

    #[test]
    fn php_write_read_ignored() {
        let mut c = cfg();
        c.deny_php_writes = true;
        c.deny_exec_dirs = v(&["/var/www/app"]);
        assert!(
            php_write_hit("/var/www/app/i.php", "/var/www/app/config.php", false, &c).is_none()
        );
    }

    #[test]
    fn php_ext_variants() {
        for p in ["/a/x.php", "/a/x.PHP5", "/a/x.phtml", "/a/x.PhAr"] {
            assert!(has_php_ext(p), "{p}");
        }
        for p in ["/a/x.txt", "/a.php/x", "/a/php", "/a/x.php.bak"] {
            assert!(!has_php_ext(p), "{p}");
        }
    }
}

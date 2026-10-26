//! Layer 4 (after a breach): pure classification of post-compromise behavior.
//!
//! Every function here is sandbox-pure: no filesystem access. All incoming
//! paths must already be absolute, resolved realpaths (the C extension
//! resolves them); matching is lexical on `/` boundaries. A hit's `detail`
//! names only a directory, host, or binary basename -- never an argument,
//! payload, or file content.
//!
//! The T5 file guards (`delete_hit`, `secret_read_hit`, and the upload tier of
//! `php_write_hit`) classify the path argument the PHP call was given,
//! lexically (`..` and `.` collapsed, no filesystem access). A hit's `detail`
//! carries only a path CATEGORY (`wp-config`, `dotenv`, `private-key`,
//! `htaccess`, ...), the guarded function name and the calling script's
//! `file:line` -- never the target path or any content.

use crate::config::{BehaviorConfig, Mode};
use crate::limits::RuleId;
use crate::sinks::ssrf::{decode_literal_ip, host_allowed};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BehaviorHit {
    pub rule: RuleId,
    pub detail: String,
    /// The mode that applies to THIS hit: `Some` for the guards that carry
    /// their own mode (`delete_guard`, `upload_write`, `secret_read`), `None`
    /// for the facets that follow the section `mode`.
    pub mode: Option<Mode>,
}

/// The PHP call site a file-guard event is attributed to: the executing
/// script (`zend_get_executed_filename`) and the line of the call. Empty
/// `file` means unknown (no active script).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Origin<'a> {
    pub file: &'a str,
    pub line: u32,
}

impl Origin<'_> {
    /// ` at <file>:<line>` (or ` at <file>` without a line, or empty).
    fn suffix(&self) -> String {
        if self.file.is_empty() {
            String::new()
        } else if self.line == 0 {
            format!(" at {}", self.file)
        } else {
            format!(" at {}:{}", self.file, self.line)
        }
    }
}

/// How a write sink reaches the disk (the `is_write_mode` code the glue passes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteOp {
    /// A read-mode open: never a write finding.
    Read,
    /// A write from `file_put_contents`, `fopen` (write mode), `rename`, `copy`.
    Write,
    /// `move_uploaded_file`: the file came in through an HTTP upload.
    Upload,
}

impl WriteOp {
    /// `0` read, `2` upload move, any other non-zero value a plain write.
    pub fn from_code(code: i32) -> WriteOp {
        match code {
            0 => WriteOp::Read,
            2 => WriteOp::Upload,
            _ => WriteOp::Write,
        }
    }
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

fn ci_eq(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

fn ci_starts(a: &str, prefix: &str) -> bool {
    a.len() >= prefix.len() && a.as_bytes()[..prefix.len()].eq_ignore_ascii_case(prefix.as_bytes())
}

fn ci_contains(hay: &str, needle: &str) -> bool {
    let (h, n) = (hay.as_bytes(), needle.as_bytes());
    n.is_empty() || h.windows(n.len()).any(|w| w.eq_ignore_ascii_case(n))
}

/// Category of a file name a write sink must not create from PHP: an
/// executable extension or the handler-config set that re-enables one (the
/// durable upload bypass: an uploaded `.htaccess` / `.user.ini` makes the next
/// `.jpg` run as PHP). Returns a LABEL (never the name): `php` (`.php`,
/// `.php3`..`.php8`), `phtml` (`.phtml`, `.pht`), `phar`, `include` (`.inc`),
/// `htaccess`, `user-ini`, `web-config`. Case-insensitive, last extension only.
/// `resource=<name>` (the tail of a `php://filter` write target) is read as
/// `<name>`.
pub fn dangerous_write_kind(path: &str) -> Option<&'static str> {
    let name = basename(path.trim_end_matches('/'));
    let name = name.rsplit('=').next().unwrap_or(name);
    if ci_eq(name, ".htaccess") {
        return Some("htaccess");
    }
    if ci_eq(name, ".user.ini") {
        return Some("user-ini");
    }
    if ci_eq(name, "web.config") {
        return Some("web-config");
    }
    let ext = &name[name.rfind('.')? + 1..];
    let is = |list: &[&str]| list.iter().any(|e| ext.eq_ignore_ascii_case(e));
    if is(&["php", "php3", "php4", "php5", "php7", "php8"]) {
        Some("php")
    } else if is(&["phtml", "pht"]) {
        Some("phtml")
    } else if is(&["phar"]) {
        Some("phar")
    } else if is(&["inc"]) {
        Some("include")
    } else {
        None
    }
}

/// A local path from a PHP path argument: a `file://` URL loses its scheme;
/// any other `scheme://` is a stream wrapper (not a local file) and yields
/// `None`. Plain paths are returned as is.
fn local_path(t: &str) -> Option<&str> {
    if ci_starts(t, "file://") {
        return Some(&t[7..]);
    }
    if let Some(i) = t.find("://") {
        let scheme = &t[..i];
        if !scheme.is_empty()
            && scheme.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
        {
            return None;
        }
    }
    Some(t)
}

/// Lexical normalization: collapse `//`, `.` and `..` without touching the
/// filesystem. Returns the normalized path and whether the input had a `..`
/// segment. An absolute path stays absolute (`..` at the root is dropped); a
/// relative one keeps leading `..`.
fn lexical(path: &str) -> (String, bool) {
    let abs = path.starts_with('/');
    let mut stack: Vec<&str> = Vec::new();
    let mut dotdot = false;
    for seg in path.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                dotdot = true;
                match stack.last() {
                    Some(&l) if l != ".." => {
                        stack.pop();
                    }
                    _ => {
                        if !abs {
                            stack.push("..");
                        }
                    }
                }
            }
            s => stack.push(s),
        }
    }
    let joined = stack.join("/");
    (if abs { format!("/{joined}") } else { joined }, dotdot)
}

/// Directories PHP never legitimately deletes from (a `..` traversal that
/// lands here is an arbitrary-file-delete attempt). `/var`, `/tmp`, `/dev`
/// (shm caches) and `/opt` are deliberately absent: real apps delete there.
const DELETE_SYSTEM_DIRS: [&str; 11] = [
    "/etc", "/root", "/proc", "/sys", "/boot", "/bin", "/sbin", "/usr", "/lib", "/lib32", "/lib64",
];

/// Directories whose contents are secret to read via a `..` traversal.
const READ_SYSTEM_DIRS: [&str; 5] = ["/etc", "/root", "/proc", "/sys", "/var/log"];

/// Category of a secret/config file name -- the set the delete, rename-away
/// and secret-read guards share. Tight on purpose (a false block on a delete
/// is worse than a miss): `wp-config` (`wp-config.php`), `dotenv` (`.env`,
/// `.env.<name>` except templates `.example`/`.sample`/`.dist`/`.template`),
/// `private-key` (`id_rsa`/`id_dsa`/`id_ecdsa`/`id_ed25519`; a `.pem` whose
/// name says private/secret; a `.key` named private/privkey/server/ssl/tls/
/// oauth-private). `.key` alone is NOT enough: Keynote files end in `.key`.
pub fn secret_kind(base: &str) -> Option<&'static str> {
    if ci_eq(base, "wp-config.php") {
        return Some("wp-config");
    }
    if ci_eq(base, ".env") {
        return Some("dotenv");
    }
    if ci_starts(base, ".env.") {
        let ext = base.rsplit('.').next().unwrap_or("");
        let template = ["example", "sample", "dist", "template"].iter().any(|t| ext.eq_ignore_ascii_case(t));
        return if template { None } else { Some("dotenv") };
    }
    if ["id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"].iter().any(|n| ci_eq(base, n)) {
        return Some("private-key");
    }
    let dot = base.rfind('.')?;
    let (stem, ext) = (&base[..dot], &base[dot + 1..]);
    if ext.eq_ignore_ascii_case("pem")
        && ["private", "privkey", "secret"].iter().any(|w| ci_contains(stem, w))
    {
        return Some("private-key");
    }
    if ext.eq_ignore_ascii_case("key")
        && ["private", "privkey", "server", "ssl", "tls", "oauth-private"]
            .iter()
            .any(|w| ci_eq(stem, w))
    {
        return Some("private-key");
    }
    None
}

/// The live-config subset used for a `rename` SOURCE: moving `wp-config.php`
/// or `.env` away resets the app exactly like deleting it, but renaming
/// `.env.production` -> `.env` is an ordinary deploy step, so only the two
/// live files count.
fn live_config_kind(base: &str) -> Option<&'static str> {
    if ci_eq(base, "wp-config.php") {
        Some("wp-config")
    } else if ci_eq(base, ".env") {
        Some("dotenv")
    } else {
        None
    }
}

/// Extra categories only the READ guard flags (observe-first, so broader).
fn read_extra_kind(norm: &str, base: &str) -> Option<&'static str> {
    if ci_eq(base, ".htpasswd") {
        return Some("htpasswd");
    }
    if ["/etc/passwd", "/etc/shadow", "/etc/gshadow", "/etc/master.passwd", "/etc/sudoers"]
        .iter()
        .any(|p| ci_eq(norm, p))
    {
        return Some("system-account");
    }
    if norm.split('/').any(|s| s == ".ssh") {
        return Some("ssh");
    }
    if [".pgpass", ".my.cnf", ".netrc"].iter().any(|n| ci_eq(base, n)) {
        return Some("credentials");
    }
    None
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
        mode: None,
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
        mode: None,
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
        mode: None,
    })
}

/// `PhpWrite`: a write of an executable or handler-config file name (see
/// [`dangerous_write_kind`]). Two tiers share the rule id:
///
/// * **Upload tier** (`[behavior] upload_write`, enforced by default, needs no
///   `deny_exec_dirs`): `move_uploaded_file` into a PHP-executable name or a
///   handler-config name (`.htaccess`, `.user.ini`, `web.config`). Nothing
///   legitimate moves an HTTP upload to such a name, so it is safe to enforce
///   everywhere. `.inc` is excluded here (it is only a scoped-tier name).
/// * **Scoped tier** (`deny_php_writes = true`, opt-in): ANY write sink
///   (`file_put_contents`, write-mode `fopen`, `rename`, `copy`,
///   `move_uploaded_file`) creating such a name under `deny_exec_dirs` (target
///   or caller under one). With no `deny_exec_dirs` it scopes to nothing and
///   never fires; the operator must name the writable directories. Apps that
///   legitimately write `.php` (Blade/Twig caches, WordPress updates) or
///   `.htaccess` (permalinks) are why this tier is not global.
///
/// `detail` is a category and the call site, never the target.
pub fn php_write_hit(
    origin: Origin<'_>,
    target_path: &str,
    op: WriteOp,
    cfg: &BehaviorConfig,
) -> Option<BehaviorHit> {
    if op == WriteOp::Read {
        return None;
    }
    let kind = dangerous_write_kind(target_path)?;
    if op == WriteOp::Upload && cfg.upload_write != Mode::Off && kind != "include" {
        return Some(BehaviorHit {
            rule: RuleId::PhpWrite,
            detail: format!("upload moved to a {kind} file name{}", origin.suffix()),
            mode: Some(cfg.upload_write),
        });
    }
    if !cfg.deny_php_writes {
        return None;
    }
    let dir = under_any(target_path, &cfg.deny_exec_dirs)
        .or_else(|| under_any(origin.file, &cfg.deny_exec_dirs))?;
    Some(BehaviorHit {
        rule: RuleId::PhpWrite,
        detail: format!("{dir}: {kind} file written{}", origin.suffix()),
        mode: None,
    })
}

/// `FileDelete`: `func` (`unlink`, `rmdir`, or `rename` with `is_move` for the
/// SOURCE operand) was given a sensitive target: a secret/config file by name
/// ([`secret_kind`]; just the live `wp-config.php`/`.env` for a rename source)
/// or a `..` traversal that lands in a system directory. Gated by
/// `[behavior] delete_guard`. The name test runs on the lexically normalized
/// path, so `uploads/../wp-config.php` is caught; `/tmp/php123`, cache, session
/// and upload files are not on any list. `detail` is a category and the call
/// site, never the path.
pub fn delete_hit(
    origin: Origin<'_>,
    func: &str,
    target: &str,
    is_move: bool,
    cfg: &BehaviorConfig,
) -> Option<BehaviorHit> {
    if cfg.delete_guard == Mode::Off {
        return None;
    }
    let t = local_path(target)?;
    let verb = if is_move { "moves away" } else { "deletes" };
    let name_kind = |base: &str| if is_move { live_config_kind(base) } else { secret_kind(base) };
    let detail = if !(t.contains("..") || t.contains("/./") || t.ends_with("/.") || t == ".") {
        // Hot path (a plain unlink of a cache/temp/upload file): without a `.`
        // or `..` segment the path is already normal, so the name test on the
        // raw basename is exact and there is no traversal. No allocation.
        let k = name_kind(basename(t.trim_end_matches('/')))?;
        format!("{func} {verb} a {k} file{}", origin.suffix())
    } else {
        let (norm, dotdot) = lexical(t);
        if let Some(k) = name_kind(basename(&norm)) {
            format!("{func} {verb} a {k} file{}", origin.suffix())
        } else if dotdot && !is_move && DELETE_SYSTEM_DIRS.iter().any(|d| path_under(&norm, d)) {
            format!("{func} reaches a system directory through a '..' traversal{}", origin.suffix())
        } else {
            return None;
        }
    };
    Some(BehaviorHit { rule: RuleId::FileDelete, detail, mode: Some(cfg.delete_guard) })
}

/// `SecretRead`: a read-open (`file_get_contents`, `readfile`, `file`, `fopen` in
/// read mode) of secret material: [`secret_kind`] names, the read-only extras
/// (`.htpasswd`, `/etc/passwd`-class files, `.ssh`, DB/netrc credential
/// files) or a `..` traversal into a system directory. Gated by
/// `[behavior] secret_read` (off by default: apps read their own config).
pub fn secret_read_hit(
    origin: Origin<'_>,
    func: &str,
    target: &str,
    cfg: &BehaviorConfig,
) -> Option<BehaviorHit> {
    if cfg.secret_read == Mode::Off {
        return None;
    }
    let (norm, dotdot) = lexical(local_path(target)?);
    let base = basename(&norm);
    let detail = if let Some(k) = secret_kind(base).or_else(|| read_extra_kind(&norm, base)) {
        format!("{func} reads a {k} file{}", origin.suffix())
    } else if dotdot && READ_SYSTEM_DIRS.iter().any(|d| path_under(&norm, d)) {
        format!("{func} reaches a system directory through a '..' traversal{}", origin.suffix())
    } else {
        return None;
    };
    Some(BehaviorHit { rule: RuleId::SecretRead, detail, mode: Some(cfg.secret_read) })
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

    fn o(file: &str) -> Origin<'_> {
        Origin { file, line: 7 }
    }

    #[test]
    fn php_write_blade_guard_and_scoping() {
        let mut c = cfg();
        c.deny_php_writes = true;
        let caller = "/var/www/app/index.php";
        let blade = "/var/www/app/storage/framework/views/x.php";
        let w = WriteOp::Write;
        assert!(php_write_hit(o(caller), blade, w, &c).is_none());
        c.deny_exec_dirs = v(&["/var/www/uploads"]);
        assert!(php_write_hit(o(caller), blade, w, &c).is_none());
        let h = php_write_hit(o(caller), "/var/www/uploads/s.PHP", w, &c).unwrap();
        assert_eq!(h.rule, RuleId::PhpWrite);
        assert_eq!(h.mode, None); // the scoped tier follows the section mode
        assert!(h.detail.starts_with("/var/www/uploads: php file written at /var/www/app/index.php:7"));
        // Caller under a denied dir writing elsewhere also fires.
        assert!(php_write_hit(o("/var/www/uploads/s.php"), blade, w, &c).is_some());
        // Non-dangerous extensions ignored.
        for ok in ["a.txt", "a.json", "a.log", "a.jpg", "a.php.bak", "a.html"] {
            let t = format!("/var/www/uploads/{ok}");
            assert!(php_write_hit(o(caller), &t, w, &c).is_none(), "{ok}");
        }
        // Disabled flag.
        c.deny_php_writes = false;
        assert!(php_write_hit(o(caller), "/var/www/uploads/s.php", w, &c).is_none());
    }

    #[test]
    fn php_write_read_ignored() {
        let mut c = cfg();
        c.deny_php_writes = true;
        c.deny_exec_dirs = v(&["/var/www/app"]);
        assert!(php_write_hit(
            o("/var/www/app/i.php"),
            "/var/www/app/config.php",
            WriteOp::Read,
            &c
        )
        .is_none());
        assert!(php_write_hit(
            o("/var/www/app/i.php"),
            "/var/www/app/.htaccess",
            WriteOp::Read,
            &c
        )
        .is_none());
    }

    #[test]
    fn scoped_tier_covers_the_full_set() {
        let mut c = cfg();
        c.deny_php_writes = true;
        c.deny_exec_dirs = v(&["/var/www/uploads"]);
        let caller = "/var/www/app/i.php";
        for (name, kind) in [
            ("s.php", "php"),
            ("s.php3", "php"),
            ("s.PHP4", "php"),
            ("s.php5", "php"),
            ("s.php7", "php"),
            ("s.phtml", "phtml"),
            ("s.pht", "phtml"),
            ("s.phar", "phar"),
            ("s.inc", "include"),
            (".htaccess", "htaccess"),
            (".HTACCESS", "htaccess"),
            (".user.ini", "user-ini"),
            ("web.config", "web-config"),
        ] {
            let t = format!("/var/www/uploads/sub/{name}");
            let h = php_write_hit(o(caller), &t, WriteOp::Write, &c)
                .unwrap_or_else(|| panic!("{name} not flagged"));
            assert!(h.detail.contains(&format!("{kind} file written")), "{name}: {}", h.detail);
            assert!(!h.detail.contains(name), "target name leaked: {}", h.detail);
        }
        // php://filter write wrapper hides the real name behind resource=.
        assert!(php_write_hit(
            o("/var/www/uploads/x.php"),
            "php://filter/write=string.rot13/resource=s.php",
            WriteOp::Write,
            &c
        )
        .is_some());
    }

    #[test]
    fn upload_tier_is_on_without_any_config_and_is_tight() {
        let c = cfg(); // deny_php_writes off, no deny_exec_dirs: nothing scoped
        let caller = "/var/www/app/upload.php";
        for name in ["s.php", "s.phtml", "s.pht", "s.php5", "s.php7", "s.phar", ".htaccess", ".user.ini", "web.config", "S.PHP"] {
            let t = format!("/var/www/app/files/{name}");
            let h = php_write_hit(o(caller), &t, WriteOp::Upload, &c)
                .unwrap_or_else(|| panic!("upload to {name} not flagged"));
            assert_eq!(h.rule, RuleId::PhpWrite);
            assert_eq!(h.mode, Some(Mode::Block), "{name}");
            assert!(h.detail.starts_with("upload moved to a "), "{}", h.detail);
            assert!(h.detail.ends_with("at /var/www/app/upload.php:7"), "{}", h.detail);
            assert!(!h.detail.contains("files"), "target leaked: {}", h.detail);
        }
        // Benign uploads: documents, media, archives, data files, .inc.
        for name in ["a.txt", "a.json", "a.log", "a.jpg", "a.png", "a.pdf", "a.zip", "a.csv", "a.inc", "a.php.jpg", "photo", "htaccess", "user.ini", "my.config"] {
            let t = format!("/var/www/app/files/{name}");
            assert!(php_write_hit(o(caller), &t, WriteOp::Upload, &c).is_none(), "{name} wrongly flagged");
        }
        // The same names via a plain write sink: NOT flagged without the scoped tier.
        for name in ["s.php", ".htaccess", ".user.ini"] {
            let t = format!("/var/www/app/files/{name}");
            assert!(php_write_hit(o(caller), &t, WriteOp::Write, &c).is_none(), "{name}");
        }
        // Switchable: off silences it; detect carries detect.
        let mut off = cfg();
        off.upload_write = Mode::Off;
        assert!(php_write_hit(o(caller), "/x/s.php", WriteOp::Upload, &off).is_none());
        let mut det = cfg();
        det.upload_write = Mode::Detect;
        assert_eq!(php_write_hit(o(caller), "/x/s.php", WriteOp::Upload, &det).unwrap().mode, Some(Mode::Detect));
        // With the scoped tier on, an upload of .inc under a denied dir is still flagged.
        let mut sc = cfg();
        sc.deny_php_writes = true;
        sc.deny_exec_dirs = v(&["/x"]);
        assert!(php_write_hit(o(caller), "/x/s.inc", WriteOp::Upload, &sc).is_some());
    }

    #[test]
    fn write_op_codes() {
        assert_eq!(WriteOp::from_code(0), WriteOp::Read);
        assert_eq!(WriteOp::from_code(1), WriteOp::Write);
        assert_eq!(WriteOp::from_code(2), WriteOp::Upload);
        assert_eq!(WriteOp::from_code(7), WriteOp::Write);
    }

    fn del(func: &str, t: &str) -> Option<BehaviorHit> {
        delete_hit(o("/var/www/html/wp-content/plugins/x/x.php"), func, t, false, &cfg())
    }

    #[test]
    fn delete_guard_blocks_sensitive_and_traversal() {
        for t in [
            "/var/www/html/wp-config.php",
            "wp-config.php",
            "../wp-config.php",
            "/var/www/html/uploads/../wp-config.php",
            "/var/www/html/WP-CONFIG.PHP",
            "/var/www/./html/wp-config.php",
            "/var/www/html/wp-config.php/.",
            "/var/www/html//wp-config.php",
            "file:///var/www/html/wp-config.php",
            "/var/www/html/.env",
            ".env",
            "/srv/app/.env.local",
            "/srv/app/.env.production",
            "/srv/app/.env.testing",
            "/home/u/.ssh/id_rsa",
            "/etc/ssl/private/server.key",
            "/etc/ssl/private/privkey.pem",
            "/srv/app/storage/oauth-private.key",
            "/var/www/html/uploads/../../../../etc/passwd",
            "/var/www/html/uploads/../../../../root/.bashrc",
            "/var/www/html/uploads/../../../../../usr/lib/x.so",
        ] {
            let h = del("unlink", t).unwrap_or_else(|| panic!("{t} not flagged"));
            assert_eq!(h.rule, RuleId::FileDelete, "{t}");
            assert_eq!(h.mode, Some(Mode::Block), "{t}");
            assert!(h.detail.contains("unlink"), "{}", h.detail);
            assert!(h.detail.ends_with("at /var/www/html/wp-content/plugins/x/x.php:7"), "{}", h.detail);
            // Never the target path or file name.
            assert!(!h.detail.contains("wp-config.php"), "{}", h.detail);
            assert!(!h.detail.contains(".env"), "{}", h.detail);
            assert!(!h.detail.contains("/etc"), "{}", h.detail);
        }
        // Categories are named.
        assert!(del("unlink", "/a/wp-config.php").unwrap().detail.contains("a wp-config file"));
        assert!(del("unlink", "/a/.env").unwrap().detail.contains("a dotenv file"));
        assert!(del("unlink", "/a/id_ed25519").unwrap().detail.contains("a private-key file"));
        assert!(del("rmdir", "/a/../../etc/cron.d").unwrap().detail.contains("system directory"));
    }

    #[test]
    fn delete_guard_zero_benign_fp() {
        // The ordinary things web apps delete: cache, temp, sessions, uploads,
        // logs, compiled templates, lock files, thumbnails, backups, dirs.
        for t in [
            "/tmp/php8Hk2Jd",
            "/tmp/phpUpload123",
            "/var/lib/php/sessions/sess_abc123",
            "/var/www/html/wp-content/cache/page/index.html",
            "/var/www/html/wp-content/uploads/2026/10/photo.jpg",
            "/var/www/html/wp-content/uploads/2026/10/photo-150x150.jpg",
            "/var/www/html/wp-content/uploads/report.pdf",
            "/var/www/html/wp-content/upgrade/plugin-tmp/x.php",
            "/var/www/html/wp-content/debug.log",
            "/var/www/html/.maintenance",
            "/var/www/app/storage/framework/views/abc.php",
            "/var/www/app/storage/framework/cache/data/ab/cd/abcdef",
            "/var/www/app/storage/logs/laravel-2026-10-26.log",
            "/var/www/app/bootstrap/cache/services.php",
            "/var/www/html/wp-config-sample.php",
            "/var/www/app/.env.example",
            "/var/www/app/.env.sample",
            "/var/www/app/.env.dist",
            "/var/www/app/environment.php",
            "/var/www/app/env",
            "/var/www/app/myenv.txt",
            "/var/www/app/config.php",
            "/var/www/app/composer.json",
            "/var/www/html/.htaccess",
            "/var/www/uploads/presentation.key",
            "/var/www/uploads/Private Equity Deck.key",
            "/var/www/uploads/cacert.pem",
            "/var/www/uploads/cert.pem",
            "/var/www/uploads/identity.pem",
            "/var/www/uploads/upload.pfx",
            "/var/www/uploads/id_rsa.pub",
            "/var/www/uploads/privacy-policy.pdf",
            "/var/cache/app/../tmp/x",
            "/var/www/shared/../releases/12/cache/x",
            "/var/www/html/wp-content/uploads/../cache/x.tmp",
            "/var/www/app/../app/cache/x",
            "/dev/shm/apc-x",
            "/opt/app/cache/x",
            "relative/dir/file.tmp",
            "cache/../cache/x",
            "../shared/cache/x",
            "/var/www/html/wp-content/uploads/.",
            "",
            "/",
            "ftp://host/wp-config.php",
            "phar:///x/y.phar/.env",
            "data://text/plain,wp-config.php",
            "php://temp",
            "/tmp/a/wp-config.php.bak",
            "/tmp/a/.env.bak.old/x",
        ] {
            assert!(del("unlink", t).is_none(), "benign delete wrongly flagged: {t:?}");
            assert!(del("rmdir", t).is_none(), "benign rmdir wrongly flagged: {t:?}");
        }
        // Direct (non-traversal) absolute system paths are not this guard's job.
        assert!(del("unlink", "/etc/cron.d/x").is_none());
        assert!(del("unlink", "/usr/local/x").is_none());
    }

    #[test]
    fn delete_guard_modes_and_rename_source() {
        let src = o("/var/www/html/x.php");
        let mut c = cfg();
        // rename SOURCE: just the live files; deploy-step renames are fine.
        assert!(delete_hit(src, "rename", "/a/wp-config.php", true, &c).is_some());
        assert!(delete_hit(src, "rename", "/a/.env", true, &c).is_some());
        let h = delete_hit(src, "rename", "/a/.env", true, &c).unwrap();
        assert!(h.detail.contains("rename moves away a dotenv file"), "{}", h.detail);
        assert!(delete_hit(src, "rename", "/a/.env.production", true, &c).is_none());
        assert!(delete_hit(src, "rename", "/a/.env.example", true, &c).is_none());
        assert!(delete_hit(src, "rename", "/a/uploads/../../../etc/x", true, &c).is_none());
        assert!(delete_hit(src, "rename", "/a/cache/x.tmp", true, &c).is_none());
        c.delete_guard = Mode::Off;
        assert!(delete_hit(src, "unlink", "/a/wp-config.php", false, &c).is_none());
        c.delete_guard = Mode::Detect;
        assert_eq!(delete_hit(src, "unlink", "/a/wp-config.php", false, &c).unwrap().mode, Some(Mode::Detect));
        // No origin known: still a category line, no " at ".
        let h = delete_hit(Origin::default(), "unlink", "/a/.env", false, &cfg()).unwrap();
        assert!(!h.detail.contains(" at "), "{}", h.detail);
    }

    fn rd(t: &str) -> Option<BehaviorHit> {
        let mut c = cfg();
        c.secret_read = Mode::Detect;
        secret_read_hit(o("/var/www/html/app.php"), "file_get_contents", t, &c)
    }

    #[test]
    fn secret_read_flags_secrets_but_is_off_by_default() {
        for (t, kind) in [
            ("/var/www/html/.env", "dotenv"),
            (".env.local", "dotenv"),
            ("/var/www/html/wp-config.php", "wp-config"),
            ("/home/u/.ssh/id_rsa", "private-key"),
            ("/etc/ssl/private/server.key", "private-key"),
            ("/var/www/.htpasswd", "htpasswd"),
            ("/etc/passwd", "system-account"),
            ("/etc/shadow", "system-account"),
            ("/home/u/.ssh/authorized_keys", "ssh"),
            ("/home/u/.my.cnf", "credentials"),
            ("file:///var/www/html/.env", "dotenv"),
        ] {
            let h = rd(t).unwrap_or_else(|| panic!("{t} not flagged"));
            assert_eq!(h.rule, RuleId::SecretRead);
            assert_eq!(h.mode, Some(Mode::Detect));
            assert!(h.detail.contains(&format!("reads a {kind} file")), "{t}: {}", h.detail);
            assert!(h.detail.ends_with("at /var/www/html/app.php:7"), "{}", h.detail);
        }
        // Traversal out of a content dir into a system dir.
        let h = rd("/var/www/html/uploads/../../../../etc/hostname").unwrap();
        assert!(h.detail.contains("system directory"), "{}", h.detail);
        assert!(rd("/var/www/html/../../../../var/log/auth.log").is_some());
        // Off by default: no hit at all.
        assert!(secret_read_hit(o("/x.php"), "readfile", "/var/www/html/.env", &cfg()).is_none());
        // Ordinary reads are untouched.
        for t in [
            "/var/www/html/index.php",
            "/var/www/html/wp-content/themes/x/style.css",
            "/var/www/app/config/app.php",
            "/var/www/app/.env.example",
            "/etc/hosts",
            "/etc/mime.types",
            "/proc/cpuinfo",
            "/proc/meminfo",
            "/var/www/app/../vendor/autoload.php",
            "/var/www/app/data/../data/x.json",
            "relative/x.txt",
            "../vendor/autoload.php",
            "https://example.com/.env",
            "php://input",
            "php://stdin",
            "/var/www/html/uploads/cacert.pem",
            "",
        ] {
            assert!(rd(t).is_none(), "benign read wrongly flagged: {t:?}");
        }
    }

    #[test]
    fn path_helpers() {
        assert_eq!(lexical("/a/b/../c/./d//e"), ("/a/c/d/e".to_string(), true));
        assert_eq!(lexical("/../../x"), ("/x".to_string(), true));
        assert_eq!(lexical("../../x"), ("../../x".to_string(), true));
        assert_eq!(lexical("a/b"), ("a/b".to_string(), false));
        assert_eq!(lexical("/"), ("/".to_string(), false));
        assert_eq!(local_path("file:///etc/x"), Some("/etc/x"));
        assert_eq!(local_path("FILE:///etc/x"), Some("/etc/x"));
        assert_eq!(local_path("/plain/path"), Some("/plain/path"));
        assert_eq!(local_path("rel:name/x"), Some("rel:name/x"));
        assert_eq!(local_path("php://temp"), None);
        assert_eq!(local_path("http://h/x"), None);
        assert_eq!(dangerous_write_kind("/a/b/"), None);
        assert_eq!(secret_kind(".env.example"), None);
        assert_eq!(secret_kind(".ENV.PROD"), Some("dotenv"));
    }

    #[test]
    fn dangerous_write_kind_variants() {
        assert_eq!(dangerous_write_kind("/a/x.php"), Some("php"));
        assert_eq!(dangerous_write_kind("/a/x.PhAr"), Some("phar"));
        assert_eq!(dangerous_write_kind("/a/x.Pht"), Some("phtml"));
        assert_eq!(dangerous_write_kind("/a/x.php8"), Some("php"));
        assert_eq!(dangerous_write_kind("/a/.User.Ini"), Some("user-ini"));
        assert_eq!(dangerous_write_kind("/a/x.txt"), None);
        assert_eq!(dangerous_write_kind("/a/x.php.bak"), None);
        assert_eq!(dangerous_write_kind("/a/x.json"), None);
        assert_eq!(dangerous_write_kind("/a/x.log"), None);
        assert_eq!(dangerous_write_kind("/a.php/x"), None);
        assert_eq!(dangerous_write_kind("/a/.htaccess/"), Some("htaccess"));
        assert_eq!(dangerous_write_kind("php://filter/write=convert.base64-decode/resource=.htaccess"), Some("htaccess"));
        assert_eq!(dangerous_write_kind("php://memory"), None);
        assert_eq!(dangerous_write_kind(""), None);
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

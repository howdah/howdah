//! Include/open wrapper-scheme firewall: pure, hand-written, linear-time.
//!
//! No regex, no backtracking, no filesystem access (wasm-safe like the rest of
//! the core). Two independent predicates:
//!
//!   * [`classify_scheme`] labels the stream-wrapper scheme of an include/open
//!     TARGET (the fully resolved string the in-process hook sees, after
//!     concatenation / variables / decoding). `file://` and a plain path are
//!     local; `phar://` is left to the phar sink; everything else is a
//!     non-file wrapper. The include policy ([`SchemeClass::blocks_include`])
//!     refuses every non-file, non-phar wrapper (including a wrapper is never
//!     legitimate). The open policy ([`SchemeClass::blocks_open`]) refuses only
//!     the near-zero-benign-use wrappers (`php://filter`, `data:`, `expect://`),
//!     so a legitimate `file_get_contents('php://input')`, `fopen('php://temp')`
//!     or a remote fetch (left to the SSRF sink) is never a false positive.
//!
//!   * [`classify_poison`] flags a poisonable LOCAL target: `/proc/self/environ`
//!     and other `/proc/*`, a file under the runtime `session.save_path`, and
//!     PHP's configured `error_log` — the classic LFI->RCE log/session/proc
//!     poisoning sinks. Kept deliberately TIGHT (anchored at the effective root,
//!     exact `error_log` match) so a benign relative template include or an
//!     absolute app path never matches.
//!
//! Only a scheme/category LABEL is ever surfaced for logging; the target
//! content (which carries user data) is not.

/// The wrapper-scheme class of an include/open target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchemeClass {
    /// No scheme, or `file://`: a local filesystem path. Allowed everywhere.
    Local,
    /// `phar://`: handled by the phar sink; this firewall ignores it.
    Phar,
    /// `php://filter...`: the LFI->RCE filter-chain primitive.
    PhpFilter,
    /// `php://input`: the include-the-request-body RCE vector.
    PhpInput,
    /// Any other `php://` wrapper (temp, memory, output, stdin, fd, ...).
    PhpOther,
    /// `data:` / `data://` inline data (RFC 2397).
    Data,
    /// `expect://` command execution.
    Expect,
    /// Remote `http://` / `https://`.
    Http,
    /// Remote `ftp://` / `ftps://`.
    Ftp,
    /// Any other scheme (`zip://`, `compress.*://`, `glob://`, ...).
    Other,
}

impl SchemeClass {
    /// A short, privacy-preserving label for the log `reason` (never the target).
    pub fn as_label(&self) -> &'static str {
        match self {
            SchemeClass::Local => "file://",
            SchemeClass::Phar => "phar://",
            SchemeClass::PhpFilter => "php://filter",
            SchemeClass::PhpInput => "php://input",
            SchemeClass::PhpOther => "php://*",
            SchemeClass::Data => "data://",
            SchemeClass::Expect => "expect://",
            SchemeClass::Http => "http(s)://",
            SchemeClass::Ftp => "ftp(s)://",
            SchemeClass::Other => "wrapper://",
        }
    }

    /// True iff `include`/`require` must refuse this target: any non-file,
    /// non-phar wrapper. Including a stream wrapper is never legitimate, so the
    /// whole set is refused (phar stays with the phar sink).
    pub fn blocks_include(&self) -> bool {
        !matches!(self, SchemeClass::Local | SchemeClass::Phar)
    }

    /// True iff a file-OPEN sink (fopen/file_get_contents/readfile) must refuse
    /// this target. Only the near-zero-benign-use wrappers: `php://filter` (the
    /// LFI exfil / filter-chain primitive), `data:` and `expect://`. Remote
    /// schemes are left to the SSRF sink; `php://input`/`php://temp`/`php://memory`
    /// and the other php wrappers are legitimate open targets.
    pub fn blocks_open(&self) -> bool {
        matches!(self, SchemeClass::PhpFilter | SchemeClass::Data | SchemeClass::Expect)
    }
}

fn is_scheme_start(b: u8) -> bool {
    b.is_ascii_alphabetic()
}

fn is_scheme_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.')
}

/// `body` begins with `needle` (ASCII-case-insensitive).
fn starts_with_ci(body: &[u8], needle: &[u8]) -> bool {
    body.len() >= needle.len() && body[..needle.len()].eq_ignore_ascii_case(needle)
}

fn classify_php(body: &[u8]) -> SchemeClass {
    if starts_with_ci(body, b"filter") {
        SchemeClass::PhpFilter
    } else if starts_with_ci(body, b"input") {
        SchemeClass::PhpInput
    } else {
        SchemeClass::PhpOther
    }
}

/// Classify the stream-wrapper scheme of an include/open `target`.
///
/// A scheme is a leading `[A-Za-z][A-Za-z0-9+.-]*` run followed by `:`. For
/// every scheme but `data` the wrapper form requires `://`; `data:` is matched
/// with or without `//` (the RFC 2397 form has none). A scheme-looking token
/// with no `//` (and not `data:`) is treated as a local path, so an odd
/// filename that merely contains a colon never false-positives.
pub fn classify_scheme(target: &[u8]) -> SchemeClass {
    let t = target.trim_ascii_start();
    if t.is_empty() || !is_scheme_start(t[0]) {
        return SchemeClass::Local;
    }
    let mut i = 1;
    while i < t.len() && is_scheme_byte(t[i]) {
        i += 1;
    }
    if i >= t.len() || t[i] != b':' {
        return SchemeClass::Local;
    }
    let scheme = &t[..i];
    let after = &t[i + 1..];
    let slashes = after.starts_with(b"//");
    let body = if slashes { &after[2..] } else { after };

    // `data:` is a wrapper with or without the slashes (RFC 2397).
    if scheme.eq_ignore_ascii_case(b"data") {
        return SchemeClass::Data;
    }
    // Any other scheme is only a stream wrapper in the `scheme://` form.
    if !slashes {
        return SchemeClass::Local;
    }
    if scheme.eq_ignore_ascii_case(b"file") {
        SchemeClass::Local
    } else if scheme.eq_ignore_ascii_case(b"phar") {
        SchemeClass::Phar
    } else if scheme.eq_ignore_ascii_case(b"php") {
        classify_php(body)
    } else if scheme.eq_ignore_ascii_case(b"expect") {
        SchemeClass::Expect
    } else if scheme.eq_ignore_ascii_case(b"http") || scheme.eq_ignore_ascii_case(b"https") {
        SchemeClass::Http
    } else if scheme.eq_ignore_ascii_case(b"ftp") || scheme.eq_ignore_ascii_case(b"ftps") {
        SchemeClass::Ftp
    } else {
        SchemeClass::Other
    }
}

/// A poisonable local include/open target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoisonKind {
    /// `/proc/self/environ` (or `/proc/<pid>/environ`): environ poisoning.
    ProcEnviron,
    /// Any other `/proc/*` pseudo-file.
    Proc,
    /// A file under the runtime `session.save_path`: session poisoning.
    Session,
    /// PHP's configured `error_log`: log poisoning.
    Log,
}

impl PoisonKind {
    /// A short label for the log `reason` (never the target).
    pub fn as_label(&self) -> &'static str {
        match self {
            PoisonKind::ProcEnviron => "proc_environ",
            PoisonKind::Proc => "proc",
            PoisonKind::Session => "session",
            PoisonKind::Log => "log",
        }
    }
}

/// Split `path` into components anchored at the effective root: `.` and empty
/// components are dropped and `..` pops (clamped at root), WITHOUT requiring a
/// leading `/`. So both `/proc/self/environ` and `../../../proc/self/environ`
/// resolve to `[proc, self, environ]`, while `templates/proc/x` stays rooted at
/// `templates`. Used only to anchor the `/proc` match.
fn resolve_anchored(path: &[u8]) -> Vec<&[u8]> {
    let mut out: Vec<&[u8]> = Vec::new();
    for comp in path.split(|&b| b == b'/') {
        match comp {
            b"" | b"." => {}
            b".." => {
                out.pop();
            }
            c => out.push(c),
        }
    }
    out
}

/// Lexically normalize an ABSOLUTE path into components (`.`/empty dropped,
/// `..` pops, clamped at root). `None` for a relative path.
fn normalize_abs(path: &[u8]) -> Option<Vec<&[u8]>> {
    if path.first() != Some(&b'/') {
        return None;
    }
    Some(resolve_anchored(path))
}

/// True iff `p` lies at or under `base` (component-wise prefix).
fn under(p: &[Vec<u8>], base: &[Vec<u8>]) -> bool {
    !base.is_empty() && p.len() >= base.len() && p[..base.len()] == base[..]
}

fn owned(v: Vec<&[u8]>) -> Vec<Vec<u8>> {
    v.into_iter().map(|c| c.to_vec()).collect()
}

/// Longest target we classify. The kernel rejects a path past `PATH_MAX`
/// (`ENAMETOOLONG`), so PHP never opens one; a megabytes-long `a/a/a/…` would
/// otherwise cost one `Vec` entry and a heap copy per component (F7).
const POISON_MAX_LEN: usize = 4096;

/// Strip a leading `file://[authority]` wrapper so the path is classified:
/// `file:///proc/self/environ` -> `/proc/self/environ`,
/// `file://localhost/var/.../sess_x` -> `/var/.../sess_x`. The `file` scheme is
/// allowed by the wrapper key, so the poison check must see through it (F5a).
fn strip_file_wrapper(t: &[u8]) -> &[u8] {
    if t.len() >= 7 && t[..4].eq_ignore_ascii_case(b"file") && &t[4..7] == b"://" {
        let after = &t[7..];
        return match after.iter().position(|&b| b == b'/') {
            Some(i) => &after[i..],
            None => after,
        };
    }
    t
}

/// Flag a poisonable LOCAL target. `session` is the runtime `session.save_path`
/// and `error_log` PHP's configured `error_log` (either empty when unknown —
/// the glue passes them per request). Matching is anchored at the root and the
/// `error_log` match is exact, so benign relative/absolute app paths never hit.
pub fn classify_poison(target: &[u8], session: &[u8], error_log: &[u8]) -> Option<PoisonKind> {
    if target.len() > POISON_MAX_LEN {
        return None;
    }
    let target = strip_file_wrapper(target);
    // `/proc` (and traversal into it): anchored, so `templates/proc/x` is safe.
    let comps = resolve_anchored(target);
    if comps.first().map(|c| c.as_ref()) == Some(b"proc".as_ref()) {
        let is_environ = comps.len() == 3
            && comps[2] == b"environ"
            && (comps[1] == b"self" || comps[1].iter().all(u8::is_ascii_digit));
        return Some(if is_environ { PoisonKind::ProcEnviron } else { PoisonKind::Proc });
    }
    // session.save_path and error_log are absolute config paths. Anchor the
    // target at the root (not absolute-only) so a `..` traversal into the
    // session dir is caught as well (F5b:
    // `../../../var/lib/php/sessions/sess_x`); a shallow relative app path
    // never climbs far enough to land under an absolute config base.
    let tgt = owned(resolve_anchored(target));
    if !session.is_empty() {
        // session.save_path may be `N;/path` or `N;MODE;/path` (the depth/mode
        // prefix); take the trailing path component.
        let path = session.rsplit(|&b| b == b';').next().unwrap_or(session);
        if let Some(base) = normalize_abs(path) {
            // Require the `sess_` prefix PHP's file handler always writes, so a
            // broad base (e.g. the temp-dir fallback from F5c) flags only
            // session files, never every include under /tmp.
            let is_sess = tgt.last().is_some_and(|n| n.starts_with(b"sess_"));
            if is_sess && under(&tgt, &owned(base)) {
                return Some(PoisonKind::Session);
            }
        }
    }
    if !error_log.is_empty() {
        if let Some(log) = normalize_abs(error_log) {
            if tgt == owned(log) {
                return Some(PoisonKind::Log);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scheme_local_and_file() {
        for t in [
            &b""[..],
            b"templates/header.php",
            b"/var/www/app/config.php",
            b"vendor/autoload.php",
            b"./pages/home.php",
            b"../lib/util.php",
            b"uploads/php-logo.png", // merely contains "php"
            b"C:some\\win\\path",     // scheme-looking token, no `//` -> local
            b"a:b:c",
            b"file:///etc/passwd",
            b"FILE:///etc/passwd",
        ] {
            assert_eq!(classify_scheme(t), SchemeClass::Local, "{:?}", String::from_utf8_lossy(t));
            assert!(!classify_scheme(t).blocks_include(), "{:?}", String::from_utf8_lossy(t));
            assert!(!classify_scheme(t).blocks_open(), "{:?}", String::from_utf8_lossy(t));
        }
    }

    #[test]
    fn scheme_php_variants() {
        assert_eq!(classify_scheme(b"php://filter/convert.base64-encode/resource=/etc/passwd"), SchemeClass::PhpFilter);
        assert_eq!(classify_scheme(b"PHP://FILTER/read=string.rot13/resource=x"), SchemeClass::PhpFilter);
        assert_eq!(classify_scheme(b"php://input"), SchemeClass::PhpInput);
        assert_eq!(classify_scheme(b"php://temp"), SchemeClass::PhpOther);
        assert_eq!(classify_scheme(b"php://memory"), SchemeClass::PhpOther);
        assert_eq!(classify_scheme(b"php://stdout"), SchemeClass::PhpOther);
    }

    #[test]
    fn scheme_data_expect_remote() {
        assert_eq!(classify_scheme(b"data://text/plain;base64,PD9waHAgZXZhbA=="), SchemeClass::Data);
        assert_eq!(classify_scheme(b"data:text/plain;base64,PD9waHA="), SchemeClass::Data); // no //
        assert_eq!(classify_scheme(b"DATA:,inline"), SchemeClass::Data);
        assert_eq!(classify_scheme(b"expect://id"), SchemeClass::Expect);
        assert_eq!(classify_scheme(b"http://evil.example/shell.txt"), SchemeClass::Http);
        assert_eq!(classify_scheme(b"https://evil.example/shell.txt"), SchemeClass::Http);
        assert_eq!(classify_scheme(b"ftp://evil.example/x"), SchemeClass::Ftp);
        assert_eq!(classify_scheme(b"ftps://evil.example/x"), SchemeClass::Ftp);
        assert_eq!(classify_scheme(b"zip://archive.zip%23file"), SchemeClass::Other);
        assert_eq!(classify_scheme(b"compress.zlib://file.gz"), SchemeClass::Other);
    }

    #[test]
    fn scheme_phar_left_to_phar_sink() {
        assert_eq!(classify_scheme(b"phar:///srv/app/a.phar/x.php"), SchemeClass::Phar);
        assert!(!classify_scheme(b"phar:///srv/app/a.phar").blocks_include());
        assert!(!classify_scheme(b"phar:///srv/app/a.phar").blocks_open());
    }

    #[test]
    fn include_policy_refuses_every_non_file_wrapper() {
        for t in [
            &b"php://filter/resource=x"[..],
            b"php://input",
            b"php://temp",
            b"data://text/plain;base64,x",
            b"expect://id",
            b"http://evil/shell.txt",
            b"ftp://evil/x",
            b"zip://a.zip",
        ] {
            assert!(classify_scheme(t).blocks_include(), "{:?}", String::from_utf8_lossy(t));
        }
    }

    #[test]
    fn open_policy_is_tight() {
        // Blocked: the near-zero-benign-use wrappers.
        for t in [&b"php://filter/resource=x"[..], b"data://text/plain;base64,x", b"expect://id"] {
            assert!(classify_scheme(t).blocks_open(), "{:?}", String::from_utf8_lossy(t));
        }
        // Allowed: legitimate open targets (remote is the SSRF sink's job).
        for t in [
            &b"php://input"[..],
            b"php://temp",
            b"php://memory",
            b"php://output",
            b"http://api.example/data.json",
            b"https://api.example/data.json",
            b"zip://a.zip",
            b"/var/www/app/data.json",
        ] {
            assert!(!classify_scheme(t).blocks_open(), "{:?}", String::from_utf8_lossy(t));
        }
    }

    #[test]
    fn leading_whitespace_is_ignored() {
        assert_eq!(classify_scheme(b"  \tphp://input"), SchemeClass::PhpInput);
        assert_eq!(classify_scheme(b"   /var/www/x.php"), SchemeClass::Local);
    }

    #[test]
    fn poison_proc() {
        assert_eq!(classify_poison(b"/proc/self/environ", b"", b""), Some(PoisonKind::ProcEnviron));
        assert_eq!(classify_poison(b"/proc/1234/environ", b"", b""), Some(PoisonKind::ProcEnviron));
        assert_eq!(classify_poison(b"/proc/self/cmdline", b"", b""), Some(PoisonKind::Proc));
        assert_eq!(classify_poison(b"/proc/mounts", b"", b""), Some(PoisonKind::Proc));
        // Traversal into /proc, anchored at root.
        assert_eq!(classify_poison(b"../../../../proc/self/environ", b"", b""), Some(PoisonKind::ProcEnviron));
        assert_eq!(classify_poison(b"/var/www/../../proc/self/environ", b"", b""), Some(PoisonKind::ProcEnviron));
    }

    #[test]
    fn poison_session_and_log() {
        assert_eq!(classify_poison(b"/var/lib/php/sessions/sess_abc", b"/var/lib/php/sessions", b""), Some(PoisonKind::Session));
        // session.save_path with a depth/mode prefix.
        assert_eq!(classify_poison(b"/var/lib/php/sess_x", b"1;0600;/var/lib/php", b""), Some(PoisonKind::Session));
        assert_eq!(classify_poison(b"/var/log/php_errors.log", b"", b"/var/log/php_errors.log"), Some(PoisonKind::Log));
        // error_log match is exact: a sibling file is not it.
        assert_eq!(classify_poison(b"/var/log/other.log", b"", b"/var/log/php_errors.log"), None);
    }

    #[test]
    fn poison_benign_is_none() {
        // A dir literally rooted elsewhere that merely contains "proc"/"session".
        for t in [
            &b"templates/proc/header.php"[..],
            b"my_proc/x.php",
            b"/var/www/app/config.php",
            b"vendor/autoload.php",
            b"src/Session/Handler.php",
            b"/var/www/app/sessions/view.php", // not the runtime session dir
        ] {
            assert_eq!(classify_poison(t, b"/var/lib/php/sessions", b"/var/log/php_errors.log"), None, "{:?}", String::from_utf8_lossy(t));
        }
        // No runtime paths known: session/log never fire, only /proc.
        assert_eq!(classify_poison(b"/var/lib/php/sessions/sess_abc", b"", b""), None);
    }
    #[test]
    fn poison_sec_review_fixes() {
        // F5a: a file:// wrapper is stripped before classifying.
        assert_eq!(classify_poison(b"file:///proc/self/environ", b"", b""), Some(PoisonKind::ProcEnviron));
        assert_eq!(classify_poison(b"file://localhost/proc/self/environ", b"", b""), Some(PoisonKind::ProcEnviron));
        assert_eq!(
            classify_poison(b"file:///var/lib/php/sessions/sess_x", b"/var/lib/php/sessions", b""),
            Some(PoisonKind::Session)
        );
        // F5b: a relative traversal into the session dir is caught.
        assert_eq!(
            classify_poison(b"../../../../var/lib/php/sessions/sess_x", b"/var/lib/php/sessions", b""),
            Some(PoisonKind::Session)
        );
        // sess_ precision: a non-session file under the base is not flagged (so a
        // broad temp-dir base from the F5c fallback never over-blocks).
        assert_eq!(classify_poison(b"/var/lib/php/sessions/notes.txt", b"/var/lib/php/sessions", b""), None);
        // F7: an over-long path is not classified (the kernel rejects it anyway;
        // this avoids the per-component allocation blow-up).
        let long = [b'a'; 5000];
        assert_eq!(classify_poison(&long, b"", b""), None);
    }
}

//! Layer-2 input inspection: hand-written, strictly linear-time scanners.
//!
//! No regex and no backtracking: every signature is a bounded forward walk over
//! an ASCII-lowercased prefix of the value. Defensive, log-only classification;
//! this module only reports which class (if any) matched.

use crate::limits::RuleId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InspectClass {
    SqlInjection,
    PathTraversal,
    CommandInjection,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct InspectLimits {
    pub max_value_bytes: usize,
    pub max_total_bytes: usize,
    pub max_values: usize,
}

impl Default for InspectLimits {
    fn default() -> Self {
        Self::defaults()
    }
}

impl InspectLimits {
    pub fn defaults() -> InspectLimits {
        InspectLimits {
            max_value_bytes: 16 * 1024,
            max_total_bytes: 2 * 1024 * 1024,
            max_values: 2000,
        }
    }

    /// Reject configurations that would silently disable scanning (any limit of 0).
    pub fn validate(&self) -> Result<(), String> {
        let fields = [
            ("max_value_bytes", self.max_value_bytes),
            ("max_total_bytes", self.max_total_bytes),
            ("max_values", self.max_values),
        ];
        for (name, v) in fields {
            if v == 0 {
                return Err(format!("inspect.limits.{name} must be greater than 0"));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Get,
    Post,
    Cookie,
    Path,
}

pub fn class_rule(c: InspectClass) -> RuleId {
    match c {
        InspectClass::SqlInjection => RuleId::SqlInjection,
        InspectClass::PathTraversal => RuleId::PathTraversal,
        InspectClass::CommandInjection => RuleId::CommandInjection,
    }
}

/// Scan at most `limits.max_value_bytes` of `value`. Priority: SQLi, then
/// command injection, then path traversal. (Command injection outranks path
/// traversal so `; cat /etc/passwd` classifies as command injection even
/// though it contains a traversal target.)
pub fn scan(value: &[u8], source: Source, limits: &InspectLimits) -> Option<InspectClass> {
    let prefix = &value[..value.len().min(limits.max_value_bytes)];
    let mut views = vec![prefix.to_ascii_lowercase()];
    if source == Source::Path {
        views.push(percent_decode(prefix).to_ascii_lowercase());
    }

    if views.iter().any(|v| sqli(v)) {
        return Some(InspectClass::SqlInjection);
    }
    if views.iter().any(|v| cmdi(v)) {
        return Some(InspectClass::CommandInjection);
    }
    if views.iter().any(|v| traversal(v)) {
        return Some(InspectClass::PathTraversal);
    }
    None
}

fn percent_decode(input: &[u8]) -> Vec<u8> {
    fn hex(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    }
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i] == b'%' && i + 2 < input.len() {
            if let (Some(h), Some(l)) = (hex(input[i + 1]), hex(input[i + 2])) {
                out.push(h * 16 + l);
                i += 3;
                continue;
            }
        }
        out.push(input[i]);
        i += 1;
    }
    out
}

fn is_word(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn is_ws(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)
}

fn skip_ws(s: &[u8], mut i: usize) -> usize {
    while i < s.len() && is_ws(s[i]) {
        i += 1;
    }
    i
}

/// `word` (lowercase) occurs at `i` with word boundaries on both sides.
fn word_at(s: &[u8], i: usize, word: &[u8]) -> bool {
    s.len() >= i + word.len()
        && &s[i..i + word.len()] == word
        && (i == 0 || !is_word(s[i - 1]))
        && (i + word.len() == s.len() || !is_word(s[i + word.len()]))
}

fn contains(s: &[u8], needle: &[u8]) -> bool {
    s.windows(needle.len()).any(|w| w == needle)
}

fn is_quote(b: u8) -> bool {
    b == b'\'' || b == b'"'
}

fn sqli(s: &[u8]) -> bool {
    for i in 0..s.len() {
        match s[i] {
            b'u' if word_at(s, i, b"union") => {
                let j = skip_ws(s, i + 5);
                if j > i + 5 && word_at(s, j, b"select") {
                    return true;
                }
            }
            b'\'' | b'"' => {
                let rest = &s[i + 1..];
                // (c) quote + comment introducer
                if rest.starts_with(b"--") || rest.starts_with(b"#") || rest.starts_with(b"/*") {
                    return true;
                }
                // (b) quote + ws* + or/and + ws* + X=
                let j = skip_ws(s, i + 1);
                let kw = if word_at(s, j, b"or") {
                    2
                } else if word_at(s, j, b"and") {
                    3
                } else {
                    0
                };
                if kw > 0 {
                    let mut k = skip_ws(s, j + kw);
                    if k < s.len() && is_quote(s[k]) {
                        k += 1;
                    }
                    let start = k;
                    while k < s.len() && is_word(s[k]) {
                        k += 1;
                    }
                    if k > start {
                        if k < s.len() && is_quote(s[k]) {
                            k += 1;
                        }
                        k = skip_ws(s, k);
                        if k < s.len() && s[k] == b'=' {
                            return true;
                        }
                    }
                }
            }
            b';' => {
                let j = skip_ws(s, i + 1);
                if stacked_statement(s, j) {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

/// After a `;`: does a stacked SQL statement start at `j`? Requires the
/// statement's second token to look like SQL, so prose such as
/// "Thanks; update your profile" or "fine; select one option" stays clean.
fn stacked_statement(s: &[u8], j: usize) -> bool {
    let drop_follow: [&[u8]; 6] = [b"table", b"database", b"schema", b"view", b"index", b"user"];
    let simple: [(&[u8], &[&[u8]]); 3] = [
        (b"drop", &drop_follow),
        (b"delete", &[b"from"]),
        (b"insert", &[b"into"]),
    ];
    for (kw, follow) in simple {
        if word_at(s, j, kw) {
            let e = j + kw.len();
            let k = skip_ws(s, e);
            return k > e && follow.iter().any(|f| word_at(s, k, f));
        }
    }
    if word_at(s, j, b"update") {
        // update <ident> set
        let k = skip_ws(s, j + 6);
        let mut e = k;
        while e < s.len() && (is_word(s[e]) || s[e] == b'.' || s[e] == b'`') {
            e += 1;
        }
        return k > j + 6 && e > k && word_at(s, skip_ws(s, e), b"set");
    }
    if word_at(s, j, b"select") {
        let k = skip_ws(s, j + 6);
        if k == j + 6 || k >= s.len() {
            return false;
        }
        if matches!(s[k], b'*' | b'@' | b'(') || s[k].is_ascii_digit() {
            return true;
        }
        // select <cols> from ... within a short window
        let end = (k + 64).min(s.len());
        return (k..end).any(|p| word_at(s, p, b"from"));
    }
    false
}

const BINARIES:[&[u8]; 14] = [
    b"cat", b"ls", b"id", b"whoami", b"uname", b"wget", b"curl", b"nc", b"ncat", b"bash", b"sh",
    b"ping", b"python", b"perl",
];
const SINKS: [&[u8]; 8] = [
    b"system", b"exec", b"shell_exec", b"passthru", b"proc_open", b"popen", b"eval", b"assert",
];

fn cmdi(s: &[u8]) -> bool {
    let mut open_backtick: Option<usize> = None;
    for i in 0..s.len() {
        match s[i] {
            b'$' if s.get(i + 1) == Some(&b'(') => return true,
            b'`' => match open_backtick {
                // A closed backtick pair only counts when the command
                // substitution starts with a known binary (markdown
                // `foo` stays clean).
                Some(f) if i > f + 1 => {
                    let j = skip_ws(s, f + 1);
                    if BINARIES.iter().any(|b| word_at(s, j, b)) {
                        return true;
                    }
                    open_backtick = Some(i);
                }
                _ => open_backtick = Some(i),
            },
            b';' | b'|' | b'&' => {
                let mut j = i + 1;
                if s[i] != b';' && s.get(j) == Some(&s[i]) {
                    j += 1; // && or ||
                } else if s[i] == b'&' {
                    continue; // a lone '&' is not a separator signal
                }
                let j = skip_ws(s, j);
                if BINARIES.iter().any(|b| word_at(s, j, b)) {
                    return true;
                }
            }
            c if c.is_ascii_lowercase() => {
                for sink in SINKS {
                    if word_at(s, i, sink) && s.get(i + sink.len()) == Some(&b'(') {
                        return true;
                    }
                }
            }
            _ => {}
        }
    }
    false
}

fn traversal(s: &[u8]) -> bool {
    s.windows(3)
        .any(|w| w[0] == b'.' && w[1] == b'.' && (w[2] == b'/' || w[2] == b'\\'))
        || [
            &b"/etc/passwd"[..],
            b"/proc/self/",
            b"php://",
            b"file://",
            b"boot.ini",
        ]
        .iter()
        .any(|n| contains(s, n))
}

// ---- php-cgi argument injection (CVE-2012-1823, CVE-2024-4577) -------------
//
// When PHP runs as php-cgi behind a CGI front end (Apache mod_cgi, IIS), RFC
// 3875 4.4 lets the server hand a query string that contains no unencoded `=`
// to the program as command-line words, split on `+` and percent-decoded. A
// client can then drive php-cgi's own options: `?-d+allow_url_include%3d1
// +-d+auto_prepend_file%3dphp://input` is code execution, `?-s` is source
// disclosure (CVE-2012-1823). CVE-2024-4577 revives the same shape on Windows,
// where the `-` that the 2012 fix filters is spelled as a soft hyphen (0xAD)
// that the console code page's best-fit mapping turns into `-` (the request is
// `?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input`).
//
// The `=` is percent-encoded (`%3d`) in every working exploit, because a
// literal `=` makes the CGI front end treat the query as ordinary form data.
// That is the signature's first gate: a raw query string with a literal `=`
// is never a match. Past it the match is deliberately narrow, so ordinary
// `=`-less queries (search words, ids, base64 tokens, `?-1`, `?-sale`,
// `?/route/path`, UTF-8 text) stay clean:
//   * a `+`/space-separated word that is a php-cgi option: a known flag
//     exactly (`-s`, `-n`, `--info`), or an argument option (`-d`, `-c`, `-z`,
//     `-f`, `-b`, `-T`, `-r`, `--define`, ...) followed by its argument word, or
//     carrying an attached `name=value` / `scheme://` argument. The leading `-`
//     may be a literal dash, `%2d`, or a soft hyphen (`%AD`, `%C2%AD`);
//   * a word that names a php-cgi directive (`auto_prepend_file`,
//     `allow_url_include`, ...), bare or `name=value`;
//   * a stray soft-hyphen byte (0xAD) anywhere in the decoded query that is not
//     the continuation byte of a well-formed UTF-8 sequence. A plain 0xAD
//     match would block every query containing `i` with an acute accent (C3 AD)
//     or many CJK characters (E4 B8 AD), which is why the UTF-8 walk exists.
//
// One linear pass to decode and split, one pass per word over a bounded
// prefix. No regex, no backtracking. The query itself is never logged.

/// php-cgi single-letter options with no argument that expose source or
/// configuration: `-s`/`-w` (highlighted source), `-i` (phpinfo), `-m`, `-v`,
/// `-h`, `-n` (no php.ini). Matched only as the whole word.
const CGI_FLAG_OPTS: &[u8] = b"swimvhn";
/// Options that take an argument: php-cgi `-d` (ini entry), `-c` (php.ini
/// path), `-z` (Zend extension), `-f` (script file), `-b` (bind path), `-T`
/// (timing), and the CLI's `-r` (code).
const CGI_ARG_OPTS: &[u8] = b"dczfbTr";
/// Long options with no argument.
const CGI_LONG_FLAGS: [&[u8]; 9] = [
    b"info", b"version", b"help", b"modules", b"usage", b"no-php-ini", b"syntax-highlight",
    b"syntax-highlighting", b"strip",
];
/// Long options that take an argument.
const CGI_LONG_ARGS: [&[u8]; 6] =
    [b"define", b"php-ini", b"file", b"zend-extension", b"bindpath", b"timing"];
/// php.ini directives a php-cgi exploit sets (or CGI-mode gates it clears).
const CGI_DIRECTIVES: [&[u8]; 6] = [
    b"auto_prepend_file",
    b"auto_append_file",
    b"allow_url_include",
    b"cgi.force_redirect",
    b"cgi.redirect_status_env",
    b"cgi.fix_pathinfo",
];

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Percent-decode `q` into one buffer and record the `(start, end)` of each
/// word. Words split on `+`, space and tab, whether written raw or as `%20`/
/// `%09` (an encoded `+`, `%2b`, is data, not a separator). Empty words are
/// dropped.
fn cgi_words(q: &[u8]) -> (Vec<u8>, Vec<(usize, usize)>) {
    let mut dec = Vec::with_capacity(q.len());
    let mut words = Vec::new();
    let mut start = 0;
    let mut i = 0;
    while i < q.len() {
        let mut b = q[i];
        let mut step = 1;
        if b == b'%' && i + 2 < q.len() {
            if let (Some(h), Some(l)) = (hex_val(q[i + 1]), hex_val(q[i + 2])) {
                b = h * 16 + l;
                step = 3;
            }
        }
        let sep = (step == 1 && b == b'+') || b == b' ' || b == b'\t';
        if sep {
            if dec.len() > start {
                words.push((start, dec.len()));
            }
            start = dec.len();
        } else {
            dec.push(b);
        }
        i += step;
    }
    if dec.len() > start {
        words.push((start, dec.len()));
    }
    (dec, words)
}

/// A 0xAD byte that is not the continuation byte of a well-formed UTF-8
/// sequence. A multibyte lead consumes the continuation bytes that follow it
/// (so `C3 AD`, the accented i, and `E4 B8 AD`, a common CJK character, are
/// text); an AD anywhere else can only be a soft hyphen written as a raw byte.
fn stray_soft_hyphen(d: &[u8]) -> bool {
    let mut i = 0;
    while i < d.len() {
        let need = match d[i] {
            0xC2..=0xDF => 1,
            0xE0..=0xEF => 2,
            0xF0..=0xF4 => 3,
            _ => 0,
        };
        if need == 0 {
            if d[i] == 0xAD {
                return true;
            }
            i += 1;
            continue;
        }
        let mut k = 0;
        while k < need && i + 1 + k < d.len() && (0x80..=0xBF).contains(&d[i + 1 + k]) {
            k += 1;
        }
        i += 1 + k;
    }
    false
}

/// `w` names a php-cgi directive: the directive (ASCII case-insensitive) is the
/// whole word, or is followed by `=`.
fn cgi_directive(w: &[u8]) -> bool {
    CGI_DIRECTIVES.iter().any(|d| {
        w.len() >= d.len()
            && w[..d.len()].eq_ignore_ascii_case(d)
            && (w.len() == d.len() || w[d.len()] == b'=')
    })
}

/// An attached argument that really is a setting or a stream URL, not a word:
/// `name=value` with a non-empty value that is not just base64 `=` padding, or
/// a `scheme://` URL. (`-dGVzdA==` from a base64url token is padding, not an
/// ini assignment.)
fn cgi_attached_arg(tail: &[u8]) -> bool {
    if contains(tail, b"://") {
        return true;
    }
    match tail.iter().position(|&b| b == b'=') {
        Some(eq) => eq > 0 && tail[eq + 1..].iter().any(|&b| b != b'='),
        None => false,
    }
}

/// `w` is a php-cgi option. `has_next` says another word follows (an argument
/// option's separate argument).
fn cgi_option(w: &[u8], has_next: bool) -> bool {
    // Leading dash: `-`, or a soft hyphen as a raw byte (AD) or UTF-8 (C2 AD).
    let rest = match w {
        [b'-', r @ ..] | [0xAD, r @ ..] | [0xC2, 0xAD, r @ ..] => r,
        _ => return false,
    };
    if rest.is_empty() {
        return false;
    }
    // A second dash makes it a long option.
    if let [b'-', body @ ..] | [0xAD, body @ ..] | [0xC2, 0xAD, body @ ..] = rest {
        let eq = body.iter().position(|&b| b == b'=');
        let name = body[..eq.unwrap_or(body.len())].to_ascii_lowercase();
        if CGI_LONG_FLAGS.iter().any(|f| name == *f) {
            return eq.is_none();
        }
        return CGI_LONG_ARGS.iter().any(|f| name == *f) && (eq.is_some() || has_next);
    }
    let (c, tail) = (rest[0], &rest[1..]);
    if CGI_FLAG_OPTS.contains(&c) {
        return tail.is_empty();
    }
    if CGI_ARG_OPTS.contains(&c) {
        return if tail.is_empty() { has_next } else { cgi_attached_arg(tail) };
    }
    false
}

/// Does the raw (undecoded) query string have the shape of php-cgi
/// command-line arguments? `query` is what the SAPI reports as the query
/// string, without the leading `?`. At most `max_bytes` of it are scanned (the
/// literal-`=` gate looks at all of it).
pub fn cgi_arg_injection(query: &[u8], max_bytes: usize) -> bool {
    if query.is_empty() || query.contains(&b'=') {
        return false;
    }
    let q = &query[..query.len().min(max_bytes)];
    let (dec, words) = cgi_words(q);
    if stray_soft_hyphen(&dec) {
        return true;
    }
    words.iter().enumerate().any(|(i, &(s, e))| {
        let w = &dec[s..e];
        cgi_directive(w) || cgi_option(w, i + 1 < words.len())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use InspectClass::*;

    fn d() -> InspectLimits {
        InspectLimits::defaults()
    }

    #[test]
    fn sqli_tautology_and_union_and_comment_caught() {
        assert_eq!(scan(b"' OR 1=1 --", Source::Get, &d()), Some(SqlInjection));
        assert_eq!(
            scan(b"1 UNION SELECT pw FROM users", Source::Get, &d()),
            Some(SqlInjection)
        );
        assert_eq!(scan(b"admin'--", Source::Post, &d()), Some(SqlInjection));
        assert_eq!(scan(b"\" OR 'a'='a", Source::Get, &d()), Some(SqlInjection));
        assert_eq!(scan(b"x; DROP TABLE t", Source::Get, &d()), Some(SqlInjection));
        for v in [
            &b"1; DELETE FROM users"[..],
            b"1; update users set admin=1",
            b"1; insert into t values(1)",
            b"1; select * from users",
            b"1; select password from users",
            b"1; select @@version",
        ] {
            assert_eq!(scan(v, Source::Get, &d()), Some(SqlInjection), "{:?}", v);
        }
        assert_eq!(scan(b"a `id` b", Source::Get, &d()), Some(CommandInjection));
        assert_eq!(scan(b"system ('x')", Source::Get, &d()), None);
    }

    #[test]
    fn traversal_caught() {
        assert_eq!(scan(b"../../etc/passwd", Source::Get, &d()), Some(PathTraversal));
        assert_eq!(scan(b"/proc/self/environ", Source::Get, &d()), Some(PathTraversal));
        assert_eq!(
            scan(b"php://filter/convert.base64-encode/resource=x", Source::Get, &d()),
            Some(PathTraversal)
        );
    }

    #[test]
    fn encoded_traversal_caught() {
        assert_eq!(
            scan(b"%2e%2e%2fetc%2fpasswd", Source::Path, &d()),
            Some(PathTraversal)
        );
    }

    #[test]
    fn cmdi_caught() {
        for v in [&b"; cat /etc/passwd"[..], b"$(id)", b"`whoami`", b"system('ls')"] {
            assert_eq!(scan(v, Source::Get, &d()), Some(CommandInjection), "{:?}", v);
        }
    }

    #[test]
    fn benign_corpus_is_clean() {
        for v in [
            &b"I think 1 or 2 will do"[..],
            b"union of two sets",
            b"rock & roll",
            b"reports/2024/q1.pdf",
            b"./theme/style.css",
            b"it's a test",
            b"name=O'Brien",
            b"operating system (Linux)",
            b"file system (ext4)",
            b"use `foo` here",
            b"#fff",
            b"#main",
            b"Thanks; update your profile",
            b"fine; select one option",
        ] {
            assert_eq!(scan(v, Source::Get, &d()), None, "{:?}", v);
            assert_eq!(scan(v, Source::Path, &d()), None, "{:?}", v);
        }
    }

    #[test]
    fn huge_value_is_prefix_bounded() {
        let lim = d();
        let mut v = vec![b'a'; 4 * 1024 * 1024];
        v[lim.max_value_bytes + 10..lim.max_value_bytes + 21].copy_from_slice(b"' or 1=1 --");
        let t = std::time::Instant::now();
        assert_eq!(scan(&v, Source::Path, &lim), None);
        assert!(t.elapsed().as_secs() < 2);
    }

    #[test]
    fn path_source_also_scans_decoded() {
        assert_eq!(scan(b"..%2f..%2f", Source::Path, &d()), Some(PathTraversal));
        assert_eq!(scan(b"..%2f..%2f", Source::Get, &d()), None);
    }

    const CGI_MAX: usize = 2 * 1024 * 1024;
    fn cgi(q: &[u8]) -> bool {
        cgi_arg_injection(q, CGI_MAX)
    }

    #[test]
    fn cgi_arg_cve_2012_1823_shapes_match() {
        for q in [
            // The Metasploit / public PoC shape: ini overrides on the command line.
            &b"-d+allow_url_include%3d1+-d+auto_prepend_file%3dphp://input"[..],
            b"-d+allow_url_include%3dtrue+-d+auto_prepend_file%3dphp://input",
            // Encoded dash (the classic filter bypass), upper and lower hex.
            b"%2dd+allow_url_include%3d1+%2dd+auto_prepend_file%3dphp://input",
            b"%2Dd+allow_url_include%3D1+%2Dd+auto_prepend_file%3Dphp://input",
            // Space as %20 instead of +.
            b"-d%20allow_url_include%3d1%20-d%20auto_prepend_file%3dphp://input",
            // Argument attached to the option.
            b"-dauto_prepend_file%3dphp://input",
            b"-dallow_url_include%3d1+-dauto_prepend_file%3dphp://input",
            // Source disclosure and other flag options.
            b"-s", b"-w", b"-i", b"-m", b"-v", b"-h", b"-n", b"-n+-s", b"%2ds",
            // Long options.
            b"--info", b"--version", b"--define+auto_prepend_file%3dphp://input",
            b"--define%3dauto_prepend_file%3dphp://input",
            // Other argument options with their argument word.
            b"-c+/proc/self/fd/0", b"-z+/tmp/x.so", b"-f+/etc/passwd", b"-r+phpinfo();",
            b"-b+127.0.0.1:9000",
        ] {
            assert!(cgi(q), "should match: {}", String::from_utf8_lossy(q));
        }
    }

    #[test]
    fn cgi_arg_cve_2024_4577_soft_hyphen_shapes_match() {
        for q in [
            // DEVCORE's PoC: the soft hyphen (0xAD) stands in for the dash.
            &b"%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input"[..],
            b"%adn+%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input",
            b"%ADs",
            b"%ADdauto_prepend_file%3dphp://input",
            // UTF-8 soft hyphen (C2 AD) as the dash.
            b"%C2%ADd+auto_prepend_file%3dphp://input",
            b"%C2%ADs",
            // Soft hyphen as the second dash of a long option.
            b"-%ADinfo",
            // A raw 0xAD byte on the wire, not percent-encoded.
            b"\xADd+allow_url_include%3d1+\xADd+auto_prepend_file%3dphp://input",
        ] {
            assert!(cgi(q), "should match: {:?}", String::from_utf8_lossy(q));
        }
    }

    #[test]
    fn cgi_arg_directive_tokens_and_stray_soft_hyphen_match() {
        for q in [
            &b"auto_prepend_file%3dphp://input"[..],
            b"allow_url_include",
            b"AUTO_APPEND_FILE%3d/tmp/x",
            b"cgi.force_redirect%3d0",
            b"cgi.redirect_status_env%3dfoo",
            b"x+allow_url_include%3d1",
            // A lone soft hyphen byte that is not part of a UTF-8 sequence.
            b"foo%ADbar",
            b"%AD",
            b"abc+def%ADghi",
        ] {
            assert!(cgi(q), "should match: {}", String::from_utf8_lossy(q));
        }
    }

    #[test]
    fn cgi_arg_literal_equals_is_never_a_match() {
        // A literal `=` makes the CGI front end parse the query as form data, so
        // php-cgi never sees these as arguments. Exploits always write `%3d`.
        for q in [
            &b"-d+allow_url_include=1+-d+auto_prepend_file=php://input"[..],
            b"%ADd+allow_url_include=1+%ADd+auto_prepend_file=php://input",
            b"q=search&page=2",
            b"-=",
            b"-s=1",
            b"auto_prepend_file=php://input",
            b"id=5&-d+allow_url_include%3d1",
        ] {
            assert!(!cgi(q), "must not match: {}", String::from_utf8_lossy(q));
        }
    }

    #[test]
    fn cgi_arg_benign_corpus_is_clean() {
        for q in [
            // Empty and trivial.
            &b""[..], b"q", b"x", b"a+b", b"+", b"++", b"%", b"%2", b"%zz",
            // Search words and phrases.
            b"hello+world", b"how+to+reset+password", b"php+tutorial+for+beginners",
            b"tom+%26+jerry", b"100%25+cotton", b"caf%C3%A9",
            // Dash-leading words that are not php-cgi options.
            b"-", b"--", b"---", b"-1", b"-5+10", b"-foo", b"-dog", b"-cat", b"-cat+-dog",
            b"-sale", b"-iphone", b"-water", b"-name", b"-date", b"-id", b"-created",
            b"-views", b"-final.pdf", b"-version", b"--no-such-flag", b"-n1", b"-sx",
            // An argument option with nothing after it is not a command line.
            b"-d", b"-c", b"-z", b"%2dd",
            // Dates, slugs, ids, version strings.
            b"2024-10-25", b"2024-01-01..2024-12-31", b"my-post-title", b"a-b-c",
            b"v1.2.3-rc1", b"item-1234-red",
            // Framework / front-controller style `=`-less queries.
            b"/users/12/edit", b"/blog/my-post", b"index.php/admin/dashboard",
            b"route/site/index", b"controller:action", b"page/2",
            // Base64 and base64url tokens (including padding) without a `=` key.
            b"dGVzdA", b"SGVsbG8gV29ybGQ", b"aGVsbG8%2Bd29ybGQ%2F", b"dGVzdA%3D%3D",
            b"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc-_def",
            b"-dGVzdA%3D%3D", b"-fGVzdA%3D", b"-cGVzdA%3D%3D",
            // A whole URL or JSON blob passed as the query.
            b"http%3A%2F%2Fexample.com%2F%3Fa%3Db", b"%7B%22a%22%3A1%7D",
            b"q%3Dfoo", b"redirect%3D%2Fhome",
            // UTF-8 text: the accented i (C3 AD), CJK (E4 B8 AD), emoji, a valid
            // UTF-8 soft hyphen inside a word.
            b"garc%C3%ADa", b"%C3%ADndice", b"%E4%B8%AD%E6%96%87", b"%E6%97%A5%E6%9C%AC%E8%AA%9E",
            b"%F0%9F%98%80", b"%E2%80%90", b"co%C2%ADoperate", b"na%C3%AFve+car%C3%A9",
            // Words that merely contain directive-like substrings or flag letters.
            b"auto_prepend", b"allow_url", b"prepend_file", b"include+allow", b"file_get_contents",
            b"phpinfo", b"display_errors", b"cgi", b"force_redirect",
        ] {
            assert!(!cgi(q), "must not match: {}", String::from_utf8_lossy(q));
        }
    }

    #[test]
    fn cgi_arg_is_bounded_and_linear() {
        let t = std::time::Instant::now();
        // 4 MiB of benign words, a million separators, and a long run of '%'.
        let mut q = Vec::new();
        while q.len() < 4 * 1024 * 1024 {
            q.extend_from_slice(b"word+-x+");
        }
        assert!(!cgi_arg_injection(&q, CGI_MAX));
        assert!(!cgi_arg_injection(&vec![b'%'; 4 * 1024 * 1024], CGI_MAX));
        // The prefix cap: an attack past max_bytes is not scanned, one inside it is.
        let mut late = vec![b'a'; 1000];
        late.extend_from_slice(b"+-d+auto_prepend_file%3dphp://input");
        assert!(!cgi_arg_injection(&late, 500));
        assert!(cgi_arg_injection(&late, 2000));
        // The literal-`=` gate sees the whole query, not just the scanned prefix.
        let mut tail_eq = b"-s".to_vec();
        tail_eq.extend_from_slice(&[b'a'; 100]);
        tail_eq.extend_from_slice(b"&k=v");
        assert!(!cgi_arg_injection(&tail_eq, 10));
        assert!(t.elapsed().as_secs() < 5, "{:?}", t.elapsed());
    }
}

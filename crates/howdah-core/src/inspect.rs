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

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
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

const BINARIES: [&[u8]; 14] = [
    b"cat", b"ls", b"id", b"whoami", b"uname", b"wget", b"curl", b"nc", b"ncat", b"bash", b"sh",
    b"ping", b"python", b"perl",
];
const SINKS: [&[u8]; 8] = [
    b"system",
    b"exec",
    b"shell_exec",
    b"passthru",
    b"proc_open",
    b"popen",
    b"eval",
    b"assert",
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
        assert_eq!(
            scan(b"x; DROP TABLE t", Source::Get, &d()),
            Some(SqlInjection)
        );
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
        assert_eq!(
            scan(b"../../etc/passwd", Source::Get, &d()),
            Some(PathTraversal)
        );
        assert_eq!(
            scan(b"/proc/self/environ", Source::Get, &d()),
            Some(PathTraversal)
        );
        assert_eq!(
            scan(
                b"php://filter/convert.base64-encode/resource=x",
                Source::Get,
                &d()
            ),
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
        for v in [
            &b"; cat /etc/passwd"[..],
            b"$(id)",
            b"`whoami`",
            b"system('ls')",
        ] {
            assert_eq!(
                scan(v, Source::Get, &d()),
                Some(CommandInjection),
                "{:?}",
                v
            );
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
}

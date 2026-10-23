//! Layer-3 sink policy: pure, hand-written, strictly linear-time checks.
//!
//! No regex, no backtracking, no filesystem access (wasm-compatible like the
//! rest of the core). Each function answers only "is this sink use benign /
//! allowlisted?"; the caller resolves the outcome against the configured mode.

/// Dangerous PHP sinks guarded by Layer 3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SinkId {
    CommandExec,
    Include,
    Eval,
    Unserialize,
}

/// Policy outcome before mode resolution. `Allow` = allowlisted / benign;
/// `Log`/`Block` = matched, caller resolves against mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SinkOutcome {
    Allow,
    Log,
    Block,
}

/// Maximum number of class names reported by `unserialize_classes`.
pub const MAX_CLASSES: usize = 64;
/// Maximum bytes of a single reported class name.
pub const MAX_CLASS_NAME: usize = 256;
/// Maximum digits accepted in a serialized length prefix.
const MAX_LEN_DIGITS: usize = 10;

/// True iff `cmd` matches one allowlist pattern.
///
/// A pattern is an anchored literal matched against the WHOLE command, unless
/// it ends in a single `*`, which matches any suffix. The trailing `*` is the
/// only metacharacter. Empty patterns never match.
///
/// A trailing `*` means ANY suffix: `"cmd *"` matches `cmd a; rm -rf /` by
/// design, and a bare `"*"` allows every command. This is intentional; the
/// operator chooses how loose a pattern is. A `*` elsewhere is literal.
pub fn command_allowed(cmd: &[u8], allow: &[String]) -> bool {
    allow.iter().any(|pat| {
        let p = pat.as_bytes();
        if p.is_empty() {
            return false;
        }
        match p.split_last() {
            Some((b'*', prefix)) => cmd.starts_with(prefix),
            _ => cmd == p,
        }
    })
}

/// Lexically normalize an absolute path into components (`.` and empty
/// components dropped, `..` pops, clamped at root). Returns `None` for
/// relative paths.
fn normalize(path: &[u8]) -> Option<Vec<&[u8]>> {
    if path.first() != Some(&b'/') {
        return None;
    }
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
    Some(out)
}

/// True iff the lexically normalized `path` lies under one of `allow_paths`
/// (component-wise prefix). Relative paths are never allowed. An empty
/// `allow_paths` returns false; the caller treats that as "sink inert".
pub fn include_allowed(path: &[u8], allow_paths: &[String]) -> bool {
    let Some(p) = normalize(path) else {
        return false;
    };
    allow_paths.iter().any(|a| match normalize(a.as_bytes()) {
        Some(base) => p.len() >= base.len() && p[..base.len()] == base[..],
        None => false,
    })
}

/// Result of scanning a serialized payload for object/class tokens.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UnserializeScan {
    /// Class names found (at most `MAX_CLASSES`, each at most `MAX_CLASS_NAME` bytes).
    pub classes: Vec<String>,
    /// True when more than `MAX_CLASSES` class tokens were present, so
    /// `classes` is incomplete. An allowlist check MUST FAIL CLOSED when this
    /// is set: a payload we could not fully enumerate is not "all allowed".
    pub capped: bool,
}

impl UnserializeScan {
    pub fn has_classes(&self) -> bool {
        !self.classes.is_empty()
    }
}

fn is_class_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'\\' || b >= 0x80
}

/// Bounded forward scan for `O:<len>:"Name"` / `C:<len>:"Name"` tokens.
/// Not a deserializer. A token must sit at the start or follow one of
/// `; { } :`. Reports at most `MAX_CLASSES` names and sets `capped` if more
/// exist; per-position work is bounded.
pub fn unserialize_classes(payload: &[u8]) -> UnserializeScan {
    let mut scan = UnserializeScan::default();
    let n = payload.len();
    let mut i = 0;
    while i + 1 < n {
        let at_boundary = i == 0 || matches!(payload[i - 1], b';' | b'{' | b'}' | b':');
        if at_boundary && matches!(payload[i], b'O' | b'C') && payload[i + 1] == b':' {
            if let Some((name, next)) = parse_class_token(payload, i + 2) {
                if scan.classes.len() >= MAX_CLASSES {
                    scan.capped = true;
                    break;
                }
                scan.classes.push(name);
                i = next;
                continue;
            }
        }
        i += 1;
    }
    scan
}

/// Parse `<digits>:"Name` starting at `pos`; returns the name and the index
/// just past it.
fn parse_class_token(p: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let start = pos;
    let mut len: usize = 0;
    while pos < p.len() && p[pos].is_ascii_digit() && pos - start < MAX_LEN_DIGITS {
        // Saturating: wasm32 has a 32-bit usize; 10 digits can overflow it.
        len = len.saturating_mul(10).saturating_add((p[pos] - b'0') as usize);
        pos += 1;
    }
    if pos == start || p.get(pos) != Some(&b':') || p.get(pos + 1) != Some(&b'"') {
        return None;
    }
    pos += 2;
    let take = len.min(MAX_CLASS_NAME);
    let mut end = pos;
    while end < p.len() && end - pos < take && is_class_byte(p[end]) {
        end += 1;
    }
    if end == pos {
        return None;
    }
    Some((String::from_utf8_lossy(&p[pos..end]).into_owned(), end))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn command_allow_is_anchored_whole_string() {
        let allow = s(&["id", "/usr/bin/convert *"]);
        assert!(command_allowed(b"id", &allow));
        assert!(!command_allowed(b"id; rm -rf /", &allow));
        assert!(command_allowed(b"/usr/bin/convert a b", &allow));
        assert!(!command_allowed(b"x/usr/bin/convert a", &allow));
        assert!(!command_allowed(b"/usr/bin/convert", &allow));
    }

    #[test]
    fn include_under_allow_paths() {
        let allow = s(&["/var/www/app"]);
        assert!(include_allowed(b"/var/www/app/tpl/x.php", &allow));
        assert!(!include_allowed(b"/var/www/app/../../etc/passwd", &allow));
        assert!(!include_allowed(b"/tmp/x.php", &allow));
        assert!(!include_allowed(b"/var/www/application/x.php", &allow));
    }

    #[test]
    fn unserialize_plain_data_is_allow() {
        assert!(unserialize_classes(b"a:1:{i:0;s:3:\"abc\";}").classes.is_empty());
        let o = unserialize_classes(b"O:8:\"stdClass\":0:{}");
        assert_eq!(o.classes, vec!["stdClass".to_string()]);
        assert!(o.has_classes());
        let c = unserialize_classes(b"C:3:\"Foo\":0:{}");
        assert_eq!(c.classes, vec!["Foo".to_string()]);
    }

    #[test]
    fn command_adversarial() {
        let id = s(&["id"]);
        assert!(!command_allowed(b"id ", &id));
        assert!(!command_allowed(b"", &id));
        let mid = s(&["a*b"]);
        assert!(command_allowed(b"a*b", &mid));
        assert!(!command_allowed(b"axb", &mid));
        assert!(!command_allowed(b"ab", &mid));
        let any = s(&["*"]);
        assert!(command_allowed(b"rm -rf /", &any));
        assert!(command_allowed(b"", &any));
        let sfx = s(&["cmd *"]);
        assert!(command_allowed(b"cmd a; rm -rf /", &sfx));
    }

    #[test]
    fn include_adversarial() {
        let allow = s(&["/var/www/app"]);
        assert!(include_allowed(b"/var/www/app", &allow));
        assert!(include_allowed(b"/var/www/app/", &allow));
        assert!(include_allowed(b"/var/www/./app//x.php", &allow));
        assert!(!include_allowed(b"var/www/app/x.php", &allow));
        assert!(!include_allowed(b"", &allow));
        assert!(!include_allowed(b"/var/www/app/x.php", &[]));
    }

    #[test]
    fn unserialize_adversarial() {
        let r = unserialize_classes(b"O:9999999999:\"A\":0:{}");
        assert_eq!(r.classes, vec!["A".to_string()]);
        assert!(!r.capped);
        assert!(unserialize_classes(b"O:5:\"").classes.is_empty());
        assert!(unserialize_classes(b"O:").classes.is_empty());
        assert!(unserialize_classes(b"O:99999999999999999999:\"A\"").classes.is_empty());
        let mut long = b"O:400:\"".to_vec();
        long.extend(std::iter::repeat(b'a').take(400));
        long.extend_from_slice(b"\":0:{}");
        let r = unserialize_classes(&long);
        assert_eq!(r.classes.len(), 1);
        assert_eq!(r.classes[0].len(), MAX_CLASS_NAME);
    }

    #[test]
    fn unserialize_cap_sets_capped() {
        let mut p = Vec::new();
        for _ in 0..MAX_CLASSES {
            p.extend_from_slice(b"O:1:\"A\":0:{}");
        }
        let r = unserialize_classes(&p);
        assert_eq!(r.classes.len(), MAX_CLASSES);
        assert!(!r.capped);
        p.extend_from_slice(b"O:1:\"B\":0:{}");
        let r = unserialize_classes(&p);
        assert_eq!(r.classes.len(), MAX_CLASSES);
        assert!(r.capped);
    }

    #[test]
    fn unserialize_scan_is_bounded() {
        let mut big = Vec::new();
        while big.len() < 4 * 1024 * 1024 {
            big.extend_from_slice(b"O:1:\"A\":0:{}");
        }
        let t = std::time::Instant::now();
        let r = unserialize_classes(&big);
        assert!(t.elapsed().as_secs() < 5);
        assert!(r.classes.len() <= MAX_CLASSES);
        assert!(r.has_classes());
        assert!(r.capped);
    }
}

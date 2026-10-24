//! Layer-3 legacy-era sink policy: the cheap checks behind the `mail`,
//! `preg_eval`, `create_function`, `assert`, `callback`, `xml` and `tls`
//! sinks. Most of these guard functions or behaviours PHP removed in 7.0 or
//! 8.0; they matter on the 5.x/7.x third of the web Howdah exists for and are
//! inert where the function no longer exists.
//!
//! Same rules as the rest of `sinks`: pure, hand-written, linear-time,
//! bounded, no regex, no filesystem. Each function answers "does this
//! argument have the dangerous shape?" and returns a fixed reason string that
//! never embeds the argument. The caller resolves the outcome against the
//! configured mode.

/// Longest prefix of an XML document the external-entity scan looks at. The
/// DOCTYPE (where entity declarations live) must precede the root element, so
/// nothing past the first element start is ever read; this cap bounds a
/// document that never opens one.
pub const XML_SCAN_MAX: usize = 64 * 1024;

/// Reason strings (fixed; never carry argument bytes).
pub const REASON_MAIL_PARAMS: &str =
    "mail(): sendmail option other than -f<address> in additional_parameters";
pub const REASON_MAIL_HEADERS: &str =
    "mail(): line break not followed by a header in additional_headers";
pub const REASON_PREG_EVAL: &str = "preg pattern with the /e modifier (code evaluation)";
pub const REASON_XXE: &str = "XML document declares an external entity";
pub const REASON_XXE_DTD: &str = "XML document references an external DTD";
pub const REASON_TLS_PEER: &str = "CURLOPT_SSL_VERIFYPEER disabled";
pub const REASON_TLS_HOST: &str = "CURLOPT_SSL_VERIFYHOST set to 0";

/// True iff `b` may appear in a sendmail `-f` envelope sender: the usual
/// address characters and nothing a shell or sendmail option parser cares
/// about (no quotes, spaces, backslashes, `<>`, `;`, `|`, `$`, backticks).
fn is_addr_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'%' | b'+' | b'-' | b'@' | b'=')
}

/// A sane envelope-sender shape: non-empty, 1 to 254 bytes, address bytes
/// only, exactly one `@` that is neither first nor last.
fn sane_address(a: &[u8]) -> bool {
    if a.is_empty() || a.len() > 254 || !a.iter().all(|&b| is_addr_byte(b)) {
        return false;
    }
    let ats = a.iter().filter(|&&b| b == b'@').count();
    ats == 1 && a[0] != b'@' && a[a.len() - 1] != b'@'
}

/// `mail()` 5th argument (`additional_parameters`, passed to the sendmail
/// command line). Returns a reason when it carries anything other than
/// `-f<address>` / `-f <address>` (or Postfix's alias `-r`) with a sane
/// address: any other `-X` option (`-O`, `-C`, `-X`, `-bq`, and also the
/// benign-looking `-oi` / `-t`, which are expected detect noise), a quoted or
/// malformed address, or a stray token that is not an option.
/// Whitespace-separated; an empty value is fine.
pub fn mail_params_hit(params: &[u8]) -> Option<&'static str> {
    let mut toks = params.split(|&b| b == b' ' || b == b'\t').filter(|t| !t.is_empty());
    while let Some(t) = toks.next() {
        let Some(rest) = t.strip_prefix(b"-") else {
            return Some(REASON_MAIL_PARAMS); // a bare token: not an option at all
        };
        let Some(addr) = rest.strip_prefix(b"f").or_else(|| rest.strip_prefix(b"r")) else {
            return Some(REASON_MAIL_PARAMS); // any option other than -f / -r
        };
        let addr: &[u8] = if addr.is_empty() {
            match toks.next() {
                Some(a) => a,
                None => return Some(REASON_MAIL_PARAMS), // "-f" with nothing after it
            }
        } else {
            addr
        };
        if !sane_address(addr) {
            return Some(REASON_MAIL_PARAMS);
        }
    }
    None
}

fn is_header_name_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'_'
}

/// `mail()` 4th argument (`additional_headers`, a string). Returns a reason
/// when a CR or LF is followed by something that is not a header: an empty
/// line (which ends the headers and starts an injected body), a line that
/// does not start with `name:` (RFC 5322 folding, a leading space or tab, is
/// allowed). A trailing line break is fine. `Bcc:`-style injected headers are
/// NOT flagged here: they look like headers, and PHP itself accepts extra
/// headers; this rule is about the body/command-injection shape. An argument
/// without CR/LF never matches.
pub fn mail_headers_hit(headers: &[u8]) -> Option<&'static str> {
    let n = headers.len();
    let mut i = 0;
    while i < n {
        let b = headers[i];
        if b != b'\r' && b != b'\n' {
            i += 1;
            continue;
        }
        // Consume one line break (\r\n, \n or a bare \r).
        i += 1;
        if b == b'\r' && i < n && headers[i] == b'\n' {
            i += 1;
        }
        if i == n {
            return None; // trailing break
        }
        let next = headers[i];
        if next == b'\r' || next == b'\n' {
            return Some(REASON_MAIL_HEADERS); // blank line: body injection
        }
        if next == b' ' || next == b'\t' {
            continue; // folded continuation
        }
        // Must be a header name followed by ':'.
        let mut j = i;
        while j < n && is_header_name_byte(headers[j]) {
            j += 1;
        }
        if j == i || j >= n || headers[j] != b':' {
            return Some(REASON_MAIL_HEADERS);
        }
        i = j + 1;
    }
    None
}

/// True iff a PCRE pattern string (`<delim>...<delim><modifiers>`) carries
/// the `e` modifier (PHP 5.x evaluates the replacement as code; removed in
/// 7.0). Mirrors PHP's delimiter rules: leading whitespace skipped, the
/// delimiter is the first byte (not alphanumeric or backslash), bracket
/// delimiters pair with their closing bracket, the modifiers follow the LAST
/// closing delimiter. A string that does not parse as a pattern is false
/// (PHP would reject it anyway).
pub fn preg_pattern_has_e(pattern: &[u8]) -> bool {
    let mut i = 0;
    while i < pattern.len() && pattern[i].is_ascii_whitespace() {
        i += 1;
    }
    if i >= pattern.len() {
        return false;
    }
    let open = pattern[i];
    if open.is_ascii_alphanumeric() || open == b'\\' {
        return false;
    }
    let close = match open {
        b'(' => b')',
        b'[' => b']',
        b'{' => b'}',
        b'<' => b'>',
        d => d,
    };
    let end = match pattern.iter().rposition(|&b| b == close) {
        Some(e) if e > i => e,
        _ => return false,
    };
    pattern[end + 1..].contains(&b'e')
}

/// The command/code-execution functions a string callback may name. Lowercase.
const DANGEROUS_CALLBACKS: &[&str] = &[
    "system",
    "exec",
    "passthru",
    "shell_exec",
    "popen",
    "proc_open",
    "pcntl_exec",
    "assert",
    "create_function",
];

/// Longest name in `DANGEROUS_CALLBACKS` plus a leading backslash; a cheap
/// prefilter for callers that want to skip longer strings.
pub const MAX_DANGEROUS_CALLBACK_LEN: usize = 16;

/// If `cb` (a string callback as passed to `call_user_func`, `array_map`,
/// ...) names a command/code-execution function, return its canonical
/// lowercase name (a static string, safe to log). A leading `\` is ignored
/// and the comparison is ASCII-case-insensitive, as PHP's function lookup
/// is. `Class::method` strings, closures and arrays are not callbacks this
/// function sees, and never match.
pub fn dangerous_callback(cb: &[u8]) -> Option<&'static str> {
    let cb = cb.strip_prefix(b"\\").unwrap_or(cb);
    if cb.is_empty() || cb.len() > MAX_DANGEROUS_CALLBACK_LEN {
        return None;
    }
    DANGEROUS_CALLBACKS
        .iter()
        .copied()
        .find(|name| name.as_bytes().eq_ignore_ascii_case(cb))
}

/// True iff `hay[at..]` starts with `needle`.
fn starts_at(hay: &[u8], at: usize, needle: &[u8]) -> bool {
    hay.len() >= at + needle.len() && &hay[at..at + needle.len()] == needle
}

/// What the XML prolog scan found. The reason is fixed text (never document
/// bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XxeHit {
    pub reason: &'static str,
    /// True when an `<!ENTITY ... SYSTEM|PUBLIC ...>` (general or parameter
    /// entity) is declared: the shape worth refusing. False for a bare
    /// external DTD reference in the DOCTYPE (`SYSTEM`/`PUBLIC` with no
    /// external entity), which standard XHTML and SVG documents carry and
    /// which is therefore reported for detect only, never blocked.
    pub external_entity: bool,
}

/// True iff the bytes look like UTF-16 (a BOM, or a NUL-interleaved `<?`),
/// in which case libxml would decode them while a byte scan would see NULs
/// between every character.
fn utf16_shape(doc: &[u8]) -> bool {
    doc.starts_with(&[0xFF, 0xFE])
        || doc.starts_with(&[0xFE, 0xFF])
        || doc.starts_with(b"<\0?\0")
        || doc.starts_with(b"\0<\0?")
}

/// Bounded scan of an XML document's prolog for an external DTD or an
/// external entity declaration: a `<!DOCTYPE` whose declaration (before the
/// `[` internal subset or the closing `>`) carries `SYSTEM`/`PUBLIC`
/// (`external_entity: false`), or an `<!ENTITY ... SYSTEM|PUBLIC ...>` inside
/// the internal subset (`external_entity: true`, reported in preference). The
/// keywords are case-sensitive, as in the XML spec. Comments and processing
/// instructions are skipped both before the DOCTYPE and inside the internal
/// subset (a `]` inside one does not end the subset). A UTF-16 document (BOM
/// or NUL-interleaved `<?`) has its NULs squeezed out of the scanned prefix
/// first. The scan stops at the first element start (`<` followed by a name
/// byte) or after `XML_SCAN_MAX` bytes, so a large document with no DOCTYPE
/// costs nothing past its prolog. The document is never logged. Whether PHP
/// would actually fetch the entity depends on the parser options
/// (`LIBXML_NOENT`, `LIBXML_DTDLOAD`) and the libxml version: this is the
/// attempt shape.
pub fn xml_external_entity_hit(doc: &[u8]) -> Option<XxeHit> {
    let head = &doc[..doc.len().min(XML_SCAN_MAX)];
    if utf16_shape(head) {
        let squeezed: Vec<u8> = head.iter().copied().filter(|&b| b != 0).collect();
        return scan_prolog(&squeezed);
    }
    scan_prolog(head)
}

/// Advance past a comment (`<!-- ... -->`) or processing instruction
/// (`<? ... ?>`) starting at `i`, if one starts there; returns the new index
/// (unchanged when neither starts at `i`). An unterminated one runs to the
/// end of the scanned bytes.
fn skip_comment_or_pi(doc: &[u8], i: usize) -> usize {
    let n = doc.len();
    if starts_at(doc, i, b"<!--") {
        let mut j = i + 4;
        while j + 2 < n && !starts_at(doc, j, b"-->") {
            j += 1;
        }
        return (j + 3).min(n);
    }
    if starts_at(doc, i, b"<?") {
        let mut j = i + 2;
        while j + 1 < n && !starts_at(doc, j, b"?>") {
            j += 1;
        }
        return (j + 2).min(n);
    }
    i
}

fn scan_prolog(doc: &[u8]) -> Option<XxeHit> {
    const DOCTYPE: &[u8] = b"<!DOCTYPE";
    const ENTITY: &[u8] = b"<!ENTITY";
    let n = doc.len();
    // Find the DOCTYPE, skipping comments and processing instructions.
    let mut i = 0;
    let mut dt = None;
    while i < n {
        if doc[i] != b'<' {
            i += 1;
            continue;
        }
        if starts_at(doc, i, DOCTYPE) {
            dt = Some(i + DOCTYPE.len());
            break;
        }
        let skipped = skip_comment_or_pi(doc, i);
        if skipped != i {
            i = skipped;
            continue;
        }
        // Any other markup before a DOCTYPE is the root element: no DOCTYPE.
        return None;
    }
    let mut i = dt?;
    // The doctype declaration up to '[' or '>'.
    let mut has_subset = false;
    let decl_start = i;
    while i < n && doc[i] != b'>' && doc[i] != b'[' {
        i += 1;
    }
    if i < n && doc[i] == b'[' {
        has_subset = true;
    }
    let decl = &doc[decl_start..i];
    let external_dtd = contains_keyword(decl, b"SYSTEM") || contains_keyword(decl, b"PUBLIC");
    if has_subset {
        // Internal subset: each <!ENTITY ...> declaration until the ']' that
        // closes the subset; a ']' inside a comment or PI does not count.
        i += 1;
        while i < n && doc[i] != b']' {
            let skipped = skip_comment_or_pi(doc, i);
            if skipped != i {
                i = skipped;
                continue;
            }
            if starts_at(doc, i, ENTITY) {
                let start = i + ENTITY.len();
                let mut j = start;
                while j < n && doc[j] != b'>' {
                    j += 1;
                }
                let body = &doc[start..j];
                if contains_keyword(body, b"SYSTEM") || contains_keyword(body, b"PUBLIC") {
                    return Some(XxeHit { reason: REASON_XXE, external_entity: true });
                }
                i = j;
            }
            i += 1;
        }
    }
    external_dtd.then_some(XxeHit { reason: REASON_XXE_DTD, external_entity: false })
}

/// `kw` as a whole whitespace-delimited word outside quoted literals (a
/// `SYSTEM`/`PUBLIC` keyword in a declaration is always followed by a quoted
/// identifier; one inside quotes is just a value).
fn contains_keyword(hay: &[u8], kw: &[u8]) -> bool {
    let n = hay.len();
    let mut i = 0;
    while i < n {
        let b = hay[i];
        if b == b'"' || b == b'\'' {
            // Skip the quoted literal (to the matching quote or the end).
            i += 1;
            while i < n && hay[i] != b {
                i += 1;
            }
            i += 1;
            continue;
        }
        if i + kw.len() <= n
            && &hay[i..i + kw.len()] == kw
            && (i == 0 || hay[i - 1].is_ascii_whitespace())
            && (i + kw.len() == n || hay[i + kw.len()].is_ascii_whitespace())
        {
            return true;
        }
        i += 1;
    }
    false
}

/// Which curl TLS verification option a `tls` sink hit names. The C shim
/// passes one of these tokens (not the URL, not the handle).
pub fn tls_reason(option: &[u8]) -> Option<&'static str> {
    match option {
        b"verifypeer" => Some(REASON_TLS_PEER),
        b"verifyhost" => Some(REASON_TLS_HOST),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mail_params_f_address_is_fine() {
        assert_eq!(mail_params_hit(b""), None);
        assert_eq!(mail_params_hit(b"-fbounce@example.com"), None);
        assert_eq!(mail_params_hit(b"-f bounce@example.com"), None);
        assert_eq!(mail_params_hit(b"  -fno-reply+tag@sub.example.co.uk  "), None);
        // Postfix's -r alias of -f.
        assert_eq!(mail_params_hit(b"-rbounce@example.com"), None);
        assert_eq!(mail_params_hit(b"-r bounce@example.com"), None);
    }

    #[test]
    fn mail_params_other_options_hit() {
        // Representative shapes only: any option letter other than f, a bare
        // token, a quoted or malformed address, an empty -f.
        for p in [
            &b"-Oopt=x"[..],
            b"-X/tmp/f",
            b"-C/tmp/cf",
            b"-bq",
            b"-fa@b.c -Oopt=x",
            b"plain",
            b"-f",
            b"-f\"a@b.c\"",
            b"-fa@b.c;x",
            b"-fnoat",
            b"-f@b.c",
            b"-fa@",
            b"-fa@b@c",
            // Benign-looking but not -f/-r: expected detect noise, documented.
            b"-oi",
            b"-t",
            b"-oi -fa@b.c",
            b"-r",
            b"-rnoat",
        ] {
            assert_eq!(mail_params_hit(p), Some(REASON_MAIL_PARAMS), "{p:?}");
        }
    }

    #[test]
    fn mail_headers_headers_are_fine() {
        assert_eq!(mail_headers_hit(b""), None);
        assert_eq!(mail_headers_hit(b"From: a@b.c"), None);
        assert_eq!(mail_headers_hit(b"From: a@b.c\r\nReply-To: x@y.z\r\n"), None);
        assert_eq!(mail_headers_hit(b"From: a@b.c\nX-Mailer: app\n"), None);
        assert_eq!(mail_headers_hit(b"Subject: a\r\n folded\r\n\tmore"), None);
        assert_eq!(mail_headers_hit(b"Content-Type: text/plain\r\n"), None);
    }

    #[test]
    fn mail_headers_break_not_followed_by_header_hits() {
        for h in [
            &b"From: a@b.c\r\n\r\nbody"[..],
            b"From: a@b.c\n\ntext",
            b"From: a@b.c\r\nnot a header",
            b"From: a@b.c\r\n: empty name",
            b"From: a@b.c\r\nname only",
            b"From: a@b.c\rtext",
            b"From: a@b.c\r\n\n",
        ] {
            assert_eq!(mail_headers_hit(h), Some(REASON_MAIL_HEADERS), "{h:?}");
        }
    }

    #[test]
    fn preg_e_modifier_detected_by_delimiter() {
        assert!(preg_pattern_has_e(b"/a/e"));
        assert!(preg_pattern_has_e(b"/a/ie"));
        assert!(preg_pattern_has_e(b"  #a/b#e"));
        assert!(preg_pattern_has_e(b"(a)e"));
        assert!(preg_pattern_has_e(b"[a]ei"));
        assert!(preg_pattern_has_e(b"{a}e"));
        assert!(preg_pattern_has_e(b"<a>e"));
        assert!(preg_pattern_has_e(b"/a\\/e/e"));
        assert!(!preg_pattern_has_e(b"/a/i"));
        assert!(!preg_pattern_has_e(b"/e/"));
        assert!(!preg_pattern_has_e(b"/e/i"));
        assert!(!preg_pattern_has_e(b"(e)"));
        assert!(!preg_pattern_has_e(b"abc"));
        assert!(!preg_pattern_has_e(b""));
        assert!(!preg_pattern_has_e(b"/"));
        assert!(!preg_pattern_has_e(b"\\a\\e"));
    }

    #[test]
    fn dangerous_callback_names() {
        assert_eq!(dangerous_callback(b"system"), Some("system"));
        assert_eq!(dangerous_callback(b"\\system"), Some("system"));
        assert_eq!(dangerous_callback(b"SyStEm"), Some("system"));
        assert_eq!(dangerous_callback(b"shell_exec"), Some("shell_exec"));
        assert_eq!(dangerous_callback(b"create_function"), Some("create_function"));
        assert_eq!(dangerous_callback(b"assert"), Some("assert"));
        assert_eq!(dangerous_callback(b"proc_open"), Some("proc_open"));
        for benign in [
            &b"trim"[..],
            b"strtoupper",
            b"",
            b"systems",
            b"system ",
            b"Foo::system",
            b"\\\\system",
            b"eval",
            b"a_very_long_callback_name_here",
        ] {
            assert_eq!(dangerous_callback(benign), None, "{benign:?}");
        }
        for n in DANGEROUS_CALLBACKS {
            assert!(n.len() < MAX_DANGEROUS_CALLBACK_LEN, "{n}");
        }
    }

    /// `Some(true)` = external entity (blockable), `Some(false)` = bare
    /// external DTD (detect only), `None` = clean.
    fn xxe(doc: &[u8]) -> Option<bool> {
        xml_external_entity_hit(doc).map(|h| {
            assert_eq!(h.reason, if h.external_entity { REASON_XXE } else { REASON_XXE_DTD });
            h.external_entity
        })
    }

    #[test]
    fn xml_external_entity_shapes() {
        assert_eq!(xxe(b"<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY x SYSTEM \"file:///x\">]><r>&x;</r>"), Some(true));
        assert_eq!(xxe(b"<!DOCTYPE r [ <!ENTITY % p PUBLIC \"id\" \"http://h/d\"> ]><r/>"), Some(true));
        assert_eq!(xxe(b"<!-- c --><?pi x?><!DOCTYPE r[<!ENTITY a SYSTEM 'f'>]><r/>"), Some(true));
        assert_eq!(xxe(b"<!DOCTYPE r [<!ENTITY x SYSTEM"), Some(true));
        // External DTD + external entity: the entity wins (blockable).
        assert_eq!(xxe(b"<!DOCTYPE r SYSTEM \"r.dtd\" [<!ENTITY x SYSTEM \"f\">]><r/>"), Some(true));
        // A bare external DTD (XHTML/SVG doctypes): detect only.
        assert_eq!(xxe(b"<!DOCTYPE r SYSTEM \"http://h/r.dtd\"><r/>"), Some(false));
        assert_eq!(xxe(b"<!DOCTYPE r PUBLIC \"-//x//\" \"r.dtd\"><r/>"), Some(false));
        assert_eq!(
            xxe(b"<!DOCTYPE svg PUBLIC \"-//W3C//DTD SVG 1.1//EN\" \"http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd\"><svg/>"),
            Some(false)
        );
        assert_eq!(xxe(b"<!DOCTYPE r SYSTEM \"r.dtd\" [<!ENTITY x \"v\">]><r/>"), Some(false));
        // Benign: no DOCTYPE, an internal entity only, keywords in content.
        assert_eq!(xxe(b"<?xml version=\"1.0\"?><r>SYSTEM PUBLIC</r>"), None);
        assert_eq!(xxe(b"<!DOCTYPE r [<!ENTITY x \"v\">]><r>&x;</r>"), None);
        assert_eq!(xxe(b"<!DOCTYPE r><r/>"), None);
        assert_eq!(xxe(b"<r><!DOCTYPE r SYSTEM \"x\"></r>"), None);
        assert_eq!(xxe(b"<!DOCTYPE r [<!ENTITY x \"SYSTEM\">]><r/>"), None);
        assert_eq!(xxe(b"<!DOCTYPE r [<!ENTITY system \"v\">]><r/>"), None);
        assert_eq!(xxe(b""), None);
        assert_eq!(xxe(b"<!DOCTYPE"), None);
        assert_eq!(xxe(b"<!--"), None);
    }

    #[test]
    fn xml_subset_comment_or_pi_does_not_end_the_subset() {
        // A ']' inside a comment or PI in the internal subset used to stop the
        // scan before the entity declaration.
        assert_eq!(xxe(b"<!DOCTYPE r [<!-- ] --><!ENTITY x SYSTEM \"f\">]><r/>"), Some(true));
        assert_eq!(xxe(b"<!DOCTYPE r [<?pi ] ?><!ENTITY x SYSTEM \"f\">]><r/>"), Some(true));
        assert_eq!(xxe(b"<!DOCTYPE r [<!-- <!ENTITY x SYSTEM \"f\"> --><!ENTITY y \"v\">]><r/>"), None);
        assert_eq!(xxe(b"<!DOCTYPE r [<!-- unterminated <!ENTITY x SYSTEM \"f\">"), None);
    }

    #[test]
    fn xml_utf16_document_is_squeezed_before_scanning() {
        let text = "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY x SYSTEM \"file:///x\">]><r>&x;</r>";
        // UTF-16LE with BOM.
        let mut le = vec![0xFF, 0xFE];
        for u in text.encode_utf16() {
            le.extend_from_slice(&u.to_le_bytes());
        }
        assert_eq!(xxe(&le), Some(true));
        // UTF-16BE with BOM.
        let mut be = vec![0xFE, 0xFF];
        for u in text.encode_utf16() {
            be.extend_from_slice(&u.to_be_bytes());
        }
        assert_eq!(xxe(&be), Some(true));
        // No BOM, NUL-interleaved `<?` in either byte order.
        let le_nobom: Vec<u8> = le[2..].to_vec();
        assert!(le_nobom.starts_with(b"<\0?\0"));
        assert_eq!(xxe(&le_nobom), Some(true));
        let be_nobom: Vec<u8> = be[2..].to_vec();
        assert!(be_nobom.starts_with(b"\0<\0?"));
        assert_eq!(xxe(&be_nobom), Some(true));
        // A clean UTF-16 document stays clean; an 8-bit document with stray
        // NULs is not treated as UTF-16.
        let mut clean = vec![0xFF, 0xFE];
        for u in "<?xml version=\"1.0\"?><r/>".encode_utf16() {
            clean.extend_from_slice(&u.to_le_bytes());
        }
        assert_eq!(xxe(&clean), None);
        assert_eq!(xxe(b"<r>\0</r>"), None);
    }

    #[test]
    fn xml_scan_is_bounded() {
        let mut big = b"<r>".to_vec();
        big.resize(8 * 1024 * 1024, b'a');
        let t = std::time::Instant::now();
        assert_eq!(xml_external_entity_hit(&big), None);
        assert!(t.elapsed().as_millis() < 500);
        // A DOCTYPE past the cap is not seen (documented bound).
        let mut late = vec![b' '; XML_SCAN_MAX + 10];
        late.extend_from_slice(b"<!DOCTYPE r SYSTEM \"x\"><r/>");
        assert_eq!(xml_external_entity_hit(&late), None);
    }

    #[test]
    fn tls_reasons() {
        assert_eq!(tls_reason(b"verifypeer"), Some(REASON_TLS_PEER));
        assert_eq!(tls_reason(b"verifyhost"), Some(REASON_TLS_HOST));
        assert_eq!(tls_reason(b"other"), None);
    }

    #[test]
    fn reasons_never_embed_arguments() {
        for r in [
            REASON_MAIL_PARAMS,
            REASON_MAIL_HEADERS,
            REASON_PREG_EVAL,
            REASON_XXE,
            REASON_XXE_DTD,
            REASON_TLS_PEER,
            REASON_TLS_HOST,
        ] {
            assert!(!r.contains("{}") && !r.contains('\n'));
        }
    }
}

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
/// document that never opens one. A prolog that is still open at the cap (a
/// DOCTYPE pushed out of the window with a megabyte of comment) is reported,
/// not waved through: see `XxeKind::Unscannable`.
pub const XML_SCAN_MAX: usize = 1024 * 1024;

/// libxml parser option bits (PHP's `LIBXML_*` constants) that let a parse
/// act on a document's entity and DTD declarations.
pub(crate) const LIBXML_NOENT: i64 = 2;
pub(crate) const LIBXML_DTDLOAD: i64 = 4;
pub(crate) const LIBXML_DTDATTR: i64 = 8;
pub(crate) const LIBXML_DTDVALID: i64 = 16;
/// The flags that make an external entity or an entity bomb live: `NOENT`
/// substitutes entities, `DTDLOAD`/`DTDATTR` fetch the external DTD (whose
/// parameter entities can read files and call out), `DTDVALID` loads external
/// entities for validation. Without any of them libxml 2.9+ neither expands
/// nor fetches what a DOCTYPE declares.
pub(crate) const XML_DANGEROUS_FLAGS: i64 = LIBXML_NOENT | LIBXML_DTDLOAD | LIBXML_DTDATTR | LIBXML_DTDVALID;
/// What actually fetches an external DTD reference.
const XML_DTD_FETCH_FLAGS: i64 = LIBXML_DTDLOAD | LIBXML_DTDATTR;

/// Entity declarations the bomb check evaluates, and the expansion (bytes) at
/// which a declaration chain counts as a bomb. A billion-laughs chain expands
/// to gigabytes from a few hundred bytes; honest documents declare a handful
/// of short entities.
const XML_BOMB_MAX_ENTITIES: usize = 128;
const XML_BOMB_EXPANSION: u64 = 1 << 20;

/// Reason strings (fixed; never carry argument bytes).
pub const REASON_MAIL_PARAMS: &str =
    "mail(): sendmail option other than -f<address> in additional_parameters";
pub const REASON_MAIL_HEADERS: &str =
    "mail(): line break not followed by a header in additional_headers";
pub const REASON_PREG_EVAL: &str = "preg pattern with the /e modifier (code evaluation)";
pub const REASON_XXE: &str = "XML document declares an external entity";
pub const REASON_XXE_BOMB: &str = "XML document declares nested entities that expand past 1 MiB";
pub const REASON_XXE_DTD: &str = "XML document references an external DTD";
pub const REASON_XXE_ENCODING: &str = "XML document is in an encoding that hides its DOCTYPE from inspection";
pub const REASON_XXE_LONG_PROLOG: &str = "XML prolog is longer than the inspection window";
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

/// The shape the XML prolog scan found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XxeKind {
    /// An `<!ENTITY ... SYSTEM|PUBLIC ...>` (general or parameter entity) is
    /// declared: the shape worth refusing when a dangerous flag is on.
    ExternalEntity,
    /// Internal entities whose nested references expand past
    /// `XML_BOMB_EXPANSION` bytes (billion laughs and its variants).
    EntityBomb,
    /// A bare external DTD reference in the DOCTYPE (`SYSTEM`/`PUBLIC` with no
    /// external entity), which standard XHTML, SVG, SAML and Office XML carry:
    /// reported for detect only, never blocked.
    ExternalDtd,
    /// A document the scan cannot read: an encoding that hides the DOCTYPE from
    /// an ASCII scan (UTF-7, EBCDIC) or a prolog longer than the inspection
    /// window. Treated like an external entity: with a dangerous flag set, the
    /// document cannot be shown to be safe.
    Unscannable,
}

/// What the XML prolog scan found. The reason is fixed text (never document
/// bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XxeHit {
    pub reason: &'static str,
    pub kind: XxeKind,
}

impl XxeHit {
    /// True for the shapes worth refusing (an external entity or an entity
    /// bomb); false for the bare external DTD, which only ever logs.
    pub fn is_attack(&self) -> bool {
        self.kind != XxeKind::ExternalDtd
    }
}

/// True iff the bytes look like a wide-character document (UTF-16 or UCS-4 /
/// UTF-32, any byte order: a BOM, or a NUL-interleaved `<`), which libxml
/// decodes while a byte scan would see NULs between every character.
fn wide_shape(doc: &[u8]) -> bool {
    doc.starts_with(&[0xFF, 0xFE])
        || doc.starts_with(&[0xFE, 0xFF])
        || doc.starts_with(&[0x00, 0x00, 0xFE, 0xFF])
        || doc.starts_with(b"<\0?\0")
        || doc.starts_with(b"\0<\0?")
        || doc.starts_with(b"<\0\0\0")
        || doc.starts_with(b"\0\0\0<")
        || doc.starts_with(b"\0\0<\0")
        || doc.starts_with(b"\0<\0\0")
}

/// The `encoding` named by the XML declaration at the start of `head`, if any
/// (after an optional UTF-8 BOM and whitespace).
fn declared_encoding(head: &[u8]) -> Option<&[u8]> {
    let n = head.len();
    let mut i = if head.starts_with(&[0xEF, 0xBB, 0xBF]) { 3 } else { 0 };
    while i < n && head[i].is_ascii_whitespace() {
        i += 1;
    }
    if !starts_at(head, i, b"<?xml") || !head.get(i + 5).is_some_and(|b| b.is_ascii_whitespace()) {
        return None;
    }
    let decl = &head[i..n.min(i + 512)];
    let end = decl.windows(2).position(|w| w == b"?>").unwrap_or(decl.len());
    let decl = &decl[..end];
    let at = decl.windows(8).position(|w| w == b"encoding")?;
    let mut j = at + 8;
    while j < decl.len() && decl[j].is_ascii_whitespace() {
        j += 1;
    }
    if decl.get(j) != Some(&b'=') {
        return None;
    }
    j += 1;
    while j < decl.len() && decl[j].is_ascii_whitespace() {
        j += 1;
    }
    let quote = *decl.get(j)?;
    if quote != b'"' && quote != b'\'' {
        return None;
    }
    let rest = &decl[j + 1..];
    let close = rest.iter().position(|&b| b == quote)?;
    Some(&rest[..close])
}

/// EBCDIC code pages libxml2 can decode through iconv (the `ibm037`/`cp1047`
/// family). EBCDIC is not ASCII-compatible: a DOCTYPE in it is invisible to a
/// byte scan.
const EBCDIC_CODE_PAGES: &[u32] = &[
    37, 273, 277, 278, 280, 284, 285, 290, 297, 420, 423, 424, 500, 838, 870, 871, 875, 880, 905, 918, 930, 933,
    935, 937, 939, 1025, 1026, 1047, 1097, 1112, 1122, 1123, 1130, 1132, 1137, 1140, 1141, 1142, 1143, 1144, 1145,
    1146, 1147, 1148, 1149, 1153, 1154, 1155, 1156, 1157, 1158, 1160, 1164, 1165, 1166, 1371, 1388, 1390, 1399,
];

/// True for an encoding name (ASCII case-insensitive) whose bytes an ASCII
/// scan cannot read: UTF-7 (`+ADw-` for `<`), EBCDIC code pages, and the wide
/// encodings (UTF-16/32, UCS-2/4) when the document itself is not wide-shaped,
/// i.e. libxml switches decoding in the middle of the document.
fn hidden_encoding_name(name: &[u8]) -> bool {
    let lower: Vec<u8> = name.iter().take(48).map(|b| b.to_ascii_lowercase()).collect();
    let s = lower.as_slice();
    if matches!(s, b"utf-7" | b"utf7" | b"unicode-1-1-utf-7" | b"csunicode11utf7") {
        return true;
    }
    for prefix in [&b"utf-16"[..], b"utf16", b"utf-32", b"utf32", b"ucs-2", b"ucs2", b"ucs-4", b"ucs4", b"unicode", b"csunicode", b"iso-10646", b"ebcdic", b"cp-ebcdic"] {
        if s.starts_with(prefix) {
            return true;
        }
    }
    // ibm037, cp037, ibm-037, ibm_037, csibm037
    let s = s.strip_prefix(b"cs").unwrap_or(s);
    for prefix in [&b"ibm"[..], b"cp"] {
        if let Some(rest) = s.strip_prefix(prefix) {
            let rest = rest.strip_prefix(b"-").or_else(|| rest.strip_prefix(b"_")).unwrap_or(rest);
            if !rest.is_empty() && rest.iter().all(u8::is_ascii_digit) {
                let page = rest.iter().fold(0u32, |a, d| a.saturating_mul(10).saturating_add(u32::from(d - b'0')));
                return EBCDIC_CODE_PAGES.contains(&page);
            }
        }
    }
    false
}

/// True iff the document's text is in an encoding the byte scan cannot read:
/// the EBCDIC `<?xm` signature libxml auto-detects, or a declared encoding that
/// `hidden_encoding_name` names. Evaluated on the raw (un-squeezed) head, and
/// only for documents that are not wide-shaped themselves.
fn hidden_encoding(head: &[u8]) -> bool {
    head.starts_with(&[0x4C, 0x6F, 0xA7, 0x94]) || declared_encoding(head).is_some_and(hidden_encoding_name)
}

/// Bounded scan of an XML document's prolog for an external DTD or an
/// external entity declaration: a `<!DOCTYPE` whose declaration (before the
/// `[` internal subset or the closing `>`) carries `SYSTEM`/`PUBLIC`
/// (`ExternalDtd`), or an `<!ENTITY ... SYSTEM|PUBLIC ...>` inside the internal
/// subset (`ExternalEntity`, reported in preference), including one a
/// parameter entity's literal declares and then expands (`<!ENTITY % p "<!ENTITY
/// x SYSTEM 'f'>"> %p;`, character references decoded). The keywords are
/// case-sensitive, as in the XML spec, and quoted literals (a `>` or `[` inside
/// the DOCTYPE's own system literal) are skipped, not parsed. Comments and
/// processing instructions are skipped both before the DOCTYPE and inside the
/// internal subset (a `]` inside one does not end the subset). A wide document
/// (UTF-16 or UTF-32, BOM or NUL-interleaved `<`) has its NULs squeezed out of
/// the scanned prefix first. The scan stops at the first element start (`<`
/// followed by a name byte), so a large document with no DOCTYPE costs nothing
/// past its prolog.
///
/// Two shapes are reported because the scan cannot see through them, not
/// because it saw an entity: a document in an encoding that hides its DOCTYPE
/// from an ASCII scan (`Unscannable`: UTF-7, EBCDIC, or a declared wide
/// encoding on an ASCII-looking document, which libxml honours mid-stream) and a
/// prolog longer than `XML_SCAN_MAX` that never reaches the root element
/// (padding with comments or whitespace to push the DOCTYPE out of the window).
/// The document is never logged. Whether PHP would actually fetch the entity
/// depends on the parser options (`LIBXML_NOENT`, `LIBXML_DTDLOAD`) and the
/// libxml version: this is the attempt shape.
pub fn xml_external_entity_hit(doc: &[u8]) -> Option<XxeHit> {
    let head = &doc[..doc.len().min(XML_SCAN_MAX)];
    let truncated = doc.len() > XML_SCAN_MAX;
    if wide_shape(head) {
        let squeezed: Vec<u8> = head.iter().copied().filter(|&b| b != 0).collect();
        return scan_prolog(&squeezed, truncated);
    }
    if hidden_encoding(head) {
        return Some(XxeHit { reason: REASON_XXE_ENCODING, kind: XxeKind::Unscannable });
    }
    scan_prolog(head, truncated)
}

/// The flag-aware verdict for one parse: `flags` is the libxml option mask
/// the call passes, `engine_ignores_flags` is true on libxml2 older than 2.9,
/// which resolves external entities whatever the flags say (the flags are then
/// treated as if `LIBXML_NOENT` were set). Nothing is reported unless a
/// dangerous flag coincides with an external entity or an entity bomb in the
/// document. A bare external DTD reference (every XHTML, SVG, SAML and Office
/// document carries one) is reported only when a flag actually fetches it
/// (`LIBXML_DTDLOAD`/`LIBXML_DTDATTR`), and is never an attack. A document
/// with a DOCTYPE and no external entity is clean whatever the flags.
pub fn xml_flag_aware_hit(doc: &[u8], flags: i64, engine_ignores_flags: bool) -> Option<XxeHit> {
    let effective = if engine_ignores_flags { flags | LIBXML_NOENT } else { flags };
    if effective & XML_DANGEROUS_FLAGS == 0 {
        return None;
    }
    let hit = xml_external_entity_hit(doc)?;
    match hit.kind {
        XxeKind::ExternalDtd if flags & XML_DTD_FETCH_FLAGS == 0 => None,
        _ => Some(hit),
    }
}

/// The dangerous flags set in `flags` (or implied by the engine), as a fixed
/// vocabulary for the log reason: never document bytes.
pub fn xml_flag_names(flags: i64, engine_ignores_flags: bool) -> String {
    if engine_ignores_flags {
        return "any flags on libxml before 2.9".to_string();
    }
    let mut names: Vec<&str> = Vec::new();
    for (bit, name) in [
        (LIBXML_NOENT, "NOENT"),
        (LIBXML_DTDLOAD, "DTDLOAD"),
        (LIBXML_DTDATTR, "DTDATTR"),
        (LIBXML_DTDVALID, "DTDVALID"),
    ] {
        if flags & bit != 0 {
            names.push(name);
        }
    }
    names.iter().map(|n| format!("LIBXML_{n}")).collect::<Vec<_>>().join("|")
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

fn scan_prolog(doc: &[u8], truncated: bool) -> Option<XxeHit> {
    const DOCTYPE: &[u8] = b"<!DOCTYPE";
    const ENTITY: &[u8] = b"<!ENTITY";
    let n = doc.len();
    // The prolog ran off the end of the scanned window without reaching the
    // root element (or the end of the DOCTYPE): with a document longer than the
    // window, what lies past it is unknown.
    let long_prolog = XxeHit { reason: REASON_XXE_LONG_PROLOG, kind: XxeKind::Unscannable };
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
    let Some(mut i) = dt else {
        return truncated.then_some(long_prolog);
    };
    // The doctype declaration up to '[' or '>'; a quoted literal (a system
    // identifier may contain either) is skipped whole.
    let decl_start = i;
    while i < n && doc[i] != b'>' && doc[i] != b'[' {
        if doc[i] == b'"' || doc[i] == b'\'' {
            let quote = doc[i];
            i += 1;
            while i < n && doc[i] != quote {
                i += 1;
            }
        }
        if i < n {
            i += 1;
        }
    }
    let mut ran_out = i >= n;
    let has_subset = i < n && doc[i] == b'[';
    let decl = &doc[decl_start..i.min(n)];
    let external_dtd = contains_keyword(decl, b"SYSTEM") || contains_keyword(decl, b"PUBLIC");
    let mut ents: Vec<(&[u8], &[u8])> = Vec::new();
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
                    return Some(XxeHit { reason: REASON_XXE, kind: XxeKind::ExternalEntity });
                }
                i = j;
                // An entity with an internal literal: a general entity is
                // remembered for the expansion check; a parameter entity whose
                // literal itself declares an external entity (and is expanded
                // as markup by a later `%name;`) is an external entity too.
                // Either way resume after the literal so a '>' inside it does
                // not end the declaration early.
                if let Some((param, name, value, end)) = internal_entity(doc, start) {
                    if param {
                        if literal_declares_external_entity(value) {
                            return Some(XxeHit { reason: REASON_XXE, kind: XxeKind::ExternalEntity });
                        }
                    } else if ents.len() < XML_BOMB_MAX_ENTITIES {
                        ents.push((name, value));
                    }
                    i = i.max(end);
                }
            }
            i += 1;
        }
        ran_out = i >= n;
    }
    if entity_expansion_exceeds(&ents, XML_BOMB_EXPANSION) {
        return Some(XxeHit { reason: REASON_XXE_BOMB, kind: XxeKind::EntityBomb });
    }
    if ran_out && truncated {
        return Some(long_prolog);
    }
    external_dtd.then_some(XxeHit { reason: REASON_XXE_DTD, kind: XxeKind::ExternalDtd })
}

/// The `name` and quoted literal of an entity declaration with an internal
/// value whose body starts at `start` (just past `<!ENTITY`), whether it is a
/// parameter entity (`%`), and the index of the literal's closing quote. `None`
/// for an external or malformed declaration, or a literal that never closes.
fn internal_entity(doc: &[u8], start: usize) -> Option<(bool, &[u8], &[u8], usize)> {
    let n = doc.len();
    let mut i = start;
    while i < n && doc[i].is_ascii_whitespace() {
        i += 1;
    }
    let param = i < n && doc[i] == b'%';
    if param {
        i += 1;
        while i < n && doc[i].is_ascii_whitespace() {
            i += 1;
        }
    }
    let name_start = i;
    while i < n && !doc[i].is_ascii_whitespace() && !matches!(doc[i], b'"' | b'\'' | b'>') {
        i += 1;
    }
    let name = &doc[name_start..i];
    while i < n && doc[i].is_ascii_whitespace() {
        i += 1;
    }
    if name.is_empty() || i >= n || !matches!(doc[i], b'"' | b'\'') {
        return None;
    }
    let quote = doc[i];
    let value_start = i + 1;
    let close = doc[value_start..].iter().position(|&b| b == quote)? + value_start;
    Some((param, name, &doc[value_start..close], close))
}

/// True iff a parameter entity's literal, once its character references are
/// decoded (`&#60;` and `&#x3c;` become `<`, as the parser does when it builds
/// a parameter entity's replacement text), contains an `<!ENTITY` declaration
/// with a `SYSTEM`/`PUBLIC` keyword. That is how an external entity hides from
/// a scan of the declarations: `<!ENTITY % p "<!ENTITY x SYSTEM 'f'>"> %p;`.
fn literal_declares_external_entity(value: &[u8]) -> bool {
    if !value.windows(2).any(|w| w == b"<!") && !value.windows(2).any(|w| w == b"&#") {
        return false;
    }
    let mut dec: Vec<u8> = Vec::with_capacity(value.len());
    let mut i = 0;
    while i < value.len() {
        if value[i] == b'&' && value.get(i + 1) == Some(&b'#') {
            let (radix, from) = match value.get(i + 2) {
                Some(b'x') | Some(b'X') => (16, i + 3),
                _ => (10, i + 2),
            };
            let digits = value[from..].iter().take(8).take_while(|b| b.is_ascii_hexdigit()).count();
            if value.get(from + digits) == Some(&b';') && digits > 0 {
                let code = std::str::from_utf8(&value[from..from + digits])
                    .ok()
                    .and_then(|s| u32::from_str_radix(s, radix).ok());
                if let Some(c) = code {
                    dec.push(if c < 128 { c as u8 } else { b'?' });
                    i = from + digits + 1;
                    continue;
                }
            }
        }
        dec.push(value[i]);
        i += 1;
    }
    let mut at = 0;
    while let Some(p) = dec[at..].windows(8).position(|w| w == b"<!ENTITY") {
        let start = at + p + 8;
        let end = dec[start..].iter().position(|&b| b == b'>').map_or(dec.len(), |e| start + e);
        let body = &dec[start..end];
        if contains_keyword(body, b"SYSTEM") || contains_keyword(body, b"PUBLIC") {
            return true;
        }
        at = start;
    }
    false
}

/// True iff some declared entity expands to at least `limit` bytes once the
/// entities its literal references are substituted (a billion-laughs chain, in
/// any declaration order). A character reference or an unknown/predefined
/// entity counts one byte. Sizes grow monotonically with each substitution
/// pass, so the pass count (one per declaration, which lets any chain reach its
/// full size) and every sum are bounded; a reference loop that multiplies is
/// reported, one that does not is not.
fn entity_expansion_exceeds(ents: &[(&[u8], &[u8])], limit: u64) -> bool {
    let n = ents.len();
    if n == 0 {
        return false;
    }
    // Per entity: bytes of literal text, and the entities its literal names.
    let mut base = vec![0u64; n];
    let mut refs: Vec<Vec<usize>> = vec![Vec::new(); n];
    for (k, (_, value)) in ents.iter().enumerate() {
        let v = *value;
        let mut i = 0;
        while i < v.len() {
            if v[i] == b'&' {
                if let Some(semi) = v[i + 1..].iter().take(64).position(|&b| b == b';') {
                    let name = &v[i + 1..i + 1 + semi];
                    match ents.iter().position(|(nm, _)| *nm == name) {
                        Some(idx) if !name.starts_with(b"#") => refs[k].push(idx),
                        _ => base[k] += 1,
                    }
                    i += semi + 2;
                    continue;
                }
            }
            base[k] += 1;
            i += 1;
        }
    }
    let mut size = base.clone();
    for _ in 0..n {
        if size.iter().any(|&s| s >= limit) {
            return true;
        }
        let mut next = base.clone();
        for (k, rs) in refs.iter().enumerate() {
            for &r in rs {
                next[k] = next[k].saturating_add(size[r]);
            }
        }
        if next == size {
            return false; // converged below the limit
        }
        size = next;
    }
    size.iter().any(|&s| s >= limit)
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

    /// `Some(true)` = attack shape (external entity or entity bomb, blockable
    /// with a dangerous flag), `Some(false)` = bare external DTD (detect
    /// only), `None` = clean.
    fn xxe(doc: &[u8]) -> Option<bool> {
        xml_external_entity_hit(doc).map(|h| {
            let want = match h.kind {
                XxeKind::ExternalEntity => REASON_XXE,
                XxeKind::EntityBomb => REASON_XXE_BOMB,
                XxeKind::ExternalDtd => REASON_XXE_DTD,
                XxeKind::Unscannable => h.reason,
            };
            assert_eq!(h.reason, want);
            h.is_attack()
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
        // A DOCTYPE past the window is not seen, so the padded prolog itself is
        // reported (fail closed; see xml_prolog_padding_...).
        let mut late = vec![b' '; XML_SCAN_MAX + 10];
        late.extend_from_slice(b"<!DOCTYPE r SYSTEM \"x\"><r/>");
        assert_eq!(xml_external_entity_hit(&late).unwrap().kind, XxeKind::Unscannable);
    }

    /// The documents an application legitimately parses: every one carries a
    /// DOCTYPE or internal entities, none declares an external entity.
    fn benign_xml_corpus() -> Vec<Vec<u8>> {
        let mut v: Vec<Vec<u8>> = [
            // No DOCTYPE at all: SOAP, Atom, OOXML parts, SAML, sitemaps.
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><r><a>1</a></r>",
            "<?xml version=\"1.0\"?><samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" ID=\"_x\" Version=\"2.0\"><saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"><saml:Issuer>idp</saml:Issuer></saml:Assertion></samlp:Response>",
            "<?xml version=\"1.0\" standalone=\"yes\"?><w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\"><w:body><w:p><w:r><w:t>SYSTEM PUBLIC</w:t></w:r></w:p></w:body></w:document>",
            // A bare DOCTYPE, with and without an internal subset.
            "<!DOCTYPE html><html><body>x</body></html>",
            "<?xml version=\"1.0\"?><!DOCTYPE note><note/>",
            "<?xml version=\"1.0\"?><!DOCTYPE note [<!ELEMENT note (#PCDATA)>]><note>hi</note>",
            // Internal entities, including short nested ones.
            "<?xml version=\"1.0\"?><!DOCTYPE d [<!ENTITY co \"ACME\"><!ENTITY addr \"1 Main St, &co;\"><!ENTITY sig \"&co; - &addr;\">]><d>&sig;</d>",
            "<!DOCTYPE r [<!ENTITY nbsp \"&#160;\"><!ENTITY copy \"&#169;\"><!ENTITY a \"x>y\">]><r>&nbsp;&copy;</r>",
            // Bare external DTDs: XHTML, SVG, RSS, plist, ODF.
            "<?xml version=\"1.0\"?><!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\"><html xmlns=\"http://www.w3.org/1999/xhtml\"><body/></html>",
            "<?xml version=\"1.0\"?><!DOCTYPE svg PUBLIC \"-//W3C//DTD SVG 1.1//EN\" \"http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd\"><svg xmlns=\"http://www.w3.org/2000/svg\"><rect/></svg>",
            "<?xml version=\"1.0\"?><!DOCTYPE rss PUBLIC \"-//Netscape Communications//DTD RSS 0.91//EN\" \"http://my.netscape.com/publish/formats/rss-0.91.dtd\"><rss version=\"0.91\"/>",
            "<?xml version=\"1.0\"?><!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\"><plist version=\"1.0\"><dict/></plist>",
            "<?xml version=\"1.0\"?><!DOCTYPE office:document PUBLIC \"-//OpenOffice.org//DTD OfficeDocument1.0//EN\" \"office.dtd\"><office:document xmlns:office=\"urn:oasis:names:tc:opendocument:xmlns:office:1.0\"/>",
            "<?xml version=\"1.0\"?><!DOCTYPE r SYSTEM \"r.dtd\" [<!ENTITY x \"internal\">]><r>&x;</r>",
        ]
        .iter()
        .map(|s| s.as_bytes().to_vec())
        .collect();
        // A UTF-16 SVG.
        let mut u16doc = vec![0xFF, 0xFE];
        for u in "<?xml version=\"1.0\"?><!DOCTYPE svg PUBLIC \"-//W3C//DTD SVG 1.1//EN\" \"svg11.dtd\"><svg/>".encode_utf16() {
            u16doc.extend_from_slice(&u.to_le_bytes());
        }
        v.push(u16doc);
        v
    }

    const XXE_DOC: &[u8] = b"<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY x SYSTEM \"file:///etc/passwd\">]><r>&x;</r>";

    #[test]
    fn xml_flag_aware_needs_a_dangerous_flag_and_an_external_entity() {
        // An external entity with no dangerous flag is not reported: libxml
        // 2.9+ neither expands nor fetches it.
        for flags in [0, 1, 32, 64, 128, 256, 1024, 2048, 8192, 16384, 65536, 1 << 19, 1 << 22] {
            assert_eq!(xml_flag_aware_hit(XXE_DOC, flags, false), None, "flags {flags}");
        }
        // Each dangerous flag, alone or mixed with benign ones, reports it.
        for flags in [2, 4, 8, 16, 2 | 4, 2 | 4 | 8, 2 | 16384, 4 | 256 | 2048, 8 | 1 << 19, 30, 31, 1 << 19 | 2] {
            let h = xml_flag_aware_hit(XXE_DOC, flags, false).unwrap_or_else(|| panic!("flags {flags}"));
            assert_eq!(h.kind, XxeKind::ExternalEntity);
            assert!(h.is_attack());
        }
        // A parameter entity (the out-of-band shape) is an external entity too.
        let oob = b"<!DOCTYPE r [<!ENTITY % d SYSTEM \"http://h/e.dtd\"> %d;]><r/>";
        assert!(xml_flag_aware_hit(oob, LIBXML_NOENT | LIBXML_DTDLOAD, false).is_some());
        assert_eq!(xml_flag_aware_hit(oob, 0, false), None);
        // libxml before 2.9 resolves external entities whatever the flags say.
        let h = xml_flag_aware_hit(XXE_DOC, 0, true).unwrap();
        assert!(h.is_attack());
        // ...but a document with no external entity is clean on every engine.
        assert_eq!(xml_flag_aware_hit(b"<!DOCTYPE r><r/>", 0, true), None);
        assert_eq!(xml_flag_aware_hit(b"<r/>", 30, true), None);
    }

    #[test]
    fn xml_flag_aware_bare_doctype_and_external_dtd_are_never_an_attack() {
        for doc in benign_xml_corpus() {
            for flags in [0i64, 2, 4, 8, 16, 30, 2 | 16384, 4 | 2048, 31, 1 << 19 | 6] {
                for ignores in [false, true] {
                    if let Some(h) = xml_flag_aware_hit(&doc, flags, ignores) {
                        assert_eq!(h.kind, XxeKind::ExternalDtd, "{flags} {ignores}: {:?}", String::from_utf8_lossy(&doc));
                        assert!(!h.is_attack());
                        // reported only when a flag really fetches the DTD
                        assert!(flags & (LIBXML_DTDLOAD | LIBXML_DTDATTR) != 0);
                    }
                }
            }
        }
        // The SVG doctype without DTDLOAD/DTDATTR is silent, with DTDLOAD it is a
        // detect-only log shape.
        let svg = b"<!DOCTYPE svg PUBLIC \"-//W3C//DTD SVG 1.1//EN\" \"http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd\"><svg/>";
        assert_eq!(xml_flag_aware_hit(svg, LIBXML_NOENT, false), None);
        assert_eq!(xml_flag_aware_hit(svg, 0, true), None);
        assert_eq!(xml_flag_aware_hit(svg, LIBXML_DTDLOAD, false).unwrap().kind, XxeKind::ExternalDtd);
    }

    #[test]
    fn xml_entity_bomb_shapes() {
        let bomb = |n: usize, fan: usize| -> Vec<u8> {
            // lol0 = "lol"; lolK = fan x &lol(K-1);
            let mut s = String::from("<?xml version=\"1.0\"?><!DOCTYPE lolz [<!ENTITY lol0 \"lol\">");
            for k in 1..=n {
                s.push_str(&format!("<!ENTITY lol{k} \"{}\">", format!("&lol{};", k - 1).repeat(fan)));
            }
            s.push_str(&format!("]><lolz>&lol{n};</lolz>"));
            s.into_bytes()
        };
        // The classic: ten levels of ten.
        assert_eq!(xxe(&bomb(9, 10)), Some(true));
        assert_eq!(xml_external_entity_hit(&bomb(9, 10)).unwrap().kind, XxeKind::EntityBomb);
        // Shallower and narrower variants that still pass 1 MiB.
        assert_eq!(xxe(&bomb(7, 10)), Some(true)); // 3 * 10^7
        assert_eq!(xxe(&bomb(20, 2)), Some(true)); // 3 * 2^20 = 3 MiB, smallest fan-out
        // A bomb that stays below 1 MiB is not one.
        assert_eq!(xxe(&bomb(4, 10)), None); // 3 * 10^4
        assert_eq!(xxe(&bomb(5, 10)), None); // 3 * 10^5
        // Declared in reverse order (a forward reference is legal XML).
        let rev = b"<!DOCTYPE r [<!ENTITY c \"&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;\"><!ENTITY b \"&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;\"><!ENTITY a \"&z;&z;&z;&z;&z;&z;&z;&z;&z;&z;\"><!ENTITY z \"&y;&y;&y;&y;&y;&y;&y;&y;&y;&y;\"><!ENTITY y \"&x;&x;&x;&x;&x;&x;&x;&x;&x;&x;\"><!ENTITY x \"&w;&w;&w;&w;&w;&w;&w;&w;&w;&w;\"><!ENTITY w \"aaaaaaaaaa\">]><r>&c;</r>";
        assert_eq!(xxe(rev), Some(true));
        // Quadratic shape: one wide level.
        let mut quad = String::from("<!DOCTYPE r [<!ENTITY a \"");
        quad.push_str(&"x".repeat(2000));
        quad.push_str("\"><!ENTITY b \"");
        quad.push_str(&"&a;".repeat(1000));
        quad.push_str("\">]><r>&b;</r>");
        assert_eq!(xxe(quad.as_bytes()), Some(true));
        // Nested but small, parameter entities, character references and
        // undeclared references do not count.
        assert_eq!(xxe(b"<!DOCTYPE r [<!ENTITY a \"x\"><!ENTITY b \"&a;&a;&a;\"><!ENTITY c \"&b;&b;&b;\">]><r/>"), None);
        assert_eq!(xxe(b"<!DOCTYPE r [<!ENTITY % p \"&#37;p;\"><!ENTITY a \"&#65;&#66;&gone;&amp;\">]><r/>"), None);
        // An external entity is reported as such, ahead of a bomb.
        let both = [&bomb(9, 10)[..bomb(9, 10).len() - 22], b"<!ENTITY e SYSTEM \"f\">]><r/>"].concat();
        assert_eq!(xml_external_entity_hit(&both).unwrap().kind, XxeKind::ExternalEntity);
        // Gated by flags like the external entity: no dangerous flag, no hit.
        assert_eq!(xml_flag_aware_hit(&bomb(9, 10), 0, false), None);
        assert_eq!(xml_flag_aware_hit(&bomb(9, 10), LIBXML_NOENT, false).unwrap().kind, XxeKind::EntityBomb);
    }

    #[test]
    fn xml_entity_bomb_check_is_bounded() {
        // 128 entities x ~480 references each inside the 64 KiB window: the
        // worst case the check evaluates. Must stay fast and must not panic.
        let mut s = String::from("<!DOCTYPE r [<!ENTITY e0 \"a\">");
        for k in 1..400 {
            s.push_str(&format!("<!ENTITY e{k} \"{}\">", "&e0;".repeat(120)));
        }
        s.push_str("]><r/>");
        let t = std::time::Instant::now();
        let _ = xml_external_entity_hit(s.as_bytes());
        assert!(t.elapsed().as_millis() < 500, "{:?}", t.elapsed());
    }

    #[test]
    fn xml_flag_names_are_a_fixed_vocabulary() {
        assert_eq!(xml_flag_names(LIBXML_NOENT | 16384, false), "LIBXML_NOENT");
        assert_eq!(xml_flag_names(14, false), "LIBXML_NOENT|LIBXML_DTDLOAD|LIBXML_DTDATTR");
        assert_eq!(xml_flag_names(16, false), "LIBXML_DTDVALID");
        assert_eq!(xml_flag_names(0, true), "any flags on libxml before 2.9");
    }

    #[test]
    fn xml_doctype_literals_do_not_hide_the_subset() {
        // A '>' or '[' inside the DOCTYPE's own system literal used to end the
        // declaration early and hide the internal subset (libxml still read it).
        assert_eq!(xxe(b"<!DOCTYPE r SYSTEM \"a>b\" [<!ENTITY x SYSTEM 'f'>]><r/>"), Some(true));
        assert_eq!(xxe(b"<!DOCTYPE r PUBLIC \"-//a[b//\" 'u>' [<!ENTITY x SYSTEM \"f\">]><r/>"), Some(true));
        assert_eq!(xxe(b"<!DOCTYPE r SYSTEM 'a[b' [<!ENTITY x \"v\">]><r/>"), Some(false));
        // unterminated literals are safe (no panic) and still a bare external DTD
        assert_eq!(xxe(b"<!DOCTYPE r SYSTEM \"abc"), Some(false));
        assert_eq!(xxe(b"<!DOCTYPE r SYSTEM 'abc [<!ENTITY x SYSTEM \"f\">]>"), Some(false));
    }

    #[test]
    fn xml_parameter_entity_literal_cannot_smuggle_an_external_entity() {
        // libxml expands `%p;` between declarations and parses the replacement
        // text as markup, so the external entity is declared by the literal.
        for doc in [
            &b"<!DOCTYPE r [<!ENTITY % p \"<!ENTITY x SYSTEM 'file:///f'>\"> %p;]><r>&x;</r>"[..],
            b"<!DOCTYPE r [<!ENTITY % p '<!ENTITY x PUBLIC \"i\" \"file:///f\">'> %p;]><r/>",
            b"<!DOCTYPE r [<!ENTITY % p \"&#60;!ENTITY x SYSTEM 'f'&#62;\"> %p;]><r/>",
            b"<!DOCTYPE r [<!ENTITY % p \"&#x3C;!ENTITY x SYSTEM 'f'&#x3e;\"> %p;]><r/>",
            b"<!DOCTYPE r [<!ENTITY % p \"<!ENTITY x SYS&#84;EM 'f'>\"> %p;]><r/>",
            b"<!DOCTYPE r [<!-- c --><!ENTITY % p \"<!ENTITY a 'v'><!ENTITY x SYSTEM 'f'>\"> %p;]><r/>",
        ] {
            assert_eq!(xxe(doc), Some(true), "{:?}", String::from_utf8_lossy(doc));
        }
        // Parameter entities that declare nothing external stay clean.
        for doc in [
            &b"<!DOCTYPE r [<!ENTITY % p \"<!ELEMENT a (b)>\"> %p;]><r/>"[..],
            b"<!DOCTYPE r [<!ENTITY % p \"<!ENTITY x 'SYSTEM'>\"> %p;]><r/>",
            b"<!DOCTYPE r [<!ENTITY % p \"&#37;q;\"> <!ENTITY % q 'v'>]><r/>",
            b"<!DOCTYPE r [<!ENTITY % p \"&#999999999;&#;&#x;<!\">]><r/>",
            b"<!DOCTYPE r [<!ENTITY % p \"no markup at all\">]><r/>",
        ] {
            assert_eq!(xxe(doc), None, "{:?}", String::from_utf8_lossy(doc));
        }
    }

    #[test]
    fn xml_wide_documents_in_any_byte_order_are_squeezed() {
        let text = "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY x SYSTEM \"file:///x\">]><r>&x;</r>";
        let enc32 = |be: bool, bom: bool| -> Vec<u8> {
            let mut v = Vec::new();
            if bom {
                v.extend_from_slice(if be { &[0, 0, 0xFE, 0xFF] } else { &[0xFF, 0xFE, 0, 0] });
            }
            for c in text.chars() {
                let u = c as u32;
                v.extend_from_slice(&if be { u.to_be_bytes() } else { u.to_le_bytes() });
            }
            v
        };
        for (be, bom) in [(true, false), (false, false), (true, true), (false, true)] {
            assert_eq!(xxe(&enc32(be, bom)), Some(true), "utf-32 be={be} bom={bom}");
        }
        // UCS-4 unusual byte orders (2143, 3412): `\0\0<\0` and `\0<\0\0`.
        let mut o2143 = Vec::new();
        let mut o3412 = Vec::new();
        for c in text.bytes() {
            o2143.extend_from_slice(&[0, 0, c, 0]);
            o3412.extend_from_slice(&[0, c, 0, 0]);
        }
        assert_eq!(xxe(&o2143), Some(true));
        assert_eq!(xxe(&o3412), Some(true));
        // a clean wide document stays clean
        let clean: Vec<u8> = "<?xml version=\"1.0\"?><r/>".chars().flat_map(|c| (c as u32).to_be_bytes()).collect();
        assert_eq!(xxe(&clean), None);
    }

    #[test]
    fn xml_hidden_encodings_are_reported_but_ordinary_ones_are_not() {
        let decl = |enc: &str| format!("<?xml version=\"1.0\" encoding=\"{enc}\"?><!DOCTYPE r><r/>").into_bytes();
        let hit = |doc: &[u8]| xml_external_entity_hit(doc).map(|h| (h.kind, h.reason));
        let hidden = Some((XxeKind::Unscannable, REASON_XXE_ENCODING));
        for enc in [
            "UTF-7", "utf-7", "UTF7", "UNICODE-1-1-UTF-7", "IBM037", "ibm-037", "cp037", "IBM1047", "cp1047", "CP500",
            "csIBM500", "EBCDIC-US", "ebcdic-cp-us", "IBM_1140", "UTF-16LE", "utf-16", "UCS-2", "UTF-32", "UCS-4",
            "UnicodeBig", "ISO-10646-UCS-2",
        ] {
            assert_eq!(hit(&decl(enc)), hidden, "{enc}");
        }
        // single-quoted, spaced, and after a BOM / whitespace
        assert_eq!(hit(b"<?xml version='1.0' encoding = 'UTF-7' ?><r/>"), hidden);
        assert_eq!(hit(b"\xEF\xBB\xBF  <?xml version=\"1.0\" encoding=\"UTF-7\"?><r/>"), hidden);
        // the EBCDIC `<?xm` signature libxml detects
        assert_eq!(hit(&[0x4C, 0x6F, 0xA7, 0x94, 0x40, 0x85]), hidden);
        // Ordinary encodings, including look-alikes of the families above.
        for enc in [
            "UTF-8", "utf-8", "US-ASCII", "ISO-8859-1", "iso-8859-15", "windows-1252", "cp1252", "CP1251", "Shift_JIS",
            "EUC-JP", "EUC-KR", "GB2312", "GBK", "Big5", "KOI8-R", "IBM850", "IBM866", "cp437", "ISO-2022-JP", "MacRoman",
            "UTF8", "latin1", "ibm", "cp", "ibm0", "cp12", "x-unicode", "",
        ] {
            assert_eq!(hit(&decl(enc)), None, "{enc}");
        }
        // no declaration / no encoding attribute / encoding only in content
        assert_eq!(hit(b"<r>encoding=\"UTF-7\"</r>"), None);
        assert_eq!(hit(b"<?xml version=\"1.0\"?><r/>"), None);
        assert_eq!(hit(b"<!-- <?xml encoding=\"UTF-7\"?> --><r/>"), None);
        // A real UTF-16 document declaring UTF-16 is squeezed and scanned, not "hidden".
        let mut u16doc = vec![0xFF, 0xFE];
        for u in "<?xml version=\"1.0\" encoding=\"UTF-16\"?><!DOCTYPE r><r/>".encode_utf16() {
            u16doc.extend_from_slice(&u.to_le_bytes());
        }
        assert_eq!(hit(&u16doc), None);
    }

    #[test]
    fn xml_prolog_padding_cannot_push_the_doctype_out_of_the_window() {
        let tail = b"<!DOCTYPE r [<!ENTITY x SYSTEM \"f\">]><r>&x;</r>";
        let long = Some((XxeKind::Unscannable, REASON_XXE_LONG_PROLOG));
        let hit = |doc: &[u8]| xml_external_entity_hit(doc).map(|h| (h.kind, h.reason));
        // comment padding, whitespace padding, a PI, a huge internal subset
        for pad in [
            [&b"<!--"[..], &vec![b'x'; XML_SCAN_MAX + 10], b"-->"].concat(),
            vec![b' '; XML_SCAN_MAX + 10],
            [&b"<?pi "[..], &vec![b'x'; XML_SCAN_MAX + 10], b"?>"].concat(),
        ] {
            let doc = [&pad[..], tail].concat();
            assert_eq!(hit(&doc), long);
        }
        let mut big_subset = b"<!DOCTYPE r [".to_vec();
        big_subset.extend(std::iter::repeat_n(b' ', XML_SCAN_MAX + 10));
        big_subset.extend_from_slice(b"]><r/>");
        assert_eq!(hit(&big_subset), long);
        // ...but a normal document with a big body, and a prolog that fits the
        // window and reaches the root, are clean.
        let mut body = b"<r>".to_vec();
        body.resize(XML_SCAN_MAX * 4, b'a');
        assert_eq!(hit(&body), None);
        let mut fits = b"<?xml version=\"1.0\"?><!-- ".to_vec();
        fits.extend(std::iter::repeat_n(b'x', XML_SCAN_MAX / 2));
        fits.extend_from_slice(b" --><r/>");
        assert_eq!(hit(&fits), None);
        // A document that merely ends inside its prolog is malformed, not padded.
        assert_eq!(hit(b"   "), None);
        // An external entity found inside the window still wins over the length rule.
        let mut ext_then_pad = b"<!DOCTYPE r [<!ENTITY x SYSTEM \"f\">".to_vec();
        ext_then_pad.extend(std::iter::repeat_n(b' ', XML_SCAN_MAX + 10));
        assert_eq!(xml_external_entity_hit(&ext_then_pad).unwrap().kind, XxeKind::ExternalEntity);
    }

    #[test]
    fn xml_flag_aware_reports_unscannable_documents_only_with_a_dangerous_flag() {
        let utf7 = b"<?xml version=\"1.0\" encoding=\"UTF-7\"?>+ADw-!DOCTYPE r+AFs-+ADw-!ENTITY x SYSTEM \"f\"+AD4-+AF0-+AD4-";
        assert_eq!(xml_flag_aware_hit(utf7, 0, false), None);
        assert_eq!(xml_flag_aware_hit(utf7, 64 | 256, false), None);
        let h = xml_flag_aware_hit(utf7, LIBXML_NOENT, false).unwrap();
        assert_eq!((h.kind, h.reason), (XxeKind::Unscannable, REASON_XXE_ENCODING));
        assert!(h.is_attack());
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
            REASON_XXE_BOMB,
            REASON_XXE_DTD,
            REASON_XXE_ENCODING,
            REASON_XXE_LONG_PROLOG,
            REASON_TLS_PEER,
            REASON_TLS_HOST,
        ] {
            assert!(!r.contains("{}") && !r.contains('\n'));
        }
    }
}

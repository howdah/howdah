//! Layer-3 SOAP request guard (CVE-2026-129506, CVE-2026-15353).
//!
//! Two malformed SOAP request shapes are refused BEFORE PHP's `ext/soap`
//! parser touches them, so the vulnerable code never runs:
//!
//!   * **DTD / DOCTYPE in the document prolog** (CVE-2026-129506,
//!     GHSA-4646-p932-gw34): `ext/soap` already rejects DTDs ("DTD are not
//!     supported by SOAP"), but the use-after-free strikes while it cleans up
//!     that rejected DTD (and the rejection can be bypassed). SOAP forbids DTDs
//!     outright, so refusing a DOCTYPE-bearing request changes no legitimate
//!     behaviour.
//!   * **Malformed SOAP-ENC `arraySize`** (CVE-2026-15353,
//!     GHSA-q23r-hr55-xmpg): `calc_dimension_12()` reads an uninitialised first
//!     dimension when an `arraySize` attribute value is empty, whitespace-only,
//!     or not a valid dimension list, giving a heap over-read / info
//!     disclosure.
//!
//! Pure, hand-written, strictly linear-time, no allocation, no regex — like the
//! rest of the core. The classifier is fed the raw request XML bytes and only
//! ever answers "refuse (why)" or "allow"; the caller resolves the outcome
//! against the configured mode. The reason it returns is a FIXED string, never
//! any request bytes (values-never-logged).

/// Why a SOAP request was refused. Fixed strings, never request bytes.
pub const REASON_DTD: &str = "dtd";
pub const REASON_ARRAY_DIMENSIONS: &str = "array-dimensions";

/// Classify the raw bytes of a SOAP request body. Returns the fixed reason a
/// dangerous shape is refused for, or `None` when the request is benign.
///
/// The DTD check runs first (it is the prolog, cheapest and most dangerous),
/// then the `arraySize` scan.
pub fn soap_request_verdict(xml: &[u8]) -> Option<&'static str> {
    if dtd_in_prolog(xml) {
        return Some(REASON_DTD);
    }
    if malformed_array_size(xml) {
        return Some(REASON_ARRAY_DIMENSIONS);
    }
    None
}

/// Find `needle` in `hay`, returning the start index of the first match.
fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > hay.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

/// True iff the document's PROLOG opens a DTD (`<!DOCTYPE ...>`). Only a
/// `<!DOCTYPE` that is the FIRST markup counts: a UTF-8 BOM, the `<?xml ... ?>`
/// declaration, comments and processing instructions, and whitespace are
/// skipped; the first thing that is not one of those must not be a DOCTYPE. A
/// `<!DOCTYPE` inside a CDATA section or as element text content is NEVER
/// reached (the scan stops at the first element start tag), so SAML/SVG-style
/// payloads that merely *contain* the literal do not trip it.
///
/// If the body carries a UTF-16 (or other non-ASCII) byte-order mark the check
/// is skipped (returns false): scanning UTF-16 as bytes would mis-read it. This
/// is a documented gap — a UTF-16-encoded prolog DOCTYPE is not caught here.
fn dtd_in_prolog(xml: &[u8]) -> bool {
    let mut x = xml;
    // Skip a UTF-8 BOM.
    if let Some(rest) = x.strip_prefix(&[0xEF, 0xBB, 0xBF]) {
        x = rest;
    }
    // A UTF-16 BOM (LE or BE): skip the check rather than mis-scan the bytes.
    if x.starts_with(&[0xFF, 0xFE]) || x.starts_with(&[0xFE, 0xFF]) {
        return false;
    }
    let n = x.len();
    let mut i = 0;
    loop {
        // Skip whitespace between prolog items.
        while i < n && x[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= n {
            return false;
        }
        // The first markup of a well-formed document begins with '<'. Anything
        // else at the top of the prolog means there is no prolog DOCTYPE.
        if x[i] != b'<' {
            return false;
        }
        let rest = &x[i..];
        if rest.starts_with(b"<!--") {
            // XML comment: skip to its terminator.
            match find(&rest[4..], b"-->") {
                Some(e) => {
                    i += 4 + e + 3;
                    continue;
                }
                None => return false, // unterminated comment: nothing more to judge
            }
        }
        if rest.starts_with(b"<?") {
            // XML declaration or processing instruction.
            match find(&rest[2..], b"?>") {
                Some(e) => {
                    i += 2 + e + 2;
                    continue;
                }
                None => return false,
            }
        }
        // `<!DOCTYPE` (XML keyword is uppercase; match case-insensitively so a
        // mixed-case bypass attempt is still refused — no legitimate SOAP has
        // a DOCTYPE at all). Require a boundary after it so `<!DOCTYPEX` (not a
        // real construct) does not match a bare element.
        if rest.len() >= 9 && rest[1] == b'!' && rest[2..9].eq_ignore_ascii_case(b"DOCTYPE") {
            let after = rest.get(9).copied();
            match after {
                None => return true,
                Some(c) if c.is_ascii_whitespace() || c == b'[' || c == b'>' => return true,
                Some(_) => return false,
            }
        }
        // First real markup is the root element (or some other `<!` construct,
        // which at prolog level is not a DOCTYPE): no prolog DOCTYPE.
        return false;
    }
}

/// The two SOAP encoding namespaces `ext/soap` reads `arraySize` from
/// (SOAP_1_1_ENC_NAMESPACE / SOAP_1_2_ENC_NAMESPACE). An `arraySize` attribute
/// in any other namespace is business XML and never reaches `calc_dimension_12`.
const SOAP11_ENC_NS: &[u8] = b"http://schemas.xmlsoap.org/soap/encoding/";
const SOAP12_ENC_NS: &[u8] = b"http://www.w3.org/2003/05/soap-encoding";

fn is_soap_enc_ns(uri: &[u8]) -> bool {
    uri == SOAP11_ENC_NS || uri == SOAP12_ENC_NS
}

/// Max distinct prefixes tracked as bound to a SOAP encoding namespace. Past
/// this, every prefix is conservatively treated as SOAP-ENC (fail closed).
const MAX_ENC_PREFIXES: usize = 16;

/// Namespace prefixes (and the default namespace) bound to a SOAP encoding
/// namespace ANYWHERE in the document. Document-wide rather than scoped: a
/// superset of the real scope, so a prefix re-bound or declared deep in the tree
/// is never missed (no bypass); the cost is at most a rare over-flag.
struct EncNs<'a> {
    prefixes: [&'a [u8]; MAX_ENC_PREFIXES],
    count: usize,
    overflow: bool,
    default_bound: bool,
}

impl<'a> EncNs<'a> {
    fn has_prefix(&self, p: &[u8]) -> bool {
        self.overflow || self.prefixes[..self.count].contains(&p)
    }
}

/// Walk the attributes of one start tag's bytes (between `<` and `>`),
/// calling `f(name, value)` for each quoted attribute; stops and returns true
/// as soon as `f` does. End tags carry no attributes.
fn for_each_attr<'a>(tag: &'a [u8], f: &mut dyn FnMut(&'a [u8], &'a [u8]) -> bool) -> bool {
    let n = tag.len();
    let mut i = 0;
    if i < n && tag[i] == b'/' {
        return false;
    }
    // Skip the element name.
    while i < n && !tag[i].is_ascii_whitespace() {
        i += 1;
    }
    while i < n {
        while i < n && tag[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= n {
            break;
        }
        if tag[i] == b'/' {
            i += 1;
            continue;
        }
        let name_start = i;
        while i < n && !tag[i].is_ascii_whitespace() && tag[i] != b'=' {
            i += 1;
        }
        let name = &tag[name_start..i];
        while i < n && tag[i].is_ascii_whitespace() {
            i += 1;
        }
        if i < n && tag[i] == b'=' {
            i += 1;
            while i < n && tag[i].is_ascii_whitespace() {
                i += 1;
            }
            if i < n && (tag[i] == b'"' || tag[i] == b'\'') {
                let q = tag[i];
                i += 1;
                let val_start = i;
                while i < n && tag[i] != q {
                    i += 1;
                }
                let val = &tag[val_start..i];
                if i < n {
                    i += 1;
                }
                if f(name, val) {
                    return true;
                }
            }
        }
    }
    false
}

/// Visit every element start/end tag's inner bytes (between `<` and `>`),
/// skipping comments, CDATA, PIs and `<!...>` declarations so literals inside
/// them are never mistaken for attributes. Stops (true) when `f` returns true.
fn for_each_tag<'a>(xml: &'a [u8], f: &mut dyn FnMut(&'a [u8]) -> bool) -> bool {
    let n = xml.len();
    let mut i = 0;
    while i < n {
        if xml[i] != b'<' {
            i += 1;
            continue;
        }
        let rest = &xml[i..];
        if rest.starts_with(b"<!--") {
            match find(&rest[4..], b"-->") {
                Some(e) => i += 4 + e + 3,
                None => return false,
            }
            continue;
        }
        if rest.starts_with(b"<![CDATA[") {
            match find(&rest[9..], b"]]>") {
                Some(e) => i += 9 + e + 3,
                None => return false,
            }
            continue;
        }
        if rest.starts_with(b"<?") {
            match find(&rest[2..], b"?>") {
                Some(e) => i += 2 + e + 2,
                None => return false,
            }
            continue;
        }
        if rest.starts_with(b"<!") {
            match find(&rest[2..], b">") {
                Some(e) => i += 2 + e + 1,
                None => return false,
            }
            continue;
        }
        // An element tag: find its end '>' while respecting quoted values.
        let tag_start = i + 1;
        let mut j = tag_start;
        let mut quote: Option<u8> = None;
        while j < n {
            let c = xml[j];
            match quote {
                Some(q) => {
                    if c == q {
                        quote = None;
                    }
                }
                None => {
                    if c == b'"' || c == b'\'' {
                        quote = Some(c);
                    } else if c == b'>' {
                        break;
                    }
                }
            }
            j += 1;
        }
        if f(&xml[tag_start..j]) {
            return true;
        }
        i = if j < n { j + 1 } else { j };
    }
    false
}

/// Mirror `calc_dimension_12`'s accepted grammar: one or more
/// whitespace-separated tokens, each a non-negative integer, with an optional
/// leading `*` allowed ONLY as the first token. Returns true iff `value` is a
/// valid dimension list. Empty / whitespace-only / non-numeric values are not
/// valid (they are what the CVE reads uninitialised).
fn valid_dimension_list(value: &[u8]) -> bool {
    let mut tokens = value.split(|b| b.is_ascii_whitespace()).filter(|t| !t.is_empty());
    let mut any = false;
    for (idx, tok) in (&mut tokens).enumerate() {
        any = true;
        if idx == 0 && tok == b"*" {
            continue; // leading '*' (unbounded) allowed as the first token only
        }
        if !tok.iter().all(|b| b.is_ascii_digit()) {
            return false;
        }
    }
    any
}

/// True iff some element carries an `arraySize` attribute in a SOAP encoding
/// namespace (resolved by namespace URI, never by a hardcoded prefix) whose
/// value is empty, whitespace-only or not a valid dimension list. `arraySize`
/// attributes whose prefix is not bound to a SOAP-ENC URI are business XML and
/// are ignored. An unprefixed `arraySize` counts only when a default `xmlns=`
/// binds a SOAP-ENC URI (conservative: XML itself gives such attributes no
/// namespace).
fn malformed_array_size(xml: &[u8]) -> bool {
    // Pass 1: collect xmlns declarations that bind a SOAP encoding namespace.
    let mut ns = EncNs {
        prefixes: [&[]; MAX_ENC_PREFIXES],
        count: 0,
        overflow: false,
        default_bound: false,
    };
    for_each_tag(xml, &mut |tag| {
        for_each_attr(tag, &mut |name, val| {
            if !is_soap_enc_ns(val) {
                return false;
            }
            if name == b"xmlns" {
                ns.default_bound = true;
            } else if let Some(p) = name.strip_prefix(b"xmlns:") {
                if ns.count < MAX_ENC_PREFIXES {
                    ns.prefixes[ns.count] = p;
                    ns.count += 1;
                } else {
                    ns.overflow = true;
                }
            }
            false
        })
    });
    // Nothing binds a SOAP-ENC namespace: no arraySize can be the vulnerable one.
    if ns.count == 0 && !ns.default_bound && !ns.overflow {
        return false;
    }
    // Pass 2: any in-namespace arraySize with an invalid value.
    for_each_tag(xml, &mut |tag| {
        for_each_attr(tag, &mut |name, val| {
            let in_enc_ns = match name.iter().rposition(|&b| b == b':') {
                Some(p) => &name[p + 1..] == b"arraySize" && ns.has_prefix(&name[..p]),
                None => name == b"arraySize" && ns.default_bound,
            };
            in_enc_ns && !valid_dimension_list(val)
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn soap11(body: &str) -> String {
        format!(
            "<?xml version=\"1.0\"?>\
             <soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">\
             <soap:Body>{body}</soap:Body></soap:Envelope>"
        )
    }

    // ---- DTD / DOCTYPE in the prolog ------------------------------------
    #[test]
    fn prolog_doctype_flagged_plain() {
        let x = b"<!DOCTYPE foo [<!ENTITY x \"y\">]><root/>";
        assert_eq!(soap_request_verdict(x), Some(REASON_DTD));
    }

    #[test]
    fn prolog_doctype_after_decl_comment_pi_and_ws() {
        for prefix in [
            "<?xml version=\"1.0\"?>",
            "   \n\t",
            "<?xml version=\"1.0\"?>\n<!-- a comment -->\n",
            "<!-- c --><?pi data?>  ",
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!--x--><!--y-->",
        ] {
            let x = format!("{prefix}<!DOCTYPE Envelope><root/>");
            assert_eq!(soap_request_verdict(x.as_bytes()), Some(REASON_DTD), "{prefix}");
        }
    }

    #[test]
    fn prolog_doctype_with_utf8_bom() {
        let mut x = vec![0xEF, 0xBB, 0xBF];
        x.extend_from_slice(b"<!DOCTYPE r><r/>");
        assert_eq!(soap_request_verdict(&x), Some(REASON_DTD));
    }

    #[test]
    fn mixed_case_doctype_flagged() {
        let x = b"<!doctype r><r/>";
        assert_eq!(soap_request_verdict(x), Some(REASON_DTD));
    }

    #[test]
    fn doctype_in_cdata_not_flagged() {
        let x = soap11("<n><![CDATA[<!DOCTYPE html>]]></n>");
        assert_eq!(soap_request_verdict(x.as_bytes()), None);
    }

    #[test]
    fn doctype_as_text_content_not_flagged() {
        // The literal appears as text, after the root element has started.
        let x = soap11("<note>see &lt;!DOCTYPE html&gt; or <!-- <!DOCTYPE x> --></note>");
        assert_eq!(soap_request_verdict(x.as_bytes()), None);
        let x2 = "<r>plain text mentioning DOCTYPE html here</r>";
        assert_eq!(soap_request_verdict(x2.as_bytes()), None);
    }

    #[test]
    fn utf16_bom_skips_dtd_check() {
        // A UTF-16 LE BOM followed by bytes we must NOT mis-scan: documented gap.
        let x = [0xFF, 0xFE, b'<', 0x00, b'!', 0x00];
        assert_eq!(soap_request_verdict(&x), None);
    }

    #[test]
    fn doctype_not_first_markup_not_flagged() {
        // A root element opens first; a later DOCTYPE-looking tag is content.
        let x = b"<root><child>x</child></root>";
        assert_eq!(soap_request_verdict(x), None);
    }

    // ---- malformed arraySize -------------------------------------------
    fn arr(size: &str) -> String {
        soap11(&format!(
            "<enc:Array xmlns:enc=\"http://www.w3.org/2003/05/soap-encoding\" enc:arraySize=\"{size}\"><i>1</i></enc:Array>"
        ))
    }

    #[test]
    fn array_size_empty_whitespace_nonnumeric_flagged() {
        for bad in ["", " ", "\t\n", "abc", "2,3", "2a", "-1", "*2", "2 *", "1.5"] {
            assert_eq!(
                soap_request_verdict(arr(bad).as_bytes()),
                Some(REASON_ARRAY_DIMENSIONS),
                "arraySize={bad:?}"
            );
        }
    }

    #[test]
    fn array_size_valid_passes() {
        for ok in ["*", "2", "2 3", "* 3", "0", "10 20 30", " 2  3 "] {
            assert_eq!(soap_request_verdict(arr(ok).as_bytes()), None, "arraySize={ok:?}");
        }
    }

    #[test]
    fn array_size_single_quotes() {
        let x = soap11("<a xmlns:enc='http://schemas.xmlsoap.org/soap/encoding/' enc:arraySize='abc'/>");
        assert_eq!(soap_request_verdict(x.as_bytes()), Some(REASON_ARRAY_DIMENSIONS));
        let ok = soap11("<a xmlns:enc='http://schemas.xmlsoap.org/soap/encoding/' enc:arraySize='2 3'/>");
        assert_eq!(soap_request_verdict(ok.as_bytes()), None);
    }

    #[test]
    fn array_size_no_prefix_business_not_flagged() {
        // No SOAP-ENC namespace bound anywhere: business XML, must pass.
        for v in ["auto", "", "abc"] {
            let x = soap11(&format!("<grid arraySize=\"{v}\"/>"));
            assert_eq!(soap_request_verdict(x.as_bytes()), None, "{v:?}");
        }
    }

    #[test]
    fn array_size_other_namespace_not_flagged() {
        let x = soap11("<g xmlns:biz=\"urn:biz\" biz:arraySize=\"auto\"/>");
        assert_eq!(soap_request_verdict(x.as_bytes()), None);
        // A SOAP-ENC binding elsewhere does not taint a differently-bound prefix.
        let y = soap11(
            "<e xmlns:enc=\"http://www.w3.org/2003/05/soap-encoding\" enc:arraySize=\"2\">\
             <g xmlns:biz=\"urn:biz\" biz:arraySize=\"auto\"/></e>",
        );
        assert_eq!(soap_request_verdict(y.as_bytes()), None);
    }

    #[test]
    fn array_size_custom_prefix_bound_to_soap_enc_caught() {
        for ns in ["http://www.w3.org/2003/05/soap-encoding", "http://schemas.xmlsoap.org/soap/encoding/"] {
            let x = soap11(&format!("<a xmlns:zz=\"{ns}\" zz:arraySize=\"auto\"/>"));
            assert_eq!(soap_request_verdict(x.as_bytes()), Some(REASON_ARRAY_DIMENSIONS), "{ns}");
        }
        // Declared on an ancestor, used on a descendant.
        let y = soap11("<r xmlns:q=\"http://schemas.xmlsoap.org/soap/encoding/\"><a q:arraySize=\"\"/></r>");
        assert_eq!(soap_request_verdict(y.as_bytes()), Some(REASON_ARRAY_DIMENSIONS));
        // Default namespace bound to SOAP-ENC, unprefixed attribute (conservative).
        let z = soap11("<a xmlns=\"http://www.w3.org/2003/05/soap-encoding\" arraySize=\"x\"/>");
        assert_eq!(soap_request_verdict(z.as_bytes()), Some(REASON_ARRAY_DIMENSIONS));
    }

    #[test]
    fn array_size_literal_in_text_not_flagged() {
        // The word arraySize appears as text / inside a value of another attr,
        // never as an attribute name of this element.
        let x = soap11("<note>the arraySize=\"\" was wrong</note>");
        assert_eq!(soap_request_verdict(x.as_bytes()), None);
        let y = soap11("<a xmlns:enc=\"http://www.w3.org/2003/05/soap-encoding\" title=\"arraySize=\"/>");
        assert_eq!(soap_request_verdict(y.as_bytes()), None);
    }

    #[test]
    fn similar_attr_name_not_matched() {
        // myArraySize / arraySizes must NOT match the local name arraySize.
        let x = soap11("<a xmlns:enc=\"http://www.w3.org/2003/05/soap-encoding\" myarraySize=\"\" enc:xarraySizes=\"\"/>");
        assert_eq!(soap_request_verdict(x.as_bytes()), None);
    }

    // ---- benign envelopes pass -----------------------------------------
    #[test]
    fn benign_soap11_and_soap12_pass() {
        let s11 = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
            <soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">\
            <soap:Body><m:Add xmlns:m=\"urn:x\"><a>1</a><b>2</b></m:Add></soap:Body></soap:Envelope>";
        assert_eq!(soap_request_verdict(s11.as_bytes()), None);
        let s12 = "<?xml version=\"1.0\"?>\
            <env:Envelope xmlns:env=\"http://www.w3.org/2003/05/soap-envelope\">\
            <env:Body><m:Echo xmlns:m=\"urn:x\"><text>hi</text></m:Echo></env:Body></env:Envelope>";
        assert_eq!(soap_request_verdict(s12.as_bytes()), None);
    }

    #[test]
    fn valid_array_envelope_passes() {
        let x = soap11(
            "<enc:Array xmlns:enc=\"http://www.w3.org/2003/05/soap-encoding\" \
             enc:arraySize=\"* 3\" enc:itemType=\"xsd:int\"><i>1</i><i>2</i></enc:Array>",
        );
        assert_eq!(soap_request_verdict(x.as_bytes()), None);
    }

    #[test]
    fn empty_input_is_benign() {
        assert_eq!(soap_request_verdict(b""), None);
        assert_eq!(soap_request_verdict(b"   "), None);
    }
}

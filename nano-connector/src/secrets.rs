//! Secret matching for redaction and outbound exfil checks.
//!
//! A credential can leave or come back in more shapes than its literal
//! value: percent-encoded in a URL, form-encoded in a body, JSON-escaped,
//! hex, or base64 (alone, inside a longer base64 run at any of the three
//! byte alignments, or as HTTP Basic `user:password`). [`SecretSet`] holds
//! every such shape and scrubs or detects all of them in one pass.
//!
//! Percent-encoding comes in upper- and lowercase hex and with the reserved
//! sets of the common encoders (everything non-alphanumeric, RFC 3986
//! unreserved, `encodeURIComponent`, Python `quote`, forms). JSON escaping
//! comes as serde writes it, with `\/`, as Go writes it (`<>&` as
//! `\u003c`...) and with every non-alphanumeric character as `\uXXXX`.
//! For refusal, [`SecretSet::contains_decoded`] also matches a
//! percent-decoded and a JSON-unescaped view of the input, so a shape not
//! listed here is still caught on the way out.
//!
//! Values shorter than [`MIN_SECRET_LEN`] are not matched: a 4-character
//! "secret" would redact ordinary words out of every response. Auth
//! plugins should refuse such credentials instead (see SECURITY.md).

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC};

/// RFC 3986: everything but unreserved (`A-Z a-z 0-9 - . _ ~`).
const RFC3986: &AsciiSet = &NON_ALPHANUMERIC.remove(b'-').remove(b'.').remove(b'_').remove(b'~');
/// Python `urllib.parse.quote` default (`safe='/'`).
const PY_QUOTE: &AsciiSet = &RFC3986.remove(b'/');
/// JavaScript `encodeURIComponent`.
const URI_COMPONENT: &AsciiSet =
    &NON_ALPHANUMERIC.remove(b'-').remove(b'_').remove(b'.').remove(b'!').remove(b'~').remove(b'*').remove(b'\'').remove(b'(').remove(b')');

pub const MIN_SECRET_LEN: usize = 6;
pub const REDACTED: &[u8] = b"[REDACTED]";
/// Inputs up to this size get three decoding rounds in
/// [`SecretSet::contains_decoded`]; larger ones get one.
pub const DEEP_DECODE_MAX_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Default)]
pub struct SecretSet {
    needles: Vec<Vec<u8>>,
    /// One pass over the input for every shape; leftmost-longest, so a
    /// longer shape wins over a shorter one it contains.
    matcher: Option<aho_corasick::AhoCorasick>,
}

impl SecretSet {
    pub fn new<'a>(secrets: impl IntoIterator<Item = &'a str>) -> Self {
        Self::with_derived(secrets, std::iter::empty())
    }

    /// Derived secrets retain every encoded shape, including aligned base64
    /// cores inside compound values. Only credentials need the additional
    /// HTTP Basic pairs; pairing a run's request signatures would build a
    /// quadratic number of needles on every signed request.
    pub fn with_derived<'a>(
        credentials: impl IntoIterator<Item = &'a str>,
        derived: impl IntoIterator<Item = &'a str>,
    ) -> Self {
        let raw: Vec<&str> = credentials.into_iter().filter(|s| s.len() >= MIN_SECRET_LEN).collect();
        let mut needles: Vec<Vec<u8>> = Vec::new();
        for s in raw.iter().copied().chain(derived).filter(|s| s.len() >= MIN_SECRET_LEN) {
            needles.extend(shapes(s));
        }
        // HTTP Basic: base64("a:b") for every ordered pair of credentials.
        for a in &raw {
            for b in &raw {
                if a != b {
                    let pair = format!("{a}:{b}");
                    needles.push(STANDARD.encode(&pair).into_bytes());
                    needles.push(URL_SAFE.encode(&pair).into_bytes());
                }
            }
        }
        // Basic auth with a short user name ("api:<secret>") is still
        // caught by the aligned base64 shapes of the secret itself.
        needles.retain(|n| n.len() >= MIN_SECRET_LEN);
        needles.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
        needles.dedup();
        let matcher = if needles.is_empty() {
            None
        } else {
            aho_corasick::AhoCorasick::builder()
                .match_kind(aho_corasick::MatchKind::LeftmostLongest)
                .build(&needles)
                .ok()
        };
        Self { needles, matcher }
    }

    pub fn is_empty(&self) -> bool {
        self.needles.is_empty()
    }

    pub fn contains(&self, hay: &[u8]) -> bool {
        match &self.matcher {
            Some(m) => m.is_match(hay),
            // Builder failure is not expected; fall back to a plain scan.
            None => self.needles.iter().any(|n| find(hay, n).is_some()),
        }
    }

    pub fn contains_str(&self, hay: &str) -> bool {
        self.contains(hay.as_bytes())
    }

    /// [`SecretSet::contains`] on `hay` and on every view reachable by up to
    /// three rounds (one above [`DEEP_DECODE_MAX_BYTES`]) of percent-decoding (`+` as space) and JSON-unescaping,
    /// in any order (the engine itself percent-encodes query values, so a
    /// program's own encoding arrives one layer deeper). For refusing
    /// outbound data and checking what redaction left: it says whether a
    /// secret is there, not where.
    pub fn contains_decoded(&self, hay: &[u8]) -> bool {
        if self.is_empty() {
            return false;
        }
        if self.contains(hay) {
            return true;
        }
        if !hay.iter().any(|b| matches!(b, b'%' | b'+' | b'\\')) {
            return false;
        }
        // Each round can double the views; keep big bodies (responses up
        // to the decompression cap) to one round so this stays a few copies.
        let rounds = if hay.len() <= DEEP_DECODE_MAX_BYTES { 3 } else { 1 };
        let mut frontier = vec![hay.to_vec()];
        for _ in 0..rounds {
            let mut next = Vec::new();
            for v in &frontier {
                if v.contains(&b'%') || v.contains(&b'+') {
                    next.push(percent_decode_form(v));
                }
                if v.contains(&b'\\') {
                    next.push(json_unescape(v));
                }
            }
            next.retain(|n| !frontier.contains(n));
            next.dedup();
            if next.is_empty() {
                return false;
            }
            if next.iter().any(|n| self.contains(n)) {
                return true;
            }
            frontier = next;
        }
        false
    }

    pub fn redact(&self, hay: &[u8]) -> Vec<u8> {
        let mut out = match &self.matcher {
            Some(m) => m.replace_all_bytes(hay, &vec![REDACTED; self.needles.len()]),
            None => hay.to_vec(),
        };
        // A replacement can join two fragments into a new match; repeat
        // until stable (bounded: each pass only shrinks matches away).
        for _ in 0..4 {
            if !self.contains(&out) {
                break;
            }
            for n in &self.needles {
                out = replace(&out, n, REDACTED);
            }
        }
        out
    }

    pub fn redact_str(&self, s: &str) -> String {
        String::from_utf8_lossy(&self.redact(s.as_bytes())).into_owned()
    }
}

/// Every encoded form of one secret worth matching.
fn shapes(s: &str) -> Vec<Vec<u8>> {
    let b = s.as_bytes();
    let mut out = vec![b.to_vec()];
    let mut pct = vec![url::form_urlencoded::byte_serialize(b).collect::<String>()];
    for set in [NON_ALPHANUMERIC, RFC3986, PY_QUOTE, URI_COMPONENT] {
        pct.push(percent_encoding::utf8_percent_encode(s, set).to_string());
    }
    for p in pct {
        out.push(lower_percent_hex(&p).into_bytes());
        out.push(p.into_bytes());
    }
    if let Ok(j) = serde_json::to_string(s) {
        let j = j.trim_matches('"');
        out.push(j.as_bytes().to_vec());
        // serde_json does not escape '/', but other encoders do.
        out.push(j.replace('/', "\\/").into_bytes());
        // Go's encoding/json escapes HTML characters.
        out.push(j.replace('<', "\\u003c").replace('>', "\\u003e").replace('&', "\\u0026").into_bytes());
        // Python's ensure_ascii: only non-ASCII as \uXXXX.
        if !j.is_ascii() {
            let mut buf = [0u16; 2];
            let ascii: String = j
                .chars()
                .map(|c| if c.is_ascii() { c.to_string() } else { c.encode_utf16(&mut buf).iter().map(|u| format!("\\u{u:04x}")).collect() })
                .collect();
            out.push(ascii.into_bytes());
        }
    }
    // Every non-alphanumeric character as \uXXXX (ensure_ascii-style
    // encoders), in both hex cases.
    for upper in [false, true] {
        let all_u: String = s
            .encode_utf16()
            .map(|u| match char::from_u32(u as u32) {
                Some(c) if c.is_ascii_alphanumeric() => c.to_string(),
                _ if upper => format!("\\u{u:04X}"),
                _ => format!("\\u{u:04x}"),
            })
            .collect();
        out.push(all_u.into_bytes());
    }
    out.push(hex::encode(b).into_bytes());
    out.push(hex::encode_upper(b).into_bytes());
    for engine in [&STANDARD, &URL_SAFE] {
        out.push(engine.encode(b).into_bytes());
    }
    for engine in [&STANDARD_NO_PAD, &URL_SAFE_NO_PAD] {
        out.extend(aligned_base64(b, engine));
    }
    out
}

/// The base64 characters that encode `secret` wherever it sits inside a
/// longer base64-encoded buffer: one stable core per byte alignment.
fn aligned_base64(secret: &[u8], engine: &base64::engine::GeneralPurpose) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for pad in 0..3usize {
        let mut buf = vec![0u8; pad];
        buf.extend_from_slice(secret);
        let enc = engine.encode(&buf);
        // Characters fully determined by the secret: skip those that mix in
        // the prefix bytes, stop before the last partial group (it would mix
        // in whatever follows).
        let start = (pad * 8).div_ceil(6);
        let end = (buf.len() * 8) / 6;
        if end > start && end <= enc.len() {
            out.push(enc.as_bytes()[start..end].to_vec());
        }
    }
    out
}

/// `%2F` → `%2f`.
fn lower_percent_hex(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = 0usize;
    for c in s.chars() {
        if rest > 0 {
            out.push(c.to_ascii_lowercase());
            rest -= 1;
        } else {
            if c == '%' {
                rest = 2;
            }
            out.push(c);
        }
    }
    out
}

/// Percent-decode, with `+` as a space (form bodies).
fn percent_decode_form(hay: &[u8]) -> Vec<u8> {
    let plus: Vec<u8> = hay.iter().map(|b| if *b == b'+' { b' ' } else { *b }).collect();
    percent_encoding::percent_decode(&plus).collect()
}

/// Undo JSON string escapes (`\uXXXX` incl. surrogate pairs, `\/`, `\n`...)
/// wherever they appear; anything else is copied through.
fn json_unescape(hay: &[u8]) -> Vec<u8> {
    let hex4 = |b: &[u8]| -> Option<u32> {
        let s = std::str::from_utf8(b.get(..4)?).ok()?;
        u32::from_str_radix(s, 16).ok()
    };
    let mut out = Vec::with_capacity(hay.len());
    let mut i = 0;
    while i < hay.len() {
        if hay[i] != b'\\' || i + 1 >= hay.len() {
            out.push(hay[i]);
            i += 1;
            continue;
        }
        let simple = match hay[i + 1] {
            b'n' => Some(b'\n'),
            b't' => Some(b'\t'),
            b'r' => Some(b'\r'),
            b'b' => Some(8),
            b'f' => Some(12),
            b'/' => Some(b'/'),
            b'\\' => Some(b'\\'),
            b'"' => Some(b'"'),
            _ => None,
        };
        if let Some(c) = simple {
            out.push(c);
            i += 2;
            continue;
        }
        if hay[i + 1] == b'u' {
            if let Some(hi) = hex4(&hay[i + 2..]) {
                let (cp, used) = if (0xD800..0xDC00).contains(&hi)
                    && hay.get(i + 6) == Some(&b'\\')
                    && hay.get(i + 7) == Some(&b'u')
                {
                    match hex4(&hay[i + 8..]) {
                        Some(lo) if (0xDC00..0xE000).contains(&lo) => (0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00), 12),
                        _ => (hi, 6),
                    }
                } else {
                    (hi, 6)
                };
                if let Some(c) = char::from_u32(cp) {
                    let mut buf = [0u8; 4];
                    out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
                    i += used;
                    continue;
                }
            }
        }
        out.push(hay[i]);
        i += 1;
    }
    out
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    (0..=hay.len() - needle.len()).find(|&i| hay[i..].starts_with(needle))
}

fn replace(hay: &[u8], needle: &[u8], with: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(hay.len());
    let mut i = 0;
    while i < hay.len() {
        if hay.len() - i >= needle.len() && hay[i..].starts_with(needle) {
            out.extend_from_slice(with);
            i += needle.len();
        } else {
            out.push(hay[i]);
            i += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: &str = "sk_live/THIS+IS=THE&SECRET-42";

    #[test]
    fn every_shape_is_caught() {
        let set = SecretSet::new([S]);
        let enc = |e: &base64::engine::GeneralPurpose, v: &str| e.encode(v);
        for hay in [
            S.to_string(),
            percent_encoding::utf8_percent_encode(S, percent_encoding::NON_ALPHANUMERIC).to_string(),
            url::form_urlencoded::byte_serialize(S.as_bytes()).collect::<String>(),
            serde_json::to_string(S).unwrap(),
            hex::encode(S),
            enc(&STANDARD, S),
            enc(&URL_SAFE_NO_PAD, S),
            // inside a longer base64 run, at every alignment
            enc(&STANDARD, &format!("token={S};")),
            enc(&STANDARD, &format!("xtoken={S};")),
            enc(&STANDARD, &format!("xxtoken={S};")),
            enc(&URL_SAFE_NO_PAD, &format!("{{\"k\":\"{S}\"}}")),
            enc(&STANDARD, &format!("api:{S}")),
        ] {
            assert!(set.contains_str(&hay), "missed {hay}");
            assert!(!set.redact_str(&hay).contains(S), "redaction left the secret in {hay}");
            assert!(!set.contains(&set.redact(hay.as_bytes())), "redaction left a shape in {hay}");
        }
        assert!(!set.contains_str("nothing to see here, 1234567890"));
    }

    #[test]
    fn encoder_variants_are_caught() {
        // A secret with characters the encoders disagree on.
        let s = "abc~def/ghi&j'k(l)<m>";
        let set = SecretSet::new([s]);
        let rfc: &AsciiSet = RFC3986;
        for hay in [
            // RFC 3986 / encodeURIComponent / Python quote, either hex case
            percent_encoding::utf8_percent_encode(s, rfc).to_string(),
            lower_percent_hex(&percent_encoding::utf8_percent_encode(s, rfc).to_string()),
            percent_encoding::utf8_percent_encode(s, URI_COMPONENT).to_string(),
            lower_percent_hex(&percent_encoding::utf8_percent_encode(s, PY_QUOTE).to_string()),
            lower_percent_hex(&url::form_urlencoded::byte_serialize(s.as_bytes()).collect::<String>()),
            // Go-style and ensure_ascii-style JSON
            r"abc~def/ghi\u0026j'k(l)\u003cm\u003e".to_string(),
            r"abc\u007edef\u002fghi\u0026j\u0027k\u0028l\u0029\u003cm\u003e".to_string(),
            r"abc\u007Edef\u002Fghi\u0026j\u0027k\u0028l\u0029\u003Cm\u003E".to_string(),
        ] {
            assert!(set.contains_str(&hay), "missed {hay}");
            assert!(!set.contains(&set.redact(hay.as_bytes())), "redaction left a shape in {hay}");
        }
        // Shapes nobody listed are still caught decoded: mixed hex case,
        // a percent-encoded string inside JSON escapes.
        let mixed = "abc%7Edef%2fghi%26j%27k%28l%29%3Cm%3e";
        assert!(!set.contains_str(mixed));
        assert!(set.contains_decoded(mixed.as_bytes()));
        let nested = r"abc\u007edef%2Fghi\u0026j'k(l)%3cm\u003e";
        assert!(set.contains_decoded(nested.as_bytes()));
        assert!(set.contains_decoded("x=abc~def%2Fghi%26j%27k%28l%29%3Cm%3E&y=1".as_bytes()));
        assert!(!set.contains_decoded(b"abc~def%2Fother"));
    }

    #[test]
    fn json_unescape_handles_surrogates_and_junk() {
        assert_eq!(json_unescape(br"a\u00e9\ud83d\ude00\/\n\q\u12"), "a\u{e9}\u{1f600}/\n\\q\\u12".as_bytes());
    }

    #[test]
    fn basic_auth_pairs_and_short_values() {
        let set = SecretSet::new(["client-id-123", "client-secret-456", "abc"]);
        assert!(set.contains_str(&STANDARD.encode("client-id-123:client-secret-456")));
        assert!(!set.contains_str("abc"), "short values are not matched");
    }
}

/*!
Scans for the elements inside a header value.

The functions here split a header value into the elements that RFC 3261
section 25.1 builds every header grammar from, such as a `token`, a `host`, or
a `quoted-string`. [`value`](crate::value) reads whole productions with them,
such as an address or a Via. Use these directly for a header that `value` has
no production for, instead of copying the rules.

Each function takes the rest of a value and looks at its start. It returns the
element it finds there, together with what follows it, or `None` when the value
does not start with that element. Nothing is copied, and the element is
returned as written. Stripping the brackets of an IPv6 reference or unescaping
a quoted string is left to the caller, as is deciding what a missing element
means.

The input is a header value as the parser or [`check::header_value`] returned
it, or a tail of one. `CR` and `LF` then only occur in folds, which are linear
whitespace. On other input the scans still return a well-formed result, but
treat a bare `CR` or `LF` as whitespace too.

```
use siparse::scan;

// The first `via-parm` of a `Via` value.
let value = "SIP/2.0/UDP pc33.atlanta.example.com:5060;branch=z9hG4bK776asdhds";

let (protocol, rest) = scan::token(value).unwrap();
let rest = scan::separator(rest, '/').unwrap();
let (version, rest) = scan::token(rest).unwrap();
let rest = scan::separator(rest, '/').unwrap();
let (transport, rest) = scan::token(rest).unwrap();
let rest = scan::lws(rest).unwrap();
let (host, rest) = scan::host(rest).unwrap();
let rest = scan::separator(rest, ':').unwrap();
let (port, rest) = scan::digits(rest).unwrap();
let rest = scan::separator(rest, ';').unwrap();
let (name, rest) = scan::token(rest).unwrap();
let rest = scan::separator(rest, '=').unwrap();
let (branch, rest) = scan::token(rest).unwrap();

assert_eq!((protocol, version, transport), ("SIP", "2.0", "UDP"));
assert_eq!((host, port), ("pc33.atlanta.example.com", "5060"));
assert_eq!((name, branch), ("branch", "z9hG4bK776asdhds"));
assert_eq!(rest, "");
```

[`check::header_value`]: crate::check::header_value
*/

use crate::{iter::Bytes, simd};

/// Skips `SWS`, which is any amount of whitespace, including none.
///
/// Whitespace is `SP`, `HTAB`, and the `CRLF` of a fold.
///
/// # Example
///
/// ```
/// use siparse::scan;
///
/// assert_eq!(scan::sws(" \t\r\n ;tag=1"), ";tag=1");
/// assert_eq!(scan::sws(";tag=1"), ";tag=1");
/// ```
#[inline]
pub fn sws(src: &str) -> &str {
    // Whitespace is ASCII, so the split is on a character boundary.
    &src[whitespace_len(src.as_bytes())..]
}

/// Skips `LWS`, which is at least one byte of whitespace.
///
/// Returns `None` if `src` does not start with whitespace. See [`sws`] for
/// what counts as whitespace.
///
/// # Example
///
/// ```
/// use siparse::scan;
///
/// assert_eq!(scan::lws(" INVITE"), Some("INVITE"));
/// assert_eq!(scan::lws("INVITE"), None);
/// ```
#[inline]
pub fn lws(src: &str) -> Option<&str> {
    let n = whitespace_len(src.as_bytes());
    if n == 0 {
        return None;
    }
    Some(&src[n..])
}

/// Skips a separator, which is `sep` with `SWS` on both sides.
///
/// This covers `SEMI`, `COMMA`, `COLON`, `EQUAL`, `SLASH`, and the other
/// separators that RFC 3261 section 25.1 defines this way. Returns `None` if
/// `src` does not start with `sep` after whitespace.
///
/// # Example
///
/// ```
/// use siparse::scan;
///
/// assert_eq!(scan::separator(" ; tag=1", ';'), Some("tag=1"));
/// assert_eq!(scan::separator(";tag=1", ';'), Some("tag=1"));
/// assert_eq!(scan::separator("tag=1", ';'), None);
/// ```
#[inline]
pub fn separator(src: &str, sep: char) -> Option<&str> {
    Some(sws(sws(src).strip_prefix(sep)?))
}

/// Scans a `token`.
///
/// A token is one or more of `alphanum` and `-.!%*_+` `` ` `` `'~`. Returns
/// `None` if `src` does not start with one.
///
/// # Example
///
/// ```
/// use siparse::scan;
///
/// assert_eq!(scan::token("z9hG4bK776asdhds;rport"), Some(("z9hG4bK776asdhds", ";rport")));
/// assert_eq!(scan::token(";rport"), None);
/// ```
#[inline]
pub fn token(src: &str) -> Option<(&str, &str)> {
    split_run(src, simd::match_token_vectored)
}

/// Scans `1*DIGIT`.
///
/// Returns the digits as written, with any leading zeros, and `None` if `src`
/// does not start with a digit. Converting them to a number, and deciding what
/// range it may have, is up to the caller.
///
/// # Example
///
/// ```
/// use siparse::scan;
///
/// let (digits, rest) = scan::digits("314159 INVITE").unwrap();
/// assert_eq!(digits.parse::<u32>(), Ok(314159));
/// assert_eq!(rest, " INVITE");
/// assert_eq!(scan::digits("INVITE"), None);
/// ```
#[inline]
pub fn digits(src: &str) -> Option<(&str, &str)> {
    split_run(src, simd::match_digits_vectored)
}

/// Scans a `host`, which is a hostname, an IPv4 address, or an IPv6 reference
/// in brackets.
///
/// The host is returned as written, so an IPv6 reference keeps its brackets.
/// This checks character classes, not structure. A hostname is one or more of
/// `alphanum`, `-`, and `.`, which also covers an IPv4 address, and an IPv6
/// reference is `[`, one or more of `HEXDIG`, `:`, and `.`, then `]`. Whether
/// the result is a valid name or address is for the caller to decide, usually
/// by parsing it as one.
///
/// # Example
///
/// ```
/// use siparse::scan;
///
/// assert_eq!(scan::host("pc33.atlanta.example.com:5060"), Some(("pc33.atlanta.example.com", ":5060")));
/// assert_eq!(scan::host("[2001:db8::1]:5060"), Some(("[2001:db8::1]", ":5060")));
/// assert_eq!(scan::host(":5060"), None);
/// ```
#[inline]
pub fn host(src: &str) -> Option<(&str, &str)> {
    if let Some(rest) = src.strip_prefix('[') {
        let (address, rest) = split_run(rest, simd::match_ipv6_vectored)?;
        if !rest.starts_with(']') {
            return None;
        }
        // The brackets and the address are ASCII.
        return Some(src.split_at(address.len() + 2));
    }
    split_run(src, simd::match_hostname_vectored)
}

/// Scans a `quoted-string`.
///
/// The string is returned with its quotes and escapes as written. A backslash
/// escapes the byte after it, which must be ASCII other than `CR` or `LF`, as
/// `quoted-pair` allows. Returns `None` if `src` does not start with `"`, if
/// the string has no closing `"`, or if an escape is malformed.
///
/// # Example
///
/// ```
/// use siparse::scan;
///
/// let value = "\"Bob \\\"B\\\" Smith\" <sip:bob@biloxi.example.com>";
/// let (name, rest) = scan::quoted_string(value).unwrap();
/// assert_eq!(name, "\"Bob \\\"B\\\" Smith\"");
/// assert_eq!(rest, " <sip:bob@biloxi.example.com>");
/// assert_eq!(scan::quoted_string("\"unterminated"), None);
/// ```
#[inline]
pub fn quoted_string(src: &str) -> Option<(&str, &str)> {
    if !src.starts_with('"') {
        return None;
    }
    let mut bytes = Bytes::new(src.as_bytes());
    // SAFETY: `starts_with` saw the opening quote.
    unsafe { bytes.advance(1) };

    loop {
        simd::match_qdtext_vectored(&mut bytes);
        match bytes.next()? {
            // The closing quote is ASCII, so the split is on a character
            // boundary.
            b'"' => return Some(src.split_at(bytes.pos())),
            _ => match bytes.next()? {
                b'\r' | b'\n' | 0x80.. => return None,
                _ => {}
            },
        }
    }
}

/// Splits `src` after the run of bytes that `scan` consumes, or returns `None`
/// if the run is empty.
///
/// The scans only consume ASCII, so the split is on a character boundary.
#[inline(always)]
pub(crate) fn split_run(
    src: &str,
    scan: fn(&mut Bytes<'_>),
) -> Option<(&str, &str)> {
    let mut bytes = Bytes::new(src.as_bytes());
    scan(&mut bytes);
    let n = bytes.pos();
    if n == 0 {
        return None;
    }
    Some(src.split_at(n))
}

/// Returns the length of the whitespace at the start of `src`.
#[inline]
fn whitespace_len(src: &[u8]) -> usize {
    // Whitespace runs are short, usually zero or one byte, so a block scan
    // would mostly miss.
    src.iter()
        .position(|b| !matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
        .unwrap_or(src.len())
}

#[cfg(test)]
mod tests {
    use std::{format, string::ToString, vec::Vec};

    use super::*;

    #[test]
    fn whitespace() {
        assert_eq!(sws(""), "");
        assert_eq!(sws("a"), "a");
        assert_eq!(sws(" \t\r\n \t a b"), "a b");
        assert_eq!(sws("  "), "");
        assert_eq!(lws(""), None);
        assert_eq!(lws("a"), None);
        assert_eq!(lws("\r\n a"), Some("a"));
        assert_eq!(lws(" "), Some(""));
    }

    #[test]
    fn separators() {
        assert_eq!(separator("/UDP", '/'), Some("UDP"));
        assert_eq!(separator(" \r\n / \r\n UDP", '/'), Some("UDP"));
        assert_eq!(separator("/", '/'), Some(""));
        assert_eq!(separator("", '/'), None);
        assert_eq!(separator(" ", '/'), None);
        assert_eq!(separator("UDP", '/'), None);
        assert_eq!(separator("//", '/'), Some("/"));
    }

    #[test]
    fn tokens() {
        assert_eq!(token("INVITE"), Some(("INVITE", "")));
        assert_eq!(token("INVITE sip:"), Some(("INVITE", " sip:")));
        assert_eq!(
            token("-.!%*_+`'~09azAZ;"),
            Some(("-.!%*_+`'~09azAZ", ";"))
        );
        assert_eq!(token(""), None);
        assert_eq!(token(" INVITE"), None);
        assert_eq!(token(";"), None);
        assert_eq!(token("\u{e9}"), None);
        assert_eq!(token("a\u{e9}"), Some(("a", "\u{e9}")));
        // Longer than one SWAR block.
        let long = "z9hG4bK776asdhds-z9hG4bK776asdhds";
        assert_eq!(token(long), Some((long, "")));
        assert_eq!(
            token("z9hG4bK776asdhds,next"),
            Some(("z9hG4bK776asdhds", ",next"))
        );
    }

    #[test]
    fn digit_runs() {
        assert_eq!(digits("0"), Some(("0", "")));
        assert_eq!(digits("007 ACK"), Some(("007", " ACK")));
        assert_eq!(
            digits("12345678901234567890x"),
            Some(("12345678901234567890", "x"))
        );
        assert_eq!(digits(""), None);
        assert_eq!(digits("-1"), None);
        assert_eq!(digits("+1"), None);
        assert_eq!(digits(" 1"), None);
    }

    #[test]
    fn hosts() {
        assert_eq!(host("a"), Some(("a", "")));
        assert_eq!(
            host("pc33.atlanta.example.com;branch=1"),
            Some(("pc33.atlanta.example.com", ";branch=1"))
        );
        assert_eq!(host("192.0.2.4:5060"), Some(("192.0.2.4", ":5060")));
        assert_eq!(host("a-b.c_d"), Some(("a-b.c", "_d")));
        assert_eq!(host("[::1]"), Some(("[::1]", "")));
        assert_eq!(
            host("[2001:db8::192.0.2.4]:5060"),
            Some(("[2001:db8::192.0.2.4]", ":5060"))
        );
        assert_eq!(host("[fe80::1%25eth0]"), None);
        assert_eq!(host(""), None);
        assert_eq!(host(":5060"), None);
        assert_eq!(host("["), None);
        assert_eq!(host("[]"), None);
        assert_eq!(host("[::1"), None);
        assert_eq!(host("[::1 ]"), None);
        assert_eq!(host("[g::1]"), None);
        assert_eq!(host("\u{e9}.example"), None);
    }

    #[test]
    fn quoted_strings() {
        assert_eq!(quoted_string("\"\""), Some(("\"\"", "")));
        assert_eq!(quoted_string("\"a\" b"), Some(("\"a\"", " b")));
        assert_eq!(quoted_string("\"a;b,c\";x"), Some(("\"a;b,c\"", ";x")));
        assert_eq!(quoted_string("\"a\\\"b\""), Some(("\"a\\\"b\"", "")));
        assert_eq!(quoted_string("\"a\\\\\"b"), Some(("\"a\\\\\"", "b")));
        assert_eq!(quoted_string("\"\\\x01\""), Some(("\"\\\x01\"", "")));
        assert_eq!(
            quoted_string("\"\u{7530}\u{4e2d}\" <sip:t@example.com>"),
            Some(("\"\u{7530}\u{4e2d}\"", " <sip:t@example.com>"))
        );
        assert_eq!(quoted_string("\"a \r\n b\""), Some(("\"a \r\n b\"", "")));
        // Longer than one SWAR block before the escape and the end.
        let long = "\"0123456789abcdef\\\"0123456789abcdef\" rest";
        assert_eq!(
            quoted_string(long),
            Some((&long[..long.len() - 5], " rest"))
        );
        assert_eq!(quoted_string(""), None);
        assert_eq!(quoted_string("a\"b\""), None);
        assert_eq!(quoted_string("\""), None);
        assert_eq!(quoted_string("\"abc"), None);
        assert_eq!(quoted_string("\"abc\\"), None);
        assert_eq!(quoted_string("\"abc\\\""), None);
        assert_eq!(quoted_string("\"\\\r\n \""), None);
        assert_eq!(quoted_string("\"\\\u{e9}\""), None);
    }

    /// Scalar references for the scans, as the fuzz target also uses.
    mod reference {
        pub(super) fn run(
            src: &str,
            accept: impl Fn(u8) -> bool,
        ) -> Option<(&str, &str)> {
            let n = src.bytes().take_while(|&b| accept(b)).count();
            if n == 0 {
                return None;
            }
            Some(src.split_at(n))
        }

        pub(super) fn is_token(b: u8) -> bool {
            b.is_ascii_alphanumeric() || b"-.!%*_+`'~".contains(&b)
        }

        pub(super) fn quoted_string(src: &str) -> Option<(&str, &str)> {
            let bytes = src.as_bytes();
            if bytes.first() != Some(&b'"') {
                return None;
            }
            let mut i = 1;
            loop {
                match *bytes.get(i)? {
                    b'"' => return Some(src.split_at(i + 1)),
                    b'\\' => match *bytes.get(i + 1)? {
                        b'\r' | b'\n' | 0x80.. => return None,
                        _ => i += 2,
                    },
                    _ => i += 1,
                }
            }
        }
    }

    #[test]
    fn scans_match_the_scalar_references() {
        // Every string of up to three bytes from an alphabet that covers each
        // class, plus a few longer ones, at every character boundary.
        const ALPHABET: &[char] =
            &['a', '0', '-', '[', ']', ':', '"', '\\', ' ', '\r', '\u{e9}'];
        let mut inputs = Vec::new();
        for a in ALPHABET {
            inputs.push(a.to_string());
            for b in ALPHABET {
                inputs.push(format!("{a}{b}"));
                for c in ALPHABET {
                    inputs.push(format!("{a}{b}{c}"));
                }
            }
        }
        inputs.push("\"0123456789abcdef\\\"0123456789abcdef\" rest".into());
        inputs.push("pc33.atlanta.example.com:5060;branch=z9hG4bK".into());
        inputs.push("[2001:db8::192.0.2.4]:5060".into());

        for input in &inputs {
            let starts = input.char_indices().map(|(i, _)| i);
            for start in starts.chain([input.len()]) {
                let src = &input[start..];
                assert_eq!(
                    token(src),
                    reference::run(src, reference::is_token),
                    "token {src:?}"
                );
                assert_eq!(
                    digits(src),
                    reference::run(src, |b| b.is_ascii_digit()),
                    "digits {src:?}"
                );
                assert_eq!(
                    quoted_string(src),
                    reference::quoted_string(src),
                    "quoted_string {src:?}"
                );
            }
        }
    }
}

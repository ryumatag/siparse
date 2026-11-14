/*!
Scans the lexical elements at the start of a checked header value.

Input comes from a parsed [`crate::Header`], [`HeaderValue::new`] or
[`crate::check::header_value`]. Each scan returns the element as written
and a checked remainder. Nothing is decoded or copied. A missing or
malformed element returns `None`.

```
use siparse::{HeaderValue, scan::{self, Separator}};
let input = HeaderValue::new("branch=z9hG4bK;received=192.0.2.1")?;
let (name, rest) = scan::token(input).unwrap();
let rest = scan::separator(rest, Separator::Equal).unwrap();
let (branch, rest) = scan::token(rest).unwrap();
assert_eq!(name, "branch");
assert_eq!(branch, "z9hG4bK");
assert_eq!(rest.as_str(), ";received=192.0.2.1");
# Ok::<(), siparse::Error>(())
```

A raw string cannot be scanned without checking its header-value syntax:

```compile_fail
siparse::scan::token("INVITE"); // Expected HeaderValue, not &str.
```
*/

use crate::{host::is_host, HeaderValue};

pub(crate) mod raw;

/// An RFC 3261 separator with optional whitespace on both sides.
///
/// Restricting this to grammar separators prevents cutting a checked input
/// inside a quoted-pair or fold. Angle brackets and parentheses belong to
/// the productions that read them, not this whitespace-symmetric rule.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Separator {
    /// `COLON`, `:` with optional whitespace.
    Colon,
    /// `COMMA`, `,` with optional whitespace.
    Comma,
    /// `SEMI`, `;` with optional whitespace.
    Semi,
    /// `EQUAL`, `=` with optional whitespace.
    Equal,
    /// `SLASH`, `/` with optional whitespace.
    Slash,
}

impl Separator {
    fn character(self) -> char {
        match self {
            Separator::Colon => ':',
            Separator::Comma => ',',
            Separator::Semi => ';',
            Separator::Equal => '=',
            Separator::Slash => '/',
        }
    }
}

/// Skips `SWS`, including complete folds. An empty run is allowed.
#[inline]
pub fn sws(src: HeaderValue<'_>) -> HeaderValue<'_> {
    HeaderValue::from_validated(raw::sws(src.as_str()))
}

/// Skips `LWS`, returning `None` if there is no leading whitespace.
#[inline]
pub fn lws(src: HeaderValue<'_>) -> Option<HeaderValue<'_>> {
    raw::lws(src.as_str()).map(HeaderValue::from_validated)
}

/// Skips a separator and optional whitespace on both sides.
#[inline]
pub fn separator(
    src: HeaderValue<'_>,
    sep: Separator,
) -> Option<HeaderValue<'_>> {
    raw::separator(src.as_str(), sep.character())
        .map(HeaderValue::from_validated)
}

/// Reads an RFC 3261 `token`, keeping its spelling unchanged.
/// A token contains one or more alphanumeric bytes or `-.!%*_+` `` ` `` `'~`.
#[inline]
pub fn token(src: HeaderValue<'_>) -> Option<(&str, HeaderValue<'_>)> {
    split(src, raw::token)
}

/// Reads `1*DIGIT` without converting it or checking a numeric range.
#[inline]
pub fn digits(src: HeaderValue<'_>) -> Option<(&str, HeaderValue<'_>)> {
    split(src, raw::digits)
}

/// Reads a structurally valid hostname, IPv4 address or bracketed IPv6
/// reference. IP syntax follows RFC 5954's correction to RFC 3261.
/// Brackets, case and trailing dots are preserved.
#[inline]
pub fn host(src: HeaderValue<'_>) -> Option<(&str, HeaderValue<'_>)> {
    let (host, rest) = split(src, raw::host)?;
    is_host(host).then_some((host, rest))
}

/// Reads a `quoted-string`, preserving quotes and escapes.
/// A quoted-pair escapes one ASCII byte other than CR or LF.
#[inline]
pub fn quoted_string(src: HeaderValue<'_>) -> Option<(&str, HeaderValue<'_>)> {
    split(src, raw::quoted_string)
}

/// Reads a possibly nested `comment`, preserving parentheses and escapes.
/// Nesting uses a counter rather than recursion.
#[inline]
pub fn comment(src: HeaderValue<'_>) -> Option<(&str, HeaderValue<'_>)> {
    split(src, raw::comment)
}

// The readers stop between grammar elements, never inside a quoted-pair,
// UTF-8 sequence or fold, so their remainders retain the input's invariant.
#[inline(always)]
fn split<'a>(
    src: HeaderValue<'a>,
    read: fn(&'a str) -> Option<(&'a str, &'a str)>,
) -> Option<(&'a str, HeaderValue<'a>)> {
    let (token, rest) = read(src.as_str())?;
    Some((token, HeaderValue::from_validated(rest)))
}

#[cfg(test)]
mod tests {
    use std::{string::String, vec::Vec};

    use super::*;

    #[test]
    #[cfg_attr(
        miri,
        ignore = "exhaustive grammar inputs do not add pointer coverage"
    )]
    fn scans_preserve_checked_remainders() {
        const PIECES: &[&str] =
            &["a", "1", ";", "\"", "(", ")", "\\", "\x01", "\r\n ", "é"];
        let mut inputs = Vec::from([String::new()]);
        let mut level = inputs.clone();
        for _ in 0..4 {
            level = level
                .iter()
                .flat_map(|s| {
                    PIECES.iter().map(move |p| {
                        let mut next = s.clone();
                        next.push_str(p);
                        next
                    })
                })
                .collect();
            inputs.extend(level.iter().cloned());
        }
        let reads = [token, digits, host, quoted_string, comment];
        for text in &inputs {
            let Ok(input) = HeaderValue::new(text) else { continue };
            let assert_tail = |tail: HeaderValue<'_>| {
                assert!(
                    HeaderValue::new(tail.as_str()).is_ok(),
                    "{text:?} -> {tail:?}"
                );
                assert_eq!(
                    tail.as_str().as_ptr(),
                    text[text.len() - tail.len()..].as_ptr()
                );
            };
            assert_tail(sws(input));
            if let Some(tail) = lws(input) {
                assert_tail(tail);
            }
            for sep in [
                Separator::Colon,
                Separator::Comma,
                Separator::Semi,
                Separator::Equal,
                Separator::Slash,
            ] {
                if let Some(tail) = separator(input, sep) {
                    assert_tail(tail);
                }
            }
            for read in reads {
                if let Some((_, tail)) = read(input) {
                    assert_tail(tail);
                }
            }
        }
    }

    #[test]
    fn hosts_have_structure_and_preserve_their_spelling() {
        for text in ["-", "[:::]", "a..example.com"] {
            assert!(host(HeaderValue::new(text).unwrap()).is_none());
        }
        let (found, rest) =
            host(HeaderValue::new("[2001:DB8::1]:5060").unwrap()).unwrap();
        assert_eq!(found, "[2001:DB8::1]");
        assert_eq!(rest.as_str(), ":5060");
    }
}

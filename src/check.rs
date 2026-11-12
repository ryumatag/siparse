/*!
Checks single elements before they are written into a head.

Each function checks that the whole input is one element, such as a header
value, and returns it as a `&str` borrowed from the input. A crate that
builds SIP messages from parts can use these to accept exactly what the
parser accepts in a head, without copying the grammar. The checks cover what
a head allows, not the grammar of a particular header or URI. To read a
received value by its grammar, use [`value`](crate::value) or
[`uri`](crate::uri).

Unlike in a head, nothing follows the element. A delimiter that would end
it in a head, such as the `SP` after a method or a `CRLF` that does not
start a fold, is an error here. A header value may also start with
whitespace or a fold, which a head would count as part of the separator
after the `:`.

Each check comes in two forms:

* The plain one, such as [`header_value`], runs the same code as the head
  parser, so it is as fast and accepts exactly the same bytes.
* The `_const` one, such as [`header_value_const`], is a `const fn`, for
  checking constants at compile time. It checks one byte at a time, so it
  is slower at run time. It accepts the same bytes and reports the same
  [`ErrorKind`](crate::ErrorKind) as the plain one.

An `_error_offset` function, such as [`header_value_error_offset`], also
says where a check fails. See [error offsets](#error-offsets).

```
use siparse::{check, ErrorKind};

let value = check::header_value(b"\"Bob \\\x01\" <sip:bob@biloxi.example.com>")?;
assert!(value.starts_with("\"Bob"));

let err = check::header_value(b"one\r\ntwo").unwrap_err();
assert_eq!(err.kind(), ErrorKind::HeaderValue);

const CONTENT_TYPE: &str = match check::header_value_const(b"application/sdp") {
    Ok(value) => value,
    Err(_) => panic!("invalid header value"),
};
assert_eq!(CONTENT_TYPE, "application/sdp");
# Ok::<(), siparse::Error>(())
```

# Error offsets

[`Error`] does not say where a check failed, which keeps it small for the
head parser. When the place matters, such as in an error message, call
`*_error_offset` after a check fails. It scans `src` again one byte at a
time, so a successful check costs nothing extra.

The offset points at the first byte that the check does not accept:

* a byte outside the element's set, such as a control in a header value
  that no backslash escapes;
* a bare `CR` or `LF`;
* the byte after a `CRLF` that does not start a fold;
* a `%`-escape digit that is not hexadecimal;
* the byte of a UTF-8 sequence that does not fit it.

It is `src.len()` if `src` ends too early, such as an empty method or a
cut-off `%`-escape, UTF-8 sequence, or fold.

```
use siparse::check;

let src = b"\"Alice\" <sip:alice@atlanta.example.com>\x01";
assert!(check::header_value(src).is_err());
assert_eq!(check::header_value_error_offset(src), Some(src.len() - 1));
```

The status code and the version have no checks here. They are fixed
three-digit and literal tokens that a consumer usually narrows further.
*/

use core::str;

use crate::{
    error::Error,
    iter::Bytes,
    parse::{self, Result as ParseResult, Status, Whole},
    token::{
        is_header_name_token, is_header_value_ascii, is_method_token,
        is_reason_phrase_octet, is_uri_token,
    },
};

/// Checks that `src` is a SIP method, an RFC 3261 `token`.
///
/// # Errors
///
/// Returns an [`ErrorKind::Method`](crate::ErrorKind::Method) error if
/// `src` is empty or has a byte outside the `token` set.
#[inline]
pub fn method(src: &[u8]) -> Result<&str, Error> {
    whole(src, parse::method::<Whole>, Error::method())
}

/// Checks that `src` is a Request-URI, in the URI character set that the
/// parser accepts in a request-line.
///
/// This does not check the structure of a SIP or other URI. See the
/// crate's notes on the request-line.
///
/// # Errors
///
/// Returns an [`ErrorKind::RequestUri`](crate::ErrorKind::RequestUri) error
/// if `src` is empty or has a byte outside that set.
#[inline]
pub fn request_uri(src: &[u8]) -> Result<&str, Error> {
    whole(src, parse::request_uri::<Whole>, Error::request_uri())
}

/// Checks that `src` is a reason phrase. It may be empty.
///
/// `%`-escapes are checked but not decoded.
///
/// # Errors
///
/// Returns an [`ErrorKind::ReasonPhrase`](crate::ErrorKind::ReasonPhrase)
/// error if `src` has a byte outside the reason phrase set, including `CR`
/// and `LF`, a malformed `%`-escape, or invalid UTF-8.
#[inline]
pub fn reason_phrase(src: &[u8]) -> Result<&str, Error> {
    whole(src, parse::reason_phrase::<Whole>, Error::reason_phrase())
}

/// Checks that `src` is a header field name, an RFC 3261 `token`.
///
/// # Errors
///
/// Returns an [`ErrorKind::HeaderName`](crate::ErrorKind::HeaderName) error
/// if `src` is empty or has a byte outside the `token` set, including
/// whitespace and `:`.
#[inline]
pub fn header_name(src: &[u8]) -> Result<&str, Error> {
    whole(src, parse::header_name::<Whole>, Error::header_name())
}

/// Checks that `src` is a header field value. It may be empty.
///
/// This accepts what the parser accepts in a header row, as described in the
/// crate's [header value policy](crate#header-values), with folds kept. It
/// also accepts leading whitespace and folds.
///
/// # Errors
///
/// Returns an error of kind:
///
/// * [`BareCr`](crate::ErrorKind::BareCr) for a `CR` not followed by `LF`;
/// * [`BareLf`](crate::ErrorKind::BareLf) for an `LF` not preceded by `CR`;
/// * [`HeaderValue`](crate::ErrorKind::HeaderValue) for a `CRLF` not
///   followed by `SP` or `HTAB`, a control that no backslash escapes, or
///   invalid UTF-8.
#[inline]
pub fn header_value(src: &[u8]) -> Result<&str, Error> {
    whole(src, parse::header_value::<Whole>, Error::header_value())
}

/// Runs a production on `src` as one whole token.
///
/// A production only runs out of input in the middle of a `%`-escape or a
/// UTF-8 sequence, which `truncated` then reports.
#[inline(always)]
fn whole<'a>(
    src: &'a [u8],
    production: impl FnOnce(&mut Bytes<'a>) -> ParseResult<&'a str>,
    truncated: Error,
) -> Result<&'a str, Error> {
    let mut bytes = Bytes::new(src);
    match production(&mut bytes)? {
        Status::Complete(token) => {
            debug_assert!(bytes.is_empty());
            Ok(token)
        }
        Status::Partial => Err(truncated),
    }
}

// The `const` forms and the error offsets.
//
// Each element has one scalar scan that finds the first fault, as the error
// and the offset of the byte the check does not accept. `*_const` keeps the
// error and `*_error_offset` keeps the offset, so the two always agree.

/// An error and where it was found. See the module docs for the offsets.
type Fault = (Error, usize);

// Scans a `token`-like element whose bytes all come from one set. A macro
// rather than a function, because a `const fn` cannot call a function
// pointer on stable Rust.
macro_rules! token_fault {
    ($src:expr, $predicate:path, $error:expr) => {{
        let src: &[u8] = $src;
        let mut fault = None;
        if src.is_empty() {
            fault = Some(($error, 0));
        }
        let mut i = 0;
        while fault.is_none() && i < src.len() {
            if !$predicate(src[i]) {
                fault = Some(($error, i));
            }
            i += 1;
        }
        fault
    }};
}

const fn method_fault(src: &[u8]) -> Option<Fault> {
    token_fault!(src, is_method_token, Error::method())
}

const fn request_uri_fault(src: &[u8]) -> Option<Fault> {
    token_fault!(src, is_uri_token, Error::request_uri())
}

const fn header_name_fault(src: &[u8]) -> Option<Fault> {
    token_fault!(src, is_header_name_token, Error::header_name())
}

const fn reason_phrase_fault(src: &[u8]) -> Option<Fault> {
    let error = Error::reason_phrase();
    let mut i = 0;
    while i < src.len() {
        let b = src[i];
        if is_reason_phrase_octet(b) {
            i += 1;
        } else if b == b'%' {
            // `%` HEXDIG HEXDIG. Point at the first digit that is wrong or
            // missing.
            let mut j = i + 1;
            while j < i + 3 {
                if j >= src.len() {
                    return Some((error, src.len()));
                }
                if !src[j].is_ascii_hexdigit() {
                    return Some((error, j));
                }
                j += 1;
            }
            i += 3;
        } else if b >= 0x80 {
            match utf8_char(src, i) {
                Ok(len) => i += len,
                Err(at) => return Some((error, at)),
            }
        } else {
            return Some((error, i));
        }
    }
    None
}

const fn header_value_fault(src: &[u8]) -> Option<Fault> {
    let mut i = 0;
    // Whether the bytes before `i` end in an odd run of backslashes. The
    // head parser looks back for that run only when it meets a control. A
    // flag gives the same answer in one forward pass.
    let mut escaped = false;

    while i < src.len() {
        let b = src[i];
        let was_escaped = escaped;
        escaped = false;

        match b {
            b'\r' => {
                if i + 1 >= src.len() || src[i + 1] != b'\n' {
                    return Some((Error::bare_cr(), i));
                }
                // A `CRLF` must start a fold. Point at what follows it.
                if i + 2 >= src.len() {
                    return Some((Error::header_value(), src.len()));
                }
                if !matches!(src[i + 2], b' ' | b'\t') {
                    return Some((Error::header_value(), i + 2));
                }
                i += 3;
            }
            b'\n' => return Some((Error::bare_lf(), i)),
            b'\\' => {
                escaped = !was_escaped;
                i += 1;
            }
            0x00..=0x08 | 0x0b..=0x0c | 0x0e..=0x1f | 0x7f => {
                if !was_escaped {
                    return Some((Error::header_value(), i));
                }
                i += 1;
            }
            b if is_header_value_ascii(b) => i += 1,
            _ => match utf8_char(src, i) {
                Ok(len) => i += len,
                Err(at) => return Some((Error::header_value(), at)),
            },
        }
    }
    None
}

/// Returns the length of the modern UTF-8 sequence that starts at `src[i]`.
///
/// This accepts the same sequences as the parser's UTF-8 check. If the
/// sequence is invalid, the error is the offset of the first byte that does
/// not fit it, or `src.len()` if it is cut short.
const fn utf8_char(src: &[u8], i: usize) -> Result<usize, usize> {
    // The length, and the range of the second byte. Later bytes are always
    // `0x80..=0xbf`.
    let (len, low, high) = match src[i] {
        0xc2..=0xdf => (2, 0x80, 0xbf),
        0xe0 => (3, 0xa0, 0xbf),
        0xe1..=0xec | 0xee..=0xef => (3, 0x80, 0xbf),
        0xed => (3, 0x80, 0x9f),
        0xf0 => (4, 0x90, 0xbf),
        0xf1..=0xf3 => (4, 0x80, 0xbf),
        0xf4 => (4, 0x80, 0x8f),
        _ => return Err(i),
    };
    let mut j = 1;
    while j < len {
        if i + j >= src.len() {
            return Err(src.len());
        }
        let (low, high) = if j == 1 { (low, high) } else { (0x80, 0xbf) };
        if src[i + j] < low || src[i + j] > high {
            return Err(i + j);
        }
        j += 1;
    }
    Ok(len)
}

/// Returns `src` as a `&str` if the scan found no fault.
///
/// # Safety
///
/// `fault` must come from one of the scans above, run on `src`. Each scan
/// only passes ASCII and complete modern UTF-8 sequences.
const unsafe fn into_result(
    src: &[u8],
    fault: Option<Fault>,
) -> Result<&str, Error> {
    match fault {
        Some((error, _)) => Err(error),
        // SAFETY: Forwarded to the caller. The scan found every byte of
        // `src` to be valid UTF-8.
        None => Ok(unsafe { str::from_utf8_unchecked(src) }),
    }
}

const fn into_offset(fault: Option<Fault>) -> Option<usize> {
    match fault {
        Some((_, at)) => Some(at),
        None => None,
    }
}

macro_rules! const_forms {
    ($(
        $check:ident, $check_const:ident, $error_offset:ident, $fault:ident;
    )+) => {
        $(
            #[doc = concat!(
                "Checks `src` like [`", stringify!($check), "`], in a ",
                "`const` context.\n\n",
                "# Errors\n\n",
                "The same as [`", stringify!($check), "`].",
            )]
            pub const fn $check_const(src: &[u8]) -> Result<&str, Error> {
                // SAFETY: The fault comes from the scan for this element,
                // run on `src`.
                unsafe { into_result(src, $fault(src)) }
            }

            #[doc = concat!(
                "Returns where [`", stringify!($check), "`] fails on `src`, ",
                "or `None` if it accepts `src`.\n\n",
                "See [error offsets](self#error-offsets) for what the ",
                "offset points at.",
            )]
            pub const fn $error_offset(src: &[u8]) -> Option<usize> {
                into_offset($fault(src))
            }
        )+
    };
}

const_forms! {
    method, method_const, method_error_offset, method_fault;
    request_uri, request_uri_const, request_uri_error_offset,
        request_uri_fault;
    reason_phrase, reason_phrase_const, reason_phrase_error_offset,
        reason_phrase_fault;
    header_name, header_name_const, header_name_error_offset,
        header_name_fault;
    header_value, header_value_const, header_value_error_offset,
        header_value_fault;
}

#[cfg(test)]
mod tests {
    use std::vec::Vec;

    use super::*;
    use crate::{AnyHead, ErrorKind, HeaderBuf, StartLine, Status};

    type Check = fn(&[u8]) -> Result<&str, Error>;

    const CHECKS: [(&str, Check, Check); 5] = [
        ("method", method, method_const),
        ("request_uri", request_uri, request_uri_const),
        ("reason_phrase", reason_phrase, reason_phrase_const),
        ("header_name", header_name, header_name_const),
        ("header_value", header_value, header_value_const),
    ];

    /// Bytes that take every branch of the checks: delimiters, line
    /// endings, controls, backslashes, escapes, and UTF-8 lead and
    /// continuation bytes, valid or not.
    const ALPHABET: &[u8] = &[
        b'a', b'4', b'g', b' ', b'\t', b'\r', b'\n', b'\\', b'%', b':', 0x01,
        0x7f, 0xc3, 0xa9, 0xe2, 0x82, 0xac, 0xed, 0xa0, 0xff,
    ];

    /// Calls `f` with every string over `ALPHABET` of up to `max_len` bytes.
    fn for_each_input(max_len: usize, mut f: impl FnMut(&[u8])) {
        let mut input = Vec::new();
        let mut stack = Vec::from([0usize]);
        f(&input);
        while let Some(&next) = stack.last() {
            if input.len() < max_len && next < ALPHABET.len() {
                input.push(ALPHABET[next]);
                f(&input);
                stack.push(0);
            } else {
                stack.pop();
                input.pop();
                if let Some(top) = stack.last_mut() {
                    *top += 1;
                }
            }
        }
    }

    #[test]
    fn const_forms_agree_with_runtime_forms() {
        for (name, runtime, konst) in CHECKS {
            for_each_input(4, |input| {
                assert_eq!(runtime(input), konst(input), "{name} {input:?}");
            });
        }
    }

    /// Returns what a head parser stores for the element of `name` when
    /// `input` is placed in a head, if it parses.
    fn parsed_in_head(name: &str, input: &[u8]) -> Option<Vec<u8>> {
        let (before, after): (&[u8], &[u8]) = match name {
            "method" => (b"", b" sip:a SIP/2.0\r\n\r\n"),
            "request_uri" => (b"OPTIONS ", b" SIP/2.0\r\n\r\n"),
            "reason_phrase" => (b"SIP/2.0 200 ", b"\r\n\r\n"),
            "header_name" => (b"OPTIONS sip:a SIP/2.0\r\n", b": v\r\n\r\n"),
            "header_value" => (b"OPTIONS sip:a SIP/2.0\r\nX: ", b"\r\n\r\n"),
            _ => unreachable!(),
        };
        let mut buf = Vec::from(before);
        buf.extend_from_slice(input);
        buf.extend_from_slice(after);

        let mut headers = HeaderBuf::<4>::new();
        let mut head = AnyHead::new(&mut headers);
        let Ok(Status::Complete(_)) = head.parse(&buf) else {
            return None;
        };
        let token = match (name, head.start_line?) {
            ("method", StartLine::Request(line)) => line.method?,
            ("request_uri", StartLine::Request(line)) => line.uri?,
            ("reason_phrase", StartLine::Status(line)) => line.reason_phrase?,
            ("header_name", _) => head.headers.first()?.name,
            ("header_value", _) => head.headers.first()?.value,
            _ => return None,
        };
        Some(token.as_bytes().to_vec())
    }

    // A check accepts an input exactly when the head parser stores that same
    // input for the element. Values that start with whitespace are skipped,
    // because a head counts it as part of the separator.
    #[test]
    fn agrees_with_head_parsing() {
        for (name, runtime, _) in CHECKS {
            for_each_input(3, |input| {
                if name == "header_value"
                    && (input.starts_with(b" ")
                        || input.starts_with(b"\t")
                        || input.starts_with(b"\r\n"))
                {
                    return;
                }
                let checked =
                    runtime(input).ok().map(|s| s.as_bytes().to_vec());
                let parsed =
                    parsed_in_head(name, input).filter(|token| token == input);
                assert_eq!(checked, parsed, "{name} {input:?}");
            });
        }
    }

    type ErrorOffset = fn(&[u8]) -> Option<usize>;

    const OFFSETS: [(&str, Check, ErrorOffset); 5] = [
        ("method", method, method_error_offset),
        ("request_uri", request_uri, request_uri_error_offset),
        ("reason_phrase", reason_phrase, reason_phrase_error_offset),
        ("header_name", header_name, header_name_error_offset),
        ("header_value", header_value, header_value_error_offset),
    ];

    // An offset exists exactly when the check fails, and lies within the
    // input or just past it.
    #[test]
    fn error_offsets_agree_with_checks() {
        for (name, check, error_offset) in OFFSETS {
            for_each_input(4, |input| {
                let offset = error_offset(input);
                assert_eq!(
                    offset.is_some(),
                    check(input).is_err(),
                    "{name} {input:?}"
                );
                assert!(
                    offset.map_or(true, |at| at <= input.len()),
                    "{name} {input:?}"
                );
            });
        }
    }

    #[test]
    fn error_offsets_point_at_the_fault() {
        assert_eq!(method_error_offset(b""), Some(0));
        assert_eq!(method_error_offset(b"IN VITE"), Some(2));
        assert_eq!(
            request_uri_error_offset(b"sip:bob@biloxi.example.com#x"),
            Some(26)
        );
        assert_eq!(header_name_error_offset(b"Call-ID:"), Some(7));

        assert_eq!(reason_phrase_error_offset(b"Busy Here"), None);
        assert_eq!(reason_phrase_error_offset(b"Say \"hi\""), Some(4));
        assert_eq!(reason_phrase_error_offset(b"100%4g"), Some(5));
        assert_eq!(reason_phrase_error_offset(b"100%4"), Some(5));
        assert_eq!(reason_phrase_error_offset(b"ab\xe3\x81"), Some(4));
        assert_eq!(reason_phrase_error_offset(b"ab\xe3\x41\x81"), Some(3));

        assert_eq!(header_value_error_offset(b"one\r\n two"), None);
        assert_eq!(header_value_error_offset(b"one\rtwo"), Some(3));
        assert_eq!(header_value_error_offset(b"one\ntwo"), Some(3));
        assert_eq!(header_value_error_offset(b"one\r\ntwo"), Some(5));
        assert_eq!(header_value_error_offset(b"one\r\n"), Some(5));
        assert_eq!(header_value_error_offset(b"a\\\\\x01"), Some(3));
        assert_eq!(header_value_error_offset(b"a\\\x01\x01"), Some(3));
        assert_eq!(header_value_error_offset(b"caf\xc3"), Some(4));
        assert_eq!(header_value_error_offset(b"\xff"), Some(0));
    }

    #[test]
    fn error_offsets_are_const() {
        const OFFSET: Option<usize> = header_value_error_offset(b"bad\x00");
        assert_eq!(OFFSET, Some(3));
    }

    fn kind(result: Result<&str, Error>) -> ErrorKind {
        result.unwrap_err().kind()
    }

    #[test]
    fn tokens() {
        assert_eq!(method(b"INVITE"), Ok("INVITE"));
        assert_eq!(kind(method(b"")), ErrorKind::Method);
        assert_eq!(kind(method(b"IN VITE")), ErrorKind::Method);
        assert_eq!(kind(method(b"INVITE ")), ErrorKind::Method);

        assert_eq!(header_name(b"Call-ID"), Ok("Call-ID"));
        assert_eq!(kind(header_name(b"")), ErrorKind::HeaderName);
        assert_eq!(kind(header_name(b"Call-ID:")), ErrorKind::HeaderName);
        assert_eq!(kind(header_name(b"Call ID")), ErrorKind::HeaderName);

        assert_eq!(
            request_uri(b"sip:bob@[2001:db8::1];transport=tcp"),
            Ok("sip:bob@[2001:db8::1];transport=tcp")
        );
        assert_eq!(kind(request_uri(b"")), ErrorKind::RequestUri);
        assert_eq!(
            kind(request_uri(b"sip:bob@biloxi.example.com ")),
            ErrorKind::RequestUri
        );
    }

    #[test]
    fn reason_phrases() {
        assert_eq!(reason_phrase(b""), Ok(""));
        assert_eq!(reason_phrase(b"Busy Here"), Ok("Busy Here"));
        assert_eq!(reason_phrase(b"Say %22hi%22"), Ok("Say %22hi%22"));
        assert_eq!(reason_phrase("話し中".as_bytes()), Ok("話し中"));

        for invalid in
            [&b"Busy\r"[..], b"Busy\n", b"100%", b"100%4", b"%4g", b"\xe8\xa9"]
        {
            assert_eq!(
                kind(reason_phrase(invalid)),
                ErrorKind::ReasonPhrase,
                "{invalid:?}"
            );
        }
    }

    #[test]
    fn header_values() {
        assert_eq!(header_value(b""), Ok(""));
        assert_eq!(
            header_value(b" leading and trailing\t"),
            Ok(" leading and trailing\t")
        );
        assert_eq!(
            header_value(b"\r\n folded first"),
            Ok("\r\n folded first")
        );
        assert_eq!(
            header_value(b"one\r\n\ttwo\r\n "),
            Ok("one\r\n\ttwo\r\n ")
        );
        assert_eq!(header_value(b"\"a\\\x01\""), Ok("\"a\\\x01\""));

        assert_eq!(kind(header_value(b"one\r\ntwo")), ErrorKind::HeaderValue);
        assert_eq!(kind(header_value(b"one\r\n")), ErrorKind::HeaderValue);
        assert_eq!(kind(header_value(b"one\r")), ErrorKind::BareCr);
        assert_eq!(kind(header_value(b"one\rtwo")), ErrorKind::BareCr);
        assert_eq!(kind(header_value(b"one\ntwo")), ErrorKind::BareLf);
        assert_eq!(
            kind(header_value(b"\"a\\\\\x01\"")),
            ErrorKind::HeaderValue
        );
        assert_eq!(kind(header_value(b"\xc3")), ErrorKind::HeaderValue);
        assert_eq!(kind(header_value(b"\\\xff")), ErrorKind::HeaderValue);
    }

    // The inputs above are shorter than one block of the vectored scans.
    // These put two bytes from `ALPHABET` at every position of a longer
    // valid input, so they land in a block, at a block edge, and in the tail.
    #[test]
    fn const_forms_agree_on_long_inputs() {
        const BASE: &[u8] = b"abcdefghijklmnopqrstuvwxyz";

        for (name, runtime, konst) in CHECKS {
            for at in 0..=BASE.len() {
                for &first in ALPHABET {
                    for &second in ALPHABET {
                        let mut input = Vec::from(&BASE[..at]);
                        input.extend([first, second]);
                        input.extend_from_slice(&BASE[at..]);
                        assert_eq!(
                            runtime(&input),
                            konst(&input),
                            "{name} {input:?}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn usable_in_constants() {
        const METHOD: Result<&str, Error> = method_const(b"OPTIONS");
        const URI: Result<&str, Error> =
            request_uri_const(b"sip:carol@chicago.example.com");
        const REASON: Result<&str, Error> = reason_phrase_const(b"Ringing");
        const NAME: Result<&str, Error> = header_name_const(b"Max-Forwards");
        const VALUE: Result<&str, Error> = header_value_const(b"70");

        assert_eq!(METHOD, Ok("OPTIONS"));
        assert_eq!(URI, Ok("sip:carol@chicago.example.com"));
        assert_eq!(REASON, Ok("Ringing"));
        assert_eq!(NAME, Ok("Max-Forwards"));
        assert_eq!(VALUE, Ok("70"));
    }
}

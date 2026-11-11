/*!
Public API fuzzing for siparse.

A smoke run with AddressSanitizer and bounded input size:

```text
mkdir -p tmp/fuzz-request tmp/fuzz-response
cargo +nightly fuzz run request_head \
    tmp/fuzz-request fuzz/corpus/request_head -- \
    -max_total_time=30 -max_len=4096
cargo +nightly fuzz run response_head \
    tmp/fuzz-response fuzz/corpus/response_head -- \
    -max_total_time=30 -max_len=4096
```

The `find_head_end` target compares [`siparse::find_head_end`] against a
one-window-at-a-time search at every `scanned`, and checks that it finds
the end the parser returns:

```text
mkdir -p tmp/fuzz-find-head-end
cargo +nightly fuzz run find_head_end \
    tmp/fuzz-find-head-end fuzz/corpus/request_head -- \
    -max_total_time=30 -max_len=4096
```

The `scan` target compares each function of [`siparse::scan`] against a
scalar reference at every character boundary of the input, and checks that
the element and the rest are the two halves of the input:

```text
mkdir -p tmp/fuzz-scan
cargo +nightly fuzz run scan \
    tmp/fuzz-scan fuzz/corpus/scan -- \
    -max_total_time=30 -max_len=4096
```

The `check` target runs each function of [`siparse::check`] on the input.
The plain form runs the head parser's code, SIMD included, and the `_const`
form and the error offset scan one byte at a time, so it checks that all
three agree. It also checks that a failing input is accepted up to its
error offset:

```text
mkdir -p tmp/fuzz-check
cargo +nightly fuzz run check \
    tmp/fuzz-check fuzz/corpus/check -- \
    -max_total_time=30 -max_len=4096
```

The `value` target compares [`siparse::value`] against a reference that
walks byte indices, on input that is a valid header value. It checks the
addresses of a list, a single address, and the parameters at every character
boundary, and that every part is borrowed from the input:

```text
mkdir -p tmp/fuzz-value
cargo +nightly fuzz run value \
    tmp/fuzz-value fuzz/corpus/value -- \
    -max_total_time=30 -max_len=4096
```

The harness checks borrowed ranges and initialized rows on every outcome,
including errors. It compares parsing results across header buffer capacities,
including zero, exact-fit, and insufficient capacities, using a 16-slot parse
as the reference. Inputs exceeding 16 rows still exercise overflow, but
successful complete-head properties require at most 16 rows. Each parse reuses
a head first populated with a valid row to exercise reset. Both targets also
check that `AnyHead` returns exactly what the parser its start-line selects
returns.

Only a head that actually returns `Complete(end)` supplies the prefix oracle.
Each fuzz iteration checks the beginning, the last position before end, and one
sampled interior cut. It makes no claim that an arbitrary `Partial` can be
extended into valid input. The deterministic seed tests check every cut
position and run without nightly or sanitizer support:

```text
cargo test --manifest-path fuzz/Cargo.toml --lib
```
*/

use std::ops::Range;

use siparse::{
    AnyHead, Error, ErrorKind, HeaderBuf, RequestHead, ResponseHead,
    StartLine, Status,
};

type ParseResult = Result<Status<usize>, Error>;

#[derive(Debug, PartialEq, Eq)]
struct Observation {
    result: ParseResult,
    fields: [Option<Range<usize>>; 3],
    rows: Vec<(Range<usize>, Range<usize>)>,
}

fn borrowed_range(input: &[u8], token: &str) -> Range<usize> {
    let start = (token.as_ptr() as usize)
        .checked_sub(input.as_ptr() as usize)
        .expect("token starts within input");
    let end =
        start.checked_add(token.len()).expect("token range does not overflow");
    let source = input.get(start..end).expect("token ends within input");
    assert!(std::str::from_utf8(source).is_ok());
    assert_eq!(token.as_bytes(), source);
    start..end
}

fn check_capacity(
    reference: &Observation,
    actual: &Observation,
    capacity: usize,
) {
    assert_eq!(actual.fields, reference.fields);
    let visible = reference.rows.len().min(capacity);
    assert_eq!(actual.rows, reference.rows[..visible]);
    if reference.rows.len() > capacity {
        assert_eq!(
            actual.result.unwrap_err().kind(),
            ErrorKind::TooManyHeaders
        );
    } else {
        // A full buffer can still return Partial for an unfinished extra row.
        assert_eq!(actual.result, reference.result);
    }
}

fn check_prefix(reference: &Observation, prefix: &Observation) {
    assert_eq!(prefix.result, Ok(Status::Partial));
    for (field, complete) in prefix.fields.iter().zip(&reference.fields) {
        if field.is_some() {
            assert_eq!(field, complete);
        }
    }
    assert_eq!(prefix.rows, reference.rows[..prefix.rows.len()]);
}

macro_rules! exact_capacity {
    ($parse:ident, $reference:ident, $input:ident, $($n:literal),*) => {
        match $reference.rows.len() {
            0 => {},
            $( $n => {
                check_capacity(&$reference, &$parse::<$n>($input), $n);
                check_capacity(&$reference, &$parse::<{ $n - 1 }>($input), $n - 1);
            }, )*
            _ => unreachable!("reference storage holds at most 16 rows"),
        }
    };
}

// Both public entry points must satisfy the same storage and borrowing
// contract. Generate the identical oracle for their different start-line
// fields without introducing a parser abstraction into the library.
macro_rules! harness {
    ($run:ident, $parse:ident, $head:ident, [$($field:ident),+], $primer:expr) => {
        fn $parse<const N: usize>(input: &[u8]) -> Observation {
            let mut storage = HeaderBuf::<N>::new();
            let mut head = $head::new(&mut storage);
            // Even zero-capacity storage must reset a previously parsed
            // start-line after the primer reports TooManyHeaders.
            let _ = head.parse($primer);
            let result = head.parse(input);
            let limit = match result {
                Ok(Status::Complete(end)) => {
                    assert!(end <= input.len());
                    assert!(head.start_line.complete().is_some());
                    end
                }
                _ => input.len(),
            };
            let fields = [$(head.start_line.$field.map(|s| borrowed_range(input, s))),+];
            let rows: Vec<_> = head.headers.iter().map(|row| {
                (borrowed_range(input, row.name), borrowed_range(input, row.value))
            }).collect();
            assert!(rows.len() <= N);
            let mut previous_end = 0;
            for range in fields.iter().flatten() {
                assert!(range.start >= previous_end);
                assert!(range.end <= limit);
                previous_end = range.end;
            }
            for (name, value) in &rows {
                assert!(name.start >= previous_end);
                assert!(value.start > name.end);
                assert!(value.end <= limit);
                previous_end = value.end;
            }
            Observation { result, fields, rows }
        }

        pub fn $run(input: &[u8]) {
            check_any_head(input);

            let reference = $parse::<16>(input);
            check_capacity(&reference, &$parse::<0>(input), 0);
            // Const capacities keep the harness on the public HeaderBuf API.
            // The reference also covers spare capacity when it holds <16 rows.
            exact_capacity!($parse, reference, input,
                1usize, 2usize, 3usize, 4usize, 5usize,
                6usize, 7usize, 8usize, 9usize, 10usize, 11usize, 12usize,
                13usize, 14usize, 15usize, 16usize);

            if let Ok(Status::Complete(end)) = reference.result {
                assert!(end > 0);
                // Sampling avoids quadratic work for large successful heads.
                // Mutation of these bytes also explores different cut positions.
                let selector = input.iter().fold(0usize, |n, &b| {
                    n.wrapping_mul(257).wrapping_add(b as usize)
                });
                for cut in [0, 1, end - 1, selector % end] {
                    check_prefix(&reference, &$parse::<16>(&input[..cut]));
                }
            }
        }
    };
}

// `AnyHead` must behave exactly like the parser its start-line selects. The
// oracle decides the kind independently of the library, from the first four
// bytes after any leading `CRLF`s.
fn check_any_head(input: &[u8]) {
    let mut start = input;
    while let Some(rest) = start.strip_prefix(b"\r\n") {
        start = rest;
    }
    let is_status_line =
        start.get(..4).is_some_and(|p| p.eq_ignore_ascii_case(b"SIP/"));
    let reference = if is_status_line {
        parse_response::<16>(input)
    } else {
        parse_request::<16>(input)
    };

    let mut storage = HeaderBuf::<16>::new();
    let mut head = AnyHead::new(&mut storage);
    // Prime with the other kind so a stale variant would show up.
    let _ = head.parse(if is_status_line {
        b"OPTIONS sip:a@b SIP/2.0\r\nX: prime\r\n\r\n".as_slice()
    } else {
        b"SIP/2.0 200 OK\r\nX: prime\r\n\r\n".as_slice()
    });
    let result = head.parse(input);
    if let Ok(Status::Complete(_)) = result {
        assert!(head.start_line.and_then(|line| line.complete()).is_some());
    }

    let range = |token: Option<&str>| token.map(|s| borrowed_range(input, s));
    let fields = match head.start_line {
        None => [None, None, None],
        Some(StartLine::Request(line)) => {
            assert!(!is_status_line);
            [range(line.method), range(line.uri), range(line.version)]
        }
        Some(StartLine::Status(line)) => {
            assert!(is_status_line);
            [
                range(line.version),
                range(line.status_code),
                range(line.reason_phrase),
            ]
        }
    };
    let rows: Vec<_> = head
        .headers
        .iter()
        .map(|row| {
            (borrowed_range(input, row.name), borrowed_range(input, row.value))
        })
        .collect();

    assert_eq!(Observation { result, fields, rows }, reference);
}

harness!(
    request,
    parse_request,
    RequestHead,
    [method, uri, version],
    b"OPTIONS sip:a@b SIP/2.0\r\nX: prime\r\n\r\n"
);

/// Checks `find_head_end` against a scalar search at every `scanned`.
///
/// The parser is the second oracle. The search from `0` must land on the
/// end the parser returns, unless it stops at the `CRLF`s that the parser
/// skips before the start-line. A `Partial` head has no other end.
pub fn find_head_end(input: &[u8]) {
    const HEAD_END: &[u8] = b"\r\n\r\n";

    let scalar = |scanned: usize| {
        let start = scanned.saturating_sub(HEAD_END.len() - 1);
        input[start..]
            .windows(HEAD_END.len())
            .position(|window| window == HEAD_END)
            .map(|i| start + i + HEAD_END.len())
    };

    for scanned in 0..=input.len() {
        assert_eq!(
            siparse::find_head_end(input, scanned),
            scalar(scanned),
            "scanned={scanned}"
        );
    }

    let found = siparse::find_head_end(input, 0);
    let in_leading_crlfs =
        |end: usize| input[..end].chunks(2).all(|pair| pair == b"\r\n");
    match parse_request::<16>(input).result {
        Ok(Status::Complete(end)) => {
            let found = found.expect("a complete head has an end");
            assert!(found == end || in_leading_crlfs(found), "end={found}");
        }
        Ok(Status::Partial) => {
            if let Some(found) = found {
                assert!(in_leading_crlfs(found), "end={found}");
            }
        }
        Err(_) => {}
    }
}

harness!(
    response,
    parse_response,
    ResponseHead,
    [version, status_code, reason_phrase],
    b"SIP/2.0 200 OK\r\nX: prime\r\n\r\n"
);

/// Checks every scan against a scalar reference at every character boundary.
///
/// A scan only applies to a header value, which is valid UTF-8, so input
/// that is not is skipped. Each scan must either return `None` or split the
/// input in two at the reference's position, with both halves borrowed from
/// it.
pub fn scan(input: &[u8]) {
    use siparse::scan;

    let Ok(input) = std::str::from_utf8(input) else {
        return;
    };

    fn run(src: &str, accept: impl Fn(u8) -> bool) -> Option<(&str, &str)> {
        let n = src.bytes().take_while(|&b| accept(b)).count();
        (n > 0).then(|| src.split_at(n))
    }

    fn is_token(b: u8) -> bool {
        b.is_ascii_alphanumeric() || b"-.!%*_+`'~".contains(&b)
    }

    fn is_hostname(b: u8) -> bool {
        b.is_ascii_alphanumeric() || b == b'-' || b == b'.'
    }

    fn is_ipv6(b: u8) -> bool {
        b.is_ascii_hexdigit() || b == b':' || b == b'.'
    }

    fn whitespace(src: &str) -> usize {
        src.bytes()
            .take_while(|b| matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
            .count()
    }

    fn host(src: &str) -> Option<(&str, &str)> {
        match src.strip_prefix('[') {
            Some(rest) => {
                let (address, rest) = run(rest, is_ipv6)?;
                rest.strip_prefix(']')?;
                Some(src.split_at(address.len() + 2))
            }
            None => run(src, is_hostname),
        }
    }

    fn quoted_string(src: &str) -> Option<(&str, &str)> {
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

    fn check(
        src: &str,
        actual: Option<(&str, &str)>,
        expected: Option<(&str, &str)>,
        what: &str,
    ) {
        assert_eq!(actual, expected, "{what} {src:?}");
        if let Some((element, rest)) = actual {
            borrowed_range(src.as_bytes(), element);
            borrowed_range(src.as_bytes(), rest);
            assert_eq!(element.len() + rest.len(), src.len());
            assert_eq!(
                rest.as_ptr() as usize,
                src.as_ptr() as usize + element.len()
            );
        }
    }

    let starts = input.char_indices().map(|(i, _)| i);
    for start in starts.chain([input.len()]) {
        let src = &input[start..];
        let ws = whitespace(src);

        assert_eq!(scan::sws(src), &src[ws..], "sws {src:?}");
        assert_eq!(
            scan::lws(src),
            (ws > 0).then(|| &src[ws..]),
            "lws {src:?}"
        );
        for sep in [';', ',', ':', '=', '/', '\u{e9}'] {
            let expected = src[ws..]
                .strip_prefix(sep)
                .map(|rest| &rest[whitespace(rest)..]);
            assert_eq!(
                scan::separator(src, sep),
                expected,
                "separator {sep:?} {src:?}"
            );
        }
        check(src, scan::token(src), run(src, is_token), "token");
        check(
            src,
            scan::digits(src),
            run(src, |b| b.is_ascii_digit()),
            "digits",
        );
        check(src, scan::host(src), host(src), "host");
        check(
            src,
            scan::quoted_string(src),
            quoted_string(src),
            "quoted_string",
        );
    }
}

/// Checks that the three forms of each check agree on `input`.
///
/// For each element:
///
/// * The plain form and the `_const` form both accept `input` or both
///   reject it with the same [`ErrorKind`].
/// * An accepted element is `input` itself, borrowed.
/// * The error offset is `None` exactly when the check accepts `input`, and
///   otherwise at most its length.
/// * The bytes before the offset are accepted, or end too early. The offset
///   is the first byte that is not accepted, so a check of the bytes before
///   it can only fail at their end.
pub fn check(input: &[u8]) {
    use siparse::check;

    type Check = fn(&[u8]) -> Result<&str, Error>;
    type Offset = fn(&[u8]) -> Option<usize>;

    let checks: [(&str, Check, Check, Offset); 5] = [
        (
            "method",
            check::method,
            check::method_const,
            check::method_error_offset,
        ),
        (
            "request_uri",
            check::request_uri,
            check::request_uri_const,
            check::request_uri_error_offset,
        ),
        (
            "reason_phrase",
            check::reason_phrase,
            check::reason_phrase_const,
            check::reason_phrase_error_offset,
        ),
        (
            "header_name",
            check::header_name,
            check::header_name_const,
            check::header_name_error_offset,
        ),
        (
            "header_value",
            check::header_value,
            check::header_value_const,
            check::header_value_error_offset,
        ),
    ];

    for (what, plain, constant, offset) in checks {
        let result = plain(input);
        assert_eq!(
            result.map_err(|err| err.kind()),
            constant(input).map_err(|err| err.kind()),
            "{what} {input:?}"
        );

        match (result, offset(input)) {
            (Ok(element), None) => {
                assert_eq!(borrowed_range(input, element), 0..input.len());
            }
            (Err(_), Some(at)) => {
                assert!(at <= input.len(), "{what} offset {at} {input:?}");
                let before = &input[..at];
                assert!(
                    offset(before).is_none_or(|n| n == before.len()),
                    "{what} fails before its offset {at} {input:?}"
                );
            }
            (result, at) => {
                panic!("{what} {result:?} with offset {at:?} {input:?}")
            }
        }
    }
}

/// Checks [`siparse::value`] against a reference that walks byte indices.
///
/// The parsers apply to a header value, so input that
/// [`siparse::check::header_value`] rejects is only checked for borrowed
/// parts. On the rest:
///
/// * [`value::addresses`](siparse::value::addresses) yields the reference's
///   addresses, parts and parameters, and ends after the same error.
/// * [`value::address`](siparse::value::address) agrees with a list of one.
/// * [`value::params`](siparse::value::params) agrees with the reference at
///   every character boundary.
/// * Every part is borrowed from the input.
pub fn value(input: &[u8]) {
    use siparse::value;

    // Any `&str` is safe to pass, even one that no header value matches.
    // There the results are unspecified, but every part must be borrowed.
    let Ok(text) = std::str::from_utf8(input) else {
        return;
    };
    for address in value::addresses(text).flatten() {
        reference::Address::from(address).check_borrowed(text);
    }

    let Ok(input) = siparse::check::header_value(input) else {
        return;
    };

    let list: Vec<_> = value::addresses(input)
        .map(|item| item.map(reference::Address::from).map_err(|e| e.kind()))
        .collect();
    assert_eq!(list, reference::addresses(input), "addresses {input:?}");
    for address in list.iter().flatten() {
        address.check_borrowed(input);
    }

    let single = value::address(input)
        .map(reference::Address::from)
        .map_err(|err| err.kind());
    let expected = match list.as_slice() {
        [Ok(address)] => Ok(address.clone()),
        // A list of more than one is not an address. The reference reports
        // where the list goes wrong, which for `address` is the `,` already.
        [Ok(_), ..] => Err(ErrorKind::Address),
        [Err(kind), ..] => Err(*kind),
        [] => unreachable!("a list yields at least one item"),
    };
    assert_eq!(single, expected, "address {input:?}");

    let starts = input.char_indices().map(|(i, _)| i);
    for start in starts.chain([input.len()]) {
        let src = &input[start..];
        let actual = value::params(src)
            .map(|(params, rest)| {
                let list: Vec<_> =
                    params.iter().map(|p| (p.name, p.value)).collect();
                (list, params.as_str(), rest)
            })
            .map_err(|err| err.kind());
        assert_eq!(actual, reference::params(src), "params {src:?}");
        if let Ok((list, text, rest)) = actual {
            borrowed_range(src.as_bytes(), text);
            borrowed_range(src.as_bytes(), rest);
            for (name, value) in list {
                borrowed_range(text.as_bytes(), name);
                if let Some(value) = value {
                    borrowed_range(text.as_bytes(), value);
                }
            }
        }
    }
}

/// A scalar reading of the `value` productions, for the `value` target.
///
/// It follows RFC 3261 section 25.1 with byte indices and the character
/// classes written out, independent of `siparse::scan`.
mod reference {
    use siparse::{value, ErrorKind};

    use crate::borrowed_range;

    type Param<'a> = (&'a str, Option<&'a str>);

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub(crate) struct Address<'a> {
        display_name: Option<&'a str>,
        uri: &'a str,
        bracketed: bool,
        params_text: &'a str,
        params: Vec<Param<'a>>,
    }

    impl<'a> From<value::Address<'a>> for Address<'a> {
        fn from(address: value::Address<'a>) -> Address<'a> {
            Address {
                display_name: address.display_name,
                uri: address.uri,
                bracketed: address.bracketed,
                params_text: address.params.as_str(),
                params: address
                    .params
                    .iter()
                    .map(|p| (p.name, p.value))
                    .collect(),
            }
        }
    }

    impl Address<'_> {
        pub(crate) fn check_borrowed(&self, input: &str) {
            let input = input.as_bytes();
            borrowed_range(input, self.uri);
            borrowed_range(input, self.params_text);
            if let Some(display_name) = self.display_name {
                borrowed_range(input, display_name);
            }
            for (name, value) in &self.params {
                borrowed_range(self.params_text.as_bytes(), name);
                if let Some(value) = value {
                    borrowed_range(self.params_text.as_bytes(), value);
                }
            }
        }
    }

    fn is_ws(b: u8) -> bool {
        matches!(b, b' ' | b'\t' | b'\r' | b'\n')
    }

    fn is_token(b: u8) -> bool {
        b.is_ascii_alphanumeric() || b"-.!%*_+`'~".contains(&b)
    }

    // RFC 2396 `reserved`, `unreserved` and `%`, plus the brackets of an
    // IPv6 reference.
    fn is_uri(b: u8) -> bool {
        b.is_ascii_alphanumeric() || b";/?:@&=+$,-_.!~*'()%[]".contains(&b)
    }

    fn skip(s: &[u8], mut i: usize, accept: fn(u8) -> bool) -> usize {
        while i < s.len() && accept(s[i]) {
            i += 1;
        }
        i
    }

    /// The index after the closing quote of a `quoted-string` at `i`.
    fn quoted_end(s: &[u8], i: usize) -> Option<usize> {
        let mut i = i + 1;
        loop {
            match *s.get(i)? {
                b'"' => return Some(i + 1),
                b'\\' => match *s.get(i + 1)? {
                    b'\r' | b'\n' | 0x80.. => return None,
                    _ => i += 2,
                },
                _ => i += 1,
            }
        }
    }

    fn has_scheme(uri: &str) -> bool {
        let Some(colon) = uri.find(':') else {
            return false;
        };
        let scheme = &uri.as_bytes()[..colon];
        !scheme.is_empty()
            && scheme[0].is_ascii_alphabetic()
            && scheme.iter().all(|&b| {
                b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.')
            })
            && colon + 1 < uri.len()
    }

    /// `*( SEMI generic-param )` at the start of `src`.
    pub(crate) fn params(
        src: &str,
    ) -> Result<(Vec<Param<'_>>, &str, &str), ErrorKind> {
        let s = src.as_bytes();
        let invalid = ErrorKind::GenericParam;
        let mut list = Vec::new();
        let mut first = None;
        let mut end = 0;

        loop {
            let semi = skip(s, end, is_ws);
            if s.get(semi) != Some(&b';') {
                break;
            }
            first.get_or_insert(semi);

            let name_start = skip(s, semi + 1, is_ws);
            let name_end = skip(s, name_start, is_token);
            if name_end == name_start {
                return Err(invalid);
            }
            let name = &src[name_start..name_end];

            let eq = skip(s, name_end, is_ws);
            if s.get(eq) != Some(&b'=') {
                list.push((name, None));
                end = name_end;
                continue;
            }
            let value_start = skip(s, eq + 1, is_ws);
            let value_end = match s.get(value_start) {
                Some(b'"') => quoted_end(s, value_start).ok_or(invalid)?,
                Some(b'[') => {
                    let close = skip(s, value_start + 1, |b| {
                        b.is_ascii_hexdigit() || b == b':' || b == b'.'
                    });
                    if close == value_start + 1 || s.get(close) != Some(&b']')
                    {
                        return Err(invalid);
                    }
                    close + 1
                }
                _ => skip(s, value_start, is_token),
            };
            if value_end == value_start {
                return Err(invalid);
            }
            list.push((name, Some(&src[value_start..value_end])));
            end = value_end;
        }

        let text = match first {
            Some(first) => &src[first..end],
            None => &src[..0],
        };
        Ok((list, text, &src[end..]))
    }

    /// `[ display-name ] LAQUOT addr-spec RAQUOT` at `i`, returning the
    /// display name, the URI and the index after `>`.
    fn name_addr(src: &str, i: usize) -> Option<(Option<&str>, &str, usize)> {
        let s = src.as_bytes();
        let (display_name, open) = if s.get(i) == Some(&b'"') {
            let end = quoted_end(s, i)?;
            (Some(&src[i..end]), skip(s, end, is_ws))
        } else {
            let mut at = i;
            let mut end = i;
            loop {
                let token_end = skip(s, at, is_token);
                if token_end == at {
                    break;
                }
                let after = skip(s, token_end, is_ws);
                if after == token_end {
                    return None;
                }
                end = token_end;
                at = after;
            }
            ((end > i).then(|| &src[i..end]), at)
        };

        if s.get(open) != Some(&b'<') {
            return None;
        }
        let close = skip(s, open + 1, is_uri);
        let uri = &src[open + 1..close];
        (s.get(close) == Some(&b'>') && has_scheme(uri)).then_some((
            display_name,
            uri,
            close + 1,
        ))
    }

    fn address(
        src: &str,
        i: usize,
    ) -> Result<(Address<'_>, usize), ErrorKind> {
        let s = src.as_bytes();
        let i = skip(s, i, is_ws);

        let (display_name, uri, bracketed, end) = match name_addr(src, i) {
            Some((display_name, uri, end)) => (display_name, uri, true, end),
            None => {
                let end = skip(s, i, |b| is_uri(b) && !b";,?".contains(&b));
                let uri = &src[i..end];
                if end == i || s.get(end) == Some(&b'?') || !has_scheme(uri) {
                    return Err(ErrorKind::Address);
                }
                (None, uri, false, end)
            }
        };
        let (params, params_text, rest) = params(&src[end..])?;

        let address =
            Address { display_name, uri, bracketed, params_text, params };
        Ok((address, src.len() - rest.len()))
    }

    /// A comma-separated list of addresses, ending after the first error.
    pub(crate) fn addresses(src: &str) -> Vec<Result<Address<'_>, ErrorKind>> {
        let s = src.as_bytes();
        let mut list = Vec::new();
        let mut at = 0;

        loop {
            let (address, end) = match address(src, at) {
                Ok(found) => found,
                Err(kind) => {
                    list.push(Err(kind));
                    return list;
                }
            };
            let next = skip(s, end, is_ws);
            match s.get(next) {
                None => {
                    list.push(Ok(address));
                    return list;
                }
                Some(b',') => {
                    list.push(Ok(address));
                    at = next + 1;
                }
                Some(_) => {
                    list.push(Err(ErrorKind::Address));
                    return list;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn value_seeds() {
        for seed in [
            &b""[..],
            b"\"Bob \\\"B\\\" Smith\" <sip:bob@biloxi.example.com>;tag=a6c85cf",
            b"Alice <sip:alice@atlanta.example.com>;tag=1928301774",
            b"sip:bob@biloxi.example.com ;\r\n tag = a6c85cf ",
            b"<sip:p1.example.com;lr>;x=\"a,b\", <sip:[2001:db8::1];lr>",
            b"sip:a@x;expires=60,sip:b@x;q=0.5, <sip:c@x?h=1,2>",
            b"\"\xe7\x94\xb0\xe4\xb8\xad\" <sip:tanaka@example.com>",
            b"<sip:a@x>;received=[2001:db8::2];rport",
            b"Bob<sip:b@x>",
            b"<sip:a@x>,,<sip:b@x>",
            b"sip:b@x?Subject=lunch",
            b"<sip:a@x>;x=",
            b"*",
            b"\xff",
        ] {
            value(seed);
        }
    }

    #[test]
    fn scan_seeds() {
        for seed in [
            &b""[..],
            b"SIP/2.0/UDP pc33.atlanta.example.com:5060;branch=z9hG4bK776asdhds",
            b"SIP/2.0/TCP [2001:db8::1]:5061;rport;received=192.0.2.4 , SIP/2.0/UDP a",
            b"\"Bob \\\"B\\\" Smith\" <sip:bob@biloxi.example.com>;tag=a6c85cf",
            b"\"\xe7\x94\xb0\xe4\xb8\xad\" <sip:tanaka@example.com>",
            b"314159 INVITE",
            b"\"unterminated\\",
            b"\"\\\xc3\xa9\"",
            b"\xff",
        ] {
            scan(seed);
        }
    }

    #[derive(Clone, Copy)]
    enum Expected {
        Complete,
        Partial,
        Error,
        TooManyHeaders,
    }

    struct Seed {
        name: &'static str,
        input: &'static [u8],
        expected: Expected,
    }

    fn check_seeds(
        inputs: &[Seed],
        run: fn(&[u8]),
        parse: fn(&[u8]) -> Observation,
    ) {
        let mut completed = 0;

        for seed in inputs {
            let name = seed.name;
            let input = seed.input;

            run(input);
            let reference = parse(input);

            match seed.expected {
                Expected::Complete => {
                    assert!(
                        matches!(reference.result, Ok(Status::Complete(_))),
                        "seed={name}"
                    );
                }
                Expected::Partial => {
                    assert_eq!(
                        reference.result,
                        Ok(Status::Partial),
                        "seed={name}"
                    );
                }
                Expected::Error => {
                    assert!(reference.result.is_err(), "seed={name}");
                }
                Expected::TooManyHeaders => {
                    assert_eq!(
                        reference.result.map_err(|error| error.kind()),
                        Err(ErrorKind::TooManyHeaders),
                        "seed={name}"
                    );
                }
            }

            if let Ok(Status::Complete(end)) = reference.result {
                completed += 1;
                for cut in 0..end {
                    check_prefix(&reference, &parse(&input[..cut]));
                }
            }
        }

        assert!(completed > 0, "corpus must exercise complete heads");

        // Empty input is not a corpus file, since libFuzzer ignores empty
        // seeds. It must still clear the primed fields and rows.
        run(b"");
        let empty = parse(b"");
        assert_eq!(empty.result, Ok(Status::Partial));
        assert_eq!(empty.fields, [None, None, None]);
        assert!(empty.rows.is_empty());
    }

    // Embed wire bytes so these tests also run under Miri's isolation.
    // Keep this list in sync when adding checked-in seeds.
    macro_rules! seeds {
    (@files $target:literal; $($name:literal),* $(,)?) => {
        [
            $(
                include_bytes!(concat!("../corpus/", $target, "/", $name))
                    .as_slice(),
            )*
        ]
    };

    (
        @list $target:literal;
        $($name:literal => $expected:ident),* $(,)?
    ) => {
        &[
            $(
                Seed {
                    name: $name,
                    input: include_bytes!(concat!(
                        "../corpus/", $target, "/", $name
                    )).as_slice(),
                    expected: Expected::$expected,
                },
            )*
        ]
    };

    (
        $target:literal;
        $($extra:literal => $expected:ident),* $(,)?
    ) => {
        seeds! {
            @list $target;
            "backslash_parity" => Complete,
            "bare_cr" => Error,
            "bare_lf" => Error,
            "capacity_16" => Complete,
            "capacity_17" => TooManyHeaders,
            "comment" => Complete,
            "empty_values" => Complete,
            "escaped_crlf" => Complete,
            "escaped_fold" => Complete,
            "fold" => Complete,
            "leading_crlf" => Complete,
            "minimal" => Complete,
            "quoted_pair" => Complete,
            "unescaped_control" => Error,
            "utf8_above_max" => Error,
            "utf8_boundaries" => Complete,
            "utf8_historical" => Error,
            "utf8_invalid" => Error,
            "utf8_overlong" => Error,
            "utf8_surrogate" => Error,
            "utf8_truncated" => Partial,
            "word_boundaries" => Complete,
            $($extra => $expected,)*
        }
    };
}

    #[test]
    fn find_head_end_seeds() {
        for seed in seeds!("request_head";) {
            find_head_end(seed.input);
        }
        find_head_end(b"");
        find_head_end(b"\r\n\r\n");
        find_head_end(b"\r\n\r\n\r\nINVITE sip:a@b SIP/2.0\r\n");
    }

    #[test]
    fn request_seeds_and_every_complete_head_prefix() {
        check_seeds(seeds!("request_head";), request, parse_request::<16>);
    }

    #[test]
    fn response_seeds_and_every_complete_head_prefix() {
        check_seeds(
            seeds!(
                "response_head";
                "percent_invalid" => Error,
                "percent_partial" => Partial,
                "utf8_reason" => Complete,
            ),
            response,
            parse_response::<16>,
        );
    }

    #[test]
    fn check_target_seeds() {
        for seed in seeds!(@files "check";
            "header_value_long",
            "header_value_escapes",
            "header_value_fold",
            "header_value_utf8",
            "reason_phrase_escapes",
            "request_uri",
            "token",
        ) {
            check(seed);
        }
        check(b"");
    }
}

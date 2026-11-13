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

The `find_head_end` target compares [`siparse::frame::find_head_end`]
against a one-window-at-a-time search at every `scanned`, and checks that
it finds the end the parser returns:

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

The `uri` target compares [`siparse::uri::sip_uri`] against the SIP URI
parser it replaced, which checks IP literals with `std::net`:

```text
mkdir -p tmp/fuzz-uri
cargo +nightly fuzz run uri \
    tmp/fuzz-uri fuzz/corpus/uri -- \
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
            siparse::frame::find_head_end(input, scanned),
            scalar(scanned),
            "scanned={scanned}"
        );
    }

    let found = siparse::frame::find_head_end(input, 0);
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

    fn comment(src: &str) -> Option<(&str, &str)> {
        let bytes = src.as_bytes();
        if bytes.first() != Some(&b'(') {
            return None;
        }
        let mut open = 0;
        let mut i = 0;
        loop {
            match *bytes.get(i)? {
                b'(' => open += 1,
                b')' if open == 1 => return Some(src.split_at(i + 1)),
                b')' => open -= 1,
                b'\\' => match *bytes.get(i + 1)? {
                    b'\r' | b'\n' | 0x80.. => return None,
                    _ => i += 1,
                },
                _ => {}
            }
            i += 1;
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
        check(src, scan::comment(src), comment(src), "comment");
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
/// * [`value::token_param`](siparse::value::token_param),
///   [`value::token_params`](siparse::value::token_params),
///   [`value::media_type`](siparse::value::media_type),
///   [`value::challenge`](siparse::value::challenge) and
///   [`value::credentials`](siparse::value::credentials) agree with the
///   reference.
/// * [`value::tokens`](siparse::value::tokens),
///   [`value::media_ranges`](siparse::value::media_ranges) and
///   [`value::via_parms`](siparse::value::via_parms) agree with the
///   reference, and every list iterator leaves the same rest after each item.
/// * [`value::via_parm`](siparse::value::via_parm) reads the first
///   `via-parm` as `via_parms` does, and leaves the same rest.
/// * [`value::cseq`](siparse::value::cseq),
///   [`value::call_id`](siparse::value::call_id) and
///   [`value::call_id_params`](siparse::value::call_id_params) agree with
///   the reference.
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

    let mut list = Vec::new();
    let mut addresses = value::addresses(input);
    while let Some(item) = addresses.next() {
        borrowed_range(input.as_bytes(), addresses.as_str());
        let item = item.map(reference::Address::from).map_err(|e| e.kind());
        list.push((item, addresses.as_str()));
    }
    assert_eq!(list, reference::addresses(input), "addresses {input:?}");
    for (address, _) in &list {
        if let Ok(address) = address {
            address.check_borrowed(input);
        }
    }
    let list: Vec<_> = list.into_iter().map(|(item, _)| item).collect();

    let mut tokens = Vec::new();
    let mut token_list = value::tokens(input);
    while let Some(item) = token_list.next() {
        borrowed_range(input.as_bytes(), token_list.as_str());
        if let Ok(token) = item {
            borrowed_range(input.as_bytes(), token);
        }
        tokens.push((item.map_err(|err| err.kind()), token_list.as_str()));
    }
    assert_eq!(tokens, reference::tokens(input), "tokens {input:?}");

    fn token_param(t: value::TokenParam<'_>) -> reference::TokenParam<'_> {
        let params = t.params.iter().map(|p| (p.name, p.value)).collect();
        (t.token, params, t.params.as_str())
    }
    let single =
        value::token_param(input).map(token_param).map_err(|e| e.kind());
    assert_eq!(single, reference::token_param(input), "token_param {input:?}");

    let mut items = Vec::new();
    let mut item_list = value::token_params(input);
    while let Some(item) = item_list.next() {
        borrowed_range(input.as_bytes(), item_list.as_str());
        let item = item.map(token_param).map_err(|err| err.kind());
        if let Ok((token, _, text)) = &item {
            borrowed_range(input.as_bytes(), token);
            borrowed_range(input.as_bytes(), text);
        }
        items.push((item, item_list.as_str()));
    }
    assert_eq!(
        items,
        reference::token_params(input),
        "token_params {input:?}"
    );

    fn auth(a: value::Auth<'_>) -> reference::Auth<'_> {
        let params = a.params.iter().map(|p| (p.name, p.value)).collect();
        (a.scheme, params, a.params.as_str())
    }
    let challenge = value::challenge(input).map(auth).map_err(|e| e.kind());
    assert_eq!(challenge, reference::auth(input), "challenge {input:?}");
    let credentials =
        value::credentials(input).map(auth).map_err(|e| e.kind());
    assert_eq!(credentials, challenge, "credentials {input:?}");
    if let Ok((scheme, params, text)) = &challenge {
        borrowed_range(input.as_bytes(), scheme);
        borrowed_range(input.as_bytes(), text);
        for (name, value) in params {
            borrowed_range(text.as_bytes(), name);
            borrowed_range(text.as_bytes(), value);
        }
    }

    fn media(m: value::MediaType<'_>) -> reference::Media<'_> {
        let params = m.params.iter().map(|p| (p.name, p.value)).collect();
        (m.kind, m.subtype, params, m.params.as_str())
    }
    let single = value::media_type(input).map(media).map_err(|e| e.kind());
    assert_eq!(single, reference::media_type(input), "media_type {input:?}");

    let mut ranges = Vec::new();
    let mut range_list = value::media_ranges(input);
    while let Some(item) = range_list.next() {
        borrowed_range(input.as_bytes(), range_list.as_str());
        let item = item.map(media).map_err(|err| err.kind());
        if let Ok((kind, subtype, _, text)) = &item {
            for part in [kind, subtype, text] {
                borrowed_range(input.as_bytes(), part);
            }
        }
        ranges.push((item, range_list.as_str()));
    }
    assert_eq!(
        ranges,
        reference::media_ranges(input),
        "media_ranges {input:?}"
    );

    let mut vias = Vec::new();
    let mut parms = value::via_parms(input);
    while let Some(item) = parms.next() {
        borrowed_range(input.as_bytes(), parms.as_str());
        let item = item.map(reference::Via::from).map_err(|e| e.kind());
        if let Ok(via) = &item {
            via.check_borrowed(input);
        }
        vias.push((item, parms.as_str()));
    }
    assert_eq!(vias, reference::via_parms(input), "via_parms {input:?}");

    // `via_parm` reads the first `via-parm` as `via_parms` does, one
    // parameter at a time.
    let top = value::via_parm(input).map_err(|err| err.kind()).and_then(
        |mut reader| {
            let mut params = Vec::new();
            while let Some(param) = reader.next() {
                borrowed_range(input.as_bytes(), reader.as_str());
                borrowed_range(input.as_bytes(), reader.text());
                let param = param.map_err(|err| err.kind())?;
                params.push((param.name, param.value));
            }
            // A checked run starts at its first `;`, and nothing before the
            // parameters holds one.
            let text = reader.text();
            let start = text.find(';').unwrap_or(text.len());
            let via = reference::Via {
                protocol: reader.protocol,
                version: reader.version,
                transport: reader.transport,
                host: reader.host,
                port: reader.port,
                params_text: &text[start..],
                params,
                text,
            };
            via.check_borrowed(input);
            Ok((via, reader.as_str()))
        },
    );
    match (top, &vias[0]) {
        (Ok((via, rest)), (Ok(expected), expected_rest)) => {
            assert_eq!(via, *expected, "via_parm {input:?}");
            assert_eq!(rest, *expected_rest, "via_parm {input:?}");
        }
        (Err(kind), (Err(expected), _)) => {
            assert_eq!(kind, *expected, "via_parm {input:?}");
        }
        (top, expected) => {
            panic!("via_parm {input:?}: {top:?} against {expected:?}")
        }
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

    let cseq = value::cseq(input)
        .map(|cseq| (cseq.number, cseq.method))
        .map_err(|err| err.kind());
    assert_eq!(cseq, reference::cseq(input), "cseq {input:?}");
    if let Ok((number, method)) = cseq {
        borrowed_range(input.as_bytes(), number);
        borrowed_range(input.as_bytes(), method);
    }

    let with_params = value::call_id_params(input)
        .map(|c| {
            let params = c.params.iter().map(|p| (p.name, p.value)).collect();
            (c.call_id, params, c.params.as_str())
        })
        .map_err(|err| err.kind());
    assert_eq!(
        with_params,
        reference::call_id_params(input),
        "call_id_params {input:?}"
    );
    if let Ok((call_id, _, text)) = &with_params {
        borrowed_range(input.as_bytes(), call_id);
        borrowed_range(input.as_bytes(), text);
    }

    let call_id = value::call_id(input).map_err(|err| err.kind());
    assert_eq!(call_id, reference::call_id(input), "call_id {input:?}");
    if let Ok(call_id) = call_id {
        borrowed_range(input.as_bytes(), call_id);
    }

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
        params_of(src, Grammar::Generic)
    }

    /// `*( SEMI generic-param )`, or `*( SEMI via-params )` when `via` is
    /// set, which adds a `received` that holds a bare IPv6 address.
    /// The parameter grammars the reference reads.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Grammar {
        /// `generic-param`.
        Generic,
        /// `via-params`, which adds a bare IPv6 `received`.
        Via,
        /// `m-parameter`, which always has a token or quoted value.
        MParam,
        /// `accept-param` or `m-parameter`, where `q` holds a `qvalue`.
        Accept,
    }

    fn is_qvalue(value: &str) -> bool {
        let (whole, decimals) = value.split_once('.').unwrap_or((value, ""));
        decimals.len() <= 3
            && ((whole == "0" && decimals.bytes().all(|b| b.is_ascii_digit()))
                || (whole == "1" && decimals.bytes().all(|b| b == b'0')))
    }

    fn params_of(
        src: &str,
        grammar: Grammar,
    ) -> Result<(Vec<Param<'_>>, &str, &str), ErrorKind> {
        let s = src.as_bytes();
        let invalid = match grammar {
            Grammar::Generic | Grammar::Via => ErrorKind::GenericParam,
            Grammar::MParam | Grammar::Accept => ErrorKind::MediaType,
        };
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
                let needs_value = grammar == Grammar::MParam
                    || (grammar == Grammar::Accept
                        && name.eq_ignore_ascii_case("q"));
                if needs_value {
                    return Err(invalid);
                }
                list.push((name, None));
                end = name_end;
                continue;
            }
            let value_start = skip(s, eq + 1, is_ws);
            let bare = skip(s, value_start, |b| {
                b.is_ascii_hexdigit() || b == b':' || b == b'.'
            });
            let value_end = match s.get(value_start) {
                _ if grammar == Grammar::Via
                    && name.eq_ignore_ascii_case("received")
                    && src[value_start..bare].contains(':') =>
                {
                    bare
                }
                Some(b'"') => quoted_end(s, value_start).ok_or(invalid)?,
                Some(b'[') if grammar != Grammar::MParam => {
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
            let value = &src[value_start..value_end];
            if grammar == Grammar::Accept
                && name.eq_ignore_ascii_case("q")
                && !is_qvalue(value)
            {
                return Err(invalid);
            }
            list.push((name, Some(value)));
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

    /// `1*DIGIT LWS Method` with whitespace around it.
    pub(crate) fn cseq(src: &str) -> Result<(&str, &str), ErrorKind> {
        let s = src.as_bytes();
        let invalid = ErrorKind::CSeq;

        let number_start = skip(s, 0, is_ws);
        let number_end = skip(s, number_start, |b| b.is_ascii_digit());
        let method_start = skip(s, number_end, is_ws);
        let method_end = skip(s, method_start, is_token);
        if number_end == number_start
            || method_start == number_end
            || method_end == method_start
            || skip(s, method_end, is_ws) != s.len()
        {
            return Err(invalid);
        }
        Ok((&src[number_start..number_end], &src[method_start..method_end]))
    }

    /// `word [ "@" word ]` with whitespace around it.
    /// The start and end of `word [ "@" word ]` after any whitespace.
    fn call_id_span(s: &[u8]) -> Result<(usize, usize), ErrorKind> {
        fn is_word(b: u8) -> bool {
            b.is_ascii_alphanumeric()
                || b"-.!%*_+`'~()<>:\\\"/[]?{}".contains(&b)
        }

        let start = skip(s, 0, is_ws);
        let mut end = skip(s, start, is_word);
        if end == start {
            return Err(ErrorKind::CallId);
        }
        if s.get(end) == Some(&b'@') {
            let host_end = skip(s, end + 1, is_word);
            if host_end == end + 1 {
                return Err(ErrorKind::CallId);
            }
            end = host_end;
        }
        Ok((start, end))
    }

    pub(crate) fn call_id(src: &str) -> Result<&str, ErrorKind> {
        let s = src.as_bytes();
        let (start, end) = call_id_span(s)?;
        if skip(s, end, is_ws) != s.len() {
            return Err(ErrorKind::CallId);
        }
        Ok(&src[start..end])
    }

    /// A `callid`, its parameters and their text.
    pub(crate) type CallIdParams<'a> = (&'a str, Vec<Param<'a>>, &'a str);

    pub(crate) fn call_id_params(
        src: &str,
    ) -> Result<CallIdParams<'_>, ErrorKind> {
        let s = src.as_bytes();
        let (start, end) = call_id_span(s)?;
        let (params, text, rest) = params_of(&src[end..], Grammar::Generic)?;
        if skip(rest.as_bytes(), 0, is_ws) != rest.len() {
            return Err(ErrorKind::CallId);
        }
        Ok((&src[start..end], params, text))
    }

    /// Reads one list element at an index, returning it and its end.
    type Read<'a, T> = fn(&'a str, usize) -> Result<(T, usize), ErrorKind>;

    /// A comma-separated list read by `read`, ending after the first error.
    /// Each item comes with what is left of the value after it.
    fn list<'a, T>(
        src: &'a str,
        read: Read<'a, T>,
        invalid: ErrorKind,
    ) -> Vec<(Result<T, ErrorKind>, &'a str)> {
        let s = src.as_bytes();
        let mut list = Vec::new();
        let mut at = 0;

        loop {
            let (element, end) = match read(src, at) {
                Ok(found) => found,
                Err(kind) => {
                    list.push((Err(kind), ""));
                    return list;
                }
            };
            let next = skip(s, end, is_ws);
            match s.get(next) {
                None => {
                    list.push((Ok(element), ""));
                    return list;
                }
                Some(b',') => {
                    list.push((Ok(element), &src[next + 1..]));
                    at = next + 1;
                }
                Some(_) => {
                    list.push((Err(invalid), ""));
                    return list;
                }
            }
        }
    }

    pub(crate) fn addresses(
        src: &str,
    ) -> Vec<(Result<Address<'_>, ErrorKind>, &str)> {
        list(src, address, ErrorKind::Address)
    }

    /// A `token` after optional whitespace at `i`.
    fn token_at(src: &str, i: usize) -> Result<(&str, usize), ErrorKind> {
        let s = src.as_bytes();
        let start = skip(s, i, is_ws);
        let end = skip(s, start, is_token);
        if end == start {
            return Err(ErrorKind::Tokens);
        }
        Ok((&src[start..end], end))
    }

    pub(crate) fn tokens(src: &str) -> Vec<(Result<&str, ErrorKind>, &str)> {
        list(src, token_at, ErrorKind::Tokens)
    }

    /// A token, its parameters and their text.
    pub(crate) type TokenParam<'a> = (&'a str, Vec<Param<'a>>, &'a str);

    /// A `token` and `generic-param`s at `i`.
    fn token_param_at(
        src: &str,
        i: usize,
    ) -> Result<(TokenParam<'_>, usize), ErrorKind> {
        let s = src.as_bytes();
        let start = skip(s, i, is_ws);
        let end = skip(s, start, is_token);
        if end == start {
            return Err(ErrorKind::TokenParam);
        }
        let (params, text, rest) = params_of(&src[end..], Grammar::Generic)?;
        Ok(((&src[start..end], params, text), src.len() - rest.len()))
    }

    pub(crate) fn token_param(src: &str) -> Result<TokenParam<'_>, ErrorKind> {
        let (value, end) = token_param_at(src, 0)?;
        if skip(src.as_bytes(), end, is_ws) != src.len() {
            return Err(ErrorKind::TokenParam);
        }
        Ok(value)
    }

    pub(crate) fn token_params(
        src: &str,
    ) -> Vec<(Result<TokenParam<'_>, ErrorKind>, &str)> {
        list(src, token_param_at, ErrorKind::TokenParam)
    }

    /// A scheme, its `auth-param`s and their text.
    pub(crate) type Auth<'a> = (&'a str, Vec<(&'a str, &'a str)>, &'a str);

    /// `auth-scheme LWS auth-param *(COMMA auth-param)`, with whitespace
    /// around it.
    pub(crate) fn auth(src: &str) -> Result<Auth<'_>, ErrorKind> {
        let s = src.as_bytes();
        let invalid = ErrorKind::Auth;
        let scheme_start = skip(s, 0, is_ws);
        let scheme_end = skip(s, scheme_start, is_token);
        let first = skip(s, scheme_end, is_ws);
        if scheme_end == scheme_start || first == scheme_end {
            return Err(invalid);
        }

        let mut params = Vec::new();
        let mut at = first;
        loop {
            let name_start = skip(s, at, is_ws);
            let name_end = skip(s, name_start, is_token);
            let eq = skip(s, name_end, is_ws);
            if name_end == name_start || s.get(eq) != Some(&b'=') {
                return Err(invalid);
            }
            let value_start = skip(s, eq + 1, is_ws);
            let value_end = if s.get(value_start) == Some(&b'"') {
                quoted_end(s, value_start).ok_or(invalid)?
            } else {
                skip(s, value_start, is_token)
            };
            if value_end == value_start {
                return Err(invalid);
            }
            params.push((
                &src[name_start..name_end],
                &src[value_start..value_end],
            ));

            let next = skip(s, value_end, is_ws);
            match s.get(next) {
                Some(b',') => at = next + 1,
                None => {
                    let text = &src[first..value_end];
                    return Ok((&src[scheme_start..scheme_end], params, text));
                }
                Some(_) => return Err(invalid),
            }
        }
    }

    /// A media type or range: the kind, the subtype, the parameters and
    /// their text.
    pub(crate) type Media<'a> = (&'a str, &'a str, Vec<Param<'a>>, &'a str);

    /// `m-type SLASH m-subtype` and parameters of `grammar` at `i`.
    fn media_at(
        src: &str,
        i: usize,
        grammar: Grammar,
    ) -> Result<(Media<'_>, usize), ErrorKind> {
        let s = src.as_bytes();
        let invalid = ErrorKind::MediaType;
        let kind_start = skip(s, i, is_ws);
        let kind_end = skip(s, kind_start, is_token);
        let slash = skip(s, kind_end, is_ws);
        if kind_end == kind_start || s.get(slash) != Some(&b'/') {
            return Err(invalid);
        }
        let subtype_start = skip(s, slash + 1, is_ws);
        let subtype_end = skip(s, subtype_start, is_token);
        if subtype_end == subtype_start {
            return Err(invalid);
        }
        let kind = &src[kind_start..kind_end];
        let subtype = &src[subtype_start..subtype_end];
        if grammar == Grammar::Accept && kind == "*" && subtype != "*" {
            return Err(invalid);
        }
        let (params, text, rest) = params_of(&src[subtype_end..], grammar)?;
        Ok(((kind, subtype, params, text), src.len() - rest.len()))
    }

    pub(crate) fn media_type(src: &str) -> Result<Media<'_>, ErrorKind> {
        let (media, end) = media_at(src, 0, Grammar::MParam)?;
        if skip(src.as_bytes(), end, is_ws) != src.len() {
            return Err(ErrorKind::MediaType);
        }
        Ok(media)
    }

    pub(crate) fn media_ranges(
        src: &str,
    ) -> Vec<(Result<Media<'_>, ErrorKind>, &str)> {
        list(
            src,
            |src, i| media_at(src, i, Grammar::Accept),
            ErrorKind::MediaType,
        )
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub(crate) struct Via<'a> {
        pub(crate) protocol: &'a str,
        pub(crate) version: &'a str,
        pub(crate) transport: &'a str,
        pub(crate) host: &'a str,
        pub(crate) port: Option<&'a str>,
        pub(crate) params_text: &'a str,
        pub(crate) params: Vec<Param<'a>>,
        pub(crate) text: &'a str,
    }

    impl<'a> From<value::ViaParm<'a>> for Via<'a> {
        fn from(via: value::ViaParm<'a>) -> Via<'a> {
            Via {
                protocol: via.protocol,
                version: via.version,
                transport: via.transport,
                host: via.host,
                port: via.port,
                params_text: via.params.as_str(),
                params: via.params.iter().map(|p| (p.name, p.value)).collect(),
                text: via.text,
            }
        }
    }

    impl Via<'_> {
        pub(crate) fn check_borrowed(&self, input: &str) {
            let input = input.as_bytes();
            for part in
                [self.protocol, self.version, self.transport, self.host]
            {
                borrowed_range(input, part);
            }
            borrowed_range(input, self.text);
            borrowed_range(input, self.params_text);
            if let Some(port) = self.port {
                borrowed_range(input, port);
            }
            for (name, value) in &self.params {
                borrowed_range(self.params_text.as_bytes(), name);
                if let Some(value) = value {
                    borrowed_range(self.params_text.as_bytes(), value);
                }
            }
        }
    }

    /// `sent-protocol LWS sent-by *( SEMI via-params )` at `i`.
    fn via_parm(src: &str, i: usize) -> Result<(Via<'_>, usize), ErrorKind> {
        let s = src.as_bytes();
        let invalid = ErrorKind::Via;
        let token = |at: usize| -> Result<(&str, usize), ErrorKind> {
            let end = skip(s, at, is_token);
            if end == at {
                return Err(invalid);
            }
            Ok((&src[at..end], end))
        };
        let slash = |at: usize| -> Result<usize, ErrorKind> {
            let at = skip(s, at, is_ws);
            if s.get(at) != Some(&b'/') {
                return Err(invalid);
            }
            Ok(skip(s, at + 1, is_ws))
        };

        let start = skip(s, i, is_ws);
        let (protocol, at) = token(start)?;
        let (version, at) = token(slash(at)?)?;
        let (transport, at) = token(slash(at)?)?;

        let host_start = skip(s, at, is_ws);
        if host_start == at {
            return Err(invalid);
        }
        let host_end = if s.get(host_start) == Some(&b'[') {
            let close = skip(s, host_start + 1, |b| {
                b.is_ascii_hexdigit() || b == b':' || b == b'.'
            });
            if close == host_start + 1 || s.get(close) != Some(&b']') {
                return Err(invalid);
            }
            close + 1
        } else {
            skip(s, host_start, |b| {
                b.is_ascii_alphanumeric() || b"-.".contains(&b)
            })
        };
        if host_end == host_start {
            return Err(invalid);
        }

        let colon = skip(s, host_end, is_ws);
        let (port, end) = if s.get(colon) == Some(&b':') {
            let port_start = skip(s, colon + 1, is_ws);
            let port_end = skip(s, port_start, |b| b.is_ascii_digit());
            if port_end == port_start {
                return Err(invalid);
            }
            (Some(&src[port_start..port_end]), port_end)
        } else {
            (None, host_end)
        };

        let (params, params_text, rest) =
            params_of(&src[end..], Grammar::Via)?;
        let end = src.len() - rest.len();
        let via = Via {
            protocol,
            version,
            transport,
            host: &src[host_start..host_end],
            port,
            params_text,
            params,
            text: &src[start..end],
        };
        Ok((via, end))
    }

    pub(crate) fn via_parms(
        src: &str,
    ) -> Vec<(Result<Via<'_>, ErrorKind>, &str)> {
        list(src, via_parm, ErrorKind::Via)
    }
}

/// Checks [`siparse::uri::sip_uri`] against the parser it replaced, and
/// [`siparse::uri::tel_uri`] and [`siparse::uri::telephone_subscriber`]
/// against a reference that walks RFC 3966's grammar.
///
/// The reference is the SIP URI parser signa-core had before this one, which
/// checks IP literals with `std::net`. Both must accept the same input, split
/// it into the same parts, and reject it with the same kind of error. Every
/// part must be borrowed from the input.
pub fn uri(input: &[u8]) {
    use siparse::uri;

    let Ok(input) = std::str::from_utf8(input) else {
        return;
    };

    let actual = uri::sip_uri(input)
        .map(|uri| {
            for part in [uri.host, uri.params.as_str(), uri.headers.as_str()] {
                borrowed_range(input.as_bytes(), part);
            }
            for part in
                [uri.user, uri.password, uri.port].into_iter().flatten()
            {
                borrowed_range(input.as_bytes(), part);
            }
            reference_uri::Parts {
                sips: uri.scheme == uri::Scheme::Sips,
                user: uri.user,
                password: uri.password,
                host: uri.host,
                port: uri.port,
                params: uri.params.iter().map(|p| (p.name, p.value)).collect(),
                headers: uri
                    .headers
                    .iter()
                    .map(|h| (h.name, h.value))
                    .collect(),
            }
        })
        .map_err(|err| err.kind());
    assert_eq!(actual, reference_uri::parse(input), "sip_uri {input:?}");

    fn tel(t: uri::TelephoneSubscriber<'_>) -> reference_tel::Tel<'_> {
        (t.number, t.params.iter().map(|p| (p.name, p.value)).collect())
    }
    let tel_uri = uri::tel_uri(input).map(tel).map_err(|err| err.kind());
    assert_eq!(tel_uri, reference_tel::tel_uri(input), "tel_uri {input:?}");
    let subscriber =
        uri::telephone_subscriber(input).map(tel).map_err(|err| err.kind());
    assert_eq!(
        subscriber,
        reference_tel::subscriber(input),
        "telephone_subscriber {input:?}"
    );
    if let Ok((number, params)) = &subscriber {
        borrowed_range(input.as_bytes(), number);
        for (name, value) in params {
            borrowed_range(input.as_bytes(), name);
            if let Some(value) = value {
                borrowed_range(input.as_bytes(), value);
            }
        }
    }
}

/// RFC 3966's `telephone-subscriber`, read with byte indices for the `uri`
/// target.
mod reference_tel {
    use siparse::ErrorKind;

    /// A number and its parameters.
    pub(crate) type Tel<'a> = (&'a str, Vec<(&'a str, Option<&'a str>)>);

    fn visual(b: u8) -> bool {
        b"-.()".contains(&b)
    }

    fn global_digits(s: &[u8]) -> bool {
        s.iter().all(|&b| b.is_ascii_digit() || visual(b))
            && s.iter().any(|b| b.is_ascii_digit())
    }

    fn local_digits(s: &[u8]) -> bool {
        let digit = |b: u8| b.is_ascii_hexdigit() || b == b'*' || b == b'#';
        s.iter().all(|&b| digit(b) || visual(b)) && s.iter().any(|&b| digit(b))
    }

    fn hostname(src: &str) -> bool {
        let name = src.strip_suffix('.').unwrap_or(src);
        let labels: Vec<&str> = name.split('.').collect();
        let top_ok = labels
            .last()
            .and_then(|top| top.bytes().next())
            .is_some_and(|b| b.is_ascii_alphabetic());
        top_ok
            && labels.iter().all(|label| {
                let b = label.as_bytes();
                !b.is_empty()
                    && b[0].is_ascii_alphanumeric()
                    && b[b.len() - 1].is_ascii_alphanumeric()
                    && b.iter()
                        .all(|&c| c.is_ascii_alphanumeric() || c == b'-')
            })
    }

    fn unreserved(b: u8) -> bool {
        b.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&b)
    }

    /// Checks `%`-escapes and the bytes `allowed` takes.
    fn value(src: &str, allowed: fn(u8) -> bool) -> Result<(), ErrorKind> {
        if src.is_empty() {
            return Err(ErrorKind::UriParam);
        }
        let b = src.as_bytes();
        let mut i = 0;
        while i < b.len() {
            if b[i] == b'%' {
                let hex =
                    |at: usize| b.get(at).is_some_and(u8::is_ascii_hexdigit);
                if !hex(i + 1) || !hex(i + 2) {
                    return Err(ErrorKind::UriEscape);
                }
                i += 3;
            } else if allowed(b[i]) {
                i += 1;
            } else {
                return Err(ErrorKind::UriParam);
            }
        }
        Ok(())
    }

    pub(crate) fn subscriber(src: &str) -> Result<Tel<'_>, ErrorKind> {
        let mut parts = src.split(';');
        let number = parts.next().unwrap_or("");
        let nb = number.as_bytes();
        let ok = match nb.first() {
            Some(b'+') => global_digits(&nb[1..]),
            _ => local_digits(nb),
        };
        if !ok {
            return Err(ErrorKind::TelNumber);
        }

        let mut params = Vec::new();
        let mut context = false;
        for pair in parts {
            let (name, val) = match pair.find('=') {
                Some(at) => (&pair[..at], Some(&pair[at + 1..])),
                None => (pair, None),
            };
            if name.is_empty()
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            {
                return Err(ErrorKind::UriParam);
            }
            if let Some(val) = val {
                if name.eq_ignore_ascii_case("isub") {
                    value(val, |b| {
                        unreserved(b) || b"/?:@&=+$,".contains(&b)
                    })?;
                } else {
                    value(val, |b| unreserved(b) || b"[]/:&+$".contains(&b))?;
                }
                if name.eq_ignore_ascii_case("phone-context") {
                    let vb = val.as_bytes();
                    context |= match vb.first() {
                        Some(b'+') => global_digits(&vb[1..]),
                        _ => hostname(val),
                    };
                }
            }
            params.push((name, val));
        }
        if nb.first() != Some(&b'+') && !context {
            return Err(ErrorKind::TelNumber);
        }
        Ok((number, params))
    }

    pub(crate) fn tel_uri(src: &str) -> Result<Tel<'_>, ErrorKind> {
        match src.get(..4) {
            Some(scheme) if scheme.eq_ignore_ascii_case("tel:") => {
                subscriber(&src[4..])
            }
            _ => Err(ErrorKind::UriScheme),
        }
    }
}

/// The SIP URI parser of signa-core before it moved to siparse, rewritten to
/// return the parts and siparse's error kinds.
mod reference_uri {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use siparse::ErrorKind;

    type Param<'a> = (&'a str, Option<&'a str>);

    #[derive(Debug, PartialEq, Eq)]
    pub(crate) struct Parts<'a> {
        pub(crate) sips: bool,
        pub(crate) user: Option<&'a str>,
        pub(crate) password: Option<&'a str>,
        pub(crate) host: &'a str,
        pub(crate) port: Option<&'a str>,
        pub(crate) params: Vec<Param<'a>>,
        pub(crate) headers: Vec<(&'a str, &'a str)>,
    }

    fn unreserved(b: u8) -> bool {
        b.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&b)
    }

    fn component(
        src: &str,
        allowed: impl Fn(u8) -> bool,
        empty: bool,
        kind: ErrorKind,
    ) -> Result<(), ErrorKind> {
        if src.is_empty() && !empty {
            return Err(kind);
        }
        let bytes = src.as_bytes();
        let mut index = 0;
        while index < bytes.len() {
            if bytes[index] == b'%' {
                let hex = |at: usize| {
                    bytes.get(at).is_some_and(|b| b.is_ascii_hexdigit())
                };
                if !hex(index + 1) || !hex(index + 2) {
                    return Err(ErrorKind::UriEscape);
                }
                index += 3;
            } else if allowed(bytes[index]) {
                index += 1;
            } else {
                return Err(kind);
            }
        }
        Ok(())
    }

    fn host(src: &str) -> bool {
        if let Some(inner) =
            src.strip_prefix('[').and_then(|s| s.strip_suffix(']'))
        {
            return inner.parse::<Ipv6Addr>().is_ok();
        }
        if src.parse::<Ipv4Addr>().is_ok() {
            return true;
        }
        let name = src.strip_suffix('.').unwrap_or(src);
        let top = name.rsplit('.').next().unwrap_or("");
        if !top.as_bytes().first().is_some_and(u8::is_ascii_alphabetic) {
            return false;
        }
        name.split('.').all(|label| {
            label.as_bytes().first().is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    }

    pub(crate) fn parse(src: &str) -> Result<Parts<'_>, ErrorKind> {
        let sips = if src
            .get(..4)
            .is_some_and(|s| s.eq_ignore_ascii_case("sip:"))
        {
            false
        } else if src.get(..5).is_some_and(|s| s.eq_ignore_ascii_case("sips:"))
        {
            true
        } else {
            return Err(ErrorKind::UriScheme);
        };
        let start = if sips { 5 } else { 4 };

        let user_char = |b| unreserved(b) || b"&=+$,;?/".contains(&b);
        let password_char = |b| unreserved(b) || b"&=+$,".contains(&b);
        let param_char = |b| unreserved(b) || b"[]/:&+$".contains(&b);
        let header_char = |b| unreserved(b) || b"[]/?:+$".contains(&b);

        let (user, password, host_start) =
            if let Some(at) = src[start..].find('@') {
                let at = start + at;
                let info = &src[start..at];
                let (user, password) = match info.find(':') {
                    Some(colon) => (&info[..colon], Some(&info[colon + 1..])),
                    None => (info, None),
                };
                component(user, user_char, false, ErrorKind::UriUser)?;
                if let Some(password) = password {
                    component(
                        password,
                        password_char,
                        true,
                        ErrorKind::UriPassword,
                    )?;
                }
                (Some(user), password, at + 1)
            } else {
                (None, None, start)
            };

        let port_end = src[host_start..]
            .find([';', '?'])
            .map_or(src.len(), |n| host_start + n);
        let authority = &src[host_start..port_end];
        let host_len = if authority.starts_with('[') {
            let close = authority.find(']').ok_or(ErrorKind::UriHost)?;
            if !host(&authority[..=close]) {
                return Err(ErrorKind::UriHost);
            }
            close + 1
        } else {
            let end = authority.find(':').unwrap_or(authority.len());
            if !host(&authority[..end]) {
                return Err(ErrorKind::UriHost);
            }
            end
        };
        let host_end = host_start + host_len;
        let port = if host_end < port_end {
            let rest = &src[host_end..port_end];
            if !rest.starts_with(':')
                || rest.len() == 1
                || !rest.as_bytes()[1..].iter().all(u8::is_ascii_digit)
            {
                return Err(ErrorKind::UriPort);
            }
            Some(&rest[1..])
        } else {
            None
        };

        let params_end =
            src[port_end..].find('?').map_or(src.len(), |n| port_end + n);
        let mut params = Vec::new();
        if params_end > port_end {
            for pair in src[port_end + 1..params_end].split(';') {
                let (name, value) = pair
                    .split_once('=')
                    .map_or((pair, None), |(n, v)| (n, Some(v)));
                component(name, param_char, false, ErrorKind::UriParam)?;
                if let Some(value) = value {
                    component(value, param_char, false, ErrorKind::UriParam)?;
                }
                params.push((name, value));
            }
        }

        let mut headers = Vec::new();
        if params_end < src.len() {
            for pair in src[params_end + 1..].split('&') {
                let (name, value) =
                    pair.split_once('=').ok_or(ErrorKind::UriHeader)?;
                component(name, header_char, false, ErrorKind::UriHeader)?;
                component(value, header_char, true, ErrorKind::UriHeader)?;
                headers.push((name, value));
            }
        }

        Ok(Parts {
            sips,
            user,
            password,
            host: &src[host_start..host_end],
            port,
            params,
            headers,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uri_seeds() {
        for seed in [
            &b"sip:alice@atlanta.example.com"[..],
            b"SiPs:alice;phone?work/desk:secret%3a@[2001:db8::1]:005061;Transport=quic;lr?Subject=hello%20world&Subject=",
            b"sip:[::ffff:192.0.2.1]",
            b"sip:192.000.2.1",
            b"sip:example.com;x=a=b",
            b"sip:a%2@example.com",
            b"tel:+1-201-555-0123",
            b"tel:863-1234;phone-context=+1-914-555",
            b"tel:7042;isub=a@b;ext=1;phone-context=example.com",
            b"+1-212-555-1212;ext=99",
            b"\xff",
        ] {
            uri(seed);
        }
    }

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
            b"314159 INVITE",
            b" 7\r\n ACK \t",
            b"1INVITE",
            b"a84b4c76e66710@pc33.atlanta.example.com",
            b"<{a}>:\\\"/[b]?@(c)",
            b"a@b@c",
            b"SIP/2.0/UDP pc33.atlanta.example.com:5060;branch=z9hG4bK776asdhds",
            b"SIP/2.0/UDP h;received=2001:db8::9;rport, SIP / 2.0 / TCP [::1]:5061",
            b"SIP/2.0/UDP h;x=a/b",
            b"SIP/2.0/UDPh",
            b"100rel, timer,\r\n replaces",
            b"gzip,,identity",
            b"text/plain; charset=\"utf-8\"",
            b"application/sdp;level=1;q=0.8;ext, text/*;q=0.5, */*;q=0",
            b"*/sdp;q=2",
            b"Digest realm=\"atlanta.com\", qop=\"auth,auth-int\", stale=FALSE",
            b"Digest realm=\"a\",",
            b"SIP;cause=200;text=\"Call completed, elsewhere\", Q.850;cause=16",
            b"terminated;reason=timeout;retry-after=30",
            b"98732@sip.example.com;from-tag=r33th4x0r;to-tag=ff87ff;early-only",
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

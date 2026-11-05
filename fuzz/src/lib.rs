/*!
Public API fuzzing for `siparse`.

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

#[cfg(test)]
mod tests {
    use super::*;

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
}

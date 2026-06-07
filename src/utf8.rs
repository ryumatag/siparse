use core::ops::RangeInclusive;

use crate::{iter::Bytes, parser::Status};

/// A UTF-8 validation error produced by the parser's modern UTF-8 checker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Utf8Error {
    _priv: (),
}

#[inline]
pub(crate) fn parse_utf8_char(
    bytes: &mut Bytes<'_>,
) -> Result<crate::parser::Status<()>, Utf8Error> {
    let first = next!(bytes);

    match first {
        0x00..=0x7f => Ok(Status::Complete(())),
        0xc2..=0xdf => parse_tail(bytes, 1),
        0xe0 => parse_tail_in(bytes, &[0xa0..=0xbf, 0x80..=0xbf]),
        0xe1..=0xec | 0xee..=0xef => {
            parse_tail_in(bytes, &[0x80..=0xbf, 0x80..=0xbf])
        }
        0xed => parse_tail_in(bytes, &[0x80..=0x9f, 0x80..=0xbf]),
        0xf0 => parse_tail_in(bytes, &[0x90..=0xbf, 0x80..=0xbf, 0x80..=0xbf]),
        0xf1..=0xf3 => {
            parse_tail_in(bytes, &[0x80..=0xbf, 0x80..=0xbf, 0x80..=0xbf])
        }
        0xf4 => parse_tail_in(bytes, &[0x80..=0x8f, 0x80..=0xbf, 0x80..=0xbf]),
        _ => Err(Utf8Error::new()),
    }
}

/// Consumes consecutive non-ASCII UTF-8 sequences.
///
/// The run stops in front of the next byte that starts an ASCII character
/// without consuming it, so the caller's grammar decides what `CR`, `LF`,
/// `%` or `NUL` mean. An ASCII byte in a continuation position is consumed
/// and reported as an error, exactly as `parse_utf8_char` does.
#[inline]
pub(crate) fn parse_utf8_run(
    bytes: &mut Bytes<'_>,
) -> Result<Status<()>, Utf8Error> {
    while matches!(bytes.peek(), Some(0x80..=0xff)) {
        match parse_utf8_char(bytes)? {
            Status::Complete(()) => {}
            Status::Partial => return Ok(Status::Partial),
        }
    }

    Ok(Status::Complete(()))
}

#[inline]
fn parse_tail(
    bytes: &mut Bytes<'_>,
    count: usize,
) -> Result<Status<()>, Utf8Error> {
    for _ in 0..count {
        ensure!(bytes.next() == 0x80..=0xbf => Utf8Error::new());
    }

    Ok(Status::Complete(()))
}

#[inline]
fn parse_tail_in(
    bytes: &mut Bytes<'_>,
    ranges: &[RangeInclusive<u8>],
) -> Result<Status<()>, Utf8Error> {
    for range in ranges {
        let byte = next!(bytes);

        if !range.contains(&byte) {
            return Err(Utf8Error::new());
        }
    }

    Ok(Status::Complete(()))
}

impl Utf8Error {
    #[inline]
    const fn new() -> Utf8Error {
        Utf8Error { _priv: () }
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_utf8_char, parse_utf8_run, Utf8Error};
    use crate::{iter::Bytes, parser::Status};

    fn parser_accepts_utf8(bytes: &[u8]) -> bool {
        let mut input = Bytes::new(bytes);

        while !input.is_empty() {
            match parse_utf8_char(&mut input) {
                Ok(Status::Complete(())) => {}
                Ok(Status::Partial) | Err(_) => return false,
            }
        }

        true
    }

    /// The three-state result of a run together with the cursor position at
    /// the moment it returned.
    type RunOutcome = (Result<Status<()>, Utf8Error>, usize);

    fn utf8_run(bytes: &[u8]) -> RunOutcome {
        let mut input = Bytes::new(bytes);

        let status = parse_utf8_run(&mut input);

        (status, input.pos())
    }

    #[test]
    #[cfg_attr(miri, ignore = "exhaustive input is too slow under Miri")]
    fn parser_accepts_every_rust_scalar_utf8_encoding() {
        let mut buf = [0; 4];

        for scalar in 0..=0x10ffff {
            let Some(ch) = char::from_u32(scalar) else {
                continue;
            };

            let encoded = ch.encode_utf8(&mut buf);

            assert!(
                parser_accepts_utf8(encoded.as_bytes()),
                "scalar U+{scalar:04X} should be accepted",
            );
        }
    }

    #[test]
    #[cfg_attr(miri, ignore = "exhaustive input is too slow under Miri")]
    fn parser_matches_from_utf8_for_exhaustive_two_byte_sequences() {
        for a in u8::MIN..=u8::MAX {
            for b in u8::MIN..=u8::MAX {
                let bytes = [a, b];

                assert_eq!(
                    parser_accepts_utf8(&bytes),
                    core::str::from_utf8(&bytes).is_ok(),
                    "bytes={bytes:02X?}",
                );
            }
        }
    }

    #[test]
    #[cfg_attr(miri, ignore = "exhaustive input is too slow under Miri")]
    fn parser_matches_from_utf8_for_dense_boundary_sequences_up_to_four_bytes()
    {
        const BOUNDARY_BYTES: &[u8] = &[
            0x00, 0x01, 0x09, 0x20, 0x7f, 0x80, 0x8f, 0x90, 0x9f, 0xa0, 0xbf,
            0xc0, 0xc1, 0xc2, 0xdf, 0xe0, 0xe1, 0xec, 0xed, 0xee, 0xef, 0xf0,
            0xf1, 0xf3, 0xf4, 0xf5, 0xf8, 0xfc, 0xff,
        ];

        for &a in BOUNDARY_BYTES {
            let one = [a];
            assert_eq!(
                parser_accepts_utf8(&one),
                core::str::from_utf8(&one).is_ok(),
                "bytes={one:02X?}",
            );

            for &b in BOUNDARY_BYTES {
                let two = [a, b];
                assert_eq!(
                    parser_accepts_utf8(&two),
                    core::str::from_utf8(&two).is_ok(),
                    "bytes={two:02X?}",
                );

                for &c in BOUNDARY_BYTES {
                    let three = [a, b, c];
                    assert_eq!(
                        parser_accepts_utf8(&three),
                        core::str::from_utf8(&three).is_ok(),
                        "bytes={three:02X?}",
                    );

                    for &d in BOUNDARY_BYTES {
                        let four = [a, b, c, d];
                        assert_eq!(
                            parser_accepts_utf8(&four),
                            core::str::from_utf8(&four).is_ok(),
                            "bytes={four:02X?}",
                        );
                    }
                }
            }
        }
    }

    const OK: Result<Status<()>, Utf8Error> = Ok(Status::Complete(()));
    const PARTIAL: Result<Status<()>, Utf8Error> = Ok(Status::Partial);
    const ERR: Result<Status<()>, Utf8Error> = Err(Utf8Error::new());

    #[test]
    fn utf8_run_reports_status_and_consumption() {
        let cases: &[(&[u8], _, usize)] = &[
            (&[], OK, 0),
            // A run never consumes a leading ASCII byte, even when an invalid
            // byte follows it.
            (&[0x41, 0xff], OK, 0),
            (&[0xc2], PARTIAL, 1),
            // `E0` requires `A0..=BF` next. The error must not wait for the
            // missing third byte.
            (&[0xe0, 0x80], ERR, 2),
            (&[0xe0, 0xa0], PARTIAL, 2),
            (&[0xf4, 0x90, 0x80, 0x80], ERR, 2),
            (&[0xe3, 0x81, 0x82, 0x0d, 0x0a], OK, 3),
            // ASCII in a continuation position is consumed as an error.
            (&[0xe3, 0x81, 0x0d, 0x0a], ERR, 3),
            (&[0xe3, 0x81, 0x82, 0xc2], PARTIAL, 4),
            (&[0xe3, 0x81, 0x82, 0x41, 0x80], OK, 3),
        ];

        for &(bytes, expected_status, expected_pos) in cases {
            assert_eq!(
                utf8_run(bytes),
                (expected_status, expected_pos),
                "bytes={bytes:02X?}",
            );
        }
    }

    #[test]
    fn utf8_run_checks_special_second_byte_bounds() {
        // `(lead, lowest valid second byte, highest valid second byte)`.
        const BOUNDS: &[(u8, u8, u8)] = &[
            (0xe0, 0xa0, 0xbf),
            (0xe1, 0x80, 0xbf),
            (0xed, 0x80, 0x9f),
            (0xee, 0x80, 0xbf),
            (0xf0, 0x90, 0xbf),
            (0xf1, 0x80, 0xbf),
            (0xf4, 0x80, 0x8f),
        ];

        for &(lead, low, high) in BOUNDS {
            let width = if lead >= 0xf0 { 4 } else { 3 };

            for second in [low - 1, low, high, high.wrapping_add(1)] {
                // A full character followed by an ASCII terminator.
                let mut bytes = [lead, second, 0x80, 0x80, b'\r'];
                bytes[width] = b'\r';
                let bytes = &bytes[..=width];

                let expected = if (low..=high).contains(&second) {
                    (OK, width)
                } else {
                    (ERR, 2)
                };
                assert_eq!(utf8_run(bytes), expected, "bytes={bytes:02X?}");
            }
        }
    }

    #[test]
    fn utf8_run_consumes_mixed_width_run() {
        let text = "\u{e9}\u{3042}\u{1f600}\u{df}\u{10ffff}\u{800}\u{80}";
        let mut input = text.as_bytes().to_vec();
        input.extend_from_slice(b"\r\n");

        assert_eq!(utf8_run(&input), (OK, text.len()));

        // A truncation inside a character is `Partial` and consumes the whole
        // truncated input. A truncation between characters is a complete run.
        // Neither is an error.
        for end in 0..=text.len() {
            let status = if text.is_char_boundary(end) { OK } else { PARTIAL };

            assert_eq!(utf8_run(&input[..end]), (status, end), "end={end}");
        }
    }

    #[test]
    fn utf8_run_stops_before_every_ascii_byte() {
        let run = "\u{e9}\u{3042}\u{1f600}".as_bytes();

        for ascii in 0x00..=0x7f {
            // The invalid bytes after the ASCII byte must be left alone for
            // the caller's grammar to see.
            for tail in [&[][..], &[0xff], &[0x80], &[0xe0, 0x80], &[0xc2]] {
                let mut input = run.to_vec();
                input.push(ascii);
                input.extend_from_slice(tail);

                assert_eq!(
                    utf8_run(&input),
                    (OK, run.len()),
                    "bytes={input:02X?}",
                );
            }
        }
    }

    #[test]
    fn utf8_run_reports_invalid_byte_after_valid_character() {
        let valid = ["\u{e9}", "\u{3042}", "\u{1f600}"];
        // `(invalid bytes, bytes consumed up to and including the first
        // rejected byte)`.
        let invalid: &[(&[u8], usize)] = &[
            // Rejected as a lead byte.
            (&[0x80], 1),
            (&[0xbf], 1),
            (&[0xc0, 0x80], 1),
            (&[0xc1, 0xbf], 1),
            (&[0xf5, 0x80, 0x80, 0x80], 1),
            (&[0xff], 1),
            // Rejected at a restricted second byte.
            (&[0xe0, 0x9f, 0x80], 2),
            (&[0xed, 0xa0, 0x80], 2),
            (&[0xf0, 0x8f, 0x80, 0x80], 2),
            (&[0xf4, 0x90, 0x80, 0x80], 2),
            // Rejected at ASCII in a continuation position.
            (&[0xe3, 0x81, b'\r'], 3),
        ];

        for prefix in valid {
            for &(bad, consumed) in invalid {
                let mut input = prefix.as_bytes().to_vec();
                input.extend_from_slice(bad);
                input.extend_from_slice(b"\r\n");

                assert_eq!(
                    utf8_run(&input),
                    (ERR, prefix.len() + consumed),
                    "bytes={input:02X?}",
                );
            }
        }
    }
}

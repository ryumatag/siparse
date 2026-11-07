use crate::{
    error::Error,
    iter::Bytes,
    parse::{Boundary, Delimited, Result, Status},
    simd,
    token::is_method_token,
    utf8::parse_utf8_run,
};

/// SIP request-line fields, each set once the parser has validated it.
///
/// Each field borrows from the parsed input buffer. Fields are filled in wire
/// order, so after [`Status::Partial`] or an error the fields parsed before
/// the parser stopped are `Some` and the rest are `None`. After
/// [`Status::Complete`], every field is `Some`.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct RequestLine<'buf> {
    /// The request method token, such as `INVITE`.
    pub method: Option<&'buf str>,
    /// The raw request URI. It is not percent-decoded.
    pub uri: Option<&'buf str>,
    /// The SIP version token as it appeared on the wire, such as `SIP/2.0`.
    pub version: Option<&'buf str>,
}

impl<'buf> RequestLine<'buf> {
    /// Returns the fields without their `Option`s, or `None` if any is
    /// missing.
    ///
    /// After [`Status::Complete`] this is always `Some`, so code that has
    /// a complete head can take the fields once instead of unwrapping each.
    ///
    /// # Example
    ///
    /// ```
    /// use siparse::{HeaderBuf, RequestHead, Status};
    ///
    /// let buf = b"BYE sip:alice@pc33.example.com SIP/2.0\r\n\r\n";
    ///
    /// let mut headers = HeaderBuf::<16>::new();
    /// let mut head = RequestHead::new(&mut headers);
    /// assert_eq!(head.parse(buf)?, Status::Complete(buf.len()));
    ///
    /// let line = head.start_line.complete().expect("the head is complete");
    /// assert_eq!(line.method, "BYE");
    /// assert_eq!(line.uri, "sip:alice@pc33.example.com");
    /// # Ok::<(), siparse::Error>(())
    /// ```
    #[inline]
    pub fn complete(&self) -> Option<CompleteRequestLine<'buf>> {
        Some(CompleteRequestLine {
            method: self.method?,
            uri: self.uri?,
            version: self.version?,
        })
    }
}

/// SIP status-line fields, each set once the parser has validated it.
///
/// Each field borrows from the parsed input buffer. Fields are filled in wire
/// order, so after [`Status::Partial`] or an error the fields parsed before
/// the parser stopped are `Some` and the rest are `None`. After
/// [`Status::Complete`], every field is `Some`.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct StatusLine<'buf> {
    /// The SIP version token as it appeared on the wire, such as `SIP/2.0`.
    pub version: Option<&'buf str>,
    /// The three-digit status code, such as `200`.
    ///
    /// This stays a string because converting it to an integer is semantic
    /// decoding, which belongs to the consumer.
    pub status_code: Option<&'buf str>,
    /// The raw reason phrase, possibly empty. `%`-escapes are not decoded.
    pub reason_phrase: Option<&'buf str>,
}

impl<'buf> StatusLine<'buf> {
    /// Returns the status code as a number.
    ///
    /// SIP transaction handling branches on the code class all the time,
    /// for example provisional `1xx` versus final responses, so this saves
    /// every caller from converting the string itself.
    ///
    /// Returns `None` if `status_code` is `None`. It also returns `None` if
    /// `status_code` is not exactly three ASCII digits. The parser never
    /// stores such a value, but the field is public and can be set by hand.
    ///
    /// The value is not range-checked. RFC 3261 only defines classes `1xx`
    /// through `6xx`, but the parser accepts any three digits.
    ///
    /// # Example
    ///
    /// ```
    /// use siparse::StatusLine;
    ///
    /// let line = StatusLine {
    ///     version: Some("SIP/2.0"),
    ///     status_code: Some("180"),
    ///     reason_phrase: Some("Ringing"),
    /// };
    /// assert_eq!(line.code(), Some(180));
    /// ```
    #[inline]
    pub fn code(&self) -> Option<u16> {
        status_code_number(self.status_code?)
    }

    /// Returns the fields without their `Option`s, or `None` if any is
    /// missing.
    ///
    /// After [`Status::Complete`] this is always `Some`. See
    /// [`RequestLine::complete`].
    #[inline]
    pub fn complete(&self) -> Option<CompleteStatusLine<'buf>> {
        Some(CompleteStatusLine {
            version: self.version?,
            status_code: self.status_code?,
            reason_phrase: self.reason_phrase?,
        })
    }
}

/// Converts three ASCII digits to a number.
#[inline]
fn status_code_number(status_code: &str) -> Option<u16> {
    match *status_code.as_bytes() {
        [a @ b'0'..=b'9', b @ b'0'..=b'9', c @ b'0'..=b'9'] => Some(
            u16::from(a - b'0') * 100
                + u16::from(b - b'0') * 10
                + u16::from(c - b'0'),
        ),
        _ => None,
    }
}

/// A request-line or status-line, for heads whose kind is not known in
/// advance.
///
/// Stream and datagram transports deliver requests and responses on the same
/// connection or socket, so a SIP element often has to parse a head before it
/// knows which kind it is. [`AnyHead`](crate::AnyHead) decides from the first
/// bytes of the start-line and stores the result here.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum StartLine<'buf> {
    /// A request-line, such as `INVITE sip:bob@example.com SIP/2.0`.
    Request(RequestLine<'buf>),
    /// A status-line, such as `SIP/2.0 200 OK`.
    Status(StatusLine<'buf>),
}

impl<'buf> StartLine<'buf> {
    /// Returns the start-line without its `Option`s, or `None` if any
    /// field is missing.
    ///
    /// After [`Status::Complete`] this is always `Some`. See
    /// [`RequestLine::complete`].
    ///
    /// # Example
    ///
    /// ```
    /// use siparse::{AnyHead, CompleteStartLine, HeaderBuf, Status};
    ///
    /// let buf = b"SIP/2.0 486 Busy Here\r\n\r\n";
    ///
    /// let mut headers = HeaderBuf::<16>::new();
    /// let mut head = AnyHead::new(&mut headers);
    /// assert_eq!(head.parse(buf)?, Status::Complete(buf.len()));
    ///
    /// match head.start_line.and_then(|line| line.complete()) {
    ///     Some(CompleteStartLine::Status(line)) => {
    ///         assert_eq!(line.code(), Some(486));
    ///         assert_eq!(line.reason_phrase, "Busy Here");
    ///     }
    ///     other => panic!("expected a status-line, got {other:?}"),
    /// }
    /// # Ok::<(), siparse::Error>(())
    /// ```
    #[inline]
    pub fn complete(&self) -> Option<CompleteStartLine<'buf>> {
        match self {
            StartLine::Request(line) => {
                line.complete().map(CompleteStartLine::Request)
            }
            StartLine::Status(line) => {
                line.complete().map(CompleteStartLine::Status)
            }
        }
    }
}

/// A request-line with every field present.
///
/// [`RequestLine::complete`] returns this once the parser has filled every
/// field. Each field borrows from the parsed input buffer.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CompleteRequestLine<'buf> {
    /// The request method token, such as `INVITE`.
    pub method: &'buf str,
    /// The raw request URI. It is not percent-decoded.
    pub uri: &'buf str,
    /// The SIP version token as it appeared on the wire, such as `SIP/2.0`.
    pub version: &'buf str,
}

/// A status-line with every field present.
///
/// [`StatusLine::complete`] returns this once the parser has filled every
/// field. Each field borrows from the parsed input buffer.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CompleteStatusLine<'buf> {
    /// The SIP version token as it appeared on the wire, such as `SIP/2.0`.
    pub version: &'buf str,
    /// The three-digit status code, such as `200`.
    pub status_code: &'buf str,
    /// The raw reason phrase, possibly empty. `%`-escapes are not decoded.
    pub reason_phrase: &'buf str,
}

impl CompleteStatusLine<'_> {
    /// Returns the status code as a number.
    ///
    /// This behaves like [`StatusLine::code`]. It returns `None` only for a
    /// `status_code` set by hand that is not exactly three ASCII digits.
    #[inline]
    pub fn code(&self) -> Option<u16> {
        status_code_number(self.status_code)
    }
}

/// A request-line or status-line with every field present.
///
/// [`StartLine::complete`] returns this once the parser has filled every
/// field.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CompleteStartLine<'buf> {
    /// A request-line, such as `INVITE sip:bob@example.com SIP/2.0`.
    Request(CompleteRequestLine<'buf>),
    /// A status-line, such as `SIP/2.0 200 OK`.
    Status(CompleteStatusLine<'buf>),
}

/// Parses a request-line or status-line, deciding which from its first bytes.
///
/// A status-line starts with `SIP/`, compared case-insensitively like the
/// version. A request-line cannot, because a method token never contains `/`.
/// So the first four bytes decide, and `line` stays `None` until they arrive.
/// A method named `SIP` is still a request, since the fourth byte is then
/// `SP`.
///
/// After that, `line` holds the variant with whatever fields its parser filled
/// in, even on `Partial` or an error.
#[inline]
pub(super) fn parse_start_line<'buf>(
    bytes: &mut Bytes<'buf>,
    line: &mut Option<StartLine<'buf>>,
) -> Result<()> {
    const STATUS_LINE_PREFIX: &[u8; 4] = b"SIP/";

    let is_status_line = match bytes.peek_n::<4>() {
        Some(prefix) => prefix.eq_ignore_ascii_case(STATUS_LINE_PREFIX),
        None => {
            let remaining = bytes.remaining();
            // `remaining` is shorter than the prefix here.
            if remaining
                .eq_ignore_ascii_case(&STATUS_LINE_PREFIX[..remaining.len()])
            {
                return Ok(Status::Partial);
            }

            false
        }
    };

    // Store the variant first and let its parser fill it in place, so the
    // fields parsed before `Partial` or an error stay readable. The other
    // arm is unreachable because `insert` returns the variant it just stored.
    // Parsing into a local and moving it into `line` afterwards was a few
    // percent slower on the `any_head` corpus benchmark.
    if is_status_line {
        match line.insert(StartLine::Status(StatusLine::default())) {
            StartLine::Status(status_line) => {
                parse_status_line(bytes, status_line)
            }
            StartLine::Request(_) => unreachable!(),
        }
    } else {
        match line.insert(StartLine::Request(RequestLine::default())) {
            StartLine::Request(request_line) => {
                parse_request_line(bytes, request_line)
            }
            StartLine::Status(_) => unreachable!(),
        }
    }
}

#[inline]
pub(super) fn parse_request_line<'buf>(
    bytes: &mut Bytes<'buf>,
    line: &mut RequestLine<'buf>,
) -> Result<()> {
    // RFC 3261, Section 7.1 defines:
    //
    //     Request-Line  =  Method SP Request-URI SP SIP-Version CRLF
    //
    // Ref: https://www.rfc-editor.org/rfc/rfc3261.html#section-7.1

    line.method = Some(complete!(method::<Delimited>(bytes)));
    ensure!(bytes.next() == b' ' => Error::method());
    line.uri = Some(complete!(request_uri::<Delimited>(bytes)));
    ensure!(bytes.next() == b' ' => Error::request_uri());
    line.version = Some(complete!(parse_version(bytes)));
    complete!(parse_crlf(bytes, Error::version()));

    Ok(Status::Complete(()))
}

#[inline]
pub(crate) fn method<'buf, B: Boundary>(
    bytes: &mut Bytes<'buf>,
) -> Result<&'buf str> {
    // TODO: Add a fast-path here only when benchmarks justify it.

    let mark = bytes.mark_token();

    loop {
        match peek_or_end!(bytes, B) {
            // The end of a whole token, or the `SP` after one in a head.
            None => break,
            Some(b' ') if !B::WHOLE => break,
            Some(b) if is_method_token(b) => {
                // SAFETY: `peek_or_end!` just returned a byte.
                unsafe { bytes.advance(1) }
            }
            Some(_) => return Err(Error::method()),
        }
    }

    if mark.is_empty(bytes) {
        return Err(Error::method());
    }
    // SAFETY: Every consumed byte satisfied `is_method_token`, which only
    // accepts ASCII.
    let method = unsafe { mark.exit_str(bytes) };

    Ok(Status::Complete(method))
}

#[inline]
pub(crate) fn request_uri<'buf, B: Boundary>(
    bytes: &mut Bytes<'buf>,
) -> Result<&'buf str> {
    let mark = bytes.mark_token();

    simd::match_uri_vectored(bytes);

    match peek_or_end!(bytes, B) {
        // The end of a whole token, or the `SP` after one in a head.
        None => {}
        Some(b' ') if !B::WHOLE => {}
        Some(_) => return Err(Error::request_uri()),
    }

    if mark.is_empty(bytes) {
        return Err(Error::request_uri());
    }
    // SAFETY: `match_uri_vectored` only consumes bytes that satisfy
    // `is_uri_token`, which rejects raw non-ASCII.
    let uri = unsafe { mark.exit_str(bytes) };

    Ok(Status::Complete(uri))
}

#[inline]
pub(super) fn parse_status_line<'buf>(
    bytes: &mut Bytes<'buf>,
    line: &mut StatusLine<'buf>,
) -> Result<()> {
    // RFC 3261, Section 7.2 defines:
    //
    //     Status-Line  =  SIP-Version SP Status-Code SP Reason-Phrase CRLF
    //
    // Ref: https://www.rfc-editor.org/rfc/rfc3261.html#section-7.2

    line.version = Some(complete!(parse_version(bytes)));
    ensure!(bytes.next() == b' ' => Error::version());
    line.status_code = Some(complete!(parse_status_code(bytes)));
    ensure!(bytes.next() == b' ' => Error::status_code());
    line.reason_phrase = Some(complete!(reason_phrase::<Delimited>(bytes)));
    // `parse_reason_phrase` only stops before `CR`, so `parse_crlf` never
    // sees another byte here.
    complete!(parse_crlf(bytes, Error::reason_phrase()));

    Ok(Status::Complete(()))
}

#[inline]
pub(crate) fn parse_status_code<'buf>(
    bytes: &mut Bytes<'buf>,
) -> Result<&'buf str> {
    let mark = bytes.mark_token();

    ensure!(bytes.next() == b'0'..=b'9' => Error::status_code());
    ensure!(bytes.next() == b'0'..=b'9' => Error::status_code());
    ensure!(bytes.next() == b'0'..=b'9' => Error::status_code());

    ensure!(bytes.peek() == b' ' => Error::status_code());

    // SAFETY: Exactly three ASCII digits were consumed.
    let status_code = unsafe { mark.exit_str(bytes) };

    Ok(Status::Complete(status_code))
}

#[inline]
pub(crate) fn reason_phrase<'buf, B: Boundary>(
    bytes: &mut Bytes<'buf>,
) -> Result<&'buf str> {
    let mark = bytes.mark_token();

    loop {
        simd::match_reason_phrase_ascii_vectored(bytes);

        // The SIMD pass above consumes every byte for which
        // `is_reason_phrase_octet` returns true. The next byte is
        // therefore guaranteed to be outside that set, so there is no arm here
        // for `is_reason_phrase_octet`.
        match peek_or_end!(bytes, B) {
            // The end of a whole token, or the `CR` after one in a head.
            None => break,
            Some(b'\r') if !B::WHOLE => break,
            // A whole reason phrase has no line ending to blame a bare `LF`
            // on, so it is just a byte the phrase does not allow.
            Some(b'\n') if !B::WHOLE => return Err(Error::bare_lf()),
            Some(b'%') => {
                // SAFETY: `peek_or_end!` just returned a byte.
                unsafe { bytes.advance(1) };
                complete!(parse_escaped_octet(bytes));
            }
            // Validated in place on purpose. See `parse_header_value`.
            Some(b) if b >= 0x80 => {
                complete!(
                    parse_utf8_run(bytes).map_err(|_| Error::reason_phrase())
                );
            }
            _ => return Err(Error::reason_phrase()),
        }
    }

    // SAFETY: Every consumed byte is an ASCII `is_reason_phrase_octet`, part
    // of an ASCII `%`-escape, or part of a sequence accepted by
    // `parse_utf8_run`.
    let reason_phrase = unsafe { mark.exit_str(bytes) };

    Ok(Status::Complete(reason_phrase))
}

#[allow(missing_docs)]
#[inline]
fn parse_escaped_octet(bytes: &mut Bytes<'_>) -> Result<()> {
    ensure!(
        bytes.next() == b'0'..=b'9' | b'A'..=b'F' | b'a'..=b'f'
            => Error::reason_phrase()
    );
    ensure!(
        bytes.next() == b'0'..=b'9' | b'A'..=b'F' | b'a'..=b'f'
            => Error::reason_phrase()
    );

    Ok(Status::Complete(()))
}

#[inline]
pub(crate) fn parse_version<'buf>(
    bytes: &mut Bytes<'buf>,
) -> Result<&'buf str> {
    const SIP_2_0: [u8; 7] = *b"SIP/2.0";

    let mark = bytes.mark_token();

    // Fast-path the common upper-case literal, ...
    if let Some(SIP_2_0) = bytes.peek_n::<7>() {
        // SAFETY: `peek_n` just returned 7 bytes.
        unsafe { bytes.advance(7) };

        // SAFETY: The consumed bytes are the ASCII literal `SIP/2.0`.
        let version = unsafe { mark.exit_str(bytes) };
        return Ok(Status::Complete(version));
    }

    // ... then fall back to a case-insensitive match for the same 7-byte
    // token.
    //
    // RFC 3261 says:
    //
    // > ..., applications sending SIP messages MUST include a SIP-Version of
    // > "SIP/2.0". The SIP-Version string is case-insensitive, but
    // > implementations MUST send upper-case.
    ensure!(bytes.next() == b'S' | b's' => Error::version());
    ensure!(bytes.next() == b'I' | b'i' => Error::version());
    ensure!(bytes.next() == b'P' | b'p' => Error::version());
    ensure!(bytes.next() == b'/' => Error::version());
    ensure!(bytes.next() == b'2' => Error::version());
    ensure!(bytes.next() == b'.' => Error::version());
    ensure!(bytes.next() == b'0' => Error::version());

    // SAFETY: Every consumed byte matched one of the ASCII patterns above.
    let version = unsafe { mark.exit_str(bytes) };

    Ok(Status::Complete(version))
}

/// Parses the `CRLF` that terminates the start-line.
///
/// `unexpected` is the error for a byte that is neither `CR` nor `LF`. Such
/// a byte means the last start-line element did not end where it should, so
/// the caller reports it as that element.
#[inline]
fn parse_crlf(bytes: &mut Bytes<'_>, unexpected: Error) -> Result<()> {
    const CRLF: [u8; 2] = *b"\r\n";

    match bytes.peek_n::<2>() {
        Some(CRLF) => {
            // SAFETY: `peek_n` just returned 2 bytes.
            unsafe { bytes.advance(2) };
            Ok(Status::Complete(()))
        }
        Some([b'\r', _]) => Err(Error::bare_cr()),
        Some([b'\n', _]) => Err(Error::bare_lf()),
        Some(_) => Err(unexpected),
        // Fewer than two bytes remain. The input is partial unless the
        // remaining byte already rules out `CRLF`.
        None => match bytes.peek() {
            None | Some(b'\r') => Ok(Status::Partial),
            Some(b'\n') => Err(Error::bare_lf()),
            Some(_) => Err(unexpected),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::format;

    fn line_with_code(status_code: Option<&str>) -> StatusLine<'_> {
        StatusLine { status_code, ..StatusLine::default() }
    }

    #[test]
    fn code_converts_every_three_digit_code() {
        for n in 0..=999u16 {
            let digits = format!("{n:03}");
            assert_eq!(line_with_code(Some(&digits)).code(), Some(n));
        }
    }

    // The parser never stores these, but `status_code` is a public field.
    #[test]
    fn code_returns_none_for_values_the_parser_never_stores() {
        for status_code in
            [None, Some(""), Some("20"), Some("2000"), Some("+20")]
        {
            assert_eq!(line_with_code(status_code).code(), None);
        }
    }

    #[test]
    fn complete_needs_every_request_line_field() {
        let line = RequestLine {
            method: Some("INVITE"),
            uri: Some("sip:bob@example.com"),
            version: Some("SIP/2.0"),
        };
        assert_eq!(
            line.complete(),
            Some(CompleteRequestLine {
                method: "INVITE",
                uri: "sip:bob@example.com",
                version: "SIP/2.0",
            })
        );

        for partial in [
            RequestLine { method: None, ..line },
            RequestLine { uri: None, ..line },
            RequestLine { version: None, ..line },
        ] {
            assert_eq!(partial.complete(), None, "{partial:?}");
        }
    }

    #[test]
    fn complete_needs_every_status_line_field() {
        let line = StatusLine {
            version: Some("SIP/2.0"),
            status_code: Some("200"),
            reason_phrase: Some(""),
        };
        let complete = line.complete().unwrap();
        assert_eq!(
            complete,
            CompleteStatusLine {
                version: "SIP/2.0",
                status_code: "200",
                reason_phrase: "",
            }
        );
        assert_eq!(complete.code(), Some(200));

        for partial in [
            StatusLine { version: None, ..line },
            StatusLine { status_code: None, ..line },
            StatusLine { reason_phrase: None, ..line },
        ] {
            assert_eq!(partial.complete(), None, "{partial:?}");
        }
    }

    #[test]
    fn start_line_complete_keeps_the_kind() {
        let request = RequestLine {
            method: Some("ACK"),
            uri: Some("sip:bob@example.com"),
            version: Some("SIP/2.0"),
        };
        assert_eq!(
            StartLine::Request(request).complete(),
            request.complete().map(CompleteStartLine::Request)
        );
        assert_eq!(
            StartLine::Request(RequestLine::default()).complete(),
            None
        );

        let status = StatusLine {
            version: Some("SIP/2.0"),
            status_code: Some("180"),
            reason_phrase: Some("Ringing"),
        };
        assert_eq!(
            StartLine::Status(status).complete(),
            status.complete().map(CompleteStartLine::Status)
        );
        assert_eq!(StartLine::Status(StatusLine::default()).complete(), None);
    }
}

use crate::{
    error::Error,
    iter::Bytes,
    parse::{Result, Status},
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
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RequestLine<'buf> {
    /// The request method token, such as `INVITE`.
    pub method: Option<&'buf str>,
    /// The raw request URI. It is not percent-decoded.
    pub uri: Option<&'buf str>,
    /// The SIP version token as it appeared on the wire, such as `SIP/2.0`.
    pub version: Option<&'buf str>,
}

/// SIP status-line fields, each set once the parser has validated it.
///
/// Each field borrows from the parsed input buffer. Fields are filled in wire
/// order, so after [`Status::Partial`] or an error the fields parsed before
/// the parser stopped are `Some` and the rest are `None`. After
/// [`Status::Complete`], every field is `Some`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
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

    line.method = Some(complete!(parse_method(bytes)));
    ensure!(bytes.next() == b' ' => Error::method());
    line.uri = Some(complete!(parse_request_uri(bytes)));
    ensure!(bytes.next() == b' ' => Error::request_uri());
    line.version = Some(complete!(parse_version(bytes)));
    complete!(parse_crlf(bytes, Error::version()));

    Ok(Status::Complete(()))
}

#[allow(missing_docs)]
#[inline]
pub fn parse_method<'buf>(bytes: &mut Bytes<'buf>) -> Result<&'buf str> {
    // TODO: Add a fast-path here only when benchmarks justify it.

    let mark = bytes.mark_token();

    loop {
        match peek!(bytes) {
            b' ' if mark.is_empty(bytes) => return Err(Error::method()),
            b' ' => {
                // SAFETY: Every consumed byte satisfied `is_method_token`,
                // which only accepts ASCII.
                let method = unsafe { mark.exit_str(bytes) };
                return Ok(Status::Complete(method));
            }
            b if is_method_token(b) => {
                // SAFETY: `peek!` just returned a byte.
                unsafe { bytes.advance(1) }
            }
            _ => return Err(Error::method()),
        }
    }
}

#[allow(missing_docs)]
#[inline]
pub fn parse_request_uri<'buf>(bytes: &mut Bytes<'buf>) -> Result<&'buf str> {
    let mark = bytes.mark_token();

    simd::match_uri_vectored(bytes);

    match peek!(bytes) {
        b' ' if !mark.is_empty(bytes) => {
            // SAFETY: `match_uri_vectored` only consumes bytes that satisfy
            // `is_uri_token`, which rejects raw non-ASCII.
            let uri = unsafe { mark.exit_str(bytes) };
            Ok(Status::Complete(uri))
        }
        _ => Err(Error::request_uri()),
    }
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
    line.reason_phrase = Some(complete!(parse_reason_phrase(bytes)));
    // `parse_reason_phrase` only stops before `CR`, so `parse_crlf` never
    // sees another byte here.
    complete!(parse_crlf(bytes, Error::reason_phrase()));

    Ok(Status::Complete(()))
}

#[allow(missing_docs)]
#[inline]
pub fn parse_status_code<'buf>(bytes: &mut Bytes<'buf>) -> Result<&'buf str> {
    let mark = bytes.mark_token();

    ensure!(bytes.next() == b'0'..=b'9' => Error::status_code());
    ensure!(bytes.next() == b'0'..=b'9' => Error::status_code());
    ensure!(bytes.next() == b'0'..=b'9' => Error::status_code());

    ensure!(bytes.peek() == b' ' => Error::status_code());

    // SAFETY: Exactly three ASCII digits were consumed.
    let status_code = unsafe { mark.exit_str(bytes) };
    Ok(Status::Complete(status_code))
}

#[allow(missing_docs)]
#[inline]
pub fn parse_reason_phrase<'buf>(
    bytes: &mut Bytes<'buf>,
) -> Result<&'buf str> {
    let mark = bytes.mark_token();

    loop {
        simd::match_reason_phrase_ascii_vectored(bytes);

        // The SIMD pass above consumes every byte for which
        // `is_reason_phrase_octet` returns true. The next byte is
        // therefore guaranteed to be outside that set, so there is no arm here
        // for `is_reason_phrase_octet`.
        match peek!(bytes) {
            b'\r' => {
                // SAFETY: Every consumed byte is an ASCII
                // `is_reason_phrase_octet`, part of an ASCII `%`-escape, or
                // part of a sequence accepted by `parse_utf8_run`.
                let reason_phrase = unsafe { mark.exit_str(bytes) };
                return Ok(Status::Complete(reason_phrase));
            }
            b'\n' => return Err(Error::bare_lf()),
            b'%' => {
                // SAFETY: `peek!` just returned a byte.
                unsafe { bytes.advance(1) };
                complete!(parse_escaped_octet(bytes));
            }
            // Validated in place on purpose. See `parse_header_value`.
            b if b >= 0x80 => {
                complete!(
                    parse_utf8_run(bytes).map_err(|_| Error::reason_phrase())
                );
            }
            _ => return Err(Error::reason_phrase()),
        }
    }
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

#[allow(missing_docs)]
#[inline]
pub fn parse_version<'buf>(bytes: &mut Bytes<'buf>) -> Result<&'buf str> {
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

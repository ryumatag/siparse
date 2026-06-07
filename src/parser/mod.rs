/*!
SIP head parser.
*/

mod header;
mod start_line;

use core::mem::MaybeUninit;

use crate::{error::Error, iter::Bytes};

pub use self::{
    header::{parse_header_name, parse_header_value, Header},
    start_line::{
        parse_method, parse_reason_phrase, parse_request_uri,
        parse_status_code, parse_version, RequestLine, StatusLine,
    },
};

/// Parser result type used by the SIP head parser.
///
/// A successful parse returns either:
///
/// * `Status::Partial` if more input is required
/// * `Status::Complete(T)` if a full SIP head has been parsed
type Result<T> = core::result::Result<Status<T>, Error>;

/// A parsed SIP request head.
///
/// This is a syntactic view over the request-line and header rows. It does
/// not perform semantic decoding.
pub type RequestHead<'hdr, 'buf> = MessageHead<'hdr, 'buf, RequestLine<'buf>>;

/// A parsed SIP response head.
///
/// This is a syntactic view over the status-line and header rows. It does
/// not perform semantic decoding.
pub type ResponseHead<'hdr, 'buf> = MessageHead<'hdr, 'buf, StatusLine<'buf>>;

/// Whether the input contained a complete SIP head.
///
/// A parser returns `Complete(T)` when a full SIP head has been parsed
/// successfully and `Partial` when the input ends before the head does.
/// Parsing is not resumable. After `Partial`, the caller parses again from
/// the beginning once more input has arrived.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Status<T> {
    /// Parsing completed successfully and produced `T`.
    Complete(T),
    /// More input is required to finish parsing.
    Partial,
}

/// A parsed SIP message head.
///
/// `MessageHead` is intentionally lightweight:
///
/// * The start-line is stored as a small struct of `&'buf str` fields.
/// * The header rows live in caller-provided storage that is borrowed for
///   `'hdr`.
/// * Every parsed string borrows from the input buffer that lives for
///   `'buf`. Nothing is copied or allocated.
///
/// The parser validates every string it returns before borrowing it. ASCII
/// productions (method, request URI, version, status code, header name) are
/// checked against their RFC 3261 token sets. Reason phrases and header
/// values are checked against modern UTF-8 (RFC 3629). Returning `&str`
/// therefore costs no extra validation pass.
///
/// A `MessageHead` is only produced for a complete head. Parsing is not
/// resumable, so on `Status::Partial` the caller parses again from the
/// beginning once more input has arrived.
///
/// `MessageHead` is a **syntactic parser output**. It does not:
///
/// * Normalize header names.
/// * Construct typed SIP header values.
/// * Validate higher-level SIP semantics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MessageHead<'hdr, 'buf, S> {
    /// Parsed request-line or status-line.
    pub start_line: S,

    /// Parsed header rows, in original wire order.
    pub headers: &'hdr [Header<'buf>],
}

impl<'hdr, 'buf> MessageHead<'hdr, 'buf, RequestLine<'buf>> {
    /// Parses a SIP request head from the beginning of `buf`.
    ///
    /// Header rows are written into `headers` in wire order. On
    /// `Status::Complete`, this returns the parsed head together with
    /// `head_end`, the offset in `buf` just past the empty line that
    /// terminates the head. The message body, if any, starts there.
    ///
    /// On `Status::Partial` or an error, slots in `headers` may have been
    /// overwritten with rows parsed before the parser stopped.
    ///
    /// `Status::Partial` means `buf` ends before the head does. The parser
    /// keeps no state between calls, so each retry with a longer buffer
    /// parses it again from the start. In streaming code, limit the head
    /// size and the number or duration of retries. Otherwise a head that
    /// arrives in many small reads costs time quadratic in its length.
    ///
    /// # Errors
    ///
    /// Returns an error if the head is syntactically invalid or has more
    /// header rows than `headers` can hold. [`Error::kind`] tells the two
    /// apart.
    #[inline]
    pub fn parse(
        buf: &'buf [u8],
        headers: &'hdr mut [Header<'buf>],
    ) -> Result<(RequestHead<'hdr, 'buf>, usize)> {
        parse_head(buf, as_uninit(headers), start_line::parse_request_line)
    }

    /// Parses a SIP request head into uninitialized header storage.
    ///
    /// This behaves like [`RequestHead::parse`] but lets callers skip
    /// initializing `headers` up front, which matters for large header
    /// storage.
    ///
    /// # Errors
    ///
    /// Returns an error if the head is syntactically invalid or has more
    /// header rows than `headers` can hold. [`Error::kind`] tells the two
    /// apart.
    #[inline]
    pub fn parse_uninit(
        buf: &'buf [u8],
        headers: &'hdr mut [MaybeUninit<Header<'buf>>],
    ) -> Result<(RequestHead<'hdr, 'buf>, usize)> {
        parse_head(buf, headers, start_line::parse_request_line)
    }
}

impl<'hdr, 'buf> MessageHead<'hdr, 'buf, StatusLine<'buf>> {
    /// Parses a SIP response head from the beginning of `buf`.
    ///
    /// Header rows are written into `headers` in wire order. On
    /// `Status::Complete`, this returns the parsed head together with
    /// `head_end`, the offset in `buf` just past the empty line that
    /// terminates the head. The message body, if any, starts there.
    ///
    /// On `Status::Partial` or an error, slots in `headers` may have been
    /// overwritten with rows parsed before the parser stopped.
    ///
    /// `Status::Partial` means `buf` ends before the head does. The parser
    /// keeps no state between calls, so each retry with a longer buffer
    /// parses it again from the start. In streaming code, limit the head
    /// size and the number or duration of retries. Otherwise a head that
    /// arrives in many small reads costs time quadratic in its length.
    ///
    /// # Errors
    ///
    /// Returns an error if the head is syntactically invalid or has more
    /// header rows than `headers` can hold. [`Error::kind`] tells the two
    /// apart.
    #[inline]
    pub fn parse(
        buf: &'buf [u8],
        headers: &'hdr mut [Header<'buf>],
    ) -> Result<(ResponseHead<'hdr, 'buf>, usize)> {
        parse_head(buf, as_uninit(headers), start_line::parse_status_line)
    }

    /// Parses a SIP response head into uninitialized header storage.
    ///
    /// This behaves like [`ResponseHead::parse`] but lets callers skip
    /// initializing `headers` up front, which matters for large header
    /// storage.
    ///
    /// # Errors
    ///
    /// Returns an error if the head is syntactically invalid or has more
    /// header rows than `headers` can hold. [`Error::kind`] tells the two
    /// apart.
    #[inline]
    pub fn parse_uninit(
        buf: &'buf [u8],
        headers: &'hdr mut [MaybeUninit<Header<'buf>>],
    ) -> Result<(ResponseHead<'hdr, 'buf>, usize)> {
        parse_head(buf, headers, start_line::parse_status_line)
    }
}

// The request and response entry points only differ in how they parse the
// start-line, so everything else is shared here.
#[inline]
fn parse_head<'hdr, 'buf, S>(
    buf: &'buf [u8],
    headers: &'hdr mut [MaybeUninit<Header<'buf>>],
    parse_start_line: fn(&mut Bytes<'buf>) -> Result<S>,
) -> Result<(MessageHead<'hdr, 'buf, S>, usize)> {
    let mut bytes = complete!(init_head_bytes(buf));
    let start_line = complete!(parse_start_line(&mut bytes));
    let headers = complete!(header::parse_headers(headers, &mut bytes));

    Ok(Status::Complete((MessageHead { start_line, headers }, bytes.pos())))
}

/// Views initialized header storage as uninitialized storage so that both
/// public entry points can share [`parse_head`].
///
/// This is sound only because the parser never writes an uninitialized value
/// into a slot. `header::parse_headers` only ever writes complete `Header`
/// values, so the caller's storage is still fully initialized once the
/// mutable borrow ends.
#[inline]
fn as_uninit<'hdr, 'buf>(
    headers: &'hdr mut [Header<'buf>],
) -> &'hdr mut [MaybeUninit<Header<'buf>>] {
    // SAFETY: `MaybeUninit<T>` has the same layout as `T`. See the function
    // documentation for why the slice stays initialized. `Header` is `Copy`,
    // so overwriting a slot without dropping its old value leaks nothing.
    unsafe {
        &mut *(headers as *mut [Header<'buf>]
            as *mut [MaybeUninit<Header<'buf>>])
    }
}

impl<T> Status<T> {
    /// Returns `true` if parsing requires more input.
    #[inline]
    pub fn is_partial(&self) -> bool {
        matches!(*self, Status::Partial)
    }

    /// Returns `true` if parsing completed successfully.
    #[inline]
    pub fn is_complete(&self) -> bool {
        matches!(*self, Status::Complete(..))
    }

    /// Returns the parsed value, panicking if the status is `Partial`.
    #[inline]
    pub fn unwrap(self) -> T {
        match self {
            Status::Complete(t) => t,
            Status::Partial => {
                panic!("called `Status::unwrap()` on a `Partial`")
            }
        }
    }
}

#[inline]
fn init_head_bytes(buf: &[u8]) -> Result<Bytes<'_>> {
    if buf.is_empty() {
        return Ok(Status::Partial);
    }

    // RFC 3261, Section 7.5 says:
    //
    // > Implementations processing SIP messages over stream-oriented
    // > transports MUST ignore any CRLF appearing before the start-line
    let mut bytes = Bytes::new(buf);

    while bytes.peek_n::<2>() == Some(*b"\r\n") {
        // SAFETY: `peek_n` just returned 2 bytes.
        unsafe { bytes.advance(2) };
    }

    // A lone trailing `\r` may still turn into another ignored `CRLF`.
    if bytes.is_empty() || bytes.remaining() == b"\r" {
        return Ok(Status::Partial);
    }

    Ok(Status::Complete(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorKind;

    const N_HEADERS: usize = 4;

    // Defines a test that parses `$buf` as `$head_ty`. Three forms exist:
    //
    // * `|head| body` expects a complete head that consumes all of `$buf`
    //   and runs `body` against it.
    // * `=> Partial` expects `Status::Partial`.
    // * `=> Err(Kind)` expects an error of `ErrorKind::Kind`.
    //
    // Every form accepts optional header storage after `$buf`.
    macro_rules! head_test {
        ($head_ty:ident { $name:ident, $buf:expr, => $($expect:tt)+ }) => {
            head_test! {
                $head_ty {
                    $name, $buf, [Header::EMPTY; N_HEADERS], => $($expect)+
                }
            }
        };
        ($head_ty:ident {
            $name:ident, $buf:expr, $headers:expr, => Partial
        }) => {
            #[test]
            fn $name() {
                let buf: &[u8] = $buf.as_ref();
                let mut headers = $headers;
                let status = $head_ty::parse(buf, &mut headers);
                assert_eq!(status, Ok(Status::Partial));
            }
        };
        ($head_ty:ident {
            $name:ident, $buf:expr, $headers:expr,
            => Err($kind:ident)
        }) => {
            #[test]
            fn $name() {
                let buf: &[u8] = $buf.as_ref();
                let mut headers = $headers;
                let err = $head_ty::parse(buf, &mut headers).unwrap_err();
                assert_eq!(err.kind(), ErrorKind::$kind);
            }
        };
        ($head_ty:ident {
            $name:ident, $buf:expr, |$head:ident| $body:expr
        }) => {
            head_test! {
                $head_ty {
                    $name, $buf, [Header::EMPTY; N_HEADERS], |$head| $body
                }
            }
        };
        ($head_ty:ident {
            $name:ident, $buf:expr, $headers:expr, |$head:ident| $body:expr
        }) => {
            #[test]
            fn $name() {
                let buf: &[u8] = $buf.as_ref();
                let mut headers = $headers;
                let ($head, head_end) =
                    $head_ty::parse(buf, &mut headers).unwrap().unwrap();
                assert_eq!(head_end, buf.len());

                $body
            }
        };
    }

    macro_rules! req {
        ($($input:tt)*) => { head_test! { RequestHead { $($input)* } } };
    }

    macro_rules! res {
        ($($input:tt)*) => { head_test! { ResponseHead { $($input)* } } };
    }

    // RFC 3261, Section 7.1:
    //
    // > ```
    // > Request-Line  =  Method SP Request-URI SP SIP-Version CRLF
    // > ```
    req! {
        parses_basic_request_head,
        b"INVITE sip:bob@example.com SIP/2.0\r\n\
          Via: SIP/2.0/UDP host.example.com;branch=z9hG4bK\r\n\
          Content-Length: 0\r\n\
          \r\n",
        |head| {
            assert_eq!(head.start_line.method, "INVITE");
            assert_eq!(head.start_line.uri, "sip:bob@example.com");
            assert_eq!(head.start_line.version, "SIP/2.0");

            assert_eq!(head.headers.len(), 2);
            assert_eq!(head.headers[0].name, "Via");
            assert_eq!(
                head.headers[0].value,
                "SIP/2.0/UDP host.example.com;branch=z9hG4bK"
            );
            assert_eq!(head.headers[1].name, "Content-Length");
            assert_eq!(head.headers[1].value, "0");
        }
    }

    req! {
        returns_partial_for_empty_input_request,
        b"",
        => Partial
    }

    req! {
        returns_partial_when_request_line_crlf_is_missing,
        b"INVITE sip:bob@example.com SIP/2.0",
        => Partial
    }

    // A lone `\r` may still be followed by `\n`, so it is not an error yet.
    req! {
        returns_partial_when_request_line_ends_with_cr,
        b"INVITE sip:bob@example.com SIP/2.0\r",
        => Partial
    }

    // Even with a single byte left, anything other than `\r` already rules
    // out the `CRLF` terminator. The version token then did not end where it
    // should, so this is a version error.
    req! {
        rejects_request_line_with_single_trailing_non_cr_byte,
        b"INVITE sip:bob@example.com SIP/2.0X",
        => Err(Version)
    }

    req! {
        rejects_request_line_with_cr_not_followed_by_lf,
        b"INVITE sip:bob@example.com SIP/2.0\rX",
        => Err(BareCr)
    }

    req! {
        returns_partial_when_head_terminator_is_missing,
        b"INVITE sip:bob@example.com SIP/2.0\r\n\
          Via: SIP/2.0/UDP host.example.com\r\n",
        => Partial
    }

    // A header row is only confirmed once the parser has seen the first byte
    // of the following line, since that byte decides between folding and
    // termination. The trailing `C` commits `Via` and then runs out of input
    // in the middle of the next row.
    req! {
        returns_partial_when_next_header_row_is_incomplete,
        b"INVITE sip:bob@example.com SIP/2.0\r\n\
          Via: SIP/2.0/UDP host.example.com\r\n\
          C",
        => Partial
    }

    // A lone `\r` before the start-line may still become an ignored `CRLF`.
    req! {
        returns_partial_when_leading_crlf_is_incomplete,
        b"\r\n\r",
        => Partial
    }

    // RFC 3261, Section 7.5:
    //
    // > Implementations processing SIP messages over stream-oriented
    // > transports MUST ignore any CRLF appearing before the start-line.
    req! {
        ignores_leading_crlf_before_start_line,
        b"\r\n\r\nINVITE sip:bob@example.com SIP/2.0\r\n\
          Content-Length: 0\r\n\
          \r\n",
        |head| {
            assert_eq!(head.start_line.method, "INVITE");
            assert_eq!(head.start_line.uri, "sip:bob@example.com");
            assert_eq!(head.start_line.version, "SIP/2.0");
        }
    }

    // RFC 3261, Section 7.3.1:
    //
    // > The relative order of header field rows with the same field name is
    // > important.
    req! {
        preserves_same_name_header_row_order,
        b"INVITE sip:bob@example.com SIP/2.0\r\n\
          Route: <sip:edge-1.example.com;lr>\r\n\
          Route: <sip:edge-2.example.com;lr>\r\n\
          Content-Length: 0\r\n\
          \r\n",
        |head| {
            assert_eq!(head.start_line.method, "INVITE");
            assert_eq!(head.start_line.uri, "sip:bob@example.com");
            assert_eq!(head.start_line.version, "SIP/2.0");

            assert_eq!(head.headers.len(), 3);
            assert_eq!(head.headers[0].name, "Route");
            assert_eq!(head.headers[0].value, "<sip:edge-1.example.com;lr>");
            assert_eq!(head.headers[1].name, "Route");
            assert_eq!(head.headers[1].value, "<sip:edge-2.example.com;lr>");
        }
    }

    req! {
        rejects_header_without_colon,
        b"INVITE sip:bob@example.com SIP/2.0\r\n\
          Via SIP/2.0/UDP host.example.com\r\n\
          \r\n",
        => Err(MissingColon)
    }

    req! {
        rejects_header_with_empty_name,
        b"INVITE sip:bob@example.com SIP/2.0\r\n\
          : value\r\n\
          \r\n",
        => Err(HeaderName)
    }

    req! {
        rejects_when_header_storage_is_too_small,
        b"INVITE sip:bob@example.com SIP/2.0\r\n\
          Via: SIP/2.0/UDP host.example.com\r\n\
          Content-Length: 0\r\n\
          \r\n",
        [Header::EMPTY; 1],
        => Err(TooManyHeaders)
    }

    req! {
        accepts_when_header_storage_exactly_matches_header_count,
        b"INVITE sip:bob@example.com SIP/2.0\r\n\
          name: value\r\n\
          \r\n",
        [Header::EMPTY; 1],
        |head| {
            assert_eq!(head.headers[0].name, "name");
            assert_eq!(head.headers[0].value, "value");
        }
    }

    // RFC 3261, Section 7.3.1:
    //
    // > Header fields can be extended over multiple lines by preceding each
    // > extra line with at least one SP or horizontal tab (HT).  The line
    // > break and the whitespace at the beginning of the next line are
    // > treated as a single SP character.
    req! {
        preserves_folded_header_lines_in_single_raw_value,
        b"INVITE sip:bob@example.com SIP/2.0\r\n\
          Subject: I know you're there,\r\n\x20\
          pick up the phone\r\n\
          Content-Length: 0\r\n\
          \r\n",
        |head| {
            assert_eq!(head.start_line.method, "INVITE");
            assert_eq!(head.start_line.uri, "sip:bob@example.com");
            assert_eq!(head.start_line.version, "SIP/2.0");

            assert_eq!(head.headers.len(), 2);
            assert_eq!(head.headers[0].name, "Subject");
            assert_eq!(
                head.headers[0].value,
                "I know you're there,\r\n pick up the phone"
            );
        }
    }

    // RFC 3261, Section 7.3.1 says the following are valid and equivalent:
    //
    // > ```text
    // > Subject:            lunch
    // > Subject      :      lunch
    // > Subject            :lunch
    // > Subject: lunch
    // > ```
    //
    // The parser should therefore not include the pre-colon whitespace in
    // the field-name token.
    req! {
        trims_optional_whitespace_before_colon_from_header_name,
        b"INVITE sip:bob@example.com SIP/2.0\r\n\
          Subject :lunch\r\n\
          \r\n",
        |head| {
            assert_eq!(head.start_line.method, "INVITE");
            assert_eq!(head.start_line.uri, "sip:bob@example.com");
            assert_eq!(head.start_line.version, "SIP/2.0");

            assert_eq!(head.headers.len(), 1);
            assert_eq!(head.headers[0].name, "Subject");
            assert_eq!(head.headers[0].value, "lunch");
        }
    }

    // RFC 3261, Section 7.1:
    //
    // > No linear whitespace (LWS) is allowed in any of the elements.
    req! {
        rejects_request_line_with_extra_lws_between_method_and_uri,
        b"INVITE  sip:bob@example.com SIP/2.0\r\n\
          Content-Length: 0\r\n\
          \r\n",
        => Err(RequestUri)
    }

    req! {
        rejects_request_line_with_extra_lws_between_uri_and_version,
        b"INVITE sip:bob@example.com  SIP/2.0\r\n\
          Content-Length: 0\r\n\
          \r\n",
        => Err(Version)
    }

    req! {
        accepts_request_line_with_lowercase_sip_version,
        b"INVITE sip:bob@example.com sip/2.0\r\n\
          Content-Length: 0\r\n\
          \r\n",
        |head| {
            assert_eq!(head.start_line.method, "INVITE");
            assert_eq!(head.start_line.uri, "sip:bob@example.com");
            assert_eq!(head.start_line.version, "sip/2.0");
        }
    }

    req! {
        rejects_request_line_with_unsupported_sip_version,
        b"INVITE sip:bob@example.com SIP/3.0\r\n\
          Content-Length: 0\r\n\
          \r\n",
        => Err(Version)
    }

    req! {
        rejects_request_line_with_invalid_method_token,
        b"INV@TE sip:bob@example.com SIP/2.0\r\n\
          Content-Length: 0\r\n\
          \r\n",
        => Err(Method)
    }

    req! {
        rejects_request_line_with_hash_in_method,
        b"INV#TE sip:bob@example.com SIP/2.0\r\n\
          Content-Length: 0\r\n\
          \r\n",
        => Err(Method)
    }

    req! {
        rejects_request_line_with_invalid_uri_byte,
        b"INVITE sip:bob@\x7fexample.com SIP/2.0\r\n\
          Content-Length: 0\r\n\
          \r\n",
        => Err(RequestUri)
    }

    req! {
        rejects_request_line_with_caret_in_uri,
        b"INVITE sip:bob^carol@example.com SIP/2.0\r\n\
          Content-Length: 0\r\n\
          \r\n",
        => Err(RequestUri)
    }

    req! {
        rejects_request_line_with_non_ascii_uri_byte,
        b"INVITE sip:bob\xc3\xa9@example.com SIP/2.0\r\n\
          Content-Length: 0\r\n\
          \r\n",
        => Err(RequestUri)
    }

    // RFC 3261 allows IPv6 literals in the host component via
    // `IPv6reference = "[" IPv6address "]"`.
    req! {
        accepts_request_line_with_ipv6_literal_uri,
        b"INVITE sip:bob@[2001:db8::1] SIP/2.0\r\n\
          Content-Length: 0\r\n\
          \r\n",
        |head| {
            assert_eq!(head.start_line.method, "INVITE");
            assert_eq!(head.start_line.uri, "sip:bob@[2001:db8::1]");
            assert_eq!(head.start_line.version, "SIP/2.0");
        }
    }

    req! {
        rejects_header_name_with_invalid_token_byte,
        b"INVITE sip:bob@example.com SIP/2.0\r\n\
          Su[b]ject: lunch\r\n\
          \r\n",
        => Err(HeaderName)
    }

    req! {
        rejects_header_name_with_caret,
        b"INVITE sip:bob@example.com SIP/2.0\r\n\
          Sub^ject: lunch\r\n\
          \r\n",
        => Err(HeaderName)
    }

    req! {
        rejects_header_value_with_invalid_control_byte,
        b"INVITE sip:bob@example.com SIP/2.0\r\n\
          Subject: lun\x7fch\r\n\
          \r\n",
        => Err(HeaderValue)
    }

    // RFC 3261, Section 25.1, with `WSP` from RFC 2234:
    //
    // > ```
    // > header-value  =  *(TEXT-UTF8char / UTF8-CONT / LWS)
    // > LWS           =  [*WSP CRLF] 1*WSP ; linear whitespace
    // > WSP           =  SP / HTAB
    // > ```
    //
    // The `TAB` and the byte after it sit in the same SWAR block. Its lane
    // must not change how the next byte is classified.
    req! {
        accepts_header_value_with_htab_followed_by_sp,
        b"INVITE sip:bob@example.com SIP/2.0\r\n\
          Subject: hi\t there\r\n\
          \r\n",
        |head| {
            assert_eq!(head.headers[0].name, "Subject");
            assert_eq!(head.headers[0].value, "hi\t there");
        }
    }

    req! {
        rejects_header_value_with_htab_followed_by_control_byte,
        b"INVITE sip:bob@example.com SIP/2.0\r\n\
          Subject: hi\t\x08there\r\n\
          \r\n",
        => Err(HeaderValue)
    }

    req! {
        rejects_header_value_with_0xfe,
        b"INVITE sip:bob@example.com SIP/2.0\r\n\
          Subject: lun\xfech\r\n\
          \r\n",
        => Err(HeaderValue)
    }

    req! {
        rejects_header_value_with_0xff,
        b"INVITE sip:bob@example.com SIP/2.0\r\n\
          Subject: lun\xffch\r\n\
          \r\n",
        => Err(HeaderValue)
    }

    req! {
        rejects_header_value_with_bare_utf8_continuation_byte,
        b"INVITE sip:bob@example.com SIP/2.0\r\n\
          Subject: \x80\r\n\
          \r\n",
        => Err(HeaderValue)
    }

    req! {
        rejects_header_value_with_overlong_utf8_sequence,
        b"INVITE sip:bob@example.com SIP/2.0\r\n\
          Subject: \xC0\x80\r\n\
          \r\n",
        => Err(HeaderValue)
    }

    req! {
        rejects_header_value_with_five_byte_utf8_sequence,
        b"INVITE sip:bob@example.com SIP/2.0\r\n\
          Subject: \xF8\x88\x80\x80\x80\r\n\
          \r\n",
        => Err(HeaderValue)
    }

    req! {
        accepts_header_value_with_modern_utf8_sequence,
        b"INVITE sip:bob@example.com SIP/2.0\r\n\
          Subject: \xF0\x9F\x98\x80\r\n\
          \r\n",
        |head| {
            assert_eq!(head.start_line.method, "INVITE");
            assert_eq!(head.start_line.uri, "sip:bob@example.com");
            assert_eq!(head.start_line.version, "SIP/2.0");
            assert_eq!(head.headers[0].name, "Subject");
            assert_eq!(head.headers[0].value, "\u{1f600}");
        }
    }

    #[test]
    fn request_head_end_points_immediately_after_crlfcrlf() {
        let buf = b"\
            INVITE sip:bob@example.com SIP/2.0\r\n\
            Content-Length: 3\r\n\
            \r\n\
            foo";
        let mut headers = [Header::EMPTY; N_HEADERS];

        let (head, head_end) =
            RequestHead::parse(buf, &mut headers).unwrap().unwrap();

        assert_eq!(head.start_line.method, "INVITE");
        assert_eq!(&buf[head_end..], b"foo");
    }

    // RFC 3261, Section 7.2:
    //
    // > ```
    // > Status-Line  =  SIP-Version SP Status-Code SP Reason-Phrase CRLF
    // > ```
    res! {
        returns_partial_for_empty_input_response,
        b"",
        => Partial
    }

    res! {
        parses_basic_response_head,
        b"SIP/2.0 200 OK\r\n\
          Via: SIP/2.0/UDP host.example.com;branch=z9hG4bK\r\n\
          Content-Length: 0\r\n\
          \r\n",
        |head| {
            assert_eq!(head.start_line.version, "SIP/2.0");
            assert_eq!(head.start_line.status_code, "200");
            assert_eq!(head.start_line.reason_phrase, "OK");

            assert_eq!(head.headers.len(), 2);
            assert_eq!(head.headers[0].name, "Via");
            assert_eq!(
                head.headers[0].value,
                "SIP/2.0/UDP host.example.com;branch=z9hG4bK"
            );
            assert_eq!(head.headers[1].name, "Content-Length");
            assert_eq!(head.headers[1].value, "0");
        }
    }

    res! {
        rejects_status_line_with_one_digit_status_code,
        b"SIP/2.0 2 OK\r\n\
          Content-Length: 0\r\n\
          \r\n",
        => Err(StatusCode)
    }

    res! {
        rejects_status_line_with_two_digit_status_code,
        b"SIP/2.0 20 OK\r\n\
          Content-Length: 0\r\n\
          \r\n",
        => Err(StatusCode)
    }

    res! {
        rejects_status_line_with_four_digit_status_code,
        b"SIP/2.0 2000 OK\r\n\
          Content-Length: 0\r\n\
          \r\n",
        => Err(StatusCode)
    }

    // RFC 3261, Section 25.1:
    //
    // > ```
    // > Reason-Phrase   =  *(reserved / unreserved / escaped
    // >                    / UTF8-NONASCII / UTF8-CONT / SP / HTAB)
    // > ```
    //
    // So an empty reason phrase is syntactically allowed after the `SP`.
    res! {
        accepts_empty_reason_phrase,
        b"SIP/2.0 200 \r\n\
          Content-Length: 0\r\n\
          \r\n",
        |head| {
            assert_eq!(head.start_line.version, "SIP/2.0");
            assert_eq!(head.start_line.status_code, "200");
            assert_eq!(head.start_line.reason_phrase, "");
        }
    }

    res! {
        rejects_status_line_with_bare_lf_in_reason_phrase,
        b"SIP/2.0 200 O\nK\r\n\
          Content-Length: 0\r\n\
          \r\n",
        => Err(BareLf)
    }

    res! {
        rejects_status_line_with_nul_in_reason_phrase,
        b"SIP/2.0 200 O\x00K\r\n\
          Content-Length: 0\r\n\
          \r\n",
        => Err(ReasonPhrase)
    }

    // `Reason-Phrase` allows `SP` and `HTAB` in any order. The `TAB` and the
    // byte after it sit in the same SWAR block.
    res! {
        accepts_status_line_with_htab_followed_by_sp_in_reason_phrase,
        b"SIP/2.0 404 Not\t Found\r\n\
          Content-Length: 0\r\n\
          \r\n",
        |head| {
            assert_eq!(head.start_line.reason_phrase, "Not\t Found");
        }
    }

    res! {
        rejects_status_line_with_htab_followed_by_control_byte,
        b"SIP/2.0 404 Not\t\x08Found\r\n\
          Content-Length: 0\r\n\
          \r\n",
        => Err(ReasonPhrase)
    }

    res! {
        rejects_status_line_with_bare_percent_in_reason_phrase,
        b"SIP/2.0 200 100%\r\n\
          Content-Length: 0\r\n\
          \r\n",
        => Err(ReasonPhrase)
    }

    res! {
        accepts_status_line_with_escaped_reason_phrase_octet,
        b"SIP/2.0 200 100%20Trying\r\n\
          Content-Length: 0\r\n\
          \r\n",
        |head| {
            assert_eq!(head.start_line.version, "SIP/2.0");
            assert_eq!(head.start_line.status_code, "200");
            assert_eq!(head.start_line.reason_phrase, "100%20Trying");
        }
    }

    res! {
        rejects_status_line_with_bare_utf8_continuation_byte,
        b"SIP/2.0 200 \x80\r\n\
          Content-Length: 0\r\n\
          \r\n",
        => Err(ReasonPhrase)
    }

    res! {
        rejects_status_line_with_overlong_utf8_sequence,
        b"SIP/2.0 200 \xC0\x80\r\n\
          Content-Length: 0\r\n\
          \r\n",
        => Err(ReasonPhrase)
    }

    res! {
        rejects_status_line_with_five_byte_utf8_sequence,
        b"SIP/2.0 200 \xF8\x88\x80\x80\x80\r\n\
          Content-Length: 0\r\n\
          \r\n",
        => Err(ReasonPhrase)
    }

    res! {
        accepts_status_line_with_modern_utf8_reason_phrase,
        b"SIP/2.0 200 \xF0\x9F\x98\x80\r\n\
          Content-Length: 0\r\n\
          \r\n",
        |head| {
            assert_eq!(head.start_line.version, "SIP/2.0");
            assert_eq!(head.start_line.status_code, "200");
            assert_eq!(head.start_line.reason_phrase, "\u{1f600}");
        }
    }

    #[test]
    fn parse_uninit_parses_request_head() {
        let buf = b"INVITE sip:bob@example.com SIP/2.0\r\n\
                    Via: SIP/2.0/UDP host.example.com\r\n\
                    Content-Length: 0\r\n\
                    \r\n";
        let mut headers = [MaybeUninit::<Header>::uninit(); N_HEADERS];

        let (head, head_end) =
            RequestHead::parse_uninit(buf, &mut headers).unwrap().unwrap();

        assert_eq!(head_end, buf.len());
        assert_eq!(head.start_line.method, "INVITE");
        assert_eq!(head.headers.len(), 2);
        assert_eq!(head.headers[0].name, "Via");
        assert_eq!(head.headers[1].value, "0");
    }

    #[test]
    fn parse_uninit_parses_response_head() {
        let buf = b"SIP/2.0 180 Ringing\r\n\
                    Content-Length: 0\r\n\
                    \r\n";
        let mut headers = [MaybeUninit::<Header>::uninit(); N_HEADERS];

        let (head, head_end) =
            ResponseHead::parse_uninit(buf, &mut headers).unwrap().unwrap();

        assert_eq!(head_end, buf.len());
        assert_eq!(head.start_line.status_code, "180");
        assert_eq!(head.start_line.reason_phrase, "Ringing");
        assert_eq!(head.headers.len(), 1);
    }

    #[test]
    fn parse_uninit_rejects_when_header_storage_is_too_small() {
        let buf = b"INVITE sip:bob@example.com SIP/2.0\r\n\
                    Via: SIP/2.0/UDP host.example.com\r\n\
                    Content-Length: 0\r\n\
                    \r\n";
        let mut headers = [MaybeUninit::<Header>::uninit(); 1];

        let err = RequestHead::parse_uninit(buf, &mut headers).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::TooManyHeaders);
    }

    // Storage is only borrowed for the duration of the call, so the same
    // array can be reused for the next message without re-initializing it.
    #[test]
    fn header_storage_is_reusable_across_parses() {
        let partial = b"INVITE sip:bob@example.com SIP/2.0\r\n\
                        Via: SIP/2.0/UDP host.example.com\r\n";
        let complete = b"BYE sip:bob@example.com SIP/2.0\r\n\
                         Content-Length: 0\r\n\
                         \r\n";
        let mut headers = [Header::EMPTY; N_HEADERS];

        let status = RequestHead::parse(partial, &mut headers);
        assert_eq!(status, Ok(Status::Partial));

        let (head, _) =
            RequestHead::parse(complete, &mut headers).unwrap().unwrap();
        assert_eq!(head.start_line.method, "BYE");
        assert_eq!(head.headers.len(), 1);
        assert_eq!(head.headers[0].name, "Content-Length");
    }

    // Parsed strings borrow from the input rather than copying it, so their
    // addresses must fall inside `buf`.
    #[test]
    fn parsed_strings_borrow_from_input() {
        let buf = b"INVITE sip:bob@example.com SIP/2.0\r\n\
                    Subject: lunch\r\n\
                    \r\n";
        let mut headers = [Header::EMPTY; N_HEADERS];

        let (head, _) =
            RequestHead::parse(buf, &mut headers).unwrap().unwrap();

        let buf_range = buf.as_ptr_range();
        let tokens = [
            head.start_line.method,
            head.start_line.uri,
            head.start_line.version,
            head.headers[0].name,
            head.headers[0].value,
        ];
        for token in tokens {
            let token_range = token.as_bytes().as_ptr_range();
            assert!(buf_range.start <= token_range.start);
            assert!(token_range.end <= buf_range.end);
        }
    }

    // Malformed input at rejection sites that the grammar-oriented tests
    // above do not reach.

    req! {
        rejects_request_line_with_empty_method,
        b" sip:bob@example.com SIP/2.0\r\n\
          \r\n",
        => Err(Method)
    }

    res! {
        rejects_status_line_with_trailing_byte_after_version,
        b"SIP/2.0X 200 OK\r\n\
          \r\n",
        => Err(Version)
    }

    res! {
        rejects_status_line_with_malformed_percent_escape,
        b"SIP/2.0 200 100%4G\r\n\
          \r\n",
        => Err(ReasonPhrase)
    }

    req! {
        rejects_header_value_with_truncated_utf8_sequence,
        b"INVITE sip:bob@example.com SIP/2.0\r\n\
          Subject: \xE3\x81A\r\n\
          \r\n",
        => Err(HeaderValue)
    }

    req! {
        rejects_header_value_with_cr_not_followed_by_lf,
        b"INVITE sip:bob@example.com SIP/2.0\r\n\
          Subject: lunch\rX\r\n\
          \r\n",
        => Err(BareCr)
    }

    req! {
        rejects_header_row_starting_with_bare_lf,
        b"INVITE sip:bob@example.com SIP/2.0\r\n\
          \nSubject: lunch\r\n\
          \r\n",
        => Err(BareLf)
    }

    req! {
        rejects_head_terminator_with_cr_not_followed_by_lf,
        b"INVITE sip:bob@example.com SIP/2.0\r\n\
          Subject: lunch\r\n\
          \rX",
        => Err(BareCr)
    }

    // Line structure errors are reported by cause, whichever line they
    // occur on. A sender that terminates lines with `LF` alone therefore
    // gets `BareLf` for both requests and responses.

    req! {
        rejects_request_line_terminated_by_bare_lf,
        b"INVITE sip:bob@example.com SIP/2.0\n\
          Content-Length: 0\n\
          \n",
        => Err(BareLf)
    }

    res! {
        rejects_status_line_terminated_by_bare_lf,
        b"SIP/2.0 200 OK\n\
          Content-Length: 0\n\
          \n",
        => Err(BareLf)
    }

    res! {
        rejects_status_line_with_cr_not_followed_by_lf,
        b"SIP/2.0 200 OK\rX\r\n\
          \r\n",
        => Err(BareCr)
    }

    req! {
        rejects_header_row_terminated_by_bare_lf,
        b"INVITE sip:bob@example.com SIP/2.0\r\n\
          Subject: lunch\n\
          Content-Length: 0\r\n\
          \r\n",
        => Err(BareLf)
    }

    // A line that ends before its last element is reported as the element
    // that was cut short, not as a line ending error.
    res! {
        rejects_status_line_ending_after_status_code,
        b"SIP/2.0 200\n\
          \n",
        => Err(StatusCode)
    }

    req! {
        rejects_header_name_followed_by_line_end,
        b"INVITE sip:bob@example.com SIP/2.0\r\n\
          Subject\r\n\
          \r\n",
        => Err(MissingColon)
    }

    req! {
        rejects_header_name_containing_whitespace,
        b"INVITE sip:bob@example.com SIP/2.0\r\n\
          Call ID: a84b4c76e66710\r\n\
          \r\n",
        => Err(MissingColon)
    }

    #[test]
    fn error_display_describes_kind() {
        let buf = b"INV@TE sip:bob@example.com SIP/2.0\r\n\r\n";
        let mut headers = [Header::EMPTY; N_HEADERS];

        let err = RequestHead::parse(buf, &mut headers).unwrap_err();

        assert_eq!(
            std::string::ToString::to_string(&err),
            "invalid SIP method",
        );
    }
}

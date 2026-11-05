/*!
SIP head parser.
*/

mod head_end;
mod header;
mod keepalive;
mod start_line;

use crate::{error::Error, iter::Bytes};

pub(crate) use self::{
    header::{header_name, header_value},
    start_line::{method, reason_phrase, request_uri},
};

pub use self::{
    head_end::find_head_end,
    header::{
        parse_header_name, parse_header_value, Header, HeaderBuf, Headers,
        ValueLines,
    },
    keepalive::{parse_ping, parse_pong},
    start_line::{
        parse_method, parse_reason_phrase, parse_request_uri,
        parse_status_code, parse_version, RequestLine, StartLine, StatusLine,
    },
};

/// Where a token that a production parses ends.
///
/// Inside a head, a token ends at the delimiter after it, such as the `SP`
/// after a method or the `CRLF` after a header value, and running out of
/// input means more may arrive. The checks in [`crate::check`] get just the
/// token, so the end of the input ends it and a delimiter in it is an error.
///
/// The productions are generic over this so that the head parser and the
/// checks share one implementation. Each production is monomorphized per
/// boundary, so the branches on `WHOLE` cost nothing at run time. Only this
/// crate implements it.
pub(crate) trait Boundary {
    /// `true` if the input is exactly one token.
    const WHOLE: bool;
}

/// A token inside a head, ended by its delimiter.
pub(crate) enum Delimited {}

/// A token that is the whole input.
pub(crate) enum Whole {}

impl Boundary for Delimited {
    const WHOLE: bool = false;
}

impl Boundary for Whole {
    const WHOLE: bool = true;
}

/// Parser result type used by the SIP head parser.
///
/// A successful parse returns either:
///
/// * `Status::Partial` if more input is required
/// * `Status::Complete(T)` if a full SIP head has been parsed
pub(crate) type Result<T> = core::result::Result<Status<T>, Error>;

/// Whether the input contained a complete SIP head.
///
/// A parser returns `Complete(T)` when a full SIP head has been parsed
/// successfully and `Partial` when the input ends before the head does.
/// Parsing is not resumable. After `Partial`, the head holds what was parsed
/// so far, and the caller parses again from the beginning once more input has
/// arrived.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Status<T> {
    /// Parsing completed successfully and produced `T`.
    Complete(T),
    /// More input is required to finish parsing.
    Partial,
}

/// A SIP message head that the parser fills in place.
///
/// * The start-line is a small struct of `Option<&'buf str>` fields, or for
///   [`AnyHead`] an `Option` of either struct.
/// * The header rows live in caller-provided [`Headers`] storage that is
///   borrowed for `'hdr`.
/// * Every parsed string borrows from the input buffer that lives for
///   `'buf`. Nothing is copied or allocated.
///
/// The parser validates every string before it stores it. ASCII productions
/// (method, request URI, version, status code, header name) are checked
/// against their RFC 3261 token sets. Reason phrases and header values are
/// checked against modern UTF-8 (RFC 3629). Storing `&str` therefore costs
/// no extra validation pass.
///
/// Fields are filled in wire order. After `Status::Partial` or an error,
/// the start-line fields and header rows parsed before the parser stopped
/// remain readable.
///
/// `MessageHead` is a **syntactic parser output**. It does not:
///
/// * Normalize header names.
/// * Construct typed SIP header values.
/// * Validate higher-level SIP semantics.
#[derive(Debug)]
pub struct MessageHead<'hdr, 'buf, S> {
    /// Parsed request-line or status-line fields.
    pub start_line: S,
    /// Parsed header rows, in original wire order.
    pub headers: &'hdr mut Headers<'buf>,
}

/// A SIP request head that the parser fills in place.
///
/// This is a syntactic view over the request-line and header rows. It does
/// not perform semantic decoding.
pub type RequestHead<'hdr, 'buf> = MessageHead<'hdr, 'buf, RequestLine<'buf>>;

/// A SIP response head that the parser fills in place.
///
/// This is a syntactic view over the status-line and header rows. It does
/// not perform semantic decoding.
pub type ResponseHead<'hdr, 'buf> = MessageHead<'hdr, 'buf, StatusLine<'buf>>;

/// A SIP request or response head that the parser fills in place.
///
/// Use this when the kind of head is not known before parsing, for example on
/// a socket that receives both requests and responses. The start-line is
/// `None` until the parser has seen enough bytes to tell the two apart, and
/// is always `Some` after [`Status::Complete`].
///
/// # Example
///
/// ```
/// use siparse::{AnyHead, HeaderBuf, StartLine, Status};
///
/// let buf = b"SIP/2.0 180 Ringing\r\n\
///             Content-Length: 0\r\n\
///             \r\n";
///
/// let mut headers = HeaderBuf::<16>::new();
/// let mut head = AnyHead::new(&mut headers);
/// assert_eq!(head.parse(buf)?, Status::Complete(buf.len()));
///
/// let Some(StartLine::Status(line)) = head.start_line else {
///     panic!("expected a status-line");
/// };
/// assert_eq!(line.code(), Some(180));
/// # Ok::<(), siparse::Error>(())
/// ```
pub type AnyHead<'hdr, 'buf> =
    MessageHead<'hdr, 'buf, Option<StartLine<'buf>>>;

impl<'hdr, 'buf, S: Default> MessageHead<'hdr, 'buf, S> {
    /// Creates an empty head that stores header rows in `headers`.
    #[inline]
    pub fn new(
        headers: &'hdr mut Headers<'buf>,
    ) -> MessageHead<'hdr, 'buf, S> {
        MessageHead { start_line: S::default(), headers }
    }
}

// Parsing takes no options for now. A configurable parser type can be
// added once an option is actually needed.
impl<'hdr, 'buf> RequestHead<'hdr, 'buf> {
    /// Parses a SIP request head from the beginning of `buf` into this head.
    ///
    /// Header rows are written into `self.headers` in wire order. On
    /// [`Status::Complete`], this returns `head_end`, the offset in `buf` just
    /// past the empty line that terminates the head. The message body, if any,
    /// starts there.
    ///
    /// The head is reset first, so after `Status::Partial` or an error it
    /// holds exactly what this call parsed before stopping.
    ///
    /// `Status::Partial` means `buf` ends before the head does. The parser
    /// keeps no state between calls, so each retry with a longer buffer parses
    /// it again from the start. In streaming code, limit the head size and the
    /// number or duration of retries. Otherwise a head that arrives in many
    /// small reads costs time quadratic in its length.
    ///
    /// # Errors
    ///
    /// Returns an error if the head is syntactically invalid or has more
    /// header rows than `self.headers` can hold. [`Error::kind`] tells the
    /// two apart.
    pub fn parse(&mut self, buf: &'buf [u8]) -> Result<usize> {
        parse_head(self, buf, start_line::parse_request_line)
    }
}

impl<'hdr, 'buf> ResponseHead<'hdr, 'buf> {
    /// Parses a SIP response head from the beginning of `buf` into this
    /// head.
    ///
    /// Header rows are written into `self.headers` in wire order. On
    /// [`Status::Complete`], this returns `head_end`, the offset in `buf` just
    /// past the empty line that terminates the head. The message body, if any,
    /// starts there.
    ///
    /// The head is reset first, so after `Status::Partial` or an error it
    /// holds exactly what this call parsed before stopping.
    ///
    /// `Status::Partial` means `buf` ends before the head does. The parser
    /// keeps no state between calls, so each retry with a longer buffer parses
    /// it again from the start. In streaming code, limit the head size and the
    /// number or duration of retries. Otherwise a head that arrives in many
    /// small reads costs time quadratic in its length.
    ///
    /// # Errors
    ///
    /// Returns an error if the head is syntactically invalid or has more
    /// header rows than `self.headers` can hold. [`Error::kind`] tells the two
    /// apart.
    pub fn parse(&mut self, buf: &'buf [u8]) -> Result<usize> {
        parse_head(self, buf, start_line::parse_status_line)
    }
}

impl<'hdr, 'buf> AnyHead<'hdr, 'buf> {
    /// Parses a SIP request or response head from the beginning of `buf` into
    /// this head.
    ///
    /// This behaves like [`RequestHead::parse`] or [`ResponseHead::parse`],
    /// whichever matches the start-line. A start-line that begins with `SIP/`,
    /// compared case-insensitively, is parsed as a status-line. Anything else
    /// is parsed as a request-line, because a method token cannot contain
    /// `/`.
    ///
    /// # Errors
    ///
    /// Returns the same errors as the parser for the chosen kind of head. For
    /// example, `SIP/3.0 200 OK` is a [`Version`](crate::ErrorKind::Version)
    /// error, not a [`Method`](crate::ErrorKind::Method) error.
    pub fn parse(&mut self, buf: &'buf [u8]) -> Result<usize> {
        parse_head(self, buf, start_line::parse_start_line)
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

// The request and response entry points only differ in how they parse the
// start-line, so everything else is shared here.
#[inline]
fn parse_head<'buf, S: Default>(
    head: &mut MessageHead<'_, 'buf, S>,
    buf: &'buf [u8],
    parse_start_line: fn(&mut Bytes<'buf>, &mut S) -> Result<()>,
) -> Result<usize> {
    head.start_line = S::default();
    head.headers.clear();

    let mut bytes = complete!(init_head_bytes(buf));
    complete!(parse_start_line(&mut bytes, &mut head.start_line));
    complete!(header::parse_headers(head.headers, &mut bytes));

    Ok(Status::Complete(bytes.pos()))
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

    // Defines a test that parses `$buf` with `$head_ty::parse`. Three forms
    // exist:
    //
    // * `|head| body` expects a complete head that consumes all of `$buf`
    //   and runs `body` against it.
    // * `=> Partial` expects `Status::Partial`.
    // * `=> Err(Kind)` expects an error of `ErrorKind::Kind`.
    //
    // Every form accepts optional header storage after `$buf`.
    macro_rules! head_test {
        ($head_ty:ident {
            $name:ident, $buf:expr, => $($expect:tt)+
        }) => {
            head_test! {
                $head_ty {
                    $name, $buf, HeaderBuf::<N_HEADERS>::new(),
                    => $($expect)+
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
                let mut head = $head_ty::new(&mut headers);
                let status = head.parse(buf);
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
                let mut head = $head_ty::new(&mut headers);
                let err = head.parse(buf).unwrap_err();
                assert_eq!(err.kind(), ErrorKind::$kind);
            }
        };
        ($head_ty:ident {
            $name:ident, $buf:expr, |$head:ident| $body:expr
        }) => {
            head_test! {
                $head_ty {
                    $name, $buf, HeaderBuf::<N_HEADERS>::new(),
                    |$head| $body
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
                let mut $head = $head_ty::new(&mut headers);
                let head_end = $head.parse(buf).unwrap().unwrap();
                assert_eq!(head_end, buf.len());

                $body
            }
        };
    }

    macro_rules! req {
        ($($input:tt)*) => {
            head_test! { RequestHead { $($input)* } }
        };
    }

    macro_rules! res {
        ($($input:tt)*) => {
            head_test! { ResponseHead { $($input)* } }
        };
    }

    macro_rules! any {
        ($($input:tt)*) => {
            head_test! { AnyHead { $($input)* } }
        };
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
            assert_eq!(head.start_line.method, Some("INVITE"));
            assert_eq!(head.start_line.uri, Some("sip:bob@example.com"));
            assert_eq!(head.start_line.version, Some("SIP/2.0"));

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
            assert_eq!(head.start_line.method, Some("INVITE"));
            assert_eq!(head.start_line.uri, Some("sip:bob@example.com"));
            assert_eq!(head.start_line.version, Some("SIP/2.0"));
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
            assert_eq!(head.start_line.method, Some("INVITE"));
            assert_eq!(head.start_line.uri, Some("sip:bob@example.com"));
            assert_eq!(head.start_line.version, Some("SIP/2.0"));

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
        HeaderBuf::<1>::new(),
        => Err(TooManyHeaders)
    }

    req! {
        accepts_when_header_storage_exactly_matches_header_count,
        b"INVITE sip:bob@example.com SIP/2.0\r\n\
          name: value\r\n\
          \r\n",
        HeaderBuf::<1>::new(),
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
            assert_eq!(head.start_line.method, Some("INVITE"));
            assert_eq!(head.start_line.uri, Some("sip:bob@example.com"));
            assert_eq!(head.start_line.version, Some("SIP/2.0"));

            assert_eq!(head.headers.len(), 2);
            assert_eq!(head.headers[0].name, "Subject");
            assert_eq!(
                head.headers[0].value,
                "I know you're there,\r\n pick up the phone"
            );
        }
    }

    // RFC 3261, Section 25.1:
    //
    // > ```text
    // > HCOLON  =  *( SP / HTAB ) ":" SWS
    // > SWS     =  [LWS] ; sep whitespace
    // > ```
    //
    // Leading LWS, including a fold, is part of the separator. Trailing LWS
    // stays, because only the header's own grammar can say whether it matters.
    #[test]
    fn strips_leading_but_keeps_trailing_linear_whitespace() {
        for (row, expected) in [
            (&b"Subject:\r\n lunch"[..], "lunch"),
            (b"Subject: \t\r\n \r\n\t lunch", "lunch"),
            (b"Subject:\r\n lunch\r\n soon", "lunch\r\n soon"),
            (b"Subject:\r\n \r\n\t", ""),
            (b"Subject: lunch \t", "lunch \t"),
            (b"Subject: lunch\r\n \t", "lunch\r\n \t"),
        ] {
            let mut buf = std::vec::Vec::from(
                &b"OPTIONS sip:carol@example.com SIP/2.0\r\n"[..],
            );
            buf.extend_from_slice(row);
            buf.extend_from_slice(b"\r\nMax-Forwards: 70\r\n\r\n");

            let mut headers = HeaderBuf::<N_HEADERS>::new();
            let mut head = RequestHead::new(&mut headers);
            let head_end = head.parse(&buf).unwrap().unwrap();

            assert_eq!(head_end, buf.len());
            assert_eq!(head.headers[0].value, expected, "row={row:?}");
            assert_eq!(head.headers[1].value, "70");
        }
    }

    // The byte after the `CRLF` decides between a leading fold and an empty
    // value, so the parser has to wait for it.
    req! {
        returns_partial_when_crlf_after_colon_is_last,
        b"OPTIONS sip:carol@example.com SIP/2.0\r\n\
          Subject:\r\n",
        => Partial
    }

    req! {
        returns_partial_when_leading_fold_is_last,
        b"OPTIONS sip:carol@example.com SIP/2.0\r\n\
          Subject:\r\n ",
        => Partial
    }

    req! {
        returns_partial_when_cr_after_colon_is_last,
        b"OPTIONS sip:carol@example.com SIP/2.0\r\n\
          Subject:\r",
        => Partial
    }

    req! {
        rejects_bare_cr_after_colon,
        b"OPTIONS sip:carol@example.com SIP/2.0\r\n\
          Subject:\r lunch\r\n\
          \r\n",
        => Err(BareCr)
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
    // The parser should therefore not include the pre-colon whitespace in the
    // field-name token.
    req! {
        trims_optional_whitespace_before_colon_from_header_name,
        b"INVITE sip:bob@example.com SIP/2.0\r\n\
          Subject :lunch\r\n\
          \r\n",
        |head| {
            assert_eq!(head.start_line.method, Some("INVITE"));
            assert_eq!(head.start_line.uri, Some("sip:bob@example.com"));
            assert_eq!(head.start_line.version, Some("SIP/2.0"));

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
            assert_eq!(head.start_line.method, Some("INVITE"));
            assert_eq!(head.start_line.uri, Some("sip:bob@example.com"));
            assert_eq!(head.start_line.version, Some("sip/2.0"));
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
            assert_eq!(head.start_line.method, Some("INVITE"));
            assert_eq!(head.start_line.uri, Some("sip:bob@[2001:db8::1]"));
            assert_eq!(head.start_line.version, Some("SIP/2.0"));
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
            assert_eq!(head.start_line.method, Some("INVITE"));
            assert_eq!(head.start_line.uri, Some("sip:bob@example.com"));
            assert_eq!(head.start_line.version, Some("SIP/2.0"));
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
        let mut headers = HeaderBuf::<N_HEADERS>::new();
        let mut head = RequestHead::new(&mut headers);

        let head_end = head.parse(buf).unwrap().unwrap();

        assert_eq!(head.start_line.method, Some("INVITE"));
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
            assert_eq!(head.start_line.version, Some("SIP/2.0"));
            assert_eq!(head.start_line.status_code, Some("200"));
            assert_eq!(head.start_line.code(), Some(200));
            assert_eq!(head.start_line.reason_phrase, Some("OK"));

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
            assert_eq!(head.start_line.version, Some("SIP/2.0"));
            assert_eq!(head.start_line.status_code, Some("200"));
            assert_eq!(head.start_line.reason_phrase, Some(""));
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
            assert_eq!(head.start_line.reason_phrase, Some("Not\t Found"));
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
            assert_eq!(head.start_line.version, Some("SIP/2.0"));
            assert_eq!(head.start_line.status_code, Some("200"));
            assert_eq!(head.start_line.reason_phrase, Some("100%20Trying"));
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
            assert_eq!(head.start_line.version, Some("SIP/2.0"));
            assert_eq!(head.start_line.status_code, Some("200"));
            assert_eq!(head.start_line.reason_phrase, Some("\u{1f600}"));
        }
    }

    // `HeaderBuf::new` leaves every slot uninitialized, so these exercise
    // the parser writing into storage that was never initialized.
    #[test]
    fn uninit_storage_parses_request_head() {
        let buf = b"INVITE sip:bob@example.com SIP/2.0\r\n\
                    Via: SIP/2.0/UDP host.example.com\r\n\
                    Content-Length: 0\r\n\
                    \r\n";
        let mut headers = HeaderBuf::<N_HEADERS>::new();
        let mut head = RequestHead::new(&mut headers);

        let head_end = head.parse(buf).unwrap().unwrap();

        assert_eq!(head_end, buf.len());
        assert_eq!(head.start_line.method, Some("INVITE"));
        assert_eq!(head.headers.len(), 2);
        assert_eq!(head.headers[0].name, "Via");
        assert_eq!(head.headers[1].value, "0");
    }

    #[test]
    fn uninit_storage_parses_response_head() {
        let buf = b"SIP/2.0 180 Ringing\r\n\
                    Content-Length: 0\r\n\
                    \r\n";
        let mut headers = HeaderBuf::<N_HEADERS>::new();
        let mut head = ResponseHead::new(&mut headers);

        let head_end = head.parse(buf).unwrap().unwrap();

        assert_eq!(head_end, buf.len());
        assert_eq!(head.start_line.status_code, Some("180"));
        assert_eq!(head.start_line.reason_phrase, Some("Ringing"));
        assert_eq!(head.headers.len(), 1);
    }

    // The rows that fit stay readable after the error.
    #[test]
    fn uninit_storage_rejects_when_header_storage_is_too_small() {
        let buf = b"INVITE sip:bob@example.com SIP/2.0\r\n\
                    Via: SIP/2.0/UDP host.example.com\r\n\
                    Content-Length: 0\r\n\
                    \r\n";
        let mut headers = HeaderBuf::<1>::new();
        let mut head = RequestHead::new(&mut headers);

        let err = head.parse(buf).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::TooManyHeaders);
        assert_eq!(head.headers.len(), 1);
        assert_eq!(head.headers[0].name, "Via");
    }

    // Every parse resets the head first, so the same head can be reused for
    // the next message, and a `Partial` leaves nothing from earlier calls.
    #[test]
    fn header_storage_is_reusable_across_parses() {
        let partial = b"INVITE sip:bob@example.com SIP/2.0\r\n\
                        Via: SIP/2.0/UDP host.example.com\r\n";
        let complete = b"BYE sip:bob@example.com SIP/2.0\r\n\
                         Content-Length: 0\r\n\
                         \r\n";
        let mut headers = HeaderBuf::<N_HEADERS>::new();
        let mut head = RequestHead::new(&mut headers);

        let status = head.parse(partial);
        assert_eq!(status, Ok(Status::Partial));
        assert_eq!(head.start_line.method, Some("INVITE"));

        head.parse(complete).unwrap().unwrap();
        assert_eq!(head.start_line.method, Some("BYE"));
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
        let mut headers = HeaderBuf::<N_HEADERS>::new();
        let mut head = RequestHead::new(&mut headers);

        head.parse(buf).unwrap().unwrap();

        let buf_range = buf.as_ptr_range();
        let line = head.start_line;
        let tokens = [
            line.method.unwrap(),
            line.uri.unwrap(),
            line.version.unwrap(),
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
        let mut headers = HeaderBuf::<N_HEADERS>::new();
        let mut head = RequestHead::new(&mut headers);

        let err = head.parse(buf).unwrap_err();

        assert_eq!(
            std::string::ToString::to_string(&err),
            "invalid SIP method",
        );
    }

    // The tests below cover what `Status::Partial` and errors leave in the
    // head.

    const INVITE: &[u8] = b"INVITE sip:bob@example.com SIP/2.0\r\n\
        Via: SIP/2.0/UDP pc33.example.com;branch=z9hG4bK776asdhds\r\n\
        Content-Length: 0\r\n\
        \r\n";

    #[test]
    fn fills_fields_in_order_for_every_prefix() {
        for end in 0..INVITE.len() {
            let mut headers = HeaderBuf::<N_HEADERS>::new();
            let mut head = RequestHead::new(&mut headers);

            let status = head.parse(&INVITE[..end]);

            assert_eq!(status, Ok(Status::Partial), "end={end}");
            let line = head.start_line;
            assert!(line.uri.is_none() || line.method.is_some());
            assert!(line.version.is_none() || line.uri.is_some());
            assert!(head.headers.is_empty() || line.version.is_some());
        }
    }

    #[test]
    fn quoted_pair_controls_in_request_and_response_headers() {
        macro_rules! check {
            ($head_ty:ident, $start:expr) => {
                // From uses quoted-string. Retry-After allows a nested
                // comment. Extension fields exercise the deliberately
                // broader raw-value policy, including unbalanced quotes.
                for (name, before, after) in [
                    (
                        "From",
                        b"\"A".as_slice(),
                        b"B\" <sip:a@b>;tag=x".as_slice(),
                    ),
                    ("Retry-After", b"120 (outer (A", b"B))"),
                    ("X-Extension", b"A", b"B"),
                    ("X-Extension", b"\"A", b"B"),
                ] {
                    for byte in (0x00..=0x08)
                        .chain(0x0b..=0x0c)
                        .chain(0x0e..=0x1f)
                        .chain(core::iter::once(0x7f))
                    {
                        let mut buf = std::vec::Vec::from($start.as_slice());
                        buf.extend_from_slice(name.as_bytes());
                        buf.extend_from_slice(b": ");
                        let value_start = buf.len();
                        buf.extend_from_slice(before);
                        buf.extend_from_slice(&[b'\\', byte]);
                        buf.extend_from_slice(after);
                        let value_end = buf.len();
                        buf.extend_from_slice(b"\r\n\r\nbody");
                        let mut headers = HeaderBuf::<1>::new();
                        let mut head = $head_ty::new(&mut headers);
                        assert_eq!(
                            head.parse(&buf),
                            Ok(Status::Complete(buf.len() - 4))
                        );
                        assert_eq!(head.headers.len(), 1);
                        assert_eq!(head.headers[0].name, name);
                        let value = head.headers[0].value;
                        assert_eq!(
                            value.as_bytes(),
                            &buf[value_start..value_end]
                        );
                        assert_eq!(
                            value.as_ptr(),
                            buf[value_start..].as_ptr()
                        );
                    }
                }
            };
        }
        check!(RequestHead, b"INVITE sip:b@host SIP/2.0\r\n");
        check!(ResponseHead, b"SIP/2.0 200 OK\r\n");
    }

    #[test]
    fn quoted_pair_utf8_and_fold_for_every_prefix() {
        macro_rules! check {
            ($head_ty:ident, $start:expr) => {
                let mut buf = std::vec::Vec::from($start.as_slice());
                let value = "\"田\\\u{0}中\\\u{8}\\\\\\\u{7f}\r\n \t📞\" <sip:a@b>;tag=x";
                buf.extend_from_slice(b"From: ");
                buf.extend_from_slice(value.as_bytes());
                buf.extend_from_slice(b"\r\n\r\n");
                for end in 0..buf.len() {
                    let mut headers = HeaderBuf::<1>::new();
                    let mut head = $head_ty::new(&mut headers);
                    assert_eq!(head.parse(&buf[..end]), Ok(Status::Partial), "end={end}");
                }
                let mut headers = HeaderBuf::<1>::new();
                let mut head = $head_ty::new(&mut headers);
                assert_eq!(head.parse(&buf), Ok(Status::Complete(buf.len())));
                assert_eq!(head.headers[0].value, value);
            };
        }
        check!(RequestHead, b"INVITE sip:b@host SIP/2.0\r\n");
        check!(ResponseHead, b"SIP/2.0 200 OK\r\n");
    }

    #[test]
    fn exposes_rows_parsed_before_partial() {
        let mut headers = HeaderBuf::<N_HEADERS>::new();
        let mut head = RequestHead::new(&mut headers);
        let buf = b"OPTIONS sip:carol@example.com SIP/2.0\r\n\
            Max-Forwards: 70\r\n\
            To:";

        let status = head.parse(buf);

        assert_eq!(status, Ok(Status::Partial));
        assert_eq!(head.start_line.method, Some("OPTIONS"));
        assert_eq!(head.start_line.version, Some("SIP/2.0"));
        assert_eq!(head.headers.len(), 1);
        assert_eq!(head.headers[0].name, "Max-Forwards");
    }

    #[test]
    fn exposes_start_line_fields_parsed_before_error() {
        let mut headers = HeaderBuf::<N_HEADERS>::new();
        let mut head = ResponseHead::new(&mut headers);
        let buf = b"SIP/2.0 20 OK\r\n\r\n";

        let err = head.parse(buf).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::StatusCode);
        assert_eq!(head.start_line.version, Some("SIP/2.0"));
        assert_eq!(head.start_line.status_code, None);
    }

    #[test]
    fn resets_head_before_each_parse() {
        let mut headers = HeaderBuf::<N_HEADERS>::new();
        let mut head = RequestHead::new(&mut headers);

        assert!(head.parse(INVITE).is_ok());
        let status = head.parse(b"BYE");
        assert_eq!(status, Ok(Status::Partial));

        assert_eq!(head.start_line, RequestLine::default());
        assert!(head.headers.is_empty());
    }

    #[test]
    fn zero_capacity_storage_parses_head_without_rows() {
        let mut headers = HeaderBuf::<0>::new();
        let mut head = RequestHead::new(&mut headers);
        let buf = b"ACK sip:bob@example.com SIP/2.0\r\n\r\n";

        let status = head.parse(buf);

        assert_eq!(status, Ok(Status::Complete(buf.len())));
        assert_eq!(head.headers.capacity(), 0);
    }

    any! {
        any_head_parses_request,
        b"\r\nINVITE sip:bob@example.com SIP/2.0\r\n\
          Content-Length: 0\r\n\
          \r\n",
        |head| {
            let Some(StartLine::Request(line)) = head.start_line else {
                panic!("expected a request-line, got {:?}", head.start_line);
            };
            assert_eq!(line.method, Some("INVITE"));
            assert_eq!(line.uri, Some("sip:bob@example.com"));
            assert_eq!(head.headers[0].value, "0");
        }
    }

    any! {
        any_head_parses_response,
        b"\r\nSIP/2.0 200 OK\r\n\
          Content-Length: 0\r\n\
          \r\n",
        |head| {
            let Some(StartLine::Status(line)) = head.start_line else {
                panic!("expected a status-line, got {:?}", head.start_line);
            };
            assert_eq!(line.status_code, Some("200"));
            assert_eq!(line.reason_phrase, Some("OK"));
            assert_eq!(head.headers[0].value, "0");
        }
    }

    // The version is case-insensitive, so the prefix check must be too.
    any! {
        any_head_parses_lowercase_status_line,
        b"sip/2.0 200 OK\r\n\r\n",
        |head| {
            assert!(matches!(head.start_line, Some(StartLine::Status(_))));
        }
    }

    // `SIP` is a valid method token. Only a `/` in fourth place makes it a
    // version.
    any! {
        any_head_parses_method_named_sip,
        b"SIP sip:bob@example.com SIP/2.0\r\n\r\n",
        |head| {
            let Some(StartLine::Request(line)) = head.start_line else {
                panic!("expected a request-line, got {:?}", head.start_line);
            };
            assert_eq!(line.method, Some("SIP"));
        }
    }

    any! {
        any_head_reports_status_line_errors,
        b"SIP/3.0 200 OK\r\n\r\n",
        => Err(Version)
    }

    any! {
        any_head_reports_request_line_errors,
        b"INV@TE sip:bob@example.com SIP/2.0\r\n\r\n",
        => Err(Method)
    }

    #[test]
    fn any_head_waits_until_prefix_decides_kind() {
        for buf in [&b""[..], b"\r\n", b"S", b"si", b"SIP", b"\r\nsIp"] {
            let mut headers = HeaderBuf::<N_HEADERS>::new();
            let mut head = AnyHead::new(&mut headers);

            assert_eq!(head.parse(buf), Ok(Status::Partial), "buf={buf:?}");
            assert_eq!(head.start_line, None, "buf={buf:?}");
        }
    }

    #[test]
    fn any_head_keeps_partial_start_line_of_decided_kind() {
        let mut headers = HeaderBuf::<N_HEADERS>::new();
        let mut head = AnyHead::new(&mut headers);

        assert_eq!(head.parse(b"SIP/"), Ok(Status::Partial));
        assert_eq!(
            head.start_line,
            Some(StartLine::Status(StatusLine::default()))
        );

        assert_eq!(head.parse(b"SIPS"), Ok(Status::Partial));
        assert_eq!(
            head.start_line,
            Some(StartLine::Request(RequestLine::default()))
        );

        assert_eq!(head.parse(b"SIP/2.0 486 "), Ok(Status::Partial));
        let Some(StartLine::Status(line)) = head.start_line else {
            panic!("expected a status-line, got {:?}", head.start_line);
        };
        assert_eq!(line.code(), Some(486));
        assert_eq!(line.reason_phrase, None);
    }

    #[test]
    fn any_head_resets_start_line_before_each_parse() {
        let mut headers = HeaderBuf::<N_HEADERS>::new();
        let mut head = AnyHead::new(&mut headers);

        assert!(head.parse(INVITE).is_ok());
        assert_eq!(head.parse(b"SI"), Ok(Status::Partial));
        assert_eq!(head.start_line, None);
        assert!(head.headers.is_empty());
    }
}

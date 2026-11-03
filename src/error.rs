use core::fmt;

/// A syntactic SIP parse error.
///
/// [`Error::kind`] reports which grammar element rejected the input.
///
/// The error deliberately carries no byte offset. Tracking where parsing
/// failed slowed down successful parses of small heads by up to 20% in the
/// benchmarks, because the parser then had to keep its cursor available at
/// every error exit. Errors are the rare case on a hot path, so that cost is
/// not worth paying here.
///
/// The type is a single byte and copyable. It represents structural parse
/// failures, not higher-level semantic errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Error {
    kind: ErrorKind,
}

/// The category of a syntactic SIP parse error.
///
/// Most variants name the grammar element that rejected the input.
/// [`BareCr`](ErrorKind::BareCr), [`BareLf`](ErrorKind::BareLf), and
/// [`MissingColon`](ErrorKind::MissingColon) instead name a broken line
/// structure, wherever it occurs. A problem with a line ending is therefore
/// reported the same way whether the line is the start-line or a header row.
///
/// A line that ends before the start-line has all of its elements, or before
/// a header name is followed by `:`, is reported as the element that was cut
/// short (or as `MissingColon`), not as a bare `CR` or `LF`. For example,
/// `SIP/2.0 200\n` is a [`StatusCode`](ErrorKind::StatusCode) error, while
/// `SIP/2.0 200 OK\n` is a `BareLf` error.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorKind {
    /// The `SIP-Version` token is not `SIP/2.0`, compared case-insensitively.
    Version,
    /// The request method is empty or contains a byte outside the RFC 3261
    /// `token` set.
    Method,
    /// The request URI is empty or contains a byte outside the URI token set.
    RequestUri,
    /// The status code is not exactly three ASCII digits.
    StatusCode,
    /// The reason phrase contains a disallowed byte, a malformed `%`-escape,
    /// or invalid UTF-8.
    ReasonPhrase,
    /// The header name is empty or contains a byte outside the RFC 3261
    /// `token` set.
    HeaderName,
    /// The header value contains an unescaped ASCII control other than `HTAB`,
    /// unescaped `DEL`, or invalid modern UTF-8. `CR` and `LF` follow the line
    /// structure rules and cannot be escaped by a backslash.
    ///
    /// Header-specific quoted-string and comment syntax is not validated.
    /// See the crate's [header value policy](crate#header-value-policy).
    HeaderValue,
    /// A header name is not followed by `:`. This covers a row that ends right
    /// after the name and whitespace inside the name, as in
    /// `Call ID: a84b4c76e66710`.
    MissingColon,
    /// A `CR` is not followed by `LF`.
    ///
    /// RFC 3261 only allows `CR` as part of a `CRLF` line terminator. Reason
    /// phrases must `%`-escape it, and header values may only contain it in
    /// line folding (`CRLF` followed by `SP` or `HTAB`).
    BareCr,
    /// An `LF` is not preceded by `CR`.
    ///
    /// This typically means the sender terminates lines with `LF` alone.
    /// RFC 3261 requires `CRLF`.
    BareLf,
    /// The caller-provided header storage is too small to hold every header
    /// row in the head.
    ///
    /// Unlike the other kinds, this does not mean the input is invalid.
    /// Parsing again with larger storage may succeed.
    TooManyHeaders,
}

impl Error {
    /// Returns the category of this error.
    #[inline]
    pub const fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// Returns an error indicating an invalid SIP version.
    #[inline]
    pub(crate) fn version() -> Error {
        Error { kind: ErrorKind::Version }
    }

    /// Returns an error indicating an invalid SIP method token.
    #[inline]
    pub(crate) fn method() -> Error {
        Error { kind: ErrorKind::Method }
    }

    /// Returns an error indicating an invalid SIP request URI.
    #[inline]
    pub(crate) fn request_uri() -> Error {
        Error { kind: ErrorKind::RequestUri }
    }

    /// Returns an error indicating an invalid SIP status code.
    #[inline]
    pub(crate) fn status_code() -> Error {
        Error { kind: ErrorKind::StatusCode }
    }

    /// Returns an error indicating an invalid SIP reason phrase.
    #[inline]
    pub(crate) fn reason_phrase() -> Error {
        Error { kind: ErrorKind::ReasonPhrase }
    }

    /// Returns an error indicating an invalid SIP header field name.
    #[inline]
    pub(crate) fn header_name() -> Error {
        Error { kind: ErrorKind::HeaderName }
    }

    /// Returns an error indicating a header name not followed by `:`.
    #[inline]
    pub(crate) fn missing_colon() -> Error {
        Error { kind: ErrorKind::MissingColon }
    }

    /// Returns an error indicating a `CR` not followed by `LF`.
    #[inline]
    pub(crate) fn bare_cr() -> Error {
        Error { kind: ErrorKind::BareCr }
    }

    /// Returns an error indicating an `LF` not preceded by `CR`.
    #[inline]
    pub(crate) fn bare_lf() -> Error {
        Error { kind: ErrorKind::BareLf }
    }

    /// Returns an error indicating an invalid SIP header field value.
    #[inline]
    pub(crate) fn header_value() -> Error {
        Error { kind: ErrorKind::HeaderValue }
    }

    /// Returns an error indicating that the caller-provided header row buffer
    /// was too small to hold all parsed header rows.
    #[inline]
    pub(crate) fn too_many_headers() -> Error {
        Error { kind: ErrorKind::TooManyHeaders }
    }
}

impl ErrorKind {
    const fn description(self) -> &'static str {
        match self {
            ErrorKind::Version => "invalid SIP version",
            ErrorKind::Method => "invalid SIP method",
            ErrorKind::RequestUri => "invalid SIP request URI",
            ErrorKind::StatusCode => "invalid SIP status code",
            ErrorKind::ReasonPhrase => "invalid SIP reason phrase",
            ErrorKind::HeaderName => "invalid SIP header name",
            ErrorKind::HeaderValue => "invalid SIP header value",
            ErrorKind::MissingColon => "missing colon after SIP header name",
            ErrorKind::BareCr => "CR not followed by LF",
            ErrorKind::BareLf => "LF not preceded by CR",
            ErrorKind::TooManyHeaders => {
                "too many SIP headers for provided header buffer"
            }
        }
    }
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.description())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.kind, f)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

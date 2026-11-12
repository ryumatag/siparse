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
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
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
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
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
    /// See the crate's [header value policy](crate#header-values).
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
    /// A header value is not a `name-addr` or an `addr-spec`, or a list of
    /// them, where [`value::address`](crate::value::address) or
    /// [`value::addresses`](crate::value::addresses) reads one.
    ///
    /// This covers the display name, the angle brackets, the URI, and what
    /// may follow an address. A malformed parameter is a
    /// [`GenericParam`](ErrorKind::GenericParam) error instead.
    Address,
    /// A `;` is not followed by a `generic-param`, which is a `token`
    /// optionally followed by `=` and a `token`, `host` or `quoted-string`.
    GenericParam,
    /// A value is not a challenge or credentials, where
    /// [`value::challenge`](crate::value::challenge) or
    /// [`value::credentials`](crate::value::credentials) reads one: a scheme,
    /// whitespace, and one or more `auth-param`s separated by `,`.
    Auth,
    /// A value is not a media type, where
    /// [`value::media_type`](crate::value::media_type) reads one, or not a
    /// list of media ranges, where
    /// [`value::media_ranges`](crate::value::media_ranges) reads one.
    ///
    /// This covers the parameters too, since an `m-parameter` is narrower
    /// than a `generic-param` and a `q` has to hold a `qvalue`.
    MediaType,
    /// A value is not a comma-separated list of tokens, where
    /// [`value::tokens`](crate::value::tokens) reads one.
    Tokens,
    /// A Via value is not a list of `via-parm`s, where
    /// [`value::via_parms`](crate::value::via_parms) reads one.
    ///
    /// This covers `sent-protocol`, `sent-by` and what may follow a
    /// `via-parm`. A malformed parameter is a
    /// [`GenericParam`](ErrorKind::GenericParam) error instead.
    Via,
    /// A CSeq value is not `1*DIGIT LWS Method`, where
    /// [`value::cseq`](crate::value::cseq) reads one.
    CSeq,
    /// A Call-ID value is not `word [ "@" word ]`, where
    /// [`value::call_id`](crate::value::call_id) reads one.
    CallId,
    /// A URI does not start with `sip:` or `sips:`, compared
    /// case-insensitively, where [`uri::sip_uri`](crate::uri::sip_uri) reads
    /// one.
    UriScheme,
    /// The `user` of a SIP URI is empty or has a byte outside its set.
    UriUser,
    /// The `password` of a SIP URI has a byte outside its set.
    UriPassword,
    /// The `host` of a SIP URI is not a hostname, an IPv4 address or an IPv6
    /// reference.
    UriHost,
    /// What follows the `host` of a SIP URI, before its parameters, is not
    /// `:` and one or more digits.
    UriPort,
    /// A parameter of a SIP URI has an empty or malformed name or value.
    UriParam,
    /// A header of a SIP URI is not a name, `=` and a value, or one of them
    /// has a byte outside its set.
    UriHeader,
    /// A `%` in a SIP URI is not followed by two hexadecimal digits.
    UriEscape,
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
    pub(crate) const fn version() -> Error {
        Error { kind: ErrorKind::Version }
    }

    /// Returns an error indicating an invalid SIP method token.
    #[inline]
    pub(crate) const fn method() -> Error {
        Error { kind: ErrorKind::Method }
    }

    /// Returns an error indicating an invalid SIP request URI.
    #[inline]
    pub(crate) const fn request_uri() -> Error {
        Error { kind: ErrorKind::RequestUri }
    }

    /// Returns an error indicating an invalid SIP status code.
    #[inline]
    pub(crate) const fn status_code() -> Error {
        Error { kind: ErrorKind::StatusCode }
    }

    /// Returns an error indicating an invalid SIP reason phrase.
    #[inline]
    pub(crate) const fn reason_phrase() -> Error {
        Error { kind: ErrorKind::ReasonPhrase }
    }

    /// Returns an error indicating an invalid SIP header field name.
    #[inline]
    pub(crate) const fn header_name() -> Error {
        Error { kind: ErrorKind::HeaderName }
    }

    /// Returns an error indicating a header name not followed by `:`.
    #[inline]
    pub(crate) const fn missing_colon() -> Error {
        Error { kind: ErrorKind::MissingColon }
    }

    /// Returns an error indicating a `CR` not followed by `LF`.
    #[inline]
    pub(crate) const fn bare_cr() -> Error {
        Error { kind: ErrorKind::BareCr }
    }

    /// Returns an error indicating an `LF` not preceded by `CR`.
    #[inline]
    pub(crate) const fn bare_lf() -> Error {
        Error { kind: ErrorKind::BareLf }
    }

    /// Returns an error indicating an invalid SIP header field value.
    #[inline]
    pub(crate) const fn header_value() -> Error {
        Error { kind: ErrorKind::HeaderValue }
    }

    /// Returns an error indicating an invalid `name-addr` or `addr-spec`.
    #[inline]
    pub(crate) const fn address() -> Error {
        Error { kind: ErrorKind::Address }
    }

    /// Returns an error indicating an invalid `generic-param`.
    #[inline]
    pub(crate) const fn generic_param() -> Error {
        Error { kind: ErrorKind::GenericParam }
    }

    /// Returns an error indicating an invalid challenge or credentials.
    #[inline]
    pub(crate) const fn auth() -> Error {
        Error { kind: ErrorKind::Auth }
    }

    /// Returns an error indicating an invalid media type or media range.
    #[inline]
    pub(crate) const fn media_type() -> Error {
        Error { kind: ErrorKind::MediaType }
    }

    /// Returns an error indicating an invalid list of tokens.
    #[inline]
    pub(crate) const fn tokens() -> Error {
        Error { kind: ErrorKind::Tokens }
    }

    /// Returns an error indicating an invalid `via-parm`.
    #[inline]
    pub(crate) const fn via() -> Error {
        Error { kind: ErrorKind::Via }
    }

    /// Returns an error indicating an invalid CSeq value.
    #[inline]
    pub(crate) const fn cseq() -> Error {
        Error { kind: ErrorKind::CSeq }
    }

    /// Returns an error indicating an invalid Call-ID value.
    #[inline]
    pub(crate) const fn call_id() -> Error {
        Error { kind: ErrorKind::CallId }
    }

    /// Returns an error of `kind` for a part of a SIP URI.
    #[inline]
    pub(crate) const fn uri(kind: ErrorKind) -> Error {
        Error { kind }
    }

    /// Returns an error indicating that the caller-provided header row buffer
    /// was too small to hold all parsed header rows.
    #[inline]
    pub(crate) const fn too_many_headers() -> Error {
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
            ErrorKind::Address => "invalid SIP name-addr or addr-spec",
            ErrorKind::GenericParam => "invalid SIP generic-param",
            ErrorKind::Auth => "invalid SIP challenge or credentials",
            ErrorKind::MediaType => "invalid SIP media type",
            ErrorKind::Tokens => "invalid SIP token list",
            ErrorKind::Via => "invalid SIP via-parm",
            ErrorKind::CSeq => "invalid SIP CSeq",
            ErrorKind::CallId => "invalid SIP Call-ID",
            ErrorKind::UriScheme => "expected a SIP or SIPS URI",
            ErrorKind::UriUser => "invalid SIP URI user",
            ErrorKind::UriPassword => "invalid SIP URI password",
            ErrorKind::UriHost => "invalid SIP URI host",
            ErrorKind::UriPort => "invalid SIP URI port",
            ErrorKind::UriParam => "invalid SIP URI parameter",
            ErrorKind::UriHeader => "invalid SIP URI header",
            ErrorKind::UriEscape => "invalid SIP URI percent escape",
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

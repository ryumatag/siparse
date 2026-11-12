/*!
siparse is a syntactic parser for SIP message heads. It parses the
request-line or status-line and the header rows that follow.

It does not perform semantic decoding. Header names are not normalized, compact
forms such as `v` for `Via` are not expanded, and folded values are returned
raw. A header value can be split into the parts its grammar names, but nothing
in it is converted or decoded. Message bodies, including `Content-Length`
handling, are left to the caller.

Every token is returned as a `&str` borrowed from the caller's input buffer,
and header rows are written into storage that the caller provides. Parsing
neither copies nor allocates.

Scanning uses portable SWAR (SIMD Within A Register) code, and SIMD on x86_64
and aarch64 for header values and the end of a head. See [SIMD](#simd).

Parse a SIP request:

```
use siparse::{HeaderBuf, RequestHead, Status};

let buf = b"INVITE sip:bob@example.com SIP/2.0\r\n\
            Via: SIP/2.0/UDP pc33.example.com;branch=z9hG4bK776asdhds\r\n\
            Content-Length: 0\r\n\
            \r\n";

let mut headers = HeaderBuf::<16>::new();
let mut head = RequestHead::new(&mut headers);

let Status::Complete(head_end) = head.parse(buf)? else {
    // `head` holds what was parsed so far. Read more input and parse again
    // from the beginning.
    return Ok(());
};

assert_eq!(head.start_line.method, Some("INVITE"));
assert_eq!(head.start_line.uri, Some("sip:bob@example.com"));
assert_eq!(head.headers[0].name, "Via");
assert_eq!(head.headers[1].value, "0");
assert_eq!(head_end, buf.len());
# Ok::<(), siparse::Error>(())
```

[`ResponseHead`] parses a response the same way. When a head may be either,
as on a socket that carries both, parse it with [`AnyHead`] and match on its
[`StartLine`].

The start-line fields are `Option`s so that a partial head can show how far
the parser got. Once the head is complete, `complete()` on the start-line,
such as [`RequestLine::complete`], returns the same fields without them.

# Modules

Which part of the crate to use depends on what is at hand:

| At hand | Use |
|---|---|
| Bytes received on a socket | [`RequestHead`], [`ResponseHead`] or [`AnyHead`], at the root |
| A stream of messages, such as TCP | [`frame`], to find where each head ends and to spot keepalives |
| A header value to read | [`value`], which reads the productions header grammars share |
| A header with no production in `value` | [`scan`], the lexical elements to read it with |
| A URI to read | [`uri`] |
| A value about to be written into a head | [`check`] |

The modules that read go from coarse to fine. The head parsers return each
header value raw. [`value`] splits one by its RFC 3261 production, such as a
`name-addr` with its parameters, and [`uri`] splits a SIP URI. [`scan`] returns
the single elements that header grammars, and `value`, are built from, such as
a `token` or a `quoted-string`. Each returns its parts as `&str`s borrowed from
the input, and none decodes them.

[`check`] works the other way. It tells whether a value that an application
built may go into a head, by the same rules the head parser applies, such as
the characters a header value or a Request-URI may hold. That is the envelope
of a head, not the grammar of a particular header, so `check::request_uri`
accepts URIs that [`uri::sip_uri`] rejects. Each check also has a `const fn`
form for constants.

Within [`value`] and [`uri`]:

* [`value::address`] reads a From or To value, and [`value::addresses`] a
  Contact, Route or Record-Route list, into the display name, the URI and the
  header parameters.
* [`value::params`] reads the `generic-param`s that end many other headers.
* [`value::tokens`] reads the token lists of Require, Supported, Allow and
  Content-Encoding.
* [`value::media_type`] reads a Content-Type, and [`value::media_ranges`] the
  ranges of an Accept.
* [`value::via_parms`] reads the values of a Via.
* [`value::cseq`] and [`value::call_id`] read CSeq and Call-ID.
* [`uri::sip_uri`] splits a SIP or SIPS URI into its user, password, host,
  port, parameters and headers.

They follow RFC 3261 strictly. Unquoting, decoding, defaults, and deciding
which production a header takes are left to the consumer.

# Partial input

[`Status::Partial`] is not an error. It means the buffer ends before the head
does. The head then holds the start-line fields and header rows parsed so far,
so a caller can act on them early, for example to reject an unknown method
before the rest arrives. The parser keeps no state between calls, so the
caller reads more input and parses the whole buffer again from the beginning.
Each parse resets the head first.

The head and its [`HeaderBuf`] borrow the buffer they were filled from. When
the buffer grows between parses, create them again for each parse.
`HeaderBuf::new` leaves its slots uninitialized, so this costs nothing.

Because every retry starts over, a head that arrives in many small reads costs
time quadratic in its length. On stream transports, limit the head size. A
framer can also skip most retries with [`frame::find_head_end`]. After a
`Partial`, it scans only the newly read bytes, plus the last three bytes of the
previous read, for the empty line `\r\n\r\n`, and parses again only once that
appears.

# Keepalives

The parser skips any `CRLF` before the start-line, as [RFC 3261 section 7.5]
requires for stream transports. It therefore never reports an [RFC 5626]
keepalive. A double `CRLF` ping on its own returns `Partial`, and a ping in
front of a message is skipped silently.

On a connection-oriented transport that implements RFC 5626, check for a
keepalive at each message boundary before parsing a head. A server calls
[`frame::parse_ping`] and answers each ping with a single `CRLF`. A client
calls [`frame::parse_pong`] to notice the reply. The two checks are separate
because they treat a buffer that ends in `CRLF` differently. A server may have
half of a split ping, while a client must not wait for more bytes.

[RFC 3261 section 7.5]: https://www.rfc-editor.org/rfc/rfc3261#section-7.5

# Keeping parsed data

A filled [`MessageHead`] borrows the input buffer, so it cannot outlive that
buffer or survive a reallocation of it, such as a growing [`BytesMut`]. Callers
that need to keep tokens record where each one lies while the head is still
alive, then let the head go. A token's start offset is
`token.as_ptr() as usize - buf.as_ptr() as usize`, which works with any buffer
type.

With the [`bytes`] crate, the recorded ranges let the caller share the head
without copying it:

```
use bytes::{Bytes, BytesMut};
use siparse::{HeaderBuf, RequestHead, Status};

let mut buf = BytesMut::from(
    &b"OPTIONS sip:carol@example.com SIP/2.0\r\n\
       Call-ID: a84b4c76e66710@pc33.example.com\r\n\
       \r\n"[..],
);

let mut headers = HeaderBuf::<16>::new();
let mut head = RequestHead::new(&mut headers);
let head_end = match head.parse(&buf)? {
    Status::Complete(head_end) => head_end,
    Status::Partial => return Ok(()),
};

let base = buf.as_ptr() as usize;
let value_ranges: Vec<_> = head
    .headers
    .iter()
    .map(|header| {
        let start = header.value.as_ptr() as usize - base;
        start..start + header.value.len()
    })
    .collect();

// The parsed head no longer borrows `buf`, so it can be split.
let head_bytes = buf.split_to(head_end).freeze();
let values: Vec<Bytes> =
    value_ranges.into_iter().map(|range| head_bytes.slice(range)).collect();

assert_eq!(values[0], "a84b4c76e66710@pc33.example.com");
# Ok::<(), siparse::Error>(())
```

siparse leaves this conversion to the caller so that it stays free of
transport and buffer-type dependencies.

[`bytes`]: https://docs.rs/bytes
[`BytesMut`]: https://docs.rs/bytes/latest/bytes/struct.BytesMut.html
[RFC 5626]: https://www.rfc-editor.org/rfc/rfc5626

# Parsing policy

### Header values

Header values are checked as raw field values without selecting a grammar from
the header name. The parser accepts `HTAB`, printable ASCII (`0x20..=0x7e`),
modern UTF-8, and line folding. It also accepts ASCII controls other than `CR`
and `LF`, and `DEL`, when immediately preceded by an odd-length run of
backslashes. The bytes are returned verbatim, including backslashes and any
escaped NUL or other controls.

This accommodates [RFC 3261 section 25.1]'s `quoted-pair` in known headers'
`quoted-string` and `comment` productions. Its generic `extension-header`
`header-value` production does not permit those controls, even after a
backslash. The parser deliberately accepts a broader envelope for every
header name. Checking whether a quoted-pair occurs in a quoted string or
comment allowed by that field's grammar is the consumer's responsibility.
Quote balancing, comment nesting, and other field-specific syntax are also
left to the consumer. Acceptance here does not establish that a header value
matches its RFC grammar.

The parser does not track quotation marks or parentheses. Their meaning
depends on the field's grammar, and tracking them for every value would add
work to ordinary ASCII parsing. Instead, only otherwise disallowed controls
trigger a backward check of the immediately preceding backslash run. An even
run has no unpaired backslash and does not permit a control.

Backslashes never escape `CR` or `LF`. A `CRLF` followed by `SP` or `HTAB`
is preserved as a fold, and any other `CRLF` ends the row, even after a
backslash. Bare `CR` and bare `LF` are rejected. Incomplete line endings
return [`Status::Partial`]. Non-ASCII bytes must form modern UTF-8 even after
a backslash. No quoting mechanism bypasses this validation.

Leading `SP`, `HTAB`, and folds are not part of a value, because RFC 3261's
`HCOLON` makes them part of the separator. Trailing whitespace is kept. Some
header grammars give it no meaning, while the generic `header-value` includes
it, so trimming it is left to the consumer.

[RFC 3261 section 25.1]: https://www.rfc-editor.org/rfc/rfc3261#section-25.1

### UTF-8

Header values and reason phrases are validated against modern UTF-8
([RFC 3629], the same model used by Rust's `str` type) at parse time. This is
an intentional narrowing relative to [RFC 3261]'s historical RFC 2279-era UTF-8
ABNF. Overlong encodings, surrogates, and 5- and 6-byte forms are rejected.
Because the parser validates before it borrows, returning `&str` costs no extra
validation pass.

[RFC 3629]: https://www.rfc-editor.org/rfc/rfc3629
[RFC 3261]: https://www.rfc-editor.org/rfc/rfc3261

# SIMD

Two scans use SIMD where the target has it. The header value scan covers most
of the bytes in a head, and [`frame::find_head_end`] covers every byte of it:

* **x86_64** - SSE2, 16 bytes at a time.
* **aarch64** (little-endian) - NEON, 16 bytes at a time. Header values start
  with a block of SWAR, because many end within those first bytes, and SWAR
  handles them with less overhead.
* **Other targets** - SWAR only, 8 bytes at a time on 64-bit targets and 4 on
  32-bit ones. This includes 32-bit x86 and big-endian aarch64.

SSE2 and NEON are part of the x86_64 and aarch64 baselines, so there is no
run-time CPU detection and nothing to configure. Building with
`-C target-cpu=native` does not enable wider instructions such as AVX2. The
same holds without `std`.

Every path accepts the same input and stops at the same byte as the others.
Tests compare each one with a scalar reference. SIMD pays off as values get
longer. Values of a few bytes cost about the same as with SWAR.
[`frame::find_head_end`] gains on reads of any length, since it skips whole
blocks until the end of the head and needs no setup.

The other scans, for header names, the Request-URI, reason phrases, and the
[`scan`] module, use SWAR or a lookup table per byte. What they cover is
usually short, where SIMD saves little.

# Crate features

* **`std`** (enabled by default) - Implements `std::error::Error` for [`Error`].
  Implies `alloc`. Without it, siparse is `no_std`.
* **`alloc`** (enabled by `std`) - Adds `Headers::with_capacity`, which
  allocates header storage whose capacity is chosen at run time. Parsing itself
  never allocates.

A `__bench` feature exists for the benchmark crate in this repository. It is
unstable and not part of the public API.
*/

#![no_std]
#![allow(
    // My preference.
    clippy::use_self,
    clippy::needless_lifetimes,
)]
#![deny(
    unreachable_pub,
    clippy::missing_safety_doc,
    clippy::undocumented_unsafe_blocks,
    rustdoc::broken_intra_doc_links
)]
#![warn(missing_docs, missing_debug_implementations)]

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(any(test, feature = "std"))]
extern crate std;

#[macro_use]
mod macros;

pub mod check;
mod error;
pub mod frame;
mod iter;
mod parse;
pub mod scan;
mod simd;
mod token;
pub mod uri;
mod utf8;
pub mod value;

#[doc(inline)]
pub use self::{
    error::{Error, ErrorKind},
    parse::{
        AnyHead, CompleteRequestLine, CompleteStartLine, CompleteStatusLine,
        Header, HeaderBuf, Headers, MessageHead, RequestHead, RequestLine,
        ResponseHead, StartLine, Status, StatusLine, ValueLines,
    },
};

// The framing functions lived at the root before they moved to `frame`.
// `#[deprecated]` on a `pub use` has no effect, so the old paths are
// wrappers. They go away in the next release that breaks compatibility.

/// Finds the end of the first head in `buf`.
///
/// This moved to [`frame::find_head_end`].
#[deprecated(since = "0.4.7", note = "use `siparse::frame::find_head_end`")]
#[inline]
pub fn find_head_end(buf: &[u8], scanned: usize) -> Option<usize> {
    frame::find_head_end(buf, scanned)
}

/// Checks for an RFC 5626 ping at the start of `buf`.
///
/// This moved to [`frame::parse_ping`].
#[deprecated(since = "0.4.7", note = "use `siparse::frame::parse_ping`")]
#[inline]
pub fn parse_ping(buf: &[u8]) -> Status<Option<usize>> {
    frame::parse_ping(buf)
}

/// Checks for an RFC 5626 pong at the start of `buf`.
///
/// This moved to [`frame::parse_pong`].
#[deprecated(since = "0.4.7", note = "use `siparse::frame::parse_pong`")]
#[inline]
pub fn parse_pong(buf: &[u8]) -> Status<Option<usize>> {
    frame::parse_pong(buf)
}

/// Entry points for the `siparse-bench` crate, behind the `__bench` feature.
///
/// Each function parses one production directly, so the benchmarks can locate
/// a cost inside the head parser. Nothing here is part of the public API, and
/// the feature can change or go away in any release.
#[cfg(feature = "__bench")]
#[doc(hidden)]
pub mod bench {
    #[doc(hidden)]
    pub use crate::iter::Bytes;
    use crate::parse::{self, Delimited, Result};

    #[doc(hidden)]
    #[inline]
    pub fn parse_method<'buf>(bytes: &mut Bytes<'buf>) -> Result<&'buf str> {
        parse::method::<Delimited>(bytes)
    }

    #[doc(hidden)]
    #[inline]
    pub fn parse_request_uri<'buf>(
        bytes: &mut Bytes<'buf>,
    ) -> Result<&'buf str> {
        parse::request_uri::<Delimited>(bytes)
    }

    #[doc(hidden)]
    #[inline]
    pub fn parse_version<'buf>(bytes: &mut Bytes<'buf>) -> Result<&'buf str> {
        parse::parse_version(bytes)
    }

    #[doc(hidden)]
    #[inline]
    pub fn parse_status_code<'buf>(
        bytes: &mut Bytes<'buf>,
    ) -> Result<&'buf str> {
        parse::parse_status_code(bytes)
    }

    #[doc(hidden)]
    #[inline]
    pub fn parse_reason_phrase<'buf>(
        bytes: &mut Bytes<'buf>,
    ) -> Result<&'buf str> {
        parse::reason_phrase::<Delimited>(bytes)
    }

    #[doc(hidden)]
    #[inline]
    pub fn parse_header_name<'buf>(
        bytes: &mut Bytes<'buf>,
    ) -> Result<&'buf str> {
        parse::parse_header_name(bytes)
    }

    /// [`find_head_end`](crate::frame::find_head_end) with SWAR only, the
    /// fallback on other targets.
    #[doc(hidden)]
    #[inline]
    pub fn find_head_end_swar(buf: &[u8], scanned: usize) -> Option<usize> {
        crate::frame::find_head_end_with(
            buf,
            scanned,
            crate::simd::find_head_end_swar,
        )
    }

    /// Advances over ASCII header value bytes with the scan the parser uses,
    /// SIMD where the target has it, and returns how many it passed.
    #[doc(hidden)]
    #[inline]
    pub fn find_header_value_stop(bytes: &mut Bytes<'_>) -> usize {
        let start = bytes.pos();
        crate::simd::match_header_value_vectored(bytes);
        bytes.pos() - start
    }

    /// The same scan with SWAR only, the fallback on other targets.
    #[doc(hidden)]
    #[inline]
    pub fn find_header_value_stop_swar(bytes: &mut Bytes<'_>) -> usize {
        let start = bytes.pos();
        crate::simd::match_header_value_swar(bytes);
        bytes.pos() - start
    }

    #[doc(hidden)]
    #[inline]
    pub fn parse_header_value<'buf>(
        bytes: &mut Bytes<'buf>,
    ) -> Result<&'buf str> {
        parse::parse_header_value(bytes)
    }
}

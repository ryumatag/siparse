/*!
`siparse` is a syntactic parser for SIP message heads. It parses the
request-line or status-line and the header rows that follow.

It does not perform semantic decoding. Header names are not normalized, compact
forms such as `v` for `Via` are not expanded, typed header values are not
parsed, and folded values are returned raw. Message bodies, including
`Content-Length` handling, are left to the caller.

Every token is returned as a `&str` borrowed from the caller's input buffer,
and header rows are written into storage that the caller provides. Parsing
neither copies nor allocates.

Delimiter scanning currently uses portable SWAR (SIMD Within A Register) code
on every target. SIMD fast paths for x86_64 and aarch64 are planned.

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
framer can also skip most retries. After a `Partial`, it scans only the newly
read bytes, plus the last three bytes of the previous read, for the empty line
`\r\n\r\n`, and parses again only once that appears. A false match only costs
one extra parse, so the scan does not need to follow the grammar exactly. For
example, an [RFC 5626] keepalive `\r\n\r\n` before the start-line is harmless,
because the parser skips leading `CRLF`s and reports `Partial` again.

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

`siparse` leaves this conversion to the caller so that it stays free of
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

# Crate features

* **std** (enabled by default) - Implements `std::error::Error` for [`Error`].
  Without it, `siparse` is `no_std` and does not use `alloc`.
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

#[cfg(any(test, feature = "std"))]
extern crate std;

#[macro_use]
mod macros;

mod error;
mod iter;
mod parse;
mod simd;
mod token;
mod utf8;

#[doc(inline)]
pub use self::{
    error::{Error, ErrorKind},
    parse::{
        Header, HeaderBuf, Headers, MessageHead, RequestHead, RequestLine,
        ResponseHead, Status, StatusLine,
    },
};

// For benchmarking by the `siparse-bench` crate. Not part of the public API.
#[doc(hidden)]
pub mod _private {
    #[doc(hidden)]
    pub use super::{
        iter::Bytes,
        parse::{
            parse_header_name, parse_header_value, parse_method,
            parse_reason_phrase, parse_request_uri, parse_status_code,
            parse_version,
        },
    };
}

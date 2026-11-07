<div align="center">

siparse
=======
A syntactic parser for SIP message heads in Rust.

[![Build status](https://github.com/ryumatag/siparse/actions/workflows/ci.yml/badge.svg)](https://github.com/ryumatag/siparse/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/siparse.svg)](https://crates.io/crates/siparse)
[![Docs.rs](https://img.shields.io/docsrs/siparse)](https://docs.rs/siparse)

</div>

<br>

siparse parses SIP request-lines, status-lines, and header rows. It is a
syntactic parser only and does not perform semantic decoding. Header names
are not normalized, typed header values are not parsed, and message bodies
are left to the caller.

Every parsed token is a `&str` borrowed from the input buffer, so parsing
neither copies nor allocates. It works without `std`.

Scanning uses portable SWAR (SIMD Within A Register) code. Header values and
the search for the end of a head use SSE2 on x86_64 and NEON on aarch64.

### Example

```rust
use siparse::{HeaderBuf, RequestHead, Status};

let buf = b"INVITE sip:bob@example.com SIP/2.0\r\n\
            Via: SIP/2.0/UDP pc33.example.com;branch=z9hG4bK776asdhds\r\n\
            Content-Length: 0\r\n\
            \r\n";

let mut headers = HeaderBuf::<16>::new();
let mut head = RequestHead::new(&mut headers);

match head.parse(buf)? {
    Status::Complete(head_end) => {
        assert_eq!(head.start_line.method, Some("INVITE"));
        assert_eq!(head.start_line.uri, Some("sip:bob@example.com"));
        assert_eq!(head.headers[0].name, "Via");
        assert_eq!(head.headers[1].value, "0");
        assert_eq!(head_end, buf.len());
    }
    Status::Partial => {
        // `head` holds what was parsed so far. Read more input and parse
        // again from the beginning.
    }
}
```

### Acknowledgements

The parser internals draw heavily on
[`httparse`](https://docs.rs/httparse).

### License

This project is licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
   https://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or
   https://opensource.org/licenses/MIT)

at your option.

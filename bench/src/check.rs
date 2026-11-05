use std::hint::black_box as bb;

use criterion::Criterion;
use siparse::{check, Error};

use crate::benchmark;

type Check = fn(&[u8]) -> Result<&str, Error>;

pub(super) fn check(c: &mut Criterion) {
    // Each element in its plain form, which shares the head parser's code,
    // and its `const` form, which checks one byte at a time.
    let cases: [(&str, &[u8], Check, Check); _] = [
        ("method", b"INVITE", check::method, check::method_const),
        (
            "request_uri",
            b"sip:bob@biloxi.example.com;transport=tcp",
            check::request_uri,
            check::request_uri_const,
        ),
        (
            "reason_phrase",
            b"Call/Transaction Does Not Exist",
            check::reason_phrase,
            check::reason_phrase_const,
        ),
        (
            "header_name",
            b"Proxy-Authorization",
            check::header_name,
            check::header_name_const,
        ),
        (
            "header_value",
            b"SIP/2.0/UDP pc33.atlanta.example.com;branch=z9hG4bK776asdhds",
            check::header_value,
            check::header_value_const,
        ),
        (
            "header_value/utf8",
            "\"\u{7530}\u{4e2d}\" <sip:tanaka@example.com>;tag=1928301774"
                .as_bytes(),
            check::header_value,
            check::header_value_const,
        ),
    ];

    for (thing, input, plain, konst) in cases {
        for (variant, f) in [("plain", plain), ("const", konst)] {
            let id = format!("check/{thing}/{variant}");
            benchmark(c, id, input.len() as u64, |b| {
                b.iter(|| {
                    let token = bb(f(bb(input))).unwrap();
                    assert_eq!(token.len(), input.len());
                });
            });
        }
    }
}

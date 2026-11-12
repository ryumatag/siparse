use std::hint::black_box as bb;

use criterion::Criterion;
use siparse::uri;

use crate::benchmark;

pub(super) fn sip_uri(c: &mut Criterion) {
    // The URIs signa-core measured its own parser with before it moved to
    // siparse. The throughput counts the whole URI.
    let cases = [
        ("typical", "sip:bob@biloxi.example.com"),
        ("ipv6", "sips:bob@[2001:db8::1]:5061"),
        ("userinfo", "sip:alice;phone?work:secret%3a@example.com"),
        (
            "long",
            "sip:bob@biloxi.example.com:5060;transport=tcp;lr;maddr=192.0.2.1\
             ?Subject=lunch&Priority=urgent",
        ),
    ];

    for (category, input) in cases {
        let host_len = uri::sip_uri(input).unwrap().host.len();
        benchmark(
            c,
            format!("uri/sip_uri/{category}"),
            input.len() as u64,
            |b| {
                b.iter(|| {
                    let found = bb(uri::sip_uri(bb(input))).unwrap();
                    assert_eq!(found.host.len(), host_len);
                });
            },
        );
    }

    // A global number, and a local one with the context it needs.
    let tel_cases = [
        ("global", "tel:+1-201-555-0123;ext=1234"),
        ("local", "tel:863-1234;phone-context=+1-914-555"),
    ];
    for (category, input) in tel_cases {
        benchmark(
            c,
            format!("uri/tel_uri/{category}"),
            input.len() as u64,
            |b| {
                b.iter(|| {
                    let found = bb(uri::tel_uri(bb(input))).unwrap();
                    assert_eq!(found.params.iter().count(), 1);
                });
            },
        );
    }
}

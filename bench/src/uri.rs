use std::hint::black_box as bb;

use criterion::Criterion;

use crate::{
    benchmark,
    private::{parse_request_uri, Bytes},
};

pub(super) fn parse(c: &mut Criterion) {
    fixed_shape(c);
    sweep(c);
}

fn fixed_shape(c: &mut Criterion) {
    const NAME: &str = "parse/request_uri";

    // Each input ends with a single SP that terminates the Request-URI. The
    // returned token excludes that SP.
    let cases: [(&str, &[u8]); _] = [
        ("short", b"sip:b@e "),
        ("typical", b"sip:bob@example.com "),
        ("with_params", b"sip:bob@example.com;transport=tcp;lr "),
        ("ipv6", b"sip:bob@[2001:db8::1] "),
        (
            "long",
            b"sip:bob@example.com:5060;transport=tcp;lr;\
              maddr=192.0.2.1?Subject=foo&Priority=urgent ",
        ),
    ];

    for (variant, input) in cases {
        let expected_len = input.len() - 1;
        benchmark(c, format!("{NAME}/{variant}"), expected_len as u64, |b| {
            b.iter(|| {
                let mut bytes = Bytes::new(bb(input));
                let token =
                    bb(parse_request_uri(&mut bytes).unwrap().unwrap());
                assert_eq!(token.len(), expected_len);
            });
        });
    }
}

// Geometric size sweep that mirrors the layout used by the `httparse` crate.
// The point is to draw out the SWAR scan's throughput curve. Small sizes are
// dominated by per-call overhead, and large sizes converge on the asymptotic
// byte rate of `match_uri_vectored`.
fn sweep(c: &mut Criterion) {
    const NAME: &str = "parse/request_uri/sweep";

    // All bytes in `CHUNK` are accepted by `is_uri_token`, so any prefix of
    // `chunk_4k` is a syntactically valid Request-URI.
    const CHUNK: &[u8] = b"sip:bob@example.com;transport=tcp;branch=z9hG4bK";
    let chunk_4k = CHUNK.repeat(4096 / CHUNK.len() + 1);

    // 1B to 4096B in powers of two.
    for p in 0..=12 {
        let n = 1usize << p;
        // Leak the input so the closure can hold `&'static [u8]` and the
        // benchmark closure stays `'static` without lifetime juggling.
        let input: &'static [u8] =
            Box::leak([&chunk_4k[..n], b" "].concat().into_boxed_slice());

        benchmark(c, format!("{NAME}/{n:04}b"), n as u64, |b| {
            b.iter(|| {
                let mut bytes = Bytes::new(bb(input));
                let token =
                    bb(parse_request_uri(&mut bytes).unwrap().unwrap());
                assert_eq!(token.len(), n);
            });
        });
    }
}

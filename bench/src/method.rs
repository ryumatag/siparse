use std::hint::black_box as bb;

use criterion::Criterion;
use siparse::bench::{parse_method, Bytes};

use crate::benchmark;

pub(super) fn parse(c: &mut Criterion) {
    const NAME: &str = "parse/method";

    // Each input ends with a single SP that terminates the method token. The
    // returned token excludes that SP.
    let cases: [(_, &[u8]); _] = [
        ("ack", b"ACK "),
        ("bye", b"BYE "),
        ("invite", b"INVITE "),
        ("cancel", b"CANCEL "),
        ("options", b"OPTIONS "),
        ("register", b"REGISTER "),
        ("extension", b"X-CUSTOM-METHOD "),
    ];

    for (variant, input) in cases {
        let expected_len = input.len() - 1;
        benchmark(c, format!("{NAME}/{variant}"), expected_len as u64, |b| {
            b.iter(|| {
                let mut bytes = Bytes::new(bb(input));
                let token = bb(parse_method(&mut bytes).unwrap().unwrap());
                assert_eq!(token.len(), expected_len);
            });
        });
    }
}

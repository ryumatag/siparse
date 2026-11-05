use std::hint::black_box as bb;

use criterion::Criterion;
use siparse::bench::{parse_status_code, Bytes};

use crate::benchmark;

pub(super) fn parse(c: &mut Criterion) {
    // Every status code has three ASCII digits followed by SP, so one
    // benchmark covers this production.
    const NAME: &str = "parse/status_code";
    const INPUT: &[u8] = b"200 ";

    benchmark(c, NAME, 3, |b| {
        b.iter(|| {
            let mut bytes = Bytes::new(bb(INPUT));
            let token = bb(parse_status_code(&mut bytes).unwrap().unwrap());
            assert_eq!(token.len(), 3);
        });
    });
}

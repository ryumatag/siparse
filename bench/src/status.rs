use std::hint::black_box as bb;

use criterion::Criterion;

use crate::{
    benchmark,
    private::{parse_status_code, Bytes},
};

pub(super) fn parse(c: &mut Criterion) {
    // `parse_status_code` parsing is shape-uniform (always 3 ASCII digits
    // followed by a SP), so a single benchmark covers it.
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

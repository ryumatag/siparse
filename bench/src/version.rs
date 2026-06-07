use std::hint::black_box as bb;

use criterion::Criterion;

use crate::{
    benchmark,
    private::{parse_version, Bytes},
};

pub(super) fn parse(c: &mut Criterion) {
    const NAME: &str = "parse/version";

    // Each input ends with a single SP. The returned token covers only the
    // 7-byte SIP-Version token.
    let cases: [(_, &[u8]); _] = [
        ("upper_case", b"SIP/2.0 "),
        ("lower_case", b"sip/2.0 "),
        ("mixed_case", b"Sip/2.0 "),
    ];

    for (variant, input) in cases {
        benchmark(c, format!("{NAME}/{variant}"), 7, |b| {
            b.iter(|| {
                let mut bytes = Bytes::new(bb(input));
                let token = bb(parse_version(&mut bytes).unwrap().unwrap());
                assert_eq!(token.len(), 7);
            });
        });
    }
}

use std::hint::black_box as bb;

use criterion::Criterion;

use crate::{
    benchmark,
    private::{parse_header_name, Bytes},
};

pub(super) fn parse(c: &mut Criterion) {
    fixed_shape(c);
    sweep(c);
}

fn fixed_shape(c: &mut Criterion) {
    const NAME: &str = "parse/header_name";

    // Each input ends with `:`. The returned token excludes the colon.
    let cases: [(_, &[u8]); _] = [
        ("short", b"To:"),
        ("typical", b"Via:"),
        ("long", b"Content-Length:"),
        ("very_long", b"X-Some-Custom-Vendor-Specific-Header:"),
    ];

    for (variant, input) in cases {
        let expected_len = input.len() - 1;
        benchmark(c, format!("{NAME}/{variant}"), expected_len as u64, |b| {
            b.iter(|| {
                let mut bytes = Bytes::new(bb(input));
                let token =
                    bb(parse_header_name(&mut bytes).unwrap().unwrap());
                assert_eq!(token.len(), expected_len);
            });
        });
    }
}

// Geometric size sweep over `header-name` length. Borrowed from the `httparse`
// crate so we get the same shape of throughput curve to compare against.
fn sweep(c: &mut Criterion) {
    const NAME: &str = "parse/header_name/sweep";

    // All bytes in `CHUNK` are `token` characters, so any prefix is a
    // syntactically valid `header-name`.
    const CHUNK: &[u8] = b"X-Foobar";
    let chunk_4k = CHUNK.repeat(4096 / CHUNK.len() + 1);

    // 1B to 4096B in powers of two.
    for p in 0..=12 {
        let n = 1usize << p;
        let input: &'static [u8] =
            Box::leak([&chunk_4k[..n], b":"].concat().into_boxed_slice());

        benchmark(c, format!("{NAME}/{n:04}b"), n as u64, |b| {
            b.iter(|| {
                let mut bytes = Bytes::new(bb(input));
                let token =
                    bb(parse_header_name(&mut bytes).unwrap().unwrap());
                assert_eq!(token.len(), n);
            });
        });
    }
}

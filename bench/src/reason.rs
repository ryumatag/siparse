use std::hint::black_box as bb;

use criterion::Criterion;
use siparse::bench::{parse_reason_phrase, Bytes};

use crate::benchmark;

pub(super) fn parse(c: &mut Criterion) {
    fixed_shape(c);
    sweep(c);
}

fn fixed_shape(c: &mut Criterion) {
    const NAME: &str = "parse/reason_phrase";

    // Each input ends with `\r\n`. `parse_reason_phrase` returns a token that
    // stops at `\r`, so it excludes the trailing two bytes.
    let cases: [(_, &[u8]); _] = [
        ("ascii/short", b"OK\r\n"),
        ("ascii/typical", b"Not Found\r\n"),
        ("ascii/long", b"Request Entity Too Large For This Server\r\n"),
        ("escaped", b"100%20Trying\r\n"),
        ("utf8/japanese", "完了\r\n".as_bytes()),
        ("utf8/emoji", "OK \u{1f600}\r\n".as_bytes()),
    ];

    for (variant, input) in cases {
        let expected_len = input.len() - 2;
        benchmark(c, format!("{NAME}/{variant}"), expected_len as u64, |b| {
            b.iter(|| {
                let mut bytes = Bytes::new(bb(input));
                let token =
                    bb(parse_reason_phrase(&mut bytes).unwrap().unwrap());
                assert_eq!(token.len(), expected_len);
            });
        });
    }
}

// Geometric size sweep over `Reason-Phrase` length, in the same style as
// the `httparse` crate. This is the production with the widest accepted
// character set among the ASCII SWAR scans, so the curve also doubles as a
// check that the reason-phrase block predicate has not regressed.
fn sweep(c: &mut Criterion) {
    const NAME: &str = "parse/reason_phrase/sweep";

    // All bytes in `CHUNK` are accepted by `is_reason_phrase_octet`, so any
    // prefix is a syntactically valid `Reason-Phrase`.
    const CHUNK: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let chunk_4k = CHUNK.repeat(4096 / CHUNK.len() + 1);

    // 1B to 4096B in powers of two.
    for p in 0..=12 {
        let n = 1usize << p;
        let input: &'static [u8] =
            Box::leak([&chunk_4k[..n], b"\r\n"].concat().into_boxed_slice());

        benchmark(c, format!("{NAME}/{n:04}b"), n as u64, |b| {
            b.iter(|| {
                let mut bytes = Bytes::new(bb(input));
                let token =
                    bb(parse_reason_phrase(&mut bytes).unwrap().unwrap());
                assert_eq!(token.len(), n);
            });
        });
    }
}

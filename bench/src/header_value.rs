use std::hint::black_box as bb;

use criterion::Criterion;
use siparse::bench::{
    find_header_value_stop, find_header_value_stop_swar, parse_header_value,
    Bytes,
};

use crate::benchmark;

pub(super) fn parse(c: &mut Criterion) {
    fixed_shape(c);
    sweep(c);
    find_stop(c);
}

// The scan alone, with SIMD where the target has it and with SWAR only. SWAR
// is the fallback on other targets, so a regression there shows up here.
fn find_stop(c: &mut Criterion) {
    const NAME: &str = "find/header_value_stop";

    type Find = fn(&mut Bytes<'_>) -> usize;
    let finds: [(&str, Find); _] = [
        ("simd", find_header_value_stop),
        ("swar", find_header_value_stop_swar),
    ];
    let cases: [(_, &[u8]); _] = [
        ("typical", b"SIP/2.0/UDP host.example.com;branch=z9hG4bK\r\nX"),
        (
            "long",
            b"SIP/2.0/UDP host-1.example.com:5060;\
              branch=z9hG4bKabcdefghijklmnop;rport;\
              received=192.0.2.1\r\nX",
        ),
    ];

    for (variant, input) in cases {
        let expected = input.len() - 3;
        for (find_name, find) in finds {
            let id = format!("{NAME}/{variant}/{find_name}");
            benchmark(c, id, expected as u64, |b| {
                b.iter(|| {
                    let mut bytes = Bytes::new(bb(input));
                    assert_eq!(bb(find(&mut bytes)), expected);
                });
            });
        }
    }
}

fn fixed_shape(c: &mut Criterion) {
    const NAME: &str = "parse/header_value";

    // Each input ends with `\r\n` followed by one extra non-SP/non-HTAB byte.
    // The trailing byte lets `parse_header_value` decide that the value is
    // terminated rather than folded into the next line. The returned token
    // excludes that whole `\r\n + sentinel` tail.
    //
    // The `expected_len` column accounts for the variable interior of the
    // folded variant, where intermediate `\r\n SP` sequences stay inside the
    // value.
    let cases: [(_, &[u8], _); _] = [
        ("short", b"0\r\nX", 1),
        ("typical", b"SIP/2.0/UDP host.example.com;branch=z9hG4bK\r\nX", 43),
        (
            "long",
            // Rust collapses `\` + newline + leading whitespace into nothing
            // in byte string literals, so the actual on-wire bytes are one
            // contiguous Via value followed by `\r\nX`.
            b"SIP/2.0/UDP host-1.example.com:5060;\
              branch=z9hG4bKabcdefghijklmnop;rport;\
              received=192.0.2.1\r\nX",
            91,
        ),
        (
            "folded",
            b"I know you're there,\r\n pick up the phone\r\nX",
            // `I know you're there,` (20)
            //   + `\r\n` (2)
            //   + ` pick up the phone` (18) = 40.
            40,
        ),
        ("utf8/emoji", "\u{1f600}\u{1f600}\u{1f600}\r\nX".as_bytes(), 12),
        // One short non-ASCII run inside an otherwise ASCII value, as in a
        // display name.
        (
            "utf8/short",
            "\"\u{7530}\u{4e2d}\" <sip:tanaka@example.com>;tag=1928301774\r\nX"
                .as_bytes(),
            48,
        ),
        // A long contiguous run of 3-byte characters.
        (
            "utf8/cjk",
            "\u{65e5}\u{672c}\u{8a9e}\u{306e}\u{30c6}\u{30b9}\u{30c8}\
             \u{6587}\u{5b57}\u{5217}\u{3092}\u{9577}\u{304f}\u{3057}\
             \u{305f}\u{4ef6}\u{540d}\u{3067}\u{3059}\u{3002}\r\nX"
                .as_bytes(),
            60,
        ),
        // Many 1-character runs of 2-byte characters separated by ASCII, so
        // that the cost of entering and leaving the run dominates.
        (
            "utf8/mixed",
            "caf\u{e9} cr\u{e8}me d\u{e9}j\u{e0} vu \u{e0} la \u{e7}a \
             na\u{ef}ve r\u{e9}sum\u{e9}\r\nX"
                .as_bytes(),
            48,
        ),
    ];

    for (variant, input, expected_len) in cases {
        benchmark(c, format!("{NAME}/{variant}"), expected_len as u64, |b| {
            b.iter(|| {
                let mut bytes = Bytes::new(bb(input));
                let token =
                    bb(parse_header_value(&mut bytes).unwrap().unwrap());
                assert_eq!(token.len(), expected_len);
            });
        });
    }
}

// Geometric size sweep over `header-value` length. Borrowed from the
// `httparse` crate.
fn sweep(c: &mut Criterion) {
    const NAME: &str = "parse/header_value/sweep";

    // All bytes in `CHUNK` are printable ASCII accepted by
    // `is_header_value_ascii`, so any prefix is a syntactically valid
    // single-line `header-value`.
    const CHUNK: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let chunk_4k = CHUNK.repeat(4096 / CHUNK.len() + 1);

    // 1B to 4096B in powers of two.
    for p in 0..=12 {
        let n = 1usize << p;
        // Append `\r\nX` so the parser can decide the value is terminated
        // rather than folded into the next line. The trailing `X` is the
        // sentinel byte. It is not part of the returned token.
        let input: &'static [u8] =
            Box::leak([&chunk_4k[..n], b"\r\nX"].concat().into_boxed_slice());

        benchmark(c, format!("{NAME}/{n:04}b"), n as u64, |b| {
            b.iter(|| {
                let mut bytes = Bytes::new(bb(input));
                let token =
                    bb(parse_header_value(&mut bytes).unwrap().unwrap());
                assert_eq!(token.len(), n);
            });
        });
    }
}

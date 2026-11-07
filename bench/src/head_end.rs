use std::hint::black_box as bb;

use criterion::Criterion;

use crate::benchmark;

const HEAD_END: &[u8] = b"\r\n\r\n";

type Find = fn(&[u8], usize) -> Option<usize>;

/// The crate's search, with SIMD where the target has it.
fn simd(buf: &[u8], scanned: usize) -> Option<usize> {
    siparse::find_head_end(buf, scanned)
}

/// The crate's search with SWAR only, the fallback on other targets.
fn swar(buf: &[u8], scanned: usize) -> Option<usize> {
    siparse::bench::find_head_end_swar(buf, scanned)
}

/// One window at a time, with the same overlap rule.
fn scalar(buf: &[u8], scanned: usize) -> Option<usize> {
    let start = scanned.saturating_sub(HEAD_END.len() - 1);
    buf[start..]
        .windows(HEAD_END.len())
        .position(|window| window == HEAD_END)
        .map(|i| start + i + HEAD_END.len())
}

/// The `memchr` crate's SIMD substring search, with the same overlap rule.
fn memmem(buf: &[u8], scanned: usize) -> Option<usize> {
    let start = scanned.saturating_sub(HEAD_END.len() - 1);
    memchr::memmem::find(&buf[start..], HEAD_END)
        .map(|i| start + i + HEAD_END.len())
}

// `scalar` and `memmem` are yardsticks for `find_head_end`, not part of the
// crate. They show whether the crate's scans still earn their place against a
// plain loop and a general SIMD substring search on inputs of this size.
pub(super) fn find(c: &mut Criterion) {
    const NAME: &str = "find/head_end";

    const TYPICAL: &[u8] = b"INVITE sip:bob@example.com SIP/2.0\r\n\
        Via: SIP/2.0/UDP host.example.com;branch=z9hG4bK\r\n\
        From: <sip:alice@example.com>;tag=1928301774\r\n\
        To: <sip:bob@example.com>\r\n\
        Call-ID: a84b4c76e66710\r\n\
        CSeq: 314159 INVITE\r\n\
        Contact: <sip:alice@pc33.example.com>\r\n\
        Max-Forwards: 70\r\n\
        Content-Type: application/sdp\r\n\
        Content-Length: 0\r\n\
        \r\n";

    // The whole head in one read, a head still missing its last two bytes,
    // and a read of 64 bytes onto that unfinished head. The last one scans
    // only the new bytes plus the overlap.
    let partial = &TYPICAL[..TYPICAL.len() - 2];
    let cases: [(&str, &[u8], usize, Option<usize>); _] = [
        ("typical", TYPICAL, 0, Some(TYPICAL.len())),
        ("partial", partial, 0, None),
        ("incremental", partial, partial.len() - 64, None),
    ];
    let finds: [(&str, Find); _] = [
        ("simd", simd),
        ("swar", swar),
        ("scalar", scalar),
        ("memmem", memmem),
    ];

    for (category, input, scanned, expected) in cases {
        let start = scanned.saturating_sub(HEAD_END.len() - 1);
        let throughput = (input.len() - start) as u64;
        for (variant, find) in finds {
            let id = format!("{NAME}/{category}/{variant}");
            benchmark(c, id, throughput, |b| {
                b.iter(|| {
                    assert_eq!(bb(find(bb(input), bb(scanned))), expected);
                });
            });
        }
    }
}

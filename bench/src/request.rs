use std::hint::black_box as bb;

use criterion::Criterion;
use siparse::{Header, RequestHead, Status};

use crate::benchmark;

pub(super) fn parse(c: &mut Criterion) {
    fixed_shape(c);
    corpus(c);
}

fn fixed_shape(c: &mut Criterion) {
    const NAME: &str = "parse/request_head";

    let cases: [(_, &[u8], _); _] = [
        (
            "minimal",
            b"INVITE sip:bob@example.com SIP/2.0\r\n\
              Content-Length: 0\r\n\
              \r\n",
            1,
        ),
        (
            "typical",
            b"INVITE sip:bob@example.com SIP/2.0\r\n\
              Via: SIP/2.0/UDP host.example.com;branch=z9hG4bK\r\n\
              From: <sip:alice@example.com>;tag=1928301774\r\n\
              To: <sip:bob@example.com>\r\n\
              Call-ID: a84b4c76e66710\r\n\
              CSeq: 314159 INVITE\r\n\
              Contact: <sip:alice@pc33.example.com>\r\n\
              Max-Forwards: 70\r\n\
              Content-Type: application/sdp\r\n\
              Content-Length: 0\r\n\
              \r\n",
            9,
        ),
        // The `typical` head with non-ASCII display names and subject. The
        // UTF-8 bytes appear as short runs inside otherwise ASCII values.
        (
            "typical/utf8",
            "INVITE sip:bob@example.com SIP/2.0\r\n\
             Via: SIP/2.0/UDP host.example.com;branch=z9hG4bK\r\n\
             From: \"\u{7530}\u{4e2d}\" <sip:alice@example.com>;tag=1928301774\r\n\
             To: \"Bj\u{f6}rn \u{c5}ngstr\u{f6}m\" <sip:bob@example.com>\r\n\
             Call-ID: a84b4c76e66710\r\n\
             CSeq: 314159 INVITE\r\n\
             Subject: \u{4f1a}\u{8b70}\u{306e}\u{4ef6} \u{1f4de}\r\n\
             Contact: <sip:alice@pc33.example.com>\r\n\
             Max-Forwards: 70\r\n\
             Content-Type: application/sdp\r\n\
             Content-Length: 0\r\n\
             \r\n"
                .as_bytes(),
            10,
        ),
    ];

    for (variant, input, header_count) in cases {
        let expected_end = input.len();
        // Reused storage. Each parse only borrows it for the duration of the
        // call.
        let mut storage = vec![Header::EMPTY; 32];
        benchmark(c, format!("{NAME}/{variant}"), input.len() as u64, |b| {
            b.iter(|| {
                let status =
                    RequestHead::parse(bb(input), &mut storage).unwrap();
                let Status::Complete((head, end)) = bb(status) else {
                    panic!("expected Complete, got Partial");
                };
                assert_eq!(end, expected_end);
                assert_eq!(head.headers.len(), header_count);
            });
        });
    }
}

// Requests that vary in method, header set and value lengths. See
// `corpus.rs` for why this matters next to the fixed shapes above.
fn corpus(c: &mut Criterion) {
    let messages = crate::corpus::requests();
    let total_bytes = messages.iter().map(|m| m.len() as u64).sum();

    let mut storage = vec![Header::EMPTY; 32];
    benchmark(c, "parse/request_head/corpus", total_bytes, |b| {
        b.iter(|| {
            for msg in &messages {
                let status =
                    RequestHead::parse(bb(msg), &mut storage).unwrap();
                let Status::Complete((_, end)) = bb(status) else {
                    panic!("expected Complete, got Partial");
                };
                assert_eq!(end, msg.len());
            }
        });
    });
}

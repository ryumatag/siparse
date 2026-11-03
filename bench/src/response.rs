use std::hint::black_box as bb;

use criterion::Criterion;
use siparse::{HeaderBuf, ResponseHead, Status};

use crate::benchmark;

pub(super) fn parse(c: &mut Criterion) {
    fixed_shape(c);
    corpus(c);
}

fn fixed_shape(c: &mut Criterion) {
    const NAME: &str = "parse/response_head";

    let cases: [(_, &[u8], _); _] = [
        (
            "minimal",
            b"SIP/2.0 200 OK\r\n\
              Content-Length: 0\r\n\
              \r\n",
            1,
        ),
        (
            "typical",
            b"SIP/2.0 200 OK\r\n\
              Via: SIP/2.0/UDP host.example.com;branch=z9hG4bK\r\n\
              From: <sip:alice@example.com>;tag=1928301774\r\n\
              To: <sip:bob@example.com>;tag=a6c85cf\r\n\
              Call-ID: a84b4c76e66710\r\n\
              CSeq: 314159 INVITE\r\n\
              Contact: <sip:bob@192.0.2.4>\r\n\
              Content-Type: application/sdp\r\n\
              Content-Length: 0\r\n\
              \r\n",
            8,
        ),
    ];

    for (variant, input, header_count) in cases {
        let expected_end = input.len();
        // Reused storage. Every parse resets the head first.
        let mut headers = HeaderBuf::<32>::new();
        let mut head = ResponseHead::new(&mut headers);
        benchmark(c, format!("{NAME}/{variant}"), input.len() as u64, |b| {
            b.iter(|| {
                let status = head.parse(bb(input)).unwrap();
                let Status::Complete(end) = bb(status) else {
                    panic!("expected Complete, got Partial");
                };
                assert_eq!(end, expected_end);
                assert_eq!(head.headers.len(), header_count);
            });
        });
    }
}

// Responses that vary in status, header set and value lengths. See
// `corpus.rs` for why this matters next to the fixed shapes above.
fn corpus(c: &mut Criterion) {
    let messages = crate::corpus::responses();
    let total_bytes = messages.iter().map(|m| m.len() as u64).sum();

    let mut headers = HeaderBuf::<32>::new();
    let mut head = ResponseHead::new(&mut headers);
    benchmark(c, "parse/response_head/corpus", total_bytes, |b| {
        b.iter(|| {
            for msg in &messages {
                let status = head.parse(bb(msg)).unwrap();
                let Status::Complete(end) = bb(status) else {
                    panic!("expected Complete, got Partial");
                };
                assert_eq!(end, msg.len());
            }
        });
    });
}

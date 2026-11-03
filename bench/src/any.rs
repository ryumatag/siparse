use std::hint::black_box as bb;

use criterion::Criterion;
use siparse::{AnyHead, HeaderBuf, Status};

use crate::benchmark;

pub(super) fn parse(c: &mut Criterion) {
    corpus(c);
}

// Requests and responses interleaved, as a socket that carries both would see
// them. Compare against the sum of the request and response corpus
// benchmarks to see what deciding the kind costs.
fn corpus(c: &mut Criterion) {
    let requests = crate::corpus::requests();
    let responses = crate::corpus::responses();
    let messages: Vec<_> = requests
        .iter()
        .zip(&responses)
        .flat_map(|(request, response)| [request, response])
        .chain(requests.iter().skip(responses.len()))
        .chain(responses.iter().skip(requests.len()))
        .collect();
    let total_bytes = messages.iter().map(|m| m.len() as u64).sum();

    let mut headers = HeaderBuf::<32>::new();
    let mut head = AnyHead::new(&mut headers);
    benchmark(c, "parse/any_head/corpus", total_bytes, |b| {
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

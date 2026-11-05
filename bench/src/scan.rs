use std::hint::black_box as bb;

use criterion::Criterion;
use siparse::scan;

use crate::benchmark;

type Scan = fn(&str) -> Option<(&str, &str)>;

pub(super) fn scan(c: &mut Criterion) {
    // Each element as it appears in a typical value, followed by what ends
    // it. The throughput counts the element alone.
    let cases: [(&str, &str, Scan); _] = [
        ("token", "z9hG4bK776asdhds;rport", scan::token),
        ("digits", "314159 INVITE", scan::digits),
        ("host/name", "pc33.atlanta.example.com;branch=z9hG4bK", scan::host),
        ("host/ipv6", "[2001:db8::192.0.2.4]:5060", scan::host),
        (
            "quoted_string",
            "\"Bob \\\"B\\\" Smith\" <sip:bob@biloxi.example.com>",
            scan::quoted_string,
        ),
    ];

    for (thing, input, f) in cases {
        let (element, _) = f(input).unwrap();
        let len = element.len();
        benchmark(c, format!("scan/{thing}"), len as u64, |b| {
            b.iter(|| {
                let (element, rest) = bb(f(bb(input))).unwrap();
                assert_eq!(element.len(), len);
                assert_eq!(element.len() + rest.len(), input.len());
            });
        });
    }
}

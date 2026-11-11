use std::hint::black_box as bb;

use criterion::Criterion;
use siparse::value;

use crate::benchmark;

pub(super) fn value(c: &mut Criterion) {
    // From and To values in each form, with the tag a dialog needs. The
    // throughput counts the whole value.
    let addresses = [
        ("addr_spec", "sip:alice@atlanta.example.com;tag=1928301774"),
        ("name_addr", "Alice <sip:alice@atlanta.example.com>;tag=1928301774"),
        (
            "quoted",
            "\"Bob \\\"B\\\" Smith\" <sip:bob@biloxi.example.com>;tag=a6c85cf",
        ),
    ];

    for (category, input) in addresses {
        let uri_len = value::address(input).unwrap().uri.len();
        benchmark(
            c,
            format!("value/address/{category}"),
            input.len() as u64,
            |b| {
                b.iter(|| {
                    let address = bb(value::address(bb(input))).unwrap();
                    assert_eq!(address.uri.len(), uri_len);
                });
            },
        );
    }

    // A Record-Route a proxy chain leaves, read address by address.
    let route = concat!(
        "<sip:p1.example.com;lr>, <sip:p2.example.com;lr;transport=tcp>,",
        "\r\n <sip:[2001:db8::1]:5060;lr>",
    );
    benchmark(c, "value/addresses/route", route.len() as u64, |b| {
        b.iter(|| {
            let mut count = 0;
            for item in value::addresses(bb(route)) {
                bb(item.unwrap());
                count += 1;
            }
            assert_eq!(count, 3);
        });
    });

    // The top Via a transaction key needs, alone and with what a server and
    // proxies add.
    let vias = [
        (
            "typical",
            "SIP/2.0/UDP pc33.atlanta.example.com:5060;branch=z9hG4bK776asdhds",
            1,
        ),
        (
            "full",
            concat!(
                "SIP/2.0/UDP [2001:db8::1]:5060;branch=z9hG4bK776asdhds;rport=5060",
                ";received=2001:db8::9, SIP/2.0/TCP proxy.example.com;branch=z9hG4bKa1",
            ),
            2,
        ),
    ];
    for (category, input, count) in vias {
        benchmark(
            c,
            format!("value/via_parms/{category}"),
            input.len() as u64,
            |b| {
                b.iter(|| {
                    let mut n = 0;
                    for item in value::via_parms(bb(input)) {
                        bb(item.unwrap());
                        n += 1;
                    }
                    assert_eq!(n, count);
                });
            },
        );
    }

    // The values that match a response to its transaction and a request to
    // its dialog.
    let cseq = "314159 INVITE";
    benchmark(c, "value/cseq", cseq.len() as u64, |b| {
        b.iter(|| {
            let found = bb(value::cseq(bb(cseq))).unwrap();
            assert_eq!(found.number.len(), 6);
        });
    });

    let call_id = "a84b4c76e66710@pc33.atlanta.example.com";
    benchmark(c, "value/call_id", call_id.len() as u64, |b| {
        b.iter(|| {
            let found = bb(value::call_id(bb(call_id))).unwrap();
            assert_eq!(found.len(), call_id.len());
        });
    });

    // Parameters as they follow a Via's `sent-by`, read and walked.
    let params = ";branch=z9hG4bK776asdhds;rport;received=192.0.2.4;ttl=16";
    benchmark(c, "value/params/typical", params.len() as u64, |b| {
        b.iter(|| {
            let (list, rest) = bb(value::params(bb(params))).unwrap();
            assert_eq!(list.iter().count(), 4);
            assert_eq!(rest, "");
        });
    });
}

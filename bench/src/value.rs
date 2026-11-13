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

    // The top Via of a request a proxy has filled in, with every parameter a
    // transaction layer reads and an extension, walked the way it reads them.
    let proxied = concat!(
        "SIP/2.0/UDP 192.0.2.4:5060;ttl=16;maddr=224.2.0.1;received=192.0.2.207",
        ";rport=49154;branch=z9hG4bK776asdhds;x-trace=\"a;b\",",
        "SIP/2.0/UDP pc33.atlanta.example.com;branch=z9hG4bK776asdhdt",
    );
    benchmark(c, "value/via_parms/proxied", proxied.len() as u64, |b| {
        b.iter(|| {
            let top = value::via_parms(bb(proxied)).next().unwrap().unwrap();
            let mut n = 0;
            for param in bb(top).params {
                bb(param);
                n += 1;
            }
            assert_eq!(n, 6);
        });
    });

    // The same, with the parameters read as they are checked.
    benchmark(c, "value/via_parm/proxied", proxied.len() as u64, |b| {
        b.iter(|| {
            let mut top = value::via_parm(bb(proxied)).unwrap();
            let mut n = 0;
            for param in &mut top {
                bb(param.unwrap());
                n += 1;
            }
            assert_eq!(bb(top.text()).len(), 120);
            assert_eq!(n, 6);
        });
    });

    // The Content-Type of an offer, and the Accept of a UA that takes SDP and
    // multipart bodies.
    let content_type = "application/sdp";
    benchmark(c, "value/media_type", content_type.len() as u64, |b| {
        b.iter(|| {
            let found = bb(value::media_type(bb(content_type))).unwrap();
            assert_eq!(found.subtype.len(), 3);
        });
    });

    let accept = "application/sdp, multipart/mixed;q=0.5, */*;q=0.1";
    benchmark(c, "value/media_ranges", accept.len() as u64, |b| {
        b.iter(|| {
            let mut n = 0;
            for item in value::media_ranges(bb(accept)) {
                bb(item.unwrap());
                n += 1;
            }
            assert_eq!(n, 3);
        });
    });

    // A Digest challenge and the credentials that answer it.
    let auth = [
        (
            "challenge",
            "Digest realm=\"atlanta.example.com\", qop=\"auth\", \
             nonce=\"f84f1cec41e6cbe5aea9c8e88d359\", opaque=\"\", algorithm=MD5",
            value::challenge as fn(&str) -> Result<value::Auth<'_>, siparse::Error>,
            5,
        ),
        (
            "credentials",
            "Digest username=\"bob\", realm=\"atlanta.example.com\", \
             nonce=\"f84f1cec41e6cbe5aea9c8e88d359\", uri=\"sip:bob@biloxi.example.com\", \
             qop=auth, nc=00000001, cnonce=\"0a4f113b\", \
             response=\"6629fae49393a05397450978507c4ef1\"",
            value::credentials,
            8,
        ),
    ];
    for (thing, input, read, count) in auth {
        benchmark(c, format!("value/{thing}"), input.len() as u64, |b| {
            b.iter(|| {
                let found = bb(read(bb(input))).unwrap();
                assert_eq!(found.params.iter().count(), count);
            });
        });
    }

    // A Content-Disposition, and the Reason a forking proxy puts in its
    // CANCEL.
    let disposition = "session;handling=required";
    benchmark(c, "value/token_param", disposition.len() as u64, |b| {
        b.iter(|| {
            let found = bb(value::token_param(bb(disposition))).unwrap();
            assert_eq!(found.token.len(), 7);
        });
    });

    let reason =
        "SIP;cause=200;text=\"Call completed elsewhere\", Q.850;cause=16";
    benchmark(c, "value/token_params", reason.len() as u64, |b| {
        b.iter(|| {
            let mut n = 0;
            for item in value::token_params(bb(reason)) {
                bb(item.unwrap());
                n += 1;
            }
            assert_eq!(n, 2);
        });
    });

    // The option tags a UA lists in Supported.
    let tags = "100rel, timer, replaces, norefersub";
    benchmark(c, "value/tokens", tags.len() as u64, |b| {
        b.iter(|| {
            let mut n = 0;
            for item in value::tokens(bb(tags)) {
                bb(item.unwrap());
                n += 1;
            }
            assert_eq!(n, 4);
        });
    });

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

    // The Replaces of an attended transfer.
    let replaces = "98732@sip.example.com;from-tag=r33th4x0r;to-tag=ff87ff";
    benchmark(c, "value/call_id_params", replaces.len() as u64, |b| {
        b.iter(|| {
            let found = bb(value::call_id_params(bb(replaces))).unwrap();
            assert_eq!(found.call_id.len(), 21);
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

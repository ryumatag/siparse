//! Varied but deterministic SIP heads for the `corpus` benchmarks.
//!
//! Parsing one fixed head over and over lets the branch predictor learn
//! every branch the parser takes on it, including the data-dependent exits
//! of the SWAR scans. Real traffic does not repeat like that. A corpus of
//! heads that differ in header set, order, value lengths, compact forms and
//! occasional UTF-8 keeps those branches honest.
//!
//! The corpus deliberately stays small enough to remain in cache. A server
//! parses a head right after `recv` has written it, so warm input data is
//! the realistic case.
//!
//! Two profiles share the generator. `Edge` heads look like those between
//! user agents and a proxy, about 470 bytes on average. `Carrier` heads look
//! like those inside an operator or IMS core, where proxies stack `Via` and
//! `Record-Route` rows and add credentials and `P-` headers. They run to 1 to
//! 2 KB, with many values longer than a SWAR block or two, which is where a
//! wider scan would pay off.

use std::fmt::Write as _;

use rand::{
    rngs::StdRng,
    seq::{IndexedRandom, SliceRandom},
    RngExt, SeedableRng,
};

/// Number of heads in each corpus.
const SIZE: usize = 512;

/// The kind of traffic a corpus imitates. See the module docs.
#[derive(Clone, Copy, PartialEq)]
pub(crate) enum Profile {
    Edge,
    Carrier,
}

/// Returns the request heads of the corpus.
pub(crate) fn requests(profile: Profile) -> Vec<Vec<u8>> {
    let mut rng = StdRng::seed_from_u64(seed(1, profile));
    (0..size(profile))
        .map(|_| request(&mut rng, profile).into_bytes())
        .collect()
}

/// Returns the response heads of the corpus.
pub(crate) fn responses(profile: Profile) -> Vec<Vec<u8>> {
    let mut rng = StdRng::seed_from_u64(seed(2, profile));
    (0..size(profile))
        .map(|_| response(&mut rng, profile).into_bytes())
        .collect()
}

fn seed(seed: u64, profile: Profile) -> u64 {
    match profile {
        Profile::Edge => seed,
        Profile::Carrier => seed + 100,
    }
}

// Carrier heads are about three times longer. Half as many keep the corpus
// at a similar size in cache.
fn size(profile: Profile) -> usize {
    match profile {
        Profile::Edge => SIZE,
        Profile::Carrier => SIZE / 2,
    }
}

fn request(rng: &mut StdRng, profile: Profile) -> String {
    // Rough proportions of a busy SIP edge, plus one extension method.
    const METHODS: &[(&str, u32)] = &[
        ("INVITE", 20),
        ("ACK", 20),
        ("BYE", 15),
        ("REGISTER", 15),
        ("OPTIONS", 10),
        ("NOTIFY", 6),
        ("CANCEL", 4),
        ("SUBSCRIBE", 4),
        ("MESSAGE", 4),
        ("X-CUSTOM-METHOD", 2),
    ];

    let method = METHODS.choose_weighted(rng, |m| m.1).unwrap().0;
    let uri = if method == "REGISTER" {
        format!("sip:{}", host(rng))
    } else {
        request_uri(rng)
    };
    let max_forwards = format!("Max-Forwards: {}", rng.random_range(60..=70));
    // Only in-dialog requests carry a `To` tag.
    let to_tag = rng.random_bool(0.3);

    let mut rows = vec![max_forwards];
    if profile == Profile::Carrier && !matches!(method, "ACK" | "CANCEL") {
        rows.push(format!(
            "Authorization: Digest username=\"{}\", realm=\"{}\", \
             nonce=\"{}\", uri=\"{uri}\", response=\"{}\", \
             algorithm=MD5, cnonce=\"{}\", qop=auth, nc=00000001",
            user(rng),
            host(rng),
            token(rng, 32, 48),
            token(rng, 32, 32),
            token(rng, 16, 16),
        ));
    }

    let mut head = format!("{method} {uri} SIP/2.0\r\n");
    head += &header_block(rng, method, to_tag, rows, profile);
    head
}

fn response(rng: &mut StdRng, profile: Profile) -> String {
    const STATUSES: &[(&str, u32)] = &[
        ("100 Trying", 10),
        ("180 Ringing", 15),
        ("183 Session Progress", 5),
        ("200 OK", 45),
        ("401 Unauthorized", 8),
        ("404 Not Found", 5),
        ("486 Busy Here", 5),
        ("487 Request Terminated", 4),
        ("503 Service Unavailable", 3),
    ];
    const METHODS: &[&str] = &["INVITE", "REGISTER", "BYE", "OPTIONS"];

    let status = STATUSES.choose_weighted(rng, |s| s.1).unwrap().0;
    let method = METHODS.choose(rng).unwrap();

    let mut extra = Vec::new();
    if status.starts_with("401") {
        extra.push(format!(
            "WWW-Authenticate: Digest realm=\"{}\", nonce=\"{}\", \
             algorithm=MD5, qop=\"auth\"",
            host(rng),
            token(rng, 32, 32),
        ));
    }
    if status.starts_with("503") {
        extra.push(format!("Retry-After: {}", rng.random_range(5..=120)));
    }

    let mut head = format!("SIP/2.0 {status}\r\n");
    // Every response except `100 Trying` echoes a `To` tag.
    head +=
        &header_block(rng, method, !status.starts_with("100"), extra, profile);
    head
}

/// Returns the header rows and the empty line that ends the head.
///
/// `Via` rows come first and `Content-Length` last, as most stacks emit
/// them. The rows in between are shuffled.
fn header_block(
    rng: &mut StdRng,
    method: &str,
    to_tag: bool,
    mut rows: Vec<String>,
    profile: Profile,
) -> String {
    let compact = rng.random_bool(0.2);
    let name = |full, short| if compact { short } else { full };

    rows.push(format!("{}: {}", name("From", "f"), name_addr(rng, true)));
    rows.push(format!("{}: {}", name("To", "t"), name_addr(rng, to_tag)));
    rows.push(format!("{}: {}", name("Call-ID", "i"), call_id(rng)));
    rows.push(format!("CSeq: {} {method}", rng.random_range(1..=99999)));

    if rng.random_bool(0.7) {
        rows.push(format!("{}: {}", name("Contact", "m"), contact(rng)));
    }
    if profile == Profile::Carrier {
        // Each proxy on the path records itself with its own parameters.
        for _ in 0..rng.random_range(2..=4) {
            rows.push(format!(
                "Record-Route: <sip:{};lr;ftag={};did={}>",
                host(rng),
                token(rng, 8, 12),
                token(rng, 10, 16),
            ));
        }
        rows.push(format!(
            "P-Charging-Vector: icid-value={};icid-generated-at=192.0.2.{};\
             orig-ioi={}",
            token(rng, 32, 40),
            rng.random_range(1..=254),
            host(rng),
        ));
        rows.push(format!(
            "P-Access-Network-Info: 3GPP-E-UTRAN-FDD;\
             utran-cell-id-3gpp=44010{}",
            rng.random_range(100_000_000..=999_999_999u32),
        ));
        rows.push(
            "Accept-Contact: *;+g.3gpp.icsi-ref=\
             \"urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel\""
                .to_owned(),
        );
    } else if rng.random_bool(0.2) {
        for _ in 0..rng.random_range(1..=2) {
            rows.push(format!("Record-Route: <sip:{};lr>", host(rng)));
        }
    }
    if rng.random_bool(0.5) {
        const AGENTS: &[&str] = &[
            "siparse-bench/1.0",
            "PolycomVVX-VVX_411-UA/6.3.1.8427",
            "Asterisk PBX 20.5.0",
            "FreeSWITCH-mod_sofia/1.10.11",
        ];
        rows.push(format!("User-Agent: {}", AGENTS.choose(rng).unwrap()));
    }
    if rng.random_bool(0.3) {
        // Some stacks fold long list values onto a continuation line.
        let allow = if rng.random_bool(0.3) {
            "INVITE, ACK, CANCEL, BYE,\r\n OPTIONS, NOTIFY, REFER"
        } else {
            "INVITE, ACK, CANCEL, BYE, OPTIONS, NOTIFY, REFER"
        };
        rows.push(format!("Allow: {allow}"));
    }
    if rng.random_bool(0.4) {
        rows.push(format!(
            "{}: replaces, timer, 100rel",
            name("Supported", "k")
        ));
    }
    if rng.random_bool(0.15) {
        const SUBJECTS: &[&str] = &[
            "Project review",
            "Weekly sync",
            "\u{4f1a}\u{8b70}\u{306e}\u{4ef6} \u{1f4de}",
            "Re: Angebot f\u{fc}r Bj\u{f6}rn",
        ];
        let subject = SUBJECTS.choose(rng).unwrap();
        rows.push(format!("{}: {subject}", name("Subject", "s")));
    }
    if profile == Profile::Carrier || rng.random_bool(0.2) {
        rows.push(format!("P-Asserted-Identity: {}", name_addr(rng, false)));
    }

    let content_length = if rng.random_bool(0.3) {
        rows.push(format!("{}: application/sdp", name("Content-Type", "c")));
        rng.random_range(200..=900)
    } else {
        0
    };

    rows.shuffle(rng);

    let mut block = String::new();
    let vias = match profile {
        Profile::Edge => 1..=3,
        Profile::Carrier => 3..=6,
    };
    for _ in 0..rng.random_range(vias) {
        let _ = write!(block, "{}: {}\r\n", name("Via", "v"), via(rng));
    }
    for row in rows {
        let _ = write!(block, "{row}\r\n");
    }
    let _ = write!(
        block,
        "{}: {content_length}\r\n\r\n",
        name("Content-Length", "l"),
    );
    block
}

fn request_uri(rng: &mut StdRng) -> String {
    match rng.random_range(0..10) {
        0 => format!("tel:+81{}", rng.random_range(100_000_000..=999_999_999)),
        1 => format!("sips:{}@{}", user(rng), host(rng)),
        2 => format!("sip:{}@{};transport=tcp", user(rng), host(rng)),
        _ => format!("sip:{}@{}", user(rng), host(rng)),
    }
}

fn via(rng: &mut StdRng) -> String {
    let transport = ["UDP", "TCP", "TLS"].choose(rng).unwrap();
    let mut via = format!(
        "SIP/2.0/{transport} {}:{};branch=z9hG4bK{}",
        host(rng),
        rng.random_range(5060..=5080),
        token(rng, 8, 24),
    );
    if rng.random_bool(0.3) {
        via += ";rport";
    }
    if rng.random_bool(0.2) {
        let _ = write!(via, ";received=192.0.2.{}", rng.random_range(1..=254));
    }
    via
}

fn name_addr(rng: &mut StdRng, tag: bool) -> String {
    const DISPLAY_NAMES: &[&str] = &[
        "Alice",
        "Bob Smith",
        "Support Desk",
        "\u{7530}\u{4e2d} \u{592a}\u{90ce}",
        "Bj\u{f6}rn \u{c5}ngstr\u{f6}m",
    ];

    let addr = format!("sip:{}@{}", user(rng), host(rng));
    let mut name_addr = match rng.random_range(0..10) {
        0..4 => {
            let display = DISPLAY_NAMES.choose(rng).unwrap();
            format!("\"{display}\" <{addr}>")
        }
        4..9 => format!("<{addr}>"),
        _ => addr,
    };
    if tag {
        let _ = write!(name_addr, ";tag={}", token(rng, 6, 12));
    }
    name_addr
}

fn contact(rng: &mut StdRng) -> String {
    let transport = ["udp", "tcp"].choose(rng).unwrap();
    let mut contact = format!(
        "<sip:{}@192.0.2.{}:{};transport={transport}>",
        user(rng),
        rng.random_range(1..=254),
        rng.random_range(5060..=5080),
    );
    if rng.random_bool(0.3) {
        contact += ";expires=3600";
    }
    contact
}

fn call_id(rng: &mut StdRng) -> String {
    let mut call_id = token(rng, 8, 32);
    if rng.random_bool(0.5) {
        let _ = write!(call_id, "@{}", host(rng));
    }
    call_id
}

fn user(rng: &mut StdRng) -> &'static str {
    const USERS: &[&str] =
        &["alice", "bob", "carol", "support", "+81312345678", "0312345678"];
    USERS.choose(rng).unwrap()
}

fn host(rng: &mut StdRng) -> &'static str {
    const HOSTS: &[&str] = &[
        "example.com",
        "atlanta.example.com",
        "biloxi.example.com",
        "sip.carrier.example.net",
        "192.0.2.4",
        "[2001:db8::10]",
    ];
    HOSTS.choose(rng).unwrap()
}

/// Returns a random alphanumeric string of `min..=max` bytes.
fn token(rng: &mut StdRng, min: usize, max: usize) -> String {
    const ALPHANUMERIC: &[u8] =
        b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    let len = rng.random_range(min..=max);
    (0..len).map(|_| *ALPHANUMERIC.choose(rng).unwrap() as char).collect()
}

/*!
Shared host syntax from RFC 3261, corrected by RFC 5954.

These checks validate structure without converting or normalizing the text.
*/

/// Returns whether `src` is a `host`: a hostname, an IPv4 address, or an IPv6
/// address in brackets.
///
/// RFC 3261, Section 25.1, with the IP addresses of RFC 5954:
///
/// ```text
/// host         =  hostname / IPv4address / IPv6reference
/// hostname     =  *( domainlabel "." ) toplabel [ "." ]
/// domainlabel  =  alphanum / alphanum *( alphanum / "-" ) alphanum
/// toplabel     =  ALPHA / ALPHA *( alphanum / "-" ) alphanum
/// ```
///
/// RFC 5954 replaces RFC 3261's `IPv4address`, which allowed octets above 255,
/// with that of RFC 3986, and corrects `IPv6address` to match RFC 3986 too.
pub(crate) fn is_host(src: &str) -> bool {
    if let Some(address) = src.strip_prefix('[') {
        return address.strip_suffix(']').map_or(false, is_ipv6);
    }
    if is_ipv4(src) {
        return true;
    }

    is_hostname(src)
}

/// Returns whether `src` is a `hostname`, which RFC 3966 calls a
/// `domainname`.
pub(crate) fn is_hostname(src: &str) -> bool {
    let name = src.strip_suffix('.').unwrap_or(src);
    let top = name.rsplit('.').next().unwrap_or("");
    if !top.as_bytes().first().map_or(false, u8::is_ascii_alphabetic) {
        return false;
    }
    name.split('.').all(|label| {
        let bytes = label.as_bytes();
        bytes.first().map_or(false, u8::is_ascii_alphanumeric)
            && bytes.last().map_or(false, u8::is_ascii_alphanumeric)
            && bytes.iter().all(|&b| b.is_ascii_alphanumeric() || b == b'-')
    })
}

/// Returns whether `src` is an RFC 3986 `IPv4address`.
///
/// ```text
/// IPv4address  =  dec-octet "." dec-octet "." dec-octet "." dec-octet
/// dec-octet    =  DIGIT / %x31-39 DIGIT / "1" 2DIGIT / "2" %x30-34 DIGIT
///                 / "25" %x30-35
/// ```
///
/// So each octet is 0 to 255, with no leading zero.
fn is_ipv4(src: &str) -> bool {
    let mut octets = 0;
    for octet in src.split('.') {
        let bytes = octet.as_bytes();
        let valid = match bytes {
            [d] => d.is_ascii_digit(),
            [b'1'..=b'9', d] => d.is_ascii_digit(),
            [b'1', d, e] => d.is_ascii_digit() && e.is_ascii_digit(),
            [b'2', b'0'..=b'4', e] => e.is_ascii_digit(),
            [b'2', b'5', b'0'..=b'5'] => true,
            _ => false,
        };
        if !valid {
            return false;
        }
        octets += 1;
    }
    octets == 4
}

/// Returns whether `src` is an RFC 3986 `IPv6address`, without brackets or a
/// zone.
///
/// That is eight groups of one to four hexadecimal digits, separated by `:`.
/// One `::` may stand for one or more groups of zeros, and an IPv4 address
/// may stand for the last two groups.
pub(crate) fn is_ipv6(src: &str) -> bool {
    // One pass over the bytes, counting groups. An IPv4 address counts as
    // two, and the `::` as at least one.
    let bytes = src.as_bytes();
    let mut groups = 0;
    let mut compressed = false;
    let mut i = 0;

    if bytes.starts_with(b"::") {
        compressed = true;
        i = 2;
        if i == bytes.len() {
            return true;
        }
    }

    loop {
        let start = i;
        while i < bytes.len() && bytes[i].is_ascii_hexdigit() {
            i += 1;
        }
        // An IPv4 address can only be the last piece.
        if bytes.get(i) == Some(&b'.') {
            if !is_ipv4(&src[start..]) {
                return false;
            }
            groups += 2;
            break;
        }
        if i == start || i - start > 4 {
            return false;
        }
        groups += 1;

        match bytes.get(i) {
            None => break,
            Some(b':') => i += 1,
            Some(_) => return false,
        }
        if bytes.get(i) == Some(&b':') {
            if compressed {
                return false;
            }
            compressed = true;
            i += 1;
            if i == bytes.len() {
                break;
            }
        }
    }

    if compressed {
        groups <= 7
    } else {
        groups == 8
    }
}

#[cfg(test)]
mod tests {
    use std::{
        format,
        net::{Ipv4Addr, Ipv6Addr},
        string::String,
        vec,
        vec::Vec,
    };

    use super::*;

    /// The IP checks agree with `std::net`, which also follows RFC 3986 for
    /// these forms and rejects IPv4 octets with a leading zero.
    #[test]
    fn ip_checks_match_std() {
        let mut inputs: Vec<String> = Vec::new();
        for a in [
            "0", "1", "01", "9", "10", "99", "100", "199", "200", "249",
            "250", "255", "256", "300", "1000", "", "a",
        ] {
            inputs.push(format!("{a}.0.0.0"));
            inputs.push(format!("192.0.2.{a}"));
        }
        inputs.extend(
            ["1.2.3", "1.2.3.4.5", "1..2.3", ".1.2.3", "1.2.3.4."]
                .map(String::from),
        );
        for v4 in &inputs.clone() {
            assert_eq!(is_ipv4(v4), v4.parse::<Ipv4Addr>().is_ok(), "{v4}");
        }

        let pieces =
            ["", "0", "1", "ffff", "FFFF", "fffff", "g", "192.0.2.1", "1.2.3"];
        let mut v6 = Vec::new();
        for n in 1..=9 {
            for piece in pieces {
                let mut groups = vec![String::from("1"); n];
                groups[n - 1] = String::from(piece);
                v6.push(groups.join(":"));
                for at in 0..=n {
                    let (head, tail) = groups.split_at(at);
                    v6.push(format!("{}::{}", head.join(":"), tail.join(":")));
                }
            }
        }
        v6.extend(
            [
                ":",
                ":::",
                "::1::",
                "1:::2",
                "::",
                ":1:2:3:4:5:6:7",
                "1:2:3:4:5:6:7:",
            ]
            .map(String::from),
        );
        for src in &v6 {
            assert_eq!(is_ipv6(src), src.parse::<Ipv6Addr>().is_ok(), "{src}");
        }
    }
}

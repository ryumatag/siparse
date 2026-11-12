/*!
Parses SIP and SIPS URIs into their parts.

[`sip_uri`] reads a URI such as a Request-URI, the URI of an
[`Address`](crate::value::Address), or a Route entry, and returns each part as
written. Nothing is decoded. A part keeps its `%`-escapes, a host its case and
an IPv6 reference its brackets.

# Example

```
use siparse::uri::{self, Scheme};

let target = uri::sip_uri(
    "sips:alice%40work@[2001:db8::1]:5061;transport=tcp;lr?Subject=lunch%20plans",
)?;
assert_eq!(target.scheme, Scheme::Sips);
assert_eq!(target.user, Some("alice%40work"));
assert_eq!((target.host, target.port), ("[2001:db8::1]", Some("5061")));

let params: Vec<_> = target.params.iter().map(|p| (p.name, p.value)).collect();
assert_eq!(params, [("transport", Some("tcp")), ("lr", None)]);

let subject = target.headers.iter().next().unwrap();
assert_eq!((subject.name, subject.value), ("Subject", "lunch%20plans"));
# Ok::<(), siparse::Error>(())
```

# What is left to the caller

The parts are syntax only:

* Escapes are checked to be `%` and two hexadecimal digits, and nothing more.
  Decoding a part, and comparing a parameter name in its decoded form, is up
  to the caller.
* A port is one or more digits as written. Whether it fits 16 bits, and the
  default when there is none, depends on the transport.
* Parameters are read with the generic `pname [ "=" pvalue ]` grammar of
  RFC 3261 section 25.1. The values that `transport`, `ttl`, `maddr` and the
  other known parameters allow, and where each may appear (section 19.1.1), are
  for the caller to check. Repeated parameters are all kept, in order.
* Headers are URI parts, not header fields. A decoded value may hold bytes no
  header value allows.
* URIs with other schemes, such as `tel`, are rejected rather than parsed.

[`SipUri`] has no `PartialEq`. RFC 3261 section 19.1.4 compares SIP URIs by
rules that are not an equivalence relation, so comparing the parts as written
would be misleading. Compare the input text, or the parts, explicitly.
*/

use core::iter::FusedIterator;

use crate::{
    error::{Error, ErrorKind},
    token::{is_uri_header, is_uri_param, is_uri_password, is_uri_user},
};

/// The scheme of a SIP URI.
///
/// The scheme is compared case-insensitively, so `SIP:` is [`Scheme::Sip`].
/// Recognizing `sips` says nothing about whether a secure transport is
/// available.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Scheme {
    /// `sip`, a `SIP-URI`.
    Sip,
    /// `sips`, a `SIPS-URI`.
    Sips,
}

impl Scheme {
    /// Returns the scheme name in lowercase, without its `:`.
    #[inline]
    pub const fn as_str(self) -> &'static str {
        match self {
            Scheme::Sip => "sip",
            Scheme::Sips => "sips",
        }
    }
}

/// A SIP or SIPS URI, split into its parts.
///
/// RFC 3261, Section 25.1:
///
/// ```text
/// SIP-URI   =  "sip:" [ userinfo ] hostport uri-parameters [ headers ]
/// SIPS-URI  =  "sips:" [ userinfo ] hostport uri-parameters [ headers ]
/// userinfo  =  ( user / telephone-subscriber ) [ ":" password ] "@"
/// hostport  =  host [ ":" port ]
/// ```
///
/// A `telephone-subscriber` is read with the `user` grammar.
#[derive(Clone, Copy, Debug)]
pub struct SipUri<'a> {
    /// The scheme.
    pub scheme: Scheme,
    /// The user as written, if the URI has user information. It is never
    /// empty.
    pub user: Option<&'a str>,
    /// The password as written, if the user information has a `:`. It may
    /// be empty, which is not the same as no password.
    pub password: Option<&'a str>,
    /// The host as written. An IPv6 reference keeps its brackets, and a
    /// hostname its case and any trailing dot.
    pub host: &'a str,
    /// The port digits as written, if there is a port.
    pub port: Option<&'a str>,
    /// The URI parameters.
    pub params: UriParams<'a>,
    /// The URI headers.
    pub headers: UriHeaders<'a>,
}

/// Reads a SIP or SIPS URI.
///
/// The whole of `src` must be the URI, with no whitespace around it.
///
/// # Errors
///
/// Returns an error whose [`ErrorKind`] names the first part that is
/// malformed, checked from left to right:
/// [`UriScheme`](ErrorKind::UriScheme), [`UriUser`](ErrorKind::UriUser),
/// [`UriPassword`](ErrorKind::UriPassword), [`UriHost`](ErrorKind::UriHost),
/// [`UriPort`](ErrorKind::UriPort), [`UriParam`](ErrorKind::UriParam) and
/// [`UriHeader`](ErrorKind::UriHeader). A malformed escape in any part is a
/// [`UriEscape`](ErrorKind::UriEscape) error.
///
/// # Example
///
/// ```
/// use siparse::{uri, ErrorKind};
///
/// let route = uri::sip_uri("sip:p1.example.com;lr")?;
/// assert_eq!(route.user, None);
/// assert_eq!(route.params.as_str(), ";lr");
///
/// let err = uri::sip_uri("sip:alice@example.com:5o60").unwrap_err();
/// assert_eq!(err.kind(), ErrorKind::UriPort);
/// assert_eq!(uri::sip_uri("tel:+1-201-555-0123").unwrap_err().kind(), ErrorKind::UriScheme);
/// # Ok::<(), siparse::Error>(())
/// ```
pub fn sip_uri(src: &str) -> Result<SipUri<'_>, Error> {
    let (scheme, rest) =
        scheme(src).ok_or(Error::uri(ErrorKind::UriScheme))?;

    // No part after the user information holds a raw `@`, while the user
    // may hold `;` and `?`. So the first `@` ends the user information, and
    // only the text after it is searched for the delimiters that follow.
    let (user, password, rest) = match rest.find('@') {
        Some(at) => {
            let info = &rest[..at];
            let (user, password) = match info.find(':') {
                Some(colon) => (&info[..colon], Some(&info[colon + 1..])),
                None => (info, None),
            };
            part(user, is_uri_user, false, ErrorKind::UriUser)?;
            if let Some(password) = password {
                part(password, is_uri_password, true, ErrorKind::UriPassword)?;
            }
            (Some(user), password, &rest[at + 1..])
        }
        None => (None, None, rest),
    };

    // `hostport` runs to the parameters or the headers. Neither a host nor a
    // port holds `;` or `?`.
    let hostport_end = rest.find([';', '?']).unwrap_or(rest.len());
    let (hostport, rest) = rest.split_at(hostport_end);
    let host_end = if hostport.starts_with('[') {
        hostport.find(']').map_or(hostport.len(), |close| close + 1)
    } else {
        hostport.find(':').unwrap_or(hostport.len())
    };
    let (host, port) = hostport.split_at(host_end);
    if !is_host(host) {
        return Err(Error::uri(ErrorKind::UriHost));
    }
    let port = match port.strip_prefix(':') {
        Some(digits)
            if !digits.is_empty()
                && digits.bytes().all(|b| b.is_ascii_digit()) =>
        {
            Some(digits)
        }
        None if port.is_empty() => None,
        _ => return Err(Error::uri(ErrorKind::UriPort)),
    };

    let params_end = rest.find('?').unwrap_or(rest.len());
    let (params, headers) = rest.split_at(params_end);
    if let Some(list) = params.strip_prefix(';') {
        for pair in list.split(';') {
            let (name, value) = match pair.split_once('=') {
                Some((name, value)) => (name, Some(value)),
                None => (pair, None),
            };
            part(name, is_uri_param, false, ErrorKind::UriParam)?;
            if let Some(value) = value {
                part(value, is_uri_param, false, ErrorKind::UriParam)?;
            }
        }
    }
    if let Some(list) = headers.strip_prefix('?') {
        for pair in list.split('&') {
            let (name, value) = pair
                .split_once('=')
                .ok_or(Error::uri(ErrorKind::UriHeader))?;
            part(name, is_uri_header, false, ErrorKind::UriHeader)?;
            part(value, is_uri_header, true, ErrorKind::UriHeader)?;
        }
    }

    Ok(SipUri {
        scheme,
        user,
        password,
        host,
        port,
        params: UriParams { src: params },
        headers: UriHeaders { src: headers },
    })
}

/// The parameters of a [`SipUri`], each after a `;`.
///
/// Iterating yields each [`UriParam`] in order, repeats included.
#[derive(Clone, Copy, Debug)]
pub struct UriParams<'a> {
    src: &'a str,
}

impl<'a> UriParams<'a> {
    /// Returns the parameters as written, from the first `;`. It is empty
    /// when there are none.
    #[inline]
    pub fn as_str(&self) -> &'a str {
        self.src
    }

    /// Returns whether there are no parameters.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.src.is_empty()
    }

    /// Returns an iterator over the parameters, in order.
    #[inline]
    pub fn iter(&self) -> UriParamsIter<'a> {
        UriParamsIter { rest: self.src.strip_prefix(';').unwrap_or("") }
    }
}

impl<'a> IntoIterator for UriParams<'a> {
    type Item = UriParam<'a>;
    type IntoIter = UriParamsIter<'a>;

    #[inline]
    fn into_iter(self) -> UriParamsIter<'a> {
        self.iter()
    }
}

impl<'a> IntoIterator for &UriParams<'a> {
    type Item = UriParam<'a>;
    type IntoIter = UriParamsIter<'a>;

    #[inline]
    fn into_iter(self) -> UriParamsIter<'a> {
        self.iter()
    }
}

/// One parameter of a SIP URI.
///
/// RFC 3261, Section 25.1:
///
/// ```text
/// other-param  =  pname [ "=" pvalue ]
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct UriParam<'a> {
    /// The name as written, escapes included.
    pub name: &'a str,
    /// The value as written, if there is one, such as `tcp` in
    /// `transport=tcp`. A flag such as `lr` has none.
    pub value: Option<&'a str>,
}

/// An iterator over [`UriParams`].
#[derive(Clone, Debug)]
pub struct UriParamsIter<'a> {
    rest: &'a str,
}

impl<'a> Iterator for UriParamsIter<'a> {
    type Item = UriParam<'a>;

    #[inline]
    fn next(&mut self) -> Option<UriParam<'a>> {
        // The parameters were checked, so every one is non-empty and splits
        // at the first `=`.
        let pair = next_item(&mut self.rest, ';')?;
        Some(match pair.split_once('=') {
            Some((name, value)) => UriParam { name, value: Some(value) },
            None => UriParam { name: pair, value: None },
        })
    }
}

impl FusedIterator for UriParamsIter<'_> {}

/// The headers of a [`SipUri`], after the `?`.
///
/// Iterating yields each [`UriHeader`] in order, repeats included.
#[derive(Clone, Copy, Debug)]
pub struct UriHeaders<'a> {
    src: &'a str,
}

impl<'a> UriHeaders<'a> {
    /// Returns the headers as written, from the `?`. It is empty when there
    /// are none.
    #[inline]
    pub fn as_str(&self) -> &'a str {
        self.src
    }

    /// Returns whether there are no headers.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.src.is_empty()
    }

    /// Returns an iterator over the headers, in order.
    #[inline]
    pub fn iter(&self) -> UriHeadersIter<'a> {
        UriHeadersIter { rest: self.src.strip_prefix('?').unwrap_or("") }
    }
}

impl<'a> IntoIterator for UriHeaders<'a> {
    type Item = UriHeader<'a>;
    type IntoIter = UriHeadersIter<'a>;

    #[inline]
    fn into_iter(self) -> UriHeadersIter<'a> {
        self.iter()
    }
}

impl<'a> IntoIterator for &UriHeaders<'a> {
    type Item = UriHeader<'a>;
    type IntoIter = UriHeadersIter<'a>;

    #[inline]
    fn into_iter(self) -> UriHeadersIter<'a> {
        self.iter()
    }
}

/// One header of a SIP URI.
///
/// RFC 3261, Section 25.1:
///
/// ```text
/// header  =  hname "=" hvalue
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct UriHeader<'a> {
    /// The name as written, escapes included.
    pub name: &'a str,
    /// The value as written, escapes included. It may be empty.
    pub value: &'a str,
}

/// An iterator over [`UriHeaders`].
#[derive(Clone, Debug)]
pub struct UriHeadersIter<'a> {
    rest: &'a str,
}

impl<'a> Iterator for UriHeadersIter<'a> {
    type Item = UriHeader<'a>;

    #[inline]
    fn next(&mut self) -> Option<UriHeader<'a>> {
        // The headers were checked, so every one has an `=`.
        let pair = next_item(&mut self.rest, '&')?;
        let (name, value) = pair.split_once('=')?;
        Some(UriHeader { name, value })
    }
}

impl FusedIterator for UriHeadersIter<'_> {}

/// Takes the text up to the next `delimiter` from `rest`, or `None` at the
/// end.
#[inline]
fn next_item<'a>(rest: &mut &'a str, delimiter: char) -> Option<&'a str> {
    if rest.is_empty() {
        return None;
    }
    let (item, tail) = rest.split_once(delimiter).unwrap_or((rest, ""));
    *rest = tail;
    Some(item)
}

/// Reads `sip:` or `sips:`, in any case, from the start of `src`.
fn scheme(src: &str) -> Option<(Scheme, &str)> {
    let bytes = src.as_bytes();
    if bytes.len() >= 4 && bytes[..4].eq_ignore_ascii_case(b"sip:") {
        Some((Scheme::Sip, &src[4..]))
    } else if bytes.len() >= 5 && bytes[..5].eq_ignore_ascii_case(b"sips:") {
        Some((Scheme::Sips, &src[5..]))
    } else {
        None
    }
}

/// Checks that `src` is made of bytes `allowed` accepts and `%`-escapes.
///
/// An empty `src` is a `kind` error unless `empty` allows it.
fn part(
    src: &str,
    allowed: fn(u8) -> bool,
    empty: bool,
    kind: ErrorKind,
) -> Result<(), Error> {
    if src.is_empty() && !empty {
        return Err(Error::uri(kind));
    }

    let bytes = src.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex =
                |at: usize| bytes.get(at).map_or(false, u8::is_ascii_hexdigit);
            if !hex(i + 1) || !hex(i + 2) {
                return Err(Error::uri(ErrorKind::UriEscape));
            }
            i += 3;
        } else if allowed(bytes[i]) {
            i += 1;
        } else {
            return Err(Error::uri(kind));
        }
    }
    Ok(())
}

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
fn is_host(src: &str) -> bool {
    if let Some(address) = src.strip_prefix('[') {
        return address.strip_suffix(']').map_or(false, is_ipv6);
    }
    if is_ipv4(src) {
        return true;
    }

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
fn is_ipv6(src: &str) -> bool {
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
        vec::Vec,
    };

    use super::*;

    fn kind(src: &str) -> Option<ErrorKind> {
        sip_uri(src).err().map(|err| err.kind())
    }

    fn params<'a>(uri: &SipUri<'a>) -> Vec<(&'a str, Option<&'a str>)> {
        uri.params.iter().map(|p| (p.name, p.value)).collect()
    }

    fn headers<'a>(uri: &SipUri<'a>) -> Vec<(&'a str, &'a str)> {
        uri.headers.iter().map(|h| (h.name, h.value)).collect()
    }

    /// Asserts that `part` is a slice of `src`, not a copy.
    fn assert_borrowed(src: &str, part: &str) {
        let start = part.as_ptr() as usize;
        let base = src.as_ptr() as usize;
        assert!(
            start >= base && start + part.len() <= base + src.len(),
            "{part:?} is not borrowed from {src:?}"
        );
    }

    #[test]
    fn user_delimiters_are_not_parameter_or_header_delimiters() {
        let src = "SiPs:alice;phone?work/desk:secret%3a@[2001:db8::1]:005061;Transport=quic;lr?Subject=hello%20world&Subject=";
        let uri = sip_uri(src).unwrap();

        assert_eq!(uri.scheme, Scheme::Sips);
        assert_eq!(uri.user, Some("alice;phone?work/desk"));
        assert_eq!(uri.password, Some("secret%3a"));
        assert_eq!(uri.host, "[2001:db8::1]");
        assert_eq!(uri.port, Some("005061"));
        assert_eq!(params(&uri), [("Transport", Some("quic")), ("lr", None)]);
        assert_eq!(
            headers(&uri),
            [("Subject", "hello%20world"), ("Subject", "")]
        );
        assert_eq!(uri.params.as_str(), ";Transport=quic;lr");
        assert_eq!(uri.headers.as_str(), "?Subject=hello%20world&Subject=");
    }

    #[test]
    fn missing_and_empty_parts_differ() {
        let src = "sip:Example.COM.";
        let bare = sip_uri(src).unwrap();
        assert_eq!(bare.host, "Example.COM.");
        assert_eq!((bare.user, bare.password, bare.port), (None, None, None));
        assert!(bare.params.is_empty() && bare.headers.is_empty());
        assert_eq!(bare.params.iter().next(), None);
        assert_eq!(bare.headers.iter().next(), None);
        assert_borrowed(src, bare.params.as_str());
        assert_borrowed(src, bare.headers.as_str());

        let empty = sip_uri("sip:alice:@Example.COM.:0;lr?Subject=").unwrap();
        assert_eq!(empty.password, Some(""));
        assert_eq!(empty.port, Some("0"));
        assert_eq!(params(&empty), [("lr", None)]);
        assert_eq!(headers(&empty), [("Subject", "")]);
    }

    #[test]
    fn ports_keep_their_digits() {
        for port in ["0", "65535", "65536", "005060", "999999999999999999999"]
        {
            let src = format!("sip:example.com:{port}");
            assert_eq!(sip_uri(&src).unwrap().port, Some(port), "{src}");
        }
    }

    #[test]
    fn hosts_follow_the_corrected_ip_and_hostname_grammar() {
        for host in [
            "192.0.2.1",
            "0.0.0.0",
            "255.255.255.255",
            "[::]",
            "[::1]",
            "[1::]",
            "[::ffff:192.0.2.1]",
            "[2001:DB8:0:0:0:0:0:1]",
            "[2001:db8::1:2:3:4:5]",
            "[1:2:3:4:5:6:192.0.2.1]",
            "example",
            "3com.Example.",
            "a-b.example",
            "a",
        ] {
            let src = format!("sip:{host}");
            assert_eq!(sip_uri(&src).map(|uri| uri.host), Ok(host), "{src}");
        }

        for host in [
            "",
            "256.1.1.1",
            "192.000.2.1",
            "192.0.2.1.",
            "192.0.2",
            "1",
            "example.1",
            "a..example",
            "-a.example",
            "a-.example",
            "example..",
            ".example",
            "a_b.example",
            "ex%61mple.com",
            "[::ffff:192.000.2.1]",
            "[2001:db8:::1]",
            "[1:2:3:4:5:6:7:8:9]",
            "[1:2:3:4:5:6:7]",
            "[1::2::3]",
            "[1:2:3:4:5:6:7::8]",
            "[12345::]",
            "[192.0.2.1::]",
            "[::1",
            "::1",
            "[]",
            "[v1.a]",
            "[fe80::1%25eth0]",
            "[example.com]",
        ] {
            let src = format!("sip:{host}");
            assert_eq!(kind(&src), Some(ErrorKind::UriHost), "{src}");
        }
    }

    #[test]
    fn malformed_parts_name_their_kind() {
        use ErrorKind as K;
        for (src, expected) in [
            ("http://example.com", K::UriScheme),
            ("SIP", K::UriScheme),
            ("sip", K::UriScheme),
            ("sip:@example.com", K::UriUser),
            ("sip::password@example.com", K::UriUser),
            ("sip:a b@example.com", K::UriUser),
            ("sip:alice:pass:word@example.com", K::UriPassword),
            ("sip:alice:pass;word@example.com", K::UriPassword),
            ("sip:alice@@example.com", K::UriHost),
            ("sip:", K::UriHost),
            ("sip:example.com:", K::UriPort),
            ("sip:example.com:-1", K::UriPort),
            ("sip:example.com:5o60", K::UriPort),
            ("sip:[::1]garbage", K::UriPort),
            ("sip:[::1]:", K::UriPort),
            ("sip:example.com;", K::UriParam),
            ("sip:example.com;;lr", K::UriParam),
            ("sip:example.com;x=", K::UriParam),
            ("sip:example.com;=x", K::UriParam),
            ("sip:example.com;x=a=b", K::UriParam),
            ("sip:example.com?", K::UriHeader),
            ("sip:example.com?x", K::UriHeader),
            ("sip:example.com?=x", K::UriHeader),
            ("sip:example.com?x=y&", K::UriHeader),
            ("sip:example.com?x=y=z", K::UriHeader),
            ("sip:a%2@example.com", K::UriEscape),
            ("sip:a%gg@example.com", K::UriEscape),
            ("sip:alice:%@example.com", K::UriEscape),
            ("sip:example.com;x=%", K::UriEscape),
            ("sip:example.com?x=%a", K::UriEscape),
        ] {
            assert_eq!(kind(src), Some(expected), "{src}");
        }

        for src in [
            "sip:a\u{e9}@example.com",
            "sip:example.com;x=\u{e9}",
            "sip:example.com?x=\r\n",
            "sip:example.com#fragment",
            "sip:example.com/path",
            "sip:example.com?x=raw value",
            " sip:example.com",
            "sip:example.com ",
        ] {
            assert!(kind(src).is_some(), "{src:?}");
        }
    }

    #[test]
    fn escaped_delimiters_stay_in_their_parts() {
        let uri = sip_uri(
            "sip:alice%40work:p%3Ass@example.com;p%3Bname=a%3Bb%3Fc?x=a%26b%3Dc",
        )
        .unwrap();
        assert_eq!(uri.user, Some("alice%40work"));
        assert_eq!(uri.password, Some("p%3Ass"));
        assert_eq!(params(&uri), [("p%3Bname", Some("a%3Bb%3Fc"))]);
        assert_eq!(headers(&uri), [("x", "a%26b%3Dc")]);
    }

    #[test]
    fn repeated_params_are_all_kept() {
        let uri = sip_uri("sip:example.com;lr;LR=x;%6cr=y;other=z").unwrap();
        assert_eq!(
            params(&uri),
            [
                ("lr", None),
                ("LR", Some("x")),
                ("%6cr", Some("y")),
                ("other", Some("z")),
            ]
        );
        assert_eq!((&uri.params).into_iter().count(), 4);
    }

    #[test]
    fn every_byte_obeys_its_part_class() {
        let unreserved = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.!~*'()";
        for byte in 0..=255u8 {
            for (allowed, extra) in [
                (is_uri_user as fn(u8) -> bool, &b"&=+$,;?/"[..]),
                (is_uri_password, &b"&=+$,"[..]),
                (is_uri_param, &b"[]/:&+$"[..]),
                (is_uri_header, &b"[]/?:+$"[..]),
            ] {
                assert_eq!(
                    allowed(byte),
                    unreserved.contains(&byte) || extra.contains(&byte),
                    "{byte:#x}"
                );
            }
        }

        // A byte each class allows, in its own part, parses.
        for byte in 0..0x80u8 {
            let c = char::from(byte);
            for (src, allowed) in [
                (
                    format!("sip:{c}@example.com"),
                    is_uri_user(byte) && byte != b':',
                ),
                (format!("sip:a:{c}@example.com"), is_uri_password(byte)),
                (
                    format!("sip:example.com;x={c}"),
                    is_uri_param(byte) && byte != b'=',
                ),
                (format!("sip:example.com?x={c}"), is_uri_header(byte)),
            ] {
                if allowed {
                    assert!(sip_uri(&src).is_ok(), "{src:?}");
                }
            }
        }
    }

    #[test]
    fn iterators_are_cloneable_and_fused() {
        let uri = sip_uri("sip:example.com;a;b=c?x=&y=z").unwrap();

        let mut params = uri.params.iter();
        assert_eq!(params.next().map(|p| p.name), Some("a"));
        assert_eq!(params.clone().count(), 1);
        assert_eq!(params.next().and_then(|p| p.value), Some("c"));
        assert_eq!(params.next(), None);
        assert_eq!(params.next(), None);

        let mut headers = uri.headers.iter();
        assert_eq!(headers.next().map(|h| h.name), Some("x"));
        assert_eq!(headers.clone().count(), 1);
        assert_eq!(headers.next().map(|h| h.value), Some("z"));
        assert_eq!(headers.next(), None);
        assert_eq!(headers.next(), None);
    }

    #[test]
    fn every_prefix_parses_or_fails_cleanly() {
        let value =
            "sips:a%40b;c:p%3A@[2001:db8::192.0.2.1]:5061;lr;t=tcp?h=1&i=";
        let ends = value.char_indices().map(|(i, _)| i);
        for end in ends.chain([value.len()]) {
            let src = &value[..end];
            let Ok(uri) = sip_uri(src) else { continue };
            for part in [uri.host, uri.params.as_str(), uri.headers.as_str()] {
                assert_borrowed(src, part);
            }
            for part in
                [uri.user, uri.password, uri.port].into_iter().flatten()
            {
                assert_borrowed(src, part);
            }
        }
    }

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
                let mut groups = std::vec![String::from("1"); n];
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

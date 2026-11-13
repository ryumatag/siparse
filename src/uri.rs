/*!
Parses SIP, SIPS and tel URIs into their parts.

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
* [`sip_uri`] rejects URIs with other schemes. [`tel_uri`] reads a tel URI,
  and [`telephone_subscriber`] the same number and parameters in the user of a
  SIP URI with `user=phone`.

[`SipUri`] has no `PartialEq`. RFC 3261 section 19.1.4 compares SIP URIs by
rules that are not an equivalence relation, so comparing the parts as written
would be misleading. Compare the input text, or the parts, explicitly.
*/

use core::iter::FusedIterator;

use crate::{
    error::{Error, ErrorKind},
    host::{is_host, is_hostname},
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

/// A telephone number with its parameters, as a tel URI or the user of a
/// SIP URI with `user=phone` holds it.
///
/// RFC 3966, Section 3:
///
/// ```text
/// telephone-subscriber  =  global-number / local-number
/// global-number         =  global-number-digits *par
/// local-number          =  local-number-digits *par context *par
/// par                   =  parameter / extension / isdn-subaddress
/// ```
#[derive(Clone, Copy, Debug)]
pub struct TelephoneSubscriber<'a> {
    /// The number as written, with its visual separators. A global number
    /// starts with `+`.
    pub number: &'a str,
    /// The parameters, such as `ext`, `isub` and `phone-context`.
    pub params: UriParams<'a>,
}

impl<'a> TelephoneSubscriber<'a> {
    /// Returns whether the number is global, starting with `+` and a country
    /// code. A local number has a `phone-context` instead.
    #[inline]
    pub fn is_global(&self) -> bool {
        self.number.starts_with('+')
    }
}

/// Reads a tel URI.
///
/// The whole of `src` must be the URI, `tel:` in any case and then a
/// [`telephone_subscriber`].
///
/// # Errors
///
/// Returns an [`ErrorKind::UriScheme`] error if `src` does not start with
/// `tel:`, and otherwise the errors of [`telephone_subscriber`].
///
/// # Example
///
/// ```
/// use siparse::uri;
///
/// let global = uri::tel_uri("tel:+1-201-555-0123")?;
/// assert!(global.is_global());
/// assert_eq!(global.number, "+1-201-555-0123");
///
/// let local = uri::tel_uri("tel:7042;phone-context=example.com")?;
/// let context = local.params.iter().next().unwrap();
/// assert_eq!((context.name, context.value), ("phone-context", Some("example.com")));
/// # Ok::<(), siparse::Error>(())
/// ```
pub fn tel_uri(src: &str) -> Result<TelephoneSubscriber<'_>, Error> {
    let bytes = src.as_bytes();
    if bytes.len() < 4 || !bytes[..4].eq_ignore_ascii_case(b"tel:") {
        return Err(Error::uri(ErrorKind::UriScheme));
    }
    telephone_subscriber(&src[4..])
}

/// Reads a `telephone-subscriber`, the part of a tel URI after `tel:`.
///
/// RFC 3261 section 19.1.6 puts the same grammar in the user of a SIP URI
/// whose `user` parameter is `phone`. Pass that user here, decoded first if
/// it holds escapes the SIP URI needed.
///
/// The number is checked against its form, a global or a local one, and a
/// local number needs a `phone-context` whose value is a domain name or a
/// global number. Each parameter name is letters, digits and `-`, and each
/// value the characters of RFC 3966's `pvalue`, or, for `isub`, those of a
/// `uric` up to the next `;`. As in the grammar, `ext`, `isub` and
/// `phone-context` are also plain parameters, so their own forms only widen
/// what is accepted. The order RFC 3966 gives the parameters is not checked,
/// nor are their values beyond that.
///
/// # Errors
///
/// Returns an [`ErrorKind::TelNumber`] error if the number is malformed or a
/// local number has no `phone-context`, an [`ErrorKind::UriParam`] error if
/// a parameter is malformed, and an [`ErrorKind::UriEscape`] error if a `%`
/// is not followed by two hexadecimal digits.
///
/// # Example
///
/// ```
/// use siparse::{uri, ErrorKind};
///
/// let user = uri::telephone_subscriber("863-1234;phone-context=+1-914-555")?;
/// assert!(!user.is_global());
///
/// let err = uri::telephone_subscriber("863-1234").unwrap_err();
/// assert_eq!(err.kind(), ErrorKind::TelNumber);
/// # Ok::<(), siparse::Error>(())
/// ```
pub fn telephone_subscriber(
    src: &str,
) -> Result<TelephoneSubscriber<'_>, Error> {
    let number_end = src.find(';').unwrap_or(src.len());
    let (number, params) = src.split_at(number_end);
    let valid = match number.strip_prefix('+') {
        Some(digits) => is_global_digits(digits),
        None => is_local_digits(number),
    };
    if !valid {
        return Err(Error::uri(ErrorKind::TelNumber));
    }

    let mut context = false;
    if let Some(list) = params.strip_prefix(';') {
        for pair in list.split(';') {
            let (name, value) = match pair.split_once('=') {
                Some((name, value)) => (name, Some(value)),
                None => (pair, None),
            };
            let named = !name.is_empty()
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-');
            if !named {
                return Err(Error::uri(ErrorKind::UriParam));
            }
            let Some(value) = value else { continue };
            // `isdn-subaddress` takes a `uric`, which `pvalue` narrows.
            let allowed = if name.eq_ignore_ascii_case("isub") {
                is_isub
            } else {
                is_uri_param
            };
            part(value, allowed, false, ErrorKind::UriParam)?;
            if name.eq_ignore_ascii_case("phone-context") {
                context |= is_descriptor(value);
            }
        }
    }
    if !number.starts_with('+') && !context {
        return Err(Error::uri(ErrorKind::TelNumber));
    }

    Ok(TelephoneSubscriber { number, params: UriParams { src: params } })
}

/// Returns whether `src` follows the `+` of a global number:
/// `*phonedigit DIGIT *phonedigit`.
fn is_global_digits(src: &str) -> bool {
    src.bytes().all(is_phonedigit) && src.bytes().any(|b| b.is_ascii_digit())
}

/// Returns whether `src` is the number of a local one:
/// `*phonedigit-hex (HEXDIG / "*" / "#") *phonedigit-hex`.
fn is_local_digits(src: &str) -> bool {
    let digit = |b: u8| b.is_ascii_hexdigit() || b == b'*' || b == b'#';
    src.bytes().all(|b| digit(b) || is_visual_separator(b))
        && src.bytes().any(digit)
}

/// Returns whether `b` is a `phonedigit`, a digit or a visual separator.
fn is_phonedigit(b: u8) -> bool {
    b.is_ascii_digit() || is_visual_separator(b)
}

/// Returns whether `b` is a `visual-separator`, which a number may hold for
/// readability.
fn is_visual_separator(b: u8) -> bool {
    matches!(b, b'-' | b'.' | b'(' | b')')
}

/// Returns whether `src` is the `descriptor` of a `phone-context`: a domain
/// name, or the digits of a global number.
fn is_descriptor(src: &str) -> bool {
    match src.strip_prefix('+') {
        Some(digits) => is_global_digits(digits),
        None => is_hostname(src),
    }
}

/// Returns whether `b` may appear in an `isub` value, other than as part of
/// an escape: a `uric` other than `;`, which ends the parameter.
fn is_isub(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"-_.!~*'()/?:@&=+$,".contains(&b)
}

/// The parameters of a [`SipUri`] or a [`TelephoneSubscriber`], each after a
/// `;`.
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

#[cfg(test)]
mod tests {
    use std::{format, vec, vec::Vec};

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

    /// A number, whether it is global, and its parameters.
    type Tel<'a> = (&'a str, bool, Vec<(&'a str, Option<&'a str>)>);

    fn tel(src: &str) -> Result<Tel<'_>, ErrorKind> {
        tel_uri(src)
            .map(|t| {
                (
                    t.number,
                    t.is_global(),
                    t.params.iter().map(|p| (p.name, p.value)).collect(),
                )
            })
            .map_err(|err| err.kind())
    }

    #[test]
    fn tel_uris_from_rfc_3966() {
        // The examples of RFC 3966 section 6.
        assert_eq!(
            tel("tel:+1-201-555-0123"),
            Ok(("+1-201-555-0123", true, vec![]))
        );
        assert_eq!(
            tel("tel:7042;phone-context=example.com"),
            Ok(("7042", false, vec![("phone-context", Some("example.com"))]))
        );
        assert_eq!(
            tel("tel:863-1234;phone-context=+1-914-555"),
            Ok((
                "863-1234",
                false,
                vec![("phone-context", Some("+1-914-555"))]
            ))
        );
    }

    #[test]
    fn tel_numbers_and_parameters() {
        for (src, number, params) in [
            ("TEL:+1(201)555.0123", "+1(201)555.0123", vec![]),
            (
                "tel:+1-201-555-0123;ext=1234",
                "+1-201-555-0123",
                vec![("ext", Some("1234"))],
            ),
            (
                "tel:+1-201-555-0123;isub=12;x=y",
                "+1-201-555-0123",
                vec![("isub", Some("12")), ("x", Some("y"))],
            ),
            (
                "tel:+1-201-555-0123;isub=a@b?c=d,e",
                "+1-201-555-0123",
                vec![("isub", Some("a@b?c=d,e"))],
            ),
            ("tel:+12015550123;flag", "+12015550123", vec![("flag", None)]),
            (
                "tel:+12015550123;x=%2B1",
                "+12015550123",
                vec![("x", Some("%2B1"))],
            ),
            (
                "tel:*21#;phone-context=example.com.",
                "*21#",
                vec![("phone-context", Some("example.com."))],
            ),
            (
                "tel:AB-12;PHONE-CONTEXT=example.com",
                "AB-12",
                vec![("PHONE-CONTEXT", Some("example.com"))],
            ),
            (
                "tel:7042;ext=1;phone-context=example.com",
                "7042",
                vec![
                    ("ext", Some("1")),
                    ("phone-context", Some("example.com")),
                ],
            ),
            // `ext` and `isub` are also plain parameters, which take any `pvalue`.
            (
                "tel:+12015550123;ext=abc;isub",
                "+12015550123",
                vec![("ext", Some("abc")), ("isub", None)],
            ),
        ] {
            let found =
                tel_uri(src).unwrap_or_else(|err| panic!("{src:?}: {err}"));
            assert_eq!(found.number, number, "{src:?}");
            assert_eq!(
                found
                    .params
                    .iter()
                    .map(|p| (p.name, p.value))
                    .collect::<Vec<_>>(),
                params,
                "{src:?}"
            );
            assert_borrowed(src, found.number);
            assert_borrowed(src, found.params.as_str());
        }
    }

    #[test]
    fn malformed_tel_uris() {
        use ErrorKind as K;
        for (src, expected) in [
            ("sip:+12015550123", K::UriScheme),
            ("tel", K::UriScheme),
            ("tel:", K::TelNumber),
            ("tel:+", K::TelNumber),
            ("tel:+-().", K::TelNumber),
            ("tel:+1 201", K::TelNumber),
            ("tel:+1a", K::TelNumber),
            ("tel:++1", K::TelNumber),
            ("tel:-.()", K::TelNumber),
            ("tel:7042", K::TelNumber),
            ("tel:7042;ext=1", K::TelNumber),
            ("tel:7042;phone-context=", K::UriParam),
            ("tel:7042;phone-context=-bad-", K::TelNumber),
            ("tel:7042;phone-context=+", K::TelNumber),
            ("tel:7042;phone-context=example.1", K::TelNumber),
            ("tel:+12015550123;", K::UriParam),
            ("tel:+12015550123;;x", K::UriParam),
            ("tel:+12015550123;=x", K::UriParam),
            ("tel:+12015550123;a_b=1", K::UriParam),
            ("tel:+12015550123;x=", K::UriParam),
            ("tel:+12015550123;x=a@b", K::UriParam),
            ("tel:+12015550123;x=%2", K::UriEscape),
            ("tel:+12015550123;isub=%zz", K::UriEscape),
        ] {
            assert_eq!(tel(src).map(|_| ()), Err(expected), "{src:?}");
        }
    }

    #[test]
    fn subscribers_in_the_user_of_a_sip_uri() {
        let uri = sip_uri(
            "sip:+1-212-555-1212;ext=99@gateway.example.com;user=phone",
        )
        .unwrap();
        let user = telephone_subscriber(uri.user.unwrap()).unwrap();
        assert_eq!(user.number, "+1-212-555-1212");
        assert_eq!(
            user.params.iter().next(),
            Some(UriParam { name: "ext", value: Some("99") })
        );
    }

    #[test]
    fn every_tel_prefix_parses_or_fails_cleanly() {
        let value =
            "tel:863-1234;isub=a@b;ext=12;phone-context=+1-914-555;x=%2B";
        let ends = value.char_indices().map(|(i, _)| i);
        for end in ends.chain([value.len()]) {
            let src = &value[..end];
            let Ok(found) = tel_uri(src) else { continue };
            assert_borrowed(src, found.number);
            assert_borrowed(src, found.params.as_str());
        }
    }
}

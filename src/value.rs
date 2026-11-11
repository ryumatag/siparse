/*!
Parses the RFC 3261 productions that header values are built from.

[`scan`] finds the lexical elements of a value, such as a `token`
or a `quoted-string`. The functions here put them together into the productions
that several header grammars share, and return each part as written. From, To,
Contact, Route, Record-Route and Reply-To all hold a `name-addr` or an
`addr-spec` followed by `generic-param`s, so [`address`] and [`addresses`] read
any of them. [`cseq`] and [`call_id`] read the two values that, with the tags in
From and To, tell which request and which dialog a message belongs to.

# Example

```
use siparse::value;

let to = value::address("\"Bob\" <sip:bob@biloxi.example.com>;tag=a6c85cf")?;
assert_eq!(to.display_name, Some("\"Bob\""));
assert_eq!(to.uri, "sip:bob@biloxi.example.com");

let tag = to.params.iter().find(|param| param.name.eq_ignore_ascii_case("tag"));
assert_eq!(tag.and_then(|param| param.value), Some("a6c85cf"));
# Ok::<(), siparse::Error>(())
```

# What is left to the caller

The parts are syntax only:

* Nothing is unquoted, unescaped or percent-decoded. A quoted display name or
  parameter value keeps its quotes, and an IPv6 reference its brackets.
* A URI must start with a scheme and stay within the URI character set that
  the parser accepts in a request-line. Its structure is not parsed.
* Which production a header takes is for the caller to know. Route allows only
  a `name-addr`, which [`Address::bracketed`] tells apart, and Contact may be a
  lone `*`, which [`addresses`] rejects.
* Every parameter is kept, in order, and names are not compared. Parameter
  names are case-insensitive in RFC 3261, and whether a repeated one is an
  error, or which one counts, is up to the caller.

# Input

As with [`scan`], the input is a header value as the parser or
[`check::header_value`](crate::check::header_value) returned it, so `CR` and
`LF` only occur in folds. Whitespace before and after it is allowed, since a
header value keeps its trailing whitespace.

# Strictness

The productions follow RFC 3261 section 25.1. A few rules that other parsers
relax are worth knowing:

* An unquoted display name is tokens each followed by whitespace, so
  `Bob<sip:bob@biloxi.example.com>` is not an address.
* Nothing may sit between the angle brackets and the URI, whitespace included.
* An `addr-spec` without angle brackets ends at the first `;`, `,` or
  whitespace, and may not contain `?` (section 20). Its URI parameters
  therefore read as header parameters, so in
  `tel:+12015550123;phone-context=example.com` the `phone-context` is one of
  [`Address::params`].
* A list has no empty elements, so a leading, trailing or doubled `,` is an
  error.
*/

use core::iter::FusedIterator;

use crate::{
    error::Error,
    scan::{self, split_run},
    simd,
};

/// A `name-addr` or an `addr-spec` with the header parameters after it.
///
/// Like [`Params`], two addresses are equal when they are written the same.
///
/// RFC 3261, Section 25.1:
///
/// ```text
/// name-addr     =  [ display-name ] LAQUOT addr-spec RAQUOT
/// addr-spec     =  SIP-URI / SIPS-URI / absoluteURI
/// display-name  =  *(token LWS)/ quoted-string
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Address<'a> {
    /// The display name as written, if there is one.
    ///
    /// A quoted one keeps its quotes and escapes. An unquoted one runs from
    /// its first token to its last, with the whitespace between them as
    /// written.
    pub display_name: Option<&'a str>,
    /// The URI, without angle brackets.
    pub uri: &'a str,
    /// Whether the URI was in angle brackets, which makes the address a
    /// `name-addr`.
    ///
    /// A Route or Record-Route value must be one, since `route-param` is
    /// `name-addr *( SEMI rr-param )`:
    ///
    /// ```
    /// use siparse::value;
    ///
    /// let route = value::address("sip:p1.example.com;lr")?;
    /// assert!(!route.bracketed);
    /// # Ok::<(), siparse::Error>(())
    /// ```
    pub bracketed: bool,
    /// The header parameters after the URI.
    pub params: Params<'a>,
}

/// One `generic-param`.
///
/// RFC 3261, Section 25.1:
///
/// ```text
/// generic-param  =  token [ EQUAL gen-value ]
/// gen-value      =  token / host / quoted-string
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Param<'a> {
    /// The name, in the case it was written in.
    pub name: &'a str,
    /// The value as written, if there is one. A quoted value keeps its quotes
    /// and an IPv6 reference its brackets.
    pub value: Option<&'a str>,
}

/// A run of `generic-param`s, each after a `;`, that has been checked.
///
/// [`params`] returns one, and so does each [`Address`]. Iterating it yields
/// each [`Param`] in order.
///
/// Two `Params` are equal when they are written the same, whitespace
/// included, so `;a=1` and ` ; a=1` differ. Compare their iterators to
/// compare the parameters alone.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct Params<'a> {
    src: &'a str,
}

impl<'a> Params<'a> {
    /// Returns the parameters as written, from the first `;` to the end of
    /// the last parameter. It is empty when there are none.
    ///
    /// # Example
    ///
    /// ```
    /// use siparse::value;
    ///
    /// let address = value::address("<sip:alice@atlanta.example.com> ; tag=9fxced76sl ")?;
    /// assert_eq!(address.params.as_str(), "; tag=9fxced76sl");
    /// # Ok::<(), siparse::Error>(())
    /// ```
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
    pub fn iter(&self) -> ParamsIter<'a> {
        ParamsIter { rest: self.src }
    }
}

impl<'a> IntoIterator for Params<'a> {
    type Item = Param<'a>;
    type IntoIter = ParamsIter<'a>;

    #[inline]
    fn into_iter(self) -> ParamsIter<'a> {
        self.iter()
    }
}

impl<'a> IntoIterator for &Params<'a> {
    type Item = Param<'a>;
    type IntoIter = ParamsIter<'a>;

    #[inline]
    fn into_iter(self) -> ParamsIter<'a> {
        self.iter()
    }
}

/// An iterator over the parameters of [`Params`].
#[derive(Clone, Debug)]
pub struct ParamsIter<'a> {
    rest: &'a str,
}

impl<'a> Iterator for ParamsIter<'a> {
    type Item = Param<'a>;

    #[inline]
    fn next(&mut self) -> Option<Param<'a>> {
        // `Params` was checked when it was made, so this only ends at the end
        // of it.
        let (param, rest) = generic_param(self.rest)?;
        self.rest = rest;
        Some(param)
    }
}

impl FusedIterator for ParamsIter<'_> {}

/// Reads `*( SEMI generic-param )` from the start of `src`.
///
/// Returns the parameters and what follows the last one. When `src` does not
/// start with a `;` after whitespace, there are none, and the rest is all of
/// `src`. Use this for a header whose grammar ends in `generic-param`s, such as
/// the `disp-param`s of a Content-Disposition after its type. A grammar with
/// narrower parameters, such as Content-Type's `m-parameter`, which always has
/// a value and never a bracketed host, needs the caller to check each one.
///
/// # Errors
///
/// Returns an [`ErrorKind::GenericParam`](crate::ErrorKind::GenericParam)
/// error if a `;` is not followed by a `generic-param`.
///
/// # Example
///
/// ```
/// use siparse::{scan, value};
///
/// let (disposition, rest) = scan::token("session;handling=required").unwrap();
/// assert_eq!(disposition, "session");
///
/// let (params, rest) = value::params(rest)?;
/// let handling = params.iter().next().unwrap();
/// assert_eq!((handling.name, handling.value), ("handling", Some("required")));
/// assert_eq!(rest, "");
///
/// assert!(value::params(";handling=").is_err());
/// # Ok::<(), siparse::Error>(())
/// ```
#[inline]
pub fn params(src: &str) -> Result<(Params<'_>, &str), Error> {
    let start = src.len() - scan::sws(src).len();
    let mut rest = src;

    // The run goes on while a `;` follows. A `;` with no parameter after it
    // is an error rather than the end of the run, since nothing else in a
    // header grammar starts with one.
    while scan::sws(rest).starts_with(';') {
        let (_, tail) = generic_param(rest).ok_or(Error::generic_param())?;
        rest = tail;
    }

    // No parameters are an empty slice of the input rather than a static
    // `""`, so every part points into the caller's buffer.
    let params = if rest.len() == src.len() {
        &src[..0]
    } else {
        &src[start..src.len() - rest.len()]
    };
    Ok((Params { src: params }, rest))
}

/// Reads a header value that is exactly one address, such as From or To.
///
/// RFC 3261, Section 25.1:
///
/// ```text
/// from-spec  =  ( name-addr / addr-spec ) *( SEMI from-param )
/// ```
///
/// # Errors
///
/// Returns an [`ErrorKind::Address`](crate::ErrorKind::Address) error if
/// `src` is not one `name-addr` or `addr-spec` followed by parameters, as
/// when a `,` starts a second address. A malformed parameter is an
/// [`ErrorKind::GenericParam`](crate::ErrorKind::GenericParam) error.
///
/// # Example
///
/// ```
/// use siparse::value;
///
/// let from = value::address("Alice <sip:alice@atlanta.example.com>;tag=1928301774")?;
/// assert_eq!(from.display_name, Some("Alice"));
/// assert_eq!(from.uri, "sip:alice@atlanta.example.com");
/// assert!(from.bracketed);
///
/// // Without angle brackets, the parameters belong to the header.
/// let to = value::address("sip:bob@biloxi.example.com;tag=a6c85cf")?;
/// assert_eq!(to.uri, "sip:bob@biloxi.example.com");
/// assert_eq!(to.params.as_str(), ";tag=a6c85cf");
///
/// assert!(value::address("<sip:a@example.com>, <sip:b@example.com>").is_err());
/// # Ok::<(), siparse::Error>(())
/// ```
#[inline]
pub fn address(src: &str) -> Result<Address<'_>, Error> {
    let (address, rest) = address_prefix(src)?;
    if !scan::sws(rest).is_empty() {
        return Err(Error::address());
    }
    Ok(address)
}

/// Iterates over a header value that is a comma-separated list of
/// addresses, such as Contact, Route or Record-Route.
///
/// RFC 3261, Section 25.1:
///
/// ```text
/// Route        =  "Route" HCOLON route-param *(COMMA route-param)
/// route-param  =  name-addr *( SEMI rr-param )
/// ```
///
/// Each item is an address or the error that ends the list. After an error
/// the iterator ends, since nothing past it can be trusted to start an
/// address. A list has at least one address. A Contact value of `*` is not
/// one, so check for it before calling this.
///
/// # Errors
///
/// An item is an [`ErrorKind::Address`](crate::ErrorKind::Address) error
/// where the list does not go on with an address, as after a trailing `,`,
/// and an [`ErrorKind::GenericParam`](crate::ErrorKind::GenericParam) error
/// where a parameter is malformed.
///
/// # Example
///
/// ```
/// use siparse::value;
///
/// let value = "<sip:p1.example.com;lr>,\r\n <sip:p2.example.com;lr>";
/// let mut routes = value::addresses(value);
/// assert_eq!(routes.next().unwrap()?.uri, "sip:p1.example.com;lr");
/// assert_eq!(routes.next().unwrap()?.uri, "sip:p2.example.com;lr");
/// assert!(routes.next().is_none());
///
/// let mut routes = value::addresses("<sip:p1.example.com;lr>,");
/// assert!(routes.next().unwrap().is_ok());
/// assert!(routes.next().unwrap().is_err());
/// assert!(routes.next().is_none());
/// # Ok::<(), siparse::Error>(())
/// ```
#[inline]
pub fn addresses(src: &str) -> Addresses<'_> {
    Addresses { rest: Some(src) }
}

/// An iterator over the addresses of a header value.
///
/// See [`addresses`].
#[derive(Clone, Debug)]
pub struct Addresses<'a> {
    /// What is left of the value, or `None` once the list has ended.
    rest: Option<&'a str>,
}

impl<'a> Iterator for Addresses<'a> {
    type Item = Result<Address<'a>, Error>;

    fn next(&mut self) -> Option<Result<Address<'a>, Error>> {
        let rest = self.rest.take()?;

        let (address, tail) = match address_prefix(rest) {
            Ok(found) => found,
            Err(err) => return Some(Err(err)),
        };
        let tail = scan::sws(tail);
        if let Some(next) = tail.strip_prefix(',') {
            self.rest = Some(next);
        } else if !tail.is_empty() {
            return Some(Err(Error::address()));
        }
        Some(Ok(address))
    }
}

impl FusedIterator for Addresses<'_> {}

/// Reads an address and its parameters from the start of `src`, returning
/// what follows them.
fn address_prefix(src: &str) -> Result<(Address<'_>, &str), Error> {
    let src = scan::sws(src);

    let (display_name, uri, bracketed, rest) = match name_addr(src) {
        Some((display_name, uri, rest)) => (display_name, uri, true, rest),
        None => {
            let (uri, rest) = addr_spec(src).ok_or(Error::address())?;
            (None, uri, false, rest)
        }
    };
    let (params, rest) = params(rest)?;

    Ok((Address { display_name, uri, bracketed, params }, rest))
}

/// Reads `[ display-name ] LAQUOT addr-spec RAQUOT`, or returns `None` when
/// `src` does not start with one.
fn name_addr(src: &str) -> Option<(Option<&str>, &str, &str)> {
    let (display_name, rest) = if src.starts_with('"') {
        let (quoted, rest) = scan::quoted_string(src)?;
        (Some(quoted), scan::sws(rest))
    } else {
        // `*(token LWS)`. Every token needs whitespace after it, so a token
        // directly before `<`, or before the `:` of a URI scheme, means that
        // this is no `name-addr`.
        let mut rest = src;
        let mut len = 0;
        while let Some((_, tail)) = scan::token(rest) {
            len = src.len() - tail.len();
            rest = scan::lws(tail)?;
        }
        ((len > 0).then(|| &src[..len]), rest)
    };

    // LAQUOT is `SWS "<"`, and the whitespace was skipped above. RAQUOT is
    // `">" SWS`, and whatever reads next skips its whitespace.
    let rest = rest.strip_prefix('<')?;
    let (uri, rest) = split_run(rest, simd::match_uri_vectored)?;
    let rest = rest.strip_prefix('>')?;
    has_scheme(uri).then_some((display_name, uri, rest))
}

/// Reads an `addr-spec` outside angle brackets, or returns `None` when `src`
/// does not start with one.
fn addr_spec(src: &str) -> Option<(&str, &str)> {
    let (uri, rest) = split_run(src, simd::match_addr_spec_vectored)?;
    // RFC 3261 section 20 requires angle brackets around a URI that holds a
    // `?`. A `;` or `,` ends the URI instead, since it starts the parameters
    // or the next address.
    if rest.starts_with('?') || !has_scheme(uri) {
        return None;
    }
    Some((uri, rest))
}

/// Returns whether `uri` starts with `scheme ":"` and has something after
/// the `:`.
///
/// Each form of `addr-spec` does. This keeps a display name without angle
/// brackets, such as `Bob`, from passing as a URI. RFC 2396, which RFC 3261
/// cites for `absoluteURI`:
///
/// ```text
/// scheme       =  alpha *( alpha | digit | "+" | "-" | "." )
/// absoluteURI  =  scheme ":" ( hier_part | opaque_part )
/// ```
///
/// Both `hier_part` and `opaque_part` are at least one byte.
fn has_scheme(uri: &str) -> bool {
    let bytes = uri.as_bytes();
    if !bytes.first().map_or(false, u8::is_ascii_alphabetic) {
        return false;
    }
    for (i, &b) in bytes.iter().enumerate().skip(1) {
        match b {
            b':' => return i + 1 < bytes.len(),
            b'+' | b'-' | b'.' => {}
            _ if b.is_ascii_alphanumeric() => {}
            _ => return false,
        }
    }
    false
}

/// Reads `SEMI generic-param` from the start of `src`, returning the
/// parameter and what follows it.
#[inline]
fn generic_param(src: &str) -> Option<(Param<'_>, &str)> {
    let rest = scan::separator(src, ';')?;
    let (name, rest) = scan::token(rest)?;

    let Some(value) = scan::separator(rest, '=') else {
        return Some((Param { name, value: None }, rest));
    };

    // A `host` is either a `hostname` or an `IPv4address`, which every
    // `token` covers, or an `IPv6reference`, which only `host` reads.
    let (value, rest) = match value.as_bytes().first()? {
        b'"' => scan::quoted_string(value)?,
        b'[' => scan::host(value)?,
        _ => scan::token(value)?,
    };
    Some((Param { name, value: Some(value) }, rest))
}

/// A CSeq value: a sequence number and a method.
///
/// RFC 3261, Section 25.1:
///
/// ```text
/// CSeq  =  "CSeq" HCOLON 1*DIGIT LWS Method
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CSeq<'a> {
    /// The sequence number as written, with any leading zeros.
    ///
    /// RFC 3261 section 20.16 requires it to fit in 32 bits. That is checked
    /// when the caller converts it, as with a status code.
    pub number: &'a str,
    /// The method as written, a `token`. RFC 3261 compares methods
    /// case-sensitively, so `invite` is an extension method, not INVITE.
    pub method: &'a str,
}

/// Reads a CSeq value.
///
/// # Errors
///
/// Returns an [`ErrorKind::CSeq`](crate::ErrorKind::CSeq) error if `src` is
/// not digits, whitespace and a method, with only whitespace around them.
///
/// # Example
///
/// ```
/// use siparse::value;
///
/// let cseq = value::cseq("314159 INVITE")?;
/// assert_eq!(cseq.number.parse::<u32>(), Ok(314159));
/// assert_eq!(cseq.method, "INVITE");
///
/// assert!(value::cseq("1INVITE").is_err());
/// # Ok::<(), siparse::Error>(())
/// ```
#[inline]
pub fn cseq(src: &str) -> Result<CSeq<'_>, Error> {
    let invalid = Error::cseq();

    let (number, rest) = scan::digits(scan::sws(src)).ok_or(invalid)?;
    let rest = scan::lws(rest).ok_or(invalid)?;
    let (method, rest) = scan::token(rest).ok_or(invalid)?;
    if !scan::sws(rest).is_empty() {
        return Err(invalid);
    }

    Ok(CSeq { number, method })
}

/// Reads a Call-ID value and returns the `callid` without the whitespace
/// around it.
///
/// RFC 3261 section 20.8 compares Call-IDs byte by byte, so the `callid` is
/// returned as one string, `@` included, rather than in two halves.
///
/// RFC 3261, Section 25.1:
///
/// ```text
/// Call-ID  =  ( "Call-ID" / "i" ) HCOLON callid
/// callid   =  word [ "@" word ]
/// ```
///
/// # Errors
///
/// Returns an [`ErrorKind::CallId`](crate::ErrorKind::CallId) error if `src`
/// is not one `word`, or two joined by `@`, with only whitespace around it.
///
/// # Example
///
/// ```
/// use siparse::value;
///
/// assert_eq!(value::call_id(" f81d4fae-7dec-11d0@192.0.2.4 ")?, "f81d4fae-7dec-11d0@192.0.2.4");
/// assert!(value::call_id("a@b@c").is_err());
/// # Ok::<(), siparse::Error>(())
/// ```
#[inline]
pub fn call_id(src: &str) -> Result<&str, Error> {
    let invalid = Error::call_id();

    let src = scan::sws(src);
    let (_, rest) =
        split_run(src, simd::match_word_vectored).ok_or(invalid)?;
    let rest = match rest.strip_prefix('@') {
        Some(host) => {
            split_run(host, simd::match_word_vectored).ok_or(invalid)?.1
        }
        None => rest,
    };
    if !scan::sws(rest).is_empty() {
        return Err(invalid);
    }

    Ok(&src[..src.len() - rest.len()])
}

#[cfg(test)]
mod tests {
    use std::{format, string::String, vec, vec::Vec};

    use super::*;
    use crate::{
        token::{is_addr_spec_token, is_word},
        ErrorKind,
    };

    fn param(
        name: &'static str,
        value: Option<&'static str>,
    ) -> Param<'static> {
        Param { name, value }
    }

    fn uris(src: &str) -> Result<Vec<&str>, ErrorKind> {
        addresses(src)
            .map(|address| address.map(|address| address.uri))
            .collect::<Result<_, _>>()
            .map_err(|err| err.kind())
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
    fn params_keep_every_value_as_written() {
        let src =
            " ; lr;transport = tcp;x=\"a;b,c\";received=[2001:db8::2];X=1 ,";
        let (list, rest) = params(src).unwrap();

        assert_eq!(rest, " ,");
        assert_eq!(
            list.as_str(),
            "; lr;transport = tcp;x=\"a;b,c\";received=[2001:db8::2];X=1"
        );
        assert_eq!(
            list.iter().collect::<Vec<_>>(),
            [
                param("lr", None),
                param("transport", Some("tcp")),
                param("x", Some("\"a;b,c\"")),
                param("received", Some("[2001:db8::2]")),
                param("X", Some("1")),
            ]
        );
        assert_eq!(list.into_iter().count(), 5);
    }

    #[test]
    fn params_may_be_absent() {
        for src in ["", " ", ",x", " junk"] {
            let (list, rest) = params(src).unwrap();
            assert!(list.is_empty(), "{src:?}");
            assert_eq!(list.iter().next(), None, "{src:?}");
            assert_eq!(rest, src);
        }
    }

    #[test]
    fn params_stop_where_no_semicolon_follows() {
        let (list, rest) = params(";a b").unwrap();
        assert_eq!(list.iter().collect::<Vec<_>>(), [param("a", None)]);
        assert_eq!(rest, " b");

        let (list, rest) = params(";a=b@c").unwrap();
        assert_eq!(list.iter().collect::<Vec<_>>(), [param("a", Some("b"))]);
        assert_eq!(rest, "@c");
    }

    #[test]
    fn malformed_params() {
        for src in [
            ";",
            "; ",
            ";;a",
            ";a;",
            ";=1",
            "; =1",
            ";a=",
            ";a= ",
            ";a=;b",
            ";a=\"open",
            ";a=[::1",
            ";a=\u{e9}",
            ";\u{e9}",
            ";a=1;b=",
        ] {
            assert_eq!(
                params(src).map_err(|err| err.kind()),
                Err(ErrorKind::GenericParam),
                "{src:?}"
            );
        }
    }

    #[test]
    fn addresses_come_in_every_form() {
        let cases = [
            (
                "sip:bob@biloxi.example.com",
                None,
                "sip:bob@biloxi.example.com",
                false,
            ),
            (
                "<sip:bob@biloxi.example.com>",
                None,
                "sip:bob@biloxi.example.com",
                true,
            ),
            (
                "Bob <sip:bob@biloxi.example.com>",
                Some("Bob"),
                "sip:bob@biloxi.example.com",
                true,
            ),
            ("Bob \t B.\r\n <sip:b@x>", Some("Bob \t B."), "sip:b@x", true),
            ("\"Bob\" <sip:b@x>", Some("\"Bob\""), "sip:b@x", true),
            ("\"Bob\"<sip:b@x>", Some("\"Bob\""), "sip:b@x", true),
            ("\"\" <sip:b@x>", Some("\"\""), "sip:b@x", true),
            (
                "\"Bob \\\"B\\\"\" <sip:b@x>",
                Some("\"Bob \\\"B\\\"\""),
                "sip:b@x",
                true,
            ),
            (
                "\"\u{7530}\u{4e2d}\" <sip:t@x>",
                Some("\"\u{7530}\u{4e2d}\""),
                "sip:t@x",
                true,
            ),
            (
                "\"<sip:fake@x>\" <sip:b@x>",
                Some("\"<sip:fake@x>\""),
                "sip:b@x",
                true,
            ),
            (
                "<sip:[2001:db8::1]:5060;lr>",
                None,
                "sip:[2001:db8::1]:5060;lr",
                true,
            ),
            ("sip:[2001:db8::1]", None, "sip:[2001:db8::1]", false),
            (
                "<sip:b@x?Subject=lunch,now>",
                None,
                "sip:b@x?Subject=lunch,now",
                true,
            ),
            (
                "A B <tel:+1-201-555-0123>",
                Some("A B"),
                "tel:+1-201-555-0123",
                true,
            ),
            ("tel:+1-201-555-0123", None, "tel:+1-201-555-0123", false),
            ("  <sip:b@x>  ", None, "sip:b@x", true),
            ("\r\n sip:b@x \r\n ", None, "sip:b@x", false),
        ];

        for (src, display_name, uri, bracketed) in cases {
            let found =
                address(src).unwrap_or_else(|err| panic!("{src:?}: {err}"));
            assert_eq!(found.display_name, display_name, "{src:?}");
            assert_eq!(found.uri, uri, "{src:?}");
            assert_eq!(found.bracketed, bracketed, "{src:?}");
            assert!(found.params.is_empty(), "{src:?}");
        }
    }

    #[test]
    fn parameters_follow_the_brackets_or_end_the_uri() {
        let found =
            address("<sip:p1.example.com;lr;transport=tcp>;tag=x").unwrap();
        assert_eq!(found.uri, "sip:p1.example.com;lr;transport=tcp");
        assert_eq!(
            found.params.iter().collect::<Vec<_>>(),
            [param("tag", Some("x"))]
        );

        let found = address("sip:bob@biloxi.example.com ;\r\n tag = a6c85cf ")
            .unwrap();
        assert_eq!(found.uri, "sip:bob@biloxi.example.com");
        assert_eq!(found.params.as_str(), ";\r\n tag = a6c85cf");
        assert_eq!(
            found.params.iter().collect::<Vec<_>>(),
            [param("tag", Some("a6c85cf"))]
        );

        // A repeated parameter is kept for the caller to judge.
        let found = address("<sip:b@x>;x=1;X=2").unwrap();
        assert_eq!(
            found.params.iter().collect::<Vec<_>>(),
            [param("x", Some("1")), param("X", Some("2"))]
        );
    }

    #[test]
    fn malformed_addresses() {
        for src in [
            "",
            " ",
            "<>",
            "<sip:b@x",
            "sip:b@x>",
            "<<sip:b@x>>",
            "\"Bob <sip:b@x>",
            "\"Bob\" sip:b@x",
            "\"Bob\" \"B\" <sip:b@x>",
            "Bob <sip:b@x",
            "Bob<sip:b@x>",
            "Bob \"B\" <sip:b@x>",
            "Bob; <sip:b@x>",
            "< sip:b@x>",
            "<sip:b@x >",
            "<sip:b @x>",
            "<sip:\u{e9}@x>",
            "<b@x>",
            "<sip:>",
            "<:b@x>",
            "<1sip:b@x>",
            "Bob",
            "Bob sip:b@x",
            "sip:",
            "sip:b@x?Subject=lunch",
            "sip:b@x\u{e9}",
            "sip:b@x junk",
            "<sip:b@x> junk",
            "<sip:b@x>,",
            "<sip:a@x>, <sip:b@x>",
            "sip:a@x,sip:b@x",
            "*",
            ";tag=1",
        ] {
            assert_eq!(
                address(src).map_err(|err| err.kind()),
                Err(ErrorKind::Address),
                "{src:?}"
            );
        }

        for src in
            ["<sip:b@x>;", "sip:b@x;", "<sip:b@x>;x=\"open", "<sip:b@x>;=1"]
        {
            assert_eq!(
                address(src).map_err(|err| err.kind()),
                Err(ErrorKind::GenericParam),
                "{src:?}"
            );
        }
    }

    #[test]
    fn lists_split_only_between_addresses() {
        assert_eq!(
            uris("\"Bob, the builder\" <sip:bob@x>, <sip:b2@x>"),
            Ok(vec!["sip:bob@x", "sip:b2@x"])
        );
        assert_eq!(
            uris("<sip:p1.example.com;lr>;x=\"a,b\", <sip:p2.example.com;lr>"),
            Ok(vec!["sip:p1.example.com;lr", "sip:p2.example.com;lr"])
        );
        assert_eq!(
            uris("sip:a@x;expires=60,sip:b@x , \r\n <sip:c@x?h=1,2>"),
            Ok(vec!["sip:a@x", "sip:b@x", "sip:c@x?h=1,2"])
        );
        assert_eq!(uris("<sip:a@x>"), Ok(vec!["sip:a@x"]));
    }

    #[test]
    fn a_list_ends_at_its_first_error() {
        for (src, before) in [
            ("", 0),
            (",<sip:a@x>", 0),
            ("<sip:a@x>,", 1),
            ("<sip:a@x>,,<sip:b@x>", 1),
            ("<sip:a@x> <sip:b@x>", 0),
            ("<sip:a@x>, Bob<sip:b@x>, <sip:c@x>", 1),
            ("*", 0),
        ] {
            let mut list = addresses(src);
            for _ in 0..before {
                assert!(list.next().unwrap().is_ok(), "{src:?}");
            }
            assert_eq!(
                list.next().map(|item| item.map_err(|err| err.kind())),
                Some(Err(ErrorKind::Address)),
                "{src:?}"
            );
            assert_eq!(list.next(), None, "{src:?}");
        }

        let mut list = addresses("<sip:a@x>;x=, <sip:b@x>");
        assert_eq!(
            list.next().map(|item| item.map_err(|err| err.kind())),
            Some(Err(ErrorKind::GenericParam))
        );
        assert_eq!(list.next(), None);
    }

    #[test]
    fn param_edge_cases() {
        for (src, expected, rest) in [
            (";a =\r\n b", vec![param("a", Some("b"))], ""),
            (";a\r\n =b", vec![param("a", Some("b"))], ""),
            (
                ";a=1\t;b\t; c=\"x\"",
                vec![
                    param("a", Some("1")),
                    param("b", None),
                    param("c", Some("\"x\"")),
                ],
                "",
            ),
            (";a=\"x\\\\\"", vec![param("a", Some("\"x\\\\\""))], ""),
            (";a=[::1]x", vec![param("a", Some("[::1]"))], "x"),
        ] {
            let (list, tail) = params(src).unwrap();
            assert_eq!(list.iter().collect::<Vec<_>>(), expected, "{src:?}");
            assert_eq!(tail, rest, "{src:?}");
            assert_eq!((&list).into_iter().count(), expected.len());
        }

        for src in [";a=[]", ";a=[zz]", ";a=\"x\\\""] {
            assert_eq!(
                params(src).map_err(|err| err.kind()),
                Err(ErrorKind::GenericParam),
                "{src:?}"
            );
        }
        assert_eq!(
            address("<sip:b@x>;a=[::1]x").map_err(|err| err.kind()),
            Err(ErrorKind::Address)
        );
    }

    #[test]
    fn display_names_and_whitespace_around_brackets() {
        for (src, display_name) in [
            ("Bob\t<sip:b@x>", Some("Bob")),
            ("\"a\\\\\" <sip:b@x>", Some("\"a\\\\\"")),
            ("\"Bob\"\r\n <sip:b@x>", Some("\"Bob\"")),
            ("<sip:b@x>\t;x\r\n ;y", None),
        ] {
            let found =
                address(src).unwrap_or_else(|err| panic!("{src:?}: {err}"));
            assert_eq!(found.display_name, display_name, "{src:?}");
            assert_eq!(found.uri, "sip:b@x", "{src:?}");
        }

        for src in [
            "\u{e9} <sip:b@x>",
            "<sip:\"b\"@x>",
            "<sip:<b>@x>",
            "<sip:b>@x>",
            "sip:a@x?",
            "sip:a@x ?h=1",
        ] {
            assert_eq!(
                address(src).map_err(|err| err.kind()),
                Err(ErrorKind::Address),
                "{src:?}"
            );
        }
    }

    #[test]
    fn unbracketed_uri_parameters_belong_to_the_header() {
        let found =
            address("tel:+12015550123;phone-context=example.com").unwrap();
        assert_eq!(found.uri, "tel:+12015550123");
        assert_eq!(
            found.params.iter().collect::<Vec<_>>(),
            [param("phone-context", Some("example.com"))]
        );
    }

    #[test]
    fn empty_params_point_into_the_value() {
        let src = "<sip:a@x> ";
        let found = address(src).unwrap();
        assert!(found.params.is_empty());
        assert_borrowed(src, found.params.as_str());
        assert_eq!(found.params.as_str().as_ptr(), src[9..].as_ptr());
    }

    #[test]
    fn list_separators_take_whitespace_and_folds() {
        assert_eq!(
            uris("<sip:a@x>\t,<sip:b@x>\r\n ,\r\n sip:c@x"),
            Ok(vec!["sip:a@x", "sip:b@x", "sip:c@x"])
        );

        let mut list = addresses("<sip:a@x>,\r\n ");
        assert!(list.next().unwrap().is_ok());
        assert_eq!(
            list.next().map(|item| item.map_err(|err| err.kind())),
            Some(Err(ErrorKind::Address))
        );
    }

    #[test]
    fn long_lists_parse_in_one_pass() {
        let mut src = String::from("<sip:a0@x;lr>;n=0");
        for i in 1..200 {
            src.push_str(&format!(", <sip:a{i}@x;lr>;n={i}"));
        }
        assert_eq!(addresses(&src).filter(Result::is_ok).count(), 200);
    }

    #[test]
    fn cseq_values() {
        for (src, number, method) in [
            ("314159 INVITE", "314159", "INVITE"),
            ("1 X-VENDOR", "1", "X-VENDOR"),
            (" 7 \t ACK", "7", "ACK"),
            ("7\r\n ACK", "7", "ACK"),
            ("7 ACK \r\n ", "7", "ACK"),
            ("007 BYE", "007", "BYE"),
            ("4294967296 BYE", "4294967296", "BYE"),
            ("1 invite", "1", "invite"),
        ] {
            let found =
                cseq(src).unwrap_or_else(|err| panic!("{src:?}: {err}"));
            assert_eq!(
                (found.number, found.method),
                (number, method),
                "{src:?}"
            );
            assert_borrowed(src, found.number);
            assert_borrowed(src, found.method);
        }

        for src in [
            "",
            " ",
            "INVITE",
            "1",
            "1 ",
            "1INVITE",
            "-1 INVITE",
            "+1 INVITE",
            "1 INVITE extra",
            "1 IN VITE",
            "1 IN@VITE",
            "1.0 INVITE",
            "1 INVITE;x",
            "\u{e9} INVITE",
            "1 \u{e9}",
        ] {
            assert_eq!(
                cseq(src).map_err(|err| err.kind()),
                Err(ErrorKind::CSeq),
                "{src:?}"
            );
        }
    }

    #[test]
    fn call_id_values() {
        for (src, expected) in [
            (
                "a84b4c76e66710@pc33.atlanta.com",
                "a84b4c76e66710@pc33.atlanta.com",
            ),
            ("  f81d4fae-7dec-11d0 ", "f81d4fae-7dec-11d0"),
            ("abc\r\n ", "abc"),
            ("\r\n abc", "abc"),
            ("CaseMatters", "CaseMatters"),
            ("<{a}>:\\\"/[b]?@(c)", "<{a}>:\\\"/[b]?@(c)"),
            ("-.!%*_+`'~@x", "-.!%*_+`'~@x"),
        ] {
            let found =
                call_id(src).unwrap_or_else(|err| panic!("{src:?}: {err}"));
            assert_eq!(found, expected, "{src:?}");
            assert_borrowed(src, found);
        }

        for src in [
            "",
            " ",
            "two words",
            "a@b@c",
            "@host",
            "a@",
            "a@ b",
            "a @b",
            "a,b",
            "a;b",
            "a=b",
            "a&b",
            "a#b",
            "a\u{e9}",
        ] {
            assert_eq!(
                call_id(src).map_err(|err| err.kind()),
                Err(ErrorKind::CallId),
                "{src:?}"
            );
        }
    }

    #[test]
    fn word_scan_matches_its_byte_class() {
        let mut inputs: Vec<String> = (0u8..0x80)
            .map(|b| format!("a{}bcdefghijklmnop", b as char))
            .collect();
        inputs.push(String::from("\u{e9}abc"));

        for input in &inputs {
            for start in 0..input.len() {
                if !input.is_char_boundary(start) {
                    continue;
                }
                let src = &input[start..];
                let n = src.bytes().take_while(|&b| is_word(b)).count();
                let expected = (n > 0).then(|| src.split_at(n));
                assert_eq!(
                    split_run(src, simd::match_word_vectored),
                    expected,
                    "{src:?}"
                );
            }
        }
    }

    #[test]
    fn schemes() {
        for uri in ["sip:b", "sips:b", "tel:+1", "a+b-c.9:x", "SIP:b"] {
            assert!(has_scheme(uri), "{uri:?}");
        }
        for uri in
            ["", ":", "sip", "sip:", "9sip:b", "+sip:b", "si p:b", "s_p:b"]
        {
            assert!(!has_scheme(uri), "{uri:?}");
        }
    }

    /// Cuts each value at every character boundary. A prefix of a valid value
    /// may or may not be one, but parsing it must not panic, and what it
    /// returns must be borrowed from it.
    #[test]
    fn every_prefix_parses_or_fails_cleanly() {
        let values = [
            "\"Bob \\\"B\\\" \u{7530}\" <sip:bob@[2001:db8::1]:5060;lr>;tag=a;x=\"q;,\"",
            "Bob B <sip:bob@x?h=1>;received=[::1], sip:carol@y ; expires = 60",
            "sip:alice@atlanta.example.com;tag=1928301774",
        ];

        for value in values {
            let ends = value.char_indices().map(|(i, _)| i);
            for end in ends.chain([value.len()]) {
                let src = &value[..end];
                for address in addresses(src).flatten() {
                    assert_borrowed(src, address.uri);
                    assert_borrowed(src, address.params.as_str());
                    if let Some(display_name) = address.display_name {
                        assert_borrowed(src, display_name);
                    }
                    for param in address.params {
                        assert_borrowed(address.params.as_str(), param.name);
                        if let Some(value) = param.value {
                            assert_borrowed(address.params.as_str(), value);
                        }
                    }
                }
            }
        }

        assert_eq!(uris(values[1]), Ok(vec!["sip:bob@x?h=1", "sip:carol@y"]));
    }

    #[test]
    fn addr_spec_scan_matches_its_byte_class() {
        // Every byte value on its own, and around each block boundary.
        let mut inputs: Vec<String> = (0u8..0x80)
            .map(|b| format!("sip:a{}bcdefghijklmn", b as char))
            .collect();
        inputs.push(String::from("sip:\u{e9}"));

        for input in &inputs {
            for start in 0..input.len() {
                if !input.is_char_boundary(start) {
                    continue;
                }
                let src = &input[start..];
                let n =
                    src.bytes().take_while(|&b| is_addr_spec_token(b)).count();
                let expected = (n > 0).then(|| src.split_at(n));
                assert_eq!(
                    split_run(src, simd::match_addr_spec_vectored),
                    expected,
                    "{src:?}"
                );
            }
        }
    }
}

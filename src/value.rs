/*!
Parses the RFC 3261 productions that header values are built from.

[`scan`] finds the lexical elements of a value, such as a `token`
or a `quoted-string`. The functions here put them together into the productions
that several header grammars share, and return each part as written. From, To,
Contact, Route, Record-Route and Reply-To all hold a `name-addr` or an
`addr-spec` followed by `generic-param`s, so [`address`] and [`addresses`] read
any of them. [`challenge`] and [`credentials`] read the authentication
headers, [`media_type`] and [`media_ranges`] Content-Type and Accept,
[`token_param`] and [`token_params`] the many headers that are a token with
parameters,
[`tokens`] the lists of tokens of Require, Supported, Allow and their kin, [`via_parms`] the values of a Via, and [`cseq`] and
[`call_id`] the two values that, with the tags in From and To, tell which
request and which dialog a message belongs to. [`call_id_params`] reads a
dialog named by its Call-ID and tags, as Replaces, Join and Target-Dialog
hold it.

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
    /// and an IPv6 reference its brackets. A `received` of a [`ViaParm`] may
    /// also be an IPv6 address without brackets.
    pub value: Option<&'a str>,
}

/// A run of `generic-param`s, each after a `;`, that has been checked.
///
/// [`params`] returns one, and so does each [`Address`] and [`ViaParm`].
/// Iterating it yields each [`Param`] in order.
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
        let (param, rest) = checked_param(self.rest)?;
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
    params_of(src, generic_param, Error::generic_param())
}

/// Reads a run of parameters from the start of `src`, each with `read`, as
/// [`params`] does.
///
/// It is always inlined, so that each caller gets a loop over its own
/// reader.
#[inline(always)]
fn params_of(
    src: &str,
    read: fn(&str) -> Option<(Param<'_>, &str)>,
    invalid: Error,
) -> Result<(Params<'_>, &str), Error> {
    let start = src.len() - scan::sws(src).len();
    let mut rest = src;

    // The run goes on while a `;` follows. A `;` with no parameter after it
    // is an error rather than the end of the run, since nothing else in a
    // header grammar starts with one.
    while scan::sws(rest).starts_with(';') {
        let (_, tail) = read(rest).ok_or(invalid)?;
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
    Addresses { list: List::new(src) }
}

/// An iterator over the addresses of a header value.
///
/// See [`addresses`].
#[derive(Clone, Debug)]
pub struct Addresses<'a> {
    list: List<'a>,
}

impl<'a> Addresses<'a> {
    /// Returns what is left of the value after the addresses read so far.
    ///
    /// After an address that a `,` follows, this is the rest of the value
    /// past the `,`, as written, whitespace included. A proxy that removes
    /// the top Route value (RFC 3261 section 16.4) writes this back. Once
    /// the list has ended, by its last address or by an error, it is empty.
    ///
    /// # Example
    ///
    /// ```
    /// use siparse::value;
    ///
    /// let mut routes = value::addresses("<sip:p1.example.com;lr>, <sip:p2.example.com;lr>");
    /// routes.next().unwrap()?;
    /// assert_eq!(routes.as_str(), " <sip:p2.example.com;lr>");
    /// # Ok::<(), siparse::Error>(())
    /// ```
    #[inline]
    pub fn as_str(&self) -> &'a str {
        self.list.rest
    }
}

impl<'a> Iterator for Addresses<'a> {
    type Item = Result<Address<'a>, Error>;

    fn next(&mut self) -> Option<Result<Address<'a>, Error>> {
        self.list.next(address_prefix, Error::address())
    }
}

impl FusedIterator for Addresses<'_> {}

/// The state of a comma-separated list, shared by [`Addresses`],
/// [`MediaRanges`], [`TokenParams`], [`Tokens`] and [`ViaParms`].
#[derive(Clone, Debug)]
struct List<'a> {
    /// What is left of the value. It is an empty slice at the end of the
    /// value once the list has ended, so that it still points into it.
    rest: &'a str,
    /// Whether the list has ended, after its last element or an error.
    done: bool,
}

impl<'a> List<'a> {
    #[inline]
    fn new(src: &'a str) -> List<'a> {
        List { rest: src, done: false }
    }

    /// Reads the next element with `read`, then the `,` or the end of the
    /// value after it. `invalid` is the error for anything else there.
    #[inline]
    fn next<T>(
        &mut self,
        read: impl FnOnce(&'a str) -> Result<(T, &'a str), Error>,
        invalid: Error,
    ) -> Option<Result<T, Error>> {
        if self.done {
            return None;
        }

        let (element, tail) = match read(self.rest) {
            Ok(found) => found,
            Err(err) => return Some(Err(self.fail(err))),
        };
        let tail = scan::sws(tail);
        if let Some(next) = tail.strip_prefix(',') {
            self.rest = next;
        } else if tail.is_empty() {
            self.rest = tail;
            self.done = true;
        } else {
            return Some(Err(self.fail(invalid)));
        }
        Some(Ok(element))
    }

    /// Ends the list after an error, leaving an empty rest that still points
    /// into the value.
    #[cold]
    fn fail(&mut self, err: Error) -> Error {
        self.rest = &self.rest[self.rest.len()..];
        self.done = true;
        err
    }
}

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

/// Reads the next parameter of a [`Params`], with the `;` before it.
///
/// The parameters were checked when the `Params` was made, by
/// [`generic_param`] or [`via_param`]. The only value one accepts and the
/// other does not is a bare IPv6 `received`, which a `token` cannot read
/// past, so this one reader splits both and `Params` need not say which
/// grammar it holds. Keeping that in `Params` grew [`Address`] by eight
/// bytes, and `value/address/*` measured about 9% slower.
#[inline]
fn checked_param(src: &str) -> Option<(Param<'_>, &str)> {
    let rest = scan::separator(src, ';')?;
    let (name, rest) = scan::token(rest)?;

    let Some(value) = scan::separator(rest, '=') else {
        return Some((Param { name, value: None }, rest));
    };
    let (value, rest) = match value.as_bytes().first()? {
        b'"' => scan::quoted_string(value)?,
        b'[' => scan::host(value)?,
        // A `token` stops at the first `:` of a bare IPv6 `received`, or
        // finds nothing when the address starts with `::`.
        _ => match scan::token(value) {
            Some((token, rest)) if !rest.starts_with(':') => (token, rest),
            _ => split_run(value, simd::match_ipv6_vectored)?,
        },
    };
    Some((Param { name, value: Some(value) }, rest))
}

/// Reads `SEMI via-params` from the start of `src`, returning the parameter
/// and what follows it.
///
/// RFC 3261, Section 25.1:
///
/// ```text
/// via-params    =  via-ttl / via-maddr / via-received / via-branch
///                  / via-extension
/// via-received  =  "received" EQUAL (IPv4address / IPv6address)
/// via-extension =  generic-param
/// ```
///
/// Every alternative but one is also a `generic-param`. `via-received` is
/// not, since its `IPv6address` has no brackets and holds `:`. A `received`
/// that a `generic-param` reads, such as a bracketed address, still matches
/// `via-extension`.
#[inline]
fn via_param(src: &str) -> Option<(Param<'_>, &str)> {
    let rest = scan::separator(src, ';')?;
    let (name, rest) = scan::token(rest)?;

    if name.eq_ignore_ascii_case("received") {
        if let Some(value) = scan::separator(rest, '=') {
            // A run with a `:` is no `token`, so it can only be an address.
            // Like `scan::host`, this checks the character class only.
            if let Some((address, rest)) =
                split_run(value, simd::match_ipv6_vectored)
            {
                if address.contains(':') {
                    return Some((Param { name, value: Some(address) }, rest));
                }
            }
        }
    }

    generic_param(src)
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
    let (call_id, rest) = call_id_prefix(src).ok_or(Error::call_id())?;
    if !scan::sws(rest).is_empty() {
        return Err(Error::call_id());
    }
    Ok(call_id)
}

/// A Call-ID followed by parameters, which names a dialog.
///
/// RFC 3891, RFC 3911 and RFC 4538:
///
/// ```text
/// Replaces       =  "Replaces" HCOLON callid *(SEMI replaces-param)
/// Join           =  "Join" HCOLON callid *(SEMI join-param)
/// Target-Dialog  =  "Target-Dialog" HCOLON callid *(SEMI td-param)
/// ```
///
/// Every `replaces-param`, `join-param` and `td-param`, the tags and
/// `early-only` included, is a `generic-param`.
///
/// Like [`Params`], two values are equal when they are written the same.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CallIdParams<'a> {
    /// The `callid` as written, `@` included, as [`call_id`] returns it.
    pub call_id: &'a str,
    /// The parameters, such as `to-tag`, `from-tag` or `early-only`.
    pub params: Params<'a>,
}

/// Reads a Call-ID followed by parameters, the value of Replaces, Join or
/// Target-Dialog.
///
/// Which parameters each header needs, such as both tags of a Replaces, is
/// left to the caller. A Replaces that arrives as a header of a Refer-To URI
/// is percent-escaped there, and is decoded before it is read.
///
/// # Errors
///
/// Returns an [`ErrorKind::CallId`](crate::ErrorKind::CallId) error if `src`
/// does not start with a `callid`, or if anything but parameters and
/// whitespace follows it, and an
/// [`ErrorKind::GenericParam`](crate::ErrorKind::GenericParam) error if a
/// parameter is malformed.
///
/// # Example
///
/// ```
/// use siparse::value;
///
/// let replaces = value::call_id_params(
///     "98732@sip.example.com;from-tag=r33th4x0r;to-tag=ff87ff;early-only",
/// )?;
/// assert_eq!(replaces.call_id, "98732@sip.example.com");
///
/// let names: Vec<_> = replaces.params.iter().map(|p| p.name).collect();
/// assert_eq!(names, ["from-tag", "to-tag", "early-only"]);
/// # Ok::<(), siparse::Error>(())
/// ```
#[inline]
pub fn call_id_params(src: &str) -> Result<CallIdParams<'_>, Error> {
    let invalid = Error::call_id();

    let (call_id, rest) = call_id_prefix(src).ok_or(invalid)?;
    let (params, rest) =
        params_of(rest, generic_param, Error::generic_param())?;
    if !scan::sws(rest).is_empty() {
        return Err(invalid);
    }

    Ok(CallIdParams { call_id, params })
}

/// Reads `word [ "@" word ]`, after any whitespace, from the start of `src`.
///
/// A `word` holds neither `;` nor whitespace, so the `callid` ends where
/// parameters or the end of the value begin. It is always inlined, since
/// with a second caller LLVM kept it out of line and `value/call_id` got
/// 13% slower on aarch64.
#[inline(always)]
fn call_id_prefix(src: &str) -> Option<(&str, &str)> {
    let src = scan::sws(src);
    let (_, rest) = split_run(src, simd::match_word_vectored)?;
    let rest = match rest.strip_prefix('@') {
        Some(host) => split_run(host, simd::match_word_vectored)?.1,
        None => rest,
    };
    Some((&src[..src.len() - rest.len()], rest))
}

/// Iterates over a header value that is a comma-separated list of tokens.
///
/// That is the shape of Require, Proxy-Require, Unsupported, Supported,
/// Allow and Content-Encoding, whose elements are all a `token`, and of
/// RFC 6665's Allow-Events, whose `event-type` is one too.
///
/// RFC 3261, Section 25.1:
///
/// ```text
/// Require           =  "Require" HCOLON option-tag *(COMMA option-tag)
/// Supported         =  ( "Supported" / "k" ) HCOLON
///                      [option-tag *(COMMA option-tag)]
/// Allow             =  "Allow" HCOLON [Method *(COMMA Method)]
/// Content-Encoding  =  ( "Content-Encoding" / "e" ) HCOLON
///                      content-coding *(COMMA content-coding)
/// option-tag        =  token
/// content-coding    =  token
/// ```
///
/// As with [`addresses`], each item is a token as written or the error that
/// ends the list, and a list has at least one token. Supported and Allow may
/// also be empty, so check for that before calling this. Tokens compare
/// case-sensitively or not depending on the header, which is left to the
/// caller.
///
/// # Errors
///
/// An item is an [`ErrorKind::Tokens`](crate::ErrorKind::Tokens) error
/// where the list does not go on with a token, as after a trailing `,`.
///
/// # Example
///
/// ```
/// use siparse::value;
///
/// let mut tags = value::tokens("100rel,\r\n timer");
/// assert_eq!(tags.next(), Some(Ok("100rel")));
/// assert_eq!(tags.as_str(), "\r\n timer");
/// assert_eq!(tags.next(), Some(Ok("timer")));
/// assert_eq!(tags.next(), None);
///
/// assert!(value::tokens("100rel timer").next().unwrap().is_err());
/// ```
#[inline]
pub fn tokens(src: &str) -> Tokens<'_> {
    Tokens { list: List::new(src) }
}

/// An iterator over the tokens of a header value.
///
/// See [`tokens`].
#[derive(Clone, Debug)]
pub struct Tokens<'a> {
    list: List<'a>,
}

impl<'a> Tokens<'a> {
    /// Returns what is left of the value after the tokens read so far.
    ///
    /// After a token that a `,` follows, this is the rest of the value past
    /// the `,`, as written, whitespace included. Once the list has ended, by
    /// its last token or by an error, it is empty.
    #[inline]
    pub fn as_str(&self) -> &'a str {
        self.list.rest
    }
}

impl<'a> Iterator for Tokens<'a> {
    type Item = Result<&'a str, Error>;

    #[inline]
    fn next(&mut self) -> Option<Result<&'a str, Error>> {
        self.list.next(
            |src| scan::token(scan::sws(src)).ok_or(Error::tokens()),
            Error::tokens(),
        )
    }
}

impl FusedIterator for Tokens<'_> {}

/// A media type, as Content-Type holds it, or a media range of Accept.
///
/// RFC 3261, Section 25.1:
///
/// ```text
/// media-type   =  m-type SLASH m-subtype *(SEMI m-parameter)
/// m-parameter  =  m-attribute EQUAL m-value
/// m-value      =  token / quoted-string
/// ```
///
/// Like [`Params`], two media types are equal when they are written the
/// same. RFC 3261 compares types, subtypes and parameter names
/// case-insensitively, which is left to the caller.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct MediaType<'a> {
    /// The `m-type` as written, such as `application`, or `*` in a media
    /// range.
    pub kind: &'a str,
    /// The `m-subtype` as written, such as `sdp`, or `*` in a media range.
    pub subtype: &'a str,
    /// The parameters, such as `charset` or, in a media range, `q`.
    pub params: Params<'a>,
}

/// Reads a media type, the value of Content-Type.
///
/// Each parameter is an `m-parameter`, so unlike a `generic-param` it always
/// has a value, and the value is a token or a quoted string.
///
/// # Errors
///
/// Returns an [`ErrorKind::MediaType`](crate::ErrorKind::MediaType) error if
/// `src` is not `m-type SLASH m-subtype` followed by `m-parameter`s, with
/// only whitespace around it.
///
/// # Example
///
/// ```
/// use siparse::value;
///
/// let sdp = value::media_type("application/sdp")?;
/// assert_eq!((sdp.kind, sdp.subtype), ("application", "sdp"));
///
/// let text = value::media_type("text/plain; charset=\"utf-8\"")?;
/// let charset = text.params.iter().next().unwrap();
/// assert_eq!((charset.name, charset.value), ("charset", Some("\"utf-8\"")));
///
/// assert!(value::media_type("text/plain;charset").is_err());
/// # Ok::<(), siparse::Error>(())
/// ```
#[inline]
pub fn media_type(src: &str) -> Result<MediaType<'_>, Error> {
    let invalid = Error::media_type();

    let (kind, subtype, rest) = type_and_subtype(src).ok_or(invalid)?;
    let (params, rest) = params_of(rest, m_parameter, invalid)?;
    if !scan::sws(rest).is_empty() {
        return Err(invalid);
    }

    Ok(MediaType { kind, subtype, params })
}

/// Iterates over the media ranges of an Accept value.
///
/// RFC 3261, Section 25.1:
///
/// ```text
/// Accept        =  "Accept" HCOLON [ accept-range *(COMMA accept-range) ]
/// accept-range  =  media-range *(SEMI accept-param)
/// media-range   =  ( "*/*" / ( m-type SLASH "*" ) / ( m-type SLASH m-subtype ) )
///                  *( SEMI m-parameter )
/// accept-param  =  ( "q" EQUAL qvalue ) / generic-param
/// qvalue        =  ( "0" [ "." 0*3DIGIT ] ) / ( "1" [ "." 0*3("0") ] )
/// ```
///
/// A range's `m-parameter`s and `accept-param`s are one run of parameters
/// in [`MediaType::params`]. Each is a `generic-param`, and a `q` holds a
/// `qvalue`. As in HTTP, the parameters before `q` belong to the media range
/// and those after it are accept extensions, which is for the caller to
/// split. An `m-type` of `*` takes only a `*` subtype.
///
/// As with [`addresses`], each item is a range or the error that ends the
/// list, and a list has at least one range. An Accept value may also be
/// empty, so check for that before calling this.
///
/// # Errors
///
/// An item is an [`ErrorKind::MediaType`](crate::ErrorKind::MediaType) error
/// where the list does not go on with a media range.
///
/// # Example
///
/// ```
/// use siparse::value;
///
/// let mut accept = value::media_ranges("application/sdp, text/*;q=0.5, */*;q=0");
/// let sdp = accept.next().unwrap()?;
/// assert_eq!((sdp.kind, sdp.subtype), ("application", "sdp"));
/// let text = accept.next().unwrap()?;
/// assert_eq!((text.kind, text.subtype, text.params.as_str()), ("text", "*", ";q=0.5"));
/// assert_eq!(accept.next().unwrap()?.kind, "*");
/// assert!(accept.next().is_none());
///
/// assert!(value::media_ranges("*/sdp").next().unwrap().is_err());
/// # Ok::<(), siparse::Error>(())
/// ```
#[inline]
pub fn media_ranges(src: &str) -> MediaRanges<'_> {
    MediaRanges { list: List::new(src) }
}

/// An iterator over the media ranges of an Accept value.
///
/// See [`media_ranges`].
#[derive(Clone, Debug)]
pub struct MediaRanges<'a> {
    list: List<'a>,
}

impl<'a> MediaRanges<'a> {
    /// Returns what is left of the value after the ranges read so far.
    ///
    /// After a range that a `,` follows, this is the rest of the value past
    /// the `,`, as written, whitespace included. Once the list has ended, by
    /// its last range or by an error, it is empty.
    #[inline]
    pub fn as_str(&self) -> &'a str {
        self.list.rest
    }
}

impl<'a> Iterator for MediaRanges<'a> {
    type Item = Result<MediaType<'a>, Error>;

    fn next(&mut self) -> Option<Result<MediaType<'a>, Error>> {
        self.list.next(media_range_prefix, Error::media_type())
    }
}

impl FusedIterator for MediaRanges<'_> {}

/// Reads an `accept-range` from the start of `src`, returning what follows
/// it.
fn media_range_prefix(src: &str) -> Result<(MediaType<'_>, &str), Error> {
    let invalid = Error::media_type();

    let (kind, subtype, rest) = type_and_subtype(src).ok_or(invalid)?;
    // `*` is a `token`, so the grammar's three forms of `media-range` come
    // down to this one rule.
    if kind == "*" && subtype != "*" {
        return Err(invalid);
    }
    let (params, rest) = params_of(rest, accept_param, invalid)?;

    Ok((MediaType { kind, subtype, params }, rest))
}

/// Reads `m-type SLASH m-subtype` from the start of `src`, after any
/// whitespace.
#[inline]
fn type_and_subtype(src: &str) -> Option<(&str, &str, &str)> {
    // Every form of `m-type` and `m-subtype`, `x-token` included, is a
    // `token`.
    let (kind, rest) = scan::token(scan::sws(src))?;
    let rest = scan::separator(rest, '/')?;
    let (subtype, rest) = scan::token(rest)?;
    Some((kind, subtype, rest))
}

/// Reads `SEMI m-parameter` from the start of `src`, returning the
/// parameter and what follows it.
#[inline]
fn m_parameter(src: &str) -> Option<(Param<'_>, &str)> {
    let rest = scan::separator(src, ';')?;
    let (name, rest) = scan::token(rest)?;
    let value = scan::separator(rest, '=')?;
    let (value, rest) = match value.as_bytes().first()? {
        b'"' => scan::quoted_string(value)?,
        _ => scan::token(value)?,
    };
    Some((Param { name, value: Some(value) }, rest))
}

/// Reads `SEMI accept-param`, or an `m-parameter`, which every
/// `generic-param` covers, from the start of `src`.
#[inline]
fn accept_param(src: &str) -> Option<(Param<'_>, &str)> {
    let (param, rest) = generic_param(src)?;
    if param.name.eq_ignore_ascii_case("q")
        && !param.value.map_or(false, is_qvalue)
    {
        return None;
    }
    Some((param, rest))
}

/// Returns whether `src` is a `qvalue`, a weight from 0 to 1 with at most
/// three decimals.
fn is_qvalue(src: &str) -> bool {
    let (whole, decimals) = match src.split_once('.') {
        Some((whole, decimals)) => (whole, Some(decimals)),
        None => (src, None),
    };
    let decimals = decimals.unwrap_or("");
    decimals.len() <= 3
        && match whole {
            "0" => decimals.bytes().all(|b| b.is_ascii_digit()),
            "1" => decimals.bytes().all(|b| b == b'0'),
            _ => false,
        }
}

/// A challenge or credentials: an authentication scheme and its parameters.
///
/// RFC 3261, Section 25.1:
///
/// ```text
/// challenge        =  ("Digest" LWS digest-cln *(COMMA digest-cln))
///                     / other-challenge
/// other-challenge  =  auth-scheme LWS auth-param *(COMMA auth-param)
/// credentials      =  ("Digest" LWS digest-response) / other-response
/// other-response   =  auth-scheme LWS auth-param *(COMMA auth-param)
/// auth-param       =  auth-param-name EQUAL ( token / quoted-string )
/// ```
///
/// Every `digest-cln` and `dig-resp`, such as `realm`, `nonce`, `qop` or
/// `response`, is also an `auth-param`, and so is each parameter RFC 7616
/// and RFC 8760 add. So both a challenge and credentials are a scheme and a
/// list of `auth-param`s, whatever the scheme.
///
/// Like [`Params`], two values are equal when they are written the same.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Auth<'a> {
    /// The scheme as written, such as `Digest`. RFC 3261 compares it
    /// case-insensitively.
    pub scheme: &'a str,
    /// The parameters.
    pub params: AuthParams<'a>,
}

/// The `auth-param`s of a challenge or credentials, separated by `,`.
///
/// Iterating yields each [`AuthParam`] in order, repeats included.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct AuthParams<'a> {
    src: &'a str,
}

impl<'a> AuthParams<'a> {
    /// Returns the parameters as written, from the first name to the end of
    /// the last value.
    #[inline]
    pub fn as_str(&self) -> &'a str {
        self.src
    }

    /// Returns an iterator over the parameters, in order.
    #[inline]
    pub fn iter(&self) -> AuthParamsIter<'a> {
        AuthParamsIter { rest: self.src }
    }
}

impl<'a> IntoIterator for AuthParams<'a> {
    type Item = AuthParam<'a>;
    type IntoIter = AuthParamsIter<'a>;

    #[inline]
    fn into_iter(self) -> AuthParamsIter<'a> {
        self.iter()
    }
}

impl<'a> IntoIterator for &AuthParams<'a> {
    type Item = AuthParam<'a>;
    type IntoIter = AuthParamsIter<'a>;

    #[inline]
    fn into_iter(self) -> AuthParamsIter<'a> {
        self.iter()
    }
}

/// One `auth-param`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct AuthParam<'a> {
    /// The name as written. RFC 3261 compares it case-insensitively.
    pub name: &'a str,
    /// The value as written, a token or a quoted string with its quotes and
    /// escapes.
    pub value: &'a str,
}

/// An iterator over [`AuthParams`].
#[derive(Clone, Debug)]
pub struct AuthParamsIter<'a> {
    rest: &'a str,
}

impl<'a> Iterator for AuthParamsIter<'a> {
    type Item = AuthParam<'a>;

    #[inline]
    fn next(&mut self) -> Option<AuthParam<'a>> {
        // The parameters were checked, so a `,` and whitespace sit between
        // two of them and nowhere else outside a quoted string.
        let rest = scan::sws(self.rest);
        let rest = rest.strip_prefix(',').unwrap_or(rest);
        let (param, rest) = auth_param(rest)?;
        self.rest = rest;
        Some(param)
    }
}

impl FusedIterator for AuthParamsIter<'_> {}

/// Reads a challenge, the value of WWW-Authenticate or Proxy-Authenticate.
///
/// # Errors
///
/// Returns an [`ErrorKind::Auth`](crate::ErrorKind::Auth) error if `src` is
/// not a scheme, whitespace and one or more `auth-param`s separated by `,`,
/// with only whitespace around it.
///
/// # Example
///
/// ```
/// use siparse::value;
///
/// let challenge = value::challenge(
///     "Digest realm=\"atlanta.com\", qop=\"auth,auth-int\", nonce=\"84a4cc6f3082\", algorithm=MD5",
/// )?;
/// assert_eq!(challenge.scheme, "Digest");
///
/// let params: Vec<_> = challenge.params.iter().map(|p| (p.name, p.value)).collect();
/// assert_eq!(params, [
///     ("realm", "\"atlanta.com\""),
///     ("qop", "\"auth,auth-int\""),
///     ("nonce", "\"84a4cc6f3082\""),
///     ("algorithm", "MD5"),
/// ]);
/// # Ok::<(), siparse::Error>(())
/// ```
#[inline]
pub fn challenge(src: &str) -> Result<Auth<'_>, Error> {
    auth(src)
}

/// Reads credentials, the value of Authorization or Proxy-Authorization.
///
/// Credentials have the shape of a challenge. See [`challenge`].
///
/// # Errors
///
/// Returns an [`ErrorKind::Auth`](crate::ErrorKind::Auth) error if `src` is
/// not a scheme, whitespace and one or more `auth-param`s separated by `,`,
/// with only whitespace around it.
///
/// # Example
///
/// ```
/// use siparse::value;
///
/// let credentials = value::credentials(
///     "Digest username=\"bob\", realm=\"biloxi.com\", uri=\"sip:bob@biloxi.com\", qop=auth, nc=00000001",
/// )?;
/// let nc = credentials.params.iter().find(|p| p.name.eq_ignore_ascii_case("nc"));
/// assert_eq!(nc.map(|p| p.value), Some("00000001"));
///
/// assert!(value::credentials("Digest").is_err());
/// # Ok::<(), siparse::Error>(())
/// ```
#[inline]
pub fn credentials(src: &str) -> Result<Auth<'_>, Error> {
    auth(src)
}

/// Reads `auth-scheme LWS auth-param *(COMMA auth-param)`, the shape of
/// both a challenge and credentials.
fn auth(src: &str) -> Result<Auth<'_>, Error> {
    let invalid = Error::auth();

    let (scheme, rest) = scan::token(scan::sws(src)).ok_or(invalid)?;
    let params = scan::lws(rest).ok_or(invalid)?;

    let (_, mut rest) = auth_param(params).ok_or(invalid)?;
    loop {
        // COMMA is `SWS "," SWS`. A list has no empty elements in RFC 3261,
        // unlike HTTP's, so a `,` always starts another parameter.
        let after = scan::sws(rest);
        match after.strip_prefix(',') {
            Some(next) => rest = auth_param(next).ok_or(invalid)?.1,
            None if after.is_empty() => break,
            None => return Err(invalid),
        }
    }

    let params = AuthParams { src: &params[..params.len() - rest.len()] };
    Ok(Auth { scheme, params })
}

/// Reads an `auth-param`, after any whitespace, from the start of `src`.
#[inline]
fn auth_param(src: &str) -> Option<(AuthParam<'_>, &str)> {
    let (name, rest) = scan::token(scan::sws(src))?;
    let value = scan::separator(rest, '=')?;
    let (value, rest) = match value.as_bytes().first()? {
        b'"' => scan::quoted_string(value)?,
        _ => scan::token(value)?,
    };
    Some((AuthParam { name, value }, rest))
}

/// A token followed by generic parameters.
///
/// Many headers are this one shape, as a single value or a comma-separated
/// list:
///
/// | Header | RFC | Production |
/// |---|---|---|
/// | Content-Disposition | 3261 | `disp-type *( SEMI disp-param )` |
/// | Event | 6665 | `event-type *( SEMI event-param )` |
/// | Subscription-State | 6665 | `substate-value *( SEMI subexp-params )` |
/// | Session-Expires, Min-SE | 4028 | `delta-seconds *( SEMI se-params )` |
/// | Reason | 3326 | `reason-value *(COMMA reason-value)` |
/// | Accept-Encoding | 3261 | `[ encoding *(COMMA encoding) ]` |
/// | Accept-Language | 3261 | `[ language *(COMMA language) ]` |
///
/// Each value, a disposition type, an event type, a number of seconds, a
/// protocol, a content coding or a language range, is a `token`, and each of
/// their parameters a `generic-param`.
///
/// Like [`Params`], two values are equal when they are written the same.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct TokenParam<'a> {
    /// The token as written.
    pub token: &'a str,
    /// The parameters after it.
    pub params: Params<'a>,
}

/// Reads a header value that is one token followed by parameters, such as
/// Content-Disposition, Event or Session-Expires.
///
/// What the token and each parameter must hold beyond a `token` and a
/// `generic-param`, such as the digits of a Session-Expires or the `q` of an
/// Accept-Encoding, is left to the caller.
///
/// # Errors
///
/// Returns an [`ErrorKind::TokenParam`](crate::ErrorKind::TokenParam) error
/// if `src` is not a token followed by parameters, with only whitespace
/// around it, and an
/// [`ErrorKind::GenericParam`](crate::ErrorKind::GenericParam) error if a
/// parameter is malformed.
///
/// # Example
///
/// ```
/// use siparse::value;
///
/// let disposition = value::token_param("session;handling=required")?;
/// assert_eq!(disposition.token, "session");
/// assert_eq!(disposition.params.as_str(), ";handling=required");
///
/// let expires = value::token_param("1800;refresher=uas")?;
/// assert_eq!(expires.token.parse::<u32>(), Ok(1800));
/// # Ok::<(), siparse::Error>(())
/// ```
#[inline]
pub fn token_param(src: &str) -> Result<TokenParam<'_>, Error> {
    let (value, rest) = token_param_prefix(src)?;
    if !scan::sws(rest).is_empty() {
        return Err(Error::token_param());
    }
    Ok(value)
}

/// Iterates over a header value that is a comma-separated list of tokens
/// with parameters, such as Reason, Accept-Encoding or Accept-Language.
///
/// As with [`addresses`], each item is a value or the error that ends the
/// list, and a list has at least one value. Accept-Encoding and
/// Accept-Language may also be empty, so check for that before calling this.
///
/// # Errors
///
/// An item is an [`ErrorKind::TokenParam`](crate::ErrorKind::TokenParam)
/// error where the list does not go on with a token, and an
/// [`ErrorKind::GenericParam`](crate::ErrorKind::GenericParam) error where a
/// parameter is malformed.
///
/// # Example
///
/// ```
/// use siparse::value;
///
/// let mut reasons = value::token_params(
///     "SIP;cause=200;text=\"Call completed elsewhere\", Q.850;cause=16",
/// );
/// let sip = reasons.next().unwrap()?;
/// assert_eq!(sip.token, "SIP");
/// assert_eq!(sip.params.iter().count(), 2);
/// assert_eq!(reasons.next().unwrap()?.token, "Q.850");
/// assert!(reasons.next().is_none());
/// # Ok::<(), siparse::Error>(())
/// ```
#[inline]
pub fn token_params(src: &str) -> TokenParams<'_> {
    TokenParams { list: List::new(src) }
}

/// An iterator over the tokens with parameters of a header value.
///
/// See [`token_params`].
#[derive(Clone, Debug)]
pub struct TokenParams<'a> {
    list: List<'a>,
}

impl<'a> TokenParams<'a> {
    /// Returns what is left of the value after the items read so far.
    ///
    /// After an item that a `,` follows, this is the rest of the value past
    /// the `,`, as written, whitespace included. Once the list has ended, by
    /// its last item or by an error, it is empty.
    #[inline]
    pub fn as_str(&self) -> &'a str {
        self.list.rest
    }
}

impl<'a> Iterator for TokenParams<'a> {
    type Item = Result<TokenParam<'a>, Error>;

    fn next(&mut self) -> Option<Result<TokenParam<'a>, Error>> {
        self.list.next(token_param_prefix, Error::token_param())
    }
}

impl FusedIterator for TokenParams<'_> {}

/// Reads a token and its parameters from the start of `src`, returning
/// what follows them.
fn token_param_prefix(src: &str) -> Result<(TokenParam<'_>, &str), Error> {
    let (token, rest) =
        scan::token(scan::sws(src)).ok_or(Error::token_param())?;
    let (params, rest) =
        params_of(rest, generic_param, Error::generic_param())?;
    Ok((TokenParam { token, params }, rest))
}

/// A `via-parm`, one value of a Via header.
///
/// RFC 3261, Section 25.1:
///
/// ```text
/// via-parm       =  sent-protocol LWS sent-by *( SEMI via-params )
/// sent-protocol  =  protocol-name SLASH protocol-version SLASH transport
/// sent-by        =  host [ COLON port ]
/// ```
///
/// Like [`Params`], two values are equal when they are written the same.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ViaParm<'a> {
    /// The `protocol-name`, such as `SIP`.
    pub protocol: &'a str,
    /// The `protocol-version`, such as `2.0`.
    pub version: &'a str,
    /// The `transport`, such as `UDP`.
    pub transport: &'a str,
    /// The `host` of `sent-by` as written, so an IPv6 reference keeps its
    /// brackets.
    pub host: &'a str,
    /// The `port` of `sent-by` as written, if there is one. Converting it,
    /// and choosing the default when there is none, is up to the caller.
    pub port: Option<&'a str>,
    /// The parameters after `sent-by`, such as `branch` and `received`.
    pub params: Params<'a>,
    /// The whole `via-parm` as written, from the protocol name to the end of
    /// the last parameter.
    ///
    /// A server that adds `received` or a value for `rport` (RFC 3261
    /// section 18.2.1, RFC 3581) inserts it where this ends.
    pub text: &'a str,
}

/// Iterates over the `via-parm`s of a Via value, from the topmost down.
///
/// RFC 3261, Section 25.1:
///
/// ```text
/// Via  =  ( "Via" / "v" ) HCOLON via-parm *(COMMA via-parm)
/// ```
///
/// As with [`addresses`], each item is a value or the error that ends the
/// list, and a list has at least one value. The parameters are
/// `generic-param`s, except that a `received` may also be an IPv6 address
/// without brackets, as `via-received` has it.
///
/// # Errors
///
/// An item is an [`ErrorKind::Via`](crate::ErrorKind::Via) error where the
/// list does not go on with a `via-parm`, and an
/// [`ErrorKind::GenericParam`](crate::ErrorKind::GenericParam) error where a
/// parameter is malformed.
///
/// # Example
///
/// ```
/// use siparse::value;
///
/// let value = "SIP/2.0/UDP pc33.atlanta.example.com:5060;branch=z9hG4bK776asdhds\
///              ;received=2001:db8::9, SIP/2.0/TCP [2001:db8::1]";
/// let mut vias = value::via_parms(value);
///
/// let top = vias.next().unwrap()?;
/// assert_eq!((top.protocol, top.version, top.transport), ("SIP", "2.0", "UDP"));
/// assert_eq!((top.host, top.port), ("pc33.atlanta.example.com", Some("5060")));
/// let received = top.params.iter().find(|param| param.name == "received");
/// assert_eq!(received.and_then(|param| param.value), Some("2001:db8::9"));
///
/// // What a proxy that removes its own Via value writes back.
/// assert_eq!(vias.as_str(), " SIP/2.0/TCP [2001:db8::1]");
///
/// let next = vias.next().unwrap()?;
/// assert_eq!((next.host, next.port), ("[2001:db8::1]", None));
/// assert!(vias.next().is_none());
/// # Ok::<(), siparse::Error>(())
/// ```
#[inline]
pub fn via_parms(src: &str) -> ViaParms<'_> {
    ViaParms { list: List::new(src) }
}

/// An iterator over the `via-parm`s of a Via value.
///
/// See [`via_parms`].
#[derive(Clone, Debug)]
pub struct ViaParms<'a> {
    list: List<'a>,
}

impl<'a> ViaParms<'a> {
    /// Returns what is left of the value after the `via-parm`s read so far.
    ///
    /// After a value that a `,` follows, this is the rest of the value past
    /// the `,`, as written, whitespace included. A proxy that removes its own
    /// Via value from a response (RFC 3261 section 16.7) writes this back.
    /// Once the list has ended, by its last value or by an error, it is
    /// empty.
    #[inline]
    pub fn as_str(&self) -> &'a str {
        self.list.rest
    }
}

impl<'a> Iterator for ViaParms<'a> {
    type Item = Result<ViaParm<'a>, Error>;

    fn next(&mut self) -> Option<Result<ViaParm<'a>, Error>> {
        self.list.next(via_parm_prefix, Error::via())
    }
}

impl FusedIterator for ViaParms<'_> {}

/// Reads a `via-parm` from the start of `src`, returning what follows it.
fn via_parm_prefix(src: &str) -> Result<(ViaParm<'_>, &str), Error> {
    let invalid = Error::via();
    let src = scan::sws(src);

    // SLASH is `SWS "/" SWS`, so whitespace may sit around each `/`.
    let (protocol, rest) = scan::token(src).ok_or(invalid)?;
    let rest = scan::separator(rest, '/').ok_or(invalid)?;
    let (version, rest) = scan::token(rest).ok_or(invalid)?;
    let rest = scan::separator(rest, '/').ok_or(invalid)?;
    let (transport, rest) = scan::token(rest).ok_or(invalid)?;

    let rest = scan::lws(rest).ok_or(invalid)?;
    let (host, rest) = scan::host(rest).ok_or(invalid)?;
    let (port, rest) = match scan::separator(rest, ':') {
        Some(after) => {
            let (port, rest) = scan::digits(after).ok_or(invalid)?;
            (Some(port), rest)
        }
        None => (None, rest),
    };
    let (params, rest) = params_of(rest, via_param, Error::generic_param())?;

    let text = &src[..src.len() - rest.len()];
    let via =
        ViaParm { protocol, version, transport, host, port, params, text };
    Ok((via, rest))
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

    fn via_list(src: &str) -> Result<Vec<ViaParm<'_>>, ErrorKind> {
        via_parms(src).collect::<Result<_, _>>().map_err(|err| err.kind())
    }

    #[test]
    fn via_parms_come_in_every_form() {
        let cases = [
            (
                "SIP/2.0/UDP pc33.atlanta.example.com:5060;branch=z9hG4bK776asdhds",
                ("SIP", "2.0", "UDP"),
                ("pc33.atlanta.example.com", Some("5060")),
                ";branch=z9hG4bK776asdhds",
            ),
            ("SIP/2.0/TCP 192.0.2.4", ("SIP", "2.0", "TCP"), ("192.0.2.4", None), ""),
            (
                "SIP/2.0/TLS [2001:db8::1]:5061;rport",
                ("SIP", "2.0", "TLS"),
                ("[2001:db8::1]", Some("5061")),
                ";rport",
            ),
            (
                " sip / 2.0 /\r\n udp \t host : 5060 ;\r\n branch = z9hG4bK1 ",
                ("sip", "2.0", "udp"),
                ("host", Some("5060")),
                ";\r\n branch = z9hG4bK1",
            ),
            ("X-P/9/X-T h", ("X-P", "9", "X-T"), ("h", None), ""),
        ];

        for (src, protocol, sent_by, params) in cases {
            let list =
                via_list(src).unwrap_or_else(|err| panic!("{src:?}: {err:?}"));
            let [via] = list.as_slice() else { panic!("{src:?}: {list:?}") };
            assert_eq!(
                (via.protocol, via.version, via.transport),
                protocol,
                "{src:?}"
            );
            assert_eq!((via.host, via.port), sent_by, "{src:?}");
            assert_eq!(via.params.as_str(), params, "{src:?}");
            assert_eq!(
                via.text,
                src.trim_matches([' ', '\t', '\r', '\n']),
                "{src:?}"
            );
        }
    }

    #[test]
    fn via_received_may_be_a_bare_address() {
        let src = "SIP/2.0/UDP h;received=2001:db8::9;RECEIVED=192.0.2.4;\
                   received=[2001:db8::2];rport=5060;ttl=16;maddr=239.255.255.1";
        let list = via_list(src).unwrap();
        assert_eq!(
            list[0].params.iter().collect::<Vec<_>>(),
            [
                param("received", Some("2001:db8::9")),
                param("RECEIVED", Some("192.0.2.4")),
                param("received", Some("[2001:db8::2]")),
                param("rport", Some("5060")),
                param("ttl", Some("16")),
                param("maddr", Some("239.255.255.1")),
            ]
        );

        // Only Via has `via-received`. Elsewhere it is a `generic-param`.
        assert_eq!(
            address("<sip:a@x>;received=2001:db8::9")
                .map_err(|err| err.kind()),
            Err(ErrorKind::Address)
        );
        assert_eq!(
            via_list("SIP/2.0/UDP h;x=2001:db8::9"),
            Err(ErrorKind::Via)
        );
    }

    #[test]
    fn via_lists_and_what_is_left() {
        let src = "SIP/2.0/UDP a;branch=z9hG4bK1;x=\"q,;\" ,\r\n SIP/2.0/TCP b:5060 , SIP/2.0/UDP c";
        let mut vias = via_parms(src);
        assert_eq!(vias.as_str(), src);

        let top = vias.next().unwrap().unwrap();
        assert_eq!(top.text, "SIP/2.0/UDP a;branch=z9hG4bK1;x=\"q,;\"");
        assert_eq!(vias.as_str(), "\r\n SIP/2.0/TCP b:5060 , SIP/2.0/UDP c");

        let second = vias.next().unwrap().unwrap();
        assert_eq!(second.text, "SIP/2.0/TCP b:5060");
        assert_eq!(vias.as_str(), " SIP/2.0/UDP c");

        let last = vias.next().unwrap().unwrap();
        assert_eq!(last.host, "c");
        assert_eq!(vias.as_str(), "");
        assert_borrowed(src, vias.as_str());
        assert!(vias.next().is_none());
    }

    #[test]
    fn malformed_via_parms() {
        for src in [
            "",
            " ",
            "SIP/2.0/UDP",
            "SIP/2.0/UDP ",
            "SIP/2.0 UDP host",
            "SIP/2.0/UDPhost",
            "SIP//UDP host",
            "SIP/2.0/UDP host:",
            "SIP/2.0/UDP host:abc",
            "SIP/2.0/UDP [::1",
            "SIP/2.0/UDP _host",
            "SIP/2.0/UDP host junk",
            "SIP/2.0/UDP host,",
            ", SIP/2.0/UDP host",
            "SIP/2.0/UDP a,,SIP/2.0/UDP b",
            "SIP/2.0/UDP h\u{e9}",
        ] {
            assert_eq!(via_list(src), Err(ErrorKind::Via), "{src:?}");
        }

        for src in [
            "SIP/2.0/UDP host;",
            "SIP/2.0/UDP host;branch=",
            "SIP/2.0/UDP host;received=",
            "SIP/2.0/UDP host;x=\"open",
        ] {
            assert_eq!(via_list(src), Err(ErrorKind::GenericParam), "{src:?}");
        }

        // An extension value outside `generic-param` ends the value early.
        assert_eq!(via_list("SIP/2.0/UDP host;x=a/b"), Err(ErrorKind::Via));
    }

    #[test]
    fn a_failed_list_leaves_nothing() {
        let src = "SIP/2.0/UDP a, junk";
        let mut vias = via_parms(src);
        assert!(vias.next().unwrap().is_ok());
        assert!(vias.next().unwrap().is_err());
        assert_eq!(vias.as_str(), "");
        assert_borrowed(src, vias.as_str());
        assert!(vias.next().is_none());

        let mut list = addresses("<sip:a@x> junk");
        assert!(list.next().unwrap().is_err());
        assert_eq!(list.as_str(), "");
    }

    #[test]
    fn addresses_show_what_is_left() {
        let src = "<sip:p1@x;lr>, \"B, b\" <sip:p2@x;lr>";
        let mut list = addresses(src);
        assert_eq!(list.as_str(), src);
        list.next().unwrap().unwrap();
        assert_eq!(list.as_str(), " \"B, b\" <sip:p2@x;lr>");
        list.next().unwrap().unwrap();
        assert_eq!(list.as_str(), "");
        assert_borrowed(src, list.as_str());
    }

    #[test]
    fn every_via_prefix_parses_or_fails_cleanly() {
        let value = "SIP/2.0/UDP [2001:db8::1]:5060;branch=z9hG4bK1;received=2001:db8::9;x=\"\u{7530};,\", SIP/2.0/TCP h";
        let ends = value.char_indices().map(|(i, _)| i);
        for end in ends.chain([value.len()]) {
            let src = &value[..end];
            let mut vias = via_parms(src);
            while let Some(item) = vias.next() {
                assert_borrowed(src, vias.as_str());
                let Ok(via) = item else { continue };
                for part in [
                    via.protocol,
                    via.version,
                    via.transport,
                    via.host,
                    via.text,
                ] {
                    assert_borrowed(src, part);
                }
                for param in via.params {
                    assert_borrowed(via.text, param.name);
                }
            }
        }
    }

    fn token_list(src: &str) -> Result<Vec<&str>, ErrorKind> {
        tokens(src).collect::<Result<_, _>>().map_err(|err| err.kind())
    }

    #[test]
    fn token_lists() {
        for (src, expected) in [
            ("100rel", &["100rel"][..]),
            ("100rel,timer", &["100rel", "timer"]),
            (
                " 100rel ,\r\n timer\t, replaces ",
                &["100rel", "timer", "replaces"],
            ),
            ("gzip, identity", &["gzip", "identity"]),
            ("INVITE,ACK,X-VENDOR", &["INVITE", "ACK", "X-VENDOR"]),
        ] {
            assert_eq!(token_list(src).as_deref(), Ok(expected), "{src:?}");
            for token in tokens(src).flatten() {
                assert_borrowed(src, token);
            }
        }

        for src in [
            "", " ", ",", ",a", "a,", "a,,b", "a , ,b", "a b", "a;b", "a/b",
            "a=b", "\"a\"", "\u{e9}", "a\u{e9}",
        ] {
            assert_eq!(token_list(src), Err(ErrorKind::Tokens), "{src:?}");
        }
    }

    #[test]
    fn token_lists_show_what_is_left() {
        let src = "a, b ,c";
        let mut list = tokens(src);
        assert_eq!(list.as_str(), src);
        assert_eq!(list.next(), Some(Ok("a")));
        assert_eq!(list.as_str(), " b ,c");
        assert_eq!(list.next(), Some(Ok("b")));
        assert_eq!(list.as_str(), "c");
        assert_eq!(list.next(), Some(Ok("c")));
        assert_eq!(list.as_str(), "");
        assert_borrowed(src, list.as_str());
        assert_eq!(list.next(), None);

        let mut list = tokens("a, b c");
        assert_eq!(list.next(), Some(Ok("a")));
        assert_eq!(
            list.next().map(|item| item.map_err(|err| err.kind())),
            Some(Err(ErrorKind::Tokens))
        );
        assert_eq!(list.as_str(), "");
        assert_eq!(list.next(), None);
    }

    fn media(src: &str) -> Result<(&str, &str, Vec<Param<'_>>), ErrorKind> {
        media_type(src)
            .map(|m| (m.kind, m.subtype, m.params.iter().collect()))
            .map_err(|err| err.kind())
    }

    #[test]
    fn media_types() {
        for (src, kind, subtype, params) in [
            ("application/sdp", "application", "sdp", vec![]),
            (
                " multipart/mixed ;\r\n boundary=unique-boundary-1 ",
                "multipart",
                "mixed",
                vec![param("boundary", Some("unique-boundary-1"))],
            ),
            (
                "text/plain;charset=\"utf-8\";format=flowed",
                "text",
                "plain",
                vec![
                    param("charset", Some("\"utf-8\"")),
                    param("format", Some("flowed")),
                ],
            ),
            ("Application / SDP", "Application", "SDP", vec![]),
            (
                "application/x-private;x=\"a;b,c\"",
                "application",
                "x-private",
                vec![param("x", Some("\"a;b,c\""))],
            ),
        ] {
            assert_eq!(media(src), Ok((kind, subtype, params)), "{src:?}");
        }

        for src in [
            "",
            "application",
            "application/",
            "/sdp",
            "application sdp",
            "application/sdp;",
            "application/sdp;charset",
            "application/sdp;charset=",
            "application/sdp;x=[::1]",
            "application/sdp;x=\"open",
            "application/sdp junk",
            "application/sdp, text/plain",
            "appl\u{e9}cation/sdp",
        ] {
            assert_eq!(media(src), Err(ErrorKind::MediaType), "{src:?}");
        }
    }

    #[test]
    fn media_ranges_and_their_weights() {
        let src =
            "application/sdp;level=1;q=0.8;ext, text/*;q=0.5,\r\n */*;q=0";
        let ranges: Vec<_> = media_ranges(src).map(|r| r.unwrap()).collect();
        assert_eq!(ranges.len(), 3);
        assert_eq!(
            (ranges[0].kind, ranges[0].subtype),
            ("application", "sdp")
        );
        assert_eq!(
            ranges[0].params.iter().collect::<Vec<_>>(),
            [
                param("level", Some("1")),
                param("q", Some("0.8")),
                param("ext", None)
            ]
        );
        assert_eq!((ranges[1].kind, ranges[1].subtype), ("text", "*"));
        assert_eq!((ranges[2].kind, ranges[2].subtype), ("*", "*"));

        for q in ["0", "0.", "0.5", "0.123", "1", "1.", "1.000", "Q=1"] {
            let src = if q.starts_with('Q') {
                format!("*/*;{q}")
            } else {
                format!("*/*;q={q}")
            };
            assert!(media_ranges(&src).next().unwrap().is_ok(), "{src:?}");
        }
        for src in [
            "*/*;q=2",
            "*/*;q=1.5",
            "*/*;q=0.1234",
            "*/*;q=.5",
            "*/*;q=",
            "*/*;q",
            "*/*;q=\"1\"",
            "*/sdp",
            "*/sdp;q=1",
            "",
            "application/sdp,",
            ",application/sdp",
        ] {
            let first = media_ranges(src).collect::<Result<Vec<_>, _>>();
            assert_eq!(
                first.map_err(|err| err.kind()),
                Err(ErrorKind::MediaType),
                "{src:?}"
            );
        }
    }

    /// A scheme and its parameters as name and value pairs.
    type AuthParts<'a> = (&'a str, Vec<(&'a str, &'a str)>);

    fn auth_parts(src: &str) -> Result<AuthParts<'_>, ErrorKind> {
        challenge(src)
            .map(|a| {
                (
                    a.scheme,
                    a.params.iter().map(|p| (p.name, p.value)).collect(),
                )
            })
            .map_err(|err| err.kind())
    }

    #[test]
    fn challenges_from_the_rfcs() {
        // The WWW-Authenticate example of RFC 3261 section 20.44, folded.
        let src = "Digest realm=\"atlanta.com\",\r\n domain=\"sip:boxesbybob.com\", qop=\"auth\",\r\n nonce=\"f84f1cec41e6cbe5aea9c8e88d359\",\r\n opaque=\"\", stale=FALSE, algorithm=MD5";
        assert_eq!(
            auth_parts(src),
            Ok((
                "Digest",
                vec![
                    ("realm", "\"atlanta.com\""),
                    ("domain", "\"sip:boxesbybob.com\""),
                    ("qop", "\"auth\""),
                    ("nonce", "\"f84f1cec41e6cbe5aea9c8e88d359\""),
                    ("opaque", "\"\""),
                    ("stale", "FALSE"),
                    ("algorithm", "MD5"),
                ]
            ))
        );

        // A challenge for the SHA-256 algorithm that RFC 8760 adds.
        let src = "Digest algorithm=SHA-256, realm=\"atlanta.example.com\", qop=\"auth\", nonce=\"7900f98e-3d2d-4d9c-a3cb-0c5f7f7b2f0f\", opaque=\"\"";
        let found = challenge(src).unwrap();
        assert_eq!(
            found.params.iter().next(),
            Some(AuthParam { name: "algorithm", value: "SHA-256" })
        );
        assert_eq!(found.params.iter().count(), 5);
        assert_eq!(found.params.as_str(), &src["Digest ".len()..]);
        for param in found.params {
            assert_borrowed(src, param.name);
            assert_borrowed(src, param.value);
        }
    }

    #[test]
    fn credentials_from_the_rfcs() {
        // The Authorization example of RFC 3261 section 20.7.
        let alice = "Digest username=\"Alice\", realm=\"atlanta.com\",\r\n nonce=\"84a4cc6f3082121f32b42a2187831a9e\",\r\n response=\"7587245234b3434cc3412213e5f113a5432\"";
        assert_eq!(credentials(alice).map(|a| a.params.iter().count()), Ok(4));

        // Digest credentials with a `qop`, a nonce count and a client nonce.
        let src = "Digest username=\"bob\",\r\n realm=\"biloxi.com\",\r\n nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\",\r\n uri=\"sip:bob@biloxi.com\",\r\n qop=auth,\r\n nc=00000001,\r\n cnonce=\"0a4f113b\",\r\n response=\"6629fae49393a05397450978507c4ef1\",\r\n opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"";
        let found = credentials(src).unwrap();
        assert_eq!(found.scheme, "Digest");
        let names: Vec<_> = found.params.iter().map(|p| p.name).collect();
        assert_eq!(
            names,
            [
                "username", "realm", "nonce", "uri", "qop", "nc", "cnonce",
                "response", "opaque"
            ]
        );
        assert_eq!(
            (&found.params).into_iter().nth(5).map(|p| p.value),
            Some("00000001")
        );

        // A scheme other than Digest has the same shape.
        assert_eq!(
            credentials("NewAuth  token=abc , realm = \"a,b\" ")
                .map(|a| (a.scheme, a.params.as_str())),
            Ok(("NewAuth", "token=abc , realm = \"a,b\""))
        );
    }

    #[test]
    fn malformed_challenges() {
        for src in [
            "",
            "Digest",
            "Digest ",
            "Digestrealm=\"a\"",
            "Digest realm",
            "Digest realm=",
            "Digest realm=\"open",
            "Digest realm=\"a\",",
            "Digest ,realm=\"a\"",
            "Digest realm=\"a\",,nonce=\"b\"",
            "Digest realm=\"a\" nonce=\"b\"",
            "Digest realm=\"a\";nonce=\"b\"",
            "Digest realm=a/b",
            "Digest realm=[::1]",
            "\"Digest\" realm=\"a\"",
            "Digest realm=\"a\" junk",
        ] {
            assert_eq!(auth_parts(src), Err(ErrorKind::Auth), "{src:?}");
            assert_eq!(
                credentials(src).map_err(|err| err.kind()),
                Err(ErrorKind::Auth),
                "{src:?}"
            );
        }
    }

    fn token_param_list(src: &str) -> Result<Vec<(&str, &str)>, ErrorKind> {
        token_params(src)
            .map(|item| item.map(|t| (t.token, t.params.as_str())))
            .collect::<Result<_, _>>()
            .map_err(|err| err.kind())
    }

    #[test]
    fn single_tokens_with_parameters() {
        for (src, token, params) in [
            ("session", "session", ""),
            ("render;handling=optional", "render", ";handling=optional"),
            (" icon ; x=\"a;b\" ", "icon", "; x=\"a;b\""),
            ("presence;id=1234", "presence", ";id=1234"),
            ("active;expires=3600", "active", ";expires=3600"),
            (
                "terminated;reason=timeout;retry-after=30",
                "terminated",
                ";reason=timeout;retry-after=30",
            ),
            ("1800;refresher=uas", "1800", ";refresher=uas"),
            ("90", "90", ""),
        ] {
            let found = token_param(src)
                .unwrap_or_else(|err| panic!("{src:?}: {err}"));
            assert_eq!(
                (found.token, found.params.as_str()),
                (token, params),
                "{src:?}"
            );
            assert_borrowed(src, found.token);
            assert_borrowed(src, found.params.as_str());
        }

        for src in [
            "",
            ";handling=optional",
            "session handling",
            "a/b",
            "\"a\"",
            "a, b",
        ] {
            assert_eq!(
                token_param(src).map_err(|err| err.kind()),
                Err(ErrorKind::TokenParam),
                "{src:?}"
            );
        }
        for src in ["session;", "session;handling=", "a;b=\"open"] {
            assert_eq!(
                token_param(src).map_err(|err| err.kind()),
                Err(ErrorKind::GenericParam),
                "{src:?}"
            );
        }
    }

    #[test]
    fn lists_of_tokens_with_parameters() {
        assert_eq!(
            token_param_list(
                "SIP;cause=200;text=\"Call completed, elsewhere\",\r\n Q.850 ;cause=16"
            ),
            Ok(vec![
                ("SIP", ";cause=200;text=\"Call completed, elsewhere\""),
                ("Q.850", ";cause=16"),
            ])
        );
        assert_eq!(
            token_param_list("gzip;q=1.0, identity; q=0.5, *;q=0"),
            Ok(vec![
                ("gzip", ";q=1.0"),
                ("identity", "; q=0.5"),
                ("*", ";q=0")
            ])
        );
        assert_eq!(
            token_param_list("da, en-gb;q=0.8, en;q=0.7"),
            Ok(vec![("da", ""), ("en-gb", ";q=0.8"), ("en", ";q=0.7")])
        );

        for src in ["", ",a", "a,", "a,,b", "a b", "a;q=1 b"] {
            assert_eq!(
                token_param_list(src),
                Err(ErrorKind::TokenParam),
                "{src:?}"
            );
        }
        assert_eq!(token_param_list("a;q=, b"), Err(ErrorKind::GenericParam));

        let mut list = token_params("SIP;cause=200, Q.850");
        list.next().unwrap().unwrap();
        assert_eq!(list.as_str(), " Q.850");
    }

    #[test]
    fn call_ids_with_parameters() {
        for (src, call_id, params) in [
            // Replaces values in the form of RFC 3891's examples.
            (
                "98732@sip.example.com;from-tag=r33th4x0r;to-tag=ff87ff",
                "98732@sip.example.com",
                vec![param("from-tag", Some("r33th4x0r")), param("to-tag", Some("ff87ff"))],
            ),
            (
                "12adf2f34456gs5;to-tag=12345;from-tag=54321;early-only",
                "12adf2f34456gs5",
                vec![
                    param("to-tag", Some("12345")),
                    param("from-tag", Some("54321")),
                    param("early-only", None),
                ],
            ),
            // A Target-Dialog, whose tags RFC 4538 names local and remote.
            (
                " fa77as7dad8-sd98ajzz@host.example.com ;\r\n local-tag=kkaz- ;remote-tag=6544 ",
                "fa77as7dad8-sd98ajzz@host.example.com",
                vec![param("local-tag", Some("kkaz-")), param("remote-tag", Some("6544"))],
            ),
            ("a84b4c76e66710", "a84b4c76e66710", vec![]),
        ] {
            let found = call_id_params(src).unwrap_or_else(|err| panic!("{src:?}: {err}"));
            assert_eq!(found.call_id, call_id, "{src:?}");
            assert_eq!(found.params.iter().collect::<Vec<_>>(), params, "{src:?}");
            assert_borrowed(src, found.call_id);
            assert_borrowed(src, found.params.as_str());
        }

        for src in [
            "",
            ";to-tag=1",
            "@host;to-tag=1",
            "a@b@c;to-tag=1",
            "a b;to-tag=1",
            "a;to-tag=1 junk",
            "a,b",
        ] {
            assert_eq!(
                call_id_params(src).map_err(|err| err.kind()),
                Err(ErrorKind::CallId),
                "{src:?}"
            );
        }
        for src in ["a;", "a;to-tag=", "a;to-tag=\"open"] {
            assert_eq!(
                call_id_params(src).map_err(|err| err.kind()),
                Err(ErrorKind::GenericParam),
                "{src:?}"
            );
        }

        // A plain Call-ID still takes no parameters.
        assert_eq!(
            call_id("a84b4c76e66710;to-tag=1").map_err(|err| err.kind()),
            Err(ErrorKind::CallId)
        );
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

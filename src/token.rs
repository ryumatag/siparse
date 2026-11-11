macro_rules! byte_map {
    ($($p:pat_param)|+) => {{
        let mut map = [false; 256];
        let mut i = 0;

        while i < 256 {
            map[i] = matches!(i as u8, $($p)|+);
            i += 1;
        }

        map
    }}
}

const TOKEN_MAP: [bool; 256] = byte_map!(
    b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' |
    b'!' | b'%' | b'\'' | b'*' | b'+' | b'-' | b'.' |
    b'_' | b'`' | b'~'
);

const URI_TOKEN_MAP: [bool; 256] = byte_map!(
    b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' |
    b';' | b'/' | b'?' | b':' | b'@' | b'&' | b'=' | b'+' | b'$' | b',' |
    b'-' | b'_' | b'.' | b'!' | b'~' | b'*' | b'\'' | b'(' | b')' |
    b'%' | b'[' | b']'
);

// The URI set without the three bytes that RFC 3261 section 20 only allows
// in a URI inside angle brackets.
const ADDR_SPEC_MAP: [bool; 256] = byte_map!(
    b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' |
    b'/' | b':' | b'@' | b'&' | b'=' | b'+' | b'$' |
    b'-' | b'_' | b'.' | b'!' | b'~' | b'*' | b'\'' | b'(' | b')' |
    b'%' | b'[' | b']'
);

const HEADER_VALUE_ASCII_MAP: [bool; 256] = byte_map!(b'\t' | b' '..=b'~');

const REASON_PHRASE_OCTET_MAP: [bool; 256] = byte_map!(
    b';' | b'/' | b'?' | b':' | b'@' | b'&' | b'=' | b'+' | b'$' | b',' |
    b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' |
    b'-' | b'_' | b'.' | b'!' | b'~' | b'*' | b'\'' | b'(' | b')' |
    b' ' | b'\t'
);

const HOSTNAME_MAP: [bool; 256] = byte_map!(
    b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.'
);

const IPV6_MAP: [bool; 256] = byte_map!(
    b'0'..=b'9' | b'A'..=b'F' | b'a'..=b'f' | b':' | b'.'
);

/// Returns whether `b` is valid in a SIP `Method` token.
///
/// This follows RFC 3261's `token` production, which also defines
/// `extension-method`.
///
/// RFC 3261, Section 25.1:
///
/// > ```text
/// > token             =  1*(alphanum / "-" / "." / "!" / "%" / "*"
/// >                      / "_" / "+" / "`" / "'" / "~" )
/// > Method            =  INVITEm / ACKm / OPTIONSm / BYEm
/// >                      / CANCELm / REGISTERm
/// >                      / extension-method
/// > extension-method  =  token
/// > ```
#[inline]
pub(crate) const fn is_method_token(b: u8) -> bool {
    TOKEN_MAP[b as usize]
}

/// Returns whether `b` is accepted by the parser's syntactic `Request-URI`
/// prefilter.
///
/// This is intentionally not a complete SIP URI validator. `Request-URI`
/// in RFC 3261 is `SIP-URI / SIPS-URI / absoluteURI`, so the parser only
/// rejects raw bytes that are clearly invalid across those URI forms, such as
/// whitespace, controls, `DEL`, raw non-ASCII, and visible ASCII outside the
/// RFC 2396 `reserved` / `unreserved` / `%` classes.
#[inline]
pub(crate) const fn is_uri_token(b: u8) -> bool {
    URI_TOKEN_MAP[b as usize]
}

/// Returns whether `b` is accepted in an `addr-spec` that is not in angle
/// brackets.
///
/// This is the [`is_uri_token`] set without `;`, `,` and `?`. RFC 3261
/// section 20 requires the `name-addr` form for a URI that contains any of
/// them, so outside brackets `;` starts the header parameters and `,` the
/// next element of a list.
#[inline]
pub(crate) const fn is_addr_spec_token(b: u8) -> bool {
    ADDR_SPEC_MAP[b as usize]
}

/// Returns whether `b` is valid in a SIP header field name.
///
/// At the parser layer, header names are still raw bytes, but they must match
/// RFC 3261's `header-name` syntax.
///
/// RFC 3261, Section 25.1:
///
/// > ```text
/// > token        =  1*(alphanum / "-" / "." / "!" / "%" / "*"
/// >                 / "_" / "+" / "`" / "'" / "~" )
/// > header-name  =  token
/// > ```
#[inline]
pub(crate) const fn is_header_name_token(b: u8) -> bool {
    TOKEN_MAP[b as usize]
}

/// Returns whether `b` is accepted as an ASCII octet in a raw SIP header field
/// value.
///
/// This is the context-free fast-path ASCII predicate. Escaped controls and
/// `DEL` stop the scan and are checked separately by the header value parser.
/// Non-ASCII octets must be validated separately as complete modern UTF-8
/// sequences.
///
/// RFC 3261, Section 25.1:
///
/// > ```text
/// > TEXT-UTF8char  =  %x21-7E / UTF8-NONASCII
/// > UTF8-NONASCII  =  %xC0-DF 1UTF8-CONT
/// >                /  %xE0-EF 2UTF8-CONT
/// >                /  %xF0-F7 3UTF8-CONT
/// >                /  %xF8-Fb 4UTF8-CONT
/// >                /  %xFC-FD 5UTF8-CONT
/// > UTF8-CONT      =  %x80-BF
/// > header-value   =  *(TEXT-UTF8char / UTF8-CONT / LWS)
/// > ```
///
/// This generic extension-header production does not include the controls
/// permitted by `quoted-pair` in known headers. The parser accepts those
/// separately without validating header-specific quoted-string or comment
/// syntax. See the crate's header value policy.
#[inline]
pub(crate) const fn is_header_value_ascii(b: u8) -> bool {
    HEADER_VALUE_ASCII_MAP[b as usize]
}

/// Returns whether `b` is accepted as a non-escaped octet in a SIP
/// `Reason-Phrase`.
///
/// This excludes `%`, which is only valid as the first byte of an `escaped`
/// production (`"%" HEXDIG HEXDIG`).
///
/// RFC 3261, Section 25.1:
///
/// > ```text
/// > Reason-Phrase  =  *(reserved / unreserved / escaped / UTF8-NONASCII
/// >                   / UTF8-CONT / SP / HTAB)
/// > reserved       =  ";" / "/" / "?" / ":" / "@" / "&"
/// >                   / "=" / "+" / "$" / ","
/// > unreserved     =  alphanum / mark
/// > mark           =  "-" / "_" / "." / "!" / "~" / "*"
/// >                   / "'" / "(" / ")"
/// > escaped        =  "%" HEXDIG HEXDIG
/// > ```
#[inline]
pub(crate) const fn is_reason_phrase_octet(b: u8) -> bool {
    REASON_PHRASE_OCTET_MAP[b as usize]
}

/// Returns whether `b` is valid in an RFC 3261 `token`.
#[inline]
pub(crate) const fn is_token(b: u8) -> bool {
    TOKEN_MAP[b as usize]
}

/// Returns whether `b` is valid in a `hostname` or an `IPv4address`.
///
/// RFC 3261, Section 25.1:
///
/// > ```text
/// > hostname     =  *( domainlabel "." ) toplabel [ "." ]
/// > domainlabel  =  alphanum / alphanum *( alphanum / "-" ) alphanum
/// > toplabel     =  ALPHA / ALPHA *( alphanum / "-" ) alphanum
/// > IPv4address  =  1*3DIGIT "." 1*3DIGIT "." 1*3DIGIT "." 1*3DIGIT
/// > ```
///
/// This is the character class only. The structure is left to the consumer.
#[inline]
pub(crate) const fn is_hostname_byte(b: u8) -> bool {
    HOSTNAME_MAP[b as usize]
}

/// Returns whether `b` is valid inside the brackets of an `IPv6reference`.
///
/// RFC 3261, Section 25.1:
///
/// > ```text
/// > IPv6reference  =  "[" IPv6address "]"
/// > IPv6address    =  hexpart [ ":" IPv4address ]
/// > hexpart        =  hexseq / hexseq "::" [ hexseq ] / "::" [ hexseq ]
/// > hexseq         =  hex4 *( ":" hex4)
/// > hex4           =  1*4HEXDIG
/// > ```
///
/// This is the character class only. The structure is left to the consumer.
#[inline]
pub(crate) const fn is_ipv6_byte(b: u8) -> bool {
    IPV6_MAP[b as usize]
}

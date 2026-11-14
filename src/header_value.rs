/*!
Borrowed input whose head-level header-value syntax has been checked.
*/

use core::fmt;

use crate::{check, Error};

/// A header value validated by the head parser or [`HeaderValue::new`].
///
/// This guarantees modern UTF-8, well-formed folds and the head parser's
/// [header-value policy](crate#header-values). It does not validate a
/// particular header's grammar. Use [`crate::value`] for that.
///
/// The text stays borrowed and unchanged. Only grammar-aware scans can
/// return another checked value without validation. An arbitrary substring
/// might start inside an escaped control or a fold.
///
/// ```
/// use siparse::{HeaderValue, value};
/// let input = HeaderValue::new("314159 INVITE")?;
/// assert_eq!(value::cseq(input)?.number, "314159");
/// # Ok::<(), siparse::Error>(())
/// ```
///
/// Raw strings cannot bypass validation at a production boundary:
///
/// ```compile_fail
/// siparse::value::cseq("314159 INVITE"); // Expected HeaderValue, not &str.
/// ```
///
/// The private field prevents unchecked safe construction:
///
/// ```compile_fail
/// let value = siparse::HeaderValue { text: "unvalidated" };
/// ```
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct HeaderValue<'a> {
    text: &'a str,
}

impl<'a> HeaderValue<'a> {
    /// Checks a string using the head parser's header-value policy.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`check::header_value`].
    #[inline]
    pub fn new(text: &'a str) -> Result<HeaderValue<'a>, Error> {
        check::header_value(text.as_bytes())
    }

    /// Borrows text whose header-value syntax has already been validated.
    ///
    /// An owned header-value type can use this when borrowing its storage,
    /// provided every constructor and mutation preserves the same policy.
    ///
    /// # Safety
    ///
    /// `text` must be accepted by [`check::header_value`]. Valid UTF-8 alone
    /// is insufficient. A slice of a validated value need not satisfy this
    /// precondition, since it can split a fold or quoted-pair.
    ///
    /// Calling this constructor requires an explicit unsafe block:
    ///
    /// ```compile_fail
    /// siparse::HeaderValue::from_str_unchecked("unvalidated");
    /// ```
    #[inline]
    pub const unsafe fn from_str_unchecked(text: &'a str) -> HeaderValue<'a> {
        HeaderValue { text }
    }

    /// Returns the original text, including folds and escapes.
    #[inline]
    pub const fn as_str(self) -> &'a str {
        self.text
    }

    /// Returns the original bytes.
    #[inline]
    pub const fn as_bytes(self) -> &'a [u8] {
        self.text.as_bytes()
    }

    /// Returns the length in bytes.
    #[inline]
    pub const fn len(self) -> usize {
        self.text.len()
    }

    /// Returns whether the value is empty.
    #[inline]
    pub const fn is_empty(self) -> bool {
        self.text.is_empty()
    }

    /// Used only after validation or a grammar-aware split. The remainder
    /// must not start inside a quoted-pair, UTF-8 sequence or fold.
    #[inline]
    pub(crate) const fn from_validated(text: &'a str) -> HeaderValue<'a> {
        HeaderValue { text }
    }
}

impl AsRef<str> for HeaderValue<'_> {
    fn as_ref(&self) -> &str {
        self.text
    }
}

impl fmt::Display for HeaderValue<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.text)
    }
}

impl PartialEq<&str> for HeaderValue<'_> {
    fn eq(&self, other: &&str) -> bool {
        self.text == *other
    }
}

impl PartialEq<HeaderValue<'_>> for &str {
    fn eq(&self, other: &HeaderValue<'_>) -> bool {
        *self == other.text
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{scan, value, HeaderBuf, RequestHead};

    #[test]
    fn checked_input_preserves_bytes_and_rejects_broken_envelopes() {
        for text in
            ["", "plain", "田中", "a\r\n b", "\\", "\\\x01", "\"\\\x7f\""]
        {
            let input = HeaderValue::new(text).unwrap();
            assert_eq!(input.as_str().as_ptr(), text.as_ptr());
            assert_eq!(input.as_bytes(), text.as_bytes());
            assert_eq!(
                check::header_value_const(text.as_bytes()).unwrap(),
                input
            );
            assert_eq!(
                // SAFETY: The same text was checked immediately above.
                unsafe { HeaderValue::from_str_unchecked(text) },
                input
            );
        }
        for text in ["\x01", "a\nb", "a\rb", "a\r\nb", "a\r\n"] {
            assert!(HeaderValue::new(text).is_err(), "{text:?}");
            assert!(check::header_value_const(text.as_bytes()).is_err());
        }
        assert!(check::header_value(&[0xff]).is_err());
        assert_eq!(HeaderValue::default(), "");
    }

    #[test]
    fn head_output_feeds_productions_and_lexical_scans_directly() {
        let wire =
            b"INVITE sip:b@example.com SIP/2.0\r\nCSeq: 17 INVITE\r\n\r\n";
        let mut storage = HeaderBuf::<1>::new();
        let mut head = RequestHead::new(&mut storage);
        head.parse(wire).unwrap().unwrap();
        let input = head.headers[0].value;
        assert_eq!(value::cseq(input).unwrap().method, "INVITE");
        let (number, rest) = scan::digits(input).unwrap();
        assert_eq!(number, "17");
        let (method, rest) = scan::token(scan::lws(rest).unwrap()).unwrap();
        assert_eq!(method, "INVITE");
        assert!(rest.is_empty());
    }
}

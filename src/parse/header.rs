use core::{
    fmt, iter::FusedIterator, marker::PhantomData, mem::MaybeUninit,
    ops::Deref, slice,
};

use crate::{
    error::Error,
    iter::Bytes,
    parse::{Result, Status},
    simd,
    token::is_header_name_token,
    utf8::parse_utf8_run,
};

/// Fixed-capacity header row storage for up to `N` rows.
pub type HeaderBuf<'buf, const N: usize> =
    Headers<'buf, [MaybeUninit<Header<'buf>>; N]>;

/// Header row storage that the parser fills without initializing it first.
///
/// Callers create a fixed-capacity [`HeaderBuf`] and pass it by mutable
/// reference, which coerces to `&mut Headers`. The parser therefore does
/// not depend on the capacity. The filled rows are read through `Deref` to
/// `[Header]`.
///
/// The storage holds tokens that borrow the input buffer, so it cannot be kept
/// across a mutation of that buffer. Creating a new `HeaderBuf` for each parse
/// costs nothing because its slots are left uninitialized.
pub struct Headers<'buf, R: ?Sized = [MaybeUninit<Header<'buf>>]> {
    /// INVARIANT: `len <= rows.len()` and `rows[..len]` is initialized.
    len: usize,
    // `'buf` only appears in the default for `R`, so it needs a marker. The
    // unsized `rows` must stay the last field.
    _marker: PhantomData<Header<'buf>>,
    rows: R,
}

/// A parsed SIP header row.
///
/// `Header` represents one header field row exactly as it appeared in the
/// parsed head. Both fields borrow from the parsed input buffer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Header<'buf> {
    /// The header field name, without the whitespace that may precede `:`.
    ///
    /// The name is not case-normalized and compact forms such as `v` for `Via`
    /// are not expanded.
    pub name: &'buf str,
    /// The raw header field value, without the terminating `CRLF`.
    ///
    /// Leading `SP`, `HTAB`, and folds are not part of the value, because
    /// RFC 3261's `HCOLON` makes them part of the separator. Trailing
    /// whitespace is kept, since whether it carries meaning depends on the
    /// header's grammar. A folded value keeps its interior `CRLF` and the
    /// whitespace after it verbatim. [`Header::value_lines`] splits it at
    /// those folds.
    ///
    /// The value is modern UTF-8 and may contain ASCII controls or `DEL`
    /// after an unpaired backslash. Header-specific quoted-string and
    /// comment syntax is left to the consumer. See the crate's
    /// [header value policy](crate#header-values).
    pub value: &'buf str,
}

/// An iterator over the lines of a folded header value.
///
/// This is created by [`Header::value_lines`]. See its documentation for
/// details.
#[derive(Clone, Debug)]
pub struct ValueLines<'buf> {
    /// The value from the start of the next line, or `None` once the last
    /// line has been returned.
    rest: Option<&'buf str>,
}

impl<'buf, const N: usize> HeaderBuf<'buf, N> {
    /// Creates empty storage for up to `N` header rows.
    #[inline]
    pub const fn new() -> HeaderBuf<'buf, N> {
        Headers {
            len: 0,
            _marker: PhantomData,
            rows: [MaybeUninit::uninit(); N],
        }
    }
}

impl<'buf, const N: usize> Default for HeaderBuf<'buf, N> {
    #[inline]
    fn default() -> HeaderBuf<'buf, N> {
        HeaderBuf::new()
    }
}

impl<const N: usize> fmt::Debug for HeaderBuf<'_, N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let headers: &Headers<'_> = self;
        fmt::Debug::fmt(headers, f)
    }
}

impl<'buf, const N: usize> Deref for HeaderBuf<'buf, N> {
    type Target = [Header<'buf>];

    #[inline]
    fn deref(&self) -> &[Header<'buf>] {
        (self as &Headers<'buf>).as_slice()
    }
}

impl<'buf> Headers<'buf> {
    /// Returns the maximum number of header rows the storage can hold.
    #[inline]
    pub fn capacity(&self) -> usize {
        self.rows.len()
    }

    /// Returns the filled header rows.
    #[inline]
    pub fn as_slice(&self) -> &[Header<'buf>] {
        // SAFETY: `rows[..len]` is initialized, and `MaybeUninit<T>` has the
        // same layout as `T`.
        unsafe {
            slice::from_raw_parts(
                &self.rows as *const [MaybeUninit<Header<'buf>>]
                    as *const Header<'buf>,
                self.len,
            )
        }
    }

    #[inline]
    pub(super) fn clear(&mut self) {
        self.len = 0;
    }
}

impl fmt::Debug for Headers<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.as_slice()).finish()
    }
}

impl<'buf> Deref for Headers<'buf> {
    type Target = [Header<'buf>];

    #[inline]
    fn deref(&self) -> &[Header<'buf>] {
        self.as_slice()
    }
}

impl<'buf> Header<'buf> {
    /// Returns the lines of the value, split at each fold.
    ///
    /// A fold is a `CRLF` followed by `SP` or `HTAB`. Each item is the text
    /// between two folds, without the `CRLF` and the whitespace that starts
    /// the next line. [RFC 3261 section 7.3.1] treats a fold as a single
    /// `SP`, so joining the items with one `SP` gives the unfolded value.
    /// The items borrow from the input buffer, so this does not allocate.
    ///
    /// Whitespace before a fold stays at the end of its line, just as the
    /// RFC keeps it in the unfolded value. A value without folds, including
    /// an empty one, yields itself as its only line.
    ///
    /// The parser only stores `CRLF` in a value as part of a fold. For a
    /// `Header` built by hand, this splits at every `CRLF`.
    ///
    /// [RFC 3261 section 7.3.1]: https://www.rfc-editor.org/rfc/rfc3261#section-7.3.1
    ///
    /// # Example
    ///
    /// ```
    /// use siparse::Header;
    ///
    /// let header = Header {
    ///     name: "Subject",
    ///     value: "I know you're there,\r\n   pick up the phone",
    /// };
    ///
    /// let lines: Vec<&str> = header.value_lines().collect();
    /// assert_eq!(lines, ["I know you're there,", "pick up the phone"]);
    /// assert_eq!(lines.join(" "), "I know you're there, pick up the phone");
    /// ```
    #[inline]
    pub fn value_lines(&self) -> ValueLines<'buf> {
        ValueLines { rest: Some(self.value) }
    }
}

impl<'buf> Iterator for ValueLines<'buf> {
    type Item = &'buf str;

    #[inline]
    fn next(&mut self) -> Option<&'buf str> {
        let rest = self.rest?;
        match rest.split_once("\r\n") {
            Some((line, next)) => {
                self.rest = Some(next.trim_start_matches([' ', '\t']));
                Some(line)
            }
            None => {
                self.rest = None;
                Some(rest)
            }
        }
    }
}

impl FusedIterator for ValueLines<'_> {}

/// Parses header rows up to and including the empty line that terminates the
/// head, writing them into `headers` in wire order.
///
/// The row count is kept in a local and stored once on every exit, so the loop
/// does not write `headers.len` for each row. The rows parsed before a
/// `Status::Partial` or an error therefore stay readable.
#[inline]
pub(super) fn parse_headers<'buf>(
    headers: &mut Headers<'buf>,
    bytes: &mut Bytes<'buf>,
) -> Result<()> {
    let mut n_parsed = 0;

    let result = loop {
        match parse_header(bytes) {
            Ok(Status::Complete(Some(header))) => {
                let Some(slot) = headers.rows.get_mut(n_parsed) else {
                    break Err(Error::too_many_headers());
                };
                slot.write(header);
                n_parsed += 1;
            }
            Ok(Status::Complete(None)) => break Ok(Status::Complete(())),
            Ok(Status::Partial) => break Ok(Status::Partial),
            Err(err) => break Err(err),
        }
    };

    // `n_parsed` only grows after `get_mut(n_parsed)` succeeds, and every
    // slot below it was written, which upholds the `Headers` invariant.
    headers.len = n_parsed;
    result
}

/// Parses one header row, or the empty line that terminates the head.
///
/// Returns `None` for the terminating empty line.
#[inline]
fn parse_header<'buf>(buf: &mut Bytes<'buf>) -> Result<Option<Header<'buf>>> {
    match peek!(buf) {
        b'\r' => {
            // SAFETY: `peek` just returned a byte.
            unsafe { buf.advance(1) };

            return match next!(buf) {
                b'\n' => Ok(Status::Complete(None)),
                _ => Err(Error::bare_cr()),
            };
        }
        b'\n' => return Err(Error::bare_lf()),
        _ => {}
    }

    let name = complete!(parse_header_name(buf));
    ensure!(buf.next() == b':' => Error::missing_colon());

    while matches!(buf.peek(), Some(b' ' | b'\t')) {
        // SAFETY: `peek` just returned a byte.
        unsafe { buf.advance(1) };
    }

    let value = complete!(parse_header_value(buf));

    Ok(Status::Complete(Some(Header { name, value })))
}

#[allow(missing_docs)]
#[inline]
pub fn parse_header_name<'buf>(bytes: &mut Bytes<'buf>) -> Result<&'buf str> {
    let mark = bytes.mark_token();

    simd::match_header_name_vectored(bytes);

    // SAFETY: `match_header_name_vectored` only consumes bytes that satisfy
    // `is_header_name_token`, which only accepts ASCII.
    let name = unsafe { mark.exit_str(bytes) };

    match peek!(bytes) {
        b':' if name.is_empty() => Err(Error::header_name()),
        b':' => Ok(Status::Complete(name)),
        b' ' | b'\t' => {
            while matches!(bytes.peek(), Some(b' ' | b'\t')) {
                // SAFETY: `peek` just returned a byte.
                unsafe { bytes.advance(1) };
            }

            match peek!(bytes) {
                b':' if name.is_empty() => Err(Error::header_name()),
                b':' => Ok(Status::Complete(name)),
                b'\r' | b'\n' => Err(Error::missing_colon()),
                b if is_header_name_token(b) => Err(Error::missing_colon()),
                _ => Err(Error::header_name()),
            }
        }
        b'\r' | b'\n' => Err(Error::missing_colon()),
        _ => Err(Error::header_name()),
    }
}

#[allow(missing_docs)]
#[inline]
pub fn parse_header_value<'buf>(bytes: &mut Bytes<'buf>) -> Result<&'buf str> {
    let mut mark = bytes.mark_token();

    loop {
        simd::match_header_value_vectored(bytes);

        match peek!(bytes) {
            b'\r' => {
                // SAFETY: `peek` just returned a byte.
                unsafe { bytes.advance(1) };
                ensure!(bytes.next() == b'\n' => Error::bare_cr());
                match peek!(bytes) {
                    b' ' | b'\t' => {
                        // SAFETY: `peek!` just returned a byte.
                        unsafe { bytes.advance(1) };

                        // RFC 3261 defines `HCOLON = *( SP / HTAB ) ":" SWS`
                        // with `SWS = [LWS]`. A fold before the first value
                        // byte is therefore part of the separator, so the
                        // value starts after it and its whitespace.
                        // `parse_header` has already skipped `SP` / `HTAB`
                        // after the colon, so such a fold ends exactly 3 bytes
                        // past the mark.
                        //
                        // Checking here keeps leading folds off the common
                        // path, because only a fold reaches this arm.
                        if mark.len(bytes) == 3 {
                            while matches!(bytes.peek(), Some(b' ' | b'\t')) {
                                // SAFETY: `peek` just returned a byte.
                                unsafe { bytes.advance(1) };
                            }
                            mark = bytes.mark_token();
                        }
                    }
                    _ => {
                        // SAFETY: Every consumed byte is an ASCII
                        // `is_header_value_ascii` byte, an escaped ASCII
                        // control or `DEL`, part of a folding
                        // `CRLF` plus `SP` / `HTAB`, or part of a sequence
                        // accepted by `parse_utf8_run`. Trimming the
                        // terminating ASCII `CRLF` cannot split a sequence.
                        let value = unsafe { mark.exit_str_before(bytes, 2) };
                        return Ok(Status::Complete(value));
                    }
                }
            }
            // Non-ASCII bytes are validated in place on purpose. Two
            // alternatives measured worse in the benchmarks:
            //
            // * Deferring validation to the end of the value, with either
            //   `core::str::from_utf8` or `simdutf8`, was 15-45% slower for
            //   values under about 100 bytes. That covers most non-ASCII
            //   values in SIP heads.
            // * Moving this arm, or the rest of the value, into an
            //   `#[inline(never)]` function did not speed up ASCII-only
            //   heads and slowed down several UTF-8 cases by 5-20%.
            b if b >= 0x80 => {
                complete!(
                    parse_utf8_run(bytes).map_err(|_| Error::header_value())
                )
            }
            b'\n' => return Err(Error::bare_lf()),
            0x00..=0x08 | 0x0b..=0x0c | 0x0e..=0x1f | 0x7f => {
                // SAFETY: The prefix has already passed the ASCII, folding and
                // modern UTF-8 checks above. Earlier escaped controls are
                // ASCII too. The current byte is not included.
                let prefix = unsafe { mark.exit_str(bytes) };
                if !has_unpaired_backslash(prefix) {
                    return Err(Error::header_value());
                }
                // SAFETY: `peek!` just returned the control byte.
                unsafe { bytes.advance(1) };
            }
            _ => return Err(Error::header_value()),
        }
    }
}

// Only exceptional controls need this check. Keeping backslashes in the
// ordinary ASCII scan avoids tracking quote or comment state on the hot path.
// The consumer validates where quoted-pair is allowed by the field's grammar.
// Each backward scan covers a distinct run, so total work is linear.
#[cold]
fn has_unpaired_backslash(prefix: &str) -> bool {
    prefix.as_bytes().iter().rev().take_while(|&&b| b == b'\\').count() % 2
        == 1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ErrorKind;
    use std::{string::String, vec::Vec};

    #[test]
    fn quoted_pair_ascii_and_backslash_parity() {
        // A pair consumes its backslash. An even run therefore leaves the
        // following control unescaped, including inside a quoted string.
        for byte in 0..=0x7f {
            if matches!(byte, b'\r' | b'\n') {
                continue;
            }
            for slashes in 0..=7 {
                let mut input = Vec::from(&b"\"A"[..]);
                input.extend(core::iter::repeat(b'\\').take(slashes));
                input.push(byte);
                input.extend_from_slice(b"B\"\r\nX");
                let mut bytes = Bytes::new(&input);
                let result = parse_header_value(&mut bytes);
                if matches!(byte, b'\t' | b' '..=b'~') || slashes % 2 == 1 {
                    let value = result.unwrap().unwrap();
                    assert_eq!(value.as_bytes(), &input[..input.len() - 3]);
                    assert_eq!(bytes.remaining(), b"X");
                } else {
                    assert_eq!(
                        result.unwrap_err().kind(),
                        ErrorKind::HeaderValue
                    );
                }
            }
        }
    }

    #[test]
    fn backslash_does_not_escape_line_structure() {
        for prefix in [b"A".as_slice(), b"A\\", b"A\\\\"] {
            for (ending, expected) in [
                (b"\rX".as_slice(), ErrorKind::BareCr),
                (b"\nX".as_slice(), ErrorKind::BareLf),
            ] {
                let mut input = Vec::from(prefix);
                input.extend_from_slice(ending);
                let err =
                    parse_header_value(&mut Bytes::new(&input)).unwrap_err();
                assert_eq!(err.kind(), expected);
            }
            for ending in [b"\r\nX".as_slice(), b"\r\n\tB\r\nX"] {
                let mut input = Vec::from(prefix);
                input.extend_from_slice(ending);
                let mut bytes = Bytes::new(&input);
                let value = parse_header_value(&mut bytes).unwrap().unwrap();
                assert_eq!(value.as_bytes(), &input[..input.len() - 3]);
                assert_eq!(bytes.remaining(), b"X");
            }
        }
    }

    #[test]
    fn quoted_pair_does_not_bypass_utf8_validation() {
        for invalid in [
            b"\x80".as_slice(),
            b"\xc0\x80",
            b"\xed\xa0\x80",
            b"\xf4\x90\x80\x80",
            b"\xf8\x88\x80\x80\x80",
            b"\xff",
        ] {
            for prefix in [b"A\\".as_slice(), b"A\\\x00"] {
                let mut input = Vec::from(prefix);
                input.extend_from_slice(invalid);
                input.extend_from_slice(b"\r\nX");
                let err =
                    parse_header_value(&mut Bytes::new(&input)).unwrap_err();
                assert_eq!(err.kind(), ErrorKind::HeaderValue);
            }
        }
    }

    #[test]
    fn quoted_pair_at_word_boundaries_and_unaligned_inputs() {
        let word = core::mem::size_of::<usize>();
        for offset in 0..word {
            for padding in 0..=word * 2 {
                for slashes in [1, 2, 3, word + 1, word * 2] {
                    let mut input = std::vec![0xff; offset];
                    input.extend(core::iter::repeat(b'a').take(padding));
                    input.extend(core::iter::repeat(b'\\').take(slashes));
                    input.extend_from_slice(b"\x08\r\nX");
                    let mut bytes = Bytes::new(&input[offset..]);
                    let result = parse_header_value(&mut bytes);
                    if slashes % 2 == 1 {
                        assert_eq!(
                            result.unwrap().unwrap().as_bytes(),
                            &input[offset..input.len() - 3]
                        );
                        assert_eq!(bytes.remaining(), b"X");
                    } else {
                        assert_eq!(
                            result.unwrap_err().kind(),
                            ErrorKind::HeaderValue
                        );
                    }
                }
            }
        }
    }

    fn lines(value: &str) -> Vec<&str> {
        Header { name: "Subject", value }.value_lines().collect()
    }

    #[test]
    fn value_lines_splits_at_folds() {
        assert_eq!(lines(""), [""]);
        assert_eq!(lines("lunch"), ["lunch"]);
        assert_eq!(lines("lunch\r\n soon"), ["lunch", "soon"]);
        assert_eq!(
            lines("lunch\r\n \t soon\r\n\tok"),
            ["lunch", "soon", "ok"]
        );
        // Whitespace before a fold belongs to its line.
        assert_eq!(lines("lunch \r\n soon"), ["lunch ", "soon"]);
        // A line made only of whitespace is empty once its leading
        // whitespace is removed.
        assert_eq!(lines("lunch\r\n \r\n soon"), ["lunch", "", "soon"]);
        assert_eq!(lines("lunch\r\n "), ["lunch", ""]);
        // Non-ASCII text is never split.
        assert_eq!(lines("\u{1f600}\r\n \u{3042}"), ["\u{1f600}", "\u{3042}"]);
    }

    #[test]
    fn value_lines_is_fused() {
        let header = Header { name: "Subject", value: "a\r\n b" };
        let mut lines = header.value_lines();
        assert_eq!(lines.next(), Some("a"));
        assert_eq!(lines.next(), Some("b"));
        assert_eq!(lines.next(), None);
        assert_eq!(lines.next(), None);
    }

    // RFC 3261, Section 7.3.1:
    //
    // > The line break and the whitespace at the beginning of the next line
    // > are treated as a single SP character.
    //
    // This applies that sentence literally and checks that joining the lines
    // with `SP` gives the same result for every short value built from
    // the pieces below.
    #[test]
    #[cfg_attr(miri, ignore = "exhaustive input is too slow under Miri")]
    fn value_lines_joined_by_sp_matches_rfc_unfolding() {
        // Deliberately written differently from `ValueLines` so the two do
        // not share a mistake.
        fn unfold(value: &str) -> String {
            let mut unfolded = String::new();
            let mut chars = value.chars().peekable();
            while let Some(c) = chars.next() {
                if c == '\r' && chars.peek() == Some(&'\n') {
                    chars.next();
                    unfolded.push(' ');
                    while matches!(chars.peek(), Some(' ' | '\t')) {
                        chars.next();
                    }
                } else {
                    unfolded.push(c);
                }
            }
            unfolded
        }

        // The parser never stores a bare `CR` or a `CRLF` without whitespace
        // after it, but a `Header` built by hand can hold them.
        const PIECES: [&str; 7] =
            ["a", "\u{e9}", " ", "\t", "\r\n ", "\r\n", "\r"];
        let mut value = String::new();
        for len in 0..=6u32 {
            for mut n in 0..PIECES.len().pow(len) {
                value.clear();
                for _ in 0..len {
                    value.push_str(PIECES[n % PIECES.len()]);
                    n /= PIECES.len();
                }
                assert_eq!(
                    lines(&value).join(" "),
                    unfold(&value),
                    "{value:?}"
                );
            }
        }
    }

    #[test]
    fn value_lines_of_parsed_folded_value() {
        let input =
            b"Subject: I know you're there,\r\n  pick up\r\n\tthe phone\r\nX";
        let value =
            parse_header_value(&mut Bytes::new(&input[9..])).unwrap().unwrap();
        assert_eq!(
            lines(value),
            ["I know you're there,", "pick up", "the phone"]
        );
    }
}

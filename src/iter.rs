use core::{marker::PhantomData, slice, str};

// Modeled on httparse's `Bytes` (httparse/src/iter.rs).
//
// The cursor is a raw pointer rather than an index so that `cursor <= end`
// holds by construction. With an index the compiler could not prove that
// bound and kept panicking bounds checks in the SWAR loops and token
// slicing. Removing them made whole-head parsing 8-22% faster in the
// benchmarks. The cost is that `advance` is `unsafe`, so every caller must
// show that enough bytes remain, usually through the `peek` or `peek_n`
// right before it.
#[allow(missing_docs)]
#[derive(Debug)]
pub struct Bytes<'a> {
    start: *const u8,
    end: *const u8,
    /// INVARIANT: `start <= cursor && cursor <= end`.
    cursor: *const u8,
    phantom: PhantomData<&'a [u8]>,
}

/// The start position of a token the parser is about to consume.
///
/// A mark is resolved into a `&str` borrowed from the input buffer once the
/// production has validated every byte between the mark and the cursor.
#[derive(Clone, Copy, Debug)]
pub(crate) struct TokenMark {
    start: *const u8,
}

impl<'a> Bytes<'a> {
    #[allow(missing_docs)]
    #[inline]
    pub fn new(buf: &'a [u8]) -> Bytes<'a> {
        let range = buf.as_ptr_range();
        Bytes {
            start: range.start,
            end: range.end,
            cursor: range.start,
            phantom: PhantomData,
        }
    }

    #[inline]
    pub(crate) fn pos(&self) -> usize {
        self.cursor as usize - self.start as usize
    }

    #[inline]
    pub(crate) fn mark_token(&self) -> TokenMark {
        TokenMark { start: self.cursor }
    }

    #[inline]
    pub(crate) fn len(&self) -> usize {
        self.end as usize - self.cursor as usize
    }

    #[inline]
    pub(crate) fn is_empty(&self) -> bool {
        self.cursor == self.end
    }

    #[inline]
    pub(crate) fn remaining(&self) -> &'a [u8] {
        // SAFETY: `cursor..end` lies within the borrowed buffer.
        unsafe { slice::from_raw_parts(self.cursor, self.len()) }
    }

    #[inline]
    pub(crate) fn peek(&self) -> Option<u8> {
        if self.cursor < self.end {
            // SAFETY: `cursor` points at a byte of the buffer.
            Some(unsafe { *self.cursor })
        } else {
            None
        }
    }

    #[inline]
    pub(crate) fn peek_n<const N: usize>(&self) -> Option<[u8; N]> {
        // `self.remaining().get(..N)?.try_into().ok()` is equivalent, but
        // benchmarks showed that it slows down the entire head parser...
        if self.len() < N {
            return None;
        }
        // SAFETY: At least `N` bytes remain after the cursor, and
        // `read_unaligned` has no alignment requirement.
        Some(unsafe { (self.cursor as *const [u8; N]).read_unaligned() })
    }

    /// Advances the cursor by `n` bytes.
    ///
    /// # Safety
    ///
    /// `n` must not exceed [`Bytes::len`].
    #[inline]
    pub(crate) unsafe fn advance(&mut self, n: usize) {
        debug_assert!(n <= self.len());
        // SAFETY: Forwarded to the caller.
        self.cursor = unsafe { self.cursor.add(n) };
    }
}

impl Iterator for Bytes<'_> {
    type Item = u8;

    #[inline]
    fn next(&mut self) -> Option<u8> {
        let b = self.peek()?;
        // SAFETY: `peek` just returned a byte, so at least one remains.
        unsafe { self.advance(1) };
        Some(b)
    }
}

impl TokenMark {
    #[inline]
    pub(crate) fn is_empty(&self, bytes: &Bytes) -> bool {
        self.start == bytes.cursor
    }

    /// Returns the bytes from this mark up to the cursor as a `&str`.
    ///
    /// # Safety
    ///
    /// The mark must come from `bytes`. The caller must have validated every
    /// byte in that range as part of a production whose accepted set is a
    /// subset of modern UTF-8 (RFC 3629).
    #[inline]
    pub(crate) unsafe fn exit_str<'a>(self, bytes: &Bytes<'a>) -> &'a str {
        // SAFETY: Forwarded to the caller.
        unsafe { self.exit_str_before(bytes, 0) }
    }

    /// Returns the bytes from this mark up to `trim` bytes before the cursor
    /// as a `&str`.
    ///
    /// This exists for productions that only learn where a token ends after
    /// consuming its terminator, such as a header value followed by `CRLF`.
    ///
    /// # Safety
    ///
    /// Same as [`TokenMark::exit_str`], for the shortened range. The caller
    /// must also ensure that `trim` is at most the token length and does not
    /// split a multi-byte UTF-8 sequence.
    #[inline]
    pub(crate) unsafe fn exit_str_before<'a>(
        self,
        bytes: &Bytes<'a>,
        trim: usize,
    ) -> &'a str {
        let len = bytes.cursor as usize - self.start as usize;
        debug_assert!(trim <= len);

        // SAFETY: The mark came from `bytes` and the cursor only moves
        // forward, so `start..cursor - trim` lies within the buffer.
        let token = unsafe { slice::from_raw_parts(self.start, len - trim) };

        // Every parser production validates its bytes before resolving a
        // mark. Re-checking in debug builds turns a broken production into a
        // test failure instead of silent undefined behavior.
        debug_assert!(str::from_utf8(token).is_ok());

        // SAFETY: Forwarded to the caller.
        unsafe { str::from_utf8_unchecked(token) }
    }
}

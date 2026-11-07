use crate::{
    iter::Bytes,
    token::{
        is_header_name_token, is_header_value_ascii, is_hostname_byte,
        is_ipv6_byte, is_reason_phrase_octet, is_token, is_uri_token,
    },
};

const BLOCK_SIZE: usize = core::mem::size_of::<usize>();

type ByteBlock = [u8; BLOCK_SIZE];

const HI: usize = uniform_block(0x80);
const LO7: usize = uniform_block(0x7f);

// The `match_*_vectored` scans are `#[inline(always)]`. Each production has a
// copy for the head parser and one for `crate::check`, so a scan used by both
// has two callers. With a plain `#[inline]`, LLVM then kept the scan out of
// line in a binary that used both, and whole-head parsing got up to 28% slower
// in the benchmarks. Forcing the scans inline brought it back within noise.

// The URI scan checks each byte against the lookup table instead of using a
// bitwise block predicate. Rejecting the ten visible ASCII bytes outside the
// URI token set takes ten `eq_byte` tests per block, which measured up to 47%
// slower than eight table lookups on short URIs.
#[inline(always)]
pub(crate) fn match_uri_vectored(bytes: &mut Bytes<'_>) {
    while let Some(block) = bytes.peek_n::<BLOCK_SIZE>() {
        let n = match_block(is_uri_token, block);

        // SAFETY: `n <= BLOCK_SIZE`, and `peek_n` saw a full block.
        unsafe { bytes.advance(n) };

        if n != BLOCK_SIZE {
            return;
        }
    }

    let n = match_tail(is_uri_token, bytes.remaining());
    // SAFETY: `match_tail` returns at most the remaining length.
    unsafe { bytes.advance(n) };
}

#[inline(always)]
pub(crate) fn match_header_name_vectored(bytes: &mut Bytes<'_>) {
    while let Some(block) = bytes.peek_n::<BLOCK_SIZE>() {
        let n = match_block(is_header_name_token, block);

        // SAFETY: `n <= BLOCK_SIZE`, and `peek_n` saw a full block.
        unsafe { bytes.advance(n) };

        if n != BLOCK_SIZE {
            return;
        }
    }

    let n = match_tail(is_header_name_token, bytes.remaining());
    // SAFETY: `match_tail` returns at most the remaining length.
    unsafe { bytes.advance(n) };
}

/// Advances `bytes` over one block of ASCII header value bytes. Returns `true`
/// if the whole block matched or fewer than `BLOCK_SIZE` bytes remain, so the
/// scan should go on.
#[cfg(all(target_arch = "aarch64", target_endian = "little"))]
#[inline(always)]
pub(super) fn match_header_value_first_block(bytes: &mut Bytes<'_>) -> bool {
    let Some(block) = bytes.peek_n::<BLOCK_SIZE>() else {
        return true;
    };
    let n = match_header_value_block(block);

    // SAFETY: `n <= BLOCK_SIZE`, and `peek_n` saw a full block.
    unsafe { bytes.advance(n) };

    n == BLOCK_SIZE
}

#[inline(always)]
pub(crate) fn match_header_value_vectored(bytes: &mut Bytes<'_>) {
    while let Some(block) = bytes.peek_n::<BLOCK_SIZE>() {
        let n = match_header_value_block(block);

        // SAFETY: `n <= BLOCK_SIZE`, and `peek_n` saw a full block.
        unsafe { bytes.advance(n) };

        if n != BLOCK_SIZE {
            return;
        }
    }

    let n = match_tail(is_header_value_ascii, bytes.remaining());
    // SAFETY: `match_tail` returns at most the remaining length.
    unsafe { bytes.advance(n) };
}

#[inline(always)]
pub(crate) fn match_reason_phrase_ascii_vectored(bytes: &mut Bytes<'_>) {
    while let Some(block) = bytes.peek_n::<BLOCK_SIZE>() {
        let n = match_reason_phrase_ascii_block(block);

        // SAFETY: `n <= BLOCK_SIZE`, and `peek_n` saw a full block.
        unsafe { bytes.advance(n) };

        if n != BLOCK_SIZE {
            return;
        }
    }

    let n = match_tail(is_reason_phrase_octet, bytes.remaining());
    // SAFETY: `match_tail` returns at most the remaining length.
    unsafe { bytes.advance(n) };
}

// The scans for `crate::scan`. Each consumes the bytes of one class, so
// the caller finds the element's end at the cursor. They go through one
// generic loop, since a table lookup per byte is as fast as a bitwise block
// predicate for these sets (see the URI scan above) and keeps each one a
// line long.

#[inline]
pub(crate) fn match_token_vectored(bytes: &mut Bytes<'_>) {
    match_table_vectored(is_token, bytes);
}

#[inline]
pub(crate) fn match_digits_vectored(bytes: &mut Bytes<'_>) {
    match_table_vectored(|b| b.is_ascii_digit(), bytes);
}

#[inline]
pub(crate) fn match_hostname_vectored(bytes: &mut Bytes<'_>) {
    match_table_vectored(is_hostname_byte, bytes);
}

#[inline]
pub(crate) fn match_ipv6_vectored(bytes: &mut Bytes<'_>) {
    match_table_vectored(is_ipv6_byte, bytes);
}

/// Advances `bytes` over `qdtext`, stopping at the first `"` or `\`.
///
/// The content of a quoted string was checked as a header value already,
/// so only the two bytes that end or escape it matter here.
#[inline]
pub(crate) fn match_qdtext_vectored(bytes: &mut Bytes<'_>) {
    const DQUOTE: usize = uniform_block(b'"');
    const BACKSLASH: usize = uniform_block(b'\\');

    while let Some(block) = bytes.peek_n::<BLOCK_SIZE>() {
        let x = usize::from_ne_bytes(block);
        let n = offsetnz(eq_byte(x, DQUOTE) | eq_byte(x, BACKSLASH));

        // SAFETY: `n <= BLOCK_SIZE`, and `peek_n` saw a full block.
        unsafe { bytes.advance(n) };

        if n != BLOCK_SIZE {
            return;
        }
    }

    let n = scan_tail(|b| !matches!(b, b'"' | b'\\'), bytes.remaining());
    // SAFETY: `scan_tail` returns at most the remaining length.
    unsafe { bytes.advance(n) };
}

#[inline(always)]
fn match_table_vectored(
    predicate: impl Fn(u8) -> bool,
    bytes: &mut Bytes<'_>,
) {
    while let Some(block) = bytes.peek_n::<BLOCK_SIZE>() {
        let mut n = BLOCK_SIZE;
        for (i, &b) in block.iter().enumerate() {
            if !predicate(b) {
                n = i;
                break;
            }
        }

        // SAFETY: `n <= BLOCK_SIZE`, and `peek_n` saw a full block.
        unsafe { bytes.advance(n) };

        if n != BLOCK_SIZE {
            return;
        }
    }

    let n = scan_tail(&predicate, bytes.remaining());
    // SAFETY: `scan_tail` returns at most the remaining length.
    unsafe { bytes.advance(n) };
}

// The scans keep their own tail loop so that they add no callers to
// `match_tail`, which the head parser's scans share.
#[cold]
#[inline]
fn scan_tail(predicate: impl Fn(u8) -> bool, bytes: &[u8]) -> usize {
    for (i, &b) in bytes.iter().enumerate() {
        if !predicate(b) {
            return i;
        }
    }

    bytes.len()
}

/// Advances `bytes` to the first `\r\n\r\n` at or after the cursor and returns
/// `true`. Without one, it returns `false` and leaves the cursor somewhere in
/// the last three bytes, where a later match could still start.
///
/// The scan looks for `CR` one block at a time and checks the three bytes
/// after each one. A head has one `CR` per row, so the check runs once per row
/// and the block scan does the rest of the work.
#[inline]
pub(crate) fn find_head_end_vectored(bytes: &mut Bytes<'_>) -> bool {
    const CR: usize = uniform_block(b'\r');

    while let Some(block) = bytes.peek_n::<BLOCK_SIZE>() {
        let n = offsetnz(eq_byte(usize::from_ne_bytes(block), CR));

        // SAFETY: `n <= BLOCK_SIZE`, and `peek_n` saw a full block.
        unsafe { bytes.advance(n) };

        if n == BLOCK_SIZE {
            continue;
        }

        if is_head_end(bytes) {
            return true;
        }

        // SAFETY: The `CR` found above is at the cursor.
        unsafe { bytes.advance(1) };
    }

    // Fewer than `BLOCK_SIZE` bytes remain.
    while bytes.len() >= HEAD_END.len() {
        if is_head_end(bytes) {
            return true;
        }

        // SAFETY: At least `HEAD_END.len()` bytes remain.
        unsafe { bytes.advance(1) };
    }

    false
}

const HEAD_END: [u8; 4] = *b"\r\n\r\n";

#[inline]
fn is_head_end(bytes: &Bytes<'_>) -> bool {
    bytes.peek_n::<{ HEAD_END.len() }>() == Some(HEAD_END)
}

#[cold]
#[inline]
fn match_tail(predicate: impl Fn(u8) -> bool, bytes: &[u8]) -> usize {
    for (i, &b) in bytes.iter().enumerate() {
        if !predicate(b) {
            return i;
        }
    }

    bytes.len()
}

#[inline(always)]
fn match_block(predicate: impl Fn(u8) -> bool, block: ByteBlock) -> usize {
    for (i, &b) in block.iter().enumerate() {
        if !predicate(b) {
            return i;
        }
    }

    BLOCK_SIZE
}

#[inline]
fn match_header_value_block(block: ByteBlock) -> usize {
    // Controls and DEL stop even after a backslash. The header value parser
    // checks that context without adding state to the ASCII scan.
    const TAB: usize = uniform_block(b'\t');
    const DEL: usize = uniform_block(0x7f);
    const ASCII: usize = uniform_block(0x80);

    let x = usize::from_ne_bytes(block);
    let lt_sp = lt_byte(x, b' ');
    let eq_tab = eq_byte(x, TAB);
    let eq_del = eq_byte(x, DEL);

    offsetnz(((lt_sp & !eq_tab) | eq_del | (x & ASCII)) & HI)
}

#[inline]
fn match_reason_phrase_ascii_block(block: ByteBlock) -> usize {
    const TAB: usize = uniform_block(b'\t');
    const DEL: usize = uniform_block(0x7f);
    const ASCII: usize = uniform_block(0x80);

    const DQUOTE: usize = uniform_block(b'"');
    const HASH: usize = uniform_block(b'#');
    const PERCENT: usize = uniform_block(b'%');
    const LT: usize = uniform_block(b'<');
    const GT: usize = uniform_block(b'>');
    const LBRACKET: usize = uniform_block(b'[');
    const BACKSLASH: usize = uniform_block(b'\\');
    const RBRACKET: usize = uniform_block(b']');
    const CARET: usize = uniform_block(b'^');
    const BACKTICK: usize = uniform_block(b'`');
    const LBRACE: usize = uniform_block(b'{');
    const PIPE: usize = uniform_block(b'|');
    const RBRACE: usize = uniform_block(b'}');

    let x = usize::from_ne_bytes(block);
    let lt_sp = lt_byte(x, b' ');
    let eq_tab = eq_byte(x, TAB);
    let eq_del = eq_byte(x, DEL);

    let invalid_ascii = eq_byte(x, DQUOTE)
        | eq_byte(x, HASH)
        | eq_byte(x, PERCENT)
        | eq_byte(x, LT)
        | eq_byte(x, GT)
        | eq_byte(x, LBRACKET)
        | eq_byte(x, BACKSLASH)
        | eq_byte(x, RBRACKET)
        | eq_byte(x, CARET)
        | eq_byte(x, BACKTICK)
        | eq_byte(x, LBRACE)
        | eq_byte(x, PIPE)
        | eq_byte(x, RBRACE);

    offsetnz(((lt_sp & !eq_tab) | eq_del | invalid_ascii | (x & ASCII)) & HI)
}

// The lane predicates below are exact per byte. The classic tricks, such as
// `(x - 0x01..) & !x` for a zero byte, let a borrow leak out of a matching
// byte into its neighbor. Callers that only take the first set lane can
// usually live with that, because the leak only follows a real hit. The block
// matchers cannot, because they clear `TAB` lanes out of `lt_sp`. With the
// leaky forms, a `TAB` followed by `SP` rejected the `SP`, and a `TAB`
// followed by `BS` accepted the `BS`.
//
// Each predicate instead adds into the low 7 bits of every byte, where the sum
// stays below `0x100` and never carries into the next lane.

/// Sets the high bit of every byte of `x` that equals the matching byte of
/// `needle`, and clears all other bits.
#[inline]
fn eq_byte(x: usize, needle: usize) -> usize {
    let xor = x ^ needle;
    // A byte's bit 7 ends up set iff any of its bits is set, since the low 7
    // bits plus `0x7f` is at most `0xfe`.
    let nonzero = (xor & LO7).wrapping_add(LO7) | xor;
    !nonzero & HI
}

/// Sets the high bit of every byte of `x` that is less than `bound`, and
/// clears all other bits. `bound` must be at most `0x80`.
#[inline]
fn lt_byte(x: usize, bound: u8) -> usize {
    debug_assert!(bound <= 0x80);
    // The low 7 bits plus `0x80 - bound` reach bit 7 iff they are at least
    // `bound`, and the sum is at most `0xfe`. Bytes with bit 7 already set
    // are never less than `bound`.
    let at_least = (x & LO7).wrapping_add(uniform_block(0x80 - bound)) | x;
    !at_least & HI
}

#[inline]
const fn uniform_block(b: u8) -> usize {
    usize::from_ne_bytes([b; BLOCK_SIZE])
}

#[inline]
fn offsetnz(mask: usize) -> usize {
    if mask == 0 {
        return BLOCK_SIZE;
    }

    for (i, b) in mask.to_ne_bytes().iter().copied().enumerate() {
        if b != 0 {
            return i;
        }
    }

    unreachable!()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn match_len(src: &[u8], f: fn(u8) -> bool) -> usize {
        src.iter().take_while(|&&b| f(b)).count()
    }

    /// Checks every byte pair at every offset against the scalar predicate.
    ///
    /// Uniform blocks cannot catch a lane predicate that leaks into its
    /// neighbor, such as a `TAB` that changes how the next byte is classified.
    /// Placing two arbitrary bytes side by side can. The last offset straddles
    /// the block boundary.
    fn assert_byte_pairs_match_scalar(
        vectored: fn(&mut Bytes<'_>),
        predicate: fn(u8) -> bool,
    ) {
        for a in u8::MIN..=u8::MAX {
            for b in u8::MIN..=u8::MAX {
                for offset in 0..BLOCK_SIZE {
                    // `a` is accepted by every predicate tested here.
                    let mut input = [b'a'; BLOCK_SIZE * 2];
                    input[offset] = a;
                    input[offset + 1] = b;
                    let expected = match_len(&input, predicate);
                    let mut bytes = Bytes::new(&input);

                    vectored(&mut bytes);

                    assert_eq!(
                        bytes.pos(),
                        expected,
                        "pair=[{a:#04x}, {b:#04x}] offset={offset}",
                    );
                }
            }
        }
    }

    #[test]
    #[cfg_attr(miri, ignore = "exhaustive input is too slow under Miri")]
    fn uri_vectored_matches_scalar_for_byte_pairs() {
        assert_byte_pairs_match_scalar(match_uri_vectored, is_uri_token);
    }

    #[test]
    #[cfg_attr(miri, ignore = "exhaustive input is too slow under Miri")]
    fn header_name_vectored_matches_scalar_for_byte_pairs() {
        assert_byte_pairs_match_scalar(
            match_header_name_vectored,
            is_header_name_token,
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "exhaustive input is too slow under Miri")]
    fn header_value_vectored_matches_scalar_for_byte_pairs() {
        assert_byte_pairs_match_scalar(
            match_header_value_vectored,
            is_header_value_ascii,
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "exhaustive input is too slow under Miri")]
    fn reason_phrase_ascii_vectored_matches_scalar_for_byte_pairs() {
        assert_byte_pairs_match_scalar(
            match_reason_phrase_ascii_vectored,
            is_reason_phrase_octet,
        );
    }

    #[test]
    fn uri_vectored_matches_scalar() {
        for b in u8::MIN..=u8::MAX {
            let input = [b; BLOCK_SIZE * 2];
            let expected = match_len(&input, is_uri_token);
            let mut bytes = Bytes::new(&input);

            match_uri_vectored(&mut bytes);

            assert_eq!(bytes.pos(), expected, "byte={b:#04x}");
        }
    }

    #[test]
    fn header_name_vectored_matches_scalar() {
        for b in u8::MIN..=u8::MAX {
            let input = [b; BLOCK_SIZE * 2];
            let expected = match_len(&input, is_header_name_token);
            let mut bytes = Bytes::new(&input);

            match_header_name_vectored(&mut bytes);

            assert_eq!(bytes.pos(), expected, "byte={b:#04x}");
        }
    }

    #[test]
    fn header_value_vectored_matches_scalar() {
        for b in u8::MIN..=u8::MAX {
            let input = [b; BLOCK_SIZE * 2];
            let expected = match_len(&input, is_header_value_ascii);
            let mut bytes = Bytes::new(&input);

            match_header_value_vectored(&mut bytes);

            assert_eq!(bytes.pos(), expected, "byte={b:#04x}");
        }
    }

    #[test]
    fn reason_phrase_ascii_vectored_matches_scalar() {
        for b in u8::MIN..=u8::MAX {
            let input = [b; BLOCK_SIZE * 2];
            let expected = match_len(&input, is_reason_phrase_octet);
            let mut bytes = Bytes::new(&input);

            match_reason_phrase_ascii_vectored(&mut bytes);

            assert_eq!(bytes.pos(), expected, "byte={b:#04x}");
        }
    }
}

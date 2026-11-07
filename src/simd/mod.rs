//! Delimiter scans. SWAR works on every target. The header value scan also has
//! 16-byte paths for the SIMD baselines of aarch64 (NEON) and x86_64 (SSE2),
//! and leaves the last bytes to SWAR.

#[cfg(all(target_arch = "aarch64", target_endian = "little"))]
mod neon;
#[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
mod sse2;
mod swar;

pub(super) use self::swar::{
    match_digits_vectored, match_header_name_vectored,
    match_hostname_vectored, match_ipv6_vectored, match_qdtext_vectored,
    match_reason_phrase_ascii_vectored, match_token_vectored,
    match_uri_vectored,
};

#[cfg(feature = "__bench")]
pub(crate) use self::swar::{
    find_head_end_vectored as find_head_end_swar,
    match_header_value_vectored as match_header_value_swar,
};
use crate::iter::Bytes;

/// Advances `bytes` over ASCII header value bytes, stopping at the first byte
/// that the header value parser must look at.
#[inline(always)]
pub(crate) fn match_header_value_vectored(bytes: &mut Bytes<'_>) {
    // On aarch64 the first block is SWAR. A value often ends within it, and
    // the parser enters the scan again after each non-ASCII character and
    // escaped control. Moving a NEON mask to a general register cost more
    // than a whole SWAR block there. Starting with NEON made
    // `header_value/typical` 35% and `header_value/utf8/mixed` 95% slower
    // than SWAR alone. On x86_64, `pmovmskb` is cheap, and starting with SWAR
    // made `request_head/typical` slower again (-6% instead of -12% against
    // SWAR alone).
    #[cfg(all(target_arch = "aarch64", target_endian = "little"))]
    if !swar::match_header_value_first_block(bytes)
        || !neon::match_header_value(bytes)
    {
        return;
    }
    #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
    if !sse2::match_header_value(bytes) {
        return;
    }

    swar::match_header_value_vectored(bytes);
}

/// Advances `bytes` to the first `\r\n\r\n` at or after the cursor and returns
/// `true`, or returns `false` with the cursor in the last three bytes.
///
/// SSE2 or NEON skips the 16-byte blocks that cannot hold its start, and SWAR
/// finds it in the block that can. In a head that block is the last one.
#[inline]
pub(crate) fn find_head_end_vectored(bytes: &mut Bytes<'_>) -> bool {
    #[cfg(all(target_arch = "aarch64", target_endian = "little"))]
    neon::skip_head_end_blocks(bytes);
    #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
    sse2::skip_head_end_blocks(bytes);

    swar::find_head_end_vectored(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token::is_header_value_ascii;

    const LEN: usize = 48;

    fn expected(input: &[u8]) -> usize {
        input.iter().take_while(|&&b| is_header_value_ascii(b)).count()
    }

    fn scanned(input: &[u8]) -> usize {
        let mut bytes = Bytes::new(input);
        match_header_value_vectored(&mut bytes);
        bytes.pos()
    }

    // Every byte at every offset of every input length up to three 16-byte
    // blocks, so the vector blocks, the SWAR blocks, and the tail all see
    // each stopping byte. Miri checks the bytes at the edges of each class.
    #[test]
    fn header_value_matches_scalar_for_each_byte() {
        const EDGES: [u8; 9] =
            [0x00, 0x08, 0x09, 0x0a, 0x1f, 0x20, 0x7e, 0x7f, 0x80];

        for len in 0..=LEN {
            for offset in 0..len {
                for b in u8::MIN..=u8::MAX {
                    if cfg!(miri) && !EDGES.contains(&b) && b != 0xff {
                        continue;
                    }
                    let mut input = [b'a'; LEN];
                    input[offset] = b;
                    let input = &input[..len];
                    assert_eq!(
                        scanned(input),
                        expected(input),
                        "byte={b:#04x} offset={offset} len={len}",
                    );
                }
            }
        }
    }

    /// Checks a head-end scan against a search of every window.
    ///
    /// Every string of `CR`, `LF`, and `a` up to 7 bytes long goes at every
    /// offset of a run of `a`, which crosses the 8- and 16-byte blocks and
    /// their 2-byte overlap. The buffer either ends right after the string,
    /// for the tails, or runs on to 48 bytes. Miri gets strings up to 4 bytes.
    fn assert_head_end_matches_reference(scan: fn(&mut Bytes<'_>) -> bool) {
        const ALPHABET: [u8; 3] = *b"\r\na";
        let max_len = if cfg!(miri) { 4 } else { 7 };

        for len in 0..=max_len {
            for code in 0..ALPHABET.len().pow(len as u32) {
                let mut pattern = [0; 7];
                let mut rest = code;
                for b in &mut pattern[..len] {
                    *b = ALPHABET[rest % ALPHABET.len()];
                    rest /= ALPHABET.len();
                }

                for offset in 0..=LEN - len {
                    let mut input = [b'a'; LEN];
                    input[offset..offset + len]
                        .copy_from_slice(&pattern[..len]);
                    for end in [offset + len, LEN] {
                        let input = &input[..end];
                        let expected =
                            input.windows(4).position(|w| w == b"\r\n\r\n");
                        let mut bytes = Bytes::new(input);
                        let found = scan(&mut bytes);

                        match expected {
                            Some(at) => {
                                assert!(found, "{input:?}");
                                assert_eq!(bytes.pos(), at, "{input:?}");
                            }
                            None => {
                                assert!(!found, "{input:?}");
                                assert!(
                                    bytes.pos() >= end.saturating_sub(3),
                                    "{input:?}",
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn head_end_matches_reference() {
        assert_head_end_matches_reference(find_head_end_vectored);
    }

    #[test]
    fn swar_head_end_matches_reference() {
        assert_head_end_matches_reference(swar::find_head_end_vectored);
    }

    // Two arbitrary bytes side by side catch a lane predicate that leaks
    // into its neighbor. The offsets cross both 16-byte block boundaries.
    #[test]
    #[cfg_attr(miri, ignore = "exhaustive input is too slow under Miri")]
    fn header_value_matches_scalar_for_byte_pairs() {
        for a in u8::MIN..=u8::MAX {
            for b in u8::MIN..=u8::MAX {
                for offset in 0..LEN - 1 {
                    let mut input = [b'a'; LEN];
                    input[offset] = a;
                    input[offset + 1] = b;
                    assert_eq!(
                        scanned(&input),
                        expected(&input),
                        "pair=[{a:#04x}, {b:#04x}] offset={offset}",
                    );
                }
            }
        }
    }
}

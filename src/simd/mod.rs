//! Delimiter scans. SWAR works on every target. The header value scan also has
//! 16-byte paths for the SIMD baselines of aarch64 (NEON) and x86_64 (SSE2),
//! and leaves the last bytes to SWAR.

#[cfg(all(target_arch = "aarch64", target_endian = "little"))]
mod neon;
#[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
mod sse2;
mod swar;

pub(super) use self::swar::{
    find_head_end_vectored, match_digits_vectored, match_header_name_vectored,
    match_hostname_vectored, match_ipv6_vectored, match_qdtext_vectored,
    match_reason_phrase_ascii_vectored, match_token_vectored,
    match_uri_vectored,
};

use crate::iter::Bytes;

/// Advances `bytes` over ASCII header value bytes, stopping at the first byte
/// that the header value parser must look at.
///
/// The first block is SWAR. A value often ends within it, and the parser
/// enters the scan again after each non-ASCII character and escaped control.
/// On aarch64, moving a NEON mask to a general register cost more than a whole
/// SWAR block there: `header_value/typical` took 35% longer and
/// `header_value/utf8/mixed` 95% longer than with SWAR alone.
#[inline(always)]
pub(crate) fn match_header_value_vectored(bytes: &mut Bytes<'_>) {
    if !swar::match_header_value_first_block(bytes) {
        return;
    }

    #[cfg(all(target_arch = "aarch64", target_endian = "little"))]
    if !neon::match_header_value(bytes) {
        return;
    }
    #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
    if !sse2::match_header_value(bytes) {
        return;
    }

    swar::match_header_value_vectored(bytes);
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

//! 16-byte NEON scans for aarch64. NEON is part of the aarch64 baseline, so
//! these need no run-time detection.

use core::arch::aarch64::{
    vbicq_u8, vceqq_u8, vcgeq_u8, vcltq_u8, vdupq_n_u8, vget_lane_u64,
    vld1q_u8, vorrq_u8, vreinterpret_u64_u8, vreinterpretq_u16_u8,
    vshrn_n_u16,
};

use crate::iter::Bytes;

const BLOCK_SIZE: usize = 16;

/// Advances `bytes` over whole 16-byte blocks of ASCII header value bytes, and
/// stops at the start of the first block that holds a stopping byte, or when
/// fewer than 16 bytes remain. The SWAR scan finds the byte itself.
///
/// Finding the lane here would take a move from a NEON register, a bit
/// reverse, and a count, and the next row's loads would wait for all of it.
/// The SWAR scan finds it with branches that usually predict, so the core
/// runs ahead. On an Apple core, finding the lane here made
/// `request_head/typical` 20% slower than SWAR alone.
#[inline(always)]
pub(super) fn skip_header_value_blocks(bytes: &mut Bytes<'_>) {
    while let Some(block) = bytes.peek_n::<BLOCK_SIZE>() {
        // SAFETY: NEON is part of the aarch64 baseline.
        if unsafe { has_header_value_stop(block) } {
            return;
        }

        // SAFETY: `peek_n` saw a full block.
        unsafe { bytes.advance(BLOCK_SIZE) };
    }
}

/// Returns whether an ASCII header value scan stops anywhere in `block`.
///
/// A scan stops at a control other than `HTAB`, at `DEL`, and at any byte
/// from `0x80` up.
#[inline(always)]
unsafe fn has_header_value_stop(block: [u8; BLOCK_SIZE]) -> bool {
    // SAFETY: `block` is 16 readable bytes. The caller guarantees NEON.
    unsafe {
        let x = vld1q_u8(block.as_ptr());
        let control = vcltq_u8(x, vdupq_n_u8(b' '));
        let tab = vceqq_u8(x, vdupq_n_u8(b'\t'));
        // `DEL` and every non-ASCII byte in one compare.
        let del_or_high = vcgeq_u8(x, vdupq_n_u8(0x7f));
        let stops = vorrq_u8(vbicq_u8(control, tab), del_or_high);

        // NEON has no movemask. Shifting each 16-bit pair right by 4 and
        // narrowing keeps 4 bits of every lane in 64 bits.
        let nibbles = vshrn_n_u16::<4>(vreinterpretq_u16_u8(stops));
        vget_lane_u64::<0>(vreinterpret_u64_u8(nibbles)) != 0
    }
}

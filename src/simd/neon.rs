//! 16-byte NEON scans for aarch64. NEON is part of the aarch64 baseline, so
//! these need no run-time detection.

use core::arch::aarch64::{
    vbicq_u8, vceqq_u8, vcgeq_u8, vcltq_u8, vdupq_n_u8, vget_lane_u64,
    vld1q_u8, vorrq_u8, vreinterpret_u64_u8, vreinterpretq_u16_u8,
    vshrn_n_u16,
};

use crate::iter::Bytes;

const BLOCK_SIZE: usize = 16;

/// Advances `bytes` over whole 16-byte blocks of ASCII header value bytes.
///
/// Returns `false` once a block stops the scan, with the cursor on the
/// stopping byte. Returns `true` when fewer than 16 bytes remain, for the
/// SWAR scan to finish.
#[inline(always)]
pub(super) fn match_header_value(bytes: &mut Bytes<'_>) -> bool {
    while let Some(block) = bytes.peek_n::<BLOCK_SIZE>() {
        // SAFETY: NEON is part of the aarch64 baseline.
        let stops = unsafe { header_value_stops(block) };
        // The loop tests the mask itself and advances by a constant, so the
        // next load does not wait for this block. See `swar::first_lane`.
        if stops != 0 {
            // Each lane is 4 bits of `stops`.
            let lane = stops.trailing_zeros() as usize / 4;
            // SAFETY: `lane < BLOCK_SIZE`, and `peek_n` saw a full block.
            unsafe { bytes.advance(lane) };
            return false;
        }

        // SAFETY: `peek_n` saw a full block.
        unsafe { bytes.advance(BLOCK_SIZE) };
    }

    true
}

/// Returns 4 set bits for each lane where an ASCII header value scan stops,
/// and 0 for the others, lane 0 in the low bits.
///
/// A scan stops at a control other than `HTAB`, at `DEL`, and at any byte
/// from `0x80` up.
#[inline(always)]
unsafe fn header_value_stops(block: [u8; BLOCK_SIZE]) -> u64 {
    // SAFETY: `block` is 16 readable bytes. The caller guarantees NEON.
    unsafe {
        let x = vld1q_u8(block.as_ptr());
        let control = vcltq_u8(x, vdupq_n_u8(b' '));
        let tab = vceqq_u8(x, vdupq_n_u8(b'\t'));
        // `DEL` and every non-ASCII byte in one compare.
        let del_or_high = vcgeq_u8(x, vdupq_n_u8(0x7f));
        let stops = vorrq_u8(vbicq_u8(control, tab), del_or_high);

        // NEON has no movemask. Shifting each 16-bit pair right by 4 and
        // narrowing keeps 4 bits of every lane, in lane order.
        let nibbles = vshrn_n_u16::<4>(vreinterpretq_u16_u8(stops));
        vget_lane_u64::<0>(vreinterpret_u64_u8(nibbles))
    }
}

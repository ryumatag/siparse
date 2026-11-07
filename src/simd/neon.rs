//! 16-byte NEON scans for aarch64. NEON is part of the aarch64 baseline, so
//! these need no run-time detection.

use core::arch::aarch64::{
    uint8x16_t, vandq_u8, vbicq_u8, vceqq_u8, vcgeq_u8, vcltq_u8, vdupq_n_u8,
    vget_lane_u64, vld1q_u8, vorrq_u8, vreinterpret_u64_u8,
    vreinterpretq_u16_u8, vshrn_n_u16,
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

        lane_nibbles(stops)
    }
}

/// Returns 4 bits of each lane of a compare result, lane 0 in the low bits.
///
/// NEON has no movemask. Shifting each 16-bit pair right by 4 and narrowing
/// keeps 4 bits of every lane, in lane order.
#[inline(always)]
unsafe fn lane_nibbles(mask: uint8x16_t) -> u64 {
    // SAFETY: The caller guarantees NEON.
    unsafe {
        let nibbles = vshrn_n_u16::<4>(vreinterpretq_u16_u8(mask));
        vget_lane_u64::<0>(vreinterpret_u64_u8(nibbles))
    }
}

/// Advances `bytes` over 16-byte blocks that cannot hold the start of
/// `\r\n\r\n`, and stops at the first that can, or when fewer than 18 bytes
/// remain. See `swar::find_head_end_vectored` for the test and for what
/// finishes the search.
#[inline(always)]
pub(super) fn skip_head_end_blocks(bytes: &mut Bytes<'_>) {
    while bytes.len() >= BLOCK_SIZE + 2 {
        // SAFETY: At least 18 bytes follow the pointer, and NEON is part of
        // the aarch64 baseline.
        if unsafe { has_cr_pair(bytes.remaining().as_ptr()) } {
            return;
        }

        // SAFETY: More than a full block remains.
        unsafe { bytes.advance(BLOCK_SIZE) };
    }
}

/// Returns whether some byte among the 16 at `at` and the byte two after it
/// are both `CR`.
///
/// Both loads read the input itself, not a copy of it. See
/// `sse2::has_cr_pair` for why.
///
/// # Safety
///
/// At least 18 bytes must follow `at`, and the CPU must have NEON.
#[inline(always)]
unsafe fn has_cr_pair(at: *const u8) -> bool {
    // SAFETY: Both loads read within the 18 bytes the caller guarantees.
    unsafe {
        let cr = vdupq_n_u8(b'\r');
        let here = vceqq_u8(vld1q_u8(at), cr);
        let after_two = vceqq_u8(vld1q_u8(at.add(2)), cr);
        lane_nibbles(vandq_u8(here, after_two)) != 0
    }
}

//! 16-byte SSE2 scans for x86_64. SSE2 is part of the x86_64 baseline, so
//! these need no run-time detection.

use core::arch::x86_64::{
    _mm_and_si128, _mm_andnot_si128, _mm_cmpeq_epi8, _mm_cmplt_epi8,
    _mm_loadu_si128, _mm_movemask_epi8, _mm_or_si128, _mm_set1_epi8,
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
        // SAFETY: SSE2 is part of the x86_64 baseline.
        let stops = unsafe { header_value_stops(block) };
        // The loop tests the mask itself and advances by a constant, so the
        // next load does not wait for this block. See `swar::first_lane`.
        if stops != 0 {
            let lane = stops.trailing_zeros() as usize;
            // SAFETY: `lane < BLOCK_SIZE`, and `peek_n` saw a full block.
            unsafe { bytes.advance(lane) };
            return false;
        }

        // SAFETY: `peek_n` saw a full block.
        unsafe { bytes.advance(BLOCK_SIZE) };
    }

    true
}

/// Returns a bit for each lane where an ASCII header value scan stops, lane 0
/// in bit 0.
///
/// A scan stops at a control other than `HTAB`, at `DEL`, and at any byte
/// from `0x80` up.
#[inline(always)]
unsafe fn header_value_stops(block: [u8; BLOCK_SIZE]) -> u32 {
    // SAFETY: `block` is 16 readable bytes, and `_mm_loadu_si128` has no
    // alignment requirement. The caller guarantees SSE2.
    unsafe {
        let x = _mm_loadu_si128(block.as_ptr().cast());
        // Bytes from `0x80` up are negative as `i8`, so the signed compare
        // catches them together with the controls.
        let control_or_high = _mm_cmplt_epi8(x, _mm_set1_epi8(b' ' as i8));
        let tab = _mm_cmpeq_epi8(x, _mm_set1_epi8(b'\t' as i8));
        let del = _mm_cmpeq_epi8(x, _mm_set1_epi8(0x7f));
        let stops = _mm_or_si128(_mm_andnot_si128(tab, control_or_high), del);
        _mm_movemask_epi8(stops) as u32
    }
}

/// Advances `bytes` over 16-byte blocks that cannot hold the start of
/// `\r\n\r\n`, and stops at the first that can, or when fewer than 18 bytes
/// remain. See `swar::find_head_end_vectored` for the test and for what
/// finishes the search.
#[inline(always)]
pub(super) fn skip_head_end_blocks(bytes: &mut Bytes<'_>) {
    while let Some(window) = bytes.peek_n::<{ BLOCK_SIZE + 2 }>() {
        // SAFETY: SSE2 is part of the x86_64 baseline.
        if unsafe { has_cr_pair(window) } {
            return;
        }

        // SAFETY: `peek_n` saw more than a full block.
        unsafe { bytes.advance(BLOCK_SIZE) };
    }
}

/// Returns whether some byte in the first 16 of `window` and the byte two
/// after it are both `CR`.
#[inline(always)]
unsafe fn has_cr_pair(window: [u8; BLOCK_SIZE + 2]) -> bool {
    // SAFETY: Both loads read 16 of the 18 bytes of `window`, and
    // `_mm_loadu_si128` has no alignment requirement. The caller guarantees
    // SSE2.
    unsafe {
        let cr = _mm_set1_epi8(b'\r' as i8);
        let here = _mm_loadu_si128(window.as_ptr().cast());
        let after_two = _mm_loadu_si128(window.as_ptr().add(2).cast());
        let pairs = _mm_and_si128(
            _mm_cmpeq_epi8(here, cr),
            _mm_cmpeq_epi8(after_two, cr),
        );
        _mm_movemask_epi8(pairs) != 0
    }
}

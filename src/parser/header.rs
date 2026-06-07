use core::{mem::MaybeUninit, slice};

use crate::{
    error::Error,
    iter::Bytes,
    parser::{Result, Status},
    simd,
    token::is_header_name_token,
    utf8::parse_utf8_run,
};

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
    /// The raw header field value, without the optional `SP` / `HTAB`
    /// following `:` and without the terminating `CRLF`.
    ///
    /// A folded value keeps its interior `CRLF` and leading whitespace
    /// verbatim. Unfolding is left to the consumer.
    pub value: &'buf str,
}

impl<'buf> Header<'buf> {
    /// An empty header row placeholder for caller-provided storage.
    pub const EMPTY: Header<'buf> = Header { name: "", value: "" };
}

/// Parses header rows up to and including the empty line that terminates the
/// head, writing them into `headers` in wire order.
///
/// Returns the initialized prefix of `headers`. Slots are only ever written
/// with fully initialized `Header` values, which is what lets
/// `MessageHead::parse` pass initialized storage through this function.
#[inline]
pub(super) fn parse_headers<'hdr, 'buf>(
    headers: &'hdr mut [MaybeUninit<Header<'buf>>],
    buf: &mut Bytes<'buf>,
) -> Result<&'hdr [Header<'buf>]> {
    let mut n_parsed = 0;

    while let Some(header) = complete!(parse_header(buf)) {
        let Some(slot) = headers.get_mut(n_parsed) else {
            return Err(Error::too_many_headers());
        };
        slot.write(header);
        n_parsed += 1;
    }

    // Give up mutable access so the returned prefix can borrow for `'hdr`.
    let headers: &'hdr [MaybeUninit<Header<'buf>>] = headers;
    // Build the prefix from a raw pointer rather than with
    // `&headers[..n_parsed]` to drop a bounds check.
    //
    // SAFETY: `n_parsed` only grows after `get_mut(n_parsed)` succeeds, so
    // it never exceeds `headers.len()`. Every slot in `..n_parsed` was
    // written by the loop above. `MaybeUninit<T>` has the same layout as
    // `T`.
    let parsed = unsafe {
        slice::from_raw_parts(
            headers as *const [MaybeUninit<Header<'buf>>]
                as *const Header<'buf>,
            n_parsed,
        )
    };
    Ok(Status::Complete(parsed))
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
    let mark = bytes.mark_token();

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
                        unsafe { bytes.advance(1) }
                    }
                    _ => {
                        // SAFETY: Every consumed byte is an ASCII
                        // `is_header_value_ascii` byte, part of a folding
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
            _ => return Err(Error::header_value()),
        }
    }
}

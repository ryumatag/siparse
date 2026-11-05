#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| siparse_fuzz::find_head_end(input));

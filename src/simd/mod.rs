mod swar;

pub(super) use self::swar::{
    find_head_end_vectored, match_header_name_vectored,
    match_header_value_vectored, match_reason_phrase_ascii_vectored,
    match_uri_vectored,
};

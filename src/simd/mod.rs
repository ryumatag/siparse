mod swar;

pub(super) use self::swar::{
    find_head_end_vectored, match_digits_vectored, match_header_name_vectored,
    match_header_value_vectored, match_hostname_vectored, match_ipv6_vectored,
    match_qdtext_vectored, match_reason_phrase_ascii_vectored,
    match_token_vectored, match_uri_vectored,
};

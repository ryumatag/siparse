use criterion::{Bencher, Criterion, Throughput};
use siparse::_private as private;

mod corpus;
mod header_name;
mod header_value;
mod method;
mod reason;
mod request;
mod response;
mod status;
mod uri;
mod version;

// I `assert_eq!` on every benchmark iteration. For the argument behind
// this choice, see the linked jiff issue comment.
// https://github.com/BurntSushi/jiff/issues/38#issuecomment-2250207870

criterion::criterion_group! {
    name = benches;
    config = criterion::Criterion::default()
        .configure_from_args()
        .sample_size(200)
        .warm_up_time(std::time::Duration::from_secs(1))
        .measurement_time(std::time::Duration::from_secs(3));
    targets =
        // Public API. Judge parser changes by these benchmarks, and by the
        // `corpus` ones in particular.
        request::parse,
        response::parse,
        // Private API. These call one production directly, so the compiler
        // inlines it into the benchmark loop instead of into `parse_head`,
        // and the generated code differs from what the public API runs.
        // Many finish in a few nanoseconds, where code placement alone moves
        // results by several percent. Use them to locate a cost, not to
        // accept or reject a change.
        header_name::parse,
        header_value::parse,
        method::parse,
        reason::parse,
        status::parse,
        uri::parse,
        version::parse,
}

criterion::criterion_main!(benches);

/// Defines a Criterion benchmark for the given function.
///
/// `throughput_bytes` counts the bytes of the measured production itself.
/// It excludes terminators and sentinel bytes that only tell the parser
/// where the production ends. Whole-head benchmarks count the entire head.
///
/// This helper keeps Criterion settings in one place.
///
/// Borrowing this style from the `jiff-bench` crate.
fn benchmark(
    c: &mut Criterion,
    id: impl AsRef<str>,
    throughput_bytes: u64,
    f: impl FnMut(&mut Bencher<'_>),
) {
    // Criterion exposes throughput on `BenchmarkGroup`, not on the bare
    // `bench_function`. I split the slashed id into a group prefix and a
    // function name. For an id like
    // `parse/method/invite`, the group becomes `parse` and the function
    // becomes `method/invite`. Criterion concatenates the two back to
    // `parse/method/invite` for display.
    let id = id.as_ref();
    let (group, fn_id) = id.split_once('/').unwrap_or(("bench", id));
    c.benchmark_group(group)
        .throughput(Throughput::Bytes(throughput_bytes))
        .bench_function(fn_id, f);
}

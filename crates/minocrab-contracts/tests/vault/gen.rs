//! The property harness's proptest configuration — what the conformance and
//! oracle suites scale their case counts by. The seventeen-circuit vault's
//! scenario strategies that used to live here went with that vault (M44);
//! a property harness on the flush pattern is a follow-up.

use proptest::prelude::*;

/// Default case count for the heavier property tests.
pub const DEFAULT_CASES: u32 = 48;

/// `PROPTEST_CASES`-scaled config.
pub fn config() -> ProptestConfig {
    let cases = std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_CASES);
    ProptestConfig {
        cases,
        // The scenarios are large and shrinking them is not informative
        // (a shrunk 128-bit amount is just a different boundary case);
        // the failure message carries the whole scenario anyway.
        max_shrink_iters: 64,
        ..ProptestConfig::default()
    }
}

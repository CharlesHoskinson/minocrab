//! M27 rung 1's gate, driven from `cargo test`: the Lean syntax under
//! `lean/` (`MinocrabZkir`) must parse every v3 corpus artifact and print
//! it back BYTE FOR BYTE (notes/zkir-semantics.org §1, §8). The Lean side
//! is the instrument; this test only builds it, runs it over the corpus,
//! and asserts the count the way `corpus_roundtrip.rs` does, so a partial
//! checkout cannot be green by silence.
//!
//! Needs `lake` on PATH (the nix devshell provides Lean 4) and a compiled
//! corpus; without either it SKIPS with a loud message rather than fail,
//! the same policy as the Rust round-trip. CI's lean job runs the same
//! executable directly.

use std::path::Path;
use std::process::Command;

#[test]
fn lean_syntax_round_trips_the_v3_corpus_byte_for_byte() {
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let lean_dir = crate_dir.join("lean");
    let corpus = crate_dir.join("../../corpus/zkir");
    if !corpus.join("signet-midnight-examples").exists() {
        eprintln!("skipping: no corpus at {} (run corpus/compile.sh)", corpus.display());
        return;
    }
    let lake_present = Command::new("lake").arg("--version").output().is_ok();
    if !lake_present {
        eprintln!("skipping: `lake` not on PATH (enter the nix devshell for Lean 4)");
        return;
    }

    let build = Command::new("lake")
        .arg("build")
        .current_dir(&lean_dir)
        .output()
        .expect("run lake build");
    assert!(
        build.status.success(),
        "lake build failed in {}:\n{}{}",
        lean_dir.display(),
        String::from_utf8_lossy(&build.stdout),
        String::from_utf8_lossy(&build.stderr),
    );

    let exe = lean_dir.join(".lake/build/bin/zkir-roundtrip");
    let run = Command::new(&exe)
        .arg(&corpus)
        .output()
        .expect("run zkir-roundtrip");
    let stdout = String::from_utf8_lossy(&run.stdout);
    let stderr = String::from_utf8_lossy(&run.stderr);
    assert!(
        run.status.success(),
        "zkir-roundtrip reported failures:\n{stdout}{stderr}"
    );
    // THE COUNT IS ASSERTED, mirroring corpus_roundtrip.rs: the v3 count
    // moves only when the corpus does; update both in the same commit.
    // 722 → 739 v2 skipped at the M31 compactc bump (0.33.0-rc.2 → 0.34.0):
    // compact/examples/types/examples.compact compiles under language 0.26.0
    // and adds 17 v2 artifacts. The v3 count (92) does not move.
    // 92 → 95 v3 at M43 A: the second signet-midnight-integration pin
    // (pr127, e9350c4) adds the singleton's three circuits at PR #127.
    assert!(
        stdout.starts_with("95 ok, 0 failed, 739 v2 skipped"),
        "unexpected round-trip summary (corpus size moved?): {stdout}"
    );

    // The five ops and the alignment atoms / types the corpus never
    // exercises are covered by a hand-written fixture in compactc's
    // layout — parse/print consistency only, since no compactc output
    // exists for them (notes/zkir-semantics.org §1.4).
    let fixtures = lean_dir.join("fixtures");
    let run = Command::new(&exe)
        .arg(&fixtures)
        .output()
        .expect("run zkir-roundtrip on fixtures");
    assert!(
        run.status.success(),
        "fixture round-trip failed:\n{}{}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr),
    );
}

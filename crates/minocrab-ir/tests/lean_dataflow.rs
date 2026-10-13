//! M27 rung 2's gate: the Lean dataflow functions over the real IR
//! (`MinocrabZkir.Dataflow` in crates/minocrab-zkir/lean/) agree with
//! `operands_mut` / `returned_operands` / `defined_identifiers` on EVERY
//! corpus instruction (notes/zkir-semantics.org §8). Both sides print one
//! line per instruction — path, index, operands, returned, defines, with
//! wires by name and immediates as `#` — and the two texts must be equal.
//!
//! Skips loudly without `lake` on PATH or a compiled corpus, the policy of
//! the rest of the corpus-driven gates.

use std::path::{Path, PathBuf};
use std::process::Command;

use minocrab_ir::v3::passes::{defined_identifiers, operands, returned};
use minocrab_zkir::v3::Operand;

fn collect_zkir(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_zkir(&path, out);
        } else if path.extension().is_some_and(|e| e == "zkir") {
            out.push(path);
        }
    }
}

fn op_str(op: &Operand) -> String {
    match op {
        Operand::Variable(id) => id.0.clone(),
        Operand::Immediate(_) => "#".to_string(),
    }
}

fn join<I: IntoIterator<Item = String>>(items: I) -> String {
    items.into_iter().collect::<Vec<_>>().join(",")
}

/// The Rust side's dump, in the Lean executable's exact format.
fn rust_dump(corpus: &Path) -> String {
    let mut files = Vec::new();
    collect_zkir(corpus, &mut files);
    files.sort_by(|a, b| a.to_string_lossy().as_bytes().cmp(b.to_string_lossy().as_bytes()));
    let mut out = String::new();
    for path in &files {
        if minocrab_zkir::major_version(path).expect("corpus reads") != 3 {
            continue;
        }
        let ir = minocrab_zkir::v3::read_zkir(path).expect("corpus parses");
        for (idx, ins) in ir.instructions.iter().enumerate() {
            out.push_str(&format!(
                "{}\t{idx}\t{}\t{}\t{}\n",
                path.display(),
                join(operands(ins).iter().map(op_str)),
                join(returned(ins).iter().map(op_str)),
                join(defined_identifiers(ins).into_iter().map(|id| id.0)),
            ));
        }
    }
    out
}

#[test]
fn lean_dataflow_agrees_with_the_rust_functions_on_every_corpus_instruction() {
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let lean_dir = crate_dir.join("../minocrab-zkir/lean");
    let corpus = crate_dir.join("../../corpus/zkir");
    if !corpus.join("signet-midnight-examples").exists() {
        eprintln!("skipping: no corpus at {} (run corpus/compile.sh)", corpus.display());
        return;
    }
    if Command::new("lake").arg("--version").output().is_err() {
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
    let run = Command::new(lean_dir.join(".lake/build/bin/zkir-dataflow"))
        .arg(&corpus)
        .output()
        .expect("run zkir-dataflow");
    assert!(
        run.status.success(),
        "zkir-dataflow failed:\n{}",
        String::from_utf8_lossy(&run.stderr)
    );
    let lean = String::from_utf8(run.stdout).expect("utf-8 dump");
    let rust = rust_dump(&corpus);

    if lean != rust {
        for (i, (l, r)) in lean.lines().zip(rust.lines()).enumerate() {
            assert_eq!(l, r, "dataflow dumps differ at line {}:\n  lean: {l}\n  rust: {r}", i + 1);
        }
        panic!(
            "dataflow dumps differ in length: lean {} lines, rust {} lines",
            lean.lines().count(),
            rust.lines().count()
        );
    }
    let instructions = rust.lines().count();
    // THE COUNT IS ASSERTED, as in corpus_roundtrip.rs: it moves only when
    // the corpus does; update it in the same commit, naming the source.
    assert_eq!(
        // 16815 → 16666 at the M28 corpus refresh (4d9cf61): the Poseidon
        // protocol's seventeen vault circuits replace the nine keccak/SHA ones.
        // 16666 → 18663 at M43 A: the second signet-midnight-integration pin
        // (pr127, e9350c4) adds the singleton's three circuits at PR #127
        // (569 + 736 + 692 instructions) beside the fff3421c ones.
        // 18663 → 22885 at M44 A: the vault at 375071b (29 flush-pattern
        // circuits replacing 17) and the third signet-midnight-integration
        // pin (v0.24.1, a80e98e), the singleton's three circuits again.
        instructions, 22885,
        "corpus instruction count moved ({instructions}); recompiled or extended corpus?"
    );
    println!("lean and rust dataflow agree on {instructions} corpus instructions");
}

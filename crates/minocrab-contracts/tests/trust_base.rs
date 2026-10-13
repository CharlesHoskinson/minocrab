//! M33 — the trusted-computing-base inventory, generated not typed.
//!
//! `TRUST.md` at the repository root carries a table, one row per source
//! file of the seven eDSL crates: its lines, WHAT WARRANTS IT (which test,
//! proof or gate would catch a wrong line), and the failure that would hide
//! there if it were wrong. The rows whose warrant is READING are the trusted
//! computing base — the part a human reviewer has to read.
//!
//! The classification is DATA in this file ([`ROWS`]); the line counts are
//! measured; the table in `TRUST.md` is regenerated between its markers by
//! `MINOCRAB_TRUST_BASE=1 cargo test -p minocrab-contracts --test trust_base`
//! (the same reviewable-diff rule as the snapshots). The test fails when:
//! a classified file no longer exists, a source file of those crates is not
//! classified (closure, so a new file cannot slip in unwarranted), or the
//! table in `TRUST.md` is stale.
//!
//! THE ONE ERROR THE TABLE MUST NOT CONTAIN is a warrant claimed that is not
//! there: where unsure, a row says READING and a reviewer downgrades it,
//! never the reverse (milestones.org M33).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// A source file of the eDSL: path under `crates/`, its warrant, the
/// failure that would hide in it.
struct Row {
    path: &'static str,
    warrant: &'static str,
    hides: &'static str,
}

const READING: &str = "READING";

/// The classification. Order is the read order of `TRUST.md` §2 (bottom of
/// the stack first). Warrant names are test files, proof modules or gates
/// a reviewer can run; "READING" means nothing but a human's eyes.
const ROWS: &[Row] = &[
    // ---- L0: bindings -------------------------------------------------------------------
    Row { path: "minocrab-zkir/src/lib.rs", warrant: "corpus_roundtrip (92 v3 artifacts, count asserted); lean_roundtrip (byte-exact Lean syntax, M27 rung 1)", hides: "a `.zkir` envelope or version read wrongly — every differential reads compactc's artifacts through here" },
    Row { path: "minocrab-zkir/src/v3.rs", warrant: "corpus_roundtrip; lean_roundtrip; every differential (reads compactc's artifact through this pair)", hides: "an IR re-emitted differently from what was parsed" },
    // ---- L1: the builder -----------------------------------------------------------------
    Row { path: "minocrab-ir/src/lib.rs", warrant: READING, hides: "nothing beyond re-exports (41 lines)" },
    Row { path: "minocrab-ir/src/v3.rs", warrant: "every instruction-level differential (the emitted stream equals compactc's); v3_builder. The operand-type TABLES themselves: READING against zkir-v3/src/ir_vm.rs", hides: "an instruction emitted with an operand type the VM rejects, on a path no fixture takes" },
    Row { path: "minocrab-ir/src/v3/passes.rs", warrant: "Lean (crates/minocrab-ir/lean, the pass theorems, M25/M27); v3_passes; the zkir dump + row snapshot (every pass is zero-movement on the shipped artifacts)", hides: "a pass that changes a circuit's statement while preserving its rows" },
    Row { path: "minocrab-ir/src/v3/taint.rs", warrant: "Kani harnesses (./kani.sh, M23 R4) + unit tests for the Max arithmetic; 18 unit tests over the marking rules, the three subtraction warrants' near-miss refusals and the observability walk's refused sinks; the MARKING RULES' warrants are cited in-file per rule and are READING. The observability walk (M23 R3 Class A) reads operands through passes::operands / defined_identifiers, which the Lean dataflow gate diffs", hides: "a limb marked bounded that is not, or a guarded read discharged as unobservable whose digest in fact reaches an effect the walk's sink classification waves through — a false negative in the one lint that sees what honest inputs cannot" },
    // ---- L2: the eDSL --------------------------------------------------------------------
    Row { path: "minocrab/src/lib.rs", warrant: "compile_fail doctests (a private wire cannot reach an output); READING for the lattice itself (192 lines)", hides: "a Meet impl that lets private meet public as public" },
    Row { path: "minocrab/src/v3.rs", warrant: "every differential (the streams Circuit3 emits); v3_guard_scope (guard scopes); the generated disclosure set-equality tests + compile_fail (the disclose gate). The instruction methods' operand/immediate handling and public_input minting: READING against reduce-to-zkir.ss", hides: "a guard dropped on one effect inside `when`; a public input minted in the wrong order" },
    Row { path: "minocrab/src/v3/abi.rs", warrant: "v3_entry / v3_leaves / v3_bounded (the constraint table pinned to compactc's, notes/builtin-lowering.org §9); interface_snapshot", hides: "an argument type constrained to the wrong width" },
    Row { path: "minocrab/src/v3/disclose.rs", warrant: "the generated set-equality test on every circuit; disclosure_report; v3_disclose", hides: "a disclosure recorded under a label the signature does not name" },
    Row { path: "minocrab/src/v3/effects.rs", warrant: "v3_guard_scope; every differential with a branch", hides: "an effect escaping its guard" },
    // ---- L2.5: Impact ledger ops ----------------------------------------------------------
    // M26: split from one 3724-line lib.rs into modules by concern (zero
    // behavioural movement) — the warrant below is the whole op layer's and
    // applies unchanged to every file it was split across.
    Row { path: "minocrab-ledger/src/lib.rs", warrant: READING, hides: "nothing beyond the crate doc and mod/pub-use plumbing (102 lines)" },
    Row { path: "minocrab-ledger/src/impact.rs", warrant: "differential_baseline (call-compatibility with compactc's artifacts); every contract differential; nested_differential + nested_typed (nested paths); entry_point (315 contracts). Ops no fixture reaches (VERIFICATION.md §5 'unported constructs'): READING against midnight-ledger.ss vm-code", hides: "an Impact op encoded so the ledger applies a different state change than the circuit claims" },
    Row { path: "minocrab-ledger/src/ops.rs", warrant: "differential_baseline (call-compatibility with compactc's artifacts); every contract differential; nested_differential + nested_typed (nested paths); entry_point (315 contracts). Ops no fixture reaches (VERIFICATION.md §5 'unported constructs'): READING against midnight-ledger.ss vm-code", hides: "an Impact op encoded so the ledger applies a different state change than the circuit claims" },
    Row { path: "minocrab-ledger/src/reads.rs", warrant: "differential_baseline (call-compatibility with compactc's artifacts); every contract differential; nested_differential + nested_typed (nested paths); entry_point (315 contracts). Ops no fixture reaches (VERIFICATION.md §5 'unported constructs'): READING against midnight-ledger.ss vm-code", hides: "an Impact op encoded so the ledger applies a different state change than the circuit claims" },
    Row { path: "minocrab-ledger/src/kernel.rs", warrant: "differential_baseline (call-compatibility with compactc's artifacts); every contract differential; nested_differential + nested_typed (nested paths); entry_point (315 contracts). Ops no fixture reaches (VERIFICATION.md §5 'unported constructs'): READING against midnight-ledger.ss vm-code", hides: "an Impact op encoded so the ledger applies a different state change than the circuit claims" },
    Row { path: "minocrab-ledger/src/calls.rs", warrant: "differential_baseline (call-compatibility with compactc's artifacts); every contract differential; nested_differential + nested_typed (nested paths); entry_point (315 contracts). Ops no fixture reaches (VERIFICATION.md §5 'unported constructs'): READING against midnight-ledger.ss vm-code", hides: "an Impact op encoded so the ledger applies a different state change than the circuit claims" },
    Row { path: "minocrab-ledger/src/tests.rs", warrant: READING, hides: "a unit test that pins the wrong constant or asserts a weaker property than intended, unnoticed because it still passes" },
    // ---- L3: the standard library ---------------------------------------------------------
    Row { path: "minocrab-std/src/lib.rs", warrant: READING, hides: "nothing beyond re-exports (51 lines)" },
    Row { path: "minocrab-std/src/v3.rs", warrant: "every differential; v3_leaves / v3_bounded / v3_literals / v3_secp; lean_claims (the typed-leaf claims, crates/minocrab-std/lean). `from_field_unchecked` sites: READING (the grep in TRUST.md §3)", hides: "a leaf whose type promises a bound its constructor did not constrain" },
    Row { path: "minocrab-std/src/v3/ledger.rs", warrant: "every contract differential; v3_ledger; nested_typed; the derive's layout pinned against compactc's `batch` for all 256 block sizes and the sixteen-field probe", hides: "a typed slot reading the wrong field, or a segmented path computed differently from compactc" },
    Row { path: "minocrab-std/src/v3/borsh.rs", warrant: "serialization_conformance (vectors shared with the published TypeScript decoder, spec/ts); v3_borsh; the borsh differentials", hides: "a non-canonical encoding accepted, breaking the digest's injectivity (api-safety-survey §B3)" },
    Row { path: "minocrab-std/src/v3/borsh/schema.rs", warrant: "the generated schema cross-check test per #[derive(CircuitBorsh)] (layout ≡ borsh's schema of the spec type)", hides: "a layout table disagreeing with the published spec" },
    Row { path: "minocrab-std/src/v3/kernel.rs", warrant: "kernel_tokens_differential (24 circuits, byte-identical); v3_kernel_cache", hides: "a kernel effect claimed at the wrong effects index" },
    Row { path: "minocrab-std/src/v3/blind.rs", warrant: "v3_blind (every blind op run on Midnight's on-chain VM against a seeded state, zero reads asserted; the typed spellings byte-identical to the explicit op lists); v3_stream; evm_outbox", hides: "a blind combine or snapshot that lands a different value than the step defines, or one that embeds a read" },
    Row { path: "minocrab-std/src/v3/hook.rs", warrant: "v3_hook (every builder method on the on-chain VM, each failure row of the design table, attachment order, guard capture, the after-the-body rule; a composite hook byte-identical to the explicit op lists); the two compile-fail doctests", hides: "a hook lowered to ops that read, or emitted under the wrong guard or before an inline effect" },
    Row { path: "minocrab-std/src/v3/assumed.rs", warrant: "v3_ledger and every contract differential (the wrapper is erased in the ZKIR: byte-identical artifacts); the compile-fail doctest; the backstop's refusals in the contract suites named every read-modify-write in the corpus", hides: "a read result re-entering the ledger with nothing naming the assumption — a contended write nobody sees as one" },
    Row { path: "minocrab-std/src/v3/stream.rs", warrant: "v3_stream (insert / take / combine / sequence on the on-chain VM, both layouts); evm_outbox (the contention audit); fee_ema (flushes of one to four); the two compile-fail doctests", hides: "a stream operation reading the shared accumulator where the design says it must not" },
    Row { path: "minocrab-std/src/v3/vector.rs", warrant: "v3_vector (fold and for_each on the VM: live slots only, the guard and the select; the all-dead case unexpressible); v3_bounded", hides: "a fold applying its step, or a ledger op, on a dead slot" },
    Row { path: "minocrab-std/src/v3/entry.rs", warrant: "interface_snapshot (every circuit's argument schema frozen); v3_entry; every differential", hides: "an argument declared in a different slot order than the wire" },
    Row { path: "minocrab-std/src/v3/predicate.rs", warrant: "v3_predicates; every differential with a comparison", hides: "a comparison at the wrong width, or a message-carrying assert that binds outside its branch" },
    Row { path: "minocrab-std/src/v3/call.rs", warrant: "xcall_differential / xcall_with_payment_differential / xcontract_events_differential; interface_macro; contract_matches_its_interface", hides: "call limbs hashed into the communications commitment in the wrong order" },
    Row { path: "minocrab-std/src/v3/disclose.rs", warrant: "v3_disclose; the generated set-equality tests", hides: "a leaf disclosed under fewer wires than it has" },
    Row { path: "minocrab-std/src/v3/hash.rs", warrant: "hashing_differential; every differential that hashes", hides: "a preimage aligned differently from compactc's" },
    // ---- the decorators ------------------------------------------------------------------
    Row { path: "minocrab-macros/src/lib.rs", warrant: READING, hides: "nothing beyond wrappers (the expansions are the modules below)" },
    Row { path: "minocrab-macros/src/circuit.rs", warrant: "v3_circuit (the expansion lowers to ZKIR byte-identical to the hand-written twin); the generated per-circuit tests run on every circuit. The GENERATED TESTS' own bodies: READING", hides: "an expansion that declares an argument the twin would not, or a generated test that passes vacuously" },
    Row { path: "minocrab-macros/src/circuit_arg.rs", warrant: "v3_derive (twin); every derived struct's slots in interface_snapshot", hides: "a field's slots declared out of order" },
    Row { path: "minocrab-macros/src/circuit_borsh.rs", warrant: "v3_borsh_derive (twin) + the generated schema cross-check", hides: "a Borsh field encoded at the wrong width" },
    Row { path: "minocrab-macros/src/interface.rs", warrant: "interface_macro (twin, byte-identical ZKIR); contract_matches_its_interface", hides: "a call handle passing limbs in an order the callee does not expect" },
    Row { path: "minocrab-macros/src/ledger.rs", warrant: "the derive's unit tests; in_block pinned against `batch` for every block size (minocrab-std); the sixteen-field compactc probe", hides: "a ledger field laid out at a path compactc would not use" },
    Row { path: "minocrab-macros/src/ledger_repr.rs", warrant: "v3_ledger `derived_repr` (atoms and limb round trip); the erc20_vault_pending lineage's slots", hides: "an environment's limbs split at the wrong boundaries on read-back" },
    Row { path: "minocrab-macros/src/contract.rs", warrant: "circuit_closure (every #[circuit] is listed) + the derived sets feeding both snapshots", hides: "a circuit missing from its contract's set" },
    // ---- L5: the simulator ---------------------------------------------------------------
    Row { path: "minocrab-sim/src/lib.rs", warrant: READING, hides: "nothing beyond the Profile types (129 lines)" },
    Row { path: "minocrab-sim/src/v3.rs", warrant: "cross-checked against Midnight's reference VM (`IrSource::check`) on every accepted run — spec-harness link 4 and every differential; v3_end_to_end. It is never trusted alone", hides: "a simulator accepting what the reference VM rejects (caught) — or both agreeing on a wrong statement (out of scope here; the differentials' job)" },
    Row { path: "minocrab-sim/src/v3/exec.rs", warrant: "executor_vault (the transcript it derives from state equals the vault harness's hand model, op for op, on seventeen circuits) + IrSource::check on every preimage it produces; impact_roundtrip (the decoder is the exact inverse of minocrab-ledger's encoder, one fixture per Op::field_repr branch). Test-side only: nothing a deployed circuit links", hides: "a mis-decoded Impact op — a transcript that gathers a read from the wrong slot, agreeing with nothing (caught by the harness) unless the hand model is wrong the same way" },
    Row { path: "minocrab-sim/src/v3/rowcost.rs", warrant: "calibrated against real proving (BENCHMARK.md); a MEASUREMENT model, not a correctness claim", hides: "a mis-priced primitive — a wrong k estimate, never a wrong circuit" },
    Row { path: "minocrab-sim/src/bin/minocrab.rs", warrant: READING, hides: "nothing a proof depends on (the CLI)" },
];

const CRATES: &[&str] = &["minocrab-zkir", "minocrab-ir", "minocrab", "minocrab-ledger", "minocrab-std", "minocrab-macros", "minocrab-sim"];

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().expect("repo root")
}

fn source_files(crates_dir: &Path) -> BTreeMap<String, usize> {
    let mut out = BTreeMap::new();
    for krate in CRATES {
        let src = crates_dir.join(krate).join("src");
        let mut stack = vec![src.clone()];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).expect("readable src dir") {
                let path = entry.expect("entry").path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    let rel = path.strip_prefix(crates_dir).expect("under crates/").to_string_lossy().replace('\\', "/");
                    let lines = std::fs::read_to_string(&path).expect("readable").lines().count();
                    out.insert(rel, lines);
                }
            }
        }
    }
    out
}

/// The table body, from the classification and the measured line counts.
fn table(files: &BTreeMap<String, usize>) -> String {
    let mut body = String::from("| file | lines | what warrants it | the failure that would hide there |\n|---|---:|---|---|\n");
    let mut reading = 0usize;
    let mut total = 0usize;
    for row in ROWS {
        let lines = files[row.path];
        total += lines;
        if row.warrant == READING || row.warrant.contains(": READING") {
            reading += lines;
        }
        let warrant = if row.warrant == READING { "**READING**".to_string() } else { row.warrant.replace(": READING", ": **READING**") };
        body.push_str(&format!("| `{}` | {} | {} | {} |\n", row.path, lines, warrant, row.hides));
    }
    body.push_str(&format!("\n{total} lines in the seven crates; {reading} of them in files whose warrant is READING in whole or in part (the rows in bold).\n"));
    body
}

const BEGIN: &str = "<!-- GENERATED BEGIN: trust_base.rs -->";
const END: &str = "<!-- GENERATED END -->";

fn generated_region(text: &str) -> (usize, usize) {
    let a = text.find(BEGIN).expect("TRUST.md has the BEGIN marker") + BEGIN.len();
    let b = text.find(END).expect("TRUST.md has the END marker");
    assert!(a < b, "markers out of order");
    (a, b)
}

#[test]
fn the_classification_is_closed_over_the_edsl_sources() {
    let files = source_files(&repo_root().join("crates"));
    let classified: Vec<&str> = ROWS.iter().map(|r| r.path).collect();
    for row in ROWS {
        assert!(files.contains_key(row.path), "classified file no longer exists: {}", row.path);
    }
    let unclassified: Vec<&String> = files.keys().filter(|f| !classified.contains(&f.as_str())).collect();
    assert!(
        unclassified.is_empty(),
        "source files of the eDSL crates with no row in trust_base.rs (add a row; say READING if unsure): {unclassified:?}"
    );
    let mut seen = std::collections::BTreeSet::new();
    for row in ROWS {
        assert!(seen.insert(row.path), "duplicate row: {}", row.path);
        assert!(!row.hides.is_empty(), "{}: every row names the failure it would hide", row.path);
    }
}

#[test]
fn trust_md_table_is_current() {
    let root = repo_root();
    let files = source_files(&root.join("crates"));
    let expected = format!("\n{}", table(&files));
    let path = root.join("TRUST.md");
    let text = std::fs::read_to_string(&path).expect("TRUST.md exists");
    let (a, b) = generated_region(&text);
    if std::env::var_os("MINOCRAB_TRUST_BASE").is_some() {
        let mut out = String::new();
        out.push_str(&text[..a]);
        out.push_str(&expected);
        out.push_str(&text[b..]);
        std::fs::write(&path, out).expect("TRUST.md writes");
        return;
    }
    assert_eq!(
        &text[a..b],
        expected,
        "TRUST.md's generated table is stale — regenerate with \
         `MINOCRAB_TRUST_BASE=1 cargo test -p minocrab-contracts --test trust_base` and review the diff"
    );
}

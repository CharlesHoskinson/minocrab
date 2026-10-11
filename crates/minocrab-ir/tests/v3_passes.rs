//! `passes::dedup_range_constraints` and `passes::drop_true_asserts`, pinned
//! instruction by instruction.
//!
//! The first is the opt profile's one member (notes/ir-passes.org §1, §11),
//! the second is always on (§12); for both, what they do and — more
//! importantly — what they REFUSE to do is stated here rather than left to
//! the circuits that use them. A range constraint removed where it was not
//! implied is a missing range check, and an `assert` removed where it could
//! fail is a missing check outright: both are invisible to every differential
//! on an honest preimage.
//!
//! The last section pins the map `Builder3::finish_kept` composes from what
//! each pass dropped, which carries build-time instruction indices onto the
//! finished stream (§13).

use minocrab_ir::v3::{passes::dedup_range_constraints, Builder3, IrType};
use minocrab_zkir::v3::{Identifier, Instruction, Operand};

fn var(name: &str) -> Operand {
    Operand::Variable(Identifier(name.to_string()))
}

fn bits(name: &str, bits: u32) -> Instruction {
    Instruction::ConstrainBits { val: var(name), bits }
}

fn boolean(name: &str) -> Instruction {
    Instruction::ConstrainToBoolean { val: var(name) }
}

/// An instruction the pass has no opinion about, for checking that
/// everything else survives untouched and in order.
fn assert_(name: &str) -> Instruction {
    Instruction::Assert { cond: var(name) }
}

#[test]
fn a_duplicate_is_dropped_and_the_first_kept() {
    let out = dedup_range_constraints(vec![bits("%a", 64), bits("%a", 64)]);
    assert_eq!(out, vec![bits("%a", 64)]);
}

#[test]
fn a_wider_constraint_after_a_tighter_one_is_dropped() {
    let out = dedup_range_constraints(vec![bits("%a", 8), bits("%a", 64), bits("%a", 248)]);
    assert_eq!(out, vec![bits("%a", 8)]);
}

/// THE DIRECTION THAT IS NOT SOUND, and therefore not taken: a tighter bound
/// is new information, so both constraints stay — and a third, wider one
/// after them is then measured against the TIGHTER of the two.
#[test]
fn a_tighter_constraint_after_a_wider_one_is_kept() {
    let out = dedup_range_constraints(vec![bits("%a", 64), bits("%a", 8), bits("%a", 32)]);
    assert_eq!(out, vec![bits("%a", 64), bits("%a", 8)]);
}

#[test]
fn unrelated_wires_are_untouched_and_order_is_preserved() {
    let stream = vec![
        bits("%a", 8),
        assert_("%p"),
        bits("%b", 8),
        assert_("%q"),
        bits("%a", 8),
        bits("%c", 8),
    ];
    let out = dedup_range_constraints(stream);
    assert_eq!(
        out,
        vec![
            bits("%a", 8),
            assert_("%p"),
            bits("%b", 8),
            assert_("%q"),
            bits("%c", 8),
        ]
    );
}

/// THE BOOLEAN FAMILY IS THE `bits = 1` FAMILY. `constrain_to_boolean` and
/// `constrain_bits(_, 1)` are different gadgets — `convert` to an
/// `AssignedBit` against `assert_lower_than_fixed(x, 2)` (`ir_vm.rs`; see
/// the pass's doc) — and the same PREDICATE, `val ∈ {0,1}`, which is
/// what a constraint-system pass reasons about. So the two dedup against
/// each other, in both directions.
#[test]
fn booleanity_and_a_one_bit_range_are_one_family() {
    assert_eq!(
        dedup_range_constraints(vec![boolean("%a"), boolean("%a")]),
        vec![boolean("%a")]
    );
    assert_eq!(
        dedup_range_constraints(vec![bits("%a", 1), boolean("%a")]),
        vec![bits("%a", 1)]
    );
    assert_eq!(
        dedup_range_constraints(vec![boolean("%a"), bits("%a", 1)]),
        vec![boolean("%a")]
    );
    // The case the checked Borsh serializer actually hits: a `Bool` argument
    // constrained as boolean at entry, then serialized as one BYTE.
    assert_eq!(
        dedup_range_constraints(vec![boolean("%a"), bits("%a", 8)]),
        vec![boolean("%a")]
    );
    // …and not the other way: booleanity after an eight-bit range is real
    // information and stays.
    assert_eq!(
        dedup_range_constraints(vec![bits("%a", 8), boolean("%a")]),
        vec![bits("%a", 8), boolean("%a")]
    );
}

/// A constraint on an IMMEDIATE (reachable after `fold_immediate_copies`
/// substitutes a named constant) has no wire to key on, so the pass neither
/// drops it nor lets it establish a bound for anything else.
#[test]
fn an_immediate_operand_is_left_alone() {
    let on_immediate = Instruction::ConstrainBits {
        val: Operand::Immediate(minocrab_ir::Fr::from(3u64)),
        bits: 8,
    };
    let out = dedup_range_constraints(vec![
        on_immediate.clone(),
        on_immediate.clone(),
        bits("%a", 8),
    ]);
    assert_eq!(out, vec![on_immediate.clone(), on_immediate, bits("%a", 8)]);
}

// ---- the flag ----------------------------------------------------------------

fn duplicate_constraint_circuit(dedup: bool) -> Vec<Instruction> {
    let mut b = Builder3::new();
    b.dedup_range_constraints(dedup);
    let x = b.input("x", IrType::Native);
    b.constrain_bits(x, 64);
    b.constrain_bits(x, 64);
    b.finish(false).instructions.to_vec()
}

/// DEFAULT OFF is the hard gate on this change: a genuine duplicate survives
/// `finish` unless the circuit asked for the pass.
#[test]
fn the_flag_is_off_by_default_and_finish_is_unchanged() {
    let mut b = Builder3::new();
    let x = b.input("x", IrType::Native);
    b.constrain_bits(x, 64);
    b.constrain_bits(x, 64);
    let default = b.finish(false).instructions.to_vec();

    assert_eq!(default.len(), 2, "the default must not deduplicate");
    assert_eq!(default, duplicate_constraint_circuit(false));
    assert_eq!(duplicate_constraint_circuit(true).len(), 1);
}

// ---- the Pass trait (M24) --------------------------------------------------

use minocrab_ir::v3::passes::{
    builtin_names, by_name, run_pipeline, DedupRangeConstraints, FoldImmediateCopies, Pass,
};

#[test]
fn the_dedup_wrapper_matches_the_free_function_and_reports() {
    let stream = vec![bits("%a", 64), bits("%a", 64), assert_("%p")];
    let (out, report) = DedupRangeConstraints.run(stream.clone());
    // Same result as calling the free function directly.
    assert_eq!(out, dedup_range_constraints(stream));
    // The report carries before/after and the pass name.
    assert_eq!(report.pass, "dedup_range_constraints");
    assert_eq!(report.before, 3);
    assert_eq!(report.after, 2);
    // It DROPPED an instruction, so the runner auto-warned even though a
    // valid dedup is sound — "make sure they've been warned first".
    assert!(
        report.warnings.iter().any(|w| w.contains("dropped 1 instruction")),
        "the instruction-drop auto-warning must fire: {:?}",
        report.warnings
    );
    // And the pass's own advisory warning is there too.
    assert!(report.warnings.iter().any(|w| w.contains("implied")));
}

#[test]
fn a_pass_that_changes_nothing_produces_no_drop_warning() {
    // No redundant constraints → nothing dropped → no auto-warning.
    let stream = vec![bits("%a", 64), assert_("%p")];
    let (out, report) = DedupRangeConstraints.run(stream.clone());
    assert_eq!(out, stream);
    assert_eq!(report.before, report.after);
    assert!(
        !report.warnings.iter().any(|w| w.contains("dropped")),
        "no drop, so no drop-warning: {:?}",
        report.warnings
    );
}

#[test]
fn the_registry_resolves_the_builtins_and_rejects_the_unknown() {
    for name in builtin_names() {
        assert_eq!(by_name(name).expect("built-in resolves").name(), *name);
    }
    assert!(by_name("no_such_pass").is_none());
    assert_eq!(
        builtin_names(),
        &["fold_immediate_copies", "drop_true_asserts", "dedup_range_constraints"]
    );
}

#[test]
fn a_pipeline_threads_the_ir_and_collects_a_report_per_pass() {
    let stream = vec![bits("%a", 64), bits("%a", 64), assert_("%p")];
    let passes: Vec<Box<dyn Pass>> =
        vec![Box::new(FoldImmediateCopies), Box::new(DedupRangeConstraints)];
    let (out, reports) = run_pipeline(&passes, stream);
    assert_eq!(reports.len(), 2);
    assert_eq!(reports[0].pass, "fold_immediate_copies");
    assert_eq!(reports[1].pass, "dedup_range_constraints");
    // The dedup stage still drops the duplicate after the (no-op here) fold.
    assert_eq!(out, vec![bits("%a", 64), assert_("%p")]);
}

// ---- the VerifiedPass reflection (M25) -------------------------------------

use minocrab_ir::v3::passes::{
    run_pipeline_verified, VerifiedPass, DEDUP_PROOF, FOLD_PROOF,
};

/// The claim and the proof must agree: every theorem a built-in pass cites
/// is DECLARED in the Lean file embedded at compile time. Rename or remove
/// one in lean/MinocrabProofs/ and this fires — proof drift is a test
/// failure, not a stale claim.
#[test]
fn the_builtin_proofs_declare_every_claimed_theorem() {
    for proof in [&FOLD_PROOF, &DEDUP_PROOF, &DROP_TRUE_ASSERTS_PROOF] {
        assert_eq!(
            proof.missing_theorems(),
            Vec::<&str>::new(),
            "{} no longer declares every claimed theorem",
            proof.file(),
        );
    }
}

/// The reflection asserts nothing about the TRANSFORM: the verified
/// pipeline is the plain pipeline plus the proof-drift check, byte for
/// byte on the IR it produces.
#[test]
fn the_verified_pipeline_matches_the_plain_one_and_stays_clean() {
    let stream = vec![bits("%a", 64), bits("%a", 64), assert_("%p")];
    let plain: Vec<Box<dyn Pass>> =
        vec![Box::new(FoldImmediateCopies), Box::new(DedupRangeConstraints)];
    let verified: Vec<Box<dyn VerifiedPass>> =
        vec![Box::new(FoldImmediateCopies), Box::new(DedupRangeConstraints)];
    let (out_plain, _) = run_pipeline(&plain, stream.clone());
    let (out_verified, reports) = run_pipeline_verified(&verified, stream);
    assert_eq!(out_verified, out_plain);
    // Healthy proofs → no drift warnings beyond what the passes already say.
    assert!(
        !reports
            .iter()
            .flat_map(|r| r.warnings.iter())
            .any(|w| w.contains("UNVERIFIED")),
        "no proof drift expected: {reports:?}",
    );
}

/// The drift channel itself, exercised: a ProofRef claiming a theorem the
/// file does not declare surfaces it — through `missing_theorems` and as a
/// report warning on the verified pipeline.
#[test]
fn a_drifted_proof_claim_is_surfaced_as_a_warning() {
    struct DriftedFold;
    static DRIFTED: minocrab_ir::v3::passes::ProofRef = minocrab_ir::lean_proof! {
        file: "../lean/MinocrabProofs/Fold.lean",
        theorems: ["fold_outputs", "no_such_theorem"],
    };
    impl Pass for DriftedFold {
        fn name(&self) -> &'static str {
            "drifted_fold"
        }
        fn transform(
            &self,
            ir: Vec<Instruction>,
        ) -> (Vec<Instruction>, Vec<String>) {
            (ir, Vec::new())
        }
    }
    impl VerifiedPass for DriftedFold {
        fn proof(&self) -> &'static minocrab_ir::v3::passes::ProofRef {
            &DRIFTED
        }
    }
    assert_eq!(DRIFTED.missing_theorems(), vec!["no_such_theorem"]);
    let verified: Vec<Box<dyn VerifiedPass>> = vec![Box::new(DriftedFold)];
    let (_, reports) = run_pipeline_verified(&verified, vec![assert_("%p")]);
    assert!(
        reports[0]
            .warnings
            .iter()
            .any(|w| w.contains("no_such_theorem") && w.contains("UNVERIFIED")),
        "drift must surface in the report: {:?}",
        reports[0].warnings,
    );
}

// ---- `drop_true_asserts` (M37) ------------------------------------------------
//
// notes/ir-passes.org §12, notes/evm-calls.org §3.2. The rule is one line;
// what it must NOT do is why it gets a section of its own.

use minocrab_ir::v3::passes::{drop_true_asserts, DropTrueAsserts, DROP_TRUE_ASSERTS_PROOF};

fn assert_imm(value: u64) -> Instruction {
    Instruction::Assert { cond: Operand::Immediate(minocrab_ir::Fr::from(value)) }
}

fn copy_imm(value: u64, output: &str) -> Instruction {
    Instruction::Copy {
        val: Operand::Immediate(minocrab_ir::Fr::from(value)),
        output: Identifier(output.to_string()),
    }
}

/// The rule itself: `assert 1` passes on every preimage, so it goes.
#[test]
fn an_assert_on_the_immediate_one_is_deleted() {
    let out = drop_true_asserts(vec![
        bits("%a", 64),
        assert_imm(1),
        assert_("%p"),
        assert_imm(1),
    ]);
    assert_eq!(out, vec![bits("%a", 64), assert_("%p")]);
}

/// THE DIRECTION THAT MATTERS. An `assert` on any other immediate is an
/// always-FAILING circuit — 0 rejects with "Failed direct assertion", 2 and 3
/// with "Expected boolean" — and deleting one would turn a circuit the
/// verifier REJECTS into one it ACCEPTS. Every one of them stays.
#[test]
fn an_assert_on_any_other_immediate_survives() {
    let stream = vec![assert_imm(0), assert_imm(2), assert_imm(3), assert_imm(1)];
    assert_eq!(
        drop_true_asserts(stream.clone()),
        stream[..3].to_vec(),
        "only the immediate 1 may be removed",
    );
}

/// No dataflow: a WIRE that happens to hold 1 is not this pass's business.
/// Only [`fold_immediate_copies`] may turn such a name into an immediate, and
/// then only where it can prove the copy is a rename.
#[test]
fn an_assert_on_a_wire_is_left_alone() {
    let stream = vec![copy_imm(1, "%k"), assert_("%k")];
    assert_eq!(drop_true_asserts(stream.clone()), stream);
}

/// THE ORDER TEST, and the shape the rule exists for: `assert(constant(1))`
/// is `copy %k = 1; assert %k`, which only the copy fold turns into
/// `assert 1`. Run alone the drop sees nothing (the test above);
/// `Builder3::finish` runs the fold first, so the pair costs no instruction
/// at all.
#[test]
fn assert_of_a_named_one_folds_then_drops_to_nothing() {
    let mut b = Builder3::new();
    let one = b.copy(minocrab_ir::Fr::from(1u64));
    b.assert(one);
    assert_eq!(b.finish(false).instructions.to_vec(), Vec::<Instruction>::new());
}

/// A named constant that is NOT 1 keeps its assert through both passes — the
/// always-failing circuit stays always-failing.
#[test]
fn assert_of_a_named_zero_survives_finish() {
    let mut b = Builder3::new();
    let zero = b.copy(minocrab_ir::Fr::from(0u64));
    b.assert(zero);
    assert_eq!(b.finish(false).instructions.to_vec(), vec![assert_imm(0)]);
}

#[test]
fn the_drop_wrapper_matches_the_free_function_and_reports() {
    let stream = vec![assert_imm(1), assert_("%p")];
    let (out, report) = DropTrueAsserts.run(stream.clone());
    assert_eq!(out, drop_true_asserts(stream));
    assert_eq!(report.pass, "drop_true_asserts");
    assert_eq!((report.before, report.after), (2, 1));
    assert!(report.warnings.iter().any(|w| w.contains("dropped 1 instruction")));
    assert!(report.warnings.iter().any(|w| w.contains("always")));

    // Nothing to drop → nothing to warn about.
    let (_, quiet) = DropTrueAsserts.run(vec![assert_("%p")]);
    assert!(quiet.warnings.is_empty(), "{:?}", quiet.warnings);
}

/// The proof travels with the pass, so `run_pipeline_verified` accepts it —
/// in `finish`'s own order, on `finish`'s own shape.
#[test]
fn the_drop_is_a_verified_pass_in_the_finish_order() {
    assert_eq!(DROP_TRUE_ASSERTS_PROOF.missing_theorems(), Vec::<&str>::new());
    let verified: Vec<Box<dyn VerifiedPass>> = vec![
        Box::new(FoldImmediateCopies),
        Box::new(DropTrueAsserts),
        Box::new(DedupRangeConstraints),
    ];
    let stream = vec![
        copy_imm(1, "%k"),
        assert_("%k"),
        bits("%a", 64),
        bits("%a", 64),
    ];
    let (out, reports) = run_pipeline_verified(&verified, stream);
    assert_eq!(out, vec![bits("%a", 64)]);
    assert!(
        !reports.iter().flat_map(|r| r.warnings.iter()).any(|w| w.contains("UNVERIFIED")),
        "no proof drift expected: {reports:?}",
    );
}

// ---- `Kept`: build-time indices onto the finished stream ---------------------
//
// notes/ir-passes.org §13. Every pass in `finish` only deletes, so each
// reports one kept-or-dropped bit per input instruction, and
// `Builder3::finish_kept` composes the three. The frontend moves its assert
// messages and regions with that map. Each pass's own map is pinned beside
// it (`passes/kept.rs`, on fixed and on random streams); this pins the
// composition through `finish_kept`.

/// Composition, through `finish_kept` with every pass on: the build-time
/// index of each surviving instruction names that instruction in the
/// finished stream, and `finish` is `finish_kept`'s stream.
#[test]
fn finish_kept_maps_build_indices_through_all_three_passes() {
    let build = |b: &mut Builder3| {
        b.dedup_range_constraints(true);
        let x = b.input("x", IrType::Native);
        let p = b.input("p", IrType::Native);
        let one = b.copy(minocrab_ir::Fr::from(1u64)); // 0: folded
        b.assert(one); // 1: dropped (assert 1 after the fold)
        b.constrain_bits(x, 64); // 2: kept
        b.constrain_bits(x, 64); // 3: deduped
        b.assert(p); // 4: kept
    };
    let mut b = Builder3::new();
    build(&mut b);
    let (ir, kept) = b.finish_kept(false);
    let mut again = Builder3::new();
    build(&mut again);
    assert_eq!(ir.instructions.to_vec(), again.finish(false).instructions.to_vec());

    assert_eq!((kept.input_len(), kept.output_len()), (5, ir.instructions.len()));
    assert_eq!(
        (0..5).map(|i| kept.position(i)).collect::<Vec<_>>(),
        [None, None, Some(0), None, Some(1)]
    );
    assert!(matches!(ir.instructions[1], Instruction::Assert { .. }));
    // A span over only dropped instructions is empty; one over all five
    // holds the two survivors.
    assert_eq!((kept.boundary(0), kept.boundary(2)), (0, 0));
    assert_eq!((kept.boundary(0), kept.boundary(5)), (0, 2));
}

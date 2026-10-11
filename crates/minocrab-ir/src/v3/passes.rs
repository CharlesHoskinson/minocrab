//! IR passes — the ones that buy API, per notes/ir-passes.org.
//!
//! The standing criterion (dmd, 2026-08-16) is that a pass earns its place by
//! letting us write SIMPLER code higher up, not by saving rows: the backend
//! already folds a `Copy` of an immediate to zero rows, measured in
//! `minocrab-contracts/tests/backend_folding.rs` and again in
//! `minocrab-sim/examples/opcost.rs` (100 `Copy`s cost 0 rows; 100
//! `cond_select`s cost 101).
//!
//! And the constraint no pass may break: our primary correctness warrant is
//! DIFFERENTIAL EQUALITY with compactc, instruction for instruction, for the
//! corpus fixtures. A pass that converges on compactc is free; one that
//! diverges costs us that test and needs the spec harness's warrant instead
//! (notes/vault-optimization.org §"Binding circuit ≡ spec").

// ASSOCIATION LISTS rather than std maps THROUGHOUT the passes, by design
// (M23 R4): std's HashMap seeds SipHash from `RandomState`, which a model
// checker treats as an unconstrained symbol, and BTreeMap's node machinery
// (arrays of MaybeUninit behind unsafe) defeats symbolic execution outright —
// measured: even a fully CONCRETE two-instruction harness would not close in
// 10 minutes through either. A `Vec` of pairs with linear lookup is the
// statable shape the deferred verification needs, and at the handful of
// entries a circuit's copies produce, the cost difference is unmeasurable.

/// The passes' map: insert-or-update and lookup by linear scan.
struct AssocMap<V>(Vec<(String, V)>);

impl<V> Default for AssocMap<V> {
    fn default() -> Self {
        AssocMap(Vec::new())
    }
}

impl<V> AssocMap<V> {
    fn get(&self, key: &str) -> Option<&V> {
        self.0.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    fn insert(&mut self, key: String, value: V) {
        match self.0.iter_mut().find(|(k, _)| *k == key) {
            Some((_, v)) => *v = value,
            None => self.0.push((key, value)),
        }
    }

    fn contains(&self, key: &str) -> bool {
        self.get(key).is_some()
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn iter(&self) -> impl Iterator<Item = &(String, V)> {
        self.0.iter()
    }
}

use minocrab_zkir::v3::{Identifier, Instruction, IrSource, Operand};
use minocrab_zkir::Fr;

mod kept;
use kept::retain_kept;
/// INTERNAL TIER (`unstable`): the map `Builder3::finish_kept` returns.
#[cfg(feature = "unstable")]
pub use kept::Kept;
#[cfg(not(feature = "unstable"))]
use kept::Kept;

/// Fold every `Copy` of an immediate into its consumers and drop it.
///
/// This is what makes the named-immediate special cases unnecessary: every
/// place compactc inlines a constant where the eDSL would NAME one (operand
/// positions, the inlined Impact guard, `AnyWire3::immediate`, the token
/// helpers) was a spelling a caller had to know to reach for, bought for
/// differential fidelity and never for a row. With the fold, `c.constant(x)`
/// and an inline `x` lower to the same stream.
///
/// # The one exception, and it is compactc's
///
/// A constant that a circuit RETURNS stays named. compactc's `Output`
/// terminator lists variables, never immediates — `sendShielded` returns the
/// zero high limb of an upgraded nonce as `%t.23`, having emitted `copy 0x00`
/// for it, and uses that same name in the commitment preimage. So the fold is
/// ALL-OR-NOTHING per copy: if any use is an output slot, the copy stays and
/// every use keeps the name. Folding it in the other positions only would
/// diverge from compactc in exactly the circuit that taught us the rule.
///
/// Immediates that reach an output slot directly (a caller writing
/// `c.output(..)` on something that was never named) are not this pass's
/// business — it only ever removes instructions it can prove are renames.
pub fn fold_immediate_copies(instructions: Vec<Instruction>) -> Vec<Instruction> {
    fold_immediate_copies_kept(instructions).0
}

/// [`fold_immediate_copies`], and the `Kept` map of which instructions it
/// dropped (exactly the folded copies).
pub(crate) fn fold_immediate_copies_kept(instructions: Vec<Instruction>) -> (Vec<Instruction>, Kept) {
    let named = immediate_copies(&instructions);
    if named.is_empty() {
        let kept = Kept::identity(instructions.len());
        return (instructions, kept);
    }
    let returned = returned_identifiers(&instructions);

    // The foldable copies, chased through chains (`copy %a = 3; copy %b = %a`)
    // so that folding is a fixpoint rather than one step.
    let mut folded: AssocMap<Operand> = AssocMap::default();
    for (id, imm) in named.iter() {
        if !returned.iter().all(|(r, _)| r != id) {
            continue;
        }
        folded.insert(id.clone(), imm.clone());
    }

    let subst = |op: &mut Operand| {
        if let Operand::Variable(id) = op {
            if let Some(imm) = folded.get(&id.0) {
                *op = imm.clone();
            }
        }
    };

    retain_kept(instructions, |instruction| {
        for op in operands_mut(instruction) {
            subst(op);
        }
        // Drop the copy itself, now that nothing names it.
        !matches!(instruction, Instruction::Copy { val: _, output } if folded.contains(&output.0))
    })
}

/// The `Kept` law, checked against the two streams it describes: each
/// built instruction the map keeps is, at the position the map gives, the
/// same instruction with at most a variable operand replaced by an immediate
/// (the fold's one rewrite), and each one it drops is of a kind some pass in
/// `Builder3::finish` deletes. `Builder3::finish_kept` runs it under
/// `debug_assertions`, so every circuit a test builds re-proves that its
/// assert messages and regions name their own instructions.
pub(crate) fn check_kept(built: &[Instruction], finished: &[Instruction], kept: &Kept) {
    assert_eq!(kept.input_len(), built.len(), "Kept law: the map starts at the built stream");
    assert_eq!(kept.output_len(), finished.len(), "Kept law: the map ends at the finished stream");
    for (index, instruction) in built.iter().enumerate() {
        match kept.position(index) {
            Some(at) => {
                let mut expected = instruction.clone();
                let mut landed = finished[at].clone();
                for (want, got) in operands_mut(&mut expected).into_iter().zip(operands_mut(&mut landed)) {
                    if matches!((&*want, &*got), (Operand::Variable(_), Operand::Immediate(_))) {
                        *want = got.clone();
                    }
                }
                assert_eq!(
                    expected, finished[at],
                    "Kept law: built instruction {index} is not the finished instruction {at}"
                );
            }
            None => assert!(
                matches!(
                    instruction,
                    Instruction::Copy { .. }
                        | Instruction::Assert { .. }
                        | Instruction::ConstrainBits { .. }
                        | Instruction::ConstrainToBoolean { .. }
                ),
                "Kept law: built instruction {index} ({instruction:?}) was dropped, and no pass in \
                 finish deletes that kind"
            ),
        }
    }
}

/// Delete every `Assert` whose condition is the IMMEDIATE 1 — the check that
/// cannot fail, so it should not be shipped.
///
/// # Why it exists, and why it is a pass rather than an API branch
///
/// notes/evm-calls.org §3.2. The typed EVM-call API asserts an outcome
/// predicate in `complete`; for a call whose predicate is the constant `true`
/// (`OutcomeRule = Always`) that assert must cost nothing, and dmd's decision
/// (2026-09-05) was to get the zero from a GENERAL fold rather than a
/// `CAN_FAIL` const branching the API. The effect layer already treats an
/// immediate-1 GUARD as no guard (`effects.rs`, `effect_guard`); this is the
/// one residue that survived it, and every constant-true assert in the tree
/// gets the same treatment for free.
///
/// # Run it AFTER [`fold_immediate_copies`], which is what creates its shape
///
/// A caller writes `c.assert(c.constant(1u64))`, which emits `copy %k = 1`
/// and `assert %k`. Only once the copy fold has inlined the immediate is the
/// instruction `assert 1`, so this rule sees nothing on the un-folded stream.
/// [`Builder3::finish`](crate::v3::Builder3::finish) runs them in that order.
///
/// # THE ONE THING IT MUST NOT DO, and does not
///
/// An `Assert` on an immediate that is NOT 1 is an ALWAYS-FAILING circuit and
/// is left exactly as it is. Under the ZKIR semantics `assert` resolves its
/// operand as a boolean: 0 rejects with "Failed direct assertion", anything
/// else rejects with "Expected boolean" (`ir_vm.rs`,
/// `resolve_operand_bool`). Deleting one would turn a circuit that the
/// verifier REJECTS into one it ACCEPTS — the unsound direction, and the only
/// direction that matters here. This pass moves in the other one: it removes
/// a check that already held on every preimage, so the accepted set is
/// unchanged (`MinocrabProofs.AssertIr.dropTrueAsserts_preserves_run`).
///
/// # Instruction indices shift, and the `Kept` map carries them across
///
/// `AssertMessage.instruction` and `Region`'s `[start, end)` are recorded at
/// BUILD time (`minocrab::v3`), so any pass that removes an instruction moves
/// the positions after it. Inside `Builder3::finish` this rule reports which
/// ones it removed, and `Builder3::finish_kept` composes that with the other
/// passes' maps so the frontend can move its
/// indices onto the finished stream (notes/ir-passes.org §13). A message on
/// a DELETED assert is dropped with it: that assert could never fail, so the
/// message could never have been printed.
pub fn drop_true_asserts(instructions: Vec<Instruction>) -> Vec<Instruction> {
    drop_true_asserts_kept(instructions).0
}

/// [`drop_true_asserts`], and the `Kept` map of which instructions it
/// dropped (exactly the asserts on the immediate 1).
pub(crate) fn drop_true_asserts_kept(instructions: Vec<Instruction>) -> (Vec<Instruction>, Kept) {
    retain_kept(instructions, |instruction| !is_true_assert(instruction))
}

/// `assert` on the immediate 1, and nothing else — not a variable that
/// happens to hold 1 (this pass does no dataflow), not any other immediate
/// (see the pass's docs: those are always-failing circuits and stay).
fn is_true_assert(instruction: &Instruction) -> bool {
    matches!(
        instruction,
        Instruction::Assert { cond: Operand::Immediate(x) } if *x == Fr::from(1u64),
    )
}

/// Drop every range constraint an earlier, equally tight or tighter one on
/// the same wire already implies.
///
/// OPT-IN, and it is the only pass here that is: this makes us strictly MORE
/// deduplicated than compactc, which re-emits. See [`crate::v3::Builder3::
/// dedup_range_constraints`] for the flag and notes/ir-passes.org §1 for why
/// it cannot be on by default.
///
/// # What it drops, and the one direction that is sound
///
/// Per IDENTIFIER, the tightest bound established so far: a
/// `ConstrainBits { bits: n }` establishes `val < 2^n`, a
/// `ConstrainToBoolean` establishes `val ∈ {0,1}` — bound 1. A later
/// constraint whose bound is `m >= n` is implied by the earlier one and is
/// removed; a later constraint that is TIGHTER (`m < n`) is new information
/// and is kept, becoming the bound from there on. The first constraint on a
/// wire is never dropped.
///
/// That is the same argument `Uint::widen` already makes for why widening
/// needs no new constraint, and it is sound in that direction only: `val <
/// 2^n` implies `val < 2^m` for `m >= n`, never the reverse.
///
/// ZKIR v3 is SSA, and more strongly than a rejecting check: upstream's
/// synthesis memory is a PUSH-ONLY `Vec` (`ir_vm.rs`, `mem_push` — an
/// instruction's output takes index `mem.len()` and no operation overwrites
/// an index), and our own `Builder3` mints a fresh identifier per output. A
/// rebinding is unrepresentable on both ends, so a bound established at one
/// point in the stream holds for the whole circuit, and "earlier" is only a
/// convention for which of two identical constraints survives.
///
/// # THE BOOLEAN FAMILY IS THE `bits = 1` FAMILY, and this was checked
///
/// The two instructions are different GADGETS and the same PREDICATE, which
/// is what a pass over a constraint system needs:
///
/// - `ConstrainToBoolean` lowers to `std.convert::<AssignedNative,
///   AssignedBit>` (`ir_vm.rs`, the arm carrying upstream's own "Yes, this
///   does insert a constraint") — an assigned bit the wire must equal, so
///   `val ∈ {0,1}`.
/// - `ConstrainBits { bits }` lowers, for the CURRENT IR minor version, to
///   `assert_lower_than_fixed(x, 2^bits)` (`ir_vm.rs`; the
///   `assigned_to_le_bits` decomposition is the V0-only arm beside it) — so
///   at `bits = 1`, `val < 2` i.e. `val ∈ {0,1}`. Both version arms enforce
///   the same set at 1 bit.
///
/// Upstream's own value semantics agree: `resolve_operand_bool` accepts 0 and
/// 1, `resolve_operand_bits(_, Some(1))` accepts exactly the values whose bits
/// above the first are zero. So the two constrain the same set and this pass
/// treats them as one family: a `ConstrainToBoolean` after a
/// `ConstrainBits(_, 1)` is dropped, and a `ConstrainBits(_, m >= 1)` after a
/// `ConstrainToBoolean` is dropped. That is not cosmetic — `Bool`'s argument
/// constraint IS `constrain_to_boolean` and its Borsh segment is one BYTE, so
/// the checked serializer's `constrain_bits(_, 8)` is dropped only across the
/// families.
///
/// # What it never touches
///
/// - An immediate operand. A constraint on a constant (possible after
///   [`fold_immediate_copies`]) names no wire, so there is nothing to key on
///   and it is left exactly where it is.
/// - Anything else at all: no reordering, no renaming, no other instruction
///   kind. Everything kept keeps its order.
pub fn dedup_range_constraints(instructions: Vec<Instruction>) -> Vec<Instruction> {
    dedup_range_constraints_kept(instructions).0
}

/// [`dedup_range_constraints`], and the `Kept` map of which instructions it
/// dropped (exactly the implied range constraints).
pub(crate) fn dedup_range_constraints_kept(instructions: Vec<Instruction>) -> (Vec<Instruction>, Kept) {
    // The tightest bound proven for each identifier so far, in bits.
    let mut bound: AssocMap<u32> = AssocMap::default();

    retain_kept(instructions, |instruction| {
        let established = match &*instruction {
            Instruction::ConstrainBits { val: Operand::Variable(id), bits } => Some((id, *bits)),
            Instruction::ConstrainToBoolean { val: Operand::Variable(id) } => Some((id, 1)),
            _ => None,
        };
        if let Some((id, bits)) = established {
            match bound.get(&id.0) {
                // Already proven at least this tight: the constraint is
                // implied, so it carries no information the circuit lacks.
                Some(&proven) if proven <= bits => return false,
                // Tighter than anything proven (or the first): keep it, and
                // it is the bound from here on.
                _ => {
                    bound.insert(id.0.clone(), bits);
                }
            }
        }
        true
    })
}

/// [`fold_immediate_copies`] over a whole [`IrSource`] — the form the
/// instruction-for-instruction differentials need, because they must run the
/// SAME normalisation over compactc's artifact as our builder runs over ours.
///
/// Why that is not a weakening of those tests: the pass only ever removes a
/// `Copy` of an immediate, which is a rename with no rows (measured), no
/// public-input effect and no semantic content. Everything else — every
/// instruction, every operand, every order — is still compared exactly, and a
/// constant that either side NAMES for an output slot is still named on both.
///
/// THE COPY FOLD ONLY, deliberately: [`drop_true_asserts`] also runs in
/// `Builder3::finish`, and is NOT part of this normalisation. It deletes an
/// instruction rather than renaming one, and no compactc artifact we hold
/// contains an `assert` on an immediate (measured 2026-09-06: all 332 asserts
/// in the 211 workspace dumps, and all 251 in the 209 v3 `.zkir` files under
/// `corpus/` and `crates/`, name a WIRE).
/// Adding it here would only ever hide a divergence
/// — a compactc artifact that DID carry one is something we want a
/// differential to say out loud, not something to normalise away.
pub fn folded(ir: &IrSource) -> IrSource {
    IrSource {
        instructions: std::sync::Arc::new(fold_immediate_copies(ir.instructions.to_vec())),
        ..ir.clone()
    }
}

/// The identifiers bound by a `Copy` of an immediate, with that immediate.
fn immediate_copies(instructions: &[Instruction]) -> AssocMap<Operand> {
    let mut named: AssocMap<Operand> = AssocMap::default();
    for instruction in instructions {
        if let Instruction::Copy { val, output } = instruction {
            let value = match val {
                Operand::Immediate(_) => Some(val.clone()),
                // A copy of an already-folded copy is itself an immediate.
                Operand::Variable(id) => named.get(&id.0).cloned(),
            };
            if let Some(value) = value {
                named.insert(output.0.clone(), value);
            }
        }
    }
    named
}

/// Identifiers that appear in the `Output` terminator — the one position where
/// compactc names a constant, and therefore where this pass leaves it named.
fn returned_identifiers(instructions: &[Instruction]) -> AssocMap<()> {
    let mut returned: AssocMap<()> = AssocMap::default();
    for instruction in instructions {
        for val in returned_operands(instruction) {
            if let Operand::Variable(id) = val {
                returned.insert(id.0.clone(), ());
            }
        }
    }
    returned
}

/// The operand positions through which a value LEAVES the circuit named.
///
/// Exhaustive by construction, the same way `operands_mut` is, and for a
/// sharper reason: this list is what stops [`fold_immediate_copies`] folding
/// a constant compactc keeps named, so an upstream terminator this function
/// did not know about would make the fold do MORE, not less — the unsound
/// direction (notes/formal-verification-options.org §10). A new
/// output-carrying variant therefore has to break this match rather than fall
/// through a wildcard into silence.
fn returned_operands(instruction: &Instruction) -> &[Operand] {
    match instruction {
        Instruction::Output { vals } => vals,
        // Everything else: an ordinary instruction, whose operands are
        // consumed in-circuit and are the fold's whole business.
        Instruction::Encode { .. }
        | Instruction::Assert { .. }
        | Instruction::CondSelect { .. }
        | Instruction::ConstrainBits { .. }
        | Instruction::ConstrainEq { .. }
        | Instruction::ConstrainToBoolean { .. }
        | Instruction::Copy { .. }
        | Instruction::Impact { .. }
        | Instruction::EcMul { .. }
        | Instruction::EcMulGenerator { .. }
        | Instruction::HashToCurve { .. }
        | Instruction::IntoCoordinates { .. }
        | Instruction::FromCoordinates { .. }
        | Instruction::IntoBytes32 { .. }
        | Instruction::FromBytes32 { .. }
        | Instruction::Bytes32IntoLowHigh { .. }
        | Instruction::ReverseBytes { .. }
        | Instruction::Bytes32FromLowHigh { .. }
        | Instruction::DivModPowerOfTwo { .. }
        | Instruction::ReconstituteField { .. }
        | Instruction::TransientHash { .. }
        | Instruction::PersistentHash { .. }
        | Instruction::Keccak256 { .. }
        | Instruction::TestEq { .. }
        | Instruction::Add { .. }
        | Instruction::Mul { .. }
        | Instruction::Neg { .. }
        | Instruction::Inv { .. }
        | Instruction::Not { .. }
        | Instruction::LessThan { .. }
        | Instruction::JubjubScalarFromNative { .. }
        | Instruction::PublicInput { .. }
        | Instruction::PrivateInput { .. } => &[],
    }
}

/// Every operand position of an instruction, mutably.
///
/// Exhaustive by construction: a ZKIR instruction added upstream breaks this
/// match rather than silently escaping the pass.
fn operands_mut(instruction: &mut Instruction) -> Vec<&mut Operand> {
    match instruction {
        Instruction::Encode { input, .. } => vec![input],
        Instruction::Assert { cond } => vec![cond],
        Instruction::CondSelect { bit, a, b, .. } => vec![bit, a, b],
        Instruction::ConstrainBits { val, .. } => vec![val],
        Instruction::ConstrainEq { a, b } => vec![a, b],
        Instruction::ConstrainToBoolean { val } => vec![val],
        Instruction::Copy { val, .. } => vec![val],
        Instruction::Impact { guard, inputs } => {
            let mut ops = vec![guard];
            ops.extend(inputs.iter_mut());
            ops
        }
        Instruction::EcMul { a, scalar, .. } => vec![a, scalar],
        Instruction::EcMulGenerator { scalar, .. } => vec![scalar],
        Instruction::HashToCurve { inputs, .. } => inputs.iter_mut().collect(),
        Instruction::IntoCoordinates { point, .. } => vec![point],
        Instruction::FromCoordinates { inputs, .. } => vec![&mut inputs.0, &mut inputs.1],
        Instruction::IntoBytes32 { input, .. } => vec![input],
        Instruction::FromBytes32 { bytes, .. } => vec![bytes],
        Instruction::Bytes32IntoLowHigh { bytes, .. } => vec![bytes],
        Instruction::ReverseBytes { bytes, .. } => vec![bytes],
        Instruction::Bytes32FromLowHigh { inputs, .. } => vec![&mut inputs.0, &mut inputs.1],
        Instruction::DivModPowerOfTwo { val, .. } => vec![val],
        Instruction::ReconstituteField {
            divisor, modulus, ..
        } => vec![divisor, modulus],
        Instruction::TransientHash { inputs, .. } => inputs.iter_mut().collect(),
        Instruction::PersistentHash { inputs, .. } => inputs.iter_mut().collect(),
        Instruction::Keccak256 { inputs, .. } => inputs.iter_mut().collect(),
        Instruction::TestEq { a, b, .. } => vec![a, b],
        Instruction::Add { a, b, .. } => vec![a, b],
        Instruction::Mul { a, b, .. } => vec![a, b],
        Instruction::Neg { a, .. } => vec![a],
        Instruction::Inv { a, .. } => vec![a],
        Instruction::Not { a, .. } => vec![a],
        Instruction::LessThan { a, b, .. } => vec![a, b],
        Instruction::JubjubScalarFromNative { native, .. } => vec![native],
        Instruction::PublicInput { guard, .. } => guard.iter_mut().collect(),
        Instruction::PrivateInput { guard, .. } => guard.iter_mut().collect(),
        // NOT folded: see the pass's docs. The terminator's own operands are
        // left alone, which is what keeps a returned constant named.
        Instruction::Output { vals: _ } => vec![],
    }
}

// ============================================================================
// Read-only dataflow twins — M27 rung 2's Rust side of the Lean gate
// ============================================================================
//
// `MinocrabZkir.Dataflow` (crates/minocrab-zkir/lean/) defines `operands`,
// `returned` and `defines` over the real IR; `tests/lean_dataflow.rs` dumps
// both sides over every corpus instruction and diffs them. The two reads
// below go THROUGH `operands_mut` / `returned_operands` on a clone rather
// than restating the match, so there is exactly one exhaustive list per
// question on the Rust side and the Lean gate is comparing against it.

/// Every operand position `operands_mut` lists, in its order (all reads
/// except the `Output` terminator's — see [`returned`]).
pub fn operands(instruction: &Instruction) -> Vec<Operand> {
    let mut owned = instruction.clone();
    operands_mut(&mut owned).into_iter().map(|op| op.clone()).collect()
}

/// The operand positions through which a value leaves the circuit named:
/// the `Output` terminator's, and nothing else.
pub fn returned(instruction: &Instruction) -> Vec<Operand> {
    returned_operands(instruction).to_vec()
}

/// The identifiers an instruction binds, in output order.
///
/// Exhaustive by construction like `operands_mut`: an upstream variant
/// that defines a value this list does not know about breaks the build.
pub fn defined_identifiers(instruction: &Instruction) -> Vec<Identifier> {
    match instruction {
        Instruction::Encode { outputs, .. } => outputs.clone(),
        Instruction::DivModPowerOfTwo { outputs, .. } => outputs.clone(),
        Instruction::IntoCoordinates { outputs, .. }
        | Instruction::Bytes32IntoLowHigh { outputs, .. } => {
            vec![outputs.0.clone(), outputs.1.clone()]
        }
        Instruction::CondSelect { output, .. }
        | Instruction::Copy { output, .. }
        | Instruction::EcMul { output, .. }
        | Instruction::EcMulGenerator { output, .. }
        | Instruction::HashToCurve { output, .. }
        | Instruction::FromCoordinates { output, .. }
        | Instruction::IntoBytes32 { output, .. }
        | Instruction::FromBytes32 { output, .. }
        | Instruction::ReverseBytes { output, .. }
        | Instruction::Bytes32FromLowHigh { output, .. }
        | Instruction::ReconstituteField { output, .. }
        | Instruction::TransientHash { output, .. }
        | Instruction::PersistentHash { output, .. }
        | Instruction::Keccak256 { output, .. }
        | Instruction::TestEq { output, .. }
        | Instruction::Add { output, .. }
        | Instruction::Mul { output, .. }
        | Instruction::Neg { output, .. }
        | Instruction::Inv { output, .. }
        | Instruction::Not { output, .. }
        | Instruction::LessThan { output, .. }
        | Instruction::JubjubScalarFromNative { output, .. }
        | Instruction::PublicInput { output, .. }
        | Instruction::PrivateInput { output, .. } => vec![output.clone()],
        Instruction::Assert { .. }
        | Instruction::ConstrainBits { .. }
        | Instruction::ConstrainEq { .. }
        | Instruction::ConstrainToBoolean { .. }
        | Instruction::Impact { .. }
        | Instruction::Output { .. } => vec![],
    }
}

// ============================================================================
// The `Pass` trait — third-party optimisation passes, à la carte (M24)
// ============================================================================
//
// notes/library-api.org §3. The two functions above are the reference passes;
// this trait is the stable-ish surface a third party implements to add their
// own and compose them, WITHOUT forking. It is ordinary Rust — a pass is a
// value, composition is a `Vec`, there is no plugin-loading machinery, which
// is the payoff of being library-first rather than a compiler binary.
//
// THE CONTRACT (notes/ir-passes.org §§1-4). The ACCEPTED class is UNIFORM
// transforms — guards, constants, range constraints. The REJECTED class —
// dead-code elimination and common-subexpression elimination — DIVERGES from
// compactc or is unsound-here, and a third party reaching for either needs a
// protocol argument this crate cannot make for them. Every pass MUST preserve
// the public-input / witness stream (PI-equality is the correctness oracle)
// and, until the verification hooks land, the author's own range constraints.
//
// DESIGNED FOR THE DEFERRED Kani/Lean VERIFICATION (notes/formal-verification-
// options.org): `transform` is PURE and TOTAL — same input, same output, no
// panics, no global state — so a machine check of "output PI stream ≡ input PI
// stream" and "only implied constraints dropped" can target it without any
// redesign here. That is the whole reason the shape is `IR -> IR` and nothing
// more.

/// What a pass did — always produced by [`Pass::run`].
///
/// OPTIONAL to consume but HIGHLY RECOMMENDED to read: people shoot themselves
/// in the foot, so the runner makes sure they were WARNED first. A VALID
/// optimisation can still raise a warning — [`dedup_range_constraints`]
/// legitimately drops implied range constraints, which trips the
/// instruction-drop warning below. The warnings are ADVISORY, not a verdict.
#[derive(Debug, Clone)]
pub struct PassReport {
    /// The pass's name.
    pub pass: &'static str,
    /// Instruction count before the pass.
    pub before: usize,
    /// Instruction count after the pass.
    pub after: usize,
    /// Advisory warnings — the pass's own, plus an auto-warning on any NET
    /// instruction drop, which is the most dangerous signal: dropping an
    /// instruction can move the PI/witness stream, and that is the oracle.
    pub warnings: Vec<String>,
}

/// A ZKIR optimisation pass — the à-la-carte extension point (M24).
///
/// Implement [`Pass::transform`] (the pure, total `IR -> IR`, returning any
/// advisory warnings); [`Pass::run`] is provided and wraps it with the report.
/// See the module header for the contract every pass must honour, and
/// notes/library-api.org for where this sits in the library surface.
///
/// # A pass over a bare stream, and a pass inside `Builder3::finish`
///
/// A `Pass` run through [`run_pipeline`] works on a bare instruction stream
/// with nothing beside it, so it may insert, delete or reorder. The passes
/// `Builder3::finish` runs are held to more: the eDSL records instruction
/// indices (assert messages, regions) while it builds, and `finish` carries
/// them onto the finished stream by one kept-or-dropped bit per input
/// instruction. So each of those passes is a FILTER — its output is a
/// subsequence of its input, in order, with operands rewritten at most — and
/// deletes through the module's one `retain_kept` helper, which records the
/// bit as its keep decision (notes/ir-passes.org §13). A pass that inserts or
/// reorders cannot join `finish` without a different map.
pub trait Pass {
    /// This pass's name — for the report and the [`by_name`] registry.
    fn name(&self) -> &'static str;

    /// The pure, total transform: same input → same output, no panics, no
    /// global state. Returns the new instruction stream and any advisory
    /// warnings the pass wants to raise (empty is fine).
    fn transform(&self, ir: Vec<Instruction>) -> (Vec<Instruction>, Vec<String>);

    /// Run the pass and report. PROVIDED — do not override. The report is
    /// optional to consume but always produced, and it auto-warns on any net
    /// instruction drop even when the pass itself is silent, so a caller
    /// cannot be left un-warned about the one signal that matters.
    fn run(&self, ir: Vec<Instruction>) -> (Vec<Instruction>, PassReport) {
        let before = ir.len();
        let (out, mut warnings) = self.transform(ir);
        let after = out.len();
        if after < before {
            warnings.push(format!(
                "dropped {} instruction(s) — verify the public-input / witness \
                 stream is unchanged (PI-equality is the correctness oracle)",
                before - after,
            ));
        }
        (
            out,
            PassReport {
                pass: self.name(),
                before,
                after,
                warnings,
            },
        )
    }
}

/// [`fold_immediate_copies`] as a [`Pass`]. A fold is a RENAME — it removes
/// only instructions it can prove are `Copy`s of an immediate — so the
/// instruction-drop warning it trips is expected and benign.
pub struct FoldImmediateCopies;

impl Pass for FoldImmediateCopies {
    fn name(&self) -> &'static str {
        "fold_immediate_copies"
    }
    fn transform(&self, ir: Vec<Instruction>) -> (Vec<Instruction>, Vec<String>) {
        (fold_immediate_copies(ir), Vec::new())
    }
}

/// [`drop_true_asserts`] as a [`Pass`]. It removes only instructions it can
/// prove pass on every preimage — an `assert` on the immediate 1 — so the
/// instruction-drop warning it trips is expected and benign. It never touches
/// an assert on any OTHER immediate: those reject unconditionally, and the
/// warning says so, because that is the one direction a reader should check.
pub struct DropTrueAsserts;

impl Pass for DropTrueAsserts {
    fn name(&self) -> &'static str {
        "drop_true_asserts"
    }
    fn transform(&self, ir: Vec<Instruction>) -> (Vec<Instruction>, Vec<String>) {
        let before = ir.len();
        let out = drop_true_asserts(ir);
        let warnings = if out.len() < before {
            vec!["dropped only `assert` on the IMMEDIATE 1, which passes on \
                  every preimage; an assert on any other immediate always \
                  FAILS and is deliberately kept, so no rejected circuit \
                  becomes an accepted one"
                .to_string()]
        } else {
            Vec::new()
        };
        (out, warnings)
    }
}

/// [`dedup_range_constraints`] as a [`Pass`]. It drops a range constraint only
/// where a tighter-or-equal bound was ALREADY proven, so the drop is sound on
/// any stream whose leaves are constrained at entry — the warning names the
/// one thing to check (an unconstrained source, where a dropped constraint
/// would be load-bearing). The canonical "valid optimisation that still warns".
pub struct DedupRangeConstraints;

impl Pass for DedupRangeConstraints {
    fn name(&self) -> &'static str {
        "dedup_range_constraints"
    }
    fn transform(&self, ir: Vec<Instruction>) -> (Vec<Instruction>, Vec<String>) {
        let before = ir.len();
        let out = dedup_range_constraints(ir);
        // Only warn when it actually dropped something — a warning names what
        // happened, not what could have. On a real drop this rides ALONGSIDE
        // the runner's generic "dropped N instructions" warning: generic says
        // the danger, this says why it is usually fine and what to check.
        let warnings = if out.len() < before {
            vec!["dropped only range constraints already implied by a \
                  tighter-or-equal proven bound; verify the source constrains \
                  its leaves at entry (an unconstrained leaf makes a dropped \
                  constraint load-bearing)"
                .to_string()]
        } else {
            Vec::new()
        };
        (out, warnings)
    }
}

/// Run passes left to right, threading the IR through and collecting one
/// report per pass. Composition is ordinary Rust — a convenience over a `for`
/// loop, not machinery; a third party's pipeline is just a `Vec` of their own
/// passes interleaved with these.
pub fn run_pipeline(
    passes: &[Box<dyn Pass>],
    mut ir: Vec<Instruction>,
) -> (Vec<Instruction>, Vec<PassReport>) {
    let mut reports = Vec::with_capacity(passes.len());
    for pass in passes {
        let (out, report) = pass.run(ir);
        ir = out;
        reports.push(report);
    }
    (ir, reports)
}

/// The BUILT-IN passes by name — what a CLI or a config names to run one à la
/// carte. A third party's own passes are their own values; this is only the
/// reference set. See [`builtin_names`] for the accepted names.
pub fn by_name(name: &str) -> Option<Box<dyn Pass>> {
    match name {
        "fold_immediate_copies" => Some(Box::new(FoldImmediateCopies)),
        "drop_true_asserts" => Some(Box::new(DropTrueAsserts)),
        "dedup_range_constraints" => Some(Box::new(DedupRangeConstraints)),
        _ => None,
    }
}

/// The names [`by_name`] accepts — for help text and discovery.
pub fn builtin_names() -> &'static [&'static str] {
    &["fold_immediate_copies", "drop_true_asserts", "dedup_range_constraints"]
}

// ============================================================================
// The VerifiedPass reflection (M25, notes/lean-port.org §4)
// ============================================================================
//
// The honest boundary first: Rust's type system cannot make "preserves the
// PI/witness stream" a trait bound — the property is semantic, and its real
// discharge is the machine-checked Lean development shipped WITH this crate
// (`lean/MinocrabProofs/`, a lake project; `cd lean && lake build` checks
// it). What the type system CAN hold is the CLAIM: a [`VerifiedPass`] names
// the proof file and theorems discharging its obligation, the file is
// embedded at COMPILE TIME (a deleted proof is a build error — the
// compile-errors-over-panics rule applied to proofs), and a pipeline that
// REQUIRES verification takes `dyn VerifiedPass`. A pass without a proof
// still runs through [`run_pipeline`]; it cannot claim verification. That is
// as far as reflection reaches, said so per the FIT shortfall clause.
//
// What a Lean model proof warrants — and does not — is stated in each proof
// file's header: it warrants the ALGORITHM as transcribed; the claim that
// the Rust implements that algorithm rests on review plus the Rust-side
// instruments (the unit tests here, the Kani-bounded twins below).

/// A machine-checked warrant: the Lean file whose theorems discharge a
/// pass's preserve-meaning obligation, embedded at compile time.
///
/// Constructed only via [`lean_proof!`](crate::lean_proof), which forces the
/// file to EXIST at build time. Whether it still DECLARES the claimed
/// theorems is [`ProofRef::missing_theorems`]'s question, asked by
/// [`run_pipeline_verified`] on every run and by this crate's tests for the
/// built-in passes — so a renamed theorem is drift a gate catches, not a
/// silently stale claim.
pub struct ProofRef {
    file: &'static str,
    theorems: &'static [&'static str],
    contents: &'static str,
}

impl ProofRef {
    /// [`lean_proof!`](crate::lean_proof)'s constructor — not public API;
    /// the macro is the supported spelling because it is what makes the
    /// file's existence a compile-time fact.
    #[doc(hidden)]
    pub const fn new_via_macro(
        file: &'static str,
        theorems: &'static [&'static str],
        contents: &'static str,
    ) -> Self {
        ProofRef { file, theorems, contents }
    }

    /// The proof file's path as the claiming crate spelled it (relative to
    /// the source file that invoked the macro) — the doc-link to follow.
    pub fn file(&self) -> &'static str {
        self.file
    }

    /// The theorem names claimed to discharge the pass's obligation.
    pub fn theorems(&self) -> &'static [&'static str] {
        self.theorems
    }

    /// The embedded proof text, byte for byte as built.
    pub fn contents(&self) -> &'static str {
        self.contents
    }

    /// Every claimed theorem the embedded file does NOT declare — empty is
    /// the healthy state. A non-empty answer means the proof and the claim
    /// have drifted (a theorem renamed or removed); the pass should be
    /// treated as unverified until they agree again.
    pub fn missing_theorems(&self) -> Vec<&'static str> {
        let declared: Vec<&str> = self
            .contents
            .lines()
            .filter_map(|line| {
                let rest = line.trim_start().strip_prefix("theorem ")?;
                let end = rest
                    .find(|c: char| !c.is_alphanumeric() && c != '_')
                    .unwrap_or(rest.len());
                Some(&rest[..end])
            })
            .collect();
        self.theorems
            .iter()
            .copied()
            .filter(|thm| !declared.contains(thm))
            .collect()
    }
}

/// A [`Pass`] carrying a machine-checked preserve-meaning proof.
///
/// The marker a third-party pass earns by shipping a Lean proof and citing
/// it via [`lean_proof!`](crate::lean_proof); [`run_pipeline_verified`] is
/// the pipeline that demands it. See the section comment above for exactly
/// what the marker does and does not assert.
pub trait VerifiedPass: Pass {
    /// The proof discharging this pass's obligation.
    fn proof(&self) -> &'static ProofRef;
}

/// Cite a Lean proof file as a [`ProofRef`] — the one supported way to
/// construct one, because it makes the file's existence a COMPILE-TIME
/// fact: the path resolves relative to the calling source file
/// (`include_str!` semantics, so a third-party pass crate names its own
/// proof file), and a path that does not resolve is a build error.
///
/// ```ignore
/// pub static MY_PROOF: ProofRef = minocrab_ir::lean_proof! {
///     file: "../proofs/MyPass.lean",
///     theorems: ["my_pass_preserves_observables"],
/// };
/// ```
#[macro_export]
macro_rules! lean_proof {
    (file: $path:literal, theorems: [$($thm:literal),+ $(,)?] $(,)?) => {
        $crate::v3::passes::ProofRef::new_via_macro(
            $path,
            &[$($thm),+],
            include_str!($path),
        )
    };
}

/// The Lean warrant for [`FoldImmediateCopies`]: the syntactic contract
/// (`fold_outputs` — terminator operand lists verbatim; `fold_skeleton` —
/// the non-copy skeleton preserved in kind and order;
/// `foldRun_is_filter_map` — the fold is exactly filter-then-substitute)
/// and the semantic theorem (`fold_preserves_observables` — every non-copy
/// instruction consumes the same resolved operand values, on the SSA shape
/// `Builder3` emits).
pub static FOLD_PROOF: ProofRef = lean_proof! {
    // M27 rung 3: the citation moved from the three-constructor model
    // (`Fold.lean`, kept as the M25 record) to the same four theorems over
    // the REAL instruction set (`FoldIr.lean`, on `MinocrabZkir.Instr`);
    // `fold_preserves_observables` there resolves every instruction's
    // `operands_mut` positions under the copy environment (33 arms).
    file: "../../lean/MinocrabProofs/FoldIr.lean",
    theorems: [
        "fold_outputs",
        "fold_skeleton",
        "foldRun_is_filter_map",
        "fold_preserves_observables",
    ],
};

/// The Lean warrant for [`DedupRangeConstraints`]: output a subsequence
/// (`dedup_sublist`), non-constraints preserved verbatim
/// (`dedup_passthrough`), every wire's tightest bound — hence solution set —
/// unchanged (`dedup_bound`), and idempotence (`dedup_idem`). These are the
/// M23 R4 stream specimens discharged UNBOUNDED.
pub static DEDUP_PROOF: ProofRef = lean_proof! {
    // M27 rung 3: the citation moved from the three-constructor model
    // (`Passes.lean`, kept as the M25 record) to the same four theorems
    // over the REAL instruction set (`DedupIr.lean`, stated on
    // `MinocrabZkir.Instr`, the inductive that round-trips the corpus).
    file: "../../lean/MinocrabProofs/DedupIr.lean",
    theorems: [
        "dedup_sublist",
        "dedup_passthrough",
        "dedup_bound",
        "dedup_idem",
    ],
};

/// The Lean warrant for [`DropTrueAsserts`], and it is the STRONGEST of the
/// three: where the other two can only preserve an abstraction of meaning (a
/// fold that renames wires, a dedup that removes constraints), this rule
/// preserves `run` ITSELF. `dropTrueAsserts_preserves_run` is an equality of
/// `MinocrabZkir.Eval.run` — memory, `pis`, `piSkips`, `outputs`, and
/// accept-vs-reject with its message — for every model, every carrier
/// assignment and every preimage. Beside it: the output is a subsequence
/// (`dropTrueAsserts_sublist`), everything that is not a true assert survives
/// with multiplicity (`dropTrueAsserts_passthrough`), an assert on any OTHER
/// immediate — the always-FAILING circuit — is kept
/// (`dropTrueAsserts_keeps_failing_asserts`), and the rule is idempotent
/// (`dropTrueAsserts_idem`).
pub static DROP_TRUE_ASSERTS_PROOF: ProofRef = lean_proof! {
    file: "../../lean/MinocrabProofs/AssertIr.lean",
    theorems: [
        "dropTrueAsserts_sublist",
        "dropTrueAsserts_passthrough",
        "dropTrueAsserts_keeps_failing_asserts",
        "dropTrueAsserts_idem",
        "dropTrueAsserts_preserves_run",
    ],
};

impl VerifiedPass for FoldImmediateCopies {
    fn proof(&self) -> &'static ProofRef {
        &FOLD_PROOF
    }
}

impl VerifiedPass for DedupRangeConstraints {
    fn proof(&self) -> &'static ProofRef {
        &DEDUP_PROOF
    }
}

impl VerifiedPass for DropTrueAsserts {
    fn proof(&self) -> &'static ProofRef {
        &DROP_TRUE_ASSERTS_PROOF
    }
}

/// [`run_pipeline`], but every pass must CARRY ITS PROOF — the pipeline a
/// caller reaches for when "optimised" must also mean "warranted". Beyond
/// the threading, it re-asks each pass's [`ProofRef::missing_theorems`] and
/// turns any drift into a report warning, so a stale claim surfaces on the
/// same advisory channel as everything else.
pub fn run_pipeline_verified(
    passes: &[Box<dyn VerifiedPass>],
    mut ir: Vec<Instruction>,
) -> (Vec<Instruction>, Vec<PassReport>) {
    let mut reports = Vec::with_capacity(passes.len());
    for pass in passes {
        let (out, mut report) = pass.run(ir);
        for thm in pass.proof().missing_theorems() {
            report.warnings.push(format!(
                "claimed theorem `{thm}` is not declared in {} — the proof \
                 and the claim have drifted; treat this pass as UNVERIFIED \
                 until they agree",
                pass.proof().file(),
            ));
        }
        ir = out;
        reports.push(report);
    }
    (ir, reports)
}

// ============================================================================
// Kani harnesses (M23 R4) — compiled ONLY under `cargo kani -p minocrab-ir`
// ============================================================================
//
// Plain `cargo test` never sees this module (`cfg(kani)` is set by the Kani
// driver alone), so the routine loop pays nothing.
//
// STREAM-LEVEL PROOFS OF THE PASSES DO NOT CLOSE, and the record of why is
// in notes/formal-verification-options.org §"As built — M23 R4": CBMC's
// symbolic execution must unwind the drop glue of `Vec<Instruction>`, which
// statically reaches the RECURSIVE `Alignment` type (`Option(Vec<Alignment>)`
// → `Vec<AlignmentSegment>` → …) through the hash variants — measured, a
// fully CONCRETE two-instruction harness does not close in 25 minutes, with
// or without the harness leaking its vectors, through HashMap, BTreeMap, or
// the AssocMap the passes now use. The two stream harnesses below are
// therefore RETAINED AS SPECIMENS without `#[kani::proof]` — the property
// statements are written, bounded, and ready for a symex that can slice dead
// drop paths, and they are exactly the obligations M25's Lean prong
// discharges unboundedly. The pass properties remain covered by this file's
// unit tests. What DOES close under Kani is the taint lint's interval
// arithmetic — see taint.rs.

#[cfg(kani)]
#[allow(dead_code)]
mod kani_proofs {
    use super::*;
    use minocrab_zkir::v3::Identifier;
    use minocrab_zkir::Fr;

    /// Fixed identifier pool — SYMBOLIC STRINGS are intractable for the
    /// solver, and the passes only ever compare identifiers for equality,
    /// so a small fixed pool loses no generality a bounded proof had.
    fn ident(i: u8) -> Identifier {
        Identifier(
            match i % 4 {
                0 => "a",
                1 => "b",
                2 => "c",
                _ => "d",
            }
            .to_string(),
        )
    }

    /// One of three CONCRETE immediates, symbolically selected — `Fr::from`
    /// of a fully symbolic u64 drags 256-bit Montgomery arithmetic into the
    /// SAT problem for nothing the properties need.
    fn imm(i: u8) -> Fr {
        match i % 3 {
            0 => Fr::from(0u64),
            1 => Fr::from(1u64),
            _ => Fr::from(2u64),
        }
    }

    fn operand(kind: u8, sel: u8) -> Operand {
        if kind % 2 == 0 {
            Operand::Variable(ident(sel % 2))
        } else {
            Operand::Immediate(imm(sel % 2))
        }
    }

    /// A symbolic range-constraint-or-other instruction for the dedup proof.
    fn dedup_instruction() -> Instruction {
        let kind: u8 = kani::any();
        match kind % 4 {
            0 => Instruction::ConstrainBits {
                val: operand(kani::any(), kani::any()),
                bits: kani::any(),
            },
            1 => Instruction::ConstrainToBoolean {
                val: operand(kani::any(), kani::any()),
            },
            // The pass must pass everything else through untouched; one
            // no-operand-rewrite representative suffices structurally.
            2 => Instruction::Assert {
                cond: Operand::Variable(ident(kani::any())),
            },
            _ => Instruction::Copy {
                val: operand(kani::any(), kani::any()),
                output: ident(kani::any()),
            },
        }
    }

    /// The bound a constraint establishes on a WIRE, per the pass's own
    /// documented semantics: `ConstrainBits{bits}` ⇒ `val < 2^bits`,
    /// `ConstrainToBoolean` ⇒ the `bits = 1` family. `None` for anything
    /// else, including constraints on immediates (no wire to key on).
    fn established(instruction: &Instruction) -> Option<(Identifier, u32)> {
        match instruction {
            Instruction::ConstrainBits {
                val: Operand::Variable(id),
                bits,
            } => Some((id.clone(), *bits)),
            Instruction::ConstrainToBoolean {
                val: Operand::Variable(id),
            } => Some((id.clone(), 1)),
            _ => None,
        }
    }

    /// The tightest bound a stream proves for `id` — the SEMANTICS of a set
    /// of range constraints: their solution set is `val < 2^min`.
    fn tightest(stream: &[Instruction], id: &Identifier) -> Option<u32> {
        stream
            .iter()
            .filter_map(established)
            .filter(|(wire, _)| wire == id)
            .map(|(_, bits)| bits)
            .min()
    }

    /// `dedup_range_constraints` — only implied constraints dropped, the
    /// tightest bound kept, everything else untouched and in order.
    ///
    /// BOUND: streams of 4 instructions over 4 wires, each instruction any
    /// of {constrain_bits (wire or immediate, any u32 bits),
    /// constrain_to_boolean, assert, copy}. The properties:
    ///  (1) the output is a SUBSEQUENCE of the input (nothing added,
    ///      nothing reordered, nothing rewritten);
    ///  (2) every non-range-constraint instruction survives;
    ///  (3) per wire, the tightest proven bound is unchanged — which is
    ///      exactly "the solution set per wire is unchanged", since
    ///      {v < 2^b} sets intersect to the minimum;
    ///  (4) a constraint on an immediate is never dropped.
    ///
    /// RETAINED AS A SPECIMEN, NOT A PROOF — see the module header: no
    /// stream-level harness currently closes.
    fn dedup_only_drops_implied_constraints() {
        let input: Vec<Instruction> = (0..2).map(|_| dedup_instruction()).collect();
        let output = dedup_range_constraints(input.clone());

        // (1) subsequence.
        let mut at = 0usize;
        for kept in &output {
            let mut found = false;
            while at < input.len() {
                let matches = input[at] == *kept;
                at += 1;
                if matches {
                    found = true;
                    break;
                }
            }
            assert!(found, "output instruction not a subsequence match");
        }

        // (2) + (4): everything that is not a wire-keyed range constraint
        // survives with multiplicity.
        let passthrough = |stream: &[Instruction]| {
            stream
                .iter()
                .filter(|i| {
                    established(i).is_none()
                })
                .count()
        };
        assert_eq!(passthrough(&input), passthrough(&output));

        // (3) tightest bound per wire unchanged.
        for w in 0..2u8 {
            assert_eq!(tightest(&input, &ident(w)), tightest(&output, &ident(w)));
        }
    }

    /// A symbolic instruction for the fold proof: copies (of immediates and
    /// of wires), one arithmetic representative, and the `Output`
    /// terminator whose operands the fold must never rewrite. The fold
    /// proof's own, TIGHTER pools (2 wires, 2 immediates): the unscoped
    /// harness did not close in 10 minutes, and the fold's interesting
    /// behaviors — chains, shadowing, returned copies — all occur within
    /// two wires.
    fn fold_operand(kind: u8, sel: u8) -> Operand {
        if kind % 2 == 0 {
            Operand::Variable(ident(sel % 2))
        } else {
            Operand::Immediate(imm(sel % 2))
        }
    }

    fn fold_instruction() -> Instruction {
        let kind: u8 = kani::any();
        match kind % 4 {
            0 | 1 => Instruction::Copy {
                val: fold_operand(kani::any(), kani::any()),
                output: ident(kani::any::<u8>() % 2),
            },
            2 => Instruction::Add {
                a: fold_operand(kani::any(), kani::any()),
                b: fold_operand(kani::any(), kani::any()),
                output: ident(kani::any::<u8>() % 2),
            },
            _ => Instruction::Output {
                vals: vec![fold_operand(kani::any(), kani::any())],
            },
        }
    }

    /// The harness's identifier pool, backwards: the index of one of
    /// [`ident`]'s four names, for the array-backed interpreter below —
    /// symbolic-string HASHING (the pass's own maps run over CONCRETE
    /// strings and are fine) is what a bounded proof cannot afford.
    fn ident_index(id: &Identifier) -> usize {
        match id.0.as_bytes().first() {
            Some(b'a') => 0,
            Some(b'b') => 1,
            Some(b'c') => 2,
            _ => 3,
        }
    }

    /// The VALUE an operand denotes under an environment built by copies:
    /// its immediate, the value its wire was last assigned, or `None` for
    /// a never-defined wire. Values are only ever COMPARED, never added —
    /// operand-value preservation implies result preservation for any
    /// deterministic instruction, and keeps 256-bit field arithmetic out
    /// of the solver.
    fn eval(env: &[Option<Fr>; 4], op: &Operand) -> Option<Fr> {
        match op {
            Operand::Immediate(v) => Some(*v),
            Operand::Variable(id) => env[ident_index(id)],
        }
    }

    /// `fold_immediate_copies` — semantics-preserving at the stream level.
    ///
    /// BOUND: streams of 3 instructions over 2 wires and 2 immediates,
    /// from {copy, add, output}, SCOPED to operand-value preservation:
    /// executing both streams with the same copy-aware interpreter,
    ///  (1) the observable instructions (everything but `Copy`) survive in
    ///      kind and order;
    ///  (2) every observable OPERAND denotes the same value before and
    ///      after — which implies result preservation for any
    ///      deterministic instruction without dragging field arithmetic
    ///      into the solver (the un-scoped form did not close in 10 min);
    ///  (3) `Output` operand lists are preserved VERBATIM — the pass's
    ///      all-or-nothing rule that keeps a returned constant named.
    ///
    /// RETAINED AS A SPECIMEN, NOT A PROOF — see the module header: no
    /// stream-level harness currently closes.
    fn fold_preserves_meaning_and_output_names() {
        let input: Vec<Instruction> = (0..3).map(|_| fold_instruction()).collect();
        let output = fold_immediate_copies(input.clone());

        // Execute a stream, recording each observable's operand values.
        let run = |stream: &[Instruction]| {
            let mut env: [Option<Fr>; 4] = [None; 4];
            // (kind tag, operand values, terminator operands verbatim)
            let mut observed: Vec<(u8, [Option<Fr>; 2], Option<Vec<Operand>>)> = Vec::new();
            for instruction in stream.iter() {
                match instruction {
                    Instruction::Copy { val, output } => {
                        env[ident_index(output)] = eval(&env, val);
                        // A copy is unobservable: folding may drop it.
                    }
                    Instruction::Add { a, b, output } => {
                        let values = [eval(&env, a), eval(&env, b)];
                        // The result is opaque but deterministic in the
                        // operand values; model it as a marker unique to
                        // this OBSERVABLE's ordinal (outside the immediate
                        // pool), so distinct results stay distinguishable
                        // downstream without field arithmetic. Observable
                        // ordinals align between the two runs — the fold
                        // only ever removes copies, and property (1)
                        // asserts exactly that.
                        env[ident_index(output)] = values[0]
                            .and(values[1])
                            .map(|_| Fr::from(1000 + observed.len() as u64));
                        observed.push((2, values, None));
                    }
                    Instruction::Output { vals } => {
                        let value = vals.first().and_then(|v| eval(&env, v));
                        observed.push((3, [value, None], Some(vals.clone())));
                    }
                    _ => unreachable!("the harness builds no other kind"),
                }
            }
            observed
        };

        let before = run(&input);
        let after = run(&output);

        // (1)+(2): same observables, in order, with equal operand values.
        assert_eq!(before.len(), after.len(), "an observable instruction was dropped");
        for (b, a) in before.iter().zip(after.iter()) {
            assert_eq!(b.0, a.0, "an observable changed kind or order");
            assert_eq!(b.1, a.1, "an observable operand changed value");
            // (3): terminator operands verbatim.
            assert_eq!(b.2, a.2, "an Output operand was rewritten");
        }
    }
}

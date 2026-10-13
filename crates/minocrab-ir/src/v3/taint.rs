//! The taint lint (M23 R3): every byte-atom hash-preimage limb must be
//! provably bounded to its own byte width, or constant.
//!
//! This mechanizes notes/api-safety-survey.org §B3 — "the limb packing is
//! only injective for in-range segments … without that the packing is not
//! injective and the digest binds nothing" — the one hazard class no test on
//! honest preimages can see, because an honest prover always supplies
//! in-range values.
//!
//! # What the chip already enforces, and what it cannot
//!
//! The in-circuit decoder behind `persistent_hash`/`keccak256` range-checks
//! every limb it absorbs: `fab_decode_to_bytes_atom` decomposes each `bytes`
//! limb with `assigned_to_le_bytes(f, Some(width))`, which makes the circuit
//! unsatisfiable if the limb exceeds its width (zkir-v3 ir_vm.rs:125-175;
//! midnight-circuits decomposition.rs, "Unsatisfiable Circuit"). So the LIMB
//! is always bound by the digest. What the chip cannot see is one level up:
//! a limb PACKED from several narrower segments (`a + b·2^8k + …`) is only
//! injective in those segments if each segment is bounded to its own slot.
//! The lint therefore asks for a derivable bound on the limb wire — and the
//! bound propagation below only succeeds when every wire feeding the packing
//! arithmetic is itself constrained-or-constant, which is exactly §B3's
//! precondition, checked mechanically.
//!
//! # The Impact/popeq warrant (M23 R3 ruling, dmd 2026-08-28)
//!
//! A wire embedded in an UNCONDITIONAL `popeq`/`popeqc` Impact op is bounded
//! to its limb's byte width. The warrant is EXTERNAL and two-linked: the
//! verifier checks the pushed elements against the transaction's declared
//! transcript, and the ledger accepts the transaction only if the
//! transcript's expected value equals the normalized stored value actually
//! read (`process_read`). Guarded reads are NOT marked — a false guard
//! pushes zeros, the comparison passes, and the wire is genuinely free.
//! See `mark_popeq` in this file for the exact parse and conditions.
//!
//! # Limitations, stated plainly
//!
//! What a clean run does and does not prove:
//!
//! - BOUNDS, not shift-layout disjointness. A packing whose segments overlap
//!   bit ranges is the serializer's own layout invariant, pinned by its
//!   byte-equality tests — not this lint's.
//! - The popeq bounds are CONDITIONAL ON THE LEDGER. Unlike every other
//!   marking rule (each cited to an in-circuit constraint), the popeq rule's
//!   chain runs through the ledger's normalization invariant and the
//!   transcript equality check — outside the circuit. A clean run therefore
//!   reads: "every hash-preimage limb is bounded in-circuit, or is an
//!   unconditional ledger read the platform binds". If the ledger's
//!   invariant broke, the lint would not know.
//! - Guard recognition is SYNTACTIC: only an immediate non-zero Impact guard
//!   counts as unconditional. A variable guard that is provably always 1
//!   still leaves its read unmarked (over-fires, never under-fires).
//! - The `guard` on `PublicInput`/`PrivateInput` is NOT a second warrant.
//!   In-circuit that arm ignores it entirely (zkir-v3 ir_vm.rs:978-1004
//!   resolves the wire out of the preprocessed witness memory, `guard: _`),
//!   so a `public_input … guard: %g` is exactly as free as an unguarded one;
//!   the "a skipped read yields 0, also in range" reading describes the
//!   OFF-circuit `run`/preprocess semantics (the witness GENERATOR), not a
//!   constraint. Pinned by `a_guarded_read_under_a_guarded_popeq_stays_free`
//!   and written up in notes/taint-lint.org §8.
//! - An ASSERT is a bound source in exactly THREE rules, all of them about
//!   the one shape a subtraction lowers to — `assert(a ≥ b); add(a, neg(b))`,
//!   where `Neg` wraps and the producer walk alone concludes nothing. N1
//!   needs no assert (a constant minuend and a range-constrained
//!   subtrahend); N2 needs an unconditional one; N3 needs a guarded one with
//!   both operands zeroed under that same guard. Each reads only in-circuit
//!   constraints, so none widens the external dependency above. Nothing else
//!   in the lint reads an `Assert`, and in particular an assert is never
//!   evidence about a wire it does not name — see
//!   `the_subtraction_warrants_refuse_a_mismatched_assert` for the three ways
//!   a near-miss must still fire. A subtraction whose MINUEND is itself
//!   unbounded stays a finding, which is what keeps `manager::execute` in the
//!   baseline (M23 R3 Class B, notes/taint-lint.org §8).
//! - A GUARDED read can be discharged without a bound, by OBSERVABILITY
//!   (M23 R3 Class A, option 4 of notes/taint-lint.org §8). Its value really
//!   is free when the guard is false, and no bound is invented; what is
//!   checked instead is that nothing can be stolen with it — every Impact
//!   that could publish anything derived from the read is guarded by a bit
//!   that is zero whenever the read's own guard is, and nothing constrains
//!   the derived values or returns them. When the guard IS true the popeq
//!   binds the read, which is the rule above. This is a reachability claim,
//!   so it is REFUSED on anything the walk cannot account for: an
//!   unconditional or differently-guarded Impact, an `Assert`/`ConstrainEq`/
//!   `ConstrainBits`, an `Output`, or a derived wire steering another read's
//!   guard. Two stated limits of its own:
//!   - it discharges the READ wire, not a wire merely DERIVED from one. A
//!     `cond_select` of a confined read that feeds a hash limb keeps its
//!     finding — the safe direction, and why the `manager::*` `%sel.*`
//!     residue stands.
//!   - "zero whenever `g` is zero" is SYNTACTIC, through
//!     `cond_select{a: _, b: 0, bit: k}` chains only. A guard that is
//!     semantically but not syntactically dominated marks nothing.
//! - popeq ONLY. Wires embedded in pushes (`push`/`pushs` cell contents) and
//!   dynamic `idx` keys also flow to the transcript, but their in-range
//!   argument is different (transaction well-formedness, not a read of
//!   normalized state) and is NOT encoded; such wires stay unbounded unless
//!   something in-circuit bounds them.
//! - Field-absorbing hashes (`TransientHash`, `HashToCurve`) are out of
//!   scope by design — no byte atoms, no packing-injectivity question.
//! - The operand↔atom mapping follows the in-circuit decoder's own
//!   consumption rule; a stream the decoder would reject (option/compress
//!   segments, arity mismatches) is reported as unmappable, not audited
//!   around.
//!
//! # Scope
//!
//! The subjects are `Keccak256` and `PersistentHash` — the two instructions
//! that carry an `alignment` and absorb byte atoms. `TransientHash` (and
//! `HashToCurve`) absorb native FIELD elements — no byte atoms, no
//! injective-packing concern — and are deliberately out of scope.
//!
//! # Soundness direction
//!
//! Under-marking is SAFE (the lint over-fires and a human looks); OVER-marking
//! is the danger (a false negative hides a real hole). Every marking rule
//! below cites the upstream in-circuit constraint that justifies it; when
//! unsure, we do not mark. A firing on an existing circuit goes to dmd before
//! any allowlist entry is written; extending the marking rules (with a cited
//! warrant) is preferred over allowlisting.

// Ordered maps for the same reason as passes.rs (M23 R4): std's
// randomly-seeded HashMap is opaque to a model checker, and this pass is a
// named future proof target.
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use midnight_base_crypto::fab::{Alignment, AlignmentAtom, AlignmentSegment};
use minocrab_zkir::Fr;
use minocrab_zkir::v3::{Identifier, Instruction, IrType, Operand};

/// Bytes a single field element can hold losslessly — the FAB limb width
/// (transient-crypto `FR_BYTES_STORED`; the same 31 as `bytes_limbs`).
const LIMB_BYTES: usize = 31;

/// One violation: a hash-preimage limb the lint cannot prove bounded, or a
/// preimage whose operand↔atom mapping is itself malformed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// Index of the hash instruction in the stream.
    pub index: usize,
    /// `"keccak256"` or `"persistent_hash"`.
    pub hash: &'static str,
    /// What is wrong, naming the wire and the atom/limb.
    pub detail: String,
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "instruction {} ({}): {}", self.index, self.hash, self.detail)
    }
}

/// Audit one circuit's instruction stream. Empty result = every byte-atom
/// hash-preimage limb is provably bounded to its own byte width or constant.
pub fn audit(instructions: &[Instruction]) -> Vec<Finding> {
    let cap = field_max();

    // Pass A — position-independent direct constraints. ZKIR v3 is SSA (no
    // identifier is ever rebound: upstream's synthesis memory is push-only
    // and `Builder3` mints fresh identifiers), so a constraint anywhere in
    // the stream bounds the wire for the whole circuit — the same argument
    // `dedup_range_constraints` makes. The wildcard here is the SAFE
    // direction: a missed constraint only under-marks, which over-fires.
    let mut bound: BTreeMap<String, Max> = BTreeMap::new();
    for ins in instructions {
        match ins {
            Instruction::ConstrainBits { val: Operand::Variable(id), bits } => {
                note(&mut bound, id, Max::all_ones(*bits));
            }
            Instruction::ConstrainToBoolean { val: Operand::Variable(id) } => {
                note(&mut bound, id, Max::all_ones(1));
            }
            // ir_vm.rs asserts BOTH operands in-circuit:
            // `divisor < 2^(FR_BITS − bits)` and `modulus < 2^bits`
            // (assert_lower_than_fixed, the ReconstituteField arm).
            Instruction::ReconstituteField { divisor, modulus, bits, .. } => {
                if let Operand::Variable(id) = modulus {
                    note(&mut bound, id, Max::all_ones(*bits));
                }
                if let Operand::Variable(id) = divisor {
                    note(&mut bound, id, Max::all_ones(cap.bits() - *bits));
                }
            }
            // ir_vm asserts `low`'s 32nd byte is zero (so low < 2^248) and
            // byte-range-checks `high` (< 256) — the instruction's own doc.
            Instruction::Bytes32FromLowHigh { inputs: (low, high), .. } => {
                if let Operand::Variable(id) = low {
                    note(&mut bound, id, Max::all_ones(8 * LIMB_BYTES as u32));
                }
                if let Operand::Variable(id) = high {
                    note(&mut bound, id, Max::all_ones(8));
                }
            }
            // The Impact/popeq warrant (M23 R3 ruling, dmd 2026-08-28): an
            // UNCONDITIONAL popeq[c] binds each embedded wire to the ledger
            // read it witnesses — see `mark_popeq` for the parse, the guard
            // condition, and the honest scope of the warrant.
            Instruction::Impact { guard, inputs } => {
                if matches!(guard, Operand::Immediate(g) if Max::from_fr(g).bits() != 0) {
                    mark_popeq(inputs, &mut bound);
                }
            }
            _ => {}
        }
    }

    // Pass A2 — the shapes a subtraction lowers to, and the `a ≥ b` facts the
    // stream asserts. Position-independent for the same reason as pass A: an
    // `assert` constrains the witness wherever it sits, so a fact recorded
    // here bounds a wire defined before it. These feed the N1-N3 warrants in
    // pass B's `Add` arm — the ONLY rules in the lint that read an `Assert`
    // (notes/taint-lint.org §8, M23 R3's Class B).
    let shapes = Shapes::index(instructions);
    let ge_facts = shapes.ge_facts(instructions);

    // Pass A3 — the guarded ledger reads discharged by OBSERVABILITY rather
    // than by a bound: a forged value reaches no effect that is not already
    // inert whenever the read's own guard is false (M23 R3 Class A, option 4
    // of notes/taint-lint.org §8).
    let confined = confined_reads(instructions, &shapes, &Flow::of(instructions));

    // Pass B — one forward walk: propagate producer bounds (operands always
    // precede their uses in SSA, so forward order reaches the fixpoint given
    // pass A), track which identifiers hold `Bytes32` values (for `Encode`),
    // and audit each hash as it appears. This match is EXHAUSTIVE on purpose,
    // like `operands_mut`: a new upstream instruction must break this build
    // rather than silently escape the audit — the unsound direction is a new
    // byte-absorbing hash falling through a wildcard.
    let mut is_bytes32: BTreeSet<String> = BTreeSet::new();
    let mut findings = Vec::new();
    for (index, ins) in instructions.iter().enumerate() {
        match ins {
            // ---- the two audited hashes ---------------------------------
            Instruction::PersistentHash { alignment, inputs, output } => {
                audit_hash(index, "persistent_hash", alignment, inputs, &bound, &confined, &mut findings);
                is_bytes32.insert(output.0.clone());
            }
            Instruction::Keccak256 { alignment, inputs, output } => {
                audit_hash(index, "keccak256", alignment, inputs, &bound, &confined, &mut findings);
                is_bytes32.insert(output.0.clone());
            }

            // ---- bounded producers, each with its in-circuit warrant ----
            // Encode of a Bytes32: outputs are (low 31 bytes, high byte),
            // recomposed from the value's already-range-checked assigned
            // bytes (zkir-v3 ir_instructions/encode.rs:93-96). Any other
            // input type: 2 outputs could equally be JubjubPoint coordinates
            // (field-wide), so an unknown type is left unmarked.
            Instruction::Encode { input, outputs } => {
                let input_is_bytes32 =
                    matches!(input, Operand::Variable(id) if is_bytes32.contains(&id.0));
                if input_is_bytes32 && outputs.len() == 2 {
                    note(&mut bound, &outputs[0], Max::all_ones(8 * LIMB_BYTES as u32));
                    note(&mut bound, &outputs[1], Max::all_ones(8));
                }
            }
            // Both outputs recomposed from the CANONICAL full bit
            // decomposition of `val` (assigned_to_le_bits(.., true), the
            // DivModPowerOfTwo arm): mod from bits[..bits] (< 2^bits), div
            // from bits[bits..] — and div = val >> bits, so any bound on
            // `val` shifts down with it (val is canonical, ≤ p−1).
            Instruction::DivModPowerOfTwo { val, bits, outputs } => {
                if outputs.len() == 2 {
                    let val_max = op_max(&bound, val).unwrap_or(cap);
                    note(&mut bound, &outputs[0], val_max.shr(*bits));
                    note(&mut bound, &outputs[1], Max::all_ones(*bits));
                }
            }
            // output = divisor·2^bits + modulus exactly (linear_combination),
            // with both operands asserted in range (pass A above).
            Instruction::ReconstituteField { divisor, modulus, bits, output } => {
                let d = op_max(&bound, divisor)
                    .map(|m| m.min(Max::all_ones(cap.bits() - *bits)))
                    .unwrap_or_else(|| Max::all_ones(cap.bits() - *bits));
                let m = op_max(&bound, modulus)
                    .map(|x| x.min(Max::all_ones(*bits)))
                    .unwrap_or_else(|| Max::all_ones(*bits));
                if let Some(product) = d.checked_mul(Max::pow2(*bits)) {
                    if let Some(sum) = product.checked_add(m) {
                        if sum.le(&cap) {
                            note(&mut bound, output, sum);
                        }
                    }
                }
            }
            // Bytes32 → (low 31 bytes, high byte), recomposed from the
            // value's range-checked assigned bytes; the instruction adds no
            // constraint because none is needed.
            Instruction::Bytes32IntoLowHigh { outputs: (low, high), .. } => {
                note(&mut bound, low, Max::all_ones(8 * LIMB_BYTES as u32));
                note(&mut bound, high, Max::all_ones(8));
            }
            // A rename: the output IS the operand.
            Instruction::Copy { val, output } => {
                if let Some(m) = op_max(&bound, val) {
                    note(&mut bound, output, m);
                }
                if let Operand::Variable(id) = val {
                    if is_bytes32.contains(&id.0) {
                        is_bytes32.insert(output.0.clone());
                    }
                }
            }
            // std.select over a converted AssignedBit (the CondSelect arm),
            // so the output equals one of the two branches.
            Instruction::CondSelect { bit: _, a, b, output } => {
                if let (Some(ma), Some(mb)) = (op_max(&bound, a), op_max(&bound, b)) {
                    note(&mut bound, output, ma.max(mb));
                }
            }
            // Exact interval arithmetic, valid only while the result cannot
            // wrap the field: a ≤ Ma, b ≤ Mb ⇒ a+b ≤ Ma+Mb and a·b ≤ Ma·Mb,
            // over the integers iff Ma+Mb (resp. Ma·Mb) ≤ p−1.
            Instruction::Add { a, b, output } => {
                if let (Some(ma), Some(mb)) = (op_max(&bound, a), op_max(&bound, b)) {
                    if let Some(sum) = ma.checked_add(mb) {
                        if sum.le(&cap) {
                            note(&mut bound, output, sum);
                        }
                    }
                }
                // A SUBTRACTION, which is the same instruction: `Neg` wraps and
                // is unmarked, so the interval arithmetic above concludes
                // nothing for `add(a, neg(b))`. The three warrants recover the
                // bound where the stream proves the difference non-negative.
                // Both bounds are valid upper bounds when both apply, and
                // `note` keeps the tighter.
                if let Some(m) = subtraction_max(a, b, &bound, &shapes, &ge_facts) {
                    note(&mut bound, output, m);
                }
            }
            Instruction::Mul { a, b, output } => {
                if let (Some(ma), Some(mb)) = (op_max(&bound, a), op_max(&bound, b)) {
                    if let Some(product) = ma.checked_mul(mb) {
                        if product.le(&cap) {
                            note(&mut bound, output, product);
                        }
                    }
                }
            }
            // Boolean outputs: each is std.convert of an AssignedBit.
            Instruction::TestEq { output, .. }
            | Instruction::Not { output, .. }
            | Instruction::LessThan { output, .. } => {
                note(&mut bound, output, Max::all_ones(1));
            }

            // ---- Bytes32-typed producers (for Encode above) -------------
            Instruction::IntoBytes32 { output, .. }
            | Instruction::ReverseBytes { output, .. }
            | Instruction::Bytes32FromLowHigh { output, .. } => {
                is_bytes32.insert(output.0.clone());
            }
            Instruction::PublicInput { val_t, output, .. }
            | Instruction::PrivateInput { val_t, output, .. } => {
                // The witnessed VALUE is free; only its shape is `val_t`
                // (the instruction's own doc), so nothing is bounded HERE.
                // A `PublicInput` embedded in an UNCONDITIONAL popeq is
                // bounded by pass A's Impact arm (`mark_popeq`) — via the
                // ledger's external warrant, per the M23 R3 ruling — and a
                // guarded one stays free, deliberately.
                if *val_t == IrType::Bytes32 {
                    is_bytes32.insert(output.0.clone());
                }
            }

            // ---- everything else neither bounds nor absorbs bytes -------
            // Field-absorbing hashes (no byte atoms — out of scope by the
            // R3 spec), curve/field ops whose outputs are field- or
            // point-wide, and the no-output instructions.
            Instruction::TransientHash { .. }
            | Instruction::HashToCurve { .. }
            | Instruction::Assert { .. }
            | Instruction::ConstrainBits { .. }
            | Instruction::ConstrainEq { .. }
            | Instruction::ConstrainToBoolean { .. }
            | Instruction::Impact { .. }
            | Instruction::EcMul { .. }
            | Instruction::EcMulGenerator { .. }
            | Instruction::IntoCoordinates { .. }
            | Instruction::FromCoordinates { .. }
            | Instruction::FromBytes32 { .. }
            | Instruction::Neg { .. }
            | Instruction::Inv { .. }
            | Instruction::JubjubScalarFromNative { .. }
            | Instruction::Output { .. } => {}
        }
    }
    findings
}

/// Map one hash's operands onto its alignment's atoms and check each
/// byte-limb, following the in-circuit decoder's own consumption rule
/// (`fab_decode_to_bytes_atom`, zkir-v3 ir_vm.rs:125-175): a `field` atom
/// consumes one operand unchecked (field-wide, nothing narrower to enforce);
/// a `bytes n` atom consumes its leftover (most significant, `n mod 31`
/// bytes) limb FIRST when `n` is not a multiple of 31, then `n / 31` full
/// 31-byte limbs. NB `bytes 0` consumes NOTHING here — unlike the Impact
/// FAB rule (`minocrab_ledger::atom_limbs`, which floors at one limb), the
/// hash decoder's `chunks + (stray != 0)` is zero for `n = 0`.
fn audit_hash(
    index: usize,
    hash: &'static str,
    alignment: &Alignment,
    inputs: &[Operand],
    bound: &BTreeMap<String, Max>,
    confined: &BTreeSet<String>,
    findings: &mut Vec<Finding>,
) {
    let mut ops = inputs.iter();
    let mut consumed = 0usize;
    for (ai, segment) in alignment.0.iter().enumerate() {
        let atom = match segment {
            AlignmentSegment::Atom(atom) => atom,
            // The in-circuit decoder REJECTS option segments ("not yet
            // implemented") — a circuit carrying one cannot synthesize, so
            // this fires only on a malformed stream, and the mapping past
            // it is undefined.
            AlignmentSegment::Option(_) => {
                findings.push(Finding {
                    index,
                    hash,
                    detail: format!(
                        "alignment segment {ai} is an option, which the \
                         in-circuit decoder rejects; cannot map operands to atoms"
                    ),
                });
                return;
            }
        };
        match atom {
            AlignmentAtom::Field => match ops.next() {
                Some(_) => consumed += 1,
                None => {
                    findings.push(too_few(index, hash, ai, consumed));
                    return;
                }
            },
            // Same rejection as Option: compress atoms cannot be decoded
            // in-circuit at all.
            AlignmentAtom::Compress => {
                findings.push(Finding {
                    index,
                    hash,
                    detail: format!(
                        "alignment segment {ai} is a compress atom, which the \
                         in-circuit decoder rejects; cannot map operands to atoms"
                    ),
                });
                return;
            }
            AlignmentAtom::Bytes { length } => {
                let stray = *length as usize % LIMB_BYTES;
                let chunks = *length as usize / LIMB_BYTES;
                let widths = (stray > 0)
                    .then_some(stray)
                    .into_iter()
                    .chain(std::iter::repeat_n(LIMB_BYTES, chunks));
                for (li, width) in widths.enumerate() {
                    let Some(op) = ops.next() else {
                        findings.push(too_few(index, hash, ai, consumed));
                        return;
                    };
                    consumed += 1;
                    check_limb(index, hash, op, ai, li, *length, width, bound, confined, findings);
                }
            }
        }
    }
    let leftover = ops.count();
    if leftover > 0 {
        findings.push(Finding {
            index,
            hash,
            detail: format!(
                "{leftover} operand(s) beyond what the alignment consumes \
                 ({consumed}); cannot map operands to atoms"
            ),
        });
    }
}

fn too_few(index: usize, hash: &'static str, ai: usize, consumed: usize) -> Finding {
    Finding {
        index,
        hash,
        detail: format!(
            "operands exhausted at alignment segment {ai} (consumed {consumed}); \
             cannot map operands to atoms"
        ),
    }
}

/// The per-limb verdict: constant, or provably within the limb's byte width.
#[allow(clippy::too_many_arguments)]
fn check_limb(
    index: usize,
    hash: &'static str,
    op: &Operand,
    ai: usize,
    li: usize,
    atom_len: u32,
    width_bytes: usize,
    bound: &BTreeMap<String, Max>,
    confined: &BTreeSet<String>,
    findings: &mut Vec<Finding>,
) {
    let required = 8 * width_bytes as u32;
    let place =
        format!("bytes<{atom_len}> (segment {ai}) limb {li} ({width_bytes} byte(s))");
    match op {
        // A constant the prover cannot vary is no soundness hole; one that
        // exceeds its atom's width still makes the circuit unsatisfiable at
        // the decoder, so it is flagged as the bug it is.
        Operand::Immediate(v) => {
            if Max::from_fr(v).bits() > required {
                findings.push(Finding {
                    index,
                    hash,
                    detail: format!(
                        "immediate of {} bits exceeds {place} — the decoder \
                         makes this unsatisfiable",
                        Max::from_fr(v).bits()
                    ),
                });
            }
        }
        // A guarded ledger read the observability warrant discharges: no
        // bound, and none needed, because a forged value reaches no effect
        // that is not already inert when the read's guard is false.
        Operand::Variable(id) if confined.contains(&id.0) => {}
        Operand::Variable(id) => match bound.get(&id.0) {
            Some(m) if m.bits() <= required => {}
            proven => findings.push(Finding {
                index,
                hash,
                detail: format!(
                    "wire {id:?} feeds {place} but is {} — required ≤ {required} bits; \
                     the packing is only injective for in-range values \
                     (api-safety-survey §B3)",
                    match proven {
                        Some(m) => format!("only proven ≤ {} bits", m.bits()),
                        None => "not provably bounded".to_string(),
                    }
                ),
            }),
        },
    }
}

/// The Impact/popeq warrant (M23 R3 ruling, dmd 2026-08-28): if `inputs`
/// parses EXACTLY as `popeq`/`popeqc` — `[0x0c|0x0d, atom count, one
/// alignment element per atom, then the limbs]` (`Op::field_repr`,
/// ops.rs:477-480; header encoding fab.rs:596-608: `bytes<n>` → n,
/// `compress` → p−1, `field` → p−2) — bound each `bytes` limb WIRE to its
/// limb's byte width.
///
/// THE WARRANT, and why it is EXTERNAL: the caller has checked the Impact's
/// guard is an immediate non-zero, so the instruction unconditionally pushes
/// these very elements into the public-input stream, where the verifier
/// checks them against the transaction's declared transcript op — and the
/// ledger accepts that transaction only if the transcript's expected value
/// equals the value actually read from state (`process_read`), whose
/// `ValueAtom`s are normalized in-range for their atoms. So the wire equals
/// a stored, normalized limb: ≤ its byte width. Nothing IN THE CIRCUIT
/// enforces this — the chain runs through the ledger's own invariant, which
/// is why guarded reads are NOT marked here (a false guard pushes
/// `select(guard, x, 0) = 0`, the comparison passes on zero, and the wire is
/// genuinely free). A VARIABLE guard that happens to always be 1 is also not
/// marked — conservatively, since the lint cannot prove it.
///
/// The FAB limbing (`AlignedValue::field_repr`, fab.rs:486-511): `bytes<n>`
/// is stray-FIRST — the leftover `n mod 31` most-significant bytes, then
/// `n / 31` full 31-byte limbs — and `bytes<0>` is ONE zero limb (the
/// `atom_limbs` floor; its stored value normalizes to zero, so the bound is
/// exactly 0). `field` and `compress` atoms occupy one field-wide limb each
/// and bound nothing. Anything that does not parse cleanly — wrong opcode,
/// non-immediate header, limb count mismatch, leftover elements — marks
/// NOTHING: under-marking is the safe direction.
fn mark_popeq(inputs: &[Operand], bound: &mut BTreeMap<String, Max>) {
    for (op, width) in popeq_limbs(inputs).unwrap_or_default() {
        if let (Operand::Variable(id), Some(width)) = (op, width) {
            note(bound, id, Max::all_ones(8 * width as u32));
        }
    }
}

/// The parse behind [`mark_popeq`], shared with the guarded-read index the
/// observability warrant builds (`Confinement`): each limb element of a
/// `popeq`/`popeqc` paired with its byte width, or `None` for a field- or
/// compress-wide limb that bounds nothing. `None` for the whole thing if the
/// element stream is not cleanly a popeq.
fn popeq_limbs(inputs: &[Operand]) -> Option<Vec<(&Operand, Option<usize>)>> {
    let small = |op: &Operand| -> Option<u64> {
        match op {
            Operand::Immediate(v) => {
                let m = Max::from_fr(v);
                (m.bits() <= 32).then(|| m.low_u64())
            }
            Operand::Variable(_) => None,
        }
    };
    if inputs.len() < 2 || small(&inputs[0]).is_none_or(|op| op != 0x0c && op != 0x0d) {
        return None;
    }
    let atom_count = small(&inputs[1]).map(|n| n as usize)?;
    if inputs.len() < 2 + atom_count {
        return None;
    }
    let compress_elem = field_max(); // p − 1 (fab.rs: `compress` → −1)
    let field_elem = Max::from_fr(&(Fr::from(0u64) - Fr::from(2u64))); // p − 2
    // Per limb: Some(width bytes) for a bytes limb, None for field/compress.
    let mut widths: Vec<Option<usize>> = Vec::new();
    for header in &inputs[2..2 + atom_count] {
        let Operand::Immediate(v) = header else {
            return None;
        };
        let m = Max::from_fr(v);
        if m == compress_elem || m == field_elem {
            widths.push(None);
        } else if m.bits() <= 32 {
            let n = m.low_u64() as usize;
            if n == 0 {
                widths.push(Some(0));
            } else {
                if n % LIMB_BYTES != 0 {
                    widths.push(Some(n % LIMB_BYTES));
                }
                widths.extend(std::iter::repeat_n(Some(LIMB_BYTES), n / LIMB_BYTES));
            }
        } else {
            return None;
        }
    }
    let limbs = &inputs[2 + atom_count..];
    if limbs.len() != widths.len() {
        return None;
    }
    Some(limbs.iter().zip(widths).collect())
}

// ---- the observability warrant (M23 R3 Class A, notes/taint-lint.org §8) ----
//
// `mark_popeq` refuses to bound a read whose popeq guard is a WIRE, and that
// refusal is right: in-circuit the `public_input` arm ignores its guard
// entirely, and a false guard makes the Impact push `select(g, x, 0) = 0`, so
// the verifier's comparison passes on the zero and the wire is genuinely free.
// No bound exists to prove, and inventing one would be the over-marking the
// module docs forbid.
//
// What makes such a read sound is a DIFFERENT argument, and option 4 of §8:
// OBSERVABILITY. When `g` is false, every effect a forged value could reach is
// itself inert — each Impact that would publish the digest is guarded by a bit
// that is zero whenever `g` is, so it pushes zeros too, and nothing constrains
// the digest. The branch has no effect to steal, so a forged preimage buys the
// prover nothing. When `g` is true the popeq binds the read to the ledger's
// normalized value, which is `mark_popeq`'s own warrant. Free but
// unobservable, or observable but bound: either way the packing's injectivity
// cannot be exploited.
//
// This is a REACHABILITY obligation rather than a bound, and §8 is explicit
// that "a single unguarded consumer makes it wrong" — so the classification
// below is exhaustive and every unknown is a refusal.

/// Per-instruction reads and definitions, computed once. `passes::operands`
/// clones the instruction, so calling it inside the closure's fixpoint would
/// be quadratic in clones; this pays for it once per circuit.
struct Flow {
    /// Every wire the instruction READS — `passes::operands` (all reads but
    /// the terminator's) plus `passes::returned` (the terminator's). Both are
    /// exhaustive by construction and are the lists the Lean dataflow gate
    /// diffs against `MinocrabZkir.Dataflow` (tests/lean_dataflow.rs), so a
    /// new upstream operand position cannot hide from this walk.
    reads: Vec<BTreeSet<String>>,
    /// Every wire the instruction BINDS (`passes::defined_identifiers`).
    defines: Vec<Vec<String>>,
}

impl Flow {
    fn of(instructions: &[Instruction]) -> Self {
        fn wire(op: &Operand) -> Option<String> {
            match op {
                Operand::Variable(id) => Some(id.0.clone()),
                Operand::Immediate(_) => None,
            }
        }
        Flow {
            reads: instructions
                .iter()
                .map(|ins| {
                    super::passes::operands(ins)
                        .iter()
                        .chain(super::passes::returned(ins).iter())
                        .filter_map(wire)
                        .collect()
                })
                .collect(),
            defines: instructions
                .iter()
                .map(|ins| {
                    super::passes::defined_identifiers(ins)
                        .into_iter()
                        .map(|id| id.0)
                        .collect()
                })
                .collect(),
        }
    }
}

/// How far [`Shapes::dominated_by`] chases a guard chain. `when` nests a
/// handful deep; SSA rules out a cycle, so this only bounds pathological input.
const DOMINANCE_FUEL: u32 = 32;

/// The guarded ledger reads whose forgery reaches no effect — discharged by
/// observability rather than by a bound.
fn confined_reads(instructions: &[Instruction], shapes: &Shapes, flow: &Flow) -> BTreeSet<String> {
    // The reads in question: a wire embedded as a SIZED limb of a popeq whose
    // guard is a WIRE. An immediate-guarded popeq is `mark_popeq`'s case and
    // already bounded; a field- or compress-wide limb witnesses no byte atom.
    let mut guarded: BTreeMap<String, String> = BTreeMap::new();
    for ins in instructions {
        if let Instruction::Impact { guard: Operand::Variable(g), inputs } = ins {
            for (op, width) in popeq_limbs(inputs).unwrap_or_default() {
                if let (Operand::Variable(id), Some(_)) = (op, width) {
                    guarded.insert(id.0.clone(), g.0.clone());
                }
            }
        }
    }
    guarded
        .into_iter()
        .filter(|(read, g)| confined(instructions, shapes, flow, read, g))
        .map(|(read, _)| read)
        .collect()
}

/// Is everything derived from `read` inert whenever `g` is false?
fn confined(
    instructions: &[Instruction],
    shapes: &Shapes,
    flow: &Flow,
    read: &str,
    g: &str,
) -> bool {
    // The forward closure: every wire a forged `read` could change. Grown to a
    // fixpoint rather than in stream order, so the walk does not rely on
    // operands preceding their uses even though SSA gives it.
    let mut tainted: BTreeSet<String> = BTreeSet::new();
    tainted.insert(read.to_string());
    loop {
        let mut grew = false;
        for i in 0..instructions.len() {
            if flow.reads[i].iter().any(|w| tainted.contains(w)) {
                for out in &flow.defines[i] {
                    grew |= tainted.insert(out.clone());
                }
            }
        }
        if !grew {
            break;
        }
    }

    // Every instruction reading something derived from the read must be inert
    // whenever `g` is false.
    instructions.iter().enumerate().all(|(i, ins)| {
        if !flow.reads[i].iter().any(|w| tainted.contains(w)) {
            return true;
        }
        match ins {
            // THE TRANSCRIPT. An Impact pushes `select(guard, x, 0)`, so it is
            // inert exactly when its guard is zero, and therefore inert
            // whenever `g` is zero iff its guard is dominated by `g`. An
            // IMMEDIATE guard is never dominated by a wire: it publishes
            // whatever `g` does.
            Instruction::Impact { guard: Operand::Variable(h), .. } => {
                shapes.dominated_by(&h.0, g, DOMINANCE_FUEL)
            }
            Instruction::Impact { .. } => false,

            // A CONSTRAINT on a derived wire. A forged value then changes
            // whether the circuit is satisfiable, which may well be safe — but
            // that is a different argument from "no effect to steal", and this
            // rule does not make it. Refuse.
            Instruction::Assert { .. }
            | Instruction::ConstrainEq { .. }
            | Instruction::ConstrainBits { .. }
            | Instruction::ConstrainToBoolean { .. } => false,

            // Leaving the circuit named is an effect of its own.
            Instruction::Output { .. } => false,

            // A derived wire used as the GUARD of a read — the only way these
            // two can read a tainted wire — steers the transcript WALK, how
            // many elements are consumed. That is observable even though the
            // arm ignores the guard in-circuit. Refuse.
            Instruction::PublicInput { .. } | Instruction::PrivateInput { .. } => false,

            // Everything else only COMPUTES: whatever it binds is already in
            // the closure, so its own consumers are checked in turn.
            // Exhaustive on purpose, like pass B — a new upstream instruction
            // that reaches the transcript must break this build rather than be
            // waved through as arithmetic.
            Instruction::PersistentHash { .. }
            | Instruction::Keccak256 { .. }
            | Instruction::TransientHash { .. }
            | Instruction::HashToCurve { .. }
            | Instruction::Encode { .. }
            | Instruction::DivModPowerOfTwo { .. }
            | Instruction::ReconstituteField { .. }
            | Instruction::Bytes32IntoLowHigh { .. }
            | Instruction::Bytes32FromLowHigh { .. }
            | Instruction::IntoBytes32 { .. }
            | Instruction::FromBytes32 { .. }
            | Instruction::ReverseBytes { .. }
            | Instruction::Copy { .. }
            | Instruction::CondSelect { .. }
            | Instruction::Add { .. }
            | Instruction::Mul { .. }
            | Instruction::Neg { .. }
            | Instruction::Inv { .. }
            | Instruction::TestEq { .. }
            | Instruction::Not { .. }
            | Instruction::LessThan { .. }
            | Instruction::EcMul { .. }
            | Instruction::EcMulGenerator { .. }
            | Instruction::IntoCoordinates { .. }
            | Instruction::FromCoordinates { .. }
            | Instruction::JubjubScalarFromNative { .. } => true,
        }
    })
}

/// Merge a newly proven maximum for `id`, keeping the tightest.
fn note(bound: &mut BTreeMap<String, Max>, id: &Identifier, m: Max) {
    bound
        .entry(id.0.clone())
        .and_modify(|old| *old = (*old).min(m))
        .or_insert(m);
}

/// The proven maximum of an operand: an immediate's exact value, or the
/// wire's tightest noted bound.
fn op_max(bound: &BTreeMap<String, Max>, op: &Operand) -> Option<Max> {
    match op {
        Operand::Immediate(v) => Some(Max::from_fr(v)),
        Operand::Variable(id) => bound.get(&id.0).copied(),
    }
}

/// `p − 1`: the largest value a wire can hold, and the cap past which
/// interval arithmetic could wrap and is abandoned.
fn field_max() -> Max {
    Max::from_fr(&(Fr::from(0u64) - Fr::from(1u64)))
}

// ---- the subtraction warrants (M23 R3 Class B, notes/taint-lint.org §8) -----
//
// ZKIR v3 has no `Sub`: `Uint::sub_with` / `BoundedUint::sub_with` lower to
// `assert(ge(a, b)); let n = neg(b); from_field_unchecked(add(a, n))`
// (minocrab-std/src/v3.rs). `Neg` wraps mod p and is deliberately unmarked
// (the module docs' soundness direction), so pass B's interval arithmetic
// concludes nothing about the difference and every such wire fires — the
// `%add.*` residue of the frozen baseline. These three rules recover the
// bound in the cases where the stream itself proves the difference
// non-negative. They cite only IN-CIRCUIT constraints, so unlike `mark_popeq`
// they do not widen the lint's one external dependency.

/// The instruction shapes the warrants must see through, indexed by output
/// wire. SSA, so each wire has at most one producer.
#[derive(Default)]
struct Shapes {
    /// `neg` output → its operand.
    neg: BTreeMap<String, Operand>,
    /// `not` output → its operand.
    not: BTreeMap<String, Operand>,
    /// `cond_select` output → `(bit, a, b)`; the output is `bit ? a : b`.
    select: BTreeMap<String, (Operand, Operand, Operand)>,
    /// `less_than` output → `(a, b, bits)`.
    less_than: BTreeMap<String, (Operand, Operand, u32)>,
}

/// `a ≥ b` as the stream asserts it: the width the comparison was made at, and
/// the guard it holds under (`None` = unconditionally).
struct Ge {
    a: Operand,
    b: Operand,
    bits: u32,
    guard: Option<String>,
}

impl Shapes {
    fn index(instructions: &[Instruction]) -> Self {
        let mut s = Shapes::default();
        for ins in instructions {
            match ins {
                Instruction::Neg { a, output } => {
                    s.neg.insert(output.0.clone(), a.clone());
                }
                Instruction::Not { a, output } => {
                    s.not.insert(output.0.clone(), a.clone());
                }
                Instruction::CondSelect { bit, a, b, output } => {
                    s.select
                        .insert(output.0.clone(), (bit.clone(), a.clone(), b.clone()));
                }
                Instruction::LessThan { a, b, bits, output } => {
                    s.less_than.insert(output.0.clone(), (a.clone(), b.clone(), *bits));
                }
                _ => {}
            }
        }
        s
    }

    /// Every `a ≥ b` the stream's asserts establish.
    fn ge_facts(&self, instructions: &[Instruction]) -> Vec<Ge> {
        instructions
            .iter()
            .filter_map(|ins| match ins {
                Instruction::Assert { cond } => self.ge_fact(cond),
                _ => None,
            })
            .collect()
    }

    /// What one `assert` establishes, if its condition is a shape
    /// `predicate::ge` lowers to — optionally under one guard.
    fn ge_fact(&self, cond: &Operand) -> Option<Ge> {
        // Unconditional first. This also DISAMBIGUATES the two shapes, which
        // are both a `cond_select` with `b: 1`: `cond_select{a: 0, b: 1,
        // bit: lt}` is `NOT lt` and belongs here, while the guarded form below
        // carries a wire in `a`.
        if let Some(ge) = self.not_less_than(cond) {
            return Some(ge);
        }
        // Guarded: `cond_select{a: inner, b: 1, bit: g}` is `g ? inner : true`,
        // so asserting it establishes `g ⇒ inner` — the shape an `assert`
        // inside `when` lowers to.
        let Operand::Variable(c) = cond else { return None };
        let (bit, inner, otherwise) = self.select.get(&c.0)?;
        let Operand::Variable(g) = bit else { return None };
        if !is_imm(otherwise, 1) {
            return None;
        }
        let ge = self.not_less_than(inner)?;
        Some(Ge { guard: Some(g.0.clone()), ..ge })
    }

    /// `NOT (a < b)`, in either encoding the builder emits: a `Not`
    /// instruction, or `cond_select{a: 0, b: 1, bit: lt}`.
    fn not_less_than(&self, op: &Operand) -> Option<Ge> {
        let Operand::Variable(v) = op else { return None };
        let lt = match (self.not.get(&v.0), self.select.get(&v.0)) {
            (Some(inner), _) => inner,
            (None, Some((bit, a, b))) if is_imm(a, 0) && is_imm(b, 1) => bit,
            _ => return None,
        };
        let Operand::Variable(lt) = lt else { return None };
        let (a, b, bits) = self.less_than.get(&lt.0)?;
        Some(Ge { a: a.clone(), b: b.clone(), bits: *bits, guard: None })
    }

    /// Is `h` zero whenever `g` is zero? Then an op guarded by `h` is inert
    /// whenever one guarded by `g` is — what the observability warrant needs of
    /// every Impact that could publish a forged digest.
    ///
    /// True for `h == g`, and through any chain of
    /// `cond_select{a: _, b: 0, bit: k}`: that output is zero unless `k`, so if
    /// `k` is in turn zero whenever `g` is, so is the output. This is exactly
    /// how `when` nests a guard inside an enclosing one, which is why
    /// `erc20_vault::complete_deposit` can push the coin commitment under
    /// `%sel.102 = cond_select(%mul.101, 0, %sel.65)` while the read sits under
    /// `%sel.65`. Syntactic and conservative: any other shape is not dominated
    /// as far as this rule is concerned.
    fn dominated_by(&self, h: &str, g: &str, fuel: u32) -> bool {
        if h == g {
            return true;
        }
        if fuel == 0 {
            return false;
        }
        match self.select.get(h) {
            Some((Operand::Variable(bit), _, otherwise)) if is_imm(otherwise, 0) => {
                self.dominated_by(&bit.0, g, fuel - 1)
            }
            _ => false,
        }
    }

    /// `cond_select{a: x, b: 0, bit: g}`: the operand is `x` when `g` holds and
    /// EXACTLY zero otherwise.
    fn zeroed_under(&self, op: &Operand, g: &str) -> bool {
        let Operand::Variable(v) = op else { return false };
        matches!(
            self.select.get(&v.0),
            Some((Operand::Variable(bit), _, otherwise))
                if bit.0 == g && is_imm(otherwise, 0)
        )
    }
}

/// Is this operand exactly the immediate `n`?
fn is_imm(op: &Operand, n: u64) -> bool {
    matches!(op, Operand::Immediate(v) if *v == Fr::from(n))
}

/// A bound on `add(a, b)` when it is really a SUBTRACTION — one operand the
/// `neg` of the other's subtrahend — under warrants N1, N2 or N3.
fn subtraction_max(
    a: &Operand,
    b: &Operand,
    bound: &BTreeMap<String, Max>,
    shapes: &Shapes,
    ge_facts: &[Ge],
) -> Option<Max> {
    // `add` is symmetric, so either operand may be the negation.
    for (minuend, negated) in [(a, b), (b, a)] {
        let Operand::Variable(n) = negated else { continue };
        let Some(subtrahend) = shapes.neg.get(&n.0) else { continue };
        if let Some(m) = n1(minuend, subtrahend, bound) {
            return Some(m);
        }
        if let Some(m) = n2_or_n3(minuend, subtrahend, bound, shapes, ge_facts) {
            return Some(m);
        }
    }
    None
}

/// WARRANT N1 — `add(C, neg(b))` with `C` an immediate and `b ≤ Mb ≤ C`: the
/// result is the INTEGER `C − b ∈ [0, C]`. The range constraint on `b` alone
/// rules out the wrap, so no assert is needed, which makes this the cleanest
/// of the three. (`erc20_vault_pending`'s `change_nonce`, `255 − mintNonce.hi`
/// with `constrain_bits 8` on the operand — note `Mb ≤ C` holds exactly there,
/// and a 9-bit constraint would correctly fail it.)
fn n1(minuend: &Operand, subtrahend: &Operand, bound: &BTreeMap<String, Max>) -> Option<Max> {
    let Operand::Immediate(c) = minuend else { return None };
    let c = Max::from_fr(c);
    let mb = op_max(bound, subtrahend)?;
    mb.le(&c).then_some(c)
}

/// WARRANT N2 — `a ≤ Ma`, `b ≤ Mb`, both within the width the comparison was
/// made at, plus an UNCONDITIONALLY asserted `a ≥ b`: the field difference IS
/// the integer difference, so it is `≤ Ma`.
///
/// WARRANT N3 — the same, with the assert GUARDED, when both operands are
/// `cond_select{a: x, b: 0, bit: g}` on the SAME `g`: with `g = 1` N2 applies;
/// with `g = 0` both operands are exactly 0 and the difference is 0. Either
/// way `≤ Ma`.
///
/// Both require `Ma` and `Mb` inside `2^bits − 1`: a `less_than` at a width
/// narrower than its operands is not the comparison we are reading it as, and
/// assuming otherwise would be an OVER-marking.
fn n2_or_n3(
    minuend: &Operand,
    subtrahend: &Operand,
    bound: &BTreeMap<String, Max>,
    shapes: &Shapes,
    ge_facts: &[Ge],
) -> Option<Max> {
    let ma = op_max(bound, minuend)?;
    let mb = op_max(bound, subtrahend)?;
    for fact in ge_facts {
        if fact.a != *minuend || fact.b != *subtrahend {
            continue;
        }
        let width = Max::all_ones(fact.bits);
        if !(ma.le(&width) && mb.le(&width)) {
            continue;
        }
        match &fact.guard {
            None => return Some(ma),
            Some(g) => {
                if shapes.zeroed_under(minuend, g) && shapes.zeroed_under(subtrahend, g) {
                    return Some(ma);
                }
            }
        }
    }
    None
}

// ---- exact 256-bit interval maxima ------------------------------------------
//
// Bit-count bounds ("a < 2^n") are too coarse for the one pattern that
// matters: a packed limb `a + b·2^64` with `a ≤ 2^64−1, b ≤ 2^64−1` is
// EXACTLY ≤ 2^128−1, but any rule of the form `max(n,m)+1` reports 129 bits
// and falsely fires on a full-width atom. Tracking exact maxima keeps the
// arithmetic honest in both directions: no false fire on a tight packing,
// and no false pass from rounding a bound down.

/// An exact upper bound on a wire's value, as a 256-bit little-endian
/// integer. Every tracked maximum is ≤ p − 1 (the caller drops anything
/// larger), so 4 limbs never truncate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Max([u64; 4]);

impl Max {
    /// `2^bits − 1` (`bits ≤ 256`).
    fn all_ones(bits: u32) -> Max {
        let bits = bits.min(256) as usize;
        let mut limbs = [0u64; 4];
        for (i, limb) in limbs.iter_mut().enumerate() {
            let lo = i * 64;
            *limb = if bits >= lo + 64 {
                u64::MAX
            } else if bits > lo {
                (1u64 << (bits - lo)) - 1
            } else {
                0
            };
        }
        Max(limbs)
    }

    /// `2^bits` (`bits < 256`).
    fn pow2(bits: u32) -> Max {
        let mut limbs = [0u64; 4];
        limbs[(bits / 64) as usize] = 1u64 << (bits % 64);
        Max(limbs)
    }

    /// From a field element's canonical little-endian bytes.
    fn from_fr(v: &Fr) -> Max {
        let bytes = v.as_le_bytes();
        debug_assert!(bytes.len() <= 32, "a canonical Fr fits 32 bytes");
        let mut limbs = [0u64; 4];
        for (i, byte) in bytes.iter().enumerate().take(32) {
            limbs[i / 8] |= (*byte as u64) << (8 * (i % 8));
        }
        Max(limbs)
    }

    /// Position of the highest set bit (0 for zero): `self ≤ 2^bits() − 1`.
    fn bits(&self) -> u32 {
        for i in (0..4).rev() {
            if self.0[i] != 0 {
                return 64 * i as u32 + (64 - self.0[i].leading_zeros());
            }
        }
        0
    }

    /// `None` on 256-bit overflow.
    fn checked_add(self, other: Max) -> Option<Max> {
        let mut limbs = [0u64; 4];
        let mut carry = 0u64;
        for (i, out) in limbs.iter_mut().enumerate() {
            let (a, c1) = self.0[i].overflowing_add(other.0[i]);
            let (b, c2) = a.overflowing_add(carry);
            *out = b;
            carry = (c1 as u64) + (c2 as u64);
        }
        (carry == 0).then_some(Max(limbs))
    }

    /// `None` on 256-bit overflow.
    fn checked_mul(self, other: Max) -> Option<Max> {
        let mut wide = [0u64; 8];
        for i in 0..4 {
            let mut carry = 0u128;
            for j in 0..4 {
                let t = wide[i + j] as u128 + self.0[i] as u128 * other.0[j] as u128 + carry;
                wide[i + j] = t as u64;
                carry = t >> 64;
            }
            wide[i + 4] = carry as u64;
        }
        wide[4..].iter().all(|&l| l == 0).then(|| {
            Max([wide[0], wide[1], wide[2], wide[3]])
        })
    }

    /// Logical shift right.
    fn shr(self, bits: u32) -> Max {
        if bits >= 256 {
            return Max([0; 4]);
        }
        let (limb, rem) = ((bits / 64) as usize, bits % 64);
        let mut limbs = [0u64; 4];
        for (i, out) in limbs.iter_mut().enumerate().take(4 - limb) {
            let mut v = self.0[i + limb] >> rem;
            if rem > 0 && i + limb + 1 < 4 {
                v |= self.0[i + limb + 1] << (64 - rem);
            }
            *out = v;
        }
        Max(limbs)
    }

    /// The low limb — the whole value when `bits() ≤ 64`, which is the only
    /// way it is used (small-integer recognition in the popeq parse).
    fn low_u64(&self) -> u64 {
        self.0[0]
    }

    fn le(&self, other: &Max) -> bool {
        for i in (0..4).rev() {
            if self.0[i] != other.0[i] {
                return self.0[i] < other.0[i];
            }
        }
        true
    }

    fn min(self, other: Max) -> Max {
        if self.le(&other) { self } else { other }
    }

    fn max(self, other: Max) -> Max {
        if self.le(&other) { other } else { self }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(name: &str) -> Identifier {
        Identifier(name.to_string())
    }

    fn var(name: &str) -> Operand {
        Operand::Variable(id(name))
    }

    fn imm(v: u64) -> Operand {
        Operand::Immediate(Fr::from(v))
    }

    fn bytes_atom(length: u32) -> AlignmentSegment {
        AlignmentSegment::Atom(AlignmentAtom::Bytes { length })
    }

    fn keccak(alignment: Vec<AlignmentSegment>, inputs: Vec<Operand>) -> Instruction {
        Instruction::Keccak256 {
            alignment: Alignment(alignment),
            inputs,
            output: id("digest"),
        }
    }

    #[test]
    fn max_arithmetic_is_exact() {
        // The packing identity that motivates exact maxima: (2^64−1) +
        // (2^64−1)·2^64 = 2^128−1, exactly a 16-byte atom.
        let seg = Max::all_ones(64);
        let shifted = seg.checked_mul(Max::pow2(64)).unwrap();
        let limb = seg.checked_add(shifted).unwrap();
        assert_eq!(limb, Max::all_ones(128));
        assert_eq!(limb.bits(), 128);
        // A one-bit overlap is one bit too many.
        let overlap = seg.checked_add(seg.checked_mul(Max::pow2(63)).unwrap()).unwrap();
        assert!(overlap.bits() > 127);
        // Shift inverts the packing.
        assert_eq!(limb.shr(64), Max::all_ones(64));
        // Field cap: 255 bits for the BLS12-381 scalar field.
        assert_eq!(field_max().bits(), 255);
    }

    #[test]
    fn unconstrained_limb_fires_and_constrained_passes() {
        let hash = keccak(vec![bytes_atom(20)], vec![var("w")]);
        let unconstrained = vec![
            Instruction::PrivateInput {
                guard: None,
                val_t: IrType::Native,
                output: id("w"),
            },
            hash.clone(),
        ];
        let findings = audit(&unconstrained);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(findings[0].detail.contains("not provably bounded"), "{}", findings[0]);

        // The constraint may come AFTER the hash — SSA makes it global.
        let constrained = vec![
            Instruction::PrivateInput {
                guard: None,
                val_t: IrType::Native,
                output: id("w"),
            },
            hash,
            Instruction::ConstrainBits { val: var("w"), bits: 160 },
        ];
        assert_eq!(audit(&constrained), vec![]);
    }

    #[test]
    fn packed_limb_needs_every_segment_bounded() {
        // limb = a + b·2^64 into a bytes<16> atom — the §B3 shape.
        let pack = |extra: Vec<Instruction>| {
            let mut stream = vec![
                Instruction::PrivateInput {
                    guard: None,
                    val_t: IrType::Native,
                    output: id("a"),
                },
                Instruction::PrivateInput {
                    guard: None,
                    val_t: IrType::Native,
                    output: id("b"),
                },
                Instruction::Mul {
                    a: var("b"),
                    b: Operand::Immediate(
                        Fr::from_le_bytes(&[0, 0, 0, 0, 0, 0, 0, 0, 1]).expect("2^64 fits"),
                    ),
                    output: id("shifted"),
                },
                Instruction::Add {
                    a: var("a"),
                    b: var("shifted"),
                    output: id("limb"),
                },
                keccak(vec![bytes_atom(16)], vec![var("limb")]),
            ];
            stream.extend(extra);
            stream
        };
        // Both segments constrained: the packed limb is exactly ≤ 2^128−1.
        let both = pack(vec![
            Instruction::ConstrainBits { val: var("a"), bits: 64 },
            Instruction::ConstrainBits { val: var("b"), bits: 64 },
        ]);
        assert_eq!(audit(&both), vec![]);
        // One segment unconstrained: the limb has no derivable bound.
        let one = pack(vec![Instruction::ConstrainBits { val: var("a"), bits: 64 }]);
        let findings = audit(&one);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(findings[0].detail.contains("limb"), "{}", findings[0]);
    }

    #[test]
    fn intrinsically_bounded_sources_pass() {
        // div_mod's outputs, an immediate, and a field atom need no
        // constraint instructions at all.
        let stream = vec![
            Instruction::PrivateInput {
                guard: None,
                val_t: IrType::Native,
                output: id("w"),
            },
            Instruction::DivModPowerOfTwo {
                val: var("w"),
                bits: 8,
                outputs: vec![id("div"), id("mod")],
            },
            keccak(
                vec![
                    bytes_atom(1),
                    bytes_atom(2),
                    AlignmentSegment::Atom(AlignmentAtom::Field),
                ],
                vec![var("mod"), imm(0x1234), var("w")],
            ),
        ];
        assert_eq!(audit(&stream), vec![]);
        // But div of an UNBOUNDED value is only ≤ (p−1) >> 8 — 247 bits —
        // and must not pass a narrower atom than that.
        let wide = vec![
            Instruction::PrivateInput {
                guard: None,
                val_t: IrType::Native,
                output: id("w"),
            },
            Instruction::DivModPowerOfTwo {
                val: var("w"),
                bits: 8,
                outputs: vec![id("div"), id("mod")],
            },
            keccak(vec![bytes_atom(16)], vec![var("div")]),
        ];
        assert_eq!(audit(&wide).len(), 1);
    }

    #[test]
    fn multi_limb_atom_maps_stray_first() {
        // bytes<32> = 1-byte stray (most significant) + one 31-byte limb,
        // in that order — the decoder's consumption order. A wire bounded
        // to 8 bits passes slot 0 but could not pass slot 1's 248-bit...
        // rather: a 248-bit-bounded wire in slot 0 must FIRE (slot 0 is
        // the 1-byte limb).
        let stream = vec![
            Instruction::PrivateInput {
                guard: None,
                val_t: IrType::Native,
                output: id("hi"),
            },
            Instruction::PrivateInput {
                guard: None,
                val_t: IrType::Native,
                output: id("lo"),
            },
            Instruction::ConstrainBits { val: var("hi"), bits: 248 },
            Instruction::ConstrainBits { val: var("lo"), bits: 248 },
            keccak(vec![bytes_atom(32)], vec![var("hi"), var("lo")]),
        ];
        let findings = audit(&stream);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(findings[0].detail.contains("limb 0 (1 byte"), "{}", findings[0]);
    }

    #[test]
    fn transient_hash_is_out_of_scope() {
        let stream = vec![
            Instruction::PrivateInput {
                guard: None,
                val_t: IrType::Native,
                output: id("w"),
            },
            Instruction::TransientHash { inputs: vec![var("w")], output: id("h") },
        ];
        assert_eq!(audit(&stream), vec![]);
    }

    #[test]
    fn arity_mismatch_is_reported() {
        let short = vec![keccak(vec![bytes_atom(32)], vec![imm(1)])];
        assert_eq!(audit(&short).len(), 1);
        let long = vec![keccak(vec![bytes_atom(1)], vec![imm(1), imm(2)])];
        assert_eq!(audit(&long).len(), 1);
    }

    // ---- the Impact/popeq warrant (M23 R3 ruling) ---------------------------

    /// A `public_input` gate for `name`, unguarded.
    fn pi(name: &str) -> Instruction {
        Instruction::PublicInput {
            guard: None,
            val_t: IrType::Native,
            output: id(name),
        }
    }

    /// `popeq` (0x0c) expecting one `bytes<8>` limb wire — the u64 cell
    /// read shape — under the given guard.
    /// An unconditional `push` (op 0x10) of `wire` — an effect the
    /// observability warrant cannot excuse. Added wherever a test means to pin
    /// the absence of a BOUND rather than the absence of reachability: without
    /// an observable consumer the digest is dead and the walk discharges the
    /// read, soundly but for the other reason. NB 0x10 is not a popeq, so
    /// `mark_popeq` bounds nothing from it.
    fn publish(wire: &str) -> Instruction {
        Instruction::Impact {
            guard: imm(1),
            inputs: vec![imm(0x10), imm(1), imm(1), imm(0x20), var(wire)],
        }
    }

    fn popeq_u64(guard: Operand, wire: &str) -> Instruction {
        Instruction::Impact {
            guard,
            // [opcode, atom count, bytes<8> header, the limb]
            inputs: vec![imm(0x0c), imm(1), imm(8), var(wire)],
        }
    }

    #[test]
    fn unconditional_popeq_bounds_the_read() {
        // The class-1 shape: a ledger read's %pi wire straight into a hash.
        let stream = vec![
            pi("pi"),
            popeq_u64(imm(1), "pi"),
            keccak(vec![bytes_atom(8)], vec![var("pi")]),
        ];
        assert_eq!(audit(&stream), vec![]);
        // popeqc (0x0d) carries the same warrant.
        let cached = vec![
            pi("pi"),
            Instruction::Impact {
                guard: imm(1),
                inputs: vec![imm(0x0d), imm(1), imm(8), var("pi")],
            },
            keccak(vec![bytes_atom(8)], vec![var("pi")]),
        ];
        assert_eq!(audit(&cached), vec![]);
        // And the bound is the LIMB's, not "anything": the same read feeding
        // a narrower atom still fires.
        let narrower = vec![
            pi("pi"),
            popeq_u64(imm(1), "pi"),
            keccak(vec![bytes_atom(4)], vec![var("pi")]),
        ];
        assert_eq!(audit(&narrower).len(), 1);
    }

    #[test]
    fn guarded_popeq_stays_free() {
        // A variable guard — even one that is in fact always 1 — marks
        // nothing: when the guard is false the Impact pushes zeros and the
        // wire is genuinely free. This is the ruling's `guarded reads keep
        // firing` half.
        let variable = vec![
            pi("pi"),
            popeq_u64(var("g"), "pi"),
            keccak(vec![bytes_atom(8)], vec![var("pi")]),
            publish("digest"),
        ];
        assert_eq!(audit(&variable).len(), 1);
        // An immediate-ZERO guard is a dead op, not a warrant.
        let dead = vec![
            pi("pi"),
            popeq_u64(imm(0), "pi"),
            keccak(vec![bytes_atom(8)], vec![var("pi")]),
            publish("digest"),
        ];
        assert_eq!(audit(&dead).len(), 1);
    }

    #[test]
    fn popeq_limbs_follow_the_fab_rule() {
        // bytes<32> = stray byte FIRST (8 bits), then the 31-byte limb
        // (248 bits) — and a multi-atom popeq maps positions exactly.
        // Alignment: [bytes<32>, field, bytes<8>] → limbs
        // [hi (1B), lo (31B), f (field-wide), n (8B)].
        let stream = vec![
            pi("hi"),
            pi("lo"),
            pi("f"),
            pi("n"),
            Instruction::Impact {
                guard: imm(1),
                inputs: vec![
                    imm(0x0c),
                    imm(3),
                    imm(32),
                    Operand::Immediate(Fr::from(0u64) - Fr::from(2u64)), // field
                    imm(8),
                    var("hi"),
                    var("lo"),
                    var("f"),
                    var("n"),
                ],
            },
            keccak(
                vec![bytes_atom(32), bytes_atom(8)],
                vec![var("hi"), var("lo"), var("n")],
            ),
            // The field-wide limb got NO bound: absorbing it in a byte atom
            // fires.
            keccak(vec![bytes_atom(8)], vec![var("f")]),
        ];
        assert_eq!(audit(&stream).len(), 1);
    }

    #[test]
    fn malformed_popeq_marks_nothing() {
        let hash = keccak(vec![bytes_atom(8)], vec![var("pi")]);
        // Limb count disagrees with the header: one bytes<8> atom is one
        // limb, two supplied.
        let extra = vec![
            pi("pi"),
            Instruction::Impact {
                guard: imm(1),
                inputs: vec![imm(0x0c), imm(1), imm(8), var("pi"), imm(0)],
            },
            hash.clone(),
        ];
        assert_eq!(audit(&extra).len(), 1);
        // A non-popeq opcode (push, 0x10) embedding the wire is not a read
        // and carries no normalization warrant.
        let push = vec![
            pi("pi"),
            Instruction::Impact {
                guard: imm(1),
                inputs: vec![imm(0x10), imm(1), imm(8), var("pi")],
            },
            hash.clone(),
        ];
        assert_eq!(audit(&push).len(), 1);
        // A wire in the HEADER position is malformed, not a warrant.
        let header_wire = vec![
            pi("pi"),
            Instruction::Impact {
                guard: imm(1),
                inputs: vec![imm(0x0c), imm(1), var("pi"), var("pi")],
            },
            hash,
        ];
        assert_eq!(audit(&header_wire).len(), 1);
    }

    /// A GUARDED `public_input` under a guarded popeq — the compat vault's
    /// `complete_*` shape (M44, notes/taint-lint.org §8) — still fires.
    ///
    /// The point is that the `guard` on `PublicInput` is NOT a second
    /// warrant: in-circuit the arm IGNORES it (`I::PublicInput { guard: _ }`
    /// resolves the wire straight out of the preprocessed witness memory,
    /// zkir-v3 ir_vm.rs:978-1004), so a guarded read is exactly as free as
    /// an unguarded one. Only the Impact binds anything, and under a
    /// variable guard it pushes `select(guard, x, 0)` (ir_vm.rs:869-882) —
    /// zero when the guard is false, which the transcript comparison
    /// accepts for ANY `x`. The "a skipped read yields 0, also in range"
    /// reading is the OFF-circuit `run`/preprocess semantics
    /// (minocrab-sim/src/v3.rs, the `PublicInput` arm's
    /// `default_ir_value(val_t)`), i.e. the witness GENERATOR, not a
    /// constraint a malicious prover is held to.
    #[test]
    fn a_guarded_read_under_a_guarded_popeq_stays_free() {
        let guarded_pi = Instruction::PublicInput {
            guard: Some(var("g")),
            val_t: IrType::Native,
            output: id("pi"),
        };
        let stream = vec![
            guarded_pi.clone(),
            popeq_u64(var("g"), "pi"),
            keccak(vec![bytes_atom(8)], vec![var("pi")]),
            publish("digest"),
        ];
        assert_eq!(audit(&stream).len(), 1);
        // The same read under an UNCONDITIONAL popeq is bounded — so what
        // the test above pins is the guard, not the guarded-ness of the
        // `public_input` gate.
        let unconditional = vec![
            guarded_pi,
            popeq_u64(imm(1), "pi"),
            keccak(vec![bytes_atom(8)], vec![var("pi")]),
            publish("digest"),
        ];
        assert_eq!(audit(&unconditional), vec![]);
    }

    /// `assert(a ≥ b); add(a, neg(b))` — the lowering of
    /// `Uint::<BITS>::sub_with` (minocrab-std/src/v3.rs) — is bounded by `Ma`
    /// under WARRANT N2, which is the first and only place the lint reads an
    /// `Assert` (M23 R3 Class B, notes/taint-lint.org §8).
    ///
    /// This test replaces `a_subtraction_proven_non_negative_still_fires`,
    /// which pinned the opposite and was the recorded shape of the finding.
    /// Its second half is kept: the SUM of the same operands is a different
    /// and correct firing.
    #[test]
    fn a_subtraction_proven_non_negative_is_bounded() {
        let stream = vec![
            Instruction::ConstrainBits { val: var("a"), bits: 128 },
            Instruction::ConstrainBits { val: var("b"), bits: 128 },
            Instruction::LessThan { a: var("a"), b: var("b"), bits: 128, output: id("lt") },
            Instruction::Not { a: var("lt"), output: id("ge") },
            Instruction::Assert { cond: var("ge") },
            Instruction::Neg { a: var("b"), output: id("nb") },
            Instruction::Add { a: var("a"), b: var("nb"), output: id("d") },
            keccak(vec![bytes_atom(16)], vec![var("d")]),
        ];
        assert_eq!(audit(&stream), vec![]);

        // The other encoding of `NOT (a < b)` the builder emits —
        // `cond_select{a: 0, b: 1, bit: lt}` instead of a `Not` instruction —
        // is the same warrant. This is `kernel_tokens::s_send_shielded`'s
        // actual shape.
        let selected = vec![
            Instruction::ConstrainBits { val: var("a"), bits: 128 },
            Instruction::ConstrainBits { val: var("b"), bits: 128 },
            Instruction::LessThan { a: var("a"), b: var("b"), bits: 128, output: id("lt") },
            Instruction::CondSelect {
                bit: var("lt"),
                a: imm(0),
                b: imm(1),
                output: id("ge"),
            },
            Instruction::Assert { cond: var("ge") },
            Instruction::Neg { a: var("b"), output: id("nb") },
            Instruction::Add { a: var("a"), b: var("nb"), output: id("d") },
            keccak(vec![bytes_atom(16)], vec![var("d")]),
        ];
        assert_eq!(audit(&selected), vec![]);

        // The SUM of the same two operands is bounded, by the exact interval
        // arithmetic: 2·(2^128−1) needs 129 bits, so it fires on a 16-byte
        // atom for a different and correct reason.
        let summed = vec![
            Instruction::ConstrainBits { val: var("a"), bits: 64 },
            Instruction::ConstrainBits { val: var("b"), bits: 64 },
            Instruction::Add { a: var("a"), b: var("b"), output: id("s") },
            keccak(vec![bytes_atom(16)], vec![var("s")]),
        ];
        assert_eq!(audit(&summed), vec![]);
    }

    /// WARRANT N1 — `add(C, neg(b))` with `C` an immediate: bounded by `C`
    /// when `Mb ≤ C`, and NOT otherwise. `erc20_vault_pending`'s
    /// `change_nonce` is `255 − mintNonce.hi` with `constrain_bits 8`, where
    /// `Mb = C = 255` exactly — so the boundary is the case that matters.
    #[test]
    fn a_constant_minus_a_range_constrained_wire_is_bounded() {
        let subtraction = |bits: u32| {
            vec![
                Instruction::ConstrainBits { val: var("b"), bits },
                Instruction::Neg { a: var("b"), output: id("nb") },
                Instruction::Add { a: imm(255), b: var("nb"), output: id("d") },
                keccak(vec![bytes_atom(1)], vec![var("d")]),
            ]
        };
        // Mb = 255 = C: the difference is in [0, 255], one byte.
        assert_eq!(audit(&subtraction(8)), vec![]);
        // Mb = 511 > C: `255 − b` wraps for b > 255, and the result is then
        // field-wide. Marking it would be the over-marking the module docs
        // warn against.
        let findings = audit(&subtraction(9));
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(findings[0].detail.contains("not provably bounded"));
        // An UNBOUNDED subtrahend is the same refusal.
        let free = vec![
            Instruction::Neg { a: var("b"), output: id("nb") },
            Instruction::Add { a: imm(255), b: var("nb"), output: id("d") },
            keccak(vec![bytes_atom(1)], vec![var("d")]),
        ];
        assert_eq!(audit(&free).len(), 1);
    }

    /// WARRANT N3 — a GUARDED `assert(a ≥ b)` bounds the difference only when
    /// both operands are `cond_select{a: x, b: 0, bit: g}` on the SAME `g`,
    /// which is `erc20_vault::complete_swap`'s shape. Three ways it must
    /// refuse: a different guard on one operand, an operand not zeroed at all,
    /// and an unbounded minuend (`manager::execute`, which stays a finding).
    #[test]
    fn a_guarded_subtraction_needs_both_operands_zeroed_under_one_guard() {
        // `g ? x : 0` and `g ? y : 0`, compared and subtracted under `g`.
        let guarded = |a_bit: &str, b_bit: &str| {
            vec![
                Instruction::ConstrainBits { val: var("x"), bits: 64 },
                Instruction::ConstrainBits { val: var("y"), bits: 64 },
                Instruction::CondSelect {
                    bit: var(a_bit),
                    a: var("x"),
                    b: imm(0),
                    output: id("sa"),
                },
                Instruction::CondSelect {
                    bit: var(b_bit),
                    a: var("y"),
                    b: imm(0),
                    output: id("sb"),
                },
                Instruction::ConstrainBits { val: var("sa"), bits: 64 },
                Instruction::ConstrainBits { val: var("sb"), bits: 64 },
                Instruction::LessThan { a: var("sa"), b: var("sb"), bits: 64, output: id("lt") },
                Instruction::Not { a: var("lt"), output: id("ge") },
                // `g ? (sa ≥ sb) : true` — the assert inside `when`.
                Instruction::CondSelect {
                    bit: var("g"),
                    a: var("ge"),
                    b: imm(1),
                    output: id("gge"),
                },
                Instruction::Assert { cond: var("gge") },
                Instruction::Neg { a: var("sb"), output: id("nb") },
                Instruction::Add { a: var("sa"), b: var("nb"), output: id("d") },
                keccak(vec![bytes_atom(16)], vec![var("d")]),
            ]
        };
        // Both operands zeroed under the assert's own guard: bounded.
        assert_eq!(audit(&guarded("g", "g")), vec![]);
        // One operand zeroed under a DIFFERENT bit: with `g = 0` the assert
        // says nothing and `sb` is not forced to 0, so the difference may wrap.
        assert_eq!(audit(&guarded("g", "h")).len(), 1);

        // An unbounded minuend has no bound to propagate — `manager::execute`,
        // whose minuend is itself an unbounded guarded read. Stays a finding.
        let unbounded_minuend = vec![
            Instruction::ConstrainBits { val: var("b"), bits: 64 },
            Instruction::LessThan { a: var("a"), b: var("b"), bits: 64, output: id("lt") },
            Instruction::Not { a: var("lt"), output: id("ge") },
            Instruction::Assert { cond: var("ge") },
            Instruction::Neg { a: var("b"), output: id("nb") },
            Instruction::Add { a: var("a"), b: var("nb"), output: id("d") },
            keccak(vec![bytes_atom(16)], vec![var("d")]),
        ];
        assert_eq!(audit(&unbounded_minuend).len(), 1);
    }

    /// The warrants read the asserted PAIR, not merely the presence of an
    /// assert: a `less_than` at a width narrower than its operands is not the
    /// comparison the rule reads it as, and an assert about OTHER wires
    /// bounds nothing.
    #[test]
    fn the_subtraction_warrants_refuse_a_mismatched_assert() {
        // `a ≥ b` asserted, but the comparison is at 32 bits while both
        // operands are constrained to 64 — `less_than` is not a comparison of
        // the full values, so N2 must not fire.
        let narrow = vec![
            Instruction::ConstrainBits { val: var("a"), bits: 64 },
            Instruction::ConstrainBits { val: var("b"), bits: 64 },
            Instruction::LessThan { a: var("a"), b: var("b"), bits: 32, output: id("lt") },
            Instruction::Not { a: var("lt"), output: id("ge") },
            Instruction::Assert { cond: var("ge") },
            Instruction::Neg { a: var("b"), output: id("nb") },
            Instruction::Add { a: var("a"), b: var("nb"), output: id("d") },
            keccak(vec![bytes_atom(8)], vec![var("d")]),
        ];
        assert_eq!(audit(&narrow).len(), 1);

        // The assert is about a DIFFERENT pair than the subtraction.
        let other_pair = vec![
            Instruction::ConstrainBits { val: var("a"), bits: 64 },
            Instruction::ConstrainBits { val: var("b"), bits: 64 },
            Instruction::ConstrainBits { val: var("c"), bits: 64 },
            Instruction::LessThan { a: var("a"), b: var("c"), bits: 64, output: id("lt") },
            Instruction::Not { a: var("lt"), output: id("ge") },
            Instruction::Assert { cond: var("ge") },
            Instruction::Neg { a: var("b"), output: id("nb") },
            Instruction::Add { a: var("a"), b: var("nb"), output: id("d") },
            keccak(vec![bytes_atom(8)], vec![var("d")]),
        ];
        assert_eq!(audit(&other_pair).len(), 1);

        // The pair asserted in the WRONG ORDER (`b ≥ a`) does not bound
        // `a − b`.
        let reversed = vec![
            Instruction::ConstrainBits { val: var("a"), bits: 64 },
            Instruction::ConstrainBits { val: var("b"), bits: 64 },
            Instruction::LessThan { a: var("b"), b: var("a"), bits: 64, output: id("lt") },
            Instruction::Not { a: var("lt"), output: id("ge") },
            Instruction::Assert { cond: var("ge") },
            Instruction::Neg { a: var("b"), output: id("nb") },
            Instruction::Add { a: var("a"), b: var("nb"), output: id("d") },
            keccak(vec![bytes_atom(8)], vec![var("d")]),
        ];
        assert_eq!(audit(&reversed).len(), 1);
    }

    /// OPTION 4, the observability warrant (M23 R3 Class A,
    /// notes/taint-lint.org §8). A guarded ledger read has no bound and none
    /// is invented; it is discharged exactly when every effect a forged value
    /// could reach is ALREADY inert whenever the read's own guard is false.
    ///
    /// The clean case is `erc20_vault`'s five `complete_*` circuits: the
    /// contract address is read under the arm's guard, absorbed into the
    /// tokenType digest and then the coin commitment, and every Impact that
    /// publishes either is guarded by that same bit or one nested inside it.
    #[test]
    fn a_guarded_read_is_discharged_when_its_digest_is_inert_under_its_guard() {
        // read under `g`, popeq under `g`, digest pushed under `publisher`.
        let pushed_under = |publisher: Operand| {
            vec![
                Instruction::PublicInput {
                    guard: Some(var("g")),
                    val_t: IrType::Native,
                    output: id("pi"),
                },
                popeq_u64(var("g"), "pi"),
                keccak(vec![bytes_atom(8)], vec![var("pi")]),
                Instruction::Impact {
                    guard: publisher,
                    inputs: vec![imm(0x10), imm(1), imm(1), imm(0x20), var("digest")],
                },
            ]
        };
        // The same guard: inert together. Discharged.
        assert_eq!(audit(&pushed_under(var("g"))), vec![]);
        // UNCONDITIONAL: it publishes the forged digest whatever `g` does.
        assert_eq!(audit(&pushed_under(imm(1))).len(), 1);
        // An UNRELATED wire: nothing ties it to `g`, so `g = 0` does not make
        // it inert. This is the "single unguarded consumer" §8 names.
        assert_eq!(audit(&pushed_under(var("h"))).len(), 1);

        // A guard NESTED inside `g` — `cond_select{a: _, b: 0, bit: g}`, which
        // is zero whenever `g` is. `erc20_vault::complete_deposit` pushes its
        // coin commitment under exactly this. Discharged.
        let mut nested = pushed_under(var("inner"));
        nested.insert(
            3,
            Instruction::CondSelect {
                bit: var("g"),
                a: var("whatever"),
                b: imm(0),
                output: id("inner"),
            },
        );
        assert_eq!(audit(&nested), vec![]);
        // The same shape with the ZERO branch replaced by a nonzero one is NOT
        // dominated: it can be nonzero while `g` is zero.
        let mut not_nested = pushed_under(var("inner"));
        not_nested.insert(
            3,
            Instruction::CondSelect {
                bit: var("g"),
                a: var("whatever"),
                b: imm(1),
                output: id("inner"),
            },
        );
        assert_eq!(audit(&not_nested).len(), 1);
    }

    /// The observability warrant refuses every consumer it cannot account for.
    /// A CONSTRAINT on the digest makes a forged value matter to
    /// satisfiability, which may be safe but is a different argument; leaving
    /// the circuit named is an effect; and steering another read's guard moves
    /// the transcript walk. All three keep the finding.
    #[test]
    fn the_observability_warrant_refuses_a_constrained_or_returned_digest() {
        let with = |tail: Instruction| {
            vec![
                Instruction::PublicInput {
                    guard: Some(var("g")),
                    val_t: IrType::Native,
                    output: id("pi"),
                },
                popeq_u64(var("g"), "pi"),
                keccak(vec![bytes_atom(8)], vec![var("pi")]),
                Instruction::Impact {
                    guard: var("g"),
                    inputs: vec![imm(0x10), imm(1), imm(1), imm(0x20), var("digest")],
                },
                tail,
            ]
        };
        // Baseline: without the tail this is the discharged case.
        assert_eq!(audit(&with(Instruction::Copy { val: var("pi"), output: id("unused") })), vec![]);

        for tail in [
            Instruction::Assert { cond: var("digest") },
            Instruction::ConstrainEq { a: var("digest"), b: imm(0) },
            Instruction::ConstrainBits { val: var("digest"), bits: 64 },
            Instruction::ConstrainToBoolean { val: var("digest") },
            Instruction::Output { vals: vec![var("digest")] },
            Instruction::PublicInput {
                guard: Some(var("digest")),
                val_t: IrType::Native,
                output: id("steered"),
            },
        ] {
            let findings = audit(&with(tail.clone()));
            assert_eq!(findings.len(), 1, "{tail:?} should keep the finding: {findings:?}");
        }
    }
}

// ============================================================================
// Kani harnesses (M23 R4) — compiled ONLY under `cargo kani -p minocrab-ir`
// ============================================================================
//
// The lint's soundness rests on the exact interval arithmetic: a Max that
// under-reports a maximum would prove a bound that does not hold — the false
// negative the whole instrument exists to prevent. These proofs pin the
// arithmetic against independent oracles (`u128`, bit arithmetic) at stated
// widths, and the order relation at full width. Bounds per proof; runtimes
// in notes/formal-verification-options.org §"As built — M23 R4".

#[cfg(kani)]
mod kani_proofs {
    use super::Max;

    fn from_u128(v: u128) -> Max {
        Max([v as u64, (v >> 64) as u64, 0, 0])
    }

    fn to_u128(m: &Max) -> Option<u128> {
        (m.0[2] == 0 && m.0[3] == 0).then(|| m.0[0] as u128 | (m.0[1] as u128) << 64)
    }

    /// `checked_add` agrees with `u128` addition wherever both are defined.
    /// BOUND: both operands ≤ 2^127 − 1, so the oracle cannot itself
    /// overflow; the 256-bit path has no carry at this width, which is the
    /// carry-chain's base case — `add_carries_across_limbs` covers the rest.
    #[kani::proof]
    fn add_matches_u128() {
        let a: u128 = kani::any();
        let b: u128 = kani::any();
        kani::assume(a < 1 << 127 && b < 1 << 127);
        let sum = from_u128(a).checked_add(from_u128(b)).expect("cannot overflow 256 bits");
        assert_eq!(to_u128(&sum), Some(a + b));
    }

    /// The carry propagates across every limb boundary: adding 1 to
    /// `2^n − 1` gives `2^n`, for every n < 256.
    #[kani::proof]
    fn add_carries_across_limbs() {
        let n: u32 = kani::any();
        kani::assume(n < 256);
        let sum = Max::all_ones(n).checked_add(Max::all_ones(1).min(Max::pow2(0)))
            // all_ones(1) is 1 and pow2(0) is 1; min keeps the proof honest
            // about both constructors agreeing on the value 1.
            .expect("2^n fits for n < 256");
        assert_eq!(sum, Max::pow2(n), "all_ones({n}) + 1 != pow2({n})");
    }

    /// 256-bit overflow is reported, never wrapped.
    #[kani::proof]
    fn add_overflow_is_none() {
        let a: u64 = kani::any();
        kani::assume(a > 0);
        assert!(Max::all_ones(256).checked_add(Max([a, 0, 0, 0])).is_none());
    }

    /// `checked_mul` agrees with `u128` multiplication. BOUND: 16-bit
    /// operands. Neither 64x64 nor 32x32 closed in 900s — the 4x4 limb
    /// loop embeds sixteen 64-bit partial-product multipliers in the SAT
    /// formula regardless of assumed operand width, and wide
    /// multiplication is the canonical SAT-hard circuit. 16-bit operands
    /// still drive the identical limb/carry code path against an exact
    /// oracle; the cross-limb carry at full width is
    /// `mul_carries_across_limbs`.
    #[kani::proof]
    fn mul_matches_u128() {
        let a: u64 = kani::any();
        let b: u64 = kani::any();
        kani::assume(a < 1 << 16 && b < 1 << 16);
        let product = Max([a, 0, 0, 0]).checked_mul(Max([b, 0, 0, 0])).expect("fits");
        assert_eq!(to_u128(&product), Some(a as u128 * b as u128));
    }

    /// The multiplier's cross-limb carry, at the boundary a 32-bit oracle
    /// cannot see: (2^64 - 1)^2 spans all four limbs and has an exact
    /// closed form.
    #[kani::proof]
    fn mul_carries_across_limbs() {
        let ones = Max([u64::MAX, 0, 0, 0]);
        let square = ones.checked_mul(ones).expect("fits 128 bits");
        // (2^64 - 1)^2 = 2^128 - 2^65 + 1
        assert_eq!(to_u128(&square), Some(u128::MAX - (1 << 65) + 2));
    }

    /// `shr` agrees with `u128` shifting for a SYMBOLIC 64-bit value at
    /// EVERY concrete shift 0..=64. A fully symbolic shift amount did not
    /// close in 900s at either 64- or 128-bit width (a symbolic barrel
    /// shifter across four limbs); sweeping the shift concretely keeps the
    /// value symbolic where the lint's soundness lives — `div = val >> bits`
    /// with `bits` a CONCRETE instruction field, so a concrete-shift sweep
    /// is in fact the exact shape the lint evaluates. Limb-boundary
    /// crossings of wider values: `shr_limb_boundaries` below.
    #[kani::proof]
    #[kani::unwind(70)] // 65 sweep steps; memcmp inside assert_eq is 32
    fn shr_matches_u128() {
        let v: u64 = kani::any();
        let mut s = 0u32;
        while s <= 64 {
            let shifted = Max([v, 0, 0, 0]).shr(s);
            let expect = if s >= 64 { 0 } else { (v >> s) as u128 };
            assert_eq!(to_u128(&shifted), Some(expect));
            s += 1;
        }
    }

    /// Every limb boundary of a full-width value, at concrete shifts: the
    /// all-ones 256-bit value shifted by each multiple of 32 has the
    /// closed form all_ones(256 - s).
    #[kani::proof]
    #[kani::unwind(40)] // the 8-step ladder, plus memcmp's per-byte loop
                        // inside assert_eq! over the 32-byte limb array
    fn shr_limb_boundaries() {
        let mut s = 0u32;
        while s < 256 {
            assert_eq!(Max::all_ones(256).shr(s), Max::all_ones(256 - s));
            s += 32;
        }
    }

    /// `bits()` is exactly the position of the highest set bit — the fact
    /// `m.bits() <= 8*w` relies on to mean `m ≤ 2^8w − 1`. BOUND: 128-bit
    /// values (limb-symmetric; the upper limbs run the same code path).
    #[kani::proof]
    fn bits_matches_leading_zeros() {
        let v: u128 = kani::any();
        assert_eq!(from_u128(v).bits(), 128 - v.leading_zeros());
    }

    /// `bits(all_ones(n)) == n` for every n ≤ 256 — the two sides of the
    /// verdict `m.bits() <= required` use the same ruler.
    #[kani::proof]
    fn all_ones_bits_roundtrip() {
        let n: u32 = kani::any();
        kani::assume(n <= 256);
        assert_eq!(Max::all_ones(n).bits(), n);
    }

    /// `le` is a total order and `min`/`max` select within it — at FULL
    /// 256-bit width (comparisons are cheap for the solver).
    #[kani::proof]
    fn le_total_order_and_min_max() {
        let a = Max([kani::any(), kani::any(), kani::any(), kani::any()]);
        let b = Max([kani::any(), kani::any(), kani::any(), kani::any()]);
        assert!(a.le(&a));
        assert!(a.le(&b) || b.le(&a));
        if a.le(&b) && b.le(&a) {
            assert_eq!(a, b);
        }
        let lo = a.min(b);
        assert!(lo.le(&a) && lo.le(&b) && (lo == a || lo == b));
        let hi = a.max(b);
        assert!(a.le(&hi) && b.le(&hi) && (hi == a || hi == b));
    }
}

//! v3 simulator correctness anchors.
//!
//! Every circuit here is built with the typed `Builder3`, then run through
//! BOTH our `minocrab_sim::v3::simulate` and upstream's `IrSource::check`
//! (the `Zkir` trait; literally `preprocess(..)?.pi_skips`, see
//! zkir-v3/src/ir.rs:75-81) on the same `ProofPreimage`. Acceptance must
//! agree, and our `pi_skips` must equal `check`'s — the simulator is never
//! trusted alone. Value-level spot checks go directly against Midnight's
//! crypto primitives.

use std::borrow::Cow;

use midnight_base_crypto::fab::{Alignment, AlignmentAtom, AlignmentSegment};
use midnight_transient_crypto::curve::EmbeddedGroupAffine;
use midnight_transient_crypto::hash::{transient_commit, transient_hash};
use midnight_transient_crypto::proofs::{KeyLocation, ProofPreimage, Zkir};
use minocrab_ir::v3::{Builder3, IrType};
use minocrab_sim::v3::{simulate, Run3, Sim3Error};
use minocrab_zkir::v3::{IrSource, IrValue};
use minocrab_zkir::Fr;
use sha3::Digest;

fn preimage(
    inputs: &[Fr],
    private_transcript: &[Fr],
    public_transcript_inputs: &[Fr],
    public_transcript_outputs: &[Fr],
) -> ProofPreimage {
    ProofPreimage {
        inputs: inputs.to_vec(),
        private_transcript: private_transcript.to_vec(),
        public_transcript_inputs: public_transcript_inputs.to_vec(),
        public_transcript_outputs: public_transcript_outputs.to_vec(),
        binding_input: 0.into(),
        communications_commitment: None,
        key_location: KeyLocation(Cow::Borrowed("minocrab-sim-v3")),
    }
}

/// Run our simulator and upstream `check` on the same preimage; assert they
/// agree on acceptance and on `pi_skips`; return our result.
fn cross_check(ir: &IrSource, pi: &ProofPreimage) -> Result<Run3, Sim3Error> {
    let ours = simulate(ir, pi);
    let theirs = ir.check(pi);
    match (&ours, &theirs) {
        (Ok(run), Ok(skips)) => assert_eq!(&run.pi_skips, skips, "pi_skips disagree"),
        (Err(_), Err(_)) => {}
        (ours, theirs) => panic!(
            "simulator and reference VM disagree:\n  ours: {ours:?}\n  theirs: {theirs:?}"
        ),
    }
    ours
}

fn accept(ir: &IrSource, pi: &ProofPreimage) -> Run3 {
    cross_check(ir, pi).expect("both should accept")
}

fn reject(ir: &IrSource, pi: &ProofPreimage) {
    assert!(cross_check(ir, pi).is_err(), "both should reject");
}

fn native(x: u64) -> IrValue {
    IrValue::Native(Fr::from(x))
}

#[test]
fn native_ops_agree() {
    let mut b = Builder3::new();
    let x = b.input("x", IrType::Native);
    let y = b.input("y", IrType::Native);
    let sum = b.add(x, y); // 8
    let prod = b.mul(sum, 3u64); // immediate operand: 24
    let _neg = b.neg(prod);
    let _inv = b.inv(sum);
    let imm = b.imm(24u64); // Copy of an immediate
    b.constrain_eq(imm, prod);
    let lt = b.less_than(x, y, 8); // 3 < 5 -> 1
    b.assert(lt);
    b.constrain_to_boolean(lt);
    b.constrain_bits(x, 8);
    let sel = b.cond_select(lt, sum, prod); // -> sum
    b.constrain_eq(sel, sum);
    let eq = b.test_eq(x, y); // 0
    let ne = b.not(eq); // 1
    b.assert(ne);
    b.output(&[sum.into(), sel.into()]);
    let ir = b.finish(false);

    let run = accept(&ir, &preimage(&[3.into(), 5.into()], &[], &[], &[]));
    assert_eq!(run.outputs, vec![native(8), native(8)]);
    assert_eq!(run.pis, vec![Fr::from(0u64)]); // just the binding input
    assert_eq!(run.pi_skips, vec![]);
    assert_eq!(run.consumed_private, 0);
    assert_eq!(run.consumed_public, 0);
    assert_eq!(run.op_counts["add"], 1);
    assert_eq!(run.op_counts["assert"], 2);

    // 5 < 3 fails the assert: both engines must reject.
    reject(&ir, &preimage(&[5.into(), 3.into()], &[], &[], &[]));
    // Wrong argument count: both reject.
    reject(&ir, &preimage(&[3.into()], &[], &[], &[]));
}

#[test]
fn div_mod_reconstitute_agree() {
    let mut b = Builder3::new();
    let x = b.input("x", IrType::Native);
    let (div, modulus) = b.div_mod_power_of_two(x, 4);
    let back = b.reconstitute_field(div, modulus, 4);
    b.constrain_eq(back, x);
    b.output(&[div.into(), modulus.into()]);
    let ir = b.finish(false);

    let run = accept(&ir, &preimage(&[171.into()], &[], &[], &[])); // 0xAB
    assert_eq!(run.outputs, vec![native(10), native(11)]);
}

#[test]
fn hashes_agree_and_match_primitives() {
    let two_fields = Alignment(vec![
        AlignmentSegment::Atom(AlignmentAtom::Field),
        AlignmentSegment::Atom(AlignmentAtom::Field),
    ]);
    let eight_bytes = Alignment(vec![AlignmentSegment::Atom(AlignmentAtom::Bytes {
        length: 8,
    })]);

    let mut b = Builder3::new();
    let x = b.input("x", IrType::Native);
    let y = b.input("y", IrType::Native);
    let th = b.transient_hash(&[x.into(), y.into()]);
    let ph = b.persistent_hash(two_fields, &[x.into(), y.into()]);
    let kk = b.keccak256(eight_bytes, &[x.into()]);
    b.output(&[th.into(), ph.into(), kk.into()]);
    let ir = b.finish(false);

    let (a, c) = (Fr::from(0xdeadbeefu64), Fr::from(77u64));
    let run = accept(&ir, &preimage(&[a, c], &[], &[], &[]));

    // TransientHash == transient_crypto's own Poseidon-family hash.
    assert_eq!(run.outputs[0], IrValue::Native(transient_hash(&[a, c])));

    // PersistentHash == SHA-256 over the FAB bytes: each Field atom is the
    // element's 32 canonical little-endian bytes.
    let mut fab = a.as_le_bytes();
    fab.extend(c.as_le_bytes());
    let expected: [u8; 32] = sha2::Sha256::digest(&fab).into();
    assert_eq!(run.outputs[1], IrValue::Bytes32(expected));

    // Keccak256 == sha3 over the FAB bytes: a Bytes<8> atom is the low 8
    // little-endian bytes of the element.
    let expected: [u8; 32] = sha3::Keccak256::digest(&a.as_le_bytes()[..8]).into();
    assert_eq!(run.outputs[2], IrValue::Bytes32(expected));
}

#[test]
fn jubjub_agree_and_match_curve() {
    let mut b = Builder3::new();
    let n = b.input("n", IrType::Native);
    let s = b.jubjub_scalar_from_native(n);
    let g = b.ec_mul_generator(s); // G * n
    let (gx, gy) = b.into_coordinates(g);
    let p = b.from_coordinates(IrType::JubjubPoint, gx, gy);
    let q = b.ec_mul(p, s); // G * n^2
    let sum = b.add(g, q); // G * (n + n^2)
    let (qx, qy) = b.into_coordinates(q);
    let (sx, sy) = b.into_coordinates(sum);
    let h = b.hash_to_curve(&[n.into()]);
    let (hx, hy) = b.into_coordinates(h);
    b.output(&[
        gx.into(),
        gy.into(),
        qx.into(),
        qy.into(),
        sx.into(),
        sy.into(),
        hx.into(),
        hy.into(),
    ]);
    let ir = b.finish(false);

    let n = 5u64;
    let run = accept(&ir, &preimage(&[n.into()], &[], &[], &[]));

    // Cross-check coordinates against transient-crypto's embedded curve.
    let coords = |p: EmbeddedGroupAffine| {
        (
            IrValue::Native(p.x().expect("affine x")),
            IrValue::Native(p.y().expect("affine y")),
        )
    };
    let g = EmbeddedGroupAffine::generator() * Fr::from(n);
    let q = EmbeddedGroupAffine::generator() * Fr::from(n * n);
    let sum = EmbeddedGroupAffine::generator() * Fr::from(n + n * n);
    let h = midnight_transient_crypto::hash::hash_to_curve(&[Fr::from(n)]);
    assert_eq!((run.outputs[0].clone(), run.outputs[1].clone()), coords(g));
    assert_eq!((run.outputs[2].clone(), run.outputs[3].clone()), coords(q));
    assert_eq!((run.outputs[4].clone(), run.outputs[5].clone()), coords(sum));
    assert_eq!((run.outputs[6].clone(), run.outputs[7].clone()), coords(h));
}

#[test]
fn ec_mul_generator_of_one_is_the_generator() {
    let mut b = Builder3::new();
    let n = b.input("n", IrType::Native);
    let s = b.jubjub_scalar_from_native(n);
    let g = b.ec_mul_generator(s);
    let (x, y) = b.into_coordinates(g);
    b.output(&[x.into(), y.into()]);
    let ir = b.finish(false);

    let run = accept(&ir, &preimage(&[1.into()], &[], &[], &[]));
    let generator = EmbeddedGroupAffine::generator();
    assert_eq!(
        run.outputs,
        vec![
            IrValue::Native(generator.x().expect("generator x")),
            IrValue::Native(generator.y().expect("generator y")),
        ]
    );
}

#[test]
fn bytes32_ops_agree_and_match_encoding() {
    let mut b = Builder3::new();
    let x = b.input("x", IrType::Native);
    let bytes = b.into_bytes32(x);
    let rev = b.reverse_bytes(bytes);
    let (low, high) = b.bytes32_into_low_high(bytes);
    let recomposed = b.bytes32_from_low_high(low, high);
    let back = b.from_bytes32(recomposed, IrType::Native);
    b.constrain_eq(back, x);
    // Encode of Bytes<32> is (low 31 bytes, high byte) — the same split.
    let enc = b.encode(bytes);
    b.constrain_eq(enc[0], low);
    b.constrain_eq(enc[1], high);
    b.output(&[bytes.into(), rev.into()]);
    let ir = b.finish(false);

    let x = Fr::from(0x0123_4567_89ab_cdefu64);
    let run = accept(&ir, &preimage(&[x], &[], &[], &[]));

    // IntoBytes32 == the canonical little-endian form.
    let le: [u8; 32] = x.as_le_bytes().try_into().expect("32 bytes");
    assert_eq!(run.outputs[0], IrValue::Bytes32(le));
    let mut reversed = le;
    reversed.reverse();
    assert_eq!(run.outputs[1], IrValue::Bytes32(reversed));
}

#[test]
fn transcripts_and_impact_agree() {
    let mut b = Builder3::new();
    let on = b.input("on", IrType::Native); // 1
    let off = b.input("off", IrType::Native); // 0
    let w = b.private_input(IrType::Native, None);
    let wg = b.private_input(IrType::Native, Some(off.into())); // guarded off
    let p = b.public_input(IrType::Native, None);
    let pg = b.public_input(IrType::Native, Some(off.into())); // guarded off
    b.constrain_eq(wg, 0u64); // guarded-off reads yield the type default
    b.constrain_eq(pg, 0u64);
    b.impact(on, &[w.into(), p.into()]); // taken
    b.impact(off, &[w.into()]); // guard off: zeros + skip entry
    b.output(&[w.into()]);
    let ir = b.finish(false);

    let args = [Fr::from(1u64), Fr::from(0u64)];
    let witness = [Fr::from(7u64)];
    let pub_outputs = [Fr::from(9u64)];
    // Only the *taken* impact appears in the declared public transcript.
    let mut pi = preimage(&args, &witness, &[7.into(), 9.into()], &pub_outputs);
    pi.binding_input = Fr::from(42u64);

    let run = accept(&ir, &pi);
    assert_eq!(run.binding_input, Fr::from(42u64));
    // pis: binding input, taken impact values, then zeros for the skipped one.
    assert_eq!(
        run.pis,
        vec![Fr::from(42u64), Fr::from(7u64), Fr::from(9u64), Fr::from(0u64)]
    );
    assert_eq!(run.pi_skips, vec![None, Some(1)]);
    assert_eq!(run.consumed_private, 1);
    assert_eq!(run.consumed_public, 1);
    assert_eq!(run.outputs, vec![native(7)]);

    // Tampered public transcript: both reject.
    let mut bad = pi.clone();
    bad.public_transcript_inputs = vec![7.into(), 8.into()];
    reject(&ir, &bad);

    // Declaring the skipped impact's zeros leaves the transcript
    // over-provisioned: both reject.
    let mut bad = pi.clone();
    bad.public_transcript_inputs = vec![7.into(), 9.into(), 0.into()];
    reject(&ir, &bad);

    // Leftover witness data: both reject.
    let mut bad = pi.clone();
    bad.private_transcript = vec![7.into(), 7.into()];
    reject(&ir, &bad);
}

#[test]
fn public_input_exhaustion_rejects() {
    let mut b = Builder3::new();
    let p = b.public_input(IrType::Native, None);
    b.output(&[p.into()]);
    let ir = b.finish(false);

    // Empty public transcript outputs: we return an error…
    let pi = preimage(&[], &[], &[], &[]);
    assert!(simulate(&ir, &pi).is_err());

    // …while upstream panics on the unchecked transcript slice
    // (ir_vm.rs:359). Either way it must not accept.
    let upstream = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| ir.check(&pi)));
    assert!(
        !matches!(upstream, Ok(Ok(_))),
        "upstream accepted an exhausted public transcript"
    );
}

#[test]
fn communications_commitment_agree() {
    let mut b = Builder3::new();
    let a = b.input("a", IrType::Native);
    let sum = b.add(a, 1u64);
    b.output(&[sum.into()]);
    let ir = b.finish(true); // with communications commitment

    let (a, sum) = (Fr::from(6u64), Fr::from(7u64));
    let rand = Fr::from(1234u64);
    // ir_vm.rs:662-681: commit over raw preimage inputs ++ encoded outputs.
    let commit = transient_commit(&[a, sum][..], rand);

    let mut pi = preimage(&[a], &[], &[], &[]);
    pi.communications_commitment = Some((commit, rand));
    let run = accept(&ir, &pi);
    assert_eq!(run.comm_comm, Some((commit, rand)));
    // By convention the commitment is the second public input.
    assert_eq!(run.pis, vec![Fr::from(0u64), commit]);

    // Wrong commitment: both reject.
    let mut bad = pi.clone();
    bad.communications_commitment = Some((commit + Fr::from(1u64), rand));
    reject(&ir, &bad);

    // Missing commitment: both reject.
    let mut bad = pi.clone();
    bad.communications_commitment = None;
    reject(&ir, &bad);
}

/// The whole v3 stack: the typed L2 frontend (`minocrab::v3::Circuit3`)
/// lowers through Builder3, simulates, and agrees with upstream `check`.
#[test]
fn circuit3_frontend_end_to_end() {
    use minocrab::v3::{Circuit3, FieldT};

    let mut c = Circuit3::new();
    let x = c.arg::<FieldT>("x");
    let h = c.transient_hash(&[x]);
    // Field -> Bytes32 low/high round-trip with byte reversal both ways.
    let (_q, lo) = c.div_mod_power_of_two(h, 248);
    let zero_hi = c.constant(0u64);
    let b32 = c.bytes32_from_low_high(lo, zero_hi.private());
    let rev = c.reverse_bytes(b32);
    let back = c.reverse_bytes(rev);
    let (lo2, _hi2) = c.bytes32_into_low_high(back);
    c.assert_eq(lo2, lo);
    let h_pub = c.disclose(h, "hash of x");
    c.output(h_pub, "digest");
    let compiled = c.finish(false);

    let x_val = Fr::from(42u64);
    let expected = transient_hash(&[x_val]);
    let run = accept(&compiled.ir, &preimage(&[x_val], &[], &[], &[]));
    assert_eq!(run.outputs, vec![IrValue::Native(expected)]);
    assert_eq!(compiled.disclosures.len(), 2);
}

/// A failed assert is reported with ITS message and a profile charges each
/// region its own instructions, after `finish` has deleted instructions in
/// front of both. `c.assert_with(c.constant(1), ..)` is a copy and an
/// `assert 1`, both removed by the passes; before the build-time indices
/// were moved onto the finished stream, a failing `z` check reported "x
/// must hold" and the `z check` region held nothing (notes/ir-passes.org
/// §13).
#[test]
fn a_failed_assert_and_a_region_survive_the_dropping_passes() {
    use minocrab::v3::{Circuit3, FieldT};
    use minocrab_sim::v3::{profile, simulate_compiled};

    let mut c = Circuit3::new();
    let x = c.arg::<FieldT>("x");
    let y = c.arg::<FieldT>("y");
    let z = c.arg::<FieldT>("z");
    let one = c.constant(1u64);
    c.assert_with(one, Some("cannot fail"));
    c.assert_with(x, Some("x must hold"));
    c.assert_with(y, Some("y must hold"));
    c.region("z check", |c| c.assert_with(z, Some("z must hold")));
    let compiled = c.finish(false);

    let one_ = Fr::from(1u64);
    let zero = Fr::from(0u64);
    accept(&compiled.ir, &preimage(&[one_, one_, one_], &[], &[], &[]));
    reject(&compiled.ir, &preimage(&[one_, one_, zero], &[], &[], &[]));
    match simulate_compiled(&compiled, &preimage(&[one_, one_, zero], &[], &[], &[])) {
        Err(Sim3Error::Failed { op: "assert", message, .. }) => {
            assert_eq!(message, "failed assertion: z must hold")
        }
        other => panic!("expected the z assert to fail, got {other:?}"),
    }

    let z_check = profile(&compiled)
        .regions
        .into_iter()
        .find(|r| r.label == "z check")
        .expect("the region is profiled");
    assert_eq!(z_check.instructions, 1);
    assert_eq!(z_check.op_counts.get("assert"), Some(&1));
}

/// The same under the opt profile, with all three deleting passes firing and
/// a guarded assert: a redundant 64-bit constraint after an 8-bit one is
/// deduped out of its own region (which is left empty), a constant-true
/// assert is folded and dropped, and both the guarded check and the plain
/// one after it still fail with their own messages and are profiled in
/// their own regions.
#[test]
fn messages_and_regions_survive_the_dedup_and_a_guarded_assert() {
    use minocrab::v3::{Circuit3, FieldT};
    use minocrab_sim::v3::{profile, simulate_compiled};

    let mut c = Circuit3::new();
    c.dedup_range_constraints(true);
    let x = c.arg::<FieldT>("x");
    let g = c.arg::<FieldT>("g");
    let z = c.arg::<FieldT>("z");
    let w = c.arg::<FieldT>("w");
    c.assert_bits(x, 8);
    c.region("redundant", |c| {
        c.assert_bits(x, 64);
    });
    let one = c.constant(1u64);
    c.assert_with(one, Some("cannot fail"));
    c.region("guarded", |c| {
        c.when_private(g, |c| c.assert_with(z, Some("z must hold under g")));
    });
    c.region("w check", |c| c.assert_with(w, Some("w must hold")));
    let compiled = c.finish(false);

    let (one_, zero) = (Fr::from(1u64), Fr::from(0u64));
    accept(&compiled.ir, &preimage(&[one_, one_, one_, one_], &[], &[], &[]));
    accept(&compiled.ir, &preimage(&[one_, zero, zero, one_], &[], &[], &[]));
    for (inputs, want) in [
        ([one_, one_, zero, one_], "failed assertion: z must hold under g"),
        ([one_, one_, one_, zero], "failed assertion: w must hold"),
    ] {
        let pi = preimage(&inputs, &[], &[], &[]);
        reject(&compiled.ir, &pi);
        match simulate_compiled(&compiled, &pi) {
            Err(Sim3Error::Failed { op: "assert", message, .. }) => assert_eq!(message, want),
            other => panic!("expected {want:?}, got {other:?}"),
        }
    }

    assert_eq!(compiled.assert_messages.len(), 2, "the constant-true assert's message goes with it");
    let redundant = compiled.regions.iter().find(|r| r.label == "redundant").expect("recorded");
    assert_eq!(redundant.start, redundant.end, "the deduped constraint left it empty");
    let regions = profile(&compiled).regions;
    let region = |label: &str| regions.iter().find(|r| r.label == label).expect("profiled");
    assert_eq!(region("guarded").op_counts.get("assert"), Some(&1));
    assert_eq!(region("w check").instructions, 1);
    assert_eq!(region("w check").op_counts.get("assert"), Some(&1));
}

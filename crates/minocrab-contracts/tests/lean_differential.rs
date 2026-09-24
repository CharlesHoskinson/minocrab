//! M27 rung 4's RUN-RECORD INTERFACE (notes/zkir-semantics.org §6,
//! notes/zkir-rung4.org): turn dumped `ProofPreimage`s into PLAIN-TEXT run
//! records the Lean interpreter can read without a second implementation of
//! midnight's tagged binary format.
//!
//! Lean must not parse `midnight_serialize::tagged_serialize` output — that
//! is a format we refused to re-implement at M21 and would be a second,
//! unwarranted serializer. So this regenerator (the house `--ignored`
//! pattern of `row_snapshot.rs` / `interface_snapshot.rs`) reads each dumped
//! preimage, names the `.zkir` it was proved against, runs the Rust oracle
//! (`minocrab_sim::v3::simulate`, CROSS-CHECKED against upstream
//! `IrSource::check`), and writes one record per (circuit, variant) under
//! `crates/minocrab-zkir/lean/differential/`.
//!
//! Every artifact a record names is a CORPUS artifact — compactc's own
//! `.zkir`, already tracked under `corpus/zkir/` — so the records add no
//! duplicated artifact bytes, and the gate is a differential between
//! compactc's output and our Lean rather than between two of ours. That is
//! sound because the differential suites assert PI-equality of our artifact
//! and the corpus twin on exactly these preimages
//! (`minocrab_sim::v3::assert_call_compatible`).
//!
//! REGENERATE (two steps, both from the repo root):
//!
//! ```text
//! MINOCRAB_DUMP_PREIMAGES=$PWD/target/lean-differential/preimages \
//!   cargo test -p minocrab-contracts \
//!     --test erc20_vault_differential \
//!     --test signet_contract_differential \
//!     --test manager_differential
//! MINOCRAB_PREIMAGES=$PWD/target/lean-differential/preimages \
//!   cargo test -p minocrab-contracts --test lean_differential -- --ignored
//! ```
//!
//! The gate that consumes the records is `minocrab-zkir/tests/lean_run.rs`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use midnight_base_crypto::fab::{Alignment, AlignmentAtom, AlignmentSegment};
use midnight_curves::k256;
use midnight_base_crypto::repr::BinaryHashRepr;
use midnight_transient_crypto::fab::{AlignmentExt, ValueReprAlignedValue};
use midnight_transient_crypto::hash::{transient_commit, transient_hash};
use midnight_transient_crypto::proofs::{ProofPreimage, Zkir};
use midnight_zkir_v3::ir_instructions::ec_mul::ec_mul_offcircuit;
use midnight_zkir_v3::ir_instructions::encode::{decode_offcircuit, encode_offcircuit};
use midnight_zkir_v3::ir_instructions::from_bytes32::from_bytes32_offcircuit;
use midnight_zkir_v3::ir_instructions::into_bytes32::into_bytes32_offcircuit;
use midnight_zkir_v3::ir_instructions::into_coordinates::into_coordinates_offcircuit;
use minocrab::Fr;
use minocrab_sim::v3::{simulate, Run3};
use minocrab_zkir::v3::{IrSource, IrType, IrValue};
use sha2::{Digest as _, Sha256};
use sha3::Keccak256;

/// How many values one wrapped record line carries.
const CHUNK: usize = 8;

// ==== the corpus, declared ==================================================

/// The corpus directory each family's `.zkir` lives in, repo-relative.
const VAULT_DIR: &str =
    "corpus/zkir/signet-midnight-examples/examples/erc20-vault/contract/src/erc20-vault/zkir";
const SIGNET_DIR: &str =
    "corpus/zkir/signet-midnight-integration-pr127/packages/signet-contract/src/signet-contract/zkir";
const MANAGER_DIR: &str = "corpus/zkir/aa-midnight-evm-experiment/contracts/manager/zkir";

/// `(<preimage stem>, <repo-relative artifact path>)` for every dumped
/// preimage this rung records. The stems are the ones
/// `support::dump_preimage` writes; the artifacts are the corpus twins the
/// differential suites already prove PI-equal on these preimages.
fn corpus_table() -> Vec<(&'static str, String)> {
    let mut t: Vec<(&'static str, String)> = Vec::new();
    // The seventeen vault circuits (the M28 shape). The preimage stem is
    // `Circuit::zkir_name`, which is also compactc's file stem.
    for name in [
        "initialise",
        "approveStata",
        "approveRouter",
        "startDeposit",
        "completeDeposit",
        "startWithdraw",
        "completeWithdraw",
        "refundWithdraw",
        "startSwap",
        "completeSwap",
        "refundSwap",
        "startSupply",
        "completeSupply",
        "refundSupply",
        "startRedeem",
        "completeRedeem",
        "refundRedeem",
    ] {
        t.push((name, format!("{VAULT_DIR}/{name}.zkir")));
    }
    // The Signet singleton's three emit-only circuits.
    for name in ["signBidirectional", "respond", "respondBidirectional"] {
        t.push((name, format!("{SIGNET_DIR}/{name}.zkir")));
    }
    // The manager: `depositShielded` (persistent_hash + transient_hash) and
    // the `execute` variants (keccak256 + persistent_hash + transient_hash +
    // the secp256k1 ECDSA block, all in one circuit).
    t.push((
        "manager_depositShielded",
        format!("{MANAGER_DIR}/depositShielded.zkir"),
    ));
    for name in [
        "manager_execute_reg_native",
        "manager_execute_reg_evm",
        "manager_execute_transfer_shielded",
        "manager_execute_transfer_evm",
        "manager_execute_withdraw_shielded",
        "manager_execute_withdraw_unshielded",
        "manager_execute_open_swap",
    ] {
        t.push((name, format!("{MANAGER_DIR}/execute.zkir")));
    }
    t
}

/// Which preimages get a TAMPERED sibling, and where. `(stem, part, index)`
/// with the index taken modulo the stream length, so the table survives a
/// scenario growing a slot. `Part::Inputs` tampering also breaks the
/// communications commitment — that is a genuine reject and exactly the
/// epilogue path we want exercised.
const TAMPERS: &[(&str, Part, usize)] = &[
    ("initialise", Part::Transcript, 3),
    ("initialise", Part::Inputs, 0),
    ("startWithdraw", Part::Transcript, 7),
    ("startWithdraw", Part::Witness, 0),
    ("completeWithdraw", Part::Transcript, 2),
    ("completeWithdraw", Part::Witness, 0),
    ("startSwap", Part::Transcript, 11),
    ("respond", Part::Transcript, 1),
    ("signBidirectional", Part::Inputs, 1),
    ("manager_depositShielded", Part::Transcript, 4),
    ("manager_execute_reg_native", Part::Transcript, 5),
    ("manager_execute_withdraw_shielded", Part::Witness, 0),
];

/// Which stream a tamper perturbs (the vault harness's `tamper::Part`,
/// restated here so this file does not pull in the whole vault module).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Part {
    Transcript,
    Witness,
    Inputs,
}

impl Part {
    fn tag(self) -> &'static str {
        match self {
            Part::Transcript => "transcript",
            Part::Witness => "witness",
            Part::Inputs => "inputs",
        }
    }

    fn slot(self, pi: &mut ProofPreimage) -> &mut Vec<Fr> {
        match self {
            Part::Transcript => &mut pi.public_transcript_inputs,
            Part::Witness => &mut pi.private_transcript,
            Part::Inputs => &mut pi.inputs,
        }
    }
}

// ==== lexemes ===============================================================

/// A field element as the artifact spells its immediates: `0x` then
/// LITTLE-ENDIAN hex bytes, minimal length, at least one byte
/// (compactc's `zkir-field-rep->string`, print-zkir-v3.ss:46-61; the Lean
/// twin is `MinocrabZkir.immString`).
fn fr_lexeme(x: &Fr) -> String {
    let mut bytes = x.as_le_bytes().to_vec();
    while bytes.len() > 1 && *bytes.last().unwrap() == 0 {
        bytes.pop();
    }
    let mut s = String::with_capacity(2 + 2 * bytes.len());
    s.push_str("0x");
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// A byte string in STREAM order, `#` then two lowercase hex digits each.
fn bytes_lexeme(bs: &[u8]) -> String {
    let mut s = String::with_capacity(1 + 2 * bs.len());
    s.push('#');
    for b in bs {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// `IrValue::get_type` (ir_types.rs:149-165) — upstream keeps it
/// `pub(crate)`, so it is mirrored here exactly as `minocrab-sim` mirrors it.
fn value_type(v: &IrValue) -> IrType {
    match v {
        IrValue::Native(_) => IrType::Native,
        IrValue::Bytes32(_) => IrType::Bytes32,
        IrValue::JubjubPoint(_) => IrType::JubjubPoint,
        IrValue::JubjubScalar(_) => IrType::JubjubScalar,
        IrValue::Secp256k1Point(_) => IrType::Secp256k1Point,
        IrValue::Secp256k1Base(_) => IrType::Secp256k1Base,
        IrValue::Secp256k1Scalar(_) => IrType::Secp256k1Scalar,
        IrValue::Secp256r1Point(_) => IrType::Secp256r1Point,
        IrValue::Secp256r1Base(_) => IrType::Secp256r1Base,
        IrValue::Secp256r1Scalar(_) => IrType::Secp256r1Scalar,
        IrValue::Curve25519Point(_) => IrType::Curve25519Point,
        IrValue::Curve25519Base(_) => IrType::Curve25519Base,
        IrValue::Curve25519Scalar(_) => IrType::Curve25519Scalar,
    }
}

/// The ZKIR type lexeme (`IrType`'s own spelling, ir_types.rs:36-88).
fn type_lexeme(t: IrType) -> &'static str {
    match t {
        IrType::Native => "Scalar<BLS12-381>",
        IrType::Bytes32 => "Bytes<32>",
        IrType::JubjubPoint => "Point<Jubjub>",
        IrType::JubjubScalar => "Scalar<Jubjub>",
        IrType::Secp256k1Point => "Point<Secp256k1>",
        IrType::Secp256k1Base => "Base<Secp256k1>",
        IrType::Secp256k1Scalar => "Scalar<Secp256k1>",
        IrType::Secp256r1Point => "Point<Secp256r1>",
        IrType::Secp256r1Base => "Base<Secp256r1>",
        IrType::Secp256r1Scalar => "Scalar<Secp256r1>",
        IrType::Curve25519Point => "Point<Curve25519>",
        IrType::Curve25519Base => "Base<Curve25519>",
        IrType::Curve25519Scalar => "Scalar<Curve25519>",
    }
}

/// `<type>:<limb>,<limb>` — an output value with its `encode_offcircuit`
/// limbs, so the Lean side can print the same without a value printer.
fn output_lexeme(v: &IrValue) -> String {
    let limbs: Vec<String> = encode_offcircuit(v)
        .iter()
        .map(|x| match x {
            IrValue::Native(f) => fr_lexeme(f),
            other => panic!("encode_offcircuit produced a non-Native: {:?}", value_type(other)),
        })
        .collect();
    format!("{}:{}", type_lexeme(value_type(v)), limbs.join(","))
}

/// One wrapped, repeated key line per `CHUNK` values; a single bare key line
/// when the stream is empty. Both sides emit exactly this.
fn wrapped(key: &str, values: &[String]) -> String {
    if values.is_empty() {
        return format!("{key}\n");
    }
    let mut out = String::new();
    for chunk in values.chunks(CHUNK) {
        out.push_str(key);
        for v in chunk {
            out.push(' ');
            out.push_str(v);
        }
        out.push('\n');
    }
    out
}

// ==== the oracle ============================================================

/// The Rust reference's verdict on `(ir, preimage)`, cross-checked against
/// upstream `IrSource::check` (which is `preprocess(..)?.pi_skips`
/// verbatim, zkir-v3/src/ir.rs:75-81).
///
/// `check` PANICS rather than erroring on some malformed preimages
/// (notes/zkir-semantics.org §10 I2: `decode_offcircuit`'s `assert_eq!` on a
/// `Bytes<32>` limb), so a panic there is caught and read as "not accept" —
/// which is the disposition that note already records for this rung.
fn oracle(ir: &IrSource, pi: &ProofPreimage) -> Option<Run3> {
    let ours = simulate(ir, pi).ok();
    let theirs: Option<Vec<Option<usize>>> =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| ir.check(pi)))
            .ok()
            .and_then(|r| r.ok());
    match (&ours, &theirs) {
        (Some(run), Some(skips)) => assert_eq!(
            &run.pi_skips, skips,
            "the simulator and upstream `check` disagree on pi_skips"
        ),
        (None, None) => {}
        (Some(_), None) => panic!("the simulator accepts where upstream `check` does not"),
        (None, Some(_)) => panic!("upstream `check` accepts where the simulator rejects"),
    }
    ours
}

/// Render one record.
fn record(artifact: &str, variant: &str, pi: &ProofPreimage, run: Option<&Run3>) -> String {
    let mut out = String::new();
    out.push_str(
        "# ZKIR v3 RUN RECORD — GENERATED, do not edit.\n\
         # Regenerate: see crates/minocrab-contracts/tests/lean_differential.rs.\n\
         # Field elements are `0x` + little-endian hex bytes, minimal length —\n\
         # the artifact's own immediate lexeme (print-zkir-v3.ss:46-61).\n\
         # Keys repeat to wrap; a bare key is an empty stream.\n",
    );
    out.push_str(&format!("artifact {artifact}\n"));
    out.push_str(&format!("variant {variant}\n"));
    let fr_list = |xs: &[Fr]| xs.iter().map(fr_lexeme).collect::<Vec<_>>();
    out.push_str(&wrapped("inputs", &fr_list(&pi.inputs)));
    out.push_str(&wrapped("private_transcript", &fr_list(&pi.private_transcript)));
    out.push_str(&wrapped(
        "public_transcript_inputs",
        &fr_list(&pi.public_transcript_inputs),
    ));
    out.push_str(&wrapped(
        "public_transcript_outputs",
        &fr_list(&pi.public_transcript_outputs),
    ));
    out.push_str(&format!("binding_input {}\n", fr_lexeme(&pi.binding_input)));
    match pi.communications_commitment {
        None => out.push_str("comm_comm none\n"),
        Some((c, r)) => out.push_str(&format!("comm_comm {} {}\n", fr_lexeme(&c), fr_lexeme(&r))),
    }
    // ---- the EXPECTED block: everything below this line is what
    // `lake exe zkir-run` must print, byte for byte.
    out.push_str(&expected_block(run));
    out
}

/// The expected block — `zkir-run`'s entire stdout for this record.
fn expected_block(run: Option<&Run3>) -> String {
    let Some(run) = run else {
        return "result reject\n".to_string();
    };
    let mut out = String::from("result accept\n");
    out.push_str(&wrapped(
        "pis",
        &run.pis.iter().map(fr_lexeme).collect::<Vec<_>>(),
    ));
    out.push_str(&wrapped(
        "pi_skips",
        &run
            .pi_skips
            .iter()
            .map(|s| match s {
                None => "-".to_string(),
                Some(n) => n.to_string(),
            })
            .collect::<Vec<_>>(),
    ));
    out.push_str(&wrapped(
        "outputs",
        &run.outputs.iter().map(output_lexeme).collect::<Vec<_>>(),
    ));
    out
}

// ==== known answers for the ported primitives ===============================

/// The primitive-level KATs: one line per call, in the same lexemes the run
/// records use. These are what validates each ported intrinsic on its own,
/// BEFORE the interpreter is asked to agree on a whole circuit — a
/// disagreement here names the primitive, a disagreement in a record does
/// not.
///
/// Line shape: `<op> <arg>... => <result>...`.
fn known_answers() -> String {
    let mut out = String::new();
    out.push_str(
        "# KNOWN-ANSWER VECTORS for the rung-4 intrinsics — GENERATED from the\n\
         # Rust reference (transient-crypto `transient_hash`/`transient_commit`,\n\
         # sha2 `Sha256`, sha3 `Keccak256`, zkir-v3's own `*_offcircuit`\n\
         # helpers on midnight-curves' k256). Regenerate with\n\
         # crates/minocrab-contracts/tests/lean_differential.rs.\n\
         # `0x…` is a field element in minimal little-endian hex; `#…` a byte\n\
         # string in stream order. `lake exe zkir-run --kat <this file>`\n\
         # recomputes every right-hand side in Lean.\n",
    );

    // -- Poseidon (transient_hash), including the empty input and lengths
    //    either side of the rate (2), so the chunking and the fixed-length
    //    domain separation are both pinned.
    for n in [0usize, 1, 2, 3, 4, 5, 8, 17] {
        let xs: Vec<Fr> = (0..n).map(|i| Fr::from((i as u64) * 7 + 1)).collect();
        let args: Vec<String> = xs.iter().map(fr_lexeme).collect();
        out.push_str(&format!(
            "poseidon {} => {}\n",
            args.join(" "),
            fr_lexeme(&transient_hash(&xs))
        ));
    }
    // A big element, to catch a modulus or limb-order slip.
    let big = Fr::from_le_bytes(&[0xfe; 31]).expect("31 bytes fit");
    out.push_str(&format!(
        "poseidon {} {} => {}\n",
        fr_lexeme(&big),
        fr_lexeme(&Fr::from(0u64)),
        fr_lexeme(&transient_hash(&[big, Fr::from(0u64)]))
    ));
    // transient_commit: the opening leads the value (hash.rs:86-90).
    out.push_str(&format!(
        "poseidon_commit {} {} {} => {}\n",
        fr_lexeme(&Fr::from(3u64)),
        fr_lexeme(&Fr::from(5u64)),
        fr_lexeme(&Fr::from(9u64)),
        fr_lexeme(&transient_commit(
            &[Fr::from(3u64), Fr::from(5u64)][..],
            Fr::from(9u64)
        ))
    ));

    // -- SHA-256 and Keccak-256 over raw bytes, at and around the block
    //    boundaries their padding turns on.
    for len in [0usize, 1, 3, 55, 56, 63, 64, 65, 135, 136, 137, 200] {
        let msg: Vec<u8> = (0..len).map(|i| (i * 31 + 7) as u8).collect();
        out.push_str(&format!(
            "sha256 {} => {}\n",
            bytes_lexeme(&msg),
            bytes_lexeme(&Sha256::digest(&msg))
        ));
        out.push_str(&format!(
            "keccak256 {} => {}\n",
            bytes_lexeme(&msg),
            bytes_lexeme(&Keccak256::digest(&msg))
        ));
    }

    // -- the FAB alignment decode, `preprocess`'s own path into the two
    //    byte hashes: `Alignment::parse_field_repr` then
    //    `ValueReprAlignedValue::binary_repr` (ir_vm.rs:491-499). The
    //    non-canonical vectors are the point: a limb carrying a byte above
    //    its slot must REJECT, not truncate.
    for (length, limbs) in fab_cases() {
        let align = Alignment(vec![AlignmentSegment::Atom(AlignmentAtom::Bytes { length })]);
        let got = align.parse_field_repr(&limbs).map(|v| {
            let mut repr = Vec::new();
            ValueReprAlignedValue(v).binary_repr(&mut repr);
            repr
        });
        out.push_str(&format!(
            "fab_bytes {length} {} => {}\n",
            limbs.iter().map(fr_lexeme).collect::<Vec<_>>().join(" "),
            match got {
                Some(bytes) => bytes_lexeme(&bytes),
                None => "reject".to_string(),
            }
        ));
    }
    for x in [Fr::from(0u64), Fr::from(1u64), big, Fr::from(0u64) - Fr::from(1u64)] {
        let align = Alignment(vec![AlignmentSegment::Atom(AlignmentAtom::Field)]);
        let v = align.parse_field_repr(&[x]).expect("a field atom always parses");
        let mut repr = Vec::new();
        ValueReprAlignedValue(v).binary_repr(&mut repr);
        out.push_str(&format!(
            "fab_field {} => {}\n",
            fr_lexeme(&x),
            bytes_lexeme(&repr)
        ));
    }

    // -- secp256k1. Every vector goes through zkir-v3's own off-circuit
    //    helpers, so what is pinned is exactly what `preprocess` calls.
    let scalars: Vec<k256::Fq> = [1u64, 2, 3, 7, 1_000_003, u64::MAX]
        .iter()
        .map(|n| k256::Fq::from(*n))
        .collect();
    for s in &scalars {
        let g = IrValue::Secp256k1Point(k256::K256::generator());
        let p = ec_mul_offcircuit(&g, &IrValue::Secp256k1Scalar(*s)).expect("k256 mul");
        // `k256_gen_mul <scalar limbs> => <point limbs>`: encode both sides,
        // so the emulated-limb encoding is pinned along with the arithmetic.
        out.push_str(&format!(
            "k256_gen_mul {} => {}\n",
            enc_limbs(&IrValue::Secp256k1Scalar(*s)).join(" "),
            enc_limbs(&p).join(" ")
        ));
        // The x coordinate through `into_coordinates` + `into_bytes32` — the
        // ECDSA block's own path.
        let (x, _y) = into_coordinates_offcircuit(&p).expect("affine");
        let xb = into_bytes32_offcircuit(&x).expect("into_bytes32");
        let IrValue::Bytes32(xb) = xb else {
            unreachable!("into_bytes32 yields Bytes32")
        };
        out.push_str(&format!(
            "k256_gen_mul_x {} => {}\n",
            enc_limbs(&IrValue::Secp256k1Scalar(*s)).join(" "),
            bytes_lexeme(&xb)
        ));
    }
    // Point addition, including the two degenerate cases the doubling and
    // identity branches guard.
    let g = IrValue::Secp256k1Point(k256::K256::generator());
    for (a, b) in [(1u64, 2u64), (3, 3), (5, 0), (0, 0)] {
        let pa = ec_mul_offcircuit(&g, &IrValue::Secp256k1Scalar(k256::Fq::from(a))).unwrap();
        let pb = ec_mul_offcircuit(&g, &IrValue::Secp256k1Scalar(k256::Fq::from(b))).unwrap();
        let sum = midnight_zkir_v3::ir_instructions::add::add_offcircuit(&pa, &pb).unwrap();
        out.push_str(&format!(
            "k256_add {} {} => {}\n",
            enc_limbs(&pa).join(" "),
            enc_limbs(&pb).join(" "),
            enc_limbs(&sum).join(" ")
        ));
    }
    // `from_bytes32` into a scalar — the reduction the ECDSA block leans on
    // for both `z` and `r`, including a 32-byte value above the group order.
    for bs in [
        [0u8; 32],
        [0xffu8; 32],
        {
            let mut b = [0u8; 32];
            b[0] = 1;
            b
        },
        {
            let mut b = [0x5au8; 32];
            b[31] = 0xff;
            b
        },
    ] {
        let v = from_bytes32_offcircuit(&IrType::Secp256k1Scalar, &bs).expect("scalar");
        out.push_str(&format!(
            "k256_scalar_from_bytes32 {} => {}\n",
            bytes_lexeme(&bs),
            enc_limbs(&v).join(" ")
        ));
        let v = from_bytes32_offcircuit(&IrType::Secp256k1Base, &bs).expect("base");
        out.push_str(&format!(
            "k256_base_from_bytes32 {} => {}\n",
            bytes_lexeme(&bs),
            enc_limbs(&v).join(" ")
        ));
    }
    // `decode` of a point encoding: the identity flag, a real point, and a
    // rejection (an off-curve pair).
    let id = IrValue::Secp256k1Point(k256::K256::identity());
    for limbs in [enc_limbs(&id), enc_limbs(&g)] {
        let raw: Vec<Fr> = limbs.iter().map(|s| parse_fr_lexeme(s)).collect();
        let decoded = decode_offcircuit(&raw, &IrType::Secp256k1Point);
        out.push_str(&format!(
            "k256_point_decode {} => {}\n",
            limbs.join(" "),
            match decoded {
                Ok(v) => enc_limbs(&v).join(" "),
                Err(_) => "reject".to_string(),
            }
        ));
    }
    {
        // x = 1, y = 1 is not on y^2 = x^3 + 7.
        let bad = [
            IrValue::Secp256k1Base(k256::Fp::from(1u64)),
            IrValue::Secp256k1Base(k256::Fp::from(1u64)),
        ];
        let mut limbs: Vec<String> = bad.iter().flat_map(enc_limbs).collect();
        limbs.push(fr_lexeme(&Fr::from(0u64)));
        let raw: Vec<Fr> = limbs.iter().map(|s| parse_fr_lexeme(s)).collect();
        let decoded = decode_offcircuit(&raw, &IrType::Secp256k1Point);
        out.push_str(&format!(
            "k256_point_decode {} => {}\n",
            limbs.join(" "),
            match decoded {
                Ok(v) => enc_limbs(&v).join(" "),
                Err(_) => "reject".to_string(),
            }
        ));
    }
    out
}

/// `(bytes-atom length, limbs)` for the FAB vectors: the canonical shapes
/// the corpus actually uses (a stray plus chunks, chunks only, a single
/// stray), then the three ways an input can fail to match the alignment —
/// a full limb wider than 31 bytes, a stray limb wider than its slot, and
/// too few limbs.
fn fab_cases() -> Vec<(u32, Vec<Fr>)> {
    let limb = |n: u64| Fr::from(n);
    let wide31 = Fr::from_le_bytes(&[0xab; 31]).expect("31 bytes fit");
    let over248 = Fr::from(0u64) - Fr::from(1u64); // p - 1: 32 bytes, >= 2^248
    vec![
        // hashing::keccak(64)'s shape: stray 2, chunks 2.
        (64, vec![limb(0x0102), wide31, limb(7)]),
        // A Bytes<32>: stray 1, chunks 1.
        (32, vec![limb(0xfe), wide31]),
        // Exactly one full limb.
        (31, vec![wide31]),
        // Two full limbs, no stray — note the REVERSED limb order.
        (62, vec![wide31, limb(9)]),
        // Empty.
        (0, vec![]),
        // A full limb at or above 2^248: no room in its 31-byte slot.
        (31, vec![over248]),
        // A stray limb above its 1-byte slot.
        (32, vec![limb(0x0100), wide31]),
        // Too few limbs for the declared length.
        (64, vec![limb(1), limb(2)]),
    ]
}

fn enc_limbs(v: &IrValue) -> Vec<String> {
    encode_offcircuit(v)
        .iter()
        .map(|x| match x {
            IrValue::Native(f) => fr_lexeme(f),
            other => panic!("non-Native limb: {:?}", value_type(other)),
        })
        .collect()
}

/// The inverse of [`fr_lexeme`]: `0x` + little-endian hex bytes, canonical
/// (`Fr::from_le_bytes` rejects a 32-byte string at or above the modulus,
/// which no lexeme this file writes ever is).
fn parse_fr_lexeme(s: &str) -> Fr {
    let hex = s.strip_prefix("0x").unwrap_or_else(|| panic!("not a `0x` lexeme: {s}"));
    assert!(
        hex.len().is_multiple_of(2) && !hex.is_empty() && hex.len() <= 64,
        "malformed field lexeme: {s}"
    );
    let bytes: Vec<u8> = hex
        .as_bytes()
        .chunks(2)
        .map(|pair| {
            u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16)
                .unwrap_or_else(|_| panic!("malformed field lexeme: {s}"))
        })
        .collect();
    Fr::from_le_bytes(&bytes).unwrap_or_else(|| panic!("field lexeme is not canonical: {s}"))
}

// ==== the regenerator =======================================================

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root")
}

fn records_dir() -> PathBuf {
    repo_root().join("crates/minocrab-zkir/lean/differential")
}

fn read_preimage(path: &Path) -> ProofPreimage {
    let bytes = std::fs::read(path).expect("preimage reads");
    midnight_serialize::tagged_deserialize(&mut &bytes[..]).expect("preimage deserializes")
}

#[test]
#[ignore = "regenerator: writes crates/minocrab-zkir/lean/differential/ from dumped preimages"]
fn regenerate_lean_run_records() {
    let dir = std::env::var_os("MINOCRAB_PREIMAGES")
        .map(PathBuf::from)
        .unwrap_or_else(|| repo_root().join("target/lean-differential/preimages"));
    assert!(
        dir.is_dir(),
        "no preimage dump at {} — run the differential suites with \
         MINOCRAB_DUMP_PREIMAGES set first (see this file's docs)",
        dir.display()
    );
    let root = repo_root();
    let out = records_dir();
    std::fs::create_dir_all(&out).expect("records dir");

    // Start from a clean slate so a removed circuit cannot leave a stale
    // record behind, the way the snapshot regenerators rewrite in full.
    for entry in std::fs::read_dir(&out).expect("records dir reads").flatten() {
        let p = entry.path();
        if p.extension().is_some_and(|e| e == "record") {
            std::fs::remove_file(p).expect("stale record removed");
        }
    }

    let mut tampers: BTreeMap<&str, Vec<(Part, usize)>> = BTreeMap::new();
    for (stem, part, idx) in TAMPERS {
        tampers.entry(stem).or_default().push((*part, *idx));
    }

    let mut written = 0usize;
    let mut rejects = 0usize;
    for (stem, artifact) in corpus_table() {
        let pi_path = dir.join(format!("{stem}.preimage"));
        assert!(
            pi_path.is_file(),
            "no dumped preimage for `{stem}` at {} — the differential suite \
             that dumps it did not run",
            pi_path.display()
        );
        let pi = read_preimage(&pi_path);
        let ir = minocrab_zkir::v3::read_zkir(root.join(&artifact)).unwrap_or_else(|e| {
            panic!("corpus artifact {artifact} does not parse: {e}");
        });

        let run = oracle(&ir, &pi);
        assert!(
            run.is_some(),
            "the honest preimage for `{stem}` is rejected by {artifact}"
        );
        std::fs::write(
            out.join(format!("{stem}.record")),
            record(&artifact, "honest", &pi, run.as_ref()),
        )
        .expect("record writes");
        written += 1;

        for (part, idx) in tampers.get(stem).into_iter().flatten() {
            let mut t = pi.clone();
            let slot = part.slot(&mut t);
            assert!(
                !slot.is_empty(),
                "`{stem}` has an empty {} stream — the TAMPERS table is stale",
                part.tag()
            );
            let i = idx % slot.len();
            slot[i] = slot[i] + Fr::from(1u64);
            // A tampered element is USUALLY a reject; it is not always one,
            // and that is a fact about the circuit rather than a defect in
            // this table. Transcript reads and their guards are UNCONSTRAINED
            // in the v3 statement (notes/zkir-semantics.org §4.3, and
            // upstream's own spec PR #16 §6.6(d)/O4), so a private input that
            // no downstream constraint depends on may be perturbed freely —
            // `completeWithdraw`'s guarded-off success-branch witness is
            // exactly that case (the draft's Gap 2). The record carries
            // whatever the oracle says either way; an accepting tamper pins
            // that fact as firmly as a rejecting one pins the reject, and the
            // count below keeps the reject side real.
            let run = oracle(&ir, &t);
            let variant = format!("tampered {} {i}", part.tag());
            std::fs::write(
                out.join(format!("{stem}.tamper-{}-{i}.record", part.tag())),
                record(&artifact, &variant, &t, run.as_ref()),
            )
            .expect("tamper record writes");
            written += 1;
            if run.is_none() {
                rejects += 1;
            }
        }
    }

    assert!(
        rejects >= 8,
        "only {rejects} tampered records reject — the gate would barely \
         exercise the reject path"
    );

    std::fs::write(out.join("known-answers.txt"), known_answers()).expect("KAT writes");

    println!(
        "wrote {written} run records ({rejects} rejecting) plus known-answers.txt to {}",
        out.display()
    );
}

/// The records must stay in step with the Rust oracle: re-derive every
/// record's expected block from the artifact and preimage IT NAMES and
/// compare. This is a plain `cargo test` (no `lake`, no preimage dump) —
/// what it catches is a record edited by hand or left behind by a change to
/// `simulate`.
#[test]
fn the_run_records_agree_with_the_rust_oracle() {
    let out = records_dir();
    if !out.is_dir() {
        eprintln!("skipping: no records at {}", out.display());
        return;
    }
    let root = repo_root();
    let mut checked = 0usize;
    let mut files: Vec<PathBuf> = std::fs::read_dir(&out)
        .expect("records dir reads")
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "record"))
        .collect();
    files.sort();
    for path in files {
        let text = std::fs::read_to_string(&path).expect("record reads");
        let (artifact, pi, expected) = parse_record(&text);
        let ir = minocrab_zkir::v3::read_zkir(root.join(&artifact)).expect("artifact parses");
        let run = oracle(&ir, &pi);
        assert_eq!(
            expected_block(run.as_ref()),
            expected,
            "{} disagrees with the Rust oracle — regenerate it",
            path.display()
        );
        checked += 1;
    }
    assert!(checked > 0, "no run records found under {}", out.display());
    println!("{checked} run records agree with the Rust oracle");
}

/// `(artifact, preimage, expected block)` out of a record's text.
fn parse_record(text: &str) -> (String, ProofPreimage, String) {
    let mut artifact = String::new();
    let mut streams: BTreeMap<&str, Vec<Fr>> = BTreeMap::new();
    let mut binding = Fr::from(0u64);
    let mut comm: Option<(Fr, Fr)> = None;
    let mut expected = String::new();
    let mut in_expected = false;
    for line in text.lines() {
        if in_expected {
            expected.push_str(line);
            expected.push('\n');
            continue;
        }
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        let mut it = line.split_whitespace();
        let key = it.next().expect("a key");
        let rest: Vec<&str> = it.collect();
        match key {
            "artifact" => artifact = rest[0].to_string(),
            "variant" => {}
            "binding_input" => binding = parse_fr_lexeme(rest[0]),
            "comm_comm" => {
                comm = if rest[0] == "none" {
                    None
                } else {
                    Some((
                        parse_fr_lexeme(rest[0]),
                        parse_fr_lexeme(rest[1]),
                    ))
                }
            }
            "inputs" | "private_transcript" | "public_transcript_inputs"
            | "public_transcript_outputs" => {
                let entry = streams.entry(match key {
                    "inputs" => "inputs",
                    "private_transcript" => "private_transcript",
                    "public_transcript_inputs" => "public_transcript_inputs",
                    _ => "public_transcript_outputs",
                });
                entry
                    .or_default()
                    .extend(rest.iter().map(|s| parse_fr_lexeme(s)));
            }
            "result" => {
                in_expected = true;
                expected.push_str(line);
                expected.push('\n');
            }
            other => panic!("unknown record key `{other}`"),
        }
    }
    let take = |k: &str| streams.get(k).cloned().unwrap_or_default();
    let pi = ProofPreimage {
        inputs: take("inputs"),
        private_transcript: take("private_transcript"),
        public_transcript_inputs: take("public_transcript_inputs"),
        public_transcript_outputs: take("public_transcript_outputs"),
        binding_input: binding,
        communications_commitment: comm,
        key_location: midnight_transient_crypto::proofs::KeyLocation(std::borrow::Cow::Borrowed(
            "lean-differential",
        )),
    };
    (artifact, pi, expected)
}

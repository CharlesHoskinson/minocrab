//! `opaque.compact` — the M15 differential: [`minocrab_std::v3::Opaque`] and
//! the two curve-point leaves against compactc's own artifacts.
//!
//! WHY THE FIXTURE IS OURS. The corpus has 74 `Opaque` nodes across 23 of the
//! 312 artifacts — real production code, not test fixtures (`bboard`'s
//! `message`, `welcome`'s `add_participant`, eleven OpenZeppelin token
//! contracts' `name()`) — and NONE of them is in a v3 artifact. Only the three
//! sig-net sources are compiled with `--feature-zkir-v3`, and our IR is v3;
//! their four `Opaque` nodes are all `Secp256k1Point`. So this is the
//! established tiny.compact-style fallback, compiled with the PINNED compactc,
//! with the exact invocation in the fixture's header.
//!
//! FOUR CLAIMS, in increasing interest:
//!
//! 1. `identical_instruction_streams` — for all fourteen circuits, our
//!    serialized ZKIR IS compactc's up to identifier renaming: every op, every
//!    immediate, every width, every operand position. This SUBSUMES the
//!    notes/ledger-abi.org §6 call-compatibility criterion the other
//!    differentials settle for (identical streams cannot produce differing
//!    `pis`), which is why it is first and why the preimage-based tests below
//!    are a spot-check of upstream's own `check()` rather than the main event.
//! 2. `compactc_s_abi_agrees_with_the_leafs` — the artifact's
//!    `contract-info.json`, flattened by `minocrab_abi::info`, against the
//!    `CircuitAbi` of the Rust types the generator emits for it. This is the
//!    test that would have caught the curve-point bug on day one.
//! 3. `the_vaults_own_initialize_now_flattens` — the corpus provenance the
//!    fixture route costs, recovered where the corpus does have coverage: the
//!    erc20-vault's own `initialize`, which our reader refused before M15.
//! 4. `the_compress_atom_is_a_transient_commitment` — the one claim that is
//!    not about compactc at all. An opaque's slot holds
//!    `transient_commit(bytes, len)` (upstream's
//!    `ValueAtom::field_repr_unchecked`), so a preimage whose ledger write
//!    carries the BYTES and whose circuit input carries the COMMITMENT must
//!    satisfy both artifacts. Nothing else in the suite pins that reading of
//!    upstream, and everything in `minocrab_std::v3::Opaque`'s docs rests on
//!    it.

use std::borrow::Cow;

use midnight_base_crypto::fab::{
    AlignedValue, Alignment, AlignmentAtom, AlignmentSegment, Value, ValueAtom,
};
use midnight_onchain_vm::ops::{Key, Op};
use midnight_onchain_vm::result_mode::ResultModeVerify;
use midnight_storage::db::InMemoryDB;
use midnight_transient_crypto::hash::transient_commit;
use midnight_transient_crypto::proofs::{KeyLocation, ProofPreimage, Zkir};
use midnight_transient_crypto::repr::FieldRepr;
use minocrab::v3::Compiled3;
use minocrab::Fr;
use minocrab_contracts::opaque;
use minocrab_sim::v3::simulate;
use minocrab_zkir::v3::{to_zkir_string, IrSource};

type VmOp = Op<ResultModeVerify, InMemoryDB>;

/// compactc's artifact for one fixture circuit.
fn theirs(name: &str) -> IrSource {
    let path = format!(
        "{}/tests/fixtures/opaque/out/zkir/{name}.zkir",
        env!("CARGO_MANIFEST_DIR")
    );
    minocrab_zkir::v3::read_zkir(&path).expect("the pinned compactc's artifact parses")
}

fn bytes1_value(v: u8) -> AlignedValue {
    AlignedValue::new(
        Value(vec![ValueAtom(vec![v]).normalize()]),
        Alignment(vec![AlignmentSegment::Atom(AlignmentAtom::Bytes {
            length: 1,
        })]),
    )
    .unwrap()
}

/// An `Opaque`'s stored value: the RAW BYTES under a `compress` atom.
///
/// A `compress` atom accepts a value of any length —
/// `AlignmentAtom::fits` returns `true` for it unconditionally — so the ledger
/// holds the whole string and the circuit sees only [`opaque_commitment`] of
/// it. That asymmetry is the type's whole story.
fn opaque_value(bytes: &[u8]) -> AlignedValue {
    AlignedValue::new(
        Value(vec![ValueAtom(bytes.to_vec()).normalize()]),
        Alignment(vec![AlignmentSegment::Atom(AlignmentAtom::Compress)]),
    )
    .expect("a compress atom fits any value")
}

/// The field element a circuit sees for an opaque holding `bytes`, computed
/// the way upstream computes it (`transient-crypto/src/fab.rs`,
/// `ValueAtom::field_repr_unchecked`):
///
/// ```text
/// AlignmentAtom::Compress => if bytes.is_empty() { 0 }
///                            else { transient_commit(bytes, len) }
/// ```
fn opaque_commitment(bytes: &[u8]) -> Fr {
    if bytes.is_empty() {
        return Fr::from(0u64);
    }
    transient_commit(bytes, Fr::from(bytes.len() as u64))
}

fn transcript(ops: &[VmOp]) -> Vec<Fr> {
    let mut out = Vec::new();
    for op in ops {
        op.field_repr(&mut out);
    }
    out
}

fn preimage(inputs: Vec<Fr>, transcript: Vec<Fr>) -> ProofPreimage {
    preimage_out(inputs, transcript, &[])
}

/// The communications commitment covers the circuit's INPUTS **and** its
/// OUTPUTS (`onchain-runtime-wasm/src/primitives.rs`: `input`, then `output`,
/// into `comm_comm_preimage`), so a circuit that returns a value has to declare
/// it here. `bounded_differential.rs` gets away with inputs alone because none
/// of its circuits returns anything.
fn preimage_out(inputs: Vec<Fr>, transcript: Vec<Fr>, outputs: &[Fr]) -> ProofPreimage {
    let rand = Fr::from(0xb0_u64);
    let mut comm_vals = inputs.clone();
    comm_vals.extend_from_slice(outputs);
    let comm = transient_commit(&comm_vals[..], rand);
    ProofPreimage {
        inputs,
        private_transcript: vec![],
        public_transcript_inputs: transcript,
        public_transcript_outputs: vec![],
        binding_input: 0.into(),
        communications_commitment: Some((comm, rand)),
        key_location: KeyLocation(Cow::Borrowed("minocrab-contracts-test")),
    }
}

/// `dummy.increment(1)` on ledger field 0.
fn increment_transcript() -> Vec<Fr> {
    transcript(&[
        Op::Idx {
            cached: false,
            push_path: true,
            path: vec![Key::Value(bytes1_value(0))].into(),
        },
        Op::Addi { immediate: 1 },
        Op::Ins { cached: true, n: 1 },
    ])
}

/// `cell = value` on ledger field `index` — `push key; pushs value; ins 1`.
fn cell_write_transcript(index: u8, value: AlignedValue) -> Vec<Fr> {
    transcript(&[
        Op::Push {
            storage: false,
            value: bytes1_value(index).into(),
        },
        Op::Push {
            storage: true,
            value: value.into(),
        },
        Op::Ins {
            cached: false,
            n: 1,
        },
    ])
}

/// Serialized ZKIR with every `%name.index` identifier replaced by
/// `%<order of first appearance>` — the same canonicalization
/// `bounded_differential.rs` uses, and for the same reason: names are the only
/// thing the two artifacts may differ in, and they are cosmetic to the ABI.
fn canonical(ir: &IrSource) -> String {
    // BOTH SIDES are folded first (notes/ir-passes.org §2 ii): our builder
    // inlines a `Copy` of an immediate at `finish`, and compactc names some of
    // the constants it inlines elsewhere, so the comparison is instruction for
    // instruction MODULO the naming of constants — a rename with no rows, no
    // public input and no semantics. Everything else still compares exactly.
    let ir = &minocrab_ir::v3::passes::folded(ir);
    let text = to_zkir_string(ir).expect("serializes");
    let mut renames: Vec<(String, String)> = Vec::new();
    let mut out = String::with_capacity(text.len());
    let mut rest = text.as_str();
    while let Some(at) = rest.find('%') {
        out.push_str(&rest[..at]);
        rest = &rest[at..];
        let end = rest[1..]
            .find(|ch: char| !(ch.is_alphanumeric() || ch == '_' || ch == '.'))
            .map(|i| i + 1)
            .unwrap_or(rest.len());
        let name = &rest[..end];
        let next = renames.len();
        let canon = match renames.iter().find(|(from, _)| from == name) {
            Some((_, to)) => to.clone(),
            None => {
                let to = format!("%{next}");
                renames.push((name.to_string(), to.clone()));
                to
            }
        };
        out.push_str(&canon);
        rest = &rest[end..];
    }
    out.push_str(rest);
    out
}

/// Every circuit of the fixture: compactc's artifact name and our builder.
fn cases() -> Vec<(&'static str, fn() -> Compiled3)> {
    vec![
        ("opArg", opaque::OpaqueLedger::op_arg as fn() -> Compiled3),
        ("opRet", opaque::OpaqueLedger::op_ret),
        ("opEq", opaque::OpaqueLedger::op_eq),
        ("opCell", opaque::OpaqueLedger::op_cell),
        ("opDefault", opaque::OpaqueLedger::op_default),
        ("opWitness", opaque::OpaqueLedger::op_witness),
        ("opMapValue", opaque::OpaqueLedger::op_map_value),
        ("opMapKey", opaque::OpaqueLedger::op_map_key),
        ("opSet", opaque::OpaqueLedger::op_set),
        ("opMaybe", opaque::OpaqueLedger::op_maybe),
        ("opBytes", opaque::OpaqueLedger::op_bytes),
        ("opStruct", opaque::OpaqueLedger::op_struct),
        ("opPoint", opaque::OpaqueLedger::op_point),
        ("opJubjub", opaque::OpaqueLedger::op_jubjub),
    ]
}

/// CLAIM 1, and the headline: for every position an opaque can occupy, our
/// circuit IS compactc's — op for op, immediate for immediate.
///
/// This is what says the `compress` atom's Impact immediate (`-0x01`), its
/// position in a map key versus a map value, the absence of any range
/// constraint, and the two curve alignments are all compactc's decisions and
/// not ours.
///
/// ALL FOURTEEN are equal outright. Three of them — `opDefault`, `opMapKey`
/// and `opMaybe`, the ones whose ledger value is a LITERAL — used not to be:
/// they named the constant with a `copy` where compactc inlines it, because a
/// ledger value position goes through `LedgerRepr::push_limbs`, which hands
/// back wires. That gap (M15, notes/opaque-bridging.org) was measured at zero
/// rows and described here by a bespoke `without_named_immediates` normaliser
/// plus a test counting the extra `copy`s. Both are GONE: the constant-folding
/// pass (notes/ir-passes.org §2 ii) inlines the copy at `finish`, so the
/// three circuits are equal on the same criterion as the other eleven and the
/// API change the gap was waiting on is not needed.
#[test]
fn identical_instruction_streams() {
    for (name, build) in cases() {
        assert_eq!(
            canonical(&build().ir),
            canonical(&theirs(name)),
            "{name}: our lowering differs from compactc's"
        );
    }
}

/// An opaque argument carries NO constraint instruction, which is the fact the
/// whole leaf rests on — asserted directly rather than only through stream
/// equality, so that a future change to both sides at once still fails here.
#[test]
fn an_opaque_argument_is_unconstrained() {
    let ir = opaque::OpaqueLedger::op_arg().ir;
    let text = to_zkir_string(&ir).expect("serializes");
    for constraint in ["constrain_bits", "constrain_to_boolean", "constrain_eq", "less_than"] {
        assert!(
            !text.contains(constraint),
            "opArg emitted `{constraint}` for an opaque argument"
        );
    }
    // …while its NEIGHBOUR in `opStruct` does get one, so the absence above is
    // a property of the type and not of the test.
    let tagged = to_zkir_string(&opaque::OpaqueLedger::op_struct().ir).expect("serializes");
    assert_eq!(
        tagged.matches("constrain_bits").count(),
        1,
        "opStruct should constrain exactly its `Uint<8>` field"
    );
}

/// CLAIM 4: an opaque's slot is `transient_commit(bytes, len)`.
///
/// The preimage is INCONSISTENT unless that is true: the circuit input is the
/// commitment we compute natively, the ledger write carries the raw bytes, and
/// the two are tied together only by upstream's own `field_repr` of a
/// `compress` atom. Both artifacts have to accept it, and upstream's `check()`
/// has to agree.
///
/// The empty case is the same claim at its special value: upstream writes 0
/// rather than a commitment "to make defaults work well", which is why
/// `opDefault` lowers to the immediate `0x00`.
#[test]
fn the_compress_atom_is_a_transient_commitment() {
    for bytes in [&b"hello"[..], &b""[..], &b"a much longer opaque string value"[..]] {
        let pi = preimage(
            vec![opaque_commitment(bytes)],
            cell_write_transcript(1, opaque_value(bytes)),
        );
        let ours = opaque::OpaqueLedger::op_cell().ir;
        let theirs = theirs("opCell");

        let our_run = simulate(&ours, &pi)
            .unwrap_or_else(|e| panic!("ours rejected {bytes:?}: {e:?}"));
        let their_run = simulate(&theirs, &pi)
            .unwrap_or_else(|e| panic!("compactc's rejected {bytes:?}: {e:?}"));
        assert_eq!(our_run.pis, their_run.pis, "PI vectors differ for {bytes:?}");
        assert_eq!(our_run.pi_skips, their_run.pi_skips);
        assert_eq!(
            ours.check(&pi).expect("upstream accepts ours"),
            our_run.pi_skips
        );
        assert_eq!(
            theirs.check(&pi).expect("upstream accepts compactc's"),
            their_run.pi_skips
        );
    }
}

/// The commitment BINDS: a preimage whose circuit input is the commitment of
/// one string while the ledger write carries another is rejected by both
/// artifacts.
///
/// This is what makes `Opaque::eq` an equality on the TS-side values rather
/// than on interchangeable handles — and the test would pass vacuously if the
/// slot were merely an index, so it is the one that earns that sentence in the
/// type's docs.
#[test]
fn a_mismatched_commitment_is_rejected_by_both() {
    let pi = preimage(
        vec![opaque_commitment(b"hello")],
        cell_write_transcript(1, opaque_value(b"goodbye")),
    );
    assert!(
        simulate(&opaque::OpaqueLedger::op_cell().ir, &pi).is_err(),
        "ours accepted a commitment that does not open to the written bytes"
    );
    assert!(
        simulate(&theirs("opCell"), &pi).is_err(),
        "compactc's accepted it"
    );
}

/// Call-compatibility on the increment-only circuits, so that upstream's
/// `check()` — not just our simulator — has seen an opaque argument.
#[test]
fn the_increment_only_circuits_are_call_compatible() {
    let name = opaque_commitment(b"alice");
    // A circuit's `output` is a ZKIR output instruction, NOT a public
    // transcript entry — it stays out of `public_transcript_outputs` and goes
    // into the communications commitment instead. `opEq` returns `a == b` on
    // two equal commitments, hence the `1`.
    for (label, build, inputs, outputs) in [
        ("opArg", opaque::OpaqueLedger::op_arg as fn() -> Compiled3, vec![name], vec![]),
        ("opEq", opaque::OpaqueLedger::op_eq, vec![name, name], vec![Fr::from(1u64)]),
    ] {
        let pi = preimage_out(inputs, increment_transcript(), &outputs);
        let ours = build().ir;
        let theirs = theirs(label);
        let our_run = simulate(&ours, &pi).unwrap_or_else(|e| panic!("{label}: ours: {e:?}"));
        let their_run =
            simulate(&theirs, &pi).unwrap_or_else(|e| panic!("{label}: theirs: {e:?}"));
        assert_eq!(our_run.pis, their_run.pis, "{label}: PI vectors differ");
        assert_eq!(our_run.pi_skips, their_run.pi_skips, "{label}: pi_skips differ");
        assert_eq!(ours.check(&pi).expect("upstream accepts ours"), our_run.pi_skips);
        assert_eq!(
            theirs.check(&pi).expect("upstream accepts compactc's"),
            their_run.pi_skips
        );
    }
}

/// CLAIM 2, THE ABI ROUND-TRIP: compactc's `contract-info.json`, flattened,
/// against the `CircuitAbi` of the leaf the generator maps each argument to —
/// atoms AND primitive types, slot for slot. Those two lists agreeing IS the
/// agreement check every interface crate rests on.
///
/// This is the test whose absence let the curve-point bug survive: before M15
/// `flatten()` returned `Err` for `opPoint`'s argument, so nothing compared
/// five atoms against five.
#[test]
fn compactc_s_abi_agrees_with_the_leafs() {
    use minocrab::v3::CircuitAbi;
    use minocrab::Public;
    use minocrab_abi::info::ContractInfo;
    use minocrab_std::v3::{ts, JubjubPoint, Opaque, Secp256k1Point, Uint, B32};

    let text = std::fs::read_to_string(format!(
        "{}/tests/fixtures/opaque/out/compiler/contract-info.json",
        env!("CARGO_MANIFEST_DIR")
    ))
    .expect("the pinned compactc's contract-info is committed");
    let info = ContractInfo::parse(&text).expect("contract-info parses");

    macro_rules! abi {
        ($($ty:ty),*) => {{
            let mut atoms = Vec::new();
            let mut prims = Vec::new();
            $(
                atoms.extend(<$ty as CircuitAbi>::atoms());
                prims.extend(<$ty as CircuitAbi>::prims());
            )*
            (atoms, prims)
        }};
    }

    // One entry per circuit that HAS arguments, in declaration order.
    let expected: Vec<(&str, (Vec<_>, Vec<_>))> = vec![
        ("opArg", abi!(Opaque<ts::Str, Public>)),
        ("opRet", abi!(Opaque<ts::Str, Public>)),
        ("opEq", abi!(Opaque<ts::Str, Public>, Opaque<ts::Str, Public>)),
        ("opCell", abi!(Opaque<ts::Str, Public>)),
        ("opMapValue", abi!(B32<Public>, Opaque<ts::Str, Public>)),
        ("opMapKey", abi!(Opaque<ts::Str, Public>)),
        ("opSet", abi!(Opaque<ts::Str, Public>)),
        ("opMaybe", abi!(Opaque<ts::Str, Public>)),
        // The second ts-type has the SAME layout — the distinction is a Rust
        // type-level one, and this is where that is stated as a fact.
        ("opBytes", abi!(Opaque<ts::Uint8Array, Public>)),
        ("opStruct", abi!(Uint<8, Public>, Opaque<ts::Str, Public>)),
        // The two curve spellings, which used to be `Err`.
        ("opPoint", abi!(Secp256k1Point<Public>)),
        ("opJubjub", abi!(JubjubPoint<Public>)),
    ];

    for (name, (atoms, prims)) in expected {
        let circuit = info.circuit(name).unwrap_or_else(|| panic!("{name} is exported"));
        let flat = minocrab_abi::info::flatten_all(circuit.arguments.iter().map(|a| &a.ty))
            .unwrap_or_else(|e| panic!("{name}: compactc's ABI does not flatten: {e}"));
        assert_eq!(flat.atoms, atoms, "{name}: FAB atoms differ");
        assert_eq!(flat.prims, prims, "{name}: primitive types differ");
    }
}

/// CLAIM 3: the corpus provenance the fixture route costs, recovered where the
/// corpus does have coverage.
///
/// `Secp256k1Point` is the one `Opaque` spelling the corpus DOES compile to
/// v3, and the erc20-vault — our own benchmark contract — takes one as
/// `initialise`'s seventh argument (fifth before the lending flows added
/// the two Aave addresses). Before M15 `flatten()` returned
/// `TypeError::Opaque` for it, so the benchmark contract was not importable
/// through our own interface machinery. This is that fact, from the corpus
/// artifact rather than from our fixture.
#[test]
fn the_vaults_own_initialize_now_flattens() {
    use minocrab::v3::{CircuitAbi, Prim};
    use minocrab::Public;
    use minocrab_abi::info::ContractInfo;
    use minocrab_std::v3::{Bytes, Secp256k1Point, Uint};

    let text = std::fs::read_to_string(format!(
        "{}/../../corpus/zkir/signet-midnight-examples/examples/erc20-vault/contract/\
         src/erc20-vault/compiler/contract-info.json",
        env!("CARGO_MANIFEST_DIR")
    ))
    .expect("the corpus artifact is committed");
    let info = ContractInfo::parse(&text).expect("contract-info parses");
    let initialize = info.circuit("initialise").expect("the vault exports initialise");

    // `responseKey: Secp256k1Point`, published as an `Opaque` under an alias.
    // Seventh of eight arguments since M44 — `evmHeight` follows it — so pick
    // it out by name rather than by position.
    let response_key = &initialize
        .arguments
        .iter()
        .find(|a| a.name == "responseKey")
        .expect("the vault's initialise takes a responseKey")
        .ty;
    assert_eq!(
        response_key.curve_point(),
        Some(minocrab_abi::info::CurvePoint::Secp256k1)
    );

    let flat = minocrab_abi::info::flatten_all(initialize.arguments.iter().map(|a| &a.ty))
        .expect("the vault's own initialize flattens");

    let mut atoms = Vec::new();
    let mut prims = Vec::new();
    for (a, p) in [
        (
            <Bytes<20, Public> as CircuitAbi>::atoms(),
            <Bytes<20, Public> as CircuitAbi>::prims(),
        ),
        (
            <Bytes<20, Public> as CircuitAbi>::atoms(),
            <Bytes<20, Public> as CircuitAbi>::prims(),
        ),
        (
            <Bytes<20, Public> as CircuitAbi>::atoms(),
            <Bytes<20, Public> as CircuitAbi>::prims(),
        ),
        (
            <Bytes<20, Public> as CircuitAbi>::atoms(),
            <Bytes<20, Public> as CircuitAbi>::prims(),
        ),
        (
            <Uint<64, Public> as CircuitAbi>::atoms(),
            <Uint<64, Public> as CircuitAbi>::prims(),
        ),
        (
            <Secp256k1Point<Public> as CircuitAbi>::atoms(),
            <Secp256k1Point<Public> as CircuitAbi>::prims(),
        ),
        (<Uint<8, Public> as CircuitAbi>::atoms(), <Uint<8, Public> as CircuitAbi>::prims()),
        (<Uint<64, Public> as CircuitAbi>::atoms(), <Uint<64, Public> as CircuitAbi>::prims()),
    ] {
        atoms.extend(a);
        prims.extend(p);
    }
    assert_eq!(flat.atoms, atoms, "the vault's initialize atoms");
    assert_eq!(flat.prims, prims, "the vault's initialize prims");
    // The response key is the sixth argument of eight since the flush
    // pattern (the key version and the EVM height follow it): a point slot,
    // not an opaque one.
    assert_eq!(
        prims.get(prims.len() - 3),
        Some(&Prim::Point),
        "the response key is a point slot, not an opaque one"
    );
}

//! Off-circuit primitives of the erc20-vault reference model: the FAB
//! encodings, hash constructions and signature helpers that reproduce, in
//! ordinary Rust, exactly what the circuits compute in-circuit.
//!
//! ONE concretization (M44): every vault commitment is Poseidon —
//! `upgradeFromTransient(transientHash(…))` — as the flush-pattern source has
//! it (`userCommitment`, `ownershipCommitment`, `requestIndex`, the per-action
//! args hashes, `vaultTokenDomainSeparator`), and so is the V1 protocol's
//! transaction digest, request id and attestation digest, each under its
//! `HashDomain` tag. What stays protocol-pinned and SHA-256 is the ledger's
//! own: `tokenType`, the coin commitment and nullifier.

use midnight_base_crypto::fab::{Alignment, AlignmentAtom, AlignmentSegment, AlignedValue, Value, ValueAtom};
use midnight_base_crypto::repr::BinaryHashRepr;
use midnight_curves::k256;
use midnight_onchain_state::state::StateValue;
use midnight_onchain_vm::ops::Op;
use midnight_onchain_vm::result_mode::ResultModeVerify;
use midnight_storage::arena::Sp;
use midnight_storage::db::InMemoryDB;
use midnight_transient_crypto::fab::{AlignmentExt, ValueReprAlignedValue};
use midnight_transient_crypto::hash::transient_hash;
use midnight_zkir_v3::ir_instructions::add::add_offcircuit;
use midnight_zkir_v3::ir_instructions::ec_mul::ec_mul_offcircuit;
use midnight_zkir_v3::ir_instructions::encode::encode_offcircuit;
use midnight_zkir_v3::ir_instructions::from_bytes32::from_bytes32_offcircuit;
use midnight_zkir_v3::ir_instructions::into_bytes32::into_bytes32_offcircuit;
use midnight_zkir_v3::ir_instructions::into_coordinates::into_coordinates_offcircuit;
use midnight_zkir_v3::ir_instructions::inv::inv_offcircuit;
use midnight_zkir_v3::ir_instructions::mul::mul_offcircuit;
use minocrab::Fr;
use minocrab_contracts::erc20_vault as v;
use minocrab_contracts::signet_v1::{hash_domain, ETHEREUM_CAIP2_ID};
use minocrab_zkir::v3::{IrSource, IrType, IrValue};
use sha2::{Digest, Sha256};

pub type VmOp = Op<ResultModeVerify, InMemoryDB>;

pub fn corpus_zkir_named(name: &str) -> IrSource {
    let path = format!(
        "{}/../../corpus/zkir/signet-midnight-examples/examples/erc20-vault/contract/src/erc20-vault/zkir/{name}.zkir",
        env!("CARGO_MANIFEST_DIR")
    );
    minocrab_zkir::v3::read_zkir(&path).expect("corpus golden parses")
}

pub fn atom(n: u32) -> AlignmentSegment {
    AlignmentSegment::Atom(AlignmentAtom::Bytes { length: n })
}

pub fn bytesn_value(n: u32, bytes: &[u8]) -> AlignedValue {
    AlignedValue::new(Value(vec![ValueAtom(bytes.to_vec()).normalize()]), Alignment(vec![atom(n)])).unwrap()
}

/// A multi-atom value from its limbs and atom widths.
pub fn aligned(widths: &[u32], limbs: &[Fr]) -> AlignedValue {
    Alignment(widths.iter().map(|&w| atom(w)).collect())
        .parse_field_repr(limbs)
        .expect("limbs match the alignment")
}

pub fn cell(av: AlignedValue) -> StateValue {
    StateValue::Cell(Sp::new(av))
}

/// [hi, lo] Fr slot pair of a Bytes<32>.
pub fn b32_slots(bytes: &[u8; 32]) -> (Fr, Fr) {
    (Fr::from(u64::from(bytes[31])), Fr::from_le_bytes(&bytes[..31]).unwrap())
}

/// A `Bytes<20>` as its single limb.
pub fn b20(bytes: &[u8; 20]) -> Fr {
    Fr::from_le_bytes(bytes).unwrap()
}

/// A `Uint<128>` as its single limb.
pub fn u128_limb(v: u128) -> Fr {
    Fr::from_le_bytes(&v.to_le_bytes()).unwrap()
}

/// `upgradeFromTransient(transientHash(limbs))` — Poseidon over the limbs,
/// then the field element's 31 low bytes as a `Bytes<32>` whose byte 31 is
/// zero (`[hi: 0, lo: f mod 2^248]` in slot terms).
pub fn transient_upgrade(limbs: &[Fr]) -> [u8; 32] {
    let f = transient_hash(limbs);
    let mut le = f.as_le_bytes();
    le.resize(32, 0);
    let mut out = [0u8; 32];
    out[..31].copy_from_slice(&le[..31]);
    out
}

/// `userCommitment(sk)` — `[sk, pad]` since `375071b`: the MPC's
/// key-derivation PATH of a deposit, and the deployer's identity.
pub fn user_commitment(sk: &[u8; 32]) -> [u8; 32] {
    let (p_hi, p_lo) = b32_slots(&pad32(v::USER_PAD));
    let (sk_hi, sk_lo) = b32_slots(sk);
    transient_upgrade(&[sk_hi, sk_lo, p_hi, p_lo])
}

/// `ownershipCommitment(inIndex, sk)` — `[sk, inIndex, pad]`.
pub fn ownership_commitment(in_index: u64, sk: &[u8; 32]) -> [u8; 32] {
    let (p_hi, p_lo) = b32_slots(&pad32(v::REQUEST_PAD));
    let (sk_hi, sk_lo) = b32_slots(sk);
    transient_upgrade(&[sk_hi, sk_lo, Fr::from(in_index), p_hi, p_lo])
}

/// `requestIndex(entry)` — `[pad, evmNonce, argsHash]`.
pub fn request_index(evm_nonce: u64, args_hash: &[u8; 32]) -> [u8; 32] {
    let (p_hi, p_lo) = b32_slots(&pad32(v::REQUEST_INDEX_PAD));
    let (a_hi, a_lo) = b32_slots(args_hash);
    transient_upgrade(&[p_hi, p_lo, Fr::from(evm_nonce), a_hi, a_lo])
}

/// `<action>ArgsHash(args)` — `[pad(tag), args…]` over the args' limbs.
pub fn args_hash(tag: &str, limbs: &[Fr]) -> [u8; 32] {
    let (p_hi, p_lo) = b32_slots(&pad32(tag));
    let mut all = vec![p_hi, p_lo];
    all.extend_from_slice(limbs);
    transient_upgrade(&all)
}

/// `vaultTokenDomainSeparator(erc20)` — the address `as Field as
/// Bytes<32>` is `[hi: 0, lo: addr]`.
pub fn vault_domain_sep(erc20: &[u8; 20]) -> [u8; 32] {
    let (p_hi, p_lo) = b32_slots(&pad32(v::TOKEN_PAD));
    transient_upgrade(&[p_hi, p_lo, Fr::from(0u64), b20(erc20)])
}

/// `tokenType(vaultTokenDomainSeparator(erc20), self)` — PINNED: the
/// ledger derives the colour (coin-structure/src/contract.rs:58-68).
pub fn vault_color(erc20: &[u8; 20], self_addr: &[u8; 32]) -> [u8; 32] {
    let (d_hi, d_lo) = b32_slots(&vault_domain_sep(erc20));
    let (t_hi, t_lo) = b32_slots(&pad32("midnight:derive_token"));
    let (s_hi, s_lo) = b32_slots(self_addr);
    fab_sha256(vec![atom(32), atom(32), atom(32)], &[t_hi, t_lo, d_hi, d_lo, s_hi, s_lo])
}

/// The `fff3421c` request id the Pending lineage's V2 records keep: Poseidon
/// over the WHOLE record's FAB limbs in slot order, upgraded.
pub fn request_id_of(limbs: &[Fr]) -> [u8; 32] {
    transient_upgrade(limbs)
}

/// `calculateEvmType2TxParamsDigestV1(txParams)` for an empty access list:
/// the tagged head over the scalar fields and the calldata's presence,
/// selector and word count, then each used word chained on.
#[allow(clippy::too_many_arguments)]
pub fn tx_params_digest(
    chain_id: u64,
    nonce: u64,
    priority_fee: u128,
    max_fee: u128,
    gas: u64,
    to: &[u8; 20],
    calldata: Option<(&[u8; 4], &[[u8; 32]])>,
) -> [u8; 32] {
    let (is_some, selector, words): (u64, Fr, &[[u8; 32]]) = match calldata {
        Some((sel, words)) => (1, Fr::from_le_bytes(sel).unwrap(), words),
        None => (0, Fr::from(0u64), &[]),
    };
    let mut acc = transient_hash(&[
        Fr::from(hash_domain::EVM_TYPE2_TX_HEADER),
        Fr::from(chain_id),
        Fr::from(nonce),
        u128_limb(priority_fee),
        u128_limb(max_fee),
        Fr::from(gas),
        b20(to),
        Fr::from(0u64), // value
        Fr::from(is_some),
        selector,
        Fr::from(words.len() as u64),
        Fr::from(0u64), // accessListEntryCount
    ]);
    for w in words {
        let (hi, lo) = b32_slots(w);
        acc = transient_hash(&[Fr::from(hash_domain::EVM_TYPE2_TX_WORD), acc, hi, lo]);
    }
    let mut le = acc.as_le_bytes();
    le.resize(32, 0);
    let mut out = [0u8; 32];
    out[..31].copy_from_slice(&le[..31]);
    out
}

/// `calculateRequestIdV1(RequestIdPreimageV1 { keyVersion, sender, path,
/// ecdsa, evmType2, txParamsDigest, ethereumCaip2Id() })`.
pub fn request_id_v1(key_version: u8, sender: &[u8; 32], path: &[u8; 32], tx_digest: &[u8; 32]) -> [u8; 32] {
    let (s_hi, s_lo) = b32_slots(sender);
    let (p_hi, p_lo) = b32_slots(path);
    let (d_hi, d_lo) = b32_slots(tx_digest);
    let (c_hi, c_lo) = b32_slots(&pad32(ETHEREUM_CAIP2_ID));
    transient_upgrade(&[
        Fr::from(hash_domain::REQUEST_ID),
        Fr::from(u64::from(key_version)),
        s_hi,
        s_lo,
        p_hi,
        p_lo,
        Fr::from(0u64), // algo: ecdsa
        Fr::from(0u64), // txParamType: evmType2
        d_hi,
        d_lo,
        c_hi,
        c_lo,
    ])
}

/// `calculateSignetAttestationDigestV1<len>(requestId, blockHeight,
/// outputKind, output)` — the tag, the id, the height, the verdict, the
/// WIDTH, then the output's limbs.
pub fn attestation_digest(request_id: &[u8; 32], block_height: u64, output_kind: u64, len: usize, output_limbs: &[Fr]) -> [u8; 32] {
    let (r_hi, r_lo) = b32_slots(request_id);
    let mut limbs = vec![
        Fr::from(hash_domain::ATTESTATION_DIGEST),
        r_hi,
        r_lo,
        Fr::from(block_height),
        Fr::from(output_kind),
        Fr::from(len as u64),
    ];
    limbs.extend_from_slice(output_limbs);
    transient_upgrade(&limbs)
}

pub fn scalar(v: u64) -> IrValue {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&v.to_le_bytes());
    from_bytes32_offcircuit(&IrType::Secp256k1Scalar, &bytes).unwrap()
}

pub fn natives(v: &IrValue) -> Vec<Fr> {
    encode_offcircuit(v)
        .into_iter()
        .map(|x| match x {
            IrValue::Native(f) => f,
            other => panic!("encode produced non-native {other:?}"),
        })
        .collect()
}

/// SHA-256 over the FAB binary of `limbs` laid out per `segments` — the
/// off-circuit persistent_hash.
pub fn fab_sha256(segments: Vec<AlignmentSegment>, limbs: &[Fr]) -> [u8; 32] {
    let value = Alignment(segments).parse_field_repr(limbs).expect("limbs match the alignment");
    let mut repr = Vec::new();
    ValueReprAlignedValue(value).binary_repr(&mut repr);
    Sha256::digest(&repr).into()
}

pub fn pad32(s: &str) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[..s.len()].copy_from_slice(s.as_bytes());
    bytes
}

/// Sign `digest` (big-endian integer, RFC 6979) via upstream off-circuit
/// helpers; returns (r_bytes32_le, s_bytes32_le, pk). The LE forms are the
/// circuit-input form `verifyRespondBidirectionalEventV1` takes.
pub fn sign(digest: &[u8; 32], d: &IrValue, k: &IrValue) -> ([u8; 32], [u8; 32], IrValue) {
    let generator = IrValue::Secp256k1Point(k256::K256::generator());
    let mut le = *digest;
    le.reverse();
    let z = from_bytes32_offcircuit(&IrType::Secp256k1Scalar, &le).unwrap();

    let r_point = ec_mul_offcircuit(&generator, k).unwrap();
    let (x, _y) = into_coordinates_offcircuit(&r_point).unwrap();
    let IrValue::Bytes32(x_le) = into_bytes32_offcircuit(&x).unwrap() else {
        panic!("into_bytes32 yields Bytes32");
    };
    let r = from_bytes32_offcircuit(&IrType::Secp256k1Scalar, &x_le).unwrap();

    let rd = mul_offcircuit(&r, d).unwrap();
    let z_rd = add_offcircuit(&z, &rd).unwrap();
    let k_inv = inv_offcircuit(k).unwrap();
    let s = mul_offcircuit(&k_inv, &z_rd).unwrap();

    let IrValue::Bytes32(r_le) = into_bytes32_offcircuit(&r).unwrap() else {
        panic!()
    };
    let IrValue::Bytes32(s_le) = into_bytes32_offcircuit(&s).unwrap() else {
        panic!()
    };
    let pk = ec_mul_offcircuit(&generator, d).unwrap();
    (r_le, s_le, pk)
}

/// `coinCommitment(coin, recipient)` off-circuit — `is_left`/`data` per
/// the CoinPreimage.
pub fn coin_commitment_of(nonce: &(Fr, Fr), color: &[u8; 32], value: u128, is_left: bool, data: &[u8; 32]) -> [u8; 32] {
    let prefix = Fr::from_le_bytes(b"midnight:zswap-cc[v1]").unwrap();
    let (c_hi, c_lo) = b32_slots(color);
    let (d_hi, d_lo) = b32_slots(data);
    fab_sha256(
        vec![atom(21), atom(32), atom(32), atom(16), atom(1), atom(32)],
        &[prefix, nonce.0, nonce.1, c_hi, c_lo, u128_limb(value), Fr::from(u64::from(is_left)), d_hi, d_lo],
    )
}

/// `coinNullifier(coin, addr)` off-circuit — the `zswap-cn` domain,
/// dataType 0.
pub fn coin_nullifier_of(nonce: &(Fr, Fr), color: &[u8; 32], value: u128, addr: &[u8; 32]) -> [u8; 32] {
    let prefix = Fr::from_le_bytes(b"midnight:zswap-cn[v1]").unwrap();
    let (c_hi, c_lo) = b32_slots(color);
    let (a_hi, a_lo) = b32_slots(addr);
    fab_sha256(
        vec![atom(21), atom(32), atom(32), atom(16), atom(1), atom(32)],
        &[prefix, nonce.0, nonce.1, c_hi, c_lo, u128_limb(value), Fr::from(0u64), a_hi, a_lo],
    )
}

/// `evolveNonce` as lowered: `transientHash([tag, nonce.lo])`, upgraded as
/// `[hi: 0, lo: mod 2^248]`.
pub fn evolved_nonce(nonce: &[u8; 32]) -> (Fr, Fr) {
    let tag = Fr::from_le_bytes(b"midnight:kernel:nonce_evolve").unwrap();
    let (_hi, lo) = b32_slots(nonce);
    b32_slots(&transient_upgrade(&[tag, lo]))
}

pub fn abi_addr_word(addr: &[u8; 20]) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(addr);
    w
}

pub fn abi_num_word(v: u128) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[16..].copy_from_slice(&v.to_be_bytes());
    w
}

/// A schema literal's slot limbs: one limb at 31 bytes or fewer, else the
/// FAB limbing (the leftover tail bytes 31..n FIRST, then bytes 0..31).
pub fn schema_limbs(schema: &[u8]) -> Vec<Fr> {
    if schema.len() <= 31 {
        vec![Fr::from_le_bytes(schema).unwrap()]
    } else {
        assert!(schema.len() <= 62, "two-limb schemas only");
        vec![Fr::from_le_bytes(&schema[31..]).unwrap(), Fr::from_le_bytes(&schema[..31]).unwrap()]
    }
}

/// The point at infinity as a `Secp256k1Point` value — `G * 0`.
///
/// Used by the adversarial sweeps: it is a *valid* public key (for secret
/// key 0) that authenticates every signature made under that key, so any
/// place a public key is accepted without a non-identity check is a hole.
pub fn identity_point() -> IrValue {
    ec_mul_offcircuit(&IrValue::Secp256k1Point(k256::K256::generator()), &scalar(0)).unwrap()
}

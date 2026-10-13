//! The treasury's REFERENCE MODEL: what `send`, `complete` and `refund`
//! read, write, witness and take as arguments — in ordinary Rust, so a
//! hand-built `ProofPreimage` can be handed to the simulator.
//!
//! The same shape as `tests/vault_pending/model.rs`, three circuits wide.
//! The protocol primitives (Poseidon commitments, the request id, ECDSA)
//! are the vault harness's, declared by path rather than copied — they are
//! protocol-level and not specific to any block.

use midnight_base_crypto::fab::{AlignedValue, Alignment, AlignmentAtom, AlignmentSegment};
use midnight_curves::k256;
use midnight_transient_crypto::fab::AlignmentExt;
use midnight_transient_crypto::hash::{transient_commit, transient_hash};
use midnight_transient_crypto::proofs::{KeyLocation, ProofPreimage};
use midnight_zkir_v3::ir_instructions::ec_mul::ec_mul_offcircuit;
use minocrab::Fr;
use minocrab_contracts::erc20_vault::{TRANSFER_SELECTOR, VAULT_PATH};
use minocrab_contracts::evm_flow::REFUND_PAD;
use minocrab_contracts::signet_v1::{output_kind, schema, OutputSchema, ETHEREUM_CAIP2_ID};
use minocrab_zkir::v3::IrValue;

use super::ops;
use super::prims::*;

// ---- the ledger fields, by declaration index ---------------------------------
//
// `signet: Signet` is FOUR fields under V1 (the request nonce and the caip2
// id went: notes/vault-flush.org §6), then `transfers: Pending<…, 2>` is two.

pub const SIGNET_SIGNER: u8 = 0;
pub const MPC_RESPONSE_KEY: u8 = 1;
pub const MPC_KEY_VERSION: u8 = 2;
pub const EVM_CHAIN_ID: u8 = 3;
pub const TRANSFERS_RECORDS: u8 = 4;
pub const TRANSFERS_ENVS: u8 = 5;

/// The attested width of `erc20::Transfer`'s `bool` — one Borsh byte, the
/// `LEN` inside the digest.
pub const TRANSFER_OUTPUT_LEN: usize = 1;

/// The treasury's output schema, as the record carries it.
pub type TransferSchema = <schema::Success as OutputSchema>::At<minocrab::Public>;

/// The circuit's own `kernel.self()`.
pub const SELF_ADDR: [u8; 32] = {
    let mut a = [0u8; 32];
    let s = b"treasury-addr";
    let mut i = 0;
    while i < s.len() {
        a[i] = s[i];
        i += 1;
    }
    a[31] = 0x37;
    a
};

/// A `[u8; 32]` from a short tag and a distinguishing top byte.
pub fn tagged32(tag: &[u8], top: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..tag.len()].copy_from_slice(tag);
    out[31] = top;
    out
}

/// An `AlignedValue` from an explicit atom list and limbs, in order.
pub fn aligned_atoms(atoms: &[minocrab::AlignmentAtom], limbs: &[Fr]) -> AlignedValue {
    Alignment(atoms.iter().cloned().map(AlignmentSegment::Atom).collect())
        .parse_field_repr(limbs)
        .expect("limbs match the alignment")
}

/// A `Secp256k1Point` as its cell value.
pub fn point_av(point: &IrValue) -> AlignedValue {
    aligned_atoms(
        &minocrab_contracts::common::secp256k1_point_atoms(),
        &natives(point),
    )
}

// ---- the environment ----------------------------------------------------------

/// The ledger cells every circuit may read, plus the call context.
#[derive(Clone, Debug)]
pub struct Env {
    pub self_addr: [u8; 32],
    pub signer_addr: [u8; 32],
    /// The MPC response key's secret scalar seed.
    pub key_seed: u64,
    /// `mpcKeyVersion`, a CELL under V1 — no circuit takes one.
    pub key_version: u8,
    pub chain_id: u64,
    /// The singleton's `signBidirectional` entry-point hash.
    pub ep: [u8; 32],
}

impl Default for Env {
    fn default() -> Env {
        Env::new()
    }
}

impl Env {
    pub fn new() -> Env {
        Env {
            self_addr: SELF_ADDR,
            signer_addr: tagged32(b"signet-addr", 0x32),
            key_seed: 0xf00d_face,
            key_version: 1,
            chain_id: 11_155_111,
            ep: minocrab_ledger::ep_hash("signBidirectional"),
        }
    }

    pub fn mpc_key(&self) -> IrValue {
        let generator = IrValue::Secp256k1Point(k256::K256::generator());
        ec_mul_offcircuit(&generator, &scalar(self.key_seed)).unwrap()
    }

    pub fn mpc_key_av(&self) -> AlignedValue {
        point_av(&self.mpc_key())
    }

    pub fn kernel_self(&self) -> Vec<VmOp> {
        ops::kernel_self(&self.self_addr)
    }
    pub fn read_mpc_key(&self) -> Vec<VmOp> {
        ops::read(MPC_RESPONSE_KEY, false, self.mpc_key_av())
    }
    pub fn read_signer(&self) -> Vec<VmOp> {
        ops::read(SIGNET_SIGNER, false, bytesn_value(32, &self.signer_addr))
    }
    pub fn read_key_version(&self) -> Vec<VmOp> {
        ops::read(MPC_KEY_VERSION, false, bytesn_value(1, &[self.key_version]))
    }
    pub fn read_chain_id(&self) -> Vec<VmOp> {
        ops::read(
            EVM_CHAIN_ID,
            false,
            bytesn_value(8, &self.chain_id.to_le_bytes()),
        )
    }
}

/// The `ProofPreimage` a call implies.
pub fn preimage_of(inputs: Vec<Fr>, witnesses: Vec<Fr>, ops: &[VmOp], rand: Fr) -> ProofPreimage {
    let comm = transient_commit(&inputs[..], rand);
    ProofPreimage {
        public_transcript_inputs: ops::transcript_of(ops),
        public_transcript_outputs: ops::outputs_of(ops),
        inputs,
        private_transcript: witnesses,
        binding_input: 0.into(),
        communications_commitment: Some((comm, rand)),
        key_location: KeyLocation(std::borrow::Cow::Borrowed("minocrab-contracts-test")),
    }
}

// ---- Commit<T, Tag>: `hi` is NOT forced to zero ------------------------------

/// `evm_flow::Commit::digest_of` off-circuit: `transientHash([pad.hi,
/// pad.lo, value_limbs…, id.hi, id.lo])`, then the RAW
/// `div_mod_power_of_two` split — byte for byte the construction
/// `signet_flow::Commit` performs, which is why an `Owned` environment's
/// bytes equal the deployed vault's.
pub fn commit_digest_of(domain: &str, value_limbs: &[Fr], request_id: &[u8; 32]) -> [u8; 32] {
    let (pad_hi, pad_lo) = b32_slots(&pad32(domain));
    let mut inputs = vec![pad_hi, pad_lo];
    inputs.extend_from_slice(value_limbs);
    let (id_hi, id_lo) = b32_slots(request_id);
    inputs.push(id_hi);
    inputs.push(id_lo);
    let f = transient_hash(&inputs);
    let mut le = f.as_le_bytes();
    le.resize(32, 0);
    let mut out = [0u8; 32];
    out.copy_from_slice(&le[..32]);
    out
}

/// The owner commitment `Owned` stores, under `OwnerTag::PAD`.
pub fn owner_commit_of(sk: &[u8; 32], request_id: &[u8; 32]) -> [u8; 32] {
    let (sk_hi, sk_lo) = b32_slots(sk);
    commit_digest_of(REFUND_PAD, &[sk_hi, sk_lo], request_id)
}

// ---- the V1 signing record ----------------------------------------------------

/// The `transfer(to, amount)` record `send` files — `erc20::Transfer`'s
/// selector, gas limit and fee envelope, spelled out here so the model does
/// not read them off the type it is checking.
///
/// V1 since M44 rung D: `keyVersion` leads, the request nonce is GONE, the
/// destination is the constant `pad(32, "eip155:1")`, and the record ends
/// with `signatureDest`, `params` and the OUTPUT SCHEMA — so the id is no
/// longer a hash of the whole record but of
/// `RequestIdPreimageV1`, whose transaction enters as a digest
/// (`prims::tx_params_digest`, `prims::request_id_v1`).
#[derive(Clone, Debug)]
pub struct Req {
    pub evm_nonce: u64,
    pub token: [u8; 20],
    pub to: [u8; 20],
    pub amount: u64,
}

impl Req {
    /// The two ABI words `transfer(to, amount)` encodes to.
    pub fn words(&self) -> [[u8; 32]; 2] {
        [
            abi_addr_word(&self.to),
            abi_num_word(u128::from(self.amount)),
        ]
    }

    /// `SignBidirectionalEventV1::limbs()`'s order, off-circuit.
    pub fn limbs(&self, env: &Env) -> Vec<Fr> {
        let (sender_hi, sender_lo) = b32_slots(&env.self_addr);
        let (path_hi, path_lo) = b32_slots(&pad32(VAULT_PATH));
        let (dest_hi, dest_lo) = b32_slots(&pad32(ETHEREUM_CAIP2_ID));
        let mut l = vec![
            Fr::from(u64::from(env.key_version)),
            sender_hi,
            sender_lo,
            path_hi,
            path_lo,
            Fr::from(0u64), // algo: ecdsa
            Fr::from(0u64), // txParamType: evmType2
            Fr::from(env.chain_id),
            Fr::from(self.evm_nonce),
            u128_limb(1_000_000_000),  // FIXED_PRIORITY_FEE
            u128_limb(30_000_000_000), // FIXED_MAX_FEE
            Fr::from(100_000u64),      // ERC20_CALL_GAS
            b20(&self.token),
            Fr::from(0u64), // value
            Fr::from(1u64), // calldata.is_some
            Fr::from_le_bytes(&TRANSFER_SELECTOR).expect("4 bytes fit"),
            Fr::from(2u64), // no_words
        ];
        for w in self.words() {
            let (hi, lo) = b32_slots(&w);
            l.push(hi);
            l.push(lo);
        }
        l.push(Fr::from(0u64)); // access_list_entry_count
        l.push(dest_hi);
        l.push(dest_lo);
        l.push(Fr::from(0u64)); // signatureDest: unused
        l.push(Fr::from(0u64)); // params: 3 zero limbs
        l.push(Fr::from(0u64));
        l.push(Fr::from(0u64));
        l.extend(schema_limbs(schema::Success::BYTES));
        l
    }

    pub fn atoms() -> Vec<AlignmentAtom> {
        minocrab_contracts::signet_v1::SignBidirectionalEventV1::<
            minocrab::Public,
            2,
            TransferSchema,
        >::atoms()
    }

    pub fn av(&self, env: &Env) -> AlignedValue {
        aligned_atoms(&Self::atoms(), &self.limbs(env))
    }

    /// `calculateEvmType2TxParamsDigestV1` over the two USED words.
    pub fn tx_digest(&self, env: &Env) -> [u8; 32] {
        let words = self.words();
        tx_params_digest(
            env.chain_id,
            self.evm_nonce,
            1_000_000_000,
            30_000_000_000,
            100_000,
            &self.token,
            Some((&TRANSFER_SELECTOR, &words)),
        )
    }

    pub fn request_id(&self, env: &Env) -> [u8; 32] {
        request_id_v1(
            env.key_version,
            &env.self_addr,
            &pad32(VAULT_PATH),
            &self.tx_digest(env),
        )
    }
}

/// The notification's `depth ‖ path` payload — the treasury's record map is
/// field 5 of a NARROW block, so the path is one element deep.
pub fn notification_payload_limbs(self_addr: &[u8; 32], records_field: u8) -> Vec<Fr> {
    let mut bytes = [0u8; 128];
    bytes[..32].copy_from_slice(self_addr);
    bytes[32] = 1; // depth
    bytes[33] = records_field;
    let mut limbs: Vec<Fr> = bytes
        .chunks(31)
        .map(|c| Fr::from_le_bytes(c).unwrap())
        .collect();
    limbs.reverse();
    limbs
}

/// The cross-contract-call args a request's notification commits to.
pub fn call_args(self_addr: &[u8; 32], records_field: u8, request_id: &[u8; 32]) -> Vec<Fr> {
    let (rid_hi, rid_lo) = b32_slots(request_id);
    let mut args = vec![rid_hi, rid_lo, Fr::from(1u64)];
    args.extend(notification_payload_limbs(self_addr, records_field));
    args
}

/// The cross-contract call's own witnesses: `cc-rand`, then the entry-point
/// hash's two limbs.
pub fn call_witnesses(env: &Env, cc_rand: Fr) -> Vec<Fr> {
    let (ep_hi, ep_lo) = b32_slots(&env.ep);
    vec![cc_rand, ep_hi, ep_lo]
}

/// A ticket's argument slots: `respond: RespondBidirectionalEvent` then
/// `serializedOutput` — signed over the V1 digest the VERDICT implies
/// (`prims::attestation_digest`: tag, id, height, verdict, WIDTH, output).
///
/// `signed_width` and `signed_output_limbs` are the EMPTY output (0, no
/// limbs) for a `failed` or `unviable` verdict and the one `Bool` byte for
/// an `executed` one. That difference — in the width as much as in the limbs
/// — is why `Pending::refund` hashes twice.
///
/// Slot order is the derive's: `requestId` (two), `blockHeight`,
/// `outputKind`, `serializedOutputLength`, `digest` (two), `signature`
/// (`bigR.x` two, `bigR.y` two, `s` two, `recoveryId`), then the output.
/// [`OUTPUT_KIND_SLOT`] names the one the tests relabel.
#[allow(clippy::too_many_arguments)]
pub fn ticket_inputs(
    key_seed: u64,
    nonce_seed: u64,
    request_id: &[u8; 32],
    block_height: u64,
    output_kind: u64,
    signed_width: usize,
    signed_output_limbs: &[Fr],
    ticket_output: Fr,
) -> Vec<Fr> {
    let digest = attestation_digest(
        request_id,
        block_height,
        output_kind,
        signed_width,
        signed_output_limbs,
    );
    let (rx_le, s_le, _pk) = sign(&digest, &scalar(key_seed), &scalar(nonce_seed));
    let (rid_hi, rid_lo) = b32_slots(request_id);
    let (d_hi, d_lo) = b32_slots(&digest);
    let (rx_hi, rx_lo) = b32_slots(&rx_le);
    let (s_hi, s_lo) = b32_slots(&s_le);
    vec![
        rid_hi,
        rid_lo,
        Fr::from(block_height),
        Fr::from(output_kind),
        Fr::from(signed_width as u64),
        // `digest` on the event is for off-chain readers; nothing in the
        // circuit reads it, so the honest value is the real one.
        d_hi,
        d_lo,
        rx_hi,
        rx_lo,
        Fr::from(0u64),
        Fr::from(0u64), // bigR.y (unread)
        s_hi,
        s_lo,
        Fr::from(0u64), // recoveryId (unread)
        ticket_output,
    ]
}

/// The `outputKind` argument slot of a ticket — index 3, by the order above.
pub const OUTPUT_KIND_SLOT: usize = 3;

// ---- send ---------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct SendScenario {
    pub env: Env,
    pub sk: [u8; 32],
    pub req: Req,
    pub request_exists: bool,
    pub cc_rand: Fr,
}

impl Default for SendScenario {
    fn default() -> SendScenario {
        SendScenario::new()
    }
}

impl SendScenario {
    pub fn new() -> SendScenario {
        SendScenario {
            env: Env::new(),
            sk: tagged32(b"treasurer", 0x22),
            req: Req {
                evm_nonce: 11,
                token: *b"erc20-token-contract",
                to: *b"dest-evm-address-20b",
                amount: 98_765,
            },
            request_exists: false,
            cc_rand: Fr::from(0x0d_00ffu64),
        }
    }

    pub fn request_id(&self) -> [u8; 32] {
        self.req.request_id(&self.env)
    }

    pub fn owner_commitment(&self) -> [u8; 32] {
        owner_commit_of(&self.sk, &self.request_id())
    }

    /// `Owned<Amount>`: the commitment's `Bytes<32>` then the `Uint<64>`.
    pub fn env_limbs(&self) -> Vec<Fr> {
        let (c_hi, c_lo) = b32_slots(&self.owner_commitment());
        vec![c_hi, c_lo, Fr::from(self.req.amount)]
    }

    pub fn env_av(&self) -> AlignedValue {
        aligned(&[32, 8], &self.env_limbs())
    }

    pub fn inputs(&self) -> Vec<Fr> {
        vec![
            Fr::from(self.req.evm_nonce),
            b20(&self.req.token),
            b20(&self.req.to),
            Fr::from(self.req.amount),
        ]
    }

    pub fn witnesses(&self) -> Vec<Fr> {
        let (hi, lo) = b32_slots(&self.sk);
        let mut w = vec![hi, lo];
        w.extend(call_witnesses(&self.env, self.cc_rand));
        w
    }

    pub fn ops(&self) -> Vec<VmOp> {
        let rid = self.request_id();
        let mut o = self.env.kernel_self();
        o.extend(self.env.read_chain_id());
        o.extend(self.env.read_key_version());
        o.extend(ops::member(TRANSFERS_RECORDS, &rid, self.request_exists));
        o.extend(ops::insert(TRANSFERS_RECORDS, &rid, self.req.av(&self.env)));
        o.extend(ops::insert(TRANSFERS_ENVS, &rid, self.env_av()));
        o.extend(self.env.read_signer());
        let comm = transient_commit(
            &call_args(&self.env.self_addr, TRANSFERS_RECORDS, &rid)[..],
            self.cc_rand,
        );
        o.extend(ops::claim_contract_call(
            &self.env.signer_addr,
            &self.env.ep,
            comm,
        ));
        o
    }

    pub fn preimage(&self) -> ProofPreimage {
        preimage_of(self.inputs(), self.witnesses(), &self.ops(), self.cc_rand)
    }
}

// ---- the settle half ----------------------------------------------------------

/// Which attestation a settle scenario presents.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Attestation {
    /// This call's kind with the flag set: the only thing `complete` takes.
    ExecutedTrue,
    /// This call's kind with the flag clear — a mined `transfer` that moved
    /// nothing. `refund` takes it; `complete` must not.
    ExecutedFalse,
    /// The MPC's failure kind: reverted, never mined, or undecodable. Its
    /// signed preimage is the kind byte ALONE.
    NeverExecuted,
}

impl Attestation {
    /// The MPC's VERDICT — `OutputKind`, where the `fff3421c` lineage had a
    /// response kind byte.
    pub fn output_kind(self) -> u64 {
        match self {
            Attestation::ExecutedTrue | Attestation::ExecutedFalse => output_kind::EXECUTED,
            Attestation::NeverExecuted => output_kind::FAILED,
        }
    }

    /// The attested WIDTH inside the digest: the `bool`'s one byte for an
    /// execution, zero for a non-execution.
    pub fn signed_width(self) -> usize {
        match self {
            Attestation::ExecutedTrue | Attestation::ExecutedFalse => TRANSFER_OUTPUT_LEN,
            Attestation::NeverExecuted => 0,
        }
    }

    /// The output limbs inside the signed preimage.
    pub fn signed_output_limbs(self) -> Vec<Fr> {
        match self {
            Attestation::ExecutedTrue => vec![Fr::from(1u64)],
            Attestation::ExecutedFalse => vec![Fr::from(0u64)],
            // A failed or unviable request has nothing to decode.
            Attestation::NeverExecuted => vec![],
        }
    }

    /// What the ticket's output slot carries. For a non-execution the slot
    /// is outside the signed preimage, so the prover picks it — zero, which
    /// satisfies the `Bytes<1>` range constraint.
    pub fn ticket_output(self) -> Fr {
        match self {
            Attestation::ExecutedTrue => Fr::from(1u64),
            Attestation::ExecutedFalse | Attestation::NeverExecuted => Fr::from(0u64),
        }
    }
}

/// A `complete` or a `refund` against a filed request.
#[derive(Clone, Debug)]
pub struct SettleScenario {
    pub send: SendScenario,
    pub attestation: Attestation,
    /// Is the entry still in the map?
    pub pending: bool,
    /// Whose secret the refunder presents (`None` = the sender's own).
    pub presented_sk: Option<[u8; 32]>,
    pub own_pk: [u8; 32],
    pub nonce_seed: u64,
    /// The height the MPC attests, disclosed by both settles.
    pub block_height: u64,
}

impl SettleScenario {
    pub fn new(attestation: Attestation) -> SettleScenario {
        SettleScenario {
            send: SendScenario::new(),
            attestation,
            pending: true,
            presented_sk: None,
            own_pk: tagged32(b"own-public-key", 0x55),
            nonce_seed: 0x5eed_1234,
            block_height: 21_000_000,
        }
    }

    pub fn sk(&self) -> [u8; 32] {
        self.presented_sk.unwrap_or(self.send.sk)
    }

    pub fn inputs(&self) -> Vec<Fr> {
        ticket_inputs(
            self.send.env.key_seed,
            self.nonce_seed,
            &self.send.request_id(),
            self.block_height,
            self.attestation.output_kind(),
            self.attestation.signed_width(),
            &self.attestation.signed_output_limbs(),
            self.attestation.ticket_output(),
        )
    }

    /// `complete` witnesses NOTHING — that is the property, not an economy.
    pub fn complete_witnesses(&self) -> Vec<Fr> {
        vec![]
    }

    /// `refund` witnesses a fresh secret and the caller's own public key.
    pub fn refund_witnesses(&self) -> Vec<Fr> {
        let (hi, lo) = b32_slots(&self.sk());
        let (pk_hi, pk_lo) = b32_slots(&self.own_pk);
        vec![hi, lo, pk_hi, pk_lo]
    }

    /// The settle's op stream. The record is REMOVED WITHOUT BEING READ:
    /// nothing in a V1 settle needs a field of it (there is no kind byte and
    /// no format version to re-assert), so `Pending::consume` is a
    /// membership check and two removals.
    pub fn ops(&self) -> Vec<VmOp> {
        let rid = self.send.request_id();
        let mut o = self.send.env.read_mpc_key();
        o.extend(ops::member(TRANSFERS_RECORDS, &rid, self.pending));
        o.extend(ops::remove(TRANSFERS_RECORDS, &rid));
        o.extend(ops::lookup(TRANSFERS_ENVS, &rid, self.send.env_av()));
        o.extend(ops::remove(TRANSFERS_ENVS, &rid));
        o
    }

    pub fn complete_preimage(&self) -> ProofPreimage {
        preimage_of(
            self.inputs(),
            self.complete_witnesses(),
            &self.ops(),
            Fr::from(0xc0_00deu64),
        )
    }

    pub fn refund_preimage(&self) -> ProofPreimage {
        preimage_of(
            self.inputs(),
            self.refund_witnesses(),
            &self.ops(),
            Fr::from(0xde_ad01u64),
        )
    }
}

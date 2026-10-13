//! The `erc20_vault_pending` REFERENCE MODEL, mirroring `tests/vault/model.rs`
//! (M35 rung C's spec-harness extension) but over the `Pending`-based
//! lineage: a twenty-two-field, thirteen-declaration block, V2 Borsh
//! signing records, `Pending`/`Fired` request+settle in one call each, and
//! `Commit<T>` refund commitments whose digest's `hi` limb is NOT forced
//! to zero (unlike `upgradeFromTransient`).
//!
//! Every op-sequence claim below was checked against the real circuit's
//! dumped `.zkir` (`MINOCRAB_ZKIR_DUMP=... cargo test --test zkir_dump --
//! --ignored`), instruction by instruction, for `initialize`,
//! `approve_router`, `withdraw`, `claim` and `complete_swap` — see
//! notes/signet-async.org "Rung C, the spec harness". The remaining twelve
//! circuits follow the same two skeletons (`file_request_ops` /
//! `consume_ops`) mechanically, confirmed against the source
//! (`erc20_vault_pending.rs`) read line for line.

use midnight_base_crypto::fab::{Alignment, AlignmentSegment, AlignedValue};
use midnight_curves::k256;
use midnight_transient_crypto::fab::AlignmentExt;
use midnight_transient_crypto::hash::{transient_commit, transient_hash};
use midnight_transient_crypto::proofs::{KeyLocation, ProofPreimage};
use midnight_zkir_v3::ir_instructions::ec_mul::ec_mul_offcircuit;
use minocrab::Fr;
use minocrab_contracts::erc20_vault::{
    APPROVE_SELECTOR, DEPOSIT_SELECTOR, EXACT_OUTPUT_SINGLE_SELECTOR, REDEEM_SELECTOR,
    REDEEM_WORDS, SUPPLY_WORDS, SWAP_WORDS, TRANSFER_SELECTOR, USER_PAD, VAULT_PATH, VAULT_WORDS,
};
use minocrab_contracts::evm::erc4626::CALL_GAS as LENDING_GAS;
use minocrab_contracts::evm_flow::REFUND_PAD;
// The `RESPONSE_KIND_*` constants are no longer part of this lineage's wire:
// V1 records carry an output SCHEMA where they carried a kind byte, and the
// MPC's verdict is `signet_v1::output_kind`. They survive on
// `erc20_vault_pending` only as the retired fork's documented numbering.
use minocrab_contracts::erc20_vault_pending::VAULT_TOKEN_TAG;
use minocrab_contracts::signet_v1::{output_kind, schema, OutputSchema, ETHEREUM_CAIP2_ID};
use minocrab_zkir::v3::IrValue;

use super::exec::PreState;
use super::ops;
use super::prims::*;

// ---- the ledger fields, by declaration index (confirmed against the
// dumped .zkir and tests/erc20_vault_pending.rs's record_path pins) -------

pub const INITIALIZED: u8 = 0;
pub const DEPLOYER: u8 = 1;
pub const VAULT_EVM_ADDRESS: u8 = 2;
pub const UNISWAP_ROUTER: u8 = 3;
pub const SIGNET_SIGNER: u8 = 4;
pub const MPC_RESPONSE_KEY: u8 = 5;
/// `mpcKeyVersion` — a CELL under V1, where V2 had a request-nonce counter
/// and a caip2 cell in these two positions (notes/vault-flush.org §6). Every
/// field below it moved down one at M44 rung D.
pub const MPC_KEY_VERSION: u8 = 6;
pub const EVM_CHAIN_ID: u8 = 7;
pub const DEPOSITS_RECORDS: u8 = 8;
pub const DEPOSITS_ENVS: u8 = 9;
pub const WITHDRAWALS_RECORDS: u8 = 10;
pub const WITHDRAWALS_ENVS: u8 = 11;
pub const SWAPS_RECORDS: u8 = 12;
pub const SWAPS_ENVS: u8 = 13;
pub const APPROVALS: u8 = 14;
pub const STATA_UNDERLYING: u8 = 15;
pub const STATA_TOKEN: u8 = 16;
pub const SUPPLIES_RECORDS: u8 = 17;
pub const SUPPLIES_ENVS: u8 = 18;
pub const REDEEMS_RECORDS: u8 = 19;
pub const REDEEMS_ENVS: u8 = 20;

// ---- the V1 output vocabulary ---------------------------------------------------
//
// Where the Borsh lineage had a response KIND byte per action, V1 has an
// output SCHEMA per filing and an attested WIDTH per return. The schema is
// in the record (and so outside the request id, which hashes a transaction
// digest); the width is inside the signed digest, which is why an output of
// the wrong width cannot verify.

/// `Deposit`, `Withdrawal` and `Approval` — the ERC-20 flag.
pub const SUCCESS_SCHEMA: &[u8] = <schema::Success as OutputSchema>::BYTES;
/// `Swap` — `exactOutputSingle`'s spend.
pub const AMOUNT_IN_SCHEMA: &[u8] = <schema::AmountIn as OutputSchema>::BYTES;
/// `Supply` — the ERC-4626 shares minted.
pub const SHARES_SCHEMA: &[u8] = <schema::Shares as OutputSchema>::BYTES;
/// `Redeem` — the ERC-4626 assets returned.
pub const ASSETS_SCHEMA: &[u8] = <schema::Assets as OutputSchema>::BYTES;

/// `AbiReturn::LEN` for a `Bool`: one Borsh byte.
pub const FLAG_WIDTH: usize = 1;
/// `AbiReturn::LEN` for every `uint256`: thirty-two.
pub const WORD_WIDTH: usize = 32;

/// A `uint256` attested output as its two `B32` limbs. A `u64` value sits
/// entirely in the low 31 bytes of the little-endian word, so the high limb
/// (byte 31) is zero — which is also why the narrowing's byte-31 check
/// passes for every value this model attests.
pub fn word_output_limbs(v: u64) -> Vec<Fr> {
    vec![Fr::from(0u64), Fr::from(v)]
}

/// The circuit's own `kernel.self()`.
pub const SELF_ADDR: [u8; 32] = {
    let mut a = [0u8; 32];
    let s = b"vault-addr";
    let mut i = 0;
    while i < s.len() {
        a[i] = s[i];
        i += 1;
    }
    a[31] = 0x31;
    a
};

/// `userCommitment(sk)` for THIS lineage — `upgradeFromTransient(
/// transientHash([pad(32, "vault:user:"), sk]))`, the `fff3421c` order
/// `common::commitment_transient` keeps. The compat port's shared
/// `prims::user_commitment` moved to secret-first (`[sk, pad]`) with
/// upstream's flush pattern at `375071b`; the `Pending` lineage is our own
/// design and still calls `commitment_transient`, so it keeps the pad-first
/// construction. `USER_PAD` is the one shared constant.
pub fn pending_user_commitment(sk: &[u8; 32]) -> [u8; 32] {
    let (p_hi, p_lo) = b32_slots(&pad32(USER_PAD));
    let (sk_hi, sk_lo) = b32_slots(sk);
    transient_upgrade(&[p_hi, p_lo, sk_hi, sk_lo])
}

/// A `[u8; 32]` from a short tag and a distinguishing top byte.
pub fn tagged32(tag: &[u8], top: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..tag.len()].copy_from_slice(tag);
    out[31] = top;
    out
}

// ---- the environment ------------------------------------------------------------------

/// The ledger cells every circuit may read, plus the call context.
#[derive(Clone, Debug)]
pub struct Env {
    pub initialized: u64,
    pub deployer_sk: [u8; 32],
    pub vault_evm: [u8; 20],
    pub router: [u8; 20],
    pub stata_underlying: [u8; 20],
    pub stata_token: [u8; 20],
    pub self_addr: [u8; 32],
    pub signer_addr: [u8; 32],
    /// The MPC response key's secret scalar seed.
    pub key_seed: u64,
    /// The MPC response key as a POINT, big-endian affine coordinates,
    /// overriding `key_seed` when set: the key a `SigNetSim` derives for
    /// this contract, whose secret the model does not hold — the settle
    /// then verifies the sim's signature, not one the model made.
    pub mpc_key_xy: Option<([u8; 32], [u8; 32])>,
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
            initialized: 1,
            deployer_sk: tagged32(b"deployer", 0x11),
            vault_evm: *b"vault-evm-addr-20byt",
            router: *b"uniswap-router-20byt",
            stata_underlying: *b"stata-underlying-usd",
            stata_token: *b"stata-token-wrapper!",
            self_addr: SELF_ADDR,
            signer_addr: tagged32(b"signet-addr", 0x32),
            key_seed: 0xf00d_face,
            mpc_key_xy: None,
            key_version: 1,
            chain_id: 11_155_111,
            ep: minocrab_ledger::ep_hash("signBidirectional"),
        }
    }

    pub fn mpc_key(&self) -> IrValue {
        if let Some((x, y)) = self.mpc_key_xy {
            let x = k256::Fp::from_bytes(&x.into()).expect("a coordinate below the field modulus");
            let y = k256::Fp::from_bytes(&y.into()).expect("a coordinate below the field modulus");
            let point = k256::K256Affine::from_xy(x, y).expect("a point on secp256k1");
            return IrValue::Secp256k1Point(k256::K256::from(point));
        }
        let generator = IrValue::Secp256k1Point(k256::K256::generator());
        ec_mul_offcircuit(&generator, &scalar(self.key_seed)).unwrap()
    }

    pub fn mpc_key_av(&self) -> AlignedValue {
        point_av(&self.mpc_key())
    }

    /// `userCommitment(deployer_sk)` — the `deployer` cell, in this
    /// lineage's pad-first order (see `pending_user_commitment`).
    pub fn deployer(&self) -> [u8; 32] {
        pending_user_commitment(&self.deployer_sk)
    }

    pub fn pre_state(&self) -> PreState {
        PreState {
            deployer: self.deployer(),
            vault_evm_address: self.vault_evm,
            uniswap_router: self.router,
            signer: self.signer_addr,
            mpc_response_key: Some(self.mpc_key_av()),
            key_version: self.key_version,
            evm_chain_id: self.chain_id,
            initialized: self.initialized,
            stata_underlying: self.stata_underlying,
            stata_token: self.stata_token,
            ..Default::default()
        }
    }

    // -- reads every circuit shares --
    pub fn kernel_self(&self) -> Vec<VmOp> {
        ops::kernel_self(&self.self_addr)
    }
    pub fn read_initialized(&self) -> Vec<VmOp> {
        ops::read(INITIALIZED, true, bytesn_value(8, &self.initialized.to_le_bytes()))
    }
    pub fn read_deployer(&self) -> Vec<VmOp> {
        ops::read(DEPLOYER, false, bytesn_value(32, &self.deployer()))
    }
    pub fn read_vault_evm(&self) -> Vec<VmOp> {
        ops::read(VAULT_EVM_ADDRESS, false, bytesn_value(20, &self.vault_evm))
    }
    pub fn read_router(&self) -> Vec<VmOp> {
        ops::read(UNISWAP_ROUTER, false, bytesn_value(20, &self.router))
    }
    pub fn read_stata_underlying(&self) -> Vec<VmOp> {
        ops::read(STATA_UNDERLYING, false, bytesn_value(20, &self.stata_underlying))
    }
    pub fn read_stata_token(&self) -> Vec<VmOp> {
        ops::read(STATA_TOKEN, false, bytesn_value(20, &self.stata_token))
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
        ops::read(EVM_CHAIN_ID, false, bytesn_value(8, &self.chain_id.to_le_bytes()))
    }
}

/// A `Secp256k1Point` as its cell value.
pub fn point_av(point: &IrValue) -> AlignedValue {
    aligned_atoms(&minocrab_contracts::common::secp256k1_point_atoms(), &natives(point))
}

/// An `AlignedValue` from an explicit atom list and limbs, in order —
/// unlike `prims::aligned` (which only takes plain widths), this keeps a
/// record's or a point's own [`minocrab::AlignmentAtom`] list, which may
/// contain non-`Bytes` atoms (a `Field`, for a point's fifth limb).
pub fn aligned_atoms(atoms: &[minocrab::AlignmentAtom], limbs: &[Fr]) -> AlignedValue {
    Alignment(atoms.iter().cloned().map(AlignmentSegment::Atom).collect())
        .parse_field_repr(limbs)
        .expect("limbs match the alignment")
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

// ---- vaultTokenDomainSeparator: an INJECTIVE ENCODING, not a hash ---------------------

/// `vaultTokenDomainSeparator(erc20) = [hi: VAULT_TOKEN_TAG, lo: erc20]` —
/// differs from the compat lineage's `vault_domain_sep`, which hashes; the
/// Pending lineage's ledger derivation (`tokenType`) hashes it a SECOND
/// time regardless, so this only has to be distinct per ERC-20.
pub fn vault_token_domain_sep(erc20: &[u8; 20]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..20].copy_from_slice(erc20);
    out[31] = VAULT_TOKEN_TAG;
    out
}

/// `tokenType(vaultTokenDomainSeparator(erc20), self)` — PINNED (the
/// ledger's own SHA-256 derivation), fed the Pending lineage's own domain
/// separator.
pub fn vault_color(erc20: &[u8; 20], self_addr: &[u8; 32]) -> [u8; 32] {
    let (d_hi, d_lo) = b32_slots(&vault_token_domain_sep(erc20));
    let (t_hi, t_lo) = b32_slots(&pad32("midnight:derive_token"));
    let (s_hi, s_lo) = b32_slots(self_addr);
    fab_sha256(vec![atom(32), atom(32), atom(32)], &[t_hi, t_lo, d_hi, d_lo, s_hi, s_lo])
}

// ---- Commit<T>: hi is NOT forced to zero (unlike upgradeFromTransient) --------------

/// `Commit::digest_of` off-circuit: `transientHash([pad.hi, pad.lo,
/// value_limbs…, id.hi, id.lo])`, then `{hi: f >> 248, lo: f mod 2^248}` —
/// the RAW `div_mod_power_of_two` split, not `transient_upgrade`'s
/// (`hi` there is always forced to 0). Both splits agree on `lo`; only the
/// forced-zero differs, and it is exactly `b32_slots` of the hash's plain
/// 32-byte little-endian encoding (byte 31 holds bits 248..255).
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

/// A witnessed secret key's refund `Commit`, under the shared `REFUND_PAD`
/// domain every non-deposit flow uses.
pub fn refund_commit_of(sk: &[u8; 32], request_id: &[u8; 32]) -> [u8; 32] {
    let (sk_hi, sk_lo) = b32_slots(sk);
    commit_digest_of(REFUND_PAD, &[sk_hi, sk_lo], request_id)
}

// ---- the V2 signing record --------------------------------------------------------------

/// The EVM transaction a request signs, without its chain id (the block's
/// own, read by `Pending::request`/`Fired::request`).
#[derive(Clone, Debug)]
pub struct Tx<const WORDS: usize> {
    pub nonce: u64,
    pub priority_fee: u128,
    pub max_fee: u128,
    pub gas: u64,
    pub to: [u8; 20],
    pub selector: [u8; 4],
    pub words: [[u8; 32]; WORDS],
}

/// A `SignBidirectionalEventV1<_, WORDS, Schema>`, off-circuit: what a
/// request circuit files and a settle circuit reads back.
///
/// V1 SINCE M44 RUNG D. The format-version byte, the request-nonce field and
/// the configurable caip2 are gone; `keyVersion` leads (read off the cell,
/// so it comes from [`Env`] rather than from the request), the destination is
/// the constant `pad(32, "eip155:1")`, and the record ENDS with
/// `signatureDest`, `params` and the OUTPUT SCHEMA, which is where the
/// response kind byte's job went.
#[derive(Clone, Debug)]
pub struct Req<const WORDS: usize> {
    /// The signing path: the depositor's identity commitment (`deposit`),
    /// or `pad(32, "vault")` (every other request).
    pub path: [u8; 32],
    /// The output schema this request files, as the record carries it —
    /// `Filing::Schema`'s bytes.
    pub out_schema: &'static [u8],
    pub tx: Tx<WORDS>,
}

impl<const WORDS: usize> Req<WORDS> {
    /// `SignBidirectionalEventV1::limbs()`'s order, off-circuit.
    pub fn limbs(&self, env: &Env) -> Vec<Fr> {
        let (sender_hi, sender_lo) = b32_slots(&env.self_addr);
        let (path_hi, path_lo) = b32_slots(&self.path);
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
            Fr::from(self.tx.nonce),
            u128_limb(self.tx.priority_fee),
            u128_limb(self.tx.max_fee),
            Fr::from(self.tx.gas),
            b20(&self.tx.to),
            Fr::from(0u64), // value
            Fr::from(1u64), // calldata.is_some
            Fr::from_le_bytes(&self.tx.selector).expect("4 bytes fit"),
            Fr::from(WORDS as u64), // no_words
        ];
        for w in &self.tx.words {
            let (hi, lo) = b32_slots(w);
            l.push(hi);
            l.push(lo);
        }
        l.push(Fr::from(0u64)); // accessListEntryCount
        l.push(dest_hi); // executionDest
        l.push(dest_lo);
        l.push(Fr::from(0u64)); // signatureDest: unused
        l.extend([Fr::from(0u64); 3]); // params: pad(64, "")
        l.extend(schema_limbs(self.out_schema));
        l
    }

    /// The record's FAB atom widths — the trailing `Bytes<0>`
    /// (`respondSerializationSchema`, present in the alignment and absent
    /// from the limbs) included.
    pub fn widths(&self) -> Vec<u32> {
        let mut a = vec![1, 32, 32, 1, 1, 8, 8, 16, 16, 8, 20, 16, 1, 4, 2];
        a.extend(std::iter::repeat_n(32u32, WORDS));
        a.extend([1, 32, 1, 64, self.out_schema.len() as u32, 0]);
        a
    }

    pub fn av(&self, env: &Env) -> AlignedValue {
        aligned(&self.widths(), &self.limbs(env))
    }

    /// `calculateEvmType2TxParamsDigestV1` over the USED words.
    pub fn tx_digest(&self, env: &Env) -> [u8; 32] {
        tx_params_digest(
            env.chain_id,
            self.tx.nonce,
            self.tx.priority_fee,
            self.tx.max_fee,
            self.tx.gas,
            &self.tx.to,
            Some((&self.tx.selector, &self.tx.words)),
        )
    }

    /// The id is no longer a hash of the whole record but of
    /// `RequestIdPreimageV1`, whose transaction enters as a digest — so the
    /// schema and the stored words are OUTSIDE the id, and the gas numbers
    /// are inside it.
    pub fn request_id(&self, env: &Env) -> [u8; 32] {
        request_id_v1(env.key_version, &env.self_addr, &self.path, &self.tx_digest(env))
    }
}

/// The notification's `depth ‖ path` payload, as `Bytes<128>` limbs — same
/// shape the compat lineage's `notification_payload_limbs` builds, but the
/// path comes from THIS slot's own two-element field path.
pub fn notification_payload_limbs(self_addr: &[u8; 32], records_field: u8) -> Vec<Fr> {
    let (seg, off) = ops::segment_of(records_field);
    let mut bytes = [0u8; 128];
    bytes[..32].copy_from_slice(self_addr);
    bytes[32] = 2; // depth: every path here is two elements
    bytes[33] = seg;
    bytes[34] = off;
    let mut limbs: Vec<Fr> = bytes.chunks(31).map(|c| Fr::from_le_bytes(c).unwrap()).collect();
    limbs.reverse();
    limbs
}

/// The cross-contract-call args a request's notification commits to:
/// requestId + notification (version, payload).
pub fn call_args(self_addr: &[u8; 32], records_field: u8, request_id: &[u8; 32]) -> Vec<Fr> {
    let (rid_hi, rid_lo) = b32_slots(request_id);
    let mut args = vec![rid_hi, rid_lo, Fr::from(1u64)];
    args.extend(notification_payload_limbs(self_addr, records_field));
    args
}

/// The cross-contract call's own witnesses, threaded through EVERY request
/// circuit's `Pending::request` / `Fired::request` call: `cc-rand`, then
/// the entry-point hash's two limbs (`signer.sign_bidirectional`'s
/// communications commitment). Confirmed against `withdraw.zkir` and
/// `approve_router.zkir` (the LAST private inputs each declares).
pub fn call_witnesses(env: &Env, cc_rand: Fr) -> Vec<Fr> {
    let (ep_hi, ep_lo) = b32_slots(&env.ep);
    vec![cc_rand, ep_hi, ep_lo]
}

// ---- the two shared op skeletons ----------------------------------------------------

/// The op stream `signet_flow::file_request` emits for EVERY request
/// circuit (`Pending::request` and `Fired::request` alike), in order:
/// `kernel.self()` (via `cache_self_address`), the chain id into the
/// transaction, then `mpcKeyVersion` into the record, `records.member`,
/// the record insert, the env insert (`Pending` only — `envs_field` is
/// `None` for a `Fired` slot), `signer.pin` (a fresh read), the
/// `claimContractCall`.
///
/// TWO OPS FEWER SINCE M44 RUNG D: the caip2 read and the nonce
/// read-modify-write both went, and `mpcKeyVersion` arrived — so this is the
/// one place the V1 vocabulary's contention win is visible as a count.
///
/// Confirmed instruction-for-instruction against `withdraw.zkir` (with an
/// env insert) and `approve_router.zkir` (without one).
#[allow(clippy::too_many_arguments)]
pub fn file_request_ops(
    env: &Env,
    records_field: u8,
    envs_field: Option<u8>,
    request_id: &[u8; 32],
    request_exists: bool,
    record_av: AlignedValue,
    env_av: Option<AlignedValue>,
    cc_rand: Fr,
) -> Vec<VmOp> {
    let mut o = env.kernel_self();
    o.extend(env.read_chain_id());
    o.extend(env.read_key_version());
    o.extend(ops::member(records_field, request_id, request_exists));
    o.extend(ops::insert(records_field, request_id, record_av));
    if let (Some(f), Some(av)) = (envs_field, env_av) {
        o.extend(ops::insert(f, request_id, av));
    }
    o.extend(env.read_signer());
    let comm = transient_commit(&call_args(&env.self_addr, records_field, request_id)[..], cc_rand);
    o.extend(ops::claim_contract_call(&env.signer_addr, &env.ep, comm));
    o
}

/// The op stream `Pending::consume` (shared by `complete` and `refund`)
/// emits for EVERY settle circuit, in order: the MPC key read,
/// `records.member`, `records.remove`, `envs.lookup`, `envs.remove`.
///
/// NO RECORD LOOKUP since M44 rung D: the V2 settle read the stored record
/// back, because the request id was a hash of it and the attestation had to
/// be tied to those bytes. A V1 id is a hash of `RequestIdPreimageV1`, and
/// the id itself is the ticket's key — so the entry's PRESENCE is the whole
/// of what the record has to say, and four ops go with the lookup
/// (`record_av` is kept as an argument because the pre-state still has to
/// hold the entry the member check finds).
///
/// Confirmed instruction-for-instruction against `complete_withdraw`'s
/// Impact stream.
pub fn consume_ops(
    env: &Env,
    records_field: u8,
    envs_field: u8,
    request_id: &[u8; 32],
    pending: bool,
    _record_av: AlignedValue,
    env_av: AlignedValue,
) -> Vec<VmOp> {
    let mut o = env.read_mpc_key();
    o.extend(ops::member(records_field, request_id, pending));
    o.extend(ops::remove(records_field, request_id));
    o.extend(ops::lookup(envs_field, request_id, env_av));
    o.extend(ops::remove(envs_field, request_id));
    o
}

/// The settle ticket's leading argument slots, computed from a fresh
/// signature over the V1 attestation digest
/// (`prims::attestation_digest`: tag, id, height, VERDICT, WIDTH, output).
///
/// Slot order is the derive's: `requestId` (two), `blockHeight`,
/// `outputKind`, `serializedOutputLength`, `digest` (two), `signature`
/// (`bigR.x` two, `bigR.y` two, `s` two, `recoveryId`), then the output.
/// `bigR.y` and `recoveryId` are unread and kept zero; the signature is
/// circuit-input LITTLE-endian.
///
/// V1 SINCE M44 RUNG D: where the Borsh lineage hashed `requestId` with a
/// packed `kind ‖ output` byte string, the V1 digest names the verdict and
/// the attested WIDTH as separate field elements — so an output of the wrong
/// width cannot verify, which the `kind + 256·leaf` packing could not say.
#[allow(clippy::too_many_arguments)]
pub fn settle_head_inputs(
    key_seed: u64,
    nonce_seed: u64,
    request_id: &[u8; 32],
    block_height: u64,
    output_kind: u64,
    signed_width: usize,
    output_limbs: &[Fr],
) -> Vec<Fr> {
    let digest = attestation_digest(request_id, block_height, output_kind, signed_width, output_limbs);
    let (rx_le, s_le, _pk) = sign(&digest, &scalar(key_seed), &scalar(nonce_seed));
    let (rid_hi, rid_lo) = b32_slots(request_id);
    let (d_hi, d_lo) = b32_slots(&digest);
    let (rx_hi, rx_lo) = b32_slots(&rx_le);
    let (s_hi, s_lo) = b32_slots(&s_le);
    let mut v = vec![
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
    ];
    v.extend_from_slice(output_limbs);
    v
}

/// The `outputKind` argument slot of a ticket — index 3, by the order above.
pub const OUTPUT_KIND_SLOT: usize = 3;

/// [`settle_head_inputs`] where the SIGNED preimage and the circuit's
/// ARGUMENT SLOTS differ — the shape a `Failed` ticket has (M37 rung D).
///
/// The ticket's wire block is one shape whatever the MPC attested, so the
/// attested-value slot is always there; but when the verdict is a
/// NON-EXECUTION the signed preimage has width zero and no output limbs, and
/// the slot carries prover-chosen padding. `Pending::refund` hashes the
/// preimage both ways — at the call's width and at zero — and selects by the
/// verdict, which is exactly what this models.
#[allow(clippy::too_many_arguments)]
pub fn settle_head_inputs_padded(
    key_seed: u64,
    nonce_seed: u64,
    request_id: &[u8; 32],
    block_height: u64,
    output_kind: u64,
    signed_width: usize,
    signed_limbs: &[Fr],
    slot_limbs: &[Fr],
) -> Vec<Fr> {
    let mut v = settle_head_inputs(
        key_seed,
        nonce_seed,
        request_id,
        block_height,
        output_kind,
        signed_width,
        signed_limbs,
    );
    // `settle_head_inputs` appended the SIGNED limbs to the slots; replace
    // them with what the argument slots actually carry.
    v.truncate(v.len() - signed_limbs.len());
    v.extend_from_slice(slot_limbs);
    v
}

/// WHAT THE MPC ATTESTED, for a settle that takes a `Failed` ticket.
///
/// The M37 rung D split: `complete` takes the successes, `refund` takes the
/// two non-successes — the MPC's failure kind (reverted, never mined, or an
/// undecodable return) and this call's own kind with a return the call's
/// `EvmCall::succeeded` says is not a success. A `refund` presented with a
/// SUCCESS must reject, which is the case this enum's third shape drives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Attested {
    /// A NON-EXECUTION (`output_kind::FAILED`), with prover-chosen padding
    /// in the output slot and width zero in the signed digest.
    Failure { padding: u64 },
    /// `output_kind::EXECUTED`, carrying the attested return value at the
    /// call's own width.
    Executed { value: u64 },
}

impl Attested {
    /// The MPC's VERDICT on the wire, where the Borsh lineage had a response
    /// kind byte.
    pub fn output_kind(self) -> u64 {
        match self {
            Attested::Failure { .. } => output_kind::FAILED,
            Attested::Executed { .. } => output_kind::EXECUTED,
        }
    }

    /// The attested WIDTH inside the digest: the call's own for an
    /// execution, zero for a non-execution.
    pub fn signed_width(self, executed_width: usize) -> usize {
        match self {
            Attested::Failure { .. } => 0,
            Attested::Executed { .. } => executed_width,
        }
    }

    /// The limbs inside the signed preimage, at the call's attested width.
    pub fn signed_limbs(self, executed_width: usize) -> Vec<Fr> {
        match self {
            Attested::Failure { .. } => vec![],
            Attested::Executed { value } => Self::limbs_at(executed_width, value),
        }
    }

    /// The limbs in the ticket's ARGUMENT slots — always the call's own
    /// width, whatever the verdict: the wire block is one shape, and a
    /// non-execution fills it with prover-chosen padding.
    pub fn slot_limbs(self, executed_width: usize) -> Vec<Fr> {
        match self {
            Attested::Failure { padding } => Self::limbs_at(executed_width, padding),
            Attested::Executed { value } => Self::limbs_at(executed_width, value),
        }
    }

    /// A `u64` as the slots of an attested output of `width` bytes: one limb
    /// for the ERC-20 flag's `Bytes<1>`, two for a `uint256`'s `B32`.
    fn limbs_at(width: usize, v: u64) -> Vec<Fr> {
        match width {
            FLAG_WIDTH => vec![Fr::from(v)],
            WORD_WIDTH => word_output_limbs(v),
            other => panic!("no attested output of {other} bytes in this lineage"),
        }
    }

    /// Whether `Pending::refund` accepts it.
    ///
    /// `flag_is_the_verdict` is the call's success rule: `true` for a `Bool`
    /// return whose `succeeded` is `is_true` (the ERC-20 `transfer` the
    /// withdrawal makes), `false` for a numeric return whose `succeeded` is
    /// `always` — for those, EXECUTED IS SUCCESS and only the failure kind
    /// is refundable, which is exactly the deployed semantics.
    pub fn refundable(self, flag_is_the_verdict: bool) -> bool {
        match self {
            Attested::Failure { .. } => true,
            Attested::Executed { value } => flag_is_the_verdict && value == 0,
        }
    }
}

/// The part every settle scenario shares: whether the map still holds the
/// entry, the mint nonce, the caller's own key, whose secret is
/// presented, and the signature nonce seed.
#[derive(Clone, Debug)]
pub struct Settle {
    pub pending: bool,
    pub mint_nonce: [u8; 32],
    pub own_pk: [u8; 32],
    /// The secret the CALLER witnesses. `None` = the requester's own (the
    /// gate passes); `Some(other)` drives the "Not the …" guard.
    pub claimant_sk: Option<[u8; 32]>,
    pub nonce_seed: u64,
    /// The height the MPC attests, inside the V1 digest and disclosed by
    /// every settle. It had no place in the Borsh lineage's preimage.
    pub block_height: u64,
}

impl Settle {
    pub fn new() -> Settle {
        Settle {
            pending: true,
            mint_nonce: tagged32(b"mint-nonce!", 0x41),
            own_pk: tagged32(b"own-pk", 0x43),
            claimant_sk: None,
            nonce_seed: 0x0dd_b17,
            block_height: 21_000_000,
        }
    }
    pub fn sk(&self, requester: &[u8; 32]) -> [u8; 32] {
        self.claimant_sk.unwrap_or(*requester)
    }
    pub fn nonce_slots(&self) -> [Fr; 2] {
        let (hi, lo) = b32_slots(&self.mint_nonce);
        [hi, lo]
    }
}

impl Default for Settle {
    fn default() -> Settle {
        Settle::new()
    }
}

// ==== initialize ============================================================================

#[derive(Clone, Debug)]
pub struct InitializeScenario {
    pub env: Env,
    pub sk: [u8; 32],
    pub vault_evm: [u8; 20],
    pub swap_router: [u8; 20],
    pub stata_underlying: [u8; 20],
    pub stata_token: [u8; 20],
    pub chain_id: u64,
    /// `mpcKeyVersion`, where the V2 lineage pinned a caip2 id: the caip2
    /// went with the V1 vocabulary (`executionDest` is the constant
    /// `ethereumCaip2Id()`) and the key version took its argument slot.
    pub key_version: u8,
    pub key_seed: u64,
}

impl InitializeScenario {
    pub fn new() -> InitializeScenario {
        InitializeScenario {
            env: Env::new(),
            sk: tagged32(b"deployer", 0x11),
            vault_evm: *b"vault-evm-addr-20byt",
            swap_router: *b"uniswap-router-20byt",
            stata_underlying: *b"stata-underlying-usd",
            stata_token: *b"stata-token-wrapper!",
            chain_id: 11_155_111,
            key_version: 1,
            key_seed: 0xbeef_f00d,
        }
    }

    pub fn point(&self) -> IrValue {
        let generator = IrValue::Secp256k1Point(k256::K256::generator());
        ec_mul_offcircuit(&generator, &scalar(self.key_seed)).unwrap()
    }

    pub fn inputs(&self) -> Vec<Fr> {
        vec![
            b20(&self.vault_evm),
            b20(&self.swap_router),
            b20(&self.stata_underlying),
            b20(&self.stata_token),
            Fr::from(self.chain_id),
            Fr::from(u64::from(self.key_version)),
        ]
        .into_iter()
        .chain(natives(&self.point()))
        .collect()
    }

    pub fn witnesses(&self) -> Vec<Fr> {
        let (hi, lo) = b32_slots(&self.sk);
        vec![hi, lo]
    }

    pub fn ops(&self) -> Vec<VmOp> {
        let mut o = self.env.read_initialized();
        o.extend(self.env.read_deployer());
        o.extend(ops::counter_inc(INITIALIZED));
        o.extend(ops::cell_write(VAULT_EVM_ADDRESS, bytesn_value(20, &self.vault_evm)));
        o.extend(ops::cell_write(UNISWAP_ROUTER, bytesn_value(20, &self.swap_router)));
        o.extend(ops::cell_write(STATA_UNDERLYING, bytesn_value(20, &self.stata_underlying)));
        o.extend(ops::cell_write(STATA_TOKEN, bytesn_value(20, &self.stata_token)));
        // `Signet::initialize`'s own order: the key, its version, the chain.
        o.extend(ops::cell_write(MPC_RESPONSE_KEY, point_av(&self.point())));
        o.extend(ops::cell_write(MPC_KEY_VERSION, bytesn_value(1, &[self.key_version])));
        o.extend(ops::cell_write(EVM_CHAIN_ID, bytesn_value(8, &self.chain_id.to_le_bytes())));
        o
    }

    pub fn preimage(&self) -> ProofPreimage {
        preimage_of(self.inputs(), self.witnesses(), &self.ops(), Fr::from(0x1_1111u64))
    }

    pub fn pre_state(&self) -> PreState {
        let mut pre = self.env.pre_state();
        pre.initialized = self.env.initialized;
        pre.deployer = self.env.deployer();
        pre
    }
}

impl Default for InitializeScenario {
    fn default() -> InitializeScenario {
        InitializeScenario::new()
    }
}

// ==== approveRouter / approveStata (Fired: request-only) ====================================

#[derive(Clone, Debug)]
pub struct ApproveRouterScenario {
    pub env: Env,
    pub erc20: [u8; 20],
    pub evm_nonce: u64,
    pub request_exists: bool,
    pub cc_rand: Fr,
}

impl ApproveRouterScenario {
    pub fn new() -> ApproveRouterScenario {
        ApproveRouterScenario {
            env: Env::new(),
            erc20: *b"erc20-token-contract",
            evm_nonce: 5,
            request_exists: false,
            cc_rand: Fr::from(0xa1_1a2u64),
        }
    }

    fn max_allowance_word() -> [u8; 32] {
        abi_num_word(u128::MAX)
    }

    pub fn req(&self) -> Req<VAULT_WORDS> {
        Req {
            path: pad32(VAULT_PATH),
            out_schema: SUCCESS_SCHEMA,
            tx: Tx {
                nonce: self.evm_nonce,
                priority_fee: 1_000_000_000,
                max_fee: 30_000_000_000,
                gas: 100_000,
                to: self.erc20,
                selector: APPROVE_SELECTOR,
                words: [abi_addr_word(&self.env.router), Self::max_allowance_word()],
            },
        }
    }

    pub fn request_id(&self) -> [u8; 32] {
        self.req().request_id(&self.env)
    }

    pub fn inputs(&self) -> Vec<Fr> {
        vec![b20(&self.erc20), Fr::from(self.evm_nonce)]
    }

    pub fn witnesses(&self) -> Vec<Fr> {
        call_witnesses(&self.env, self.cc_rand)
    }

    pub fn ops(&self) -> Vec<VmOp> {
        let mut o = self.env.read_initialized();
        o.extend(self.env.read_router());
        let rid = self.request_id();
        o.extend(file_request_ops(
            &self.env,
            APPROVALS,
            None,
            &rid,
            self.request_exists,
            self.req().av(&self.env),
            None,
            self.cc_rand,
        ));
        o
    }

    pub fn preimage(&self) -> ProofPreimage {
        preimage_of(self.inputs(), self.witnesses(), &self.ops(), Fr::from(0xa2_2a2u64))
    }

    pub fn pre_state(&self) -> PreState {
        let mut pre = self.env.pre_state();
        if self.request_exists {
            pre.approvals = vec![(self.request_id(), self.req().av(&self.env))];
        }
        pre
    }
}

impl Default for ApproveRouterScenario {
    fn default() -> ApproveRouterScenario {
        ApproveRouterScenario::new()
    }
}

#[derive(Clone, Debug)]
pub struct ApproveStataScenario {
    pub env: Env,
    pub evm_nonce: u64,
    pub request_exists: bool,
    pub cc_rand: Fr,
}

impl ApproveStataScenario {
    pub fn new() -> ApproveStataScenario {
        ApproveStataScenario {
            env: Env::new(),
            evm_nonce: 6,
            request_exists: false,
            cc_rand: Fr::from(0xa3_3a3u64),
        }
    }

    pub fn req(&self) -> Req<VAULT_WORDS> {
        Req {
            path: pad32(VAULT_PATH),
            out_schema: SUCCESS_SCHEMA,
            tx: Tx {
                nonce: self.evm_nonce,
                priority_fee: 1_000_000_000,
                max_fee: 30_000_000_000,
                gas: 100_000,
                to: self.env.stata_underlying,
                selector: APPROVE_SELECTOR,
                words: [abi_addr_word(&self.env.stata_token), abi_num_word(u128::MAX)],
            },
        }
    }

    pub fn request_id(&self) -> [u8; 32] {
        self.req().request_id(&self.env)
    }

    pub fn inputs(&self) -> Vec<Fr> {
        vec![Fr::from(self.evm_nonce)]
    }

    pub fn witnesses(&self) -> Vec<Fr> {
        call_witnesses(&self.env, self.cc_rand)
    }

    pub fn ops(&self) -> Vec<VmOp> {
        let mut o = self.env.read_initialized();
        o.extend(self.env.read_stata_token());
        o.extend(self.env.read_stata_underlying());
        let rid = self.request_id();
        o.extend(file_request_ops(
            &self.env,
            APPROVALS,
            None,
            &rid,
            self.request_exists,
            self.req().av(&self.env),
            None,
            self.cc_rand,
        ));
        o
    }

    pub fn preimage(&self) -> ProofPreimage {
        preimage_of(self.inputs(), self.witnesses(), &self.ops(), Fr::from(0xa4_4a4u64))
    }

    pub fn pre_state(&self) -> PreState {
        let mut pre = self.env.pre_state();
        if self.request_exists {
            pre.approvals = vec![(self.request_id(), self.req().av(&self.env))];
        }
        pre
    }
}

impl Default for ApproveStataScenario {
    fn default() -> ApproveStataScenario {
        ApproveStataScenario::new()
    }
}

// ==== deposit / claim ========================================================================

#[derive(Clone, Debug)]
pub struct StartDepositScenario {
    pub env: Env,
    pub sk: [u8; 32],
    pub evm_nonce: u64,
    pub gas_limit: u64,
    pub max_fee_per_gas: u128,
    pub max_priority_fee_per_gas: u128,
    pub erc20: [u8; 20],
    pub amount: u128,
    pub request_exists: bool,
    pub cc_rand: Fr,
}

impl StartDepositScenario {
    pub fn new() -> StartDepositScenario {
        StartDepositScenario {
            env: Env::new(),
            sk: tagged32(b"depositor", 0x21),
            evm_nonce: 7,
            gas_limit: 65_000,
            max_fee_per_gas: 30_000_000_000,
            max_priority_fee_per_gas: 1_000_000_000,
            erc20: *b"erc20-token-contract",
            amount: 123_456,
            request_exists: false,
            cc_rand: Fr::from(0xde_9051u64),
        }
    }

    pub fn commitment(&self) -> [u8; 32] {
        pending_user_commitment(&self.sk)
    }

    pub fn amount_u64(&self) -> u64 {
        unbounded_to_u64(self.amount)
    }

    pub fn req(&self) -> Req<VAULT_WORDS> {
        Req {
            path: self.commitment(),
            out_schema: SUCCESS_SCHEMA,
            tx: Tx {
                nonce: self.evm_nonce,
                priority_fee: self.max_priority_fee_per_gas,
                max_fee: self.max_fee_per_gas,
                gas: self.gas_limit,
                to: self.erc20,
                selector: TRANSFER_SELECTOR,
                words: [abi_addr_word(&self.env.vault_evm), abi_num_word(self.amount)],
            },
        }
    }

    pub fn request_id(&self) -> [u8; 32] {
        self.req().request_id(&self.env)
    }

    /// The `DepositEnv` the request stores.
    pub fn env_limbs(&self) -> Vec<Fr> {
        let (c_hi, c_lo) = b32_slots(&self.commitment());
        vec![c_hi, c_lo, b20(&self.erc20), Fr::from(self.amount_u64())]
    }

    pub fn env_av(&self) -> AlignedValue {
        aligned(&[32, 20, 8], &self.env_limbs())
    }

    pub fn inputs(&self) -> Vec<Fr> {
        vec![
            Fr::from(self.evm_nonce),
            Fr::from(self.gas_limit),
            u128_limb(self.max_fee_per_gas),
            u128_limb(self.max_priority_fee_per_gas),
            b20(&self.erc20),
            u128_limb(self.amount),
        ]
    }

    pub fn witnesses(&self) -> Vec<Fr> {
        let (hi, lo) = b32_slots(&self.sk);
        let mut w = vec![hi, lo];
        w.extend(call_witnesses(&self.env, self.cc_rand));
        w
    }

    pub fn ops(&self) -> Vec<VmOp> {
        let mut o = self.env.read_initialized();
        o.extend(self.env.read_vault_evm());
        let rid = self.request_id();
        o.extend(file_request_ops(
            &self.env,
            DEPOSITS_RECORDS,
            Some(DEPOSITS_ENVS),
            &rid,
            self.request_exists,
            self.req().av(&self.env),
            Some(self.env_av()),
            self.cc_rand,
        ));
        o
    }

    pub fn preimage(&self) -> ProofPreimage {
        preimage_of(self.inputs(), self.witnesses(), &self.ops(), Fr::from(0xde_9052u64))
    }

    pub fn pre_state(&self) -> PreState {
        let mut pre = self.env.pre_state();
        if self.request_exists {
            let rid = self.request_id();
            pre.deposits_records = vec![(rid, self.req().av(&self.env))];
            pre.deposits_envs = vec![(rid, self.env_av())];
        }
        pre
    }
}

impl Default for StartDepositScenario {
    fn default() -> StartDepositScenario {
        StartDepositScenario::new()
    }
}

/// Who a claim's minted coin goes to.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ClaimRecipient {
    Key([u8; 32]),
    Contract([u8; 32]),
    None([u8; 32]),
}

#[derive(Clone, Debug)]
pub struct ClaimScenario {
    pub d: StartDepositScenario,
    pub settle: Settle,
    pub recipient: ClaimRecipient,
    pub success: bool,
}

impl ClaimScenario {
    pub fn new() -> ClaimScenario {
        ClaimScenario {
            d: StartDepositScenario::new(),
            settle: Settle::new(),
            recipient: ClaimRecipient::Key(tagged32(b"claim-pk", 0x42)),
            success: true,
        }
    }

    pub fn output_limbs(&self) -> Vec<Fr> {
        vec![Fr::from(u64::from(self.success))]
    }

    fn recipient_data(&self) -> (bool, [u8; 32]) {
        match self.recipient {
            ClaimRecipient::Key(pk) => (true, pk),
            ClaimRecipient::Contract(addr) => (false, addr),
            ClaimRecipient::None(own_pk) => (true, own_pk),
        }
    }

    pub fn coin_commitment(&self) -> [u8; 32] {
        let color = vault_color(&self.d.erc20, &self.d.env.self_addr);
        let (is_left, data) = self.recipient_data();
        coin_commitment_of(&b32_slots(&self.settle.mint_nonce), &color, u128::from(self.d.amount_u64()), is_left, &data)
    }

    pub fn self_read_fires(&self) -> bool {
        matches!(self.recipient, ClaimRecipient::Contract(_))
    }

    pub fn auto_receive(&self) -> bool {
        matches!(self.recipient, ClaimRecipient::Contract(addr) if addr == self.d.env.self_addr)
    }

    pub fn inputs(&self) -> Vec<Fr> {
        let mut inputs = settle_head_inputs(self.d.env.key_seed, self.settle.nonce_seed, &self.d.request_id(), self.settle.block_height, output_kind::EXECUTED, FLAG_WIDTH, &self.output_limbs());
        inputs.extend(self.settle.nonce_slots());
        let (is_some, is_left, left, right) = match self.recipient {
            ClaimRecipient::Key(pk) => (1u64, 1u64, pk, [0u8; 32]),
            ClaimRecipient::Contract(addr) => (1, 0, [0u8; 32], addr),
            ClaimRecipient::None(_) => (0, 0, [0u8; 32], [0u8; 32]),
        };
        let (l_hi, l_lo) = b32_slots(&left);
        let (r_hi, r_lo) = b32_slots(&right);
        inputs.extend([Fr::from(is_some), Fr::from(is_left), l_hi, l_lo, r_hi, r_lo]);
        inputs
    }

    pub fn witnesses(&self) -> Vec<Fr> {
        let (sk_hi, sk_lo) = b32_slots(&self.settle.sk(&self.d.sk));
        let mut w = vec![sk_hi, sk_lo];
        if let ClaimRecipient::None(own_pk) = self.recipient {
            let (pk_hi, pk_lo) = b32_slots(&own_pk);
            w.extend([pk_hi, pk_lo]);
        }
        w
    }

    pub fn ops(&self) -> Vec<VmOp> {
        let rid = self.d.request_id();
        let cm = self.coin_commitment();
        let mut o = self.d.env.read_initialized();
        o.extend(consume_ops(&self.d.env, DEPOSITS_RECORDS, DEPOSITS_ENVS, &rid, self.settle.pending, self.d.req().av(&self.d.env), self.d.env_av()));
        o.extend(self.d.env.kernel_self());
        o.extend(ops::mint_and_spend(&vault_token_domain_sep(&self.d.erc20), self.d.amount_u64(), &cm));
        if self.self_read_fires() {
            o.extend(self.d.env.kernel_self());
        }
        if self.auto_receive() {
            o.extend(ops::claim(1, &cm));
        }
        o
    }

    pub fn preimage(&self) -> ProofPreimage {
        preimage_of(self.inputs(), self.witnesses(), &self.ops(), Fr::from(0xc1_a1au64))
    }

    pub fn pre_state(&self) -> PreState {
        let mut pre = self.d.env.pre_state();
        let rid = self.d.request_id();
        if self.settle.pending {
            pre.deposits_records = vec![(rid, self.d.req().av(&self.d.env))];
            pre.deposits_envs = vec![(rid, self.d.env_av())];
        }
        pre
    }
}

impl Default for ClaimScenario {
    fn default() -> ClaimScenario {
        ClaimScenario::new()
    }
}

// ==== withdraw / completeWithdraw / refundWithdrawal =========================================

#[derive(Clone, Debug)]
pub struct StartWithdrawScenario {
    pub env: Env,
    pub sk: [u8; 32],
    pub evm_nonce: u64,
    pub erc20: [u8; 20],
    pub amount: u128,
    pub dest: [u8; 20],
    pub coin_nonce: [u8; 32],
    pub coin_color: Option<[u8; 32]>,
    pub coin_value: Option<u128>,
    pub request_exists: bool,
    pub cc_rand: Fr,
}

impl StartWithdrawScenario {
    pub fn new() -> StartWithdrawScenario {
        StartWithdrawScenario {
            env: Env::new(),
            sk: tagged32(b"withdrawer", 0x22),
            evm_nonce: 11,
            erc20: *b"erc20-token-contract",
            amount: 98_765,
            dest: *b"dest-evm-address-20b",
            coin_nonce: tagged32(b"coin-nonce", 0x44),
            coin_color: None,
            coin_value: None,
            request_exists: false,
            cc_rand: Fr::from(0x0d_00ffu64),
        }
    }

    pub fn amount_u64(&self) -> u64 {
        unbounded_to_u64(self.amount)
    }

    pub fn coin_color(&self) -> [u8; 32] {
        self.coin_color.unwrap_or_else(|| vault_color(&self.erc20, &self.env.self_addr))
    }

    pub fn coin_value(&self) -> u128 {
        self.coin_value.unwrap_or(self.amount)
    }

    pub fn burn_effects(&self) -> Vec<VmOp> {
        let mut o = self.env.kernel_self();
        let evolved = evolved_nonce(&self.coin_nonce);
        let cm = coin_commitment_of(&evolved, &self.coin_color(), self.coin_value(), true, &[0u8; 32]);
        o.extend(ops::claim(2, &cm));
        o
    }

    pub fn req(&self) -> Req<VAULT_WORDS> {
        Req {
            path: pad32(VAULT_PATH),
            out_schema: SUCCESS_SCHEMA,
            tx: Tx {
                nonce: self.evm_nonce,
                priority_fee: 1_000_000_000,
                max_fee: 30_000_000_000,
                gas: 100_000,
                to: self.erc20,
                selector: TRANSFER_SELECTOR,
                words: [abi_addr_word(&self.dest), abi_num_word(self.amount)],
            },
        }
    }

    pub fn request_id(&self) -> [u8; 32] {
        self.req().request_id(&self.env)
    }

    pub fn refund_commitment(&self) -> [u8; 32] {
        refund_commit_of(&self.sk, &self.request_id())
    }

    pub fn env_limbs(&self) -> Vec<Fr> {
        let (c_hi, c_lo) = b32_slots(&self.refund_commitment());
        vec![c_hi, c_lo, b20(&self.erc20), Fr::from(self.amount_u64())]
    }

    pub fn env_av(&self) -> AlignedValue {
        aligned(&[32, 20, 8], &self.env_limbs())
    }

    pub fn inputs(&self) -> Vec<Fr> {
        vec![
            Fr::from(self.evm_nonce),
            b20(&self.erc20),
            u128_limb(self.amount),
            b20(&self.dest),
            b32_slots(&self.coin_nonce).0,
            b32_slots(&self.coin_nonce).1,
            b32_slots(&self.coin_color()).0,
            b32_slots(&self.coin_color()).1,
            u128_limb(self.coin_value()),
        ]
    }

    pub fn witnesses(&self) -> Vec<Fr> {
        let (hi, lo) = b32_slots(&self.sk);
        let mut w = vec![hi, lo];
        w.extend(call_witnesses(&self.env, self.cc_rand));
        w
    }

    pub fn ops(&self) -> Vec<VmOp> {
        let mut o = self.env.read_initialized();
        o.extend(self.burn_effects());
        let rid = self.request_id();
        o.extend(file_request_ops(
            &self.env,
            WITHDRAWALS_RECORDS,
            Some(WITHDRAWALS_ENVS),
            &rid,
            self.request_exists,
            self.req().av(&self.env),
            Some(self.env_av()),
            self.cc_rand,
        ));
        o
    }

    pub fn preimage(&self) -> ProofPreimage {
        preimage_of(self.inputs(), self.witnesses(), &self.ops(), Fr::from(0x0d_00ffu64))
    }

    pub fn pre_state(&self) -> PreState {
        let mut pre = self.env.pre_state();
        if self.request_exists {
            let rid = self.request_id();
            pre.withdrawals_records = vec![(rid, self.req().av(&self.env))];
            pre.withdrawals_envs = vec![(rid, self.env_av())];
        }
        pre
    }
}

impl Default for StartWithdrawScenario {
    fn default() -> StartWithdrawScenario {
        StartWithdrawScenario::new()
    }
}

#[derive(Clone, Debug)]
pub struct CompleteWithdrawScenario {
    pub w: StartWithdrawScenario,
    pub settle: Settle,
    pub success: bool,
}

impl CompleteWithdrawScenario {
    pub fn new() -> CompleteWithdrawScenario {
        CompleteWithdrawScenario {
            w: StartWithdrawScenario::new(),
            settle: Settle::new(),
            success: true,
        }
    }

    pub fn output_limbs(&self) -> Vec<Fr> {
        vec![Fr::from(u64::from(self.success))]
    }

    /// M37 rung D: no mint nonce. `complete_withdraw` mints nothing — a
    /// withdrawal that SUCCEEDED moved the tokens on the far side — so the
    /// ticket is the whole argument list.
    pub fn inputs(&self) -> Vec<Fr> {
        settle_head_inputs(self.w.env.key_seed, self.settle.nonce_seed, &self.w.request_id(), self.settle.block_height, output_kind::EXECUTED, FLAG_WIDTH, &self.output_limbs())
    }

    /// EMPTY, and that is the milestone: a completion witnesses no secret,
    /// so anyone holding the attestation can prove it and a stranger's proof
    /// is the same proof.
    pub fn witnesses(&self) -> Vec<Fr> {
        vec![]
    }

    pub fn ops(&self) -> Vec<VmOp> {
        let rid = self.w.request_id();
        let mut o = self.w.env.read_initialized();
        o.extend(consume_ops(&self.w.env, WITHDRAWALS_RECORDS, WITHDRAWALS_ENVS, &rid, self.settle.pending, self.w.req().av(&self.w.env), self.w.env_av()));
        o
    }

    pub fn preimage(&self) -> ProofPreimage {
        preimage_of(self.inputs(), self.witnesses(), &self.ops(), Fr::from(0xc0_00deu64))
    }

    pub fn pre_state(&self) -> PreState {
        let mut pre = self.w.env.pre_state();
        let rid = self.w.request_id();
        if self.settle.pending {
            pre.withdrawals_records = vec![(rid, self.w.req().av(&self.w.env))];
            pre.withdrawals_envs = vec![(rid, self.w.env_av())];
        }
        pre
    }
}

impl Default for CompleteWithdrawScenario {
    fn default() -> CompleteWithdrawScenario {
        CompleteWithdrawScenario::new()
    }
}

/// A `mint_nonce`'s bytes back out of its slot pair — every refund/complete
/// scenario needs the mint coin's nonce as raw bytes for `coinCommitment`.
impl Settle {
    pub fn nonce_slots_bytes(&self) -> [u8; 32] {
        self.mint_nonce
    }
}

#[derive(Clone, Debug)]
pub struct RefundWithdrawalScenario {
    pub w: StartWithdrawScenario,
    pub settle: Settle,
    /// M37 rung D: BOTH non-successes refund here, and a success must not.
    pub attested: Attested,
}

impl RefundWithdrawalScenario {
    pub fn new() -> RefundWithdrawalScenario {
        RefundWithdrawalScenario {
            w: StartWithdrawScenario::new(),
            settle: Settle::new(),
            attested: Attested::Failure { padding: 0 },
        }
    }

    /// The withdrawal's `transfer` returns a `bool`, so an executed call
    /// that returned `false` IS refundable.
    pub fn refundable(&self) -> bool {
        self.attested.refundable(true)
    }

    pub fn inputs(&self) -> Vec<Fr> {
        let mut v = settle_head_inputs_padded(
            self.w.env.key_seed,
            self.settle.nonce_seed,
            &self.w.request_id(),
            self.settle.block_height,

            self.attested.output_kind(),

            self.attested.signed_width(FLAG_WIDTH),
            &self.attested.signed_limbs(FLAG_WIDTH),
            &self.attested.slot_limbs(FLAG_WIDTH),
        );
        v.extend(self.settle.nonce_slots());
        v
    }

    pub fn witnesses(&self) -> Vec<Fr> {
        let (hi, lo) = b32_slots(&self.settle.sk(&self.w.sk));
        let (pk_hi, pk_lo) = b32_slots(&self.settle.own_pk);
        vec![hi, lo, pk_hi, pk_lo]
    }

    pub fn ops(&self) -> Vec<VmOp> {
        let rid = self.w.request_id();
        let mut o = self.w.env.read_initialized();
        o.extend(consume_ops(&self.w.env, WITHDRAWALS_RECORDS, WITHDRAWALS_ENVS, &rid, self.settle.pending, self.w.req().av(&self.w.env), self.w.env_av()));
        o.extend(self.w.env.kernel_self());
        let color = vault_color(&self.w.erc20, &self.w.env.self_addr);
        let cm = coin_commitment_of(&b32_slots(&self.settle.nonce_slots_bytes()), &color, u128::from(self.w.amount_u64()), true, &self.settle.own_pk);
        o.extend(ops::mint_and_spend(&vault_token_domain_sep(&self.w.erc20), self.w.amount_u64(), &cm));
        o
    }

    pub fn preimage(&self) -> ProofPreimage {
        preimage_of(self.inputs(), self.witnesses(), &self.ops(), Fr::from(0xde_ad01u64))
    }

    pub fn pre_state(&self) -> PreState {
        let mut pre = self.w.env.pre_state();
        let rid = self.w.request_id();
        if self.settle.pending {
            pre.withdrawals_records = vec![(rid, self.w.req().av(&self.w.env))];
            pre.withdrawals_envs = vec![(rid, self.w.env_av())];
        }
        pre
    }
}

impl Default for RefundWithdrawalScenario {
    fn default() -> RefundWithdrawalScenario {
        RefundWithdrawalScenario::new()
    }
}

// ==== swap / completeSwap / refundSwap ========================================================

#[derive(Clone, Debug)]
pub struct StartSwapScenario {
    pub env: Env,
    pub sk: [u8; 32],
    pub evm_nonce: u64,
    pub token_in: [u8; 20],
    pub token_out: [u8; 20],
    pub fee: u32,
    pub amount_out: u128,
    pub amount_in_max: u128,
    pub coin_nonce: [u8; 32],
    pub coin_color: Option<[u8; 32]>,
    pub coin_value: Option<u128>,
    pub request_exists: bool,
    pub cc_rand: Fr,
}

impl StartSwapScenario {
    pub fn new() -> StartSwapScenario {
        StartSwapScenario {
            env: Env::new(),
            sk: tagged32(b"swapper", 0x23),
            evm_nonce: 13,
            token_in: *b"token-in-contract-20",
            token_out: *b"token-out-contract20",
            fee: 3000,
            amount_out: 5_000,
            amount_in_max: 6_000,
            coin_nonce: tagged32(b"swap-coin-n", 0x45),
            coin_color: None,
            coin_value: None,
            request_exists: false,
            cc_rand: Fr::from(0x5_a1a5u64),
        }
    }

    pub fn amount_out_u64(&self) -> u64 {
        unbounded_to_u64(self.amount_out)
    }
    pub fn amount_in_max_u64(&self) -> u64 {
        unbounded_to_u64(self.amount_in_max)
    }

    pub fn coin_color(&self) -> [u8; 32] {
        self.coin_color.unwrap_or_else(|| vault_color(&self.token_in, &self.env.self_addr))
    }
    pub fn coin_value(&self) -> u128 {
        self.coin_value.unwrap_or(self.amount_in_max)
    }

    pub fn burn_effects(&self) -> Vec<VmOp> {
        let mut o = self.env.kernel_self();
        let evolved = evolved_nonce(&self.coin_nonce);
        let cm = coin_commitment_of(&evolved, &self.coin_color(), self.coin_value(), true, &[0u8; 32]);
        o.extend(ops::claim(2, &cm));
        o
    }

    fn fee_word(&self) -> [u8; 32] {
        abi_num_word(u128::from(self.fee))
    }

    pub fn req(&self) -> Req<SWAP_WORDS> {
        Req {
            path: pad32(VAULT_PATH),
            out_schema: AMOUNT_IN_SCHEMA,
            tx: Tx {
                nonce: self.evm_nonce,
                priority_fee: 1_000_000_000,
                max_fee: 30_000_000_000,
                gas: 700_000,
                to: self.env.router,
                selector: EXACT_OUTPUT_SINGLE_SELECTOR,
                words: [
                    abi_addr_word(&self.token_in),
                    abi_addr_word(&self.token_out),
                    self.fee_word(),
                    abi_addr_word(&self.env.vault_evm),
                    abi_num_word(self.amount_out),
                    abi_num_word(self.amount_in_max),
                    [0u8; 32],
                ],
            },
        }
    }

    pub fn request_id(&self) -> [u8; 32] {
        self.req().request_id(&self.env)
    }

    pub fn refund_commitment(&self) -> [u8; 32] {
        refund_commit_of(&self.sk, &self.request_id())
    }

    pub fn env_limbs(&self) -> Vec<Fr> {
        let (c_hi, c_lo) = b32_slots(&self.refund_commitment());
        vec![c_hi, c_lo, b20(&self.token_in), b20(&self.token_out), Fr::from(self.amount_out_u64()), Fr::from(self.amount_in_max_u64())]
    }

    pub fn env_av(&self) -> AlignedValue {
        aligned(&[32, 20, 20, 8, 8], &self.env_limbs())
    }

    pub fn inputs(&self) -> Vec<Fr> {
        vec![
            Fr::from(self.evm_nonce),
            b20(&self.token_in),
            b20(&self.token_out),
            Fr::from(u64::from(self.fee)),
            u128_limb(self.amount_out),
            u128_limb(self.amount_in_max),
            b32_slots(&self.coin_nonce).0,
            b32_slots(&self.coin_nonce).1,
            b32_slots(&self.coin_color()).0,
            b32_slots(&self.coin_color()).1,
            u128_limb(self.coin_value()),
        ]
    }

    pub fn witnesses(&self) -> Vec<Fr> {
        let (hi, lo) = b32_slots(&self.sk);
        let mut w = vec![hi, lo];
        w.extend(call_witnesses(&self.env, self.cc_rand));
        w
    }

    pub fn ops(&self) -> Vec<VmOp> {
        let mut o = self.env.read_initialized();
        o.extend(self.burn_effects());
        o.extend(self.env.read_vault_evm());
        o.extend(self.env.read_router());
        let rid = self.request_id();
        o.extend(file_request_ops(
            &self.env,
            SWAPS_RECORDS,
            Some(SWAPS_ENVS),
            &rid,
            self.request_exists,
            self.req().av(&self.env),
            Some(self.env_av()),
            self.cc_rand,
        ));
        o
    }

    pub fn preimage(&self) -> ProofPreimage {
        preimage_of(self.inputs(), self.witnesses(), &self.ops(), Fr::from(0x5_a1a6u64))
    }

    pub fn pre_state(&self) -> PreState {
        let mut pre = self.env.pre_state();
        if self.request_exists {
            let rid = self.request_id();
            pre.swaps_records = vec![(rid, self.req().av(&self.env))];
            pre.swaps_envs = vec![(rid, self.env_av())];
        }
        pre
    }
}

impl Default for StartSwapScenario {
    fn default() -> StartSwapScenario {
        StartSwapScenario::new()
    }
}

/// completeSwap's change-coin nonce: `[255 − hi, lo]`.
pub fn change_nonce(mint_nonce: &[u8; 32]) -> [u8; 32] {
    let (hi, _lo) = b32_slots(mint_nonce);
    let hi_u8 = {
        let bytes = hi.as_le_bytes();
        bytes.first().copied().unwrap_or(0)
    };
    let mut out = *mint_nonce;
    out[31] = 255u8.wrapping_sub(hi_u8);
    out
}

#[derive(Clone, Debug)]
pub struct CompleteSwapScenario {
    pub s: StartSwapScenario,
    pub settle: Settle,
    pub amount_in: u64,
}

impl CompleteSwapScenario {
    pub fn new() -> CompleteSwapScenario {
        CompleteSwapScenario {
            s: StartSwapScenario::new(),
            settle: Settle::new(),
            amount_in: 4_500,
        }
    }

    /// The `amountIn` as a V1 attested `uint256`: TWO limbs, not the one
    /// the Borsh `U64` output had.
    pub fn output_limbs(&self) -> Vec<Fr> {
        word_output_limbs(self.amount_in)
    }

    pub fn change(&self) -> Option<u64> {
        self.s.amount_in_max_u64().checked_sub(self.amount_in)
    }

    pub fn change_nonce(&self) -> [u8; 32] {
        change_nonce(&self.settle.mint_nonce)
    }

    pub fn inputs(&self) -> Vec<Fr> {
        let mut v = settle_head_inputs(self.s.env.key_seed, self.settle.nonce_seed, &self.s.request_id(), self.settle.block_height, output_kind::EXECUTED, WORD_WIDTH, &self.output_limbs());
        v.extend(self.settle.nonce_slots());
        v
    }

    pub fn witnesses(&self) -> Vec<Fr> {
        let (hi, lo) = b32_slots(&self.settle.sk(&self.s.sk));
        let (pk_hi, pk_lo) = b32_slots(&self.settle.own_pk);
        vec![hi, lo, pk_hi, pk_lo]
    }

    pub fn ops(&self) -> Vec<VmOp> {
        let rid = self.s.request_id();
        let mut o = self.s.env.read_initialized();
        o.extend(consume_ops(&self.s.env, SWAPS_RECORDS, SWAPS_ENVS, &rid, self.settle.pending, self.s.req().av(&self.s.env), self.s.env_av()));
        o.extend(self.s.env.kernel_self());
        // mint amountOut of tokenOut
        let color_out = vault_color(&self.s.token_out, &self.s.env.self_addr);
        let cm_out = coin_commitment_of(&b32_slots(&self.settle.mint_nonce), &color_out, u128::from(self.s.amount_out_u64()), true, &self.settle.own_pk);
        o.extend(ops::mint_and_spend(&vault_token_domain_sep(&self.s.token_out), self.s.amount_out_u64(), &cm_out));
        if let Some(change) = self.change() {
            let color_in = vault_color(&self.s.token_in, &self.s.env.self_addr);
            let cm_in = coin_commitment_of(&b32_slots(&self.change_nonce()), &color_in, u128::from(change), true, &self.settle.own_pk);
            o.extend(ops::mint_and_spend(&vault_token_domain_sep(&self.s.token_in), change, &cm_in));
        }
        o
    }

    pub fn preimage(&self) -> ProofPreimage {
        preimage_of(self.inputs(), self.witnesses(), &self.ops(), Fr::from(0x5_a1a7u64))
    }

    pub fn pre_state(&self) -> PreState {
        let mut pre = self.s.env.pre_state();
        let rid = self.s.request_id();
        if self.settle.pending {
            pre.swaps_records = vec![(rid, self.s.req().av(&self.s.env))];
            pre.swaps_envs = vec![(rid, self.s.env_av())];
        }
        pre
    }
}

impl Default for CompleteSwapScenario {
    fn default() -> CompleteSwapScenario {
        CompleteSwapScenario::new()
    }
}

#[derive(Clone, Debug)]
pub struct RefundSwapScenario {
    pub s: StartSwapScenario,
    pub settle: Settle,
    /// M37 rung D. This call's return is a NUMBER, so `EvmCall::succeeded`
    /// is `always` and an executed attestation is a success: only the MPC's
    /// failure kind refunds here, which is the deployed semantics exactly.
    pub attested: Attested,
}

impl RefundSwapScenario {
    pub fn new() -> RefundSwapScenario {
        RefundSwapScenario {
            s: StartSwapScenario::new(),
            settle: Settle::new(),
            attested: Attested::Failure { padding: 0 },
        }
    }

    pub fn refundable(&self) -> bool {
        self.attested.refundable(false)
    }

    pub fn inputs(&self) -> Vec<Fr> {
        let mut v = settle_head_inputs_padded(
            self.s.env.key_seed,
            self.settle.nonce_seed,
            &self.s.request_id(),
            self.settle.block_height,

            self.attested.output_kind(),

            self.attested.signed_width(WORD_WIDTH),
            &self.attested.signed_limbs(WORD_WIDTH),
            &self.attested.slot_limbs(WORD_WIDTH),
        );
        v.extend(self.settle.nonce_slots());
        v
    }

    pub fn witnesses(&self) -> Vec<Fr> {
        let (hi, lo) = b32_slots(&self.settle.sk(&self.s.sk));
        let (pk_hi, pk_lo) = b32_slots(&self.settle.own_pk);
        vec![hi, lo, pk_hi, pk_lo]
    }

    pub fn ops(&self) -> Vec<VmOp> {
        let rid = self.s.request_id();
        let mut o = self.s.env.read_initialized();
        o.extend(consume_ops(&self.s.env, SWAPS_RECORDS, SWAPS_ENVS, &rid, self.settle.pending, self.s.req().av(&self.s.env), self.s.env_av()));
        o.extend(self.s.env.kernel_self());
        let color = vault_color(&self.s.token_in, &self.s.env.self_addr);
        let cm = coin_commitment_of(&b32_slots(&self.settle.mint_nonce), &color, u128::from(self.s.amount_in_max_u64()), true, &self.settle.own_pk);
        o.extend(ops::mint_and_spend(&vault_token_domain_sep(&self.s.token_in), self.s.amount_in_max_u64(), &cm));
        o
    }

    pub fn preimage(&self) -> ProofPreimage {
        preimage_of(self.inputs(), self.witnesses(), &self.ops(), Fr::from(0x5_a1a8u64))
    }

    pub fn pre_state(&self) -> PreState {
        let mut pre = self.s.env.pre_state();
        let rid = self.s.request_id();
        if self.settle.pending {
            pre.swaps_records = vec![(rid, self.s.req().av(&self.s.env))];
            pre.swaps_envs = vec![(rid, self.s.env_av())];
        }
        pre
    }
}

impl Default for RefundSwapScenario {
    fn default() -> RefundSwapScenario {
        RefundSwapScenario::new()
    }
}

// ==== supply / completeSupply / refundSupply ==================================================

#[derive(Clone, Debug)]
pub struct StartSupplyScenario {
    pub env: Env,
    pub sk: [u8; 32],
    pub evm_nonce: u64,
    pub amount: u128,
    pub coin_nonce: [u8; 32],
    pub coin_color: Option<[u8; 32]>,
    pub coin_value: Option<u128>,
    pub request_exists: bool,
    pub cc_rand: Fr,
}

impl StartSupplyScenario {
    pub fn new() -> StartSupplyScenario {
        StartSupplyScenario {
            env: Env::new(),
            sk: tagged32(b"supplier", 0x24),
            evm_nonce: 17,
            amount: 8_000,
            coin_nonce: tagged32(b"supply-coin", 0x46),
            coin_color: None,
            coin_value: None,
            request_exists: false,
            cc_rand: Fr::from(0x5_5555u64),
        }
    }

    pub fn amount_u64(&self) -> u64 {
        unbounded_to_u64(self.amount)
    }
    pub fn coin_color(&self) -> [u8; 32] {
        self.coin_color.unwrap_or_else(|| vault_color(&self.env.stata_underlying, &self.env.self_addr))
    }
    pub fn coin_value(&self) -> u128 {
        self.coin_value.unwrap_or(self.amount)
    }

    pub fn burn_effects(&self) -> Vec<VmOp> {
        let mut o = self.env.kernel_self();
        let evolved = evolved_nonce(&self.coin_nonce);
        let cm = coin_commitment_of(&evolved, &self.coin_color(), self.coin_value(), true, &[0u8; 32]);
        o.extend(ops::claim(2, &cm));
        o
    }

    pub fn req(&self) -> Req<SUPPLY_WORDS> {
        Req {
            path: pad32(VAULT_PATH),
            out_schema: SHARES_SCHEMA,
            tx: Tx {
                nonce: self.evm_nonce,
                priority_fee: 1_000_000_000,
                max_fee: 30_000_000_000,
                gas: LENDING_GAS,
                to: self.env.stata_token,
                selector: DEPOSIT_SELECTOR,
                words: [abi_num_word(self.amount), abi_addr_word(&self.env.vault_evm)],
            },
        }
    }

    pub fn request_id(&self) -> [u8; 32] {
        self.req().request_id(&self.env)
    }

    pub fn refund_commitment(&self) -> [u8; 32] {
        refund_commit_of(&self.sk, &self.request_id())
    }

    pub fn env_limbs(&self) -> Vec<Fr> {
        let (c_hi, c_lo) = b32_slots(&self.refund_commitment());
        vec![c_hi, c_lo, Fr::from(self.amount_u64())]
    }

    pub fn env_av(&self) -> AlignedValue {
        aligned(&[32, 8], &self.env_limbs())
    }

    pub fn inputs(&self) -> Vec<Fr> {
        vec![
            Fr::from(self.evm_nonce),
            u128_limb(self.amount),
            b32_slots(&self.coin_nonce).0,
            b32_slots(&self.coin_nonce).1,
            b32_slots(&self.coin_color()).0,
            b32_slots(&self.coin_color()).1,
            u128_limb(self.coin_value()),
        ]
    }

    pub fn witnesses(&self) -> Vec<Fr> {
        let (hi, lo) = b32_slots(&self.sk);
        let mut w = vec![hi, lo];
        w.extend(call_witnesses(&self.env, self.cc_rand));
        w
    }

    pub fn ops(&self) -> Vec<VmOp> {
        let mut o = self.env.read_initialized();
        o.extend(self.env.read_stata_underlying());
        o.extend(self.burn_effects());
        o.extend(self.env.read_vault_evm());
        o.extend(self.env.read_stata_token());
        let rid = self.request_id();
        o.extend(file_request_ops(
            &self.env,
            SUPPLIES_RECORDS,
            Some(SUPPLIES_ENVS),
            &rid,
            self.request_exists,
            self.req().av(&self.env),
            Some(self.env_av()),
            self.cc_rand,
        ));
        o
    }

    pub fn preimage(&self) -> ProofPreimage {
        preimage_of(self.inputs(), self.witnesses(), &self.ops(), Fr::from(0x5_5556u64))
    }

    pub fn pre_state(&self) -> PreState {
        let mut pre = self.env.pre_state();
        if self.request_exists {
            let rid = self.request_id();
            pre.supplies_records = vec![(rid, self.req().av(&self.env))];
            pre.supplies_envs = vec![(rid, self.env_av())];
        }
        pre
    }
}

impl Default for StartSupplyScenario {
    fn default() -> StartSupplyScenario {
        StartSupplyScenario::new()
    }
}

#[derive(Clone, Debug)]
pub struct CompleteSupplyScenario {
    pub s: StartSupplyScenario,
    pub settle: Settle,
    pub shares: u64,
}

impl CompleteSupplyScenario {
    pub fn new() -> CompleteSupplyScenario {
        CompleteSupplyScenario {
            s: StartSupplyScenario::new(),
            settle: Settle::new(),
            shares: 7_900,
        }
    }

    /// The minted `shares` as a V1 attested `uint256`: two limbs.
    pub fn output_limbs(&self) -> Vec<Fr> {
        word_output_limbs(self.shares)
    }

    pub fn inputs(&self) -> Vec<Fr> {
        let mut v = settle_head_inputs(self.s.env.key_seed, self.settle.nonce_seed, &self.s.request_id(), self.settle.block_height, output_kind::EXECUTED, WORD_WIDTH, &self.output_limbs());
        v.extend(self.settle.nonce_slots());
        v
    }

    pub fn witnesses(&self) -> Vec<Fr> {
        let (hi, lo) = b32_slots(&self.settle.sk(&self.s.sk));
        let (pk_hi, pk_lo) = b32_slots(&self.settle.own_pk);
        vec![hi, lo, pk_hi, pk_lo]
    }

    pub fn ops(&self) -> Vec<VmOp> {
        let rid = self.s.request_id();
        let mut o = self.s.env.read_initialized();
        o.extend(consume_ops(&self.s.env, SUPPLIES_RECORDS, SUPPLIES_ENVS, &rid, self.settle.pending, self.s.req().av(&self.s.env), self.s.env_av()));
        o.extend(self.s.env.read_stata_token());
        o.extend(self.s.env.kernel_self());
        let color = vault_color(&self.s.env.stata_token, &self.s.env.self_addr);
        let cm = coin_commitment_of(&b32_slots(&self.settle.mint_nonce), &color, u128::from(self.shares), true, &self.settle.own_pk);
        o.extend(ops::mint_and_spend(&vault_token_domain_sep(&self.s.env.stata_token), self.shares, &cm));
        o
    }

    pub fn preimage(&self) -> ProofPreimage {
        preimage_of(self.inputs(), self.witnesses(), &self.ops(), Fr::from(0x5_5557u64))
    }

    pub fn pre_state(&self) -> PreState {
        let mut pre = self.s.env.pre_state();
        let rid = self.s.request_id();
        if self.settle.pending {
            pre.supplies_records = vec![(rid, self.s.req().av(&self.s.env))];
            pre.supplies_envs = vec![(rid, self.s.env_av())];
        }
        pre
    }
}

impl Default for CompleteSupplyScenario {
    fn default() -> CompleteSupplyScenario {
        CompleteSupplyScenario::new()
    }
}

#[derive(Clone, Debug)]
pub struct RefundSupplyScenario {
    pub s: StartSupplyScenario,
    pub settle: Settle,
    /// M37 rung D. This call's return is a NUMBER, so `EvmCall::succeeded`
    /// is `always` and an executed attestation is a success: only the MPC's
    /// failure kind refunds here, which is the deployed semantics exactly.
    pub attested: Attested,
}

impl RefundSupplyScenario {
    pub fn new() -> RefundSupplyScenario {
        RefundSupplyScenario {
            s: StartSupplyScenario::new(),
            settle: Settle::new(),
            attested: Attested::Failure { padding: 0 },
        }
    }

    pub fn refundable(&self) -> bool {
        self.attested.refundable(false)
    }

    pub fn inputs(&self) -> Vec<Fr> {
        let mut v = settle_head_inputs_padded(
            self.s.env.key_seed,
            self.settle.nonce_seed,
            &self.s.request_id(),
            self.settle.block_height,

            self.attested.output_kind(),

            self.attested.signed_width(WORD_WIDTH),
            &self.attested.signed_limbs(WORD_WIDTH),
            &self.attested.slot_limbs(WORD_WIDTH),
        );
        v.extend(self.settle.nonce_slots());
        v
    }

    pub fn witnesses(&self) -> Vec<Fr> {
        let (hi, lo) = b32_slots(&self.settle.sk(&self.s.sk));
        let (pk_hi, pk_lo) = b32_slots(&self.settle.own_pk);
        vec![hi, lo, pk_hi, pk_lo]
    }

    pub fn ops(&self) -> Vec<VmOp> {
        let rid = self.s.request_id();
        let mut o = self.s.env.read_initialized();
        o.extend(consume_ops(&self.s.env, SUPPLIES_RECORDS, SUPPLIES_ENVS, &rid, self.settle.pending, self.s.req().av(&self.s.env), self.s.env_av()));
        o.extend(self.s.env.read_stata_underlying());
        o.extend(self.s.env.kernel_self());
        let color = vault_color(&self.s.env.stata_underlying, &self.s.env.self_addr);
        let cm = coin_commitment_of(&b32_slots(&self.settle.mint_nonce), &color, u128::from(self.s.amount_u64()), true, &self.settle.own_pk);
        o.extend(ops::mint_and_spend(&vault_token_domain_sep(&self.s.env.stata_underlying), self.s.amount_u64(), &cm));
        o
    }

    pub fn preimage(&self) -> ProofPreimage {
        preimage_of(self.inputs(), self.witnesses(), &self.ops(), Fr::from(0x5_5558u64))
    }

    pub fn pre_state(&self) -> PreState {
        let mut pre = self.s.env.pre_state();
        let rid = self.s.request_id();
        if self.settle.pending {
            pre.supplies_records = vec![(rid, self.s.req().av(&self.s.env))];
            pre.supplies_envs = vec![(rid, self.s.env_av())];
        }
        pre
    }
}

impl Default for RefundSupplyScenario {
    fn default() -> RefundSupplyScenario {
        RefundSupplyScenario::new()
    }
}

// ==== redeem / completeRedeem / refundRedeem ===================================================

#[derive(Clone, Debug)]
pub struct StartRedeemScenario {
    pub env: Env,
    pub sk: [u8; 32],
    pub evm_nonce: u64,
    pub shares: u128,
    pub coin_nonce: [u8; 32],
    pub coin_color: Option<[u8; 32]>,
    pub coin_value: Option<u128>,
    pub request_exists: bool,
    pub cc_rand: Fr,
}

impl StartRedeemScenario {
    pub fn new() -> StartRedeemScenario {
        StartRedeemScenario {
            env: Env::new(),
            sk: tagged32(b"redeemer", 0x25),
            evm_nonce: 19,
            shares: 3_000,
            coin_nonce: tagged32(b"redeem-coin", 0x47),
            coin_color: None,
            coin_value: None,
            request_exists: false,
            cc_rand: Fr::from(0x6_6666u64),
        }
    }

    pub fn shares_u64(&self) -> u64 {
        unbounded_to_u64(self.shares)
    }
    pub fn coin_color(&self) -> [u8; 32] {
        self.coin_color.unwrap_or_else(|| vault_color(&self.env.stata_token, &self.env.self_addr))
    }
    pub fn coin_value(&self) -> u128 {
        self.coin_value.unwrap_or(self.shares)
    }

    pub fn burn_effects(&self) -> Vec<VmOp> {
        let mut o = self.env.kernel_self();
        let evolved = evolved_nonce(&self.coin_nonce);
        let cm = coin_commitment_of(&evolved, &self.coin_color(), self.coin_value(), true, &[0u8; 32]);
        o.extend(ops::claim(2, &cm));
        o
    }

    pub fn req(&self) -> Req<REDEEM_WORDS> {
        Req {
            path: pad32(VAULT_PATH),
            out_schema: ASSETS_SCHEMA,
            tx: Tx {
                nonce: self.evm_nonce,
                priority_fee: 1_000_000_000,
                max_fee: 30_000_000_000,
                gas: LENDING_GAS,
                to: self.env.stata_token,
                selector: REDEEM_SELECTOR,
                words: [abi_num_word(self.shares), abi_addr_word(&self.env.vault_evm), abi_addr_word(&self.env.vault_evm)],
            },
        }
    }

    pub fn request_id(&self) -> [u8; 32] {
        self.req().request_id(&self.env)
    }

    pub fn refund_commitment(&self) -> [u8; 32] {
        refund_commit_of(&self.sk, &self.request_id())
    }

    pub fn env_limbs(&self) -> Vec<Fr> {
        let (c_hi, c_lo) = b32_slots(&self.refund_commitment());
        vec![c_hi, c_lo, Fr::from(self.shares_u64())]
    }

    pub fn env_av(&self) -> AlignedValue {
        aligned(&[32, 8], &self.env_limbs())
    }

    pub fn inputs(&self) -> Vec<Fr> {
        vec![
            Fr::from(self.evm_nonce),
            u128_limb(self.shares),
            b32_slots(&self.coin_nonce).0,
            b32_slots(&self.coin_nonce).1,
            b32_slots(&self.coin_color()).0,
            b32_slots(&self.coin_color()).1,
            u128_limb(self.coin_value()),
        ]
    }

    pub fn witnesses(&self) -> Vec<Fr> {
        let (hi, lo) = b32_slots(&self.sk);
        let mut w = vec![hi, lo];
        w.extend(call_witnesses(&self.env, self.cc_rand));
        w
    }

    pub fn ops(&self) -> Vec<VmOp> {
        let mut o = self.env.read_initialized();
        o.extend(self.env.read_stata_token());
        o.extend(self.burn_effects());
        o.extend(self.env.read_vault_evm());
        let rid = self.request_id();
        o.extend(file_request_ops(
            &self.env,
            REDEEMS_RECORDS,
            Some(REDEEMS_ENVS),
            &rid,
            self.request_exists,
            self.req().av(&self.env),
            Some(self.env_av()),
            self.cc_rand,
        ));
        o
    }

    pub fn preimage(&self) -> ProofPreimage {
        preimage_of(self.inputs(), self.witnesses(), &self.ops(), Fr::from(0x6_6667u64))
    }

    pub fn pre_state(&self) -> PreState {
        let mut pre = self.env.pre_state();
        if self.request_exists {
            let rid = self.request_id();
            pre.redeems_records = vec![(rid, self.req().av(&self.env))];
            pre.redeems_envs = vec![(rid, self.env_av())];
        }
        pre
    }
}

impl Default for StartRedeemScenario {
    fn default() -> StartRedeemScenario {
        StartRedeemScenario::new()
    }
}

#[derive(Clone, Debug)]
pub struct CompleteRedeemScenario {
    pub s: StartRedeemScenario,
    pub settle: Settle,
    pub assets: u64,
}

impl CompleteRedeemScenario {
    pub fn new() -> CompleteRedeemScenario {
        CompleteRedeemScenario {
            s: StartRedeemScenario::new(),
            settle: Settle::new(),
            assets: 3_050,
        }
    }

    /// The returned `assets` as a V1 attested `uint256`: two limbs.
    pub fn output_limbs(&self) -> Vec<Fr> {
        word_output_limbs(self.assets)
    }

    pub fn inputs(&self) -> Vec<Fr> {
        let mut v = settle_head_inputs(self.s.env.key_seed, self.settle.nonce_seed, &self.s.request_id(), self.settle.block_height, output_kind::EXECUTED, WORD_WIDTH, &self.output_limbs());
        v.extend(self.settle.nonce_slots());
        v
    }

    pub fn witnesses(&self) -> Vec<Fr> {
        let (hi, lo) = b32_slots(&self.settle.sk(&self.s.sk));
        let (pk_hi, pk_lo) = b32_slots(&self.settle.own_pk);
        vec![hi, lo, pk_hi, pk_lo]
    }

    pub fn ops(&self) -> Vec<VmOp> {
        let rid = self.s.request_id();
        let mut o = self.s.env.read_initialized();
        o.extend(consume_ops(&self.s.env, REDEEMS_RECORDS, REDEEMS_ENVS, &rid, self.settle.pending, self.s.req().av(&self.s.env), self.s.env_av()));
        o.extend(self.s.env.read_stata_underlying());
        o.extend(self.s.env.kernel_self());
        let color = vault_color(&self.s.env.stata_underlying, &self.s.env.self_addr);
        let cm = coin_commitment_of(&b32_slots(&self.settle.mint_nonce), &color, u128::from(self.assets), true, &self.settle.own_pk);
        o.extend(ops::mint_and_spend(&vault_token_domain_sep(&self.s.env.stata_underlying), self.assets, &cm));
        o
    }

    pub fn preimage(&self) -> ProofPreimage {
        preimage_of(self.inputs(), self.witnesses(), &self.ops(), Fr::from(0x6_6668u64))
    }

    pub fn pre_state(&self) -> PreState {
        let mut pre = self.s.env.pre_state();
        let rid = self.s.request_id();
        if self.settle.pending {
            pre.redeems_records = vec![(rid, self.s.req().av(&self.s.env))];
            pre.redeems_envs = vec![(rid, self.s.env_av())];
        }
        pre
    }
}

impl Default for CompleteRedeemScenario {
    fn default() -> CompleteRedeemScenario {
        CompleteRedeemScenario::new()
    }
}

#[derive(Clone, Debug)]
pub struct RefundRedeemScenario {
    pub s: StartRedeemScenario,
    pub settle: Settle,
    /// M37 rung D. This call's return is a NUMBER, so `EvmCall::succeeded`
    /// is `always` and an executed attestation is a success: only the MPC's
    /// failure kind refunds here, which is the deployed semantics exactly.
    pub attested: Attested,
}

impl RefundRedeemScenario {
    pub fn new() -> RefundRedeemScenario {
        RefundRedeemScenario {
            s: StartRedeemScenario::new(),
            settle: Settle::new(),
            attested: Attested::Failure { padding: 0 },
        }
    }

    pub fn refundable(&self) -> bool {
        self.attested.refundable(false)
    }

    pub fn inputs(&self) -> Vec<Fr> {
        let mut v = settle_head_inputs_padded(
            self.s.env.key_seed,
            self.settle.nonce_seed,
            &self.s.request_id(),
            self.settle.block_height,

            self.attested.output_kind(),

            self.attested.signed_width(WORD_WIDTH),
            &self.attested.signed_limbs(WORD_WIDTH),
            &self.attested.slot_limbs(WORD_WIDTH),
        );
        v.extend(self.settle.nonce_slots());
        v
    }

    pub fn witnesses(&self) -> Vec<Fr> {
        let (hi, lo) = b32_slots(&self.settle.sk(&self.s.sk));
        let (pk_hi, pk_lo) = b32_slots(&self.settle.own_pk);
        vec![hi, lo, pk_hi, pk_lo]
    }

    pub fn ops(&self) -> Vec<VmOp> {
        let rid = self.s.request_id();
        let mut o = self.s.env.read_initialized();
        o.extend(consume_ops(&self.s.env, REDEEMS_RECORDS, REDEEMS_ENVS, &rid, self.settle.pending, self.s.req().av(&self.s.env), self.s.env_av()));
        o.extend(self.s.env.read_stata_token());
        o.extend(self.s.env.kernel_self());
        let color = vault_color(&self.s.env.stata_token, &self.s.env.self_addr);
        let cm = coin_commitment_of(&b32_slots(&self.settle.mint_nonce), &color, u128::from(self.s.shares_u64()), true, &self.settle.own_pk);
        o.extend(ops::mint_and_spend(&vault_token_domain_sep(&self.s.env.stata_token), self.s.shares_u64(), &cm));
        o
    }

    pub fn preimage(&self) -> ProofPreimage {
        preimage_of(self.inputs(), self.witnesses(), &self.ops(), Fr::from(0x6_6669u64))
    }

    pub fn pre_state(&self) -> PreState {
        let mut pre = self.s.env.pre_state();
        let rid = self.s.request_id();
        if self.settle.pending {
            pre.redeems_records = vec![(rid, self.s.req().av(&self.s.env))];
            pre.redeems_envs = vec![(rid, self.s.env_av())];
        }
        pre
    }
}

impl Default for RefundRedeemScenario {
    fn default() -> RefundRedeemScenario {
        RefundRedeemScenario::new()
    }
}

fn unbounded_to_u64(v: u128) -> u64 {
    u64::try_from(v).unwrap_or(u64::MAX)
}

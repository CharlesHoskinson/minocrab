//! The erc20-vault REFERENCE MODEL (M44, the flush-pattern vault): per-circuit
//! scenarios that carry a concrete pre-state plus the arguments and witnesses
//! of one call, and emit the Impact op stream and the `ProofPreimage` that
//! stream implies.
//!
//! Shape: an [`Env`] is the configuration every circuit may read plus the
//! call context; a [`Sent`] is ONE request followed through the queue — its
//! buffered entry, its flushed index, its V1 event and request id — so the
//! send, queue-attestation and complete scenarios of every action are built
//! from the same object. The op stream is built from `ops::*` in the
//! circuit's read order — the order compactc's artifact reads in, which the
//! differential pins — and the popeq results are DERIVED from that stream
//! (`ops::outputs_of`), so a scenario cannot list an output its ops never
//! read.

use std::borrow::Cow;

use midnight_base_crypto::fab::AlignedValue;
use midnight_curves::k256;
use midnight_transient_crypto::hash::transient_commit;
use midnight_transient_crypto::proofs::{KeyLocation, ProofPreimage};
use midnight_zkir_v3::ir_instructions::ec_mul::ec_mul_offcircuit;
use minocrab::Fr;
use minocrab_contracts::erc20_vault as v;
use minocrab_contracts::signet_v1::output_kind;
use minocrab_zkir::v3::IrValue;

use super::exec::PreState;
use super::ops::{self, key20, key32, key_u64};
use super::prims::*;

// ---- the ledger fields, by declaration index ----------------------------------------

pub const SIGNET_SIGNER: u8 = 0;
pub const MPC_RESPONSE_KEY: u8 = 1;
pub const MAX_FEE_PER_GAS: u8 = 2;
pub const MAX_PRIORITY_FEE_PER_GAS: u8 = 3;
pub const GAS_LIMITS: u8 = 4;
pub const INITIALISED: u8 = 5;
pub const VAULT_EVM_ADDRESS: u8 = 6;
pub const EVM_CHAIN_ID: u8 = 7;
pub const MPC_KEY_VERSION: u8 = 8;
pub const DEPLOYER: u8 = 9;
pub const UNISWAP_ROUTER: u8 = 10;
pub const STATA_UNDERLYING: u8 = 11;
pub const STATA_TOKEN: u8 = 12;
pub const ALLOWED_TOKENS: u8 = 13;
pub const GLOBAL_LAST_SEEN: u8 = 14;
pub const VAULT_ACCOUNT_NONCE: u8 = 15;
pub const INPUT_REQUEST_BUFFER: u8 = 16;
pub const OUTPUT_REQUEST_BUFFER: u8 = 17;
pub const INPUT_ATTESTATION_BUFFER: u8 = 18;
pub const OUTPUT_ATTESTATION_BUFFER: u8 = 19;
pub const EVICTION_MAP: u8 = 20;
pub const REPLACE_NONCE_MAP: u8 = 21;
pub const REPLACE_NONCE_ARGS: u8 = 22;
pub const APPROVE_MAP: u8 = 23;
pub const APPROVE_ARGS: u8 = 24;
pub const DEPOSIT_MAP: u8 = 25;
pub const DEPOSIT_ARGS: u8 = 26;
pub const WITHDRAW_MAP: u8 = 27;
pub const WITHDRAW_ARGS: u8 = 28;
pub const SWAP_MAP: u8 = 29;
pub const SWAP_ARGS: u8 = 30;
pub const SUPPLY_MAP: u8 = 31;
pub const SUPPLY_ARGS: u8 = 32;
pub const REDEEM_MAP: u8 = 33;
pub const REDEEM_ARGS: u8 = 34;

/// `enum Action`, with each action's two maps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Deposit,
    Withdraw,
    Swap,
    Supply,
    Redeem,
    Approve,
    ReplaceNonce,
}

impl Action {
    pub fn code(self) -> u64 {
        match self {
            Action::Deposit => v::action::DEPOSIT,
            Action::Withdraw => v::action::WITHDRAW,
            Action::Swap => v::action::SWAP,
            Action::Supply => v::action::SUPPLY,
            Action::Redeem => v::action::REDEEM,
            Action::Approve => v::action::APPROVE,
            Action::ReplaceNonce => v::action::REPLACE_NONCE,
        }
    }
    pub fn map_field(self) -> u8 {
        match self {
            Action::Deposit => DEPOSIT_MAP,
            Action::Withdraw => WITHDRAW_MAP,
            Action::Swap => SWAP_MAP,
            Action::Supply => SUPPLY_MAP,
            Action::Redeem => REDEEM_MAP,
            Action::Approve => APPROVE_MAP,
            Action::ReplaceNonce => REPLACE_NONCE_MAP,
        }
    }
    pub fn args_field(self) -> u8 {
        self.map_field() + 1
    }
    /// Does the vault's account sign (the flush assigns the nonce)?
    pub fn vault_signed(self) -> bool {
        !matches!(self, Action::Deposit)
    }
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

/// A `[u8; 32]` from a short tag and a distinguishing top byte.
pub fn tagged32(tag: &[u8], top: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..tag.len()].copy_from_slice(tag);
    out[31] = top;
    out
}

// ---- the environment -------------------------------------------------------------------

/// The configuration cells every circuit may read, plus the call context:
/// the contract's own address, the singleton's, the MPC key's secret seed
/// and the signer's entry-point hash.
#[derive(Clone, Debug)]
pub struct Env {
    pub initialised: bool,
    pub max_fee_per_gas: u128,
    pub max_priority_fee_per_gas: u128,
    /// `withdraw, approve, swap, supply, redeem`.
    pub gas_limits: [u64; 5],
    pub vault_evm: [u8; 20],
    pub chain_id: u64,
    pub key_version: u8,
    pub router: [u8; 20],
    pub stata_underlying: [u8; 20],
    pub stata_token: [u8; 20],
    /// An ERC20 `addAllowedToken` admitted (beside the underlying).
    pub allowed_erc20: [u8; 20],
    pub global_last_seen: u64,
    pub vault_account_nonce: u64,
    /// The secret whose commitment the `deployer` cell holds.
    pub deployer_sk: [u8; 32],
    pub self_addr: [u8; 32],
    pub signer_addr: [u8; 32],
    /// The MPC response key's secret scalar seed.
    pub key_seed: u64,
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
            initialised: true,
            max_fee_per_gas: v::DEFAULT_MAX_FEE_PER_GAS,
            max_priority_fee_per_gas: v::DEFAULT_MAX_PRIORITY_FEE_PER_GAS,
            gas_limits: [
                v::DEFAULT_WITHDRAW_GAS,
                v::DEFAULT_APPROVE_GAS,
                v::DEFAULT_SWAP_GAS,
                v::DEFAULT_SUPPLY_GAS,
                v::DEFAULT_REDEEM_GAS,
            ],
            vault_evm: *b"vault-evm-addr-20byt",
            chain_id: 11_155_111,
            key_version: 1,
            router: *b"uniswap-router-20byt",
            stata_underlying: *b"stata-underlying-usd",
            stata_token: *b"stata-token-wrapper!",
            allowed_erc20: *b"erc20-token-address!",
            global_last_seen: 7_000_000,
            vault_account_nonce: 4,
            deployer_sk: tagged32(b"deployer", 0x11),
            self_addr: SELF_ADDR,
            signer_addr: tagged32(b"signet-addr", 0x32),
            key_seed: 0xf00d_face,
            ep: minocrab_ledger::ep_hash("signBidirectional"),
        }
    }

    /// The MPC response key.
    pub fn mpc_key(&self) -> IrValue {
        let generator = IrValue::Secp256k1Point(k256::K256::generator());
        ec_mul_offcircuit(&generator, &scalar(self.key_seed)).unwrap()
    }

    /// The key as the `mpcResponseKey` cell holds it (5 FAB limbs).
    pub fn mpc_key_av(&self) -> AlignedValue {
        point_av(&self.mpc_key())
    }

    /// The `deployer` cell.
    pub fn deployer(&self) -> [u8; 32] {
        user_commitment(&self.deployer_sk)
    }

    /// The ledger with every cell set, the two allowed tokens, and every
    /// map empty.
    pub fn pre_state(&self) -> PreState {
        PreState {
            signet_signer: self.signer_addr,
            mpc_response_key: Some(self.mpc_key_av()),
            max_fee_per_gas: self.max_fee_per_gas,
            max_priority_fee_per_gas: self.max_priority_fee_per_gas,
            gas_limits: self.gas_limits,
            initialised: self.initialised,
            vault_evm: self.vault_evm,
            chain_id: self.chain_id,
            key_version: self.key_version,
            deployer: self.deployer(),
            uniswap_router: self.router,
            stata_underlying: self.stata_underlying,
            stata_token: self.stata_token,
            allowed_tokens: vec![self.stata_underlying, self.allowed_erc20],
            global_last_seen: self.global_last_seen,
            vault_account_nonce: self.vault_account_nonce,
            ..Default::default()
        }
    }

    // -- the reads every circuit shares --

    pub fn read_initialised(&self) -> Vec<VmOp> {
        ops::read(INITIALISED, false, bytesn_value(1, &[u8::from(self.initialised)]))
    }
    pub fn read_mpc_key(&self) -> Vec<VmOp> {
        ops::read(MPC_RESPONSE_KEY, false, self.mpc_key_av())
    }
    pub fn read_deployer(&self) -> Vec<VmOp> {
        ops::read(DEPLOYER, false, bytesn_value(32, &self.deployer()))
    }
    pub fn read_chain_id(&self) -> Vec<VmOp> {
        ops::read(EVM_CHAIN_ID, false, bytesn_value(8, &self.chain_id.to_le_bytes()))
    }
    pub fn read_key_version(&self) -> Vec<VmOp> {
        ops::read(MPC_KEY_VERSION, false, bytesn_value(1, &[self.key_version]))
    }
    pub fn read_b20(&self, field: u8) -> Vec<VmOp> {
        let value = match field {
            VAULT_EVM_ADDRESS => self.vault_evm,
            UNISWAP_ROUTER => self.router,
            STATA_UNDERLYING => self.stata_underlying,
            STATA_TOKEN => self.stata_token,
            _ => panic!("field {field} is not a Bytes<20> cell"),
        };
        ops::read(field, false, bytesn_value(20, &value))
    }
    pub fn read_u64(field: u8, value: u64) -> Vec<VmOp> {
        ops::read(field, false, bytesn_value(8, &value.to_le_bytes()))
    }
    /// `vaultGasLimits`, `vaultMaxFeePerGas`, `vaultMaxPriorityFeePerGas` —
    /// the three reads a vault-signed start makes for its `GasParams`.
    pub fn read_vault_gas(&self) -> Vec<VmOp> {
        let limbs: Vec<Fr> = self.gas_limits.iter().map(|g| Fr::from(*g)).collect();
        let mut o = ops::read(GAS_LIMITS, false, aligned(&[8, 8, 8, 8, 8], &limbs));
        o.extend(ops::read(MAX_FEE_PER_GAS, false, bytesn_value(16, &self.max_fee_per_gas.to_le_bytes())));
        o.extend(ops::read(MAX_PRIORITY_FEE_PER_GAS, false, bytesn_value(16, &self.max_priority_fee_per_gas.to_le_bytes())));
        o
    }
    pub fn kernel_self(&self) -> Vec<VmOp> {
        ops::kernel_self(&self.self_addr)
    }

    /// The vault's own `GasParams` for action `a`.
    pub fn vault_gas(&self, a: Action) -> Gas {
        let limit = match a {
            Action::Withdraw => self.gas_limits[0],
            Action::Approve => self.gas_limits[1],
            Action::Swap => self.gas_limits[2],
            Action::Supply => self.gas_limits[3],
            Action::Redeem => self.gas_limits[4],
            Action::ReplaceNonce => v::REPLACE_NONCE_GAS,
            Action::Deposit => panic!("a deposit's gas is the caller's"),
        };
        Gas {
            limit,
            max_fee: self.max_fee_per_gas,
            priority_fee: self.max_priority_fee_per_gas,
        }
    }

    /// The V1 notification payload: selfAddr ‖ depth ‖ path[4] ‖ zeros, as
    /// the `Bytes<128>` limbs in slot order.
    pub fn notification_payload_limbs(&self, map_field: u8) -> Vec<Fr> {
        let (seg, off) = ops::segment_of(map_field);
        let mut bytes = [0u8; 128];
        bytes[..32].copy_from_slice(&self.self_addr);
        bytes[32] = 2; // depth: every path is two elements
        bytes[33] = seg;
        bytes[34] = off;
        let mut limbs: Vec<Fr> = bytes.chunks(31).map(|chunk| Fr::from_le_bytes(chunk).unwrap()).collect();
        limbs.reverse();
        limbs
    }

    /// The cross-contract-call args: requestId + notification (version,
    /// payload).
    pub fn call_args(&self, map_field: u8, request_id: &[u8; 32]) -> Vec<Fr> {
        let (rid_hi, rid_lo) = b32_slots(request_id);
        let mut args = vec![rid_hi, rid_lo, Fr::from(1u64)];
        args.extend(self.notification_payload_limbs(map_field));
        args
    }

    /// `signetSigner.signBidirectional(requestId, notification)`: the
    /// signer read, `kernel.self()`, the claimed call.
    pub fn notify_ops(&self, map_field: u8, request_id: &[u8; 32], cc_rand: Fr) -> Vec<VmOp> {
        let mut o = ops::read(SIGNET_SIGNER, false, bytesn_value(32, &self.signer_addr));
        o.extend(self.kernel_self());
        let comm = transient_commit(&self.call_args(map_field, request_id)[..], cc_rand);
        o.extend(ops::claim_contract_call(&self.signer_addr, &self.ep, comm));
        o
    }

    /// The cross-contract call's witnesses: `cc-rand`, then the entry-point
    /// hash's two limbs.
    pub fn call_witnesses(&self, cc_rand: Fr) -> Vec<Fr> {
        let (ep_hi, ep_lo) = b32_slots(&self.ep);
        vec![cc_rand, ep_hi, ep_lo]
    }

    /// `tokenType(…, kernel.self())`'s read, then `receiveShielded(coin);
    /// sendImmediateShielded(coin, burn, value)` — the custody claim, the
    /// nullifier, the evolved-nonce output.
    pub fn coin_ops(&self, coin: &Coin) -> Vec<VmOp> {
        let nonce_slots = b32_slots(&coin.nonce);
        let cm_receive = coin_commitment_of(&nonce_slots, &coin.color, coin.value, false, &self.self_addr);
        let nullifier = coin_nullifier_of(&nonce_slots, &coin.color, coin.value, &self.self_addr);
        let cm_burn = coin_commitment_of(&evolved_nonce(&coin.nonce), &coin.color, coin.value, true, &[0u8; 32]);
        let mut o = self.kernel_self();
        o.extend(self.kernel_self());
        o.extend(ops::claim(1, &cm_receive));
        o.extend(self.kernel_self());
        o.extend(ops::claim(0, &nullifier));
        o.extend(ops::claim(2, &cm_burn));
        o
    }

    /// `mintShieldedToken(vaultTokenDomainSeparator(erc20), amount, nonce,
    /// left(pk))`: `kernel.self()`, the mint, the spend claim.
    pub fn mint_to_key_ops(&self, erc20: &[u8; 20], amount: u64, nonce: &[u8; 32], pk: &[u8; 32]) -> Vec<VmOp> {
        let color = vault_color(erc20, &self.self_addr);
        let cm = coin_commitment_of(&b32_slots(nonce), &color, u128::from(amount), true, pk);
        let mut o = self.kernel_self();
        o.extend(ops::mint_and_spend(&vault_domain_sep(erc20), amount, &cm));
        o
    }

    /// A vault coin of `value` base units of `erc20`.
    pub fn coin(&self, erc20: &[u8; 20], value: u128, tag: u8) -> Coin {
        Coin {
            nonce: tagged32(b"coin-nonce", tag),
            color: vault_color(erc20, &self.self_addr),
            value,
        }
    }
}

/// A `Secp256k1Point` as its cell value.
pub fn point_av(point: &IrValue) -> AlignedValue {
    aligned_atoms(&v::secp256k1_point_atoms(), &natives(point))
}

fn aligned_atoms(atoms: &[minocrab::AlignmentAtom], limbs: &[Fr]) -> AlignedValue {
    use midnight_base_crypto::fab::{Alignment, AlignmentSegment};
    use midnight_transient_crypto::fab::AlignmentExt;
    Alignment(atoms.iter().cloned().map(AlignmentSegment::Atom).collect())
        .parse_field_repr(limbs)
        .expect("limbs match the alignment")
}

/// The `ProofPreimage` a call implies: arguments, witnesses, the op stream's
/// `field_repr`, and the popeq results the stream reads.
pub fn preimage_of(inputs: Vec<Fr>, witnesses: Vec<Fr>, ops: &[VmOp], rand: Fr) -> ProofPreimage {
    let comm = transient_commit(&inputs[..], rand);
    ProofPreimage {
        public_transcript_inputs: ops::transcript_of(ops),
        public_transcript_outputs: ops::outputs_of(ops),
        inputs,
        private_transcript: witnesses,
        binding_input: 0.into(),
        communications_commitment: Some((comm, rand)),
        key_location: KeyLocation(Cow::Borrowed("minocrab-contracts-test")),
    }
}

/// A surrendered vault coin, as the `ShieldedCoinInfo` argument.
#[derive(Clone, Debug)]
pub struct Coin {
    pub nonce: [u8; 32],
    pub color: [u8; 32],
    pub value: u128,
}

impl Coin {
    pub fn inputs(&self) -> Vec<Fr> {
        let (n_hi, n_lo) = b32_slots(&self.nonce);
        let (c_hi, c_lo) = b32_slots(&self.color);
        vec![n_hi, n_lo, c_hi, c_lo, u128_limb(self.value)]
    }
}

// ---- the stored values -------------------------------------------------------------------

/// `struct GasParams { gasLimit, maxFeePerGas, maxPriorityFeePerGas }`.
#[derive(Clone, Copy, Debug)]
pub struct Gas {
    pub limit: u64,
    pub max_fee: u128,
    pub priority_fee: u128,
}

impl Gas {
    pub fn limbs(&self) -> Vec<Fr> {
        vec![Fr::from(self.limit), u128_limb(self.max_fee), u128_limb(self.priority_fee)]
    }
    pub const WIDTHS: [u32; 3] = [8, 16, 16];
}

/// An action's args as its args map stores them: limbs, atom widths and
/// the hash tag.
#[derive(Clone, Debug)]
pub enum Args {
    ReplaceNonce { gas: Gas },
    Approve { erc20: [u8; 20], spender: [u8; 20], gas: Gas },
    Deposit { erc20: [u8; 20], amount: u128, path: [u8; 32], gas: Gas },
    Withdraw { erc20: [u8; 20], amount: u128, dest: [u8; 20], gas: Gas },
    Swap { token_in: [u8; 20], token_out: [u8; 20], fee: u128, amount_out: u128, amount_in_max: u128, gas: Gas },
    Supply { amount: u128, gas: Gas },
    Redeem { shares: u128, gas: Gas },
}

impl Args {
    pub fn action(&self) -> Action {
        match self {
            Args::ReplaceNonce { .. } => Action::ReplaceNonce,
            Args::Approve { .. } => Action::Approve,
            Args::Deposit { .. } => Action::Deposit,
            Args::Withdraw { .. } => Action::Withdraw,
            Args::Swap { .. } => Action::Swap,
            Args::Supply { .. } => Action::Supply,
            Args::Redeem { .. } => Action::Redeem,
        }
    }

    pub fn gas(&self) -> Gas {
        match self {
            Args::ReplaceNonce { gas }
            | Args::Approve { gas, .. }
            | Args::Deposit { gas, .. }
            | Args::Withdraw { gas, .. }
            | Args::Swap { gas, .. }
            | Args::Supply { gas, .. }
            | Args::Redeem { gas, .. } => *gas,
        }
    }

    pub fn tag(&self) -> &'static str {
        match self {
            Args::ReplaceNonce { .. } => v::REPLACE_NONCE_ARGS_PAD,
            Args::Approve { .. } => v::APPROVE_ARGS_PAD,
            Args::Deposit { .. } => v::DEPOSIT_ARGS_PAD,
            Args::Withdraw { .. } => v::WITHDRAW_ARGS_PAD,
            Args::Swap { .. } => v::SWAP_ARGS_PAD,
            Args::Supply { .. } => v::SUPPLY_ARGS_PAD,
            Args::Redeem { .. } => v::REDEEM_ARGS_PAD,
        }
    }

    pub fn limbs(&self) -> Vec<Fr> {
        let mut l = match self {
            Args::ReplaceNonce { .. } => vec![],
            Args::Approve { erc20, spender, .. } => vec![b20(erc20), b20(spender)],
            Args::Deposit { erc20, amount, path, .. } => {
                let (p_hi, p_lo) = b32_slots(path);
                vec![b20(erc20), u128_limb(*amount), p_hi, p_lo]
            }
            Args::Withdraw { erc20, amount, dest, .. } => vec![b20(erc20), u128_limb(*amount), b20(dest)],
            Args::Swap {
                token_in,
                token_out,
                fee,
                amount_out,
                amount_in_max,
                ..
            } => vec![b20(token_in), b20(token_out), u128_limb(*fee), u128_limb(*amount_out), u128_limb(*amount_in_max)],
            Args::Supply { amount, .. } => vec![u128_limb(*amount)],
            Args::Redeem { shares, .. } => vec![u128_limb(*shares)],
        };
        l.extend(self.gas().limbs());
        l
    }

    pub fn widths(&self) -> Vec<u32> {
        let mut w: Vec<u32> = match self {
            Args::ReplaceNonce { .. } => vec![],
            Args::Approve { .. } => vec![20, 20],
            Args::Deposit { .. } => vec![20, 16, 32],
            Args::Withdraw { .. } => vec![20, 16, 20],
            Args::Swap { .. } => vec![20, 20, 16, 16, 16],
            Args::Supply { .. } | Args::Redeem { .. } => vec![16],
        };
        w.extend(Gas::WIDTHS);
        w
    }

    pub fn av(&self) -> AlignedValue {
        aligned(&self.widths(), &self.limbs())
    }

    pub fn hash(&self) -> [u8; 32] {
        args_hash(self.tag(), &self.limbs())
    }
}

/// `struct RequestBufferEntry`.
#[derive(Clone, Debug)]
pub struct Entry {
    pub action: Action,
    pub use_next: bool,
    pub evm_nonce: u64,
    pub in_index: u64,
    pub commitment: [u8; 32],
    pub args_hash: [u8; 32],
}

impl Entry {
    pub const WIDTHS: [u32; 6] = [1, 1, 8, 8, 32, 32];

    pub fn limbs(&self) -> Vec<Fr> {
        let (c_hi, c_lo) = b32_slots(&self.commitment);
        let (a_hi, a_lo) = b32_slots(&self.args_hash);
        vec![
            Fr::from(self.action.code()),
            Fr::from(u64::from(self.use_next)),
            Fr::from(self.evm_nonce),
            Fr::from(self.in_index),
            c_hi,
            c_lo,
            a_hi,
            a_lo,
        ]
    }

    pub fn av(&self) -> AlignedValue {
        aligned(&Self::WIDTHS, &self.limbs())
    }

    /// `OutputRequestEntry { entry, lastSeen }`.
    pub fn out_av(&self, last_seen: u64) -> AlignedValue {
        let mut limbs = self.limbs();
        limbs.push(Fr::from(last_seen));
        let mut widths = Self::WIDTHS.to_vec();
        widths.push(8);
        aligned(&widths, &limbs)
    }
}

/// `struct AttestationRecord { blockHeight, outputKind, digest }`.
#[derive(Clone, Debug)]
pub struct Record {
    pub block_height: u64,
    pub output_kind: u64,
    pub digest: [u8; 32],
}

impl Record {
    pub fn av(&self) -> AlignedValue {
        let (d_hi, d_lo) = b32_slots(&self.digest);
        aligned(&[8, 1, 32], &[Fr::from(self.block_height), Fr::from(self.output_kind), d_hi, d_lo])
    }
}

// ---- a Signet V1 request --------------------------------------------------------------------

/// The EVM transaction a request asks the MPC to sign.
#[derive(Clone, Debug)]
pub struct Tx {
    pub nonce: u64,
    pub gas: Gas,
    pub to: [u8; 20],
    /// `none` for a nonce replacement.
    pub calldata: Option<([u8; 4], Vec<[u8; 32]>)>,
    /// The record's word capacity (`EvmType2TxParams<capacity, 0, 0>`).
    pub capacity: usize,
}

/// A `SignBidirectionalEventV1` as the record holds it.
#[derive(Clone, Debug)]
pub struct Req {
    pub key_version: u8,
    pub path: [u8; 32],
    pub tx: Tx,
    pub out_schema: &'static [u8],
}

impl Req {
    /// The record's FAB limbs in slot order.
    pub fn limbs(&self, env: &Env) -> Vec<Fr> {
        let (self_hi, self_lo) = b32_slots(&env.self_addr);
        let (path_hi, path_lo) = b32_slots(&self.path);
        let (caip2_hi, caip2_lo) = b32_slots(&pad32(minocrab_contracts::signet_v1::ETHEREUM_CAIP2_ID));
        let (is_some, selector, words): (u64, Fr, Vec<[u8; 32]>) = match &self.tx.calldata {
            Some((sel, words)) => (1, Fr::from_le_bytes(sel).unwrap(), words.clone()),
            None => (0, Fr::from(0u64), vec![]),
        };
        let mut limbs = vec![
            Fr::from(u64::from(self.key_version)),
            self_hi,
            self_lo,
            path_hi,
            path_lo,
            Fr::from(0u64), // algo: ecdsa
            Fr::from(0u64), // txParamType: evmType2
            Fr::from(env.chain_id),
            Fr::from(self.tx.nonce),
            u128_limb(self.tx.gas.priority_fee),
            u128_limb(self.tx.gas.max_fee),
            Fr::from(self.tx.gas.limit),
            b20(&self.tx.to),
            Fr::from(0u64), // value
            Fr::from(is_some),
            selector,
            Fr::from(words.len() as u64), // noWords
        ];
        for i in 0..self.tx.capacity {
            let w = words.get(i).copied().unwrap_or([0u8; 32]);
            let (hi, lo) = b32_slots(&w);
            limbs.extend([hi, lo]);
        }
        limbs.push(Fr::from(0u64)); // accessListEntryCount
        limbs.extend([caip2_hi, caip2_lo]); // executionDest
        limbs.push(Fr::from(0u64)); // signatureDest: unused
        limbs.extend([Fr::from(0u64); 3]); // params: pad(64, "")
        limbs.extend(schema_limbs(self.out_schema));
        limbs
    }

    /// The record's FAB atom widths (the trailing `Bytes<0>` included).
    pub fn widths(&self) -> Vec<u32> {
        let mut a = vec![1, 32, 32, 1, 1, 8, 8, 16, 16, 8, 20, 16, 1, 4, 2];
        a.extend(std::iter::repeat_n(32u32, self.tx.capacity));
        a.extend([1, 32, 1, 64, self.out_schema.len() as u32, 0]);
        a
    }

    /// The record as an AlignedValue (the map-insert's pushed cell).
    pub fn av(&self, env: &Env) -> AlignedValue {
        aligned(&self.widths(), &self.limbs(env))
    }

    /// `calculateEvmType2TxParamsDigestV1(txParams)`.
    pub fn tx_digest(&self, env: &Env) -> [u8; 32] {
        let calldata = self.tx.calldata.as_ref().map(|(sel, words)| (sel, words.as_slice()));
        tx_params_digest(
            env.chain_id,
            self.tx.nonce,
            self.tx.gas.priority_fee,
            self.tx.gas.max_fee,
            self.tx.gas.limit,
            &self.tx.to,
            calldata,
        )
    }

    /// `calculateEvmType2RequestIdV1(request)`.
    pub fn request_id(&self, env: &Env) -> [u8; 32] {
        request_id_v1(self.key_version, &env.self_addr, &self.path, &self.tx_digest(env))
    }
}

// ---- one request through the queue ---------------------------------------------------------

/// A request followed from its start to its settlement: what each of the
/// action's three circuits (and the flush and the attestation queue) read of
/// it.
#[derive(Clone, Debug)]
pub struct Sent {
    pub env: Env,
    /// The requester's secret (the ownership commitment's preimage).
    pub sk: [u8; 32],
    pub args: Args,
    pub in_index: u64,
    /// The nonce the flush left in the entry: the vault's for a vault-signed
    /// action, the caller's for a deposit, the replaced request's for a
    /// nonce replacement.
    pub evm_nonce: u64,
    /// `globalLastSeen` when the flush moved the entry.
    pub last_seen: u64,
    /// A nonce for the cross-contract call's commitment randomness.
    pub cc_rand: Fr,
}

impl Sent {
    pub fn action(&self) -> Action {
        self.args.action()
    }

    /// The entry as `startX` queued it (a vault-signed one carries nonce 0).
    pub fn queued_entry(&self) -> Entry {
        Entry {
            action: self.action(),
            use_next: self.action().vault_signed() && self.action() != Action::ReplaceNonce,
            evm_nonce: if self.action().vault_signed() && self.action() != Action::ReplaceNonce { 0 } else { self.evm_nonce },
            in_index: self.in_index,
            commitment: ownership_commitment(self.in_index, &self.sk),
            args_hash: self.args.hash(),
        }
    }

    /// The entry as the flush moved it (the vault nonce filled in).
    pub fn flushed_entry(&self) -> Entry {
        Entry {
            evm_nonce: self.evm_nonce,
            ..self.queued_entry()
        }
    }

    /// `requestIndex(entry)` — the `outputRequestBuffer` key.
    pub fn out_index(&self) -> [u8; 32] {
        request_index(self.evm_nonce, &self.args.hash())
    }

    /// The V1 event `sendX` records.
    pub fn req(&self) -> Req {
        let env = &self.env;
        let gas = self.args.gas();
        let vault_path = pad32(v::VAULT_PATH);
        let (path, to, calldata, capacity, out_schema): ([u8; 32], [u8; 20], Option<([u8; 4], Vec<[u8; 32]>)>, usize, &'static [u8]) =
            match &self.args {
                Args::ReplaceNonce { .. } => (vault_path, env.vault_evm, None, v::VAULT_WORDS, v::REPLACE_NONCE_OUTPUT_SCHEMA),
                Args::Approve { erc20, spender, .. } => (
                    vault_path,
                    *erc20,
                    Some((v::APPROVE_SELECTOR, vec![abi_addr_word(spender), abi_num_word(u128::MAX)])),
                    v::VAULT_WORDS,
                    v::VAULT_OUTPUT_SCHEMA,
                ),
                Args::Deposit { erc20, amount, path, .. } => (
                    *path,
                    *erc20,
                    Some((v::TRANSFER_SELECTOR, vec![abi_addr_word(&env.vault_evm), abi_num_word(*amount)])),
                    v::VAULT_WORDS,
                    v::VAULT_OUTPUT_SCHEMA,
                ),
                Args::Withdraw { erc20, amount, dest, .. } => (
                    vault_path,
                    *erc20,
                    Some((v::TRANSFER_SELECTOR, vec![abi_addr_word(dest), abi_num_word(*amount)])),
                    v::VAULT_WORDS,
                    v::VAULT_OUTPUT_SCHEMA,
                ),
                Args::Swap {
                    token_in,
                    token_out,
                    fee,
                    amount_out,
                    amount_in_max,
                    ..
                } => (
                    vault_path,
                    env.router,
                    Some((
                        v::EXACT_OUTPUT_SINGLE_SELECTOR,
                        vec![
                            abi_addr_word(token_in),
                            abi_addr_word(token_out),
                            abi_num_word(*fee),
                            abi_addr_word(&env.vault_evm),
                            abi_num_word(*amount_out),
                            abi_num_word(*amount_in_max),
                            abi_num_word(0),
                        ],
                    )),
                    v::SWAP_WORDS,
                    v::SWAP_OUTPUT_SCHEMA,
                ),
                Args::Supply { amount, .. } => (
                    vault_path,
                    env.stata_token,
                    Some((v::DEPOSIT_SELECTOR, vec![abi_num_word(*amount), abi_addr_word(&env.vault_evm)])),
                    v::SUPPLY_WORDS,
                    v::SUPPLY_OUTPUT_SCHEMA,
                ),
                Args::Redeem { shares, .. } => (
                    vault_path,
                    env.stata_token,
                    Some((v::REDEEM_SELECTOR, vec![abi_num_word(*shares), abi_addr_word(&env.vault_evm), abi_addr_word(&env.vault_evm)])),
                    v::REDEEM_WORDS,
                    v::REDEEM_OUTPUT_SCHEMA,
                ),
            };
        Req {
            key_version: env.key_version,
            path,
            tx: Tx {
                nonce: self.evm_nonce,
                gas,
                to,
                calldata,
                capacity,
            },
            out_schema,
        }
    }

    pub fn request_id(&self) -> [u8; 32] {
        self.req().request_id(&self.env)
    }

    /// The reads `sendX` makes while assembling the transaction, between the
    /// args lookup and the `mpcKeyVersion` read: the calldata's cells in
    /// word order, `evmChainId`, then a `to` that is a cell.
    pub fn tx_reads(&self) -> Vec<VmOp> {
        let env = &self.env;
        let mut o = Vec::new();
        match self.action() {
            Action::ReplaceNonce => {
                o.extend(env.read_chain_id());
                o.extend(env.read_b20(VAULT_EVM_ADDRESS));
            }
            Action::Approve | Action::Withdraw => o.extend(env.read_chain_id()),
            Action::Deposit => {
                o.extend(env.read_b20(VAULT_EVM_ADDRESS));
                o.extend(env.read_chain_id());
            }
            Action::Swap => {
                o.extend(env.read_b20(VAULT_EVM_ADDRESS));
                o.extend(env.read_chain_id());
                o.extend(env.read_b20(UNISWAP_ROUTER));
            }
            Action::Supply => {
                o.extend(env.read_b20(VAULT_EVM_ADDRESS));
                o.extend(env.read_chain_id());
                o.extend(env.read_b20(STATA_TOKEN));
            }
            Action::Redeem => {
                o.extend(env.read_b20(VAULT_EVM_ADDRESS));
                o.extend(env.read_b20(VAULT_EVM_ADDRESS));
                o.extend(env.read_chain_id());
                o.extend(env.read_b20(STATA_TOKEN));
            }
        }
        o
    }

    // -- the pre-states along the way --

    /// After `startX`: the args and the queued entry.
    pub fn queued_state(&self) -> PreState {
        let mut pre = self.env.pre_state();
        pre.input_request_buffer = vec![(key_u64(self.in_index), self.queued_entry().av())];
        self.put_args(&mut pre);
        pre
    }

    /// After the flush: the args and the moved entry.
    pub fn flushed_state(&self) -> PreState {
        let mut pre = self.env.pre_state();
        pre.output_request_buffer = vec![(key32(&self.out_index()), self.flushed_entry().out_av(self.last_seen))];
        self.put_args(&mut pre);
        pre
    }

    /// After `sendX`: the flushed entry, the args, the event and the
    /// eviction entry.
    pub fn sent_state(&self) -> PreState {
        let mut pre = self.flushed_state();
        let rid = self.request_id();
        pre.eviction_map = vec![(key32(&rid), key32(&self.out_index()))];
        self.put_event(&mut pre);
        pre
    }

    /// After the attestation's flush: [`Self::sent_state`] plus the record.
    pub fn attested_state(&self, record: &Record) -> PreState {
        let mut pre = self.sent_state();
        pre.output_attestation_buffer = vec![(key32(&self.request_id()), record.av())];
        pre
    }

    fn put_args(&self, pre: &mut PreState) {
        let entry = (key_u64(self.in_index), self.args.av());
        match self.action() {
            Action::ReplaceNonce => pre.replace_nonce_args = vec![entry],
            Action::Approve => pre.approve_args = vec![entry],
            Action::Deposit => pre.deposit_args = vec![entry],
            Action::Withdraw => pre.withdraw_args = vec![entry],
            Action::Swap => pre.swap_args = vec![entry],
            Action::Supply => pre.supply_args = vec![entry],
            Action::Redeem => pre.redeem_args = vec![entry],
        }
    }

    fn put_event(&self, pre: &mut PreState) {
        let entry = (key32(&self.request_id()), self.req().av(&self.env));
        match self.action() {
            Action::ReplaceNonce => pre.replace_nonce_map = vec![entry],
            Action::Approve => pre.approve_map = vec![entry],
            Action::Deposit => pre.deposit_map = vec![entry],
            Action::Withdraw => pre.withdraw_map = vec![entry],
            Action::Swap => pre.swap_map = vec![entry],
            Action::Supply => pre.supply_map = vec![entry],
            Action::Redeem => pre.redeem_map = vec![entry],
        }
    }

    // -- the canonical requests --

    pub fn deposit() -> Sent {
        let env = Env::new();
        let sk = tagged32(b"depositor", 0x21);
        Sent {
            args: Args::Deposit {
                erc20: env.allowed_erc20,
                amount: 1_000_000,
                path: user_commitment(&sk),
                gas: Gas {
                    limit: 90_000,
                    max_fee: 40_000_000_000,
                    priority_fee: 2_000_000_000,
                },
            },
            in_index: 0x1234_5678_9abc,
            evm_nonce: 17,
            last_seen: env.global_last_seen,
            cc_rand: Fr::from(0xd3u64),
            sk,
            env,
        }
    }

    pub fn withdraw() -> Sent {
        let env = Env::new();
        Sent {
            args: Args::Withdraw {
                erc20: env.allowed_erc20,
                amount: 250_000,
                dest: *b"dest-evm-address-20b",
                gas: env.vault_gas(Action::Withdraw),
            },
            sk: tagged32(b"withdrawer", 0x22),
            in_index: 0x77,
            evm_nonce: env.vault_account_nonce,
            last_seen: env.global_last_seen,
            cc_rand: Fr::from(0xd4u64),
            env,
        }
    }

    pub fn swap() -> Sent {
        let env = Env::new();
        Sent {
            args: Args::Swap {
                token_in: env.stata_underlying,
                token_out: env.allowed_erc20,
                fee: 3000,
                amount_out: 5_000,
                amount_in_max: 6_000,
                gas: env.vault_gas(Action::Swap),
            },
            sk: tagged32(b"swapper", 0x23),
            in_index: 0x88,
            evm_nonce: env.vault_account_nonce,
            last_seen: env.global_last_seen,
            cc_rand: Fr::from(0xd5u64),
            env,
        }
    }

    pub fn supply() -> Sent {
        let env = Env::new();
        Sent {
            args: Args::Supply {
                amount: 42_000,
                gas: env.vault_gas(Action::Supply),
            },
            sk: tagged32(b"supplier", 0x24),
            in_index: 0x99,
            evm_nonce: env.vault_account_nonce,
            last_seen: env.global_last_seen,
            cc_rand: Fr::from(0xd6u64),
            env,
        }
    }

    pub fn redeem() -> Sent {
        let env = Env::new();
        Sent {
            args: Args::Redeem {
                shares: 41_000,
                gas: env.vault_gas(Action::Redeem),
            },
            sk: tagged32(b"redeemer", 0x25),
            in_index: 0xaa,
            evm_nonce: env.vault_account_nonce,
            last_seen: env.global_last_seen,
            cc_rand: Fr::from(0xd7u64),
            env,
        }
    }

    /// `startApproveRouter(inIndex, erc20)`.
    pub fn approve_router() -> Sent {
        let env = Env::new();
        Sent {
            args: Args::Approve {
                erc20: env.allowed_erc20,
                spender: env.router,
                gas: env.vault_gas(Action::Approve),
            },
            sk: env.deployer_sk,
            in_index: 0xbb,
            evm_nonce: env.vault_account_nonce,
            last_seen: env.global_last_seen,
            cc_rand: Fr::from(0xd8u64),
            env,
        }
    }

    /// `startApproveStata(inIndex)`.
    pub fn approve_stata() -> Sent {
        let env = Env::new();
        Sent {
            args: Args::Approve {
                erc20: env.stata_underlying,
                spender: env.stata_token,
                gas: env.vault_gas(Action::Approve),
            },
            sk: env.deployer_sk,
            in_index: 0xcc,
            evm_nonce: env.vault_account_nonce,
            last_seen: env.global_last_seen,
            cc_rand: Fr::from(0xd9u64),
            env,
        }
    }

    /// A nonce replacement of `replaced` (a sent, vault-signed request).
    pub fn replace_nonce(replaced: &Sent) -> Sent {
        let env = replaced.env.clone();
        Sent {
            args: Args::ReplaceNonce {
                gas: env.vault_gas(Action::ReplaceNonce),
            },
            sk: env.deployer_sk,
            in_index: 0xdd,
            evm_nonce: replaced.evm_nonce,
            last_seen: env.global_last_seen,
            cc_rand: Fr::from(0xdau64),
            env,
        }
    }
}

// ---- initialise / setGasParams / addAllowedToken --------------------------------------

/// The concrete `initialise()` call.
#[derive(Clone, Debug)]
pub struct InitialiseScenario {
    pub env: Env,
    /// The secret the CALLER witnesses; `env.deployer_sk` is whose
    /// commitment is stored.
    pub sk: [u8; 32],
    pub vault_evm: [u8; 20],
    pub swap_router: [u8; 20],
    pub stata_underlying: [u8; 20],
    pub stata_token: [u8; 20],
    pub chain_id: u64,
    pub point: IrValue,
    pub key_version: u8,
    pub evm_height: u64,
}

impl InitialiseScenario {
    pub fn new() -> InitialiseScenario {
        let env = Env {
            initialised: false,
            ..Env::new()
        };
        InitialiseScenario {
            sk: env.deployer_sk,
            vault_evm: env.vault_evm,
            swap_router: env.router,
            stata_underlying: env.stata_underlying,
            stata_token: env.stata_token,
            chain_id: env.chain_id,
            point: env.mpc_key(),
            key_version: env.key_version,
            evm_height: env.global_last_seen,
            env,
        }
    }

    pub fn inputs(&self) -> Vec<Fr> {
        let mut inputs = vec![
            b20(&self.vault_evm),
            b20(&self.swap_router),
            b20(&self.stata_underlying),
            b20(&self.stata_token),
            Fr::from(self.chain_id),
        ];
        inputs.extend(natives(&self.point));
        inputs.push(Fr::from(u64::from(self.key_version)));
        inputs.push(Fr::from(self.evm_height));
        inputs
    }

    pub fn witnesses(&self) -> Vec<Fr> {
        let (hi, lo) = b32_slots(&self.sk);
        vec![hi, lo]
    }

    pub fn ops(&self) -> Vec<VmOp> {
        let mut o = self.env.read_initialised();
        o.extend(self.env.read_deployer());
        o.extend(ops::cell_write(INITIALISED, bytesn_value(1, &[1])));
        o.extend(ops::cell_write(VAULT_EVM_ADDRESS, bytesn_value(20, &self.vault_evm)));
        o.extend(ops::cell_write(UNISWAP_ROUTER, bytesn_value(20, &self.swap_router)));
        o.extend(ops::cell_write(STATA_UNDERLYING, bytesn_value(20, &self.stata_underlying)));
        o.extend(ops::cell_write(STATA_TOKEN, bytesn_value(20, &self.stata_token)));
        o.extend(ops::set_insert(ALLOWED_TOKENS, key20(&self.stata_underlying)));
        o.extend(ops::cell_write(EVM_CHAIN_ID, bytesn_value(8, &self.chain_id.to_le_bytes())));
        o.extend(ops::cell_write(MPC_RESPONSE_KEY, point_av(&self.point)));
        o.extend(ops::cell_write(MPC_KEY_VERSION, bytesn_value(1, &[self.key_version])));
        o.extend(ops::cell_write(GLOBAL_LAST_SEEN, bytesn_value(8, &self.evm_height.to_le_bytes())));
        o.extend(ops::cell_write(MAX_FEE_PER_GAS, bytesn_value(16, &v::DEFAULT_MAX_FEE_PER_GAS.to_le_bytes())));
        o.extend(ops::cell_write(
            MAX_PRIORITY_FEE_PER_GAS,
            bytesn_value(16, &v::DEFAULT_MAX_PRIORITY_FEE_PER_GAS.to_le_bytes()),
        ));
        let limits = [v::DEFAULT_WITHDRAW_GAS, v::DEFAULT_APPROVE_GAS, v::DEFAULT_SWAP_GAS, v::DEFAULT_SUPPLY_GAS, v::DEFAULT_REDEEM_GAS];
        let limbs: Vec<Fr> = limits.iter().map(|g| Fr::from(*g)).collect();
        o.extend(ops::cell_write(GAS_LIMITS, aligned(&[8, 8, 8, 8, 8], &limbs)));
        o
    }

    pub fn preimage(&self) -> ProofPreimage {
        preimage_of(self.inputs(), self.witnesses(), &self.ops(), Fr::from(0xe20u64))
    }

    /// `initialised` as the env says, `deployer == commitment`; the
    /// configuration cells at their defaults (they are what this call writes).
    pub fn pre_state(&self) -> PreState {
        PreState {
            initialised: self.env.initialised,
            deployer: self.env.deployer(),
            ..Default::default()
        }
    }
}

/// `setGasParams(newMaxFeePerGas, newMaxPriorityFeePerGas, five limits)`.
#[derive(Clone, Debug)]
pub struct SetGasParamsScenario {
    pub env: Env,
    pub sk: [u8; 32],
    pub max_fee: u128,
    pub priority_fee: u128,
    pub limits: [u64; 5],
}

impl SetGasParamsScenario {
    pub fn new() -> SetGasParamsScenario {
        let env = Env::new();
        SetGasParamsScenario {
            sk: env.deployer_sk,
            max_fee: 200_000_000_000,
            priority_fee: 3_000_000_000,
            limits: [110_000, 120_000, 800_000, 600_000, 650_000],
            env,
        }
    }

    pub fn inputs(&self) -> Vec<Fr> {
        let mut inputs = vec![u128_limb(self.max_fee), u128_limb(self.priority_fee)];
        inputs.extend(self.limits.iter().map(|g| Fr::from(*g)));
        inputs
    }

    pub fn witnesses(&self) -> Vec<Fr> {
        let (hi, lo) = b32_slots(&self.sk);
        vec![hi, lo]
    }

    pub fn ops(&self) -> Vec<VmOp> {
        let mut o = self.env.read_initialised();
        o.extend(self.env.read_deployer());
        o.extend(ops::cell_write(MAX_FEE_PER_GAS, bytesn_value(16, &self.max_fee.to_le_bytes())));
        o.extend(ops::cell_write(MAX_PRIORITY_FEE_PER_GAS, bytesn_value(16, &self.priority_fee.to_le_bytes())));
        let limbs: Vec<Fr> = self.limits.iter().map(|g| Fr::from(*g)).collect();
        o.extend(ops::cell_write(GAS_LIMITS, aligned(&[8, 8, 8, 8, 8], &limbs)));
        o
    }

    pub fn preimage(&self) -> ProofPreimage {
        preimage_of(self.inputs(), self.witnesses(), &self.ops(), Fr::from(0x6a5u64))
    }

    pub fn pre_state(&self) -> PreState {
        self.env.pre_state()
    }
}

/// `addAllowedToken(erc20Address)`.
#[derive(Clone, Debug)]
pub struct AddAllowedTokenScenario {
    pub env: Env,
    pub sk: [u8; 32],
    pub erc20: [u8; 20],
}

impl AddAllowedTokenScenario {
    pub fn new() -> AddAllowedTokenScenario {
        let env = Env::new();
        AddAllowedTokenScenario {
            sk: env.deployer_sk,
            erc20: *b"another-erc20-token!",
            env,
        }
    }

    pub fn inputs(&self) -> Vec<Fr> {
        vec![b20(&self.erc20)]
    }

    pub fn witnesses(&self) -> Vec<Fr> {
        let (hi, lo) = b32_slots(&self.sk);
        vec![hi, lo]
    }

    pub fn ops(&self) -> Vec<VmOp> {
        let mut o = self.env.read_initialised();
        o.extend(self.env.read_deployer());
        o.extend(ops::set_insert(ALLOWED_TOKENS, key20(&self.erc20)));
        o
    }

    pub fn preimage(&self) -> ProofPreimage {
        preimage_of(self.inputs(), self.witnesses(), &self.ops(), Fr::from(0xadd0u64))
    }

    pub fn pre_state(&self) -> PreState {
        self.env.pre_state()
    }
}

// ---- the starts ------------------------------------------------------------------------

/// `assert(!inputRequestBuffer.member(i) && !argsMap.member(i))` — both
/// reads, the second guarded by the first being false.
fn index_free_ops(args_field: u8, in_index: u64, queued: bool, in_args: bool) -> Vec<VmOp> {
    let mut o = ops::member(INPUT_REQUEST_BUFFER, key_u64(in_index), queued);
    if !queued {
        o.extend(ops::member(args_field, key_u64(in_index), in_args));
    }
    o
}

/// `argsMap.insert(i, args); inputRequestBuffer.insert(i, entry)`.
fn queue_ops(sent: &Sent) -> Vec<VmOp> {
    let mut o = ops::insert(sent.action().args_field(), key_u64(sent.in_index), sent.args.av());
    o.extend(ops::insert(INPUT_REQUEST_BUFFER, key_u64(sent.in_index), sent.queued_entry().av()));
    o
}

/// `startX` for every action: the request and the flags that pick a branch.
#[derive(Clone, Debug)]
pub struct StartScenario {
    pub sent: Sent,
    /// The surrendered coin, for the four coin-spending actions.
    pub coin: Option<Coin>,
    /// Is the index already queued / already in the args map?
    pub queued: bool,
    pub in_args: bool,
    /// The deposited ERC20's / bought ERC20's `allowedTokens` membership.
    pub allowed: bool,
    /// For a nonce replacement: the sent request whose nonce is taken.
    pub replaced: Option<Box<Sent>>,
}

impl StartScenario {
    pub fn of(sent: Sent) -> StartScenario {
        let coin = match &sent.args {
            Args::Withdraw { erc20, amount, .. } => Some(sent.env.coin(erc20, *amount, 0x51)),
            Args::Swap { token_in, amount_in_max, .. } => Some(sent.env.coin(token_in, *amount_in_max, 0x52)),
            Args::Supply { amount, .. } => Some(sent.env.coin(&sent.env.stata_underlying, *amount, 0x53)),
            Args::Redeem { shares, .. } => Some(sent.env.coin(&sent.env.stata_token, *shares, 0x54)),
            _ => None,
        };
        StartScenario {
            sent,
            coin,
            queued: false,
            in_args: false,
            allowed: true,
            replaced: None,
        }
    }

    pub fn deposit() -> StartScenario {
        StartScenario::of(Sent::deposit())
    }
    pub fn withdraw() -> StartScenario {
        StartScenario::of(Sent::withdraw())
    }
    pub fn swap() -> StartScenario {
        StartScenario::of(Sent::swap())
    }
    pub fn supply() -> StartScenario {
        StartScenario::of(Sent::supply())
    }
    pub fn redeem() -> StartScenario {
        StartScenario::of(Sent::redeem())
    }
    pub fn approve_router() -> StartScenario {
        StartScenario::of(Sent::approve_router())
    }
    pub fn approve_stata() -> StartScenario {
        StartScenario::of(Sent::approve_stata())
    }
    pub fn replace_nonce() -> StartScenario {
        let replaced = Sent::withdraw();
        let mut s = StartScenario::of(Sent::replace_nonce(&replaced));
        s.replaced = Some(Box::new(replaced));
        s
    }

    pub fn env(&self) -> &Env {
        &self.sent.env
    }

    pub fn inputs(&self) -> Vec<Fr> {
        let s = &self.sent;
        let mut inputs = vec![Fr::from(s.in_index)];
        match &s.args {
            Args::Deposit { erc20, amount, gas, .. } => {
                inputs.push(Fr::from(s.evm_nonce));
                inputs.extend(gas.limbs());
                inputs.extend([b20(erc20), u128_limb(*amount)]);
            }
            Args::Withdraw { erc20, amount, dest, .. } => inputs.extend([b20(erc20), u128_limb(*amount), b20(dest)]),
            Args::Swap {
                token_in,
                token_out,
                fee,
                amount_out,
                amount_in_max,
                ..
            } => inputs.extend([b20(token_in), b20(token_out), u128_limb(*fee), u128_limb(*amount_out), u128_limb(*amount_in_max)]),
            Args::Supply { amount, .. } => inputs.push(u128_limb(*amount)),
            Args::Redeem { shares, .. } => inputs.push(u128_limb(*shares)),
            Args::Approve { erc20, spender, .. } => {
                // startApproveRouter names the ERC20; startApproveStata names nothing.
                if *spender == s.env.router {
                    inputs.push(b20(erc20));
                }
            }
            Args::ReplaceNonce { .. } => {
                let replaced = self.replaced.as_ref().expect("a replacement names a sent request");
                let (hi, lo) = b32_slots(&replaced.request_id());
                inputs.extend([hi, lo, Fr::from(replaced.action().code())]);
            }
        }
        if let Some(coin) = &self.coin {
            inputs.extend(coin.inputs());
        }
        inputs
    }

    pub fn witnesses(&self) -> Vec<Fr> {
        let (hi, lo) = b32_slots(&self.sent.sk);
        match self.sent.action() {
            // A deployer gate, or the depositor's identity, witnesses the
            // secret once before the ownership commitment does.
            Action::Deposit | Action::Approve | Action::ReplaceNonce => vec![hi, lo, hi, lo],
            _ => vec![hi, lo],
        }
    }

    pub fn ops(&self) -> Vec<VmOp> {
        let s = &self.sent;
        let env = &s.env;
        let a = s.action();
        let mut o = env.read_initialised();
        match &s.args {
            Args::Deposit { erc20, .. } => {
                o.extend(ops::member(ALLOWED_TOKENS, key20(erc20), self.allowed));
                o.extend(index_free_ops(a.args_field(), s.in_index, self.queued, self.in_args));
            }
            Args::Withdraw { .. } => {
                o.extend(env.coin_ops(self.coin.as_ref().unwrap()));
                o.extend(index_free_ops(a.args_field(), s.in_index, self.queued, self.in_args));
                o.extend(env.read_vault_gas());
            }
            Args::Swap { token_out, .. } => {
                o.extend(ops::member(ALLOWED_TOKENS, key20(token_out), self.allowed));
                o.extend(env.coin_ops(self.coin.as_ref().unwrap()));
                o.extend(index_free_ops(a.args_field(), s.in_index, self.queued, self.in_args));
                o.extend(env.read_vault_gas());
            }
            Args::Supply { .. } => {
                o.extend(env.read_b20(STATA_UNDERLYING));
                o.extend(env.coin_ops(self.coin.as_ref().unwrap()));
                o.extend(index_free_ops(a.args_field(), s.in_index, self.queued, self.in_args));
                o.extend(env.read_vault_gas());
            }
            Args::Redeem { .. } => {
                o.extend(env.read_b20(STATA_TOKEN));
                o.extend(env.coin_ops(self.coin.as_ref().unwrap()));
                o.extend(index_free_ops(a.args_field(), s.in_index, self.queued, self.in_args));
                o.extend(env.read_vault_gas());
            }
            Args::Approve { spender, .. } => {
                if *spender == env.router {
                    o.extend(env.read_b20(UNISWAP_ROUTER));
                } else {
                    o.extend(env.read_b20(STATA_UNDERLYING));
                    o.extend(env.read_b20(STATA_TOKEN));
                }
                o.extend(env.read_deployer());
                o.extend(index_free_ops(a.args_field(), s.in_index, self.queued, self.in_args));
                o.extend(env.read_vault_gas());
            }
            Args::ReplaceNonce { .. } => {
                let replaced = self.replaced.as_ref().unwrap();
                o.extend(env.read_deployer());
                // sentVaultNonce: the replaced request's map, member then lookup.
                let rid = replaced.request_id();
                o.extend(ops::member(replaced.action().map_field(), key32(&rid), true));
                o.extend(ops::lookup(replaced.action().map_field(), key32(&rid), replaced.req().av(env)));
                o.extend(index_free_ops(a.args_field(), s.in_index, self.queued, self.in_args));
                o.extend(ops::read(MAX_FEE_PER_GAS, false, bytesn_value(16, &env.max_fee_per_gas.to_le_bytes())));
                o.extend(ops::read(
                    MAX_PRIORITY_FEE_PER_GAS,
                    false,
                    bytesn_value(16, &env.max_priority_fee_per_gas.to_le_bytes()),
                ));
            }
        }
        o.extend(queue_ops(s));
        o
    }

    pub fn preimage(&self) -> ProofPreimage {
        preimage_of(self.inputs(), self.witnesses(), &self.ops(), Fr::from(0x57a7u64))
    }

    /// The configuration, plus (for a replacement) the replaced request as
    /// sent.
    pub fn pre_state(&self) -> PreState {
        match &self.replaced {
            Some(replaced) => replaced.sent_state(),
            None => self.env().pre_state(),
        }
    }
}

// ---- the sends -------------------------------------------------------------------------

/// `sendX(outIndex)` on a flushed request.
#[derive(Clone, Debug)]
pub struct SendScenario {
    pub sent: Sent,
    /// Is the request flushed (in `outputRequestBuffer`)?
    pub flushed: bool,
    /// Is the request id already sent?
    pub already_sent: bool,
}

impl SendScenario {
    pub fn of(sent: Sent) -> SendScenario {
        SendScenario {
            sent,
            flushed: true,
            already_sent: false,
        }
    }

    pub fn inputs(&self) -> Vec<Fr> {
        let (hi, lo) = b32_slots(&self.sent.out_index());
        vec![hi, lo]
    }

    pub fn witnesses(&self) -> Vec<Fr> {
        self.sent.env.call_witnesses(self.sent.cc_rand)
    }

    pub fn ops(&self) -> Vec<VmOp> {
        let s = &self.sent;
        let env = &s.env;
        let out_index = s.out_index();
        let rid = s.request_id();
        let mut o = env.read_initialised();
        o.extend(ops::member(OUTPUT_REQUEST_BUFFER, key32(&out_index), self.flushed));
        o.extend(ops::lookup(OUTPUT_REQUEST_BUFFER, key32(&out_index), s.flushed_entry().out_av(s.last_seen)));
        o.extend(ops::lookup(s.action().args_field(), key_u64(s.in_index), s.args.av()));
        o.extend(s.tx_reads());
        o.extend(env.read_key_version());
        o.extend(env.kernel_self());
        o.extend(ops::member(s.action().map_field(), key32(&rid), self.already_sent));
        o.extend(ops::insert(s.action().map_field(), key32(&rid), s.req().av(env)));
        o.extend(ops::insert(EVICTION_MAP, key32(&rid), key32(&out_index)));
        o.extend(env.notify_ops(s.action().map_field(), &rid, s.cc_rand));
        o
    }

    pub fn preimage(&self) -> ProofPreimage {
        preimage_of(self.inputs(), self.witnesses(), &self.ops(), Fr::from(0x5e4du64))
    }

    pub fn pre_state(&self) -> PreState {
        self.sent.flushed_state()
    }
}

// ---- the attestations ------------------------------------------------------------------

/// The MPC's attestation of a sent request, at a width.
#[derive(Clone, Debug)]
pub struct Attestation {
    pub block_height: u64,
    pub output_kind: u64,
    /// The serialised output's limbs at the queueing width (none at 0, one
    /// byte at 1, `[hi, lo]` at 32).
    pub output: Vec<Fr>,
    pub width: usize,
    /// The MPC's ECDSA nonce.
    pub k_seed: u64,
}

impl Attestation {
    pub fn executed_bool(success: bool) -> Attestation {
        Attestation {
            block_height: 7_000_123,
            output_kind: output_kind::EXECUTED,
            output: vec![Fr::from(u64::from(success))],
            width: 1,
            k_seed: 0x2bad_cafe,
        }
    }

    pub fn executed_u256(value: u128) -> Attestation {
        let bytes = abi_num_word(value);
        let mut le = bytes;
        le.reverse();
        let (hi, lo) = b32_slots(&le);
        Attestation {
            block_height: 7_000_123,
            output_kind: output_kind::EXECUTED,
            output: vec![hi, lo],
            width: 32,
            k_seed: 0x2bad_cafe,
        }
    }

    pub fn executed_empty() -> Attestation {
        Attestation {
            block_height: 7_000_123,
            output_kind: output_kind::EXECUTED,
            output: vec![],
            width: 0,
            k_seed: 0x2bad_cafe,
        }
    }

    pub fn failed() -> Attestation {
        Attestation {
            block_height: 7_000_200,
            output_kind: output_kind::FAILED,
            output: vec![],
            width: 0,
            k_seed: 0x2bad_cafe,
        }
    }

    pub fn unviable() -> Attestation {
        Attestation {
            output_kind: output_kind::UNVIABLE,
            ..Attestation::failed()
        }
    }

    pub fn digest(&self, request_id: &[u8; 32]) -> [u8; 32] {
        attestation_digest(request_id, self.block_height, self.output_kind, self.width, &self.output)
    }

    pub fn record(&self, request_id: &[u8; 32]) -> Record {
        Record {
            block_height: self.block_height,
            output_kind: self.output_kind,
            digest: self.digest(request_id),
        }
    }

    /// The `RespondBidirectionalEventV1` argument's fourteen limbs: the id,
    /// the height, the verdict, the width, the digest, then the signature's
    /// `bigR.x`, `bigR.y`, `s` (little-endian) and `recoveryId`.
    pub fn event_inputs(&self, env: &Env, request_id: &[u8; 32]) -> Vec<Fr> {
        let digest = self.digest(request_id);
        let (r_le, s_le, _pk) = sign(&digest, &scalar(env.key_seed), &scalar(self.k_seed));
        let (rid_hi, rid_lo) = b32_slots(request_id);
        let (d_hi, d_lo) = b32_slots(&digest);
        let (r_hi, r_lo) = b32_slots(&r_le);
        let (s_hi, s_lo) = b32_slots(&s_le);
        vec![
            rid_hi,
            rid_lo,
            Fr::from(self.block_height),
            Fr::from(self.output_kind),
            Fr::from(self.width as u64),
            d_hi,
            d_lo,
            r_hi,
            r_lo,
            Fr::from(0u64), // bigR.y: unread
            Fr::from(0u64),
            s_hi,
            s_lo,
            Fr::from(0u64), // recoveryId: unread
        ]
    }
}

/// `queueAttestation{0,1,32}(event, output)`.
#[derive(Clone, Debug)]
pub struct QueueAttestationScenario {
    pub sent: Sent,
    pub attestation: Attestation,
    pub sent_exists: bool,
    pub open: bool,
    pub already_queued: bool,
    pub already_flushed: bool,
}

impl QueueAttestationScenario {
    pub fn of(sent: Sent, attestation: Attestation) -> QueueAttestationScenario {
        QueueAttestationScenario {
            sent,
            attestation,
            sent_exists: true,
            open: true,
            already_queued: false,
            already_flushed: false,
        }
    }

    pub fn inputs(&self) -> Vec<Fr> {
        let mut inputs = self.attestation.event_inputs(&self.sent.env, &self.sent.request_id());
        inputs.extend(self.attestation.output.iter().copied());
        inputs
    }

    pub fn ops(&self) -> Vec<VmOp> {
        let s = &self.sent;
        let env = &s.env;
        let rid = s.request_id();
        let out_index = s.out_index();
        let mut o = env.read_initialised();
        o.extend(env.read_mpc_key());
        o.extend(ops::member(EVICTION_MAP, key32(&rid), self.sent_exists));
        o.extend(ops::lookup(EVICTION_MAP, key32(&rid), key32(&out_index)));
        o.extend(ops::member(OUTPUT_REQUEST_BUFFER, key32(&out_index), self.open));
        o.extend(ops::lookup(OUTPUT_REQUEST_BUFFER, key32(&out_index), s.flushed_entry().out_av(s.last_seen)));
        o.extend(ops::member(INPUT_ATTESTATION_BUFFER, key32(&rid), self.already_queued));
        o.extend(ops::member(OUTPUT_ATTESTATION_BUFFER, key32(&rid), self.already_flushed));
        o.extend(ops::insert(INPUT_ATTESTATION_BUFFER, key32(&rid), self.attestation.record(&rid).av()));
        o
    }

    pub fn preimage(&self) -> ProofPreimage {
        preimage_of(self.inputs(), vec![], &self.ops(), Fr::from(0xa77u64))
    }

    pub fn pre_state(&self) -> PreState {
        self.sent.sent_state()
    }
}

// ---- the flush -------------------------------------------------------------------------

/// One `FlushSlot`.
#[derive(Clone, Debug)]
pub enum Slot {
    Empty,
    /// A queued request (its `startX` done), flushed here.
    Request(Sent),
    /// A queued attestation of a sent request, flushed here.
    Attestation(Sent, Attestation),
}

/// `flushQueue(slots)`: ten slots run in order against one evolving
/// `vaultAccountNonce` and `globalLastSeen`.
#[derive(Clone, Debug)]
pub struct FlushScenario {
    pub env: Env,
    pub slots: Vec<Slot>,
}

impl FlushScenario {
    /// One request slot (a withdrawal) and one attestation slot (a deposit's
    /// executed attestation), the rest empty.
    pub fn new() -> FlushScenario {
        let env = Env::new();
        let mut slots = vec![Slot::Request(Sent::withdraw()), Slot::Attestation(Sent::deposit(), Attestation::executed_bool(true))];
        slots.resize(v::FLUSH_SLOTS, Slot::Empty);
        FlushScenario { env, slots }
    }

    pub fn inputs(&self) -> Vec<Fr> {
        let mut inputs = Vec::new();
        for slot in &self.slots {
            match slot {
                Slot::Empty => inputs.extend([Fr::from(0u64); 4]),
                Slot::Request(s) => {
                    inputs.extend([Fr::from(v::flush_channel::REQUEST), Fr::from(s.in_index), Fr::from(0u64), Fr::from(0u64)]);
                }
                Slot::Attestation(s, _) => {
                    let (hi, lo) = b32_slots(&s.request_id());
                    inputs.extend([Fr::from(v::flush_channel::ATTESTATION), Fr::from(0u64), hi, lo]);
                }
            }
        }
        inputs
    }

    pub fn ops(&self) -> Vec<VmOp> {
        let env = &self.env;
        let mut nonce = env.vault_account_nonce;
        let mut gls = env.global_last_seen;
        let mut o = env.read_initialised();
        for slot in &self.slots {
            match slot {
                Slot::Empty => {}
                Slot::Request(s) => {
                    let queued = s.queued_entry();
                    o.extend(ops::member(INPUT_REQUEST_BUFFER, key_u64(s.in_index), true));
                    o.extend(ops::lookup(INPUT_REQUEST_BUFFER, key_u64(s.in_index), queued.av()));
                    let evm_nonce = if queued.use_next {
                        o.extend(Env::read_u64(VAULT_ACCOUNT_NONCE, nonce));
                        o.extend(Env::read_u64(VAULT_ACCOUNT_NONCE, nonce));
                        o.extend(ops::cell_write(VAULT_ACCOUNT_NONCE, bytesn_value(8, &(nonce + 1).to_le_bytes())));
                        let taken = nonce;
                        nonce += 1;
                        taken
                    } else {
                        queued.evm_nonce
                    };
                    let out_index = request_index(evm_nonce, &queued.args_hash);
                    o.extend(ops::member(OUTPUT_REQUEST_BUFFER, key32(&out_index), false));
                    o.extend(ops::remove(INPUT_REQUEST_BUFFER, key_u64(s.in_index)));
                    o.extend(Env::read_u64(GLOBAL_LAST_SEEN, gls));
                    let moved = Entry { evm_nonce, ..queued };
                    o.extend(ops::insert(OUTPUT_REQUEST_BUFFER, key32(&out_index), moved.out_av(gls)));
                }
                Slot::Attestation(s, att) => {
                    let rid = s.request_id();
                    let record = att.record(&rid);
                    o.extend(ops::member(INPUT_ATTESTATION_BUFFER, key32(&rid), true));
                    o.extend(ops::lookup(INPUT_ATTESTATION_BUFFER, key32(&rid), record.av()));
                    o.extend(ops::remove(INPUT_ATTESTATION_BUFFER, key32(&rid)));
                    o.extend(Env::read_u64(GLOBAL_LAST_SEEN, gls));
                    if record.block_height > gls {
                        gls = record.block_height;
                    } else {
                        o.extend(Env::read_u64(GLOBAL_LAST_SEEN, gls));
                    }
                    o.extend(ops::cell_write(GLOBAL_LAST_SEEN, bytesn_value(8, &gls.to_le_bytes())));
                    o.extend(ops::insert(OUTPUT_ATTESTATION_BUFFER, key32(&rid), record.av()));
                }
            }
        }
        o
    }

    pub fn preimage(&self) -> ProofPreimage {
        preimage_of(self.inputs(), vec![], &self.ops(), Fr::from(0xf1u64))
    }

    /// Every request slot queued, every attestation slot's request sent and
    /// its attestation queued.
    pub fn pre_state(&self) -> PreState {
        let mut pre = self.env.pre_state();
        for slot in &self.slots {
            match slot {
                Slot::Empty => {}
                Slot::Request(s) => {
                    let q = s.queued_state();
                    pre.input_request_buffer.extend(q.input_request_buffer.iter().cloned());
                    merge_args(&mut pre, &q);
                }
                Slot::Attestation(s, att) => {
                    let sent = s.sent_state();
                    pre.output_request_buffer.extend(sent.output_request_buffer.iter().cloned());
                    pre.eviction_map.extend(sent.eviction_map.iter().cloned());
                    merge_args(&mut pre, &sent);
                    merge_events(&mut pre, &sent);
                    let rid = s.request_id();
                    pre.input_attestation_buffer.push((key32(&rid), att.record(&rid).av()));
                }
            }
        }
        pre
    }
}

fn merge_args(pre: &mut PreState, from: &PreState) {
    pre.replace_nonce_args.extend(from.replace_nonce_args.iter().cloned());
    pre.approve_args.extend(from.approve_args.iter().cloned());
    pre.deposit_args.extend(from.deposit_args.iter().cloned());
    pre.withdraw_args.extend(from.withdraw_args.iter().cloned());
    pre.swap_args.extend(from.swap_args.iter().cloned());
    pre.supply_args.extend(from.supply_args.iter().cloned());
    pre.redeem_args.extend(from.redeem_args.iter().cloned());
}

fn merge_events(pre: &mut PreState, from: &PreState) {
    pre.replace_nonce_map.extend(from.replace_nonce_map.iter().cloned());
    pre.approve_map.extend(from.approve_map.iter().cloned());
    pre.deposit_map.extend(from.deposit_map.iter().cloned());
    pre.withdraw_map.extend(from.withdraw_map.iter().cloned());
    pre.swap_map.extend(from.swap_map.iter().cloned());
    pre.supply_map.extend(from.supply_map.iter().cloned());
    pre.redeem_map.extend(from.redeem_map.iter().cloned());
}

// ---- the completions ---------------------------------------------------------------------

/// The deposit's claim recipient: `Maybe<Either<ZswapCoinPublicKey, ContractAddress>>`.
#[derive(Clone, Copy, Debug)]
pub enum ClaimRecipient {
    Key([u8; 32]),
    Contract([u8; 32]),
    /// `none`: the caller's own key, witnessed.
    None([u8; 32]),
}

/// `completeX(requestId, output…, nonces…)` on an attested request.
#[derive(Clone, Debug)]
pub struct CompleteScenario {
    pub sent: Sent,
    /// The attestation the flush recorded.
    pub attestation: Attestation,
    /// The output the caller presents (the attested one, unless tampered).
    pub output: Vec<Fr>,
    /// The caller's secret (the requester's, unless tampered).
    pub sk: [u8; 32],
    pub own_pk: [u8; 32],
    pub mint_nonce: [u8; 32],
    pub change_nonce: [u8; 32],
    pub recipient: ClaimRecipient,
    pub sent_exists: bool,
    pub open: bool,
    pub flushed: bool,
    pub event_present: bool,
}

impl CompleteScenario {
    /// The `serializedOutput` argument's limb count per action: the circuit
    /// takes it on every verdict, so a failed one is handed zeros.
    pub fn output_width(action: Action) -> usize {
        match action {
            Action::ReplaceNonce => 0,
            Action::Approve | Action::Deposit | Action::Withdraw => 1,
            Action::Swap | Action::Supply | Action::Redeem => 2,
        }
    }

    pub fn of(sent: Sent, attestation: Attestation) -> CompleteScenario {
        let width = Self::output_width(sent.action());
        let output = if attestation.output.len() == width { attestation.output.clone() } else { vec![Fr::from(0u64); width] };
        CompleteScenario {
            output,
            sk: sent.sk,
            own_pk: tagged32(b"own-pk", 0x61),
            mint_nonce: tagged32(b"mint-nonce", 0x62),
            change_nonce: tagged32(b"change-nonce", 0x63),
            recipient: ClaimRecipient::Key(tagged32(b"claim-pk", 0x42)),
            sent_exists: true,
            open: true,
            flushed: true,
            event_present: true,
            sent,
            attestation,
        }
    }

    pub fn env(&self) -> &Env {
        &self.sent.env
    }

    pub fn executed(&self) -> bool {
        self.attestation.output_kind == output_kind::EXECUTED
    }

    pub fn refunds(&self) -> bool {
        matches!(self.attestation.output_kind, output_kind::FAILED | output_kind::UNVIABLE)
    }

    /// `deserialize<VaultResponse, 1>(output).success` — byte == 1.
    pub fn success(&self) -> bool {
        self.output.first() == Some(&Fr::from(1u64))
    }

    /// The attested uint256 as a u64 (the completions' `as Uint<64>`).
    pub fn attested_u64(&self) -> u64 {
        let lo = self.output[1].as_le_bytes();
        let mut le = [0u8; 8];
        le.copy_from_slice(&lo[..8]);
        u64::from_le_bytes(le)
    }

    pub fn inputs(&self) -> Vec<Fr> {
        let (rid_hi, rid_lo) = b32_slots(&self.sent.request_id());
        let mut inputs = vec![rid_hi, rid_lo];
        inputs.extend(self.output.iter().copied());
        match self.sent.action() {
            Action::ReplaceNonce | Action::Approve => {}
            Action::Deposit => {
                let (n_hi, n_lo) = b32_slots(&self.mint_nonce);
                inputs.extend([n_hi, n_lo]);
                let (is_some, is_left, left, right) = match self.recipient {
                    ClaimRecipient::Key(pk) => (1u64, 1u64, pk, [0u8; 32]),
                    ClaimRecipient::Contract(addr) => (1, 0, [0u8; 32], addr),
                    ClaimRecipient::None(_) => (0, 0, [0u8; 32], [0u8; 32]),
                };
                let (l_hi, l_lo) = b32_slots(&left);
                let (r_hi, r_lo) = b32_slots(&right);
                inputs.extend([Fr::from(is_some), Fr::from(is_left), l_hi, l_lo, r_hi, r_lo]);
            }
            Action::Swap => {
                let (n_hi, n_lo) = b32_slots(&self.mint_nonce);
                let (c_hi, c_lo) = b32_slots(&self.change_nonce);
                inputs.extend([n_hi, n_lo, c_hi, c_lo]);
            }
            Action::Withdraw | Action::Supply | Action::Redeem => {
                let (n_hi, n_lo) = b32_slots(&self.mint_nonce);
                inputs.extend([n_hi, n_lo]);
            }
        }
        inputs
    }

    pub fn witnesses(&self) -> Vec<Fr> {
        let (sk_hi, sk_lo) = b32_slots(&self.sk);
        let (pk_hi, pk_lo) = b32_slots(&self.own_pk);
        let mut w = vec![sk_hi, sk_lo];
        let own_key_witnessed = match self.sent.action() {
            Action::ReplaceNonce | Action::Approve => false,
            Action::Deposit => self.executed() && self.success() && matches!(self.recipient, ClaimRecipient::None(_)),
            Action::Withdraw => self.refunds() || !self.success(),
            Action::Swap | Action::Supply | Action::Redeem => true,
        };
        if own_key_witnessed {
            w.extend([pk_hi, pk_lo]);
        }
        w
    }

    /// `settleRequest`: the eviction, request and attestation lookups, the
    /// height bound, the three removals.
    fn settle_ops(&self) -> Vec<VmOp> {
        let s = &self.sent;
        let rid = s.request_id();
        let out_index = s.out_index();
        let mut o = ops::member(EVICTION_MAP, key32(&rid), self.sent_exists);
        o.extend(ops::lookup(EVICTION_MAP, key32(&rid), key32(&out_index)));
        o.extend(ops::member(OUTPUT_REQUEST_BUFFER, key32(&out_index), self.open));
        o.extend(ops::lookup(OUTPUT_REQUEST_BUFFER, key32(&out_index), s.flushed_entry().out_av(s.last_seen)));
        o.extend(ops::member(OUTPUT_ATTESTATION_BUFFER, key32(&rid), self.flushed));
        o.extend(ops::lookup(OUTPUT_ATTESTATION_BUFFER, key32(&rid), self.attestation.record(&rid).av()));
        o.extend(ops::remove(EVICTION_MAP, key32(&rid)));
        o.extend(ops::remove(OUTPUT_ATTESTATION_BUFFER, key32(&rid)));
        o.extend(ops::remove(OUTPUT_REQUEST_BUFFER, key32(&out_index)));
        o
    }

    /// The args consumed and the event removed.
    fn consume_ops(&self, lookup_args: bool) -> Vec<VmOp> {
        let s = &self.sent;
        let rid = s.request_id();
        let a = s.action();
        let mut o = Vec::new();
        if lookup_args {
            o.extend(ops::lookup(a.args_field(), key_u64(s.in_index), s.args.av()));
        }
        o.extend(ops::remove(a.args_field(), key_u64(s.in_index)));
        o.extend(ops::member(a.map_field(), key32(&rid), self.event_present));
        o.extend(ops::remove(a.map_field(), key32(&rid)));
        o
    }

    pub fn ops(&self) -> Vec<VmOp> {
        let s = &self.sent;
        let env = &s.env;
        let mut o = env.read_initialised();
        o.extend(self.settle_ops());
        match &s.args {
            Args::ReplaceNonce { .. } | Args::Approve { .. } => o.extend(self.consume_ops(false)),
            Args::Deposit { erc20, amount, .. } => {
                o.extend(self.consume_ops(true));
                if self.executed() && self.success() {
                    let color = vault_color(erc20, &env.self_addr);
                    let (is_left, data) = match self.recipient {
                        ClaimRecipient::Key(pk) => (true, pk),
                        ClaimRecipient::Contract(addr) => (false, addr),
                        ClaimRecipient::None(_) => (true, self.own_pk),
                    };
                    let cm = coin_commitment_of(&b32_slots(&self.mint_nonce), &color, *amount, is_left, &data);
                    o.extend(env.kernel_self());
                    o.extend(ops::mint_and_spend(&vault_domain_sep(erc20), *amount as u64, &cm));
                    if let ClaimRecipient::Contract(addr) = self.recipient {
                        o.extend(env.kernel_self());
                        if addr == env.self_addr {
                            o.extend(ops::claim(1, &cm));
                        }
                    }
                }
            }
            Args::Withdraw { erc20, amount, .. } => {
                o.extend(self.consume_ops(true));
                if self.refunds() || !self.success() {
                    o.extend(env.mint_to_key_ops(erc20, *amount as u64, &self.mint_nonce, &self.own_pk));
                }
            }
            Args::Swap {
                token_in,
                token_out,
                amount_out,
                amount_in_max,
                ..
            } => {
                o.extend(self.consume_ops(true));
                if self.executed() {
                    o.extend(env.mint_to_key_ops(token_out, *amount_out as u64, &self.mint_nonce, &self.own_pk));
                    let change = (*amount_in_max as u64).saturating_sub(self.attested_u64());
                    o.extend(env.mint_to_key_ops(token_in, change, &self.change_nonce, &self.own_pk));
                }
                if self.refunds() {
                    o.extend(env.mint_to_key_ops(token_in, *amount_in_max as u64, &self.mint_nonce, &self.own_pk));
                }
            }
            Args::Supply { amount, .. } => {
                o.extend(self.consume_ops(true));
                if self.executed() {
                    o.extend(env.read_b20(STATA_TOKEN));
                    o.extend(env.mint_to_key_ops(&env.stata_token, self.attested_u64(), &self.mint_nonce, &self.own_pk));
                }
                if self.refunds() {
                    o.extend(env.read_b20(STATA_UNDERLYING));
                    o.extend(env.mint_to_key_ops(&env.stata_underlying, *amount as u64, &self.mint_nonce, &self.own_pk));
                }
            }
            Args::Redeem { shares, .. } => {
                o.extend(self.consume_ops(true));
                if self.executed() {
                    o.extend(env.read_b20(STATA_UNDERLYING));
                    o.extend(env.mint_to_key_ops(&env.stata_underlying, self.attested_u64(), &self.mint_nonce, &self.own_pk));
                }
                if self.refunds() {
                    o.extend(env.read_b20(STATA_TOKEN));
                    o.extend(env.mint_to_key_ops(&env.stata_token, *shares as u64, &self.mint_nonce, &self.own_pk));
                }
            }
        }
        o
    }

    pub fn preimage(&self) -> ProofPreimage {
        preimage_of(self.inputs(), self.witnesses(), &self.ops(), Fr::from(0xc0a7u64))
    }

    pub fn pre_state(&self) -> PreState {
        self.sent.attested_state(&self.attestation.record(&self.sent.request_id()))
    }
}

// ---- the scenario interface ----------------------------------------------------------------

/// What every scenario offers the suites: its op stream, the pre-state the
/// stream is valid against, and the preimage the two imply.
pub trait Scenario {
    fn ops(&self) -> Vec<VmOp>;
    fn pre_state(&self) -> PreState;
    fn preimage(&self) -> ProofPreimage;
    /// The contract's own address, for the executor.
    fn self_addr(&self) -> [u8; 32];
}

macro_rules! scenario {
    ($($ty:ty => $($env:ident).+),* $(,)?) => {$(
        impl Scenario for $ty {
            fn ops(&self) -> Vec<VmOp> { <$ty>::ops(self) }
            fn pre_state(&self) -> PreState { <$ty>::pre_state(self) }
            fn preimage(&self) -> ProofPreimage { <$ty>::preimage(self) }
            fn self_addr(&self) -> [u8; 32] { self.$($env).+.self_addr }
        }
    )*};
}

scenario! {
    InitialiseScenario => env,
    SetGasParamsScenario => env,
    AddAllowedTokenScenario => env,
    StartScenario => sent.env,
    SendScenario => sent.env,
    QueueAttestationScenario => sent.env,
    FlushScenario => env,
    CompleteScenario => sent.env,
}

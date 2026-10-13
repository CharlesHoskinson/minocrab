//! The reference EXECUTOR: the missing link between MinoCrab's Impact op
//! streams and ledger semantics.
//!
//! Until M10 the whole workspace only ever *encoded* ops (`Op::field_repr`
//! into a `ProofPreimage`) and compared encodings. Nothing ever ran them.
//! This module runs them, on a real contract state, through Midnight's own
//! driver — [`QueryContext::query`], which owns the `[context, effects,
//! state]` stack convention, the nine-map `Effects` encode/decode and the
//! charged-state gas accounting (onchain-runtime/src/context.rs:922-979).
//! We reuse it rather than re-deriving any of that.
//!
//! What running buys that encoding never could:
//!
//! - the op stream is well-formed at all (stack discipline, cache
//!   discipline, `Idx` paths that exist, `Popeq` results that MATCH the
//!   real state — `ResultModeVerify::process_read` errors on mismatch);
//! - the declared `Effects` are the ones the ledger would compute, which
//!   is exactly the equality `semantics.rs:1441-1447` enforces when a
//!   transaction is applied;
//! - the post-state is a real post-state, so a spec's state assertions are
//!   checked against the ledger's own state machine.

use std::ops::Deref;

use midnight_base_crypto::fab::AlignedValue;
use midnight_base_crypto::hash::HashOutput;
use midnight_coin_structure::contract::ContractAddress;
use midnight_onchain_runtime::context::{Effects, QueryContext, QueryResults};
use midnight_onchain_state::state::{ChargedState, StateValue};
use midnight_onchain_vm::cost_model::INITIAL_COST_MODEL;
use midnight_onchain_vm::ops::{Op, VersionedLogItem};
use midnight_onchain_vm::result_mode::ResultModeVerify;
use midnight_storage::db::InMemoryDB;
use midnight_storage::storage::{Array, HashMap};

use super::ops::{segment_of, FIELDS};
use super::prims::{aligned, bytesn_value, cell, VmOp};

/// A map field's entries: key → stored value, both as the ledger aligns them.
pub type Entries = Vec<(AlignedValue, AlignedValue)>;

/// The vault's ledger state, one field per Compact declaration. Field
/// indices are the declaration order (`erc20_vault`'s module doc); the
/// array order in [`PreState::fields`] IS that numbering, so a mis-numbered
/// circuit read fails at `Popeq` rather than silently reading a neighbour.
#[derive(Clone, Debug, Default)]
pub struct PreState {
    /// field 0 — `signetSigner`.
    pub signet_signer: [u8; 32],
    /// field 1 — `mpcResponseKey` (a `Secp256k1Point`, 5 FAB limbs); unset
    /// before `initialise`.
    pub mpc_response_key: Option<AlignedValue>,
    /// field 2 — `vaultMaxFeePerGas`.
    pub max_fee_per_gas: u128,
    /// field 3 — `vaultMaxPriorityFeePerGas`.
    pub max_priority_fee_per_gas: u128,
    /// field 4 — `vaultGasLimits { withdraw, approve, swap, supply, redeem }`.
    pub gas_limits: [u64; 5],
    /// field 5 — `initialised: Boolean`.
    pub initialised: bool,
    /// field 6 — `vaultEvmAddress`.
    pub vault_evm: [u8; 20],
    /// field 7 — `evmChainId`.
    pub chain_id: u64,
    /// field 8 — `mpcKeyVersion`.
    pub key_version: u8,
    /// field 9 — `deployer`.
    pub deployer: [u8; 32],
    /// field 10 — `uniswapRouter`.
    pub uniswap_router: [u8; 20],
    /// field 11 — `stataUnderlying`.
    pub stata_underlying: [u8; 20],
    /// field 12 — `stataToken`.
    pub stata_token: [u8; 20],
    /// field 13 — `allowedTokens: Set<Bytes<20>>`.
    pub allowed_tokens: Vec<[u8; 20]>,
    /// field 14 — `globalLastSeen`.
    pub global_last_seen: u64,
    /// field 15 — `vaultAccountNonce`.
    pub vault_account_nonce: u64,
    /// field 16 — `inputRequestBuffer`.
    pub input_request_buffer: Entries,
    /// field 17 — `outputRequestBuffer`.
    pub output_request_buffer: Entries,
    /// field 18 — `inputAttestationBuffer`.
    pub input_attestation_buffer: Entries,
    /// field 19 — `outputAttestationBuffer`.
    pub output_attestation_buffer: Entries,
    /// field 20 — `evictionMap`.
    pub eviction_map: Entries,
    /// fields 21/22 — `bidirectionalReplaceNonceMap`, `replaceNonceArgsMap`.
    pub replace_nonce_map: Entries,
    pub replace_nonce_args: Entries,
    /// fields 23/24 — `bidirectionalApproveMap`, `approveArgsMap`.
    pub approve_map: Entries,
    pub approve_args: Entries,
    /// fields 25/26.
    pub deposit_map: Entries,
    pub deposit_args: Entries,
    /// fields 27/28.
    pub withdraw_map: Entries,
    pub withdraw_args: Entries,
    /// fields 29/30.
    pub swap_map: Entries,
    pub swap_args: Entries,
    /// fields 31/32.
    pub supply_map: Entries,
    pub supply_args: Entries,
    /// fields 33/34.
    pub redeem_map: Entries,
    pub redeem_args: Entries,
}

fn map_of(entries: &Entries) -> StateValue {
    let mut m: HashMap<AlignedValue, StateValue<InMemoryDB>, InMemoryDB> = HashMap::new();
    for (k, v) in entries {
        m = m.insert(k.clone(), cell(v.clone()));
    }
    StateValue::Map(m)
}

fn set_of(elems: &[[u8; 20]]) -> StateValue {
    let mut m: HashMap<AlignedValue, StateValue<InMemoryDB>, InMemoryDB> = HashMap::new();
    for e in elems {
        m = m.insert(bytesn_value(20, e), StateValue::Null);
    }
    StateValue::Map(m)
}

fn u64_cell(v: u64) -> StateValue {
    cell(bytesn_value(8, &v.to_le_bytes()))
}

fn u128_cell(v: u128) -> StateValue {
    cell(bytesn_value(16, &v.to_le_bytes()))
}

impl PreState {
    /// The 35 fields in declaration order, before segmentation.
    fn fields(&self) -> Vec<StateValue> {
        let gas_limbs: Vec<minocrab::Fr> = self.gas_limits.iter().map(|g| minocrab::Fr::from(*g)).collect();
        vec![
            cell(bytesn_value(32, &self.signet_signer)),
            match &self.mpc_response_key {
                Some(av) => cell(av.clone()),
                None => StateValue::Null,
            },
            u128_cell(self.max_fee_per_gas),
            u128_cell(self.max_priority_fee_per_gas),
            cell(aligned(&[8, 8, 8, 8, 8], &gas_limbs)),
            cell(bytesn_value(1, &[u8::from(self.initialised)])),
            cell(bytesn_value(20, &self.vault_evm)),
            u64_cell(self.chain_id),
            cell(bytesn_value(1, &[self.key_version])),
            cell(bytesn_value(32, &self.deployer)),
            cell(bytesn_value(20, &self.uniswap_router)),
            cell(bytesn_value(20, &self.stata_underlying)),
            cell(bytesn_value(20, &self.stata_token)),
            set_of(&self.allowed_tokens),
            u64_cell(self.global_last_seen),
            u64_cell(self.vault_account_nonce),
            map_of(&self.input_request_buffer),
            map_of(&self.output_request_buffer),
            map_of(&self.input_attestation_buffer),
            map_of(&self.output_attestation_buffer),
            map_of(&self.eviction_map),
            map_of(&self.replace_nonce_map),
            map_of(&self.replace_nonce_args),
            map_of(&self.approve_map),
            map_of(&self.approve_args),
            map_of(&self.deposit_map),
            map_of(&self.deposit_args),
            map_of(&self.withdraw_map),
            map_of(&self.withdraw_args),
            map_of(&self.swap_map),
            map_of(&self.swap_args),
            map_of(&self.supply_map),
            map_of(&self.supply_args),
            map_of(&self.redeem_map),
            map_of(&self.redeem_args),
        ]
    }

    /// The SEGMENTED state tree the circuits index into: an array of three
    /// arrays, five fields then fifteen then fifteen (`ops::segment_of`).
    pub fn state(&self) -> StateValue {
        let fields = self.fields();
        assert_eq!(fields.len(), usize::from(FIELDS));
        let mut segments: Vec<Vec<StateValue>> = vec![Vec::new(), Vec::new(), Vec::new()];
        for (i, f) in fields.into_iter().enumerate() {
            let (seg, off) = segment_of(i as u8);
            assert_eq!(usize::from(off), segments[usize::from(seg)].len());
            segments[usize::from(seg)].push(f);
        }
        StateValue::Array(Array::from(
            segments
                .into_iter()
                .map(|s| StateValue::Array(Array::from(s)))
                .collect::<Vec<_>>(),
        ))
    }
}

/// What the reference VM produced for one call.
#[derive(Debug)]
pub struct Executed {
    /// The state after the op stream applied.
    pub post: StateValue,
    /// The ledger effects the transcript declares — the exact value
    /// `semantics.rs:1441` compares a transaction's declared effects to.
    pub effects: Effects<InMemoryDB>,
    /// Log items the program emitted (none of the vault's circuits log).
    pub events: Vec<VersionedLogItem<InMemoryDB>>,
}

/// Run `ops` against `pre` with `self_addr` as the contract's own address
/// (what `kernel.self()` reads back).
///
/// Verify mode, not gather: the vault's op streams already carry their
/// `Popeq` results, so `ResultModeVerify::process_read` checks each read
/// against the real state and errors `ReadMismatch` when the model and the
/// state disagree. That check is the point — it is what makes the model's
/// claimed pre-state real rather than asserted.
pub fn run(pre: &PreState, self_addr: &[u8; 32], ops: &[VmOp]) -> Result<Executed, String> {
    assert_normalized(ops)?;
    let ctx = QueryContext::new(ChargedState::new(pre.state()), ContractAddress(HashOutput(*self_addr)));
    let res: QueryResults<ResultModeVerify, InMemoryDB> =
        ctx.query(ops, None, &INITIAL_COST_MODEL).map_err(|e| format!("{e:?}"))?;
    Ok(Executed {
        post: res.context.state.get_ref().clone(),
        effects: res.context.effects,
        events: res.events,
    })
}

/// The trap notes/vault-optimization.org flags: `prove.rs:291-327` merges
/// adjacent `Noop`s (summing their `n`) when a transaction is proved, and
/// `verify.rs:1889-1894` REJECTS any transcript still holding two adjacent
/// `Noop`s (`MalformedTransaction::NotNormalized`). A reference op stream
/// that is compared to a circuit's must therefore be normalised the same
/// way, or the comparison is against a program the ledger would never
/// accept. The vault's circuits emit no `Noop` at all, so this is a guard
/// against regression.
pub fn assert_normalized(ops: &[VmOp]) -> Result<(), String> {
    for (i, w) in ops.windows(2).enumerate() {
        if matches!((&w[0], &w[1]), (Op::Noop { .. }, Op::Noop { .. })) {
            return Err(format!("unnormalised transcript: adjacent Noops at {i}/{}", i + 1));
        }
    }
    Ok(())
}

/// The slot of field `field` in a segmented state tree.
pub fn slot(state: &StateValue, field: u8) -> Option<StateValue> {
    let (seg, off) = segment_of(field);
    let StateValue::Array(segments) = state else {
        return None;
    };
    let StateValue::Array(fields) = segments.get(usize::from(seg))? else {
        return None;
    };
    fields.get(usize::from(off)).cloned()
}

/// Read a map field's entry as an `AlignedValue`, or `None` when absent.
pub fn map_get(state: &StateValue, field: u8, key: &AlignedValue) -> Option<AlignedValue> {
    let StateValue::Map(ref m) = slot(state, field)? else {
        return None;
    };
    let entry = m.get(key)?;
    let StateValue::Cell(av) = entry.deref() else {
        return None;
    };
    Some((**av).clone())
}

/// Is `key` present in the map (or set) at `field` of `state`?
pub fn map_member(state: &StateValue, field: u8, key: &AlignedValue) -> bool {
    match slot(state, field) {
        Some(StateValue::Map(ref m)) => m.get(key).is_some(),
        _ => false,
    }
}

/// A cell field's first atom, as bytes.
pub fn cell_bytes(state: &StateValue, field: u8) -> Option<Vec<u8>> {
    let StateValue::Cell(ref av) = slot(state, field)? else {
        return None;
    };
    av.value.0.first().map(|a| a.0.clone())
}

/// Read a `Uint<64>` cell out of a state tree.
pub fn u64_of(state: &StateValue, field: u8) -> Option<u64> {
    let bytes = cell_bytes(state, field)?;
    let mut le = [0u8; 8];
    le[..bytes.len().min(8)].copy_from_slice(&bytes[..bytes.len().min(8)]);
    Some(u64::from_le_bytes(le))
}

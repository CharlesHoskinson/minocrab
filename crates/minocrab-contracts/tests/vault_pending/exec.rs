//! The reference EXECUTOR for the `erc20_vault_pending` lineage — the
//! `Pending`-based twin of `tests/vault/exec.rs`. Runs the model's Impact
//! op streams through Midnight's own `QueryContext::query` against a real,
//! segmented, twenty-two-field state tree.

use std::ops::Deref;

use midnight_base_crypto::fab::AlignedValue;
use midnight_coin_structure::contract::ContractAddress;
use midnight_base_crypto::hash::HashOutput;
use midnight_onchain_runtime::context::{Effects, QueryContext, QueryResults};
use midnight_onchain_state::state::{ChargedState, StateValue};
use midnight_onchain_vm::cost_model::INITIAL_COST_MODEL;
use midnight_onchain_vm::ops::{Op, VersionedLogItem};
use midnight_onchain_vm::result_mode::ResultModeVerify;
use midnight_storage::db::InMemoryDB;
use midnight_storage::storage::{Array, HashMap};

use super::ops::{segment_of, FIELDS};
use super::prims::{bytesn_value, cell, VmOp};

/// A map field's entries: request id → stored value.
pub type Entries = Vec<([u8; 32], AlignedValue)>;

/// The Pending lineage's ledger state, one field per declaration index
/// (`model.rs`'s field constants).
#[derive(Clone, Debug, Default)]
pub struct PreState {
    /// field 0 — `initialized: Counter`.
    pub initialized: u64,
    /// field 1 — `deployer`.
    pub deployer: [u8; 32],
    /// field 2 — `vaultEvmAddress`.
    pub vault_evm_address: [u8; 20],
    /// field 3 — `uniswapRouter`.
    pub uniswap_router: [u8; 20],
    /// field 4 — `signet.signer` (sealed).
    pub signer: [u8; 32],
    /// field 5 — `signet.mpcResponseKey` (a `Secp256k1Point`, 5 FAB limbs).
    pub mpc_response_key: Option<AlignedValue>,
    /// field 6 — `signet.mpcKeyVersion`. The V2 lineage had a
    /// `requestNonce: Counter` and a `caip2Id` cell in these positions; both
    /// went with the V1 vocabulary (M44 rung D), so every field below moved
    /// down one.
    pub key_version: u8,
    /// field 7 — `signet.evmChainId`.
    pub evm_chain_id: u64,
    /// field 8 — `deposits` records.
    pub deposits_records: Entries,
    /// field 9 — `deposits` envs.
    pub deposits_envs: Entries,
    /// field 10 — `withdrawals` records.
    pub withdrawals_records: Entries,
    /// field 11 — `withdrawals` envs.
    pub withdrawals_envs: Entries,
    /// field 12 — `swaps` records.
    pub swaps_records: Entries,
    /// field 13 — `swaps` envs.
    pub swaps_envs: Entries,
    /// field 14 — `approvals` (Fired: records only).
    pub approvals: Entries,
    /// field 15 — `stataUnderlying`.
    pub stata_underlying: [u8; 20],
    /// field 16 — `stataToken`.
    pub stata_token: [u8; 20],
    /// field 17 — `supplies` records.
    pub supplies_records: Entries,
    /// field 18 — `supplies` envs.
    pub supplies_envs: Entries,
    /// field 19 — `redeems` records.
    pub redeems_records: Entries,
    /// field 20 — `redeems` envs.
    pub redeems_envs: Entries,
}

fn map_of(entries: &Entries) -> StateValue {
    let mut m: HashMap<AlignedValue, StateValue<InMemoryDB>, InMemoryDB> = HashMap::new();
    for (k, v) in entries {
        m = m.insert(bytesn_value(32, k), cell(v.clone()));
    }
    StateValue::Map(m)
}

impl PreState {
    /// The 22 fields in declaration order, before segmentation.
    fn fields(&self) -> Vec<StateValue> {
        vec![
            cell(bytesn_value(8, &self.initialized.to_le_bytes())),
            cell(bytesn_value(32, &self.deployer)),
            cell(bytesn_value(20, &self.vault_evm_address)),
            cell(bytesn_value(20, &self.uniswap_router)),
            cell(bytesn_value(32, &self.signer)),
            match &self.mpc_response_key {
                Some(av) => cell(av.clone()),
                None => StateValue::Null,
            },
            cell(bytesn_value(1, &[self.key_version])),
            cell(bytesn_value(8, &self.evm_chain_id.to_le_bytes())),
            map_of(&self.deposits_records),
            map_of(&self.deposits_envs),
            map_of(&self.withdrawals_records),
            map_of(&self.withdrawals_envs),
            map_of(&self.swaps_records),
            map_of(&self.swaps_envs),
            map_of(&self.approvals),
            cell(bytesn_value(20, &self.stata_underlying)),
            cell(bytesn_value(20, &self.stata_token)),
            map_of(&self.supplies_records),
            map_of(&self.supplies_envs),
            map_of(&self.redeems_records),
            map_of(&self.redeems_envs),
        ]
    }

    /// The SEGMENTED state tree the circuits index into: an array of two
    /// arrays, seven fields then fifteen (`ops::segment_of`).
    pub fn state(&self) -> StateValue {
        let fields = self.fields();
        assert_eq!(fields.len(), usize::from(FIELDS));
        let mut segments: Vec<Vec<StateValue>> = vec![Vec::new(), Vec::new()];
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
    pub post: StateValue,
    pub effects: Effects<InMemoryDB>,
    pub events: Vec<VersionedLogItem<InMemoryDB>>,
}

/// Run `ops` against `pre` with `self_addr` as the contract's own address.
pub fn run(pre: &PreState, self_addr: &[u8; 32], ops: &[VmOp]) -> Result<Executed, String> {
    assert_normalized(ops)?;
    let ctx = QueryContext::new(
        ChargedState::new(pre.state()),
        ContractAddress(HashOutput(*self_addr)),
    );
    let res: QueryResults<ResultModeVerify, InMemoryDB> = ctx
        .query(ops, None, &INITIAL_COST_MODEL)
        .map_err(|e| format!("{e:?}"))?;
    Ok(Executed {
        post: res.context.state.get_ref().clone(),
        effects: res.context.effects,
        events: res.events,
    })
}

/// See `tests/vault/exec.rs::assert_normalized`.
pub fn assert_normalized(ops: &[VmOp]) -> Result<(), String> {
    for (i, w) in ops.windows(2).enumerate() {
        if matches!((&w[0], &w[1]), (Op::Noop { .. }, Op::Noop { .. })) {
            return Err(format!(
                "unnormalised transcript: adjacent Noops at {i}/{}",
                i + 1
            ));
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
pub fn map_get(state: &StateValue, field: u8, key: &[u8; 32]) -> Option<AlignedValue> {
    let StateValue::Map(ref m) = slot(state, field)? else {
        return None;
    };
    let entry = m.get(&bytesn_value(32, key))?;
    let StateValue::Cell(av) = entry.deref() else {
        return None;
    };
    Some((**av).clone())
}

/// Is `key` present in the map at `field` of `state`?
pub fn map_member(state: &StateValue, field: u8, key: &[u8; 32]) -> bool {
    match slot(state, field) {
        Some(StateValue::Map(ref m)) => m.get(&bytesn_value(32, key)).is_some(),
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

/// Read a counter field (a `Bytes<8>` cell) out of a state tree.
pub fn counter(state: &StateValue, field: u8) -> Option<u64> {
    let bytes = cell_bytes(state, field)?;
    let mut le = [0u8; 8];
    le[..bytes.len().min(8)].copy_from_slice(&bytes[..bytes.len().min(8)]);
    Some(u64::from_le_bytes(le))
}

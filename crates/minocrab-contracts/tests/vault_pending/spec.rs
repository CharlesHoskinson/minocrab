//! The `erc20_vault_pending` SPEC: each of the seventeen circuits as a
//! total function from a scenario to an [`Outcome`] — the `Pending`-based
//! twin of `tests/vault/spec.rs`. No compactc comparator exists for this
//! lineage (notes/signet-async.org "Rung C as built"), so the oracle here
//! is this spec alone, checked against `minocrab_sim::v3::simulate` and
//! against the real ledger VM (`exec::run`) via [`check_effects`].

use midnight_base_crypto::fab::AlignedValue;
use midnight_transient_crypto::hash::transient_commit;
use minocrab::Fr;

use super::exec::{self, Executed, PreState};
use super::model::*;
use super::prims::{b32_slots, bytesn_value, coin_commitment_of, evolved_nonce};

/// Which assertion rejected — named after the Compact-style message the
/// circuit's own `.message(...)` carries (or, for `signet_flow`'s shared
/// checks, the API's own doc comment).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuardId {
    // initialize
    AlreadyInitialized,
    NotTheDeployer,
    ChainIdMustBePositive,
    RouterCannotBeZero,
    StataUnderlyingCannotBeZero,
    StataTokenCannotBeZero,
    // shared request guards
    NotInitialized,
    Erc20AddressCannotBeZero,
    AmountMustBePositive,
    AmountExceedsUint64Max,
    GasLimitMustBePositive,
    KeyVersionMustBeGe1,
    RequestAlreadyExists,
    CoinIsNotTheVaultToken,
    CoinValueMustEqualAmount,
    TokenInCannotBeZero,
    TokenOutCannotBeZero,
    AmountOutMustBePositive,
    AmountInMaximumMustBePositive,
    AmountOutExceedsUint64Max,
    AmountInMaximumExceedsUint64Max,
    SharesMustBePositive,
    SharesExceedUint64Max,
    // settle guards
    TheMpcAttestedAFailure,
    DepositNotFound,
    NotTheDepositor,
    WithdrawalNotFound,
    NotTheWithdrawer,
    SwapNotFound,
    NotTheSwapper,
    ChangeUnderflow,
    SupplyNotFound,
    NotTheSupplier,
    RedeemNotFound,
    NotTheRedeemer,
    // M37 rung D: the Succeeded / Failed split
    /// `complete` was handed an attestation the call's `succeeded`
    /// predicate says is not a success.
    TheAttestedCallDidNotSucceed,
    /// `refund` was handed neither the MPC's failure kind nor an
    /// executed-but-unsuccessful attestation.
    NotARefundableOutcome,
}

/// One declared state change or ledger claim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Effect {
    CounterInc { field: u8, by: u64 },
    MapInsert { field: u8, key: [u8; 32], value: AlignedValue },
    MapRemove { field: u8, key: [u8; 32] },
    CellWrite { field: u8, value: AlignedValue },
    MintShielded { domain_sep: [u8; 32], value: u64 },
    ClaimSpend([u8; 32]),
    ClaimReceive([u8; 32]),
    ClaimContractCall { addr: [u8; 32], ep: [u8; 32], comm: Fr },
}

/// What a circuit does with one call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    Reject(GuardId),
    Accept(Vec<Effect>),
}

impl Outcome {
    pub fn accepts(&self) -> bool {
        matches!(self, Outcome::Accept(_))
    }
    pub fn guard(&self) -> Option<GuardId> {
        match self {
            Outcome::Reject(g) => Some(*g),
            _ => None,
        }
    }
    pub fn effects(&self) -> &[Effect] {
        match self {
            Outcome::Accept(effects) => effects,
            _ => &[],
        }
    }
}

const U64_MAX_U128: u128 = u64::MAX as u128;

// ---- shared pieces -----------------------------------------------------------------------

/// The effects every request circuit declares, on top of any burn: the
/// record insert, the (optional) env insert, the notification call.
fn request_effects(
    env: &Env,
    records_field: u8,
    envs_field: Option<u8>,
    rid: [u8; 32],
    record_av: AlignedValue,
    env_av: Option<AlignedValue>,
    cc_rand: Fr,
) -> Vec<Effect> {
    let mut effects = vec![
        // No counter increment since M44 rung D: the Signet request nonce
        // went with the V1 vocabulary, so a request's first effect is the
        // record insert.
        Effect::MapInsert { field: records_field, key: rid, value: record_av },
    ];
    if let (Some(f), Some(av)) = (envs_field, env_av) {
        effects.push(Effect::MapInsert { field: f, key: rid, value: av });
    }
    effects.push(Effect::ClaimContractCall {
        addr: env.signer_addr,
        ep: env.ep,
        comm: transient_commit(&call_args(&env.self_addr, records_field, &rid)[..], cc_rand),
    });
    effects
}

/// `burn_spend`'s ONE claimed spend of the evolved-nonce output.
fn burn_effect(coin_nonce: &[u8; 32], color: &[u8; 32], value: u128) -> Effect {
    let evolved = evolved_nonce(coin_nonce);
    Effect::ClaimSpend(coin_commitment_of(&evolved, color, value, true, &[0u8; 32]))
}

/// A mint of `amount` of the vault token for `erc20` to `left(pk)`.
fn mint_effects(erc20: &[u8; 20], amount: u64, nonce: &[u8; 32], pk: &[u8; 32], self_addr: &[u8; 32]) -> Vec<Effect> {
    let color = vault_color(erc20, self_addr);
    vec![
        Effect::MintShielded { domain_sep: vault_token_domain_sep(erc20), value: amount },
        Effect::ClaimSpend(coin_commitment_of(&b32_slots(nonce), &color, u128::from(amount), true, pk)),
    ]
}

/// `Pending::consume`'s two removes.
fn consume_effects(records_field: u8, envs_field: u8, rid: [u8; 32]) -> Vec<Effect> {
    vec![
        Effect::MapRemove { field: records_field, key: rid },
        Effect::MapRemove { field: envs_field, key: rid },
    ]
}

fn coin_guards(coin_color: [u8; 32], vault_color: [u8; 32], coin_value: u128, amount: u128) -> Option<GuardId> {
    if coin_color != vault_color {
        return Some(GuardId::CoinIsNotTheVaultToken);
    }
    if coin_value != amount {
        return Some(GuardId::CoinValueMustEqualAmount);
    }
    None
}

// ---- the seventeen circuits -----------------------------------------------------------------

pub fn spec_initialize(s: &InitializeScenario) -> Outcome {
    if s.env.initialized != 0 {
        return Outcome::Reject(GuardId::AlreadyInitialized);
    }
    if pending_user_commitment(&s.sk) != s.env.deployer() {
        return Outcome::Reject(GuardId::NotTheDeployer);
    }
    // The key-version guard lives HERE since M44 rung D, where it used to
    // sit on every request: the version is a write-once cell, so this is the
    // only circuit that can choose it.
    if s.key_version == 0 {
        return Outcome::Reject(GuardId::KeyVersionMustBeGe1);
    }
    if s.chain_id == 0 {
        return Outcome::Reject(GuardId::ChainIdMustBePositive);
    }
    if s.swap_router == [0u8; 20] {
        return Outcome::Reject(GuardId::RouterCannotBeZero);
    }
    if s.stata_underlying == [0u8; 20] {
        return Outcome::Reject(GuardId::StataUnderlyingCannotBeZero);
    }
    if s.stata_token == [0u8; 20] {
        return Outcome::Reject(GuardId::StataTokenCannotBeZero);
    }
    Outcome::Accept(vec![
        Effect::CounterInc { field: INITIALIZED, by: 1 },
        Effect::CellWrite { field: VAULT_EVM_ADDRESS, value: bytesn_value(20, &s.vault_evm) },
        Effect::CellWrite { field: UNISWAP_ROUTER, value: bytesn_value(20, &s.swap_router) },
        Effect::CellWrite { field: STATA_UNDERLYING, value: bytesn_value(20, &s.stata_underlying) },
        Effect::CellWrite { field: STATA_TOKEN, value: bytesn_value(20, &s.stata_token) },
        Effect::CellWrite { field: MPC_RESPONSE_KEY, value: point_av(&s.point()) },
        Effect::CellWrite { field: MPC_KEY_VERSION, value: bytesn_value(1, &[s.key_version]) },
        Effect::CellWrite { field: EVM_CHAIN_ID, value: bytesn_value(8, &s.chain_id.to_le_bytes()) },
    ])
}

pub fn spec_approve_router(s: &ApproveRouterScenario) -> Outcome {
    if s.env.initialized < 1 {
        return Outcome::Reject(GuardId::NotInitialized);
    }
    if s.erc20 == [0u8; 20] {
        return Outcome::Reject(GuardId::Erc20AddressCannotBeZero);
    }
    if s.request_exists {
        return Outcome::Reject(GuardId::RequestAlreadyExists);
    }
    Outcome::Accept(request_effects(&s.env, APPROVALS, None, s.request_id(), s.req().av(&s.env), None, s.cc_rand))
}

pub fn spec_approve_stata(s: &ApproveStataScenario) -> Outcome {
    if s.env.initialized < 1 {
        return Outcome::Reject(GuardId::NotInitialized);
    }
    if s.request_exists {
        return Outcome::Reject(GuardId::RequestAlreadyExists);
    }
    Outcome::Accept(request_effects(&s.env, APPROVALS, None, s.request_id(), s.req().av(&s.env), None, s.cc_rand))
}

pub fn spec_start_deposit(s: &StartDepositScenario) -> Outcome {
    if s.env.initialized < 1 {
        return Outcome::Reject(GuardId::NotInitialized);
    }
    if s.erc20 == [0u8; 20] {
        return Outcome::Reject(GuardId::Erc20AddressCannotBeZero);
    }
    if s.amount == 0 {
        return Outcome::Reject(GuardId::AmountMustBePositive);
    }
    if s.amount > U64_MAX_U128 {
        return Outcome::Reject(GuardId::AmountExceedsUint64Max);
    }
    if s.gas_limit == 0 {
        return Outcome::Reject(GuardId::GasLimitMustBePositive);
    }
    if s.request_exists {
        return Outcome::Reject(GuardId::RequestAlreadyExists);
    }
    Outcome::Accept(request_effects(
        &s.env,
        DEPOSITS_RECORDS,
        Some(DEPOSITS_ENVS),
        s.request_id(),
        s.req().av(&s.env),
        Some(s.env_av()),
        s.cc_rand,
    ))
}

pub fn spec_claim(s: &ClaimScenario) -> Outcome {
    if s.d.env.initialized < 1 {
        return Outcome::Reject(GuardId::NotInitialized);
    }
    if !s.settle.pending {
        return Outcome::Reject(GuardId::DepositNotFound);
    }
    if !s.success {
        return Outcome::Reject(GuardId::TheMpcAttestedAFailure);
    }
    if pending_user_commitment(&s.settle.sk(&s.d.sk)) != s.d.commitment() {
        return Outcome::Reject(GuardId::NotTheDepositor);
    }
    let rid = s.d.request_id();
    let mut effects = consume_effects(DEPOSITS_RECORDS, DEPOSITS_ENVS, rid);
    // The recipient can be `left(pk)` OR `right(contract)`, unlike every
    // other mint in this contract (always `left(ownPublicKey)`), so the
    // commitment is built directly rather than through `mint_effects`.
    effects.push(Effect::MintShielded { domain_sep: vault_token_domain_sep(&s.d.erc20), value: s.d.amount_u64() });
    effects.push(Effect::ClaimSpend(s.coin_commitment()));
    if s.auto_receive() {
        effects.push(Effect::ClaimReceive(s.coin_commitment()));
    }
    Outcome::Accept(effects)
}

pub fn spec_start_withdraw(s: &StartWithdrawScenario) -> Outcome {
    if s.env.initialized < 1 {
        return Outcome::Reject(GuardId::NotInitialized);
    }
    if s.erc20 == [0u8; 20] {
        return Outcome::Reject(GuardId::Erc20AddressCannotBeZero);
    }
    if s.amount == 0 {
        return Outcome::Reject(GuardId::AmountMustBePositive);
    }
    if s.amount > U64_MAX_U128 {
        return Outcome::Reject(GuardId::AmountExceedsUint64Max);
    }
    if let Some(g) = coin_guards(s.coin_color(), vault_color(&s.erc20, &s.env.self_addr), s.coin_value(), s.amount) {
        return Outcome::Reject(g);
    }
    if s.request_exists {
        return Outcome::Reject(GuardId::RequestAlreadyExists);
    }
    let mut effects = vec![burn_effect(&s.coin_nonce, &s.coin_color(), s.coin_value())];
    effects.extend(request_effects(
        &s.env,
        WITHDRAWALS_RECORDS,
        Some(WITHDRAWALS_ENVS),
        s.request_id(),
        s.req().av(&s.env),
        Some(s.env_av()),
        s.cc_rand,
    ));
    Outcome::Accept(effects)
}

/// M37 rung D: ANYONE'S, and successes only. The executed-`false` branch
/// that used to live here — with its hoisted secret witness — is
/// `refund_withdrawal`'s now.
pub fn spec_complete_withdraw(s: &CompleteWithdrawScenario) -> Outcome {
    if s.w.env.initialized < 1 {
        return Outcome::Reject(GuardId::NotInitialized);
    }
    if !s.settle.pending {
        return Outcome::Reject(GuardId::WithdrawalNotFound);
    }
    if !s.success {
        return Outcome::Reject(GuardId::TheAttestedCallDidNotSucceed);
    }
    let rid = s.w.request_id();
    Outcome::Accept(consume_effects(WITHDRAWALS_RECORDS, WITHDRAWALS_ENVS, rid))
}

/// M37 rung D: BOTH non-successes — the MPC's failure kind and a mined
/// `transfer` that returned `false`.
pub fn spec_refund_withdrawal(s: &RefundWithdrawalScenario) -> Outcome {
    if s.w.env.initialized < 1 {
        return Outcome::Reject(GuardId::NotInitialized);
    }
    if !s.refundable() {
        return Outcome::Reject(GuardId::NotARefundableOutcome);
    }
    if !s.settle.pending {
        return Outcome::Reject(GuardId::WithdrawalNotFound);
    }
    let rid = s.w.request_id();
    if refund_commit_of(&s.settle.sk(&s.w.sk), &rid) != s.w.refund_commitment() {
        return Outcome::Reject(GuardId::NotTheWithdrawer);
    }
    let mut effects = consume_effects(WITHDRAWALS_RECORDS, WITHDRAWALS_ENVS, rid);
    effects.extend(mint_effects(&s.w.erc20, s.w.amount_u64(), &s.settle.mint_nonce, &s.settle.own_pk, &s.w.env.self_addr));
    Outcome::Accept(effects)
}

pub fn spec_start_swap(s: &StartSwapScenario) -> Outcome {
    if s.env.initialized < 1 {
        return Outcome::Reject(GuardId::NotInitialized);
    }
    if s.token_in == [0u8; 20] {
        return Outcome::Reject(GuardId::TokenInCannotBeZero);
    }
    if s.token_out == [0u8; 20] {
        return Outcome::Reject(GuardId::TokenOutCannotBeZero);
    }
    if s.amount_out == 0 {
        return Outcome::Reject(GuardId::AmountOutMustBePositive);
    }
    if s.amount_in_max == 0 {
        return Outcome::Reject(GuardId::AmountInMaximumMustBePositive);
    }
    if s.amount_out > U64_MAX_U128 {
        return Outcome::Reject(GuardId::AmountOutExceedsUint64Max);
    }
    if s.amount_in_max > U64_MAX_U128 {
        return Outcome::Reject(GuardId::AmountInMaximumExceedsUint64Max);
    }
    if let Some(g) = coin_guards(s.coin_color(), vault_color(&s.token_in, &s.env.self_addr), s.coin_value(), s.amount_in_max) {
        return Outcome::Reject(g);
    }
    if s.request_exists {
        return Outcome::Reject(GuardId::RequestAlreadyExists);
    }
    let mut effects = vec![burn_effect(&s.coin_nonce, &s.coin_color(), s.coin_value())];
    effects.extend(request_effects(
        &s.env,
        SWAPS_RECORDS,
        Some(SWAPS_ENVS),
        s.request_id(),
        s.req().av(&s.env),
        Some(s.env_av()),
        s.cc_rand,
    ));
    Outcome::Accept(effects)
}

pub fn spec_complete_swap(s: &CompleteSwapScenario) -> Outcome {
    if s.s.env.initialized < 1 {
        return Outcome::Reject(GuardId::NotInitialized);
    }
    if !s.settle.pending {
        return Outcome::Reject(GuardId::SwapNotFound);
    }
    let rid = s.s.request_id();
    if refund_commit_of(&s.settle.sk(&s.s.sk), &rid) != s.s.refund_commitment() {
        return Outcome::Reject(GuardId::NotTheSwapper);
    }
    let Some(change) = s.change() else {
        return Outcome::Reject(GuardId::ChangeUnderflow);
    };
    let mut effects = consume_effects(SWAPS_RECORDS, SWAPS_ENVS, rid);
    effects.extend(mint_effects(&s.s.token_out, s.s.amount_out_u64(), &s.settle.mint_nonce, &s.settle.own_pk, &s.s.env.self_addr));
    effects.extend(mint_effects(&s.s.token_in, change, &s.change_nonce(), &s.settle.own_pk, &s.s.env.self_addr));
    Outcome::Accept(effects)
}

/// M37 rung D: the ticket is `Failed`, but this call's `succeeded` is
/// `always`, so only the MPC's failure kind is refundable.
pub fn spec_refund_swap(s: &RefundSwapScenario) -> Outcome {
    if s.s.env.initialized < 1 {
        return Outcome::Reject(GuardId::NotInitialized);
    }
    if !s.refundable() {
        return Outcome::Reject(GuardId::NotARefundableOutcome);
    }
    if !s.settle.pending {
        return Outcome::Reject(GuardId::SwapNotFound);
    }
    let rid = s.s.request_id();
    if refund_commit_of(&s.settle.sk(&s.s.sk), &rid) != s.s.refund_commitment() {
        return Outcome::Reject(GuardId::NotTheSwapper);
    }
    let mut effects = consume_effects(SWAPS_RECORDS, SWAPS_ENVS, rid);
    effects.extend(mint_effects(&s.s.token_in, s.s.amount_in_max_u64(), &s.settle.mint_nonce, &s.settle.own_pk, &s.s.env.self_addr));
    Outcome::Accept(effects)
}

pub fn spec_start_supply(s: &StartSupplyScenario) -> Outcome {
    if s.env.initialized < 1 {
        return Outcome::Reject(GuardId::NotInitialized);
    }
    if s.amount == 0 {
        return Outcome::Reject(GuardId::AmountMustBePositive);
    }
    if s.amount > U64_MAX_U128 {
        return Outcome::Reject(GuardId::AmountExceedsUint64Max);
    }
    if let Some(g) = coin_guards(s.coin_color(), vault_color(&s.env.stata_underlying, &s.env.self_addr), s.coin_value(), s.amount) {
        return Outcome::Reject(g);
    }
    if s.request_exists {
        return Outcome::Reject(GuardId::RequestAlreadyExists);
    }
    let mut effects = vec![burn_effect(&s.coin_nonce, &s.coin_color(), s.coin_value())];
    effects.extend(request_effects(
        &s.env,
        SUPPLIES_RECORDS,
        Some(SUPPLIES_ENVS),
        s.request_id(),
        s.req().av(&s.env),
        Some(s.env_av()),
        s.cc_rand,
    ));
    Outcome::Accept(effects)
}

pub fn spec_complete_supply(s: &CompleteSupplyScenario) -> Outcome {
    if s.s.env.initialized < 1 {
        return Outcome::Reject(GuardId::NotInitialized);
    }
    if !s.settle.pending {
        return Outcome::Reject(GuardId::SupplyNotFound);
    }
    let rid = s.s.request_id();
    if refund_commit_of(&s.settle.sk(&s.s.sk), &rid) != s.s.refund_commitment() {
        return Outcome::Reject(GuardId::NotTheSupplier);
    }
    let mut effects = consume_effects(SUPPLIES_RECORDS, SUPPLIES_ENVS, rid);
    effects.extend(mint_effects(&s.s.env.stata_token, s.shares, &s.settle.mint_nonce, &s.settle.own_pk, &s.s.env.self_addr));
    Outcome::Accept(effects)
}

/// M37 rung D: the ticket is `Failed`, but this call's `succeeded` is
/// `always`, so only the MPC's failure kind is refundable.
pub fn spec_refund_supply(s: &RefundSupplyScenario) -> Outcome {
    if s.s.env.initialized < 1 {
        return Outcome::Reject(GuardId::NotInitialized);
    }
    if !s.refundable() {
        return Outcome::Reject(GuardId::NotARefundableOutcome);
    }
    if !s.settle.pending {
        return Outcome::Reject(GuardId::SupplyNotFound);
    }
    let rid = s.s.request_id();
    if refund_commit_of(&s.settle.sk(&s.s.sk), &rid) != s.s.refund_commitment() {
        return Outcome::Reject(GuardId::NotTheSupplier);
    }
    let mut effects = consume_effects(SUPPLIES_RECORDS, SUPPLIES_ENVS, rid);
    effects.extend(mint_effects(&s.s.env.stata_underlying, s.s.amount_u64(), &s.settle.mint_nonce, &s.settle.own_pk, &s.s.env.self_addr));
    Outcome::Accept(effects)
}

pub fn spec_start_redeem(s: &StartRedeemScenario) -> Outcome {
    if s.env.initialized < 1 {
        return Outcome::Reject(GuardId::NotInitialized);
    }
    if s.shares == 0 {
        return Outcome::Reject(GuardId::SharesMustBePositive);
    }
    if s.shares > U64_MAX_U128 {
        return Outcome::Reject(GuardId::SharesExceedUint64Max);
    }
    if let Some(g) = coin_guards(s.coin_color(), vault_color(&s.env.stata_token, &s.env.self_addr), s.coin_value(), s.shares) {
        return Outcome::Reject(g);
    }
    if s.request_exists {
        return Outcome::Reject(GuardId::RequestAlreadyExists);
    }
    let mut effects = vec![burn_effect(&s.coin_nonce, &s.coin_color(), s.coin_value())];
    effects.extend(request_effects(
        &s.env,
        REDEEMS_RECORDS,
        Some(REDEEMS_ENVS),
        s.request_id(),
        s.req().av(&s.env),
        Some(s.env_av()),
        s.cc_rand,
    ));
    Outcome::Accept(effects)
}

pub fn spec_complete_redeem(s: &CompleteRedeemScenario) -> Outcome {
    if s.s.env.initialized < 1 {
        return Outcome::Reject(GuardId::NotInitialized);
    }
    if !s.settle.pending {
        return Outcome::Reject(GuardId::RedeemNotFound);
    }
    let rid = s.s.request_id();
    if refund_commit_of(&s.settle.sk(&s.s.sk), &rid) != s.s.refund_commitment() {
        return Outcome::Reject(GuardId::NotTheRedeemer);
    }
    let mut effects = consume_effects(REDEEMS_RECORDS, REDEEMS_ENVS, rid);
    effects.extend(mint_effects(&s.s.env.stata_underlying, s.assets, &s.settle.mint_nonce, &s.settle.own_pk, &s.s.env.self_addr));
    Outcome::Accept(effects)
}

/// M37 rung D: the ticket is `Failed`, but this call's `succeeded` is
/// `always`, so only the MPC's failure kind is refundable.
pub fn spec_refund_redeem(s: &RefundRedeemScenario) -> Outcome {
    if s.s.env.initialized < 1 {
        return Outcome::Reject(GuardId::NotInitialized);
    }
    if !s.refundable() {
        return Outcome::Reject(GuardId::NotARefundableOutcome);
    }
    if !s.settle.pending {
        return Outcome::Reject(GuardId::RedeemNotFound);
    }
    let rid = s.s.request_id();
    if refund_commit_of(&s.settle.sk(&s.s.sk), &rid) != s.s.refund_commitment() {
        return Outcome::Reject(GuardId::NotTheRedeemer);
    }
    let mut effects = consume_effects(REDEEMS_RECORDS, REDEEMS_ENVS, rid);
    effects.extend(mint_effects(&s.s.env.stata_token, s.s.shares_u64(), &s.settle.mint_nonce, &s.settle.own_pk, &s.s.env.self_addr));
    Outcome::Accept(effects)
}

// ---- checking a spec against what the reference VM produced ------------------------------

fn pre_counter(pre: &PreState, field: u8) -> u64 {
    match field {
        INITIALIZED => pre.initialized,
        other => panic!("field {other} is not a counter"),
    }
}

/// Every declared effect holds of the executed run, and the run declares
/// nothing beyond them.
pub fn check_effects(effects: &[Effect], pre: &PreState, ex: &Executed) -> Result<(), String> {
    use std::collections::{BTreeMap, BTreeSet};
    // Every burn in this lineage is `burn_spend` (a claimed spend of the
    // evolved-nonce output, never a claimed nullifier), so `want_nul`
    // stays empty — kept for symmetry with the ledger's own claim sets.
    let want_nul: BTreeSet<[u8; 32]> = BTreeSet::new();
    let mut want_recv: BTreeSet<[u8; 32]> = BTreeSet::new();
    let mut want_spend: BTreeSet<[u8; 32]> = BTreeSet::new();
    let mut want_mint: BTreeMap<[u8; 32], u64> = BTreeMap::new();
    let mut want_calls: BTreeSet<(u64, [u8; 32], [u8; 32], Fr)> = BTreeSet::new();
    let mut call_seq: u64 = 0;

    for e in effects {
        match e {
            Effect::CounterInc { field, by } => {
                let want = pre_counter(pre, *field) + by;
                let got = exec::counter(&ex.post, *field)
                    .ok_or_else(|| format!("field {field} is not a counter cell after the run"))?;
                if got != want {
                    return Err(format!("counter {field}: want {want}, got {got}"));
                }
            }
            Effect::MapInsert { field, key, value } => {
                let got = exec::map_get(&ex.post, *field, key)
                    .ok_or_else(|| format!("map {field} lacks the inserted key"))?;
                if &got != value {
                    return Err(format!("map {field}: inserted value differs"));
                }
            }
            Effect::MapRemove { field, key } => {
                if exec::map_member(&ex.post, *field, key) {
                    return Err(format!("map {field}: key survived the removal"));
                }
            }
            Effect::CellWrite { field, value } => {
                let got = exec::cell_bytes(&ex.post, *field)
                    .ok_or_else(|| format!("field {field} is not a cell after the run"))?;
                let want = value.value.0.first().map(|a| a.0.clone()).unwrap_or_default();
                if got != want {
                    return Err(format!("cell {field}: want {want:?}, got {got:?}"));
                }
            }
            Effect::MintShielded { domain_sep, value } => {
                *want_mint.entry(*domain_sep).or_insert(0) += value;
            }
            Effect::ClaimSpend(cm) => {
                want_spend.insert(*cm);
            }
            Effect::ClaimReceive(cm) => {
                want_recv.insert(*cm);
            }
            Effect::ClaimContractCall { addr, ep, comm } => {
                want_calls.insert((call_seq, *addr, *ep, *comm));
                call_seq += 1;
            }
        }
    }

    let got_nul: BTreeSet<[u8; 32]> = ex.effects.claimed_nullifiers.iter().map(|n| n.0 .0).collect();
    let got_recv: BTreeSet<[u8; 32]> = ex.effects.claimed_shielded_receives.iter().map(|c| c.0 .0).collect();
    let got_spend: BTreeSet<[u8; 32]> = ex.effects.claimed_shielded_spends.iter().map(|c| c.0 .0).collect();
    let got_mint: BTreeMap<[u8; 32], u64> = ex.effects.shielded_mints.iter().map(|kv| (kv.0 .0, *kv.1)).collect();
    let got_calls: BTreeSet<(u64, [u8; 32], [u8; 32], Fr)> = ex
        .effects
        .claimed_contract_calls
        .iter()
        .map(|c| {
            let (seq, addr, ep, comm) = c.into_inner();
            (seq, addr.0 .0, ep.0, comm)
        })
        .collect();

    if got_nul != want_nul {
        return Err(format!("nullifiers: want {want_nul:?}, got {got_nul:?}"));
    }
    if got_recv != want_recv {
        return Err(format!("receives: want {want_recv:?}, got {got_recv:?}"));
    }
    if got_spend != want_spend {
        return Err(format!("spends: want {want_spend:?}, got {got_spend:?}"));
    }
    if got_mint != want_mint {
        return Err(format!("mints: want {want_mint:?}, got {got_mint:?}"));
    }
    if got_calls != want_calls {
        return Err(format!("calls: want {want_calls:?}, got {got_calls:?}"));
    }
    if !ex.effects.unshielded_mints.is_empty()
        || !ex.effects.unshielded_inputs.is_empty()
        || !ex.effects.unshielded_outputs.is_empty()
        || !ex.effects.claimed_unshielded_spends.is_empty()
    {
        return Err("unexpected unshielded effects".into());
    }
    Ok(())
}

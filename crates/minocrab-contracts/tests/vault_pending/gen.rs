//! Generation strategies for the `erc20_vault_pending` lineage — the
//! `Pending`-based twin of `tests/vault/gen.rs`: branch-aware, equal-weight
//! `prop_oneof!`s over each guard's boundary, plus one random interior arm.

use proptest::prelude::*;

use super::model::*;

pub const DEFAULT_CASES: u32 = 48;

pub fn config() -> ProptestConfig {
    let cases = std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_CASES);
    ProptestConfig {
        cases,
        max_shrink_iters: 64,
        ..ProptestConfig::default()
    }
}

pub fn amount() -> impl Strategy<Value = u128> {
    const U64MAX: u128 = u64::MAX as u128;
    prop_oneof![
        Just(0u128),
        Just(1u128),
        Just(U64MAX - 1),
        Just(U64MAX),
        Just(U64MAX + 1),
        Just(u128::MAX),
        (1u64..u64::MAX).prop_map(u128::from),
    ]
}

pub fn valid_amount() -> impl Strategy<Value = u128> {
    const U64MAX: u128 = u64::MAX as u128;
    prop_oneof![Just(1u128), Just(U64MAX - 1), Just(U64MAX), (1u64..u64::MAX).prop_map(u128::from)]
}

pub fn gas_limit() -> impl Strategy<Value = u64> {
    prop_oneof![Just(0u64), Just(1u64), Just(u64::MAX), any::<u64>()]
}

/// A key version an `initialize` may be handed — ZERO INCLUDED, because
/// that is the circuit the `keyVersion must be >= 1` guard lives on.
pub fn key_version() -> impl Strategy<Value = u8> {
    prop_oneof![Just(0u8), Just(1u8), Just(255u8), any::<u8>()]
}

/// A key version a REQUEST can see in the cell: at least one, because a
/// deployment that got past `initialize` cannot hold zero. Since M44 rung D
/// no request takes a version, so this is the configuration a request reads
/// rather than an argument it passes.
pub fn live_key_version() -> impl Strategy<Value = u8> {
    prop_oneof![Just(1u8), Just(255u8), 1u8..=255]
}

pub fn evm_nonce() -> impl Strategy<Value = u64> {
    prop_oneof![Just(0u64), Just(u64::MAX), any::<u64>()]
}

pub fn address20() -> impl Strategy<Value = [u8; 20]> {
    prop_oneof![Just([0u8; 20]), any::<[u8; 20]>()]
}

fn nonzero20() -> impl Strategy<Value = [u8; 20]> {
    any::<[u8; 20]>().prop_map(|a| if a == [0u8; 20] { [1u8; 20] } else { a })
}

pub fn counter_value() -> impl Strategy<Value = u64> {
    prop_oneof![Just(0u64), Just(1u64), Just(u64::MAX - 1), Just(u64::MAX), any::<u64>()]
}

pub fn initialized() -> impl Strategy<Value = u64> {
    prop_oneof![Just(0u64), Just(1u64), Just(u64::MAX)]
}

pub fn b32() -> impl Strategy<Value = [u8; 32]> {
    any::<[u8; 31]>().prop_map(|b| {
        let mut out = [0u8; 32];
        out[..31].copy_from_slice(&b);
        out
    })
}

fn coin_color() -> impl Strategy<Value = Option<[u8; 32]>> {
    prop_oneof![3 => Just(None), 1 => b32().prop_map(Some)]
}

fn coin_value(amount: u128) -> impl Strategy<Value = Option<u128>> {
    prop_oneof![
        3 => Just(None),
        1 => Just(Some(amount.wrapping_add(1))),
        1 => Just(Some(amount.wrapping_sub(1))),
    ]
}

/// The pre-state cells a request circuit reads.
fn env() -> impl Strategy<Value = Env> {
    (initialized(), nonzero20(), nonzero20(), nonzero20(), nonzero20()).prop_map(
        |(init, vault_evm, router, underlying, token)| Env {
            initialized: init,
            vault_evm,
            router,
            stata_underlying: underlying,
            stata_token: token,
            ..Env::new()
        },
    )
}

/// An `Env` a SETTLE reads: initialized or not, the rest configured.
fn settle_env() -> impl Strategy<Value = Env> {
    (initialized(), nonzero20(), nonzero20()).prop_map(|(init, underlying, token)| Env {
        initialized: init,
        stata_underlying: underlying,
        stata_token: token,
        ..Env::new()
    })
}

fn settle() -> impl Strategy<Value = Settle> {
    // The attested height is inside the V1 digest, so it is generated: a
    // settle that signed one height and presented another must not verify,
    // and only a varying height can witness that.
    (b32(), b32(), any::<bool>(), any::<u64>(), any::<u64>()).prop_map(
        |(mint_nonce, own_pk, pending, seed, height)| Settle {
            pending,
            mint_nonce,
            own_pk,
            claimant_sk: None,
            nonce_seed: seed | 1,
            block_height: height,
        },
    )
}

// --- initialize ------------------------------------------------------------------------------

pub fn initialize() -> impl Strategy<Value = InitializeScenario> {
    (
        b32(),
        address20(),
        address20(),
        address20(),
        address20(),
        prop_oneof![Just(0u64), Just(1u64), Just(u64::MAX), any::<u64>()],
        key_version(),
        prop_oneof![Just(0u64), Just(1u64), any::<u64>()],
        any::<bool>(),
    )
        .prop_map(
            |(sk, vault_evm, swap_router, underlying, token, chain_id, kv, count, right_sk)| {
                let mut s = InitializeScenario::new();
                s.vault_evm = vault_evm;
                s.swap_router = swap_router;
                s.stata_underlying = underlying;
                s.stata_token = token;
                s.chain_id = chain_id;
                s.key_version = kv;
                s.env.initialized = count;
                s.sk = sk;
                if right_sk {
                    s.env.deployer_sk = sk;
                }
                s
            },
        )
}

// --- the fire-and-forget allowances ------------------------------------------------------------

pub fn approve_router() -> impl Strategy<Value = ApproveRouterScenario> {
    (env(), address20(), evm_nonce(), live_key_version(), any::<bool>()).prop_map(
        |(env, erc20, nonce, kv, exists)| {
            let mut a = ApproveRouterScenario::new();
            a.env = env;
            a.erc20 = erc20;
            a.evm_nonce = nonce;
            a.env.key_version = kv;
            a.request_exists = exists;
            a
        },
    )
}

pub fn approve_stata() -> impl Strategy<Value = ApproveStataScenario> {
    (env(), evm_nonce(), live_key_version(), any::<bool>()).prop_map(|(env, nonce, kv, exists)| {
        let mut a = ApproveStataScenario::new();
        a.env = env;
        a.evm_nonce = nonce;
        a.env.key_version = kv;
        a.request_exists = exists;
        a
    })
}

// --- deposit / claim ---------------------------------------------------------------------------

pub fn start_deposit() -> impl Strategy<Value = StartDepositScenario> {
    (env(), evm_nonce(), gas_limit(), live_key_version(), address20(), amount(), any::<bool>(), b32()).prop_map(
        |(env, nonce, gas, kv, erc20, amt, exists, sk)| {
            let mut d = StartDepositScenario::new();
            d.env = env;
            d.evm_nonce = nonce;
            d.gas_limit = gas;
            d.env.key_version = kv;
            d.erc20 = erc20;
            d.amount = amt;
            d.request_exists = exists;
            d.sk = sk;
            d
        },
    )
}

/// A deposit whose record a settle could actually be settling.
fn settled_deposit() -> impl Strategy<Value = StartDepositScenario> {
    (settle_env(), evm_nonce(), 1u8..=255, nonzero20(), valid_amount(), b32()).prop_map(
        |(env, nonce, kv, erc20, amt, sk)| {
            let mut d = StartDepositScenario::new();
            d.env = env;
            d.evm_nonce = nonce;
            d.env.key_version = kv;
            d.erc20 = erc20;
            d.amount = amt;
            d.sk = sk;
            d
        },
    )
}

/// The claim recipient dimension: `left(pk)`, `right(contract)` (auto-
/// receive half the time), or `none`.
fn claim_recipient() -> impl Strategy<Value = ClaimRecipient> {
    prop_oneof![
        b32().prop_map(ClaimRecipient::Key),
        b32().prop_map(ClaimRecipient::Contract),
        b32().prop_map(ClaimRecipient::None),
    ]
}

pub fn claim() -> impl Strategy<Value = ClaimScenario> {
    (settled_deposit(), settle(), claim_recipient(), any::<bool>()).prop_map(|(d, settle, recipient, success)| {
        let mut c = ClaimScenario::new();
        c.d = d;
        c.settle = settle;
        c.recipient = recipient;
        // Half the cases present the depositor's own key (the gate
        // passes); half a stranger's.
        c.success = success;
        c
    })
}

/// A claim whose auto-receive branch actually fires — worth over-sampling.
pub fn claim_auto_receive() -> impl Strategy<Value = ClaimScenario> {
    (settled_deposit(), settle(), any::<bool>()).prop_map(|(d, mut settle, success)| {
        let mut c = ClaimScenario::new();
        settle.pending = true;
        let self_addr = d.env.self_addr;
        c.d = d;
        c.settle = settle;
        c.recipient = ClaimRecipient::Contract(self_addr);
        c.success = success;
        c
    })
}

// --- withdraw ------------------------------------------------------------------------------

pub fn start_withdraw() -> impl Strategy<Value = StartWithdrawScenario> {
    (env(), evm_nonce(), live_key_version(), address20(), amount(), address20(), b32(), any::<bool>(), b32()).prop_flat_map(
        |(env, nonce, kv, erc20, amt, dest, coin_nonce, exists, sk)| {
            coin_value(amt).prop_flat_map(move |cv| {
                let env = env.clone();
                coin_color().prop_map(move |cc| {
                    let mut w = StartWithdrawScenario::new();
                    w.env = env.clone();
                    w.evm_nonce = nonce;
                    w.env.key_version = kv;
                    w.erc20 = erc20;
                    w.amount = amt;
                    w.dest = dest;
                    w.coin_nonce = coin_nonce;
                    w.coin_value = cv;
                    w.coin_color = cc;
                    w.request_exists = exists;
                    w.sk = sk;
                    w
                })
            })
        },
    )
}

fn settled_withdraw() -> impl Strategy<Value = StartWithdrawScenario> {
    (settle_env(), evm_nonce(), 1u8..=255, nonzero20(), valid_amount(), address20(), b32(), b32()).prop_map(
        |(env, nonce, kv, erc20, amt, dest, coin_nonce, sk)| {
            let mut w = StartWithdrawScenario::new();
            w.env = env;
            w.evm_nonce = nonce;
            w.env.key_version = kv;
            w.erc20 = erc20;
            w.amount = amt;
            w.dest = dest;
            w.coin_nonce = coin_nonce;
            w.sk = sk;
            w
        },
    )
}

fn claimant(requester: [u8; 32], wrong: bool) -> Option<[u8; 32]> {
    if wrong {
        let mut sk = requester;
        sk[0] ^= 0x5a;
        Some(sk)
    } else {
        None
    }
}

/// M37 rung D: `success` is now the ACCEPT/REJECT axis, not a branch —
/// an attested `false` no longer completes, it refunds.
pub fn complete_withdraw() -> impl Strategy<Value = CompleteWithdrawScenario> {
    (settled_withdraw(), settle(), any::<bool>()).prop_map(|(w, settle, success)| {
        let mut c = CompleteWithdrawScenario::new();
        c.w = w;
        c.settle = settle;
        c.success = success;
        c
    })
}

/// The MPC's failure kind, an executed `false` (both refundable) and an
/// executed `true` (which must reject), each about a third of the cases.
pub fn attested_flag() -> impl Strategy<Value = Attested> {
    prop_oneof![
        any::<bool>().prop_map(|p| Attested::Failure { padding: u64::from(p) }),
        Just(Attested::Executed { value: 0 }),
        Just(Attested::Executed { value: 1 }),
    ]
}

/// A numeric return: the failure kind, or an executed call whose attested
/// number is a success whatever it is.
pub fn attested_number() -> impl Strategy<Value = Attested> {
    prop_oneof![
        any::<u64>().prop_map(|padding| Attested::Failure { padding }),
        any::<u64>().prop_map(|value| Attested::Executed { value }),
    ]
}

pub fn refund_withdrawal() -> impl Strategy<Value = RefundWithdrawalScenario> {
    (settled_withdraw(), settle(), any::<bool>(), attested_flag()).prop_map(
        |(w, mut settle, wrong, attested)| {
            settle.claimant_sk = claimant(w.sk, wrong);
            let mut r = RefundWithdrawalScenario::new();
            r.w = w;
            r.settle = settle;
            r.attested = attested;
            r
        },
    )
}

// --- swap ----------------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
pub fn start_swap() -> impl Strategy<Value = StartSwapScenario> {
    (env(), evm_nonce(), live_key_version(), address20(), address20(), 0u32..=1_000_000, amount(), amount(), b32(), any::<bool>(), b32())
        .prop_flat_map(|(env, nonce, kv, tin, tout, fee, aout, aimax, coin_nonce, exists, sk)| {
            coin_value(aimax).prop_flat_map(move |cv| {
                let env = env.clone();
                coin_color().prop_map(move |cc| {
                    let mut s = StartSwapScenario::new();
                    s.env = env.clone();
                    s.evm_nonce = nonce;
                    s.env.key_version = kv;
                    s.token_in = tin;
                    s.token_out = tout;
                    s.fee = fee;
                    s.amount_out = aout;
                    s.amount_in_max = aimax;
                    s.coin_nonce = coin_nonce;
                    s.coin_value = cv;
                    s.coin_color = cc;
                    s.request_exists = exists;
                    s.sk = sk;
                    s
                })
            })
        })
}

fn settled_swap() -> impl Strategy<Value = StartSwapScenario> {
    (settle_env(), evm_nonce(), 1u8..=255, nonzero20(), nonzero20(), valid_amount(), valid_amount(), b32(), b32())
        .prop_map(|(env, nonce, kv, tin, tout, aout, aimax, coin_nonce, sk)| {
            let mut s = StartSwapScenario::new();
            s.env = env;
            s.evm_nonce = nonce;
            s.env.key_version = kv;
            s.token_in = tin;
            s.token_out = tout;
            s.amount_out = aout;
            s.amount_in_max = aimax.max(aout); // usually enough headroom for change
            s.coin_nonce = coin_nonce;
            s.sk = sk;
            s
        })
}

pub fn complete_swap() -> impl Strategy<Value = CompleteSwapScenario> {
    (settled_swap(), settle(), any::<bool>(), any::<bool>()).prop_map(|(s, mut settle, wrong, over)| {
        settle.claimant_sk = claimant(s.sk, wrong);
        let amount_in = if over {
            s.amount_in_max_u64().saturating_add(1)
        } else {
            s.amount_in_max_u64() / 2
        };
        let mut c = CompleteSwapScenario::new();
        c.s = s;
        c.settle = settle;
        c.amount_in = amount_in;
        c
    })
}

pub fn refund_swap() -> impl Strategy<Value = RefundSwapScenario> {
    (settled_swap(), settle(), any::<bool>(), attested_number()).prop_map(
        |(s, mut settle, wrong, attested)| {
            settle.claimant_sk = claimant(s.sk, wrong);
            let mut r = RefundSwapScenario::new();
            r.s = s;
            r.settle = settle;
            r.attested = attested;
            r
        },
    )
}

// --- supply --------------------------------------------------------------------------------

pub fn start_supply() -> impl Strategy<Value = StartSupplyScenario> {
    (env(), evm_nonce(), live_key_version(), amount(), b32(), any::<bool>(), b32()).prop_flat_map(
        |(env, nonce, kv, amt, coin_nonce, exists, sk)| {
            coin_value(amt).prop_flat_map(move |cv| {
                let env = env.clone();
                coin_color().prop_map(move |cc| {
                    let mut s = StartSupplyScenario::new();
                    s.env = env.clone();
                    s.evm_nonce = nonce;
                    s.env.key_version = kv;
                    s.amount = amt;
                    s.coin_nonce = coin_nonce;
                    s.coin_value = cv;
                    s.coin_color = cc;
                    s.request_exists = exists;
                    s.sk = sk;
                    s
                })
            })
        },
    )
}

fn settled_supply() -> impl Strategy<Value = StartSupplyScenario> {
    (settle_env(), evm_nonce(), 1u8..=255, valid_amount(), b32(), b32()).prop_map(|(env, nonce, kv, amt, coin_nonce, sk)| {
        let mut s = StartSupplyScenario::new();
        s.env = env;
        s.evm_nonce = nonce;
        s.env.key_version = kv;
        s.amount = amt;
        s.coin_nonce = coin_nonce;
        s.sk = sk;
        s
    })
}

pub fn complete_supply() -> impl Strategy<Value = CompleteSupplyScenario> {
    (settled_supply(), settle(), any::<bool>()).prop_map(|(s, mut settle, wrong)| {
        settle.claimant_sk = claimant(s.sk, wrong);
        let mut c = CompleteSupplyScenario::new();
        c.shares = s.amount_u64();
        c.s = s;
        c.settle = settle;
        c
    })
}

pub fn refund_supply() -> impl Strategy<Value = RefundSupplyScenario> {
    (settled_supply(), settle(), any::<bool>(), attested_number()).prop_map(
        |(s, mut settle, wrong, attested)| {
            settle.claimant_sk = claimant(s.sk, wrong);
            let mut r = RefundSupplyScenario::new();
            r.s = s;
            r.settle = settle;
            r.attested = attested;
            r
        },
    )
}

// --- redeem --------------------------------------------------------------------------------

pub fn start_redeem() -> impl Strategy<Value = StartRedeemScenario> {
    (env(), evm_nonce(), live_key_version(), amount(), b32(), any::<bool>(), b32()).prop_flat_map(
        |(env, nonce, kv, shares, coin_nonce, exists, sk)| {
            coin_value(shares).prop_flat_map(move |cv| {
                let env = env.clone();
                coin_color().prop_map(move |cc| {
                    let mut s = StartRedeemScenario::new();
                    s.env = env.clone();
                    s.evm_nonce = nonce;
                    s.env.key_version = kv;
                    s.shares = shares;
                    s.coin_nonce = coin_nonce;
                    s.coin_value = cv;
                    s.coin_color = cc;
                    s.request_exists = exists;
                    s.sk = sk;
                    s
                })
            })
        },
    )
}

fn settled_redeem() -> impl Strategy<Value = StartRedeemScenario> {
    (settle_env(), evm_nonce(), 1u8..=255, valid_amount(), b32(), b32()).prop_map(|(env, nonce, kv, shares, coin_nonce, sk)| {
        let mut s = StartRedeemScenario::new();
        s.env = env;
        s.evm_nonce = nonce;
        s.env.key_version = kv;
        s.shares = shares;
        s.coin_nonce = coin_nonce;
        s.sk = sk;
        s
    })
}

pub fn complete_redeem() -> impl Strategy<Value = CompleteRedeemScenario> {
    (settled_redeem(), settle(), any::<bool>(), any::<u32>()).prop_map(|(s, mut settle, wrong, extra)| {
        settle.claimant_sk = claimant(s.sk, wrong);
        // Aave's exchange rate only grows: assets >= shares, plus a bit.
        let assets = s.shares_u64().saturating_add(u64::from(extra % 1000));
        let mut c = CompleteRedeemScenario::new();
        c.assets = assets;
        c.s = s;
        c.settle = settle;
        c
    })
}

pub fn refund_redeem() -> impl Strategy<Value = RefundRedeemScenario> {
    (settled_redeem(), settle(), any::<bool>(), attested_number()).prop_map(
        |(s, mut settle, wrong, attested)| {
            settle.claimant_sk = claimant(s.sk, wrong);
            let mut r = RefundRedeemScenario::new();
            r.s = s;
            r.settle = settle;
            r.attested = attested;
            r
        },
    )
}

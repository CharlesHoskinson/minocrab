//! erc20-vault: call-compatibility with the corpus artifacts per
//! notes/ledger-abi.org §6 — the benchmark target running on MinoCrab,
//! plus acceptance agreement on guard failures and tampering.
//!
//! Twenty-nine circuits since M44 (signet-midnight-examples `375071b`, the
//! flush pattern): for each, PI-equality on the reference model's preimage
//! against compactc's own artifact, the guard failures both artifacts must
//! reject, and the tamper sweep (every transcript and witness element
//! perturbed; zero acceptance disagreements). The per-circuit scenario
//! builders live in `tests/vault/model.rs`.

use midnight_transient_crypto::proofs::ProofPreimage;
use minocrab::Fr;
use minocrab_contracts::signet_v1::output_kind;
use minocrab_sim::v3::{assert_call_compatible, simulate};
use minocrab_zkir::v3::IrSource;

mod support;
mod vault;

use vault::artifact::Circuit;
use vault::model::*;
use vault::tamper;

/// Both artifacts must REJECT this preimage.
fn both_reject(circuit: Circuit, pi: &ProofPreimage, why: &str) {
    assert!(simulate(&circuit.ir(), pi).is_err(), "ours accepts: {why}");
    assert!(simulate(circuit.corpus(), pi).is_err(), "corpus accepts: {why}");
}

/// PI-equality on the reference preimage, dumped for the bench.
fn matches(circuit: Circuit, pi: &ProofPreimage) {
    support::dump_preimage(circuit.zkir_name(), pi);
    assert_call_compatible(&circuit.ir(), circuit.corpus(), pi);
}

/// [`matches`], and the model's op stream REPLAYED through Midnight's
/// reference VM against the scenario's pre-state: every `popeq` the model
/// claims is checked against a real state tree, so the pre-state the
/// differential pins is real rather than asserted.
fn check<S: Scenario>(circuit: Circuit, s: &S) {
    let pre = s.pre_state();
    let ops = s.ops();
    vault::exec::run(&pre, &s.self_addr(), &ops)
        .unwrap_or_else(|e| panic!("{}: the reference VM rejects the model's run: {e}", circuit.zkir_name()));
    matches(circuit, &s.preimage());
}

fn ours(circuit: Circuit) -> IrSource {
    circuit.ir()
}

fn sweep(circuit: Circuit, pi: &ProofPreimage) {
    tamper::assert_full_sweep(&ours(circuit), circuit.corpus(), pi);
}

// ==== initialise / setGasParams / addAllowedToken ===========================================

#[test]
fn initialise_matches_corpus() {
    check(Circuit::Initialise, &InitialiseScenario::new());
}

#[test]
fn initialise_rejects_guard_failures() {
    let mut s = InitialiseScenario::new();
    s.env.initialised = true;
    both_reject(Circuit::Initialise, &s.preimage(), "already initialised");

    let mut s = InitialiseScenario::new();
    s.key_version = 0;
    both_reject(Circuit::Initialise, &s.preimage(), "key version zero");

    let mut s = InitialiseScenario::new();
    s.sk[0] ^= 1;
    both_reject(Circuit::Initialise, &s.preimage(), "wrong secret");

    let mut s = InitialiseScenario::new();
    s.chain_id = 0;
    both_reject(Circuit::Initialise, &s.preimage(), "zero chain id");

    for i in 0..3 {
        let mut s = InitialiseScenario::new();
        match i {
            0 => s.swap_router = [0u8; 20],
            1 => s.stata_underlying = [0u8; 20],
            _ => s.stata_token = [0u8; 20],
        }
        both_reject(Circuit::Initialise, &s.preimage(), "zero address");
    }
}

#[test]
fn initialise_rejects_tampering() {
    sweep(Circuit::Initialise, &InitialiseScenario::new().preimage());
}

#[test]
fn set_gas_params_matches_corpus() {
    check(Circuit::SetGasParams, &SetGasParamsScenario::new());
}

#[test]
fn set_gas_params_rejects_guard_failures() {
    let mut s = SetGasParamsScenario::new();
    s.env.initialised = false;
    both_reject(Circuit::SetGasParams, &s.preimage(), "not initialised");

    let mut s = SetGasParamsScenario::new();
    s.sk[0] ^= 1;
    both_reject(Circuit::SetGasParams, &s.preimage(), "not the deployer");

    let mut s = SetGasParamsScenario::new();
    s.max_fee = 0;
    s.priority_fee = 0;
    both_reject(Circuit::SetGasParams, &s.preimage(), "zero max fee");

    let mut s = SetGasParamsScenario::new();
    s.priority_fee = s.max_fee + 1;
    both_reject(Circuit::SetGasParams, &s.preimage(), "priority fee above max fee");

    for i in 0..5 {
        let mut s = SetGasParamsScenario::new();
        s.limits[i] = 0;
        both_reject(Circuit::SetGasParams, &s.preimage(), "zero gas limit");
    }
}

#[test]
fn set_gas_params_rejects_tampering() {
    sweep(Circuit::SetGasParams, &SetGasParamsScenario::new().preimage());
}

#[test]
fn add_allowed_token_matches_corpus() {
    check(Circuit::AddAllowedToken, &AddAllowedTokenScenario::new());
}

#[test]
fn add_allowed_token_rejects_guard_failures() {
    let mut s = AddAllowedTokenScenario::new();
    s.sk[0] ^= 1;
    both_reject(Circuit::AddAllowedToken, &s.preimage(), "not the deployer");
    let mut s = AddAllowedTokenScenario::new();
    s.erc20 = [0u8; 20];
    both_reject(Circuit::AddAllowedToken, &s.preimage(), "zero address");
}

#[test]
fn add_allowed_token_rejects_tampering() {
    sweep(Circuit::AddAllowedToken, &AddAllowedTokenScenario::new().preimage());
}

// ==== the queue ==============================================================================

#[test]
fn flush_queue_matches_corpus() {
    check(Circuit::FlushQueue, &FlushScenario::new());
}

#[test]
fn flush_queue_empty_matches_corpus() {
    let mut s = FlushScenario::new();
    s.slots = vec![Slot::Empty; minocrab_contracts::erc20_vault::FLUSH_SLOTS];
    check(Circuit::FlushQueue, &s);
}

/// A sent request distinct from the canonical one: another index, another
/// nonce, so another flushed index and another request id.
fn distinct(mut s: Sent, salt: u64) -> Sent {
    s.in_index += salt;
    s.evm_nonce += salt;
    s
}

#[test]
fn flush_queue_every_action_matches_corpus() {
    // Five vault-signed requests take five consecutive nonces, a deposit
    // keeps the caller's, and three attestations fold their heights in
    // (one of them lower than the running globalLastSeen). The attestation
    // slots' requests are SENT ones at other nonces, so their flushed
    // indices do not collide with the request slots' (the reference VM
    // caught the collision when they were the same canonical requests).
    let mut s = FlushScenario::new();
    let mut low = Attestation::failed();
    low.block_height = 1;
    s.slots = vec![
        Slot::Request(Sent::withdraw()),
        Slot::Request(Sent::swap()),
        Slot::Attestation(distinct(Sent::supply(), 100), Attestation::executed_u256(40_000)),
        Slot::Request(Sent::supply()),
        Slot::Request(Sent::redeem()),
        Slot::Request(Sent::approve_router()),
        Slot::Request(Sent::deposit()),
        Slot::Attestation(distinct(Sent::withdraw(), 200), Attestation::executed_bool(true)),
        Slot::Attestation(distinct(Sent::redeem(), 300), low),
        Slot::Empty,
    ];
    check(Circuit::FlushQueue, &s);
}

#[test]
fn flush_queue_rejects_tampering() {
    sweep(Circuit::FlushQueue, &FlushScenario::new().preimage());
}

#[test]
fn queue_attestation0_matches_corpus() {
    let s = QueueAttestationScenario::of(Sent::withdraw(), Attestation::failed());
    check(Circuit::QueueAttestation0, &s);
    let s = QueueAttestationScenario::of(Sent::approve_router(), Attestation::unviable());
    check(Circuit::QueueAttestation0, &s);
    let replaced = Sent::withdraw();
    let s = QueueAttestationScenario::of(Sent::replace_nonce(&replaced), Attestation::executed_empty());
    check(Circuit::QueueAttestation0, &s);
}

#[test]
fn queue_attestation1_matches_corpus() {
    let s = QueueAttestationScenario::of(Sent::deposit(), Attestation::executed_bool(true));
    check(Circuit::QueueAttestation1, &s);
    let s = QueueAttestationScenario::of(Sent::withdraw(), Attestation::executed_bool(false));
    check(Circuit::QueueAttestation1, &s);
}

#[test]
fn queue_attestation32_matches_corpus() {
    let s = QueueAttestationScenario::of(Sent::swap(), Attestation::executed_u256(5_500));
    check(Circuit::QueueAttestation32, &s);
    let s = QueueAttestationScenario::of(Sent::supply(), Attestation::executed_u256(41_000));
    check(Circuit::QueueAttestation32, &s);
}

#[test]
fn queue_attestation_rejects_guard_failures() {
    let fresh = || QueueAttestationScenario::of(Sent::deposit(), Attestation::executed_bool(true));

    let mut s = fresh();
    s.sent_exists = false;
    both_reject(Circuit::QueueAttestation1, &s.preimage(), "request not sent");

    let mut s = fresh();
    s.open = false;
    both_reject(Circuit::QueueAttestation1, &s.preimage(), "request not open");

    let mut s = fresh();
    s.attestation.block_height = s.sent.last_seen;
    both_reject(Circuit::QueueAttestation1, &s.preimage(), "stale attestation");

    let mut s = fresh();
    s.already_queued = true;
    both_reject(Circuit::QueueAttestation1, &s.preimage(), "already queued");

    let mut s = fresh();
    s.already_flushed = true;
    both_reject(Circuit::QueueAttestation1, &s.preimage(), "already flushed");

    // A signature under another key.
    let mut s = fresh();
    s.sent.env.key_seed ^= 1;
    let mut pi = s.preimage();
    let good = fresh().preimage();
    pi.public_transcript_outputs = good.public_transcript_outputs.clone();
    pi.public_transcript_inputs = good.public_transcript_inputs.clone();
    both_reject(Circuit::QueueAttestation1, &pi, "wrong response key");
}

#[test]
fn queue_attestation_rejects_tampering() {
    sweep(Circuit::QueueAttestation0, &QueueAttestationScenario::of(Sent::withdraw(), Attestation::failed()).preimage());
    sweep(Circuit::QueueAttestation1, &QueueAttestationScenario::of(Sent::deposit(), Attestation::executed_bool(true)).preimage());
    sweep(Circuit::QueueAttestation32, &QueueAttestationScenario::of(Sent::swap(), Attestation::executed_u256(5_500)).preimage());
}

// ==== the starts ============================================================================

fn start_guard_failures(circuit: Circuit, fresh: fn() -> StartScenario) {
    let mut s = fresh();
    s.sent.env.initialised = false;
    both_reject(circuit, &s.preimage(), "not initialised");

    let mut s = fresh();
    s.queued = true;
    both_reject(circuit, &s.preimage(), "index queued");

    let mut s = fresh();
    s.in_args = true;
    both_reject(circuit, &s.preimage(), "index in the args map");
}

#[test]
fn start_deposit_matches_corpus() {
    check(Circuit::StartDeposit, &StartScenario::deposit());
}

#[test]
fn start_deposit_rejects_guard_failures() {
    start_guard_failures(Circuit::StartDeposit, StartScenario::deposit);
    let mut s = StartScenario::deposit();
    s.allowed = false;
    both_reject(Circuit::StartDeposit, &s.preimage(), "ERC20 not allowed");
    for amount in [0u128, u128::from(u64::MAX) + 1] {
        let mut s = StartScenario::deposit();
        if let Args::Deposit { amount: a, .. } = &mut s.sent.args {
            *a = amount;
        }
        both_reject(Circuit::StartDeposit, &s.preimage(), "amount out of range");
    }
    let mut s = StartScenario::deposit();
    if let Args::Deposit { gas, .. } = &mut s.sent.args {
        gas.limit = 0;
    }
    both_reject(Circuit::StartDeposit, &s.preimage(), "zero gas limit");
}

#[test]
fn start_deposit_rejects_tampering() {
    sweep(Circuit::StartDeposit, &StartScenario::deposit().preimage());
}

#[test]
fn start_withdraw_matches_corpus() {
    check(Circuit::StartWithdraw, &StartScenario::withdraw());
}

#[test]
fn start_withdraw_rejects_guard_failures() {
    start_guard_failures(Circuit::StartWithdraw, StartScenario::withdraw);
    let mut s = StartScenario::withdraw();
    if let Args::Withdraw { dest, .. } = &mut s.sent.args {
        *dest = [0u8; 20];
    }
    both_reject(Circuit::StartWithdraw, &s.preimage(), "zero destination");
    // The coin's value must equal the amount.
    let mut s = StartScenario::withdraw();
    s.coin.as_mut().unwrap().value += 1;
    both_reject(Circuit::StartWithdraw, &s.preimage(), "coin value mismatch");
    // The coin must be THIS ERC20's vault token.
    let mut s = StartScenario::withdraw();
    s.coin.as_mut().unwrap().color[0] ^= 1;
    both_reject(Circuit::StartWithdraw, &s.preimage(), "wrong colour");
}

#[test]
fn start_withdraw_rejects_tampering() {
    sweep(Circuit::StartWithdraw, &StartScenario::withdraw().preimage());
}

#[test]
fn start_swap_matches_corpus() {
    check(Circuit::StartSwap, &StartScenario::swap());
}

#[test]
fn start_swap_rejects_guard_failures() {
    start_guard_failures(Circuit::StartSwap, StartScenario::swap);
    let mut s = StartScenario::swap();
    s.allowed = false;
    both_reject(Circuit::StartSwap, &s.preimage(), "erc20AddressOut not allowed");
    let mut s = StartScenario::swap();
    if let Args::Swap { amount_out, .. } = &mut s.sent.args {
        *amount_out = 0;
    }
    both_reject(Circuit::StartSwap, &s.preimage(), "zero amountOut");
}

#[test]
fn start_swap_rejects_tampering() {
    sweep(Circuit::StartSwap, &StartScenario::swap().preimage());
}

#[test]
fn start_supply_matches_corpus() {
    check(Circuit::StartSupply, &StartScenario::supply());
}

#[test]
fn start_supply_rejects_guard_failures() {
    start_guard_failures(Circuit::StartSupply, StartScenario::supply);
    let mut s = StartScenario::supply();
    s.coin.as_mut().unwrap().value += 1;
    both_reject(Circuit::StartSupply, &s.preimage(), "coin value mismatch");
}

#[test]
fn start_supply_rejects_tampering() {
    sweep(Circuit::StartSupply, &StartScenario::supply().preimage());
}

#[test]
fn start_redeem_matches_corpus() {
    check(Circuit::StartRedeem, &StartScenario::redeem());
}

#[test]
fn start_redeem_rejects_guard_failures() {
    start_guard_failures(Circuit::StartRedeem, StartScenario::redeem);
    let mut s = StartScenario::redeem();
    s.coin.as_mut().unwrap().color[0] ^= 1;
    both_reject(Circuit::StartRedeem, &s.preimage(), "wrong colour");
}

#[test]
fn start_redeem_rejects_tampering() {
    sweep(Circuit::StartRedeem, &StartScenario::redeem().preimage());
}

#[test]
fn start_approve_router_matches_corpus() {
    check(Circuit::StartApproveRouter, &StartScenario::approve_router());
}

#[test]
fn start_approve_stata_matches_corpus() {
    check(Circuit::StartApproveStata, &StartScenario::approve_stata());
}

#[test]
fn start_approve_rejects_guard_failures() {
    start_guard_failures(Circuit::StartApproveRouter, StartScenario::approve_router);
    start_guard_failures(Circuit::StartApproveStata, StartScenario::approve_stata);
    let mut s = StartScenario::approve_router();
    s.sent.sk[0] ^= 1;
    both_reject(Circuit::StartApproveRouter, &s.preimage(), "not the deployer");
    let mut s = StartScenario::approve_stata();
    s.sent.sk[0] ^= 1;
    both_reject(Circuit::StartApproveStata, &s.preimage(), "not the deployer");
}

#[test]
fn start_approve_rejects_tampering() {
    sweep(Circuit::StartApproveRouter, &StartScenario::approve_router().preimage());
    sweep(Circuit::StartApproveStata, &StartScenario::approve_stata().preimage());
}

#[test]
fn start_replace_nonce_matches_corpus() {
    check(Circuit::StartReplaceNonce, &StartScenario::replace_nonce());
    // Every vault-signed action's map is one arm of sentVaultNonce.
    for replaced in [Sent::approve_router(), Sent::swap(), Sent::supply(), Sent::redeem()] {
        let mut s = StartScenario::of(Sent::replace_nonce(&replaced));
        s.replaced = Some(Box::new(replaced));
        check(Circuit::StartReplaceNonce, &s);
    }
    // A replacement of a replacement.
    let first = Sent::replace_nonce(&Sent::withdraw());
    let mut s = StartScenario::of(Sent::replace_nonce(&first));
    s.sent.in_index = 0xee;
    s.replaced = Some(Box::new(first));
    check(Circuit::StartReplaceNonce, &s);
}

#[test]
fn start_replace_nonce_rejects_guard_failures() {
    start_guard_failures(Circuit::StartReplaceNonce, StartScenario::replace_nonce);
    let mut s = StartScenario::replace_nonce();
    s.sent.sk[0] ^= 1;
    both_reject(Circuit::StartReplaceNonce, &s.preimage(), "not the deployer");
    // A deposit has no vault nonce.
    let deposit = Sent::deposit();
    let mut s = StartScenario::of(Sent::replace_nonce(&deposit));
    s.replaced = Some(Box::new(deposit));
    both_reject(Circuit::StartReplaceNonce, &s.preimage(), "deposit has no vault nonce");
}

#[test]
fn start_replace_nonce_rejects_tampering() {
    sweep(Circuit::StartReplaceNonce, &StartScenario::replace_nonce().preimage());
}

// ==== the sends =============================================================================

fn send_guard_failures(circuit: Circuit, sent: fn() -> Sent) {
    let mut s = SendScenario::of(sent());
    s.flushed = false;
    both_reject(circuit, &s.preimage(), "request not flushed");
    let mut s = SendScenario::of(sent());
    s.already_sent = true;
    both_reject(circuit, &s.preimage(), "request already sent");
    let mut s = SendScenario::of(sent());
    s.sent.env.key_version = 0;
    both_reject(circuit, &s.preimage(), "key version zero");
}

#[test]
fn send_deposit_matches_corpus() {
    check(Circuit::SendDeposit, &SendScenario::of(Sent::deposit()));
}

#[test]
fn send_deposit_rejects_guard_failures() {
    send_guard_failures(Circuit::SendDeposit, Sent::deposit);
    // The depositor's path may not be the reserved response-key path.
    let mut s = SendScenario::of(Sent::deposit());
    if let Args::Deposit { path, .. } = &mut s.sent.args {
        *path = vault::prims::pad32(minocrab_contracts::signet_v1::RESPONSE_KEY_PATH);
    }
    both_reject(Circuit::SendDeposit, &s.preimage(), "reserved path");
}

#[test]
fn send_deposit_rejects_tampering() {
    sweep(Circuit::SendDeposit, &SendScenario::of(Sent::deposit()).preimage());
}

#[test]
fn send_withdraw_matches_corpus() {
    check(Circuit::SendWithdraw, &SendScenario::of(Sent::withdraw()));
}

#[test]
fn send_withdraw_rejects_guard_failures() {
    send_guard_failures(Circuit::SendWithdraw, Sent::withdraw);
}

#[test]
fn send_withdraw_rejects_tampering() {
    sweep(Circuit::SendWithdraw, &SendScenario::of(Sent::withdraw()).preimage());
}

#[test]
fn send_swap_matches_corpus() {
    check(Circuit::SendSwap, &SendScenario::of(Sent::swap()));
}

#[test]
fn send_swap_rejects_guard_failures() {
    send_guard_failures(Circuit::SendSwap, Sent::swap);
}

#[test]
fn send_swap_rejects_tampering() {
    sweep(Circuit::SendSwap, &SendScenario::of(Sent::swap()).preimage());
}

#[test]
fn send_supply_matches_corpus() {
    check(Circuit::SendSupply, &SendScenario::of(Sent::supply()));
}

#[test]
fn send_supply_rejects_guard_failures() {
    send_guard_failures(Circuit::SendSupply, Sent::supply);
}

#[test]
fn send_supply_rejects_tampering() {
    sweep(Circuit::SendSupply, &SendScenario::of(Sent::supply()).preimage());
}

#[test]
fn send_redeem_matches_corpus() {
    check(Circuit::SendRedeem, &SendScenario::of(Sent::redeem()));
}

#[test]
fn send_redeem_rejects_guard_failures() {
    send_guard_failures(Circuit::SendRedeem, Sent::redeem);
}

#[test]
fn send_redeem_rejects_tampering() {
    sweep(Circuit::SendRedeem, &SendScenario::of(Sent::redeem()).preimage());
}

#[test]
fn send_approve_matches_corpus() {
    check(Circuit::SendApprove, &SendScenario::of(Sent::approve_router()));
    check(Circuit::SendApprove, &SendScenario::of(Sent::approve_stata()));
}

#[test]
fn send_approve_rejects_guard_failures() {
    send_guard_failures(Circuit::SendApprove, Sent::approve_router);
}

#[test]
fn send_approve_rejects_tampering() {
    sweep(Circuit::SendApprove, &SendScenario::of(Sent::approve_stata()).preimage());
}

#[test]
fn send_replace_nonce_matches_corpus() {
    check(Circuit::SendReplaceNonce, &SendScenario::of(Sent::replace_nonce(&Sent::withdraw())));
}

#[test]
fn send_replace_nonce_rejects_guard_failures() {
    send_guard_failures(Circuit::SendReplaceNonce, || Sent::replace_nonce(&Sent::withdraw()));
    // A send of the wrong action's entry.
    let mut s = SendScenario::of(Sent::replace_nonce(&Sent::withdraw()));
    s.sent.args = Sent::withdraw().args;
    both_reject(Circuit::SendReplaceNonce, &s.preimage(), "wrong action");
}

#[test]
fn send_replace_nonce_rejects_tampering() {
    sweep(Circuit::SendReplaceNonce, &SendScenario::of(Sent::replace_nonce(&Sent::withdraw())).preimage());
}

// ==== the completions =======================================================================

fn complete_guard_failures(circuit: Circuit, fresh: fn() -> CompleteScenario) {
    let mut s = fresh();
    s.sent_exists = false;
    both_reject(circuit, &s.preimage(), "request not sent");

    let mut s = fresh();
    s.open = false;
    both_reject(circuit, &s.preimage(), "request not open");

    let mut s = fresh();
    s.flushed = false;
    both_reject(circuit, &s.preimage(), "attestation not flushed");

    let mut s = fresh();
    s.attestation.block_height = s.sent.last_seen;
    both_reject(circuit, &s.preimage(), "stale attestation");

    let mut s = fresh();
    s.sk[0] ^= 1;
    both_reject(circuit, &s.preimage(), "not the requester");

    let mut s = fresh();
    s.event_present = false;
    both_reject(circuit, &s.preimage(), "event missing");

    // An executed verdict's output must match the attested digest.
    let mut s = fresh();
    if s.executed() && !s.output.is_empty() {
        s.output[0] = s.output[0] + Fr::from(1u64);
        both_reject(circuit, &s.preimage(), "output does not match the attestation");
    }
}

#[test]
fn complete_deposit_matches_corpus() {
    check(Circuit::CompleteDeposit, &CompleteScenario::of(Sent::deposit(), Attestation::executed_bool(true)));
    // A transfer that returned false mints nothing.
    check(Circuit::CompleteDeposit, &CompleteScenario::of(Sent::deposit(), Attestation::executed_bool(false)));
    // Failed and unviable close the request.
    check(Circuit::CompleteDeposit, &CompleteScenario::of(Sent::deposit(), Attestation::failed()));
    check(Circuit::CompleteDeposit, &CompleteScenario::of(Sent::deposit(), Attestation::unviable()));
    // The three recipient shapes.
    let mut s = CompleteScenario::of(Sent::deposit(), Attestation::executed_bool(true));
    s.recipient = ClaimRecipient::None(s.own_pk);
    check(Circuit::CompleteDeposit, &s);
    let mut s = CompleteScenario::of(Sent::deposit(), Attestation::executed_bool(true));
    s.recipient = ClaimRecipient::Contract(tagged32(b"other-contract", 0x77));
    check(Circuit::CompleteDeposit, &s);
    let mut s = CompleteScenario::of(Sent::deposit(), Attestation::executed_bool(true));
    s.recipient = ClaimRecipient::Contract(SELF_ADDR);
    check(Circuit::CompleteDeposit, &s);
}

#[test]
fn complete_deposit_rejects_guard_failures() {
    complete_guard_failures(Circuit::CompleteDeposit, || CompleteScenario::of(Sent::deposit(), Attestation::executed_bool(true)));
}

#[test]
fn complete_deposit_rejects_tampering() {
    sweep(Circuit::CompleteDeposit, &CompleteScenario::of(Sent::deposit(), Attestation::executed_bool(true)).preimage());
    sweep(Circuit::CompleteDeposit, &CompleteScenario::of(Sent::deposit(), Attestation::failed()).preimage());
}

#[test]
fn complete_withdraw_matches_corpus() {
    check(Circuit::CompleteWithdraw, &CompleteScenario::of(Sent::withdraw(), Attestation::executed_bool(true)));
    check(Circuit::CompleteWithdraw, &CompleteScenario::of(Sent::withdraw(), Attestation::executed_bool(false)));
    check(Circuit::CompleteWithdraw, &CompleteScenario::of(Sent::withdraw(), Attestation::failed()));
    check(Circuit::CompleteWithdraw, &CompleteScenario::of(Sent::withdraw(), Attestation::unviable()));
}

#[test]
fn complete_withdraw_rejects_guard_failures() {
    complete_guard_failures(Circuit::CompleteWithdraw, || CompleteScenario::of(Sent::withdraw(), Attestation::executed_bool(true)));
}

#[test]
fn complete_withdraw_rejects_tampering() {
    sweep(Circuit::CompleteWithdraw, &CompleteScenario::of(Sent::withdraw(), Attestation::executed_bool(true)).preimage());
    sweep(Circuit::CompleteWithdraw, &CompleteScenario::of(Sent::withdraw(), Attestation::executed_bool(false)).preimage());
}

#[test]
fn complete_swap_matches_corpus() {
    check(Circuit::CompleteSwap, &CompleteScenario::of(Sent::swap(), Attestation::executed_u256(5_500)));
    // An exact spend mints a zero-value change coin.
    check(Circuit::CompleteSwap, &CompleteScenario::of(Sent::swap(), Attestation::executed_u256(6_000)));
    check(Circuit::CompleteSwap, &CompleteScenario::of(Sent::swap(), Attestation::failed()));
    check(Circuit::CompleteSwap, &CompleteScenario::of(Sent::swap(), Attestation::unviable()));
}

#[test]
fn complete_swap_rejects_guard_failures() {
    complete_guard_failures(Circuit::CompleteSwap, || CompleteScenario::of(Sent::swap(), Attestation::executed_u256(5_500)));
    // The nonces must differ.
    let mut s = CompleteScenario::of(Sent::swap(), Attestation::executed_u256(5_500));
    s.change_nonce = s.mint_nonce;
    both_reject(Circuit::CompleteSwap, &s.preimage(), "equal nonces");
    // amountIn above amountInMaximum underflows the change.
    let s = CompleteScenario::of(Sent::swap(), Attestation::executed_u256(6_001));
    both_reject(Circuit::CompleteSwap, &s.preimage(), "amountIn above the maximum");
    // An attested value at or above 2^128 fails checkedTruncationU128.
    let mut s = CompleteScenario::of(Sent::swap(), Attestation::executed_u256(5_500));
    s.attestation.output[0] = Fr::from(1u64);
    s.output = s.attestation.output.clone();
    both_reject(Circuit::CompleteSwap, &s.preimage(), "value exceeds Uint<128>");
}

#[test]
fn complete_swap_rejects_tampering() {
    sweep(Circuit::CompleteSwap, &CompleteScenario::of(Sent::swap(), Attestation::executed_u256(5_500)).preimage());
    sweep(Circuit::CompleteSwap, &CompleteScenario::of(Sent::swap(), Attestation::failed()).preimage());
}

#[test]
fn complete_supply_matches_corpus() {
    check(Circuit::CompleteSupply, &CompleteScenario::of(Sent::supply(), Attestation::executed_u256(41_500)));
    check(Circuit::CompleteSupply, &CompleteScenario::of(Sent::supply(), Attestation::failed()));
}

#[test]
fn complete_supply_rejects_guard_failures() {
    complete_guard_failures(Circuit::CompleteSupply, || CompleteScenario::of(Sent::supply(), Attestation::executed_u256(41_500)));
    // Shares at or above 2^64 cannot be minted.
    let s = CompleteScenario::of(Sent::supply(), Attestation::executed_u256(u128::from(u64::MAX) + 1));
    both_reject(Circuit::CompleteSupply, &s.preimage(), "shares exceed Uint<64>");
}

#[test]
fn complete_supply_rejects_tampering() {
    sweep(Circuit::CompleteSupply, &CompleteScenario::of(Sent::supply(), Attestation::executed_u256(41_500)).preimage());
}

#[test]
fn complete_redeem_matches_corpus() {
    check(Circuit::CompleteRedeem, &CompleteScenario::of(Sent::redeem(), Attestation::executed_u256(42_500)));
    check(Circuit::CompleteRedeem, &CompleteScenario::of(Sent::redeem(), Attestation::unviable()));
}

#[test]
fn complete_redeem_rejects_guard_failures() {
    complete_guard_failures(Circuit::CompleteRedeem, || CompleteScenario::of(Sent::redeem(), Attestation::executed_u256(42_500)));
}

#[test]
fn complete_redeem_rejects_tampering() {
    sweep(Circuit::CompleteRedeem, &CompleteScenario::of(Sent::redeem(), Attestation::executed_u256(42_500)).preimage());
}

#[test]
fn complete_approve_matches_corpus() {
    check(Circuit::CompleteApprove, &CompleteScenario::of(Sent::approve_router(), Attestation::executed_bool(true)));
    check(Circuit::CompleteApprove, &CompleteScenario::of(Sent::approve_stata(), Attestation::failed()));
}

#[test]
fn complete_approve_rejects_guard_failures() {
    complete_guard_failures(Circuit::CompleteApprove, || CompleteScenario::of(Sent::approve_router(), Attestation::executed_bool(true)));
}

#[test]
fn complete_approve_rejects_tampering() {
    sweep(Circuit::CompleteApprove, &CompleteScenario::of(Sent::approve_router(), Attestation::executed_bool(true)).preimage());
}

#[test]
fn complete_replace_nonce_matches_corpus() {
    let replaced = Sent::withdraw();
    check(Circuit::CompleteReplaceNonce, &CompleteScenario::of(Sent::replace_nonce(&replaced), Attestation::executed_empty()));
    check(Circuit::CompleteReplaceNonce, &CompleteScenario::of(Sent::replace_nonce(&replaced), Attestation::unviable()));
}

#[test]
fn complete_replace_nonce_rejects_guard_failures() {
    complete_guard_failures(Circuit::CompleteReplaceNonce, || {
        CompleteScenario::of(Sent::replace_nonce(&Sent::withdraw()), Attestation::executed_empty())
    });
    // The record's digest must be over the EMPTY output on every verdict.
    let mut s = CompleteScenario::of(Sent::replace_nonce(&Sent::withdraw()), Attestation::executed_empty());
    s.attestation.width = 1;
    s.attestation.output = vec![Fr::from(1u64)];
    both_reject(Circuit::CompleteReplaceNonce, &s.preimage(), "a non-empty attested output");
}

#[test]
fn complete_replace_nonce_rejects_tampering() {
    sweep(Circuit::CompleteReplaceNonce, &CompleteScenario::of(Sent::replace_nonce(&Sent::withdraw()), Attestation::executed_empty()).preimage());
}

/// The verdicts a completion takes are exactly the three the protocol names.
#[test]
fn output_kinds_are_three() {
    assert_eq!(output_kind::COUNT, 3);
}

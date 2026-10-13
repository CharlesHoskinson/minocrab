//! The `erc20_vault_pending` PROPERTY HARNESS (M35 rung C's spec-harness
//! extension) — spec ≡ circuit ≡ ledger, at scale, for all seventeen
//! circuits on the `Pending` lineage.
//!
//! Four links per generated case, mirroring `erc20_vault_spec.rs`'s
//! `check_case` WITHOUT the compactc comparator (this lineage has no
//! compactc twin — notes/signet-async.org "Rung C as built"):
//!
//! 1. **Acceptance agreement.** The spec is a total function; `simulate`
//!    either accepts the witness or does not. They must agree.
//! 2. **Reference VM.** Every accepted run is re-validated by
//!    `IrSource::check`.
//! 3. **PI-equality, re-anchored.** The preimage's transcript IS the
//!    reference op stream's `field_repr`, and the PI vector is exactly
//!    that transcript plus the skipped Impacts' zeros.
//! 4. **Ledger execution.** The op stream runs through the real Impact VM
//!    against a real pre-state, and the declared `Effect`s must be
//!    exactly what it produced.
//!
//! Case count: `PROPTEST_CASES=500 cargo test --release` for the elevated
//! run this milestone calls for.

use midnight_transient_crypto::proofs::{ProofPreimage, Zkir};
use midnight_transient_crypto::repr::FieldRepr;
use minocrab_contracts::erc20_vault_pending as pending;
use minocrab_sim::v3::simulate;
use minocrab_zkir::v3::IrSource;
use proptest::prelude::*;

mod vault_pending;

use vault_pending::exec::{self, PreState};
use vault_pending::gen;
use vault_pending::model::*;
use vault_pending::prims::VmOp;
use vault_pending::spec::{self, Effect, Outcome};

fn counter_would_overflow(effects: &[Effect], pre: &PreState) -> bool {
    effects.iter().any(|e| match e {
        Effect::CounterInc { field, by } => {
            // `initialized` is the only counter left: the Signet request
            // nonce went with the V1 vocabulary at M44 rung D.
            let cur = match *field {
                INITIALIZED => pre.initialized,
                _ => 0,
            };
            cur.checked_add(*by).is_none()
        }
        _ => false,
    })
}

fn check_case(
    ir: &IrSource,
    outcome: &Outcome,
    pre: &PreState,
    self_addr: &[u8; 32],
    ops: &[VmOp],
    pi: &ProofPreimage,
) -> Result<(), String> {
    // --- 1. acceptance agreement ----------------------------------------
    let run = simulate(ir, pi);
    let circuit_accepts = run.is_ok();
    if circuit_accepts != outcome.accepts() {
        return Err(format!(
            "acceptance disagreement: spec {:?}, circuit accepts = {circuit_accepts}{}",
            outcome.guard(),
            match &run {
                Err(e) => format!(" ({e})"),
                Ok(_) => String::new(),
            }
        ));
    }
    let Ok(run) = run else {
        return Ok(());
    };

    // --- 2. reference VM on every accepted run --------------------------
    let skips = ir
        .check(pi)
        .map_err(|e| format!("simulator accepted but the reference VM rejected: {e}"))?;
    if skips != run.pi_skips {
        return Err("reference VM and simulator disagree on pi_skips".into());
    }

    // --- 3. PI-equality, re-anchored to OUR op stream -------------------
    let mut expected = Vec::new();
    for op in ops {
        op.field_repr(&mut expected);
    }
    if expected != pi.public_transcript_inputs {
        return Err("the preimage's transcript is not field_repr of the reference ops".into());
    }
    let skipped: usize = run.pi_skips.iter().flatten().sum();
    let prefix = 1 + usize::from(run.comm_comm.is_some());
    if run.pis.len() != prefix + expected.len() + skipped {
        return Err(format!(
            "PI vector length {} != {prefix} + transcript {} + skipped zeros {skipped}",
            run.pis.len(),
            expected.len()
        ));
    }

    // --- 4. ledger execution: declared effects == computed effects ------
    match exec::run(pre, self_addr, ops) {
        Ok(ex) => spec::check_effects(outcome.effects(), pre, &ex),
        Err(e) => {
            if counter_would_overflow(outcome.effects(), pre) {
                Ok(())
            } else {
                Err(format!("the Impact VM rejected the reference op stream: {e}"))
            }
        }
    }
}

macro_rules! property {
    ($name:ident, $ir:expr, $gen:expr, $spec:expr, |$s:ident| $env:expr) => {
        proptest! {
            #![proptest_config(gen::config())]
            #[test]
            fn $name($s in $gen) {
                let outcome = $spec(&$s);
                let env: &Env = $env;
                let ir = $ir;
                let r = check_case(&ir, &outcome, &$s.pre_state(), &env.self_addr, &$s.ops(), &$s.preimage());
                prop_assert!(r.is_ok(), "{r:?}");
            }
        }
    };
}

property!(initialize_matches_spec, pending::Vault::initialize().ir, gen::initialize(), spec::spec_initialize, |s| &s.env);
property!(approve_router_matches_spec, pending::Vault::approve_router().ir, gen::approve_router(), spec::spec_approve_router, |s| &s.env);
property!(approve_stata_matches_spec, pending::Vault::approve_stata().ir, gen::approve_stata(), spec::spec_approve_stata, |s| &s.env);
property!(deposit_matches_spec, pending::Vault::deposit().ir, gen::start_deposit(), spec::spec_start_deposit, |s| &s.env);
property!(claim_matches_spec, pending::Vault::claim().ir, gen::claim(), spec::spec_claim, |s| &s.d.env);
property!(claim_auto_receive_matches_spec, pending::Vault::claim().ir, gen::claim_auto_receive(), spec::spec_claim, |s| &s.d.env);
property!(withdraw_matches_spec, pending::Vault::withdraw().ir, gen::start_withdraw(), spec::spec_start_withdraw, |s| &s.env);
property!(complete_withdraw_matches_spec, pending::Vault::complete_withdraw().ir, gen::complete_withdraw(), spec::spec_complete_withdraw, |s| &s.w.env);
property!(refund_withdrawal_matches_spec, pending::Vault::refund_withdrawal().ir, gen::refund_withdrawal(), spec::spec_refund_withdrawal, |s| &s.w.env);
property!(swap_matches_spec, pending::Vault::swap().ir, gen::start_swap(), spec::spec_start_swap, |s| &s.env);
property!(complete_swap_matches_spec, pending::Vault::complete_swap().ir, gen::complete_swap(), spec::spec_complete_swap, |s| &s.s.env);
property!(refund_swap_matches_spec, pending::Vault::refund_swap().ir, gen::refund_swap(), spec::spec_refund_swap, |s| &s.s.env);
property!(supply_matches_spec, pending::Vault::supply().ir, gen::start_supply(), spec::spec_start_supply, |s| &s.env);
property!(complete_supply_matches_spec, pending::Vault::complete_supply().ir, gen::complete_supply(), spec::spec_complete_supply, |s| &s.s.env);
property!(refund_supply_matches_spec, pending::Vault::refund_supply().ir, gen::refund_supply(), spec::spec_refund_supply, |s| &s.s.env);
property!(redeem_matches_spec, pending::Vault::redeem().ir, gen::start_redeem(), spec::spec_start_redeem, |s| &s.env);
property!(complete_redeem_matches_spec, pending::Vault::complete_redeem().ir, gen::complete_redeem(), spec::spec_complete_redeem, |s| &s.s.env);
property!(refund_redeem_matches_spec, pending::Vault::refund_redeem().ir, gen::refund_redeem(), spec::spec_refund_redeem, |s| &s.s.env);

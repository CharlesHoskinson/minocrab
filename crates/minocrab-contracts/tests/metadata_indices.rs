//! The metadata beside every workspace circuit's ZKIR names instructions of
//! the stream that SHIPS.
//!
//! `Compiled3::assert_messages` and `Compiled3::regions` are taken while the
//! circuit is built, and `Builder3::finish` deletes instructions after that
//! (the copy fold on every circuit, the true-assert rule, the opt profile's
//! dedup). `Circuit3::finish` moves both onto the finished stream through
//! `Builder3::finish_kept` (notes/ir-passes.org §13). Before that move, 169
//! of the 260 messages named an instruction that was not an `assert`, 12
//! named a DIFFERENT assert, and 73 of the 348 regions ran past the end of
//! the stream, across 56 of the 214 circuits.
//!
//! THE EXACT CHECK runs inside the build. Under `debug_assertions`,
//! `Builder3::finish_kept` checks every kept instruction against the one it
//! became, operands included (`passes::check_kept`), and `Circuit3::finish`
//! checks that each message sits on its own assert's finished position and
//! each region is exactly the run its surviving instructions landed on. So
//! building all of `support::circuits()` here re-proves both on every real
//! circuit; what this file adds is the shape every finished circuit must
//! have, the counts (so the metadata cannot silently vanish), and one real
//! contract's error text.

mod support;
mod vault;

use minocrab_sim::v3::{simulate_compiled, Sim3Error};
use minocrab_zkir::v3::Instruction;
use vault::artifact::Circuit;
use vault::model::InitialiseScenario;

#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "the exact check is the debug-build one in Circuit3::finish; run without --release"
)]
fn every_circuit_s_messages_and_regions_name_its_finished_stream() {
    let mut wrong = Vec::new();
    let mut dropped = Vec::new();
    let (mut circuits, mut messages, mut regions) = (0, 0, 0);
    for (name, build) in support::circuits() {
        let compiled = build();
        let stream = compiled.ir.instructions.as_slice();
        circuits += 1;
        messages += compiled.assert_messages.len();
        regions += compiled.regions.len();

        // Each message names an assert, and no two share one: the passes
        // keep order, so positions rise strictly in recording order.
        for m in &compiled.assert_messages {
            if !matches!(stream.get(m.instruction), Some(Instruction::Assert { .. })) {
                wrong.push(format!("{name}: message {:?} at {}", m.message, m.instruction));
            }
        }
        for pair in compiled.assert_messages.windows(2) {
            if pair[0].instruction >= pair[1].instruction {
                wrong.push(format!("{name}: messages out of order {pair:?}"));
            }
        }

        // Each region is in range, and any two are nested or disjoint, as
        // they were when built (`Circuit3::region` is a scope).
        for r in &compiled.regions {
            if !(r.start <= r.end && r.end <= stream.len()) {
                wrong.push(format!("{name}: region {:?} [{}, {}) of {}", r.label, r.start, r.end, stream.len()));
            }
        }
        for (i, a) in compiled.regions.iter().enumerate() {
            for b in &compiled.regions[i + 1..] {
                let disjoint = a.end <= b.start || b.end <= a.start;
                let nested = (a.start <= b.start && b.end <= a.end) || (b.start <= a.start && a.end <= b.end);
                if !(disjoint || nested) {
                    wrong.push(format!("{name}: regions cross {a:?} {b:?}"));
                }
            }
        }

        let attested = "The attested call did not succeed";
        if name.starts_with("erc20_vault_pending::complete_")
            && !compiled.assert_messages.iter().any(|m| m.message == attested)
        {
            dropped.push(name.to_string());
        }
    }
    assert!(wrong.is_empty(), "{} stale indices:\n{}", wrong.len(), wrong.join("\n"));

    // The counts, pinned: a finish that lost every message or region would
    // pass every check above. Move them with the circuits.
    assert_eq!((circuits, messages, regions), (226, 453, 406));
    // The three messages that go: the `Always` outcome rule's `assert(imm 1)`,
    // deleted by the true-assert rule, takes its message with it.
    dropped.sort();
    assert_eq!(
        dropped,
        [
            "erc20_vault_pending::complete_redeem",
            "erc20_vault_pending::complete_supply",
            "erc20_vault_pending::complete_swap",
        ]
    );
}

/// The user-visible symptom, on the real circuit: before the fix, each of
/// `initialise`'s four argument checks failed with the message of the check
/// in front of it (a zero router reported "Chain ID must be positive"),
/// because the fold removed copies ahead of them.
#[test]
fn initialise_names_the_argument_check_that_failed() {
    let compiled = Circuit::Initialise.build();
    let ok = InitialiseScenario::new();
    simulate_compiled(&compiled, &ok.preimage()).expect("the honest initialise is accepted");

    let cases: [(&str, fn(&mut InitialiseScenario)); 4] = [
        ("Chain ID must be positive", |s| s.chain_id = 0),
        ("Router cannot be zero", |s| s.swap_router = [0; 20]),
        ("stataUnderlying cannot be zero", |s| s.stata_underlying = [0; 20]),
        ("stataToken cannot be zero", |s| s.stata_token = [0; 20]),
    ];
    for (want, zero) in cases {
        let mut s = InitialiseScenario::new();
        zero(&mut s);
        match simulate_compiled(&compiled, &s.preimage()) {
            Err(Sim3Error::Failed { op: "assert", message, .. }) => {
                assert_eq!(message, format!("failed assertion: {want}"))
            }
            other => panic!("expected {want:?}, got {other:?}"),
        }
    }
}

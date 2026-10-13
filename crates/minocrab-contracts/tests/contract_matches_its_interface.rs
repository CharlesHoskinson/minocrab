//! THE OTHER DIRECTION: a contract we BUILD, against the interface crate
//! it exports.
//!
//! `signet-signer-interface`'s own suite checks the crate against the
//! DEPLOYED artifact — a claim about somebody else's contract. This checks
//! it against `signet_contract`, the MinoCrab port of that same contract,
//! which is a promise: anyone who imports the crate and calls our
//! `signBidirectional` gets the layout the crate advertises.
//!
//! What is compared is the built `IrSource` — the very bytes that become
//! the deployed `.zkir` — against the trait's declared argument types, per
//! circuit: the declared input count, the opening constraint prefix slot
//! for slot (each constraint on the input of ITS slot), the communications
//! commitment, and the returned slot count. It is the same comparison
//! `minocrab-abi` runs against a corpus artifact, pointed at ourselves.
//!
//! Since PR #127 (M43) all three circuits take the interface crate's own
//! structs, so the type level already says most of this; what the test
//! still adds is the constraint prefix slot for slot — that the enum
//! argument is constrained below 3 and the two `Uint<64>`s to 64 bits, as
//! the deployed artifact constrains them.

use minocrab::Public;
use minocrab_abi::assert_ir_matches_interface;
use minocrab_contracts::signet_contract;
use signet_signer_interface::{
    RequestId, RespondBidirectionalEvent, SignBidirectionalEventNotification,
    SignatureRespondedEvent, SignetSigner,
};

type SignBidirectional = (RequestId<Public>, SignBidirectionalEventNotification<Public>);
type Respond = (SignatureRespondedEvent<Public>,);
type RespondBidirectional = (RespondBidirectionalEvent<Public>,);

/// The one whose argument type IS the interface crate's: one declaration,
/// used at `Private` by the callee and `Public` by every caller.
#[test]
fn sign_bidirectional_matches_its_interface() {
    assert_ir_matches_interface::<SignBidirectional, ()>(
        &signet_contract::SignetContract::sign_bidirectional().ir,
        SignetSigner::SIGN_BIDIRECTIONAL,
    );
}

/// The two respond circuits: nine and fourteen slots, the interface's
/// structs at `Private`.
#[test]
fn the_respond_circuits_match_their_interface() {
    assert_ir_matches_interface::<Respond, ()>(&signet_contract::SignetContract::respond().ir, SignetSigner::RESPOND);
    assert_ir_matches_interface::<RespondBidirectional, ()>(
        &signet_contract::SignetContract::respond_bidirectional().ir,
        SignetSigner::RESPOND_BIDIRECTIONAL,
    );
}

/// The check has to bite: the same circuit against the WRONG interface —
/// `respond`'s nine slots against `signBidirectional`'s eight — must fail.
#[test]
fn a_mismatched_interface_is_rejected() {
    let problems = minocrab_abi::check_ir::<SignBidirectional, ()>(
        &signet_contract::SignetContract::respond().ir,
        SignetSigner::RESPOND,
    )
    .expect_err("respond does not have signBidirectional's argument list");
    assert!(
        problems.0.iter().any(|p| p.contains("declares 9 inputs")),
        "{problems}"
    );
}

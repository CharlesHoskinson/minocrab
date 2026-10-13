//! `signet-contract` (signet-midnight-integration) — the Signet singleton,
//! the central Sig Network contract on Midnight that the erc20-vault calls
//! cross-contract. Three stateless, unauthenticated emit-only circuits
//! (verification is deliberately the reader's job — see the Compact
//! original's header):
//!
//! ```text
//! signBidirectional(requestId: Bytes<32>, notification: { version: Uint<8>, payload: Bytes<128> }):
//!   emit (Misc { name: pad(32, "SignBidirectionalEvent"),
//!                payload: Bytes[version, ...requestId, ...payload, ...zeros(95)] })
//! respond({ requestId, signature: { bigR: {x, y}, s, recoveryId } }):
//!   emit (Misc { name: pad(32, "SignatureRespondedEvent"),
//!                payload: Bytes[...requestId, ...x, ...y, ...s, recoveryId, ...zeros(127)] })
//! respondBidirectional({ requestId, blockHeight: Uint<64>, outputKind: OutputKind,
//!                        serializedOutputLength: Uint<64>, digest: Bytes<32>, signature }):
//!   emit (Misc { name: pad(32, "RespondBidirectionalEvent"),
//!                payload: Bytes[...requestId, ...blockHeight as Bytes<8> (LE), outputKind as Uint<8>,
//!                               ...serializedOutputLength as Bytes<8> (LE), ...digest,
//!                               ...x, ...y, ...s, recoveryId, ...zeros(78)] })
//! ```
//!
//! The source is midnight-integration PR #127 (`align-with-protocol-spec`,
//! `e9350c4`, M43): the request id moved INTO both event structs, and the
//! bidirectional attestation gained the block height, the MPC's verdict, the
//! output width and the digest. `respond`'s field vector and payload are
//! what they were before; `respondBidirectional`'s are not.
//!
//! No ledger fields, no witnesses; every argument is disclosed into the
//! 256-byte event payload. `Misc` is the same tag-10 event as the events
//! experiment (name(32) ‖ payload(256) = 288 serialized bytes).

use minocrab::v3::{Circuit3, FieldT, Wire3};
use minocrab::{Private, Public};
use minocrab_ledger::{emit, emit_event, ImpactElem, LedgerValue};
use minocrab_std::v3::{contract, label, Disclose, Discloses, Serializer, B32};
use signet_signer_interface::{
    RequestId, RespondBidirectionalEvent, SignBidirectionalEventNotification, Signature,
    SignatureRespondedEvent,
};

use signet_protocol::misc::{MISC_SIZE, MISC_TAG, MISC_VERSION};

/// The three event names, `pad(32, …)` — DEFINED in `signet-protocol`
/// (M30 C1), where the publisher that BUILDS these envelopes reads them; the
/// contract that EMITS them reads the same definition. Re-exported so the
/// suites keep their spelling.
pub use signet_protocol::circuits::{
    RESPOND_BIDIRECTIONAL_EVENT, SIGNATURE_RESPONDED_EVENT, SIGN_BIDIRECTIONAL_EVENT,
};

// Every argument of these three circuits goes into the event payload, so
// the declarations below ARE the parameter lists — which is exactly what a
// disclosure declaration is for. `EmittedRequestId` rather than
// `RequestId`: that name is already the interface crate's type for the
// value being disclosed. The labels are the field paths WITHIN the event
// struct, as they were when the id was a separate argument.
label! {
    EmittedRequestId = "requestId";
    NotificationVersion = "notification.version";
    NotificationPayload = "notification.payload";
    AttestationBlockHeight = "blockHeight";
    AttestationOutputKind = "outputKind";
    AttestationOutputLength = "serializedOutputLength";
    AttestationDigest = "digest";
    SignatureBigRx = "signature.bigR.x";
    SignatureBigRy = "signature.bigR.y";
    SignatureS = "signature.s";
    SignatureRecoveryId = "signature.recoveryId";
}

/// `emit (Misc { name: pad(32, name), payload })` — the serializer holds
/// name ‖ payload bytes, zero-padded to the 288-byte Misc.
fn emit_misc(c: &mut Circuit3, s: Serializer<Public>) {
    // Kept even though guard threading no longer uses it: dropping this
    // `Copy` would renumber every later identifier, moving the ZKIR
    // (notes/edsl-trim.org §B, the removal's zero-movement gate).
    let _ = c.constant(1u64);
    let serialized = s.finish::<MISC_SIZE>(c);
    let payload = LedgerValue::bytes(
        MISC_SIZE as u32,
        serialized.limbs().iter().map(|&w| ImpactElem::Wire(w)).collect(),
    );
    emit(c, &emit_event(MISC_VERSION, MISC_TAG, &payload));
}

fn misc_name(c: &mut Circuit3, name: &str) -> Serializer<Public> {
    let mut padded = [0u8; 32];
    padded[..name.len()].copy_from_slice(name.as_bytes());
    let mut s = Serializer::<Public>::new();
    s.push_literal(c, &padded);
    s
}

/// The signature's four fields, disclosed under the labels the two respond
/// circuits share, ready to push: `x`, `y`, `s` as `Bytes<32>`, `recoveryId`
/// as a one-byte `Uint<8>`.
///
/// The arguments are the interface crate's own types — `Signature`, wrapped
/// in `SignatureRespondedEvent` / `RespondBidirectionalEvent` exactly as the
/// Compact signature nests them, since PR #127 put the request id inside
/// the event and the flattening the pre-#127 port did (see git history for
/// `respond_like`) no longer buys anything: the argument IS the struct, at
/// `Private` here and `Public` for any caller, one declaration.
/// `tests/contract_matches_its_interface.rs` checks the built IR against
/// the interface slot for slot.
struct DisclosedSignature {
    x: B32<Public>,
    y: B32<Public>,
    s: B32<Public>,
    recovery_id: Wire3<FieldT, Public>,
}

fn disclose_signature(c: &mut Circuit3, sig: Signature<Private>) -> DisclosedSignature {
    DisclosedSignature {
        x: sig.big_r.x.disclose_as::<SignatureBigRx>(c),
        y: sig.big_r.y.disclose_as::<SignatureBigRy>(c),
        s: sig.s.disclose_as::<SignatureS>(c),
        recovery_id: sig.recovery_id.field().disclose_as::<SignatureRecoveryId>(c),
    }
}

impl DisclosedSignature {
    /// x(32) ‖ y(32) ‖ s(32) ‖ recoveryId(1).
    fn push(&self, s: &mut Serializer<Public>) {
        s.push_b32(&self.x);
        s.push_b32(&self.y);
        s.push_b32(&self.s);
        s.push_uint(self.recovery_id, 1);
    }
}

/// The Signet singleton — three stateless, unauthenticated emit-only
/// circuits.
pub struct SignetContract;

#[contract]
impl SignetContract {
    /// `export circuit signBidirectional(requestId: RequestId,
    /// notification: SignBidirectionalEventNotification): []`
    ///
    /// The notification's type comes from `signet-signer-interface` — THE
    /// CRATE THIS CONTRACT'S OWN CALLERS IMPORT. There is one declaration of
    /// the record, used at `Private` here (the callee witnesses its arguments)
    /// and at `Public` by every caller, so the two sides of the wire cannot
    /// disagree about its layout; `tests/contract_matches_its_interface.rs`
    /// checks the whole signature the same way.
    #[circuit]
    pub fn sign_bidirectional(
        c: &mut Circuit3,
        request_id: RequestId<Private>,
        notification: SignBidirectionalEventNotification<Private>,
    ) -> Discloses<(EmittedRequestId, NotificationVersion, NotificationPayload)> {
        let version = notification.version.field();
        let payload = notification.payload;

        let rid = request_id.disclose_as::<EmittedRequestId>(c);
        let version = version.disclose_as::<NotificationVersion>(c);
        let payload = payload.disclose_as::<NotificationPayload>(c);

        // payload: version(1) ‖ requestId(32) ‖ notification.payload(128) ‖ zeros(95)
        c.region("event serialize + emit", |c| {
            let mut s = misc_name(c, SIGN_BIDIRECTIONAL_EVENT);
            s.push_uint(version, 1);
            s.push_b32(&rid.bytes());
            s.push_bytes_n(&payload);
            emit_misc(c, s);
        });
        Discloses::of(())
    }

    /// `export circuit respond(signatureRespondedEvent:
    /// SignatureRespondedEvent): []` — `{ requestId, signature }`, nine
    /// field limbs, the same nine (and the same payload) as before PR #127
    /// moved the id into the struct.
    #[circuit]
    pub fn respond(
        c: &mut Circuit3,
        signature_responded_event: SignatureRespondedEvent<Private>,
    ) -> Discloses<(
        EmittedRequestId,
        SignatureBigRx,
        SignatureBigRy,
        SignatureS,
        SignatureRecoveryId,
    )> {
        let event = signature_responded_event;
        let rid = event.request_id.disclose_as::<EmittedRequestId>(c);
        let sig = disclose_signature(c, event.signature);

        // payload: requestId(32) ‖ x(32) ‖ y(32) ‖ s(32) ‖ recoveryId(1) ‖ zeros(127)
        c.region("event serialize + emit", |c| {
            let mut s = misc_name(c, SIGNATURE_RESPONDED_EVENT);
            s.push_b32(&rid.bytes());
            sig.push(&mut s);
            emit_misc(c, s);
        });
        Discloses::of(())
    }

    /// `export circuit respondBidirectional(respondBidirectionalEvent:
    /// RespondBidirectionalEvent): []` — `{ requestId, blockHeight,
    /// outputKind, serializedOutputLength, digest, signature }`, fourteen
    /// field limbs. `outputKind` is the interface crate's `BoundedUint<3>`
    /// (Compact's three-variant enum: the argument constraint is `less_than
    /// 3`), emitted as its one-byte variant index; the two `Uint<64>`s are
    /// emitted as eight little-endian bytes each, Compact's `as Bytes<8>`.
    #[circuit]
    pub fn respond_bidirectional(
        c: &mut Circuit3,
        respond_bidirectional_event: RespondBidirectionalEvent<Private>,
    ) -> Discloses<(
        EmittedRequestId,
        AttestationBlockHeight,
        AttestationOutputKind,
        AttestationOutputLength,
        AttestationDigest,
        SignatureBigRx,
        SignatureBigRy,
        SignatureS,
        SignatureRecoveryId,
    )> {
        let event = respond_bidirectional_event;
        let rid = event.request_id.disclose_as::<EmittedRequestId>(c);
        let height = event.block_height.field().disclose_as::<AttestationBlockHeight>(c);
        let kind = event.output_kind.field().disclose_as::<AttestationOutputKind>(c);
        let length = event
            .serialized_output_length
            .field()
            .disclose_as::<AttestationOutputLength>(c);
        let digest = event.digest.disclose_as::<AttestationDigest>(c);
        let sig = disclose_signature(c, event.signature);

        // payload: requestId(32) ‖ blockHeight(8, LE) ‖ outputKind(1) ‖
        //          serializedOutputLength(8, LE) ‖ digest(32) ‖ x(32) ‖ y(32)
        //          ‖ s(32) ‖ recoveryId(1) ‖ zeros(78)
        c.region("event serialize + emit", |c| {
            let mut s = misc_name(c, RESPOND_BIDIRECTIONAL_EVENT);
            s.push_b32(&rid.bytes());
            s.push_uint(height, 8);
            s.push_uint(kind, 1);
            s.push_uint(length, 8);
            s.push_b32(&digest);
            sig.push(&mut s);
            emit_misc(c, s);
        });
        Discloses::of(())
    }
}

//! THE OUTBOX (M41 B, notes/stream-design.org, "emit restored"): a
//! contention-free EVM call slot — [`Pending`] plus a primitive
//! [`Stream`] whose accumulator is `(last nonce, last seen)` stepped by
//! `(Add, Max)`.
//!
//! Three circuits, none of which reads the accumulator:
//!
//! - [`Outbox::call`] files the transaction MINUS its nonce under a
//!   content-derived [`Handle`] and stores the environment with it. The
//!   stream's insert is blind: `nonce += 1`, `seen = max(seen, 0)`, then
//!   both cells are snapshotted into the handle's entries — so the call's
//!   nonce is assigned on chain, never read, and two calls proven against
//!   one state both land (the spec's C5 problem, gone).
//! - [`Outbox::emit`] takes the handle's entry (two stable reads: the body
//!   and the snapshot), builds the transaction with the snapshotted nonce,
//!   files the record — hash, request id, MPC notification — exactly as a
//!   `Pending::request` files one, and moves the environment together with
//!   the snapshotted last-seen into the outstanding set under the request
//!   id (the spec's C2: last seen travels with the record). Permissionless:
//!   nothing witness-dependent, nothing to go stale in the stream. SINCE M44
//!   RUNG D IT READS NOTHING SHARED AT ALL — the Signet request nonce every
//!   `file_request` used to read and bump is gone with the V1 vocabulary, so
//!   the audited counter of notes/nonce-admin.org §10.1 is not there to
//!   audit.
//! - [`Outbox::complete`] / [`Outbox::refund`] are `Pending`'s settle
//!   bodies over the same two maps, returning the outstanding entry; then
//!   [`Outbox::raise_seen`] checks the attested height is strictly after
//!   the entry's last seen (C3) and raises last seen by a blind max (C3
//!   step 4). The height is the ATTESTATION'S OWN (spec M2, landed in V1's
//!   `RespondBidirectionalEvent.blockHeight`), so `raise_seen` takes the
//!   settled outcome and no height argument at all.
//!
//! Identical pre-records collide only between call and emit (they share a
//! handle); once emitted they are distinct requests, since the id includes
//! the nonce.

use core::marker::PhantomData;

use minocrab::v3::{Circuit3, FieldT, Wire3};
use minocrab::{Private, Public};
use minocrab_ledger::{XcallCommitment, XcallEntryPointHash};
use minocrab_std::v3::blind::{Add, Max};
use minocrab_std::v3::{
    label, own_public_key, repr_limbs, Disclose, DisclosureLabel, FieldPath, LedgerRepr,
    LedgerWidth, ProofWires, Stream, StreamSpec, Uint, ZswapCoinPublicKey,
};
use signet_signer_interface::RequestId;

use super::{
    build_tx_from_words, common, file_request, AbiReturn, AbiTuple, Called, Callee, Commit,
    Contract, Envelope, EvmCall, Extends, Failed, Filing, Handle, HandleOwned, Outcome, Pending,
    PreRecord, QueueEntry, Ret, Returned, SignRequest, Succeeded,
};
use crate::signet_flow::{RequestIdFiled, RequestRecordFiled, Signing};

label! {
    /// The handle an emit takes, disclosed: it is the map key of everything
    /// the emit reads.
    pub HandleEmitted = "emitted handle";
}

/// Everything [`Outbox::emit`] discloses: the handle, then
/// [`crate::signet_flow::Requested`]'s four.
pub type Emitted = (
    HandleEmitted,
    RequestIdFiled,
    RequestRecordFiled,
    XcallEntryPointHash,
    XcallCommitment,
);

/// The outbox's stream: keyed by handle, bodies are the pre-record and the
/// environment, the head is nothing (the delta needs nothing from the body),
/// the state is `(last nonce, last seen)` under `(Add, Max)` with delta
/// `(1, 0)` at every call.
pub struct OutboxSpec<Env, const WORDS: usize>(PhantomData<fn() -> Env>);

impl<Env: LedgerRepr, const WORDS: usize> StreamSpec for OutboxSpec<Env, WORDS> {
    type Key = Handle<Public>;
    type Body = QueueEntry<Env, WORDS>;
    type Head = ();
    type State = (Uint<64, Public>, Uint<64, Public>);
    type Step = (Add, Max);

    fn head(_c: &mut Circuit3, _body: &Self::Body) {}

    fn delta(c: &mut Circuit3, _head: &()) -> Self::State {
        (
            Uint::from_field_unchecked(c.constant(1u64)),
            Uint::from_field_unchecked(c.constant(0u64)),
        )
    }
}

/// WHAT AN EMITTED REQUEST HOLDS while it is outstanding: the caller's
/// environment and the last seen its call snapshotted (C2), the value the
/// response's height must exceed (C3).
pub struct Outstanding<Env> {
    /// The settle side's environment, moved verbatim from the call.
    pub env: Env,
    /// Last seen at the call, post-step.
    pub seen: Uint<64, Public>,
}

impl<Env: ProofWires> ProofWires for Outstanding<Env> {
    fn push_wires(&self, out: &mut Vec<minocrab::v3::Val>) {
        self.env.push_wires(out);
        self.seen.push_wires(out);
    }
}

impl<Env: LedgerRepr> LedgerRepr for Outstanding<Env> {
    fn atoms() -> Vec<minocrab::AlignmentAtom> {
        let mut atoms = Env::atoms();
        atoms.extend(<Uint<64, Public> as LedgerRepr>::atoms());
        atoms
    }

    fn push_limbs(&self, c: &mut Circuit3, limbs: &mut Vec<Wire3<FieldT, Public>>) {
        LedgerRepr::push_limbs(&self.env, c, limbs);
        LedgerRepr::push_limbs(&self.seen, c, limbs);
    }

    fn from_limbs(limbs: Vec<Wire3<FieldT, Public>>) -> Self {
        let mut limbs = limbs.into_iter();
        let env = Env::from_limbs(limbs.by_ref().take(repr_limbs::<Env>()).collect());
        Outstanding {
            env,
            seen: <Uint<64, Public> as LedgerRepr>::from_limbs(limbs.collect()),
        }
    }
}

/// A CONTENTION-FREE EVM CALL SLOT: [`Pending`]'s two maps and the
/// [`Stream`]'s five fields — bodies, the nonce cell, the last-seen cell,
/// and one snapshot map for each.
///
/// # What does not compile
///
/// A ticket for another filing, as for `Pending`:
///
/// ```compile_fail
/// use minocrab::v3::Circuit3;
/// use minocrab_contracts::evm::{erc20, Filed};
/// use minocrab_contracts::evm_flow::{Outbox, Succeeded};
/// use minocrab_contracts::signet_flow::Signet;
/// use minocrab_contracts::signet_v1::schema;
/// use minocrab_std::v3::{Ledger, LedgerRepr, Uint};
/// use minocrab::Public;
///
/// #[derive(LedgerRepr)] struct Amount { amount: Uint<64, Public> }
///
/// type Transfer = Filed<erc20::Transfer, schema::Success>;
/// type Approve = Filed<erc20::Approve, schema::Success>;
///
/// #[derive(Ledger)]
/// struct Block {
///     signet: Signet,
///     transfers: Outbox<Transfer, Amount, 2>,
///     approvals: Outbox<Approve, Amount, 2>,
/// }
/// const BLOCK: Block = Block::new();
///
/// fn settle(c: &mut Circuit3, ticket: Succeeded<Approve>) {
///     // ERROR: expected `Succeeded<Filed<Transfer, Success>>`
///     BLOCK.transfers.complete(c, ticket);
/// }
/// ```
pub struct Outbox<F: Filing, Env: LedgerRepr, const WORDS: usize> {
    /// The records and outstanding entries an emit files into — a whole
    /// `Pending`, so its settle side is not a copy of one.
    pending: Pending<F, Outstanding<Env>, WORDS>,
    /// The call side: bodies, the two accumulator cells, the two snapshot
    /// maps.
    stream: Stream<OutboxSpec<Env, WORDS>>,
}

impl<F: Filing, Env: LedgerRepr, const WORDS: usize> Outbox<F, Env, WORDS> {
    /// The slot's seven fields from flat index `start`, against the block's
    /// `Signet` at `signet_start` — what `#[derive(Ledger)]` emits for a
    /// field whose type is spelled `Outbox`.
    pub const fn at_block_with_signet(total: usize, start: usize, signet_start: usize) -> Self {
        Outbox {
            pending: Pending::at_block_with_signet(total, start, signet_start),
            stream: Stream::at_block(total, start + 2),
        }
    }

    /// The record map's ledger path: the notification's `depth ‖ path`.
    pub const fn record_path(&self) -> FieldPath {
        self.pending.record_path()
    }

    /// THE FEE SEAM: the contract's fixed envelope (notes/nonce-admin.org
    /// §3; an administrator's policy cell would be read here). Never a
    /// caller's argument.
    fn envelope(&self) -> Envelope {
        Envelope::fixed()
    }
}

impl<F: Filing, Env: LedgerRepr, const WORDS: usize> LedgerWidth for Outbox<F, Env, WORDS> {
    const WIDTH: usize = 2 + <Stream<OutboxSpec<Env, WORDS>> as LedgerWidth>::WIDTH;
}

impl<F: Filing, Env: LedgerRepr + ProofWires, const WORDS: usize> Outbox<F, Env, WORDS>
where
    Returned<F>: AbiReturn,
{
    /// CALL: encode the arguments, file the pre-record under its handle
    /// with the environment, and let the stream assign the nonce blind.
    /// Returns the handle, and discloses [`super::Inserted`] plus whatever
    /// `env` discloses.
    ///
    /// NO NONCE, NO FEE AND NO KEY VERSION ARGUMENT
    /// (notes/nonce-admin.org §1.1): the nonce is the accumulator's, the
    /// envelope the contract's, the key version the `Signet` block's.
    /// Nothing is hashed but the handle, and nothing is notified — the MPC
    /// learns of the call when the emit files its record. The one read is the
    /// not-member check on the handle: per key, never shared.
    pub fn call(
        &self,
        c: &mut Circuit3,
        callee: Contract<impl Extends<Callee<F>>>,
        args: <<Called<F> as EvmCall>::Args as AbiTuple>::Wires<Private>,
        env: impl FnOnce(&mut Circuit3, Handle<Public>) -> Env,
    ) -> Handle<Public> {
        let words = <<Called<F> as EvmCall>::Args as AbiTuple>::words(c, args);
        let pre = PreRecord::<WORDS>::file(c, callee.address(), &words);
        let handle = pre.handle(c);
        c.region("outbox: call", |c| {
            // The environment is built AFTER the handle exists, so a
            // `Commit` in it binds to this request and no other.
            let env = env(c, handle);
            self.stream.insert(c, &handle, &QueueEntry { pre, env });
        });
        handle
    }

    /// EMIT: take the handle's pre-record, environment and snapshot, build
    /// the transaction at the snapshotted nonce, file the record and notify
    /// the MPC, and move the environment with the snapshotted last-seen to
    /// the outstanding set under the request id. Returns the id and
    /// discloses [`Emitted`].
    ///
    /// PERMISSIONLESS and per key: the two stream reads are of entries
    /// written once at the call. (The Signet request nonce read inside
    /// `file_request` is the protocol record's, see the module docs.)
    pub fn emit(&self, c: &mut Circuit3, handle: Handle) -> RequestId<Public> {
        let handle = handle.disclose_as::<HandleEmitted>(c);
        // Both entries were written once at the call and are removed here;
        // the environment and the last seen re-enter the ledger under the
        // request id, so the reads are named as assumed.
        let (entry, state) = self.stream.take(c, &handle);
        let QueueEntry { pre, env } = entry.stale(c);
        let (nonce, seen) = state.stale(c);
        let tx = build_tx_from_words::<Called<F>, WORDS>(
            c,
            pre.callee(),
            pre.words(),
            self.envelope(),
            nonce.field().private(),
            F::GAS_LIMIT,
        );
        let signing = Signing::contract(c);
        file_request::<WORDS, F::Schema>(
            c,
            &self.pending.signet,
            &self.pending.records,
            SignRequest { signing, tx },
            <<Called<F> as EvmCall>::Args as AbiTuple>::WORDS,
            |c, request_id| {
                self.pending
                    .envs
                    .insert(c, &request_id, &Outstanding { env, seen });
            },
        )
    }

    /// SETTLE A SUCCESS — [`Pending::complete`], unchanged, over this slot's
    /// own record and outstanding maps. Follow it with [`Self::raise_seen`].
    pub fn complete(
        &self,
        c: &mut Circuit3,
        ticket: Succeeded<F>,
    ) -> Outcome<Outstanding<Env>, <Called<F> as EvmCall>::Success> {
        self.pending.complete(c, ticket)
    }

    /// SETTLE A NON-SUCCESS — [`Pending::refund`], unchanged. Follow it with
    /// [`Self::raise_seen`].
    pub fn refund(
        &self,
        c: &mut Circuit3,
        ticket: Failed<F>,
    ) -> Outcome<Outstanding<Env>, Ret<Called<F>>> {
        self.pending.refund(c, ticket)
    }

    /// C3, THEN C3 STEP 4: the response's height must be strictly after
    /// the last seen its call snapshotted (an equal height is dropped, as
    /// the spec's table says), and last seen is raised to it — a blind max
    /// on the accumulator, so a response contends with nothing.
    ///
    /// THE HEIGHT IS THE ATTESTATION'S OWN (spec M2, landed in V1): it comes
    /// off the settled [`Outcome`], which read it from the
    /// `RespondBidirectionalEvent` and disclosed it there — so this takes the
    /// outcome rather than a height argument, and there is no way to raise
    /// last seen past a height the MPC did not sign. Before V1 the attested
    /// payload carried no height and the reference contract had to attest one
    /// as the call's return word (`HeightedTransfer`, now gone).
    pub fn raise_seen<R>(&self, c: &mut Circuit3, outcome: &Outcome<Outstanding<Env>, R>) {
        let height = outcome.block_height;
        c.assert(
            height
                .gt(outcome.env.seen)
                .message("Response not after the call"),
        );
        let zero = Uint::from_field_unchecked(c.constant(0u64));
        self.stream.combine(c, (zero, height));
    }
}

impl<F: Filing, E: LedgerRepr + ProofWires, const WORDS: usize> Outbox<F, HandleOwned<E>, WORDS>
where
    Returned<F>: AbiReturn,
{
    /// [`Outbox::call`] with the requester's identity committed into the
    /// environment, bound to the HANDLE — the outbox twin of
    /// [`Pending::request_owned`]. `L` labels the commitment (stored, so
    /// public).
    pub fn call_owned<L: DisclosureLabel>(
        &self,
        c: &mut Circuit3,
        callee: Contract<impl Extends<Callee<F>>>,
        args: <<Called<F> as EvmCall>::Args as AbiTuple>::Wires<Private>,
        inner: impl FnOnce(&mut Circuit3, Handle<Public>) -> E,
    ) -> Handle<Public> {
        let sk = common::witness_sk(c);
        self.call(c, callee, args, |c, handle| HandleOwned {
            handle,
            owner: Commit::to::<L, _>(c, &sk, handle),
            inner: inner(c, handle),
        })
    }

    /// [`Pending::refund_to_owner`] FOR AN OUTBOX REQUEST: the stored
    /// commitment is opened against the stored HANDLE, so the requester
    /// refunds with the value they held before the emit and never had to be
    /// present at it. Returns the outstanding entry too, for
    /// [`Outbox::raise_seen`].
    pub fn refund_to_owner<L: DisclosureLabel>(
        &self,
        c: &mut Circuit3,
        ticket: Failed<F>,
    ) -> (
        ZswapCoinPublicKey<Public>,
        Outcome<Outstanding<HandleOwned<E>>, Ret<Called<F>>>,
    ) {
        let outcome = self.pending.refund(c, ticket);
        let sk = common::witness_sk(c);
        let env = &outcome.env;
        env.env.owner.open(c, &sk, env.env.handle, "Not the owner");
        let owner = own_public_key(c).disclose_as::<L>(c);
        (owner, outcome)
    }
}

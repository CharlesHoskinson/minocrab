//! The MPC's Midnight publisher, pure core (M30).
//!
//! `sig-net/mpc` publishes an MPC signature to Midnight by building a
//! `respond` call, proving it, paying its DUST fee and submitting it. Today a
//! Node 22 sidecar (`midnight-publisher-ts`) does the first three, for one
//! stated reason — "the compiled contract's bindings and executor are
//! JavaScript" (`intent.ts`'s header). This crate is the claim that this is
//! no longer true, in a form mpc's `chain-midnight` can link:
//!
//! ```text
//!  (request id, signature)                        M30 A — call.rs
//!            │                       arguments as an AlignedValue,
//!            ▼                       the Impact program, the key location
//!      SignerCall  ──prototype(state, parameters, rand)──▶ ContractCallPrototype
//!            │
//!            ▼                                            M30 B — intent.rs
//!      build ─▶ Intent (with TTL) ─▶ Transaction           prove.rs, keys.rs
//!            │                                             publish.rs
//!            ├─ prove   in process: no proof server, no child process, and
//!            │          no network once the KZG parameters are on disk
//!            ├─ balance THE DUST SEAM (M30 C) — [`dust::DustBalancer`]
//!            ├─ sign    Intent::sign
//!            └─ seal    PedersenRandomness ─▶ PureGeneratorPedersen
//! ```
//!
//! # Pure
//!
//! Nothing here talks to a node. Every input a chain would supply is an
//! argument, gathered in [`publish::ChainContext`]: the contract's state, the
//! chain's `LedgerParameters` (see [`call`]'s header for why that is not a
//! constant of this crate), its cost model, the network id, the segment and
//! the block time. The funding keys are [`publish::FundingKeys`] and the dust
//! state lives behind [`dust::DustBalancer`]. The only files read are the
//! managed key directory ([`keys::ManagedDir`]) and the KZG parameter cache
//! `MidnightDataProvider` expects under `$MIDNIGHT_PP` /
//! `$XDG_CACHE_HOME/midnight/zk-params` / `~/.cache/midnight/zk-params`. Ship
//! those in the image and a publish makes no network request at all.
//!
//! # Not here
//!
//! - The DUST wallet (M30 C). [`dust::DustBalancer`] is the seam it plugs
//!   into; [`dust::NoDust`] is what the tests run today, and it leaves the
//!   transaction unbalanced — `well_formed` must have `enforce_balancing`
//!   off, which is exactly the gap notes/mpc-publisher.org §2 names.
//! - Submission, event ingestion, the `IntentClient` swap-in and the four
//!   retry classes (`wallet_unsynced`, `proving_timeout`, `state_conflict`,
//!   `ambiguous_submit`). Those are mpc's, tracked there (milestones.org
//!   M30's "Out of scope here").

pub mod call;
pub mod dust;
pub mod error;
pub mod fab;
pub mod intent;
pub mod keys;
pub mod prove;
pub mod publish;

pub use call::{
    respond, respond_bidirectional, sign_bidirectional, Attestation, ContractKeyLocation,
    Deployment, EcdsaSignature, Notification, SignerCall, SIGNER_CIRCUITS,
};
pub use dust::{DustBalancer, NoDust};
pub use error::PublishError;
pub use intent::{PreimageIntent, PreimageTx, ProvenTx, SealedTx};
pub use keys::ManagedDir;
pub use prove::{params_provider, InProcessProver, SignerResolver};
pub use publish::{publish, ChainContext, FundingKeys};

//! L2 — the MinoCrab eDSL.
//!
//! Circuits are ordinary Rust built against [`v3::Circuit3`]; wires carry
//! their visibility in the type. A `Wire3<_, Private>` cannot reach a
//! public output — there is no method for it — until it passes through
//! [`v3::Circuit3::disclose`] (or `disclose_as::<Label>`), which is the
//! single, greppable gate for information leaving the private domain.
//! Combining wires taints: any operation touching a private wire yields a
//! private wire (see [`Meet`]).
//!
//! Disclosure policy escape hatch: `disclose` *is* the override — it always
//! compiles, and every call site names what it discloses, so `grep disclose`
//! is the audit. Stricter application policies wrap wires in newtypes that
//! hide `disclose` behind their own rules (e.g. range-blind first).
//!
//! The enforcement is a type error, not a runtime check:
//!
//! ```compile_fail
//! use minocrab::v3::{Circuit3, FieldT};
//! let mut c = Circuit3::new();
//! let secret = c.witness::<FieldT>();
//! // ERROR: expected `Wire3<FieldT, Public>`, found `Wire3<FieldT, Private>`
//! c.output(secret, "leak");
//! ```
//!
//! With `disclose` it compiles — and the leak is named and greppable:
//!
//! ```
//! use minocrab::v3::{Circuit3, FieldT};
//! let mut c = Circuit3::new();
//! let secret = c.witness::<FieldT>();
//! let public = c.disclose(secret, "intentionally published");
//! c.output(public, "value");
//! ```
//!
//! # Where this sits
//!
//! The middle of the MinoCrab stack: it builds on [`minocrab_ir`] (L1, the
//! typed instruction builder) and is what `minocrab-std` (L3, the ports of
//! Compact's standard library), `minocrab-ledger` (L2.5, Impact ledger ops)
//! and `minocrab-macros` (`#[circuit]`, `#[contract]`) are all written
//! against. `minocrab-sim` runs what [`v3::Circuit3::finish`] produces
//! under `cargo test`. Every contract targets ZKIR v3; there is no other
//! frontend.
//!
//! # Start here
//!
//! - [`v3::Circuit3`] — the builder; [`v3::Wire3`] — a typed, visibility-
//!   tagged value
//! - [`Visibility`] ([`Public`] / [`Private`]) and [`Meet`] — the lattice
//!   wires combine under
//! - [`v3::Circuit3::disclose`] / [`v3::DisclosureLabel`] — the single
//!   Private→Public gate, and the thing to grep for
//! - [`v3::Discloses`] and [`v3::assert_declared_disclosures`] — a circuit
//!   declares what it discloses, and a generated test checks it
//! - [`v3::Compiled3`] — a finished circuit: the IR plus its disclosure
//!   record and regions
//!
//! # Stability (M24 tier boundary)
//!
//! STABLE TIER (semver commitment): the v3 eDSL authoring core —
//! [`v3::Circuit3`] and its instruction-emitting methods, [`v3::Wire3`] /
//! [`v3::AnyWire3`], the visibility types, the FAB alignment re-exports,
//! and [`v3::Compiled3`]. The proposed stable set is deliberately small
//! (notes/library-api.org §1) and grows only by decision, never by
//! accident.

pub use minocrab_ir::{Alignment, AlignmentAtom, AlignmentSegment, Fr};

pub mod v3;

// --- visibility -------------------------------------------------------------

mod sealed {
    pub trait Sealed {}
}

/// Type-level visibility of a wire.
pub trait Visibility: sealed::Sealed + 'static {
    /// Runtime tag, for reports.
    const IS_PUBLIC: bool;
}

/// A visibility that may GUARD AN ON-CHAIN EFFECT — an Impact op or a
/// public-transcript read. Only [`Public`].
///
/// Whether a guarded op ran, and whether a guarded transcript read consumed
/// a value, is visible on chain: the guard bit is published by the effect
/// it guards. So a private condition guarding one is a disclosure, and the
/// disclosure type system has to see it — compactc's own rule ("performing
/// this ledger operation might disclose the boolean value of the witness
/// value … the conditional branch"), which the external review's §4.1 found
/// this API let through silently. Disclose the condition first
/// (`.disclose_as::<L>(c)`), then branch on the public wire; the manifest
/// then names it. Sealed: the two visibilities are the only ones.
#[diagnostic::on_unimplemented(
    message = "a `{Self}` value cannot guard an on-chain effect — whether the effect ran is visible on chain, so the condition is a disclosure",
    label = "private guard on an on-chain effect (Impact op, public-transcript read, or a `when` scope)",
    note = "disclose the condition first — `let cond = cond.disclose_as::<L>(c);` with `L` in the circuit's `Discloses<(..)>` — and guard on the public wire; a `Private` guard is allowed only on effects nothing on chain can see (`witness_guarded`)"
)]
pub trait OnChainGuard: Visibility {}
impl OnChainGuard for Public {}

/// Value derived only from constants and disclosed/public values.
/// (Clone/Copy so `#[derive(Clone, Copy)]` works on types generic over a
/// visibility — derives bound every type parameter.)
#[derive(Clone, Copy)]
pub enum Public {}
/// Value tainted by witness data.
#[derive(Clone, Copy)]
pub enum Private {}

impl sealed::Sealed for Public {}
impl sealed::Sealed for Private {}
impl Visibility for Public {
    const IS_PUBLIC: bool = true;
}
impl Visibility for Private {
    const IS_PUBLIC: bool = false;
}

/// Visibility join: public only if both sides are public.
///
/// The four impls below are a two-point lattice meet, and the discipline
/// they enforce — an expression types `Public` iff every private leaf
/// sits under a `disclose` — is machine-checked in
/// `minocrab-std/lean/MinocrabStdProofs/Visibility.lean` (a model proof;
/// see the file's header for the honest boundary).
#[diagnostic::on_unimplemented(
    message = "`{Self}` is not a wire visibility, so it has no meet with `{B}`",
    label = "expected `Public` or `Private`",
    note = "visibility is a two-point lattice: `Public` and `Private` are its \
            only inhabitants and `Meet` is implemented for all four pairs, so \
            a failure here is a GENERIC parameter that has not been told it is \
            one. Bound it — `V: Meet<Public, Out = V>`, or `V: Vis3`, which \
            carries that plus the rest of what a stdlib gadget needs"
)]
pub trait Meet<B: Visibility>: Visibility {
    type Out: Visibility;
}
impl Meet<Public> for Public {
    type Out = Public;
}
impl Meet<Private> for Public {
    type Out = Private;
}
impl Meet<Public> for Private {
    type Out = Private;
}
impl Meet<Private> for Private {
    type Out = Private;
}

// --- disclosure records -----------------------------------------------------

/// What a circuit reveals, recorded at build time for the simulator's report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Disclosure {
    /// Call-site label, e.g. what quantity is being disclosed and why.
    pub label: String,
    /// How it leaves the circuit.
    pub kind: DisclosureKind,
    /// ZKIR memory index of the disclosed value.
    pub index: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisclosureKind {
    /// `disclose_as::<L>()` — a private value became public inside the
    /// circuit, under a LABEL TYPE the circuit's `Discloses<..>` names.
    Disclosed,
    /// `disclose(w, "text")` — the same, under a bare string. It never
    /// satisfies a declaration: a declared label is a type, and a string
    /// that happens to spell it is exactly the shadowing the manifest must
    /// not accept (external review §4.5). The test names the fix.
    DisclosedUntyped,
    /// Declared as part of the public statement (public input block).
    Statement,
    /// Returned as a circuit output.
    Output,
}

// --- circuit ------------------------------------------------------------------

/// A named span of instructions, for cost attribution in the profiler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Region {
    pub label: String,
    /// Instruction index range [start, end) — of the FINISHED stream once
    /// the circuit is finished, which moves it across the instructions the
    /// IR passes delete (a region left with none is empty, `start == end`).
    pub start: usize,
    pub end: usize,
}

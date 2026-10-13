//! The SPEC TYPES: plain Rust declarations of the payloads the DEPLOYED
//! protocol already puts on the wire (M11 stage 0, notes/borsh-format.org).
//!
//! Nothing here is a circuit, and nothing here is an encoder. Each type is a
//! declaration of a byte layout — canonical Borsh restricted to the
//! fixed-width subset the design of record specifies — expressed once and
//! handed to TWO independent oracles:
//!
//! - `#[derive(BorshSerialize)]`, and
//! - `#[derive(serde::Serialize)]` + bincode's fixint/little-endian config.
//!
//! The conformance suite asserts the two agree with each other and with the
//! bytes the deployed circuits hash and log. Between them, the oracle
//! equality and the fixed-width property are the subset checker: a Rust
//! enum and a `Vec` make the two ENCODERS disagree, and an `Option` — which
//! both encoders spell identically — makes the WIDTH value-dependent. All
//! three are pinned as negative controls in `serialization_conformance.rs`'s
//! `subset_boundary` module, so the suite can never be vacuous.
//!
//! Deliberately NOT here: any `Vec`, `String`, `Option` or data-carrying
//! enum. Compact's `Maybe` is [`Flagged`] — a 1-byte tag with an
//! ALWAYS-PRESENT payload — never `Option`, whose Borsh encoding omits the
//! payload on `None` and so has data-dependent offsets.
//!
//! TWO LINEAGES live here, and they are not alternatives. The V1 types
//! ([`VaultEventV1`] and its four siblings, [`BoolOutput`], [`WordOutput`],
//! [`EmptyOutput`]) are the DEPLOYED Signet wire vocabulary the flush-pattern
//! vault imports (`@sig-net/midnight` 0.24.1, M44); the V2 types
//! ([`VaultEventV2`], [`VaultResponse`] and the rest) are the `Pending`
//! lineage's own format, which nothing has deployed — a SPECIFICATION, pinned
//! here against borsh's encoder and borsh's schema. What is on the wire today
//! is V1, and it is the V1 types that carry a byte-equality claim against the
//! protocol's own FAB bytes.

use borsh::schema::{BorshSchemaContainer, Declaration, Definition};
use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use serde::ser::SerializeTuple;
use serde::{Serialize, Serializer};

/// The fixed serialized width of a spec type.
///
/// Every offset in the subset is a compile-time constant, so every LEN is
/// too. The conformance suite proves the constant three ways: against
/// `borsh::object_length` over generated values (no value-dependent
/// branching), against the deployed FAB alignment's `bin_len`, and against
/// the schema walk.
pub trait FixedLen {
    const LEN: usize;
}

/// The subset's LEAF TABLE, as code: the only primitives a spec type may be
/// built from, and their widths. `Uint<BITS>` for BITS outside these widths
/// is a range constraint on the next width up, never a narrower field.
macro_rules! fixed_len_primitives {
    ($($ty:ty => $len:literal),+ $(,)?) => {
        $(impl FixedLen for $ty { const LEN: usize = $len; })+
    };
}

fixed_len_primitives!(bool => 1, u8 => 1, u16 => 2, u32 => 4, u64 => 8, u128 => 16);

impl<const N: usize> FixedLen for [u8; N] {
    const LEN: usize = N;
}

// ---- `Bytes<N>` for N > 32 ---------------------------------------------------

/// A fixed byte array whose length exceeds serde's blanket `[T; N]` impls
/// (which stop at N = 32) and whose Borsh schema declaration must not lose
/// the length.
///
/// The wrapper is TRANSPARENT under both oracles:
/// - Borsh: a newtype struct with one field serializes as that field, and
///   [`BorshSchema`] is delegated to `[u8; N]` verbatim (the derive would
///   name every instantiation `ByteArray`, which collides in a container
///   holding two different N).
/// - serde: [`Serialize`] is serde's own array impl verbatim —
///   `serialize_tuple(N)` and N elements.
///
/// `byte_array_wrapper_is_transparent` pins that claim for the N ≤ 32 where
/// the native impls exist and can be compared against.
#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct ByteArray<const N: usize>(pub [u8; N]);

impl<const N: usize> Serialize for ByteArray<N> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut tuple = serializer.serialize_tuple(N)?;
        for byte in &self.0 {
            tuple.serialize_element(byte)?;
        }
        tuple.end()
    }
}

impl<const N: usize> BorshSchema for ByteArray<N> {
    fn declaration() -> Declaration {
        <[u8; N] as BorshSchema>::declaration()
    }

    fn add_definitions_recursively(
        definitions: &mut std::collections::BTreeMap<Declaration, Definition>,
    ) {
        <[u8; N] as BorshSchema>::add_definitions_recursively(definitions);
    }
}

impl<const N: usize> FixedLen for ByteArray<N> {
    const LEN: usize = N;
}

impl<const N: usize> Default for ByteArray<N> {
    fn default() -> Self {
        ByteArray([0u8; N])
    }
}

// ---- Maybe ------------------------------------------------------------------

/// Compact's `Maybe<T>`: a 1-byte tag and an ALWAYS-PRESENT payload.
///
/// This is what `Maybe` already compiles to (the FAB record carries
/// `calldata.is_some` as its own `bytes<1>` atom followed by the full
/// calldata atoms whether or not the tag is set), and it is ordinary
/// canonical Borsh AND ordinary serde of this struct — not a dialect. The
/// single most important line of the spec for the TS side: **Maybe ↦
/// Flagged, never Option**.
#[derive(BorshSerialize, BorshDeserialize, BorshSchema, Serialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct Flagged<T> {
    pub is_some: bool,
    pub value: T,
}

impl<T: FixedLen> FixedLen for Flagged<T> {
    const LEN: usize = 1 + T::LEN;
}

// ---- the transaction parameters, shared by both lineages ---------------------
//
// `EvmType2TxParams<#maxCalldataWords, 0, 0>` is the one struct the V1 move
// did NOT touch (`signet_v1`'s module doc says so), so these declarations
// serve the deployed V1 records and the V2 specification alike. Field order,
// widths and nesting are read off the shape itself:
// `signet_v1::SignBidirectionalEventV1::atoms()` and `signet_v1::layout`.

/// `struct EvmCalldata<#maxWords>` — the ABI calldata of the EVM
/// transaction the MPC is asked to sign.
#[derive(BorshSerialize, BorshDeserialize, BorshSchema, Serialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct EvmCalldata2 {
    /// `Bytes<4>` — the 4-byte function selector, in string order.
    pub selector: [u8; 4],
    /// `Uint<16>` — how many of `words` are used.
    pub no_words: u16,
    /// `Bytes<32>[2]` — the canonical big-endian ABI words.
    pub words: [[u8; 32]; 2],
}

impl FixedLen for EvmCalldata2 {
    const LEN: usize = 4 + 2 + 2 * 32;
}

/// [`EvmCalldata2`] with the swap instantiation's seven words.
#[derive(BorshSerialize, BorshDeserialize, BorshSchema, Serialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct EvmCalldata7 {
    pub selector: [u8; 4],
    pub no_words: u16,
    pub words: [[u8; 32]; 7],
}

impl FixedLen for EvmCalldata7 {
    const LEN: usize = 4 + 2 + 7 * 32;
}

/// [`EvmCalldata2`] with the redeem instantiation's three words —
/// `redeem(shares, receiver, owner)`.
#[derive(BorshSerialize, BorshDeserialize, BorshSchema, Serialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct EvmCalldata3 {
    pub selector: [u8; 4],
    pub no_words: u16,
    pub words: [[u8; 32]; 3],
}

impl FixedLen for EvmCalldata3 {
    const LEN: usize = 4 + 2 + 3 * 32;
}

/// `struct EvmType2TxParams<#maxCalldataWords, 0, 0>` — the EIP-1559
/// envelope with an empty access list, for the 2-word instantiation.
#[derive(BorshSerialize, BorshDeserialize, BorshSchema, Serialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct EvmType2TxParams2 {
    pub chain_id: u64,
    pub nonce: u64,
    pub max_priority_fee_per_gas: u128,
    pub max_fee_per_gas: u128,
    pub gas_limit: u64,
    /// `Bytes<20>` — the destination EVM address, in display order.
    pub to: [u8; 20],
    pub value: u128,
    pub calldata: Flagged<EvmCalldata2>,
    /// `maxAccessListEntries = 0`, so no entries follow the count.
    pub access_list_entry_count: u8,
}

impl FixedLen for EvmType2TxParams2 {
    const LEN: usize = 8 + 8 + 16 + 16 + 8 + 20 + 16 + Flagged::<EvmCalldata2>::LEN + 1;
}

/// [`EvmType2TxParams2`] with the swap instantiation's seven calldata words.
#[derive(BorshSerialize, BorshDeserialize, BorshSchema, Serialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct EvmType2TxParams7 {
    pub chain_id: u64,
    pub nonce: u64,
    pub max_priority_fee_per_gas: u128,
    pub max_fee_per_gas: u128,
    pub gas_limit: u64,
    pub to: [u8; 20],
    pub value: u128,
    pub calldata: Flagged<EvmCalldata7>,
    pub access_list_entry_count: u8,
}

impl FixedLen for EvmType2TxParams7 {
    const LEN: usize = 8 + 8 + 16 + 16 + 8 + 20 + 16 + Flagged::<EvmCalldata7>::LEN + 1;
}

/// [`EvmType2TxParams2`] with the redeem instantiation's three calldata words.
#[derive(BorshSerialize, BorshDeserialize, BorshSchema, Serialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct EvmType2TxParams3 {
    pub chain_id: u64,
    pub nonce: u64,
    pub max_priority_fee_per_gas: u128,
    pub max_fee_per_gas: u128,
    pub gas_limit: u64,
    pub to: [u8; 20],
    pub value: u128,
    pub calldata: Flagged<EvmCalldata3>,
    pub access_list_entry_count: u8,
}

impl FixedLen for EvmType2TxParams3 {
    const LEN: usize = 8 + 8 + 16 + 16 + 8 + 20 + 16 + Flagged::<EvmCalldata3>::LEN + 1;
}

// ---- the request record: `SignBidirectionalEventV1` (DEPLOYED) ---------------
//
// One type per instantiation the vault writes, because the two things that
// vary — the calldata's word capacity and the output schema's width — are both
// in the layout. The vault's five are `<2, 34>` (deposit / withdraw /
// approveRouter / approveStata), `<2, 2>` (replaceNonce, whose `[]` schema says
// the MPC returns nothing), `<7, 38>` (swap), `<2, 36>` (supply) and `<3, 36>`
// (redeem).
//
// THE TRAILING `Bytes<0>` IS SPELLED OUT. `respondSerializationSchema` is
// pinned to `Bytes<0>` at every V1 site: the FAB alignment carries the atom,
// the limbs carry nothing for it, and `Alignment::bin_len` adds zero. A
// zero-width [`ByteArray<0>`] says exactly that — the published offset table
// gets a `width 0` row where the field is, so a decoder reads "there is a
// field here and it is empty" rather than inferring it from a total. That the
// two agree is `lens_match_the_deployed_alignments`, which compares each `LEN`
// against the `bin_len` of the atom list INCLUDING the `b0` atom.

/// The vault's request record: `SignBidirectionalEventV1<EvmType2TxParams<2,
/// 0, 0>, 34, 0>`, the value an action's request map stores — 362 bytes.
///
/// `sendDeposit`, `sendWithdraw` and `sendApprove` write one; the matching
/// `complete*` reads it back.
#[derive(BorshSerialize, BorshDeserialize, BorshSchema, Serialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct VaultEventV1 {
    /// Guarded `>= 1` by `constructSignBidirectionalEventV1`, and FIRST — the
    /// V1 record's byte 0, where the superseded shape put the sender.
    pub key_version: u8,
    /// The requesting contract's address (`kernel.self`).
    pub sender: [u8; 32],
    /// The MPC key-derivation path — `userCommitment(sk)` for a deposit, the
    /// fixed vault path everywhere else.
    pub path: [u8; 32],
    /// `MPCSignatureAlgorithm` — a fieldless enum, 1 byte. A Rust `enum`
    /// would leave the subset: bincode-fixint writes a 4-byte variant index
    /// where Borsh writes one (`fieldless_enum_leaves_the_subset`).
    pub algo: u8,
    /// `TxParamType`, same rule as `algo`.
    pub tx_param_type: u8,
    pub tx_params: EvmType2TxParams2,
    /// `executionDest: Bytes<32>` — `pad(32, "eip155:1")`, the MPC's routing
    /// key for every Ethereum network it watches.
    pub execution_dest: [u8; 32],
    /// `MPCDestination`, same rule as `algo`.
    pub signature_dest: u8,
    /// `Bytes<64>` — `pad(64, "")` at every deployed site.
    pub params: ByteArray<64>,
    /// The in-band ABI-JSON schema the MPC decodes the return data with.
    pub output_deserialization_schema: ByteArray<34>,
    /// `Bytes<0>` — an atom with no limb and no byte. See the note above.
    pub respond_serialization_schema: ByteArray<0>,
}

impl FixedLen for VaultEventV1 {
    // The trailing `+ 0` is `respondSerializationSchema: Bytes<0>`, spelled
    // out so the sum reads field for field against the record above. It is
    // the field whose presence in the ALIGNMENT and absence from the LIMBS
    // is the V1 record\'s one surprise, so it is not a term to tidy away.
    #[allow(clippy::identity_op)]
    const LEN: usize = 1 + 32 + 32 + 1 + 1 + EvmType2TxParams2::LEN + 32 + 1 + 64 + 34 + 0;
}

/// `sendReplaceNonce`'s record: [`VaultEventV1`]'s shape with the `[]` output
/// schema — a value-only transaction to the vault's own EVM address with NO
/// calldata, so `calldata.is_some` is 0 and the two words are zero. 330 bytes.
#[derive(BorshSerialize, BorshDeserialize, BorshSchema, Serialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReplaceNonceEventV1 {
    pub key_version: u8,
    pub sender: [u8; 32],
    pub path: [u8; 32],
    pub algo: u8,
    pub tx_param_type: u8,
    pub tx_params: EvmType2TxParams2,
    pub execution_dest: [u8; 32],
    pub signature_dest: u8,
    pub params: ByteArray<64>,
    pub output_deserialization_schema: ByteArray<2>,
    pub respond_serialization_schema: ByteArray<0>,
}

impl FixedLen for ReplaceNonceEventV1 {
    // The trailing `+ 0` is `respondSerializationSchema: Bytes<0>`, spelled
    // out so the sum reads field for field against the record above. It is
    // the field whose presence in the ALIGNMENT and absence from the LIMBS
    // is the V1 record\'s one surprise, so it is not a term to tidy away.
    #[allow(clippy::identity_op)]
    const LEN: usize = 1 + 32 + 32 + 1 + 1 + EvmType2TxParams2::LEN + 32 + 1 + 64 + 2 + 0;
}

/// The swap request record: `SignBidirectionalEventV1<EvmType2TxParams<7, 0,
/// 0>, 38, 0>` — `exactOutputSingle`'s seven ABI words and the wider schema,
/// 526 bytes.
#[derive(BorshSerialize, BorshDeserialize, BorshSchema, Serialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct SwapEventV1 {
    pub key_version: u8,
    pub sender: [u8; 32],
    pub path: [u8; 32],
    pub algo: u8,
    pub tx_param_type: u8,
    pub tx_params: EvmType2TxParams7,
    pub execution_dest: [u8; 32],
    pub signature_dest: u8,
    pub params: ByteArray<64>,
    pub output_deserialization_schema: ByteArray<38>,
    pub respond_serialization_schema: ByteArray<0>,
}

impl FixedLen for SwapEventV1 {
    // The trailing `+ 0` is `respondSerializationSchema: Bytes<0>`, spelled
    // out so the sum reads field for field against the record above. It is
    // the field whose presence in the ALIGNMENT and absence from the LIMBS
    // is the V1 record\'s one surprise, so it is not a term to tidy away.
    #[allow(clippy::identity_op)]
    const LEN: usize = 1 + 32 + 32 + 1 + 1 + EvmType2TxParams7::LEN + 32 + 1 + 64 + 38 + 0;
}

/// The supply request record: the SAME 2-word shape as [`VaultEventV1`] with
/// the lending schema two bytes longer (`shares: uint256` for `success: bool`),
/// so 364 bytes. `sendSupply` writes an ERC-4626 `deposit(assets, receiver)` to
/// the stata token.
#[derive(BorshSerialize, BorshDeserialize, BorshSchema, Serialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct SupplyEventV1 {
    pub key_version: u8,
    pub sender: [u8; 32],
    pub path: [u8; 32],
    pub algo: u8,
    pub tx_param_type: u8,
    pub tx_params: EvmType2TxParams2,
    pub execution_dest: [u8; 32],
    pub signature_dest: u8,
    pub params: ByteArray<64>,
    pub output_deserialization_schema: ByteArray<36>,
    pub respond_serialization_schema: ByteArray<0>,
}

impl FixedLen for SupplyEventV1 {
    // The trailing `+ 0` is `respondSerializationSchema: Bytes<0>`, spelled
    // out so the sum reads field for field against the record above. It is
    // the field whose presence in the ALIGNMENT and absence from the LIMBS
    // is the V1 record\'s one surprise, so it is not a term to tidy away.
    #[allow(clippy::identity_op)]
    const LEN: usize = 1 + 32 + 32 + 1 + 1 + EvmType2TxParams2::LEN + 32 + 1 + 64 + 36 + 0;
}

/// The redeem request record: three ABI words (`redeem(shares, receiver,
/// owner)`) and the lending schema, 396 bytes.
#[derive(BorshSerialize, BorshDeserialize, BorshSchema, Serialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct RedeemEventV1 {
    pub key_version: u8,
    pub sender: [u8; 32],
    pub path: [u8; 32],
    pub algo: u8,
    pub tx_param_type: u8,
    pub tx_params: EvmType2TxParams3,
    pub execution_dest: [u8; 32],
    pub signature_dest: u8,
    pub params: ByteArray<64>,
    pub output_deserialization_schema: ByteArray<36>,
    pub respond_serialization_schema: ByteArray<0>,
}

impl FixedLen for RedeemEventV1 {
    // The trailing `+ 0` is `respondSerializationSchema: Bytes<0>`, spelled
    // out so the sum reads field for field against the record above. It is
    // the field whose presence in the ALIGNMENT and absence from the LIMBS
    // is the V1 record\'s one surprise, so it is not a term to tidy away.
    #[allow(clippy::identity_op)]
    const LEN: usize = 1 + 32 + 32 + 1 + 1 + EvmType2TxParams3::LEN + 32 + 1 + 64 + 36 + 0;
}

// ---- the request record, V2 (the `Pending` lineage, M11 stage 7) -------------
//
// What the BORSH artifacts write: a FORMAT VERSION byte in front, a 1-byte
// RESPONSE KIND where the in-band ABI-JSON schema strings were, and the
// `fff3421c` field order in between (`sender` first, the request nonce after
// it, `params` before `txParamType`) — which is the order the V2 records keep
// and the deployed V1 record above no longer has. Nothing is deployed in this
// shape; like the stage-5 attested outputs it is a SPECIFICATION, and the V1
// types above are untouched by it, because what is on the wire today is still
// on the wire today.

/// `formatVersion` — the byte at offset 0 of every stage-7 record.
///
/// `0x80`: the byte with only the high bit set, so "this is not a small
/// version number" is a single bit test, and every value below it stays
/// available to Compact/Midnight (whose largest version number anywhere in the
/// pinned stack is 33).
pub const RECORD_FORMAT_VERSION: u8 = 0x80;

/// The V2 2-word record — 338 bytes, where the `fff3421c` record it versions
/// was 404.
///
/// `deposit` (kind 0, CLAIM), `approveRouter` (kind 4, APPROVE) and `withdraw`
/// (kind 1, WITHDRAW) write one; `claim`, `completeWithdraw` and `refund` read
/// one back.
#[derive(BorshSerialize, BorshDeserialize, BorshSchema, Serialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct VaultEventV2 {
    /// [`RECORD_FORMAT_VERSION`].
    pub format_version: u8,
    pub sender: [u8; 32],
    pub request_nonce: u64,
    pub key_version: u8,
    pub path: [u8; 32],
    pub algo: u8,
    pub dest: u8,
    pub params: ByteArray<64>,
    pub tx_param_type: u8,
    pub tx_params: EvmType2TxParams2,
    pub caip2_id: [u8; 32],
    /// The response KIND this request expects — the same enumeration the
    /// attested output carries at ITS byte 0, which is what lets a settle
    /// circuit check the two ends against each other. It replaces the 68 bytes
    /// of ABI-JSON the deployed record spends saying the same thing.
    pub response_kind: u8,
}

impl FixedLen for VaultEventV2 {
    const LEN: usize = 1 + 32 + 8 + 1 + 32 + 1 + 1 + 64 + 1 + EvmType2TxParams2::LEN + 32 + 1;
}

/// The V2 7-word swap record — 498 bytes, where the `fff3421c` record it
/// versions was 571. The 73 bytes are what takes that record's keccak preimage
/// from five blocks to four, and `swap` from k16 to k15.
#[derive(BorshSerialize, BorshDeserialize, BorshSchema, Serialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct SwapEventV2 {
    pub format_version: u8,
    pub sender: [u8; 32],
    pub request_nonce: u64,
    pub key_version: u8,
    pub path: [u8; 32],
    pub algo: u8,
    pub dest: u8,
    pub params: ByteArray<64>,
    pub tx_param_type: u8,
    pub tx_params: EvmType2TxParams7,
    pub caip2_id: [u8; 32],
    /// Kind 2, SWAP — the one kind whose response carries a payload.
    pub response_kind: u8,
}

impl FixedLen for SwapEventV2 {
    const LEN: usize = 1 + 32 + 8 + 1 + 32 + 1 + 1 + 64 + 1 + EvmType2TxParams7::LEN + 32 + 1;
}

/// The V2 3-word redeem record — 370 bytes (the 3-word
/// middle with the version byte in front and kind 6, REDEEM, where the schema
/// strings were). A V2 SUPPLY record needs no type of its own: it is a
/// [`VaultEventV2`] whose `response_kind` is 5, SUPPLY — the same 2-word
/// middle, as the `Pending<SupplyEnv, SupplyResponse, 2>` instantiation says.
#[derive(BorshSerialize, BorshDeserialize, BorshSchema, Serialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct RedeemEventV2 {
    pub format_version: u8,
    pub sender: [u8; 32],
    pub request_nonce: u64,
    pub key_version: u8,
    pub path: [u8; 32],
    pub algo: u8,
    pub dest: u8,
    pub params: ByteArray<64>,
    pub tx_param_type: u8,
    pub tx_params: EvmType2TxParams3,
    pub caip2_id: [u8; 32],
    /// Kind 6, REDEEM.
    pub response_kind: u8,
}

impl FixedLen for RedeemEventV2 {
    const LEN: usize = 1 + 32 + 8 + 1 + 32 + 1 + 1 + 64 + 1 + EvmType2TxParams3::LEN + 32 + 1;
}

// ---- the attested outputs: V1 (DEPLOYED) -------------------------------------
//
// What the MPC serializes back, exactly as deployed: a `Bytes<LEN>` at one of
// THREE widths, and no kind tag. The width is part of the signed digest (V1
// commits to it beside the verdict), so the three are not interchangeable —
// `queueAttestation0`, `queueAttestation1` and `queueAttestation32` are three
// circuits, one per width.
//
// NO FAILURE SENTINEL. A V1 attestation on a `failed` or `unviable` verdict
// carries an EMPTY output ([`EmptyOutput`]) and the verdict itself says what
// went wrong, so the superseded 5-byte `0xdeadbeef01` output — a value a
// settle circuit asserted equal in-circuit — has no successor here.

/// The empty attested output, `Bytes<0>`: what `queueAttestation0` takes and
/// what EVERY failed or unviable verdict carries, whatever the request asked
/// for. Zero bytes, spelled as a zero-width field so the published table says
/// where the output is rather than leaving a reader to infer that it is absent.
#[derive(BorshSerialize, BorshDeserialize, BorshSchema, Serialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct EmptyOutput {
    pub output: ByteArray<0>,
}

impl FixedLen for EmptyOutput {
    const LEN: usize = 0;
}

/// `Bytes<1>` — the attested EVM `bool` of a transfer or an approval, which
/// `completeDeposit`, `completeWithdraw` and the approvals read.
///
/// A `u8`, not a `bool`: `deserialize<VaultResponse, 1>(output).success` is
/// `(byte == 1)` with NO canonicity check, so ANY byte is accepted and
/// everything other than `0x01` routes to the failure branch (the 0x02 hazard,
/// M10's harness finding). The V2 lineage makes this a Borsh `bool`, which is
/// `0|1` and nothing else; the deployed type is a byte.
#[derive(BorshSerialize, BorshDeserialize, BorshSchema, Serialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct BoolOutput {
    pub success: u8,
}

impl FixedLen for BoolOutput {
    const LEN: usize = 1;
}

/// `Bytes<32>` — one big-endian ABI word, which is how V1 carries every
/// `uint256` the destination chain returns: the swap's `amountIn`, the
/// supply's `shares`, the redeem's `assets`. ONE type for the three sites,
/// because the wire cannot tell them apart; which map holds the request id
/// does.
#[derive(BorshSerialize, BorshDeserialize, BorshSchema, Serialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct WordOutput {
    pub word: [u8; 32],
}

impl FixedLen for WordOutput {
    const LEN: usize = 32;
}

// ---- the attested outputs, M11 stage 5 ----------------------------------------
//
// What the BORSH artifact signs: the same four sites with a response KIND at
// byte 0 and declared payload types. These are not deployed anywhere — the
// MPC has never settled on Midnight — so they are a SPECIFICATION, and this
// is where its byte layout is pinned against borsh's own encoder and schema.
// The circuit-side declarations are `erc20_vault_borsh::{VaultResponse,
// SwapResponse, FailureResponse}`; these are the independent second
// statement of them, which is the whole point of a spec type.

/// `claim` (kind 0) and `completeWithdraw` (kind 1): the kind byte and the
/// EVM outcome as a Borsh `bool`.
///
/// ONE TYPE FOR TWO SITES, unlike V1's [`BoolOutput`] at both: the two are
/// separated by the KIND VALUE rather than by being the same bytes at
/// different sites, which is what makes a cross-circuit replay a signature
/// failure instead of a state-machine question. And `success` is a `bool`, not
/// a `u8` — the 0x02 hazard closing.
#[derive(BorshSerialize, BorshDeserialize, BorshSchema, Serialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct VaultResponse {
    pub kind: u8,
    pub success: bool,
}

impl FixedLen for VaultResponse {
    const LEN: usize = 1 + 1;
}

/// `completeSwap` (kind 2): the kind byte and the attested `amountIn`.
#[derive(BorshSerialize, BorshDeserialize, BorshSchema, Serialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct SwapResponse {
    pub kind: u8,
    pub amount_in: u64,
}

impl FixedLen for SwapResponse {
    const LEN: usize = 1 + 8;
}

/// `completeSupply` (kind 5): the kind byte and the attested Aave `shares`.
#[derive(BorshSerialize, BorshDeserialize, BorshSchema, Serialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct SupplyResponse {
    pub kind: u8,
    pub shares: u64,
}

impl FixedLen for SupplyResponse {
    const LEN: usize = 1 + 8;
}

/// `completeRedeem` (kind 6): the kind byte and the attested Aave `assets`.
#[derive(BorshSerialize, BorshDeserialize, BorshSchema, Serialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct RedeemResponse {
    pub kind: u8,
    pub assets: u64,
}

impl FixedLen for RedeemResponse {
    const LEN: usize = 1 + 8;
}

/// `refund` (kind 3): the kind byte, and nothing else — the whole content of
/// the deployed 5-byte `0xdeadbeef01` sentinel, in the byte position every
/// response type puts its kind.
#[derive(BorshSerialize, BorshDeserialize, BorshSchema, Serialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct FailureResponse {
    pub kind: u8,
}

impl FixedLen for FailureResponse {
    const LEN: usize = 1;
}

/// The V2 lineage's `calculateSignetAttestationDigest(requestId,
/// serializedOutput)` preimage — the raw concatenation the MPC signs.
///
/// V2 ONLY, and that is a real difference rather than an omission: V1's
/// `calculateSignetAttestationDigestV1` is Poseidon over the FIELD limbs
/// `[HashDomain.attestationDigest, requestId, blockHeight, outputKind, LEN,
/// ..output]`, which is never a byte string, so there is nothing for a Borsh
/// declaration of it to be true of. `v1_attestation_digest_commits_to_the_kind_and_the_width`
/// states the V1 preimage instead, in limbs.
#[derive(BorshSerialize, BorshDeserialize, BorshSchema, Serialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttestationPreimage<T> {
    pub request_id: [u8; 32],
    pub output: T,
}

impl<T: FixedLen> FixedLen for AttestationPreimage<T> {
    const LEN: usize = 32 + T::LEN;
}

// ---- the Signet singleton's Misc payloads -------------------------------------
//
// `Misc` is event tag 10: `name: Bytes<32>` ‖ `payload: Bytes<256>`, 288
// serialized bytes. The spec types below are the PAYLOAD's leading bytes;
// the envelope rule (name, then these bytes, then zeros to 288) is
// `deployed::misc_envelope`.

/// `signBidirectional`'s payload: the notification version, the request id
/// and the 128-byte V1 notification payload — 161 bytes, then 95 zero bytes
/// of `Bytes<256>` pad.
#[derive(BorshSerialize, BorshDeserialize, BorshSchema, Serialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignBidirectionalMisc {
    pub version: u8,
    pub request_id: [u8; 32],
    pub payload: ByteArray<128>,
}

impl FixedLen for SignBidirectionalMisc {
    const LEN: usize = 1 + 32 + 128;
}

/// `respond`'s and `respondBidirectional`'s payload — the two circuits are
/// the same body under different event names. 129 bytes (borsh-identical to
/// `[[u8; 32]; 4] ‖ u8`, spelled as named fields), then 127 zero bytes of
/// pad.
#[derive(BorshSerialize, BorshDeserialize, BorshSchema, Serialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct RespondMisc {
    pub request_id: [u8; 32],
    pub big_r_x: [u8; 32],
    pub big_r_y: [u8; 32],
    pub s: [u8; 32],
    pub recovery_id: u8,
}

impl FixedLen for RespondMisc {
    const LEN: usize = 4 * 32 + 1;
}

/// Every spec type's Borsh schema container, for the frozen layout table.
/// Kept beside the declarations so a new spec type that is never snapshotted
/// is a visible omission.
///
/// Order is the document's: the DEPLOYED V1 records and outputs first, then
/// the V2 specification, then the singleton's logged payloads.
pub fn schema_containers() -> Vec<(&'static str, BorshSchemaContainer)> {
    vec![
        // The deployed V1 records (signet-midnight-examples 375071b).
        ("VaultEventV1", BorshSchemaContainer::for_type::<VaultEventV1>()),
        (
            "ReplaceNonceEventV1",
            BorshSchemaContainer::for_type::<ReplaceNonceEventV1>(),
        ),
        ("SwapEventV1", BorshSchemaContainer::for_type::<SwapEventV1>()),
        ("SupplyEventV1", BorshSchemaContainer::for_type::<SupplyEventV1>()),
        ("RedeemEventV1", BorshSchemaContainer::for_type::<RedeemEventV1>()),
        // The deployed V1 attested outputs — three widths, no kind tag.
        ("EmptyOutput", BorshSchemaContainer::for_type::<EmptyOutput>()),
        ("BoolOutput", BorshSchemaContainer::for_type::<BoolOutput>()),
        ("WordOutput", BorshSchemaContainer::for_type::<WordOutput>()),
        // The V2 lineage: the versioned, kind-tagged records.
        ("VaultEventV2", BorshSchemaContainer::for_type::<VaultEventV2>()),
        ("SwapEventV2", BorshSchemaContainer::for_type::<SwapEventV2>()),
        ("RedeemEventV2", BorshSchemaContainer::for_type::<RedeemEventV2>()),
        // The V2 lineage: the specified (not deployed) attested outputs.
        ("VaultResponse", BorshSchemaContainer::for_type::<VaultResponse>()),
        ("SwapResponse", BorshSchemaContainer::for_type::<SwapResponse>()),
        (
            "FailureResponse",
            BorshSchemaContainer::for_type::<FailureResponse>(),
        ),
        (
            "AttestationPreimage<VaultResponse>",
            BorshSchemaContainer::for_type::<AttestationPreimage<VaultResponse>>(),
        ),
        (
            "AttestationPreimage<SwapResponse>",
            BorshSchemaContainer::for_type::<AttestationPreimage<SwapResponse>>(),
        ),
        ("SupplyResponse", BorshSchemaContainer::for_type::<SupplyResponse>()),
        (
            "AttestationPreimage<SupplyResponse>",
            BorshSchemaContainer::for_type::<AttestationPreimage<SupplyResponse>>(),
        ),
        ("RedeemResponse", BorshSchemaContainer::for_type::<RedeemResponse>()),
        (
            "AttestationPreimage<RedeemResponse>",
            BorshSchemaContainer::for_type::<AttestationPreimage<RedeemResponse>>(),
        ),
        (
            "AttestationPreimage<FailureResponse>",
            BorshSchemaContainer::for_type::<AttestationPreimage<FailureResponse>>(),
        ),
        (
            "SignBidirectionalMisc",
            BorshSchemaContainer::for_type::<SignBidirectionalMisc>(),
        ),
        ("RespondMisc", BorshSchemaContainer::for_type::<RespondMisc>()),
    ]
}

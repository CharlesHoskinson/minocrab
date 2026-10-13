//! The `@sig-net/midnight` Signet module at **0.24.1** (`a80e98e`, corpus
//! `signet-midnight-integration-v0241`) — the **V1 wire vocabulary** the
//! flush-pattern vault imports (M44): the suffixed record, the domain-tagged
//! Poseidon hashes, the kind-bearing attestation and the empty respond
//! schema.
//!
//! What changed from the `fff3421c` module [`crate::signet`] ports, and why
//! this is a sibling rather than an edit of it: the request record REORDERED
//! (`keyVersion` first, `sender` second, the request nonce GONE, the
//! schemas last with `respondSerializationSchema` pinned to `Bytes<0>`), the
//! request id is no longer a hash of the whole record but of a PREIMAGE
//! struct whose transaction enters as a DIGEST over its used entries
//! (`calculateEvmType2TxParamsDigestV1`), every hash is prefixed with a
//! [`hash_domain`] tag, and the attestation digest commits to the block
//! height, the MPC's verdict ([`output_kind`]) and the output's WIDTH beside
//! the output itself. The `fff3421c` shapes stay in [`crate::signet`] for the
//! test-caller and the Signet-module ports still pinned there; nothing here
//! is shared with them but the transaction-parameter structs
//! ([`EvmType2TxParams`], [`EvmCalldata`]), the ABI word helpers and the
//! ECDSA plumbing, which did not move.
//!
//! Everything in-circuit is a mechanical port of `Signet.compact` at the pin,
//! function for function; the cross-checks are the vault's differential suite
//! (every `send*` circuit's request id and record bytes, every
//! `queueAttestation*`'s digest, PI-equal to compactc's artifact).
//!
//! ```text
//! struct SignBidirectionalEventV1<TxParams, #LenOut, #LenRespond> {   // FAB atoms
//!   keyVersion: Uint<8>;                                              // b1
//!   sender: ContractAddress;                                          // b32 (2 limbs)
//!   path: Bytes<32>;                                                  // b32 (2 limbs)
//!   algo: MPCSignatureAlgorithm;                                      // b1
//!   txParamType: TxParamType;                                         // b1
//!   txParams: TxParams;                                               // EvmType2TxParams
//!   executionDest: Bytes<32>;                                         // b32 (2 limbs)
//!   signatureDest: MPCDestination;                                    // b1
//!   params: Bytes<64>;                                                // b64 (3 limbs)
//!   outputDeserializationSchema: Bytes<LenOut>;                       // bLenOut
//!   respondSerializationSchema: Bytes<LenRespond>;                    // b0 — an atom, no limb
//! }
//! ```

use minocrab::v3::{Circuit3, FieldT, Wire3};
use minocrab::{AlignmentAtom, Fr, Public};
use minocrab_std::v3::hash::upgrade_from_transient;
use minocrab_std::v3::{
    bytes_limbs, bytes_literal_limbs, BoundedUint, Bytes, BytesN, ContractAddress, LedgerRepr,
    Uint, Vis3, B32,
};
use signet_signer_interface::RespondBidirectionalEvent;

use crate::common::{Caip2Id, SigningPath};
pub use crate::signet::{
    abi_word_to_uint128, evm_address_abi_word, numeric_abi_word, verify_attestation_signature,
    EvmCalldata, EvmType2TxParams, RequestId, Secp256k1SigLimbs, MPC_ALGO_ECDSA, MPC_DEST_UNUSED,
    PARAMS_LEN, TX_PARAM_TYPE_EVM_TYPE2,
};

fn bytes(length: u32) -> AlignmentAtom {
    AlignmentAtom::Bytes { length }
}

// ---- the protocol's enums --------------------------------------------------------------

/// `enum HashDomain` — the u8 index every V1 hash is prefixed with. Append
/// variants only, as the source says.
pub mod hash_domain {
    pub const REQUEST_ID: u64 = 0;
    pub const ATTESTATION_DIGEST: u64 = 1;
    pub const EVM_TYPE2_TX_HEADER: u64 = 2;
    pub const EVM_TYPE2_TX_WORD: u64 = 3;
    pub const EVM_TYPE2_TX_ACCESS_ENTRY: u64 = 4;
    pub const EVM_TYPE2_TX_STORAGE_KEY: u64 = 5;
}

/// `enum OutputKind { executed, failed, unviable }` — the MPC's verdict on a
/// request's execution, signed into the attestation digest.
pub mod output_kind {
    pub const EXECUTED: u64 = 0;
    pub const FAILED: u64 = 1;
    pub const UNVIABLE: u64 = 2;
    /// The variant count: an `OutputKind` argument is `less_than 3`.
    pub const COUNT: u128 = 3;
}

/// An `OutputKind` as a wire: a `Uint<0..3>`, which is how compactc
/// constrains a three-variant enum argument.
pub type OutputKind<V> = BoundedUint<{ output_kind::COUNT }, V>;

/// `ethereumCaip2Id()` — `pad(32, "eip155:1")`, the MPC's routing key for
/// EVERY Ethereum network it watches (the transaction's own `chainId` picks
/// the network).
pub const ETHEREUM_CAIP2_ID: &str = "eip155:1";

/// The signing path the protocol reserves for the MPC's response key;
/// `constructSignBidirectionalEventV1` refuses a request naming it.
pub const RESPONSE_KEY_PATH: &str = "midnight response key";

// ---- the output schemas -------------------------------------------------------------

/// An output-deserialisation schema as it sits in the record: a `Bytes<N>`
/// of ANY `N` — one limb at 31 bytes or fewer ([`Bytes`]), FAB-limbed above
/// that ([`BytesN`]). The record is generic over the schema TYPE so one
/// definition serves the vault's 2-, 34-, 36- and 38-byte schemas.
pub trait SchemaBytes<V: Vis3>: Clone {
    /// The schema's byte width.
    const LEN: usize;
    /// Its FAB limb count.
    const LIMBS: usize;
    /// Its FAB atoms (one, of `LEN` bytes).
    fn atoms() -> Vec<AlignmentAtom> {
        vec![bytes(Self::LEN as u32)]
    }
    /// Its limbs in slot order.
    fn limbs(&self) -> Vec<Wire3<FieldT, V>>;
    /// The schema as constant limbs, from its string bytes.
    fn literal(c: &mut Circuit3, bytes: &[u8]) -> Self;
    /// The same limbs at the other visibility (a disclosed record).
    fn from_limbs(limbs: Vec<Wire3<FieldT, V>>) -> Self;
}

impl<V: Vis3, const N: usize> SchemaBytes<V> for Bytes<N, V> {
    const LEN: usize = N;
    const LIMBS: usize = 1;

    fn limbs(&self) -> Vec<Wire3<FieldT, V>> {
        vec![self.field()]
    }

    fn literal(c: &mut Circuit3, bytes: &[u8]) -> Self {
        assert_eq!(bytes.len(), N, "Bytes<{N}> literal length");
        let w = c.constant(Fr::from_le_bytes(bytes).expect("at most 31 bytes fit a limb"));
        Bytes::from_field_unchecked(V::from_public(w))
    }

    fn from_limbs(limbs: Vec<Wire3<FieldT, V>>) -> Self {
        assert_eq!(limbs.len(), 1, "Bytes<{N}> is one limb");
        Bytes::from_field_unchecked(limbs[0])
    }
}

impl<V: Vis3, const N: usize> SchemaBytes<V> for BytesN<V, N> {
    const LEN: usize = N;
    const LIMBS: usize = BytesN::<V, N>::LIMBS;

    fn limbs(&self) -> Vec<Wire3<FieldT, V>> {
        BytesN::limbs(self).to_vec()
    }

    fn literal(c: &mut Circuit3, bytes: &[u8]) -> Self {
        BytesN::literal(c, bytes)
    }

    fn from_limbs(limbs: Vec<Wire3<FieldT, V>>) -> Self {
        BytesN::from_limbs(limbs)
    }
}

/// A SCHEMA LITERAL OF ANY WIDTH — one FAB atom of `N` bytes, `bytes_limbs(N)`
/// limbs, whatever `N` is.
///
/// The compat port picks [`Bytes`] below 31 bytes and [`BytesN`] above it by
/// hand, because each of its five records names its own schema once. The
/// TYPED API cannot: a [`OutputSchema`] is declared from a byte string by a
/// macro, which has no way to branch a type on `BYTES.len()`. So this type
/// spans both sides of the limb boundary and the branch disappears. The
/// limbing rule itself is still `minocrab_std`'s one copy
/// ([`bytes_literal_limbs`]), so a `SchemaLiteral<V, 34>` and a
/// `BytesN<V, 34>` are the same limbs under the same atom — the typed API's
/// records are byte-identical to the compat port's.
#[derive(Clone)]
pub struct SchemaLiteral<V: Vis3, const N: usize> {
    /// Invariant: `limbs.len() == bytes_limbs(N)`, leftover chunk first.
    limbs: Vec<Wire3<FieldT, V>>,
}

impl<V: Vis3, const N: usize> SchemaBytes<V> for SchemaLiteral<V, N> {
    const LEN: usize = N;
    const LIMBS: usize = bytes_limbs(N);

    fn limbs(&self) -> Vec<Wire3<FieldT, V>> {
        self.limbs.clone()
    }

    fn literal(c: &mut Circuit3, bytes: &[u8]) -> Self {
        assert_eq!(bytes.len(), N, "a Bytes<{N}> schema literal is {N} bytes");
        SchemaLiteral {
            limbs: bytes_literal_limbs(c, bytes),
        }
    }

    fn from_limbs(limbs: Vec<Wire3<FieldT, V>>) -> Self {
        assert_eq!(limbs.len(), Self::LIMBS, "a Bytes<{N}> schema is {} limbs", Self::LIMBS);
        SchemaLiteral { limbs }
    }
}

/// THE OUTPUT SCHEMA A SLOT FILES, AS A TYPE — the record's
/// `outputDeserializationSchema`, which is what tells the MPC how to decode
/// the EVM return before it attests it.
///
/// Two things, together, because a schema is used at both visibilities and
/// in both places: the BYTES (the record's literal, and the `LEN` the MPC
/// parses) and the circuit TYPE at a visibility (the record field, private
/// while the request is assembled and public once it is stored). A generic
/// associated type is what lets one name serve both — `S::At<Private>` in
/// the event, `S::At<Public>` in [`EventRecordV1`] — so a filing names its
/// schema ONCE and cannot name two different ones on the two sides.
///
/// Declare one with [`output_schema!`](crate::output_schema); the library's
/// own five are [`schema`].
pub trait OutputSchema: 'static {
    /// The schema as a record field at visibility `V`.
    type At<V: Vis3>: SchemaBytes<V>;

    /// The schema's bytes — the JSON the MPC parses, and the literal the
    /// record carries.
    const BYTES: &'static [u8];
}

/// DECLARE AN OUTPUT SCHEMA: a marker type, its bytes, and its record field
/// type at both visibilities.
///
/// The width is `BYTES.len()`, so the two cannot disagree; the schema string
/// is written out in full rather than assembled from the return type's
/// Solidity spelling and the field's name, because on stable Rust a
/// `&'static str` cannot be concatenated in a `const` — and because it is
/// the WIRE, which a deployment should be able to read off its own source.
#[macro_export]
macro_rules! output_schema {
    ($(
        $(#[$meta:meta])*
        $vis:vis struct $name:ident = $bytes:expr;
    )*) => { $(
        $(#[$meta])*
        $vis struct $name;

        impl $crate::signet_v1::OutputSchema for $name {
            type At<V: ::minocrab_std::v3::Vis3> =
                $crate::signet_v1::SchemaLiteral<V, { $bytes.len() }>;
            const BYTES: &'static [u8] = $bytes;
        }
    )* };
}

/// THE OUTPUT SCHEMAS THE DEPLOYED LINEAGE FILES — the five strings the
/// flush-pattern vault's `send*` circuits put in their records, as types the
/// typed API's filings name.
///
/// They are here rather than beside the calls because a schema is a fact
/// about what the MPC is asked to DECODE, which is the protocol's business:
/// the same `transfer` is filed with the `success` schema by a vault and
/// could be filed with `[]` by a protocol that does not look at the return.
pub mod schema {
    crate::output_schema! {
        /// `[]` — a call whose return is not decoded at all: the MPC attests
        /// an EMPTY `serializedOutput` and the verdict
        /// ([`output_kind`](super::output_kind)) is the whole answer. Two bytes.
        pub struct NoReturn = b"[]";

        /// `[{"name":"success","type":"bool"}]` — the ERC-20 `bool`, named
        /// `success` as the deployed records name it. Thirty-four bytes.
        pub struct Success = b"[{\"name\":\"success\",\"type\":\"bool\"}]";

        /// `[{"name":"amountIn","type":"uint256"}]` — a Uniswap
        /// `exactOutputSingle`'s spend. Thirty-eight bytes.
        pub struct AmountIn = b"[{\"name\":\"amountIn\",\"type\":\"uint256\"}]";

        /// `[{"name":"shares","type":"uint256"}]` — an ERC-4626 `deposit`'s
        /// minted shares. Thirty-six bytes.
        pub struct Shares = b"[{\"name\":\"shares\",\"type\":\"uint256\"}]";

        /// `[{"name":"assets","type":"uint256"}]` — an ERC-4626 `redeem`'s
        /// returned assets. Thirty-six bytes.
        pub struct Assets = b"[{\"name\":\"assets\",\"type\":\"uint256\"}]";
    }
}

// ---- the record ---------------------------------------------------------------------

/// `struct SignBidirectionalEventV1<EvmType2TxParams<WORDS, 0, 0>, LEN_OUT, 0>`
/// — field order is the wire contract (the ledger record layout; the request
/// id hashes a [`RequestIdPreimageV1`] drawn from it, not the record).
/// `respondSerializationSchema` is `Bytes<0>`: present in the alignment,
/// absent from the limbs, so it has no field here.
#[derive(Clone)]
pub struct SignBidirectionalEventV1<V: Vis3, const WORDS: usize, S: SchemaBytes<V>> {
    pub key_version: Wire3<FieldT, V>,
    pub sender: ContractAddress<V>,
    pub path: SigningPath<V>,
    pub algo: Wire3<FieldT, V>,
    pub tx_param_type: Wire3<FieldT, V>,
    pub tx_params: EvmType2TxParams<V, WORDS>,
    pub execution_dest: Caip2Id<V>,
    pub signature_dest: Wire3<FieldT, V>,
    /// `params: Bytes<64>` — 3 limbs `[2, 31, 31]`, zero-fill.
    pub params: BytesN<V, PARAMS_LEN>,
    pub output_deserialization_schema: S,
}

/// The record's FAB slot layout: each field's first slot, by summing the
/// widths before it — the order [`SignBidirectionalEventV1::limbs`] emits.
pub mod layout {
    use minocrab_std::v3::bytes_limbs;

    pub const KEY_VERSION: usize = 0;
    /// `sender: ContractAddress` — `[hi, lo]`.
    pub const SENDER: usize = KEY_VERSION + 1;
    /// `path: Bytes<32>` — `[hi, lo]`.
    pub const PATH: usize = SENDER + 2;
    pub const ALGO: usize = PATH + 2;
    pub const TX_PARAM_TYPE: usize = ALGO + 1;

    // `txParams: EvmType2TxParams<WORDS, 0, 0>`, field by field.
    pub const CHAIN_ID: usize = TX_PARAM_TYPE + 1;
    pub const NONCE: usize = CHAIN_ID + 1;
    pub const MAX_PRIORITY_FEE_PER_GAS: usize = NONCE + 1;
    pub const MAX_FEE_PER_GAS: usize = MAX_PRIORITY_FEE_PER_GAS + 1;
    pub const GAS_LIMIT: usize = MAX_FEE_PER_GAS + 1;
    pub const TO: usize = GAS_LIMIT + 1;
    pub const VALUE: usize = TO + 1;
    pub const CALLDATA_IS_SOME: usize = VALUE + 1;
    pub const SELECTOR: usize = CALLDATA_IS_SOME + 1;
    pub const NO_WORDS: usize = SELECTOR + 1;
    /// `calldata.words` — `[hi, lo]` per word.
    pub const WORDS: usize = NO_WORDS + 1;

    pub const fn word_hi(i: usize) -> usize {
        WORDS + 2 * i
    }
    pub const fn word_lo(i: usize) -> usize {
        word_hi(i) + 1
    }
    pub const fn access_list_entry_count(words: usize) -> usize {
        word_hi(words)
    }
    /// `executionDest: Bytes<32>` — `[hi, lo]`.
    pub const fn execution_dest(words: usize) -> usize {
        access_list_entry_count(words) + 1
    }
    pub const fn signature_dest(words: usize) -> usize {
        execution_dest(words) + 2
    }
    /// `params: Bytes<64>` — 3 limbs.
    pub const fn params(words: usize) -> usize {
        signature_dest(words) + 1
    }
    pub const fn output_deserialization_schema(words: usize) -> usize {
        params(words) + bytes_limbs(super::PARAMS_LEN)
    }
    /// The record's total limb count (30 for the vault's `<2, 34>`).
    pub const fn limbs(words: usize, schema_limbs: usize) -> usize {
        output_deserialization_schema(words) + schema_limbs
    }
}

impl<V: Vis3, const WORDS: usize, S: SchemaBytes<V>> SignBidirectionalEventV1<V, WORDS, S> {
    /// The record's FAB limb count.
    pub const LIMBS: usize = layout::limbs(WORDS, S::LIMBS);

    /// The record's FAB atoms, one per field (the `Bytes<32>`s are one atom,
    /// two limbs; the trailing `Bytes<0>` is one atom, no limb) — 23 for the
    /// vault's 2-word instantiation.
    pub fn atoms() -> Vec<AlignmentAtom> {
        let mut a = vec![
            bytes(1),  // keyVersion
            bytes(32), // sender
            bytes(32), // path
            bytes(1),  // algo
            bytes(1),  // txParamType
            bytes(8),  // chainId
            bytes(8),  // nonce
            bytes(16), // maxPriorityFeePerGas
            bytes(16), // maxFeePerGas
            bytes(8),  // gasLimit
            bytes(20), // to
            bytes(16), // value
            bytes(1),  // calldata.is_some
            bytes(4),  // selector
            bytes(2),  // noWords
        ];
        a.extend(std::iter::repeat_n(bytes(32), WORDS)); // words
        a.push(bytes(1)); // accessListEntryCount
        a.push(bytes(32)); // executionDest
        a.push(bytes(1)); // signatureDest
        a.extend(BytesN::<V, PARAMS_LEN>::atoms()); // params
        a.extend(S::atoms()); // outputDeserializationSchema
        a.push(bytes(0)); // respondSerializationSchema: Bytes<0>
        a
    }

    /// The record's FAB limbs, slot order ([`Self::LIMBS`] of them).
    pub fn limbs(&self) -> Vec<Wire3<FieldT, V>> {
        let mut l = vec![
            self.key_version,
            self.sender.bytes().hi,
            self.sender.bytes().lo,
            self.path.bytes().hi,
            self.path.bytes().lo,
            self.algo,
            self.tx_param_type,
        ];
        l.extend(self.tx_params.limbs());
        l.push(self.execution_dest.bytes().hi);
        l.push(self.execution_dest.bytes().lo);
        l.push(self.signature_dest);
        l.extend(self.params.limbs().iter().copied());
        l.extend(self.output_deserialization_schema.limbs());
        debug_assert_eq!(l.len(), Self::LIMBS);
        l
    }
}

/// What the LEDGER holds a V1 request as: the limbs of
/// [`SignBidirectionalEventV1`] in slot order, under its atoms. The map that
/// stores a request and the circuit that reads it back share this one impl.
pub struct EventRecordV1<const WORDS: usize, S: SchemaBytes<Public>>(Vec<Wire3<FieldT, Public>>, std::marker::PhantomData<S>);

impl<const WORDS: usize, S: SchemaBytes<Public>> EventRecordV1<WORDS, S> {
    pub const LIMBS: usize = layout::limbs(WORDS, S::LIMBS);

    /// A disclosed request as the record the map stores.
    pub fn from_event(event: &SignBidirectionalEventV1<Public, WORDS, S>) -> Self {
        EventRecordV1(event.limbs(), std::marker::PhantomData)
    }

    /// `txParams.nonce` — what `sentVaultNonce` reads off a sent request.
    pub fn nonce(&self) -> Uint<64, Public> {
        Uint::from_field_unchecked(self.0[layout::NONCE])
    }

    /// `path`.
    pub fn path(&self) -> SigningPath<Public> {
        SigningPath(B32 {
            hi: self.0[layout::PATH],
            lo: self.0[layout::PATH + 1],
        })
    }

    /// The raw limbs, slot order.
    pub fn limbs(&self) -> &[Wire3<FieldT, Public>] {
        &self.0
    }
}

impl<const WORDS: usize, S: SchemaBytes<Public>> minocrab_std::v3::ProofWires for EventRecordV1<WORDS, S> {
    fn push_wires(&self, out: &mut Vec<minocrab::v3::Val>) {
        out.extend(self.0.iter().map(|w| w.val()));
    }
}

impl<const WORDS: usize, S: SchemaBytes<Public>> LedgerRepr for EventRecordV1<WORDS, S> {
    fn atoms() -> Vec<AlignmentAtom> {
        SignBidirectionalEventV1::<Public, WORDS, S>::atoms()
    }

    fn push_limbs(&self, _c: &mut Circuit3, limbs: &mut Vec<Wire3<FieldT, Public>>) {
        limbs.extend_from_slice(&self.0);
    }

    fn from_limbs(limbs: Vec<Wire3<FieldT, Public>>) -> Self {
        assert_eq!(limbs.len(), Self::LIMBS, "V1 event record takes {} limbs", Self::LIMBS);
        EventRecordV1(limbs, std::marker::PhantomData)
    }
}

/// `constructSignBidirectionalEventV1(keyVersion, sender, path, ecdsa,
/// evmType2, txParams, executionDest, unused, pad(64, ""), outputSchema)` —
/// the record, with the source's two live asserts (`keyVersion >= 1`, `path
/// != pad(32, "midnight response key")`); the other two (`signatureDest ==
/// unused`, `params == 0`) are over constants here and fold away as they do
/// in compactc's artifact.
pub fn construct_sign_bidirectional_event_v1<V: Vis3, const WORDS: usize, S: SchemaBytes<V>>(
    c: &mut Circuit3,
    key_version: Wire3<FieldT, V>,
    sender: ContractAddress<V>,
    path: SigningPath<V>,
    tx_params: EvmType2TxParams<V, WORDS>,
    execution_dest: Caip2Id<V>,
    output_schema: &[u8],
) -> SignBidirectionalEventV1<V, WORDS, S> {
    construct_sign_bidirectional_event_v1_with(c, key_version, sender, path, tx_params, execution_dest, output_schema, true)
}

/// [`construct_sign_bidirectional_event_v1`] for a path that is a CONSTANT
/// of the contract (its own `pad(32, …)`): the reserved-path assert is over
/// two constants, which compactc folds away, so it is not emitted here
/// either — the circuits' leakage surfaces stay twins. A path derived from
/// an input (a deposit's depositor commitment) takes the checking form.
pub fn construct_sign_bidirectional_event_v1_const_path<V: Vis3, const WORDS: usize, S: SchemaBytes<V>>(
    c: &mut Circuit3,
    key_version: Wire3<FieldT, V>,
    sender: ContractAddress<V>,
    path: SigningPath<V>,
    tx_params: EvmType2TxParams<V, WORDS>,
    execution_dest: Caip2Id<V>,
    output_schema: &[u8],
) -> SignBidirectionalEventV1<V, WORDS, S> {
    construct_sign_bidirectional_event_v1_with(c, key_version, sender, path, tx_params, execution_dest, output_schema, false)
}

#[allow(clippy::too_many_arguments)]
fn construct_sign_bidirectional_event_v1_with<V: Vis3, const WORDS: usize, S: SchemaBytes<V>>(
    c: &mut Circuit3,
    key_version: Wire3<FieldT, V>,
    sender: ContractAddress<V>,
    path: SigningPath<V>,
    tx_params: EvmType2TxParams<V, WORDS>,
    execution_dest: Caip2Id<V>,
    output_schema: &[u8],
    check_path: bool,
) -> SignBidirectionalEventV1<V, WORDS, S> {
    c.region("signet v1: event assembly", |c| {
        let zero = V::from_public(c.constant(0u64));
        let one = V::from_public(c.constant(1u64));

        // assert(keyVersion >= 1): !(keyVersion < 1) over 8 bits.
        let below = c.less_than(key_version, one, 8);
        let at_least_one = c.not(below);
        c.assert_with(at_least_one, Some("keyVersion must be >= 1"));

        // assert(path != pad(32, "midnight response key")).
        if check_path {
            let reserved = B32::pad(c, RESPONSE_KEY_PATH);
            let p = path.bytes();
            let hi_eq = c.test_eq(p.hi, V::from_public(reserved.hi));
            let lo_eq = c.test_eq(p.lo, V::from_public(reserved.lo));
            let both = c.mul(hi_eq, lo_eq);
            let distinct = c.not(both);
            c.assert_with(distinct, Some("path is reserved for the MPC response key"));
        }

        let params = BytesN::from_limbs(vec![zero; BytesN::<V, PARAMS_LEN>::LIMBS]);
        let output_deserialization_schema = S::literal(c, output_schema);
        SignBidirectionalEventV1 {
            key_version,
            sender,
            path,
            algo: V::from_public(c.constant(MPC_ALGO_ECDSA)),
            tx_param_type: V::from_public(c.constant(TX_PARAM_TYPE_EVM_TYPE2)),
            tx_params,
            execution_dest,
            signature_dest: V::from_public(c.constant(MPC_DEST_UNUSED)),
            params,
            output_deserialization_schema,
        }
    })
}

// ---- the transaction digest and the request id ---------------------------------------

/// `calculateEvmType2TxParamsDigestV1(txParams)` over an
/// `EvmType2TxParams<WORDS, 0, 0>`: the head tuple (domain tag, the scalar
/// fields, the calldata's presence, selector and word count, the access-list
/// count) as one Poseidon, then each USED word chained on under its own tag,
/// then `upgradeFromTransient`. The access-list walks are over a zero
/// capacity, so they contribute nothing and the running hash passes through
/// them — exactly as the source's folds over an empty `Vector<0, …>` do.
///
/// An ABSENT calldata enters as `is_some = false`, a zero selector and a zero
/// word count (the source's `calldata.is_some ? … : default`), so the word
/// slots of a `none<EvmCalldata<n>>` are read and skipped, as in compactc.
///
/// `words_used` is the calldata's word count when the CIRCUIT knows it (a
/// literal `noWords` in the source, `0` for `none<EvmCalldata>`): compactc
/// folds the fold's `acc < noWords` against a literal, hashing exactly those
/// words and no select; `None` is the runtime fold, one `less_than` and one
/// select per capacity slot.
pub fn calculate_evm_type2_tx_params_digest_v1<V: Vis3, const WORDS: usize>(
    c: &mut Circuit3,
    tx: &EvmType2TxParams<V, WORDS>,
    words_used: Option<usize>,
) -> B32<V> {
    c.region("signet v1: tx params digest (transientHash)", |c| {
        let zero = V::from_public(c.constant(0u64));
        let is_some = tx.calldata_is_some;
        let no_words = c.cond_select(is_some, tx.calldata.no_words, zero);
        let selector = c.cond_select(is_some, tx.calldata.selector, zero);

        // assert(noWords <= maxCalldataWords); assert(accessListEntryCount <= 0).
        let cap = V::from_public(c.constant(WORDS as u64 + 1));
        let fits = c.less_than(no_words, cap, 16);
        c.assert_with(fits, Some("calldata noWords exceeds capacity"));
        let no_entries = c.test_eq(tx.access_list_entry_count, zero);
        c.assert_with(no_entries, Some("accessListEntryCount exceeds capacity"));

        let header_tag = V::from_public(c.constant(hash_domain::EVM_TYPE2_TX_HEADER));
        let mut acc = c.transient_hash(&[
            header_tag,
            tx.chain_id,
            tx.nonce,
            tx.max_priority_fee_per_gas,
            tx.max_fee_per_gas,
            tx.gas_limit,
            tx.to,
            tx.value,
            is_some,
            selector,
            no_words,
            tx.access_list_entry_count,
        ]);

        let word_tag = V::from_public(c.constant(hash_domain::EVM_TYPE2_TX_WORD));
        match words_used {
            Some(n) => {
                assert!(n <= WORDS, "{n} used words in a {WORDS}-word calldata");
                for word in &tx.calldata.words[..n] {
                    acc = c.transient_hash(&[word_tag, acc, word.hi, word.lo]);
                }
            }
            None => {
                for (i, word) in tx.calldata.words.iter().enumerate() {
                    let index = V::from_public(c.constant(i as u64));
                    let used = c.less_than(index, no_words, 16);
                    let chained = c.transient_hash(&[word_tag, acc, word.hi, word.lo]);
                    acc = c.cond_select(used, chained, acc);
                }
            }
        }
        upgrade_from_transient(c, acc)
    })
}

/// `struct RequestIdPreimageV1` — the fields of a request that name ONE
/// execution, in the record's order, with the transaction as its digest.
#[derive(Clone)]
pub struct RequestIdPreimageV1<V: Vis3> {
    pub key_version: Wire3<FieldT, V>,
    pub sender: ContractAddress<V>,
    pub path: SigningPath<V>,
    pub algo: Wire3<FieldT, V>,
    pub tx_param_type: Wire3<FieldT, V>,
    pub tx_params_digest: B32<V>,
    pub execution_dest: Caip2Id<V>,
}

/// `calculateRequestIdV1(preimage)` —
/// `upgradeFromTransient(transientHash([HashDomain.requestId, preimage]))`
/// over the preimage's twelve field-aligned limbs.
pub fn calculate_request_id_v1<V: Vis3>(c: &mut Circuit3, p: &RequestIdPreimageV1<V>) -> RequestId<V> {
    c.region("signet v1: request id (transientHash)", |c| {
        let tag = V::from_public(c.constant(hash_domain::REQUEST_ID));
        let f = c.transient_hash(&[
            tag,
            p.key_version,
            p.sender.bytes().hi,
            p.sender.bytes().lo,
            p.path.bytes().hi,
            p.path.bytes().lo,
            p.algo,
            p.tx_param_type,
            p.tx_params_digest.hi,
            p.tx_params_digest.lo,
            p.execution_dest.bytes().hi,
            p.execution_dest.bytes().lo,
        ]);
        RequestId(upgrade_from_transient(c, f))
    })
}

/// `calculateEvmType2RequestIdV1(request)` — the preimage drawn from the
/// record with its transaction digested, then [`calculate_request_id_v1`].
/// The source's `txParamType == evmType2` assert is over the constant the
/// constructor wrote and folds away.
pub fn calculate_evm_type2_request_id_v1<V: Vis3, const WORDS: usize, S: SchemaBytes<V>>(
    c: &mut Circuit3,
    request: &SignBidirectionalEventV1<V, WORDS, S>,
    words_used: Option<usize>,
) -> RequestId<V> {
    let tx_params_digest = calculate_evm_type2_tx_params_digest_v1(c, &request.tx_params, words_used);
    calculate_request_id_v1(
        c,
        &RequestIdPreimageV1 {
            key_version: request.key_version,
            sender: request.sender,
            path: request.path,
            algo: request.algo,
            tx_param_type: request.tx_param_type,
            tx_params_digest,
            execution_dest: request.execution_dest,
        },
    )
}

// ---- the attestation ------------------------------------------------------------------

/// `calculateSignetAttestationDigestV1<LEN>(requestId, blockHeight,
/// outputKind, serializedOutput)` — Poseidon over `[HashDomain.attestationDigest,
/// requestId, blockHeight, outputKind, LEN, serializedOutput]`, the width
/// entering as the constant `LEN`, then `upgradeFromTransient`.
/// `output_limbs` are the output's FAB limbs (none for `Bytes<0>`, one for
/// `Bytes<1>`, `[hi, lo]` for `Bytes<32>`).
pub fn calculate_attestation_digest_v1<V: Vis3, const LEN: usize>(
    c: &mut Circuit3,
    request_id: &RequestId<V>,
    block_height: Wire3<FieldT, V>,
    output_kind: Wire3<FieldT, V>,
    output_limbs: &[Wire3<FieldT, V>],
) -> B32<V> {
    calculate_attestation_digest_v1_at(c, request_id, block_height, output_kind, LEN as u64, output_limbs)
}

/// [`calculate_attestation_digest_v1`] WITH THE WIDTH AS DATA.
///
/// The compat port's widths are consts of the circuit, so it names them as
/// const parameters and the type says which `queueAttestation*` it is. The
/// typed API's width is `<Call::Return as AbiReturn>::LEN`, an ASSOCIATED
/// const, and stable Rust cannot pass one as a const-generic argument
/// (`generic_const_exprs`) — so this is the same function with the number in
/// the argument list. It emits the same `constant`, in the same place: the
/// two forms are instruction-identical.
pub fn calculate_attestation_digest_v1_at<V: Vis3>(
    c: &mut Circuit3,
    request_id: &RequestId<V>,
    block_height: Wire3<FieldT, V>,
    output_kind: Wire3<FieldT, V>,
    len: u64,
    output_limbs: &[Wire3<FieldT, V>],
) -> B32<V> {
    c.region("signet v1: attestation digest (transientHash)", |c| {
        let f = attestation_transient_hash_v1(c, request_id, block_height, output_kind, len, output_limbs);
        upgrade_from_transient(c, f)
    })
}

/// [`calculate_attestation_digest_v1`] WITHOUT THE UPGRADE, and with the
/// width as data rather than as a const.
///
/// Two callers need the raw Poseidon output. A refund accepts TWO
/// attestations whose preimages differ in both the width and the limbs — the
/// MPC's verdict over an EMPTY output (width 0) and this call's output at its
/// own width — and Poseidon is not a stream, so one hash cannot cover both:
/// `Pending::refund` hashes it both ways, selects the field element by the
/// verdict and upgrades ONCE, which is also where the const width stops
/// being a const. Everything else goes through
/// [`calculate_attestation_digest_v1`], whose `LEN` keeps the width a fact
/// about the call's type.
pub fn attestation_transient_hash_v1<V: Vis3>(
    c: &mut Circuit3,
    request_id: &RequestId<V>,
    block_height: Wire3<FieldT, V>,
    output_kind: Wire3<FieldT, V>,
    len: u64,
    output_limbs: &[Wire3<FieldT, V>],
) -> Wire3<FieldT, V> {
    let tag = V::from_public(c.constant(hash_domain::ATTESTATION_DIGEST));
    let width = V::from_public(c.constant(len));
    let mut limbs = vec![tag, request_id.bytes().hi, request_id.bytes().lo, block_height, output_kind, width];
    limbs.extend_from_slice(output_limbs);
    c.transient_hash(&limbs)
}

/// `verifyRespondBidirectionalEventV1<LEN>(serializedOutput, event,
/// mpcResponseKey)` — the digest over the event's id, height and verdict
/// with the caller's output, then the ECDSA check over `bigR.x` and `s`
/// (little-endian, as the circuit-input form has them). `serializedOutputLength`
/// and `digest` on the event serve off-chain readers and enter nothing.
pub fn verify_respond_bidirectional_event_v1<V: Vis3, const LEN: usize>(
    c: &mut Circuit3,
    output_limbs: &[Wire3<FieldT, V>],
    event: &RespondBidirectionalEvent<V>,
    mpc_response_key: Wire3<minocrab::v3::Secp256k1PointT, V>,
) -> Wire3<FieldT, V> {
    verify_respond_bidirectional_event_v1_at(c, LEN as u64, output_limbs, event, mpc_response_key)
}

/// [`verify_respond_bidirectional_event_v1`] WITH THE WIDTH AS DATA — the
/// typed API's form, for the same reason
/// [`calculate_attestation_digest_v1_at`] exists: the width is an associated
/// const of the call's return type, and stable Rust cannot pass one as a
/// const-generic argument.
pub fn verify_respond_bidirectional_event_v1_at<V: Vis3>(
    c: &mut Circuit3,
    len: u64,
    output_limbs: &[Wire3<FieldT, V>],
    event: &RespondBidirectionalEvent<V>,
    mpc_response_key: Wire3<minocrab::v3::Secp256k1PointT, V>,
) -> Wire3<FieldT, V> {
    let digest = calculate_attestation_digest_v1_at(
        c,
        &event.request_id,
        event.block_height.field(),
        event.output_kind.field(),
        len,
        output_limbs,
    );
    verify_attestation_signature(
        c,
        &digest,
        &Secp256k1SigLimbs {
            big_r_x: event.signature.big_r.x,
            s: event.signature.s,
        },
        mpc_response_key,
    )
}

/// `checkedTruncationU128(x: Bytes<32>): Uint<128>` — an attested uint256
/// (32 little-endian bytes) narrowed to `Uint<128>`: byte 31 must be zero
/// (the source's "seems pointless but is important" check — without it the
/// `as Uint<128>` cast of a 32-byte string reads a value mod the field),
/// then the low 31 bytes are range-checked to 128 bits.
pub fn checked_truncation_u128<V: Vis3>(c: &mut Circuit3, x: &B32<V>) -> Uint<128, V> {
    let zero = V::from_public(c.constant(0u64));
    let top_zero = c.test_eq(x.hi, zero);
    c.assert_with(top_zero, Some("Value exceeds Uint<128>"));
    Uint::<128, V>::from_field_checked(c, x.lo)
}

/// `pad(32, "eip155:1")` as the record's `executionDest`.
pub fn ethereum_caip2_id<V: Vis3>(c: &mut Circuit3) -> Caip2Id<V> {
    let p = B32::pad(c, ETHEREUM_CAIP2_ID);
    Caip2Id(B32 {
        hi: V::from_public(p.hi),
        lo: V::from_public(p.lo),
    })
}

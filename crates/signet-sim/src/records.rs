//! Mirrors of the Signet request record, as the MPC decodes it.
//!
//! MECHANICAL TRANSLATION of `sig-net/mpc` `chain-signatures/chain-midnight/
//! src/records.rs` at `b940f0a7` (develop, 2026-09-05), plus the stage-7
//! twin ([`SignBidirectionalRecordV2`]) the MPC's own work order describes
//! (notes/borsh-format.org §"THE READER CONSTANTS"): a format-version byte
//! at the head, one response-kind byte where the two schema strings were.
//!
//! AND THE V1 RECORD ([`SignBidirectionalRecordV1`], M44 rung D): the shape
//! `@sig-net/midnight` 0.24.1 ships and the deployed flush-pattern vault
//! files. It is translated from `minocrab_contracts::signet_v1` rather than
//! from the MPC, because the MPC has NOT moved — `sig-net/mpc` at `0d1e5d6e`
//! (develop, 2026-10) still decodes the `fff3421c` record, request nonce and
//! caip2 field included. When its reader lands, this is the twin to diff
//! against.

/// One signing request, the DEPLOYED `SignBidirectionalEvent` record.
#[derive(Debug, Clone, PartialEq)]
pub struct SignBidirectionalRecord {
    /// `ContractAddress { bytes: Bytes<32> }`.
    pub sender: [u8; 32],
    pub request_nonce: u64,
    /// `Uint<8>`: one byte in the preimage.
    pub key_version: u8,
    pub path: [u8; 32],
    /// `MPCSignatureAlgorithm`: ecdsa = 0, reserved = 1.
    pub algo: u8,
    /// `MPCDestination`: unused = 0, reserved = 1.
    pub dest: u8,
    pub params: [u8; 64],
    /// `TxParamType`: evmType2 = 0, reserved = 1.
    pub tx_param_type: u8,
    pub tx_params: EvmType2TxParams,
    /// ASCII `Bytes<32>`, trailing-zero-trimmed on the wire and re-padded to
    /// 32 bytes in the preimage.
    pub caip2_id: [u8; 32],
    /// `Bytes<LenOut>`, runtime width chosen per integrator.
    pub output_deserialization_schema: Vec<u8>,
    /// `Bytes<LenResp>`, runtime width chosen per integrator.
    pub respond_serialization_schema: Vec<u8>,
}

/// The STAGE-7 record: `formatVersion` first, `responseKind` last, every
/// field between identical to the deployed one.
#[derive(Debug, Clone, PartialEq)]
pub struct SignBidirectionalRecordV2 {
    /// `RECORD_FORMAT_VERSION` = 0x80.
    pub format_version: u8,
    pub sender: [u8; 32],
    pub request_nonce: u64,
    pub key_version: u8,
    pub path: [u8; 32],
    pub algo: u8,
    pub dest: u8,
    pub params: [u8; 64],
    pub tx_param_type: u8,
    pub tx_params: EvmType2TxParams,
    pub caip2_id: [u8; 32],
    /// The response kind this request expects.
    pub response_kind: u8,
}

/// The stage-7 format-version byte.
pub const RECORD_FORMAT_VERSION: u8 = 0x80;

/// The V1 record: `keyVersion` FIRST, no request nonce, the destination
/// third from last, and the two schemas at the tail with
/// `respondSerializationSchema` pinned to `Bytes<0>` — an atom with no bytes
/// at all, which is why it has no field here.
///
/// What a reader must do differently from the V2 twin, beyond the field
/// order: the request id is NOT a hash of this record. It is
/// [`crate::hashing::v1::request_id`] over a seven-field preimage whose
/// transaction enters as [`crate::hashing::v1::tx_params_digest`], computed
/// over the USED calldata words only — so two records differing in an unused
/// word slot share an id, and a record cannot be verified by hashing its
/// cell.
#[derive(Debug, Clone, PartialEq)]
pub struct SignBidirectionalRecordV1 {
    /// `Uint<8>`, at least 1 (the constructor asserts it).
    pub key_version: u8,
    /// `ContractAddress { bytes: Bytes<32> }`.
    pub sender: [u8; 32],
    pub path: [u8; 32],
    /// `MPCSignatureAlgorithm`: ecdsa = 0, reserved = 1.
    pub algo: u8,
    /// `TxParamType`: evmType2 = 0, reserved = 1.
    pub tx_param_type: u8,
    pub tx_params: EvmType2TxParams,
    /// `executionDest` — `pad(32, "eip155:1")` for every Ethereum network.
    pub execution_dest: [u8; 32],
    /// `MPCDestination`: unused = 0, reserved = 1.
    pub signature_dest: u8,
    pub params: [u8; 64],
    /// `Bytes<LenOut>`, runtime width chosen per integrator.
    pub output_deserialization_schema: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct EvmType2TxParams {
    pub chain_id: u64,
    pub nonce: u64,
    pub max_priority_fee_per_gas: u128,
    pub max_fee_per_gas: u128,
    pub gas_limit: u64,
    pub to: [u8; 20],
    pub value: u128,
    pub calldata: CompactMaybe<EvmCalldata>,
    pub access_list_entry_count: u8,
    /// `Vector<maxAccessListEntries, _>`: always at capacity, unused slots
    /// zero-filled and still hashed.
    pub access_list: Vec<EvmAccessListEntry>,
}

/// Compact's `Maybe<T>`, which is not `Option<T>`: `value` carries a full
/// default-valued `T` even when `is_some` is false.
#[derive(Debug, Clone, PartialEq)]
pub struct CompactMaybe<T> {
    pub is_some: bool,
    pub value: T,
}

#[derive(Debug, Clone, PartialEq)]
pub struct EvmCalldata {
    pub selector: [u8; 4],
    /// `Uint<16>`: two bytes in the preimage.
    pub no_words: u16,
    /// `Vector<maxCalldataWords, Bytes<32>>`: always at capacity.
    pub words: Vec<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct EvmAccessListEntry {
    pub address: [u8; 20],
    pub storage_key_count: u8,
    /// `Vector<maxStorageKeysPerEntry, Bytes<32>>`: always at capacity.
    pub storage_keys: Vec<[u8; 32]>,
}

/// Notification recovered from the singleton's emitted event payload.
#[derive(Debug, Clone, PartialEq)]
pub struct SignBidirectionalEventNotification {
    pub version: u8,
    pub request_id: [u8; 32],
    pub payload: [u8; 128],
}

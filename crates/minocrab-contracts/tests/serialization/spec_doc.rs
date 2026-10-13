//! The PUBLISHED artifact: `spec/borsh-subset.md`'s offset tables and
//! `spec/vectors/*.json`, generated from the same layout machinery the
//! conformance suite checks (M11 stage 8, notes/borsh-format.org).
//!
//! Everything a reader of the spec could implement against is generated
//! here, from `borsh`'s own schema of the spec types — never typed by hand —
//! so the document cannot drift from the format. What is hand-written in
//! `spec/borsh-subset.md` is PROSE: the subset rule, the reject rules, the
//! padding rule and the rationale. The §5 response-kind table is NOT prose any
//! more — it is the MPC's lookup table and its rows are the contract's own
//! constants, so it is generated like the offsets. Everything between a
//! generated marker pair ([`generated_regions`]) is this module's output, and
//! `spec_document::{the_committed_offset_tables_are_generated,
//! the_committed_kind_table_is_generated}` fail if the committed file
//! disagrees.
//!
//! Regenerate with:
//! `cargo test --release -p minocrab-contracts --test serialization_conformance -- \
//!      --ignored --nocapture regenerate_spec`

use std::fmt::Write as _;
use std::path::PathBuf;

use borsh::schema::BorshSchemaContainer;
use borsh::{BorshSchema, BorshSerialize};
use minocrab_contracts::signet_v1::ETHEREUM_CAIP2_ID;
use minocrab_contracts::{erc20_vault, erc20_vault_pending};
use serde::Serialize;
use sha2::Sha256;
use sha3::{Digest, Keccak256};

use super::deployed;
use super::oracle::{borsh_bytes, layout_rows};
use super::spec_types::*;
use crate::vault::prims::pad32;

/// The marker pair the generated offset tables live between in
/// `spec/borsh-subset.md`. Prose outside them is hand-written and is never
/// touched by the regenerator.
pub const TABLES_BEGIN: &str = "<!-- BEGIN GENERATED: offset tables -->";
pub const TABLES_END: &str = "<!-- END GENERATED: offset tables -->";

/// The marker pair §5's response-kind table lives between. Same rule as
/// [`TABLES_BEGIN`]: the table is generated, the prose around it is not.
pub const KINDS_BEGIN: &str = "<!-- BEGIN GENERATED: response kinds -->";
pub const KINDS_END: &str = "<!-- END GENERATED: response kinds -->";

/// The repository's `spec/` directory.
pub fn spec_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("spec")
}

/// Every generated region of `spec/borsh-subset.md`: `(begin marker, end
/// marker, what belongs between them)`, in document order.
///
/// One list, so the checker and the regenerator cannot cover different sets of
/// regions — the way a region gets added is by adding it here.
pub fn generated_regions() -> Vec<(&'static str, &'static str, String)> {
    vec![
        (KINDS_BEGIN, KINDS_END, response_kinds_markdown()),
        (TABLES_BEGIN, TABLES_END, offset_tables_markdown()),
    ]
}

// ---- §5's response kinds -------------------------------------------------------

/// One row of §5's kind table: a kind number and everything the document — and
/// the MPC's `kind ↦ (ABI types, response shape)` lookup — says about it.
///
/// The prose fields are markdown, because the table is what they are for.
struct KindRow {
    /// `erc20_vault_pending::RESPONSE_KIND_*` — the byte at offset 0 of the
    /// attested output, and the last byte of the stage-7 record.
    number: u32,
    name: &'static str,
    /// The circuit that writes a record carrying this kind, or `—`.
    requested_by: &'static str,
    /// The circuit that settles an attested output carrying it, or `—`.
    settles: &'static str,
    /// The ABI types the MPC decodes the destination-chain return data with.
    abi_types: &'static str,
    /// The response shape it serializes back.
    response: &'static str,
    /// That shape's fixed width — the spec type's own `LEN`, not a numeral.
    len: usize,
}

/// THE KIND TABLE, once. §5's markdown is written from this array and the
/// attested-output vectors' kind bytes are checked against it, so the
/// document, the vectors and the contract's constants cannot say three
/// different things.
///
/// The two asserts are the count-sync: the array is exactly `RESPONSE_KINDS`
/// long, and its numbers are `0..len` in order. `RESPONSE_KINDS` is what the
/// circuits build `Tag<RESPONSE_KINDS>` from, so a sixth kind added to the
/// contract without a row here fails HERE rather than publishing a lookup
/// table that is quietly one row short — which is a response byte the MPC can
/// sign and nobody can decode.
fn kind_rows() -> Vec<KindRow> {
    let rows = vec![
        KindRow {
            number: erc20_vault_pending::RESPONSE_KIND_CLAIM,
            name: "CLAIM",
            requested_by: "`deposit`",
            settles: "`claim`",
            abi_types: "`[bool success]`",
            response: "`VaultResponse { kind: u8, success: bool }`",
            len: VaultResponse::LEN,
        },
        KindRow {
            number: erc20_vault_pending::RESPONSE_KIND_WITHDRAW,
            name: "WITHDRAW",
            requested_by: "`withdraw`",
            settles: "`completeWithdraw`",
            abi_types: "`[bool success]`",
            response: "`VaultResponse { kind: u8, success: bool }`",
            len: VaultResponse::LEN,
        },
        KindRow {
            number: erc20_vault_pending::RESPONSE_KIND_SWAP,
            name: "SWAP",
            requested_by: "`swap`",
            settles: "`completeSwap`",
            abi_types: "`[uint256 amountIn]`",
            response: "`SwapResponse { kind: u8, amount_in: u64 }`",
            len: SwapResponse::LEN,
        },
        KindRow {
            number: erc20_vault_pending::RESPONSE_KIND_FAILURE,
            name: "FAILURE",
            requested_by: "—",
            settles: "`refund`",
            abi_types: "— (never executed)",
            response: "`FailureResponse { kind: u8 }`",
            len: FailureResponse::LEN,
        },
        KindRow {
            number: erc20_vault_pending::RESPONSE_KIND_APPROVE,
            name: "APPROVE",
            requested_by: "`approveRouter`",
            settles: "—",
            abi_types: "`[bool success]`",
            response: "`VaultResponse { kind: u8, success: bool }`",
            len: VaultResponse::LEN,
        },
        KindRow {
            number: erc20_vault_pending::RESPONSE_KIND_SUPPLY,
            name: "SUPPLY",
            requested_by: "`supply`",
            settles: "`completeSupply`",
            abi_types: "`[uint256 shares]`",
            response: "`SupplyResponse { kind: u8, shares: u64 }`",
            len: SupplyResponse::LEN,
        },
        KindRow {
            number: erc20_vault_pending::RESPONSE_KIND_REDEEM,
            name: "REDEEM",
            requested_by: "`redeem`",
            settles: "`completeRedeem`",
            abi_types: "`[uint256 assets]`",
            response: "`RedeemResponse { kind: u8, assets: u64 }`",
            len: RedeemResponse::LEN,
        },
    ];
    assert_eq!(
        rows.len(),
        erc20_vault_pending::RESPONSE_KINDS as usize,
        "§5's kind table has {} rows and the contract declares RESPONSE_KINDS = {}. The table \
         IS the MPC's lookup — add the row beside the constant",
        rows.len(),
        erc20_vault_pending::RESPONSE_KINDS
    );
    for (i, row) in rows.iter().enumerate() {
        assert_eq!(
            row.number as usize,
            i,
            "§5's kind numbers are the wire bytes and must be 0..{} in order; row {i} carries \
             kind {}",
            rows.len(),
            row.number
        );
    }
    rows
}

/// §5's table, as the markdown the document publishes.
fn response_kinds_markdown() -> String {
    let mut out = String::from("\n");
    let _ = writeln!(
        out,
        "| kind | name | requested by | settles | ABI types to decode | attested output | LEN |"
    );
    let _ = writeln!(out, "|---:|---|---|---|---|---|---:|");
    for row in kind_rows() {
        let _ = writeln!(
            out,
            "| {} | `{}` | {} | {} | {} | {} | {} |",
            row.number, row.name, row.requested_by, row.settles, row.abi_types, row.response,
            row.len
        );
    }
    out
}

/// Every kind byte in `vectors` is one §5 declares.
///
/// The loop-closer between the table and the bytes: a vector built with a kind
/// that has no row would publish an attested output no settle circuit accepts
/// and no MPC lookup can decode, and the offset tables beside it would look
/// perfectly well-formed.
fn assert_kinds_are_declared(vectors: &[Vector]) {
    let declared: Vec<u128> = kind_rows().iter().map(|row| u128::from(row.number)).collect();
    for vector in vectors {
        let field = vector
            .fields
            .iter()
            .find(|f| f.path == "kind" || f.path.ends_with(".kind"))
            .unwrap_or_else(|| panic!("{}: an attested output with no kind field", vector.kind));
        let byte = field.number.expect("a kind byte decodes to a number");
        assert!(
            declared.contains(&byte),
            "{}: kind {byte} is not one of §5's declared kinds {declared:?}",
            vector.kind
        );
    }
}

// ---- the offset tables ---------------------------------------------------------

/// Every spec type's byte-offset table, as the markdown the document
/// publishes. Walked out of `borsh::schema_container_of` — the same rows the
/// frozen `LAYOUT_SNAPSHOT` pins.
pub fn offset_tables_markdown() -> String {
    let mut out = String::new();
    for (name, container) in schema_containers() {
        let rows = layout_rows(&container);
        let len: usize = rows.iter().map(|r| r.width).sum();
        let _ = writeln!(out, "\n### `{name}` — {len} bytes\n");
        let _ = writeln!(out, "| offset | width | field | type |");
        let _ = writeln!(out, "|---:|---:|---|---|");
        for row in rows {
            let path = if row.path.is_empty() {
                "(the value)".to_string()
            } else {
                format!("`{}`", row.path)
            };
            let _ = writeln!(
                out,
                "| {} | {} | {path} | `{}` |",
                row.offset, row.width, row.kind
            );
        }
    }
    out
}

// ---- the golden vectors ----------------------------------------------------------

/// One leaf of a vector's value, in DECLARATION ORDER — which is why the
/// value is an array and not a JSON object: the format is ordered and JSON
/// objects are not.
#[derive(Serialize)]
pub struct VectorField {
    pub path: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub offset: usize,
    pub width: usize,
    /// The field's own bytes, in string order.
    pub hex: String,
    /// The little-endian integer those bytes decode to, for the leaves that
    /// are numbers (`bool` decodes to 0 or 1). Absent for byte arrays.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub number: Option<u128>,
}

/// One golden vector: a value, its bytes, its digests and its fields.
#[derive(Serialize)]
pub struct Vector {
    #[serde(rename = "type")]
    pub kind: String,
    pub len: usize,
    /// The canonical Borsh encoding — THE AUTHORITATIVE BYTES of the vector.
    pub hex: String,
    /// `SHA-256(hex)` — what Midnight's `persistentHash` computes over this
    /// preimage.
    pub sha256: String,
    /// `keccak256(hex)` — a checksum an implementation can compare against.
    /// Since the protocol move (M28) it is NOT the request id and NOT the
    /// signed digest: both are Poseidon over field elements (§6a, §5).
    pub keccak256: String,
    /// The 288-byte `Misc` envelope these bytes are logged inside, where
    /// there is one: `pad(32, eventName) ‖ hex ‖ zeros`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub envelope_hex: Option<String>,
    pub fields: Vec<VectorField>,
}

/// A committed vector file: a header saying it is generated, and the
/// vectors.
#[derive(Serialize)]
pub struct VectorFile {
    #[serde(rename = "$comment")]
    pub comment: &'static str,
    pub format: &'static str,
    pub spec: &'static str,
    pub about: &'static str,
    pub vectors: Vec<Vector>,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The little-endian integer a scalar leaf's bytes decode to; `None` for a
/// byte array, whose bytes are its value.
fn number(kind: &str, bytes: &[u8]) -> Option<u128> {
    match kind {
        "bool" | "u8" | "u16" | "u32" | "u64" | "u128" => {
            let mut buf = [0u8; 16];
            buf[..bytes.len()].copy_from_slice(bytes);
            Some(u128::from_le_bytes(buf))
        }
        _ => None,
    }
}

/// A vector of `value`, with its fields walked out of borsh's own schema.
pub fn vector<T: BorshSerialize + BorshSchema>(name: &str, value: &T) -> Vector {
    let bytes = borsh_bytes(value);
    let rows = layout_rows(&BorshSchemaContainer::for_type::<T>());
    assert_eq!(
        rows.iter().map(|r| r.width).sum::<usize>(),
        bytes.len(),
        "{name}: the schema walk and the encoding disagree on the width"
    );
    let fields = rows
        .into_iter()
        .map(|row| {
            let slice = &bytes[row.offset..row.offset + row.width];
            VectorField {
                path: if row.path.is_empty() {
                    "(the value)".to_string()
                } else {
                    row.path.clone()
                },
                number: number(&row.kind, slice),
                kind: row.kind,
                offset: row.offset,
                width: row.width,
                hex: hex(slice),
            }
        })
        .collect();
    Vector {
        kind: name.to_string(),
        len: bytes.len(),
        sha256: hex(&Sha256::digest(&bytes)),
        keccak256: hex(&Keccak256::digest(&bytes)),
        hex: hex(&bytes),
        envelope_hex: None,
        fields,
    }
}

/// A vector for a payload the singleton logs, carrying the 288-byte `Misc`
/// envelope the deployed contract emits around it.
fn misc_vector<T: BorshSerialize + BorshSchema>(name: &str, event: &str, value: &T) -> Vector {
    let mut v = vector(name, value);
    v.envelope_hex = Some(hex(&deployed::misc_envelope(event, &borsh_bytes(value))));
    v
}

// ---- the values the vectors carry ------------------------------------------------
//
// Fixed and deterministic, and realistic where the protocol fixes a value:
// the schema strings and selectors are the DEPLOYED constants
// (`erc20_vault::*`), the enum tags are the first members every deployed
// site uses, and every free byte is a visible pattern so that a wrong offset
// shows up as a wrong byte rather than as a plausible one.

/// `byte i = start + i·step`, the pattern every array in the vectors uses.
fn pattern<const N: usize>(start: u8, step: u8) -> [u8; N] {
    std::array::from_fn(|i| start.wrapping_add((i as u8).wrapping_mul(step)))
}

fn word(tag: u8) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[31] = tag;
    w
}

fn schema<const N: usize>(bytes: &[u8]) -> ByteArray<N> {
    ByteArray(bytes.try_into().expect("schema literal has its declared width"))
}

/// `ethereumCaip2Id()` — a protocol constant, not a free byte, so the vectors
/// carry the real value rather than a pattern.
fn execution_dest() -> [u8; 32] {
    pad32(ETHEREUM_CAIP2_ID)
}

/// The request nonce the V2 vectors carry. The V1 record has no such field —
/// it is one of the two the V1 move dropped — so the V2 vectors, which are a
/// specification, pick one.
const V2_REQUEST_NONCE: u64 = 7;

/// The 2-word V1 request record, in the shape `sendDeposit` writes: a
/// `transfer(to, amount)` calldata signed under a depositor's derived path.
pub fn vault_event_v1() -> VaultEventV1 {
    VaultEventV1 {
        key_version: 1,
        sender: pattern(0x10, 1),
        path: pattern(0x40, 3),
        algo: 0,
        tx_param_type: 0,
        tx_params: EvmType2TxParams2 {
            chain_id: 1,
            nonce: 42,
            max_priority_fee_per_gas: 1_000_000_000,
            max_fee_per_gas: 30_000_000_000,
            gas_limit: 100_000,
            to: pattern(0xa0, 1),
            value: 0,
            calldata: Flagged {
                is_some: true,
                value: EvmCalldata2 {
                    selector: erc20_vault::TRANSFER_SELECTOR,
                    no_words: 2,
                    words: [pattern(0xb0, 1), word(0xff)],
                },
            },
            access_list_entry_count: 0,
        },
        execution_dest: execution_dest(),
        signature_dest: 0,
        params: ByteArray::default(),
        output_deserialization_schema: schema(erc20_vault::VAULT_OUTPUT_SCHEMA),
        respond_serialization_schema: ByteArray::default(),
    }
}

/// The nonce-replacement record: the ONE V1 record whose `calldata.is_some` is
/// 0 — the vector a decoder should test its `Flagged` handling on, because the
/// word slots are still there and still read.
pub fn replace_nonce_event_v1() -> ReplaceNonceEventV1 {
    let e = vault_event_v1();
    ReplaceNonceEventV1 {
        key_version: e.key_version,
        sender: e.sender,
        path: pattern(0x60, 5),
        algo: e.algo,
        tx_param_type: e.tx_param_type,
        tx_params: EvmType2TxParams2 {
            nonce: 46,
            calldata: Flagged {
                is_some: false,
                value: EvmCalldata2 {
                    selector: [0u8; 4],
                    no_words: 0,
                    words: [[0u8; 32]; 2],
                },
            },
            ..e.tx_params
        },
        execution_dest: e.execution_dest,
        signature_dest: e.signature_dest,
        params: e.params,
        output_deserialization_schema: schema(erc20_vault::REPLACE_NONCE_OUTPUT_SCHEMA),
        respond_serialization_schema: ByteArray::default(),
    }
}

/// The 7-word swap record, in the shape `sendSwap` writes.
pub fn swap_event_v1() -> SwapEventV1 {
    let e = vault_event_v1();
    SwapEventV1 {
        key_version: e.key_version,
        sender: e.sender,
        path: e.path,
        algo: e.algo,
        tx_param_type: e.tx_param_type,
        tx_params: EvmType2TxParams7 {
            chain_id: e.tx_params.chain_id,
            nonce: 43,
            max_priority_fee_per_gas: e.tx_params.max_priority_fee_per_gas,
            max_fee_per_gas: e.tx_params.max_fee_per_gas,
            gas_limit: 700_000,
            to: e.tx_params.to,
            value: 0,
            calldata: Flagged {
                is_some: true,
                value: EvmCalldata7 {
                    selector: erc20_vault::EXACT_OUTPUT_SINGLE_SELECTOR,
                    no_words: 7,
                    words: [
                        word(1),
                        word(2),
                        word(3),
                        word(4),
                        word(5),
                        word(6),
                        pattern(0xc0, 1),
                    ],
                },
            },
            access_list_entry_count: 0,
        },
        execution_dest: e.execution_dest,
        signature_dest: e.signature_dest,
        params: e.params,
        output_deserialization_schema: schema(erc20_vault::SWAP_OUTPUT_SCHEMA),
        respond_serialization_schema: ByteArray::default(),
    }
}

/// The supply record, in the shape `sendSupply` writes: an ERC-4626
/// `deposit(assets, receiver)` to the stata token under the vault's own path.
/// The same 2-word middle as [`vault_event_v1`] with the lending schema, so
/// the two vectors differ only in the calldata and the last 36 bytes.
pub fn supply_event_v1() -> SupplyEventV1 {
    let e = vault_event_v1();
    SupplyEventV1 {
        key_version: e.key_version,
        sender: e.sender,
        path: e.path,
        algo: e.algo,
        tx_param_type: e.tx_param_type,
        tx_params: EvmType2TxParams2 {
            nonce: 44,
            gas_limit: 500_000,
            calldata: Flagged {
                is_some: true,
                value: EvmCalldata2 {
                    selector: erc20_vault::DEPOSIT_SELECTOR,
                    no_words: 2,
                    words: [word(0xff), pattern(0xb0, 1)],
                },
            },
            ..e.tx_params
        },
        execution_dest: e.execution_dest,
        signature_dest: e.signature_dest,
        params: e.params,
        output_deserialization_schema: schema(erc20_vault::SUPPLY_OUTPUT_SCHEMA),
        respond_serialization_schema: ByteArray::default(),
    }
}

/// The 3-word redeem record, in the shape `sendRedeem` writes: an ERC-4626
/// `redeem(shares, receiver, owner)` with receiver and owner both the vault.
pub fn redeem_event_v1() -> RedeemEventV1 {
    let e = vault_event_v1();
    RedeemEventV1 {
        key_version: e.key_version,
        sender: e.sender,
        path: e.path,
        algo: e.algo,
        tx_param_type: e.tx_param_type,
        tx_params: EvmType2TxParams3 {
            chain_id: e.tx_params.chain_id,
            nonce: 45,
            max_priority_fee_per_gas: e.tx_params.max_priority_fee_per_gas,
            max_fee_per_gas: e.tx_params.max_fee_per_gas,
            gas_limit: 500_000,
            to: e.tx_params.to,
            value: 0,
            calldata: Flagged {
                is_some: true,
                value: EvmCalldata3 {
                    selector: erc20_vault::REDEEM_SELECTOR,
                    no_words: 3,
                    words: [word(0xfe), pattern(0xb0, 1), pattern(0xb0, 1)],
                },
            },
            access_list_entry_count: 0,
        },
        execution_dest: e.execution_dest,
        signature_dest: e.signature_dest,
        params: e.params,
        output_deserialization_schema: schema(erc20_vault::REDEEM_OUTPUT_SCHEMA),
        respond_serialization_schema: ByteArray::default(),
    }
}

/// The 2-word record as the V2 format writes it: the same values as
/// [`vault_event_v1`], in the V2 field order, with the version byte in front,
/// a request nonce restored and the response kind (0, CLAIM — a `deposit`
/// request) where the output schema was.
///
/// Built FROM the V1 value, so a reader can diff the two vectors and see
/// exactly what the format change is.
pub fn vault_event_v2() -> VaultEventV2 {
    let e = vault_event_v1();
    VaultEventV2 {
        format_version: RECORD_FORMAT_VERSION,
        sender: e.sender,
        request_nonce: V2_REQUEST_NONCE,
        key_version: e.key_version,
        path: e.path,
        algo: e.algo,
        dest: e.signature_dest,
        params: e.params,
        tx_param_type: e.tx_param_type,
        tx_params: e.tx_params,
        caip2_id: e.execution_dest,
        response_kind: erc20_vault_pending::RESPONSE_KIND_CLAIM as u8,
    }
}

/// The 7-word swap record in V2 — response kind 2, SWAP.
pub fn swap_event_v2() -> SwapEventV2 {
    let e = swap_event_v1();
    SwapEventV2 {
        format_version: RECORD_FORMAT_VERSION,
        sender: e.sender,
        request_nonce: V2_REQUEST_NONCE,
        key_version: e.key_version,
        path: e.path,
        algo: e.algo,
        dest: e.signature_dest,
        params: e.params,
        tx_param_type: e.tx_param_type,
        tx_params: e.tx_params,
        caip2_id: e.execution_dest,
        response_kind: erc20_vault_pending::RESPONSE_KIND_SWAP as u8,
    }
}

/// The supply record in V2 — `VaultEventV2` at kind 5, SUPPLY: the lending
/// schema was the only thing that told a supply record from a vault record,
/// and V2 carries neither.
pub fn supply_event_v2() -> VaultEventV2 {
    let e = supply_event_v1();
    VaultEventV2 {
        format_version: RECORD_FORMAT_VERSION,
        sender: e.sender,
        request_nonce: V2_REQUEST_NONCE,
        key_version: e.key_version,
        path: e.path,
        algo: e.algo,
        dest: e.signature_dest,
        params: e.params,
        tx_param_type: e.tx_param_type,
        tx_params: e.tx_params,
        caip2_id: e.execution_dest,
        response_kind: erc20_vault_pending::RESPONSE_KIND_SUPPLY as u8,
    }
}

/// The 3-word redeem record in V2 — kind 6, REDEEM.
pub fn redeem_event_v2() -> RedeemEventV2 {
    let e = redeem_event_v1();
    RedeemEventV2 {
        format_version: RECORD_FORMAT_VERSION,
        sender: e.sender,
        request_nonce: V2_REQUEST_NONCE,
        key_version: e.key_version,
        path: e.path,
        algo: e.algo,
        dest: e.signature_dest,
        params: e.params,
        tx_param_type: e.tx_param_type,
        tx_params: e.tx_params,
        caip2_id: e.execution_dest,
        response_kind: erc20_vault_pending::RESPONSE_KIND_REDEEM as u8,
    }
}

/// A 32-byte checksum over a record's bytes, for the vectors' `request_id`
/// fields.
///
/// NOT the request id: V1 hashes a `RequestIdPreimageV1` with Poseidon, and
/// the V2 lineage hashes the record's field elements. This is a fixed,
/// reproducible 32 bytes to put where a notification carries an id, and the
/// vector files say so.
fn request_id_of<T: BorshSerialize>(value: &T) -> [u8; 32] {
    Keccak256::digest(borsh_bytes(value)).into()
}

// ---- the four files ---------------------------------------------------------------

const COMMENT: &str = "GENERATED — do not edit. Regenerate with: cargo test --release \
                       -p minocrab-contracts --test serialization_conformance -- --ignored \
                       regenerate_spec";
const FORMAT: &str = "borsh-subset-vectors/1";
const SPEC: &str = "spec/borsh-subset.md";

fn file(about: &'static str, vectors: Vec<Vector>) -> String {
    let file = VectorFile {
        comment: COMMENT,
        format: FORMAT,
        spec: SPEC,
        about,
        vectors,
    };
    let mut text = serde_json::to_string_pretty(&file).expect("vectors serialize");
    text.push('\n');
    text
}

/// The leaf table, as values: one vector per primitive the subset admits,
/// plus the two shapes that replace Borsh's variable-width ones.
fn leaves() -> String {
    file(
        "The leaf table as values — one vector per primitive the subset admits. \
         Flagged<T> is the Maybe replacement: a bool tag and an ALWAYS-PRESENT payload, \
         so its width does not depend on the tag (both vectors are 5 bytes).",
        vec![
            vector("bool (false)", &false),
            vector("bool (true)", &true),
            vector("u8", &0xA7u8),
            vector("u16", &0xBEEFu16),
            vector("u32", &0xDEAD_BEEFu32),
            vector("u64", &0x0102_0304_0506_0708u64),
            vector("u128", &0x0102_0304_0506_0708_090A_0B0C_0D0E_0F10u128),
            vector("[u8; 20]", &pattern::<20>(0x01, 7)),
            vector("[u8; 32]", &pattern::<32>(0x02, 11)),
            vector("[u8; 64]", &ByteArray(pattern::<64>(0x03, 13))),
            vector(
                "Flagged<u32> (set)",
                &Flagged {
                    is_some: true,
                    value: 0xDEAD_BEEFu32,
                },
            ),
            vector(
                "Flagged<u32> (unset)",
                &Flagged {
                    is_some: false,
                    value: 0u32,
                },
            ),
        ],
    )
}

/// The request records — the deployed V1 instantiations and the V2 lineage's —
/// and the checksums over their bytes.
fn records() -> String {
    file(
        "The request-record instantiations. DEPLOYED (V1, @sig-net/midnight 0.24.1): the 2-word \
         vault record that sendDeposit / sendWithdraw / sendApprove write, the nonce-replacement \
         record (the one record with NO calldata — calldata.is_some is 0 and the word slots are \
         still read), the 7-word swap record, and the lending pair. Every V1 record ends with a \
         respondSerializationSchema of width 0: a field that is present and empty, not a field \
         that is absent. The request id is NOT a hash of these bytes — V1 hashes a \
         RequestIdPreimageV1 with Poseidon (borsh-subset.md §6a) — and keccak256 here is a \
         checksum. The V2 records carry the same values as their V1 twins in the V2 field order, \
         so the diff is exactly the format change: a formatVersion = 0x80 byte at offset 0, a \
         requestNonce the V1 record does not have, and a 1-byte responseKind where the output \
         schema was.",
        vec![
            vector("VaultEventV1", &vault_event_v1()),
            vector("ReplaceNonceEventV1", &replace_nonce_event_v1()),
            vector("SwapEventV1", &swap_event_v1()),
            vector("SupplyEventV1", &supply_event_v1()),
            vector("RedeemEventV1", &redeem_event_v1()),
            vector("VaultEventV2 (kind 0 CLAIM)", &vault_event_v2()),
            vector("SwapEventV2 (kind 2 SWAP)", &swap_event_v2()),
            vector("VaultEventV2 (kind 5 SUPPLY)", &supply_event_v2()),
            vector("RedeemEventV2 (kind 6 REDEEM)", &redeem_event_v2()),
        ],
    )
}

/// The attested outputs THIS SPEC defines (the V2 lineage), with their signed
/// digest preimages.
fn attested_outputs() -> String {
    let request_id = request_id_of(&vault_event_v2());
    let claim = VaultResponse {
        kind: erc20_vault_pending::RESPONSE_KIND_CLAIM as u8,
        success: true,
    };
    let withdraw = VaultResponse {
        kind: erc20_vault_pending::RESPONSE_KIND_WITHDRAW as u8,
        success: false,
    };
    let swap = SwapResponse {
        kind: erc20_vault_pending::RESPONSE_KIND_SWAP as u8,
        amount_in: 1_234_567_890,
    };
    let failure = FailureResponse {
        kind: erc20_vault_pending::RESPONSE_KIND_FAILURE as u8,
    };
    let supply = SupplyResponse {
        kind: erc20_vault_pending::RESPONSE_KIND_SUPPLY as u8,
        shares: 987_654_321,
    };
    let redeem = RedeemResponse {
        kind: erc20_vault_pending::RESPONSE_KIND_REDEEM as u8,
        assets: 987_654_321,
    };
    let vectors = vec![
        vector("VaultResponse (kind 0, CLAIM, success)", &claim),
        vector("VaultResponse (kind 1, WITHDRAW, failure)", &withdraw),
        vector("SwapResponse (kind 2, SWAP)", &swap),
        vector("FailureResponse (kind 3, FAILURE)", &failure),
        vector("SupplyResponse (kind 5, SUPPLY)", &supply),
        vector("RedeemResponse (kind 6, REDEEM)", &redeem),
        vector(
            "AttestationPreimage<VaultResponse>",
            &AttestationPreimage {
                request_id,
                output: claim,
            },
        ),
        vector(
            "AttestationPreimage<SwapResponse>",
            &AttestationPreimage {
                request_id,
                output: swap,
            },
        ),
        vector(
            "AttestationPreimage<FailureResponse>",
            &AttestationPreimage {
                request_id,
                output: failure,
            },
        ),
        vector(
            "AttestationPreimage<SupplyResponse>",
            &AttestationPreimage {
                request_id,
                output: supply,
            },
        ),
        vector(
            "AttestationPreimage<RedeemResponse>",
            &AttestationPreimage {
                request_id,
                output: redeem,
            },
        ),
    ];
    assert_kinds_are_declared(&vectors);
    file(
        "The V2 lineage's kind-tagged attested outputs and their digest preimages. keccak256 of \
         an AttestationPreimage IS the digest the MPC would sign in that format; request_id here \
         is the checksum over the VaultEventV2 vector in records.json — the V2 record is the one \
         these responses settle, and its last byte is the kind these carry at their first. \
         Nothing is deployed in this format: what is on the wire today is \
         attested-outputs-deployed.json.",
        vectors,
    )
}

/// The attested outputs the DEPLOYED V1 protocol carries.
fn deployed_attested_outputs() -> String {
    file(
        "TODAY'S deployed (V1) attested outputs: a Bytes<LEN> at one of THREE widths, with no \
         kind byte. 0 — the EMPTY output, which queueAttestation0 takes and which EVERY failed \
         or unviable verdict carries whatever the request asked for; 1 — the EVM bool, as a raw \
         byte (any byte is accepted and everything but 0x01 routes to the failure branch: the \
         0x02 hazard); 32 — one big-endian ABI word, which is how V1 carries every uint256 the \
         destination chain returns (the swap's amountIn, the supply's shares, the redeem's \
         assets). There is NO failure sentinel: the superseded 5-byte 0xdeadbeef01 output has no \
         successor, because the verdict and the output's width are signed into the attestation \
         digest instead. That digest is Poseidon over FIELD elements — [HashDomain, requestId, \
         blockHeight, outputKind, LEN, ..output] — so it has no byte preimage and no vector here.",
        vec![
            vector(
                "EmptyOutput",
                &EmptyOutput {
                    output: ByteArray::default(),
                },
            ),
            vector("BoolOutput", &BoolOutput { success: 1 }),
            vector(
                "WordOutput",
                &WordOutput {
                    word: pattern(0x80, 1),
                },
            ),
        ],
    )
}

/// The singleton's logged payloads, inside the envelope they are logged in.
fn misc_payloads() -> String {
    let request_id = request_id_of(&vault_event_v1());
    let mut payload = [0u8; 128];
    // callerAddress ‖ depth ‖ path[0..4] ‖ zeros — the V1 notification
    // payload `construct_notification_v1` packs.
    payload[..32].copy_from_slice(&pattern::<32>(0x10, 1));
    payload[32] = 2;
    payload[33..37].copy_from_slice(b"reqs");
    file(
        "The Signet singleton's Misc log payloads, in the DEPLOYED singleton format. `hex` is \
         the payload; `envelope_hex` is the 288-byte Misc value actually logged — pad(32, \
         eventName) ‖ payload ‖ zeros — and the trailing zeros are REQUIRED, not optional (the \
         deployed circuit hashes them). The request id inside these payloads is a checksum over \
         the V1 VaultEventV1 vector (records.json), standing in for the Poseidon request id a \
         real notification carries.",
        vec![
            misc_vector(
                "SignBidirectionalMisc",
                "SignBidirectionalEvent",
                &SignBidirectionalMisc {
                    version: 1,
                    request_id,
                    payload: ByteArray(payload),
                },
            ),
            misc_vector(
                "RespondMisc",
                "SignatureRespondedEvent",
                &RespondMisc {
                    request_id,
                    big_r_x: pattern(0x20, 5),
                    big_r_y: pattern(0x30, 7),
                    s: pattern(0x50, 3),
                    recovery_id: 1,
                },
            ),
        ],
    )
}

/// Every committed vector file: `(file name, contents)`.
pub fn vector_files() -> Vec<(&'static str, String)> {
    vec![
        ("leaves.json", leaves()),
        ("records.json", records()),
        ("attested-outputs.json", attested_outputs()),
        ("attested-outputs-deployed.json", deployed_attested_outputs()),
        ("misc-payloads.json", misc_payloads()),
    ]
}

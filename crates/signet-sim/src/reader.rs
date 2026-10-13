//! Ledger-tree path walk, record decode and notification decode — what the
//! MPC does between seeing `SignBidirectionalEvent` and knowing what to
//! sign.
//!
//! MECHANICAL TRANSLATION of `chain-midnight/src/reader.rs` at `b940f0a7`
//! (the decode path; the emission decoders it also holds are not needed
//! here), plus the stage-7 decode per the MPC's work order: one leading
//! `uint<u8>` at atom 0 that must be `0x80` (dropped by NAME otherwise —
//! "record-version"), one trailing `uint<u8>` kind where the two schema
//! atoms were, every other offset shifted by one atom.

use midnight_base_crypto::fab::{AlignedValue, AlignmentAtom, AlignmentSegment, ValueAtom};
use midnight_onchain_state::state::StateValue;
use midnight_storage::DefaultDB;

use crate::records::{
    CompactMaybe, EvmAccessListEntry, EvmCalldata, EvmType2TxParams, SignBidirectionalEventNotification,
    SignBidirectionalRecord, SignBidirectionalRecordV1, SignBidirectionalRecordV2, RECORD_FORMAT_VERSION,
};
use crate::hashing::{compute_request_id, legacy_request_id};
use crate::request_id::binary_repr;

/// `TxParamType::evmType2`.
pub const TX_PARAM_TYPE_EVM_TYPE2: u8 = 0;

/// Atoms of an evmType2 record excluding its capacity-scaled vectors.
const EVM_TYPE2_FIXED_ATOMS: usize = 22;
/// `sender` through `calldata.no_words`; the calldata words begin here.
const EVM_TYPE2_HEAD_ATOMS: usize = 18;
/// `caip2_id` and the two schemas.
const EVM_TYPE2_TAIL_ATOMS: usize = 3;
/// `tx_param_type`'s fixed position: eighth field of `SignBidirectionalEvent`.
const TX_PARAM_TYPE_ATOM: usize = 7;

/// The stage-7 shifts: one atom in at the head; the tail is `caip2_id` and
/// the kind.
const V2_HEAD_SHIFT: usize = 1;
const V2_TAIL_ATOMS: usize = 2;

/// V1's head: `keyVersion, sender, path, algo, txParamType`, then the ten
/// scalar `txParams` atoms — so the calldata words begin at atom 15, three
/// in from the deployed record's 18. The V1 head is SHORTER because the
/// request nonce is gone and `params` moved to the tail.
const V1_HEAD_ATOMS: usize = 15;
/// V1's tail after the access-list region: `executionDest, signatureDest,
/// params, outputDeserializationSchema, respondSerializationSchema`.
const V1_TAIL_ATOMS: usize = 5;
/// `txParamType`'s position in a V1 record: the fifth field.
const V1_TX_PARAM_TYPE_ATOM: usize = 4;

pub type Node = StateValue<DefaultDB>;

/// Follow a resolved ledger-tree path to its node, exactly as the generated
/// `ledger()` accessor does. The path is what compactc records for the
/// field (`[4]` flat, `[1, 14]` once chunked past 15 fields); nothing here
/// re-derives the chunk structure.
pub fn signet_field_node_by_path<'a>(root: &'a Node, path: &[u8]) -> anyhow::Result<&'a Node> {
    anyhow::ensure!(!path.is_empty(), "ledger field path is empty");
    let mut node = root;
    for (level, &index) in path.iter().enumerate() {
        let StateValue::Array(children) = node else {
            if index == 0 && level == path.len() - 1 {
                return Ok(node);
            }
            anyhow::bail!("ledger field path {path:?} steps into a non-array at level {level}");
        };
        node = children.get(usize::from(index)).ok_or_else(|| {
            anyhow::anyhow!("ledger field path {path:?} index {index} out of range at level {level}")
        })?;
    }
    Ok(node)
}

/// The declared width of each atom. Signet declares only `Bytes` atoms.
fn declared_widths(cell: &AlignedValue, what: &str) -> anyhow::Result<Vec<u32>> {
    anyhow::ensure!(
        cell.alignment.0.len() == cell.value.0.len(),
        "{what} declares {} alignment segments for {} atoms",
        cell.alignment.0.len(),
        cell.value.0.len()
    );
    cell.alignment
        .0
        .iter()
        .enumerate()
        .map(|(index, segment)| match segment {
            AlignmentSegment::Atom(AlignmentAtom::Bytes { length }) => Ok(*length),
            AlignmentSegment::Atom(atom) => {
                anyhow::bail!("{what} atom {index} is aligned {atom:?}, which carries no byte width")
            }
            AlignmentSegment::Option(_) => {
                anyhow::bail!("{what} atom {index} is an alignment option, which no signet type declares")
            }
        })
        .collect()
}

fn cell_of<'a>(node: &'a Node, what: &str) -> anyhow::Result<&'a AlignedValue> {
    let StateValue::Cell(cell) = node else {
        anyhow::bail!("{what} node is not a cell");
    };
    Ok(cell)
}

struct EvmType2Capacities {
    max_calldata_words: usize,
    max_access_list_entries: usize,
    max_storage_keys_per_entry: usize,
}

/// The capacities, from the widths BETWEEN the head and the tail: `head`
/// atoms precede the calldata words, `tail` atoms follow the access list.
fn evm_type2_capacities(widths: &[u32], head: usize, tail_atoms: usize) -> anyhow::Result<EvmType2Capacities> {
    let fixed = head + 4 + tail_atoms; // head, then count + (address, key count) ≥ 0, then tail
    anyhow::ensure!(
        widths.len() >= fixed.min(EVM_TYPE2_FIXED_ATOMS),
        "request record has {} value atoms, fewer than its fixed fields need",
        widths.len()
    );
    let tail = widths.len() - tail_atoms;
    let mut index = head;
    while index < tail && widths[index] == 32 {
        index += 1;
    }
    let max_calldata_words = index - head;
    anyhow::ensure!(
        index < tail && widths[index] == 1,
        "expected the Bytes<1> access-list entry count after {max_calldata_words} calldata words, found {}",
        widths.get(index).map_or("the record's tail".to_string(), |w| format!("Bytes<{w}>"))
    );
    index += 1;
    let region = &widths[index..tail];
    let max_access_list_entries = region.iter().filter(|width| **width == 20).count();
    let max_storage_keys_per_entry = if max_access_list_entries == 0 {
        anyhow::ensure!(
            region.is_empty(),
            "the access-list region holds {} atoms but declares no Bytes<20> entry address",
            region.len()
        );
        0
    } else {
        anyhow::ensure!(
            region.len() % max_access_list_entries == 0,
            "the access-list region's {} atoms do not divide evenly across {max_access_list_entries} entries",
            region.len()
        );
        let per_entry = region.len() / max_access_list_entries;
        anyhow::ensure!(per_entry >= 2, "each access-list entry needs at least an address and a key count, got {per_entry} atoms");
        per_entry - 2
    };
    Ok(EvmType2Capacities { max_calldata_words, max_access_list_entries, max_storage_keys_per_entry })
}

fn ensure_evm_type2_param_type(cell: &AlignedValue, at: usize) -> anyhow::Result<()> {
    let atom = cell.value.0.get(at).ok_or_else(|| anyhow::anyhow!("request record ends before tx_param_type"))?;
    let tx_param_type = single_byte(atom, "tx_param_type")?;
    anyhow::ensure!(
        tx_param_type == TX_PARAM_TYPE_EVM_TYPE2,
        "unsupported tx_param_type {tx_param_type}: this decoder understands evmType2 (0)"
    );
    Ok(())
}

/// A one-byte atom, stored trailing-zero-trimmed: empty is zero (the
/// ledger's own `u8::try_from(&ValueAtom)` rule).
fn single_byte(atom: &ValueAtom, what: &str) -> anyhow::Result<u8> {
    match atom.0.as_slice() {
        [] => Ok(0),
        [b] => Ok(*b),
        other => anyhow::bail!("{what}: expected one byte, found {}", other.len()),
    }
}

/// Decode a stored DEPLOYED-format request record in one pass.
pub fn decode_record(node: &Node) -> anyhow::Result<SignBidirectionalRecord> {
    let cell = cell_of(node, "request record")?;
    ensure_evm_type2_param_type(cell, TX_PARAM_TYPE_ATOM)?;
    let widths = declared_widths(cell, "request record")?;
    let caps = evm_type2_capacities(&widths, EVM_TYPE2_HEAD_ATOMS, EVM_TYPE2_TAIL_ATOMS)?;
    let cursor = &mut AtomCursor { atoms: &cell.value.0, widths: &widths, pos: 0 };
    let record = SignBidirectionalRecord {
        sender: bytes_n::<32>(cursor, "sender")?,
        request_nonce: uint::<u64>(cursor, 8, "request_nonce")?,
        key_version: uint::<u8>(cursor, 1, "key_version")?,
        path: bytes_n::<32>(cursor, "path")?,
        algo: bounded_enum(cursor, "algo")?,
        dest: bounded_enum(cursor, "dest")?,
        params: bytes_n::<64>(cursor, "params")?,
        tx_param_type: uint::<u8>(cursor, 1, "tx_param_type")?,
        tx_params: decode_tx_params(cursor, &caps)?,
        caip2_id: bytes_n::<32>(cursor, "caip2_id")?,
        output_deserialization_schema: bytes_dyn(cursor, "output_deserialization_schema")?,
        respond_serialization_schema: bytes_dyn(cursor, "respond_serialization_schema")?,
    };
    anyhow::ensure!(cursor.pos == cell.value.0.len(), "request record decoded {} of {} atoms", cursor.pos, cell.value.0.len());
    Ok(record)
}

/// Decode a stored STAGE-7 request record. The version byte is checked
/// first and by name, which is the point of the byte.
pub fn decode_record_v2(node: &Node) -> anyhow::Result<SignBidirectionalRecordV2> {
    let cell = cell_of(node, "request record")?;
    // The head check, by NAME: a one-byte atom holding 0x80. A deployed
    // record (a 32-byte sender first) fails here too, as "record-version".
    let version_atom = cell.value.0.first().ok_or_else(|| anyhow::anyhow!("record-version: request record is empty"))?;
    let head_width = cell.alignment.0.first().and_then(|seg| match seg {
        AlignmentSegment::Atom(AlignmentAtom::Bytes { length }) => Some(*length),
        _ => None,
    });
    anyhow::ensure!(
        head_width == Some(1),
        "record-version: the record's first atom is not a one-byte format version (declared {head_width:?})"
    );
    let format_version = single_byte(version_atom, "format_version").map_err(|e| anyhow::anyhow!("record-version: {e}"))?;
    anyhow::ensure!(
        format_version == RECORD_FORMAT_VERSION,
        "record-version: format version {format_version:#04x} is not {RECORD_FORMAT_VERSION:#04x}"
    );
    ensure_evm_type2_param_type(cell, TX_PARAM_TYPE_ATOM + V2_HEAD_SHIFT)?;
    let widths = declared_widths(cell, "request record")?;
    let caps = evm_type2_capacities(&widths, EVM_TYPE2_HEAD_ATOMS + V2_HEAD_SHIFT, V2_TAIL_ATOMS)?;
    let cursor = &mut AtomCursor { atoms: &cell.value.0, widths: &widths, pos: 0 };
    let record = SignBidirectionalRecordV2 {
        format_version: uint::<u8>(cursor, 1, "format_version")?,
        sender: bytes_n::<32>(cursor, "sender")?,
        request_nonce: uint::<u64>(cursor, 8, "request_nonce")?,
        key_version: uint::<u8>(cursor, 1, "key_version")?,
        path: bytes_n::<32>(cursor, "path")?,
        algo: bounded_enum(cursor, "algo")?,
        dest: bounded_enum(cursor, "dest")?,
        params: bytes_n::<64>(cursor, "params")?,
        tx_param_type: uint::<u8>(cursor, 1, "tx_param_type")?,
        tx_params: decode_tx_params(cursor, &caps)?,
        caip2_id: bytes_n::<32>(cursor, "caip2_id")?,
        response_kind: uint::<u8>(cursor, 1, "response_kind")?,
    };
    anyhow::ensure!(cursor.pos == cell.value.0.len(), "request record decoded {} of {} atoms", cursor.pos, cell.value.0.len());
    Ok(record)
}

/// Decode a stored V1 request record in one pass (M44 rung D).
///
/// NO FORMAT-VERSION BYTE to check by name: V1 leads with `keyVersion`, and
/// what distinguishes it from the stage-7 record is the SHAPE — a one-byte
/// head whose `txParamType` sits at atom 4 rather than 8, and a five-atom
/// tail. A stage-7 record offered here fails `tx_param_type` (it reads the
/// 64-byte `params` atom where V1 expects one byte), which is the drop this
/// decoder owes.
pub fn decode_record_v1(node: &Node) -> anyhow::Result<SignBidirectionalRecordV1> {
    let cell = cell_of(node, "request record")?;
    ensure_evm_type2_param_type(cell, V1_TX_PARAM_TYPE_ATOM)?;
    let widths = declared_widths(cell, "request record")?;
    let caps = evm_type2_capacities(&widths, V1_HEAD_ATOMS, V1_TAIL_ATOMS)?;
    let cursor = &mut AtomCursor { atoms: &cell.value.0, widths: &widths, pos: 0 };
    let record = SignBidirectionalRecordV1 {
        key_version: uint::<u8>(cursor, 1, "key_version")?,
        sender: bytes_n::<32>(cursor, "sender")?,
        path: bytes_n::<32>(cursor, "path")?,
        algo: bounded_enum(cursor, "algo")?,
        tx_param_type: uint::<u8>(cursor, 1, "tx_param_type")?,
        tx_params: decode_tx_params(cursor, &caps)?,
        execution_dest: bytes_n::<32>(cursor, "execution_dest")?,
        signature_dest: bounded_enum(cursor, "signature_dest")?,
        params: bytes_n::<64>(cursor, "params")?,
        output_deserialization_schema: bytes_dyn(cursor, "output_deserialization_schema")?,
    };
    // `respondSerializationSchema` is a `Bytes<0>`: it is in the alignment
    // and contributes no limb, so the cursor still owes it one atom.
    let _ = bytes_dyn(cursor, "respond_serialization_schema")?;
    anyhow::ensure!(
        record.key_version >= 1,
        "key_version 0 is not a signing key generation"
    );
    anyhow::ensure!(cursor.pos == cell.value.0.len(), "request record decoded {} of {} atoms", cursor.pos, cell.value.0.len());
    Ok(record)
}

/// The V1 lookup. The id is NOT a hash of the cell any more: it is
/// `calculateRequestIdV1` over `RequestIdPreimageV1`, whose transaction
/// enters as a digest over the USED calldata words — so the record has to be
/// DECODED before its id can be recomputed, and two records differing only
/// in an unused word slot resolve to the same id.
pub fn resolve_verified_record_v1(map: &Node, request_id: [u8; 32]) -> Resolved<SignBidirectionalRecordV1> {
    let entry = match map_entry(map, request_id) {
        Err(d) => return relabel(d),
        Ok(None) => return Resolved::Absent,
        Ok(Some(entry)) => entry,
    };
    let record = match decode_record_v1(&entry) {
        Ok(record) => record,
        Err(err) => return Resolved::Dropped { reason: "record-undecodable", detail: format!("{err:#}") },
    };
    let recomputed = crate::hashing::v1::record_request_id(&record);
    if recomputed != request_id {
        return Resolved::Dropped {
            reason: "rid-mismatch",
            detail: format!("recomputed {}, so this is a spoofed or wrongly filed record", hex::encode(recomputed)),
        };
    }
    Resolved::Found(Box::new(record))
}

/// The outcome of looking a request id up in a caller's request map.
#[derive(Debug, PartialEq)]
pub enum Resolved<R> {
    /// The record, verified: it hashes to the id it was filed under.
    Found(Box<R>),
    /// The id is not in the caller's index.
    Absent,
    /// The entry exists and must not be signed.
    Dropped { reason: &'static str, detail: String },
}

fn map_entry(map: &Node, request_id: [u8; 32]) -> Result<Option<Node>, Resolved<()>> {
    let StateValue::Map(entries) = map else {
        return Err(Resolved::Dropped {
            reason: "request-index-not-a-map",
            detail: "the caller's requests field is not a map".to_string(),
        });
    };
    Ok(entries.get(&AlignedValue::from(request_id)).map(|entry| (*entry).clone()))
}

fn relabel<R>(dropped: Resolved<()>) -> Resolved<R> {
    match dropped {
        Resolved::Dropped { reason, detail } => Resolved::Dropped { reason, detail },
        Resolved::Absent => Resolved::Absent,
        Resolved::Found(_) => unreachable!("map_entry never yields Found"),
    }
}

/// Which request-id rule a lookup recomputes under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdRule {
    /// Poseidon over the cell's field representation — the MPC at `10360c3c`
    /// and the Signet module since `fff3421c`.
    Transient,
    /// keccak256 over the record's byte layout — the deployed singleton's
    /// callers before `fff3421c` (the captured fixture).
    LegacyKeccak,
}

/// The DEPLOYED-format lookup: the id must be present, decode, and hash back
/// to itself under `rule`.
pub fn resolve_verified_record(map: &Node, request_id: [u8; 32], rule: IdRule) -> Resolved<SignBidirectionalRecord> {
    let entry = match map_entry(map, request_id) {
        Err(d) => return relabel(d),
        Ok(None) => return Resolved::Absent,
        Ok(Some(entry)) => entry,
    };
    let cell = match cell_of(&entry, "request record") {
        Ok(cell) => cell.clone(),
        Err(err) => return Resolved::Dropped { reason: "record-undecodable", detail: format!("{err:#}") },
    };
    let record = match decode_record(&entry) {
        Ok(record) => record,
        Err(err) => return Resolved::Dropped { reason: "record-undecodable", detail: format!("{err:#}") },
    };
    let recomputed = match rule {
        IdRule::Transient => compute_request_id(&cell),
        IdRule::LegacyKeccak => legacy_request_id(&binary_repr(&record)),
    };
    if recomputed != request_id {
        return Resolved::Dropped {
            reason: "rid-mismatch",
            detail: format!("recomputed {}, so this is a spoofed or wrongly filed record", hex::encode(recomputed)),
        };
    }
    Resolved::Found(Box::new(record))
}

/// The STAGE-7 lookup, under the transient rule (the cell's field
/// representation — the format-version and kind bytes are limbs like any
/// other).
pub fn resolve_verified_record_v2(map: &Node, request_id: [u8; 32]) -> Resolved<SignBidirectionalRecordV2> {
    let entry = match map_entry(map, request_id) {
        Err(d) => return relabel(d),
        Ok(None) => return Resolved::Absent,
        Ok(Some(entry)) => entry,
    };
    let cell = match cell_of(&entry, "request record") {
        Ok(cell) => cell.clone(),
        Err(err) => return Resolved::Dropped { reason: "record-undecodable", detail: format!("{err:#}") },
    };
    let record = match decode_record_v2(&entry) {
        Ok(record) => record,
        Err(err) => {
            let text = format!("{err:#}");
            let reason = if text.starts_with("record-version") { "record-version" } else { "record-undecodable" };
            return Resolved::Dropped { reason, detail: text };
        }
    };
    let recomputed = compute_request_id(&cell);
    if recomputed != request_id {
        return Resolved::Dropped {
            reason: "rid-mismatch",
            detail: format!("recomputed {}, so this is a spoofed or wrongly filed record", hex::encode(recomputed)),
        };
    }
    Resolved::Found(Box::new(record))
}

// ---- the notification ------------------------------------------------------------------

/// The singleton's `Misc` payload width.
pub const MISC_PAYLOAD_LEN: usize = 256;

/// Decode the version, request id and packed notification from a singleton
/// event payload.
pub fn decode_notification(emitted: &[u8; MISC_PAYLOAD_LEN]) -> SignBidirectionalEventNotification {
    let mut request_id = [0u8; 32];
    request_id.copy_from_slice(&emitted[1..33]);
    let mut payload = [0u8; 128];
    payload.copy_from_slice(&emitted[33..161]);
    SignBidirectionalEventNotification { version: emitted[0], request_id, payload }
}

/// Maximum ledger-tree path depth the V1 payload carries.
const MAX_LEDGER_PATH_DEPTH: u8 = 4;

/// The V1 notification payload, unpacked: `caller_address(32) ‖
/// requests_path_depth(1) ‖ requests_path(4) ‖ zeros(91)`.
#[derive(Debug, Clone, PartialEq)]
pub struct NotificationV1 {
    pub caller_address: [u8; 32],
    /// Trimmed to its declared depth.
    pub requests_path: Vec<u8>,
}

/// Unpack the caller-supplied payload bytes; fails closed on an unsupported
/// version or a depth outside `1..=4`.
pub fn unpack_notification_v1(notification: &SignBidirectionalEventNotification) -> anyhow::Result<NotificationV1> {
    anyhow::ensure!(
        notification.version == 1,
        "notification version {} is not supported (this decoder understands version 1)",
        notification.version
    );
    let mut caller_address = [0u8; 32];
    caller_address.copy_from_slice(&notification.payload[..32]);
    let depth = notification.payload[32];
    anyhow::ensure!(
        (1..=MAX_LEDGER_PATH_DEPTH).contains(&depth),
        "notification requests_path_depth {depth} is out of range (expected 1 to {MAX_LEDGER_PATH_DEPTH})"
    );
    let requests_path = notification.payload[33..33 + usize::from(depth)].to_vec();
    Ok(NotificationV1 { caller_address, requests_path })
}

// ---- the atom cursor ----------------------------------------------------------------------

struct AtomCursor<'a> {
    atoms: &'a [ValueAtom],
    widths: &'a [u32],
    pos: usize,
}

impl<'a> AtomCursor<'a> {
    /// Consume one atom, asserting the width the ledger declared for it.
    fn shift(&mut self, declared: u32, what: &'static str) -> anyhow::Result<&'a ValueAtom> {
        let atom = self.atoms.get(self.pos).ok_or_else(|| anyhow::anyhow!("atom {} missing: expected {what}", self.pos))?;
        let found = self.widths[self.pos];
        anyhow::ensure!(found == declared, "{what}: atom {} is declared Bytes<{found}>, expected Bytes<{declared}>", self.pos);
        self.pos += 1;
        Ok(atom)
    }

    fn peek_width(&self) -> anyhow::Result<u32> {
        self.widths.get(self.pos).copied().ok_or_else(|| anyhow::anyhow!("atom {} missing: the record ends early", self.pos))
    }
}

/// A `Bytes<N>` atom, stored trailing-zero-trimmed, re-padded to `N`.
fn bytes_n<const N: usize>(cursor: &mut AtomCursor, what: &'static str) -> anyhow::Result<[u8; N]> {
    let atom = cursor.shift(N as u32, what)?;
    anyhow::ensure!(atom.0.len() <= N, "{what}: {} stored bytes exceed the declared {N}", atom.0.len());
    let mut out = [0u8; N];
    out[..atom.0.len()].copy_from_slice(&atom.0);
    Ok(out)
}

/// A `Bytes<L>` atom at whatever width the ledger declares.
fn bytes_dyn(cursor: &mut AtomCursor, what: &'static str) -> anyhow::Result<Vec<u8>> {
    let width = cursor.peek_width()?;
    let atom = cursor.shift(width, what)?;
    anyhow::ensure!(atom.0.len() <= width as usize, "{what}: {} stored bytes exceed the declared {width}", atom.0.len());
    let mut out = atom.0.clone();
    out.resize(width as usize, 0);
    Ok(out)
}

/// A `Uint<8·width>` atom: little-endian, stored trailing-zero-trimmed.
fn uint<T: UintFromLe>(cursor: &mut AtomCursor, width: u32, what: &'static str) -> anyhow::Result<T> {
    let atom = cursor.shift(width, what)?;
    anyhow::ensure!(atom.0.len() <= width as usize, "{what}: {} stored bytes exceed the declared {width}", atom.0.len());
    Ok(T::from_le(&atom.0))
}

fn boolean(cursor: &mut AtomCursor, what: &'static str) -> anyhow::Result<bool> {
    match uint::<u8>(cursor, 1, what)? {
        0 => Ok(false),
        1 => Ok(true),
        other => anyhow::bail!("{what}: {other} is not a boolean"),
    }
}

/// A one-byte enum whose only defined variants are 0 and 1.
fn bounded_enum(cursor: &mut AtomCursor, what: &'static str) -> anyhow::Result<u8> {
    let value = uint::<u8>(cursor, 1, what)?;
    anyhow::ensure!(value <= 1, "{what}: {value} is not a declared variant");
    Ok(value)
}

trait UintFromLe {
    fn from_le(bytes: &[u8]) -> Self;
}
macro_rules! uint_from_le {
    ($($t:ty),*) => {$(
        impl UintFromLe for $t {
            fn from_le(bytes: &[u8]) -> Self {
                let mut buf = [0u8; core::mem::size_of::<$t>()];
                buf[..bytes.len()].copy_from_slice(bytes);
                <$t>::from_le_bytes(buf)
            }
        }
    )*};
}
uint_from_le!(u8, u16, u64, u128);

fn decode_tx_params(cursor: &mut AtomCursor, caps: &EvmType2Capacities) -> anyhow::Result<EvmType2TxParams> {
    let chain_id = uint::<u64>(cursor, 8, "chain_id")?;
    let nonce = uint::<u64>(cursor, 8, "nonce")?;
    let max_priority_fee_per_gas = uint::<u128>(cursor, 16, "max_priority_fee_per_gas")?;
    let max_fee_per_gas = uint::<u128>(cursor, 16, "max_fee_per_gas")?;
    let gas_limit = uint::<u64>(cursor, 8, "gas_limit")?;
    let to = bytes_n::<20>(cursor, "to")?;
    let value = uint::<u128>(cursor, 16, "value")?;
    let is_some = boolean(cursor, "calldata.is_some")?;
    let selector = bytes_n::<4>(cursor, "calldata.selector")?;
    let no_words = uint::<u16>(cursor, 2, "calldata.no_words")?;
    let mut words = Vec::with_capacity(caps.max_calldata_words);
    for _ in 0..caps.max_calldata_words {
        words.push(bytes_n::<32>(cursor, "calldata word")?);
    }
    let access_list_entry_count = uint::<u8>(cursor, 1, "access_list_entry_count")?;
    let mut access_list = Vec::with_capacity(caps.max_access_list_entries);
    for _ in 0..caps.max_access_list_entries {
        let address = bytes_n::<20>(cursor, "access list address")?;
        let storage_key_count = uint::<u8>(cursor, 1, "storage_key_count")?;
        let mut storage_keys = Vec::with_capacity(caps.max_storage_keys_per_entry);
        for _ in 0..caps.max_storage_keys_per_entry {
            storage_keys.push(bytes_n::<32>(cursor, "storage key")?);
        }
        access_list.push(EvmAccessListEntry { address, storage_key_count, storage_keys });
    }
    Ok(EvmType2TxParams {
        chain_id,
        nonce,
        max_priority_fee_per_gas,
        max_fee_per_gas,
        gas_limit,
        to,
        value,
        calldata: CompactMaybe { is_some, value: EvmCalldata { selector, no_words, words } },
        access_list_entry_count,
        access_list,
    })
}

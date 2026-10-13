//! The record's BYTE layout, field by field — `chain-midnight/src/
//! request_id.rs` at `b940f0a7`, kept after the MPC deleted it in #1206 for
//! two reasons: the legacy (keccak) request id the captured fixture carries
//! is keccak over exactly these bytes, and the layout drift gate in
//! minocrab-contracts (`tests/signet_flow.rs`) fills a ledger cell from
//! them. The LIVE request id is [`crate::hashing::compute_request_id`].

use sha3::{Digest, Keccak256};

use crate::records::{
    CompactMaybe, EvmAccessListEntry, EvmCalldata, EvmType2TxParams, SignBidirectionalRecord,
    SignBidirectionalRecordV1, SignBidirectionalRecordV2,
};

/// keccak256 — the LEGACY id rule (see [`crate::hashing::legacy_request_id`]).
pub fn hash_payload(data: &[u8]) -> [u8; 32] {
    Keccak256::digest(data).into()
}

/// The hash preimage: each field at its declared width, in declaration order.
pub fn binary_repr(record: &SignBidirectionalRecord) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&record.sender);
    buf.extend_from_slice(&record.request_nonce.to_le_bytes());
    buf.push(record.key_version);
    buf.extend_from_slice(&record.path);
    buf.push(record.algo);
    buf.push(record.dest);
    buf.extend_from_slice(&record.params);
    buf.push(record.tx_param_type);
    push_tx_params(&mut buf, &record.tx_params);
    buf.extend_from_slice(&record.caip2_id);
    buf.extend_from_slice(&record.output_deserialization_schema);
    buf.extend_from_slice(&record.respond_serialization_schema);
    buf
}

/// The stage-7 preimage.
pub fn binary_repr_v2(record: &SignBidirectionalRecordV2) -> Vec<u8> {
    let mut buf = vec![record.format_version];
    buf.extend_from_slice(&record.sender);
    buf.extend_from_slice(&record.request_nonce.to_le_bytes());
    buf.push(record.key_version);
    buf.extend_from_slice(&record.path);
    buf.push(record.algo);
    buf.push(record.dest);
    buf.extend_from_slice(&record.params);
    buf.push(record.tx_param_type);
    push_tx_params(&mut buf, &record.tx_params);
    buf.extend_from_slice(&record.caip2_id);
    buf.push(record.response_kind);
    buf
}

/// The V1 record's byte layout — what the ledger cell's FAB binary is, so a
/// test can fill a cell from a record and a decoder can be checked against
/// it. NOT a hash preimage: the V1 id hashes
/// [`crate::hashing::v1::request_id`]'s seven-field struct instead.
///
/// `respondSerializationSchema` is `Bytes<0>` and contributes nothing.
pub fn binary_repr_v1(record: &SignBidirectionalRecordV1) -> Vec<u8> {
    let mut buf = vec![record.key_version];
    buf.extend_from_slice(&record.sender);
    buf.extend_from_slice(&record.path);
    buf.push(record.algo);
    buf.push(record.tx_param_type);
    push_tx_params(&mut buf, &record.tx_params);
    buf.extend_from_slice(&record.execution_dest);
    buf.push(record.signature_dest);
    buf.extend_from_slice(&record.params);
    buf.extend_from_slice(&record.output_deserialization_schema);
    buf
}

fn push_tx_params(buf: &mut Vec<u8>, params: &EvmType2TxParams) {
    buf.extend_from_slice(&params.chain_id.to_le_bytes());
    buf.extend_from_slice(&params.nonce.to_le_bytes());
    buf.extend_from_slice(&params.max_priority_fee_per_gas.to_le_bytes());
    buf.extend_from_slice(&params.max_fee_per_gas.to_le_bytes());
    buf.extend_from_slice(&params.gas_limit.to_le_bytes());
    buf.extend_from_slice(&params.to);
    buf.extend_from_slice(&params.value.to_le_bytes());
    push_calldata(buf, &params.calldata);
    buf.push(params.access_list_entry_count);
    for entry in &params.access_list {
        push_access_list_entry(buf, entry);
    }
}

fn push_calldata(buf: &mut Vec<u8>, calldata: &CompactMaybe<EvmCalldata>) {
    buf.push(u8::from(calldata.is_some));
    buf.extend_from_slice(&calldata.value.selector);
    buf.extend_from_slice(&calldata.value.no_words.to_le_bytes());
    for word in &calldata.value.words {
        buf.extend_from_slice(word);
    }
}

fn push_access_list_entry(buf: &mut Vec<u8>, entry: &EvmAccessListEntry) {
    buf.extend_from_slice(&entry.address);
    buf.push(entry.storage_key_count);
    for storage_key in &entry.storage_keys {
        buf.extend_from_slice(storage_key);
    }
}

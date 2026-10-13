//! The bridge between the reference model's requests and the spec types.
//!
//! Each function below reads a [`Sent`]'s OWN FIELDS — its args, its env, its
//! EVM nonce — and fills in the matching spec type, restating the selector,
//! the ABI words, the signing path and the output schema from the contract's
//! constants. It is deliberately NOT built from `Sent::req()`: that is the
//! model's own assembly of the record, and the conformance property is that
//! two independent assemblies produce the same bytes. The model produces the
//! deployed bytes (FAB limbs → `binary_repr`), the spec type produces the
//! Borsh/bincode bytes, and neither side is computed from the other.
//!
//! Read these side by side with `vault::model`'s `Req::limbs`: field for
//! field, in the same order, they must say the same thing.
//!
//! The REQUEST ID is not a function of these bytes and has not been since the
//! protocol move (M28): V1 hashes a `RequestIdPreimageV1` whose transaction
//! enters as a digest (`vault::prims::request_id_v1`). The byte-equality
//! claims below stand; the id claims live in the model.

use minocrab::{AlignmentAtom, Public};
use minocrab_contracts::signet::SignBidirectionalEventV2;
use minocrab_contracts::signet_v1::ETHEREUM_CAIP2_ID;
use minocrab_contracts::{erc20_vault, erc20_vault_pending};
use minocrab_std::v3::LedgerRepr;

use crate::serialization::spec_types;
use crate::serialization::spec_types::{
    ByteArray, EvmCalldata2, EvmCalldata3, EvmCalldata7, EvmType2TxParams2, EvmType2TxParams3,
    EvmType2TxParams7, Flagged, RedeemEventV1, RedeemEventV2, ReplaceNonceEventV1, SupplyEventV1,
    SwapEventV1, SwapEventV2, VaultEventV1, VaultEventV2,
};
use crate::vault::model::{Args, Sent};
use crate::vault::prims::{abi_addr_word, abi_num_word, pad32, user_commitment};

/// A response-kind constant as the wire carries it: one Borsh byte.
pub fn kind(k: u32) -> u8 {
    u8::try_from(k).expect("a Borsh tag is one byte")
}

// ---- the deployed V1 records' atoms and limb counts --------------------------
//
// Taken from the SHIPPING definitions (`erc20_vault::*Record`, the
// `LedgerRepr` the request maps are declared with), so a shape change in the
// contract reaches the spec suite rather than being restated here.

/// The FAB atoms of the 2-word vault record (`<2, 34>`).
pub fn vault_record_atoms() -> Vec<AlignmentAtom> {
    <erc20_vault::VaultRecord as LedgerRepr>::atoms()
}

/// The FAB atoms of the nonce-replacement record (`<2, 2>`).
pub fn replace_nonce_record_atoms() -> Vec<AlignmentAtom> {
    <erc20_vault::ReplaceNonceRecord as LedgerRepr>::atoms()
}

/// The FAB atoms of the 7-word swap record (`<7, 38>`).
pub fn swap_record_atoms() -> Vec<AlignmentAtom> {
    <erc20_vault::SwapRecord as LedgerRepr>::atoms()
}

/// The FAB atoms of the 2-word supply record (`<2, 36>`).
pub fn supply_record_atoms() -> Vec<AlignmentAtom> {
    <erc20_vault::SupplyRecord as LedgerRepr>::atoms()
}

/// The FAB atoms of the 3-word redeem record (`<3, 36>`).
pub fn redeem_record_atoms() -> Vec<AlignmentAtom> {
    <erc20_vault::RedeemRecord as LedgerRepr>::atoms()
}

/// The deployed records' limb counts, so a shape change here is loud.
pub const VAULT_RECORD_LIMBS: usize = erc20_vault::VaultRecord::LIMBS;
pub const REPLACE_NONCE_RECORD_LIMBS: usize = erc20_vault::ReplaceNonceRecord::LIMBS;
pub const SWAP_RECORD_LIMBS: usize = erc20_vault::SwapRecord::LIMBS;
pub const SUPPLY_RECORD_LIMBS: usize = erc20_vault::SupplyRecord::LIMBS;
pub const REDEEM_RECORD_LIMBS: usize = erc20_vault::RedeemRecord::LIMBS;

// ---- the constants every V1 record carries -----------------------------------

/// `MPCSignatureAlgorithm.ecdsa` / `TxParamType.evmType2` /
/// `MPCDestination.unused` — all first enum members, so all zero.
const TAG_FIRST_MEMBER: u8 = 0;

/// `ethereumCaip2Id()` — the `executionDest` of every V1 request the vault
/// makes.
fn execution_dest() -> [u8; 32] {
    pad32(ETHEREUM_CAIP2_ID)
}

fn schema<const N: usize>(bytes: &[u8]) -> ByteArray<N> {
    ByteArray(bytes.try_into().expect("schema literal has its declared width"))
}

/// `numericAbiWord(unlimitedAllowance())`.
fn max_allowance_word() -> [u8; 32] {
    abi_num_word(u128::MAX)
}

/// The EIP-1559 envelope's seven scalar fields, from the request's own args.
struct TxHead {
    chain_id: u64,
    nonce: u64,
    max_priority_fee_per_gas: u128,
    max_fee_per_gas: u128,
    gas_limit: u64,
    to: [u8; 20],
}

fn tx_head(s: &Sent, to: [u8; 20]) -> TxHead {
    let gas = s.args.gas();
    TxHead {
        chain_id: s.env.chain_id,
        nonce: s.evm_nonce,
        max_priority_fee_per_gas: gas.priority_fee,
        max_fee_per_gas: gas.max_fee,
        gas_limit: gas.limit,
        to,
    }
}

/// The 2-word envelope: the head, and a calldata that is always present at
/// the request sites (`value` is 0 at every one of them).
fn tx_params2(head: TxHead, selector: [u8; 4], words: [[u8; 32]; 2]) -> EvmType2TxParams2 {
    EvmType2TxParams2 {
        chain_id: head.chain_id,
        nonce: head.nonce,
        max_priority_fee_per_gas: head.max_priority_fee_per_gas,
        max_fee_per_gas: head.max_fee_per_gas,
        gas_limit: head.gas_limit,
        to: head.to,
        value: 0,
        calldata: Flagged {
            is_some: true,
            value: EvmCalldata2 {
                selector,
                no_words: 2,
                words,
            },
        },
        access_list_entry_count: 0,
    }
}

/// `deposit`'s record: a `transfer(vaultEvmAddress, amount)` request signed
/// under the depositor's own derived key (`path = userCommitment(sk)`).
pub fn deposit_event(s: &Sent) -> VaultEventV1 {
    let Args::Deposit { erc20, amount, .. } = &s.args else {
        panic!("not a deposit request");
    };
    VaultEventV1 {
        key_version: s.env.key_version,
        sender: s.env.self_addr,
        path: user_commitment(&s.sk),
        algo: TAG_FIRST_MEMBER,
        tx_param_type: TAG_FIRST_MEMBER,
        tx_params: tx_params2(
            tx_head(s, *erc20),
            erc20_vault::TRANSFER_SELECTOR,
            [abi_addr_word(&s.env.vault_evm), abi_num_word(*amount)],
        ),
        execution_dest: execution_dest(),
        signature_dest: TAG_FIRST_MEMBER,
        params: ByteArray::default(),
        output_deserialization_schema: schema(erc20_vault::VAULT_OUTPUT_SCHEMA),
        respond_serialization_schema: ByteArray::default(),
    }
}

/// `sendApprove`'s record: an `approve(spender, 2^128 − 1)` request signed
/// under the vault's own path. Both approval starts — the router's and the
/// stata token's — write this one shape.
pub fn approve_event(s: &Sent) -> VaultEventV1 {
    let Args::Approve { erc20, spender, .. } = &s.args else {
        panic!("not an approval request");
    };
    VaultEventV1 {
        key_version: s.env.key_version,
        sender: s.env.self_addr,
        path: pad32(erc20_vault::VAULT_PATH),
        algo: TAG_FIRST_MEMBER,
        tx_param_type: TAG_FIRST_MEMBER,
        tx_params: tx_params2(
            tx_head(s, *erc20),
            erc20_vault::APPROVE_SELECTOR,
            [abi_addr_word(spender), max_allowance_word()],
        ),
        execution_dest: execution_dest(),
        signature_dest: TAG_FIRST_MEMBER,
        params: ByteArray::default(),
        output_deserialization_schema: schema(erc20_vault::VAULT_OUTPUT_SCHEMA),
        respond_serialization_schema: ByteArray::default(),
    }
}

/// `withdraw`'s record: a `transfer(dest, amount)` request signed under the
/// vault's own path.
pub fn withdraw_event(s: &Sent) -> VaultEventV1 {
    let Args::Withdraw { erc20, amount, dest, .. } = &s.args else {
        panic!("not a withdrawal request");
    };
    VaultEventV1 {
        key_version: s.env.key_version,
        sender: s.env.self_addr,
        path: pad32(erc20_vault::VAULT_PATH),
        algo: TAG_FIRST_MEMBER,
        tx_param_type: TAG_FIRST_MEMBER,
        tx_params: tx_params2(
            tx_head(s, *erc20),
            erc20_vault::TRANSFER_SELECTOR,
            [abi_addr_word(dest), abi_num_word(*amount)],
        ),
        execution_dest: execution_dest(),
        signature_dest: TAG_FIRST_MEMBER,
        params: ByteArray::default(),
        output_deserialization_schema: schema(erc20_vault::VAULT_OUTPUT_SCHEMA),
        respond_serialization_schema: ByteArray::default(),
    }
}

/// `sendReplaceNonce`'s record: a value-0 transaction to the vault's own EVM
/// address with NO calldata — the only V1 record whose `calldata.is_some` is
/// 0, so the two word slots are zero and `noWords` is 0. Its output schema is
/// `[]`: the MPC returns nothing.
pub fn replace_nonce_event(s: &Sent) -> ReplaceNonceEventV1 {
    let Args::ReplaceNonce { .. } = &s.args else {
        panic!("not a nonce replacement");
    };
    let head = tx_head(s, s.env.vault_evm);
    ReplaceNonceEventV1 {
        key_version: s.env.key_version,
        sender: s.env.self_addr,
        path: pad32(erc20_vault::VAULT_PATH),
        algo: TAG_FIRST_MEMBER,
        tx_param_type: TAG_FIRST_MEMBER,
        tx_params: EvmType2TxParams2 {
            chain_id: head.chain_id,
            nonce: head.nonce,
            max_priority_fee_per_gas: head.max_priority_fee_per_gas,
            max_fee_per_gas: head.max_fee_per_gas,
            gas_limit: head.gas_limit,
            to: head.to,
            value: 0,
            calldata: Flagged {
                is_some: false,
                value: EvmCalldata2 {
                    selector: [0u8; 4],
                    no_words: 0,
                    words: [[0u8; 32]; 2],
                },
            },
            access_list_entry_count: 0,
        },
        execution_dest: execution_dest(),
        signature_dest: TAG_FIRST_MEMBER,
        params: ByteArray::default(),
        output_deserialization_schema: schema(erc20_vault::REPLACE_NONCE_OUTPUT_SCHEMA),
        respond_serialization_schema: ByteArray::default(),
    }
}

/// `swap`'s record: an `exactOutputSingle(...)` request to the router, seven
/// ABI words (the seventh is the zero `sqrtPriceLimitX96`).
pub fn swap_event(s: &Sent) -> SwapEventV1 {
    let Args::Swap {
        token_in,
        token_out,
        fee,
        amount_out,
        amount_in_max,
        ..
    } = &s.args
    else {
        panic!("not a swap request");
    };
    let head = tx_head(s, s.env.router);
    SwapEventV1 {
        key_version: s.env.key_version,
        sender: s.env.self_addr,
        path: pad32(erc20_vault::VAULT_PATH),
        algo: TAG_FIRST_MEMBER,
        tx_param_type: TAG_FIRST_MEMBER,
        tx_params: EvmType2TxParams7 {
            chain_id: head.chain_id,
            nonce: head.nonce,
            max_priority_fee_per_gas: head.max_priority_fee_per_gas,
            max_fee_per_gas: head.max_fee_per_gas,
            gas_limit: head.gas_limit,
            to: head.to,
            value: 0,
            calldata: Flagged {
                is_some: true,
                value: EvmCalldata7 {
                    selector: erc20_vault::EXACT_OUTPUT_SINGLE_SELECTOR,
                    no_words: 7,
                    words: [
                        abi_addr_word(token_in),
                        abi_addr_word(token_out),
                        abi_num_word(*fee),
                        abi_addr_word(&s.env.vault_evm),
                        abi_num_word(*amount_out),
                        abi_num_word(*amount_in_max),
                        abi_num_word(0),
                    ],
                },
            },
            access_list_entry_count: 0,
        },
        execution_dest: execution_dest(),
        signature_dest: TAG_FIRST_MEMBER,
        params: ByteArray::default(),
        output_deserialization_schema: schema(erc20_vault::SWAP_OUTPUT_SCHEMA),
        respond_serialization_schema: ByteArray::default(),
    }
}

/// `sendSupply`'s record: an ERC-4626 `deposit(assets, receiver)` to the stata
/// token, signed under the vault's own path — the 2-word shape with the
/// lending schema.
pub fn supply_event(s: &Sent) -> SupplyEventV1 {
    let Args::Supply { amount, .. } = &s.args else {
        panic!("not a supply request");
    };
    SupplyEventV1 {
        key_version: s.env.key_version,
        sender: s.env.self_addr,
        path: pad32(erc20_vault::VAULT_PATH),
        algo: TAG_FIRST_MEMBER,
        tx_param_type: TAG_FIRST_MEMBER,
        tx_params: tx_params2(
            tx_head(s, s.env.stata_token),
            erc20_vault::DEPOSIT_SELECTOR,
            [abi_num_word(*amount), abi_addr_word(&s.env.vault_evm)],
        ),
        execution_dest: execution_dest(),
        signature_dest: TAG_FIRST_MEMBER,
        params: ByteArray::default(),
        output_deserialization_schema: schema(erc20_vault::SUPPLY_OUTPUT_SCHEMA),
        respond_serialization_schema: ByteArray::default(),
    }
}

/// `sendRedeem`'s record: an ERC-4626 `redeem(shares, receiver, owner)`
/// request to the stata token — three ABI words, receiver and owner both the
/// vault's own EVM account.
pub fn redeem_event(s: &Sent) -> RedeemEventV1 {
    let Args::Redeem { shares, .. } = &s.args else {
        panic!("not a redeem request");
    };
    let head = tx_head(s, s.env.stata_token);
    RedeemEventV1 {
        key_version: s.env.key_version,
        sender: s.env.self_addr,
        path: pad32(erc20_vault::VAULT_PATH),
        algo: TAG_FIRST_MEMBER,
        tx_param_type: TAG_FIRST_MEMBER,
        tx_params: EvmType2TxParams3 {
            chain_id: head.chain_id,
            nonce: head.nonce,
            max_priority_fee_per_gas: head.max_priority_fee_per_gas,
            max_fee_per_gas: head.max_fee_per_gas,
            gas_limit: head.gas_limit,
            to: head.to,
            value: 0,
            calldata: Flagged {
                is_some: true,
                value: EvmCalldata3 {
                    selector: erc20_vault::REDEEM_SELECTOR,
                    no_words: 3,
                    words: [
                        abi_num_word(*shares),
                        abi_addr_word(&s.env.vault_evm),
                        abi_addr_word(&s.env.vault_evm),
                    ],
                },
            },
            access_list_entry_count: 0,
        },
        execution_dest: execution_dest(),
        signature_dest: TAG_FIRST_MEMBER,
        params: ByteArray::default(),
        output_deserialization_schema: schema(erc20_vault::REDEEM_OUTPUT_SCHEMA),
        respond_serialization_schema: ByteArray::default(),
    }
}

// ---- the V2 records: the same values, the `Pending` lineage's format --------

/// The FAB atoms of the V2 2-word record.
pub fn vault_record_v2_atoms() -> Vec<AlignmentAtom> {
    erc20_vault_pending::VaultEventV2::<Public>::atoms()
}

/// The FAB atoms of the V2 7-word swap record.
pub fn swap_record_v2_atoms() -> Vec<AlignmentAtom> {
    erc20_vault_pending::SwapEventV2::<Public>::atoms()
}

/// The FAB atoms of the V2 3-word redeem record (`Pending<RedeemEnv,
/// RedeemResponse, 3>`). The V2 supply record IS the 2-word record above.
pub fn redeem_record_v2_atoms() -> Vec<AlignmentAtom> {
    SignBidirectionalEventV2::<Public, { erc20_vault::REDEEM_WORDS }>::atoms()
}

/// The V2 records' limb counts (31 and 41).
pub const VAULT_RECORD_V2_LIMBS: usize = SignBidirectionalEventV2::<Public, 2>::LIMBS;
pub const SWAP_RECORD_V2_LIMBS: usize = SignBidirectionalEventV2::<Public, 7>::LIMBS;
pub const REDEEM_RECORD_V2_LIMBS: usize = SignBidirectionalEventV2::<Public, 3>::LIMBS;

/// The V2 twin of a V1 2-word record: the same field VALUES, the V2 field
/// ORDER, a format version in front, a response kind instead of the schema.
///
/// Written as a field-for-field rebuild of the V1 value rather than as a third
/// statement of the middle — the middle is what V2 does NOT change, and saying
/// it twice would let the two drift while both stayed green. `request_nonce`
/// has no V1 field to come from: the V1 record dropped it, and V2 is a
/// specification, so it enters as an argument.
fn vault_v2(e: &VaultEventV1, request_nonce: u64, response_kind: u32) -> VaultEventV2 {
    VaultEventV2 {
        format_version: spec_types::RECORD_FORMAT_VERSION,
        sender: e.sender,
        request_nonce,
        key_version: e.key_version,
        path: e.path,
        algo: e.algo,
        dest: e.signature_dest,
        params: e.params,
        tx_param_type: e.tx_param_type,
        tx_params: e.tx_params,
        caip2_id: e.execution_dest,
        response_kind: kind(response_kind),
    }
}

/// `deposit`'s V2 record — response kind CLAIM.
pub fn deposit_event_v2(s: &Sent, request_nonce: u64) -> VaultEventV2 {
    vault_v2(&deposit_event(s), request_nonce, erc20_vault_pending::RESPONSE_KIND_CLAIM)
}

/// `approveRouter`'s V2 record — response kind APPROVE, the one kind no settle
/// circuit accepts.
pub fn approve_event_v2(s: &Sent, request_nonce: u64) -> VaultEventV2 {
    vault_v2(&approve_event(s), request_nonce, erc20_vault_pending::RESPONSE_KIND_APPROVE)
}

/// `withdraw`'s V2 record — response kind WITHDRAW.
pub fn withdraw_event_v2(s: &Sent, request_nonce: u64) -> VaultEventV2 {
    vault_v2(&withdraw_event(s), request_nonce, erc20_vault_pending::RESPONSE_KIND_WITHDRAW)
}

/// `startSupply`'s V2 record — response kind SUPPLY, in the 2-word type: the
/// V1 supply record's middle is a vault record's middle, and V2 drops the only
/// field that told them apart.
pub fn supply_event_v2(s: &Sent, request_nonce: u64) -> VaultEventV2 {
    let e = supply_event(s);
    VaultEventV2 {
        format_version: spec_types::RECORD_FORMAT_VERSION,
        sender: e.sender,
        request_nonce,
        key_version: e.key_version,
        path: e.path,
        algo: e.algo,
        dest: e.signature_dest,
        params: e.params,
        tx_param_type: e.tx_param_type,
        tx_params: e.tx_params,
        caip2_id: e.execution_dest,
        response_kind: kind(erc20_vault_pending::RESPONSE_KIND_SUPPLY),
    }
}

/// `swap`'s V2 record — response kind SWAP.
pub fn swap_event_v2(s: &Sent, request_nonce: u64) -> SwapEventV2 {
    let e = swap_event(s);
    SwapEventV2 {
        format_version: spec_types::RECORD_FORMAT_VERSION,
        sender: e.sender,
        request_nonce,
        key_version: e.key_version,
        path: e.path,
        algo: e.algo,
        dest: e.signature_dest,
        params: e.params,
        tx_param_type: e.tx_param_type,
        tx_params: e.tx_params,
        caip2_id: e.execution_dest,
        response_kind: kind(erc20_vault_pending::RESPONSE_KIND_SWAP),
    }
}

/// `startRedeem`'s V2 record — response kind REDEEM.
pub fn redeem_event_v2(s: &Sent, request_nonce: u64) -> RedeemEventV2 {
    let e = redeem_event(s);
    RedeemEventV2 {
        format_version: spec_types::RECORD_FORMAT_VERSION,
        sender: e.sender,
        request_nonce,
        key_version: e.key_version,
        path: e.path,
        algo: e.algo,
        dest: e.signature_dest,
        params: e.params,
        tx_param_type: e.tx_param_type,
        tx_params: e.tx_params,
        caip2_id: e.execution_dest,
        response_kind: kind(erc20_vault_pending::RESPONSE_KIND_REDEEM),
    }
}

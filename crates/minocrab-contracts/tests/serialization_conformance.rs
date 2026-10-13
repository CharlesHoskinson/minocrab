//! "Today's protocol is already Borsh" — with a test behind it (M11
//! stage 0, notes/borsh-format.org §Phasing).
//!
//! No circuit changes and no new encoder: every byte string on the DEPLOYED
//! side of an assertion here is produced by the protocol's own code — the
//! FAB `binary_repr` the ledger holds a record as, the `Misc` envelope the
//! singleton logs, the reference model M44's differential suite pins to the
//! compactc artifacts. Every byte string on the SPEC side is produced by
//! borsh's and serde+bincode's derives over the declarations in
//! `serialization::spec_types`.
//!
//! TWO FORMATS are checked, and they are not alternatives: the deployed
//! SIGNET V1 records and outputs (`@sig-net/midnight` 0.24.1, which the
//! flush-pattern vault imports), and the V2 lineage's own format, which
//! nothing has deployed. Only the V1 half has a deployed-bytes claim; the V2
//! half is a specification pinned against borsh's encoder, borsh's schema and
//! the `Pending` records' own FAB alignments.
//!
//! The four properties of the stage, in the order the design of record lists
//! them:
//!
//! a. DUAL ORACLE — `borsh::to_vec(v) == bincode-fixint(v)` for every spec
//!    type over generated values. Together with (b) this is the subset
//!    checker; `subset_boundary` below pins the three known-bad shapes and
//!    which of the two properties catches each.
//! b. FIXED WIDTH — `borsh::object_length(v) == T::LEN` for all v, and
//!    `T::LEN` equals the deployed FAB alignment's own `bin_len`, trailing
//!    `Bytes<0>` atom included (`the_trailing_b0_atom_is_free`). No
//!    value-dependent branching, so every offset is a compile-time constant.
//! c. THE HEADLINE — byte-equality against the deployed protocol's actual
//!    bytes: the five V1 request records, the three V1 attested-output
//!    widths, and the singleton's Misc payloads, the last checked by handing
//!    the bytes to the CORPUS ARTIFACT itself. NEITHER the request id NOR the
//!    attestation digest is a hash of these bytes: both are Poseidon over
//!    FIELD elements, which is why there is no V1 preimage spec type and why
//!    `v1_attestation_digest_commits_to_the_kind_and_the_width` states the
//!    V1 digest in limbs instead.
//! d. SCHEMA DRIFT — the Borsh schema walked into a frozen `(path, kind,
//!    offset, width)` table, the seed of stage 8's published offset tables.
//!
//! Case counts scale with `PROPTEST_CASES` (see `vault::gen::config`).

mod serialization;
mod support;
mod vault;

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use minocrab::{AlignmentAtom, Fr};
use minocrab_contracts::signet_v1::{hash_domain, output_kind};
use minocrab_contracts::{erc20_vault, signet_contract};
use minocrab_sim::v3::simulate;
use proptest::prelude::*;
use proptest::test_runner::TestRunner;
use serde::Serialize;

use serialization::deployed;
use serialization::oracle::{bincode_fixint_bytes, borsh_bytes, layout_rows, schema_len, Row};
use serialization::records;
use serialization::spec_types;
use serialization::spec_types::*;
use vault::gen;
use vault::model::{Args, Env, Gas, Req, Sent};
use vault::prims::{attestation_digest, b32_slots, transient_upgrade, user_commitment};

// ---- (a) + (b): the dual oracle and the fixed width --------------------------

/// Assert everything that holds of a spec-type VALUE regardless of where it
/// came from: the two oracles agree, the width is the type's constant, and
/// the encoding round-trips (bijective on the subset — there is nothing to
/// choose between two encodings of the same value).
fn assert_conformant<T>(value: &T)
where
    T: BorshSerialize + BorshDeserialize + BorshSchema + Serialize + FixedLen + PartialEq + std::fmt::Debug,
{
    let borsh = borsh_bytes(value);
    let bincode = bincode_fixint_bytes(value);
    assert_eq!(
        borsh, bincode,
        "the two oracles disagree — {} has left the circuit-safe subset",
        std::any::type_name::<T>()
    );
    assert_eq!(
        borsh::object_length(value).expect("spec types measure infallibly"),
        T::LEN,
        "{} is not fixed-width at this value",
        std::any::type_name::<T>()
    );
    assert_eq!(borsh.len(), T::LEN);
    let back = T::try_from_slice(&borsh).expect("the encoding decodes");
    assert_eq!(&back, value, "{} does not round-trip", std::any::type_name::<T>());
}

/// A `[u8; N]` for any N (proptest's blanket array impls stop at 32, as
/// serde's do).
fn byte_array<const N: usize>() -> impl Strategy<Value = [u8; N]> {
    proptest::collection::vec(any::<u8>(), N).prop_map(|v| v.try_into().expect("N bytes in, N out"))
}

fn calldata2() -> impl Strategy<Value = EvmCalldata2> {
    (byte_array::<4>(), any::<u16>(), byte_array::<32>(), byte_array::<32>()).prop_map(
        |(selector, no_words, w0, w1)| EvmCalldata2 {
            selector,
            no_words,
            words: [w0, w1],
        },
    )
}

fn calldata7() -> impl Strategy<Value = EvmCalldata7> {
    (
        byte_array::<4>(),
        any::<u16>(),
        proptest::collection::vec(byte_array::<32>(), 7),
    )
        .prop_map(|(selector, no_words, words)| EvmCalldata7 {
            selector,
            no_words,
            words: words.try_into().expect("seven words in, seven out"),
        })
}

fn calldata3() -> impl Strategy<Value = EvmCalldata3> {
    (
        byte_array::<4>(),
        any::<u16>(),
        proptest::collection::vec(byte_array::<32>(), 3),
    )
        .prop_map(|(selector, no_words, words)| EvmCalldata3 {
            selector,
            no_words,
            words: words.try_into().expect("three words in, three out"),
        })
}

/// The seven scalar fields every `EvmType2TxParams` instantiation shares.
type TxHeader = (u64, u64, u128, u128, u64, [u8; 20], u128);

fn tx_header() -> impl Strategy<Value = TxHeader> {
    (
        any::<u64>(),
        any::<u64>(),
        any::<u128>(),
        any::<u128>(),
        any::<u64>(),
        byte_array::<20>(),
        any::<u128>(),
    )
}

fn tx_params2() -> impl Strategy<Value = EvmType2TxParams2> {
    (tx_header(), any::<bool>(), calldata2(), any::<u8>()).prop_map(
        |((chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas, gas_limit, to, value),
          is_some,
          calldata,
          access_list_entry_count)| EvmType2TxParams2 {
            chain_id,
            nonce,
            max_priority_fee_per_gas,
            max_fee_per_gas,
            gas_limit,
            to,
            value,
            calldata: Flagged { is_some, value: calldata },
            access_list_entry_count,
        },
    )
}

fn tx_params7() -> impl Strategy<Value = EvmType2TxParams7> {
    (tx_header(), any::<bool>(), calldata7(), any::<u8>()).prop_map(
        |((chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas, gas_limit, to, value),
          is_some,
          calldata,
          access_list_entry_count)| EvmType2TxParams7 {
            chain_id,
            nonce,
            max_priority_fee_per_gas,
            max_fee_per_gas,
            gas_limit,
            to,
            value,
            calldata: Flagged { is_some, value: calldata },
            access_list_entry_count,
        },
    )
}

fn tx_params3() -> impl Strategy<Value = EvmType2TxParams3> {
    (tx_header(), any::<bool>(), calldata3(), any::<u8>()).prop_map(
        |((chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas, gas_limit, to, value),
          is_some,
          calldata,
          access_list_entry_count)| EvmType2TxParams3 {
            chain_id,
            nonce,
            max_priority_fee_per_gas,
            max_fee_per_gas,
            gas_limit,
            to,
            value,
            calldata: Flagged { is_some, value: calldata },
            access_list_entry_count,
        },
    )
}

// ---- the spec types' own strategies ------------------------------------------

/// The V1 record's shared fields: everything before `txParams` and everything
/// after it but the output schema. Generated, not fixed, at every one — the
/// conformance properties are about the ENCODING, so they must hold at every
/// value the type admits and not only at the values the protocol writes.
type RecordHeaderV1 = (u8, [u8; 32], [u8; 32], u8, u8, [u8; 32], u8, [u8; 64]);

fn record_header_v1() -> impl Strategy<Value = RecordHeaderV1> {
    (
        any::<u8>(),
        byte_array::<32>(),
        byte_array::<32>(),
        any::<u8>(),
        any::<u8>(),
        byte_array::<32>(),
        any::<u8>(),
        byte_array::<64>(),
    )
}

/// The five V1 record strategies. A macro rather than five copies because the
/// five differ in exactly two places — the `txParams` instantiation and the
/// output schema's width — and a copy is a place for them to differ in a
/// third.
macro_rules! v1_record_strategy {
    ($name:ident -> $ty:ident, $params:ident, $schema:literal) => {
        fn $name() -> impl Strategy<Value = $ty> {
            (record_header_v1(), $params(), byte_array::<$schema>()).prop_map(
                |(
                    (
                        key_version,
                        sender,
                        path,
                        algo,
                        tx_param_type,
                        execution_dest,
                        signature_dest,
                        params,
                    ),
                    tx_params,
                    out_schema,
                )| $ty {
                    key_version,
                    sender,
                    path,
                    algo,
                    tx_param_type,
                    tx_params,
                    execution_dest,
                    signature_dest,
                    params: ByteArray(params),
                    output_deserialization_schema: ByteArray(out_schema),
                    // `Bytes<0>`: there is no value to generate.
                    respond_serialization_schema: ByteArray::default(),
                },
            )
        }
    };
}

v1_record_strategy!(vault_event_v1 -> VaultEventV1, tx_params2, 34);
v1_record_strategy!(replace_nonce_event_v1 -> ReplaceNonceEventV1, tx_params2, 2);
v1_record_strategy!(swap_event_v1 -> SwapEventV1, tx_params7, 38);
v1_record_strategy!(supply_event_v1 -> SupplyEventV1, tx_params2, 36);
v1_record_strategy!(redeem_event_v1 -> RedeemEventV1, tx_params3, 36);

/// The V2 record's header — the `fff3421c` field order the V2 format keeps,
/// which is NOT the V1 order ([`record_header_v1`]): the sender first, the
/// request nonce after it, `params` before `txParamType`.
type RecordHeaderV2 = ([u8; 32], u64, u8, [u8; 32], u8, u8, [u8; 64], u8, [u8; 32]);

fn record_header_v2() -> impl Strategy<Value = RecordHeaderV2> {
    (
        byte_array::<32>(),
        any::<u64>(),
        any::<u8>(),
        byte_array::<32>(),
        any::<u8>(),
        any::<u8>(),
        byte_array::<64>(),
        any::<u8>(),
        byte_array::<32>(),
    )
}

fn redeem_event_v2() -> impl Strategy<Value = RedeemEventV2> {
    (record_header_v2(), tx_params3(), any::<u8>()).prop_map(
        |((sender, request_nonce, key_version, path, algo, dest, params, tx_param_type, caip2_id),
          tx_params,
          response_kind)| RedeemEventV2 {
            format_version: RECORD_FORMAT_VERSION,
            sender,
            request_nonce,
            key_version,
            path,
            algo,
            dest,
            params: ByteArray(params),
            tx_param_type,
            tx_params,
            caip2_id,
            response_kind,
        },
    )
}

/// The V2 2-word record: the same generated middle, a version byte and a kind
/// byte, both generated — see [`record_header_v1`] on why.
fn vault_event_v2() -> impl Strategy<Value = VaultEventV2> {
    (record_header_v2(), tx_params2(), any::<u8>(), any::<u8>()).prop_map(
        |((sender, request_nonce, key_version, path, algo, dest, params, tx_param_type, caip2_id),
          tx_params,
          format_version,
          response_kind)| VaultEventV2 {
            format_version,
            sender,
            request_nonce,
            key_version,
            path,
            algo,
            dest,
            params: ByteArray(params),
            tx_param_type,
            tx_params,
            caip2_id,
            response_kind,
        },
    )
}

/// The V2 7-word record. See [`vault_event_v2`].
fn swap_event_v2() -> impl Strategy<Value = SwapEventV2> {
    (record_header_v2(), tx_params7(), any::<u8>(), any::<u8>()).prop_map(
        |((sender, request_nonce, key_version, path, algo, dest, params, tx_param_type, caip2_id),
          tx_params,
          format_version,
          response_kind)| SwapEventV2 {
            format_version,
            sender,
            request_nonce,
            key_version,
            path,
            algo,
            dest,
            params: ByteArray(params),
            tx_param_type,
            tx_params,
            caip2_id,
            response_kind,
        },
    )
}

fn sign_bidirectional_misc() -> impl Strategy<Value = SignBidirectionalMisc> {
    (any::<u8>(), byte_array::<32>(), byte_array::<128>()).prop_map(|(version, request_id, payload)| {
        SignBidirectionalMisc {
            version,
            request_id,
            payload: ByteArray(payload),
        }
    })
}

fn respond_misc() -> impl Strategy<Value = RespondMisc> {
    (
        byte_array::<32>(),
        byte_array::<32>(),
        byte_array::<32>(),
        byte_array::<32>(),
        any::<u8>(),
    )
        .prop_map(|(request_id, big_r_x, big_r_y, s, recovery_id)| RespondMisc {
            request_id,
            big_r_x,
            big_r_y,
            s,
            recovery_id,
        })
}

// ---- the deployed side: generated requests -----------------------------------
//
// `vault::gen`'s scenario strategies went with the seventeen-circuit vault
// (M44), so the generators here are LOCAL and small: they take one of the
// model's canonical requests — `Sent::deposit()` and its siblings, each a
// request followed through the flush queue — and replace the values a caller
// controls. The model then assembles the record from them (`Sent::req()`), the
// bridge in `serialization::records` assembles the spec type from them, and
// the property is that the two agree.

/// The caller-controlled values of a request: the sender and the requester's
/// secret, five EVM addresses, the chain id / key version / EVM nonce, the gas
/// parameters, and three amounts.
type RequestValues = (
    [u8; 32],
    [u8; 32],
    Vec<[u8; 20]>,
    (u64, u8, u64),
    (u64, u128, u128),
    (u128, u128, u128),
);

fn request_values() -> impl Strategy<Value = RequestValues> {
    (
        byte_array::<32>(),
        byte_array::<32>(),
        // Five DISTINCT slots rather than one address reused, so a record that
        // puts the right kind of value in the wrong field still fails.
        proptest::collection::vec(byte_array::<20>(), 5),
        // `keyVersion >= 1` is guarded by `constructSignBidirectionalEventV1`.
        (any::<u64>(), 1u8..=u8::MAX, any::<u64>()),
        (any::<u64>(), any::<u128>(), any::<u128>()),
        (any::<u128>(), any::<u128>(), any::<u128>()),
    )
}

/// One of the model's canonical requests with [`request_values`] substituted
/// in — the amounts, addresses, nonces and gas a caller or the configuration
/// supplies, at every value the record's fields admit.
fn sent(base: fn() -> Sent) -> impl Strategy<Value = Sent> {
    request_values().prop_map(
        move |(
            self_addr,
            sk,
            addr,
            (chain_id, key_version, evm_nonce),
            (limit, max_fee, priority_fee),
            (first, second, third),
        )| {
            let mut s = base();
            s.env.self_addr = self_addr;
            s.env.chain_id = chain_id;
            s.env.key_version = key_version;
            s.env.vault_evm = addr[0];
            s.env.router = addr[1];
            s.env.stata_token = addr[2];
            s.sk = sk;
            s.evm_nonce = evm_nonce;
            let gas = Gas {
                limit,
                max_fee,
                priority_fee,
            };
            match &mut s.args {
                Args::ReplaceNonce { gas: g } => *g = gas,
                Args::Approve { erc20, spender, gas: g } => {
                    *erc20 = addr[3];
                    *spender = addr[4];
                    *g = gas;
                }
                Args::Deposit { erc20, amount, path, gas: g } => {
                    *erc20 = addr[3];
                    *amount = first;
                    // The deposit's path IS the requester's commitment; the
                    // bridge recomputes it from `sk`, so the two must agree.
                    *path = user_commitment(&sk);
                    *g = gas;
                }
                Args::Withdraw { erc20, amount, dest, gas: g } => {
                    *erc20 = addr[3];
                    *amount = first;
                    *dest = addr[4];
                    *g = gas;
                }
                Args::Swap {
                    token_in,
                    token_out,
                    fee,
                    amount_out,
                    amount_in_max,
                    gas: g,
                } => {
                    *token_in = addr[3];
                    *token_out = addr[4];
                    *fee = first;
                    *amount_out = second;
                    *amount_in_max = third;
                    *g = gas;
                }
                Args::Supply { amount, gas: g } => {
                    *amount = first;
                    *g = gas;
                }
                Args::Redeem { shares, gas: g } => {
                    *shares = first;
                    *g = gas;
                }
            }
            s
        },
    )
}

/// `Sent::replace_nonce` needs the request it replaces, so it is not a bare
/// `fn() -> Sent` like the others.
fn replace_nonce_base() -> Sent {
    Sent::replace_nonce(&Sent::withdraw())
}

proptest! {
    #![proptest_config(gen::config())]

    /// (a) + (b) for the five deployed V1 request records.
    #[test]
    fn records_are_conformant(
        vault in vault_event_v1(),
        replace_nonce in replace_nonce_event_v1(),
        swap in swap_event_v1(),
        supply in supply_event_v1(),
        redeem in redeem_event_v1(),
    ) {
        assert_conformant(&vault);
        assert_conformant(&replace_nonce);
        assert_conformant(&swap);
        assert_conformant(&supply);
        assert_conformant(&redeem);
    }

    /// (a) + (b) for the V2 lineage's three request records.
    #[test]
    fn v2_records_are_conformant(
        vault in vault_event_v2(),
        swap in swap_event_v2(),
        redeem in redeem_event_v2(),
    ) {
        assert_conformant(&vault);
        assert_conformant(&swap);
        assert_conformant(&redeem);
    }

    /// (a) + (b) for the three V1 attested-output widths.
    ///
    /// [`EmptyOutput`] has no value to generate — zero bytes is its only
    /// value — which is itself the fixed-width property at its limit.
    #[test]
    fn attested_outputs_are_conformant(
        success in any::<u8>(),
        word in byte_array::<32>(),
    ) {
        assert_conformant(&empty_output());
        assert_conformant(&BoolOutput { success });
        assert_conformant(&WordOutput { word });
    }

    /// (a) + (b) for the V2 lineage's kind-tagged outputs and their digest
    /// preimages.
    #[test]
    fn v2_attested_outputs_are_conformant(
        request_id in byte_array::<32>(),
        success in any::<bool>(),
        amount in any::<u64>(),
        kind in any::<u8>(),
    ) {
        let vault = VaultResponse { kind, success };
        let swap = SwapResponse { kind, amount_in: amount };
        let supply = SupplyResponse { kind, shares: amount };
        let redeem = RedeemResponse { kind, assets: amount };
        let failure = FailureResponse { kind };
        assert_conformant(&vault);
        assert_conformant(&swap);
        assert_conformant(&supply);
        assert_conformant(&redeem);
        assert_conformant(&failure);
        assert_conformant(&AttestationPreimage { request_id, output: vault });
        assert_conformant(&AttestationPreimage { request_id, output: swap });
        assert_conformant(&AttestationPreimage { request_id, output: supply });
        assert_conformant(&AttestationPreimage { request_id, output: redeem });
        assert_conformant(&AttestationPreimage { request_id, output: failure });
    }

    /// (a) + (b) for the singleton's three Misc payloads (`respond` and
    /// `respondBidirectional` share one shape).
    #[test]
    fn misc_payloads_are_conformant(
        sign in sign_bidirectional_misc(),
        respond in respond_misc(),
    ) {
        assert_conformant(&sign);
        assert_conformant(&respond);
    }
}

/// The only [`EmptyOutput`] there is.
fn empty_output() -> EmptyOutput {
    EmptyOutput {
        output: ByteArray::default(),
    }
}

/// (b), the other half: each `LEN` is the DEPLOYED shape's own width, not an
/// arithmetic claim of ours. `Alignment::bin_len` is what the ledger and the
/// hash chips size a record by.
#[test]
fn lens_match_the_deployed_alignments() {
    // The five deployed V1 records. `fab_len` sums the atom list INCLUDING the
    // trailing `Bytes<0>` — so this equality is also the claim the zero-width
    // `respond_serialization_schema` field makes, and `the_trailing_b0_atom_is_free`
    // below isolates it.
    assert_eq!(
        VaultEventV1::LEN,
        deployed::fab_len(&records::vault_record_atoms()),
        "vault record width"
    );
    assert_eq!(
        ReplaceNonceEventV1::LEN,
        deployed::fab_len(&records::replace_nonce_record_atoms()),
        "nonce-replacement record width"
    );
    assert_eq!(
        SwapEventV1::LEN,
        deployed::fab_len(&records::swap_record_atoms()),
        "swap record width"
    );
    assert_eq!(
        SupplyEventV1::LEN,
        deployed::fab_len(&records::supply_record_atoms()),
        "supply record width"
    );
    assert_eq!(
        RedeemEventV1::LEN,
        deployed::fab_len(&records::redeem_record_atoms()),
        "redeem record width"
    );

    // The numbers, so a shape change is a number in a diff. The siblings are
    // written as the vault record plus their own difference: one more ABI word
    // (32) and a schema two bytes longer, or the `[]` schema of a nonce
    // replacement.
    assert_eq!(VaultEventV1::LEN, 362);
    assert_eq!(erc20_vault::VAULT_SCHEMA_LEN, 34);
    assert_eq!(SupplyEventV1::LEN, 362 + 2);
    assert_eq!(RedeemEventV1::LEN, 362 + 32 + 2);
    assert_eq!(
        ReplaceNonceEventV1::LEN,
        362 - erc20_vault::VAULT_SCHEMA_LEN + erc20_vault::REPLACE_NONCE_SCHEMA_LEN
    );
    assert_eq!(SwapEventV1::LEN, 526);

    // The keccak blocks those widths buy, counted by the ROW MODEL's own
    // `keccak_blocks` (rate 136, at least one padding byte) rather than by a
    // second copy of the padding rule. The V1 swap record is FOUR blocks where
    // the `fff3421c` one was five: pinning `respondSerializationSchema` to
    // `Bytes<0>` took 571 bytes to 526, under the 544-byte boundary — the
    // block the V2 format was going to save, saved by the protocol instead.
    use minocrab_sim::v3::rowcost::keccak_blocks as blocks;
    assert_eq!(blocks(VaultEventV1::LEN), 3);
    assert_eq!(blocks(SwapEventV1::LEN), 4);
    assert_eq!((blocks(VaultEventV2::LEN), blocks(SwapEventV2::LEN)), (3, 4));

    // The three V1 attested-output widths, which are the three
    // `queueAttestation*` circuits.
    assert_eq!(EmptyOutput::LEN, 0);
    assert_eq!(BoolOutput::LEN, 1);
    assert_eq!(WordOutput::LEN, 32);

    // THE V2 LINEAGE, and the same statement about a SHIPPING alignment: the
    // widths are the `Pending` records' own atom lists, not our arithmetic.
    assert_eq!(
        VaultEventV2::LEN,
        deployed::fab_len(&records::vault_record_v2_atoms()),
        "V2 vault record width"
    );
    assert_eq!(
        SwapEventV2::LEN,
        deployed::fab_len(&records::swap_record_v2_atoms()),
        "V2 swap record width"
    );
    assert_eq!(
        RedeemEventV2::LEN,
        deployed::fab_len(&records::redeem_record_v2_atoms()),
        "V2 redeem record width"
    );
    assert_eq!(VaultEventV2::LEN, 338);
    assert_eq!(SwapEventV2::LEN, 498);
    assert_eq!(RedeemEventV2::LEN, 370);

    // The V2 lineage's shapes, and the digest preimages they define. These are
    // THE SPEC — nothing has settled in this format — so what pins them is
    // borsh's own encoder, borsh's own schema, and the circuit that hashes
    // them.
    assert_eq!(VaultResponse::LEN, 2);
    assert_eq!(SwapResponse::LEN, 9);
    assert_eq!(FailureResponse::LEN, 1);
    assert_eq!(SupplyResponse::LEN, 9);
    assert_eq!(RedeemResponse::LEN, 9);
    assert_eq!(AttestationPreimage::<VaultResponse>::LEN, 34);
    assert_eq!(AttestationPreimage::<SwapResponse>::LEN, 41);
    assert_eq!(AttestationPreimage::<FailureResponse>::LEN, 33);
    assert_eq!(AttestationPreimage::<SupplyResponse>::LEN, 41);
    assert_eq!(AttestationPreimage::<RedeemResponse>::LEN, 41);

    // The Misc payloads sit inside `Bytes<256>` after the 32-byte name.
    assert_eq!(SignBidirectionalMisc::LEN, 161);
    assert_eq!(RespondMisc::LEN, 129);
    const { assert!(SignBidirectionalMisc::LEN + 32 <= minocrab_contracts::events::MISC_SIZE) };
    const { assert!(RespondMisc::LEN + 32 <= minocrab_contracts::events::MISC_SIZE) };
}

/// The trailing `respondSerializationSchema: Bytes<0>` is an ATOM that costs
/// nothing — which is what licenses spelling it as a zero-width
/// [`ByteArray<0>`] rather than leaving it out of the spec type.
///
/// Three statements, one per thing a reader could doubt: the atom is really
/// there and really zero-length; dropping it from the alignment changes no
/// width; and it consumes no limb, so the record's limb count is the same with
/// it as without.
#[test]
fn the_trailing_b0_atom_is_free() {
    for (name, atoms, len, limbs) in [
        ("vault", records::vault_record_atoms(), VaultEventV1::LEN, records::VAULT_RECORD_LIMBS),
        (
            "replaceNonce",
            records::replace_nonce_record_atoms(),
            ReplaceNonceEventV1::LEN,
            records::REPLACE_NONCE_RECORD_LIMBS,
        ),
        ("swap", records::swap_record_atoms(), SwapEventV1::LEN, records::SWAP_RECORD_LIMBS),
        ("supply", records::supply_record_atoms(), SupplyEventV1::LEN, records::SUPPLY_RECORD_LIMBS),
        ("redeem", records::redeem_record_atoms(), RedeemEventV1::LEN, records::REDEEM_RECORD_LIMBS),
    ] {
        assert_eq!(
            atoms.last(),
            Some(&AlignmentAtom::Bytes { length: 0 }),
            "{name}: the last atom is not the Bytes<0>"
        );
        assert_eq!(
            deployed::fab_len(&atoms[..atoms.len() - 1]),
            len,
            "{name}: the Bytes<0> atom carries bytes"
        );
        // One atom per field, and the b0 is the one with no limb: the limb
        // count is the field count less the multi-limb fields' extras, and
        // taking the b0 off the END changes nothing a limb index points at.
        let value = deployed::fab_len(&atoms);
        assert_eq!(value, len, "{name}: declared width");
        assert!(limbs > 0, "{name}: a record has limbs");
    }
}

/// (b), the third half: the schema walk's own width agrees with `LEN`, so
/// the frozen offset table and the encoder cannot drift apart.
#[test]
fn schema_widths_match_the_lens() {
    let expected: Vec<(&str, usize)> = vec![
        ("VaultEventV1", VaultEventV1::LEN),
        ("ReplaceNonceEventV1", ReplaceNonceEventV1::LEN),
        ("SwapEventV1", SwapEventV1::LEN),
        ("SupplyEventV1", SupplyEventV1::LEN),
        ("RedeemEventV1", RedeemEventV1::LEN),
        ("EmptyOutput", EmptyOutput::LEN),
        ("BoolOutput", BoolOutput::LEN),
        ("WordOutput", WordOutput::LEN),
        ("VaultEventV2", VaultEventV2::LEN),
        ("SwapEventV2", SwapEventV2::LEN),
        ("RedeemEventV2", RedeemEventV2::LEN),
        ("VaultResponse", VaultResponse::LEN),
        ("SwapResponse", SwapResponse::LEN),
        ("FailureResponse", FailureResponse::LEN),
        (
            "AttestationPreimage<VaultResponse>",
            AttestationPreimage::<VaultResponse>::LEN,
        ),
        (
            "AttestationPreimage<SwapResponse>",
            AttestationPreimage::<SwapResponse>::LEN,
        ),
        ("SupplyResponse", SupplyResponse::LEN),
        (
            "AttestationPreimage<SupplyResponse>",
            AttestationPreimage::<SupplyResponse>::LEN,
        ),
        ("RedeemResponse", RedeemResponse::LEN),
        (
            "AttestationPreimage<RedeemResponse>",
            AttestationPreimage::<RedeemResponse>::LEN,
        ),
        (
            "AttestationPreimage<FailureResponse>",
            AttestationPreimage::<FailureResponse>::LEN,
        ),
        ("SignBidirectionalMisc", SignBidirectionalMisc::LEN),
        ("RespondMisc", RespondMisc::LEN),
    ];
    let containers = spec_types::schema_containers();
    assert_eq!(containers.len(), expected.len(), "a spec type is missing a LEN check");
    for ((name, container), (expected_name, len)) in containers.iter().zip(expected) {
        assert_eq!(*name, expected_name, "schema container list out of order");
        assert_eq!(schema_len(container), len, "{name}: schema width vs LEN");
    }
}

// ---- (c) THE HEADLINE: the deployed bytes ------------------------------------

/// A V2 record's limbs from the model's V1 request: the same field VALUES, in
/// the V2 slot order.
///
/// V2 is a specification, so there is no model to take its limbs from; what
/// there is, is the V1 record the vault actually writes. This reorders those
/// limbs — the version byte in front, the request nonce restored after the
/// sender, `params` before `txParamType`, the response kind where the output
/// schema was — and changes nothing else. The VALUES stay the model's, which
/// is what keeps the byte claim below two independent statements rather than
/// one restated.
fn v2_limbs(req: &Req, env: &Env, request_nonce: u64, kind: u8) -> Vec<Fr> {
    use minocrab_contracts::signet_v1::layout as v1;
    use minocrab_std::v3::bytes_limbs;

    let l = req.limbs(env);
    let words = req.tx.capacity;
    let params = v1::params(words);
    let execution_dest = v1::execution_dest(words);
    let mut out = vec![Fr::from(u64::from(spec_types::RECORD_FORMAT_VERSION))];
    out.extend([l[v1::SENDER], l[v1::SENDER + 1]]);
    out.push(Fr::from(request_nonce));
    out.push(l[v1::KEY_VERSION]);
    out.extend([l[v1::PATH], l[v1::PATH + 1]]);
    out.push(l[v1::ALGO]);
    out.push(l[v1::signature_dest(words)]);
    out.extend_from_slice(&l[params..params + bytes_limbs(64)]);
    out.push(l[v1::TX_PARAM_TYPE]);
    out.extend_from_slice(&l[v1::CHAIN_ID..=v1::access_list_entry_count(words)]);
    out.extend([l[execution_dest], l[execution_dest + 1]]);
    out.push(Fr::from(u64::from(kind)));
    out
}

/// One record's two byte strings, asserted equal: the deployed FAB packing of
/// the model's limbs, and canonical Borsh of the spec type. The second oracle
/// runs here too, so a spec type that strayed out of the subset would be
/// caught at a deployed value and not only at a generated one.
fn assert_record_bytes<T>(name: &str, atoms: &[AlignmentAtom], limbs: &[Fr], expected_limbs: usize, spec: &T)
where
    T: BorshSerialize + Serialize + FixedLen,
{
    assert_eq!(limbs.len(), expected_limbs, "{name}: limb count");
    let on_chain = deployed::fab_bytes(atoms, limbs);
    assert_eq!(on_chain.len(), T::LEN, "{name}: deployed width vs LEN");
    assert_eq!(on_chain, borsh_bytes(spec), "{name}: record bytes differ");
    assert_eq!(on_chain, bincode_fixint_bytes(spec), "{name}: bincode disagrees");
}

proptest! {
    #![proptest_config(gen::config())]

    /// The 2-word request record — `sendDeposit`, `sendWithdraw` and both
    /// approval routes (`sendApprove` for the router and for the stata token)
    /// write this shape.
    ///
    /// LEFT: the bytes the deployed record holds. The reference model's limbs
    /// under `erc20_vault::VaultRecord`'s atoms, packed by the FAB rule
    /// (`parse_field_repr` + `binary_repr`) — the record M44's differential
    /// suite pins to compactc's artifact.
    ///
    /// RIGHT: `borsh::to_vec` of the spec type at the same field values.
    #[test]
    fn vault_record_bytes_are_canonical_borsh(
        deposit in sent(Sent::deposit),
        withdraw in sent(Sent::withdraw),
        router in sent(Sent::approve_router),
        stata in sent(Sent::approve_stata),
    ) {
        let atoms = records::vault_record_atoms();
        for (name, s, spec) in [
            ("sendDeposit", &deposit, records::deposit_event(&deposit)),
            ("sendWithdraw", &withdraw, records::withdraw_event(&withdraw)),
            ("sendApprove (router)", &router, records::approve_event(&router)),
            ("sendApprove (stata)", &stata, records::approve_event(&stata)),
        ] {
            assert_record_bytes(
                name,
                &atoms,
                &s.req().limbs(&s.env),
                records::VAULT_RECORD_LIMBS,
                &spec,
            );
        }
    }

    /// The nonce-replacement record: the one V1 record with NO calldata, so
    /// `calldata.is_some` is 0 and the word slots the alignment still reserves
    /// are zero — the `Maybe ↦ Flagged` rule at the value that distinguishes
    /// it from `Option`.
    #[test]
    fn replace_nonce_record_bytes_are_canonical_borsh(s in sent(replace_nonce_base)) {
        let spec = records::replace_nonce_event(&s);
        assert_record_bytes(
            "sendReplaceNonce",
            &records::replace_nonce_record_atoms(),
            &s.req().limbs(&s.env),
            records::REPLACE_NONCE_RECORD_LIMBS,
            &spec,
        );
        prop_assert!(!spec.tx_params.calldata.is_some);
    }

    /// The 7-word swap record.
    #[test]
    fn swap_record_bytes_are_canonical_borsh(s in sent(Sent::swap)) {
        assert_record_bytes(
            "sendSwap",
            &records::swap_record_atoms(),
            &s.req().limbs(&s.env),
            records::SWAP_RECORD_LIMBS,
            &records::swap_event(&s),
        );
    }

    /// The lending pair: `sendSupply`'s 2-word record with the lending schema,
    /// and `sendRedeem`'s 3-word record.
    #[test]
    fn lending_record_bytes_are_canonical_borsh(
        supply in sent(Sent::supply),
        redeem in sent(Sent::redeem),
    ) {
        assert_record_bytes(
            "sendSupply",
            &records::supply_record_atoms(),
            &supply.req().limbs(&supply.env),
            records::SUPPLY_RECORD_LIMBS,
            &records::supply_event(&supply),
        );
        assert_record_bytes(
            "sendRedeem",
            &records::redeem_record_atoms(),
            &redeem.req().limbs(&redeem.env),
            records::REDEEM_RECORD_LIMBS,
            &records::redeem_event(&redeem),
        );
    }

    /// THE V2 LINEAGE: the record the `Pending` format writes.
    ///
    /// The V1 properties above are untouched; this is the same statement about
    /// the V2 format, with the same two independent sides. LEFT: the V2 limbs
    /// under `VaultEventV2::atoms()` ([`v2_limbs`]). RIGHT: `borsh::to_vec` of
    /// the spec twin.
    #[test]
    fn v2_record_bytes_are_canonical_borsh(
        deposit in sent(Sent::deposit),
        withdraw in sent(Sent::withdraw),
        approve in sent(Sent::approve_router),
        swap in sent(Sent::swap),
        supply in sent(Sent::supply),
        redeem in sent(Sent::redeem),
        request_nonce in any::<u64>(),
    ) {
        use minocrab_contracts::erc20_vault_pending::{
            RESPONSE_KIND_APPROVE, RESPONSE_KIND_CLAIM, RESPONSE_KIND_REDEEM, RESPONSE_KIND_SUPPLY,
            RESPONSE_KIND_SWAP, RESPONSE_KIND_WITHDRAW,
        };
        let atoms = records::vault_record_v2_atoms();
        for (name, s, kind, spec) in [
            (
                "deposit",
                &deposit,
                RESPONSE_KIND_CLAIM,
                records::deposit_event_v2(&deposit, request_nonce),
            ),
            (
                "withdraw",
                &withdraw,
                RESPONSE_KIND_WITHDRAW,
                records::withdraw_event_v2(&withdraw, request_nonce),
            ),
            (
                "approveRouter",
                &approve,
                RESPONSE_KIND_APPROVE,
                records::approve_event_v2(&approve, request_nonce),
            ),
            (
                "supply",
                &supply,
                RESPONSE_KIND_SUPPLY,
                records::supply_event_v2(&supply, request_nonce),
            ),
        ] {
            let limbs = v2_limbs(&s.req(), &s.env, request_nonce, records::kind(kind));
            assert_record_bytes(name, &atoms, &limbs, records::VAULT_RECORD_V2_LIMBS, &spec);
            // The version byte is the first byte, before anything else.
            prop_assert_eq!(borsh_bytes(&spec)[0], spec_types::RECORD_FORMAT_VERSION);
        }

        let limbs = v2_limbs(&swap.req(), &swap.env, request_nonce, records::kind(RESPONSE_KIND_SWAP));
        assert_record_bytes(
            "swap",
            &records::swap_record_v2_atoms(),
            &limbs,
            records::SWAP_RECORD_V2_LIMBS,
            &records::swap_event_v2(&swap, request_nonce),
        );

        let limbs = v2_limbs(&redeem.req(), &redeem.env, request_nonce, records::kind(RESPONSE_KIND_REDEEM));
        assert_record_bytes(
            "redeem",
            &records::redeem_record_v2_atoms(),
            &limbs,
            records::REDEEM_RECORD_V2_LIMBS,
            &records::redeem_event_v2(&redeem, request_nonce),
        );
    }

    /// The V1 attested outputs, at the three widths the three
    /// `queueAttestation*` circuits take.
    ///
    /// LEFT: `Bytes<LEN>`'s FAB binary over the limbs the circuit discloses —
    /// a `Bytes<1>`'s single limb, a `Bytes<32>`'s `[hi, lo]` slot pair, and
    /// the empty output's nothing. RIGHT: `borsh::to_vec` of the spec type.
    #[test]
    fn attested_output_bytes_are_canonical_borsh(
        success in any::<u8>(),
        word in byte_array::<32>(),
    ) {
        let empty = empty_output();
        prop_assert!(deployed::output_bytes(0, &[]).is_empty());
        prop_assert_eq!(deployed::output_bytes(0, &[]), borsh_bytes(&empty));
        prop_assert_eq!(bincode_fixint_bytes(&empty), borsh_bytes(&empty));

        let spec = BoolOutput { success };
        let on_chain = deployed::output_bytes(1, &[Fr::from(u64::from(success))]);
        prop_assert_eq!(&on_chain, &borsh_bytes(&spec));
        prop_assert_eq!(on_chain.len(), BoolOutput::LEN);

        let (hi, lo) = b32_slots(&word);
        let spec = WordOutput { word };
        let on_chain = deployed::output_bytes(32, &[hi, lo]);
        prop_assert_eq!(&on_chain, &borsh_bytes(&spec));
        prop_assert_eq!(on_chain.len(), WordOutput::LEN);
    }
}

/// The V1 attestation digest's preimage, and the two facts that replaced the
/// retired `0xdeadbeef01` failure output.
///
/// a. THE PREIMAGE IS FIELD ELEMENTS, not bytes: Poseidon over
///    `[HashDomain.attestationDigest, requestId.hi, requestId.lo, blockHeight,
///    outputKind, LEN, ..output]`. That is why there is no
///    `AttestationPreimageV1` spec type to put in the offset tables — there is
///    no byte string for one to describe. The order is restated here against
///    `prims::attestation_digest`, which the vault's differential suite pins
///    to compactc's artifact.
/// b. A FAILED OR UNVIABLE VERDICT CARRIES AN EMPTY OUTPUT. There is no
///    sentinel value to assert equal in-circuit any more; what a refund path
///    goes on is the verdict and the width, which is exactly why V1 signs both
///    of them. The three `assert_ne!`s are that claim: the same empty output
///    under two verdicts, and the empty output against a one-byte zero, are
///    different digests.
#[test]
fn v1_attestation_digest_commits_to_the_kind_and_the_width() {
    let request_id: [u8; 32] = std::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(3));
    let height = 7_000_123u64;
    let word: [u8; 32] = std::array::from_fn(|i| 0xa0u8.wrapping_add(i as u8));
    let (w_hi, w_lo) = b32_slots(&word);
    let (r_hi, r_lo) = b32_slots(&request_id);

    let digest = |kind: u64, len: usize, output: &[Fr]| attestation_digest(&request_id, height, kind, len, output);

    // (a) the preimage, limb for limb.
    for (kind, len, output) in [
        (output_kind::EXECUTED, EmptyOutput::LEN, vec![]),
        (output_kind::EXECUTED, BoolOutput::LEN, vec![Fr::from(1u64)]),
        (output_kind::EXECUTED, WordOutput::LEN, vec![w_hi, w_lo]),
        (output_kind::FAILED, EmptyOutput::LEN, vec![]),
        (output_kind::UNVIABLE, EmptyOutput::LEN, vec![]),
    ] {
        let mut preimage = vec![
            Fr::from(hash_domain::ATTESTATION_DIGEST),
            r_hi,
            r_lo,
            Fr::from(height),
            Fr::from(kind),
            Fr::from(len as u64),
        ];
        preimage.extend_from_slice(&output);
        assert_eq!(
            digest(kind, len, &output),
            transient_upgrade(&preimage),
            "the V1 attestation preimage is not [tag, requestId, height, kind, LEN, ..output]"
        );
    }

    // (b) the empty output, and what the digest still distinguishes without it.
    assert_eq!(EmptyOutput::LEN, 0);
    assert!(borsh_bytes(&empty_output()).is_empty());
    assert!(deployed::output_bytes(0, &[]).is_empty());
    assert_ne!(
        digest(output_kind::FAILED, 0, &[]),
        digest(output_kind::UNVIABLE, 0, &[]),
        "the verdict is not in the digest"
    );
    assert_ne!(
        digest(output_kind::EXECUTED, 0, &[]),
        digest(output_kind::FAILED, 0, &[]),
        "an execution and a failure sign the same digest"
    );
    assert_ne!(
        digest(output_kind::EXECUTED, 1, &[Fr::from(0u64)]),
        digest(output_kind::EXECUTED, 0, &[]),
        "the width is not in the digest — a one-byte output replays as an empty one"
    );
}

/// The Signet singleton's `signBidirectional` Misc payload.
///
/// The strong form: the bytes are not compared against a second Rust
/// construction of them, they are handed to the PINNED COMPACTC ARTIFACT as
/// the logged transcript. The corpus circuit accepts the borsh envelope, and
/// rejects it as soon as any single byte moves — including a byte of the
/// zero pad, which is the padding rule ("bytes 0..LEN are the payload,
/// LEN..N MUST be zero") enforced in-circuit.
///
/// Written against `TestRunner` rather than `proptest!` so the two artifacts
/// are built and parsed ONCE rather than per case.
#[test]
fn sign_bidirectional_misc_bytes_are_canonical_borsh() {
    let ours = signet_contract::SignetContract::sign_bidirectional().ir;
    let theirs = deployed::corpus_signet_zkir("signBidirectional");
    let strategy = (
        sign_bidirectional_misc(),
        0usize..minocrab_contracts::events::MISC_SIZE,
    );
    TestRunner::new(gen::config())
        .run(&strategy, |(payload, tamper)| {
            let envelope = deployed::misc_envelope(
                signet_contract::SIGN_BIDIRECTIONAL_EVENT,
                &borsh_bytes(&payload),
            );
            let (hi, lo) = b32_slots(&payload.request_id);
            let mut inputs = vec![hi, lo, Fr::from(u64::from(payload.version))];
            inputs.extend(deployed::b128_limbs(&payload.payload.0));

            let pi = deployed::misc_preimage(inputs.clone(), &envelope);
            prop_assert!(
                simulate(&theirs, &pi).is_ok(),
                "the corpus artifact rejects the Borsh encoding"
            );
            prop_assert!(simulate(&ours, &pi).is_ok(), "our artifact rejects the Borsh encoding");

            let mut tampered = envelope.clone();
            tampered[tamper] ^= 0x01;
            let pi = deployed::misc_preimage(inputs, &tampered);
            prop_assert!(
                simulate(&theirs, &pi).is_err(),
                "the corpus artifact accepts byte {tamper} moved"
            );
            prop_assert!(
                simulate(&ours, &pi).is_err(),
                "our artifact accepts byte {tamper} moved"
            );
            Ok(())
        })
        .expect("signBidirectional's Misc payload is canonical Borsh");
}

/// `respond` — requestId ‖ signature, checked against its corpus artifact.
/// Until midnight-integration PR #127 `respondBidirectional` shared this
/// payload under its own event name and sat in the same table; its payload
/// now carries the attestation (height, kind, width, digest) between the id
/// and the signature, a different Borsh record, and its byte-level tamper
/// coverage lives in `signet_construction.rs` (M43 B).
#[test]
fn respond_misc_bytes_are_canonical_borsh() {
    let circuits = [(
        "respond",
        signet_contract::SIGNATURE_RESPONDED_EVENT,
        signet_contract::SignetContract::respond().ir,
        deployed::corpus_signet_zkir("respond"),
    )];
    let strategy = (respond_misc(), 0usize..minocrab_contracts::events::MISC_SIZE);
    TestRunner::new(gen::config())
        .run(&strategy, |(payload, tamper)| {
            let mut inputs = Vec::new();
            for b32 in [&payload.request_id, &payload.big_r_x, &payload.big_r_y, &payload.s] {
                let (hi, lo) = b32_slots(b32);
                inputs.extend([hi, lo]);
            }
            inputs.push(Fr::from(u64::from(payload.recovery_id)));

            for (circuit, name, ours, theirs) in &circuits {
                let envelope = deployed::misc_envelope(name, &borsh_bytes(&payload));
                let pi = deployed::misc_preimage(inputs.clone(), &envelope);
                prop_assert!(
                    simulate(theirs, &pi).is_ok(),
                    "{circuit}: the corpus artifact rejects the Borsh encoding"
                );
                prop_assert!(simulate(ours, &pi).is_ok(), "{circuit}: ours rejects the Borsh encoding");

                let mut tampered = envelope.clone();
                tampered[tamper] ^= 0x01;
                let pi = deployed::misc_preimage(inputs.clone(), &tampered);
                prop_assert!(
                    simulate(theirs, &pi).is_err(),
                    "{circuit}: the corpus artifact accepts byte {tamper} moved"
                );
                prop_assert!(
                    simulate(ours, &pi).is_err(),
                    "{circuit}: ours accepts byte {tamper} moved"
                );
            }
            Ok(())
        })
        .expect("respond's Misc payload is canonical Borsh");
}

// ---- the wrapper's transparency ----------------------------------------------

/// [`ByteArray`] exists only because serde's blanket `[T; N]` impls stop at
/// N = 32 and borsh's derived schema declaration would drop the length. It
/// must add NOTHING to either encoding — checked at the N where the native
/// impls exist and can be compared against.
#[test]
fn byte_array_wrapper_is_transparent() {
    macro_rules! check {
        ($($n:literal),+) => {$({
            let bytes: [u8; $n] = std::array::from_fn(|i| (i as u8).wrapping_mul(37).wrapping_add(11));
            assert_eq!(borsh_bytes(&ByteArray(bytes)), borsh_bytes(&bytes), "borsh, N={}", $n);
            assert_eq!(
                bincode_fixint_bytes(&ByteArray(bytes)),
                bincode_fixint_bytes(&bytes),
                "bincode, N={}", $n
            );
            assert_eq!(borsh_bytes(&ByteArray(bytes)).len(), $n);
            assert_eq!(
                <ByteArray<$n> as BorshSchema>::declaration(),
                <[u8; $n] as BorshSchema>::declaration(),
                "schema declaration, N={}", $n
            );
        })+};
    }
    check!(1, 2, 5, 20, 31, 32);
}

// ---- the subset boundary ------------------------------------------------------

/// The three shapes the design of record excludes, and WHICH property
/// catches each. Without these the conformance suite could be vacuous: they
/// are the negative controls.
mod subset_boundary {
    use super::*;

    #[derive(BorshSerialize, Serialize)]
    enum FieldlessEnum {
        _First,
        Second,
    }

    /// A Rust `enum` — the shape the design of record's leaf table calls
    /// `Tag<K>`. CAUGHT BY THE DUAL ORACLE: borsh writes a 1-byte
    /// discriminant, bincode-fixint writes a 4-byte variant index. Hence
    /// every tag in `spec_types` is a `u8`, which is what Compact's `Tag`
    /// already is.
    #[test]
    fn fieldless_enum_leaves_the_subset() {
        assert_eq!(borsh_bytes(&FieldlessEnum::Second), vec![1]);
        assert_eq!(bincode_fixint_bytes(&FieldlessEnum::Second), vec![1, 0, 0, 0]);
    }

    /// A `Vec` — CAUGHT BY THE DUAL ORACLE: borsh prefixes a `u32` length,
    /// bincode-fixint a `u64` one. (Either way the layout would be
    /// value-dependent, which is the deeper reason it is excluded; the
    /// record uses `[T; K]` plus a separate `noWords` count instead.)
    #[test]
    fn vec_leaves_the_subset() {
        let v: Vec<u8> = vec![7, 8];
        assert_eq!(borsh_bytes(&v), vec![2, 0, 0, 0, 7, 8]);
        assert_eq!(bincode_fixint_bytes(&v), vec![2, 0, 0, 0, 0, 0, 0, 0, 7, 8]);
    }

    /// An `Option` — NOT caught by the dual oracle: both write a 1-byte tag
    /// and then the payload, so the two agree byte for byte. It is caught by
    /// the FIXED-WIDTH property instead, because borsh omits the payload on
    /// `None` and the width becomes value-dependent. This is why the design
    /// of record insists on `Flagged` (1-byte tag, payload ALWAYS present)
    /// and why the suite runs both properties rather than just the oracle.
    #[test]
    fn option_is_caught_by_the_width_property_not_the_oracle() {
        assert_eq!(borsh_bytes(&Some(9u8)), bincode_fixint_bytes(&Some(9u8)));
        assert_eq!(borsh_bytes(&Option::<u8>::None), bincode_fixint_bytes(&Option::<u8>::None));

        assert_eq!(borsh::object_length(&Some(9u8)).unwrap(), 2);
        assert_eq!(borsh::object_length(&Option::<u8>::None).unwrap(), 1);

        // Flagged, the replacement, is fixed-width at both values.
        let some = Flagged { is_some: true, value: 9u8 };
        let none = Flagged { is_some: false, value: 0u8 };
        assert_eq!(borsh::object_length(&some).unwrap(), Flagged::<u8>::LEN);
        assert_eq!(borsh::object_length(&none).unwrap(), Flagged::<u8>::LEN);
        assert_eq!(borsh_bytes(&some), bincode_fixint_bytes(&some));
    }
}

// ---- (d) the schema drift alarm -----------------------------------------------

/// Every spec type's layout, walked out of `borsh::schema_container_of` into
/// `(type, path, kind, offset, width)` and frozen. This table is the seed of
/// stage 8's published per-record offset tables — the artifact the TS and
/// MPC sides implement against — so a silent move here is exactly the
/// failure that would desynchronise them.
///
/// To regenerate after an INTENTIONAL layout change:
/// `cargo test --release -p minocrab-contracts --test serialization_conformance -- \
///      --ignored --nocapture print_layout_snapshot`
const LAYOUT_SNAPSHOT: &[(&str, &str, &str, usize, usize)] = &[
    ("VaultEventV1", "key_version", "u8", 0, 1),
    ("VaultEventV1", "sender", "[u8; 32]", 1, 32),
    ("VaultEventV1", "path", "[u8; 32]", 33, 32),
    ("VaultEventV1", "algo", "u8", 65, 1),
    ("VaultEventV1", "tx_param_type", "u8", 66, 1),
    ("VaultEventV1", "tx_params.chain_id", "u64", 67, 8),
    ("VaultEventV1", "tx_params.nonce", "u64", 75, 8),
    ("VaultEventV1", "tx_params.max_priority_fee_per_gas", "u128", 83, 16),
    ("VaultEventV1", "tx_params.max_fee_per_gas", "u128", 99, 16),
    ("VaultEventV1", "tx_params.gas_limit", "u64", 115, 8),
    ("VaultEventV1", "tx_params.to", "[u8; 20]", 123, 20),
    ("VaultEventV1", "tx_params.value", "u128", 143, 16),
    ("VaultEventV1", "tx_params.calldata.is_some", "bool", 159, 1),
    ("VaultEventV1", "tx_params.calldata.value.selector", "[u8; 4]", 160, 4),
    ("VaultEventV1", "tx_params.calldata.value.no_words", "u16", 164, 2),
    ("VaultEventV1", "tx_params.calldata.value.words[0]", "[u8; 32]", 166, 32),
    ("VaultEventV1", "tx_params.calldata.value.words[1]", "[u8; 32]", 198, 32),
    ("VaultEventV1", "tx_params.access_list_entry_count", "u8", 230, 1),
    ("VaultEventV1", "execution_dest", "[u8; 32]", 231, 32),
    ("VaultEventV1", "signature_dest", "u8", 263, 1),
    ("VaultEventV1", "params", "[u8; 64]", 264, 64),
    ("VaultEventV1", "output_deserialization_schema", "[u8; 34]", 328, 34),
    ("VaultEventV1", "respond_serialization_schema", "[u8; 0]", 362, 0),
    ("ReplaceNonceEventV1", "key_version", "u8", 0, 1),
    ("ReplaceNonceEventV1", "sender", "[u8; 32]", 1, 32),
    ("ReplaceNonceEventV1", "path", "[u8; 32]", 33, 32),
    ("ReplaceNonceEventV1", "algo", "u8", 65, 1),
    ("ReplaceNonceEventV1", "tx_param_type", "u8", 66, 1),
    ("ReplaceNonceEventV1", "tx_params.chain_id", "u64", 67, 8),
    ("ReplaceNonceEventV1", "tx_params.nonce", "u64", 75, 8),
    ("ReplaceNonceEventV1", "tx_params.max_priority_fee_per_gas", "u128", 83, 16),
    ("ReplaceNonceEventV1", "tx_params.max_fee_per_gas", "u128", 99, 16),
    ("ReplaceNonceEventV1", "tx_params.gas_limit", "u64", 115, 8),
    ("ReplaceNonceEventV1", "tx_params.to", "[u8; 20]", 123, 20),
    ("ReplaceNonceEventV1", "tx_params.value", "u128", 143, 16),
    ("ReplaceNonceEventV1", "tx_params.calldata.is_some", "bool", 159, 1),
    ("ReplaceNonceEventV1", "tx_params.calldata.value.selector", "[u8; 4]", 160, 4),
    ("ReplaceNonceEventV1", "tx_params.calldata.value.no_words", "u16", 164, 2),
    ("ReplaceNonceEventV1", "tx_params.calldata.value.words[0]", "[u8; 32]", 166, 32),
    ("ReplaceNonceEventV1", "tx_params.calldata.value.words[1]", "[u8; 32]", 198, 32),
    ("ReplaceNonceEventV1", "tx_params.access_list_entry_count", "u8", 230, 1),
    ("ReplaceNonceEventV1", "execution_dest", "[u8; 32]", 231, 32),
    ("ReplaceNonceEventV1", "signature_dest", "u8", 263, 1),
    ("ReplaceNonceEventV1", "params", "[u8; 64]", 264, 64),
    ("ReplaceNonceEventV1", "output_deserialization_schema", "[u8; 2]", 328, 2),
    ("ReplaceNonceEventV1", "respond_serialization_schema", "[u8; 0]", 330, 0),
    ("SwapEventV1", "key_version", "u8", 0, 1),
    ("SwapEventV1", "sender", "[u8; 32]", 1, 32),
    ("SwapEventV1", "path", "[u8; 32]", 33, 32),
    ("SwapEventV1", "algo", "u8", 65, 1),
    ("SwapEventV1", "tx_param_type", "u8", 66, 1),
    ("SwapEventV1", "tx_params.chain_id", "u64", 67, 8),
    ("SwapEventV1", "tx_params.nonce", "u64", 75, 8),
    ("SwapEventV1", "tx_params.max_priority_fee_per_gas", "u128", 83, 16),
    ("SwapEventV1", "tx_params.max_fee_per_gas", "u128", 99, 16),
    ("SwapEventV1", "tx_params.gas_limit", "u64", 115, 8),
    ("SwapEventV1", "tx_params.to", "[u8; 20]", 123, 20),
    ("SwapEventV1", "tx_params.value", "u128", 143, 16),
    ("SwapEventV1", "tx_params.calldata.is_some", "bool", 159, 1),
    ("SwapEventV1", "tx_params.calldata.value.selector", "[u8; 4]", 160, 4),
    ("SwapEventV1", "tx_params.calldata.value.no_words", "u16", 164, 2),
    ("SwapEventV1", "tx_params.calldata.value.words[0]", "[u8; 32]", 166, 32),
    ("SwapEventV1", "tx_params.calldata.value.words[1]", "[u8; 32]", 198, 32),
    ("SwapEventV1", "tx_params.calldata.value.words[2]", "[u8; 32]", 230, 32),
    ("SwapEventV1", "tx_params.calldata.value.words[3]", "[u8; 32]", 262, 32),
    ("SwapEventV1", "tx_params.calldata.value.words[4]", "[u8; 32]", 294, 32),
    ("SwapEventV1", "tx_params.calldata.value.words[5]", "[u8; 32]", 326, 32),
    ("SwapEventV1", "tx_params.calldata.value.words[6]", "[u8; 32]", 358, 32),
    ("SwapEventV1", "tx_params.access_list_entry_count", "u8", 390, 1),
    ("SwapEventV1", "execution_dest", "[u8; 32]", 391, 32),
    ("SwapEventV1", "signature_dest", "u8", 423, 1),
    ("SwapEventV1", "params", "[u8; 64]", 424, 64),
    ("SwapEventV1", "output_deserialization_schema", "[u8; 38]", 488, 38),
    ("SwapEventV1", "respond_serialization_schema", "[u8; 0]", 526, 0),
    ("SupplyEventV1", "key_version", "u8", 0, 1),
    ("SupplyEventV1", "sender", "[u8; 32]", 1, 32),
    ("SupplyEventV1", "path", "[u8; 32]", 33, 32),
    ("SupplyEventV1", "algo", "u8", 65, 1),
    ("SupplyEventV1", "tx_param_type", "u8", 66, 1),
    ("SupplyEventV1", "tx_params.chain_id", "u64", 67, 8),
    ("SupplyEventV1", "tx_params.nonce", "u64", 75, 8),
    ("SupplyEventV1", "tx_params.max_priority_fee_per_gas", "u128", 83, 16),
    ("SupplyEventV1", "tx_params.max_fee_per_gas", "u128", 99, 16),
    ("SupplyEventV1", "tx_params.gas_limit", "u64", 115, 8),
    ("SupplyEventV1", "tx_params.to", "[u8; 20]", 123, 20),
    ("SupplyEventV1", "tx_params.value", "u128", 143, 16),
    ("SupplyEventV1", "tx_params.calldata.is_some", "bool", 159, 1),
    ("SupplyEventV1", "tx_params.calldata.value.selector", "[u8; 4]", 160, 4),
    ("SupplyEventV1", "tx_params.calldata.value.no_words", "u16", 164, 2),
    ("SupplyEventV1", "tx_params.calldata.value.words[0]", "[u8; 32]", 166, 32),
    ("SupplyEventV1", "tx_params.calldata.value.words[1]", "[u8; 32]", 198, 32),
    ("SupplyEventV1", "tx_params.access_list_entry_count", "u8", 230, 1),
    ("SupplyEventV1", "execution_dest", "[u8; 32]", 231, 32),
    ("SupplyEventV1", "signature_dest", "u8", 263, 1),
    ("SupplyEventV1", "params", "[u8; 64]", 264, 64),
    ("SupplyEventV1", "output_deserialization_schema", "[u8; 36]", 328, 36),
    ("SupplyEventV1", "respond_serialization_schema", "[u8; 0]", 364, 0),
    ("RedeemEventV1", "key_version", "u8", 0, 1),
    ("RedeemEventV1", "sender", "[u8; 32]", 1, 32),
    ("RedeemEventV1", "path", "[u8; 32]", 33, 32),
    ("RedeemEventV1", "algo", "u8", 65, 1),
    ("RedeemEventV1", "tx_param_type", "u8", 66, 1),
    ("RedeemEventV1", "tx_params.chain_id", "u64", 67, 8),
    ("RedeemEventV1", "tx_params.nonce", "u64", 75, 8),
    ("RedeemEventV1", "tx_params.max_priority_fee_per_gas", "u128", 83, 16),
    ("RedeemEventV1", "tx_params.max_fee_per_gas", "u128", 99, 16),
    ("RedeemEventV1", "tx_params.gas_limit", "u64", 115, 8),
    ("RedeemEventV1", "tx_params.to", "[u8; 20]", 123, 20),
    ("RedeemEventV1", "tx_params.value", "u128", 143, 16),
    ("RedeemEventV1", "tx_params.calldata.is_some", "bool", 159, 1),
    ("RedeemEventV1", "tx_params.calldata.value.selector", "[u8; 4]", 160, 4),
    ("RedeemEventV1", "tx_params.calldata.value.no_words", "u16", 164, 2),
    ("RedeemEventV1", "tx_params.calldata.value.words[0]", "[u8; 32]", 166, 32),
    ("RedeemEventV1", "tx_params.calldata.value.words[1]", "[u8; 32]", 198, 32),
    ("RedeemEventV1", "tx_params.calldata.value.words[2]", "[u8; 32]", 230, 32),
    ("RedeemEventV1", "tx_params.access_list_entry_count", "u8", 262, 1),
    ("RedeemEventV1", "execution_dest", "[u8; 32]", 263, 32),
    ("RedeemEventV1", "signature_dest", "u8", 295, 1),
    ("RedeemEventV1", "params", "[u8; 64]", 296, 64),
    ("RedeemEventV1", "output_deserialization_schema", "[u8; 36]", 360, 36),
    ("RedeemEventV1", "respond_serialization_schema", "[u8; 0]", 396, 0),
    ("EmptyOutput", "output", "[u8; 0]", 0, 0),
    ("BoolOutput", "success", "u8", 0, 1),
    ("WordOutput", "word", "[u8; 32]", 0, 32),
    ("VaultEventV2", "format_version", "u8", 0, 1),
    ("VaultEventV2", "sender", "[u8; 32]", 1, 32),
    ("VaultEventV2", "request_nonce", "u64", 33, 8),
    ("VaultEventV2", "key_version", "u8", 41, 1),
    ("VaultEventV2", "path", "[u8; 32]", 42, 32),
    ("VaultEventV2", "algo", "u8", 74, 1),
    ("VaultEventV2", "dest", "u8", 75, 1),
    ("VaultEventV2", "params", "[u8; 64]", 76, 64),
    ("VaultEventV2", "tx_param_type", "u8", 140, 1),
    ("VaultEventV2", "tx_params.chain_id", "u64", 141, 8),
    ("VaultEventV2", "tx_params.nonce", "u64", 149, 8),
    ("VaultEventV2", "tx_params.max_priority_fee_per_gas", "u128", 157, 16),
    ("VaultEventV2", "tx_params.max_fee_per_gas", "u128", 173, 16),
    ("VaultEventV2", "tx_params.gas_limit", "u64", 189, 8),
    ("VaultEventV2", "tx_params.to", "[u8; 20]", 197, 20),
    ("VaultEventV2", "tx_params.value", "u128", 217, 16),
    ("VaultEventV2", "tx_params.calldata.is_some", "bool", 233, 1),
    ("VaultEventV2", "tx_params.calldata.value.selector", "[u8; 4]", 234, 4),
    ("VaultEventV2", "tx_params.calldata.value.no_words", "u16", 238, 2),
    ("VaultEventV2", "tx_params.calldata.value.words[0]", "[u8; 32]", 240, 32),
    ("VaultEventV2", "tx_params.calldata.value.words[1]", "[u8; 32]", 272, 32),
    ("VaultEventV2", "tx_params.access_list_entry_count", "u8", 304, 1),
    ("VaultEventV2", "caip2_id", "[u8; 32]", 305, 32),
    ("VaultEventV2", "response_kind", "u8", 337, 1),
    ("SwapEventV2", "format_version", "u8", 0, 1),
    ("SwapEventV2", "sender", "[u8; 32]", 1, 32),
    ("SwapEventV2", "request_nonce", "u64", 33, 8),
    ("SwapEventV2", "key_version", "u8", 41, 1),
    ("SwapEventV2", "path", "[u8; 32]", 42, 32),
    ("SwapEventV2", "algo", "u8", 74, 1),
    ("SwapEventV2", "dest", "u8", 75, 1),
    ("SwapEventV2", "params", "[u8; 64]", 76, 64),
    ("SwapEventV2", "tx_param_type", "u8", 140, 1),
    ("SwapEventV2", "tx_params.chain_id", "u64", 141, 8),
    ("SwapEventV2", "tx_params.nonce", "u64", 149, 8),
    ("SwapEventV2", "tx_params.max_priority_fee_per_gas", "u128", 157, 16),
    ("SwapEventV2", "tx_params.max_fee_per_gas", "u128", 173, 16),
    ("SwapEventV2", "tx_params.gas_limit", "u64", 189, 8),
    ("SwapEventV2", "tx_params.to", "[u8; 20]", 197, 20),
    ("SwapEventV2", "tx_params.value", "u128", 217, 16),
    ("SwapEventV2", "tx_params.calldata.is_some", "bool", 233, 1),
    ("SwapEventV2", "tx_params.calldata.value.selector", "[u8; 4]", 234, 4),
    ("SwapEventV2", "tx_params.calldata.value.no_words", "u16", 238, 2),
    ("SwapEventV2", "tx_params.calldata.value.words[0]", "[u8; 32]", 240, 32),
    ("SwapEventV2", "tx_params.calldata.value.words[1]", "[u8; 32]", 272, 32),
    ("SwapEventV2", "tx_params.calldata.value.words[2]", "[u8; 32]", 304, 32),
    ("SwapEventV2", "tx_params.calldata.value.words[3]", "[u8; 32]", 336, 32),
    ("SwapEventV2", "tx_params.calldata.value.words[4]", "[u8; 32]", 368, 32),
    ("SwapEventV2", "tx_params.calldata.value.words[5]", "[u8; 32]", 400, 32),
    ("SwapEventV2", "tx_params.calldata.value.words[6]", "[u8; 32]", 432, 32),
    ("SwapEventV2", "tx_params.access_list_entry_count", "u8", 464, 1),
    ("SwapEventV2", "caip2_id", "[u8; 32]", 465, 32),
    ("SwapEventV2", "response_kind", "u8", 497, 1),
    ("RedeemEventV2", "format_version", "u8", 0, 1),
    ("RedeemEventV2", "sender", "[u8; 32]", 1, 32),
    ("RedeemEventV2", "request_nonce", "u64", 33, 8),
    ("RedeemEventV2", "key_version", "u8", 41, 1),
    ("RedeemEventV2", "path", "[u8; 32]", 42, 32),
    ("RedeemEventV2", "algo", "u8", 74, 1),
    ("RedeemEventV2", "dest", "u8", 75, 1),
    ("RedeemEventV2", "params", "[u8; 64]", 76, 64),
    ("RedeemEventV2", "tx_param_type", "u8", 140, 1),
    ("RedeemEventV2", "tx_params.chain_id", "u64", 141, 8),
    ("RedeemEventV2", "tx_params.nonce", "u64", 149, 8),
    ("RedeemEventV2", "tx_params.max_priority_fee_per_gas", "u128", 157, 16),
    ("RedeemEventV2", "tx_params.max_fee_per_gas", "u128", 173, 16),
    ("RedeemEventV2", "tx_params.gas_limit", "u64", 189, 8),
    ("RedeemEventV2", "tx_params.to", "[u8; 20]", 197, 20),
    ("RedeemEventV2", "tx_params.value", "u128", 217, 16),
    ("RedeemEventV2", "tx_params.calldata.is_some", "bool", 233, 1),
    ("RedeemEventV2", "tx_params.calldata.value.selector", "[u8; 4]", 234, 4),
    ("RedeemEventV2", "tx_params.calldata.value.no_words", "u16", 238, 2),
    ("RedeemEventV2", "tx_params.calldata.value.words[0]", "[u8; 32]", 240, 32),
    ("RedeemEventV2", "tx_params.calldata.value.words[1]", "[u8; 32]", 272, 32),
    ("RedeemEventV2", "tx_params.calldata.value.words[2]", "[u8; 32]", 304, 32),
    ("RedeemEventV2", "tx_params.access_list_entry_count", "u8", 336, 1),
    ("RedeemEventV2", "caip2_id", "[u8; 32]", 337, 32),
    ("RedeemEventV2", "response_kind", "u8", 369, 1),
    ("VaultResponse", "kind", "u8", 0, 1),
    ("VaultResponse", "success", "bool", 1, 1),
    ("SwapResponse", "kind", "u8", 0, 1),
    ("SwapResponse", "amount_in", "u64", 1, 8),
    ("FailureResponse", "kind", "u8", 0, 1),
    ("AttestationPreimage<VaultResponse>", "request_id", "[u8; 32]", 0, 32),
    ("AttestationPreimage<VaultResponse>", "output.kind", "u8", 32, 1),
    ("AttestationPreimage<VaultResponse>", "output.success", "bool", 33, 1),
    ("AttestationPreimage<SwapResponse>", "request_id", "[u8; 32]", 0, 32),
    ("AttestationPreimage<SwapResponse>", "output.kind", "u8", 32, 1),
    ("AttestationPreimage<SwapResponse>", "output.amount_in", "u64", 33, 8),
    ("SupplyResponse", "kind", "u8", 0, 1),
    ("SupplyResponse", "shares", "u64", 1, 8),
    ("AttestationPreimage<SupplyResponse>", "request_id", "[u8; 32]", 0, 32),
    ("AttestationPreimage<SupplyResponse>", "output.kind", "u8", 32, 1),
    ("AttestationPreimage<SupplyResponse>", "output.shares", "u64", 33, 8),
    ("RedeemResponse", "kind", "u8", 0, 1),
    ("RedeemResponse", "assets", "u64", 1, 8),
    ("AttestationPreimage<RedeemResponse>", "request_id", "[u8; 32]", 0, 32),
    ("AttestationPreimage<RedeemResponse>", "output.kind", "u8", 32, 1),
    ("AttestationPreimage<RedeemResponse>", "output.assets", "u64", 33, 8),
    ("AttestationPreimage<FailureResponse>", "request_id", "[u8; 32]", 0, 32),
    ("AttestationPreimage<FailureResponse>", "output.kind", "u8", 32, 1),
    ("SignBidirectionalMisc", "version", "u8", 0, 1),
    ("SignBidirectionalMisc", "request_id", "[u8; 32]", 1, 32),
    ("SignBidirectionalMisc", "payload", "[u8; 128]", 33, 128),
    ("RespondMisc", "request_id", "[u8; 32]", 0, 32),
    ("RespondMisc", "big_r_x", "[u8; 32]", 32, 32),
    ("RespondMisc", "big_r_y", "[u8; 32]", 64, 32),
    ("RespondMisc", "s", "[u8; 32]", 96, 32),
    ("RespondMisc", "recovery_id", "u8", 128, 1),
];

fn snapshot_rows() -> Vec<(&'static str, Row)> {
    spec_types::schema_containers()
        .into_iter()
        .flat_map(|(name, container)| {
            layout_rows(&container).into_iter().map(move |row| (name, row))
        })
        .collect()
}

#[test]
fn layout_matches_its_frozen_table() {
    let rows = snapshot_rows();
    let frozen: Vec<(&str, Row)> = LAYOUT_SNAPSHOT
        .iter()
        .map(|&(ty, path, kind, offset, width)| {
            (
                ty,
                Row {
                    path: path.to_string(),
                    kind: kind.to_string(),
                    offset,
                    width,
                },
            )
        })
        .collect();
    assert_eq!(
        rows.len(),
        frozen.len(),
        "the frozen table has {} rows but the spec types walk to {} — \
         regenerate with the `print_layout_snapshot` test",
        frozen.len(),
        rows.len()
    );
    let mut failures = Vec::new();
    for ((ty, got), (frozen_ty, want)) in rows.iter().zip(&frozen) {
        if ty != frozen_ty || got != want {
            failures.push(format!("  {ty}.{got:?} != {frozen_ty}.{want:?}"));
        }
    }
    assert!(
        failures.is_empty(),
        "the serialization layout moved — every offset here is a wire \
         commitment:\n{}",
        failures.join("\n")
    );
}

// ---- (e) THE IN-CIRCUIT ENCODER against a deployed shape (M11 stage 1) ---------
//
// Stage 1 built `minocrab_std::v3::borsh` — the same Borsh subset, emitted by
// a circuit. Its own suite proves it against a twin of its own. Here it is
// pointed at a DEPLOYED payload shape, `RespondMisc`, whose bytes stage 0
// proved the pinned compactc artifact itself accepts: the circuit's packed
// output must equal `borsh::to_vec` of the spec type, and the circuit's
// layout table must equal the table walked out of borsh's own schema.

mod in_circuit {
    use super::*;

    use minocrab_std::v3::borsh::{to_bytes, CircuitBorsh};
    use minocrab_std::v3::{ArgPath, CircuitArg, Uint, Vis3, B32};

    use minocrab::v3::Circuit3;
    use minocrab::Private;
    use minocrab_zkir::v3::IrValue;

    /// [`RespondMisc`] over wires — ONE DERIVE for the circuit-argument
    /// family and the serialization, and `#[borsh(spec = …)]` for the
    /// generated cross-check against borsh's own schema of the spec type
    /// (`__minocrab_borsh_spec_RespondMiscCircuit` in this binary's test
    /// list).
    ///
    /// The field names are the SPEC type's, so the layout paths need no
    /// override; the argument labels are the mechanical camelCase ones, which
    /// nothing here is pinned to (this circuit is a test fixture, not a
    /// deployed interface).
    #[derive(CircuitBorsh)]
    #[borsh(spec = RespondMisc)]
    struct RespondMiscCircuit<V: Vis3> {
        request_id: B32<V>,
        big_r_x: B32<V>,
        big_r_y: B32<V>,
        s: B32<V>,
        recovery_id: Uint<8, V>,
    }

    /// A preimage for a circuit that is nothing but its arguments: no
    /// transcripts, no ledger operations.
    fn arg_preimage(inputs: Vec<Fr>) -> midnight_transient_crypto::proofs::ProofPreimage {
        midnight_transient_crypto::proofs::ProofPreimage {
            inputs,
            private_transcript: vec![],
            public_transcript_inputs: vec![],
            public_transcript_outputs: vec![],
            binding_input: 0.into(),
            communications_commitment: None,
            key_location: midnight_transient_crypto::proofs::KeyLocation(
                std::borrow::Cow::Borrowed("minocrab-contracts-test"),
            ),
        }
    }

    /// The packed bytes a circuit built through `CircuitBorsh` emits for the
    /// deployed `respond` payload ARE `borsh::to_vec` of the spec type.
    #[test]
    fn the_circuit_encoder_emits_the_spec_bytes() {
        let mut c = Circuit3::new();
        let value =
            <RespondMiscCircuit<Private> as CircuitArg>::declare(&mut c, &ArgPath::root("respond"));
        value.constrain(&mut c);
        let bytes = to_bytes::<{ RespondMisc::LEN }, _, _>(&mut c, &value);
        for (i, limb) in bytes.limbs().to_vec().into_iter().enumerate() {
            let public = c.disclose(limb, "payload limb");
            c.output(public, &format!("payload limb {i}"));
        }
        let ir = c.finish(false).ir;

        TestRunner::new(gen::config())
            .run(&respond_misc(), |payload| {
                let mut inputs = Vec::new();
                for b32 in [
                    &payload.request_id,
                    &payload.big_r_x,
                    &payload.big_r_y,
                    &payload.s,
                ] {
                    let (hi, lo) = b32_slots(b32);
                    inputs.extend([hi, lo]);
                }
                inputs.push(Fr::from(u64::from(payload.recovery_id)));

                let run = simulate(&ir, &arg_preimage(inputs)).expect("the encoder circuit accepts");
                let limbs: Vec<Fr> = run
                    .outputs
                    .iter()
                    .map(|v| match v {
                        IrValue::Native(fr) => *fr,
                        other => panic!("expected a native output, got {other:?}"),
                    })
                    .collect();

                // Slot 0 is the leftover (most significant) chunk, so string
                // order is the slots reversed.
                let mut bytes = Vec::with_capacity(RespondMisc::LEN);
                for (i, limb) in limbs.iter().enumerate().rev() {
                    let width =
                        minocrab_std::v3::BytesN::<Private, { RespondMisc::LEN }>::limb_len(i);
                    bytes.extend_from_slice(&limb.as_le_bytes()[..width]);
                }
                prop_assert_eq!(bytes, borsh_bytes(&payload));
                Ok(())
            })
            .expect("the in-circuit encoder emits canonical Borsh");
    }

    /// The generated cross-check is not vacuous: move one offset and it
    /// fires, naming the row.
    #[test]
    #[should_panic(expected = "is not its spec type's Borsh schema")]
    fn the_schema_cross_check_catches_a_moved_offset() {
        let mut ours = <RespondMiscCircuit<Private> as CircuitBorsh<Private>>::layout();
        ours[1].offset += 1;
        minocrab_std::v3::borsh::schema::assert_matches_schema::<RespondMisc>(
            "RespondMiscCircuit",
            &ours,
        );
    }

    /// The circuit type's layout table IS borsh's own schema walk of the spec
    /// type — same paths, same kinds, same offsets, same widths. (This is the
    /// cross-check `#[borsh(spec = …)]` generates in stage 3, done by hand for
    /// one deployed shape.)
    #[test]
    fn the_circuit_layout_is_the_schema_layout() {
        assert_eq!(
            <RespondMiscCircuit<Private> as CircuitBorsh<Private>>::LEN,
            RespondMisc::LEN
        );
        let ours: Vec<(String, String, usize, usize)> =
            <RespondMiscCircuit<Private> as CircuitBorsh<Private>>::layout()
                .into_iter()
                .map(|f| (f.path, f.kind, f.offset, f.width))
                .collect();
        let theirs: Vec<(String, String, usize, usize)> =
            layout_rows(&borsh::schema::BorshSchemaContainer::for_type::<RespondMisc>())
                .into_iter()
                .map(|r| (r.path, r.kind, r.offset, r.width))
                .collect();
        assert_eq!(ours, theirs);
    }
}

/// Regeneration helper: prints the `LAYOUT_SNAPSHOT` table body.
#[test]
#[ignore = "regeneration helper, not a check"]
fn print_layout_snapshot() {
    for (ty, row) in snapshot_rows() {
        println!(
            "    (\"{ty}\", \"{}\", \"{}\", {}, {}),",
            row.path, row.kind, row.offset, row.width
        );
    }
}

// ---- (f) THE PUBLISHED SPEC (M11 stages 8 and 10) ------------------------------
//
// `spec/borsh-subset.md`, `spec/vectors/*.json` and `spec/ts/` are the
// artifact the TS and MPC sides implement against. The prose is hand-written;
// every OFFSET, every BYTE and every line of the TypeScript DECODER is
// generated from the same schema walk this suite checks, and the tests below
// fail if the committed files stop being that generator's output. A spec that
// can drift from the format is worse than no spec, so the document — and now
// the code that reads it — is a test fixture as much as a deliverable.

mod spec_document {
    use super::*;

    use serialization::{spec_doc, ts_codegen};

    /// `(what the document has between a marker pair, what the generator says
    /// belongs there)` — read from the SAME list the regenerator writes from,
    /// so a check and a rewrite cannot disagree about what a region is.
    fn committed_and_generated(begin_marker: &str) -> (String, String) {
        let path = spec_doc::spec_dir().join("borsh-subset.md");
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("{} is not readable: {e}", path.display()));
        let (_, end_marker, want) = spec_doc::generated_regions()
            .into_iter()
            .find(|(begin, _, _)| *begin == begin_marker)
            .unwrap_or_else(|| panic!("`{begin_marker}` is not a generated region"));
        let from = text
            .find(begin_marker)
            .unwrap_or_else(|| panic!("{} has no `{begin_marker}`", path.display()))
            + begin_marker.len();
        let to = text
            .find(end_marker)
            .unwrap_or_else(|| panic!("{} has no `{end_marker}`", path.display()));
        (text[from..to].to_string(), want)
    }

    /// The generated region of `spec/borsh-subset.md` IS
    /// `spec_doc::offset_tables_markdown()` — same types, same order, same
    /// offsets. Prose outside the markers is not touched by either side.
    #[test]
    fn the_committed_offset_tables_are_generated() {
        let (committed, generated) = committed_and_generated(spec_doc::TABLES_BEGIN);
        assert_eq!(
            committed, generated,
            "spec/borsh-subset.md's offset tables are not the generated ones — every offset \
             there is a wire commitment; regenerate with the `regenerate_spec` test"
        );
    }

    /// §5's response-kind table IS the generated one, and the generator's own
    /// asserts hold: exactly `RESPONSE_KINDS` rows, numbered `0..n` in order.
    ///
    /// The table is the MPC's `kind ↦ (ABI types, response shape)` lookup, so
    /// a row that drifts from the contract's constants is a decoder reading
    /// the wrong shape off a correctly signed response.
    #[test]
    fn the_committed_kind_table_is_generated() {
        let (committed, generated) = committed_and_generated(spec_doc::KINDS_BEGIN);
        assert_eq!(
            committed, generated,
            "spec/borsh-subset.md §5's kind table is not the generated one — it is the MPC's \
             lookup table; regenerate with the `regenerate_spec` test"
        );
    }

    /// Every committed vector file IS the generator's output, and the
    /// directory holds exactly those files (a stale vector is as misleading
    /// as a wrong one).
    #[test]
    fn the_committed_vectors_are_generated() {
        let dir = spec_doc::spec_dir().join("vectors");
        let files = spec_doc::vector_files();
        for (name, want) in &files {
            let path = dir.join(name);
            let got = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("{} is not readable: {e}", path.display()));
            assert_eq!(
                &got, want,
                "{} is not the generated vector file — regenerate with the `regenerate_spec` test",
                path.display()
            );
        }

        let mut committed: Vec<String> = std::fs::read_dir(&dir)
            .expect("spec/vectors exists")
            .map(|entry| entry.expect("readable").file_name().to_string_lossy().into_owned())
            .collect();
        committed.sort();
        let mut expected: Vec<String> = files.iter().map(|(name, _)| name.to_string()).collect();
        expected.sort();
        assert_eq!(committed, expected, "spec/vectors holds a file nobody generates");
    }

    /// The committed vectors are INTERNALLY consistent: the fields tile the
    /// value exactly — same order, no gap, no overlap — and their bytes
    /// concatenate to the vector's own `hex`. An implementer who decodes
    /// field by field and one who hashes the whole string are looking at the
    /// same bytes.
    #[test]
    fn every_vector_is_tiled_by_its_fields() {
        for (name, text) in spec_doc::vector_files() {
            let file: serde_json::Value =
                serde_json::from_str(&text).unwrap_or_else(|e| panic!("{name} is not JSON: {e}"));
            let vectors = file["vectors"].as_array().expect("vectors is an array");
            assert!(!vectors.is_empty(), "{name} carries no vectors");
            for vector in vectors {
                let ty = vector["type"].as_str().expect("type");
                let hex = vector["hex"].as_str().expect("hex");
                let len = vector["len"].as_u64().expect("len") as usize;
                assert_eq!(hex.len(), 2 * len, "{name}/{ty}: hex is not len bytes");

                let mut offset = 0usize;
                let mut tiled = String::new();
                for field in vector["fields"].as_array().expect("fields is an array") {
                    let at = field["offset"].as_u64().expect("offset") as usize;
                    let width = field["width"].as_u64().expect("width") as usize;
                    let bytes = field["hex"].as_str().expect("field hex");
                    assert_eq!(at, offset, "{name}/{ty}: a gap or overlap at offset {at}");
                    assert_eq!(bytes.len(), 2 * width, "{name}/{ty}: field hex is not width bytes");
                    assert_eq!(
                        bytes,
                        &hex[2 * at..2 * (at + width)],
                        "{name}/{ty}: field at {at} is not the value's own bytes"
                    );
                    tiled.push_str(bytes);
                    offset += width;
                }
                assert_eq!(offset, len, "{name}/{ty}: the fields do not cover the value");
                assert_eq!(tiled, hex, "{name}/{ty}: the fields do not concatenate to the value");
            }
        }
    }

    /// Every committed file of `spec/ts/` IS the generator's output (M11
    /// stage 10), and the directory holds exactly those files.
    ///
    /// `borsh-subset.ts` is walked out of the same Borsh schema the offset
    /// tables are, so a format change that misses the TypeScript is a failing
    /// test rather than a decoder that silently reads the wrong offsets; the
    /// hand-written files beside it are copied verbatim from
    /// `tests/serialization/ts/`, which is where they are edited.
    #[test]
    fn the_committed_typescript_is_generated() {
        let dir = spec_doc::spec_dir().join("ts");
        let files = ts_codegen::ts_files();
        for (name, want) in &files {
            let path = dir.join(name);
            let got = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("{} is not readable: {e}", path.display()));
            assert_eq!(
                &got, want,
                "{} is not the generated file — regenerate with the `regenerate_spec` test",
                path.display()
            );
        }

        let mut committed: Vec<String> = std::fs::read_dir(&dir)
            .expect("spec/ts exists")
            .map(|entry| entry.expect("readable").file_name().to_string_lossy().into_owned())
            .collect();
        committed.sort();
        let mut expected: Vec<String> = files.iter().map(|(name, _)| name.to_string()).collect();
        expected.sort();
        assert_eq!(committed, expected, "spec/ts holds a file nobody generates");
    }

    /// Every vector has a generated TypeScript codec to decode it with —
    /// keyed by the vector's own type name with its parenthetical annotation
    /// stripped, which is the lookup `vectors.test.ts` performs.
    ///
    /// The loop-closer between stage 8 and stage 10: a new vector for a type
    /// the codegen does not cover fails HERE, in Rust, rather than in the
    /// node suite.
    #[test]
    fn every_vector_type_has_a_typescript_codec() {
        let codecs: Vec<&str> = ts_codegen::ts_types().iter().map(|(name, _)| *name).collect();
        let mut seen = 0usize;
        for (file, text) in spec_doc::vector_files() {
            let parsed: serde_json::Value =
                serde_json::from_str(&text).unwrap_or_else(|e| panic!("{file} is not JSON: {e}"));
            for vector in parsed["vectors"].as_array().expect("vectors is an array") {
                let ty = vector["type"].as_str().expect("type");
                let base = ty.split(" (").next().expect("a non-empty type name");
                assert!(
                    codecs.contains(&base),
                    "{file}/{ty}: no TypeScript codec for `{base}` — add it to \
                     `ts_codegen::ts_types` and regenerate spec/ts"
                );
                seen += 1;
            }
        }
        assert!(seen >= 29, "the vectors shrank to {seen} — that is a spec change, not a test fix");
    }

    /// The node side, from cargo: `node --test spec/ts/vectors.test.ts`.
    ///
    /// `#[ignore]`d because it needs a node toolchain, which the flake's
    /// devshell supplies (`nix develop`) and a bare `cargo test` cannot
    /// assume. The TypeScript suite decodes every vector with the generated
    /// codec, checks it leaf by leaf and re-serializes it to byte equality;
    /// this is only the shortcut for running it beside the Rust ones.
    #[test]
    #[ignore = "needs node (nix develop supplies it)"]
    fn the_typescript_vectors_pass() {
        let root = spec_doc::spec_dir().join("..");
        let status = std::process::Command::new("node")
            .current_dir(&root)
            .args(["--test", "spec/ts/vectors.test.ts"])
            .status()
            .expect("node is on PATH — run inside `nix develop`");
        assert!(status.success(), "the TypeScript vector suite failed");
    }

    /// Regeneration helper: rewrites every generated region of
    /// `spec/borsh-subset.md`, every `spec/vectors/*.json` and every
    /// `spec/ts/` file.
    #[test]
    #[ignore = "regeneration helper, not a check"]
    fn regenerate_spec() {
        let dir = spec_doc::spec_dir();
        let doc = dir.join("borsh-subset.md");
        let mut text = std::fs::read_to_string(&doc).expect("the document exists");
        for (begin_marker, end_marker, body) in spec_doc::generated_regions() {
            let begin = text.find(begin_marker).expect("begin marker") + begin_marker.len();
            let end = text.find(end_marker).expect("end marker");
            let mut out = String::new();
            out.push_str(&text[..begin]);
            out.push_str(&body);
            out.push_str(&text[end..]);
            text = out;
        }
        std::fs::write(&doc, text).expect("the document is writable");
        println!("wrote {}", doc.display());

        let vectors = dir.join("vectors");
        std::fs::create_dir_all(&vectors).expect("spec/vectors is creatable");
        for (name, contents) in spec_doc::vector_files() {
            let path = vectors.join(name);
            std::fs::write(&path, contents).expect("the vector file is writable");
            println!("wrote {}", path.display());
        }

        let ts = dir.join("ts");
        std::fs::create_dir_all(&ts).expect("spec/ts is creatable");
        for (name, contents) in ts_codegen::ts_files() {
            let path = ts.join(name);
            std::fs::write(&path, contents).expect("the TypeScript file is writable");
            println!("wrote {}", path.display());
        }
    }
}

//! "Today's protocol is already Borsh" — with a test behind it (M11
//! stage 0, notes/borsh-format.org §Phasing).
//!
//! No circuit changes and no new encoder: every byte string on the DEPLOYED
//! side of an assertion here is produced by the protocol's own code — the
//! FAB `binary_repr` the keccak chips consume, the `Misc` envelope the
//! singleton logs, the reference model M10's differential suite pins to the
//! compactc artifacts. Every byte string on the SPEC side is produced by
//! borsh's and serde+bincode's derives over the declarations in
//! `serialization::spec_types`.
//!
//! The four properties of the stage, in the order the design of record lists
//! them:
//!
//! a. DUAL ORACLE — `borsh::to_vec(v) == bincode-fixint(v)` for every spec
//!    type over generated values. Together with (b) this is the subset
//!    checker; `subset_boundary` below pins the three known-bad shapes and
//!    which of the two properties catches each.
//! b. FIXED WIDTH — `borsh::object_length(v) == T::LEN` for all v, and
//!    `T::LEN` equals the deployed FAB alignment's own `bin_len`. No
//!    value-dependent branching, so every offset is a compile-time constant.
//! c. THE HEADLINE — byte-equality against the deployed protocol's actual
//!    bytes: the request records, the attestation digest preimages, and the
//!    singleton's three Misc payloads, the last checked by handing the bytes
//!    to the CORPUS ARTIFACT itself. (Since the protocol move — M28 — the
//!    request id and the signed digest are Poseidon over the FIELD-ALIGNED
//!    limbs, not a hash of these bytes; the byte claims stand, the hash
//!    claims live in the vault model.)
//! d. SCHEMA DRIFT — the Borsh schema walked into a frozen `(path, kind,
//!    offset, width)` table, the seed of stage 8's published offset tables.
//!
//! Case counts scale with `PROPTEST_CASES` (see `vault::gen::config`).

mod serialization;
mod support;
mod vault;

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use minocrab::Fr;
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
use vault::prims::b32_slots;

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

/// The record header every instantiation shares.
type RecordHeader = ([u8; 32], u64, u8, [u8; 32], u8, u8, [u8; 64], u8, [u8; 32]);

fn record_header() -> impl Strategy<Value = RecordHeader> {
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

fn vault_event() -> impl Strategy<Value = VaultEvent> {
    (
        record_header(),
        tx_params2(),
        byte_array::<34>(),
        byte_array::<34>(),
    )
        .prop_map(
            |((sender, request_nonce, key_version, path, algo, dest, params, tx_param_type, caip2_id),
              tx_params,
              out_schema,
              respond_schema)| VaultEvent {
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
                output_deserialization_schema: ByteArray(out_schema),
                respond_serialization_schema: ByteArray(respond_schema),
            },
        )
}

fn swap_event() -> impl Strategy<Value = SwapEvent> {
    (
        record_header(),
        tx_params7(),
        byte_array::<38>(),
        byte_array::<37>(),
    )
        .prop_map(
            |((sender, request_nonce, key_version, path, algo, dest, params, tx_param_type, caip2_id),
              tx_params,
              out_schema,
              respond_schema)| SwapEvent {
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
                output_deserialization_schema: ByteArray(out_schema),
                respond_serialization_schema: ByteArray(respond_schema),
            },
        )
}

fn supply_event() -> impl Strategy<Value = SupplyEvent> {
    (
        record_header(),
        tx_params2(),
        byte_array::<36>(),
        byte_array::<35>(),
    )
        .prop_map(
            |((sender, request_nonce, key_version, path, algo, dest, params, tx_param_type, caip2_id),
              tx_params,
              out_schema,
              respond_schema)| SupplyEvent {
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
                output_deserialization_schema: ByteArray(out_schema),
                respond_serialization_schema: ByteArray(respond_schema),
            },
        )
}

fn redeem_event() -> impl Strategy<Value = RedeemEvent> {
    (
        record_header(),
        tx_params3(),
        byte_array::<36>(),
        byte_array::<35>(),
    )
        .prop_map(
            |((sender, request_nonce, key_version, path, algo, dest, params, tx_param_type, caip2_id),
              tx_params,
              out_schema,
              respond_schema)| RedeemEvent {
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
                output_deserialization_schema: ByteArray(out_schema),
                respond_serialization_schema: ByteArray(respond_schema),
            },
        )
}

fn redeem_event_v2() -> impl Strategy<Value = RedeemEventV2> {
    (record_header(), tx_params3(), any::<u8>()).prop_map(
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

/// M11 stage 7's 2-word record: the same generated middle, a version byte and
/// a kind byte. Generated, not fixed, at both ends — the conformance
/// properties are about the ENCODING, so they must hold at every value the
/// type admits, not only at the two the protocol writes.
fn vault_event_v2() -> impl Strategy<Value = VaultEventV2> {
    (record_header(), tx_params2(), any::<u8>(), any::<u8>()).prop_map(
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

/// M11 stage 7's 7-word record. See [`vault_event_v2`].
fn swap_event_v2() -> impl Strategy<Value = SwapEventV2> {
    (record_header(), tx_params7(), any::<u8>(), any::<u8>()).prop_map(
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

proptest! {
    #![proptest_config(gen::config())]

    /// (a) + (b) for the four deployed request records.
    #[test]
    fn records_are_conformant(
        vault in vault_event(),
        swap in swap_event(),
        supply in supply_event(),
        redeem in redeem_event(),
    ) {
        assert_conformant(&vault);
        assert_conformant(&swap);
        assert_conformant(&supply);
        assert_conformant(&redeem);
    }

    /// (a) + (b) for M11 stage 7's three request records.
    #[test]
    fn stage7_records_are_conformant(
        vault in vault_event_v2(),
        swap in swap_event_v2(),
        redeem in redeem_event_v2(),
    ) {
        assert_conformant(&vault);
        assert_conformant(&swap);
        assert_conformant(&redeem);
    }

    /// (a) + (b) for the four attested outputs and their digest preimages.
    #[test]
    fn attested_outputs_are_conformant(
        request_id in byte_array::<32>(),
        success in any::<u8>(),
        failure in byte_array::<5>(),
        amount_in in any::<u64>(),
    ) {
        let claim = ClaimOutput { success };
        let complete_withdraw = CompleteWithdrawOutput { success };
        let refund = RefundOutput { failure };
        let complete_swap = CompleteSwapOutput { amount_in };
        assert_conformant(&claim);
        assert_conformant(&complete_withdraw);
        assert_conformant(&refund);
        assert_conformant(&complete_swap);
        assert_conformant(&AttestationPreimage { request_id, output: claim });
        assert_conformant(&AttestationPreimage { request_id, output: complete_withdraw });
        assert_conformant(&AttestationPreimage { request_id, output: refund });
        assert_conformant(&AttestationPreimage { request_id, output: complete_swap });
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

/// (b), the other half: each `LEN` is the DEPLOYED shape's own width, not an
/// arithmetic claim of ours. `Alignment::bin_len` is what the ledger and the
/// hash chips size the preimage by.
#[test]
fn lens_match_the_deployed_alignments() {
    assert_eq!(
        VaultEvent::LEN,
        deployed::fab_len(&records::vault_record_atoms()),
        "vault record width"
    );
    assert_eq!(
        SwapEvent::LEN,
        deployed::fab_len(&records::swap_record_atoms()),
        "swap record width"
    );
    // The design of record's stage-7 arithmetic is built on this number.
    assert_eq!(SwapEvent::LEN, 571);
    assert_eq!(VaultEvent::LEN, 404);
    // The lending pair: the vault record's shape with schema strings two and
    // one bytes longer (407), and its 3-word sibling (one more ABI word, 439).
    assert_eq!(
        SupplyEvent::LEN,
        deployed::fab_len(&records::supply_record_atoms()),
        "supply record width"
    );
    assert_eq!(
        RedeemEvent::LEN,
        deployed::fab_len(&records::redeem_record_atoms()),
        "redeem record width"
    );
    assert_eq!(SupplyEvent::LEN, 404 + 2 + 1);
    assert_eq!(RedeemEvent::LEN, 404 + 32 + 2 + 1);

    // M11 STAGE 7, and the same statement about the SHIPPING alignment: the
    // widths are the borsh artifacts' own atom lists, not our arithmetic.
    assert_eq!(
        VaultEventV2::LEN,
        deployed::fab_len(&records::vault_record_v2_atoms()),
        "stage-7 vault record width"
    );
    assert_eq!(
        SwapEventV2::LEN,
        deployed::fab_len(&records::swap_record_v2_atoms()),
        "stage-7 swap record width"
    );
    // 404 → 338 and 571 → 498: +1 version byte, −68/−75 of schema, +1 kind.
    assert_eq!(VaultEventV2::LEN, 404 + 1 - 2 * 34 + 1);
    assert_eq!(VaultEventV2::LEN, 338);
    assert_eq!(SwapEventV2::LEN, 571 + 1 - 38 - 37 + 1);
    assert_eq!(SwapEventV2::LEN, 498);
    // The V2 redeem record: 439 → 370 by the same two edits; the V2 supply
    // record is `VaultEventV2` itself (the schema strings were the only
    // difference, and V2 has none).
    assert_eq!(
        RedeemEventV2::LEN,
        deployed::fab_len(&records::redeem_record_v2_atoms()),
        "V2 redeem record width"
    );
    assert_eq!(RedeemEventV2::LEN, 439 + 1 - 36 - 35 + 1);
    assert_eq!(RedeemEventV2::LEN, 370);
    // The keccak block counts those widths buy: 3 → 3 for the vault record,
    // 5 → 4 for the swap record — the block that takes `swap` from k16 to
    // k15. Counted by the ROW MODEL's own `keccak_blocks` (rate 136, at least
    // one padding byte) rather than by a second copy of the padding rule
    // here: the block this saves is the block the cost model charges for, and
    // that is the claim.
    use minocrab_sim::v3::rowcost::keccak_blocks as blocks;
    assert_eq!((blocks(VaultEvent::LEN), blocks(VaultEventV2::LEN)), (3, 3));
    assert_eq!((blocks(SwapEvent::LEN), blocks(SwapEventV2::LEN)), (5, 4));

    assert_eq!(ClaimOutput::LEN, 1);
    assert_eq!(CompleteWithdrawOutput::LEN, 1);
    assert_eq!(RefundOutput::LEN, erc20_vault::MPC_FAILURE_OUTPUT.len());
    assert_eq!(CompleteSwapOutput::LEN, 8);
    assert_eq!(AttestationPreimage::<ClaimOutput>::LEN, 33);
    assert_eq!(AttestationPreimage::<CompleteSwapOutput>::LEN, 40);

    // M11 stage 5's shapes, and the digest preimages they define. These are
    // THE SPEC — the MPC has never settled on Midnight, so there is nothing
    // deployed to compare them against; what pins them is borsh's own
    // encoder, borsh's own schema, and the circuit that hashes them.
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

/// (b), the third half: the schema walk's own width agrees with `LEN`, so
/// the frozen offset table and the encoder cannot drift apart.
#[test]
fn schema_widths_match_the_lens() {
    let expected: Vec<(&str, usize)> = vec![
        ("VaultEvent", VaultEvent::LEN),
        ("SwapEvent", SwapEvent::LEN),
        ("SupplyEvent", SupplyEvent::LEN),
        ("RedeemEvent", RedeemEvent::LEN),
        ("VaultEventV2", VaultEventV2::LEN),
        ("SwapEventV2", SwapEventV2::LEN),
        ("RedeemEventV2", RedeemEventV2::LEN),
        ("ClaimOutput", ClaimOutput::LEN),
        ("CompleteWithdrawOutput", CompleteWithdrawOutput::LEN),
        ("RefundOutput", RefundOutput::LEN),
        ("CompleteSwapOutput", CompleteSwapOutput::LEN),
        ("AttestationPreimage<ClaimOutput>", AttestationPreimage::<ClaimOutput>::LEN),
        (
            "AttestationPreimage<CompleteWithdrawOutput>",
            AttestationPreimage::<CompleteWithdrawOutput>::LEN,
        ),
        ("AttestationPreimage<RefundOutput>", AttestationPreimage::<RefundOutput>::LEN),
        (
            "AttestationPreimage<CompleteSwapOutput>",
            AttestationPreimage::<CompleteSwapOutput>::LEN,
        ),
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

/// A V2 (M11 stage 7) record's limbs from the deployed record's: the
/// format-version byte in front, the two schema strings (four limbs) traded
/// for the response kind at the end. The middle is untouched — which is the
/// point of building it this way rather than restating it.
fn v2_limbs(deployed: &[Fr], kind: u8) -> Vec<Fr> {
    let mut limbs = vec![Fr::from(u64::from(spec_types::RECORD_FORMAT_VERSION))];
    limbs.extend_from_slice(&deployed[..deployed.len() - 4]);
    limbs.push(Fr::from(u64::from(kind)));
    limbs
}

proptest! {
    #![proptest_config(gen::config())]

    /// The 2-word request record — `startDeposit`, `approveRouter` and
    /// `startWithdraw` all write this shape.
    ///
    /// LEFT: the bytes the deployed record holds. The reference model's
    /// limbs under `erc20_vault::VaultEvent::atoms()`, packed by the FAB
    /// rule (`parse_field_repr` + `binary_repr`) — the record M28's
    /// differential suite pins to compactc's artifact.
    ///
    /// RIGHT: `borsh::to_vec` of the spec type at the same field values.
    #[test]
    fn vault_record_bytes_are_canonical_borsh(
        deposit in gen::start_deposit(),
        approve in gen::approve_router(),
        withdraw in gen::start_withdraw(),
    ) {
        let atoms = records::vault_record_atoms();
        for (name, limbs, spec) in [
            ("startDeposit", deposit.req().limbs(&deposit.env), records::deposit_event(&deposit)),
            ("approveRouter", approve.req().limbs(&approve.env), records::approve_event(&approve)),
            ("startWithdraw", withdraw.req().limbs(&withdraw.env), records::withdraw_event(&withdraw)),
        ] {
            prop_assert_eq!(limbs.len(), records::VAULT_RECORD_LIMBS);
            let on_chain = deployed::fab_bytes(&atoms, &limbs);
            let spec_bytes = borsh_bytes(&spec);
            prop_assert_eq!(&on_chain, &spec_bytes, "{}: record bytes differ", name);
            prop_assert_eq!(bincode_fixint_bytes(&spec), on_chain.clone(), "{}", name);
        }
    }

    /// The 7-word swap record.
    #[test]
    fn swap_record_bytes_are_canonical_borsh(swap in gen::start_swap()) {
        let limbs = swap.req().limbs(&swap.env);
        prop_assert_eq!(limbs.len(), records::SWAP_RECORD_LIMBS);
        let on_chain = deployed::fab_bytes(&records::swap_record_atoms(), &limbs);
        let spec = records::swap_event(&swap);
        prop_assert_eq!(&on_chain, &borsh_bytes(&spec));
        prop_assert_eq!(bincode_fixint_bytes(&spec), on_chain.clone());
    }

    /// The lending pair: `startSupply`'s 2-word record with the lending
    /// schemas, and `startRedeem`'s 3-word record.
    #[test]
    fn lending_record_bytes_are_canonical_borsh(
        supply in gen::start_supply(),
        redeem in gen::start_redeem(),
    ) {
        let limbs = supply.req().limbs(&supply.env);
        prop_assert_eq!(limbs.len(), records::SUPPLY_RECORD_LIMBS);
        let on_chain = deployed::fab_bytes(&records::supply_record_atoms(), &limbs);
        let spec = records::supply_event(&supply);
        prop_assert_eq!(on_chain.len(), SupplyEvent::LEN);
        prop_assert_eq!(&on_chain, &borsh_bytes(&spec));
        prop_assert_eq!(bincode_fixint_bytes(&spec), on_chain.clone());

        let limbs = redeem.req().limbs(&redeem.env);
        prop_assert_eq!(limbs.len(), records::REDEEM_RECORD_LIMBS);
        let on_chain = deployed::fab_bytes(&records::redeem_record_atoms(), &limbs);
        let spec = records::redeem_event(&redeem);
        prop_assert_eq!(on_chain.len(), RedeemEvent::LEN);
        prop_assert_eq!(&on_chain, &borsh_bytes(&spec));
        prop_assert_eq!(bincode_fixint_bytes(&spec), on_chain.clone());
    }

    /// The lending pair in V2: supply lands in `VaultEventV2` (kind 5), redeem
    /// in its own 3-word type (kind 6).
    #[test]
    fn stage7_lending_record_bytes_are_canonical_borsh(
        supply in gen::start_supply(),
        redeem in gen::start_redeem(),
    ) {
        use minocrab_contracts::erc20_vault_pending::{RESPONSE_KIND_REDEEM, RESPONSE_KIND_SUPPLY};
        let limbs = v2_limbs(&supply.req().limbs(&supply.env), records::kind(RESPONSE_KIND_SUPPLY));
        prop_assert_eq!(limbs.len(), records::VAULT_RECORD_V2_LIMBS);
        let on_chain = deployed::fab_bytes(&records::vault_record_v2_atoms(), &limbs);
        let spec = records::supply_event_v2(&supply);
        prop_assert_eq!(on_chain.len(), VaultEventV2::LEN);
        prop_assert_eq!(&on_chain, &borsh_bytes(&spec));
        prop_assert_eq!(bincode_fixint_bytes(&spec), on_chain.clone());

        let limbs = v2_limbs(&redeem.req().limbs(&redeem.env), records::kind(RESPONSE_KIND_REDEEM));
        prop_assert_eq!(limbs.len(), records::REDEEM_RECORD_V2_LIMBS);
        let on_chain = deployed::fab_bytes(&records::redeem_record_v2_atoms(), &limbs);
        let spec = records::redeem_event_v2(&redeem);
        prop_assert_eq!(on_chain.len(), RedeemEventV2::LEN);
        prop_assert_eq!(&on_chain, &borsh_bytes(&spec));
        prop_assert_eq!(bincode_fixint_bytes(&spec), on_chain.clone());
        prop_assert_eq!(on_chain[0], spec_types::RECORD_FORMAT_VERSION);
    }

    /// M11 STAGE 7: the record the V2 format writes (the `Pending`
    /// lineage's records).
    ///
    /// The deployed properties above are untouched; this is the same
    /// statement about the V2 format, with the same two independent sides.
    /// LEFT: the V2 limbs under `VaultEventV2::atoms()` — the deployed
    /// record's limbs with the version byte in front and the kind where the
    /// schema strings were ([`v2_limbs`]). RIGHT: `borsh::to_vec` of the
    /// spec twin.
    #[test]
    fn stage7_record_bytes_are_canonical_borsh(
        deposit in gen::start_deposit(),
        approve in gen::approve_router(),
        withdraw in gen::start_withdraw(),
        swap in gen::start_swap(),
    ) {
        use minocrab_contracts::erc20_vault_pending::{
            RESPONSE_KIND_APPROVE, RESPONSE_KIND_CLAIM, RESPONSE_KIND_SWAP, RESPONSE_KIND_WITHDRAW,
        };
        let atoms = records::vault_record_v2_atoms();
        for (name, limbs, spec) in [
            (
                "startDeposit",
                v2_limbs(&deposit.req().limbs(&deposit.env), records::kind(RESPONSE_KIND_CLAIM)),
                records::deposit_event_v2(&deposit),
            ),
            (
                "approveRouter",
                v2_limbs(&approve.req().limbs(&approve.env), records::kind(RESPONSE_KIND_APPROVE)),
                records::approve_event_v2(&approve),
            ),
            (
                "startWithdraw",
                v2_limbs(&withdraw.req().limbs(&withdraw.env), records::kind(RESPONSE_KIND_WITHDRAW)),
                records::withdraw_event_v2(&withdraw),
            ),
        ] {
            prop_assert_eq!(limbs.len(), records::VAULT_RECORD_V2_LIMBS);
            let on_chain = deployed::fab_bytes(&atoms, &limbs);
            prop_assert_eq!(on_chain.len(), VaultEventV2::LEN);
            let spec_bytes = borsh_bytes(&spec);
            prop_assert_eq!(&on_chain, &spec_bytes, "{}: stage-7 record bytes differ", name);
            prop_assert_eq!(bincode_fixint_bytes(&spec), on_chain.clone(), "{}", name);
            // The version byte is the first byte, before anything else.
            prop_assert_eq!(on_chain[0], spec_types::RECORD_FORMAT_VERSION);
        }

        let limbs = v2_limbs(&swap.req().limbs(&swap.env), records::kind(RESPONSE_KIND_SWAP));
        prop_assert_eq!(limbs.len(), records::SWAP_RECORD_V2_LIMBS);
        let on_chain = deployed::fab_bytes(&records::swap_record_v2_atoms(), &limbs);
        let spec = records::swap_event_v2(&swap);
        prop_assert_eq!(on_chain.len(), SwapEventV2::LEN);
        prop_assert_eq!(&on_chain, &borsh_bytes(&spec));
        prop_assert_eq!(bincode_fixint_bytes(&spec), on_chain.clone());
    }

    /// The attestation digest preimages of the settle circuits, one per
    /// output width.
    ///
    /// LEFT: `calculateSignetAttestationDigest`'s own alignment,
    /// `[Bytes<32>, Bytes<LEN_OUTPUT>]`, over the request id's slot pair
    /// and the output's limbs — the BYTES; the digest itself is Poseidon
    /// over those limbs since the protocol move, checked in the vault
    /// model against compactc's artifacts.
    #[test]
    fn attestation_preimages_are_canonical_borsh(
        claim in gen::complete_deposit(),
        complete_withdraw in gen::complete_withdraw(),
        refund in gen::refund_withdraw(),
        complete_swap in gen::complete_swap(),
    ) {
        // completeDeposit: Bytes<1>
        let rid = claim.d.request_id();
        let spec = AttestationPreimage { request_id: rid, output: ClaimOutput { success: claim.serialized_output } };
        let on_chain = deployed::attestation_preimage_bytes(&rid, 1, &claim.output_limbs());
        prop_assert_eq!(&on_chain, &borsh_bytes(&spec));

        // completeWithdraw: Bytes<1>
        let rid = complete_withdraw.w.request_id();
        let spec = AttestationPreimage {
            request_id: rid,
            output: CompleteWithdrawOutput { success: complete_withdraw.outcome },
        };
        let on_chain = deployed::attestation_preimage_bytes(&rid, 1, &complete_withdraw.output_limbs());
        prop_assert_eq!(&on_chain, &borsh_bytes(&spec));

        // refundWithdraw: Bytes<5>
        let rid = refund.w.request_id();
        let spec = AttestationPreimage {
            request_id: rid,
            output: RefundOutput { failure: refund.serialized_output },
        };
        let on_chain = deployed::attestation_preimage_bytes(&rid, 5, &refund.output_limbs());
        prop_assert_eq!(&on_chain, &borsh_bytes(&spec));

        // completeSwap: Bytes<8>, already a Borsh u64.
        let rid = complete_swap.s.request_id();
        let spec = AttestationPreimage {
            request_id: rid,
            output: CompleteSwapOutput { amount_in: complete_swap.amount_in },
        };
        let on_chain = deployed::attestation_preimage_bytes(&rid, 8, &complete_swap.output_limbs());
        prop_assert_eq!(&on_chain, &borsh_bytes(&spec));
    }
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
    ("VaultEvent", "sender", "[u8; 32]", 0, 32),
    ("VaultEvent", "request_nonce", "u64", 32, 8),
    ("VaultEvent", "key_version", "u8", 40, 1),
    ("VaultEvent", "path", "[u8; 32]", 41, 32),
    ("VaultEvent", "algo", "u8", 73, 1),
    ("VaultEvent", "dest", "u8", 74, 1),
    ("VaultEvent", "params", "[u8; 64]", 75, 64),
    ("VaultEvent", "tx_param_type", "u8", 139, 1),
    ("VaultEvent", "tx_params.chain_id", "u64", 140, 8),
    ("VaultEvent", "tx_params.nonce", "u64", 148, 8),
    ("VaultEvent", "tx_params.max_priority_fee_per_gas", "u128", 156, 16),
    ("VaultEvent", "tx_params.max_fee_per_gas", "u128", 172, 16),
    ("VaultEvent", "tx_params.gas_limit", "u64", 188, 8),
    ("VaultEvent", "tx_params.to", "[u8; 20]", 196, 20),
    ("VaultEvent", "tx_params.value", "u128", 216, 16),
    ("VaultEvent", "tx_params.calldata.is_some", "bool", 232, 1),
    ("VaultEvent", "tx_params.calldata.value.selector", "[u8; 4]", 233, 4),
    ("VaultEvent", "tx_params.calldata.value.no_words", "u16", 237, 2),
    ("VaultEvent", "tx_params.calldata.value.words[0]", "[u8; 32]", 239, 32),
    ("VaultEvent", "tx_params.calldata.value.words[1]", "[u8; 32]", 271, 32),
    ("VaultEvent", "tx_params.access_list_entry_count", "u8", 303, 1),
    ("VaultEvent", "caip2_id", "[u8; 32]", 304, 32),
    ("VaultEvent", "output_deserialization_schema", "[u8; 34]", 336, 34),
    ("VaultEvent", "respond_serialization_schema", "[u8; 34]", 370, 34),
    ("SwapEvent", "sender", "[u8; 32]", 0, 32),
    ("SwapEvent", "request_nonce", "u64", 32, 8),
    ("SwapEvent", "key_version", "u8", 40, 1),
    ("SwapEvent", "path", "[u8; 32]", 41, 32),
    ("SwapEvent", "algo", "u8", 73, 1),
    ("SwapEvent", "dest", "u8", 74, 1),
    ("SwapEvent", "params", "[u8; 64]", 75, 64),
    ("SwapEvent", "tx_param_type", "u8", 139, 1),
    ("SwapEvent", "tx_params.chain_id", "u64", 140, 8),
    ("SwapEvent", "tx_params.nonce", "u64", 148, 8),
    ("SwapEvent", "tx_params.max_priority_fee_per_gas", "u128", 156, 16),
    ("SwapEvent", "tx_params.max_fee_per_gas", "u128", 172, 16),
    ("SwapEvent", "tx_params.gas_limit", "u64", 188, 8),
    ("SwapEvent", "tx_params.to", "[u8; 20]", 196, 20),
    ("SwapEvent", "tx_params.value", "u128", 216, 16),
    ("SwapEvent", "tx_params.calldata.is_some", "bool", 232, 1),
    ("SwapEvent", "tx_params.calldata.value.selector", "[u8; 4]", 233, 4),
    ("SwapEvent", "tx_params.calldata.value.no_words", "u16", 237, 2),
    ("SwapEvent", "tx_params.calldata.value.words[0]", "[u8; 32]", 239, 32),
    ("SwapEvent", "tx_params.calldata.value.words[1]", "[u8; 32]", 271, 32),
    ("SwapEvent", "tx_params.calldata.value.words[2]", "[u8; 32]", 303, 32),
    ("SwapEvent", "tx_params.calldata.value.words[3]", "[u8; 32]", 335, 32),
    ("SwapEvent", "tx_params.calldata.value.words[4]", "[u8; 32]", 367, 32),
    ("SwapEvent", "tx_params.calldata.value.words[5]", "[u8; 32]", 399, 32),
    ("SwapEvent", "tx_params.calldata.value.words[6]", "[u8; 32]", 431, 32),
    ("SwapEvent", "tx_params.access_list_entry_count", "u8", 463, 1),
    ("SwapEvent", "caip2_id", "[u8; 32]", 464, 32),
    ("SwapEvent", "output_deserialization_schema", "[u8; 38]", 496, 38),
    ("SwapEvent", "respond_serialization_schema", "[u8; 37]", 534, 37),
    ("SupplyEvent", "sender", "[u8; 32]", 0, 32),
    ("SupplyEvent", "request_nonce", "u64", 32, 8),
    ("SupplyEvent", "key_version", "u8", 40, 1),
    ("SupplyEvent", "path", "[u8; 32]", 41, 32),
    ("SupplyEvent", "algo", "u8", 73, 1),
    ("SupplyEvent", "dest", "u8", 74, 1),
    ("SupplyEvent", "params", "[u8; 64]", 75, 64),
    ("SupplyEvent", "tx_param_type", "u8", 139, 1),
    ("SupplyEvent", "tx_params.chain_id", "u64", 140, 8),
    ("SupplyEvent", "tx_params.nonce", "u64", 148, 8),
    ("SupplyEvent", "tx_params.max_priority_fee_per_gas", "u128", 156, 16),
    ("SupplyEvent", "tx_params.max_fee_per_gas", "u128", 172, 16),
    ("SupplyEvent", "tx_params.gas_limit", "u64", 188, 8),
    ("SupplyEvent", "tx_params.to", "[u8; 20]", 196, 20),
    ("SupplyEvent", "tx_params.value", "u128", 216, 16),
    ("SupplyEvent", "tx_params.calldata.is_some", "bool", 232, 1),
    ("SupplyEvent", "tx_params.calldata.value.selector", "[u8; 4]", 233, 4),
    ("SupplyEvent", "tx_params.calldata.value.no_words", "u16", 237, 2),
    ("SupplyEvent", "tx_params.calldata.value.words[0]", "[u8; 32]", 239, 32),
    ("SupplyEvent", "tx_params.calldata.value.words[1]", "[u8; 32]", 271, 32),
    ("SupplyEvent", "tx_params.access_list_entry_count", "u8", 303, 1),
    ("SupplyEvent", "caip2_id", "[u8; 32]", 304, 32),
    ("SupplyEvent", "output_deserialization_schema", "[u8; 36]", 336, 36),
    ("SupplyEvent", "respond_serialization_schema", "[u8; 35]", 372, 35),
    ("RedeemEvent", "sender", "[u8; 32]", 0, 32),
    ("RedeemEvent", "request_nonce", "u64", 32, 8),
    ("RedeemEvent", "key_version", "u8", 40, 1),
    ("RedeemEvent", "path", "[u8; 32]", 41, 32),
    ("RedeemEvent", "algo", "u8", 73, 1),
    ("RedeemEvent", "dest", "u8", 74, 1),
    ("RedeemEvent", "params", "[u8; 64]", 75, 64),
    ("RedeemEvent", "tx_param_type", "u8", 139, 1),
    ("RedeemEvent", "tx_params.chain_id", "u64", 140, 8),
    ("RedeemEvent", "tx_params.nonce", "u64", 148, 8),
    ("RedeemEvent", "tx_params.max_priority_fee_per_gas", "u128", 156, 16),
    ("RedeemEvent", "tx_params.max_fee_per_gas", "u128", 172, 16),
    ("RedeemEvent", "tx_params.gas_limit", "u64", 188, 8),
    ("RedeemEvent", "tx_params.to", "[u8; 20]", 196, 20),
    ("RedeemEvent", "tx_params.value", "u128", 216, 16),
    ("RedeemEvent", "tx_params.calldata.is_some", "bool", 232, 1),
    ("RedeemEvent", "tx_params.calldata.value.selector", "[u8; 4]", 233, 4),
    ("RedeemEvent", "tx_params.calldata.value.no_words", "u16", 237, 2),
    ("RedeemEvent", "tx_params.calldata.value.words[0]", "[u8; 32]", 239, 32),
    ("RedeemEvent", "tx_params.calldata.value.words[1]", "[u8; 32]", 271, 32),
    ("RedeemEvent", "tx_params.calldata.value.words[2]", "[u8; 32]", 303, 32),
    ("RedeemEvent", "tx_params.access_list_entry_count", "u8", 335, 1),
    ("RedeemEvent", "caip2_id", "[u8; 32]", 336, 32),
    ("RedeemEvent", "output_deserialization_schema", "[u8; 36]", 368, 36),
    ("RedeemEvent", "respond_serialization_schema", "[u8; 35]", 404, 35),
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
    ("ClaimOutput", "success", "u8", 0, 1),
    ("CompleteWithdrawOutput", "success", "u8", 0, 1),
    ("RefundOutput", "failure", "[u8; 5]", 0, 5),
    ("CompleteSwapOutput", "amount_in", "u64", 0, 8),
    ("AttestationPreimage<ClaimOutput>", "request_id", "[u8; 32]", 0, 32),
    ("AttestationPreimage<ClaimOutput>", "output.success", "u8", 32, 1),
    ("AttestationPreimage<CompleteWithdrawOutput>", "request_id", "[u8; 32]", 0, 32),
    ("AttestationPreimage<CompleteWithdrawOutput>", "output.success", "u8", 32, 1),
    ("AttestationPreimage<RefundOutput>", "request_id", "[u8; 32]", 0, 32),
    ("AttestationPreimage<RefundOutput>", "output.failure", "[u8; 5]", 32, 5),
    ("AttestationPreimage<CompleteSwapOutput>", "request_id", "[u8; 32]", 0, 32),
    ("AttestationPreimage<CompleteSwapOutput>", "output.amount_in", "u64", 32, 8),
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

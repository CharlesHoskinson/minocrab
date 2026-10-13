//! A frozen snapshot of every circuit's ORDERED interface: arguments,
//! outputs and witness reads.
//!
//! The differential comparator (`assert_call_compatible`) checks only the
//! *type* column of the input schema — and nearly every argument is a
//! `Scalar<BLS12-381>`, so a same-typed permutation of the argument list is
//! invisible to it except through PI equality on the one honest preimage it
//! runs. Argument ORDER is the real contract: it feeds the communications
//! commitment and the preimage layout, so a reorder, rename or insertion
//! silently breaks every caller. This test is the instrument that makes such
//! movement mechanically visible before the M9 port starts rewriting the
//! argument lists.
//!
//! Per circuit it freezes, in order:
//!   - `in  <label>: <type>` — one line per `IrSource::inputs` entry (the
//!     `c.arg` calls, in declaration order). The label is the declared name
//!     with the `%`/`.index` disambiguator stripped.
//!   - `out <label>: <type>` — one line per `IrSource::outputs` entry,
//!     labelled from the matching `DisclosureKind::Output` record (the IR
//!     itself carries no output names).
//!   - `wit <type>` — one line per `PrivateInput` instruction, i.e. per
//!     private-transcript read, in execution order; `(guarded)` marks a
//!     conditional read. Witnesses are not entry-point arguments, and
//!     `Compiled3` only counts them, so the list is recovered from the
//!     instruction stream (the count is cross-checked against
//!     `Compiled3::witnesses`).
//!
//! To regenerate after an INTENTIONAL interface change (a toolchain bump
//! that moves a schema is one — notes/version-bump.org):
//! `cargo test --release -p minocrab-contracts --test interface_snapshot -- \
//!      --ignored regenerate_interface_snapshot`, or `./bump.sh accept` to
//! run every regenerator at once. It rewrites the table below in place, so
//! the new baseline arrives as a reviewable diff.

mod support;

use minocrab::v3::Compiled3;
use minocrab::DisclosureKind;
use minocrab_zkir::v3::{Instruction, IrType};
use support::{circuits, diff, rewrite_generated_region, test_source};

/// `(circuit, interface)` — frozen at "M9 phase 0: freeze every circuit's
/// ordered interface in a snapshot guard test".
const SNAPSHOT: &[(&str, &str)] = &[
    // GENERATED BEGIN — rewritten by `regenerate_interface_snapshot`
    (
        "erc20_vault::initialise",
        "\
in  vaultEvm: Scalar<BLS12-381>
in  swapRouter: Scalar<BLS12-381>
in  stataUnderlyingAddr: Scalar<BLS12-381>
in  stataTokenAddr: Scalar<BLS12-381>
in  chainId: Scalar<BLS12-381>
in  responseKey: Point<Secp256k1>
in  responseKeyVersion: Scalar<BLS12-381>
in  evmHeight: Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
",
    ),
    (
        "erc20_vault::set_gas_params",
        "\
in  newMaxFeePerGas: Scalar<BLS12-381>
in  newMaxPriorityFeePerGas: Scalar<BLS12-381>
in  newWithdrawGasLimit: Scalar<BLS12-381>
in  newApproveGasLimit: Scalar<BLS12-381>
in  newSwapGasLimit: Scalar<BLS12-381>
in  newSupplyGasLimit: Scalar<BLS12-381>
in  newRedeemGasLimit: Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
",
    ),
    (
        "erc20_vault::add_allowed_token",
        "\
in  erc20Address: Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
",
    ),
    (
        "erc20_vault::flush_queue",
        "\
in  slots_0_channel: Scalar<BLS12-381>
in  slots_0_inIndex: Scalar<BLS12-381>
in  slots_0_requestId_hi: Scalar<BLS12-381>
in  slots_0_requestId_lo: Scalar<BLS12-381>
in  slots_1_channel: Scalar<BLS12-381>
in  slots_1_inIndex: Scalar<BLS12-381>
in  slots_1_requestId_hi: Scalar<BLS12-381>
in  slots_1_requestId_lo: Scalar<BLS12-381>
in  slots_2_channel: Scalar<BLS12-381>
in  slots_2_inIndex: Scalar<BLS12-381>
in  slots_2_requestId_hi: Scalar<BLS12-381>
in  slots_2_requestId_lo: Scalar<BLS12-381>
in  slots_3_channel: Scalar<BLS12-381>
in  slots_3_inIndex: Scalar<BLS12-381>
in  slots_3_requestId_hi: Scalar<BLS12-381>
in  slots_3_requestId_lo: Scalar<BLS12-381>
in  slots_4_channel: Scalar<BLS12-381>
in  slots_4_inIndex: Scalar<BLS12-381>
in  slots_4_requestId_hi: Scalar<BLS12-381>
in  slots_4_requestId_lo: Scalar<BLS12-381>
in  slots_5_channel: Scalar<BLS12-381>
in  slots_5_inIndex: Scalar<BLS12-381>
in  slots_5_requestId_hi: Scalar<BLS12-381>
in  slots_5_requestId_lo: Scalar<BLS12-381>
in  slots_6_channel: Scalar<BLS12-381>
in  slots_6_inIndex: Scalar<BLS12-381>
in  slots_6_requestId_hi: Scalar<BLS12-381>
in  slots_6_requestId_lo: Scalar<BLS12-381>
in  slots_7_channel: Scalar<BLS12-381>
in  slots_7_inIndex: Scalar<BLS12-381>
in  slots_7_requestId_hi: Scalar<BLS12-381>
in  slots_7_requestId_lo: Scalar<BLS12-381>
in  slots_8_channel: Scalar<BLS12-381>
in  slots_8_inIndex: Scalar<BLS12-381>
in  slots_8_requestId_hi: Scalar<BLS12-381>
in  slots_8_requestId_lo: Scalar<BLS12-381>
in  slots_9_channel: Scalar<BLS12-381>
in  slots_9_inIndex: Scalar<BLS12-381>
in  slots_9_requestId_hi: Scalar<BLS12-381>
in  slots_9_requestId_lo: Scalar<BLS12-381>
",
    ),
    (
        "erc20_vault::queue_attestation0",
        "\
in  respondBidirectionalEvent_requestId_hi: Scalar<BLS12-381>
in  respondBidirectionalEvent_requestId_lo: Scalar<BLS12-381>
in  respondBidirectionalEvent_blockHeight: Scalar<BLS12-381>
in  respondBidirectionalEvent_outputKind: Scalar<BLS12-381>
in  respondBidirectionalEvent_serializedOutputLength: Scalar<BLS12-381>
in  respondBidirectionalEvent_digest_hi: Scalar<BLS12-381>
in  respondBidirectionalEvent_digest_lo: Scalar<BLS12-381>
in  respondBidirectionalEvent_signature_bigR_x_hi: Scalar<BLS12-381>
in  respondBidirectionalEvent_signature_bigR_x_lo: Scalar<BLS12-381>
in  respondBidirectionalEvent_signature_bigR_y_hi: Scalar<BLS12-381>
in  respondBidirectionalEvent_signature_bigR_y_lo: Scalar<BLS12-381>
in  respondBidirectionalEvent_signature_s_hi: Scalar<BLS12-381>
in  respondBidirectionalEvent_signature_s_lo: Scalar<BLS12-381>
in  respondBidirectionalEvent_signature_recoveryId: Scalar<BLS12-381>
",
    ),
    (
        "erc20_vault::queue_attestation1",
        "\
in  respondBidirectionalEvent_requestId_hi: Scalar<BLS12-381>
in  respondBidirectionalEvent_requestId_lo: Scalar<BLS12-381>
in  respondBidirectionalEvent_blockHeight: Scalar<BLS12-381>
in  respondBidirectionalEvent_outputKind: Scalar<BLS12-381>
in  respondBidirectionalEvent_serializedOutputLength: Scalar<BLS12-381>
in  respondBidirectionalEvent_digest_hi: Scalar<BLS12-381>
in  respondBidirectionalEvent_digest_lo: Scalar<BLS12-381>
in  respondBidirectionalEvent_signature_bigR_x_hi: Scalar<BLS12-381>
in  respondBidirectionalEvent_signature_bigR_x_lo: Scalar<BLS12-381>
in  respondBidirectionalEvent_signature_bigR_y_hi: Scalar<BLS12-381>
in  respondBidirectionalEvent_signature_bigR_y_lo: Scalar<BLS12-381>
in  respondBidirectionalEvent_signature_s_hi: Scalar<BLS12-381>
in  respondBidirectionalEvent_signature_s_lo: Scalar<BLS12-381>
in  respondBidirectionalEvent_signature_recoveryId: Scalar<BLS12-381>
in  serializedOutput: Scalar<BLS12-381>
",
    ),
    (
        "erc20_vault::queue_attestation32",
        "\
in  respondBidirectionalEvent_requestId_hi: Scalar<BLS12-381>
in  respondBidirectionalEvent_requestId_lo: Scalar<BLS12-381>
in  respondBidirectionalEvent_blockHeight: Scalar<BLS12-381>
in  respondBidirectionalEvent_outputKind: Scalar<BLS12-381>
in  respondBidirectionalEvent_serializedOutputLength: Scalar<BLS12-381>
in  respondBidirectionalEvent_digest_hi: Scalar<BLS12-381>
in  respondBidirectionalEvent_digest_lo: Scalar<BLS12-381>
in  respondBidirectionalEvent_signature_bigR_x_hi: Scalar<BLS12-381>
in  respondBidirectionalEvent_signature_bigR_x_lo: Scalar<BLS12-381>
in  respondBidirectionalEvent_signature_bigR_y_hi: Scalar<BLS12-381>
in  respondBidirectionalEvent_signature_bigR_y_lo: Scalar<BLS12-381>
in  respondBidirectionalEvent_signature_s_hi: Scalar<BLS12-381>
in  respondBidirectionalEvent_signature_s_lo: Scalar<BLS12-381>
in  respondBidirectionalEvent_signature_recoveryId: Scalar<BLS12-381>
in  serializedOutput_hi: Scalar<BLS12-381>
in  serializedOutput_lo: Scalar<BLS12-381>
",
    ),
    (
        "erc20_vault::start_replace_nonce",
        "\
in  inIndex: Scalar<BLS12-381>
in  requestId_hi: Scalar<BLS12-381>
in  requestId_lo: Scalar<BLS12-381>
in  action: Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
",
    ),
    (
        "erc20_vault::send_replace_nonce",
        "\
in  outIndex_hi: Scalar<BLS12-381>
in  outIndex_lo: Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
",
    ),
    (
        "erc20_vault::complete_replace_nonce",
        "\
in  requestId_hi: Scalar<BLS12-381>
in  requestId_lo: Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
",
    ),
    (
        "erc20_vault::start_approve_router",
        "\
in  inIndex: Scalar<BLS12-381>
in  erc20Address: Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
",
    ),
    (
        "erc20_vault::start_approve_stata",
        "\
in  inIndex: Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
",
    ),
    (
        "erc20_vault::send_approve",
        "\
in  outIndex_hi: Scalar<BLS12-381>
in  outIndex_lo: Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
",
    ),
    (
        "erc20_vault::complete_approve",
        "\
in  requestId_hi: Scalar<BLS12-381>
in  requestId_lo: Scalar<BLS12-381>
in  serializedOutput: Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
",
    ),
    (
        "erc20_vault::start_deposit",
        "\
in  inIndex: Scalar<BLS12-381>
in  evmNonce: Scalar<BLS12-381>
in  gas_gasLimit: Scalar<BLS12-381>
in  gas_maxFeePerGas: Scalar<BLS12-381>
in  gas_maxPriorityFeePerGas: Scalar<BLS12-381>
in  depositRequest_erc20Address: Scalar<BLS12-381>
in  depositRequest_amount: Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
",
    ),
    (
        "erc20_vault::send_deposit",
        "\
in  outIndex_hi: Scalar<BLS12-381>
in  outIndex_lo: Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
",
    ),
    (
        "erc20_vault::complete_deposit",
        "\
in  requestId_hi: Scalar<BLS12-381>
in  requestId_lo: Scalar<BLS12-381>
in  serializedOutput: Scalar<BLS12-381>
in  mintNonce_hi: Scalar<BLS12-381>
in  mintNonce_lo: Scalar<BLS12-381>
in  recipient_is_some: Scalar<BLS12-381>
in  recipient_is_left: Scalar<BLS12-381>
in  recipient_left_hi: Scalar<BLS12-381>
in  recipient_left_lo: Scalar<BLS12-381>
in  recipient_right_hi: Scalar<BLS12-381>
in  recipient_right_lo: Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381> (guarded)
wit Scalar<BLS12-381> (guarded)
",
    ),
    (
        "erc20_vault::start_withdraw",
        "\
in  inIndex: Scalar<BLS12-381>
in  withdrawRequest_erc20Address: Scalar<BLS12-381>
in  withdrawRequest_amount: Scalar<BLS12-381>
in  withdrawRequest_destEvmAddress: Scalar<BLS12-381>
in  coin_nonce_hi: Scalar<BLS12-381>
in  coin_nonce_lo: Scalar<BLS12-381>
in  coin_color_hi: Scalar<BLS12-381>
in  coin_color_lo: Scalar<BLS12-381>
in  coin_value: Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
",
    ),
    (
        "erc20_vault::send_withdraw",
        "\
in  outIndex_hi: Scalar<BLS12-381>
in  outIndex_lo: Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
",
    ),
    (
        "erc20_vault::complete_withdraw",
        "\
in  requestId_hi: Scalar<BLS12-381>
in  requestId_lo: Scalar<BLS12-381>
in  serializedOutput: Scalar<BLS12-381>
in  mintNonce_hi: Scalar<BLS12-381>
in  mintNonce_lo: Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381> (guarded)
wit Scalar<BLS12-381> (guarded)
",
    ),
    (
        "erc20_vault::start_swap",
        "\
in  inIndex: Scalar<BLS12-381>
in  swapRequest_erc20AddressIn: Scalar<BLS12-381>
in  swapRequest_erc20AddressOut: Scalar<BLS12-381>
in  swapRequest_fee: Scalar<BLS12-381>
in  swapRequest_amountOut: Scalar<BLS12-381>
in  swapRequest_amountInMaximum: Scalar<BLS12-381>
in  coin_nonce_hi: Scalar<BLS12-381>
in  coin_nonce_lo: Scalar<BLS12-381>
in  coin_color_hi: Scalar<BLS12-381>
in  coin_color_lo: Scalar<BLS12-381>
in  coin_value: Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
",
    ),
    (
        "erc20_vault::send_swap",
        "\
in  outIndex_hi: Scalar<BLS12-381>
in  outIndex_lo: Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
",
    ),
    (
        "erc20_vault::complete_swap",
        "\
in  requestId_hi: Scalar<BLS12-381>
in  requestId_lo: Scalar<BLS12-381>
in  serializedOutput_hi: Scalar<BLS12-381>
in  serializedOutput_lo: Scalar<BLS12-381>
in  mintNonce_hi: Scalar<BLS12-381>
in  mintNonce_lo: Scalar<BLS12-381>
in  changeNonce_hi: Scalar<BLS12-381>
in  changeNonce_lo: Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
",
    ),
    (
        "erc20_vault::start_supply",
        "\
in  inIndex: Scalar<BLS12-381>
in  supplyRequest_amount: Scalar<BLS12-381>
in  coin_nonce_hi: Scalar<BLS12-381>
in  coin_nonce_lo: Scalar<BLS12-381>
in  coin_color_hi: Scalar<BLS12-381>
in  coin_color_lo: Scalar<BLS12-381>
in  coin_value: Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
",
    ),
    (
        "erc20_vault::send_supply",
        "\
in  outIndex_hi: Scalar<BLS12-381>
in  outIndex_lo: Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
",
    ),
    (
        "erc20_vault::complete_supply",
        "\
in  requestId_hi: Scalar<BLS12-381>
in  requestId_lo: Scalar<BLS12-381>
in  serializedOutput_hi: Scalar<BLS12-381>
in  serializedOutput_lo: Scalar<BLS12-381>
in  mintNonce_hi: Scalar<BLS12-381>
in  mintNonce_lo: Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
",
    ),
    (
        "erc20_vault::start_redeem",
        "\
in  inIndex: Scalar<BLS12-381>
in  redeemRequest_shares: Scalar<BLS12-381>
in  coin_nonce_hi: Scalar<BLS12-381>
in  coin_nonce_lo: Scalar<BLS12-381>
in  coin_color_hi: Scalar<BLS12-381>
in  coin_color_lo: Scalar<BLS12-381>
in  coin_value: Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
",
    ),
    (
        "erc20_vault::send_redeem",
        "\
in  outIndex_hi: Scalar<BLS12-381>
in  outIndex_lo: Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
",
    ),
    (
        "erc20_vault::complete_redeem",
        "\
in  requestId_hi: Scalar<BLS12-381>
in  requestId_lo: Scalar<BLS12-381>
in  serializedOutput_hi: Scalar<BLS12-381>
in  serializedOutput_lo: Scalar<BLS12-381>
in  mintNonce_hi: Scalar<BLS12-381>
in  mintNonce_lo: Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
",
    ),
    (
        "erc20_vault_pending::initialize",
        "\
in  vaultEvm: Scalar<BLS12-381>
in  swapRouter: Scalar<BLS12-381>
in  stataUnderlyingAddr: Scalar<BLS12-381>
in  stataTokenAddr: Scalar<BLS12-381>
in  chainId: Scalar<BLS12-381>
in  keyVersion: Scalar<BLS12-381>
in  responseKey: Point<Secp256k1>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
",
    ),
    (
        "erc20_vault_pending::deposit",
        "\
in  evmNonce: Scalar<BLS12-381>
in  gasLimit: Scalar<BLS12-381>
in  maxFeePerGas: Scalar<BLS12-381>
in  maxPriorityFeePerGas: Scalar<BLS12-381>
in  depositRequest_erc20Address: Scalar<BLS12-381>
in  depositRequest_amount: Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
",
    ),
    (
        "erc20_vault_pending::claim",
        "\
in  ticket_respond_requestId_hi: Scalar<BLS12-381>
in  ticket_respond_requestId_lo: Scalar<BLS12-381>
in  ticket_respond_blockHeight: Scalar<BLS12-381>
in  ticket_respond_outputKind: Scalar<BLS12-381>
in  ticket_respond_serializedOutputLength: Scalar<BLS12-381>
in  ticket_respond_digest_hi: Scalar<BLS12-381>
in  ticket_respond_digest_lo: Scalar<BLS12-381>
in  ticket_respond_signature_bigR_x_hi: Scalar<BLS12-381>
in  ticket_respond_signature_bigR_x_lo: Scalar<BLS12-381>
in  ticket_respond_signature_bigR_y_hi: Scalar<BLS12-381>
in  ticket_respond_signature_bigR_y_lo: Scalar<BLS12-381>
in  ticket_respond_signature_s_hi: Scalar<BLS12-381>
in  ticket_respond_signature_s_lo: Scalar<BLS12-381>
in  ticket_respond_signature_recoveryId: Scalar<BLS12-381>
in  ticket_serializedOutput: Scalar<BLS12-381>
in  mintNonce_hi: Scalar<BLS12-381>
in  mintNonce_lo: Scalar<BLS12-381>
in  recipient_is_some: Scalar<BLS12-381>
in  recipient_is_left: Scalar<BLS12-381>
in  recipient_left_hi: Scalar<BLS12-381>
in  recipient_left_lo: Scalar<BLS12-381>
in  recipient_right_hi: Scalar<BLS12-381>
in  recipient_right_lo: Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381> (guarded)
wit Scalar<BLS12-381> (guarded)
",
    ),
    (
        "erc20_vault_pending::approve_router",
        "\
in  erc20Address: Scalar<BLS12-381>
in  evmNonce: Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
",
    ),
    (
        "erc20_vault_pending::withdraw",
        "\
in  evmNonce: Scalar<BLS12-381>
in  withdrawRequest_erc20Address: Scalar<BLS12-381>
in  withdrawRequest_amount: Scalar<BLS12-381>
in  withdrawRequest_destEvmAddress: Scalar<BLS12-381>
in  coin_nonce_hi: Scalar<BLS12-381>
in  coin_nonce_lo: Scalar<BLS12-381>
in  coin_color_hi: Scalar<BLS12-381>
in  coin_color_lo: Scalar<BLS12-381>
in  coin_value: Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
",
    ),
    (
        "erc20_vault_pending::complete_withdraw",
        "\
in  ticket_respond_requestId_hi: Scalar<BLS12-381>
in  ticket_respond_requestId_lo: Scalar<BLS12-381>
in  ticket_respond_blockHeight: Scalar<BLS12-381>
in  ticket_respond_outputKind: Scalar<BLS12-381>
in  ticket_respond_serializedOutputLength: Scalar<BLS12-381>
in  ticket_respond_digest_hi: Scalar<BLS12-381>
in  ticket_respond_digest_lo: Scalar<BLS12-381>
in  ticket_respond_signature_bigR_x_hi: Scalar<BLS12-381>
in  ticket_respond_signature_bigR_x_lo: Scalar<BLS12-381>
in  ticket_respond_signature_bigR_y_hi: Scalar<BLS12-381>
in  ticket_respond_signature_bigR_y_lo: Scalar<BLS12-381>
in  ticket_respond_signature_s_hi: Scalar<BLS12-381>
in  ticket_respond_signature_s_lo: Scalar<BLS12-381>
in  ticket_respond_signature_recoveryId: Scalar<BLS12-381>
in  ticket_serializedOutput: Scalar<BLS12-381>
",
    ),
    (
        "erc20_vault_pending::refund_withdrawal",
        "\
in  ticket_respond_requestId_hi: Scalar<BLS12-381>
in  ticket_respond_requestId_lo: Scalar<BLS12-381>
in  ticket_respond_blockHeight: Scalar<BLS12-381>
in  ticket_respond_outputKind: Scalar<BLS12-381>
in  ticket_respond_serializedOutputLength: Scalar<BLS12-381>
in  ticket_respond_digest_hi: Scalar<BLS12-381>
in  ticket_respond_digest_lo: Scalar<BLS12-381>
in  ticket_respond_signature_bigR_x_hi: Scalar<BLS12-381>
in  ticket_respond_signature_bigR_x_lo: Scalar<BLS12-381>
in  ticket_respond_signature_bigR_y_hi: Scalar<BLS12-381>
in  ticket_respond_signature_bigR_y_lo: Scalar<BLS12-381>
in  ticket_respond_signature_s_hi: Scalar<BLS12-381>
in  ticket_respond_signature_s_lo: Scalar<BLS12-381>
in  ticket_respond_signature_recoveryId: Scalar<BLS12-381>
in  ticket_serializedOutput: Scalar<BLS12-381>
in  mintNonce_hi: Scalar<BLS12-381>
in  mintNonce_lo: Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
",
    ),
    (
        "erc20_vault_pending::swap",
        "\
in  evmNonce: Scalar<BLS12-381>
in  swapRequest_tokenIn: Scalar<BLS12-381>
in  swapRequest_tokenOut: Scalar<BLS12-381>
in  swapRequest_fee: Scalar<BLS12-381>
in  swapRequest_amountOut: Scalar<BLS12-381>
in  swapRequest_amountInMaximum: Scalar<BLS12-381>
in  coin_nonce_hi: Scalar<BLS12-381>
in  coin_nonce_lo: Scalar<BLS12-381>
in  coin_color_hi: Scalar<BLS12-381>
in  coin_color_lo: Scalar<BLS12-381>
in  coin_value: Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
",
    ),
    (
        "erc20_vault_pending::complete_swap",
        "\
in  ticket_respond_requestId_hi: Scalar<BLS12-381>
in  ticket_respond_requestId_lo: Scalar<BLS12-381>
in  ticket_respond_blockHeight: Scalar<BLS12-381>
in  ticket_respond_outputKind: Scalar<BLS12-381>
in  ticket_respond_serializedOutputLength: Scalar<BLS12-381>
in  ticket_respond_digest_hi: Scalar<BLS12-381>
in  ticket_respond_digest_lo: Scalar<BLS12-381>
in  ticket_respond_signature_bigR_x_hi: Scalar<BLS12-381>
in  ticket_respond_signature_bigR_x_lo: Scalar<BLS12-381>
in  ticket_respond_signature_bigR_y_hi: Scalar<BLS12-381>
in  ticket_respond_signature_bigR_y_lo: Scalar<BLS12-381>
in  ticket_respond_signature_s_hi: Scalar<BLS12-381>
in  ticket_respond_signature_s_lo: Scalar<BLS12-381>
in  ticket_respond_signature_recoveryId: Scalar<BLS12-381>
in  ticket_serializedOutput_hi: Scalar<BLS12-381>
in  ticket_serializedOutput_lo: Scalar<BLS12-381>
in  mintNonce_hi: Scalar<BLS12-381>
in  mintNonce_lo: Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
",
    ),
    (
        "erc20_vault_pending::refund_swap",
        "\
in  ticket_respond_requestId_hi: Scalar<BLS12-381>
in  ticket_respond_requestId_lo: Scalar<BLS12-381>
in  ticket_respond_blockHeight: Scalar<BLS12-381>
in  ticket_respond_outputKind: Scalar<BLS12-381>
in  ticket_respond_serializedOutputLength: Scalar<BLS12-381>
in  ticket_respond_digest_hi: Scalar<BLS12-381>
in  ticket_respond_digest_lo: Scalar<BLS12-381>
in  ticket_respond_signature_bigR_x_hi: Scalar<BLS12-381>
in  ticket_respond_signature_bigR_x_lo: Scalar<BLS12-381>
in  ticket_respond_signature_bigR_y_hi: Scalar<BLS12-381>
in  ticket_respond_signature_bigR_y_lo: Scalar<BLS12-381>
in  ticket_respond_signature_s_hi: Scalar<BLS12-381>
in  ticket_respond_signature_s_lo: Scalar<BLS12-381>
in  ticket_respond_signature_recoveryId: Scalar<BLS12-381>
in  ticket_serializedOutput_hi: Scalar<BLS12-381>
in  ticket_serializedOutput_lo: Scalar<BLS12-381>
in  mintNonce_hi: Scalar<BLS12-381>
in  mintNonce_lo: Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
",
    ),
    (
        "erc20_vault_pending::approve_stata",
        "\
in  evmNonce: Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
",
    ),
    (
        "erc20_vault_pending::supply",
        "\
in  evmNonce: Scalar<BLS12-381>
in  amount: Scalar<BLS12-381>
in  coin_nonce_hi: Scalar<BLS12-381>
in  coin_nonce_lo: Scalar<BLS12-381>
in  coin_color_hi: Scalar<BLS12-381>
in  coin_color_lo: Scalar<BLS12-381>
in  coin_value: Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
",
    ),
    (
        "erc20_vault_pending::complete_supply",
        "\
in  ticket_respond_requestId_hi: Scalar<BLS12-381>
in  ticket_respond_requestId_lo: Scalar<BLS12-381>
in  ticket_respond_blockHeight: Scalar<BLS12-381>
in  ticket_respond_outputKind: Scalar<BLS12-381>
in  ticket_respond_serializedOutputLength: Scalar<BLS12-381>
in  ticket_respond_digest_hi: Scalar<BLS12-381>
in  ticket_respond_digest_lo: Scalar<BLS12-381>
in  ticket_respond_signature_bigR_x_hi: Scalar<BLS12-381>
in  ticket_respond_signature_bigR_x_lo: Scalar<BLS12-381>
in  ticket_respond_signature_bigR_y_hi: Scalar<BLS12-381>
in  ticket_respond_signature_bigR_y_lo: Scalar<BLS12-381>
in  ticket_respond_signature_s_hi: Scalar<BLS12-381>
in  ticket_respond_signature_s_lo: Scalar<BLS12-381>
in  ticket_respond_signature_recoveryId: Scalar<BLS12-381>
in  ticket_serializedOutput_hi: Scalar<BLS12-381>
in  ticket_serializedOutput_lo: Scalar<BLS12-381>
in  mintNonce_hi: Scalar<BLS12-381>
in  mintNonce_lo: Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
",
    ),
    (
        "erc20_vault_pending::refund_supply",
        "\
in  ticket_respond_requestId_hi: Scalar<BLS12-381>
in  ticket_respond_requestId_lo: Scalar<BLS12-381>
in  ticket_respond_blockHeight: Scalar<BLS12-381>
in  ticket_respond_outputKind: Scalar<BLS12-381>
in  ticket_respond_serializedOutputLength: Scalar<BLS12-381>
in  ticket_respond_digest_hi: Scalar<BLS12-381>
in  ticket_respond_digest_lo: Scalar<BLS12-381>
in  ticket_respond_signature_bigR_x_hi: Scalar<BLS12-381>
in  ticket_respond_signature_bigR_x_lo: Scalar<BLS12-381>
in  ticket_respond_signature_bigR_y_hi: Scalar<BLS12-381>
in  ticket_respond_signature_bigR_y_lo: Scalar<BLS12-381>
in  ticket_respond_signature_s_hi: Scalar<BLS12-381>
in  ticket_respond_signature_s_lo: Scalar<BLS12-381>
in  ticket_respond_signature_recoveryId: Scalar<BLS12-381>
in  ticket_serializedOutput_hi: Scalar<BLS12-381>
in  ticket_serializedOutput_lo: Scalar<BLS12-381>
in  mintNonce_hi: Scalar<BLS12-381>
in  mintNonce_lo: Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
",
    ),
    (
        "erc20_vault_pending::redeem",
        "\
in  evmNonce: Scalar<BLS12-381>
in  shares: Scalar<BLS12-381>
in  coin_nonce_hi: Scalar<BLS12-381>
in  coin_nonce_lo: Scalar<BLS12-381>
in  coin_color_hi: Scalar<BLS12-381>
in  coin_color_lo: Scalar<BLS12-381>
in  coin_value: Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
",
    ),
    (
        "erc20_vault_pending::complete_redeem",
        "\
in  ticket_respond_requestId_hi: Scalar<BLS12-381>
in  ticket_respond_requestId_lo: Scalar<BLS12-381>
in  ticket_respond_blockHeight: Scalar<BLS12-381>
in  ticket_respond_outputKind: Scalar<BLS12-381>
in  ticket_respond_serializedOutputLength: Scalar<BLS12-381>
in  ticket_respond_digest_hi: Scalar<BLS12-381>
in  ticket_respond_digest_lo: Scalar<BLS12-381>
in  ticket_respond_signature_bigR_x_hi: Scalar<BLS12-381>
in  ticket_respond_signature_bigR_x_lo: Scalar<BLS12-381>
in  ticket_respond_signature_bigR_y_hi: Scalar<BLS12-381>
in  ticket_respond_signature_bigR_y_lo: Scalar<BLS12-381>
in  ticket_respond_signature_s_hi: Scalar<BLS12-381>
in  ticket_respond_signature_s_lo: Scalar<BLS12-381>
in  ticket_respond_signature_recoveryId: Scalar<BLS12-381>
in  ticket_serializedOutput_hi: Scalar<BLS12-381>
in  ticket_serializedOutput_lo: Scalar<BLS12-381>
in  mintNonce_hi: Scalar<BLS12-381>
in  mintNonce_lo: Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
",
    ),
    (
        "erc20_vault_pending::refund_redeem",
        "\
in  ticket_respond_requestId_hi: Scalar<BLS12-381>
in  ticket_respond_requestId_lo: Scalar<BLS12-381>
in  ticket_respond_blockHeight: Scalar<BLS12-381>
in  ticket_respond_outputKind: Scalar<BLS12-381>
in  ticket_respond_serializedOutputLength: Scalar<BLS12-381>
in  ticket_respond_digest_hi: Scalar<BLS12-381>
in  ticket_respond_digest_lo: Scalar<BLS12-381>
in  ticket_respond_signature_bigR_x_hi: Scalar<BLS12-381>
in  ticket_respond_signature_bigR_x_lo: Scalar<BLS12-381>
in  ticket_respond_signature_bigR_y_hi: Scalar<BLS12-381>
in  ticket_respond_signature_bigR_y_lo: Scalar<BLS12-381>
in  ticket_respond_signature_s_hi: Scalar<BLS12-381>
in  ticket_respond_signature_s_lo: Scalar<BLS12-381>
in  ticket_respond_signature_recoveryId: Scalar<BLS12-381>
in  ticket_serializedOutput_hi: Scalar<BLS12-381>
in  ticket_serializedOutput_lo: Scalar<BLS12-381>
in  mintNonce_hi: Scalar<BLS12-381>
in  mintNonce_lo: Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
",
    ),
    (
        "signet_contract::sign_bidirectional",
        "\
in  requestId_hi: Scalar<BLS12-381>
in  requestId_lo: Scalar<BLS12-381>
in  notification_version: Scalar<BLS12-381>
in  notification_payload_0: Scalar<BLS12-381>
in  notification_payload_1: Scalar<BLS12-381>
in  notification_payload_2: Scalar<BLS12-381>
in  notification_payload_3: Scalar<BLS12-381>
in  notification_payload_4: Scalar<BLS12-381>
",
    ),
    (
        "signet_contract::respond",
        "\
in  signatureRespondedEvent_requestId_hi: Scalar<BLS12-381>
in  signatureRespondedEvent_requestId_lo: Scalar<BLS12-381>
in  signatureRespondedEvent_signature_bigR_x_hi: Scalar<BLS12-381>
in  signatureRespondedEvent_signature_bigR_x_lo: Scalar<BLS12-381>
in  signatureRespondedEvent_signature_bigR_y_hi: Scalar<BLS12-381>
in  signatureRespondedEvent_signature_bigR_y_lo: Scalar<BLS12-381>
in  signatureRespondedEvent_signature_s_hi: Scalar<BLS12-381>
in  signatureRespondedEvent_signature_s_lo: Scalar<BLS12-381>
in  signatureRespondedEvent_signature_recoveryId: Scalar<BLS12-381>
",
    ),
    (
        "signet_contract::respond_bidirectional",
        "\
in  respondBidirectionalEvent_requestId_hi: Scalar<BLS12-381>
in  respondBidirectionalEvent_requestId_lo: Scalar<BLS12-381>
in  respondBidirectionalEvent_blockHeight: Scalar<BLS12-381>
in  respondBidirectionalEvent_outputKind: Scalar<BLS12-381>
in  respondBidirectionalEvent_serializedOutputLength: Scalar<BLS12-381>
in  respondBidirectionalEvent_digest_hi: Scalar<BLS12-381>
in  respondBidirectionalEvent_digest_lo: Scalar<BLS12-381>
in  respondBidirectionalEvent_signature_bigR_x_hi: Scalar<BLS12-381>
in  respondBidirectionalEvent_signature_bigR_x_lo: Scalar<BLS12-381>
in  respondBidirectionalEvent_signature_bigR_y_hi: Scalar<BLS12-381>
in  respondBidirectionalEvent_signature_bigR_y_lo: Scalar<BLS12-381>
in  respondBidirectionalEvent_signature_s_hi: Scalar<BLS12-381>
in  respondBidirectionalEvent_signature_s_lo: Scalar<BLS12-381>
in  respondBidirectionalEvent_signature_recoveryId: Scalar<BLS12-381>
",
    ),
    (
        "attest::map_only",
        "\
in  requestId_hi: Scalar<BLS12-381>
in  requestId_lo: Scalar<BLS12-381>
",
    ),
    (
        "attest::verify_only",
        "\
in  requestId_hi: Scalar<BLS12-381>
in  requestId_lo: Scalar<BLS12-381>
in  digest_hi: Scalar<BLS12-381>
in  digest_lo: Scalar<BLS12-381>
in  r_hi: Scalar<BLS12-381>
in  r_lo: Scalar<BLS12-381>
in  s_hi: Scalar<BLS12-381>
in  s_lo: Scalar<BLS12-381>
in  pk: Point<Secp256k1>
",
    ),
    (
        "attest::sha_verify",
        "\
in  requestId_hi: Scalar<BLS12-381>
in  requestId_lo: Scalar<BLS12-381>
in  output_0: Scalar<BLS12-381>
in  output_1: Scalar<BLS12-381>
in  output_2: Scalar<BLS12-381>
in  output_3: Scalar<BLS12-381>
in  output_4: Scalar<BLS12-381>
in  r_hi: Scalar<BLS12-381>
in  r_lo: Scalar<BLS12-381>
in  s_hi: Scalar<BLS12-381>
in  s_lo: Scalar<BLS12-381>
in  pk: Point<Secp256k1>
",
    ),
    (
        "attest::keccak_verify",
        "\
in  requestId_hi: Scalar<BLS12-381>
in  requestId_lo: Scalar<BLS12-381>
in  output_0: Scalar<BLS12-381>
in  output_1: Scalar<BLS12-381>
in  output_2: Scalar<BLS12-381>
in  output_3: Scalar<BLS12-381>
in  output_4: Scalar<BLS12-381>
in  r_hi: Scalar<BLS12-381>
in  r_lo: Scalar<BLS12-381>
in  s_hi: Scalar<BLS12-381>
in  s_lo: Scalar<BLS12-381>
in  pk: Point<Secp256k1>
",
    ),
    (
        "events::base",
        "\
in  recipient_hi: Scalar<BLS12-381>
in  recipient_lo: Scalar<BLS12-381>
in  amount: Scalar<BLS12-381>
",
    ),
    (
        "events::emit_n(1)",
        "\
in  recipient_hi: Scalar<BLS12-381>
in  recipient_lo: Scalar<BLS12-381>
in  amount: Scalar<BLS12-381>
",
    ),
    (
        "events::emit_n(2)",
        "\
in  recipient_hi: Scalar<BLS12-381>
in  recipient_lo: Scalar<BLS12-381>
in  amount: Scalar<BLS12-381>
",
    ),
    (
        "events::emit_n(4)",
        "\
in  recipient_hi: Scalar<BLS12-381>
in  recipient_lo: Scalar<BLS12-381>
in  amount: Scalar<BLS12-381>
",
    ),
    (
        "events_borsh::base",
        "\
in  recipient_hi: Scalar<BLS12-381>
in  recipient_lo: Scalar<BLS12-381>
in  amount: Scalar<BLS12-381>
",
    ),
    (
        "events_borsh::emit_n(1)",
        "\
in  recipient_hi: Scalar<BLS12-381>
in  recipient_lo: Scalar<BLS12-381>
in  amount: Scalar<BLS12-381>
",
    ),
    (
        "events_borsh::emit_n(2)",
        "\
in  recipient_hi: Scalar<BLS12-381>
in  recipient_lo: Scalar<BLS12-381>
in  amount: Scalar<BLS12-381>
",
    ),
    (
        "events_borsh::emit_n(4)",
        "\
in  recipient_hi: Scalar<BLS12-381>
in  recipient_lo: Scalar<BLS12-381>
in  amount: Scalar<BLS12-381>
",
    ),
    (
        "hashing::control(32)",
        "\
in  data_0: Scalar<BLS12-381>
in  data_1: Scalar<BLS12-381>
",
    ),
    (
        "hashing::control(64)",
        "\
in  data_0: Scalar<BLS12-381>
in  data_1: Scalar<BLS12-381>
in  data_2: Scalar<BLS12-381>
",
    ),
    (
        "hashing::control(128)",
        "\
in  data_0: Scalar<BLS12-381>
in  data_1: Scalar<BLS12-381>
in  data_2: Scalar<BLS12-381>
in  data_3: Scalar<BLS12-381>
in  data_4: Scalar<BLS12-381>
",
    ),
    (
        "hashing::control(256)",
        "\
in  data_0: Scalar<BLS12-381>
in  data_1: Scalar<BLS12-381>
in  data_2: Scalar<BLS12-381>
in  data_3: Scalar<BLS12-381>
in  data_4: Scalar<BLS12-381>
in  data_5: Scalar<BLS12-381>
in  data_6: Scalar<BLS12-381>
in  data_7: Scalar<BLS12-381>
in  data_8: Scalar<BLS12-381>
",
    ),
    (
        "hashing::control(1024)",
        "\
in  data_0: Scalar<BLS12-381>
in  data_1: Scalar<BLS12-381>
in  data_2: Scalar<BLS12-381>
in  data_3: Scalar<BLS12-381>
in  data_4: Scalar<BLS12-381>
in  data_5: Scalar<BLS12-381>
in  data_6: Scalar<BLS12-381>
in  data_7: Scalar<BLS12-381>
in  data_8: Scalar<BLS12-381>
in  data_9: Scalar<BLS12-381>
in  data_10: Scalar<BLS12-381>
in  data_11: Scalar<BLS12-381>
in  data_12: Scalar<BLS12-381>
in  data_13: Scalar<BLS12-381>
in  data_14: Scalar<BLS12-381>
in  data_15: Scalar<BLS12-381>
in  data_16: Scalar<BLS12-381>
in  data_17: Scalar<BLS12-381>
in  data_18: Scalar<BLS12-381>
in  data_19: Scalar<BLS12-381>
in  data_20: Scalar<BLS12-381>
in  data_21: Scalar<BLS12-381>
in  data_22: Scalar<BLS12-381>
in  data_23: Scalar<BLS12-381>
in  data_24: Scalar<BLS12-381>
in  data_25: Scalar<BLS12-381>
in  data_26: Scalar<BLS12-381>
in  data_27: Scalar<BLS12-381>
in  data_28: Scalar<BLS12-381>
in  data_29: Scalar<BLS12-381>
in  data_30: Scalar<BLS12-381>
in  data_31: Scalar<BLS12-381>
in  data_32: Scalar<BLS12-381>
in  data_33: Scalar<BLS12-381>
",
    ),
    (
        "hashing::persistent(32)",
        "\
in  data_0: Scalar<BLS12-381>
in  data_1: Scalar<BLS12-381>
",
    ),
    (
        "hashing::persistent(64)",
        "\
in  data_0: Scalar<BLS12-381>
in  data_1: Scalar<BLS12-381>
in  data_2: Scalar<BLS12-381>
",
    ),
    (
        "hashing::persistent(128)",
        "\
in  data_0: Scalar<BLS12-381>
in  data_1: Scalar<BLS12-381>
in  data_2: Scalar<BLS12-381>
in  data_3: Scalar<BLS12-381>
in  data_4: Scalar<BLS12-381>
",
    ),
    (
        "hashing::persistent(256)",
        "\
in  data_0: Scalar<BLS12-381>
in  data_1: Scalar<BLS12-381>
in  data_2: Scalar<BLS12-381>
in  data_3: Scalar<BLS12-381>
in  data_4: Scalar<BLS12-381>
in  data_5: Scalar<BLS12-381>
in  data_6: Scalar<BLS12-381>
in  data_7: Scalar<BLS12-381>
in  data_8: Scalar<BLS12-381>
",
    ),
    (
        "hashing::persistent(1024)",
        "\
in  data_0: Scalar<BLS12-381>
in  data_1: Scalar<BLS12-381>
in  data_2: Scalar<BLS12-381>
in  data_3: Scalar<BLS12-381>
in  data_4: Scalar<BLS12-381>
in  data_5: Scalar<BLS12-381>
in  data_6: Scalar<BLS12-381>
in  data_7: Scalar<BLS12-381>
in  data_8: Scalar<BLS12-381>
in  data_9: Scalar<BLS12-381>
in  data_10: Scalar<BLS12-381>
in  data_11: Scalar<BLS12-381>
in  data_12: Scalar<BLS12-381>
in  data_13: Scalar<BLS12-381>
in  data_14: Scalar<BLS12-381>
in  data_15: Scalar<BLS12-381>
in  data_16: Scalar<BLS12-381>
in  data_17: Scalar<BLS12-381>
in  data_18: Scalar<BLS12-381>
in  data_19: Scalar<BLS12-381>
in  data_20: Scalar<BLS12-381>
in  data_21: Scalar<BLS12-381>
in  data_22: Scalar<BLS12-381>
in  data_23: Scalar<BLS12-381>
in  data_24: Scalar<BLS12-381>
in  data_25: Scalar<BLS12-381>
in  data_26: Scalar<BLS12-381>
in  data_27: Scalar<BLS12-381>
in  data_28: Scalar<BLS12-381>
in  data_29: Scalar<BLS12-381>
in  data_30: Scalar<BLS12-381>
in  data_31: Scalar<BLS12-381>
in  data_32: Scalar<BLS12-381>
in  data_33: Scalar<BLS12-381>
",
    ),
    (
        "hashing::keccak(64)",
        "\
in  data_0: Scalar<BLS12-381>
in  data_1: Scalar<BLS12-381>
in  data_2: Scalar<BLS12-381>
",
    ),
    (
        "hashing::keccak(128)",
        "\
in  data_0: Scalar<BLS12-381>
in  data_1: Scalar<BLS12-381>
in  data_2: Scalar<BLS12-381>
in  data_3: Scalar<BLS12-381>
in  data_4: Scalar<BLS12-381>
",
    ),
    (
        "hashing::keccak(256)",
        "\
in  data_0: Scalar<BLS12-381>
in  data_1: Scalar<BLS12-381>
in  data_2: Scalar<BLS12-381>
in  data_3: Scalar<BLS12-381>
in  data_4: Scalar<BLS12-381>
in  data_5: Scalar<BLS12-381>
in  data_6: Scalar<BLS12-381>
in  data_7: Scalar<BLS12-381>
in  data_8: Scalar<BLS12-381>
",
    ),
    (
        "hashing::transient(32)",
        "\
in  data_0: Scalar<BLS12-381>
in  data_1: Scalar<BLS12-381>
",
    ),
    (
        "hashing::transient(256)",
        "\
in  data_0: Scalar<BLS12-381>
in  data_1: Scalar<BLS12-381>
in  data_2: Scalar<BLS12-381>
in  data_3: Scalar<BLS12-381>
in  data_4: Scalar<BLS12-381>
in  data_5: Scalar<BLS12-381>
in  data_6: Scalar<BLS12-381>
in  data_7: Scalar<BLS12-381>
in  data_8: Scalar<BLS12-381>
",
    ),
    (
        "hashing::transient(1024)",
        "\
in  data_0: Scalar<BLS12-381>
in  data_1: Scalar<BLS12-381>
in  data_2: Scalar<BLS12-381>
in  data_3: Scalar<BLS12-381>
in  data_4: Scalar<BLS12-381>
in  data_5: Scalar<BLS12-381>
in  data_6: Scalar<BLS12-381>
in  data_7: Scalar<BLS12-381>
in  data_8: Scalar<BLS12-381>
in  data_9: Scalar<BLS12-381>
in  data_10: Scalar<BLS12-381>
in  data_11: Scalar<BLS12-381>
in  data_12: Scalar<BLS12-381>
in  data_13: Scalar<BLS12-381>
in  data_14: Scalar<BLS12-381>
in  data_15: Scalar<BLS12-381>
in  data_16: Scalar<BLS12-381>
in  data_17: Scalar<BLS12-381>
in  data_18: Scalar<BLS12-381>
in  data_19: Scalar<BLS12-381>
in  data_20: Scalar<BLS12-381>
in  data_21: Scalar<BLS12-381>
in  data_22: Scalar<BLS12-381>
in  data_23: Scalar<BLS12-381>
in  data_24: Scalar<BLS12-381>
in  data_25: Scalar<BLS12-381>
in  data_26: Scalar<BLS12-381>
in  data_27: Scalar<BLS12-381>
in  data_28: Scalar<BLS12-381>
in  data_29: Scalar<BLS12-381>
in  data_30: Scalar<BLS12-381>
in  data_31: Scalar<BLS12-381>
in  data_32: Scalar<BLS12-381>
in  data_33: Scalar<BLS12-381>
",
    ),
    (
        "hashing::persistent_vec8",
        "\
in  data_0_hi: Scalar<BLS12-381>
in  data_0_lo: Scalar<BLS12-381>
in  data_1_hi: Scalar<BLS12-381>
in  data_1_lo: Scalar<BLS12-381>
in  data_2_hi: Scalar<BLS12-381>
in  data_2_lo: Scalar<BLS12-381>
in  data_3_hi: Scalar<BLS12-381>
in  data_3_lo: Scalar<BLS12-381>
in  data_4_hi: Scalar<BLS12-381>
in  data_4_lo: Scalar<BLS12-381>
in  data_5_hi: Scalar<BLS12-381>
in  data_5_lo: Scalar<BLS12-381>
in  data_6_hi: Scalar<BLS12-381>
in  data_6_lo: Scalar<BLS12-381>
in  data_7_hi: Scalar<BLS12-381>
in  data_7_lo: Scalar<BLS12-381>
",
    ),
    (
        "xcall::local_base",
        "\
in  recipient_hi: Scalar<BLS12-381>
in  recipient_lo: Scalar<BLS12-381>
in  amount: Scalar<BLS12-381>
",
    ),
    (
        "xcall::call_once",
        "\
in  recipient_hi: Scalar<BLS12-381>
in  recipient_lo: Scalar<BLS12-381>
in  amount: Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
",
    ),
    (
        "xcall::call_emit",
        "\
in  recipient_hi: Scalar<BLS12-381>
in  recipient_lo: Scalar<BLS12-381>
in  amount: Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
",
    ),
    (
        "xcall::call_once_bound",
        "\
in  recipient_hi: Scalar<BLS12-381>
in  recipient_lo: Scalar<BLS12-381>
in  amount: Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
",
    ),
    (
        "xcall::call_twice",
        "\
in  recipient_hi: Scalar<BLS12-381>
in  recipient_lo: Scalar<BLS12-381>
in  amount: Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
",
    ),
    (
        "xcall::call_big",
        "\
in  data_0: Scalar<BLS12-381>
in  data_1: Scalar<BLS12-381>
in  data_2: Scalar<BLS12-381>
in  data_3: Scalar<BLS12-381>
in  data_4: Scalar<BLS12-381>
in  data_5: Scalar<BLS12-381>
in  data_6: Scalar<BLS12-381>
in  data_7: Scalar<BLS12-381>
in  data_8: Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
",
    ),
    (
        "xcall::target_deposit",
        "\
in  recipient_hi: Scalar<BLS12-381>
in  recipient_lo: Scalar<BLS12-381>
in  amount: Scalar<BLS12-381>
",
    ),
    (
        "xcall::target_deposit_emit",
        "\
in  recipient_hi: Scalar<BLS12-381>
in  recipient_lo: Scalar<BLS12-381>
in  amount: Scalar<BLS12-381>
",
    ),
    (
        "xcall::target_deposit_big",
        "\
in  data_0: Scalar<BLS12-381>
in  data_1: Scalar<BLS12-381>
in  data_2: Scalar<BLS12-381>
in  data_3: Scalar<BLS12-381>
in  data_4: Scalar<BLS12-381>
in  data_5: Scalar<BLS12-381>
in  data_6: Scalar<BLS12-381>
in  data_7: Scalar<BLS12-381>
in  data_8: Scalar<BLS12-381>
",
    ),
    (
        "xcall_with_payment::call_once",
        "\
in  coin_nonce_hi: Scalar<BLS12-381>
in  coin_nonce_lo: Scalar<BLS12-381>
in  coin_color_hi: Scalar<BLS12-381>
in  coin_color_lo: Scalar<BLS12-381>
in  coin_value: Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
",
    ),
    (
        "xcall_with_payment::request",
        "\
in  requestId_hi: Scalar<BLS12-381>
in  requestId_lo: Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
",
    ),
    (
        "xcall_with_payment::notify",
        "\
in  coin_nonce_hi: Scalar<BLS12-381>
in  coin_nonce_lo: Scalar<BLS12-381>
in  coin_color_hi: Scalar<BLS12-381>
in  coin_color_lo: Scalar<BLS12-381>
in  coin_value: Scalar<BLS12-381>
",
    ),
    (
        "xcall_with_payment::pay",
        "\
in  requestId_hi: Scalar<BLS12-381>
in  requestId_lo: Scalar<BLS12-381>
in  coin_nonce_hi: Scalar<BLS12-381>
in  coin_nonce_lo: Scalar<BLS12-381>
in  coin_color_hi: Scalar<BLS12-381>
in  coin_color_lo: Scalar<BLS12-381>
in  coin_value: Scalar<BLS12-381>
",
    ),
    (
        "xcall_with_payment::confirm_request",
        "\
in  requestId_hi: Scalar<BLS12-381>
in  requestId_lo: Scalar<BLS12-381>
",
    ),
    (
        "xcontract_events::deposit_via_vault",
        "\
in  amount: Scalar<BLS12-381>
out event hash (hi): Scalar<BLS12-381>
out event hash (lo): Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
",
    ),
    (
        "xcontract_events::token_deposit",
        "\
in  amount: Scalar<BLS12-381>
in  caller_hi: Scalar<BLS12-381>
in  caller_lo: Scalar<BLS12-381>
out event hash (hi): Scalar<BLS12-381>
out event hash (lo): Scalar<BLS12-381>
",
    ),
    (
        "xcontract_events_borsh::token_deposit",
        "\
in  amount: Scalar<BLS12-381>
in  caller_hi: Scalar<BLS12-381>
in  caller_lo: Scalar<BLS12-381>
out event hash (hi): Scalar<BLS12-381>
out event hash (lo): Scalar<BLS12-381>
",
    ),
    (
        "mint_tokens::mint_with_recipient_argument",
        "\
in  recipient_hi: Scalar<BLS12-381>
in  recipient_lo: Scalar<BLS12-381>
in  mintNonce_hi: Scalar<BLS12-381>
in  mintNonce_lo: Scalar<BLS12-381>
",
    ),
    (
        "mint_tokens::mint_with_recipient_own_public_key",
        "\
in  recipient_hi: Scalar<BLS12-381>
in  recipient_lo: Scalar<BLS12-381>
in  mintNonce_hi: Scalar<BLS12-381>
in  mintNonce_lo: Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
",
    ),
    (
        "serde_builtin::check_roundtrip",
        "\
in  bytes_0: Scalar<BLS12-381>
in  bytes_1: Scalar<BLS12-381>
in  bytes_2: Scalar<BLS12-381>
in  bytes_3: Scalar<BLS12-381>
in  bytes_4: Scalar<BLS12-381>
",
    ),
    (
        "test_caller::initialise",
        "\
in  responseKey: Point<Secp256k1>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
",
    ),
    (
        "treasury::send",
        "\
in  evmNonce: Scalar<BLS12-381>
in  token: Scalar<BLS12-381>
in  to: Scalar<BLS12-381>
in  amount: Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
",
    ),
    (
        "treasury::complete",
        "\
in  ticket_respond_requestId_hi: Scalar<BLS12-381>
in  ticket_respond_requestId_lo: Scalar<BLS12-381>
in  ticket_respond_blockHeight: Scalar<BLS12-381>
in  ticket_respond_outputKind: Scalar<BLS12-381>
in  ticket_respond_serializedOutputLength: Scalar<BLS12-381>
in  ticket_respond_digest_hi: Scalar<BLS12-381>
in  ticket_respond_digest_lo: Scalar<BLS12-381>
in  ticket_respond_signature_bigR_x_hi: Scalar<BLS12-381>
in  ticket_respond_signature_bigR_x_lo: Scalar<BLS12-381>
in  ticket_respond_signature_bigR_y_hi: Scalar<BLS12-381>
in  ticket_respond_signature_bigR_y_lo: Scalar<BLS12-381>
in  ticket_respond_signature_s_hi: Scalar<BLS12-381>
in  ticket_respond_signature_s_lo: Scalar<BLS12-381>
in  ticket_respond_signature_recoveryId: Scalar<BLS12-381>
in  ticket_serializedOutput: Scalar<BLS12-381>
",
    ),
    (
        "treasury::refund",
        "\
in  ticket_respond_requestId_hi: Scalar<BLS12-381>
in  ticket_respond_requestId_lo: Scalar<BLS12-381>
in  ticket_respond_blockHeight: Scalar<BLS12-381>
in  ticket_respond_outputKind: Scalar<BLS12-381>
in  ticket_respond_serializedOutputLength: Scalar<BLS12-381>
in  ticket_respond_digest_hi: Scalar<BLS12-381>
in  ticket_respond_digest_lo: Scalar<BLS12-381>
in  ticket_respond_signature_bigR_x_hi: Scalar<BLS12-381>
in  ticket_respond_signature_bigR_x_lo: Scalar<BLS12-381>
in  ticket_respond_signature_bigR_y_hi: Scalar<BLS12-381>
in  ticket_respond_signature_bigR_y_lo: Scalar<BLS12-381>
in  ticket_respond_signature_s_hi: Scalar<BLS12-381>
in  ticket_respond_signature_s_lo: Scalar<BLS12-381>
in  ticket_respond_signature_recoveryId: Scalar<BLS12-381>
in  ticket_serializedOutput: Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
",
    ),
    (
        "bounded::b10",
        "\
in  x: Scalar<BLS12-381>
",
    ),
    (
        "bounded::b300",
        "\
in  x: Scalar<BLS12-381>
",
    ),
    (
        "bounded::b1000",
        "\
in  x: Scalar<BLS12-381>
",
    ),
    (
        "bounded::b70000",
        "\
in  x: Scalar<BLS12-381>
",
    ),
    (
        "bounded::b1",
        "\
in  x: Scalar<BLS12-381>
",
    ),
    (
        "bounded::b2",
        "\
in  x: Scalar<BLS12-381>
",
    ),
    (
        "bounded::b256",
        "\
in  x: Scalar<BLS12-381>
",
    ),
    (
        "bounded::b255",
        "\
in  x: Scalar<BLS12-381>
",
    ),
    (
        "bounded::b_enum",
        "\
in  x: Scalar<BLS12-381>
",
    ),
    (
        "bounded::b_struct",
        "\
in  order_kind: Scalar<BLS12-381>
in  order_quantity: Scalar<BLS12-381>
in  order_price: Scalar<BLS12-381>
in  order_tag: Scalar<BLS12-381>
",
    ),
    (
        "bounded::b_compare",
        "\
in  a: Scalar<BLS12-381>
in  b: Scalar<BLS12-381>
",
    ),
    (
        "bounded_ledger::bl_write",
        "\
in  x: Scalar<BLS12-381>
",
    ),
    (
        "bounded_ledger::bl_read",
        "\
out cell: Scalar<BLS12-381>
",
    ),
    (
        "opaque::op_arg",
        "\
in  x: Scalar<BLS12-381>
",
    ),
    (
        "opaque::op_ret",
        "\
in  x: Scalar<BLS12-381>
out name: Scalar<BLS12-381>
",
    ),
    (
        "opaque::op_eq",
        "\
in  a: Scalar<BLS12-381>
in  b: Scalar<BLS12-381>
out equal: Scalar<BLS12-381>
",
    ),
    (
        "opaque::op_default",
        "\
",
    ),
    (
        "opaque::op_cell",
        "\
in  x: Scalar<BLS12-381>
",
    ),
    (
        "opaque::op_witness",
        "\
wit Scalar<BLS12-381>
",
    ),
    (
        "opaque::op_map_value",
        "\
in  k_hi: Scalar<BLS12-381>
in  k_lo: Scalar<BLS12-381>
in  v: Scalar<BLS12-381>
",
    ),
    (
        "opaque::op_map_key",
        "\
in  k: Scalar<BLS12-381>
",
    ),
    (
        "opaque::op_set",
        "\
in  k: Scalar<BLS12-381>
out member: Scalar<BLS12-381>
",
    ),
    (
        "opaque::op_maybe",
        "\
in  x: Scalar<BLS12-381>
",
    ),
    (
        "opaque::op_bytes",
        "\
in  x: Scalar<BLS12-381>
",
    ),
    (
        "opaque::op_struct",
        "\
in  w_tag: Scalar<BLS12-381>
in  w_name: Scalar<BLS12-381>
",
    ),
    (
        "opaque::op_point",
        "\
in  p: Point<Secp256k1>
",
    ),
    (
        "opaque::op_jubjub",
        "\
in  p: Point<Jubjub>
",
    ),
    (
        "adts::set_insert",
        "\
in  x_hi: Scalar<BLS12-381>
in  x_lo: Scalar<BLS12-381>
",
    ),
    (
        "adts::set_member",
        "\
in  x_hi: Scalar<BLS12-381>
in  x_lo: Scalar<BLS12-381>
out member: Scalar<BLS12-381>
",
    ),
    (
        "adts::set_remove",
        "\
in  x_hi: Scalar<BLS12-381>
in  x_lo: Scalar<BLS12-381>
",
    ),
    (
        "adts::set_size",
        "\
out size: Scalar<BLS12-381>
",
    ),
    (
        "adts::set_is_empty",
        "\
out empty: Scalar<BLS12-381>
",
    ),
    (
        "adts::set_reset",
        "\
",
    ),
    (
        "adts::list_push_front",
        "\
in  x_hi: Scalar<BLS12-381>
in  x_lo: Scalar<BLS12-381>
",
    ),
    (
        "adts::list_pop_front",
        "\
",
    ),
    (
        "adts::list_head",
        "\
out head (is_some): Scalar<BLS12-381>
out head (hi): Scalar<BLS12-381>
out head (lo): Scalar<BLS12-381>
",
    ),
    (
        "adts::list_length",
        "\
out length: Scalar<BLS12-381>
",
    ),
    (
        "adts::list_is_empty",
        "\
out empty: Scalar<BLS12-381>
",
    ),
    (
        "adts::list_reset",
        "\
",
    ),
    (
        "adts::map_insert_default",
        "\
in  k_hi: Scalar<BLS12-381>
in  k_lo: Scalar<BLS12-381>
",
    ),
    (
        "adts::map_reset",
        "\
",
    ),
    (
        "adts::mt_insert",
        "\
in  x_hi: Scalar<BLS12-381>
in  x_lo: Scalar<BLS12-381>
",
    ),
    (
        "adts::mt_insert_index",
        "\
in  x_hi: Scalar<BLS12-381>
in  x_lo: Scalar<BLS12-381>
in  i: Scalar<BLS12-381>
",
    ),
    (
        "adts::mt_insert_hash",
        "\
in  h_hi: Scalar<BLS12-381>
in  h_lo: Scalar<BLS12-381>
",
    ),
    (
        "adts::mt_insert_hash_index",
        "\
in  h_hi: Scalar<BLS12-381>
in  h_lo: Scalar<BLS12-381>
in  i: Scalar<BLS12-381>
",
    ),
    (
        "adts::mt_insert_index_default",
        "\
in  i: Scalar<BLS12-381>
",
    ),
    (
        "adts::mt_check_root",
        "\
in  r: Scalar<BLS12-381>
out ok: Scalar<BLS12-381>
",
    ),
    (
        "adts::mt_is_full",
        "\
out full: Scalar<BLS12-381>
",
    ),
    (
        "adts::mt_reset",
        "\
",
    ),
    (
        "adts::hmt_insert",
        "\
in  x_hi: Scalar<BLS12-381>
in  x_lo: Scalar<BLS12-381>
",
    ),
    (
        "adts::hmt_insert_index",
        "\
in  x_hi: Scalar<BLS12-381>
in  x_lo: Scalar<BLS12-381>
in  i: Scalar<BLS12-381>
",
    ),
    (
        "adts::hmt_insert_hash",
        "\
in  h_hi: Scalar<BLS12-381>
in  h_lo: Scalar<BLS12-381>
",
    ),
    (
        "adts::hmt_insert_hash_index",
        "\
in  h_hi: Scalar<BLS12-381>
in  h_lo: Scalar<BLS12-381>
in  i: Scalar<BLS12-381>
",
    ),
    (
        "adts::hmt_insert_index_default",
        "\
in  i: Scalar<BLS12-381>
",
    ),
    (
        "adts::hmt_check_root",
        "\
in  r: Scalar<BLS12-381>
out ok: Scalar<BLS12-381>
",
    ),
    (
        "adts::hmt_is_full",
        "\
out full: Scalar<BLS12-381>
",
    ),
    (
        "adts::hmt_reset_history",
        "\
",
    ),
    (
        "adts::hmt_reset",
        "\
",
    ),
    (
        "kernel_tokens::k_mint_unshielded",
        "\
in  ds_hi: Scalar<BLS12-381>
in  ds_lo: Scalar<BLS12-381>
in  amount: Scalar<BLS12-381>
",
    ),
    (
        "kernel_tokens::k_claim_unshielded_coin_spend",
        "\
in  color_hi: Scalar<BLS12-381>
in  color_lo: Scalar<BLS12-381>
in  addr_is_left: Scalar<BLS12-381>
in  addr_left_hi: Scalar<BLS12-381>
in  addr_left_lo: Scalar<BLS12-381>
in  addr_right_hi: Scalar<BLS12-381>
in  addr_right_lo: Scalar<BLS12-381>
in  amount: Scalar<BLS12-381>
",
    ),
    (
        "kernel_tokens::k_inc_unshielded_outputs",
        "\
in  color_hi: Scalar<BLS12-381>
in  color_lo: Scalar<BLS12-381>
in  amount: Scalar<BLS12-381>
",
    ),
    (
        "kernel_tokens::k_inc_unshielded_inputs",
        "\
in  color_hi: Scalar<BLS12-381>
in  color_lo: Scalar<BLS12-381>
in  amount: Scalar<BLS12-381>
",
    ),
    (
        "kernel_tokens::k_balance",
        "\
in  color_hi: Scalar<BLS12-381>
in  color_lo: Scalar<BLS12-381>
out balance: Scalar<BLS12-381>
",
    ),
    (
        "kernel_tokens::k_balance_less_than",
        "\
in  color_hi: Scalar<BLS12-381>
in  color_lo: Scalar<BLS12-381>
in  amount: Scalar<BLS12-381>
out less: Scalar<BLS12-381>
",
    ),
    (
        "kernel_tokens::k_balance_greater_than",
        "\
in  color_hi: Scalar<BLS12-381>
in  color_lo: Scalar<BLS12-381>
in  amount: Scalar<BLS12-381>
out greater: Scalar<BLS12-381>
",
    ),
    (
        "kernel_tokens::k_block_time_less_than",
        "\
in  t: Scalar<BLS12-381>
out before: Scalar<BLS12-381>
",
    ),
    (
        "kernel_tokens::k_block_time_greater_than",
        "\
in  t: Scalar<BLS12-381>
out after: Scalar<BLS12-381>
",
    ),
    (
        "kernel_tokens::s_block_time_lt",
        "\
in  t: Scalar<BLS12-381>
out lt: Scalar<BLS12-381>
",
    ),
    (
        "kernel_tokens::s_block_time_gte",
        "\
in  t: Scalar<BLS12-381>
out gte: Scalar<BLS12-381>
",
    ),
    (
        "kernel_tokens::s_block_time_gt",
        "\
in  t: Scalar<BLS12-381>
out gt: Scalar<BLS12-381>
",
    ),
    (
        "kernel_tokens::s_block_time_lte",
        "\
in  t: Scalar<BLS12-381>
out lte: Scalar<BLS12-381>
",
    ),
    (
        "kernel_tokens::s_unshielded_balance",
        "\
in  color_hi: Scalar<BLS12-381>
in  color_lo: Scalar<BLS12-381>
out balance: Scalar<BLS12-381>
",
    ),
    (
        "kernel_tokens::s_unshielded_balance_lt",
        "\
in  color_hi: Scalar<BLS12-381>
in  color_lo: Scalar<BLS12-381>
in  a: Scalar<BLS12-381>
out lt: Scalar<BLS12-381>
",
    ),
    (
        "kernel_tokens::s_unshielded_balance_gte",
        "\
in  color_hi: Scalar<BLS12-381>
in  color_lo: Scalar<BLS12-381>
in  a: Scalar<BLS12-381>
out gte: Scalar<BLS12-381>
",
    ),
    (
        "kernel_tokens::s_unshielded_balance_gt",
        "\
in  color_hi: Scalar<BLS12-381>
in  color_lo: Scalar<BLS12-381>
in  a: Scalar<BLS12-381>
out gt: Scalar<BLS12-381>
",
    ),
    (
        "kernel_tokens::s_unshielded_balance_lte",
        "\
in  color_hi: Scalar<BLS12-381>
in  color_lo: Scalar<BLS12-381>
in  a: Scalar<BLS12-381>
out lte: Scalar<BLS12-381>
",
    ),
    (
        "kernel_tokens::s_receive_unshielded",
        "\
in  color_hi: Scalar<BLS12-381>
in  color_lo: Scalar<BLS12-381>
in  a: Scalar<BLS12-381>
",
    ),
    (
        "kernel_tokens::s_send_unshielded",
        "\
in  color_hi: Scalar<BLS12-381>
in  color_lo: Scalar<BLS12-381>
in  a: Scalar<BLS12-381>
in  r_is_left: Scalar<BLS12-381>
in  r_left_hi: Scalar<BLS12-381>
in  r_left_lo: Scalar<BLS12-381>
in  r_right_hi: Scalar<BLS12-381>
in  r_right_lo: Scalar<BLS12-381>
",
    ),
    (
        "kernel_tokens::s_mint_unshielded_token",
        "\
in  ds_hi: Scalar<BLS12-381>
in  ds_lo: Scalar<BLS12-381>
in  a: Scalar<BLS12-381>
in  r_is_left: Scalar<BLS12-381>
in  r_left_hi: Scalar<BLS12-381>
in  r_left_lo: Scalar<BLS12-381>
in  r_right_hi: Scalar<BLS12-381>
in  r_right_lo: Scalar<BLS12-381>
out color (hi): Scalar<BLS12-381>
out color (lo): Scalar<BLS12-381>
",
    ),
    (
        "kernel_tokens::s_merge_coin",
        "\
in  a_nonce_hi: Scalar<BLS12-381>
in  a_nonce_lo: Scalar<BLS12-381>
in  a_color_hi: Scalar<BLS12-381>
in  a_color_lo: Scalar<BLS12-381>
in  a_value: Scalar<BLS12-381>
in  a_mtIndex: Scalar<BLS12-381>
in  b_nonce_hi: Scalar<BLS12-381>
in  b_nonce_lo: Scalar<BLS12-381>
in  b_color_hi: Scalar<BLS12-381>
in  b_color_lo: Scalar<BLS12-381>
in  b_value: Scalar<BLS12-381>
in  b_mtIndex: Scalar<BLS12-381>
out coin nonce (hi): Scalar<BLS12-381>
out coin nonce (lo): Scalar<BLS12-381>
out coin color (hi): Scalar<BLS12-381>
out coin color (lo): Scalar<BLS12-381>
out coin value: Scalar<BLS12-381>
",
    ),
    (
        "kernel_tokens::s_merge_coin_immediate",
        "\
in  a_nonce_hi: Scalar<BLS12-381>
in  a_nonce_lo: Scalar<BLS12-381>
in  a_color_hi: Scalar<BLS12-381>
in  a_color_lo: Scalar<BLS12-381>
in  a_value: Scalar<BLS12-381>
in  a_mtIndex: Scalar<BLS12-381>
in  b_nonce_hi: Scalar<BLS12-381>
in  b_nonce_lo: Scalar<BLS12-381>
in  b_color_hi: Scalar<BLS12-381>
in  b_color_lo: Scalar<BLS12-381>
in  b_value: Scalar<BLS12-381>
out coin nonce (hi): Scalar<BLS12-381>
out coin nonce (lo): Scalar<BLS12-381>
out coin color (hi): Scalar<BLS12-381>
out coin color (lo): Scalar<BLS12-381>
out coin value: Scalar<BLS12-381>
",
    ),
    (
        "kernel_tokens::s_send_shielded",
        "\
in  input_nonce_hi: Scalar<BLS12-381>
in  input_nonce_lo: Scalar<BLS12-381>
in  input_color_hi: Scalar<BLS12-381>
in  input_color_lo: Scalar<BLS12-381>
in  input_value: Scalar<BLS12-381>
in  input_mtIndex: Scalar<BLS12-381>
in  r_is_left: Scalar<BLS12-381>
in  r_left_hi: Scalar<BLS12-381>
in  r_left_lo: Scalar<BLS12-381>
in  r_right_hi: Scalar<BLS12-381>
in  r_right_lo: Scalar<BLS12-381>
in  v: Scalar<BLS12-381>
out result change (is_some): Scalar<BLS12-381>
out result change nonce (hi): Scalar<BLS12-381>
out result change nonce (lo): Scalar<BLS12-381>
out result change color (hi): Scalar<BLS12-381>
out result change color (lo): Scalar<BLS12-381>
out result change value: Scalar<BLS12-381>
out result sent nonce (hi): Scalar<BLS12-381>
out result sent nonce (lo): Scalar<BLS12-381>
out result sent color (hi): Scalar<BLS12-381>
out result sent color (lo): Scalar<BLS12-381>
out result sent value: Scalar<BLS12-381>
",
    ),
    (
        "coins::set_insert_coin",
        "\
in  coin_nonce_hi: Scalar<BLS12-381>
in  coin_nonce_lo: Scalar<BLS12-381>
in  coin_color_hi: Scalar<BLS12-381>
in  coin_color_lo: Scalar<BLS12-381>
in  coin_value: Scalar<BLS12-381>
in  r_is_left: Scalar<BLS12-381>
in  r_left_hi: Scalar<BLS12-381>
in  r_left_lo: Scalar<BLS12-381>
in  r_right_hi: Scalar<BLS12-381>
in  r_right_lo: Scalar<BLS12-381>
",
    ),
    (
        "coins::map_insert_coin",
        "\
in  k_hi: Scalar<BLS12-381>
in  k_lo: Scalar<BLS12-381>
in  coin_nonce_hi: Scalar<BLS12-381>
in  coin_nonce_lo: Scalar<BLS12-381>
in  coin_color_hi: Scalar<BLS12-381>
in  coin_color_lo: Scalar<BLS12-381>
in  coin_value: Scalar<BLS12-381>
in  r_is_left: Scalar<BLS12-381>
in  r_left_hi: Scalar<BLS12-381>
in  r_left_lo: Scalar<BLS12-381>
in  r_right_hi: Scalar<BLS12-381>
in  r_right_lo: Scalar<BLS12-381>
",
    ),
    (
        "coins::list_push_front_coin",
        "\
in  coin_nonce_hi: Scalar<BLS12-381>
in  coin_nonce_lo: Scalar<BLS12-381>
in  coin_color_hi: Scalar<BLS12-381>
in  coin_color_lo: Scalar<BLS12-381>
in  coin_value: Scalar<BLS12-381>
in  r_is_left: Scalar<BLS12-381>
in  r_left_hi: Scalar<BLS12-381>
in  r_left_lo: Scalar<BLS12-381>
in  r_right_hi: Scalar<BLS12-381>
in  r_right_lo: Scalar<BLS12-381>
",
    ),
    (
        "nested::map_insert",
        "\
in  k_hi: Scalar<BLS12-381>
in  k_lo: Scalar<BLS12-381>
in  k2_hi: Scalar<BLS12-381>
in  k2_lo: Scalar<BLS12-381>
in  v: Scalar<BLS12-381>
",
    ),
    (
        "nested::map_insert_default",
        "\
in  k_hi: Scalar<BLS12-381>
in  k_lo: Scalar<BLS12-381>
in  k2_hi: Scalar<BLS12-381>
in  k2_lo: Scalar<BLS12-381>
",
    ),
    (
        "nested::map_lookup",
        "\
in  k_hi: Scalar<BLS12-381>
in  k_lo: Scalar<BLS12-381>
in  k2_hi: Scalar<BLS12-381>
in  k2_lo: Scalar<BLS12-381>
out value: Scalar<BLS12-381>
",
    ),
    (
        "nested::map_member",
        "\
in  k_hi: Scalar<BLS12-381>
in  k_lo: Scalar<BLS12-381>
in  k2_hi: Scalar<BLS12-381>
in  k2_lo: Scalar<BLS12-381>
out member: Scalar<BLS12-381>
",
    ),
    (
        "nested::map_remove",
        "\
in  k_hi: Scalar<BLS12-381>
in  k_lo: Scalar<BLS12-381>
in  k2_hi: Scalar<BLS12-381>
in  k2_lo: Scalar<BLS12-381>
",
    ),
    (
        "nested::map_size",
        "\
in  k_hi: Scalar<BLS12-381>
in  k_lo: Scalar<BLS12-381>
out size: Scalar<BLS12-381>
",
    ),
    (
        "nested::map_is_empty",
        "\
in  k_hi: Scalar<BLS12-381>
in  k_lo: Scalar<BLS12-381>
out empty: Scalar<BLS12-381>
",
    ),
    (
        "nested::map_reset",
        "\
in  k_hi: Scalar<BLS12-381>
in  k_lo: Scalar<BLS12-381>
",
    ),
    (
        "nested::outer_insert_default",
        "\
in  k_hi: Scalar<BLS12-381>
in  k_lo: Scalar<BLS12-381>
",
    ),
    (
        "nested::list_push_front",
        "\
in  k_hi: Scalar<BLS12-381>
in  k_lo: Scalar<BLS12-381>
in  v_hi: Scalar<BLS12-381>
in  v_lo: Scalar<BLS12-381>
",
    ),
    (
        "nested::list_pop_front",
        "\
in  k_hi: Scalar<BLS12-381>
in  k_lo: Scalar<BLS12-381>
",
    ),
    (
        "nested::list_length",
        "\
in  k_hi: Scalar<BLS12-381>
in  k_lo: Scalar<BLS12-381>
out length: Scalar<BLS12-381>
",
    ),
    (
        "nested::list_head",
        "\
in  k_hi: Scalar<BLS12-381>
in  k_lo: Scalar<BLS12-381>
out head (is_some): Scalar<BLS12-381>
out head (hi): Scalar<BLS12-381>
out head (lo): Scalar<BLS12-381>
",
    ),
    (
        "nested::list_is_empty",
        "\
in  k_hi: Scalar<BLS12-381>
in  k_lo: Scalar<BLS12-381>
out empty: Scalar<BLS12-381>
",
    ),
    (
        "nested::list_reset",
        "\
in  k_hi: Scalar<BLS12-381>
in  k_lo: Scalar<BLS12-381>
",
    ),
    (
        "nested::set_insert",
        "\
in  k_hi: Scalar<BLS12-381>
in  k_lo: Scalar<BLS12-381>
in  e_hi: Scalar<BLS12-381>
in  e_lo: Scalar<BLS12-381>
",
    ),
    (
        "nested::set_remove",
        "\
in  k_hi: Scalar<BLS12-381>
in  k_lo: Scalar<BLS12-381>
in  e_hi: Scalar<BLS12-381>
in  e_lo: Scalar<BLS12-381>
",
    ),
    (
        "nested::set_member",
        "\
in  k_hi: Scalar<BLS12-381>
in  k_lo: Scalar<BLS12-381>
in  e_hi: Scalar<BLS12-381>
in  e_lo: Scalar<BLS12-381>
out member: Scalar<BLS12-381>
",
    ),
    (
        "nested::set_reset",
        "\
in  k_hi: Scalar<BLS12-381>
in  k_lo: Scalar<BLS12-381>
",
    ),
    (
        "nested::counter_increment",
        "\
in  k_hi: Scalar<BLS12-381>
in  k_lo: Scalar<BLS12-381>
",
    ),
    (
        "nested::counter_read",
        "\
in  k_hi: Scalar<BLS12-381>
in  k_lo: Scalar<BLS12-381>
out count: Scalar<BLS12-381>
",
    ),
    (
        "nested::counter_reset",
        "\
in  k_hi: Scalar<BLS12-381>
in  k_lo: Scalar<BLS12-381>
",
    ),
    (
        "nested::mt_insert",
        "\
in  k_hi: Scalar<BLS12-381>
in  k_lo: Scalar<BLS12-381>
in  item_hi: Scalar<BLS12-381>
in  item_lo: Scalar<BLS12-381>
",
    ),
    (
        "nested::mt_check_root",
        "\
in  k_hi: Scalar<BLS12-381>
in  k_lo: Scalar<BLS12-381>
in  rt: Scalar<BLS12-381>
out ok: Scalar<BLS12-381>
",
    ),
    (
        "nested::mt_reset",
        "\
in  k_hi: Scalar<BLS12-381>
in  k_lo: Scalar<BLS12-381>
",
    ),
    (
        "nested::hmt_insert",
        "\
in  k_hi: Scalar<BLS12-381>
in  k_lo: Scalar<BLS12-381>
in  item_hi: Scalar<BLS12-381>
in  item_lo: Scalar<BLS12-381>
",
    ),
    (
        "nested::hmt_reset_history",
        "\
in  k_hi: Scalar<BLS12-381>
in  k_lo: Scalar<BLS12-381>
",
    ),
    (
        "nested::hmt_reset",
        "\
in  k_hi: Scalar<BLS12-381>
in  k_lo: Scalar<BLS12-381>
",
    ),
    (
        "nested::deep_insert",
        "\
in  k_hi: Scalar<BLS12-381>
in  k_lo: Scalar<BLS12-381>
in  k2_hi: Scalar<BLS12-381>
in  k2_lo: Scalar<BLS12-381>
in  k3_hi: Scalar<BLS12-381>
in  k3_lo: Scalar<BLS12-381>
in  v: Scalar<BLS12-381>
",
    ),
    (
        "nested::deep_lookup",
        "\
in  k_hi: Scalar<BLS12-381>
in  k_lo: Scalar<BLS12-381>
in  k2_hi: Scalar<BLS12-381>
in  k2_lo: Scalar<BLS12-381>
in  k3_hi: Scalar<BLS12-381>
in  k3_lo: Scalar<BLS12-381>
out value: Scalar<BLS12-381>
",
    ),
    (
        "manager::is_registered",
        "\
in  owner_hi: Scalar<BLS12-381>
in  owner_lo: Scalar<BLS12-381>
out registered: Scalar<BLS12-381>
",
    ),
    (
        "manager::account_record",
        "\
in  account_hi: Scalar<BLS12-381>
in  account_lo: Scalar<BLS12-381>
out record registered: Scalar<BLS12-381>
out record mode: Scalar<BLS12-381>
out record owner: Scalar<BLS12-381>
out record nextNonce: Scalar<BLS12-381>
",
    ),
    (
        "manager::shielded_account_balance",
        "\
in  owner_hi: Scalar<BLS12-381>
in  owner_lo: Scalar<BLS12-381>
in  colour_hi: Scalar<BLS12-381>
in  colour_lo: Scalar<BLS12-381>
out balance: Scalar<BLS12-381>
",
    ),
    (
        "manager::unshielded_account_balance",
        "\
in  owner_hi: Scalar<BLS12-381>
in  owner_lo: Scalar<BLS12-381>
in  colour_hi: Scalar<BLS12-381>
in  colour_lo: Scalar<BLS12-381>
out balance: Scalar<BLS12-381>
",
    ),
    (
        "manager::pool_value",
        "\
in  colour_hi: Scalar<BLS12-381>
in  colour_lo: Scalar<BLS12-381>
out value: Scalar<BLS12-381>
",
    ),
    (
        "manager::pool_has_colour",
        "\
in  colour_hi: Scalar<BLS12-381>
in  colour_lo: Scalar<BLS12-381>
out present: Scalar<BLS12-381>
",
    ),
    (
        "manager::deposit_shielded",
        "\
in  coin_nonce_hi: Scalar<BLS12-381>
in  coin_nonce_lo: Scalar<BLS12-381>
in  coin_color_hi: Scalar<BLS12-381>
in  coin_color_lo: Scalar<BLS12-381>
in  coin_value: Scalar<BLS12-381>
in  account_hi: Scalar<BLS12-381>
in  account_lo: Scalar<BLS12-381>
",
    ),
    (
        "manager::deposit_unshielded",
        "\
in  colour_hi: Scalar<BLS12-381>
in  colour_lo: Scalar<BLS12-381>
in  amount: Scalar<BLS12-381>
in  account_hi: Scalar<BLS12-381>
in  account_lo: Scalar<BLS12-381>
",
    ),
    (
        "manager::execute",
        "\
in  payload_selector: Scalar<BLS12-381>
in  payload_authMode: Scalar<BLS12-381>
in  payload_account_hi: Scalar<BLS12-381>
in  payload_account_lo: Scalar<BLS12-381>
in  payload_owner: Scalar<BLS12-381>
in  payload_accountSalt_hi: Scalar<BLS12-381>
in  payload_accountSalt_lo: Scalar<BLS12-381>
in  payload_nonce: Scalar<BLS12-381>
in  payload_validUntil: Scalar<BLS12-381>
in  payload_primaryColor_hi: Scalar<BLS12-381>
in  payload_primaryColor_lo: Scalar<BLS12-381>
in  payload_primaryAmount: Scalar<BLS12-381>
in  payload_recipientKind: Scalar<BLS12-381>
in  payload_recipient_hi: Scalar<BLS12-381>
in  payload_recipient_lo: Scalar<BLS12-381>
in  payload_toAccount_hi: Scalar<BLS12-381>
in  payload_toAccount_lo: Scalar<BLS12-381>
in  payload_wantNonce_hi: Scalar<BLS12-381>
in  payload_wantNonce_lo: Scalar<BLS12-381>
in  payload_wantColor_hi: Scalar<BLS12-381>
in  payload_wantColor_lo: Scalar<BLS12-381>
in  payload_wantAmount: Scalar<BLS12-381>
in  payload_creditAccount_hi: Scalar<BLS12-381>
in  payload_creditAccount_lo: Scalar<BLS12-381>
in  sig_r: Scalar<Secp256k1>
in  sig_s: Scalar<Secp256k1>
in  pk: Point<Secp256k1>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
",
    ),
    // GENERATED END
];

/// The serde name of an [`IrType`], i.e. the type column the differential
/// comparator compares (`Scalar<BLS12-381>`, `Bytes<32>`, ...).
fn type_name(ty: &IrType) -> String {
    match serde_json::to_value(ty).expect("IrType serializes") {
        serde_json::Value::String(s) => s,
        other => other.to_string(),
    }
}

/// `%evmNonce.3` → `evmNonce`. The `%` prefix and the `.index` suffix are
/// `Builder3`'s uniquifiers, not part of the declared name; anything that
/// does not have that exact shape is kept verbatim.
fn label(name: &str) -> &str {
    let name = name.strip_prefix('%').unwrap_or(name);
    match name.rsplit_once('.') {
        Some((head, index)) if !index.is_empty() && index.bytes().all(|b| b.is_ascii_digit()) => {
            head
        }
        _ => name,
    }
}

/// One circuit's interface, one line per argument / output / witness read.
fn interface(c: &Compiled3) -> Vec<String> {
    let mut lines = Vec::new();

    let inputs = serde_json::to_value(&c.ir.inputs).expect("inputs serialize");
    for ti in inputs.as_array().expect("inputs are an array") {
        let name = ti["name"].as_str().expect("input name is a string");
        let ty = ti["type"].as_str().expect("input type is a string");
        lines.push(format!("in  {}: {ty}", label(name)));
    }

    // The IR's output signature is types only; `Circuit3::output` records one
    // `Output` disclosure per queued output, in the same order.
    let out_labels: Vec<&str> = c
        .disclosures
        .iter()
        .filter(|d| d.kind == DisclosureKind::Output)
        .map(|d| d.label.as_str())
        .collect();
    assert_eq!(
        out_labels.len(),
        c.ir.outputs.len(),
        "output disclosures do not match the IR output signature"
    );
    for (l, ty) in out_labels.iter().zip(&c.ir.outputs) {
        lines.push(format!("out {l}: {}", type_name(ty)));
    }

    let mut witnesses = 0;
    for instr in c.ir.instructions.iter() {
        if let Instruction::PrivateInput { guard, val_t, .. } = instr {
            witnesses += 1;
            let guarded = if guard.is_some() { " (guarded)" } else { "" };
            lines.push(format!("wit {}{guarded}", type_name(val_t)));
        }
    }
    assert_eq!(
        witnesses, c.witnesses,
        "private-transcript reads do not match the recorded witness count"
    );

    lines
}

#[test]
fn every_circuit_matches_its_frozen_interface() {
    let circuits = circuits();
    assert_eq!(
        circuits.len(),
        SNAPSHOT.len(),
        "snapshot table covers {} circuits but {} are built — add the new \
         circuit to SNAPSHOT (regenerate with the `print_interface_snapshot` \
         test)",
        SNAPSHOT.len(),
        circuits.len()
    );

    let mut failures = Vec::new();
    for ((name, build), (snap_name, snap)) in circuits.iter().zip(SNAPSHOT) {
        assert_eq!(name, snap_name, "snapshot table out of order");
        let expected: Vec<&str> = snap.lines().collect();
        let actual = interface(&build());
        let actual: Vec<&str> = actual.iter().map(String::as_str).collect();
        if expected != actual {
            failures.push(format!("  {name}:\n{}", diff(&expected, &actual)));
        }
    }
    assert!(
        failures.is_empty(),
        "circuit interface changed — argument order and types are the wire \
         contract (they feed the communications commitment and the proof \
         preimage), so any movement here breaks callers. `-` is the frozen \
         interface, `+` what this build produces:\n{}",
        failures.join("\n")
    );
}

/// The diff is the whole value of the instrument when it fires, so it gets
/// its own check: a reorder, a rename and an insertion, all at once.
#[test]
fn diff_shows_reorders_renames_and_insertions() {
    let expected = ["a", "b", "c", "d"];
    let actual = ["b", "a", "c", "new", "d2"];
    assert_eq!(
        diff(&expected, &actual),
        concat!(
            "    - a\n",
            "      b\n",
            "    + a\n",
            "      c\n",
            "    - d\n",
            "    + new\n",
            "    + d2\n",
        )
    );
}

/// Regeneration helper: rewrites the SNAPSHOT table in this file.
#[test]
#[ignore = "regeneration helper, not a check"]
fn regenerate_interface_snapshot() {
    let mut body = String::new();
    for (name, build) in circuits() {
        let lines = interface(&build());
        assert!(
            lines.iter().all(|l| !l.contains('"')),
            "{name}: a label contains a quote — it cannot go in the table verbatim"
        );
        body.push_str(&format!("    (\n        \"{name}\",\n        \"\\\n"));
        for line in lines {
            body.push_str(&line);
            body.push('\n');
        }
        body.push_str("\",\n    ),\n");
    }
    rewrite_generated_region(&test_source("interface_snapshot.rs"), &body);
}

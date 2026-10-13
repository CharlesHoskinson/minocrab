//! The erc20-vault on the TYPED EVM-CALL API — M37 rung D: every Sig
//! Network suspension owned by an [`crate::evm_flow::Pending`] slot whose
//! type is the CALL it makes. (It was written as the twin of the
//! `erc20_vault_modern` fork; that fork and its two parents were retired in
//! M28 — notes/vault-refresh.org §0 — and this lineage is the one place
//! their constructions live on.)
//!
//! WHAT THIS LINEAGE IS. A NEW DEPLOYMENT LAYOUT, not a byte-twin: its
//! ledger block declares twenty-two fields (so compactc-style segmentation
//! is live — every path is two elements), its request records and
//! environments sit in `Pending` slots, and its settle circuits take one
//! typed TICKET each. It has no compactc twin to differential against; the
//! spec harness's shared model is the oracle for it, as for the opt lineage.
//!
//! WHAT MOVED OUT OF THE CIRCUITS, and where it went:
//!
//! | invariant                        | now                                     |
//! |----------------------------------|-----------------------------------------|
//! | the four-byte selector           | `EvmCall::selector` (keccak, build time)|
//! | the ABI words and the word count | `AbiType::word` + `AbiTuple` (E0080)    |
//! | response kind byte               | `Filing::KIND` on the slot's filing     |
//! | the attested value's field name  | `Filing::RETURN_FIELD`                  |
//! | the fee envelope and gas limit   | `Envelope` + `EvmCall::GAS_LIMIT`       |
//! | record format version            | inside `complete` / `refund`            |
//! | notification depth + path bytes  | derived from the slot                   |
//! | request map / env map / nonce    | one `Pending` slot + one `Signet`       |
//! | `&VAULT.signet`                  | `#[derive(Ledger)]`                     |
//! | amount, token for settle         | typed `Env` fields                      |
//! | verify → kind → lookup → remove  | one `complete` / `refund`               |
//! | refund commitment hash + gate    | `Owned` + `request_owned` / `refund_to_owner` |
//! | "a `false` must not complete"    | `EvmCall::succeeded`, asserted          |
//!
//! THE OUTCOME PICKS THE CIRCUIT (M37 rung D, notes/evm-calls.org §3). The
//! two tickets are symmetric and neither stands in for the other:
//!
//! - `complete_withdraw` takes a `Succeeded<Withdrawal>`, and
//!   `Pending::complete` asserts the call's own success predicate — for an
//!   ERC-20 `transfer` that is the attested flag. So a `transfer` that MINED
//!   AND RETURNED `false` cannot complete, whoever presents it. It is also
//!   ANYONE'S: no secret is witnessed, and there is nothing to mint (the
//!   tokens left the vault's EVM account).
//! - `refund_withdrawal` takes a `Failed<…>` and accepts BOTH non-successes
//!   — the MPC's failure kind (reverted, never mined, or an undecodable
//!   return) and the executed-`false` — opening the owner commitment with a
//!   fresh witness before it re-mints.
//!
//! The deployed lineage put the executed-`false` case in a `when(!succeeded)`
//! branch INSIDE `completeWithdraw`, hoisting a secret witness for a branch
//! it might not take. That is Gap 2; this is its repair, and the API has no
//! method that lets it be written again.
//!
//! WHY THE OTHER THREE COMPLETIONS ARE STILL THE OWNER'S. `complete_swap`,
//! `complete_supply` and `complete_redeem` mint their proceeds to
//! `own_public_key` — the caller's. Making them anyone's would make the
//! proceeds anyone's, so each still opens its stored commitment with a fresh
//! witness. That is a CHECKED consumption of a secret, not the hoisted one
//! Gap 2 is about; nothing in them runs before the check. (Their `refund_*`
//! twins take a `Failed` ticket whose executed branch is unreachable: the
//! attested value is a NUMBER, so `EvmCall::succeeded` is `always` and only
//! the MPC's failure kind refunds — the deployed semantics exactly.)
//!
//! THE IDENTITY COMMITMENT follows upstream's protocol move (`0d9c1660`):
//! `userCommitment` is `upgradeFromTransient(transientHash([pad, sk]))`,
//! not the SHA-256 forms the older lineages keep — ~1,500 rows out of
//! `initialize`, `deposit` and `claim` each, and the same bytes the deployed
//! vault derives keys from.
//!
//! WHAT STAYED, deliberately: the initialization gate, the deployer gate,
//! the business guards, the coin burns and mints, and every authorization
//! with a FRESH witness (`witness_sk` in `claim`, the three owner-gated
//! completions, and every refund).
//!
//! ONE DEVIATION IN CIRCUIT COUNT from the deployed contract: `refund`
//! routed a failure over BOTH request maps in one circuit with guarded
//! lookups; a `Pending` slot settles its own entries, so there is one refund
//! circuit per flow here. Seventeen circuits in total, on twenty-two ledger
//! fields; `approveRouter` and `approveStata` file into a
//! [`crate::evm_flow::Fired`] slot, a request-only shape with no settle
//! method at all.

use core::cell::Cell;

use minocrab::v3::{Circuit3, FieldT, Wire3};
use minocrab::{Private, Public};
use minocrab_std::v3::kernel;
use minocrab_std::v3::{
    contract, eq, label, own_public_key, Bytes, Check, CircuitArg, CoinColor, CoinNonce,
    CoinRecipient, Disclose, Discloses, Either, Ledger, LedgerCell, LedgerCounter, LedgerRepr,
    Maybe, Secp256k1Point, TokenDomainSeparator, Uint, B32,
};

use crate::common;
use crate::erc20_vault::{REDEEM_WORDS, SUPPLY_WORDS, SWAP_WORDS, VAULT_WORDS};
use crate::evm::erc20::Erc20;
use crate::evm::erc4626::Erc4626;
use crate::evm::uniswap_v3::UniswapV3Router;
use crate::evm::{erc20, erc4626, uniswap_v3, Envelope, Filed, Filing};
use crate::evm_flow::{Commit, Contract, Failed, Fired, Owned, Pending, Succeeded};
use crate::signet;
use crate::signet_flow::{Requested, Settled, Signet, Signing};
use crate::signet_v1::schema;

// ---- the wire: constants inherited from the retired borsh fork ---------------------

/// The vault's two Borsh-format (V2) event instantiations: the versioned,
/// kind-tagged record the `Pending` slots write (`signet::SignBidirectionalEventV2`).
pub type VaultEventV2<V> = signet::SignBidirectionalEventV2<V, VAULT_WORDS>;
/// See [`VaultEventV2`].
pub type SwapEventV2<V> = signet::SignBidirectionalEventV2<V, SWAP_WORDS>;

/// Byte 31 of `vault_token_domain_separator`'s encoding: the kind tag of
/// "the vault token of an EVM ERC-20". The separator is the injective
/// encoding `[hi: TAG, lo: erc20]` rather than a hash (M10 rung iii): a
/// pre-token only has to be distinct per ERC-20 and the ledger hashes it
/// again in `tokenType`.
pub const VAULT_TOKEN_TAG: u8 = 0x01;

/// The number of response kinds — `Tag<RESPONSE_KINDS>` is one Borsh byte.
pub const RESPONSE_KINDS: u32 = 7;

/// Response kinds, at BYTE 0 of every attested output AND in the last byte of
/// every V2 request record (M11 stages 5 and 7; the format is specified in
/// spec/borsh-subset.md and notes/borsh-format.org).
///
/// The discriminant is what makes cross-circuit attestation replay
/// STRUCTURALLY impossible: the kind is inside the signed preimage, so two
/// settle circuits' digests differ for the same request id and outcome, and
/// each circuit asserts its own kind (`EvmCall::KIND`, checked by
/// `Pending::complete`).
///
/// Since M37 rung D the CALL TYPE names the kind, so this table's last
/// column is a type in [`crate::evm`] rather than a response struct here:
///
/// | kind | name | recorded by | settled by | attested | filing → call |
/// |------|------|-------------|------------|----------|---------------|
/// | 0 | CLAIM | `deposit` | `claim` | `bool success` | [`Deposit`] → `erc20::Transfer` |
/// | 1 | WITHDRAW | `withdraw` | `complete_withdraw` | `bool success` | [`Withdrawal`] → `erc20::Transfer` |
/// | 2 | SWAP | `swap` | `complete_swap` | `uint64 amountIn` | [`Swap`] → `uniswap_v3::ExactOutputSingle` |
/// | 3 | FAILURE | — | `refund_*` | — | `evm_flow::FAILURE_KIND` |
/// | 4 | APPROVE | `approve_router`, `approve_stata` | — | `bool` | [`Approval`] → `erc20::Approve` |
/// | 5 | SUPPLY | `supply` | `complete_supply` | `uint64 shares` | [`Supply`] → `erc4626::Deposit` |
/// | 6 | REDEEM | `redeem` | `complete_redeem` | `uint64 assets` | [`Redeem`] → `erc4626::Redeem` |
///
/// FAILURE is response-only (an outcome, not a request) and APPROVE is
/// request-only (fire-and-forget); giving the approve request its own kind
/// is what makes an approve RESPONSE a kind no settle circuit accepts.
/// `approveStata` reuses the APPROVE kind — it is request-only, like
/// `approveRouter`.
///
/// THE FIRST TWO ROWS ARE ONE SOLIDITY FUNCTION FILED TWICE:
/// `transfer(address,uint256)` under two kinds, because a deposit's inbound
/// transfer and a withdrawal's outbound one are two OPERATIONS of the
/// protocol and the kind byte is what says so. Since M38 rung A that is one
/// LIBRARY call ([`erc20::Transfer`]) and two FILINGS of it ([`Deposit`],
/// [`Withdrawal`]) rather than two call types — the kind and the record's
/// field name are the deployment's, and this module is the deployment.
pub const RESPONSE_KIND_CLAIM: u32 = 0;
/// See [`RESPONSE_KIND_CLAIM`].
pub const RESPONSE_KIND_WITHDRAW: u32 = 1;
/// See [`RESPONSE_KIND_CLAIM`].
pub const RESPONSE_KIND_SWAP: u32 = 2;
/// See [`RESPONSE_KIND_CLAIM`].
pub const RESPONSE_KIND_FAILURE: u32 = 3;
/// The REQUEST-ONLY kind — see [`RESPONSE_KIND_CLAIM`]'s table.
pub const RESPONSE_KIND_APPROVE: u32 = 4;
/// See [`RESPONSE_KIND_CLAIM`].
pub const RESPONSE_KIND_SUPPLY: u32 = 5;
/// See [`RESPONSE_KIND_CLAIM`].
pub const RESPONSE_KIND_REDEEM: u32 = 6;

// ---- the environments -------------------------------------------------------------------
//
// THE RESPONSE TYPES ARE GONE (M37 rung D). `ClaimResponse`,
// `WithdrawResponse`, `SwapResponse`, `Failure`, `ApproveResponse`,
// `SupplyResponse` and `RedeemResponse` each existed to carry one kind byte
// and one attested field. Since M38 rung A the kind byte and the field name
// are this lineage's own `Filing` impls below, and the attested TYPE is the
// library call's `EvmCall::Return`. The kind CONSTANTS above stay — they are
// the wire, and the filings name them.

// ---- the filings: how THIS deployment files the library's calls ------------------------

/// `erc20::Transfer` AS A DEPOSIT'S INBOUND TRANSFER — the depositor's own
/// account paying tokens in, filed under CLAIM, with the deployed record's
/// name for the flag.
///
/// The record is `{ kind, success }`, so `claim`'s ticket reads
/// `serializedOutput.output.success`. A Solidity `transfer` return is
/// anonymous; this name is the DEPLOYMENT's, which is exactly why it lives
/// here and not on [`erc20::Transfer`].
pub struct Deposit;

impl Filing for Deposit {
    type Call = erc20::Transfer;
    type Schema = schema::Success;
}

/// `erc20::Transfer` AS A WITHDRAWAL — the vault's outbound transfer, filed
/// under WITHDRAW. Same Solidity function as [`Deposit`], same record shape,
/// different protocol operation.
pub struct Withdrawal;

impl Filing for Withdrawal {
    type Call = erc20::Transfer;
    type Schema = schema::Success;
}

/// `uniswap_v3::ExactOutputSingle` under SWAP; the record is
/// `{ kind, amountIn }`.
pub struct Swap;

impl Filing for Swap {
    type Call = uniswap_v3::ExactOutputSingle;
    type Schema = schema::AmountIn;
}

/// `erc4626::Deposit` on the stata wrapper, under SUPPLY; the record is
/// `{ kind, shares }`.
pub struct Supply;

impl Filing for Supply {
    type Call = erc4626::Deposit;
    type Schema = schema::Shares;
}

/// `erc4626::Redeem` on the stata wrapper, under REDEEM; the record is
/// `{ kind, assets }`.
pub struct Redeem;

impl Filing for Redeem {
    type Call = erc4626::Redeem;
    type Schema = schema::Assets;
}

/// `erc20::Approve` — the ONE filing with nothing to say beyond its schema,
/// so it is the off-the-shelf [`Filed`] rather than an impl: the slot is
/// [`Fired`], nothing settles it, and the attested `bool` is never read.
pub type Approval = Filed<erc20::Approve, schema::Success>;

/// What `claim` needs back: who may claim, which token, how much.
///
/// Not [`Owned`]: a deposit's gate is the depositor's IDENTITY commitment
/// (`userCommitment`, unbound to the request), which is what the deployed
/// protocol derives the depositor's own EVM account from — not the
/// request-bound refund commitment the other four flows carry.
#[derive(LedgerRepr)]
pub struct DepositEnv {
    pub depositor: common::UserCommitment<Public>,
    pub erc20: Bytes<20, Public>,
    pub amount: Uint<64, Public>,
}

/// What `refund_withdrawal` needs back once [`Owned`] has produced the
/// owner: what to re-mint, and of which token.
///
/// The owner half is [`Owned::owner`] — the same `transientHash([pad(32,
/// "vault:refund:"), sk, requestId])` digest the field named `withdrawer`
/// held, in the same ledger limb, so the environment map's bytes are
/// unchanged.
#[derive(LedgerRepr)]
pub struct WithdrawEnv {
    pub erc20: Bytes<20, Public>,
    pub amount: Uint<64, Public>,
}

/// What `complete_swap` / `refund_swap` need back, beside [`Owned::owner`].
#[derive(LedgerRepr)]
pub struct SwapEnv {
    pub token_in: Bytes<20, Public>,
    pub token_out: Bytes<20, Public>,
    pub amount_out: Uint<64, Public>,
    pub amount_in_maximum: Uint<64, Public>,
}

/// What `complete_supply` / `refund_supply` need back, beside
/// [`Owned::owner`].
#[derive(LedgerRepr)]
pub struct SupplyEnv {
    pub amount: Uint<64, Public>,
}

/// What `complete_redeem` / `refund_redeem` need back, beside
/// [`Owned::owner`].
#[derive(LedgerRepr)]
pub struct RedeemEnv {
    pub shares: Uint<64, Public>,
}

// ---- the ledger block ---------------------------------------------------------------------

/// Twenty-two ledger fields from thirteen declarations — SEGMENTED by
/// compactc's rule (past fifteen), so every path here is two elements and
/// every cell write is nested, as the upstream vault's own block is since
/// its lending extension (M28). The layout is this lineage's own.
#[derive(Ledger)]
pub struct Vault {
    pub initialized: LedgerCounter,
    /// `sealed ledger deployer: Bytes<32>` — write-once at deployment.
    pub deployer: LedgerCell<common::UserCommitment<Public>>,
    pub vault_evm_address: LedgerCell<Bytes<20, Public>>,
    pub uniswap_router: LedgerCell<Bytes<20, Public>>,
    /// signer, mpcResponseKey, mpcKeyVersion, evmChainId — FOUR fields
    /// under V1, where the V2 vocabulary had six.
    pub signet: Signet,
    pub deposits: Pending<Deposit, DepositEnv, VAULT_WORDS>,
    pub withdrawals: Pending<Withdrawal, Owned<WithdrawEnv>, VAULT_WORDS>,
    pub swaps: Pending<Swap, Owned<SwapEnv>, SWAP_WORDS>,
    /// Request-only: no settle exists for it.
    pub approvals: Fired<Approval, VAULT_WORDS>,
    pub stata_underlying: LedgerCell<Bytes<20, Public>>,
    pub stata_token: LedgerCell<Bytes<20, Public>>,
    pub supplies: Pending<Supply, Owned<SupplyEnv>, SUPPLY_WORDS>,
    pub redeems: Pending<Redeem, Owned<RedeemEnv>, REDEEM_WORDS>,
}

pub const VAULT: Vault = Vault::new();

label! {
    VaultEvmAddress = "the vault's derived EVM address";
    UniswapRouter = "the Uniswap router address";
    EvmChainId = "the EVM chain id";
    MpcKeyVersion = "the MPC key version";
    MpcResponseKey = "the MPC response key";
    DepositorCommitment = "depositor identity commitment";
    DepositedErc20 = "the deposited ERC20";
    DepositedAmount = "the deposited amount";
    WithdrawnErc20 = "the withdrawn ERC20";
    WithdrawnAmount = "the withdrawn amount";
    SurrenderedCoinNonce = "surrendered coin nonce";
    SurrenderedCoinColor = "surrendered coin color";
    SurrenderedCoinValue = "surrendered coin value";
    WithdrawerRefundCommitment = "withdrawer refund commitment";
    SoldErc20 = "the sold ERC20";
    BoughtErc20 = "the bought ERC20";
    SwapAmountOut = "the swap's amountOut";
    SwapAmountInMaximum = "the swap's amountInMaximum";
    SwapperRefundCommitment = "swapper refund commitment";
    SuppliedAmount = "the supplied amount";
    SupplierRefundCommitment = "supplier refund commitment";
    RedeemedShares = "the redeemed shares";
    RedeemerRefundCommitment = "redeemer refund commitment";
    ApprovedErc20 = "the approved ERC20";
    StataUnderlying = "the Aave underlying ERC20 (USDC)";
    StataToken = "the Aave stata wrapper (ERC-4626)";
    WithdrawalOutcome = "withdrawal EVM outcome";
    RefundMintNonce = "refund mint nonce";
    RefundRecipient = "own public key as refund recipient";
    SwapRecipient = "own public key as swap recipient";
    SwapMintNonce = "swap mint nonce";
    AttestedAmountIn = "attested amountIn spent";
    SupplyRecipient = "own public key as supply recipient";
    SupplyMintNonce = "supply mint nonce";
    AttestedShares = "attested shares minted";
    RedeemRecipient = "own public key as redeem recipient";
    RedeemMintNonce = "redeem mint nonce";
    AttestedAssets = "attested assets redeemed";
    ClaimRecipientTag = "claim recipient tag";
    ClaimRecipientSide = "claim recipient side";
    ClaimRecipientOwnKey = "own public key as claim recipient";
    ClaimRecipientKey = "claim recipient key";
    ClaimRecipientContract = "claim recipient contract";
    ClaimMintNonce = "claim mint nonce";
}

// ---- shared pieces ------------------------------------------------------------------------

fn assert_initialized(c: &mut Circuit3) {
    let init = VAULT.initialized.read(c);
    c.assert(init.gt(0u64).message("Not initialized"));
}

fn b32_eq(a: &B32<Private>, b: &B32<Private>) -> Check<Private> {
    eq(a.hi, b.hi).and(eq(a.lo, b.lo))
}

fn assert_deployer(c: &mut Circuit3) {
    let sk = common::witness_sk(c);
    let digest = common::commitment_transient(c, &sk);
    let stored = VAULT.deployer.read(c);
    c.assert(b32_eq(&digest.bytes(), &stored.private().bytes()).message("Not the deployer"));
}

/// The vault token's pre-token for an ERC-20 (see
/// `erc20_vault_modern::vault_token_domain_separator`).
fn vault_token_domain_separator(
    c: &mut Circuit3,
    erc20_address: Wire3<FieldT, Public>,
) -> TokenDomainSeparator<Public> {
    c.region("token domain separator", |c| {
        TokenDomainSeparator(B32 {
            hi: c.constant(u64::from(VAULT_TOKEN_TAG)),
            lo: erc20_address,
        })
    })
}

/// The private `Bytes<20>` an ABI `address` argument takes, from a ledger
/// cell read HERE — inside an argument builder, so the read emits where the
/// deployed circuit reads it (`crate::evm::AbiArgs`).
fn cell_address(c: &mut Circuit3, cell: &LedgerCell<Bytes<20, Public>>) -> Bytes<20, Private> {
    Bytes::from_field_unchecked(cell.read(c).stale(c).field().private())
}

/// `struct ShieldedCoinInfo { nonce, color, value }` as an argument.
#[derive(CircuitArg)]
struct ShieldedCoinArg {
    nonce: CoinNonce<Private>,
    color: CoinColor<Private>,
    value: Uint<128>,
}

/// The surrendered coin must be the vault token for `erc20` of exactly
/// `amount`; then it is burned. Returns nothing: the checks assert.
fn burn_vault_coin(
    c: &mut Circuit3,
    one: Wire3<FieldT, Public>,
    erc20: Wire3<FieldT, Public>,
    amount: Wire3<FieldT, Private>,
    coin: ShieldedCoinArg,
) {
    let domain_sep = vault_token_domain_separator(c, erc20);
    let me = kernel::cache_self_address(c);
    let color = minocrab_std::v3::token_type(c, &domain_sep, &me.bytes());
    c.assert(b32_eq(&coin.color.bytes(), &color.private().bytes()));
    c.assert(eq(coin.value.field(), amount));
    let coin = minocrab_std::v3::ShieldedCoinInfo3 {
        nonce: coin.nonce.disclose_as::<SurrenderedCoinNonce>(c),
        color: coin.color.disclose_as::<SurrenderedCoinColor>(c),
        value: coin.value.field().disclose_as::<SurrenderedCoinValue>(c),
    };
    common::burn_spend(c, one, &coin);
}

/// completeSwap's change-coin nonce: `[255 − hi, lo]` (see
/// `erc20_vault_modern::change_nonce`).
fn change_nonce(c: &mut Circuit3, mint_nonce: &CoinNonce<Public>) -> CoinNonce<Public> {
    c.region("change nonce", |c| {
        let neg_hi = c.neg(mint_nonce.bytes().hi);
        CoinNonce(B32 {
            hi: c.add(255u64, neg_hi),
            lo: mint_nonce.bytes().lo,
        })
    })
}

/// `numericAbiWord(unlimitedAllowance())` — 2^128 − 1 as an ABI word: 16
/// zero bytes then 16 `0xff` bytes.
fn unlimited_allowance_word(c: &mut Circuit3) -> B32<Private> {
    let mut max_word = [0u8; 32];
    max_word[16..].copy_from_slice(&[0xff; 16]);
    B32 {
        hi: c.constant(minocrab::Fr::from(u64::from(max_word[31]))).private(),
        lo: c.constant(minocrab::Fr::from_le_bytes(&max_word[..31]).unwrap()).private(),
    }
}

/// `struct DepositRequest { erc20Address: Bytes<20>, amount: Uint<128> }`.
#[derive(CircuitArg)]
struct DepositRequest {
    erc20_address: Bytes<20>,
    amount: Uint<128>,
}

/// `struct WithdrawRequest { erc20Address, amount, destEvmAddress }`.
#[derive(CircuitArg)]
struct WithdrawRequest {
    erc20_address: Bytes<20>,
    amount: Uint<128>,
    dest_evm_address: Bytes<20>,
}

/// `struct SwapRequest { tokenIn, tokenOut, fee: Uint<24>, amountOut,
/// amountInMaximum }`.
#[derive(CircuitArg)]
struct SwapRequest {
    token_in: Bytes<20>,
    token_out: Bytes<20>,
    fee: Uint<24>,
    amount_out: Uint<128>,
    amount_in_maximum: Uint<128>,
}

#[contract]
impl Vault {
    // ---- initialize ---------------------------------------------------------------------------------

    /// `initialize(vaultEvm, swapRouter, stataUnderlyingAddr, stataTokenAddr,
    /// chainId, keyVersion, responseKey)`.
    ///
    /// The caip2 id went with the V1 vocabulary (`executionDest` is the
    /// constant `ethereumCaip2Id()`); the MPC key version arrived in its
    /// place, as a cell, so no later circuit takes one.
    #[circuit]
    pub fn initialize(
        c: &mut Circuit3,
        vault_evm: Bytes<20>,
        swap_router: Bytes<20>,
        stata_underlying_addr: Bytes<20>,
        stata_token_addr: Bytes<20>,
        chain_id: Uint<64>,
        key_version: Uint<8>,
        response_key: Secp256k1Point,
    ) -> Discloses<(
        VaultEvmAddress,
        UniswapRouter,
        StataUnderlying,
        StataToken,
        EvmChainId,
        MpcKeyVersion,
        MpcResponseKey,
    )> {
        c.region("initialized gate", |c| {
            let count = VAULT.initialized.read(c);
            c.assert(count.eq(0u64).message("Already initialized"));
        });
        c.region("deployer gate", assert_deployer);
        // THE KEY VERSION IS GUARDED HERE, and only here: it is a write-once
        // cell under V1, so this is the one circuit that can choose it. The
        // compat lineage carries the same assert on its own `initialize`
        // (`erc20_vault::initialize`), and before M44 rung D every request
        // circuit repeated it because every request took a version.
        c.assert(key_version.ge(1u64).message("keyVersion must be >= 1"));
        c.assert(chain_id.gt(0u64).message("Chain ID must be positive"));
        c.assert(swap_router.ne(0u64).message("Router cannot be zero"));
        c.assert(stata_underlying_addr.ne(0u64).message("stataUnderlying cannot be zero"));
        c.assert(stata_token_addr.ne(0u64).message("stataToken cannot be zero"));
        // An identity key authenticates anything; extracting coordinates IS
        // the check (external review §4.5).
        c.region("response key is a point", |c| {
            let _ = c.into_coordinates(response_key.point());
        });

        VAULT.initialized.increment(c, 1);

        c.region("configuration writes", |c| {
            let vault_evm = vault_evm.disclose_as::<VaultEvmAddress>(c);
            VAULT.vault_evm_address.write(c, &vault_evm);
            let swap_router = swap_router.disclose_as::<UniswapRouter>(c);
            VAULT.uniswap_router.write(c, &swap_router);
            let stata_underlying = stata_underlying_addr.disclose_as::<StataUnderlying>(c);
            VAULT.stata_underlying.write(c, &stata_underlying);
            let stata_token = stata_token_addr.disclose_as::<StataToken>(c);
            VAULT.stata_token.write(c, &stata_token);
            let chain_id = chain_id.disclose_as::<EvmChainId>(c);
            let key_version = key_version.disclose_as::<MpcKeyVersion>(c);
            let response_key = response_key.disclose_as::<MpcResponseKey>(c);
            VAULT.signet.initialize(c, &response_key, &key_version, &chain_id);
        });
        Discloses::of(())
    }

    // ---- deposit / claim ------------------------------------------------------------------------

    /// `deposit(evmNonce, gasLimit, maxFeePerGas, maxPriorityFeePerGas,
    /// keyVersion, depositRequest)`: file `transfer(vaultEvmAddress, amount)`
    /// under the depositor's identity commitment and notify the MPC.
    #[circuit]
    pub fn deposit(
        c: &mut Circuit3,
        evm_nonce: Uint<64>,
        gas_limit: Uint<64>,
        max_fee_per_gas: Uint<128>,
        max_priority_fee_per_gas: Uint<128>,
        deposit_request: DepositRequest,
    ) -> Discloses<(DepositorCommitment, DepositedErc20, DepositedAmount, Requested)> {
        c.region("guards", |c| {
            assert_initialized(c);
            c.assert(deposit_request.erc20_address.ne(0u64));
            c.assert(deposit_request.amount.gt(0u64));
            c.assert(deposit_request.amount.le(u64::MAX));
            c.assert(gas_limit.gt(0u64));
        });

        let sk = common::witness_sk(c);
        let caller = common::commitment_transient(c, &sk).disclose_as::<DepositorCommitment>(c);

        // transfer(vaultEvmAddress, amount), paid from the DEPOSITOR's own EVM
        // account: the gas envelope is the caller's, and the signing path is
        // the depositor's identity commitment rather than the contract's pad.
        let erc20 = deposit_request.erc20_address.disclose_as::<DepositedErc20>(c);
        let amount = deposit_request.amount.field().disclose_as::<DepositedAmount>(c);
        VAULT.deposits.request_with(
            c,
            |c| Contract::<Erc20>::from_address(c, deposit_request.erc20_address),
            (
                |c: &mut Circuit3| cell_address(c, &VAULT.vault_evm_address),
                |_c: &mut Circuit3| deposit_request.amount,
            ),
            Envelope::caller(max_priority_fee_per_gas, max_fee_per_gas, gas_limit),
            evm_nonce,
            |_c| (Signing::derived(common::SigningPath::from(caller.private())), ()),
            |_c, _id, ()| DepositEnv {
                depositor: caller,
                erc20,
                amount: Uint::from_field_unchecked(amount),
            },
        );
        Discloses::of(())
    }

    /// `claim(ticket, mintNonce, recipient)`: settle a deposit — the attested
    /// transfer succeeded — and mint the deposited amount as shielded vault
    /// tokens to the recipient (depositor-only).
    #[circuit]
    pub fn claim(
        c: &mut Circuit3,
        ticket: Succeeded<Deposit>,
        mint_nonce: CoinNonce<Private>,
        recipient: Maybe<
            Either<
                minocrab_std::v3::ZswapCoinPublicKey<Private>,
                minocrab_std::v3::ContractAddress<Private>,
                Private,
            >,
        >,
    ) -> Discloses<(
        Settled,
        ClaimRecipientTag,
        ClaimRecipientSide,
        ClaimRecipientOwnKey,
        ClaimRecipientKey,
        ClaimRecipientContract,
        ClaimMintNonce,
    )> {
        let one = c.constant(1u64);
        assert_initialized(c);
        // `complete` asserts `erc20::Transfer::succeeded` — `is_true`
        // on the attested flag — so the MPC's attested `false` cannot reach
        // the mint below, and nothing in this body has to remember to look.
        let outcome = VAULT.deposits.complete(c, ticket);

        // Depositor gate: a FRESH witness against the filed commitment.
        c.region("depositor gate", |c| {
            let sk = common::witness_sk(c);
            let caller = common::commitment_transient(c, &sk).bytes();
            c.assert(
                b32_eq(&caller, &outcome.env.depositor.private().bytes()).message("Not the depositor"),
            );
        });

        let domain_sep = vault_token_domain_separator(c, outcome.env.erc20.field());
        let recipient = c.region("recipient select", |c| {
            let rec_is_some = recipient.is_some.field().disclose_as::<ClaimRecipientTag>(c);
            let rec_is_left = recipient.value.is_left.field().disclose_as::<ClaimRecipientSide>(c);
            let not_some = c.not(rec_is_some);
            let own_pk = c
                .when(not_some, own_public_key)
                .or_default()
                .disclose_as::<ClaimRecipientOwnKey>(c);
            let rec_left = recipient.value.left.disclose_as::<ClaimRecipientKey>(c);
            let rec_right = recipient.value.right.disclose_as::<ClaimRecipientContract>(c);
            let is_left = c.cond_select(rec_is_some, rec_is_left, one);
            let left = minocrab_std::v3::ZswapCoinPublicKey(B32 {
                hi: c.cond_select(rec_is_some, rec_left.bytes().hi, own_pk.bytes().hi),
                lo: c.cond_select(rec_is_some, rec_left.bytes().lo, own_pk.bytes().lo),
            });
            let right = minocrab_std::v3::ContractAddress(B32 {
                hi: c.cond_select(rec_is_some, rec_right.bytes().hi, 0u64),
                lo: c.cond_select(rec_is_some, rec_right.bytes().lo, 0u64),
            });
            CoinRecipient { is_left, left, right }
        });

        let mint_nonce = mint_nonce.disclose_as::<ClaimMintNonce>(c);
        common::mint_shielded_token(c, &domain_sep, outcome.env.amount, &mint_nonce, &recipient);
        Discloses::of(())
    }

    // ---- withdraw / completeWithdraw / refundWithdrawal ---------------------------------

    /// `withdraw(evmNonce, keyVersion, withdrawRequest, coin)`: burn the
    /// surrendered vault tokens and file `transfer(destEvmAddress, amount)`
    /// signed by the VAULT's account, the withdrawer kept as a commitment.
    #[circuit]
    pub fn withdraw(
        c: &mut Circuit3,
        evm_nonce: Uint<64>,
        withdraw_request: WithdrawRequest,
        coin: ShieldedCoinArg,
    ) -> Discloses<(
        WithdrawnErc20,
        WithdrawnAmount,
        SurrenderedCoinNonce,
        SurrenderedCoinColor,
        SurrenderedCoinValue,
        WithdrawerRefundCommitment,
        Requested,
    )> {
        let one = c.constant(1u64);
        c.region("guards", |c| {
            assert_initialized(c);
            c.assert(withdraw_request.erc20_address.ne(0u64));
            c.assert(withdraw_request.amount.gt(0u64));
            c.assert(withdraw_request.amount.le(u64::MAX));
        });

        let erc20 = withdraw_request.erc20_address.disclose_as::<WithdrawnErc20>(c);
        let amount = withdraw_request.amount.field();
        burn_vault_coin(c, one, erc20.field(), amount, coin);

        VAULT.withdrawals.request_with(
            c,
            |c| Contract::<Erc20>::from_address(c, erc20),
            (
                |_c: &mut Circuit3| withdraw_request.dest_evm_address,
                |_c: &mut Circuit3| withdraw_request.amount,
            ),
            Envelope::fixed(),
            evm_nonce,
            // The secret is witnessed HERE — after the transaction, before
            // the record is filed, which is where the deployed circuit
            // witnesses it.
            |c| {
                let sk = common::witness_sk(c);
                let amount = amount.disclose_as::<WithdrawnAmount>(c);
                (Signing::contract(c), (sk, amount))
            },
            |c, id, (sk, amount)| Owned {
                owner: Commit::to::<WithdrawerRefundCommitment, _>(c, sk, id),
                inner: WithdrawEnv {
                    erc20,
                    amount: Uint::from_field_unchecked(*amount),
                },
            },
        );
        Discloses::of(())
    }

    /// `completeWithdraw(ticket)`: the withdrawal EXECUTED AND SUCCEEDED —
    /// the tokens left the vault's EVM account, and there is nothing to mint.
    ///
    /// ANYONE MAY CALL IT (M37 rung D): the attestation is the gate, there is
    /// no witness in the circuit, and the attested `false` case cannot reach
    /// here at all — it is a [`Failed`] ticket and `refund_withdrawal`'s
    /// business. The deployed lineage put that case in a `when(!succeeded)`
    /// branch INSIDE this circuit, hoisting a secret witness for a branch it
    /// might not take; that is Gap 2, and this is its repair.
    #[circuit]
    pub fn complete_withdraw(
        c: &mut Circuit3,
        ticket: Succeeded<Withdrawal>,
    ) -> Discloses<Settled> {
        assert_initialized(c);
        VAULT.withdrawals.complete(c, ticket);
        Discloses::of(())
    }

    /// `refundWithdrawal(ticket, mintNonce)`: the withdrawal DID NOT SUCCEED —
    /// either the MPC attested its failure kind (reverted, never mined, or an
    /// undecodable return) or the transfer mined and returned `false` — so
    /// re-mint the surrendered value to the withdrawer.
    ///
    /// ONLY THE ORIGINAL WITHDRAWER: `refund_to_owner` witnesses a fresh
    /// secret and opens the environment's commitment against it.
    #[circuit]
    pub fn refund_withdrawal(
        c: &mut Circuit3,
        ticket: Failed<Withdrawal>,
        mint_nonce: CoinNonce<Private>,
    ) -> Discloses<(Settled, RefundRecipient, RefundMintNonce)> {
        assert_initialized(c);
        let (own_pk, env, _flag) = VAULT
            .withdrawals
            .refund_to_owner::<RefundRecipient>(c, ticket);
        let mint_nonce = mint_nonce.disclose_as::<RefundMintNonce>(c);
        let domain_sep = vault_token_domain_separator(c, env.erc20.field());
        common::mint_shielded_token_to_key(c, &domain_sep, env.amount, &mint_nonce, &own_pk);
        Discloses::of(())
    }

    // ---- swap / completeSwap / refundSwap ----------------------------------------------------

    /// `swap(evmNonce, keyVersion, swapRequest, coin)`: burn the surrendered
    /// tokenIn (amountInMaximum) and file `exactOutputSingle` on the pinned
    /// router, signed by the VAULT's account.
    #[circuit]
    pub fn swap(
        c: &mut Circuit3,
        evm_nonce: Uint<64>,
        swap_request: SwapRequest,
        coin: ShieldedCoinArg,
    ) -> Discloses<(
        SoldErc20,
        BoughtErc20,
        SwapAmountOut,
        SwapAmountInMaximum,
        SurrenderedCoinNonce,
        SurrenderedCoinColor,
        SurrenderedCoinValue,
        SwapperRefundCommitment,
        Requested,
    )> {
        let one = c.constant(1u64);
        let zero = c.constant(0u64);
        c.region("guards", |c| {
            assert_initialized(c);
            c.assert(swap_request.token_in.ne(0u64));
            c.assert(swap_request.token_out.ne(0u64));
            c.assert(swap_request.amount_out.gt(0u64));
            c.assert(swap_request.amount_in_maximum.gt(0u64));
            c.assert(swap_request.amount_out.le(u64::MAX));
            c.assert(swap_request.amount_in_maximum.le(u64::MAX));
        });

        let amount_out = swap_request.amount_out.field();
        let amount_in_max = swap_request.amount_in_maximum.field();
        let token_in = swap_request.token_in.disclose_as::<SoldErc20>(c);
        burn_vault_coin(c, one, token_in.field(), amount_in_max, coin);

        // exactOutputSingle((tokenIn, tokenOut, fee, vault, amountOut,
        // amountInMaximum, 0)).
        let token_out = swap_request.token_out.disclose_as::<BoughtErc20>(c);
        VAULT.swaps.request_with(
            c,
            |c| {
                let router = VAULT.uniswap_router.read(c).stale(c);
                Contract::<UniswapV3Router>::from_address(c, router)
            },
            (
                |_c: &mut Circuit3| Bytes::from_field_unchecked(token_in.field().private()),
                |_c: &mut Circuit3| Bytes::from_field_unchecked(token_out.field().private()),
                |_c: &mut Circuit3| swap_request.fee,
                |c: &mut Circuit3| cell_address(c, &VAULT.vault_evm_address),
                |_c: &mut Circuit3| swap_request.amount_out,
                |_c: &mut Circuit3| swap_request.amount_in_maximum,
                // `sqrtPriceLimitX96 = 0`: a `U256`/`U160` wire IS the
                // already-encoded word, so this emits nothing.
                |_c: &mut Circuit3| B32::<Private> {
                    hi: zero.private(),
                    lo: zero.private(),
                },
            ),
            // The struct-literal spelling: the zero and the one are the
            // circuit's own (see `Envelope::literal`).
            Envelope::fixed().literal(Some(zero.private()), one.private()),
            evm_nonce,
            |c| {
                let sk = common::witness_sk(c);
                let amount_out = amount_out.disclose_as::<SwapAmountOut>(c);
                let amount_in_max = amount_in_max.disclose_as::<SwapAmountInMaximum>(c);
                (
                    Signing::contract(c),
                    (sk, amount_out, amount_in_max),
                )
            },
            |c, id, (sk, amount_out, amount_in_max)| Owned {
                owner: Commit::to::<SwapperRefundCommitment, _>(c, sk, id),
                inner: SwapEnv {
                    token_in,
                    token_out,
                    amount_out: Uint::from_field_unchecked(*amount_out),
                    amount_in_maximum: Uint::from_field_unchecked(*amount_in_max),
                },
            },
        );
        Discloses::of(())
    }

    /// `completeSwap(ticket, mintNonce)`: the swap EXECUTED; mint the exact
    /// amountOut of tokenOut and the unspent tokenIn as change, to the swapper
    /// (fresh witness against the commitment).
    #[circuit]
    pub fn complete_swap(
        c: &mut Circuit3,
        ticket: Succeeded<Swap>,
        mint_nonce: CoinNonce<Private>,
    ) -> Discloses<(Settled, SwapRecipient, SwapMintNonce, AttestedAmountIn)> {
        assert_initialized(c);
        let outcome = VAULT.swaps.complete(c, ticket);
        // STILL THE SWAPPER'S, deliberately (see the module docs): the
        // proceeds are minted to `own_public_key`, so "anyone may complete"
        // would be "anyone may take the proceeds". The secret is opened
        // against the stored commitment, so this is a CHECKED consumption,
        // not the hoisted one `complete_withdraw` used to have.
        let sk = common::witness_sk(c);
        outcome
            .env
            .owner
            .open(c, &sk, outcome.request_id, "Not the swapper");

        kernel::cache_self_address(c);
        let recipient = own_public_key(c).disclose_as::<SwapRecipient>(c);
        let mint_nonce = mint_nonce.disclose_as::<SwapMintNonce>(c);

        let env = outcome.env.map(|e| e.inner);
        let ds_out = vault_token_domain_separator(c, env.token_out.field());
        common::mint_shielded_token_to_key(c, &ds_out, env.amount_out, &mint_nonce, &recipient);

        // Change: amountInMaximum − attested amountIn, guarded against
        // underflow by `sub_with` (the most dangerous arithmetic in the contract).
        let amount_in = outcome.output.disclose_as::<AttestedAmountIn>(c);
        let change = env
            .amount_in_maximum
            .sub_with(c, amount_in, "Attested amountIn exceeds amountInMaximum");
        // CHECKED: the difference is re-bounded to 64 bits where it enters the
        // coin commitment (one `constrain_bits 64`), as the modern lineage does
        // — the taint lint's warrant for the 16-byte value atom.
        let change = Uint::<64, Public>::from_field_checked(c, change.field());
        let ds_in = vault_token_domain_separator(c, env.token_in.field());
        let change_nonce = change_nonce(c, &mint_nonce);
        common::mint_shielded_token_to_key(c, &ds_in, change, &change_nonce, &recipient);
        Discloses::of(())
    }

    /// `refundSwap(ticket, mintNonce)`: the swap DID NOT SUCCEED — for this
    /// call that is the MPC's failure kind alone, because
    /// `uniswap_v3::ExactOutputSingle::succeeded` is `always` (the `amountIn` IS
    /// the outcome; there is no failure flag to read). Re-mint the
    /// surrendered amountInMaximum of tokenIn to the swapper.
    #[circuit]
    pub fn refund_swap(
        c: &mut Circuit3,
        ticket: Failed<Swap>,
        mint_nonce: CoinNonce<Private>,
    ) -> Discloses<(Settled, RefundRecipient, RefundMintNonce)> {
        assert_initialized(c);
        let (own_pk, env, _amount_in) = VAULT.swaps.refund_to_owner::<RefundRecipient>(c, ticket);
        let mint_nonce = mint_nonce.disclose_as::<RefundMintNonce>(c);
        let domain_sep = vault_token_domain_separator(c, env.token_in.field());
        common::mint_shielded_token_to_key(
            c,
            &domain_sep,
            env.amount_in_maximum,
            &mint_nonce,
            &own_pk,
        );
        Discloses::of(())
    }

    // ---- approveRouter / approveStata --------------------------------------------------------------

    /// `approveRouter(erc20Address, evmNonce, keyVersion)`: file
    /// `approve(uniswapRouter, 2^128−1)` signed by the VAULT's account.
    /// Request-only.
    #[circuit]
    pub fn approve_router(
        c: &mut Circuit3,
        erc20_address: Bytes<20>,
        evm_nonce: Uint<64>,
    ) -> Discloses<(ApprovedErc20, Requested)> {
        c.region("guards", |c| {
            assert_initialized(c);
            c.assert(erc20_address.ne(0u64));
        });

        let erc20 = erc20_address.disclose_as::<ApprovedErc20>(c);
        VAULT.approvals.request_with(
            c,
            |c| Contract::<Erc20>::from_address(c, erc20),
            (
                |c: &mut Circuit3| cell_address(c, &VAULT.uniswap_router),
                |c: &mut Circuit3| unlimited_allowance_word(c),
            ),
            Envelope::fixed(),
            evm_nonce,
            Signing::contract,
        );
        Discloses::of(())
    }

    /// `approveStata(evmNonce, keyVersion)`: file `approve(stataToken,
    /// 2^128−1)` ON the underlying USDC, signed by the VAULT's account, so the
    /// wrapper can pull it during a supply. Request-only.
    #[circuit]
    pub fn approve_stata(
        c: &mut Circuit3,
        evm_nonce: Uint<64>,
    ) -> Discloses<(Requested,)> {
        assert_initialized(c);

        VAULT.approvals.request_with(
            c,
            |c| {
                // THE CALLEE IS THE UNDERLYING ERC-20, and the stata
                // token is the SPENDER argument: this approval lets the
                // wrapper pull the underlying during a supply.
                let underlying = VAULT.stata_underlying.read(c).stale(c);
                Contract::<Erc20>::from_address(c, underlying)
            },
            (
                |c: &mut Circuit3| cell_address(c, &VAULT.stata_token),
                |c: &mut Circuit3| unlimited_allowance_word(c),
            ),
            Envelope::fixed(),
            evm_nonce,
            Signing::contract,
        );
        Discloses::of(())
    }

    // ---- supply / completeSupply / refundSupply ----------------------------------------------

    /// `supply(evmNonce, keyVersion, amount, coin)`: burn the surrendered USDC
    /// vault coin and file `stataToken.deposit(amount, vaultEvmAddress)`,
    /// signed by the VAULT's account (exact-input, so no change).
    #[circuit]
    pub fn supply(
        c: &mut Circuit3,
        evm_nonce: Uint<64>,
        amount: Uint<128>,
        coin: ShieldedCoinArg,
    ) -> Discloses<(
        SurrenderedCoinNonce,
        SurrenderedCoinColor,
        SurrenderedCoinValue,
        SupplierRefundCommitment,
        SuppliedAmount,
        Requested,
    )> {
        let one = c.constant(1u64);
        c.region("guards", |c| {
            assert_initialized(c);
            c.assert(amount.gt(0u64).message("amount must be positive"));
            // refund_supply re-mints via the Uint<64> mint API.
            c.assert(amount.le(u64::MAX).message("amount exceeds Uint<64> max"));
        });

        let amount_field = amount.field();
        let stata_underlying = VAULT.stata_underlying.read(c).stale(c);
        burn_vault_coin(c, one, stata_underlying.field(), amount_field, coin);

        // deposit(amount, vaultEvmAddress) on the wrapper.
        VAULT.supplies.request_with(
            c,
            |c| {
                let stata = VAULT.stata_token.read(c).stale(c);
                Contract::<Erc4626>::from_address(c, stata)
            },
            (
                |_c: &mut Circuit3| amount,
                |c: &mut Circuit3| cell_address(c, &VAULT.vault_evm_address),
            ),
            Envelope::fixed(),
            evm_nonce,
            |c| {
                let sk = common::witness_sk(c);
                let amount = amount_field.disclose_as::<SuppliedAmount>(c);
                (Signing::contract(c), (sk, amount))
            },
            |c, id, (sk, amount)| Owned {
                owner: Commit::to::<SupplierRefundCommitment, _>(c, sk, id),
                inner: SupplyEnv {
                    amount: Uint::from_field_unchecked(*amount),
                },
            },
        );
        Discloses::of(())
    }

    /// `completeSupply(ticket, mintNonce)`: the supply EXECUTED; mint the
    /// attested shares as shielded stataToken to the supplier (fresh witness
    /// against the commitment).
    #[circuit]
    pub fn complete_supply(
        c: &mut Circuit3,
        ticket: Succeeded<Supply>,
        mint_nonce: CoinNonce<Private>,
    ) -> Discloses<(Settled, SupplyRecipient, SupplyMintNonce, AttestedShares)> {
        assert_initialized(c);
        let outcome = VAULT.supplies.complete(c, ticket);
        // Still the supplier's — the shares are minted to `own_public_key`.
        let sk = common::witness_sk(c);
        outcome
            .env
            .owner
            .open(c, &sk, outcome.request_id, "Not the supplier");

        let recipient = own_public_key(c).disclose_as::<SupplyRecipient>(c);
        let mint_nonce = mint_nonce.disclose_as::<SupplyMintNonce>(c);
        let shares = outcome.output.disclose_as::<AttestedShares>(c);
        let stata_token = VAULT.stata_token.read(c).stale(c);
        let domain_sep = vault_token_domain_separator(c, stata_token.field());
        common::mint_shielded_token_to_key(c, &domain_sep, shares, &mint_nonce, &recipient);
        Discloses::of(())
    }

    /// `refundSupply(ticket, mintNonce)`: the supply DID NOT SUCCEED (for an
    /// ERC-4626 `deposit`, the MPC's failure kind — the attested share count
    /// IS the outcome); re-mint the surrendered USDC amount to the supplier.
    #[circuit]
    pub fn refund_supply(
        c: &mut Circuit3,
        ticket: Failed<Supply>,
        mint_nonce: CoinNonce<Private>,
    ) -> Discloses<(Settled, RefundRecipient, RefundMintNonce)> {
        assert_initialized(c);
        let (own_pk, env, _shares) = VAULT.supplies.refund_to_owner::<RefundRecipient>(c, ticket);
        let mint_nonce = mint_nonce.disclose_as::<RefundMintNonce>(c);
        let stata_underlying = VAULT.stata_underlying.read(c).stale(c);
        let domain_sep = vault_token_domain_separator(c, stata_underlying.field());
        common::mint_shielded_token_to_key(c, &domain_sep, env.amount, &mint_nonce, &own_pk);
        Discloses::of(())
    }

    // ---- redeem / completeRedeem / refundRedeem ----------------------------------------------

    /// `redeem(evmNonce, keyVersion, shares, coin)`: burn the surrendered
    /// stataToken vault coin and file `stataToken.redeem(shares,
    /// vaultEvmAddress, vaultEvmAddress)`, signed by the VAULT's account.
    ///
    /// CAUTION (upstream's): the bound is on `shares`, not the assets that come
    /// back — Aave's exchange rate only grows, and `complete_redeem` mints
    /// assets through the same `Uint<64>` API after the coin is already burned.
    #[circuit]
    pub fn redeem(
        c: &mut Circuit3,
        evm_nonce: Uint<64>,
        shares: Uint<128>,
        coin: ShieldedCoinArg,
    ) -> Discloses<(
        SurrenderedCoinNonce,
        SurrenderedCoinColor,
        SurrenderedCoinValue,
        RedeemerRefundCommitment,
        RedeemedShares,
        Requested,
    )> {
        let one = c.constant(1u64);
        c.region("guards", |c| {
            assert_initialized(c);
            c.assert(shares.gt(0u64).message("shares must be positive"));
            c.assert(shares.le(u64::MAX).message("shares exceeds Uint<64> max"));
        });

        let shares_field = shares.field();
        // The wrapper token gates both the burn and `to`: one read, reused (this
        // lineage is not PI-pinned to compactc, which reads it twice).
        let stata_token = VAULT.stata_token.read(c).stale(c);
        burn_vault_coin(c, one, stata_token.field(), shares_field, coin);

        // redeem(shares, vaultEvmAddress, vaultEvmAddress) — the cell is read
        // once and the wire reused for both words, so the second `address`
        // builder hands back what the first one read.
        let vault_evm: Cell<Option<Bytes<20, Private>>> = Cell::new(None);
        VAULT.redeems.request_with(
            c,
            |_c| Contract::<Erc4626>::from_address(_c, stata_token),
            (
                |_c: &mut Circuit3| shares,
                |c: &mut Circuit3| {
                    let read = cell_address(c, &VAULT.vault_evm_address);
                    vault_evm.set(Some(read));
                    read
                },
                |_c: &mut Circuit3| {
                    vault_evm
                        .get()
                        .expect("the second address builder runs after the first")
                },
            ),
            // The struct-literal spelling; the one is the circuit's own (it
            // guarded the coin burn), the zero is named by the builder.
            Envelope::fixed().literal(None, one.private()),
            evm_nonce,
            |c| {
                let sk = common::witness_sk(c);
                let shares = shares_field.disclose_as::<RedeemedShares>(c);
                (Signing::contract(c), (sk, shares))
            },
            |c, id, (sk, shares)| Owned {
                owner: Commit::to::<RedeemerRefundCommitment, _>(c, sk, id),
                inner: RedeemEnv {
                    shares: Uint::from_field_unchecked(*shares),
                },
            },
        );
        Discloses::of(())
    }

    /// `completeRedeem(ticket, mintNonce)`: the redeem EXECUTED; mint the
    /// attested assets as shielded stataUnderlying to the redeemer (fresh
    /// witness against the commitment).
    #[circuit]
    pub fn complete_redeem(
        c: &mut Circuit3,
        ticket: Succeeded<Redeem>,
        mint_nonce: CoinNonce<Private>,
    ) -> Discloses<(Settled, RedeemRecipient, RedeemMintNonce, AttestedAssets)> {
        assert_initialized(c);
        let outcome = VAULT.redeems.complete(c, ticket);
        // Still the redeemer's — the assets are minted to `own_public_key`.
        let sk = common::witness_sk(c);
        outcome
            .env
            .owner
            .open(c, &sk, outcome.request_id, "Not the redeemer");

        let recipient = own_public_key(c).disclose_as::<RedeemRecipient>(c);
        let mint_nonce = mint_nonce.disclose_as::<RedeemMintNonce>(c);
        let assets = outcome.output.disclose_as::<AttestedAssets>(c);
        let stata_underlying = VAULT.stata_underlying.read(c).stale(c);
        let domain_sep = vault_token_domain_separator(c, stata_underlying.field());
        common::mint_shielded_token_to_key(c, &domain_sep, assets, &mint_nonce, &recipient);
        Discloses::of(())
    }

    /// `refundRedeem(ticket, mintNonce)`: the redeem DID NOT SUCCEED (for an
    /// ERC-4626 `redeem`, the MPC's failure kind); re-mint the surrendered
    /// stataToken shares to the redeemer.
    #[circuit]
    pub fn refund_redeem(
        c: &mut Circuit3,
        ticket: Failed<Redeem>,
        mint_nonce: CoinNonce<Private>,
    ) -> Discloses<(Settled, RefundRecipient, RefundMintNonce)> {
        assert_initialized(c);
        let (own_pk, env, _assets) = VAULT.redeems.refund_to_owner::<RefundRecipient>(c, ticket);
        let mint_nonce = mint_nonce.disclose_as::<RefundMintNonce>(c);
        let stata_token = VAULT.stata_token.read(c).stale(c);
        let domain_sep = vault_token_domain_separator(c, stata_token.field());
        common::mint_shielded_token_to_key(c, &domain_sep, env.shares, &mint_nonce, &own_pk);
        Discloses::of(())
    }
}

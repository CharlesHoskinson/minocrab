//! `erc20-vault` (signet-midnight-examples `375071b`, main at 2026-10-07) —
//! THE benchmark target, on the FLUSH PATTERN and the Signet V1 vocabulary
//! (M44). Ported circuit by circuit, instruction order following the Compact
//! source; each port carries a differential test against compactc's artifact
//! (`tests/erc20_vault_differential.rs`).
//!
//! TWENTY-NINE CIRCUITS. Admin without EVM transactions: `initialise`,
//! `setGasParams`, `addAllowedToken`. The request queue every action shares:
//! `flushQueue` and the three `queueAttestation{0,1,32}`. Then seven actions,
//! each a START (queue the request under a caller-chosen index), a SEND
//! (record the flushed request's Signet event and notify the MPC) and a
//! COMPLETE (consume the flushed attestation and settle): nonce replacement
//! (`startReplaceNonce` / `sendReplaceNonce` / `completeReplaceNonce`),
//! approvals (`startApproveRouter` + `startApproveStata` / `sendApprove` /
//! `completeApprove`), deposit, withdraw, swap, supply and redeem.
//!
//! WHAT CHANGED FROM THE SEVENTEEN-CIRCUIT VAULT (notes/vault-flush.org):
//! the six steps of every action are start → flush → send → queue the
//! attestation → flush → complete, so a user circuit writes only entries
//! keyed by its own request and reads configuration only the deployer
//! changes, and `flushQueue` is the ONE circuit that touches the two
//! contended cells (`globalLastSeen`, `vaultAccountNonce`). Requests are
//! identified three ways along the way: the caller's `inIndex` (a
//! `Uint<64>`), the flush's `requestIndex` (Poseidon over the nonce and the
//! args hash) and the Signet request id (the V1 preimage hash). Every settle
//! is bound to the attested block height, strictly above the `globalLastSeen`
//! the flush pinned into the request; the MPC's verdict ([`OutputKind`]) picks
//! the completion's arms, so there are no `refund*` circuits. Gas is the
//! vault's setting at start (`vaultGasLimits`, the two fee cells) and travels
//! in the args; the request nonce and the caip2 cell are gone (the
//! executionDest is the constant `ethereumCaip2Id()`); `initialised` is a
//! `Boolean`; `allowedTokens` gates what a deposit may bring in and a swap
//! may buy.
//!
//! The ledger block is 35 fields, which compactc SEGMENTS three ways (five at
//! `[0, i]`, fifteen at `[1, i − 5]`, fifteen at `[2, i − 20]`) —
//! `#[derive(Ledger)]` computes the same paths, and every notification's
//! depth and path bytes are read off the map handle.
//!
//! The Compact ledger block, in declaration order (the field index):
//! ```text
//! sealed ledger signetSigner: SignetSigner;                        // 0  [0,0]
//! export ledger mpcResponseKey: Secp256k1Point;                    // 1  [0,1]
//! export ledger vaultMaxFeePerGas: Uint<128>;                      // 2  [0,2]
//! export ledger vaultMaxPriorityFeePerGas: Uint<128>;              // 3  [0,3]
//! export ledger vaultGasLimits: VaultGasLimits;                    // 4  [0,4]
//! export ledger initialised: Boolean;                              // 5  [1,0]
//! export ledger vaultEvmAddress: Bytes<20>;                        // 6  [1,1]
//! export ledger evmChainId: Uint<64>;                              // 7  [1,2]
//! export ledger mpcKeyVersion: Uint<8>;                            // 8  [1,3]
//! sealed ledger deployer: Bytes<32>;                               // 9  [1,4]
//! export ledger uniswapRouter: Bytes<20>;                          // 10 [1,5]
//! export ledger stataUnderlying: Bytes<20>;                        // 11 [1,6]
//! export ledger stataToken: Bytes<20>;                             // 12 [1,7]
//! export ledger allowedTokens: Set<Bytes<20>>;                     // 13 [1,8]
//! export ledger globalLastSeen: Uint<64>;                          // 14 [1,9]
//! export ledger vaultAccountNonce: Uint<64>;                       // 15 [1,10]
//! export ledger inputRequestBuffer: Map<Uint<64>, RequestBufferEntry>;      // 16 [1,11]
//! export ledger outputRequestBuffer: Map<Bytes<32>, OutputRequestEntry>;    // 17 [1,12]
//! export ledger inputAttestationBuffer: Map<RequestId, AttestationRecord>;  // 18 [1,13]
//! export ledger outputAttestationBuffer: Map<RequestId, AttestationRecord>; // 19 [1,14]
//! export ledger evictionMap: Map<RequestId, Bytes<32>>;            // 20 [2,0]
//! export ledger bidirectionalReplaceNonceMap: …<EvmType2TxParams<2,0,0>, 2>;  // 21 [2,1]
//! export ledger replaceNonceArgsMap: Map<Uint<64>, ReplaceNonceArgs>;        // 22 [2,2]
//! export ledger bidirectionalApproveMap: …<EvmType2TxParams<2,0,0>, 34>;      // 23 [2,3]
//! export ledger approveArgsMap: Map<Uint<64>, ApproveArgs>;                  // 24 [2,4]
//! export ledger bidirectionalDepositMap: …<EvmType2TxParams<2,0,0>, 34>;      // 25 [2,5]
//! export ledger depositArgsMap: Map<Uint<64>, DepositArgs>;                  // 26 [2,6]
//! export ledger bidirectionalWithdrawMap: …<EvmType2TxParams<2,0,0>, 34>;     // 27 [2,7]
//! export ledger withdrawArgsMap: Map<Uint<64>, WithdrawArgs>;                // 28 [2,8]
//! export ledger bidirectionalSwapMap: …<EvmType2TxParams<7,0,0>, 38>;         // 29 [2,9]
//! export ledger swapArgsMap: Map<Uint<64>, SwapArgs>;                        // 30 [2,10]
//! export ledger bidirectionalSupplyMap: …<EvmType2TxParams<2,0,0>, 36>;       // 31 [2,11]
//! export ledger supplyArgsMap: Map<Uint<64>, SupplyArgs>;                    // 32 [2,12]
//! export ledger bidirectionalRedeemMap: …<EvmType2TxParams<3,0,0>, 36>;       // 33 [2,13]
//! export ledger redeemArgsMap: Map<Uint<64>, RedeemArgs>;                    // 34 [2,14]
//! ```

use minocrab::v3::{Circuit3, FieldT, Wire3};
use minocrab::{Private, Public};
use minocrab_ledger::{XcallCommitment, XcallEntryPointHash};
use minocrab_std::v3::hash::upgrade_from_transient;
use minocrab_std::v3::kernel;
use minocrab_std::v3::{
    b32_newtype, contract, eq, is_true, label, not, own_public_key, Bool, BoundedUint, Bytes,
    Bytes0, BytesN, Check, CircuitArg, CoinColor, CoinNonce, CoinRecipient, Disclose, Discloses,
    Either, Ledger, LedgerCell, LedgerField, LedgerMap, LedgerRepr, LedgerSet, Maybe,
    Secp256k1Point, TokenDomainSeparator, Uint, Vis3, B32,
};

use signet_signer_interface::notification::construct_notification_v1;
use signet_signer_interface::{RespondBidirectionalEvent, SignetSigner};

use crate::common::{self, SigningPath, UserCommitment};
use crate::signet_v1::{self, output_kind, EventRecordV1, SchemaBytes};

pub use crate::signet_v1::RequestId;

// ---- disclosure labels ---------------------------------------------------------------

// What each circuit discloses, one zero-sized type per logical value; a
// circuit's `Discloses<(…)>` names exactly the set it makes public, and the
// generated test beside each circuit fails on any other disclosure.
label! {
    VaultEvmAddress = "the vault's derived EVM address";
    UniswapRouter = "the Uniswap router address";
    StataUnderlying = "the Aave underlying ERC20 (USDC)";
    StataToken = "the Aave stata wrapper (ERC-4626)";
    EvmChainId = "the EVM chain id";
    MpcResponseKey = "the MPC response key";
    MpcKeyVersion = "the MPC root-key version";
    EvmHeight = "the EVM height initialise pins as globalLastSeen";
    MaxFeePerGas = "the vault account's maxFeePerGas";
    MaxPriorityFeePerGas = "the vault account's maxPriorityFeePerGas";
    GasLimits = "the per-action gas limits";
    AllowedErc20 = "an ERC20 admitted to the vault";
    InIndex = "the caller-chosen request index";
    OutIndex = "the flushed request's index";
    EvmNonce = "the caller's EVM account nonce";
    GasParams = "the request's EIP-1559 fee envelope";
    OwnershipCommitment = "the request's ownership commitment";
    ArgsHash = "the request's args hash";
    DepositorCommitment = "depositor identity commitment";
    DepositedErc20 = "the deposited ERC20";
    DepositedAmount = "the deposited amount";
    WithdrawnErc20 = "the withdrawn ERC20";
    WithdrawnAmount = "the withdrawn amount";
    WithdrawDestination = "the withdrawal's destination EVM address";
    SoldErc20 = "the sold ERC20";
    BoughtErc20 = "the bought ERC20";
    SwapFee = "the Uniswap pool fee tier";
    SwapAmountOut = "the swap's amountOut";
    SwapAmountInMaximum = "the swap's amountInMaximum";
    SuppliedAmount = "the supplied amount";
    RedeemedShares = "the redeemed shares";
    ReplacedRequestId = "the request whose nonce is replaced";
    ReplacedAction = "the replaced request's action";
    SurrenderedCoinNonce = "surrendered coin nonce";
    SurrenderedCoinColor = "surrendered coin color";
    SurrenderedCoinValue = "surrendered coin value";
    FlushSlotChannel = "a flush slot's channel";
    FlushSlotInIndex = "a flush slot's request index";
    FlushSlotRequestId = "a flush slot's request id";
    Attestation = "the MPC's attestation (id, height, verdict, width, digest, signature)";
    SerializedOutput = "the attested serialised output";
    RequestIdDisclosed = "request id";
    RequestRecord = "request record";
    SettleRequestId = "settle request id";
    MintNonce = "mint nonce";
    ChangeNonce = "swap change nonce";
    Recipient = "own public key as mint recipient";
    ClaimRecipientTag = "claim recipient tag";
    ClaimRecipientSide = "claim recipient side";
    ClaimRecipientOwnKey = "own public key as claim recipient";
    ClaimRecipientKey = "claim recipient key";
    ClaimRecipientContract = "claim recipient contract";
}

// ---- constants -----------------------------------------------------------------------

/// The domain-separation prefix of `userCommitment`.
pub const USER_PAD: &str = "vault:user:";
/// The domain-separation prefix of `vaultTokenDomainSeparator`.
pub const TOKEN_PAD: &str = "erc20:vault:";
/// The domain-separation suffix of `ownershipCommitment`.
pub const REQUEST_PAD: &str = "vault:request:";
/// The domain-separation prefix of `requestIndex`.
pub const REQUEST_INDEX_PAD: &str = "vault:request:index";
/// The args-hash tags, one per action; no two alike, since the tag stands
/// in for the action in `requestIndex`.
pub const REPLACE_NONCE_ARGS_PAD: &str = "vault:replaceNonce:args";
pub const APPROVE_ARGS_PAD: &str = "vault:approve:args";
pub const DEPOSIT_ARGS_PAD: &str = "vault:deposit:args";
pub const WITHDRAW_ARGS_PAD: &str = "vault:withdraw:args";
pub const SWAP_ARGS_PAD: &str = "vault:swap:args";
pub const SUPPLY_ARGS_PAD: &str = "vault:supply:args";
pub const REDEEM_ARGS_PAD: &str = "vault:redeem:args";
/// The vault's own signing path, `pad(32, "vault")`.
pub const VAULT_PATH: &str = "vault";

/// `vaultOutputSchema()` — the ERC20 transfer/approve bool return.
pub const VAULT_OUTPUT_SCHEMA: &[u8] = b"[{\"name\":\"success\",\"type\":\"bool\"}]";
/// `replaceNonceOutputSchema()` — a plain transfer returns nothing.
pub const REPLACE_NONCE_OUTPUT_SCHEMA: &[u8] = b"[]";
/// `swapOutputSchema()`.
pub const SWAP_OUTPUT_SCHEMA: &[u8] = b"[{\"name\":\"amountIn\",\"type\":\"uint256\"}]";
/// `supplyOutputSchema()`.
pub const SUPPLY_OUTPUT_SCHEMA: &[u8] = b"[{\"name\":\"shares\",\"type\":\"uint256\"}]";
/// `redeemOutputSchema()`.
pub const REDEEM_OUTPUT_SCHEMA: &[u8] = b"[{\"name\":\"assets\",\"type\":\"uint256\"}]";

pub const VAULT_SCHEMA_LEN: usize = VAULT_OUTPUT_SCHEMA.len();
pub const REPLACE_NONCE_SCHEMA_LEN: usize = REPLACE_NONCE_OUTPUT_SCHEMA.len();
pub const SWAP_SCHEMA_LEN: usize = SWAP_OUTPUT_SCHEMA.len();
pub const SUPPLY_SCHEMA_LEN: usize = SUPPLY_OUTPUT_SCHEMA.len();
pub const REDEEM_SCHEMA_LEN: usize = REDEEM_OUTPUT_SCHEMA.len();

/// `transfer(address,uint256)`.
pub const TRANSFER_SELECTOR: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];
/// `approve(address,uint256)`.
pub const APPROVE_SELECTOR: [u8; 4] = [0x09, 0x5e, 0xa7, 0xb3];
/// `exactOutputSingle((address,address,uint24,address,uint256,uint256,uint160))`.
pub const EXACT_OUTPUT_SINGLE_SELECTOR: [u8; 4] = [0x50, 0x23, 0xb4, 0xdf];
/// ERC-4626 `deposit(uint256,address)`.
pub const DEPOSIT_SELECTOR: [u8; 4] = [0x6e, 0x55, 0x3f, 0x65];
/// ERC-4626 `redeem(uint256,address,address)`.
pub const REDEEM_SELECTOR: [u8; 4] = [0xba, 0x08, 0x76, 0x52];

/// Calldata word counts per action.
pub const VAULT_WORDS: usize = 2;
pub const SWAP_WORDS: usize = 7;
pub const SUPPLY_WORDS: usize = 2;
pub const REDEEM_WORDS: usize = 3;

/// `initialise()`'s fee envelope and gas limits.
pub const DEFAULT_MAX_FEE_PER_GAS: u128 = 150_000_000_000;
pub const DEFAULT_MAX_PRIORITY_FEE_PER_GAS: u128 = 1_000_000_000;
pub const DEFAULT_WITHDRAW_GAS: u64 = 100_000;
pub const DEFAULT_APPROVE_GAS: u64 = 100_000;
pub const DEFAULT_SWAP_GAS: u64 = 700_000;
pub const DEFAULT_SUPPLY_GAS: u64 = 500_000;
pub const DEFAULT_REDEEM_GAS: u64 = 500_000;
/// The gas a plain transfer costs: a nonce replacement's limit.
pub const REPLACE_NONCE_GAS: u64 = 21_000;

/// `enum Action { deposit, withdraw, swap, supply, redeem, approve, replaceNonce }`.
pub mod action {
    pub const DEPOSIT: u64 = 0;
    pub const WITHDRAW: u64 = 1;
    pub const SWAP: u64 = 2;
    pub const SUPPLY: u64 = 3;
    pub const REDEEM: u64 = 4;
    pub const APPROVE: u64 = 5;
    pub const REPLACE_NONCE: u64 = 6;
    pub const COUNT: u128 = 7;
}

/// `enum FlushChannel { empty, request, attestation }`.
pub mod flush_channel {
    pub const EMPTY: u64 = 0;
    pub const REQUEST: u64 = 1;
    pub const ATTESTATION: u64 = 2;
    pub const COUNT: u128 = 3;
}

/// `flushQueue(slots: Vector<10, FlushSlot>)`.
pub const FLUSH_SLOTS: usize = 10;

/// `unlimitedAllowance()` — 2^128 − 1.
pub const UNLIMITED_ALLOWANCE: u128 = u128::MAX;

// ---- the record types -----------------------------------------------------------------

pub type Action<V> = BoundedUint<{ action::COUNT }, V>;
pub type FlushChannel<V> = BoundedUint<{ flush_channel::COUNT }, V>;
pub type OutputKind<V> = signet_v1::OutputKind<V>;

/// `SignBidirectionalEventV1<EvmType2TxParams<2, 0, 0>, 34, 0>` as the ledger holds it.
pub type VaultRecord = EventRecordV1<VAULT_WORDS, BytesN<Public, VAULT_SCHEMA_LEN>>;
pub type ReplaceNonceRecord = EventRecordV1<VAULT_WORDS, Bytes<REPLACE_NONCE_SCHEMA_LEN, Public>>;
pub type SwapRecord = EventRecordV1<SWAP_WORDS, BytesN<Public, SWAP_SCHEMA_LEN>>;
pub type SupplyRecord = EventRecordV1<SUPPLY_WORDS, BytesN<Public, SUPPLY_SCHEMA_LEN>>;
pub type RedeemRecord = EventRecordV1<REDEEM_WORDS, BytesN<Public, REDEEM_SCHEMA_LEN>>;

/// The in-circuit (private) event each record is the disclosure of.
pub type VaultEvent = signet_v1::SignBidirectionalEventV1<Private, VAULT_WORDS, BytesN<Private, VAULT_SCHEMA_LEN>>;
pub type ReplaceNonceEvent =
    signet_v1::SignBidirectionalEventV1<Private, VAULT_WORDS, Bytes<REPLACE_NONCE_SCHEMA_LEN, Private>>;
pub type SwapEvent = signet_v1::SignBidirectionalEventV1<Private, SWAP_WORDS, BytesN<Private, SWAP_SCHEMA_LEN>>;
pub type SupplyEvent = signet_v1::SignBidirectionalEventV1<Private, SUPPLY_WORDS, BytesN<Private, SUPPLY_SCHEMA_LEN>>;
pub type RedeemEvent = signet_v1::SignBidirectionalEventV1<Private, REDEEM_WORDS, BytesN<Private, REDEEM_SCHEMA_LEN>>;

pub use crate::common::secp256k1_point_atoms;

b32_newtype! {
    /// `ownershipCommitment(inIndex, sk)` — pinned into every buffered
    /// request, proven at complete. Deliberately NOT a [`UserCommitment`]:
    /// reuse would link a request's ownership to its depositor identity.
    RequestOwnership,
    /// `requestIndex(entry)` — the `outputRequestBuffer` key: Poseidon over
    /// the nonce and the args hash, which together fix the EVM transaction.
    RequestIndex,
    /// An action's args hash: `transientHash([tag, args])`, upgraded. The
    /// tag stands in for the action.
    ArgsDigest,
}

// ---- the ledger value types ----------------------------------------------------------

/// `struct VaultGasLimits { withdraw, approve, swap, supply, redeem: Uint<64> }`.
#[derive(Clone, LedgerRepr)]
pub struct VaultGasLimits {
    pub withdraw: Uint<64, Public>,
    pub approve: Uint<64, Public>,
    pub swap: Uint<64, Public>,
    pub supply: Uint<64, Public>,
    pub redeem: Uint<64, Public>,
}

/// `struct GasParams { gasLimit: Uint<64>; maxFeePerGas: Uint<128>;
/// maxPriorityFeePerGas: Uint<128> }` as stored in an action's args.
#[derive(Clone, LedgerRepr)]
pub struct StoredGas {
    pub gas_limit: Uint<64, Public>,
    pub max_fee_per_gas: Uint<128, Public>,
    pub max_priority_fee_per_gas: Uint<128, Public>,
}

/// `struct RequestBufferEntry` — everything the flush needs of a request,
/// at one size for every action.
#[derive(Clone, LedgerRepr)]
pub struct RequestBufferEntry {
    pub action: Action<Public>,
    pub use_next_vault_account_nonce: Bool<Public>,
    pub evm_nonce: Uint<64, Public>,
    pub in_index: Uint<64, Public>,
    pub commitment: RequestOwnership<Public>,
    pub args_hash: ArgsDigest<Public>,
}

/// `struct OutputRequestEntry { entry; lastSeen: Uint<64> }`.
#[derive(Clone, LedgerRepr)]
pub struct OutputRequestEntry {
    pub entry: RequestBufferEntry,
    pub last_seen: Uint<64, Public>,
}

/// `struct AttestationRecord { blockHeight; outputKind; digest }` — a
/// verified attestation under its request id, holding no output.
#[derive(Clone, LedgerRepr)]
pub struct AttestationRecord {
    pub block_height: Uint<64, Public>,
    pub output_kind: OutputKind<Public>,
    pub digest: B32<Public>,
}

/// `struct ReplaceNonceArgs { gas }`.
#[derive(Clone, LedgerRepr)]
pub struct ReplaceNonceArgs {
    pub gas: StoredGas,
}

/// `struct ApproveRequest { erc20Address; spender }`.
#[derive(Clone, LedgerRepr)]
pub struct StoredApproveRequest {
    pub erc20_address: Bytes<20, Public>,
    pub spender: Bytes<20, Public>,
}

/// `struct ApproveArgs { request; gas }`.
#[derive(Clone, LedgerRepr)]
pub struct ApproveArgs {
    pub request: StoredApproveRequest,
    pub gas: StoredGas,
}

/// `struct DepositRequest { erc20Address; amount }` as stored.
#[derive(Clone, LedgerRepr)]
pub struct StoredDepositRequest {
    pub erc20_address: Bytes<20, Public>,
    pub amount: Uint<128, Public>,
}

/// `struct DepositArgs { request; path; gas }` — `path` is the depositor's
/// `userCommitment`, the MPC derivation path of the signing account.
#[derive(Clone, LedgerRepr)]
pub struct DepositArgs {
    pub request: StoredDepositRequest,
    pub path: UserCommitment<Public>,
    pub gas: StoredGas,
}

/// `struct WithdrawRequest { erc20Address; amount; destEvmAddress }` as stored.
#[derive(Clone, LedgerRepr)]
pub struct StoredWithdrawRequest {
    pub erc20_address: Bytes<20, Public>,
    pub amount: Uint<128, Public>,
    pub dest_evm_address: Bytes<20, Public>,
}

/// `struct WithdrawArgs { request; gas }`.
#[derive(Clone, LedgerRepr)]
pub struct WithdrawArgs {
    pub request: StoredWithdrawRequest,
    pub gas: StoredGas,
}

/// `struct SwapRequest { erc20AddressIn; erc20AddressOut; fee; amountOut;
/// amountInMaximum }` as stored.
#[derive(Clone, LedgerRepr)]
pub struct StoredSwapRequest {
    pub erc20_address_in: Bytes<20, Public>,
    pub erc20_address_out: Bytes<20, Public>,
    pub fee: Uint<128, Public>,
    pub amount_out: Uint<128, Public>,
    pub amount_in_maximum: Uint<128, Public>,
}

/// `struct SwapArgs { request; gas }`.
#[derive(Clone, LedgerRepr)]
pub struct SwapArgs {
    pub request: StoredSwapRequest,
    pub gas: StoredGas,
}

/// `struct SupplyRequest { amount }` as stored.
#[derive(Clone, LedgerRepr)]
pub struct StoredSupplyRequest {
    pub amount: Uint<128, Public>,
}

/// `struct SupplyArgs { request; gas }`.
#[derive(Clone, LedgerRepr)]
pub struct SupplyArgs {
    pub request: StoredSupplyRequest,
    pub gas: StoredGas,
}

/// `struct RedeemRequest { shares }` as stored.
#[derive(Clone, LedgerRepr)]
pub struct StoredRedeemRequest {
    pub shares: Uint<128, Public>,
}

/// `struct RedeemArgs { request; gas }`.
#[derive(Clone, LedgerRepr)]
pub struct RedeemArgs {
    pub request: StoredRedeemRequest,
    pub gas: StoredGas,
}

// ---- the ledger block ------------------------------------------------------------------

/// THE LEDGER BLOCK — the Compact `ledger` declarations in the module doc,
/// as types. Declaration order IS the field index and `#[derive(Ledger)]`
/// computes each field's segmented path from it.
#[derive(Ledger)]
pub struct Vault {
    /// `sealed ledger signetSigner: SignetSigner` — a handle read through the
    /// interface crate's own `SignetSigner::at_field_path`.
    pub signet_signer: LedgerField,
    pub mpc_response_key: LedgerCell<Secp256k1Point<Public>>,
    pub vault_max_fee_per_gas: LedgerCell<Uint<128, Public>>,
    pub vault_max_priority_fee_per_gas: LedgerCell<Uint<128, Public>>,
    pub vault_gas_limits: LedgerCell<VaultGasLimits>,
    pub initialised: LedgerCell<Bool<Public>>,
    pub vault_evm_address: LedgerCell<Bytes<20, Public>>,
    pub evm_chain_id: LedgerCell<Uint<64, Public>>,
    pub mpc_key_version: LedgerCell<Uint<8, Public>>,
    /// `sealed ledger deployer: Bytes<32>` — write-once at deployment; the
    /// read is an ordinary cell read.
    pub deployer: LedgerCell<UserCommitment<Public>>,
    pub uniswap_router: LedgerCell<Bytes<20, Public>>,
    pub stata_underlying: LedgerCell<Bytes<20, Public>>,
    pub stata_token: LedgerCell<Bytes<20, Public>>,
    pub allowed_tokens: LedgerSet<Bytes<20, Public>>,
    pub global_last_seen: LedgerCell<Uint<64, Public>>,
    pub vault_account_nonce: LedgerCell<Uint<64, Public>>,
    pub input_request_buffer: LedgerMap<Uint<64, Public>, RequestBufferEntry>,
    pub output_request_buffer: LedgerMap<RequestIndex<Public>, OutputRequestEntry>,
    pub input_attestation_buffer: LedgerMap<RequestId<Public>, AttestationRecord>,
    pub output_attestation_buffer: LedgerMap<RequestId<Public>, AttestationRecord>,
    pub eviction_map: LedgerMap<RequestId<Public>, RequestIndex<Public>>,
    pub bidirectional_replace_nonce_map: LedgerMap<RequestId<Public>, ReplaceNonceRecord>,
    pub replace_nonce_args_map: LedgerMap<Uint<64, Public>, ReplaceNonceArgs>,
    pub bidirectional_approve_map: LedgerMap<RequestId<Public>, VaultRecord>,
    pub approve_args_map: LedgerMap<Uint<64, Public>, ApproveArgs>,
    pub bidirectional_deposit_map: LedgerMap<RequestId<Public>, VaultRecord>,
    pub deposit_args_map: LedgerMap<Uint<64, Public>, DepositArgs>,
    pub bidirectional_withdraw_map: LedgerMap<RequestId<Public>, VaultRecord>,
    pub withdraw_args_map: LedgerMap<Uint<64, Public>, WithdrawArgs>,
    pub bidirectional_swap_map: LedgerMap<RequestId<Public>, SwapRecord>,
    pub swap_args_map: LedgerMap<Uint<64, Public>, SwapArgs>,
    pub bidirectional_supply_map: LedgerMap<RequestId<Public>, SupplyRecord>,
    pub supply_args_map: LedgerMap<Uint<64, Public>, SupplyArgs>,
    pub bidirectional_redeem_map: LedgerMap<RequestId<Public>, RedeemRecord>,
    pub redeem_args_map: LedgerMap<Uint<64, Public>, RedeemArgs>,
}

/// The vault's ledger block. A `const`: the whole thing is field paths, so
/// it exists at compile time and costs nothing at run time.
pub const VAULT: Vault = Vault::new();

// ---- shared pieces -----------------------------------------------------------------------

/// `requireInitialised()` — `assert(initialised, "Not initialised")`.
fn require_initialised(c: &mut Circuit3) {
    let init = VAULT.initialised.read(c);
    c.assert(is_true(init).message("Not initialised"));
}

fn b32_eq<V: Vis3>(a: &B32<V>, b: &B32<V>) -> Check<V> {
    eq(a.hi, b.hi).and(eq(a.lo, b.lo))
}

/// `assert(userCommitment(callerSecretKey()) == deployer, "Not the deployer")`
/// — the witness, the hash, then the `deployer` read where the source names it.
fn assert_deployer(c: &mut Circuit3) {
    c.region("deployer gate", |c| {
        let sk = common::witness_sk(c);
        let mine = user_commitment(c, &sk);
        let stored = VAULT.deployer.read(c);
        c.assert(b32_eq(&mine.bytes(), &stored.private().bytes()).message("Not the deployer"));
    });
}

/// `userCommitment(sk)` — `upgradeFromTransient(transientHash([sk, pad(32,
/// "vault:user:")]))`: the identity commitment, the deployer's gate and the
/// MPC's key-derivation PATH of a deposit. The SECRET leads the pad since
/// `375071b` (the seventeen-circuit vault hashed the pad first), so this is
/// the vault's own and not `common::commitment_transient`.
fn user_commitment(c: &mut Circuit3, sk: &common::SecretKey<Private>) -> UserCommitment<Private> {
    let sk = sk.bytes();
    c.region("identity commitment (transientHash)", |c| {
        let pad = B32::pad(c, USER_PAD);
        let f = c.transient_hash(&[sk.hi, sk.lo, pad.hi.private(), pad.lo.private()]);
        UserCommitment(upgrade_from_transient(c, f))
    })
}

/// `vaultTokenDomainSeparator(erc20Address)` —
/// `upgradeFromTransient(transientHash([pad(32, "erc20:vault:"),
/// erc20Address as Field as Bytes<32>]))`; the address's `Bytes<32>`
/// rendering is `[hi: 0, lo: addr]`.
fn vault_token_domain_separator(c: &mut Circuit3, erc20_address: Wire3<FieldT, Public>) -> TokenDomainSeparator<Public> {
    c.region("token domain separator (transientHash)", |c| {
        let pad = B32::pad(c, TOKEN_PAD);
        let zero = c.constant(0u64);
        let f = c.transient_hash(&[pad.hi, pad.lo, zero, erc20_address]);
        TokenDomainSeparator(upgrade_from_transient(c, f))
    })
}

/// `ownershipCommitment(inIndex, sk)` — `upgradeFromTransient(transientHash([sk,
/// inIndex, pad(32, "vault:request:")]))`, over a FRESH witness.
fn ownership_commitment(c: &mut Circuit3, in_index: Wire3<FieldT, Private>) -> RequestOwnership<Private> {
    let sk = common::witness_sk(c).bytes();
    c.region("ownership commitment (transientHash)", |c| {
        let pad = B32::pad(c, REQUEST_PAD);
        let f = c.transient_hash(&[sk.hi, sk.lo, in_index, pad.hi.private(), pad.lo.private()]);
        RequestOwnership(upgrade_from_transient(c, f))
    })
}

/// `requestIndex(entry)` — `upgradeFromTransient(transientHash([pad(32,
/// "vault:request:index"), entry.evmNonce, entry.argsHash]))`.
fn request_index(c: &mut Circuit3, evm_nonce: Wire3<FieldT, Public>, args_hash: &ArgsDigest<Public>) -> RequestIndex<Public> {
    c.region("request index (transientHash)", |c| {
        let pad = B32::pad(c, REQUEST_INDEX_PAD);
        let ah = args_hash.bytes();
        let f = c.transient_hash(&[pad.hi, pad.lo, evm_nonce, ah.hi, ah.lo]);
        RequestIndex(upgrade_from_transient(c, f))
    })
}

/// `<action>ArgsHash(args)` — `upgradeFromTransient(transientHash([pad(32,
/// tag), args]))` over the args' field-aligned limbs (their ledger limbs).
fn args_hash<A: LedgerRepr>(c: &mut Circuit3, tag: &str, args: &A) -> ArgsDigest<Public> {
    c.region("args hash (transientHash)", |c| {
        let pad = B32::pad(c, tag);
        let mut limbs = vec![pad.hi, pad.lo];
        args.push_limbs(c, &mut limbs);
        let f = c.transient_hash(&limbs);
        ArgsDigest(upgrade_from_transient(c, f))
    })
}

/// `assert(!inputRequestBuffer.member(i) && !<args>Map.member(i), "Index
/// already in use")` — the `&&` short-circuits, so the second read is
/// guarded by the first being false, as compactc emits it.
fn assert_index_free<A: LedgerRepr>(c: &mut Circuit3, in_index: &Uint<64, Public>, args_map: &LedgerMap<Uint<64, Public>, A>) {
    c.region("index free", |c| {
        let queued = VAULT.input_request_buffer.member(c, in_index);
        let unqueued = c.not(queued.field());
        let in_args = c.when(unqueued, |c| args_map.member(c, in_index)).or_default();
        c.assert(not(is_true(queued)).and(not(is_true(in_args))).message("Index already in use"));
    });
}

/// `GasParams { gasLimit: vaultGasLimits.<action>, maxFeePerGas:
/// vaultMaxFeePerGas, maxPriorityFeePerGas: vaultMaxPriorityFeePerGas }` —
/// the vault's three gas reads, in the struct literal's order.
fn vault_gas(c: &mut Circuit3, pick: impl FnOnce(&VaultGasLimits) -> Uint<64, Public>) -> StoredGas {
    let limits = VAULT.vault_gas_limits.read(c).stale(c);
    let max_fee_per_gas = VAULT.vault_max_fee_per_gas.read(c).stale(c);
    let max_priority_fee_per_gas = VAULT.vault_max_priority_fee_per_gas.read(c).stale(c);
    StoredGas {
        gas_limit: pick(&limits),
        max_fee_per_gas,
        max_priority_fee_per_gas,
    }
}

/// `inputRequestBuffer.insert(disclosedIndex, disclose(RequestBufferEntry {
/// action, useNextVaultAccountNonce, evmNonce, inIndex, commitment:
/// ownershipCommitment(inIndex, callerSecretKey()), argsHash }))` — the
/// queueing every start ends with.
fn queue_request(
    c: &mut Circuit3,
    action: u64,
    use_next_vault_account_nonce: bool,
    evm_nonce: Wire3<FieldT, Public>,
    in_index: Uint<64, Public>,
    args_hash: ArgsDigest<Public>,
) {
    let commitment = ownership_commitment(c, in_index.field().private()).disclose_as::<OwnershipCommitment>(c);
    let action = Action::<Public>::from_field_unchecked(c.constant(action));
    let use_next = Bool::<Public>::from_field_unchecked(c.constant(u64::from(use_next_vault_account_nonce)));
    let entry = RequestBufferEntry {
        action,
        use_next_vault_account_nonce: use_next,
        evm_nonce: Uint::from_field_unchecked(evm_nonce),
        in_index,
        commitment,
        args_hash,
    };
    VAULT.input_request_buffer.insert(c, &in_index, &entry);
}

/// `EvmCalldata<WORDS> { selector, noWords: WORDS, words }`.
fn calldata<const WORDS: usize>(c: &mut Circuit3, selector: &[u8; 4], words: [B32<Private>; WORDS]) -> signet_v1::EvmCalldata<Private, WORDS> {
    let selector = c.constant(minocrab::Fr::from_le_bytes(selector).unwrap());
    let no_words = c.constant(WORDS as u64);
    signet_v1::EvmCalldata {
        selector: selector.private(),
        no_words: no_words.private(),
        words,
    }
}

/// `none<EvmCalldata<2>>()` — a zero tag, zero selector and count, zero words.
fn no_calldata<const WORDS: usize>(c: &mut Circuit3) -> signet_v1::EvmCalldata<Private, WORDS> {
    let zero = c.constant(0u64).private();
    signet_v1::EvmCalldata {
        selector: zero,
        no_words: zero,
        words: [B32 { hi: zero, lo: zero }; WORDS],
    }
}

/// `EvmType2TxParams<WORDS, 0, 0> { chainId: evmChainId, nonce: entry.evmNonce,
/// maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value: 0, calldata,
/// accessListEntryCount: 0, accessList: [] }` — the `evmChainId` read is
/// made HERE, first in the literal, before a `to` that is a cell read.
fn tx_params<const WORDS: usize>(
    c: &mut Circuit3,
    entry: &RequestBufferEntry,
    gas: &StoredGas,
    to: impl FnOnce(&mut Circuit3) -> Wire3<FieldT, Private>,
    calldata: signet_v1::EvmCalldata<Private, WORDS>,
    calldata_is_some: bool,
) -> signet_v1::EvmType2TxParams<Private, WORDS> {
    let chain_id = VAULT.evm_chain_id.read(c).stale(c);
    let to = to(c);
    let zero = c.constant(0u64).private();
    let is_some = c.constant(u64::from(calldata_is_some)).private();
    signet_v1::EvmType2TxParams {
        chain_id: chain_id.field().private(),
        nonce: entry.evm_nonce.field().private(),
        max_priority_fee_per_gas: gas.max_priority_fee_per_gas.field().private(),
        max_fee_per_gas: gas.max_fee_per_gas.field().private(),
        gas_limit: gas.gas_limit.field().private(),
        to,
        value: zero,
        calldata_is_some: is_some,
        calldata,
        access_list_entry_count: zero,
    }
}

/// `signetSigner.signBidirectional(requestId,
/// constructSignBidirectionalEventNotificationV1(kernel.self(), depth,
/// path))` — the signer read, the caller's own address, the notification and
/// the cross-contract call. The notification's depth and path bytes ARE the
/// request map's compiled ledger path, read off the handle.
fn notify_signet<K, V>(c: &mut Circuit3, request_id: &RequestId<Public>, map: &LedgerMap<K, V>) {
    c.region("xcall: notify signet", |c| {
        // compactc evaluates a call's RECEIVER before its argument
        // expressions, so the sealed-cell read is pinned FIRST.
        let signer = SignetSigner::at_field_path(VAULT.signet_signer.field_path().as_slice()).pin(c);
        let me = kernel::self_address(c);
        let path = map.field_path();
        let mut bytes = [0u8; 4];
        bytes[..path.as_slice().len()].copy_from_slice(path.as_slice());
        let notification = construct_notification_v1::<Public>(c, &me.bytes(), path.depth(), bytes);
        signer.sign_bidirectional(c, *request_id, notification);
    });
}

/// The whole of a `send*` circuit after its flushed entry and args are in
/// hand: the transaction (action-specific, `build`), the V1 event with its
/// `mpcKeyVersion` and `kernel.self()` reads, the request id, the freshness
/// check, the record, the eviction entry and the notification.
#[allow(clippy::too_many_arguments)]
fn send_request<const WORDS: usize, SP, SR, A>(
    c: &mut Circuit3,
    out_index: RequestIndex<Private>,
    action: u64,
    args_map: &LedgerMap<Uint<64, Public>, A>,
    request_map: &LedgerMap<RequestId<Public>, EventRecordV1<WORDS, SR>>,
    output_schema: &[u8],
    build: impl FnOnce(&mut Circuit3, &RequestBufferEntry, &A) -> (signet_v1::EvmType2TxParams<Private, WORDS>, SigningPath<Private>),
    words_used: usize,
    path_is_const: bool,
) where
    SP: SchemaBytes<Private>,
    SR: SchemaBytes<Public>,
    A: LedgerRepr + minocrab_std::v3::ProofWires,
{
    require_initialised(c);
    let out_index = out_index.disclose_as::<OutIndex>(c);
    let entry = c.region("flushed entry", |c| {
        let flushed = VAULT.output_request_buffer.member(c, &out_index);
        c.assert(is_true(flushed).message("Request not flushed"));
        let out = VAULT.output_request_buffer.lookup(c, &out_index).stale(c);
        c.assert(out.entry.action.eq(action).message("Wrong action"));
        out.entry
    });
    let args = args_map.lookup(c, &entry.in_index).stale(c);
    let (tx, path) = build(c, &entry, &args);

    // constructSignBidirectionalEventV1(mpcKeyVersion, kernel.self(), path, …)
    let key_version = VAULT.mpc_key_version.read(c).stale(c);
    let sender = kernel::self_address(c).private();
    let dest = signet_v1::ethereum_caip2_id::<Private>(c);
    // The reserved-path assert is folded for the vault's own constant path,
    // as compactc folds it; the calldata word count is a literal in every send.
    let kv = key_version.field().private();
    let request: signet_v1::SignBidirectionalEventV1<Private, WORDS, SP> = if path_is_const {
        signet_v1::construct_sign_bidirectional_event_v1_const_path(c, kv, sender, path, tx, dest, output_schema)
    } else {
        signet_v1::construct_sign_bidirectional_event_v1(c, kv, sender, path, tx, dest, output_schema)
    };
    let request_id = signet_v1::calculate_evm_type2_request_id_v1(c, &request, Some(words_used)).disclose_as::<RequestIdDisclosed>(c);

    c.region("record: freshness and insert", |c| {
        let sent = request_map.member(c, &request_id);
        c.assert(not(is_true(sent)).message("Request already sent"));
        let record = EventRecordV1::<WORDS, SR>::from_limbs(request.limbs().disclose_as::<RequestRecord>(c));
        request_map.insert(c, &request_id, &record);
        VAULT.eviction_map.insert(c, &request_id, &out_index);
    });
    notify_signet(c, &request_id, request_map);
}

/// `settleRequest(requestId, action): [RequestBufferEntry, AttestationRecord]`
/// — the open request and the flushed attestation that settles it, the height
/// bound, the ownership proof over a FRESH witness, and the three removals.
fn settle_request(c: &mut Circuit3, request_id: &RequestId<Public>, action: u64) -> (RequestBufferEntry, AttestationRecord) {
    c.region("settle request", |c| {
        let sent = VAULT.eviction_map.member(c, request_id);
        c.assert(is_true(sent).message("Request not sent"));
        let out_index = VAULT.eviction_map.lookup(c, request_id).stale(c);
        let open = VAULT.output_request_buffer.member(c, &out_index);
        c.assert(is_true(open).message("Request not open"));
        let out = VAULT.output_request_buffer.lookup(c, &out_index).stale(c);
        c.assert(out.entry.action.eq(action).message("Wrong action"));

        let flushed = VAULT.output_attestation_buffer.member(c, request_id);
        c.assert(is_true(flushed).message("Attestation not flushed"));
        let record = VAULT.output_attestation_buffer.lookup(c, request_id).stale(c);
        let above = c.less_than(out.last_seen.field(), record.block_height.field(), 64);
        c.assert_with(above, Some("Stale attestation"));

        let mine = ownership_commitment(c, out.entry.in_index.field().private());
        c.assert(b32_eq(&mine.bytes(), &out.entry.commitment.private().bytes()).message("Not the requester"));

        VAULT.eviction_map.remove(c, request_id);
        VAULT.output_attestation_buffer.remove(c, request_id);
        VAULT.output_request_buffer.remove(c, &out_index);
        (out.entry, record)
    })
}

/// `record.outputKind == OutputKind.executed`.
fn executed(c: &mut Circuit3, record: &AttestationRecord) -> Wire3<FieldT, Public> {
    let kind = c.constant(output_kind::EXECUTED);
    c.test_eq(record.output_kind.field(), kind)
}

/// `outcomeRefunds(outputKind)` — `failed || unviable`.
fn outcome_refunds(c: &mut Circuit3, record: &AttestationRecord) -> Wire3<FieldT, Public> {
    let failed = c.constant(output_kind::FAILED);
    let unviable = c.constant(output_kind::UNVIABLE);
    let is_failed = c.test_eq(record.output_kind.field(), failed);
    let is_unviable = c.test_eq(record.output_kind.field(), unviable);
    let one = c.constant(1u64);
    c.cond_select(is_failed, one, is_unviable)
}

/// `assert(calculateSignetAttestationDigestV1<LEN>(requestId, record.blockHeight,
/// record.outputKind, output) == record.digest, "Output does not match the
/// attestation")` — inside whatever guard the caller opened.
fn assert_output_matches<const LEN: usize>(c: &mut Circuit3, request_id: &RequestId<Public>, record: &AttestationRecord, output_limbs: &[Wire3<FieldT, Public>]) {
    let digest = signet_v1::calculate_attestation_digest_v1::<Public, LEN>(
        c,
        request_id,
        record.block_height.field(),
        record.output_kind.field(),
        output_limbs,
    );
    c.assert(b32_eq(&digest, &record.digest).message("Output does not match the attestation"));
}

/// `deserialize<VaultResponse, 1>(output).success` — the packed Boolean is
/// (byte == 1), with no canonicity check, as compactc lowers it.
fn attested_success(c: &mut Circuit3, output: Wire3<FieldT, Public>) -> Wire3<FieldT, Public> {
    let one = c.constant(1u64);
    c.test_eq(output, one)
}

/// `amount as Uint<64>` on a stored `Uint<128>` — the range check compactc's
/// cast emits, where the caller's guard holds.
fn as_u64(c: &mut Circuit3, amount: Uint<128, Public>) -> Uint<64, Public> {
    Uint::<64, Public>::from_field_checked(c, amount.field())
}

/// `mintShieldedToken(vaultTokenDomainSeparator(erc20), amount, disclose(nonce),
/// left(pk))` to an ALREADY-witnessed key.
fn mint_to_key(c: &mut Circuit3, erc20: Wire3<FieldT, Public>, amount: Uint<64, Public>, mint_nonce: &CoinNonce<Public>, pk: &minocrab_std::v3::ZswapCoinPublicKey<Public>) {
    let domain_sep = vault_token_domain_separator(c, erc20);
    common::mint_shielded_token_to_key(c, &domain_sep, amount, mint_nonce, pk);
}

/// `struct ShieldedCoinInfo { nonce: Bytes<32>, color: Bytes<32>,
/// value: Uint<128> }` as an argument.
#[derive(CircuitArg)]
struct ShieldedCoinArg {
    nonce: CoinNonce<Private>,
    color: CoinColor<Private>,
    value: Uint<128>,
}

/// `color = tokenType(vaultTokenDomainSeparator(erc20), kernel.self());
/// assert(coin.color == color); assert(coin.value == amount)` — the
/// surrendered coin must be THIS vault token, of exactly `amount`.
fn assert_vault_coin(
    c: &mut Circuit3,
    erc20: Wire3<FieldT, Public>,
    amount: Wire3<FieldT, Private>,
    coin: &ShieldedCoinArg,
    color_message: &'static str,
    value_message: &'static str,
) {
    let domain_sep = vault_token_domain_separator(c, erc20);
    let me = kernel::self_address(c);
    let color = minocrab_std::v3::token_type(c, &domain_sep, &me.bytes());
    c.assert(b32_eq(&coin.color.bytes(), &color.private().bytes()).message(color_message));
    c.assert(eq(coin.value.field(), amount).message(value_message));
}

/// `receiveShielded(disclose(coin)); sendImmediateShielded(disclose(coin),
/// shieldedBurnAddress(), disclose(coin).value)` — custody, then the
/// full-value burn.
fn burn_surrendered_coin(c: &mut Circuit3, coin: ShieldedCoinArg) {
    let one = c.constant(1u64);
    let coin = minocrab_std::v3::ShieldedCoinInfo3 {
        nonce: coin.nonce.disclose_as::<SurrenderedCoinNonce>(c),
        color: coin.color.disclose_as::<SurrenderedCoinColor>(c),
        value: coin.value.field().disclose_as::<SurrenderedCoinValue>(c),
    };
    common::receive_shielded(c, &coin);
    common::burn_coin(c, one, &coin);
}

/// The attestation-queueing body the three `queueAttestation*` share:
/// `requireInitialised`, the verify against `mpcResponseKey`, the digest and
/// `recordAttestation`. `output_limbs` is the disclosed output at width `LEN`.
fn queue_attestation<const LEN: usize>(c: &mut Circuit3, event: &RespondBidirectionalEvent<Private>, output_limbs: &[Wire3<FieldT, Private>]) {
    require_initialised(c);
    let mpc_key = VAULT.mpc_response_key.read(c);
    let valid = signet_v1::verify_respond_bidirectional_event_v1::<Private, LEN>(c, output_limbs, event, mpc_key.point().private());
    c.assert_with(valid, Some("Invalid attestation signature"));

    // The disclosed attestation: every field of the event is public input.
    let request_id = event.request_id.disclose_as::<Attestation>(c);
    let block_height = event.block_height.disclose_as::<Attestation>(c);
    let kind = event.output_kind.disclose_as::<Attestation>(c);
    let output_public: Vec<Wire3<FieldT, Public>> = output_limbs.to_vec().disclose_as::<SerializedOutput>(c);
    let digest = signet_v1::calculate_attestation_digest_v1::<Public, LEN>(c, &request_id, block_height.field(), kind.field(), &output_public);

    // recordAttestation(attestation, digest)
    c.region("record attestation", |c| {
        let sent = VAULT.eviction_map.member(c, &request_id);
        c.assert(is_true(sent).message("Request not sent"));
        let out_index = VAULT.eviction_map.lookup(c, &request_id).stale(c);
        let open = VAULT.output_request_buffer.member(c, &out_index);
        c.assert(is_true(open).message("Request not open"));
        let out = VAULT.output_request_buffer.lookup(c, &out_index).stale(c);
        let above = c.less_than(out.last_seen.field(), block_height.field(), 64);
        c.assert_with(above, Some("Stale attestation"));
        let queued = VAULT.input_attestation_buffer.member(c, &request_id);
        c.assert(not(is_true(queued)).message("Attestation already queued"));
        let flushed = VAULT.output_attestation_buffer.member(c, &request_id);
        c.assert(not(is_true(flushed)).message("Attestation already flushed"));
        let record = AttestationRecord {
            block_height,
            output_kind: kind,
            digest,
        };
        VAULT.input_attestation_buffer.insert(c, &request_id, &record);
    });
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

/// `queueApprove(inIndex, approveRequest)` — the deployer gate and the
/// queueing both approval starts share, after each start's own validation.
fn queue_approve(c: &mut Circuit3, in_index: Uint<64>, erc20_address: Bytes<20, Public>, spender: Bytes<20, Public>) {
    assert_deployer(c);
    let in_index = in_index.disclose_as::<InIndex>(c);
    assert_index_free(c, &in_index, &VAULT.approve_args_map);
    let gas = vault_gas(c, |l| l.approve);
    let args = ApproveArgs {
        request: StoredApproveRequest { erc20_address, spender },
        gas,
    };
    VAULT.approve_args_map.insert(c, &in_index, &args);
    let zero = c.constant(0u64);
    let digest = args_hash(c, APPROVE_ARGS_PAD, &args);
    queue_request(c, action::APPROVE, true, zero, in_index, digest);
}

// ---- the circuit arguments ---------------------------------------------------------------

/// `struct GasParams { gasLimit: Uint<64>; maxFeePerGas: Uint<128>;
/// maxPriorityFeePerGas: Uint<128> }` as a circuit argument.
#[derive(CircuitArg)]
pub struct GasParamsArg {
    gas_limit: Uint<64>,
    max_fee_per_gas: Uint<128>,
    max_priority_fee_per_gas: Uint<128>,
}

/// `struct DepositRequest { erc20Address: Bytes<20>, amount: Uint<128> }`.
#[derive(CircuitArg)]
struct DepositRequest {
    erc20_address: Bytes<20>,
    amount: Uint<128>,
}

/// `struct WithdrawRequest { erc20Address: Bytes<20>, amount: Uint<128>,
/// destEvmAddress: Bytes<20> }`.
#[derive(CircuitArg)]
struct WithdrawRequest {
    erc20_address: Bytes<20>,
    amount: Uint<128>,
    dest_evm_address: Bytes<20>,
}

/// `struct SwapRequest { erc20AddressIn; erc20AddressOut; fee: Uint<128>;
/// amountOut; amountInMaximum }`.
#[derive(CircuitArg)]
struct SwapRequest {
    erc20_address_in: Bytes<20>,
    erc20_address_out: Bytes<20>,
    fee: Uint<128>,
    amount_out: Uint<128>,
    amount_in_maximum: Uint<128>,
}

/// `struct SupplyRequest { amount: Uint<128> }`.
#[derive(CircuitArg)]
struct SupplyRequest {
    amount: Uint<128>,
}

/// `struct RedeemRequest { shares: Uint<128> }`.
#[derive(CircuitArg)]
struct RedeemRequest {
    shares: Uint<128>,
}

/// `struct FlushSlot { channel: FlushChannel; inIndex: Uint<64>; requestId:
/// RequestId }`.
#[derive(CircuitArg)]
struct FlushSlot {
    channel: FlushChannel<Private>,
    in_index: Uint<64>,
    request_id: RequestId<Private>,
}

#[contract]
impl Vault {
    // ==== Admin without EVM transactions ================================================

    /// `export circuit initialise(vaultEvm, swapRouter, stataUnderlyingAddr,
    /// stataTokenAddr: Bytes<20>, chainId: Uint<64>, responseKey:
    /// Secp256k1Point, responseKeyVersion: Uint<8>, evmHeight: Uint<64>): []`
    /// — one-shot, deployer-gated post-deploy configuration.
    #[circuit]
    pub fn initialise(
        c: &mut Circuit3,
        vault_evm: Bytes<20>,
        swap_router: Bytes<20>,
        stata_underlying_addr: Bytes<20>,
        stata_token_addr: Bytes<20>,
        chain_id: Uint<64>,
        response_key: Secp256k1Point,
        response_key_version: Uint<8>,
        evm_height: Uint<64>,
    ) -> Discloses<(
        VaultEvmAddress,
        UniswapRouter,
        StataUnderlying,
        StataToken,
        AllowedErc20,
        EvmChainId,
        MpcResponseKey,
        MpcKeyVersion,
        EvmHeight,
    )> {
        // assert(!initialised, "Already initialised")
        c.region("initialised gate", |c| {
            let init = VAULT.initialised.read(c);
            c.assert(not(is_true(init)).message("Already initialised"));
        });
        c.assert(response_key_version.ge(1u64).message("keyVersion must be >= 1"));
        assert_deployer(c);
        c.assert(chain_id.gt(0u64).message("Chain ID must be positive"));
        c.assert(swap_router.ne(0u64).message("Router cannot be zero"));
        c.assert(stata_underlying_addr.ne(0u64).message("stataUnderlying cannot be zero"));
        c.assert(stata_token_addr.ne(0u64).message("stataToken cannot be zero"));

        c.region("configuration writes", |c| {
            let yes = Bool::<Public>::from_field_unchecked(c.constant(1u64));
            VAULT.initialised.write(c, &yes);
            let vault_evm = vault_evm.disclose_as::<VaultEvmAddress>(c);
            VAULT.vault_evm_address.write(c, &vault_evm);
            let swap_router = swap_router.disclose_as::<UniswapRouter>(c);
            VAULT.uniswap_router.write(c, &swap_router);
            let stata_underlying = stata_underlying_addr.disclose_as::<StataUnderlying>(c);
            VAULT.stata_underlying.write(c, &stata_underlying);
            let stata_token = stata_token_addr.disclose_as::<StataToken>(c);
            VAULT.stata_token.write(c, &stata_token);
            // Otherwise no stataUnderlying vault coin could ever be minted to start a supply.
            let allowed = stata_underlying_addr.disclose_as::<AllowedErc20>(c);
            VAULT.allowed_tokens.insert(c, &allowed);
            let chain_id = chain_id.disclose_as::<EvmChainId>(c);
            VAULT.evm_chain_id.write(c, &chain_id);
            let response_key = response_key.disclose_as::<MpcResponseKey>(c);
            VAULT.mpc_response_key.write(c, &response_key);
            let key_version = response_key_version.disclose_as::<MpcKeyVersion>(c);
            VAULT.mpc_key_version.write(c, &key_version);
            let height = evm_height.disclose_as::<EvmHeight>(c);
            VAULT.global_last_seen.write(c, &height);

            let max_fee = Uint::<128, Public>::from_field_unchecked(c.constant(minocrab::Fr::from_le_bytes(&DEFAULT_MAX_FEE_PER_GAS.to_le_bytes()).unwrap()));
            VAULT.vault_max_fee_per_gas.write(c, &max_fee);
            let max_prio = Uint::<128, Public>::from_field_unchecked(c.constant(minocrab::Fr::from_le_bytes(&DEFAULT_MAX_PRIORITY_FEE_PER_GAS.to_le_bytes()).unwrap()));
            VAULT.vault_max_priority_fee_per_gas.write(c, &max_prio);
            let limits = VaultGasLimits {
                withdraw: Uint::from_field_unchecked(c.constant(DEFAULT_WITHDRAW_GAS)),
                approve: Uint::from_field_unchecked(c.constant(DEFAULT_APPROVE_GAS)),
                swap: Uint::from_field_unchecked(c.constant(DEFAULT_SWAP_GAS)),
                supply: Uint::from_field_unchecked(c.constant(DEFAULT_SUPPLY_GAS)),
                redeem: Uint::from_field_unchecked(c.constant(DEFAULT_REDEEM_GAS)),
            };
            VAULT.vault_gas_limits.write(c, &limits);
        });
        Discloses::of(())
    }

    /// `export circuit setGasParams(newMaxFeePerGas, newMaxPriorityFeePerGas:
    /// Uint<128>, newWithdrawGasLimit, newApproveGasLimit, newSwapGasLimit,
    /// newSupplyGasLimit, newRedeemGasLimit: Uint<64>): []` — the deployer
    /// resets the fee envelope and the per-action gas limits.
    #[circuit]
    pub fn set_gas_params(
        c: &mut Circuit3,
        new_max_fee_per_gas: Uint<128>,
        new_max_priority_fee_per_gas: Uint<128>,
        new_withdraw_gas_limit: Uint<64>,
        new_approve_gas_limit: Uint<64>,
        new_swap_gas_limit: Uint<64>,
        new_supply_gas_limit: Uint<64>,
        new_redeem_gas_limit: Uint<64>,
    ) -> Discloses<(MaxFeePerGas, MaxPriorityFeePerGas, GasLimits)> {
        require_initialised(c);
        assert_deployer(c);
        c.assert(new_max_fee_per_gas.gt(0u64).message("maxFeePerGas must be positive"));
        c.assert(
            new_max_priority_fee_per_gas
                .le(new_max_fee_per_gas)
                .message("maxPriorityFeePerGas cannot exceed maxFeePerGas"),
        );
        c.assert(new_withdraw_gas_limit.gt(0u64).message("Gas limit must be positive"));
        c.assert(new_approve_gas_limit.gt(0u64).message("Gas limit must be positive"));
        c.assert(new_swap_gas_limit.gt(0u64).message("Gas limit must be positive"));
        c.assert(new_supply_gas_limit.gt(0u64).message("Gas limit must be positive"));
        c.assert(new_redeem_gas_limit.gt(0u64).message("Gas limit must be positive"));

        let max_fee = new_max_fee_per_gas.disclose_as::<MaxFeePerGas>(c);
        VAULT.vault_max_fee_per_gas.write(c, &max_fee);
        let max_prio = new_max_priority_fee_per_gas.disclose_as::<MaxPriorityFeePerGas>(c);
        VAULT.vault_max_priority_fee_per_gas.write(c, &max_prio);
        let limits = VaultGasLimits {
            withdraw: new_withdraw_gas_limit.disclose_as::<GasLimits>(c),
            approve: new_approve_gas_limit.disclose_as::<GasLimits>(c),
            swap: new_swap_gas_limit.disclose_as::<GasLimits>(c),
            supply: new_supply_gas_limit.disclose_as::<GasLimits>(c),
            redeem: new_redeem_gas_limit.disclose_as::<GasLimits>(c),
        };
        VAULT.vault_gas_limits.write(c, &limits);
        Discloses::of(())
    }

    /// `export circuit addAllowedToken(erc20Address: Bytes<20>): []` — the
    /// deployer grows `allowedTokens`; the set only grows.
    #[circuit]
    pub fn add_allowed_token(c: &mut Circuit3, erc20_address: Bytes<20>) -> Discloses<(AllowedErc20,)> {
        require_initialised(c);
        assert_deployer(c);
        c.assert(erc20_address.ne(0u64).message("ERC20 address cannot be zero"));
        let erc20 = erc20_address.disclose_as::<AllowedErc20>(c);
        VAULT.allowed_tokens.insert(c, &erc20);
        Discloses::of(())
    }

    // ==== Request queue ==================================================================

    /// `export circuit flushQueue(slots: Vector<10, FlushSlot>): []` —
    /// permissionless; slots run in order, a request slot moving a queued
    /// request into the output buffer under the vault's next nonce (if it
    /// signs) and the current `globalLastSeen`, an attestation slot moving a
    /// queued attestation out and folding its height into `globalLastSeen`.
    #[circuit]
    pub fn flush_queue(
        c: &mut Circuit3,
        slots: [FlushSlot; FLUSH_SLOTS],
    ) -> Discloses<(FlushSlotChannel, FlushSlotInIndex, FlushSlotRequestId)> {
        require_initialised(c);
        for slot in slots {
            let channel = slot.channel.disclose_as::<FlushSlotChannel>(c);
            let in_index = slot.in_index.disclose_as::<FlushSlotInIndex>(c);
            let request_id = slot.request_id.disclose_as::<FlushSlotRequestId>(c);
            let request = c.constant(flush_channel::REQUEST);
            let attestation = c.constant(flush_channel::ATTESTATION);
            let is_request = c.test_eq(channel.field(), request);
            let is_attestation = c.test_eq(channel.field(), attestation);
            c.when(is_request, |c| flush_request(c, &in_index))
                .else_when(is_attestation, |c| flush_attestation(c, &request_id));
        }
        Discloses::of(())
    }

    /// `export circuit queueAttestation0(respondBidirectionalEvent:
    /// RespondBidirectionalEventV1, serializedOutput: Bytes<0>): []` — a
    /// verified attestation with an EMPTY output (a failed or unviable
    /// execution, or an executed nonce replacement), queued for the flush.
    ///
    /// IT DISCLOSES NO OUTPUT, and says so: at `LEN = 0` the limb vector is
    /// empty, so `queue_attestation`'s `disclose_as::<SerializedOutput>`
    /// discloses nothing at all. Declaring the label anyway would claim an
    /// audit surface this circuit does not have — the width-1 and width-32
    /// twins below are where it is real.
    #[circuit]
    pub fn queue_attestation0(
        c: &mut Circuit3,
        #[arg(name = "respondBidirectionalEvent")] event: RespondBidirectionalEvent<Private>,
        serialized_output: Bytes0,
    ) -> Discloses<(Attestation,)> {
        let _ = serialized_output;
        queue_attestation::<0>(c, &event, &[]);
        Discloses::of(())
    }

    /// `export circuit queueAttestation1(respondBidirectionalEvent,
    /// serializedOutput: Bytes<1>): []` — the ERC20 transfer/approve bool.
    #[circuit]
    pub fn queue_attestation1(
        c: &mut Circuit3,
        #[arg(name = "respondBidirectionalEvent")] event: RespondBidirectionalEvent<Private>,
        serialized_output: Bytes<1>,
    ) -> Discloses<(Attestation, SerializedOutput)> {
        queue_attestation::<1>(c, &event, &[serialized_output.field()]);
        Discloses::of(())
    }

    /// `export circuit queueAttestation32(respondBidirectionalEvent,
    /// serializedOutput: Bytes<32>): []` — a uint256 return, attested whole.
    #[circuit]
    pub fn queue_attestation32(
        c: &mut Circuit3,
        #[arg(name = "respondBidirectionalEvent")] event: RespondBidirectionalEvent<Private>,
        serialized_output: B32<Private>,
    ) -> Discloses<(Attestation, SerializedOutput)> {
        queue_attestation::<32>(c, &event, &[serialized_output.hi, serialized_output.lo]);
        Discloses::of(())
    }

    // ==== Replace nonce ==================================================================

    /// `export circuit startReplaceNonce(inIndex: Uint<64>, requestId:
    /// RequestId, action: Action): []` — EMERGENCY USE ONLY: queues a
    /// zero-value self-transfer at the nonce of the sent request named, read
    /// off that request's own event. Deployer-gated.
    #[circuit]
    pub fn start_replace_nonce(
        c: &mut Circuit3,
        in_index: Uint<64>,
        request_id: RequestId<Private>,
        action: Action<Private>,
    ) -> Discloses<(ReplacedRequestId, ReplacedAction, InIndex, OwnershipCommitment)> {
        require_initialised(c);
        assert_deployer(c);

        // const evmNonce = sentVaultNonce(disclose(requestId), disclose(action))
        let request_id = request_id.disclose_as::<ReplacedRequestId>(c);
        let act = action.disclose_as::<ReplacedAction>(c);
        let evm_nonce = sent_vault_nonce(c, &request_id, &act);

        let in_index = in_index.disclose_as::<InIndex>(c);
        assert_index_free(c, &in_index, &VAULT.replace_nonce_args_map);

        let max_fee_per_gas = VAULT.vault_max_fee_per_gas.read(c).stale(c);
        let max_priority_fee_per_gas = VAULT.vault_max_priority_fee_per_gas.read(c).stale(c);
        let args = ReplaceNonceArgs {
            gas: StoredGas {
                gas_limit: Uint::from_field_unchecked(c.constant(REPLACE_NONCE_GAS)),
                max_fee_per_gas,
                max_priority_fee_per_gas,
            },
        };
        VAULT.replace_nonce_args_map.insert(c, &in_index, &args);
        let digest = args_hash(c, REPLACE_NONCE_ARGS_PAD, &args);
        queue_request(c, action::REPLACE_NONCE, false, evm_nonce.field(), in_index, digest);
        Discloses::of(())
    }

    /// `export circuit sendReplaceNonce(outIndex: Bytes<32>): []` — records
    /// the flushed replacement's event (no calldata, `to: vaultEvmAddress`)
    /// and notifies the MPC. Permissionless.
    #[circuit]
    pub fn send_replace_nonce(
        c: &mut Circuit3,
        out_index: RequestIndex<Private>,
    ) -> Discloses<(OutIndex, RequestIdDisclosed, RequestRecord, XcallEntryPointHash, XcallCommitment)> {
        send_request::<VAULT_WORDS, Bytes<REPLACE_NONCE_SCHEMA_LEN, Private>, Bytes<REPLACE_NONCE_SCHEMA_LEN, Public>, ReplaceNonceArgs>(
            c,
            out_index,
            action::REPLACE_NONCE,
            &VAULT.replace_nonce_args_map,
            &VAULT.bidirectional_replace_nonce_map,
            REPLACE_NONCE_OUTPUT_SCHEMA,
            |c, entry, args| {
                let calldata = no_calldata::<VAULT_WORDS>(c);
                let tx = tx_params(
                    c,
                    entry,
                    &args.gas,
                    |c| VAULT.vault_evm_address.read(c).stale(c).field().private(),
                    calldata,
                    false,
                );
                (tx, SigningPath::vault_path(c).private())
            },
            0,
            true,
        );
        Discloses::of(())
    }

    /// `export circuit completeReplaceNonce(requestId: RequestId): []` —
    /// settles a replacement on every verdict by closing it; the empty
    /// output is checked against the record's digest. Deployer-gated through
    /// the ownership commitment.
    #[circuit]
    pub fn complete_replace_nonce(c: &mut Circuit3, request_id: RequestId<Private>) -> Discloses<(SettleRequestId,)> {
        require_initialised(c);
        let request_id = request_id.disclose_as::<SettleRequestId>(c);
        let (entry, record) = settle_request(c, &request_id, action::REPLACE_NONCE);
        VAULT.replace_nonce_args_map.remove(c, &entry.in_index);
        c.region("event consume", |c| {
            let present = VAULT.bidirectional_replace_nonce_map.member(c, &request_id);
            c.assert(is_true(present).message("Request event missing"));
            VAULT.bidirectional_replace_nonce_map.remove(c, &request_id);
        });
        assert_output_matches::<0>(c, &request_id, &record, &[]);
        Discloses::of(())
    }

    // ==== Approve ========================================================================

    /// `export circuit startApproveRouter(inIndex: Uint<64>, erc20Address:
    /// Bytes<20>): []` — queues the vault's approval of the pinned router to
    /// spend `erc20Address`. Deployer-gated.
    #[circuit]
    pub fn start_approve_router(
        c: &mut Circuit3,
        in_index: Uint<64>,
        erc20_address: Bytes<20>,
    ) -> Discloses<(AllowedErc20, InIndex, OwnershipCommitment)> {
        require_initialised(c);
        c.assert(erc20_address.ne(0u64).message("ERC20 address cannot be zero"));
        // ApproveRequest { erc20Address, spender: uniswapRouter }
        let erc20 = erc20_address.disclose_as::<AllowedErc20>(c);
        let router = VAULT.uniswap_router.read(c).stale(c);
        queue_approve(c, in_index, erc20, router);
        Discloses::of(())
    }

    /// `export circuit startApproveStata(inIndex: Uint<64>): []` — queues the
    /// vault's approval of the stata wrapper to spend the underlying.
    /// Deployer-gated.
    #[circuit]
    pub fn start_approve_stata(c: &mut Circuit3, in_index: Uint<64>) -> Discloses<(InIndex, OwnershipCommitment)> {
        require_initialised(c);
        // ApproveRequest { erc20Address: stataUnderlying, spender: stataToken }
        let underlying = VAULT.stata_underlying.read(c).stale(c);
        let wrapper = VAULT.stata_token.read(c).stale(c);
        queue_approve(c, in_index, underlying, wrapper);
        Discloses::of(())
    }

    /// `export circuit sendApprove(outIndex: Bytes<32>): []` — records the
    /// flushed approval's event (`approve(spender, unlimitedAllowance())` on
    /// the ERC20) and notifies the MPC. Permissionless.
    #[circuit]
    pub fn send_approve(
        c: &mut Circuit3,
        out_index: RequestIndex<Private>,
    ) -> Discloses<(OutIndex, RequestIdDisclosed, RequestRecord, XcallEntryPointHash, XcallCommitment)> {
        send_request::<VAULT_WORDS, BytesN<Private, VAULT_SCHEMA_LEN>, BytesN<Public, VAULT_SCHEMA_LEN>, ApproveArgs>(
            c,
            out_index,
            action::APPROVE,
            &VAULT.approve_args_map,
            &VAULT.bidirectional_approve_map,
            VAULT_OUTPUT_SCHEMA,
            |c, entry, args| {
                let word0 = signet_v1::evm_address_abi_word(c, args.request.spender.field().private());
                let word1 = unlimited_allowance_word(c);
                let calldata = calldata(c, &APPROVE_SELECTOR, [word0, word1]);
                let to = args.request.erc20_address.field().private();
                let tx = tx_params(c, entry, &args.gas, |_c| to, calldata, true);
                (tx, SigningPath::vault_path(c).private())
            },
            VAULT_WORDS,
            true,
        );
        Discloses::of(())
    }

    /// `export circuit completeApprove(requestId: RequestId, serializedOutput:
    /// Bytes<1>): []` — settles an approval on any verdict: an executed one
    /// checks the output against the attestation; nothing was surrendered,
    /// so every verdict only closes the request.
    #[circuit]
    pub fn complete_approve(
        c: &mut Circuit3,
        request_id: RequestId<Private>,
        serialized_output: Bytes<1>,
    ) -> Discloses<(SettleRequestId, SerializedOutput)> {
        require_initialised(c);
        let request_id = request_id.disclose_as::<SettleRequestId>(c);
        let (entry, record) = settle_request(c, &request_id, action::APPROVE);
        VAULT.approve_args_map.remove(c, &entry.in_index);
        c.region("event consume", |c| {
            let present = VAULT.bidirectional_approve_map.member(c, &request_id);
            c.assert(is_true(present).message("Request event missing"));
            VAULT.bidirectional_approve_map.remove(c, &request_id);
        });
        let is_executed = executed(c, &record);
        let output = serialized_output.disclose_as::<SerializedOutput>(c);
        c.when(is_executed, |c| assert_output_matches::<1>(c, &request_id, &record, &[output.field()]));
        Discloses::of(())
    }

    // ==== Deposit ========================================================================

    /// `export circuit startDeposit(inIndex: Uint<64>, evmNonce: Uint<64>,
    /// gas: GasParams, depositRequest: DepositRequest): []` — queues
    /// `transfer(vaultEvmAddress, amount)` on an allowed ERC20, signed by the
    /// MPC with the DEPOSITOR's derived account at their own nonce and gas.
    #[circuit]
    pub fn start_deposit(
        c: &mut Circuit3,
        in_index: Uint<64>,
        evm_nonce: Uint<64>,
        gas: GasParamsArg,
        deposit_request: DepositRequest,
    ) -> Discloses<(
        DepositedErc20,
        InIndex,
        DepositedAmount,
        DepositorCommitment,
        GasParams,
        EvmNonce,
        OwnershipCommitment,
    )> {
        require_initialised(c);
        let erc20 = deposit_request.erc20_address.disclose_as::<DepositedErc20>(c);
        c.region("guards", |c| {
            let allowed = VAULT.allowed_tokens.member(c, &erc20);
            c.assert(is_true(allowed).message("ERC20 not allowed"));
            c.assert(deposit_request.amount.gt(0u64).message("Amount must be positive"));
            // completeDeposit mints via a Uint<64> API, so reject unclaimable amounts.
            c.assert(deposit_request.amount.le(u64::MAX).message("Amount exceeds Uint<64> max"));
            c.assert(gas.gas_limit.gt(0u64).message("Gas limit must be positive"));
        });

        let in_index = in_index.disclose_as::<InIndex>(c);
        assert_index_free(c, &in_index, &VAULT.deposit_args_map);

        // const args = disclose(DepositArgs { request, path: userCommitment(callerSecretKey()), gas })
        let sk = common::witness_sk(c);
        let path = user_commitment(c, &sk).disclose_as::<DepositorCommitment>(c);
        let args = DepositArgs {
            request: StoredDepositRequest {
                erc20_address: erc20,
                amount: deposit_request.amount.disclose_as::<DepositedAmount>(c),
            },
            path,
            gas: StoredGas {
                gas_limit: gas.gas_limit.disclose_as::<GasParams>(c),
                max_fee_per_gas: gas.max_fee_per_gas.disclose_as::<GasParams>(c),
                max_priority_fee_per_gas: gas.max_priority_fee_per_gas.disclose_as::<GasParams>(c),
            },
        };
        VAULT.deposit_args_map.insert(c, &in_index, &args);
        let evm_nonce = evm_nonce.disclose_as::<EvmNonce>(c);
        let digest = args_hash(c, DEPOSIT_ARGS_PAD, &args);
        queue_request(c, action::DEPOSIT, false, evm_nonce.field(), in_index, digest);
        Discloses::of(())
    }

    /// `export circuit sendDeposit(outIndex: Bytes<32>): []` — records the
    /// flushed deposit's event (`transfer(vaultEvmAddress, amount)`, signed
    /// from the depositor's path) and notifies the MPC. Permissionless.
    #[circuit]
    pub fn send_deposit(
        c: &mut Circuit3,
        out_index: RequestIndex<Private>,
    ) -> Discloses<(OutIndex, RequestIdDisclosed, RequestRecord, XcallEntryPointHash, XcallCommitment)> {
        send_request::<VAULT_WORDS, BytesN<Private, VAULT_SCHEMA_LEN>, BytesN<Public, VAULT_SCHEMA_LEN>, DepositArgs>(
            c,
            out_index,
            action::DEPOSIT,
            &VAULT.deposit_args_map,
            &VAULT.bidirectional_deposit_map,
            VAULT_OUTPUT_SCHEMA,
            |c, entry, args| {
                // The pinned recipient stops a client having the MPC sign a transfer to themselves.
                let vault_evm = VAULT.vault_evm_address.read(c).stale(c);
                let word0 = signet_v1::evm_address_abi_word(c, vault_evm.field().private());
                let word1 = signet_v1::numeric_abi_word(c, args.request.amount.field().private());
                let calldata = calldata(c, &TRANSFER_SELECTOR, [word0, word1]);
                let to = args.request.erc20_address.field().private();
                let tx = tx_params(c, entry, &args.gas, |_c| to, calldata, true);
                (tx, SigningPath::from(args.path.private()))
            },
            VAULT_WORDS,
            false,
        );
        Discloses::of(())
    }

    /// `export circuit completeDeposit(requestId: RequestId, serializedOutput:
    /// Bytes<1>, mintNonce: Bytes<32>, recipient: Maybe<Either<ZswapCoinPublicKey,
    /// ContractAddress>>): []` — settles a deposit on any verdict: executed
    /// and `true` mints the deposited amount to the recipient (the caller by
    /// default); anything else only closes the request. Depositor-gated.
    #[circuit]
    pub fn complete_deposit(
        c: &mut Circuit3,
        request_id: RequestId<Private>,
        serialized_output: Bytes<1>,
        mint_nonce: CoinNonce<Private>,
        recipient: Maybe<Either<minocrab_std::v3::ZswapCoinPublicKey<Private>, minocrab_std::v3::ContractAddress<Private>, Private>>,
    ) -> Discloses<(
        SettleRequestId,
        SerializedOutput,
        ClaimRecipientTag,
        ClaimRecipientSide,
        ClaimRecipientOwnKey,
        ClaimRecipientKey,
        ClaimRecipientContract,
        MintNonce,
    )> {
        require_initialised(c);
        let request_id = request_id.disclose_as::<SettleRequestId>(c);
        let (entry, record) = settle_request(c, &request_id, action::DEPOSIT);
        let args = VAULT.deposit_args_map.lookup(c, &entry.in_index).stale(c);
        VAULT.deposit_args_map.remove(c, &entry.in_index);
        c.region("event consume", |c| {
            let present = VAULT.bidirectional_deposit_map.member(c, &request_id);
            c.assert(is_true(present).message("Request event missing"));
            VAULT.bidirectional_deposit_map.remove(c, &request_id);
        });

        let is_executed = executed(c, &record);
        let output = serialized_output.disclose_as::<SerializedOutput>(c);
        c.when(is_executed, |c| {
            assert_output_matches::<1>(c, &request_id, &record, &[output.field()]);
            let success = attested_success(c, output.field());
            c.when(success, |c| {
                // const claimRecipient = disclose(recipient).is_some
                //   ? disclose(recipient).value : left(ownPublicKey())
                let one = c.constant(1u64);
                let claim_recipient = c.region("recipient select", |c| {
                    let rec_is_some = recipient.is_some.field().disclose_as::<ClaimRecipientTag>(c);
                    let rec_is_left = recipient.value.is_left.field().disclose_as::<ClaimRecipientSide>(c);
                    let not_some = c.not(rec_is_some);
                    let own_pk = c.when(not_some, own_public_key).or_default().disclose_as::<ClaimRecipientOwnKey>(c);
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
                let domain_sep = vault_token_domain_separator(c, args.request.erc20_address.field());
                let amount = as_u64(c, args.request.amount);
                let mint_nonce = mint_nonce.disclose_as::<MintNonce>(c);
                common::mint_shielded_token(c, &domain_sep, amount, &mint_nonce, &claim_recipient);
            });
        });
        Discloses::of(())
    }

    // ==== Withdraw =======================================================================

    /// `export circuit startWithdraw(inIndex: Uint<64>, withdrawRequest:
    /// WithdrawRequest, coin: ShieldedCoinInfo): []` — burns the surrendered
    /// vault coin and queues `transfer(destEvmAddress, amount)`, signed by
    /// the vault's account under its gas settings.
    #[circuit]
    pub fn start_withdraw(
        c: &mut Circuit3,
        in_index: Uint<64>,
        withdraw_request: WithdrawRequest,
        coin: ShieldedCoinArg,
    ) -> Discloses<(
        WithdrawnErc20,
        SurrenderedCoinNonce,
        SurrenderedCoinColor,
        SurrenderedCoinValue,
        InIndex,
        WithdrawnAmount,
        WithdrawDestination,
        OwnershipCommitment,
    )> {
        require_initialised(c);
        c.region("guards", |c| {
            c.assert(withdraw_request.erc20_address.ne(0u64).message("ERC20 address cannot be zero"));
            c.assert(withdraw_request.dest_evm_address.ne(0u64).message("Destination address cannot be zero"));
            c.assert(withdraw_request.amount.gt(0u64).message("Amount must be positive"));
            // completeWithdraw re-mints via a Uint<64> API, so reject unrefundable amounts.
            c.assert(withdraw_request.amount.le(u64::MAX).message("Amount exceeds Uint<64> max"));
        });

        let erc20 = withdraw_request.erc20_address.disclose_as::<WithdrawnErc20>(c);
        assert_vault_coin(
            c,
            erc20.field(),
            withdraw_request.amount.field(),
            &coin,
            "Coin is not the vault token for this ERC20",
            "Coin value must equal the withdraw amount",
        );
        burn_surrendered_coin(c, coin);

        let in_index = in_index.disclose_as::<InIndex>(c);
        assert_index_free(c, &in_index, &VAULT.withdraw_args_map);

        let gas = vault_gas(c, |l| l.withdraw);
        let args = WithdrawArgs {
            request: StoredWithdrawRequest {
                erc20_address: erc20,
                amount: withdraw_request.amount.disclose_as::<WithdrawnAmount>(c),
                dest_evm_address: withdraw_request.dest_evm_address.disclose_as::<WithdrawDestination>(c),
            },
            gas,
        };
        VAULT.withdraw_args_map.insert(c, &in_index, &args);
        let zero = c.constant(0u64);
        let digest = args_hash(c, WITHDRAW_ARGS_PAD, &args);
        queue_request(c, action::WITHDRAW, true, zero, in_index, digest);
        Discloses::of(())
    }

    /// `export circuit sendWithdraw(outIndex: Bytes<32>): []` — records the
    /// flushed withdrawal's event and notifies the MPC. Permissionless.
    #[circuit]
    pub fn send_withdraw(
        c: &mut Circuit3,
        out_index: RequestIndex<Private>,
    ) -> Discloses<(OutIndex, RequestIdDisclosed, RequestRecord, XcallEntryPointHash, XcallCommitment)> {
        send_request::<VAULT_WORDS, BytesN<Private, VAULT_SCHEMA_LEN>, BytesN<Public, VAULT_SCHEMA_LEN>, WithdrawArgs>(
            c,
            out_index,
            action::WITHDRAW,
            &VAULT.withdraw_args_map,
            &VAULT.bidirectional_withdraw_map,
            VAULT_OUTPUT_SCHEMA,
            |c, entry, args| {
                let word0 = signet_v1::evm_address_abi_word(c, args.request.dest_evm_address.field().private());
                let word1 = signet_v1::numeric_abi_word(c, args.request.amount.field().private());
                let calldata = calldata(c, &TRANSFER_SELECTOR, [word0, word1]);
                let to = args.request.erc20_address.field().private();
                let tx = tx_params(c, entry, &args.gas, |_c| to, calldata, true);
                (tx, SigningPath::vault_path(c).private())
            },
            VAULT_WORDS,
            true,
        );
        Discloses::of(())
    }

    /// `export circuit completeWithdraw(requestId: RequestId, serializedOutput:
    /// Bytes<1>, mintNonce: Bytes<32>): []` — settles a withdrawal on any
    /// verdict: an executed `true` leaves the burn standing; a `false`, a
    /// failed or an unviable transaction re-mints the surrendered amount to
    /// the caller. Withdrawer-gated.
    #[circuit]
    pub fn complete_withdraw(
        c: &mut Circuit3,
        request_id: RequestId<Private>,
        serialized_output: Bytes<1>,
        mint_nonce: CoinNonce<Private>,
    ) -> Discloses<(SettleRequestId, SerializedOutput, MintNonce, Recipient)> {
        require_initialised(c);
        let request_id = request_id.disclose_as::<SettleRequestId>(c);
        let (entry, record) = settle_request(c, &request_id, action::WITHDRAW);
        let args = VAULT.withdraw_args_map.lookup(c, &entry.in_index).stale(c);
        VAULT.withdraw_args_map.remove(c, &entry.in_index);
        c.region("event consume", |c| {
            let present = VAULT.bidirectional_withdraw_map.member(c, &request_id);
            c.assert(is_true(present).message("Request event missing"));
            VAULT.bidirectional_withdraw_map.remove(c, &request_id);
        });

        let is_executed = executed(c, &record);
        let output = serialized_output.disclose_as::<SerializedOutput>(c);
        c.when(is_executed, |c| assert_output_matches::<1>(c, &request_id, &record, &[output.field()]));

        // if (outcomeRefunds(record.outputKind) || !deserialize<VaultResponse, 1>(output).success)
        let refunds = outcome_refunds(c, &record);
        let success = attested_success(c, output.field());
        let returned_false = c.not(success);
        let one = c.constant(1u64);
        let refunding = c.cond_select(refunds, one, returned_false);
        let mint_nonce = mint_nonce.disclose_as::<MintNonce>(c);
        c.when(refunding, |c| {
            let amount = as_u64(c, args.request.amount);
            let own_pk = own_public_key(c).disclose_as::<Recipient>(c);
            mint_to_key(c, args.request.erc20_address.field(), amount, &mint_nonce, &own_pk);
        });
        Discloses::of(())
    }

    // ==== Swap ===========================================================================

    /// `export circuit startSwap(inIndex: Uint<64>, swapRequest: SwapRequest,
    /// coin: ShieldedCoinInfo): []` — burns the surrendered `amountInMaximum`
    /// of the sold ERC20 and queues `exactOutputSingle` on the router,
    /// buying an allowed ERC20 into the vault's account.
    #[circuit]
    pub fn start_swap(
        c: &mut Circuit3,
        in_index: Uint<64>,
        swap_request: SwapRequest,
        coin: ShieldedCoinArg,
    ) -> Discloses<(
        BoughtErc20,
        SoldErc20,
        SurrenderedCoinNonce,
        SurrenderedCoinColor,
        SurrenderedCoinValue,
        InIndex,
        SwapFee,
        SwapAmountOut,
        SwapAmountInMaximum,
        OwnershipCommitment,
    )> {
        require_initialised(c);
        let token_out = swap_request.erc20_address_out.disclose_as::<BoughtErc20>(c);
        c.region("guards", |c| {
            c.assert(swap_request.erc20_address_in.ne(0u64).message("erc20AddressIn cannot be zero"));
            let allowed = VAULT.allowed_tokens.member(c, &token_out);
            c.assert(is_true(allowed).message("erc20AddressOut not allowed"));
            c.assert(swap_request.amount_out.gt(0u64).message("amountOut must be positive"));
            c.assert(swap_request.amount_in_maximum.gt(0u64).message("amountInMaximum must be positive"));
            // completeSwap mints both amounts via a Uint<64> API, so reject unclaimable ones.
            c.assert(swap_request.amount_out.le(u64::MAX).message("amountOut exceeds Uint<64> max"));
            c.assert(swap_request.amount_in_maximum.le(u64::MAX).message("amountInMaximum exceeds Uint<64> max"));
        });

        let token_in = swap_request.erc20_address_in.disclose_as::<SoldErc20>(c);
        assert_vault_coin(
            c,
            token_in.field(),
            swap_request.amount_in_maximum.field(),
            &coin,
            "Coin is not the vault token for erc20AddressIn",
            "Coin value must equal amountInMaximum",
        );
        burn_surrendered_coin(c, coin);

        let in_index = in_index.disclose_as::<InIndex>(c);
        assert_index_free(c, &in_index, &VAULT.swap_args_map);

        let gas = vault_gas(c, |l| l.swap);
        let args = SwapArgs {
            request: StoredSwapRequest {
                erc20_address_in: token_in,
                erc20_address_out: token_out,
                fee: swap_request.fee.disclose_as::<SwapFee>(c),
                amount_out: swap_request.amount_out.disclose_as::<SwapAmountOut>(c),
                amount_in_maximum: swap_request.amount_in_maximum.disclose_as::<SwapAmountInMaximum>(c),
            },
            gas,
        };
        VAULT.swap_args_map.insert(c, &in_index, &args);
        let zero = c.constant(0u64);
        let digest = args_hash(c, SWAP_ARGS_PAD, &args);
        queue_request(c, action::SWAP, true, zero, in_index, digest);
        Discloses::of(())
    }

    /// `export circuit sendSwap(outIndex: Bytes<32>): []` — records the
    /// flushed swap's event (`exactOutputSingle` delivering to the vault's
    /// account) and notifies the MPC. Permissionless.
    #[circuit]
    pub fn send_swap(
        c: &mut Circuit3,
        out_index: RequestIndex<Private>,
    ) -> Discloses<(OutIndex, RequestIdDisclosed, RequestRecord, XcallEntryPointHash, XcallCommitment)> {
        send_request::<SWAP_WORDS, BytesN<Private, SWAP_SCHEMA_LEN>, BytesN<Public, SWAP_SCHEMA_LEN>, SwapArgs>(
            c,
            out_index,
            action::SWAP,
            &VAULT.swap_args_map,
            &VAULT.bidirectional_swap_map,
            SWAP_OUTPUT_SCHEMA,
            |c, entry, args| {
                let zero = c.constant(0u64).private();
                let word0 = signet_v1::evm_address_abi_word(c, args.request.erc20_address_in.field().private());
                let word1 = signet_v1::evm_address_abi_word(c, args.request.erc20_address_out.field().private());
                let word2 = signet_v1::numeric_abi_word(c, args.request.fee.field().private());
                let vault_evm = VAULT.vault_evm_address.read(c).stale(c);
                let word3 = signet_v1::evm_address_abi_word(c, vault_evm.field().private());
                let word4 = signet_v1::numeric_abi_word(c, args.request.amount_out.field().private());
                let word5 = signet_v1::numeric_abi_word(c, args.request.amount_in_maximum.field().private());
                let word6 = signet_v1::numeric_abi_word(c, zero); // sqrtPriceLimitX96: no price limit
                let calldata = calldata(c, &EXACT_OUTPUT_SINGLE_SELECTOR, [word0, word1, word2, word3, word4, word5, word6]);
                let tx = tx_params(
                    c,
                    entry,
                    &args.gas,
                    |c| VAULT.uniswap_router.read(c).stale(c).field().private(),
                    calldata,
                    true,
                );
                (tx, SigningPath::vault_path(c).private())
            },
            SWAP_WORDS,
            true,
        );
        Discloses::of(())
    }

    /// `export circuit completeSwap(requestId: RequestId, serializedOutput:
    /// Bytes<32>, mintNonce, changeNonce: Bytes<32>): []` — settles a swap on
    /// any verdict: executed mints exactly `amountOut` of the bought token
    /// and the unspent `amountInMaximum − amountIn` as change; failed or
    /// unviable re-mints the surrendered `amountInMaximum`. Swapper-gated.
    #[circuit]
    pub fn complete_swap(
        c: &mut Circuit3,
        request_id: RequestId<Private>,
        serialized_output: B32<Private>,
        mint_nonce: CoinNonce<Private>,
        change_nonce: CoinNonce<Private>,
    ) -> Discloses<(SettleRequestId, Recipient, SerializedOutput, MintNonce, ChangeNonce)> {
        require_initialised(c);
        let request_id = request_id.disclose_as::<SettleRequestId>(c);
        let (entry, record) = settle_request(c, &request_id, action::SWAP);
        let args = VAULT.swap_args_map.lookup(c, &entry.in_index).stale(c);
        VAULT.swap_args_map.remove(c, &entry.in_index);
        c.region("event consume", |c| {
            let present = VAULT.bidirectional_swap_map.member(c, &request_id);
            c.assert(is_true(present).message("Request event missing"));
            VAULT.bidirectional_swap_map.remove(c, &request_id);
        });

        // const recipient = left(ownPublicKey())
        let recipient = own_public_key(c).disclose_as::<Recipient>(c);
        let is_executed = executed(c, &record);
        let output = serialized_output.disclose_as::<SerializedOutput>(c);
        let mint_nonce = mint_nonce.disclose_as::<MintNonce>(c);
        let change_nonce = change_nonce.disclose_as::<ChangeNonce>(c);
        c.when(is_executed, |c| {
            assert_output_matches::<32>(c, &request_id, &record, &[output.hi, output.lo]);
            // The two mints need distinct nonces or their coins link.
            c.assert(not(b32_eq(&change_nonce.bytes(), &mint_nonce.bytes())).message("changeNonce must differ from mintNonce"));
            let amount_out = as_u64(c, args.request.amount_out);
            mint_to_key(c, args.request.erc20_address_out.field(), amount_out, &mint_nonce, &recipient);
            // The router spends at most amountInMaximum, which start capped at Uint<64> max.
            let amount_in = signet_v1::checked_truncation_u128(c, &output);
            let amount_in = as_u64(c, amount_in);
            let change = as_u64(c, args.request.amount_in_maximum).sub_with(c, amount_in, "Attested amountIn exceeds amountInMaximum");
            mint_to_key(c, args.request.erc20_address_in.field(), change, &change_nonce, &recipient);
        });
        let refunds = outcome_refunds(c, &record);
        c.when(refunds, |c| {
            let amount = as_u64(c, args.request.amount_in_maximum);
            mint_to_key(c, args.request.erc20_address_in.field(), amount, &mint_nonce, &recipient);
        });
        Discloses::of(())
    }

    // ==== Supply =========================================================================

    /// `export circuit startSupply(inIndex: Uint<64>, supplyRequest:
    /// SupplyRequest, coin: ShieldedCoinInfo): []` — burns the surrendered
    /// underlying vault coin and queues `stataToken.deposit(amount, vault)`.
    #[circuit]
    pub fn start_supply(
        c: &mut Circuit3,
        in_index: Uint<64>,
        supply_request: SupplyRequest,
        coin: ShieldedCoinArg,
    ) -> Discloses<(
        SurrenderedCoinNonce,
        SurrenderedCoinColor,
        SurrenderedCoinValue,
        InIndex,
        SuppliedAmount,
        OwnershipCommitment,
    )> {
        require_initialised(c);
        c.region("guards", |c| {
            c.assert(supply_request.amount.gt(0u64).message("Amount must be positive"));
            c.assert(supply_request.amount.le(u64::MAX).message("Amount exceeds Uint<64> max"));
        });
        let underlying = VAULT.stata_underlying.read(c).stale(c);
        assert_vault_coin(
            c,
            underlying.field(),
            supply_request.amount.field(),
            &coin,
            "Coin is not the vault token for the underlying",
            "Coin value must equal the supply amount",
        );
        burn_surrendered_coin(c, coin);

        let in_index = in_index.disclose_as::<InIndex>(c);
        assert_index_free(c, &in_index, &VAULT.supply_args_map);

        let gas = vault_gas(c, |l| l.supply);
        let args = SupplyArgs {
            request: StoredSupplyRequest {
                amount: supply_request.amount.disclose_as::<SuppliedAmount>(c),
            },
            gas,
        };
        VAULT.supply_args_map.insert(c, &in_index, &args);
        let zero = c.constant(0u64);
        let digest = args_hash(c, SUPPLY_ARGS_PAD, &args);
        queue_request(c, action::SUPPLY, true, zero, in_index, digest);
        Discloses::of(())
    }

    /// `export circuit sendSupply(outIndex: Bytes<32>): []` — records the
    /// flushed supply's event and notifies the MPC. Permissionless.
    #[circuit]
    pub fn send_supply(
        c: &mut Circuit3,
        out_index: RequestIndex<Private>,
    ) -> Discloses<(OutIndex, RequestIdDisclosed, RequestRecord, XcallEntryPointHash, XcallCommitment)> {
        send_request::<SUPPLY_WORDS, BytesN<Private, SUPPLY_SCHEMA_LEN>, BytesN<Public, SUPPLY_SCHEMA_LEN>, SupplyArgs>(
            c,
            out_index,
            action::SUPPLY,
            &VAULT.supply_args_map,
            &VAULT.bidirectional_supply_map,
            SUPPLY_OUTPUT_SCHEMA,
            |c, entry, args| {
                // The pinned receiver keeps the shares in the vault account.
                let word0 = signet_v1::numeric_abi_word(c, args.request.amount.field().private());
                let vault_evm = VAULT.vault_evm_address.read(c).stale(c);
                let word1 = signet_v1::evm_address_abi_word(c, vault_evm.field().private());
                let calldata = calldata(c, &DEPOSIT_SELECTOR, [word0, word1]);
                let tx = tx_params(
                    c,
                    entry,
                    &args.gas,
                    |c| VAULT.stata_token.read(c).stale(c).field().private(),
                    calldata,
                    true,
                );
                (tx, SigningPath::vault_path(c).private())
            },
            SUPPLY_WORDS,
            true,
        );
        Discloses::of(())
    }

    /// `export circuit completeSupply(requestId: RequestId, serializedOutput:
    /// Bytes<32>, mintNonce: Bytes<32>): []` — executed mints the attested
    /// shares as the wrapper's vault coin; failed or unviable re-mints the
    /// surrendered underlying. Supplier-gated.
    #[circuit]
    pub fn complete_supply(
        c: &mut Circuit3,
        request_id: RequestId<Private>,
        serialized_output: B32<Private>,
        mint_nonce: CoinNonce<Private>,
    ) -> Discloses<(SettleRequestId, Recipient, SerializedOutput, MintNonce)> {
        require_initialised(c);
        let request_id = request_id.disclose_as::<SettleRequestId>(c);
        let (entry, record) = settle_request(c, &request_id, action::SUPPLY);
        let args = VAULT.supply_args_map.lookup(c, &entry.in_index).stale(c);
        VAULT.supply_args_map.remove(c, &entry.in_index);
        c.region("event consume", |c| {
            let present = VAULT.bidirectional_supply_map.member(c, &request_id);
            c.assert(is_true(present).message("Request event missing"));
            VAULT.bidirectional_supply_map.remove(c, &request_id);
        });

        let caller = own_public_key(c).disclose_as::<Recipient>(c);
        let is_executed = executed(c, &record);
        let output = serialized_output.disclose_as::<SerializedOutput>(c);
        let mint_nonce = mint_nonce.disclose_as::<MintNonce>(c);
        c.when(is_executed, |c| {
            assert_output_matches::<32>(c, &request_id, &record, &[output.hi, output.lo]);
            let stata_token = VAULT.stata_token.read(c).stale(c);
            let shares = signet_v1::checked_truncation_u128(c, &output);
            let shares = as_u64(c, shares);
            mint_to_key(c, stata_token.field(), shares, &mint_nonce, &caller);
        });
        let refunds = outcome_refunds(c, &record);
        c.when(refunds, |c| {
            let underlying = VAULT.stata_underlying.read(c).stale(c);
            let amount = as_u64(c, args.request.amount);
            mint_to_key(c, underlying.field(), amount, &mint_nonce, &caller);
        });
        Discloses::of(())
    }

    // ==== Redeem =========================================================================

    /// `export circuit startRedeem(inIndex: Uint<64>, redeemRequest:
    /// RedeemRequest, coin: ShieldedCoinInfo): []` — burns the surrendered
    /// wrapper vault coin and queues `stataToken.redeem(shares, vault, vault)`.
    #[circuit]
    pub fn start_redeem(
        c: &mut Circuit3,
        in_index: Uint<64>,
        redeem_request: RedeemRequest,
        coin: ShieldedCoinArg,
    ) -> Discloses<(
        SurrenderedCoinNonce,
        SurrenderedCoinColor,
        SurrenderedCoinValue,
        InIndex,
        RedeemedShares,
        OwnershipCommitment,
    )> {
        require_initialised(c);
        c.region("guards", |c| {
            c.assert(redeem_request.shares.gt(0u64).message("shares must be positive"));
            c.assert(redeem_request.shares.le(u64::MAX).message("shares exceeds Uint<64> max"));
        });
        let wrapper = VAULT.stata_token.read(c).stale(c);
        assert_vault_coin(
            c,
            wrapper.field(),
            redeem_request.shares.field(),
            &coin,
            "Coin is not the vault token for the wrapper",
            "Coin value must equal shares",
        );
        burn_surrendered_coin(c, coin);

        let in_index = in_index.disclose_as::<InIndex>(c);
        assert_index_free(c, &in_index, &VAULT.redeem_args_map);

        let gas = vault_gas(c, |l| l.redeem);
        let args = RedeemArgs {
            request: StoredRedeemRequest {
                shares: redeem_request.shares.disclose_as::<RedeemedShares>(c),
            },
            gas,
        };
        VAULT.redeem_args_map.insert(c, &in_index, &args);
        let zero = c.constant(0u64);
        let digest = args_hash(c, REDEEM_ARGS_PAD, &args);
        queue_request(c, action::REDEEM, true, zero, in_index, digest);
        Discloses::of(())
    }

    /// `export circuit sendRedeem(outIndex: Bytes<32>): []` — records the
    /// flushed redeem's event and notifies the MPC. Permissionless.
    #[circuit]
    pub fn send_redeem(
        c: &mut Circuit3,
        out_index: RequestIndex<Private>,
    ) -> Discloses<(OutIndex, RequestIdDisclosed, RequestRecord, XcallEntryPointHash, XcallCommitment)> {
        send_request::<REDEEM_WORDS, BytesN<Private, REDEEM_SCHEMA_LEN>, BytesN<Public, REDEEM_SCHEMA_LEN>, RedeemArgs>(
            c,
            out_index,
            action::REDEEM,
            &VAULT.redeem_args_map,
            &VAULT.bidirectional_redeem_map,
            REDEEM_OUTPUT_SCHEMA,
            |c, entry, args| {
                // The pinned receiver and owner keep the assets in, and burn the
                // shares from, the vault account — the cell is read once per word,
                // as the source spells it.
                let word0 = signet_v1::numeric_abi_word(c, args.request.shares.field().private());
                let vault_evm = VAULT.vault_evm_address.read(c).stale(c);
                let word1 = signet_v1::evm_address_abi_word(c, vault_evm.field().private());
                let vault_evm = VAULT.vault_evm_address.read(c).stale(c);
                let word2 = signet_v1::evm_address_abi_word(c, vault_evm.field().private());
                let calldata = calldata(c, &REDEEM_SELECTOR, [word0, word1, word2]);
                let tx = tx_params(
                    c,
                    entry,
                    &args.gas,
                    |c| VAULT.stata_token.read(c).stale(c).field().private(),
                    calldata,
                    true,
                );
                (tx, SigningPath::vault_path(c).private())
            },
            REDEEM_WORDS,
            true,
        );
        Discloses::of(())
    }

    /// `export circuit completeRedeem(requestId: RequestId, serializedOutput:
    /// Bytes<32>, mintNonce: Bytes<32>): []` — executed mints the attested
    /// assets as the underlying's vault coin; failed or unviable re-mints the
    /// surrendered shares. Redeemer-gated.
    #[circuit]
    pub fn complete_redeem(
        c: &mut Circuit3,
        request_id: RequestId<Private>,
        serialized_output: B32<Private>,
        mint_nonce: CoinNonce<Private>,
    ) -> Discloses<(SettleRequestId, Recipient, SerializedOutput, MintNonce)> {
        require_initialised(c);
        let request_id = request_id.disclose_as::<SettleRequestId>(c);
        let (entry, record) = settle_request(c, &request_id, action::REDEEM);
        let args = VAULT.redeem_args_map.lookup(c, &entry.in_index).stale(c);
        VAULT.redeem_args_map.remove(c, &entry.in_index);
        c.region("event consume", |c| {
            let present = VAULT.bidirectional_redeem_map.member(c, &request_id);
            c.assert(is_true(present).message("Request event missing"));
            VAULT.bidirectional_redeem_map.remove(c, &request_id);
        });

        let caller = own_public_key(c).disclose_as::<Recipient>(c);
        let is_executed = executed(c, &record);
        let output = serialized_output.disclose_as::<SerializedOutput>(c);
        let mint_nonce = mint_nonce.disclose_as::<MintNonce>(c);
        c.when(is_executed, |c| {
            assert_output_matches::<32>(c, &request_id, &record, &[output.hi, output.lo]);
            let underlying = VAULT.stata_underlying.read(c).stale(c);
            let assets = signet_v1::checked_truncation_u128(c, &output);
            let assets = as_u64(c, assets);
            mint_to_key(c, underlying.field(), assets, &mint_nonce, &caller);
        });
        let refunds = outcome_refunds(c, &record);
        c.when(refunds, |c| {
            let wrapper = VAULT.stata_token.read(c).stale(c);
            let shares = as_u64(c, args.request.shares);
            mint_to_key(c, wrapper.field(), shares, &mint_nonce, &caller);
        });
        Discloses::of(())
    }
}

// ---- the flush's two bodies ----------------------------------------------------------------

/// `flushRequest(inIndex)` — inside the slot's request guard: the queued
/// entry, the vault nonce it takes (if it signs), its output index, the
/// twin check, the move into `outputRequestBuffer` under `globalLastSeen`.
fn flush_request(c: &mut Circuit3, in_index: &Uint<64, Public>) {
    let queued_present = VAULT.input_request_buffer.member(c, in_index);
    c.assert(is_true(queued_present).message("Request not queued"));
    let queued = VAULT.input_request_buffer.lookup(c, in_index).stale(c);
    let use_next = queued.use_next_vault_account_nonce.field();

    // const entry = queued.useNextVaultAccountNonce
    //   ? RequestBufferEntry { ...queued, evmNonce: vaultAccountNonce } : queued;
    let next_nonce = c.when(use_next, |c| VAULT.vault_account_nonce.read(c)).or_default();
    let next_nonce = next_nonce.stale(c).field();
    let evm_nonce = c.cond_select(use_next, next_nonce, queued.evm_nonce.field());
    // if (queued.useNextVaultAccountNonce) { vaultAccountNonce = (vaultAccountNonce + 1) as Uint<64>; }
    c.when(use_next, |c| {
        let current = VAULT.vault_account_nonce.read(c).stale(c);
        let one = c.constant(1u64);
        let bumped = c.add(current.field(), one);
        let bumped = Uint::<64, Public>::from_field_checked(c, bumped);
        VAULT.vault_account_nonce.write(c, &bumped);
    });

    let out_index = request_index(c, evm_nonce, &queued.args_hash);
    let twin_open = VAULT.output_request_buffer.member(c, &out_index);
    c.assert(not(is_true(twin_open)).message("Identical request open"));
    VAULT.input_request_buffer.remove(c, in_index);
    let last_seen = VAULT.global_last_seen.read(c).stale(c);
    let moved = OutputRequestEntry {
        entry: RequestBufferEntry {
            evm_nonce: Uint::from_field_unchecked(evm_nonce),
            ..queued
        },
        last_seen,
    };
    VAULT.output_request_buffer.insert(c, &out_index, &moved);
}

/// `flushAttestation(requestId)` — inside the slot's attestation guard: the
/// queued record moves to `outputAttestationBuffer`, and `globalLastSeen` is
/// raised to its height if higher (the ternary's `else` arm re-reads the
/// cell, as compactc emits it).
fn flush_attestation(c: &mut Circuit3, request_id: &RequestId<Public>) {
    let queued = VAULT.input_attestation_buffer.member(c, request_id);
    c.assert(is_true(queued).message("Attestation not queued"));
    let record = VAULT.input_attestation_buffer.lookup(c, request_id).stale(c);
    VAULT.input_attestation_buffer.remove(c, request_id);
    let last_seen = VAULT.global_last_seen.read(c).stale(c);
    let higher = c.less_than(last_seen.field(), record.block_height.field(), 64);
    let not_higher = c.not(higher);
    let kept = c.when(not_higher, |c| VAULT.global_last_seen.read(c)).or_default();
    let kept = kept.stale(c).field();
    let raised = c.cond_select(higher, record.block_height.field(), kept);
    VAULT.global_last_seen.write(c, &Uint::<64, Public>::from_field_unchecked(raised));
    VAULT.output_attestation_buffer.insert(c, request_id, &record);
}

/// `sentVaultNonce(requestId, action)` — the vault account nonce a sent
/// request holds, read from its event in the action's map: an if-chain over
/// the six vault-signed actions, each arm's member check and lookup guarded
/// by the action matching, the nonce selected out of the arm that ran.
fn sent_vault_nonce(c: &mut Circuit3, request_id: &RequestId<Public>, act: &Action<Public>) -> Uint<64, Public> {
    c.assert(act.ne(action::DEPOSIT).message("Deposit has no vault nonce"));
    let is = |c: &mut Circuit3, which: u64| {
        let k = c.constant(which);
        c.test_eq(act.field(), k)
    };
    fn nonce_of<const WORDS: usize, S: SchemaBytes<Public>>(
        c: &mut Circuit3,
        map: &LedgerMap<RequestId<Public>, EventRecordV1<WORDS, S>>,
        request_id: &RequestId<Public>,
    ) -> Uint<64, Public> {
        let sent = map.member(c, request_id);
        c.assert(is_true(sent).message("Request not sent"));
        map.lookup(c, request_id).stale(c).nonce()
    }
    let withdraw = is(c, action::WITHDRAW);
    let approve = is(c, action::APPROVE);
    let swap = is(c, action::SWAP);
    let supply = is(c, action::SUPPLY);
    let redeem = is(c, action::REDEEM);
    c.when_value(withdraw, |c| nonce_of(c, &VAULT.bidirectional_withdraw_map, request_id))
        .else_when(approve, |c| nonce_of(c, &VAULT.bidirectional_approve_map, request_id))
        .else_when(swap, |c| nonce_of(c, &VAULT.bidirectional_swap_map, request_id))
        .else_when(supply, |c| nonce_of(c, &VAULT.bidirectional_supply_map, request_id))
        .else_when(redeem, |c| nonce_of(c, &VAULT.bidirectional_redeem_map, request_id))
        .otherwise(|c| nonce_of(c, &VAULT.bidirectional_replace_nonce_map, request_id))
        .into_inner()
}

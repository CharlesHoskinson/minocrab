//! The sig-net corpus contracts, rewritten in the MinoCrab eDSL.
//!
//! Milestone 4: each contract here is a mechanical rewrite of its Compact
//! original (corpus/src/signet-*), and each circuit carries a differential
//! test against compactc's compiled artifact — call-compatibility per
//! notes/ledger-abi.org §6 (same typed I/O schema, same pis/pi_skips on a
//! shared preimage).

pub mod adts;
pub mod attest;
pub mod bounded;
pub mod bounded_ledger;
pub mod coins;
pub mod common;
pub mod erc20_vault;
pub mod erc20_vault_pending;
pub mod evm;
pub mod evm_flow;
pub mod events;
pub mod events_borsh;
pub mod hashing;
pub mod interfaces;
pub mod kernel_tokens;
pub mod manager;
pub mod mint_tokens;
pub mod nested;
pub mod opaque;
pub mod serde_builtin;
pub mod signet;
pub mod signet_v1;
pub mod signet_flow;
pub mod signet_contract;
pub mod test_caller;
pub mod treasury;
pub mod xcall;
pub mod xcall_with_payment;
pub mod xcontract_events;
pub mod xcontract_events_borsh;

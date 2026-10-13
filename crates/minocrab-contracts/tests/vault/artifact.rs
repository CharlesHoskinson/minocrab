//! The vault's twenty-nine circuits, named independently of the module that
//! builds them, with each one's compactc `.zkir` stem.
//!
//! One artifact since M28: the compat port, PI-equal to compactc's (the
//! flush-pattern vault since M44).

use minocrab::v3::Compiled3;
use minocrab_contracts::erc20_vault;
use minocrab_zkir::v3::IrSource;

/// One vault circuit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Circuit {
    Initialise,
    SetGasParams,
    AddAllowedToken,
    FlushQueue,
    QueueAttestation0,
    QueueAttestation1,
    QueueAttestation32,
    StartReplaceNonce,
    SendReplaceNonce,
    CompleteReplaceNonce,
    StartApproveRouter,
    StartApproveStata,
    SendApprove,
    CompleteApprove,
    StartDeposit,
    SendDeposit,
    CompleteDeposit,
    StartWithdraw,
    SendWithdraw,
    CompleteWithdraw,
    StartSwap,
    SendSwap,
    CompleteSwap,
    StartSupply,
    SendSupply,
    CompleteSupply,
    StartRedeem,
    SendRedeem,
    CompleteRedeem,
}

impl Circuit {
    pub const ALL: [Circuit; 29] = [
        Circuit::Initialise,
        Circuit::SetGasParams,
        Circuit::AddAllowedToken,
        Circuit::FlushQueue,
        Circuit::QueueAttestation0,
        Circuit::QueueAttestation1,
        Circuit::QueueAttestation32,
        Circuit::StartReplaceNonce,
        Circuit::SendReplaceNonce,
        Circuit::CompleteReplaceNonce,
        Circuit::StartApproveRouter,
        Circuit::StartApproveStata,
        Circuit::SendApprove,
        Circuit::CompleteApprove,
        Circuit::StartDeposit,
        Circuit::SendDeposit,
        Circuit::CompleteDeposit,
        Circuit::StartWithdraw,
        Circuit::SendWithdraw,
        Circuit::CompleteWithdraw,
        Circuit::StartSwap,
        Circuit::SendSwap,
        Circuit::CompleteSwap,
        Circuit::StartSupply,
        Circuit::SendSupply,
        Circuit::CompleteSupply,
        Circuit::StartRedeem,
        Circuit::SendRedeem,
        Circuit::CompleteRedeem,
    ];

    /// The compactc `.zkir` stem — also the dumped preimage stem the
    /// benchmark harness reads.
    pub fn zkir_name(self) -> &'static str {
        match self {
            Circuit::Initialise => "initialise",
            Circuit::SetGasParams => "setGasParams",
            Circuit::AddAllowedToken => "addAllowedToken",
            Circuit::FlushQueue => "flushQueue",
            Circuit::QueueAttestation0 => "queueAttestation0",
            Circuit::QueueAttestation1 => "queueAttestation1",
            Circuit::QueueAttestation32 => "queueAttestation32",
            Circuit::StartReplaceNonce => "startReplaceNonce",
            Circuit::SendReplaceNonce => "sendReplaceNonce",
            Circuit::CompleteReplaceNonce => "completeReplaceNonce",
            Circuit::StartApproveRouter => "startApproveRouter",
            Circuit::StartApproveStata => "startApproveStata",
            Circuit::SendApprove => "sendApprove",
            Circuit::CompleteApprove => "completeApprove",
            Circuit::StartDeposit => "startDeposit",
            Circuit::SendDeposit => "sendDeposit",
            Circuit::CompleteDeposit => "completeDeposit",
            Circuit::StartWithdraw => "startWithdraw",
            Circuit::SendWithdraw => "sendWithdraw",
            Circuit::CompleteWithdraw => "completeWithdraw",
            Circuit::StartSwap => "startSwap",
            Circuit::SendSwap => "sendSwap",
            Circuit::CompleteSwap => "completeSwap",
            Circuit::StartSupply => "startSupply",
            Circuit::SendSupply => "sendSupply",
            Circuit::CompleteSupply => "completeSupply",
            Circuit::StartRedeem => "startRedeem",
            Circuit::SendRedeem => "sendRedeem",
            Circuit::CompleteRedeem => "completeRedeem",
        }
    }

    pub fn build(self) -> Compiled3 {
        match self {
            Circuit::Initialise => erc20_vault::Vault::initialise(),
            Circuit::SetGasParams => erc20_vault::Vault::set_gas_params(),
            Circuit::AddAllowedToken => erc20_vault::Vault::add_allowed_token(),
            Circuit::FlushQueue => erc20_vault::Vault::flush_queue(),
            Circuit::QueueAttestation0 => erc20_vault::Vault::queue_attestation0(),
            Circuit::QueueAttestation1 => erc20_vault::Vault::queue_attestation1(),
            Circuit::QueueAttestation32 => erc20_vault::Vault::queue_attestation32(),
            Circuit::StartReplaceNonce => erc20_vault::Vault::start_replace_nonce(),
            Circuit::SendReplaceNonce => erc20_vault::Vault::send_replace_nonce(),
            Circuit::CompleteReplaceNonce => erc20_vault::Vault::complete_replace_nonce(),
            Circuit::StartApproveRouter => erc20_vault::Vault::start_approve_router(),
            Circuit::StartApproveStata => erc20_vault::Vault::start_approve_stata(),
            Circuit::SendApprove => erc20_vault::Vault::send_approve(),
            Circuit::CompleteApprove => erc20_vault::Vault::complete_approve(),
            Circuit::StartDeposit => erc20_vault::Vault::start_deposit(),
            Circuit::SendDeposit => erc20_vault::Vault::send_deposit(),
            Circuit::CompleteDeposit => erc20_vault::Vault::complete_deposit(),
            Circuit::StartWithdraw => erc20_vault::Vault::start_withdraw(),
            Circuit::SendWithdraw => erc20_vault::Vault::send_withdraw(),
            Circuit::CompleteWithdraw => erc20_vault::Vault::complete_withdraw(),
            Circuit::StartSwap => erc20_vault::Vault::start_swap(),
            Circuit::SendSwap => erc20_vault::Vault::send_swap(),
            Circuit::CompleteSwap => erc20_vault::Vault::complete_swap(),
            Circuit::StartSupply => erc20_vault::Vault::start_supply(),
            Circuit::SendSupply => erc20_vault::Vault::send_supply(),
            Circuit::CompleteSupply => erc20_vault::Vault::complete_supply(),
            Circuit::StartRedeem => erc20_vault::Vault::start_redeem(),
            Circuit::SendRedeem => erc20_vault::Vault::send_redeem(),
            Circuit::CompleteRedeem => erc20_vault::Vault::complete_redeem(),
        }
    }

    pub fn ir(self) -> IrSource {
        self.build().ir
    }

    /// compactc's own artifact, parsed once per circuit.
    pub fn corpus(self) -> &'static IrSource {
        use std::collections::HashMap;
        use std::sync::OnceLock;
        static TWINS: OnceLock<HashMap<Circuit, IrSource>> = OnceLock::new();
        &TWINS.get_or_init(|| {
            Circuit::ALL
                .iter()
                .map(|c| (*c, super::prims::corpus_zkir_named(c.zkir_name())))
                .collect()
        })[&self]
    }
}

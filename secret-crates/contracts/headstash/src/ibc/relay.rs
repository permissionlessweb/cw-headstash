//! This module contains the entry points for:
//! - The IBC packet acknowledgement.
//! - The IBC packet timeout.
//! - The IBC packet receive.

use cosmwasm_std::entry_point;
use cosmwasm_std::{
    from_binary, DepsMut, Env, IbcBasicResponse, IbcPacketAckMsg, IbcPacketReceiveMsg,
    IbcPacketTimeoutMsg, IbcReceiveResponse,
};

use crate::error::ContractError;
use crate::state;
use crate::types::cosmos_msg::Never;

use super::types::{events, packet::acknowledgement::Data as AcknowledgementData};

/// Implements the IBC module's `OnAcknowledgementPacket` handler.
///
/// # Errors
///
/// This function returns an error if:
///
/// - The acknowledgement data is invalid.
/// - [`ibc_packet_ack::success`] or [`ibc_packet_ack::error`] returns an error.
#[entry_point]
#[allow(clippy::needless_pass_by_value)]
pub fn ibc_packet_ack(
    deps: DepsMut,
    _env: Env,
    ack: IbcPacketAckMsg,
) -> Result<IbcBasicResponse, ContractError> {
    // This lets the ICA controller know whether or not the sent transactions succeeded.
    match from_binary(&ack.acknowledgement.data)? {
        AcknowledgementData::Result(res) => {
            ibc_packet_ack::success(deps, ack.original_packet, ack.relayer, res)
        }
        AcknowledgementData::Error(err) => {
            ibc_packet_ack::error(deps, ack.original_packet, ack.relayer, err)
        }
    }
}

/// Implements the IBC module's `OnTimeoutPacket` handler.
///
/// # Errors
///
/// This function returns an error if:
///
/// - [`ibc_packet_timeout::callback`] returns an error.
/// - The channel state cannot be loaded or saved.
#[entry_point]
#[allow(clippy::needless_pass_by_value)]
pub fn ibc_packet_timeout(
    deps: DepsMut,
    _env: Env,
    msg: IbcPacketTimeoutMsg,
) -> Result<IbcBasicResponse, ContractError> {
    // If the channel is ordered, close it.
    let mut channel_state = state::CHANNEL_STATE.load(deps.storage)?;
    if channel_state.is_ordered() {
        channel_state.close();
        state::CHANNEL_STATE.save(deps.storage, &channel_state)?;
    }

    ibc_packet_timeout::callback(deps, msg.packet, msg.relayer)
}

/// Implements the IBC module's `OnRecvPacket` handler.
///
/// # Panics
/// Always panics because the ICA controller cannot receive packets.
#[entry_point]
#[allow(clippy::needless_pass_by_value, clippy::missing_errors_doc)]
pub fn ibc_packet_receive(
    _deps: DepsMut,
    _env: Env,
    _msg: IbcPacketReceiveMsg,
) -> Result<IbcReceiveResponse, Never> {
    // An ICA controller cannot receive packets, so this is a panic.
    // It must be implemented to satisfy the wasmd interface.
    unreachable!("ICA controller cannot receive packets")
}

mod ibc_packet_ack {
    use cosmwasm_std::{Addr, Binary, IbcPacket};

    use crate::types::callbacks::IcaControllerCallbackMsg;

    use super::{events, state, AcknowledgementData, ContractError, DepsMut, IbcBasicResponse};

    /// Handles the successful acknowledgement of an ica packet. This means that the
    /// transaction was successfully executed on the host chain.
    #[allow(clippy::needless_pass_by_value)]
    pub fn success(
        deps: DepsMut,
        packet: IbcPacket,
        relayer: Addr,
        res: Binary,
    ) -> Result<IbcBasicResponse, ContractError> {
        let state = state::STATE.load(deps.storage)?;

        let success_event = events::packet_ack::success(&packet, &res);

        if let Some(contract) = state.callback_contract {
            let callback_msg = IcaControllerCallbackMsg::OnAcknowledgementPacketCallback {
                ica_acknowledgement: AcknowledgementData::Result(res),
                original_packet: packet,
                relayer,
            }
            .into_cosmos_msg(contract.address, contract.code_hash)?;

            Ok(IbcBasicResponse::default()
                .add_message(callback_msg)
                .add_event(success_event))
        } else {
            Ok(IbcBasicResponse::default().add_event(success_event))
        }
    }

    #[allow(clippy::needless_pass_by_value)]
    pub fn error(
        deps: DepsMut,
        packet: IbcPacket,
        relayer: Addr,
        err: String,
    ) -> Result<IbcBasicResponse, ContractError> {
        let state = state::STATE.load(deps.storage)?;

        let error_event = events::packet_ack::error(&packet, &err);

        if let Some(contract) = state.callback_contract {
            let callback_msg = IcaControllerCallbackMsg::OnAcknowledgementPacketCallback {
                ica_acknowledgement: AcknowledgementData::Error(err),
                original_packet: packet,
                relayer,
            }
            .into_cosmos_msg(contract.address, contract.code_hash)?;

            Ok(IbcBasicResponse::default()
                .add_message(callback_msg)
                .add_event(error_event))
        } else {
            Ok(IbcBasicResponse::default().add_event(error_event))
        }
    }
}

mod ibc_packet_timeout {
    use cosmwasm_std::{Addr, IbcPacket};

    use crate::{
        state::{self, STATE},
        types::callbacks::IcaControllerCallbackMsg,
    };

    use super::{ContractError, DepsMut, IbcBasicResponse};

    /// Handles the timeout callbacks.
    #[allow(clippy::needless_pass_by_value)]
    pub fn callback(
        deps: DepsMut,
        packet: IbcPacket,
        relayer: Addr,
    ) -> Result<IbcBasicResponse, ContractError> {
        let state = STATE.load(deps.storage)?;

        if let Some(contract) = state.callback_contract {
            let callback_msg = IcaControllerCallbackMsg::OnTimeoutPacketCallback {
                original_packet: packet,
                relayer,
            }
            .into_cosmos_msg(contract.address, contract.code_hash)?;

            Ok(IbcBasicResponse::default().add_message(callback_msg))
        } else {
            Ok(IbcBasicResponse::default())
        }
    }
}

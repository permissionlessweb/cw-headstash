//! This module handles the execution logic of the contract.

use cosmwasm_std::{entry_point, Addr, Reply, SubMsg};
use cosmwasm_std::{to_json_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult};

use crate::ibc::types::stargate::channel::new_ica_channel_open_init_cosmos_msg;
use crate::types::keys;
use crate::types::msg::{ExecuteMsg, InstantiateMsg, MigrateMsg, QueryMsg};
use crate::types::state::{self, ChannelState, ContractState, UPLOAD_REPLY_ID};
use crate::types::ContractError;

/// Custom Reply id
pub const CUSTOM_CALLBACK: &str = "ica_callback_id";

/// Instantiates the contract.
#[entry_point]
#[allow(clippy::pedantic)]
pub fn instantiate(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    cw2::set_contract_version(deps.storage, keys::CONTRACT_NAME, keys::CONTRACT_VERSION)?;

    let owner = msg.owner.unwrap_or_else(|| info.sender.to_string());
    cw_ownable::initialize_owner(deps.storage, deps.api, Some(&owner))?;

    let callback_address = msg
        .send_callbacks_to
        .map(|addr| deps.api.addr_validate(&addr))
        .transpose()?;

    // Save the admin. Ica address is determined during handshake. Save headstash params.
    state::STATE.save(deps.storage, &ContractState::new(callback_address))?;

    state::CHANNEL_OPEN_INIT_OPTIONS.save(deps.storage, &msg.channel_open_init_options)?;

    state::ALLOW_CHANNEL_OPEN_INIT.save(deps.storage, &true)?;

    let ica_channel_open_init_msg = new_ica_channel_open_init_cosmos_msg(
        env.contract.address.to_string(),
        msg.channel_open_init_options.connection_id,
        msg.channel_open_init_options.counterparty_port_id,
        msg.channel_open_init_options.counterparty_connection_id,
        None,
        msg.channel_open_init_options.channel_ordering,
    );

    // CW_GLOB.save(deps.storage, &deps.api.addr_validate(&msg.cw_glob)?)?;

    Ok(Response::new().add_message(ica_channel_open_init_msg))
}

/// Handles the execution of the contract.
#[entry_point]
#[allow(clippy::pedantic)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::CreateChannel {
            channel_open_init_options,
        } => execute::create_channel(deps, env, info, channel_open_init_options),
        ExecuteMsg::CloseChannel {} => execute::close_channel(deps, info),
        ExecuteMsg::UpdateCallbackAddress { callback_address } => {
            execute::update_callback_address(deps, info, callback_address)
        }
        ExecuteMsg::SendCosmosMsgs {
            messages,
            queries,
            packet_memo,
            timeout_seconds,
        } => execute::send_cosmos_msgs(
            deps,
            env,
            info,
            messages,
            queries,
            packet_memo,
            timeout_seconds,
        ),
        ExecuteMsg::UpdateOwnership(action) => execute::update_ownership(deps, env, info, action),
        ExecuteMsg::SendUploadMsg {
            cw_glob,
            glob_key,
            packet_memo,
            timeout_seconds,
        } => execute::upload_wasm_blob(
            deps,
            env,
            info,
            glob_key,
            cw_glob,
            packet_memo,
            timeout_seconds,
        ),
        ExecuteMsg::SetGlob { cw_glob } => execute::set_cw_glob(deps, env, info, cw_glob),
    }
}

/// Handles the replies to the submessages.
#[entry_point]
#[allow(clippy::pedantic)]
pub fn reply(deps: DepsMut, env: Env, msg: Reply) -> Result<Response, ContractError> {
    match &msg.result {
        cosmwasm_std::SubMsgResult::Ok(res) => match msg.id {
            keys::reply_ids::SEND_QUERY_PACKET => {
                reply_helper::send_query_packet(deps, env, msg.result)
            }
            UPLOAD_REPLY_ID => {
                // Extract the event attributes
                let event = res
                    .events
                    .iter()
                    .find(|e| e.ty == "wasm-headstash")
                    .expect("InvalidEvent");

                // message from cw-glob to broadcast
                #[allow(deprecated)]
                let wasm_blob = res.data.clone();
                // sender (will be ica-account)
                let sender = event.attributes.iter().find(|a| a.key == "sender");
                // optional memo
                let memo = event.attributes.iter().find(|a| a.key == "memo");
                // ibc packet timeout
                let timeout = event.attributes.iter().find(|a| a.key == "timeout");

                if wasm_blob.is_none() {
                    return Err(ContractError::MissingAttribute("wasm_blob".into()));
                } else if sender.is_none() {
                    return Err(ContractError::MissingAttribute("sender".to_string()));
                } else if memo.is_none() {
                    return Err(ContractError::MissingAttribute("memo".to_string()));
                } else if timeout.is_none() {
                    return Err(ContractError::MissingAttribute("timeout".to_string()));
                }

                let sender = &sender.unwrap().value;
                let memo = &memo.unwrap().value;
                let timeout_seconds = &timeout.unwrap().value;

                // Form StargateMsg
                let upload_msg = helpers::upload_contract_msg(
                    Addr::unchecked(sender.clone()),
                    &wasm_blob.unwrap(),
                )?;

                // send msg with wasm from glob as ica
                let ica_info = state::STATE.load(deps.storage)?.get_ica_info()?;

                // prepare ICA packet data
                let ica_packet = crate::ibc::types::packet::IcaPacketData::from_cosmos_msgs(
                    deps.storage,
                    vec![upload_msg],
                    vec![],
                    &ica_info.encoding,
                    Some(memo.to_string()),
                    &ica_info.ica_address,
                )?;
                // form IbcMsg
                let send_packet_msg = ica_packet.to_ibc_msg(
                    &env,
                    ica_info.channel_id,
                    Some(u64::from_str_radix(&timeout_seconds, 10)?),
                )?;

                // respond with submessage
                return Ok(Response::new().add_submessage(SubMsg::new(send_packet_msg)));
            }
            _ => Err(ContractError::UnknownReplyId(msg.id)),
        },
        cosmwasm_std::SubMsgResult::Err(a) => {
            return Err(ContractError::SubMsgError(a.to_string()))
        }
    }
}

/// Handles the query of the contract.
#[entry_point]
#[allow(clippy::pedantic)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetContractState {} => to_json_binary(&query::state(deps)?),
        QueryMsg::GetChannel {} => to_json_binary(&query::channel(deps)?),
        QueryMsg::Ownership {} => to_json_binary(&cw_ownable::get_ownership(deps.storage)?),
    }
}

/// Migrate contract if version is lower than current version
#[entry_point]
#[allow(clippy::pedantic)]
pub fn migrate(deps: DepsMut, _env: Env, _msg: MigrateMsg) -> Result<Response, ContractError> {
    migrate::validate_semver(deps.as_ref())?;
    migrate::validate_channel_encoding(deps.as_ref())?;

    cw2::set_contract_version(deps.storage, keys::CONTRACT_NAME, keys::CONTRACT_VERSION)?;
    // If state structure changed in any contract version in the way migration is needed, it
    // should occur here

    Ok(Response::default())
}

mod execute {
    use super::CUSTOM_CALLBACK;
    use crate::{
        ibc::types::packet::IcaPacketData,
        types::{
            msg::{options::ChannelOpenInitOptions, HeadstashCallback},
            state::{CW_GLOB, UPLOAD_REPLY_ID},
        },
    };
    use cosmwasm_std::{Addr, CosmosMsg, IbcMsg, SubMsg};

    use super::{
        keys, new_ica_channel_open_init_cosmos_msg, state, ContractError, DepsMut, Env,
        MessageInfo, Response,
    };

    use cosmwasm_std::{Empty, QueryRequest};

    pub fn set_cw_glob(
        deps: DepsMut,
        _env: Env,
        info: MessageInfo,
        cw_glob: String,
    ) -> Result<Response, ContractError> {
        cw_ownable::assert_owner(deps.storage, &info.sender)?;

        if CW_GLOB.may_load(deps.storage)?.is_some() {
            return Err(ContractError::GlobAlreadySet {});
        } else {
            CW_GLOB.save(deps.storage, &deps.api.addr_validate(&cw_glob)?)?;
        }
        Ok(Response::new())
    }

    /// Retrieves the wasm-blob from cw-glob, replies with ica msg to upload blob.
    pub fn upload_wasm_blob(
        deps: DepsMut,
        _env: Env,
        info: MessageInfo,
        wasm: String,
        cw_glob: Option<Addr>,
        memo: Option<String>,
        timeout: Option<u64>,
    ) -> Result<Response, ContractError> {
        cw_ownable::assert_owner(deps.storage, &info.sender)?;
        let contract_state = state::STATE.load(deps.storage)?;
        let ica_info = contract_state.get_ica_info()?;

        let glob = match cw_glob {
            Some(a) => a,
            None => CW_GLOB.load(deps.storage)?,
        };

        // grab the msg to upload wasm via ica-controller from cw-glob
        let upload_msg = super::helpers::cw_glob_execute(
            glob,
            cw_glob::msg::ExecuteMsg::TakeGlob {
                sender: ica_info.ica_address.clone(),
                key: wasm,
                memo,
                timeout,
            },
        )?;

        Ok(Response::new()
            .add_submessage(SubMsg::reply_always(upload_msg, UPLOAD_REPLY_ID))
            .add_attribute(CUSTOM_CALLBACK, HeadstashCallback::UploadHeadstash))
    }

    /// Submits a stargate `MsgChannelOpenInit` to the chain.
    /// Can only be called by the contract owner or a whitelisted address.
    /// Only the contract owner can include the channel open init options.
    #[allow(clippy::needless_pass_by_value)]
    pub fn create_channel(
        deps: DepsMut,
        env: Env,
        info: MessageInfo,
        options: Option<ChannelOpenInitOptions>,
    ) -> Result<Response, ContractError> {
        cw_ownable::assert_owner(deps.storage, &info.sender)?;

        let options = if let Some(new_options) = options {
            state::CHANNEL_OPEN_INIT_OPTIONS.save(deps.storage, &new_options)?;
            new_options
        } else {
            state::CHANNEL_OPEN_INIT_OPTIONS
                .may_load(deps.storage)?
                .ok_or(ContractError::NoChannelInitOptions)?
        };

        state::ALLOW_CHANNEL_OPEN_INIT.save(deps.storage, &true)?;

        let ica_channel_open_init_msg = new_ica_channel_open_init_cosmos_msg(
            env.contract.address.to_string(),
            options.connection_id,
            options.counterparty_port_id,
            options.counterparty_connection_id,
            None,
            options.channel_ordering,
        );

        Ok(Response::new().add_message(ica_channel_open_init_msg))
    }

    /// Submits a [`IbcMsg::CloseChannel`].
    #[allow(clippy::needless_pass_by_value)]
    pub fn close_channel(deps: DepsMut, info: MessageInfo) -> Result<Response, ContractError> {
        cw_ownable::assert_owner(deps.storage, &info.sender)?;

        let channel_state = state::CHANNEL_STATE.load(deps.storage)?;
        if !channel_state.is_open() {
            return Err(ContractError::InvalidChannelStatus {
                expected: state::ChannelStatus::Open.to_string(),
                actual: channel_state.channel_status.to_string(),
            });
        }

        state::ALLOW_CHANNEL_CLOSE_INIT.save(deps.storage, &true)?;

        let channel_close_msg = CosmosMsg::Ibc(IbcMsg::CloseChannel {
            channel_id: channel_state.channel.endpoint.channel_id,
        });

        Ok(Response::new().add_message(channel_close_msg))
    }

    /// Sends an array of [`CosmosMsg`] to the ICA host.
    #[allow(clippy::needless_pass_by_value)]
    pub fn send_cosmos_msgs(
        deps: DepsMut,
        env: Env,
        info: MessageInfo,
        messages: Vec<CosmosMsg>,
        queries: Vec<QueryRequest<Empty>>,
        packet_memo: Option<String>,
        timeout_seconds: Option<u64>,
    ) -> Result<Response, ContractError> {
        cw_ownable::assert_owner(deps.storage, &info.sender)?;

        let contract_state = state::STATE.load(deps.storage)?;
        let ica_info = contract_state.get_ica_info()?;
        let has_queries = !queries.is_empty();

        let ica_packet = IcaPacketData::from_cosmos_msgs(
            deps.storage,
            messages,
            queries,
            &ica_info.encoding,
            packet_memo,
            &ica_info.ica_address,
        )?;
        let send_packet_msg = ica_packet.to_ibc_msg(&env, ica_info.channel_id, timeout_seconds)?;

        let send_packet_submsg = if has_queries {
            // TODO: use payload when we switch to cosmwasm_2_0 feature
            SubMsg::reply_on_success(send_packet_msg, keys::reply_ids::SEND_QUERY_PACKET)
        } else {
            SubMsg::new(send_packet_msg)
        };

        Ok(Response::default().add_submessage(send_packet_submsg))
    }

    /// Update the ownership of the contract.
    #[allow(clippy::needless_pass_by_value)]
    pub fn update_ownership(
        deps: DepsMut,
        env: Env,
        info: MessageInfo,
        action: cw_ownable::Action,
    ) -> Result<Response, ContractError> {
        if action == cw_ownable::Action::RenounceOwnership {
            return Err(ContractError::OwnershipCannotBeRenounced);
        };

        cw_ownable::update_ownership(deps, &env.block, &info.sender, action)?;

        Ok(Response::default())
    }

    /// Updates the callback address.
    #[allow(clippy::needless_pass_by_value)]
    pub fn update_callback_address(
        deps: DepsMut,
        info: MessageInfo,
        callback_address: Option<String>,
    ) -> Result<Response, ContractError> {
        cw_ownable::assert_owner(deps.storage, &info.sender)?;

        let mut contract_state = state::STATE.load(deps.storage)?;

        contract_state.callback_address = callback_address
            .map(|addr| deps.api.addr_validate(&addr))
            .transpose()?;

        state::STATE.save(deps.storage, &contract_state)?;

        Ok(Response::default())
    }
}

mod reply_helper {
    use cosmwasm_std::SubMsgResult;

    use super::{state, ContractError, DepsMut, Env, Response};

    /// Handles the reply to the query packet.
    #[allow(clippy::needless_pass_by_value)]
    pub fn send_query_packet(
        deps: DepsMut,
        _env: Env,
        result: SubMsgResult,
    ) -> Result<Response, ContractError> {
        match result {
            SubMsgResult::Ok(resp) => {
                #[allow(deprecated)] // TODO: Remove deprecated `.data` field
                let sequence = anybuf::Bufany::deserialize(&resp.data.unwrap_or_default())?
                    .uint64(1)
                    .unwrap();
                let channel_id = state::STATE.load(deps.storage)?.get_ica_info()?.channel_id;
                let query_paths = state::QUERY.load(deps.storage)?;

                state::QUERY.remove(deps.storage);
                state::PENDING_QUERIES.save(deps.storage, (&channel_id, sequence), &query_paths)?;

                Ok(Response::default())
            }
            SubMsgResult::Err(err) => unreachable!("query packet failed: {err}"),
        }
    }
}

mod helpers {
    use super::*;
    use anybuf::Anybuf;
    use cosmwasm_std::{CosmosMsg, Empty, StdError};

    /// Defines the msg to instantiate the headstash contract
    pub fn cw_glob_execute(
        cw_glob: Addr,
        msg: cw_glob::msg::ExecuteMsg,
    ) -> Result<CosmosMsg, ContractError> {
        Ok(CosmosMsg::<Empty>::Wasm(cosmwasm_std::WasmMsg::Execute {
            contract_addr: cw_glob.to_string(),
            msg: to_json_binary(&msg)?,
            funds: vec![],
        }))
    }

    /// Defines the msg to upload the nested wasm blobs.
    pub fn upload_contract_msg(
        sender: ::cosmwasm_std::Addr,
        wasm: &Binary,
    ) -> Result<CosmosMsg, StdError> {
        Ok(
            #[allow(deprecated)]
            CosmosMsg::Stargate {
                type_url: "/secret.compute.v1beta1.MsgStoreCode".into(),
                value: Anybuf::new()
                    .append_string(1, sender.clone()) // sender (DAO)
                    .append_bytes(2, &wasm) // updated binary of transfer msg.
                    .into_vec()
                    .into(),
            },
        )
    }
}

mod query {
    use super::{state, ChannelState, ContractState, Deps, StdResult};

    /// Returns the saved contract state.
    pub fn state(deps: Deps) -> StdResult<ContractState> {
        state::STATE.load(deps.storage)
    }

    /// Returns the saved channel state if it exists.
    pub fn channel(deps: Deps) -> StdResult<ChannelState> {
        state::CHANNEL_STATE.load(deps.storage)
    }
}

mod migrate {
    use super::{keys, state, ContractError, Deps};

    /// Validate that the contract version is semver compliant
    /// and greater than the previous version.
    pub fn validate_semver(deps: Deps) -> Result<(), ContractError> {
        let prev_cw2_version = cw2::get_contract_version(deps.storage)?;
        if prev_cw2_version.contract != keys::CONTRACT_NAME {
            return Err(ContractError::InvalidMigrationVersion {
                expected: keys::CONTRACT_NAME.to_string(),
                actual: prev_cw2_version.contract,
            });
        }

        let version: semver::Version = keys::CONTRACT_VERSION.parse()?;
        let prev_version: semver::Version = prev_cw2_version.version.parse()?;
        if prev_version >= version {
            return Err(ContractError::InvalidMigrationVersion {
                expected: format!("> {prev_version}"),
                actual: keys::CONTRACT_VERSION.to_string(),
            });
        }
        Ok(())
    }

    /// Validate that the channel encoding is protobuf if set.
    pub fn validate_channel_encoding(deps: Deps) -> Result<(), ContractError> {
        // Reject the migration if the channel encoding is not protobuf
        if let Some(ica_info) = state::STATE.load(deps.storage)?.ica_info {
            if !matches!(
                ica_info.encoding,
                crate::ibc::types::metadata::TxEncoding::Protobuf
            ) {
                return Err(ContractError::UnsupportedPacketEncoding(
                    ica_info.encoding.to_string(),
                ));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::any::Any;

    use crate::types::msg::options::ChannelOpenInitOptions;

    use super::*;
    use cosmwasm_std::testing::{message_info, mock_dependencies, mock_env};
    use cosmwasm_std::{
        Api, CosmosMsg, Empty, Event, IbcTimeout, IbcTimeoutBlock, StdError, SubMsg,
    };
    // use state::headstash::HeadstashTokenParams;

    #[test]
    fn test_instantiate() {
        let mut deps = mock_dependencies();

        let creator = deps.api.addr_make("creator");
        // let cw_glob = deps.api.addr_make("cw_glob");
        let info = message_info(&creator, &[]);
        let env = mock_env();

        let channel_open_init_options = ChannelOpenInitOptions {
            connection_id: "connection-0".to_string(),
            counterparty_connection_id: "connection-1".to_string(),
            counterparty_port_id: None,
            channel_ordering: None,
        };

        let msg = InstantiateMsg {
            owner: None,
            channel_open_init_options: channel_open_init_options.clone(),
            send_callbacks_to: None,
        };

        let res = instantiate(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();

        // Ensure that the channel open init options are saved correctly
        assert_eq!(
            state::CHANNEL_OPEN_INIT_OPTIONS
                .load(deps.as_ref().storage)
                .unwrap(),
            channel_open_init_options
        );

        // Ensure the contract is instantiated successfully
        assert_eq!(1, res.messages.len());

        let expected_msg = new_ica_channel_open_init_cosmos_msg(
            env.contract.address.to_string(),
            channel_open_init_options.connection_id,
            channel_open_init_options.counterparty_port_id,
            channel_open_init_options.counterparty_connection_id,
            None,
            channel_open_init_options.channel_ordering,
        );
        assert_eq!(res.messages[0], SubMsg::new(expected_msg));

        // Ensure the admin is saved correctly
        let owner = cw_ownable::get_ownership(&deps.storage)
            .unwrap()
            .owner
            .unwrap();
        assert_eq!(owner, info.sender);

        // Ensure that the contract name and version are saved correctly
        let contract_version = cw2::get_contract_version(&deps.storage).unwrap();
        assert_eq!(contract_version.contract, keys::CONTRACT_NAME);
        assert_eq!(contract_version.version, keys::CONTRACT_VERSION);
    }

    #[test]
    fn test_headstash_replies() {
        // simulated testing environment
        let mut deps = mock_dependencies();
        let env = mock_env();

        // simulated addrs
        let creator = deps.api.addr_make("creator");
        let owner = deps.api.addr_make("owner");
        // let cw_glob = deps.api.addr_make("cw-glob");
        let ica_addr = deps.api.addr_make("ica-addr");

        // simulated message info
        let info_owner = message_info(&owner, &[]);
        let info_creator = message_info(&creator, &[]);

        let channel_open_init_options = ChannelOpenInitOptions {
            connection_id: "connection-0".to_string(),
            counterparty_connection_id: "connection-1".to_string(),
            counterparty_port_id: None,
            channel_ordering: None,
        };

        // Instantiate the contract
        let _res = instantiate(
            deps.as_mut(),
            env.clone(),
            info_creator.clone(),
            InstantiateMsg {
                owner: Some(owner.to_string()),
                channel_open_init_options,
                send_callbacks_to: Some(owner.to_string()),
            },
        )
        .unwrap();

        // set the contract info
        state::STATE
            .update::<_, StdError>(&mut deps.storage, |mut state| {
                state.set_ica_info("", "", crate::ibc::types::metadata::TxEncoding::Protobuf);
                Ok(state)
            })
            .unwrap();

        // simulate calling cw-glob for contracts
        let upload_wasm_msg = ExecuteMsg::SendUploadMsg {
            glob_key: "snip120u".to_string(),
            packet_memo: None,
            timeout_seconds: None,
            cw_glob: None,
        };
        let res = execute(deps.as_mut(), env.clone(), info_owner, upload_wasm_msg).unwrap();
        assert_eq!(res.messages[0].id, 710);
        assert_eq!(
            res.attributes
                .iter()
                .find(|a| a.key == "ica_callback_id")
                .unwrap()
                .value,
            "upload_headstash".to_string()
        );

        // simulate upload snip120u reply
        let bytes: Vec<u8> = vec![0u8; 20_000]; // 5MB of zeros
        let binary = Binary::from(bytes);
        // confirm we get expected submessage id

        #[allow(deprecated)]
        let msg = Reply {
            id: res.messages[0].id,
            payload: Binary::from("none".as_bytes()),
            gas_used: 6969696u64,
            result: cosmwasm_std::SubMsgResult::Ok(cosmwasm_std::SubMsgResponse {
                events: vec![
                    Event::new("wasm-headstash")
                        .add_attribute("memo", "memo".to_string())
                        .add_attribute("timeout", "24".to_string())
                        .add_attribute("sender", ica_addr.to_string()), // ica-account
                ],
                data: Some(binary),
                msg_responses: vec![],
            }),
        };
        // println!("simulated reply from cw-blob: {:#?}", msg);

        // simulate response from cw-glob
        let res = reply(deps.as_mut(), env.clone(), msg).unwrap();
        // println!("{:#?}", res);
        assert_eq!(
            res.messages[0].msg.type_id(),
            CosmosMsg::<Empty>::Ibc(cosmwasm_std::IbcMsg::SendPacket {
                channel_id: "".into(),
                data: Binary::new(vec![]),
                timeout: IbcTimeout::with_block(IbcTimeoutBlock {
                    revision: 0,
                    height: 69
                })
            })
            .type_id()
        )
        // simulate upload headstash reply
    }
    #[test]
    fn test_update_callback_address() {
        let mut deps = mock_dependencies();

        let creator = deps.api.addr_make("creator");
        let info = message_info(&creator, &[]);
        let env = mock_env();

        let channel_open_init_options = ChannelOpenInitOptions {
            connection_id: "connection-0".to_string(),
            counterparty_connection_id: "connection-1".to_string(),
            counterparty_port_id: None,
            channel_ordering: None,
        };

        // Instantiate the contract
        let _res = instantiate(
            deps.as_mut(),
            env.clone(),
            info.clone(),
            InstantiateMsg {
                owner: None,
                channel_open_init_options,
                send_callbacks_to: None,
            },
        )
        .unwrap();

        // Ensure the contract admin can update the callback address
        let new_callback_address = deps.api.addr_make("new_callback_address").to_string();
        let msg = ExecuteMsg::UpdateCallbackAddress {
            callback_address: Some(new_callback_address.clone()),
        };
        let res = execute(deps.as_mut(), env.clone(), info, msg).unwrap();

        assert_eq!(0, res.messages.len());

        let state = state::STATE.load(&deps.storage).unwrap();
        assert_eq!(
            state.callback_address,
            Some(deps.api.addr_validate(&new_callback_address).unwrap())
        );

        // Ensure a non-admin cannot update the callback address
        let non_admin = deps.api.addr_make("non-admin");
        let info = message_info(&non_admin, &[]);
        let msg = ExecuteMsg::UpdateCallbackAddress {
            callback_address: Some("new_callback_address".to_string()),
        };

        let res = execute(deps.as_mut(), env, info, msg);
        assert_eq!(
            res.unwrap_err().to_string(),
            "Caller is not the contract's current owner".to_string()
        );
    }

    // In this test, we aim to verify that the semver validation is performed correctly.
    // And that the contract version in cw2 is updated correctly.
    #[test]
    fn test_migrate() {
        let mut deps = mock_dependencies();

        let creator = deps.api.addr_make("creator");
        let info = message_info(&creator, &[]);

        let channel_open_init_options = ChannelOpenInitOptions {
            connection_id: "connection-0".to_string(),
            counterparty_connection_id: "connection-1".to_string(),
            counterparty_port_id: None,
            channel_ordering: None,
        };

        // let mock_headstash_params = state::headstash::HeadstashParams {
        //     headstash_code_id: Some(2),
        //     token_params: vec![
        //         HeadstashTokenParams {
        //             native: "native1".into(),
        //             ibc: "ibc/native1".into(),
        //             symbol: "scrtNATIVE1".into(),
        //             name: "name-of-native1".into(),
        //             snip_addr: None,
        //         },
        //         HeadstashTokenParams {
        //             native: "native2".into(),
        //             ibc: "ibc/native2".into(),
        //             symbol: "scrtNATIVE2".into(),
        //             name: "name-of-native2".into(),
        //             snip_addr: None,
        //         },
        //     ],
        //     headstash: None,
        //     snip120u_code_id: 1u64,
        //     snip120u_code_hash: "234567jkhgfdsa".into(),
        //     feegranter: None,
        // };

        // Instantiate the contract
        let _res = instantiate(
            deps.as_mut(),
            mock_env(),
            info,
            InstantiateMsg {
                owner: None,
                channel_open_init_options,
                send_callbacks_to: None,
            },
        )
        .unwrap();

        // We need to set the contract version manually to a lower version than the current version
        cw2::set_contract_version(&mut deps.storage, keys::CONTRACT_NAME, "0.0.1").unwrap();

        // Ensure that the contract version is updated correctly
        let contract_version = cw2::get_contract_version(&deps.storage).unwrap();
        assert_eq!(contract_version.contract, keys::CONTRACT_NAME);
        assert_eq!(contract_version.version, "0.0.1");

        // Perform the migration
        let _res = migrate(deps.as_mut(), mock_env(), MigrateMsg {}).unwrap();

        let contract_version = cw2::get_contract_version(&deps.storage).unwrap();
        assert_eq!(contract_version.contract, keys::CONTRACT_NAME);
        assert_eq!(contract_version.version, keys::CONTRACT_VERSION);

        // Ensure that the contract version cannot be downgraded
        cw2::set_contract_version(&mut deps.storage, keys::CONTRACT_NAME, "100.0.0").unwrap();

        let res = migrate(deps.as_mut(), mock_env(), MigrateMsg {});
        assert_eq!(
            res.unwrap_err().to_string(),
            format!(
                "invalid migration version: expected > 100.0.0, got {}",
                keys::CONTRACT_VERSION
            )
        );
    }

    #[test]
    fn test_migrate_with_encoding() {
        let mut deps = mock_dependencies();

        let creator = deps.api.addr_make("creator");
        let info = message_info(&creator, &[]);

        let channel_open_init_options = ChannelOpenInitOptions {
            connection_id: "connection-0".to_string(),
            counterparty_connection_id: "connection-1".to_string(),
            counterparty_port_id: None,
            channel_ordering: None,
        };

        // Instantiate the contract
        let _res = instantiate(
            deps.as_mut(),
            mock_env(),
            info,
            InstantiateMsg {
                owner: None,
                channel_open_init_options,
                send_callbacks_to: None,
            },
        )
        .unwrap();

        // We need to set the contract version manually to a lower version than the current version
        cw2::set_contract_version(&mut deps.storage, keys::CONTRACT_NAME, "0.0.1").unwrap();

        // Ensure that the contract version is updated correctly
        let contract_version = cw2::get_contract_version(&deps.storage).unwrap();
        assert_eq!(contract_version.contract, keys::CONTRACT_NAME);
        assert_eq!(contract_version.version, "0.0.1");

        // Set the encoding to proto3json
        state::STATE
            .update::<_, StdError>(&mut deps.storage, |mut state| {
                state.set_ica_info("", "", crate::ibc::types::metadata::TxEncoding::Proto3Json);
                Ok(state)
            })
            .unwrap();

        // Migration should fail because the encoding is not protobuf
        let err = migrate(deps.as_mut(), mock_env(), MigrateMsg {}).unwrap_err();
        assert_eq!(
            err.to_string(),
            ContractError::UnsupportedPacketEncoding(
                crate::ibc::types::metadata::TxEncoding::Proto3Json.to_string()
            )
            .to_string()
        );

        // Set the encoding to protobuf
        state::STATE
            .update::<_, StdError>(&mut deps.storage, |mut state| {
                state.set_ica_info("", "", crate::ibc::types::metadata::TxEncoding::Protobuf);
                Ok(state)
            })
            .unwrap();

        // Migration should succeed because the encoding is protobuf
        let _res = migrate(deps.as_mut(), mock_env(), MigrateMsg {}).unwrap();

        let contract_version = cw2::get_contract_version(&deps.storage).unwrap();
        assert_eq!(contract_version.contract, keys::CONTRACT_NAME);
        assert_eq!(contract_version.version, keys::CONTRACT_VERSION);
    }
}

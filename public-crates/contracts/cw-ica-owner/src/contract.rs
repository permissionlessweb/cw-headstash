#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    from_base64, to_json_binary, Addr, Binary, CosmosMsg, Deps, DepsMut, Env, MessageInfo, Reply,
    Response, StdResult,
};
// use cw2::set_contract_version;
use crate::{
    error::ContractError,
    headstash::commands::upload_contract_msg,
    msg::{ExecuteMsg, HeadstashCallback, InstantiateMsg, QueryMsg, SudoMsg},
    state::{
        self, headstash::HeadstashTokenParams, ContractState, CLOCK_INTERVAL,
        CONTRACT_ADDR_TO_ICA_ID, ICA_COUNT, ICA_STATES, STATE,
    },
};
use cw_ica_controller::{
    helpers::{CwIcaControllerCode, CwIcaControllerContract},
    types::{
        callbacks::IcaControllerCallbackMsg,
        msg::{options::ChannelOpenInitOptions, ExecuteMsg as IcaControllerExecuteMsg},
    },
};

pub const CUSTOM_CALLBACK: &str = "ica_callback_id";
/*
// version info for migration info
const CONTRACT_NAME: &str = "crates.io:cw-ica-owner";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");
*/

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    cw_ownable::initialize_owner(
        deps.storage,
        deps.api,
        Some(&msg.owner.unwrap_or_else(|| info.sender.to_string())),
    )?;
    STATE.save(
        deps.storage,
        &ContractState::new(msg.ica_controller_code_id, msg.headstash_params),
    )?;
    Ok(Response::default())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::CreateIcaContract {
            salt,
            channel_open_init_options,
            headstash_params,
        } => headstash::create_ica_contract(
            deps,
            env,
            info,
            salt,
            channel_open_init_options,
            headstash_params,
        ),
        ExecuteMsg::UploadContractOnSecret { ica_id, wasm } => {
            upload::ica_upload_contract_on_secret(deps, info, ica_id, wasm)
        }
        ExecuteMsg::ReceiveIcaCallback(callback_msg) => {
            ica::ica_callback_handler(deps, info, callback_msg)
        }
        // ExecuteMsg::InitHeadstash { ica_id, start_date } => {
        //     instantiate::ica_instantiate_headstash_contract(deps, env, info, ica_id, start_date)
        // }
        // ExecuteMsg::InitSnip120u { ica_id, tokens } => {
        //     instantiate::ica_instantiate_terp_network_snip120us(deps, info, ica_id, tokens)
        // }
        // ExecuteMsg::AuthorizeMinter { ica_id } => {
        //     headstash::ica_authorize_snip120u_minter(deps, info, ica_id)
        // }
        // ExecuteMsg::IBCTransferTokens { ica_id, channel_id } => {
        //     headstash::ibc_transfer_to_snip_contracts(deps, env, info, ica_id, channel_id)
        // }
        // ExecuteMsg::AddHeadstashClaimers { ica_id, to_add } => {
        //     headstash::ica_add_headstash_claimers(deps, info, ica_id, to_add)
        // }
        // ExecuteMsg::AuthorizeFeegrant {
        //     ica_id,
        //     to_grant,
        //     owner,
        // } => headstash::ica_authorize_feegrant(deps, info, ica_id, to_grant, owner),
        ExecuteMsg::UpdateOwnership(action) => headstash::update_ownership(deps, env, info, action),
        // ExecuteMsg::InitHeadstashCircuitboard { ica_id } => {
        //     instantiate::ica_instantiate_headstash_circuitboard(deps, info, ica_id)
        // }
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetContractState {} => to_json_binary(&query::state(deps)?),
        QueryMsg::GetIcaContractState { ica_id } => {
            to_json_binary(&query::ica_state(deps, ica_id)?)
        }
        QueryMsg::GetIcaCount {} => to_json_binary(&query::ica_count(deps)?),
        QueryMsg::Ownership {} => to_json_binary(&cw_ownable::get_ownership(deps.storage)?),
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn reply(deps: DepsMut, _env: Env, reply: Reply) -> Result<Response, ContractError> {
    match reply.result {
        cosmwasm_std::SubMsgResult::Ok(res) => match reply.id {
            710u64 => {
                // Extract the event attributes
                let event = res.events.iter().find(|e| e.ty == "headstash");
                if let Some(event) = event {
                    let ica_upload_msg =
                        event.attributes.iter().find(|a| a.key == "ica-upload-msg");
                    let sender = event.attributes.iter().find(|a| a.key == "sender");
                    let owner = event.attributes.iter().find(|a| a.key == "owner");
                    let ica_id = event.attributes.iter().find(|a| a.key == "ica-id");

                    if let (Some(ica_upload_msg), Some(sender), Some(owner), Some(ica_id)) =
                        (ica_upload_msg, sender, owner, ica_id)
                    {
                        // Decode the base64 encoded wasm blob
                        let decoded_wasm = from_base64(ica_upload_msg.value.as_str())?;
                        // let wasm_blob = Binary(decoded_wasm);

                        let upload_msg = upload_contract_msg(
                            deps.api.addr_validate(&sender.value.clone())?,
                            decoded_wasm,
                        )?;

                        // bypass ownership check, this was done already.
                        let cw_ica_account =
                            CwIcaControllerContract::new(Addr::unchecked(sender.value.clone()));

                        // send msg with wasm from glob as ica
                        let msg = helpers::send_msg_as_ica(vec![upload_msg], cw_ica_account);

                        return Ok(Response::new().add_message(msg));
                    } else {
                        return Err(ContractError::InvalidAttribute {});
                    }
                } else {
                    return Err(ContractError::InvalidEvent {});
                }
            }
            _ => return Err(ContractError::Unauthorized {}),
        },
        cosmwasm_std::SubMsgResult::Err(_) => return Err(ContractError::SubMsgError {}),
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn sudo(deps: DepsMut, env: Env, msg: SudoMsg) -> Result<Response, ContractError> {
    match msg {
        SudoMsg::HandleIbcBloom {} => {
            if env.block.height % CLOCK_INTERVAL.load(deps.storage)? != 0 {
                // Send msg to process ibc-blooms
                // get default ica account to call
                // call contract as ica to handleBloom

                // expect callback with new interval
                return Ok(Response::new());
            }
        }
    }

    Ok(Response::new())
}

pub mod upload {

    use cosmwasm_std::{SubMsg, WasmMsg};
    use state::CW_GLOB;

    use crate::{headstash::commands::upload_contract_msg, msg};

    pub fn into_cosmos_msg(
        contract_addr: String,
        msg: impl Into<msg::ExecuteMsg>,
    ) -> StdResult<CosmosMsg> {
        let msg = to_json_binary(&msg.into())?;
        Ok(WasmMsg::Execute {
            contract_addr,
            msg,
            funds: vec![],
        }
        .into())
    }

    use super::*;

    /// uploads specific wasm blobs.
    pub fn ica_upload_contract_on_secret(
        deps: DepsMut,
        info: MessageInfo,
        ica_id: u64,
        contract: String,
    ) -> Result<Response, ContractError> {
        let cw_ica_contract =
            helpers::retrieve_ica_owner_account(deps.as_ref(), info.sender.clone(), ica_id)?;

        // msg to grab wasm blob from cw_glob
        let msg = cw_glob::msg::ExecuteMsg::TakeGlob {
            sender: cw_ica_contract.addr().to_string(),
            key: contract,
            id: ica_id,
        };

        // grab the msg to upload wasm via ica-controller from cw-glob
        let upload_msg = helpers::cw_goop_execute(CW_GLOB.load(deps.storage)?.to_string(), msg)?;

        // send as submsg to handle reply
        Ok(Response::default()
            .add_submessage(SubMsg::reply_always(upload_msg, 710))
            .add_attribute(CUSTOM_CALLBACK, HeadstashCallback::UploadHeadstash))
    }
}

pub mod instantiate {
    use headstash::ica_create_headstash_circuitboard;

    use crate::msg::HeadstashCallback;

    use super::helpers::*;
    use super::*;
    pub fn ica_instantiate_headstash_contract(
        deps: DepsMut,
        env: Env,
        info: MessageInfo,
        ica_id: u64,
        start_date: u64,
    ) -> Result<Response, ContractError> {
        let mut msgs = vec![];
        let ica_state = ICA_STATES.load(deps.storage, ica_id)?;
        let hs = ica_state.headstash_params;
        let cw_ica_contract =
            retrieve_ica_owner_account(deps.as_ref(), info.sender.clone(), ica_id.clone())?;

        if let Some(ica) = ica_state.ica_state {
            // headstash must have been uploaded
            if let Some(code_id) = hs.headstash_code_id {
                // snip
                // we must have snip contract addrs
                for snips in hs.token_params.clone() {
                    if snips.snip_addr.is_none() {
                        return Err(ContractError::NoSnipContractAddr {});
                    }
                }
                let init_headstash_msg = instantiate_headstash_msg(
                    code_id,
                    crate::state::headstash::InstantiateMsg {
                        claim_msg_plaintext: "{wallet}".into(),
                        end_date: Some(env.block.time.plus_days(365u64).nanos()),
                        // snip20_1: headstash_cosmwasm_std::ContractInfo {
                        //     address: headstash_cosmwasm_std::Addr::unchecked(
                        //         hs.token_params[0].snip_addr.clone().unwrap(),
                        //     ),
                        //     code_hash: hs.snip120u_code_hash.clone(),
                        // },
                        // snip20_2: Some(headstash_cosmwasm_std::ContractInfo {
                        //     address: headstash_cosmwasm_std::Addr::unchecked(
                        //         hs.token_params[1].snip_addr.clone().unwrap(),
                        //     ),
                        //     code_hash: hs.snip120u_code_hash.clone(),
                        // }),
                        start_date: Some(start_date),
                        viewing_key: "eretskeretjablret".into(),
                        owner: Addr::unchecked(ica.ica_addr),
                        snip120u_code_id: hs.snip120u_code_id.clone(),
                        snip120u_code_hash: hs.snip120u_code_hash.clone(),
                        snips: vec![],
                        circuitboard: "todo!()".into(),
                    },
                )?;
                let msg = send_msg_as_ica(vec![init_headstash_msg], cw_ica_contract);
                msgs.push(msg)
            } else {
                return Err(ContractError::NoHeadstashCodeId {});
            }
        } else {
            return Err(ContractError::NoIcaInfo {});
        }

        Ok(Response::new()
            .add_messages(msgs)
            .add_attribute(CUSTOM_CALLBACK, HeadstashCallback::InstantiateHeadstash))
    }

    /// Creates a snip120u msg for ica-controller to send.
    pub fn ica_instantiate_terp_network_snip120us(
        deps: DepsMut,
        info: MessageInfo,
        ica_id: u64,
        tokens: Vec<HeadstashTokenParams>,
    ) -> Result<Response, ContractError> {
        let mut msgs: Vec<CosmosMsg> = vec![];
        let cw_ica_contract =
            retrieve_ica_owner_account(deps.as_ref(), info.sender.clone(), ica_id)?;

        let state = ICA_STATES.load(deps.storage, ica_id)?;
        let hp = state.headstash_params;

        // we expect first coin in map to be scrtTERP,
        // second coin to be scrtTHIOL.
        for token in tokens.clone() {
            if let Some(t) = hp.token_params.iter().find(|t| t.native == token.native) {
                let msg = self::ica::form_instantiate_snip120u(
                    cw_ica_contract.addr().to_string(),
                    token,
                    hp.snip120u_code_hash.clone(),
                    hp.snip120u_code_id,
                    hp.headstash.clone(),
                    t.symbol.clone(),
                )?;
                msgs.push(msg);
            }
        }
        let msg = send_msg_as_ica(msgs, cw_ica_contract);

        Ok(Response::new()
            .add_message(msg)
            .add_attribute(CUSTOM_CALLBACK, HeadstashCallback::InstantiateSnip120us))
    }

    pub fn ica_instantiate_headstash_circuitboard(
        deps: DepsMut,
        info: MessageInfo,
        ica_id: u64,
    ) -> Result<Response, ContractError> {
        let cw_ica_contract =
            retrieve_ica_owner_account(deps.as_ref(), info.sender.clone(), ica_id)?;

        let state = ICA_STATES.load(deps.storage, ica_id)?;
        let hp = state.headstash_params;
        let cosmos_msg = ica_create_headstash_circuitboard()?;
        let msg = send_msg_as_ica(vec![cosmos_msg], cw_ica_contract);

        Ok(Response::new().add_message(msg))
    }
}

mod headstash {

    use state::{
        headstash::{Headstash, HeadstashParams},
        SNIP120U_CONTRACTS,
    };

    use super::*;
    use crate::msg::HeadstashCallback;

    pub fn create_ica_contract(
        deps: DepsMut,
        env: Env,
        info: MessageInfo,
        salt: Option<String>,
        channel_open_init_options: ChannelOpenInitOptions,
        headstash_params: HeadstashParams,
    ) -> Result<Response, ContractError> {
        cw_ownable::assert_owner(deps.storage, &info.sender)?;
        let state = STATE.load(deps.storage)?;

        let ica_code = CwIcaControllerCode::new(state.ica_controller_code_id);

        let instantiate_msg = cw_ica_controller::types::msg::InstantiateMsg {
            owner: Some(env.contract.address.to_string()),
            channel_open_init_options,
            send_callbacks_to: Some(env.contract.address.to_string()),
            // headstash_params: headstash_params.clone(),
        };

        let ica_count = ICA_COUNT.load(deps.storage).unwrap_or(0);

        let salt = salt.unwrap_or(env.block.time.seconds().to_string());
        let label = format!("ica-controller-{}-{}", env.contract.address, ica_count);

        let (cosmos_msg, contract_addr) = ica_code.instantiate2(
            deps.api,
            &deps.querier,
            &env,
            instantiate_msg,
            label,
            Some(env.contract.address.to_string()),
            salt,
        )?;

        let initial_state = state::IcaContractState::new(contract_addr.clone(), headstash_params);

        ICA_STATES.save(deps.storage, ica_count, &initial_state)?;

        CONTRACT_ADDR_TO_ICA_ID.save(deps.storage, contract_addr, &ica_count)?;

        ICA_COUNT.save(deps.storage, &(ica_count + 1))?;

        Ok(Response::new().add_message(cosmos_msg))
    }

    pub fn ica_authorize_snip120u_minter(
        deps: DepsMut,
        info: MessageInfo,
        ica_id: u64,
    ) -> Result<Response, ContractError> {
        let mut msgs = vec![];
        let cw_ica_contract =
            helpers::retrieve_ica_owner_account(deps.as_ref(), info.sender.clone(), ica_id)?;

        let state = ICA_STATES.load(deps.storage, ica_id)?;
        let hp = state.headstash_params;

        if let Some(ica) = state.ica_state.clone() {
            let hs_addr = hp.headstash.unwrap();
            // load snip120u's from state
            let snip120u = SNIP120U_CONTRACTS.load(deps.storage)?;
            for snip in snip120u {
                // add minter msg
                let msg = ica::form_authorize_minter(
                    ica.ica_addr.clone(),
                    hs_addr.clone(),
                    snip.to_string(),
                )?;
                msgs.push(msg);
            }
        }
        // push msgs for ica to run
        let ica_msg = helpers::send_msg_as_ica(msgs, cw_ica_contract);
        Ok(Response::new()
            .add_message(ica_msg)
            .add_attribute(CUSTOM_CALLBACK, HeadstashCallback::SetHeadstashAsSnipMinter))
    }

    /// transfer each token to their respective snip120u addrs
    pub fn ibc_transfer_to_snip_contracts(
        deps: DepsMut,
        env: Env,
        info: MessageInfo,
        ica_id: u64,
        channel_id: String,
    ) -> Result<Response, ContractError> {
        cw_ownable::assert_owner(deps.storage, &info.sender)?;
        let mut msgs = vec![];
        let state = ICA_STATES.load(deps.storage, ica_id)?;
        let hp = state.headstash_params;
        for coin in info.funds {
            if let Some(token) = hp.token_params.iter().find(|t| t.native == coin.denom) {
                if let Some(snip) = token.snip_addr.clone() {
                    let msg = ica::form_ibc_transfer_msg(
                        env.block.time,
                        600u64,
                        snip,
                        channel_id.clone(),
                        coin,
                    )?;
                    // add minter msg
                    msgs.push(msg);
                } else {
                    return Err(ContractError::NoSnipContractAddr {});
                }
            } else {
                return Err(ContractError::NoCoinSentMatchesHeadstashParams {});
            }
        }

        Ok(Response::new()
            .add_messages(msgs)
            .add_attribute(CUSTOM_CALLBACK, HeadstashCallback::FundHeadstash))
    }

    pub fn ica_add_headstash_claimers(
        deps: DepsMut,
        info: MessageInfo,
        ica_id: u64,
        to_add: Vec<Headstash>,
    ) -> Result<Response, ContractError> {
        let mut msgs = vec![];
        let cw_ica_contract =
            helpers::retrieve_ica_owner_account(deps.as_ref(), info.sender.clone(), ica_id)?;
        let state = ICA_STATES.load(deps.storage, ica_id)?;

        if let Some(ica) = state.ica_state.clone() {
            let hp = state.headstash_params;
            if let Some(hs_addr) = hp.headstash {
                // add headstash claimers msg
                let msg = ica::form_add_headstash(ica.ica_addr.clone(), hs_addr.clone(), to_add)?;
                msgs.push(msg);
            } else {
                return Err(ContractError::NoHeadstashContract {});
            }
        } else {
            return Err(ContractError::IcaInfoNotSet {});
        }
        // push msgs for ica to run
        let ica_msg = helpers::send_msg_as_ica(msgs, cw_ica_contract);
        Ok(Response::new()
            .add_message(ica_msg)
            .add_attribute(CUSTOM_CALLBACK, HeadstashCallback::AddHeadstashers))
    }

    pub fn ica_authorize_feegrant(
        deps: DepsMut,
        info: MessageInfo,
        ica_id: u64,
        to_grant: Vec<String>,
        owner: Option<String>,
    ) -> Result<Response, ContractError> {
        let mut msgs = vec![];
        let feegranter = STATE.load(deps.storage)?.headstash_params.fee_granter;
        // fee granter may also call this entry point.
        let cw_ica_contract = match owner {
            Some(a) => {
                if let Some(b) = feegranter {
                    if info.sender.to_string() != b {
                        return Err(ContractError::NotValidFeegranter {});
                    }
                }
                helpers::retrieve_ica_owner_account(
                    deps.as_ref(),
                    deps.api.addr_validate(&a)?,
                    ica_id,
                )?
            }
            None => {
                helpers::retrieve_ica_owner_account(deps.as_ref(), info.sender.clone(), ica_id)?
            }
        };

        let state = ICA_STATES.load(deps.storage, ica_id)?;

        if let Some(ica) = state.ica_state.clone() {
            // add headstash claimers msg
            for addr in to_grant {
                let msg = ica::form_authorize_feegrant(ica.ica_addr.clone(), addr)?;
                msgs.push(msg);
            }
        } else {
            return Err(ContractError::IcaInfoNotSet {});
        }
        // push msgs for ica to run
        let ica_msg = helpers::send_msg_as_ica(msgs, cw_ica_contract);
        Ok(Response::new()
            .add_message(ica_msg)
            .add_attribute(CUSTOM_CALLBACK, HeadstashCallback::AuthorizeFeeGrants))
    }

    pub fn ica_create_headstash_circuitboard() -> Result<CosmosMsg, ContractError> {
        Ok(
            #[allow(deprecated)]
            CosmosMsg::Stargate {
                type_url: "/secret.compute.v1beta1.MsgExecuteContract".into(),
                value: anybuf::Anybuf::new()
                    // .append_string(1, sender.to_string()) // sender (DAO)
                    // .append_string(2, &snip120u.to_string()) // contract
                    // .append_bytes(3, to_json_binary(&set_minter_msg)?.as_slice())
                    .into_vec()
                    .into(),
            },
        )
    }

    /// Update the ownership of this contract.
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
}

mod query {
    use crate::state::{IcaContractState, ICA_COUNT, ICA_STATES};

    use super::*;

    /// Returns the saved contract state.
    pub fn state(deps: Deps) -> StdResult<ContractState> {
        STATE.load(deps.storage)
    }

    /// Returns the saved ICA state for the given ICA ID.
    pub fn ica_state(deps: Deps, ica_id: u64) -> StdResult<IcaContractState> {
        ICA_STATES.load(deps.storage, ica_id)
    }

    /// Returns the saved ICA count.
    pub fn ica_count(deps: Deps) -> StdResult<u64> {
        ICA_COUNT.load(deps.storage)
    }
}

pub mod ica {
    use anybuf::Anybuf;
    use cosmwasm_std::{from_json, Coin, Empty, IbcTimeout, Timestamp, Uint128};
    use cw_ica_controller::{
        ibc::types::packet::acknowledgement::Data,
        types::state::{ChannelState, ChannelStatus},
    };
    use state::headstash::Headstash;

    use crate::msg::HeadstashCallback;

    use super::*;
    /// Handles ICA controller callback messages.
    pub fn ica_callback_handler(
        deps: DepsMut,
        info: MessageInfo,
        callback_msg: IcaControllerCallbackMsg,
    ) -> Result<Response, ContractError> {
        let ica_id = CONTRACT_ADDR_TO_ICA_ID.load(deps.storage, info.sender)?;
        let mut ica_state = ICA_STATES.load(deps.storage, ica_id)?;
        match callback_msg {
            IcaControllerCallbackMsg::OnAcknowledgementPacketCallback {
                ica_acknowledgement,
                ..
            } => match ica_acknowledgement {
                Data::Result(res) => {
                    let response: Response<Empty> = from_json(res)?;
                    if let Some(attr) = response
                        .attributes
                        .iter()
                        .find(|attr| attr.key == CUSTOM_CALLBACK)
                    {
                        match HeadstashCallback::from(attr.value.clone()) {
                            HeadstashCallback::AddHeadstashers => {
                                // do nothing (or, save pubkey to state)
                                Ok(Response::default())
                            }
                            HeadstashCallback::UploadHeadstash => {
                                // 1. save code-id to state
                                if let Some(event) =
                                    response.events.iter().find(|e| e.ty == "store_code")
                                {
                                    let checksum = event.attributes[0].value.clone();
                                    let code_id = event.attributes[1].value.clone();
                                    ica_state.headstash_params.headstash_code_id =
                                        Some(u64::from_str_radix(&code_id, 10)?);
                                    ica_state.headstash_params.snip120u_code_hash = checksum;
                                }
                                Ok(Response::default())
                            }
                            HeadstashCallback::InstantiateHeadstash => {
                                // 2. save headstash addr to state
                                // (may need to add permissioned query)
                                // todo: handle saving any snip120u contract to state if created
                                if let Some(event) =
                                    response.events.iter().find(|e| e.ty == "instantiate")
                                {
                                    ica_state.headstash_params.headstash =
                                        Some(event.attributes[0].value.clone());
                                }
                                Ok(Response::default())
                            }
                            HeadstashCallback::InstantiateSnip120us => {
                                let mut count: usize = 0;
                                // 3. save snips to state
                                for event in response
                                    .events
                                    .iter()
                                    .filter(|e| e.ty == "instantiate")
                                    .collect::<Vec<_>>()
                                {
                                    // todo: match the native denom with saved headstash params
                                    ica_state.headstash_params.token_params[count].snip_addr =
                                        Some(event.attributes[count].value.clone());
                                    count += count;
                                }

                                Ok(Response::default())
                            }
                            HeadstashCallback::SetHeadstashAsSnipMinter => {
                                // 4. do nothing.
                                Ok(Response::default())
                            }
                            HeadstashCallback::AuthorizeFeeGrants => {
                                // 5. do nothing.
                                Ok(Response::default())
                            }
                            HeadstashCallback::FundHeadstash => {
                                // 6. do nothing.
                                Ok(Response::default())
                            }
                        }
                    } else {
                        // The attribute does not exist
                        return Err(ContractError::CallbackError {});
                    }
                }
                Data::Error(_) => Ok(Response::default()),
            },
            IcaControllerCallbackMsg::OnTimeoutPacketCallback { .. } => Ok(Response::default()),
            IcaControllerCallbackMsg::OnChannelOpenAckCallback {
                channel,
                ica_address,
                tx_encoding,
            } => {
                ica_state.ica_state = Some(crate::state::IcaState {
                    ica_id,
                    channel_state: ChannelState {
                        channel,
                        channel_status: ChannelStatus::Open,
                    },
                    ica_addr: ica_address,
                    tx_encoding,
                });
                ICA_STATES.save(deps.storage, ica_id, &ica_state)?;
                Ok(Response::default())
            }
        }
    }

    /// Instantiates a snip120u token on Secret Network via Stargate
    pub fn form_instantiate_snip120u(
        sender: String,
        coin: HeadstashTokenParams,
        code_hash: String,
        code_id: u64,
        headstash: Option<String>,
        symbol: String,
    ) -> Result<CosmosMsg, ContractError> {
        let init_msg = crate::state::snip120u::InstantiateMsg {
            name: "Terp Network SNIP120U - ".to_owned() + coin.name.as_str(),
            admin: headstash,
            symbol,
            decimals: 6u8,
            initial_balances: None,
            prng_seed: Binary::new(
                "eretjeretskeretjablereteretjeretskeretjableret"
                    .to_string()
                    .into_bytes(),
            ),
            config: None,
            supported_denoms: Some(vec![coin.ibc.clone()]),
        };
        Ok(
            #[allow(deprecated)]
            // proto ref: https://github.com/scrtlabs/SecretNetwork/blob/master/proto/secret/compute/v1beta1/msg.proto
            CosmosMsg::Stargate {
                type_url: "/secret.compute.v1beta1.MsgInstantiateContract".into(),
                value: anybuf::Anybuf::new()
                    .append_string(1, sender.to_string()) // sender (DAO)
                    .append_string(2, &code_hash.to_string()) // callback_code_hash
                    .append_uint64(3, code_id) // code-id of snip-25
                    .append_string(
                        4,
                        "SNIP120U For Secret Network - ".to_owned() + coin.name.as_str(),
                    ) // label of snip20
                    .append_bytes(5, to_json_binary(&init_msg)?.as_slice())
                    .append_string(8, &code_hash.to_string()) // callback_code_hash
                    .into_vec()
                    .into(),
            },
        )
    }
    pub fn form_authorize_minter(
        sender: String,
        headstash: String,
        snip120u: String,
    ) -> Result<CosmosMsg, ContractError> {
        let set_minter_msg = crate::state::snip120u::AddMinters {
            minters: vec![headstash.clone()],
            padding: None,
        };

        Ok(
            // proto ref: https://github.com/scrtlabs/SecretNetwork/blob/master/proto/secret/compute/v1beta1/msg.proto
            #[allow(deprecated)]
            CosmosMsg::Stargate {
                type_url: "/secret.compute.v1beta1.MsgExecuteContract".into(),
                value: anybuf::Anybuf::new()
                    .append_string(1, sender.to_string()) // sender (DAO)
                    .append_string(2, &snip120u.to_string()) // contract
                    .append_bytes(3, to_json_binary(&set_minter_msg)?.as_slice())
                    .into_vec()
                    .into(),
            },
        )
    }
    pub fn form_ibc_transfer_msg(
        time: Timestamp,
        seconds: u64,
        snip120u: String,
        channel_id: String,
        coin: Coin,
    ) -> Result<CosmosMsg, ContractError> {
        Ok(CosmosMsg::Ibc(cosmwasm_std::IbcMsg::Transfer {
            channel_id,
            to_address: snip120u,
            amount: coin,
            timeout: IbcTimeout::with_timestamp(time.plus_seconds(seconds)),
            memo: None,
        }))
    }

    pub fn form_add_headstash(
        sender: String,
        headstash: String,
        to_add: Vec<Headstash>,
    ) -> Result<CosmosMsg, ContractError> {
        // proto ref: https://github.com/scrtlabs/SecretNetwork/blob/master/proto/secret/compute/v1beta1/msg.proto
        let msg = crate::state::headstash::Add { headstash: to_add };
        Ok(
            #[allow(deprecated)]
            CosmosMsg::Stargate {
                type_url: "/secret.compute.v1beta1.MsgExecuteContract".into(),
                value: anybuf::Anybuf::new()
                    .append_string(1, sender.to_string()) // sender (DAO)
                    .append_string(2, &headstash.to_string()) // contract
                    .append_bytes(3, to_json_binary(&msg)?.as_slice())
                    .into_vec()
                    .into(),
            },
        )
    }

    pub fn form_authorize_feegrant(
        sender: String,
        grantee: String,
    ) -> Result<CosmosMsg, ContractError> {
        // proto ref: https://github.com/cosmos/cosmos-sdk/blob/main/x/feegrant/proto/cosmos/feegrant/v1beta1/feegrant.proto
        let token = Anybuf::new()
            .append_string(1, "uscrt")
            .append_string(2, Uint128::one().to_string());
        // basic feegrant
        let basic_allowance = Anybuf::new().append_repeated_message(1, &[token]);
        // FeeAllowanceI implementation
        let allowance = Anybuf::new()
            .append_string(1, "/cosmos.feegrant.v1beta1.BasicAllowance")
            .append_message(2, &basic_allowance);
        Ok(
            // proto ref: https://github.com/cosmos/cosmos-sdk/blob/main/x/feegrant/proto/cosmos/feegrant/v1beta1/tx.proto
            #[allow(deprecated)]
            CosmosMsg::Stargate {
                type_url: "/cosmos.feegrant.v1beta1.MsgGrantAllowance".into(),
                value: Anybuf::new()
                    .append_string(1, sender.to_string()) // granter (DAO)
                    .append_string(2, &grantee.to_string()) // grantee
                    .append_message(3, &allowance)
                    .into_vec()
                    .into(),
            },
        )
    }
}

pub mod helpers {

    use cosmwasm_std::Empty;

    use crate::state::ICA_STATES;

    use super::*;

    /// Retrieves an ica account for the given sender and the account id. only contract owner can call this.
    pub fn retrieve_ica_owner_account(
        deps: Deps,
        sender: Addr,
        ica_id: u64,
    ) -> Result<CwIcaControllerContract, ContractError> {
        cw_ownable::assert_owner(deps.storage, &sender)?;

        let ica_state = ICA_STATES.load(deps.storage, ica_id)?;

        Ok(CwIcaControllerContract::new(Addr::unchecked(
            ica_state.contract_addr,
        )))
    }

    pub fn send_msg_as_ica(
        msgs: Vec<CosmosMsg>,
        cw_ica_contract: CwIcaControllerContract,
    ) -> CosmosMsg {
        let ica_controller_msg = IcaControllerExecuteMsg::SendCosmosMsgs {
            messages: msgs,
            packet_memo: None,
            timeout_seconds: None,
            queries: vec![],
        };

        cw_ica_contract.execute(ica_controller_msg).unwrap()
    }

    /// Defines the msg to instantiate the headstash contract
    pub fn instantiate_headstash_msg(
        code_id: u64,
        scrt_headstash_msg: crate::state::headstash::InstantiateMsg,
    ) -> Result<CosmosMsg, ContractError> {
        Ok(CosmosMsg::<Empty>::Wasm(
            cosmwasm_std::WasmMsg::Instantiate {
                admin: None,
                code_id,
                label: "Secret-Headstash Airdrop Contract: Terp Network".into(),
                msg: to_json_binary(&scrt_headstash_msg)?,
                funds: vec![],
            },
        ))
    }
    /// Defines the msg to instantiate the headstash contract
    pub fn cw_goop_execute(
        cw_glob: String,
        msg: cw_glob::msg::ExecuteMsg,
    ) -> Result<CosmosMsg, ContractError> {
        Ok(CosmosMsg::<Empty>::Wasm(cosmwasm_std::WasmMsg::Execute {
            contract_addr: cw_glob,
            msg: to_json_binary(&msg)?,
            funds: vec![],
        }))
    }
}

#[cfg(test)]
mod tests {}

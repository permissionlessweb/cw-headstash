#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    from_base64, to_json_binary, Addr, Binary, CosmosMsg, Deps, DepsMut, Env, MessageInfo, Reply,
    Response, StdResult,
};
// use cw2::set_contract_version;
use crate::{
    error::ContractError,
    msg::{ExecuteMsg, HeadstashCallback, InstantiateMsg, QueryMsg, SudoMsg},
    state::{
        self,
        headstash::{HeadstashParams, HeadstashTokenParams},
        ContractState, CLOCK_INTERVAL, CONTRACT_ADDR_TO_ICA_ID, DEPLOYMENT_SEQUENCE, ICA_COUNT,
        ICA_STATES, STATE,
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
    println!("ADMIN: {:#?}", info.sender);
    cw_ownable::initialize_owner(
        deps.storage,
        deps.api,
        Some(&msg.owner.unwrap_or_else(|| info.sender.to_string())),
    )?;

    let HeadstashParams {
        snip120u_code_id,
        headstash_code_id,
        snip120u_code_hash,
        ..
    } = msg.headstash_params.clone();
    if snip120u_code_id.is_some() {
        // require code-hash also
        if snip120u_code_hash.is_none() {
            return Err(ContractError::NoSnip120uCodeHash {});
        }
        DEPLOYMENT_SEQUENCE.save(deps.storage, "snip120u".into(), &true)?;
    }
    if headstash_code_id.is_some() {
        DEPLOYMENT_SEQUENCE.save(deps.storage, "cw-headstash".into(), &true)?;
    }
    // if there is any snip120u addr in params, save to map with enumerated position as part of key
    for (i, param) in msg.headstash_params.token_params.iter().enumerate() {
        if let Some(_) = &param.snip_addr {
            DEPLOYMENT_SEQUENCE.save(
                deps.storage,
                "snip120u-init-".to_owned() + &i.to_string(),
                &true,
            )?;
        }
    }

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
            cw_glob,
        } => headstash::create_ica_contract(
            deps,
            env,
            info,
            salt,
            channel_open_init_options,
            headstash_params,
            cw_glob,
        ),
        ExecuteMsg::UploadContractOnSecret { ica_id, wasm } => {
            upload::ica_upload_contract_on_secret(deps, info, ica_id, wasm)
        }
        ExecuteMsg::ReceiveIcaCallback(callback_msg) => {
            ica::ica_callback_handler(deps, info, callback_msg)
        }
        ExecuteMsg::UpdateOwnership(action) => headstash::update_ownership(deps, env, info, action),
        ExecuteMsg::InitSnip120u { ica_id, tokens } => {
            instantiate::ica_instantiate_snips(deps, info, ica_id, tokens)
        }
        ExecuteMsg::InitHeadstash { ica_id, start_date } => {
            instantiate::ica_instantiate_headstash_contract(deps, env, info, ica_id, start_date)
        }
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
            // 710u64 => {
            //     // Extract the event attributes
            //     let event = res.events.iter().find(|e| e.ty == "wasm-headstash");
            //     if let Some(event) = event {
            //         let ica_upload_msg =
            //             event.attributes.iter().find(|a| a.key == "ica-upload-msg");
            //         let sender = event.attributes.iter().find(|a| a.key == "sender");

            //         if ica_upload_msg.is_none() {
            //             return Err(ContractError::MissingAttribute("ica-upload-msg".into()));
            //         } else if sender.is_none() {
            //             return Err(ContractError::MissingAttribute("sender".to_string()));
            //         }

            //         let ica_upload_msg = ica_upload_msg.unwrap();
            //         let sender = sender.unwrap();

            //         // Decode the base64 encoded wasm blob
            //         let decoded_wasm = from_base64(ica_upload_msg.value.as_str())?;

            //         let upload_msg =
            //             upload_contract_msg(Addr::unchecked(sender.value.clone()), decoded_wasm)?;

            //         // bypass ownership check, this was done already.
            //         let cw_ica_account =
            //             CwIcaControllerContract::new(Addr::unchecked(sender.value.clone()));

            //         // send msg with wasm from glob as ica
            //         let msg = helpers::send_msg_as_ica(vec![upload_msg], cw_ica_account);

            //         return Ok(Response::new().add_message(msg));
            //     } else {
            //         return Err(ContractError::InvalidEvent {});
            //     }
            // }
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

    use super::*;
    use crate::msg;
    use cosmwasm_std::{StdError, WasmMsg};

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

    /// uploads specific wasm blobs.
    pub fn ica_upload_contract_on_secret(
        deps: DepsMut,
        info: MessageInfo,
        ica_id: u64,
        contract: String,
    ) -> Result<Response, ContractError> {
        let cw_ica_contract =
            helpers::retrieve_ica_owner_account(deps.as_ref(), info.sender.clone(), ica_id)?;

        match contract.as_str() {
            "snip120u" => {
                if DEPLOYMENT_SEQUENCE
                    .may_load(deps.storage, "snip120u".to_string())?
                    .is_some()
                {
                    return Err(ContractError::Std(StdError::generic_err(
                        "already have set snip120u code-id",
                    )));
                }
            }
            "cw-headstash" => {
                if DEPLOYMENT_SEQUENCE
                    .may_load(deps.storage, "snip120u".to_string())?
                    .is_none()
                {
                    return Err(ContractError::Std(StdError::generic_err(
                        "must upload snip120u first",
                    )));
                } else if DEPLOYMENT_SEQUENCE
                    .may_load(deps.storage, "cw-headstash".into())?
                    .is_some()
                {
                    return Err(ContractError::Std(StdError::generic_err(
                        "already have set headstash code-id",
                    )));
                };
            }
            _ => return Err(ContractError::BadContractid {}),
        }

        // msg to trigger ica-controller grabbing the wasm blob
        let upload_msg = helpers::cw_ica_controller_execute(
            cw_ica_contract.addr().to_string(),
            cw_ica_controller::types::msg::ExecuteMsg::SendUploadMsg {
                wasm: contract,
                packet_memo: Some("23".into()),
                timeout_seconds: None,
            },
        )?;

        // set the wasm blob key in state, in order to properly handle code-id in ica callback
        // - sequence for continuity

        // send as submsg to handle reply
        Ok(Response::default().add_message(upload_msg))
    }
}

pub mod instantiate {
    use headstash::ica_create_headstash_circuitboard;
    use state::headstash::Snip120u;

    use super::helpers::*;
    use super::*;
    use crate::msg::HeadstashCallback;

    /// Creates a snip120u msg for ica-controller to send.
    pub fn ica_instantiate_snips(
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

        // if headstash or snip120u is not set, we cannot instantiate snips
        if !DEPLOYMENT_SEQUENCE.load(deps.storage, "snip120u".to_string())? {
            return Err(ContractError::NoSnipCodeId {});
        } else if DEPLOYMENT_SEQUENCE.load(deps.storage, "cw-headstash".to_string())? {
            return Err(ContractError::NoHeadstashCodeId {});
        }

        let tokens = if tokens.len().lt(&1) {
            hp.token_params.clone()
        } else {
            tokens
        };

        for token in tokens.clone() {
            if let Some(t) = hp.token_params.iter().find(|t| t.native == token.native) {
                if hp.snip120u_code_hash.is_none() {
                    return Err(ContractError::NoSnip120uCodeHash {});
                } else if hp.snip120u_code_id.is_none() {
                    return Err(ContractError::NoSnipCodeId {});
                }
                let msg = self::ica::form_instantiate_snip120u(
                    cw_ica_contract.addr().to_string(),
                    token,
                    hp.snip120u_code_hash.clone().unwrap(),
                    hp.snip120u_code_id.unwrap(),
                    hp.headstash_addr.clone(),
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

    pub fn ica_instantiate_headstash_contract(
        deps: DepsMut,
        env: Env,
        info: MessageInfo,
        ica_id: u64,
        start_date: u64,
    ) -> Result<Response, ContractError> {
        let mut msgs = vec![];
        let ica_state = ICA_STATES.load(deps.storage, ica_id)?;
        let hs_params = ica_state.headstash_params;
        let cw_ica_contract =
            retrieve_ica_owner_account(deps.as_ref(), info.sender.clone(), ica_id.clone())?;

        // if headstash or snips have not been set
        if !DEPLOYMENT_SEQUENCE.load(deps.storage, "snip120u-init".to_string())? {
            return Err(ContractError::NoSnipCodeId {});
        }

        if let Some(ica) = ica_state.ica_state {
            // cw-headstash code-id must be known
            if let Some(code_id) = hs_params.headstash_code_id {
                if let Some(snip120u_code_hash) = hs_params.snip120u_code_hash {
                    let mut hs_snips = vec![];
                    // at least 1 snip120u must exist
                    for snip in hs_params.token_params.clone() {
                        if snip.snip_addr.is_none() {
                            return Err(ContractError::NoSnipContractAddr {});
                        }
                        let snip = Snip120u {
                            token: snip.native,
                            name: snip.name,
                            addr: Some(deps.api.addr_validate(&snip.snip_addr.unwrap())?),
                            total_amount: snip.total,
                        };
                        hs_snips.push(snip);
                    }
                    // form cw-headstash instantiate msg
                    let init_headstash_msg = instantiate_headstash_msg(
                        code_id,
                        crate::state::headstash::InstantiateMsg {
                            claim_msg_plaintext: "{wallet}".into(),
                            end_date: Some(env.block.time.plus_days(365u64).nanos()),
                            start_date: Some(start_date),
                            viewing_key: "eretskeretjablret".into(),
                            owner: Addr::unchecked(ica.ica_addr),
                            snip120u_code_hash: snip120u_code_hash,
                            snips: hs_snips,
                            multiplier: hs_params.multiplier,
                            bloom_config: hs_params.bloom_config,
                        },
                    )?;
                    let msg = send_msg_as_ica(vec![init_headstash_msg], cw_ica_contract);
                    msgs.push(msg)
                } else {
                    return Err(ContractError::NoSnip120uCodeHash {});
                }
            } else {
                return Err(ContractError::NoHeadstashCodeId {});
            }
        } else {
            return Err(ContractError::NoIcaInfo {});
        }

        Ok(
            Response::new(), // .add_messages(msgs)
                             // .add_attribute(CUSTOM_CALLBACK, HeadstashCallback::InstantiateHeadstash)
        )
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
        headstash_params: Option<HeadstashParams>,
        cw_glob: String,
    ) -> Result<Response, ContractError> {
        cw_ownable::assert_owner(deps.storage, &info.sender)?;
        let state = STATE.load(deps.storage)?;

        let ica_code = CwIcaControllerCode::new(state.ica_controller_code_id);

        let instantiate_msg = cw_ica_controller::types::msg::InstantiateMsg {
            owner: Some(env.contract.address.to_string()),
            channel_open_init_options,
            send_callbacks_to: Some(env.contract.address.to_string()),
            cw_glob,
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

        let hs_params = headstash_params.unwrap_or(state.headstash_params);
        let initial_state = state::IcaContractState::new(contract_addr.clone(), hs_params);

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
            if let Some(hs_addr) = hp.headstash_addr {
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
            } else {
                return Err(ContractError::NoHeadstashContract {});
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
            if let Some(hs_addr) = hp.headstash_addr {
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
    /// The following callbacks are expected:
    /// 1. code-id callback for snip120u
    /// 2. code-id callback for headstash
    /// 3. contract addr for snip120u(s)
    /// 4. contract addr for cw-headstash
    pub fn ica_callback_handler(
        deps: DepsMut,
        info: MessageInfo,
        callback_msg: IcaControllerCallbackMsg,
    ) -> Result<Response, ContractError> {
        let ica_id = CONTRACT_ADDR_TO_ICA_ID.load(deps.storage, info.sender.clone())?;
        let mut ica_state = ICA_STATES.load(deps.storage, ica_id)?;

        match callback_msg {
            IcaControllerCallbackMsg::OnAcknowledgementPacketCallback {
                ica_acknowledgement,
                ..
            } => match ica_acknowledgement {
                Data::Result(res) => {
                    let response: Response<Empty> = from_json(&res)?;

                    println!("ica_acknowledgement result: {:#?}", response);

                    // 1. if snip has not been uploaded, this is a snip upload callback
                    if !DEPLOYMENT_SEQUENCE.load(deps.storage, "snip120u".into())? {
                        if let Some(event) = response.events.iter().find(|e| e.ty == "store_code") {
                            let code_id = event.attributes[0].value.clone();
                            // set code-id for snip120u to state
                            ica_state.headstash_params.snip120u_code_id =
                                Some(u64::from_str_radix(&code_id, 10)?);
                            ICA_STATES.save(deps.storage, ica_id, &ica_state)?
                        } else {
                            return Err(ContractError::BadStoreSnip120uCodeResponse {});
                        }
                        Ok(Response::default())
                    // 2. if headstash has not been uploaded, this is a snip upload callback
                    } else if !DEPLOYMENT_SEQUENCE.load(deps.storage, "cw-headstash".into())? {
                        if let Some(event) = response.events.iter().find(|e| e.ty == "store_code") {
                            let code_id = event.attributes[0].value.clone();
                            // set code-id for headstash to state
                            ica_state.headstash_params.headstash_code_id =
                                Some(u64::from_str_radix(&code_id, 10)?);
                            // set code-hash for headstash to state
                            // ica_state.headstash_params.headstash_code_hash = Some(checksum);
                            ICA_STATES.save(deps.storage, ica_id, &ica_state)?
                        } else {
                            return Err(ContractError::BadStoreHeadstashCodeResponse {});
                        }
                        Ok(Response::default())
                    // 3. if snip120u addr has not been deployed, this is snip120u init
                    } else if !DEPLOYMENT_SEQUENCE.load(deps.storage, "snip120u-init".into())? {
                        let mut count: usize = 0;
                        // 3. save snips to state
                        for event in response
                            .events
                            .iter()
                            .filter(|e| e.ty == "_instantiate")
                            .collect::<Vec<_>>()
                        {
                            // todo: match the native denom with saved headstash params
                            ica_state.headstash_params.token_params[count].snip_addr =
                                Some(event.attributes[count].value.clone());
                            count += count;

                            ICA_STATES.save(deps.storage, ica_id, &ica_state)?;
                        }
                        Ok(Response::default())
                    // 4. if headstash addr has not been deployed, this is headstash init
                    } else if !DEPLOYMENT_SEQUENCE.load(deps.storage, "snip120u-init".into())? {
                        if let Some(event) = response.events.iter().find(|e| e.ty == "_instantiate")
                        {
                            ica_state.headstash_params.headstash_addr =
                                Some(event.attributes[0].value.clone());
                        }
                        ICA_STATES.save(deps.storage, ica_id, &ica_state)?;

                        Ok(Response::default())
                    } else {
                        Ok(Response::default())
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
    pub fn cw_ica_controller_execute(
        cw_ica_controller: String,
        msg: cw_ica_controller::types::msg::ExecuteMsg,
    ) -> Result<CosmosMsg, ContractError> {
        Ok(CosmosMsg::<Empty>::Wasm(cosmwasm_std::WasmMsg::Execute {
            contract_addr: cw_ica_controller,
            msg: to_json_binary(&msg)?,
            funds: vec![],
        }))
    }
}

#[cfg(test)]
mod tests {
    use anybuf::Anybuf;
    use cosmwasm_std::{
        testing::{message_info, mock_dependencies, mock_env},
        to_json_binary, Addr, Binary, CosmosMsg, Empty, Event, IbcChannel, IbcEndpoint, IbcOrder,
        IbcPacket, IbcTimeout, IbcTimeoutBlock, Reply, Response, SubMsg,
    };
    use cw_ica_controller::{
        ibc::types::{metadata::TxEncoding, packet::acknowledgement::Data},
        types::{
            callbacks::IcaControllerCallbackMsg,
            msg::options::ChannelOpenInitOptions,
            state::{ChannelState, ChannelStatus},
        },
    };
    use cw_multi_test::{App, AppResponse, BankSudo, Contract, ContractWrapper, Executor, SudoMsg};

    use crate::{
        contract::{execute, reply, CUSTOM_CALLBACK},
        msg::{ExecuteMsg, HeadstashCallback, InstantiateMsg},
        state::{
            self,
            headstash::{BloomConfig, HeadstashParams, HeadstashTokenParams},
            snip120u, ContractState, IcaContractState, IcaState, CONTRACT_ADDR_TO_ICA_ID,
            ICA_COUNT, ICA_STATES, UPLOAD_REPLY_ID,
        },
    };

    use super::instantiate;

    fn init_helper() {}

    fn cw_ica_headstash_owner() -> Box<dyn Contract<Empty>> {
        let contract = ContractWrapper::new(
            crate::contract::execute,
            crate::contract::instantiate,
            crate::contract::query,
        );
        Box::new(contract)
    }

    // init test

    #[test]
    fn test_integration() {
        // simulated testing environment
        let mut deps = mock_dependencies();
        let env = mock_env();

        // simulated addrs
        let creator = deps.api.addr_make("creator");
        let owner = deps.api.addr_make("owner");
        let feegranter = deps.api.addr_make("feegranter");
        let cw_glob = deps.api.addr_make("cw-glob");
        let cw_ica_controller = deps.api.addr_make("ica-controller-contract-addr");
        let ica_addr = deps.api.addr_make("ica_addr");

        // simulated IBC endpoints
        let ibc_endpoint_source = IbcEndpoint {
            port_id: "icacontroller".into(),
            channel_id: "channel-id-endpoint".into(),
        };
        let ibc_endpoint_counterparty = IbcEndpoint {
            port_id: "icahost".into(),
            channel_id: "channel-id-counterparty".into(),
        };

        // default snip params
        // let snip_token_params = vec![
        //     HeadstashTokenParams {
        //         name: "snip120u1-name".into(),
        //         symbol: "SNIP120u1".into(),
        //         native: "usnip120u1".into(),
        //         ibc: "ibc/snip120u1".into(),
        //         snip_addr: Some("secrete1snip120u1".into()),
        //         total: 420u128.into(),
        //     },
        //     HeadstashTokenParams {
        //         name: "snip120u2-name".into(),
        //         symbol: "SNIP120u2".into(),
        //         native: "usnip120u2".into(),
        //         ibc: "ibc/snip120u2".into(),
        //         snip_addr: Some("secrete1snip120u2".into()),
        //         total: 710u128.into(),
        //     },
        // ];

        let headstash_params = HeadstashParams {
            cw_glob: cw_glob.to_string(),
            snip120u_code_id: None,
            headstash_code_id: None,
            headstash_addr: None,
            snip120u_code_hash: None,
            token_params: vec![],
            fee_granter: None,
            multiplier: true,
            bloom_config: Some(BloomConfig {
                default_cadance: 10u64,
                min_cadance: 0u64,
                max_granularity: 5,
            }),
        };

        // init msg
        let msg = InstantiateMsg {
            owner: Some(owner.to_string()),
            feegranter: Some(feegranter.to_string()),
            ica_controller_code_id: 1u64,
            headstash_params: headstash_params.clone(),
        };

        let info = message_info(&creator, &[]);
        instantiate(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();

        assert_eq!(
            state::STATE.load(deps.as_ref().storage).unwrap(),
            ContractState {
                ica_controller_code_id: 1u64,
                headstash_params: headstash_params.clone()
            }
        );

        // manually create ica-account for testing purposes
        ICA_STATES
            .save(
                &mut deps.storage,
                0u64,
                &IcaContractState {
                    contract_addr: cw_ica_controller.clone(),
                    ica_state: Some(IcaState::new(
                        1,
                        "ica-addr".into(),
                        TxEncoding::Proto3Json,
                        ChannelState {
                            channel: IbcChannel::new(
                                ibc_endpoint_source.clone(),
                                ibc_endpoint_counterparty.clone(),
                                IbcOrder::Ordered,
                                "420",
                                "connection-id_69",
                            ),
                            channel_status: ChannelStatus::Open,
                        },
                    )),
                    headstash_params,
                },
            )
            .unwrap();

        CONTRACT_ADDR_TO_ICA_ID
            .save(&mut deps.storage, cw_ica_controller.clone(), &0)
            .unwrap();

        ICA_COUNT.save(&mut deps.storage, &(1)).unwrap();

        // broadcast msg to receive wasm blob from cw-glob
        let get_blob = ExecuteMsg::UploadContractOnSecret {
            ica_id: 0,
            wasm: "snip120u".into(),
        };
        let info = message_info(&owner, &[]);
        let res = execute(deps.as_mut(), env.clone(), info, get_blob).unwrap();
        // println!("{:#?}", res);

        // TODO: move into cw-ica-controller test.
        // let bytes: Vec<u8> = vec![0u8; 120_000]; // 5MB of zeros
        // let binary = Binary::from(bytes);
        // confirm we get expected submessage id
        // assert_eq!(res.messages[0].id, 710);
        // let msg = Reply {
        //     id: res.messages[0].id,
        //     payload: Binary::from("none".as_bytes()),
        //     gas_used: 6969696u64,
        //     result: cosmwasm_std::SubMsgResult::Ok(cosmwasm_std::SubMsgResponse {
        //         events: vec![
        //             Event::new("wasm-headstash")
        //                 .add_attribute("ica-upload-msg", binary.to_string())
        //                 .add_attribute("sender", cw_ica_controller.to_string()), // cw-ica-controller contract
        //         ],
        //         data: None,
        //         msg_responses: vec![],
        //     }),
        // };
        // println!("simulated reply from cw-blob: {:#?}", msg);
        // simulate response from cw-glob
        // let res = reply(deps.as_mut(), env.clone(), msg).unwrap();

        // simulate ica-callback for storing the wasm blobs. These are expected to come from the cw-ica-controller
        let msg_store_code: CosmosMsg<Empty> = CosmosMsg::Stargate {
            type_url: "/secret.compute.v1beta1.MsgStoreCode".into(),
            value: Anybuf::new()
                .append_string(1, ica_addr.clone()) // ica account addr
                .append_bytes(2, &Binary::from("This will be wasm bytes. This will be large. This will need to be paid for. I got 5 on it".as_bytes())) // updated binary of transfer msg.
                .into_vec()
                .into(),
        };

        let submsg = SubMsg::reply_always(msg_store_code.clone(), UPLOAD_REPLY_ID);

        // simulated ibcPacketData for cw-headstash upload
        let original_ica_upload_data = Response::new()
            .add_submessage(submsg.clone())
            .add_attribute(CUSTOM_CALLBACK, HeadstashCallback::UploadHeadstash);

        // simulated response w/ event from secret cosmwasm vm
        let ica_upload_wasm_result = Response::<Empty>::new()
            .add_event(Event::new("store_code").add_attribute("code_id", "369"));

        // simulate ibc-callback storing headstash code-id
        let receive_ica_callback = ExecuteMsg::ReceiveIcaCallback(
            IcaControllerCallbackMsg::OnAcknowledgementPacketCallback {
                ica_acknowledgement: Data::Result(to_json_binary(&ica_upload_wasm_result).unwrap()),
                original_packet: IbcPacket::new(
                    to_json_binary(&original_ica_upload_data).unwrap(),
                    ibc_endpoint_source.clone(),
                    ibc_endpoint_counterparty.clone(),
                    0,
                    IbcTimeout::with_block(IbcTimeoutBlock {
                        revision: 0,
                        height: env.block.height.clone(),
                    }),
                ),
                relayer: Addr::unchecked("based-relayer"),
                query_result: None,
            },
        );
        // println!("receive_ica_callback: {:#?}", receive_ica_callback);

        // simulate reply from cw-ica-controller
        let info = message_info(&cw_ica_controller, &[]);
        execute(
            deps.as_mut(),
            env.clone(),
            info.clone(),
            receive_ica_callback.clone(),
        )
        .unwrap();

        // assert correct code-id is set
        assert_eq!(
            ICA_STATES
                .load(&deps.storage, 0)
                .unwrap()
                .headstash_params
                .headstash_code_id,
            Some(369)
        );

        // simulated mesage
        let original_ica_upload_data = Response::new()
            .add_submessage(submsg.clone())
            .add_attribute(CUSTOM_CALLBACK, HeadstashCallback::UploadSnip120u);

        // simulated response w/ event from secret cosmwasmVM
        let ica_upload_wasm_result = Response::<Empty>::new()
            .add_event(Event::new("store_code").add_attribute("code_id", "420"));

        // simulate ibc-callback storing snip120u code-id
        let receive_ica_callback = ExecuteMsg::ReceiveIcaCallback(
            IcaControllerCallbackMsg::OnAcknowledgementPacketCallback {
                ica_acknowledgement: Data::Result(to_json_binary(&ica_upload_wasm_result).unwrap()),
                original_packet: IbcPacket::new(
                    to_json_binary(&original_ica_upload_data).unwrap(),
                    ibc_endpoint_source.clone(),
                    ibc_endpoint_counterparty.clone(),
                    1,
                    IbcTimeout::with_block(IbcTimeoutBlock {
                        revision: 0,
                        height: env.block.height.clone(),
                    }),
                ),
                relayer: Addr::unchecked("based-relayer"),
                query_result: None,
            },
        );

        // simulate cw-ica-controller to respond
        let info = message_info(&cw_ica_controller, &[]);
        execute(
            deps.as_mut(),
            env.clone(),
            info.clone(),
            receive_ica_callback.clone(),
        )
        .unwrap();

        // assert correct code-id is set
        assert_eq!(
            ICA_STATES
                .load(&deps.storage, 0)
                .unwrap()
                .headstash_params
                .headstash_code_id,
            Some(420)
        );

        // instantiate snip entrypoint
        // let handle_msg = ExecuteMsg::InitSnip120u {
        //     ica_id: 0,
        //     tokens: vec![],
        // };
        // let info = message_info(&creator.clone(), &[]);
        // let res = execute(deps.as_mut(), env.clone(), info.clone(), handle_msg.clone()).unwrap();
        // println!("{:#?}", res);

        // // recieve callback w/ snip120u addrs for HeadstashCallback::InstantiateSnip120us
        // let init_msgs = vec![
        //     snip120u::InstantiateMsg {
        //         name: "TERP".into(),
        //         admin: None,
        //         symbol: "TERP".into(),
        //         decimals: 6,
        //         initial_balances: None,
        //         prng_seed: Binary::new("random".as_bytes().to_vec()),
        //         config: None,
        //         supported_denoms: Some(vec!["uterp".into()]),
        //     },
        //     snip120u::InstantiateMsg {
        //         name: "TERP2".into(),
        //         admin: None,
        //         symbol: "TERP2".into(),
        //         decimals: 6,
        //         initial_balances: None,
        //         prng_seed: Binary::new("random2".as_bytes().to_vec()),
        //         config: None,
        //         supported_denoms: Some(vec!["uterp2".into()]),
        //     },
        // ];
        // let cosmos_msgs: Vec<CosmosMsg<Empty>> = init_msgs
        //     .into_iter()
        //     .enumerate()
        //     .map(|(i, init_msg)| {
        //         CosmosMsg::Stargate {
        //             type_url: "/secret.compute.v1beta1.MsgInstantiateContract".into(),
        //             value: anybuf::Anybuf::new()
        //                 .append_string(1, ica_addr.clone()) // sender (DAO)
        //                 .append_string(2, &format!("CODE_HASH{}", i)) // callback_code_hash
        //                 .append_uint64(3, 420) // code-id of snip-120u
        //                 .append_string(4, format!("SNIP120U For Secret Network - TERP{}", i)) // label of snip20
        //                 .append_bytes(5, to_json_binary(&init_msg).unwrap().as_slice())
        //                 .append_string(8, &format!("CODE_HASH{}", i)) // callback_code_hash
        //                 .into_vec()
        //                 .into(),
        //         }
        //     })
        //     .collect();
        // let mut submsgs = vec![];
        // for msgs in cosmos_msgs {
        //     submsgs.push(SubMsg::new(msgs));
        // }
        // let instantiate_snip120u_res = Response::new()
        //     .add_submessages(submsgs)
        //     .add_attribute(CUSTOM_CALLBACK, HeadstashCallback::InstantiateSnip120us)
        //     .add_event(
        //         Event::new("_instantiate").add_attribute("contract_address", "secret1_snip120u"),
        //     );

        // let on_ack_callback = IcaControllerCallbackMsg::OnAcknowledgementPacketCallback {
        //     ica_acknowledgement: Data::Result(to_json_binary(&instantiate_snip120u_res).unwrap()),
        //     original_packet: IbcPacket::new(
        //         to_json_binary(&msg_store_code).unwrap(),
        //         ibc_endpoint_source.clone(),
        //         ibc_endpoint_counterparty.clone(),
        //         1,
        //         IbcTimeout::with_block(IbcTimeoutBlock {
        //             revision: 0,
        //             height: env.block.height.clone(),
        //         }),
        //     ),
        //     relayer: Addr::unchecked("based-relayer"),
        //     query_result: None,
        // };
        // let receive_ica_callback = ExecuteMsg::ReceiveIcaCallback(on_ack_callback);
        // execute(
        //     deps.as_mut(),
        //     env.clone(),
        //     info.clone(),
        //     receive_ica_callback.clone(),
        // )
        // .unwrap();

        // assert_eq!(
        //     ICA_STATES
        //         .load(&deps.storage, 0)
        //         .unwrap()
        //         .headstash_params
        //         .token_params[0]
        //         .snip_addr,
        //     Some("secret1_snip120u".into())
        // );

        // if tokens lens is 0, grab tokens from init
        // error on no snip code-id or code hash

        // broadcast headstash init msg

        // receive calllback w/ headstash

        // broadcast authorize minter msg

        // broadcast ibc-transfer msg

        // broadcast adding eligible claimers

        // broadcast feegrant authorization

        // reply test
    }
}

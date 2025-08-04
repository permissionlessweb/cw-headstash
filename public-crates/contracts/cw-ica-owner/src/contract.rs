#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    to_json_binary, Addr, Binary, CosmosMsg, Deps, DepsMut, Env, MessageInfo, Reply, Response,
    StdResult,
};
use headstash_public::state::HeadstashParams;
// use cw2::set_contract_version;
use crate::{
    error::ContractError,
    msg::{ExecuteMsg, InstantiateMsg, QueryMsg},
    state::{
        self, ContractState, DeploymentSeq, DEPLOYMENT_SEQUENCE, GLOBAL_CONTRACT_STATE, GRANTEE,
        ICA_CREATED, ICA_STATES,
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

    let HeadstashParams {
        snip120u_code_id,
        headstash_code_id,
        token_params,
        headstash_addr,
        ..
    } = msg.headstash_params.clone();

    if snip120u_code_id.is_some() {
        DEPLOYMENT_SEQUENCE.save(deps.storage, DeploymentSeq::UploadSnip.into(), &true)?;
    } else {
        DEPLOYMENT_SEQUENCE.save(deps.storage, DeploymentSeq::UploadSnip.into(), &false)?;
    }
    if headstash_code_id.is_some() {
        DEPLOYMENT_SEQUENCE.save(deps.storage, DeploymentSeq::UploadHeadstash.into(), &true)?;
    } else {
        DEPLOYMENT_SEQUENCE.save(deps.storage, DeploymentSeq::UploadHeadstash.into(), &false)?;
    }
    // atleast 1 snip120u token param must be set
    if token_params.len() == 0 {
        return Err(ContractError::NoSnip120uParamsSet {});
    }
    // if there is any snip120u addr in params, save to map with enumerated position as part of key
    for (i, param) in token_params.iter().enumerate() {
        if let Some(_) = &param.snip_addr {
            DEPLOYMENT_SEQUENCE.save(
                deps.storage,
                DeploymentSeq::InitSnips.indexed_snip(i),
                &true,
            )?;
        } else {
            DEPLOYMENT_SEQUENCE.save(
                deps.storage,
                DeploymentSeq::InitSnips.indexed_snip(i),
                &false,
            )?;
        }
    }
    if headstash_addr.is_none() {
        DEPLOYMENT_SEQUENCE.save(deps.storage, DeploymentSeq::InitHeadstash.into(), &false)?;
    } else {
        DEPLOYMENT_SEQUENCE.save(deps.storage, DeploymentSeq::InitHeadstash.into(), &true)?;
    }
    ICA_CREATED.save(deps.storage, &false)?;
    GLOBAL_CONTRACT_STATE.save(
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
        // ExecuteMsg::SetCwGlob { cw_glob } => upload::set_cw_glob(deps, info, cw_glob),
        ExecuteMsg::UploadContractOnSecret { wasm, cw_glob } => {
            upload::ica_upload_contract_on_secret(deps, info, wasm, cw_glob)
        }
        ExecuteMsg::ReceiveIcaCallback(callback_msg) => {
            ica::ica_callback_handler(deps, info, callback_msg)
        }
        ExecuteMsg::UpdateOwnership(action) => headstash::update_ownership(deps, env, info, action),
        ExecuteMsg::InitSnip120u {} => instantiate::ica_instantiate_snips(deps, info),
        ExecuteMsg::InitHeadstash {} => {
            instantiate::ica_instantiate_headstash_contract(deps, env, info)
        }
        ExecuteMsg::AuthorizeHeadstashAsSnipMinter {} => {
            headstash::ica_authorize_snip120u_minter(deps, info)
        }
        ExecuteMsg::IbcTransferTokens { channel_id } => {
            headstash::ibc_transfer_to_snip_contracts(deps, env, info, channel_id)
        }
        ExecuteMsg::AddHeadstashClaimers { to_add } => {
            headstash::ica_add_headstash_claimers(deps, info, to_add)
        }
        ExecuteMsg::AuthorizeFeegrant { to_grant, owner } => {
            headstash::ica_authorize_feegrant(deps, info, to_grant, owner)
        }
        ExecuteMsg::AuthzDeployer { grantee } => ica::set_deployer_via_authz(deps, info, grantee),
        ExecuteMsg::SetHeadstashAddr { addr } => headstash::set_headstash_addr(deps, info, addr),
        ExecuteMsg::SetSnip120uAddr { denom, addr } => {
            headstash::set_snip120u(deps, info, denom, addr)
        }
        ExecuteMsg::SetHeadstashCodeId { code_id } => {
            headstash::set_headstash_code_id(deps, info, code_id)
        }
        ExecuteMsg::SetSnip120uCodeId { code_id } => {
            headstash::set_snip120u_code_id(deps, info, code_id)
        }
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetContractState {} => to_json_binary(&query::state(deps)?),
        QueryMsg::GetIcaContractState {} => to_json_binary(&query::ica_state(deps)?),
        QueryMsg::Ownership {} => to_json_binary(&cw_ownable::get_ownership(deps.storage)?),
        QueryMsg::AuthzGrantee {} => to_json_binary(&GRANTEE.load(deps.storage)?),
        QueryMsg::GetDeploymentState {} => todo!(),
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn reply(_deps: DepsMut, _env: Env, reply: Reply) -> Result<Response, ContractError> {
    match reply.result {
        cosmwasm_std::SubMsgResult::Ok(_res) => match reply.id {
            _ => return Err(ContractError::BadReply {}),
        },
        cosmwasm_std::SubMsgResult::Err(a) => return Err(ContractError::SubMsgError(a)),
    }
}

/// Sudo entry point
// #[entry_point]
// #[allow(clippy::pedantic)]
// pub fn sudo(deps: DepsMut, env: Env, msg: SudoMsg) -> Result<Response, ContractError> {
//     let interval = CLOCK_INTERVAL.may_load(deps.storage)?;
//     if let Some(i) = interval {
//         match msg {
//             SudoMsg::HandleIbcBloom {} => {
//                 if env.block.height % i != 0 {
//                     // Send msg to process ibc-blooms
//                     // get default ica account to call
//                     // call contract as ica to handleBloom

//                     // expect callback with new interval
//                     return Ok(Response::new());
//                 }
//             }
//         }
//     }

//     Ok(Response::new())
// }

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

    // pub fn set_cw_glob(
    //     deps: DepsMut,
    //     info: MessageInfo,
    //     cw_glob: String,
    // ) -> Result<Response, ContractError> {
    //     cw_ownable::assert_owner(deps.storage, &info.sender)?;
    //     GLOBAL_CONTRACT_STATE.update(deps.storage, |mut a| {
    //         if a.default_hs_params.cw_glob.is_none() {
    //             a.default_hs_params.cw_glob = Some(deps.api.addr_validate(&cw_glob)?)
    //         } else {
    //             return Err(ContractError::CwGlobExists {});
    //         }
    //         Ok(a)
    //     })?;
    //     Ok(Response::new())
    // }

    /// uploads specific wasm blobs.
    pub fn ica_upload_contract_on_secret(
        deps: DepsMut,
        info: MessageInfo,
        key: String,
        cw_blob: Option<String>,
    ) -> Result<Response, ContractError> {
        let cw_ica_contract =
            helpers::retrieve_ica_owner_account(deps.as_ref(), info.sender.clone())?;

        let blob = match cw_blob.clone() {
            Some(a) => deps.api.addr_validate(&a)?,
            None => {
                GLOBAL_CONTRACT_STATE
                    .load(deps.storage)?
                    .default_hs_params
                    .cw_glob
            }
        };

        match key.as_str() {
            "snip120u" => {
                if DEPLOYMENT_SEQUENCE.load(deps.storage, DeploymentSeq::UploadSnip.into())? {
                    return Err(ContractError::Std(StdError::generic_err(
                        "already have set snip120u code-id",
                    )));
                }
            }
            "cw-headstash" => {
                if !DEPLOYMENT_SEQUENCE.load(deps.storage, DeploymentSeq::UploadSnip.into())? {
                    return Err(ContractError::Std(StdError::generic_err(
                        "must upload snip120u first",
                    )));
                } else if DEPLOYMENT_SEQUENCE
                    .load(deps.storage, DeploymentSeq::UploadHeadstash.into())?
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
                glob_key: key.clone(),
                packet_memo: Some("23".into()),
                timeout_seconds: None,
                cw_glob: Some(blob),
            },
        )?;

        Ok(Response::default().add_message(upload_msg))
    }
}

pub mod instantiate {

    use headstash_public::state::{InstantiateMsg, Snip120u};

    use super::helpers::*;
    use super::*;
    use crate::msg::HeadstashCallback;

    /// Creates a snip120u msg for ica-controller to send.
    pub fn ica_instantiate_snips(
        deps: DepsMut,
        info: MessageInfo,
    ) -> Result<Response, ContractError> {
        let mut msgs = vec![];
        let cw_ica_contract = retrieve_ica_owner_account(deps.as_ref(), info.sender.clone())?;

        let state = ICA_STATES.load(deps.storage)?;
        let hp = state.headstash_params;

        // if headstash or snip120u is not set, we cannot instantiate snips
        if !DEPLOYMENT_SEQUENCE.load(deps.storage, DeploymentSeq::UploadSnip.into())?
            && hp.snip120u_code_id.is_none()
        {
            return Err(ContractError::NoSnipCodeId {});
        } else if !DEPLOYMENT_SEQUENCE.load(deps.storage, DeploymentSeq::UploadHeadstash.into())?
            && hp.headstash_code_id.is_none()
        {
            return Err(ContractError::NoHeadstashCodeId {});
        }

        for token in &hp.token_params {
            if hp.token_params.len() != 0 {
                if let Some(t) = hp.token_params.iter().find(|t| t.native == token.native) {
                    let msg = self::ica::form_instantiate_snip120u(
                        cw_ica_contract.addr().to_string(),
                        token.clone(),
                        hp.snip120u_code_hash.clone(),
                        hp.snip120u_code_id.unwrap(),
                        hp.headstash_addr.clone(),
                        t.symbol.clone(),
                    )?;
                    msgs.push(msg);
                }
            } else {
                return Err(ContractError::NoSnip120uParamsSet {});
            }
        }

        let msg_lens = msgs.len().to_string();
        let msg = send_msg_as_ica(msgs, cw_ica_contract);

        Ok(Response::new()
            .add_message(msg)
            .add_attribute(CUSTOM_CALLBACK, HeadstashCallback::InstantiateSnip120us)
            .add_attribute("msg_lens", msg_lens))
    }

    pub fn ica_instantiate_headstash_contract(
        deps: DepsMut,
        env: Env,
        info: MessageInfo,
    ) -> Result<Response, ContractError> {
        let mut msgs = vec![];
        let ica_state = ICA_STATES.load(deps.storage)?;
        let hs_params = ica_state.headstash_params;
        let cw_ica_contract = retrieve_ica_owner_account(deps.as_ref(), info.sender.clone())?;

        // iterate and enumerate for each snip in snip params, if they deployment sequence is not met, and there is addr for each snip, error.
        for (i, hstp) in hs_params.token_params.iter().enumerate() {
            // println!("token_param: {i}, {:#?}", param);
            if !DEPLOYMENT_SEQUENCE.load(deps.storage, DeploymentSeq::InitSnips.indexed_snip(i))?
                && hstp.snip_addr.is_none()
            {
                return Err(ContractError::NoSnip120uContract {});
            }
        }

        if let Some(ica) = ica_state.ica_state {
            // println!("{:#?}", hs_params);
            // cw-headstash code-id must be known
            if let Some(code_id) = hs_params.headstash_code_id {
                let mut hs_snips = vec![];
                // at least 1 snip120u must exist
                for snip in hs_params.token_params.clone() {
                    // println!("{:#?}", snip.snip_addr);
                    if snip.snip_addr.is_none() {
                        return Err(ContractError::NoSnipContractAddr {});
                    }
                    let snip = Snip120u {
                        token: snip.native,
                        name: snip.name,
                        addr: Some(Addr::unchecked(snip.snip_addr.unwrap())),
                        total_amount: snip.total,
                    };
                    hs_snips.push(snip);
                }
                // form cw-headstash instantiate msg
                let init_headstash_msg = instantiate_headstash_msg(
                    code_id,
                    InstantiateMsg {
                        claim_msg_plaintext: hs_params.headstash_init_config.claim_msg_plaintxt,
                        end_date: Some(
                            hs_params
                                .headstash_init_config
                                .end_date
                                .unwrap_or(env.block.time.plus_days(365u64).nanos()), // one year
                        ),
                        start_date: hs_params.headstash_init_config.end_date,
                        random_key: hs_params.headstash_init_config.random_key,
                        owner: Addr::unchecked(ica.ica_addr),
                        snip120u_code_hash: hs_params.snip120u_code_hash,
                        snips: hs_snips,
                        multiplier: hs_params.multiplier,
                        bloom_config: hs_params.bloom_config,
                    },
                )?;
                let msg = send_msg_as_ica(vec![init_headstash_msg], cw_ica_contract);
                msgs.push(msg)
            } else {
                return Err(ContractError::BadContractid {});
            }
        } else {
            return Err(ContractError::NoIcaInfo {});
        }

        Ok(Response::new().add_messages(msgs))
    }
}

mod headstash {
    use cosmwasm_std::coin;
    use headstash_public::state::Headstash;
    use state::DeploymentSeq;

    use super::*;
    use crate::msg::HeadstashCallback;

    pub fn create_ica_contract(
        deps: DepsMut,
        env: Env,
        info: MessageInfo,
        salt: Option<String>,
        channel_open_init_options: ChannelOpenInitOptions,
        headstash_params: Option<HeadstashParams>,
    ) -> Result<Response, ContractError> {
        cw_ownable::assert_owner(deps.storage, &info.sender)?;
        let state = GLOBAL_CONTRACT_STATE.load(deps.storage)?;

        let ica_code = CwIcaControllerCode::new(state.ica_controller_code_id);

        let instantiate_msg = cw_ica_controller::types::msg::InstantiateMsg {
            owner: Some(env.contract.address.to_string()),
            channel_open_init_options,
            send_callbacks_to: Some(env.contract.address.to_string()), // always send callbacks to this contract.
        };

        if ICA_CREATED.load(deps.storage)? {
            return Err(ContractError::IcaAccountExists {});
        };

        let salt = salt.unwrap_or(env.block.time.seconds().to_string());
        let label = format!(
            "ica-controller-{}-{}",
            env.contract.address,
            cw_ownable::get_ownership(deps.storage)?
                .owner
                .unwrap_or(info.sender)
        );

        let (cosmos_msg, contract_addr) = ica_code.instantiate2(
            deps.api,
            &deps.querier,
            &env,
            instantiate_msg,
            label,
            Some(env.contract.address.to_string()),
            salt,
        )?;

        let hs_params = headstash_params.unwrap_or(state.default_hs_params); // provide new headstash params, or borrow from params set on init.
        let initial_state = state::IcaContractState::new(contract_addr.clone(), hs_params);

        ICA_STATES.save(deps.storage, &initial_state)?;

        // CONTRACT_ADDR_TO_ICA_ID.save(deps.storage, contract_addr, &ica_count)?;

        Ok(Response::new().add_message(cosmos_msg))
    }

    pub fn ica_authorize_snip120u_minter(
        deps: DepsMut,
        info: MessageInfo,
    ) -> Result<Response, ContractError> {
        let mut msgs = vec![];
        let cw_ica_contract =
            helpers::retrieve_ica_owner_account(deps.as_ref(), info.sender.clone())?;

        let state = ICA_STATES.load(deps.storage)?;
        let hp = state.headstash_params;

        if let Some(ica) = state.ica_state.clone() {
            if let Some(hs_addr) = hp.headstash_addr {
                // load snip120u's from state
                for snip in hp.token_params {
                    if let Some(addr) = snip.snip_addr {
                        // add minter msg
                        let msg = ica::form_authorize_minter(
                            ica.ica_addr.clone(),
                            hs_addr.clone(),
                            addr,
                        )?;
                        msgs.push(msg);
                    } else {
                        return Err(ContractError::NoSnip120uContract {});
                    }
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

    /// transfer each token to their respective snip120u addrs.
    /// This contract is expected to have a balance of the funds expected to be sent in the tokenParams\
    /// todo: add custom amount to transfer, ensure contract has balance or funds were sent in msg.
    pub fn ibc_transfer_to_snip_contracts(
        deps: DepsMut,
        env: Env,
        info: MessageInfo,
        channel_id: String,
    ) -> Result<Response, ContractError> {
        cw_ownable::assert_owner(deps.storage, &info.sender)?;
        let mut msgs = vec![];
        let state = ICA_STATES.load(deps.storage)?;
        let hp = state.headstash_params;
        for token in hp.token_params {
            if let Some(snip) = token.snip_addr.clone() {
                let msg = ica::form_ibc_transfer_msg(
                    env.block.time,
                    600u64,
                    snip,
                    channel_id.clone(),
                    coin(token.total.into(), token.native),
                )?;
                msgs.push(msg);
            } else {
                return Err(ContractError::NoSnipContractAddr {});
            }
        }

        Ok(Response::new()
            .add_messages(msgs)
            .add_attribute(CUSTOM_CALLBACK, HeadstashCallback::FundHeadstash))
    }

    pub fn ica_add_headstash_claimers(
        deps: DepsMut,
        info: MessageInfo,
        to_add: Vec<Headstash>,
    ) -> Result<Response, ContractError> {
        let mut msgs = vec![];
        let cw_ica_contract =
            helpers::retrieve_ica_owner_account(deps.as_ref(), info.sender.clone())?;
        let state = ICA_STATES.load(deps.storage)?;

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
        to_grant: Vec<String>,
        owner: Option<String>,
    ) -> Result<Response, ContractError> {
        let mut msgs = vec![];
        let feegranter = GLOBAL_CONTRACT_STATE
            .load(deps.storage)?
            .default_hs_params
            .fee_granter;
        // fee granter provides owner, contract checks sender is feegranter.
        let cw_ica_contract = match owner {
            Some(a) => {
                if let Some(b) = feegranter {
                    if info.sender.to_string() != b {
                        return Err(ContractError::NotValidFeegranter {});
                    }
                }
                helpers::retrieve_ica_owner_account(deps.as_ref(), deps.api.addr_validate(&a)?)?
            }
            None => helpers::retrieve_ica_owner_account(deps.as_ref(), info.sender.clone())?,
        };

        let state = ICA_STATES.load(deps.storage)?;

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

    pub fn set_snip120u_code_id(
        deps: DepsMut,
        info: MessageInfo,
        code_id: u64,
    ) -> Result<Response, ContractError> {
        cw_ownable::assert_owner(deps.storage, &info.sender)?;
        let mut state = ICA_STATES.load(deps.storage)?;
        let HeadstashParams {
            snip120u_code_id, ..
        } = state.headstash_params;
        if snip120u_code_id.is_some() {
            return Err(ContractError::SetSnip120uCodeError {});
        } else {
            state.headstash_params.snip120u_code_id = Some(code_id);
            DEPLOYMENT_SEQUENCE.save(deps.storage, DeploymentSeq::UploadSnip.into(), &true)?;
            ICA_STATES.save(deps.storage, &state)?;
        }
        Ok(Response::new())
    }

    pub fn set_headstash_code_id(
        deps: DepsMut,
        info: MessageInfo,
        code_id: u64,
    ) -> Result<Response, ContractError> {
        cw_ownable::assert_owner(deps.storage, &info.sender)?;

        let mut state = ICA_STATES.load(deps.storage)?;
        let HeadstashParams {
            headstash_code_id,
            snip120u_code_id,
            ..
        } = state.headstash_params;

        if headstash_code_id.is_some() || snip120u_code_id.is_none() {
            return Err(ContractError::SetHeadstashCodeError {});
        } else {
            state.headstash_params.headstash_code_id = Some(code_id);
            DEPLOYMENT_SEQUENCE.save(deps.storage, DeploymentSeq::UploadHeadstash.into(), &true)?;
            ICA_STATES.save(deps.storage, &state)?;
        }

        Ok(Response::new())
    }
    pub fn set_headstash_addr(
        deps: DepsMut,
        info: MessageInfo,
        addr_to_set: String,
    ) -> Result<Response, ContractError> {
        cw_ownable::assert_owner(deps.storage, &info.sender)?;
        let mut state = ICA_STATES.load(deps.storage)?;
        // ensure snip & headstash code-id upload sequence is set
        let HeadstashParams {
            headstash_addr,
            headstash_code_id,
            snip120u_code_id,
            ..
        } = state.headstash_params;

        if headstash_code_id.is_none() || snip120u_code_id.is_none() || headstash_addr.is_some() {
            return Err(ContractError::SetHeadstashAddrError {});
        } else {
            state.headstash_params.headstash_addr = Some(addr_to_set);
        }
        ICA_STATES.save(deps.storage, &state)?;
        DEPLOYMENT_SEQUENCE.save(deps.storage, DeploymentSeq::InitHeadstash.into(), &true)?;

        Ok(Response::new())
    }

    pub fn set_snip120u(
        deps: DepsMut,
        info: MessageInfo,

        token: String,
        contract_addr: String,
    ) -> Result<Response, ContractError> {
        cw_ownable::assert_owner(deps.storage, &info.sender)?;
        let mut state = ICA_STATES.load(deps.storage)?;
        let HeadstashParams {
            headstash_code_id,
            snip120u_code_id,
            ..
        } = state.headstash_params;

        if headstash_code_id.is_none() || snip120u_code_id.is_none() {
            return Err(ContractError::SetInitSnip120uError {});
        } else {
            if let Some((i, a)) = state
                .headstash_params
                .token_params
                .iter_mut()
                .enumerate()
                .find(|(_, a)| a.symbol == token)
            {
                // println!("found index at {:#?}", i);
                if a.snip_addr.is_none() {
                    a.snip_addr = Some(contract_addr);
                    DEPLOYMENT_SEQUENCE.save(
                        deps.storage,
                        DeploymentSeq::InitSnips.indexed_snip(i),
                        &true,
                    )?;
                } else {
                    return Err(ContractError::Snip120uAddrAlreadySet {});
                }
            }
        }
        ICA_STATES.save(deps.storage, &state)?;
        Ok(Response::new())
    }
}

mod query {
    use crate::state::{IcaContractState, ICA_STATES};

    use super::*;

    /// Returns the saved contract state.
    pub fn state(deps: Deps) -> StdResult<ContractState> {
        GLOBAL_CONTRACT_STATE.load(deps.storage)
    }

    /// Returns the saved ICA state for the given ICA ID.
    pub fn ica_state(deps: Deps) -> StdResult<IcaContractState> {
        ICA_STATES.load(deps.storage)
    }
}

pub mod ica {
    use anybuf::Anybuf;
    use cosmos_sdk_proto::{
        cosmos::authz::v1beta1::{GenericAuthorization, Grant, MsgGrant},
        prost, Any,
    };
    use headstash_public::state::{Headstash, HeadstashTokenParams};
    use prost::Message;
    // use cosmrs::{
    //     proto::cosmos::authz::v1beta1::{GenericAuthorization, Grant, MsgGrant},
    //     tx::MessageExt,
    //     Any,
    // };
    use cosmwasm_std::{from_json, Coin, Empty, IbcTimeout, Timestamp, Uint128};
    use cw_ica_controller::{
        ibc::types::packet::acknowledgement::Data,
        types::state::{ChannelState, ChannelStatus},
    };
    use state::DeploymentSeq;

    use crate::msg::constants::*;

    use super::*;
    /// Handles ICA controller callback messages.
    /// The following callbacks are expected:
    /// 1. code-id callback for snip120u
    /// 2. code-id callback for headstash
    /// 3. contract addr for snip120u(s)
    /// 4. contract addr for cw-headstash
    pub fn ica_callback_handler(
        deps: DepsMut,
        _info: MessageInfo,
        callback_msg: IcaControllerCallbackMsg,
    ) -> Result<Response, ContractError> {
        let mut ica_state = ICA_STATES.load(deps.storage)?;
        let token_params = ica_state.headstash_params.token_params.clone();

        match callback_msg {
            IcaControllerCallbackMsg::OnAcknowledgementPacketCallback {
                ica_acknowledgement,
                // original_packet,
                ..
            } => match ica_acknowledgement {
                Data::Result(res) => {
                    let response: Response<Empty> = from_json(&res)?;
                    // 1. if snip has not been uploaded, this is a snip upload callback.
                    // This deployment sequence step will be set to true, if snip code-id provided during ica-owner contract init.
                    if !DEPLOYMENT_SEQUENCE.load(deps.storage, DeploymentSeq::UploadSnip.into())? {
                        if let Some(event) = response.events.iter().find(|e| e.ty == "store_code") {
                            let code_id = event.attributes[0].value.clone();
                            // get code-hash from cw-glob (via query?)
                            // set code-id for snip120u to state
                            ica_state.headstash_params.snip120u_code_id =
                                Some(u64::from_str_radix(&code_id, 10)?);
                            ICA_STATES.save(deps.storage, &ica_state)?;
                            DEPLOYMENT_SEQUENCE.save(
                                deps.storage,
                                DeploymentSeq::UploadSnip.into(),
                                &true,
                            )?;
                        } else {
                            return Err(ContractError::BadStoreSnip120uCodeResponse {});
                        }
                        Ok(Response::default().add_attribute("sequence", "upload_snip120u"))
                    // 2. if headstash has not been uploaded, this is a headstash upload callback
                    // This deployment sequence step will be set to true, if headstash code-id provided during ica-owner contract init.
                    } else if !DEPLOYMENT_SEQUENCE
                        .load(deps.storage, DeploymentSeq::UploadHeadstash.into())?
                    {
                        // TODO: if snip120u code-id is still not set, something must have errored
                        if ica_state.headstash_params.snip120u_code_id.is_none() {}
                        if let Some(event) = response.events.iter().find(|e| e.ty == "store_code") {
                            let code_id = event.attributes[0].value.clone();
                            // set code-id for headstash to state
                            ica_state.headstash_params.headstash_code_id =
                                Some(u64::from_str_radix(&code_id, 10)?);
                            // set code-hash for headstash to state
                            // ica_state.headstash_params.headstash_code_hash = Some(checksum);
                            ICA_STATES.save(deps.storage, &ica_state)?;
                            DEPLOYMENT_SEQUENCE.save(deps.storage, "cw-headstash".into(), &true)?;
                        } else {
                            return Err(ContractError::BadStoreHeadstashCodeResponse {});
                        }
                        Ok(Response::default().add_attribute("sequence", "upload_headstash"))
                    // 3. if both snip120u & headstash code-id exist, this callback is for instantiating snip120u's.
                    // The deployment sequence step is saved by enumerated index for each snip involved. These will be set to true for each snip
                    } else {
                        if ica_state.headstash_params.headstash_code_id.is_none() {}
                        // check if each snip in token_params has been instantiated.

                        let mut uninstantiated_snips = Vec::new();
                        for (i, hstp) in token_params.iter().enumerate() {
                            if !DEPLOYMENT_SEQUENCE
                                .load(deps.storage, DeploymentSeq::InitSnips.indexed_snip(i))?
                            {
                                uninstantiated_snips.push((i, hstp));
                            }
                        }

                        if !uninstantiated_snips.is_empty() {
                            for index in uninstantiated_snips {
                                for event in
                                    response.events.iter().filter(|e| e.ty == "instantiate")
                                {
                                    if let Some(attr) = event
                                        .attributes
                                        .iter()
                                        .find(|a| a.key == "contract_address")
                                    {
                                        // println!(
                                        //     "attr: {:#?},{:#?},{:#?},",
                                        //     attr,
                                        //     index.0,
                                        //     attr.value.clone()
                                        // );
                                        let mut current_index = index.0;
                                        // Recursively try the next index until we find one that does not exist
                                        while current_index
                                            < ica_state.headstash_params.token_params.len()
                                            && ica_state.headstash_params.token_params
                                                [current_index]
                                                .snip_addr
                                                .is_some()
                                        {
                                            current_index += 1;
                                        }

                                        if current_index
                                            < ica_state.headstash_params.token_params.len()
                                        {
                                            ica_state.headstash_params.token_params
                                                [current_index]
                                                .snip_addr = Some(attr.value.clone());
                                        }

                                        ICA_STATES.save(deps.storage, &ica_state)?;
                                        DEPLOYMENT_SEQUENCE.save(
                                            deps.storage,
                                            DeploymentSeq::InitSnips.indexed_snip(index.0),
                                            &true,
                                        )?;
                                    }
                                }
                            }

                            Ok(Response::new())
                        } else {
                            if !DEPLOYMENT_SEQUENCE
                                .load(deps.storage, DeploymentSeq::InitHeadstash.into())?
                            {
                                if let Some(event) =
                                    response.events.iter().find(|e| e.ty == "instantiate")
                                {
                                    ica_state.headstash_params.headstash_addr =
                                        Some(event.attributes[0].value.clone());
                                }
                                ICA_STATES.save(deps.storage, &ica_state)?;
                                DEPLOYMENT_SEQUENCE.save(
                                    deps.storage,
                                    DeploymentSeq::InitHeadstash.into(),
                                    &true,
                                )?;

                                return Ok(Response::default());
                            }
                            Ok(Response::default())
                        }
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
                    channel_state: ChannelState {
                        channel,
                        channel_status: ChannelStatus::Open,
                    },
                    ica_addr: ica_address,
                    tx_encoding,
                });
                ICA_STATES.save(deps.storage, &ica_state)?;
                Ok(Response::default())
            }
        }
    }

    pub fn set_deployer_via_authz(
        deps: DepsMut,
        info: MessageInfo,
        grantee: String,
    ) -> Result<Response, ContractError> {
        if GRANTEE.may_load(deps.storage)?.is_some() {
            return Err(ContractError::AuthzGranteeExists {});
        }
        // grab ica info
        let cw_ica_contract =
            helpers::retrieve_ica_owner_account(deps.as_ref(), info.sender.clone())?;
        let ica_state = ICA_STATES.load(deps.storage)?;
        let terp_ica_addr = ica_state.ica_state.expect("no ica state exists").ica_addr;

        // form grant msgs data for x/authz module on secret. proto ref: https://github.com/cosmos/cosmos-sdk/blob/v0.45.16/proto/cosmos/authz/v1beta1/tx.proto
        let grant_msgs: Vec<MsgGrant> = vec![
            SECRET_COMPUTE_STORE_CODE,
            SECRET_COMPUTE_INSTANTIATE,
            SECRET_COMPUTE_EXECUTE,
        ]
        .into_iter()
        .map(|msg| {
            let grant = Grant {
                authorization: Some(Any {
                    type_url: COSMOS_GENERIC_AUTHZ.to_string(),
                    value: GenericAuthorization {
                        msg: msg.to_string(),
                    }
                    .encode_to_vec(),
                }),
                expiration: None,
            };
            MsgGrant {
                granter: terp_ica_addr.to_string(),
                grantee: grantee.clone(),
                grant: Some(grant),
            }
        })
        .collect();

        // form Cosmos messages for ica to broadcasts.
        let msgs: Vec<CosmosMsg> = grant_msgs
            .into_iter()
            .map(|grant| {
                // form ica-msg to grant CosmWasm Actions on behalf of ica
                let msg = Anybuf::new()
                    .append_string(1, terp_ica_addr.clone()) // granter
                    .append_string(2, grantee.clone()) // grantee
                    .append_bytes(
                        3,                                  // grant
                        Binary::new(grant.encode_to_vec()), // cw-ica SendCosmosMsgs
                    )
                    .append_repeated_bytes::<Vec<u8>>(5, &[]) // funds
                    .into_vec()
                    .into();

                #[allow(deprecated)]
                CosmosMsg::Stargate {
                    type_url: COSMOS_AUTHZ_GRANT.to_string(),
                    value: msg,
                }
            })
            .collect();

        // push msgs for ica to run
        let ica_msg = helpers::send_msg_as_ica(msgs, cw_ica_contract);

        Ok(Response::new().add_message(ica_msg))
    }

    /// Instantiates a snip120u token on Secret Network via Stargate
    pub fn form_instantiate_snip120u(
        sender: String,
        coin: HeadstashTokenParams,
        _code_hash: String,
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
                    .append_string(1, sender.to_string()) // sender (ICA Address)
                    .append_uint64(3, code_id) // code-id of snip-25
                    .append_string(
                        4,
                        "SNIP120U For Secret Network - ".to_owned() + coin.name.as_str(),
                    ) // label of snip20
                    .append_bytes(5, to_json_binary(&init_msg)?.as_slice())
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
                    .append_string(1, sender.to_string()) // sender (ICA Addr)
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
        let msg = headstash_public::state::ExecuteMsg::AddEligibleHeadStash { headstash: to_add };
        Ok(
            #[allow(deprecated)]
            CosmosMsg::Stargate {
                type_url: SECRET_COMPUTE_EXECUTE.into(),
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
    use super::*;
    use crate::state::ICA_STATES;
    use cosmwasm_std::Empty;

    /// Retrieves an ica account for the given sender and the account id. only contract owner can call this.
    pub fn retrieve_ica_owner_account(
        deps: Deps,
        sender: Addr,
    ) -> Result<CwIcaControllerContract, ContractError> {
        cw_ownable::assert_owner(deps.storage, &sender)?;

        let ica_state = ICA_STATES.load(deps.storage)?;

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
        scrt_headstash_msg: headstash_public::state::InstantiateMsg,
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
    use crate::{
        contract::{execute, instantiate},
        msg::{ExecuteMsg, InstantiateMsg},
        state::{
            self, snip120u, ContractState, DeploymentSeq, IcaContractState, IcaState, ICA_CREATED,
            ICA_STATES, UPLOAD_REPLY_ID,
        },
        ContractError,
    };
    use anybuf::Anybuf;
    use cosmwasm_std::{
        testing::{message_info, mock_dependencies, mock_env},
        to_json_binary, Addr, Binary, CosmosMsg, Empty, Event, IbcChannel, IbcEndpoint, IbcOrder,
        IbcPacket, IbcTimeout, IbcTimeoutBlock, Response, SubMsg,
    };
    use cw_ica_controller::{
        ibc::types::{metadata::TxEncoding, packet::acknowledgement::Data},
        types::{
            callbacks::IcaControllerCallbackMsg,
            msg::options::ChannelOpenInitOptions,
            state::{ChannelState, ChannelStatus},
        },
    };
    use cw_ownable::OwnershipError;
    use headstash_public::state::{
        BloomConfig, HeadstashInitConfig, HeadstashParams, HeadstashTokenParams, Snip120u,
    };
    use std::error::Error;

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
        let ica_addr = Addr::unchecked("ica_addr");
        let headstash_addr = Addr::unchecked("secret1_headstash_addr");
        let authz_grantee = Addr::unchecked("secret1_authz_grantee");

        // simulated token-info
        let snip_token_params = vec![
            HeadstashTokenParams {
                name: "snip120u1-name".into(),
                symbol: "SNIP120u1".into(),
                native: "usnip120u1".into(),
                ibc: "ibc/snip120u1".into(),
                snip_addr: None,
                total: 420u128.into(),
                source_channel: "eretskeret".into(),
            },
            HeadstashTokenParams {
                name: "snip120u2-name".into(),
                symbol: "SNIP120u2".into(),
                native: "usnip120u2".into(),
                ibc: "ibc/snip120u2".into(),
                snip_addr: None,
                total: 710u128.into(),
                source_channel: "jeretbleret".into(),
            },
        ];

        // simulated IBC endpoints
        let ibc_endpoint_source = IbcEndpoint {
            port_id: "icacontroller".into(),
            channel_id: "channel-id-endpoint".into(),
        };
        let ibc_endpoint_counterparty = IbcEndpoint {
            port_id: "icahost".into(),
            channel_id: "channel-id-counterparty".into(),
        };

        // simmulated message info
        let info_creator = message_info(&creator, &[]);
        let info_owner = message_info(&owner, &[]);
        let info_ica_controller = message_info(&cw_ica_controller, &[]);

        // simulated messages
        let msg_init_headstash = ExecuteMsg::InitHeadstash {};
        let msg_init_snip120u = ExecuteMsg::InitSnip120u {};
        let msg_upload_snip120u = ExecuteMsg::UploadContractOnSecret {
            wasm: DeploymentSeq::UploadSnip.into(),
            cw_glob: Some(cw_glob.to_string()),
        };
        let msg_upload_headstash = ExecuteMsg::UploadContractOnSecret {
            wasm: DeploymentSeq::UploadHeadstash.into(),
            cw_glob: Some(cw_glob.to_string()),
        };
        let msg_authorize_minter = ExecuteMsg::AuthorizeHeadstashAsSnipMinter {};
        let msg_ibc_transfer = ExecuteMsg::IbcTransferTokens {
            channel_id: "transfer-channel".into(),
        };
        let msg_add_headstashers = ExecuteMsg::AddHeadstashClaimers { to_add: vec![] };
        let msg_authorize_feegrant = ExecuteMsg::AuthorizeFeegrant {
            to_grant: vec![],
            owner: None,
        };
        let msg_set_authz_grantee = ExecuteMsg::AuthzDeployer {
            grantee: authz_grantee.to_string(),
        };
        let msg_set_headstash_code_manually = ExecuteMsg::SetHeadstashCodeId { code_id: 69 };
        let msg_set_snip120u_code_manually = ExecuteMsg::SetSnip120uCodeId { code_id: 420 };
        let msg_set_headstash_manually = ExecuteMsg::SetHeadstashAddr {
            addr: "secret1-new-headstash".into(),
        };
        let msg_set_snip_manually: Vec<ExecuteMsg> = (1..2)
            .map(|i| ExecuteMsg::SetSnip120uAddr {
                addr: format!("secret1-new-snip120u{}", i),
                denom: format!("SNIP120u{}", i),
            })
            .collect();

        let headstash_params = HeadstashParams {
            snip120u_code_id: None,
            headstash_code_id: None,
            headstash_addr: None,
            snip120u_code_hash: "SNIP120U_CODE_HASH".into(),
            token_params: snip_token_params.clone(),
            fee_granter: None,
            multiplier: true,
            bloom_config: Some(BloomConfig {
                default_cadance: 10u64,
                min_cadance: 0u64,
                max_granularity: 5,
            }),
            cw_glob: Addr::unchecked("cw-glob"),
            headstash_init_config: HeadstashInitConfig {
                claim_msg_plaintxt: "HREAM ~ {wallet} ~ {secondary_addr} ~ {expiration}".into(),
                end_date: None,
                start_date: None,
                random_key: "eretskeretjableret".into(),
            },
        };

        // init msg
        let msg = InstantiateMsg {
            owner: Some(owner.to_string()),
            feegranter: Some(feegranter.to_string()),
            ica_controller_code_id: 1u64,
            headstash_params: headstash_params.clone(),
        };
        // instantiate cw-ica-owner
        instantiate(deps.as_mut(), env.clone(), info_creator.clone(), msg).unwrap();

        // confirm contract state
        assert_eq!(
            state::GLOBAL_CONTRACT_STATE
                .load(deps.as_ref().storage)
                .unwrap(),
            ContractState {
                ica_controller_code_id: 1u64,
                default_hs_params: headstash_params.clone()
            }
        );

        // test create ica-account
        let create_msg = ExecuteMsg::CreateIcaContract {
            salt: Some("salllllt".into()),
            channel_open_init_options: ChannelOpenInitOptions {
                connection_id: "connection-69".into(),
                counterparty_connection_id: "connection-id_420".into(),
                counterparty_port_id: None,
                channel_ordering: None,
            },
            headstash_params: None,
        };

        // cannot create if not owner
        let res = execute(
            deps.as_mut(),
            env.clone(),
            info_creator.clone(),
            create_msg.clone(),
        )
        .unwrap_err();
        assert_eq!(
            res.source().unwrap().to_string(),
            ContractError::OwnershipError(cw_ownable::OwnershipError::NotOwner).to_string()
        );

        // manually create ica-account for testing purposes
        ICA_STATES
            .save(
                &mut deps.storage,
                &IcaContractState {
                    contract_addr: cw_ica_controller.clone(),
                    ica_state: Some(IcaState::new(
                        "ica-addr".into(),
                        TxEncoding::Proto3Json,
                        ChannelState {
                            channel: IbcChannel::new(
                                ibc_endpoint_source.clone(),
                                ibc_endpoint_counterparty.clone(),
                                IbcOrder::Ordered,
                                "420",
                                "connection-69",
                            ),
                            channel_status: ChannelStatus::Open,
                        },
                    )),
                    headstash_params,
                },
            )
            .unwrap();

        // manually set cw-ica-controller key
        ICA_CREATED.save(&mut deps.storage, &true).unwrap();

        // UPLOAD HEADSTASH

        // cannot upload headstash before snip120u
        let res = execute(
            deps.as_mut(),
            env.clone(),
            info_owner.clone(),
            msg_upload_headstash,
        )
        .unwrap_err();
        assert_eq!(
            res.source().unwrap().to_string(),
            "Generic error: must upload snip120u first".to_string()
        );
        // error on no snip contract addrs
        let err = execute(
            deps.as_mut(),
            env.clone(),
            info_owner.clone(),
            msg_init_headstash.clone(),
        )
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            ContractError::NoSnip120uContract {}.to_string()
        );

        // cannot manually set values before code-ids are set
        let err = execute(
            deps.as_mut(),
            env.clone(),
            info_creator.clone(),
            msg_set_headstash_manually.clone(),
        )
        .unwrap_err();
        assert_eq!(err.to_string(), OwnershipError::NotOwner {}.to_string());
        let err = execute(
            deps.as_mut(),
            env.clone(),
            info_owner.clone(),
            msg_set_headstash_manually.clone(),
        )
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            ContractError::SetHeadstashAddrError {}.to_string()
        );

        for msg in msg_set_snip_manually.clone() {
            let err = execute(
                deps.as_mut(),
                env.clone(),
                info_creator.clone(),
                msg.clone(),
            )
            .unwrap_err();
            assert_eq!(err.to_string(), OwnershipError::NotOwner {}.to_string());
            let err =
                execute(deps.as_mut(), env.clone(), info_owner.clone(), msg.clone()).unwrap_err();
            assert_eq!(
                err.to_string(),
                ContractError::SetInitSnip120uError {}.to_string()
            );
        }

        // cannot manually set values before code-ids are set
        let err = execute(
            deps.as_mut(),
            env.clone(),
            info_creator.clone(),
            msg_set_headstash_code_manually.clone(),
        )
        .unwrap_err();
        assert_eq!(err.to_string(), OwnershipError::NotOwner {}.to_string());
        let err = execute(
            deps.as_mut(),
            env.clone(),
            info_owner.clone(),
            msg_set_headstash_code_manually.clone(),
        )
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            ContractError::SetHeadstashCodeError {}.to_string()
        );

        // UPLOAD SNIP120u
        execute(
            deps.as_mut(),
            env.clone(),
            info_owner.clone(),
            msg_upload_snip120u,
        )
        .unwrap();
        // assert correct contract value is passed in attribute

        // simulate ica-callback for storing the wasm blobs.
        #[allow(deprecated)]
        let msg_store_code: CosmosMsg<Empty> = CosmosMsg::Stargate {
            type_url: "/secret.compute.v1beta1.MsgStoreCode".into(),
            value: Anybuf::new()
                .append_string(1, ica_addr.clone()) // ica account addr
                .append_bytes(2, &Binary::from("This will be wasm bytes. This will be large. This will need to be paid for. I got 5 on it".as_bytes())) // updated binary of transfer msg.
                .into_vec()
                .into(),
        };

        let submsg = SubMsg::reply_always(msg_store_code.clone(), UPLOAD_REPLY_ID);

        // simulated ibcPacketData for snip120u upload
        let original_ica_upload_data = Response::new().add_submessage(submsg.clone());

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
        execute(
            deps.as_mut(),
            env.clone(),
            info_ica_controller.clone(),
            receive_ica_callback.clone(),
        )
        .unwrap();

        // assert correct code-id is set
        assert_eq!(
            ICA_STATES
                .load(&deps.storage)
                .unwrap()
                .headstash_params
                .snip120u_code_id,
            Some(369)
        );

        let err = execute(
            deps.as_mut(),
            env.clone(),
            info_creator.clone(),
            msg_set_snip120u_code_manually.clone(),
        )
        .unwrap_err();
        assert_eq!(err.to_string(), OwnershipError::NotOwner {}.to_string());
        let err = execute(
            deps.as_mut(),
            env.clone(),
            info_owner.clone(),
            msg_set_snip120u_code_manually.clone(),
        )
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            ContractError::SetSnip120uCodeError {}.to_string()
        );

        // simulated mesage
        let original_ica_upload_data = Response::new().add_submessage(submsg.clone());

        // simulated response w/ event from secret cosmwasmVM
        let ica_upload_wasm_result = Response::<Empty>::new()
            .add_event(Event::new("store_code").add_attribute("code_id", "420"));

        // simulate ibc-callback storing cw-headstash code-id
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

        execute(
            deps.as_mut(),
            env.clone(),
            info_ica_controller.clone(),
            receive_ica_callback.clone(),
        )
        .unwrap();

        // assert correct code-id is set
        assert_eq!(
            ICA_STATES
                .load(&deps.storage)
                .unwrap()
                .headstash_params
                .headstash_code_id,
            Some(420)
        );

        // cannot instantiate headstash without instantiating snip120u first
        let res = execute(
            deps.as_mut(),
            env.clone(),
            info_owner.clone(),
            msg_init_headstash.clone(),
        )
        .unwrap_err();

        assert_eq!(res.to_string(), "NoSnip120uContract");

        // broadcast snip120u init msg
        let res = execute(
            deps.as_mut(),
            env.clone(),
            info_owner.clone(),
            msg_init_snip120u.clone(),
        )
        .unwrap();

        assert_eq!(
            res.attributes
                .iter()
                .find(|a| a.key == "msg_lens")
                .unwrap()
                .value,
            2.to_string()
        );

        // // recieve callback w/ snip120u addrs for HeadstashCallback::InstantiateSnip120us
        let init_msgs = vec![
            snip120u::InstantiateMsg {
                name: "TERP".into(),
                admin: None,
                symbol: "TERP".into(),
                decimals: 6,
                initial_balances: None,
                prng_seed: Binary::new("random".as_bytes().to_vec()),
                config: None,
                supported_denoms: Some(vec!["uterp".into()]),
            },
            snip120u::InstantiateMsg {
                name: "TERP2".into(),
                admin: None,
                symbol: "TERP2".into(),
                decimals: 6,
                initial_balances: None,
                prng_seed: Binary::new("random2".as_bytes().to_vec()),
                config: None,
                supported_denoms: Some(vec!["uterp2".into()]),
            },
        ];

        let cosmos_msgs: Vec<CosmosMsg<Empty>> = init_msgs
            .into_iter()
            .enumerate()
            .map(|(i, init_msg)| {
                #[allow(deprecated)]
                CosmosMsg::Stargate {
                    type_url: "/secret.compute.v1beta1.MsgInstantiateContract".into(),
                    value: anybuf::Anybuf::new()
                        .append_string(1, ica_addr.clone()) // ica-account addr
                        .append_string(2, &format!("CODE_HASH")) // callback_code_hash
                        .append_uint64(3, 420) // code-id of snip-120u
                        .append_string(4, format!("SNIP120U For Secret Network - TERP{}", i)) // label of snip20
                        .append_bytes(5, to_json_binary(&init_msg).unwrap().as_slice())
                        .append_string(8, &format!("CODE_HASH")) // callback_code_hash
                        .into_vec()
                        .into(),
                }
            })
            .collect();
        let mut submsgs = vec![];
        for msgs in cosmos_msgs {
            submsgs.push(SubMsg::new(msgs));
        }

        let instantiate_snip120u_res = Response::new()
            .add_submessages(submsgs)
            .add_attribute("msg_lens", 2.to_string())
            .add_event(
                Event::new("instantiate").add_attribute("contract_address", "secret1_snip120u1"),
            )
            .add_event(
                Event::new("instantiate").add_attribute("contract_address", "secret1_snip120u2"),
            );

        let on_ack_callback = IcaControllerCallbackMsg::OnAcknowledgementPacketCallback {
            ica_acknowledgement: Data::Result(to_json_binary(&instantiate_snip120u_res).unwrap()),
            original_packet: IbcPacket::new(
                to_json_binary(&msg_store_code).unwrap(),
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
        };

        let _res = execute(
            deps.as_mut(),
            env.clone(),
            info_ica_controller.clone(),
            ExecuteMsg::ReceiveIcaCallback(on_ack_callback),
        )
        .unwrap();
        // println!("INSTANTIATE SNIP120US: {:#?}", _res);

        // confirm the addresses have been set for each snip
        let ica_state = ICA_STATES.load(&deps.storage).unwrap();
        for (i, param) in ica_state.headstash_params.token_params.iter().enumerate() {
            // println!("TEST HeadstashTokenParams: {:#?}", param);
            assert_eq!(
                param.snip_addr,
                Some(format!("secret1_snip120u{}", i + 1).into())
            );
        }

        // broadcast headstash init msg
        let _res = execute(
            deps.as_mut(),
            env.clone(),
            info_owner.clone(),
            msg_init_headstash.clone(),
        )
        .unwrap();
        // println!("INSTANTIATE HEADSTASH: {:#?}", _res);

        // receive calllback w/ headstash
        let hs_params = ica_state.headstash_params;
        let mut hs_snips = vec![];
        // at least 1 snip120u must exist
        for snip in hs_params.token_params.clone() {
            // println!("{:#?}", snip.snip_addr);
            let snip = Snip120u {
                token: snip.native,
                name: snip.name,
                addr: Some(Addr::unchecked(snip.snip_addr.unwrap())),
                total_amount: snip.total,
            };
            hs_snips.push(snip);
        }
        // form headstash_init_messaage
        let init_headstash_msg = super::helpers::instantiate_headstash_msg(
            hs_params.headstash_code_id.expect("duhh"),
            headstash_public::state::InstantiateMsg {
                claim_msg_plaintext: "{wallet}".into(),
                end_date: Some(env.block.time.plus_days(365u64).nanos()),
                start_date: None,
                random_key: "eretskeretjablret".into(),
                owner: Addr::unchecked(ica_addr),
                snip120u_code_hash: hs_params.snip120u_code_hash,
                snips: hs_snips,
                multiplier: hs_params.multiplier,
                bloom_config: hs_params.bloom_config,
            },
        )
        .unwrap();
        let instantiate_headstash_res = Response::<Empty>::new()
            // .add_submessage(SubMsg::new(init_headstash_msg))
            // .add_attribute(CUSTOM_CALLBACK, HeadstashCallback::InstantiateHeadstash)
            // .add_attribute("msg_lens", 1.to_string())
            .add_event(
                Event::new("instantiate")
                    .add_attribute("contract_address", headstash_addr.to_string()),
            );

        let on_ack_callback = IcaControllerCallbackMsg::OnAcknowledgementPacketCallback {
            ica_acknowledgement: Data::Result(to_json_binary(&instantiate_headstash_res).unwrap()),
            original_packet: IbcPacket::new(
                to_json_binary(&init_headstash_msg).unwrap(),
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
        };

        let _res = execute(
            deps.as_mut(),
            env.clone(),
            info_ica_controller.clone(),
            ExecuteMsg::ReceiveIcaCallback(on_ack_callback),
        )
        .unwrap();
        // println!("INSTANTIATE HEADSTASH CALLBACK: {:#?}", _res);

        // confirm contract addr is in state now
        let ica_state = ICA_STATES.load(&deps.storage).unwrap();
        assert_eq!(
            ica_state.headstash_params.headstash_addr.unwrap(),
            headstash_addr.to_string()
        );

        // AUTHORIZE MINTER
        // cannot authorize unless owner

        let err = execute(
            deps.as_mut(),
            env.clone(),
            info_creator.clone(),
            msg_authorize_minter.clone(),
        )
        .unwrap_err();
        assert_eq!(err.to_string(), OwnershipError::NotOwner.to_string());

        let res = execute(
            deps.as_mut(),
            env.clone(),
            info_owner.clone(),
            msg_authorize_minter.clone(),
        )
        .unwrap();
        assert_eq!(
            res.attributes
                .iter()
                .find(|a| a.key == "ica_callback_id")
                .unwrap()
                .value,
            "set_headstash_as_snip_minter"
        );

        // IBC TRANSFER TO SNIPS

        // cannot transfer if not owner
        let err = execute(
            deps.as_mut(),
            env.clone(),
            info_creator.clone(),
            msg_ibc_transfer.clone(),
        )
        .unwrap_err();
        assert_eq!(err.to_string(), OwnershipError::NotOwner.to_string());

        let _res = execute(
            deps.as_mut(),
            env.clone(),
            info_owner.clone(),
            msg_ibc_transfer.clone(),
        )
        .unwrap();
        // println!("IBC TRANSFER {:#?}", _res);

        // ADD ELIGIBLE CLAIMERS

        // cannot add if not owner
        let err = execute(
            deps.as_mut(),
            env.clone(),
            info_creator.clone(),
            msg_add_headstashers.clone(),
        )
        .unwrap_err();
        assert_eq!(err.to_string(), OwnershipError::NotOwner.to_string());

        // cannot add duplicates

        // successful
        let _res = execute(
            deps.as_mut(),
            env.clone(),
            info_owner.clone(),
            msg_add_headstashers.clone(),
        )
        .unwrap();

        // println!("ADD HEADSTASHERS {:#?}", _res);

        // FEEGRANT_AUTHORIZATION

        // cannot grant fees if not owner
        let err = execute(
            deps.as_mut(),
            env.clone(),
            info_creator.clone(),
            msg_authorize_feegrant.clone(),
        )
        .unwrap_err();
        assert_eq!(err.to_string(), OwnershipError::NotOwner.to_string());

        // successful
        let _res = execute(
            deps.as_mut(),
            env.clone(),
            info_owner.clone(),
            msg_authorize_feegrant.clone(),
        )
        .unwrap();

        // println!("AUTHORIZE FEEGRANT {:#?}", _res);

        // AUTHZ_GRANT
        let err = execute(
            deps.as_mut(),
            env.clone(),
            info_creator.clone(),
            msg_set_authz_grantee.clone(),
        )
        .unwrap_err();
        assert_eq!(err.to_string(), OwnershipError::NotOwner.to_string());

        let _res = execute(
            deps.as_mut(),
            env.clone(),
            info_owner.clone(),
            msg_set_authz_grantee,
        )
        .unwrap();
        // println!("AUTHZ GRANTS {:#?}", _res);

        let err = execute(
            deps.as_mut(),
            env.clone(),
            info_creator.clone(),
            msg_set_headstash_manually.clone(),
        )
        .unwrap_err();
        assert_eq!(err.to_string(), OwnershipError::NotOwner {}.to_string());
        let err = execute(
            deps.as_mut(),
            env.clone(),
            info_owner.clone(),
            msg_set_headstash_manually.clone(),
        )
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            ContractError::SetHeadstashAddrError {}.to_string()
        );

        for msg in msg_set_snip_manually {
            let err = execute(
                deps.as_mut(),
                env.clone(),
                info_creator.clone(),
                msg.clone(),
            )
            .unwrap_err();
            assert_eq!(err.to_string(), OwnershipError::NotOwner {}.to_string());
            let err =
                execute(deps.as_mut(), env.clone(), info_owner.clone(), msg.clone()).unwrap_err();
            assert_eq!(
                err.to_string(),
                ContractError::Snip120uAddrAlreadySet {}.to_string()
            );
        }
    }
}

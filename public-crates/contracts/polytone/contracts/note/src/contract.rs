#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    to_json_binary, Binary, Deps, DepsMut, Env, IbcMsg, IbcTimeout, MessageInfo, Response,
    StdError, StdResult,
};
use cw2::set_contract_version;
use polytone::callbacks::CallbackRequestType;
use polytone::{accounts, callbacks, ibc};

use crate::error::ContractError;

use crate::headstash::constants::DEFAULT_TIMEOUT;
use crate::ibc::ERR_GAS_NEEDED;
use crate::msg::{ExecuteMsg, HeadstashParams, InstantiateMsg, MigrateMsg, Pair, QueryMsg};
use crate::state::{
    increment_sequence_number, HeadstashSeq, BLOCK_MAX_GAS, CHANNEL, CONNECTION_REMOTE_PORT,
    HEADSTASH_PARAMS, HEADSTASH_SEQUENCE,
};

const CONTRACT_NAME: &str = "crates.io:polytone-note";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    if msg.block_max_gas.u64() <= ERR_GAS_NEEDED {
        return Err(ContractError::GasLimitsMismatch);
    }

    BLOCK_MAX_GAS.save(deps.storage, &msg.block_max_gas.u64())?;

    let mut response = Response::default()
        .add_attribute("method", "instantiate")
        .add_attribute("block_max_gas", msg.block_max_gas);

    if let Some(Pair {
        connection_id,
        remote_port,
    }) = msg.pair
    {
        response = response
            .add_attribute("pair_connection", connection_id.to_string())
            .add_attribute("pair_port", remote_port.to_string());
        CONNECTION_REMOTE_PORT.save(deps.storage, &(connection_id, remote_port))?;
    };

    // CUSTOM HEADSTASH SEQUENCE

    let HeadstashParams {
        snip120u_code_id,
        headstash_code_id,
        token_params,
        headstash_addr,
        ..
    } = msg.headstash_params.clone();

    if snip120u_code_id.is_some() {
        HEADSTASH_SEQUENCE.save(deps.storage, HeadstashSeq::UploadSnip.into(), &true)?;
    } else {
        HEADSTASH_SEQUENCE.save(deps.storage, HeadstashSeq::UploadSnip.into(), &false)?;
    }
    if headstash_code_id.is_some() {
        HEADSTASH_SEQUENCE.save(deps.storage, HeadstashSeq::UploadHeadstash.into(), &true)?;
    } else {
        HEADSTASH_SEQUENCE.save(deps.storage, HeadstashSeq::UploadHeadstash.into(), &false)?;
    }
    // atleast 1 snip120u token param must be set
    if token_params.len() == 0 {
        return Err(ContractError::NoSnip120uParamsSet {});
    }
    // if there is any snip120u addr in params, save to map with enumerated position as part of key
    for (i, param) in token_params.iter().enumerate() {
        if let Some(_) = &param.snip_addr {
            HEADSTASH_SEQUENCE.save(
                deps.storage,
                HeadstashSeq::InitSnips.indexed_snip(i),
                &true,
            )?;
        } else {
            HEADSTASH_SEQUENCE.save(
                deps.storage,
                HeadstashSeq::InitSnips.indexed_snip(i),
                &false,
            )?;
        }
    }
    if headstash_addr.is_none() {
        HEADSTASH_SEQUENCE.save(deps.storage, HeadstashSeq::InitHeadstash.into(), &false)?;
    } else {
        HEADSTASH_SEQUENCE.save(deps.storage, HeadstashSeq::InitHeadstash.into(), &true)?;
    }
    HEADSTASH_PARAMS.save(deps.storage, &msg.headstash_params)?;
    Ok(response)
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    let mut hscb = false;

    let (msg, callback, timeout_seconds, request_type) = match msg {
        ExecuteMsg::Execute {
            headstash_msg,
            timeout_seconds,
            ..
        } => (
            ibc::Msg::Execute {
                msgs: headstash_msg.to_cosmos_msgs(&env, deps.storage, deps.api, info.clone())?,
            },
            headstash_msg.to_callback_request(&env, deps.storage, deps.api)?,
            timeout_seconds,
            CallbackRequestType::Execute,
        ),
        ExecuteMsg::Query {
            msgs,
            callback,
            timeout_seconds,
        } => (
            ibc::Msg::Query { msgs },
            callback,
            timeout_seconds,
            CallbackRequestType::Query,
        ),
        ExecuteMsg::HeadstashCallBack { rx } => {
            hscb = true;
            (
                ibc::Msg::Execute {
                    msgs: rx.into_headstash_msg(deps.storage)?,
                },
                rx.into_callback(env.contract.address.to_string())?,
                DEFAULT_TIMEOUT.into(),
                CallbackRequestType::Execute,
            )
        }
    };

    // currently only local callbacks for headstash.
    // todo: implement ibc packet callbacks for headstash
    let response = match hscb {
        false => {
            let channel_id = CHANNEL
                .may_load(deps.storage)?
                .ok_or(ContractError::NoPair)?;

            let sequence_number = increment_sequence_number(deps.storage, channel_id.clone())?;

            callbacks::request_callback(
                deps.storage,
                deps.api,
                channel_id.clone(),
                sequence_number,
                info.sender.clone(),
                Some(callback),
                request_type,
            )?;

            accounts::on_send_packet(
                deps.storage,
                channel_id.clone(),
                sequence_number,
                &info.sender,
            )?;

            Response::new().add_message(IbcMsg::SendPacket {
                channel_id,
                data: to_json_binary(&ibc::Packet {
                    sender: info.sender.into_string(),
                    msg,
                })
                .expect("msgs are known to be serializable"),
                timeout: IbcTimeout::with_timestamp(
                    env.block.time.plus_seconds(timeout_seconds.u64()),
                ),
            })
        }
        true => {
            let msgs = match msg {
                ibc::Msg::Execute { msgs } => Ok(msgs),
                _ => Err(ContractError::Std(StdError::generic_err("unimplemented"))),
            }?;
            Response::new().add_messages(msgs)
        }
    };

    Ok(response)
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::ActiveChannel => to_json_binary(&CHANNEL.may_load(deps.storage)?),
        QueryMsg::Pair => to_json_binary(&CONNECTION_REMOTE_PORT.may_load(deps.storage)?.map(
            |(connection_id, remote_port)| Pair {
                connection_id,
                remote_port,
            },
        )),
        QueryMsg::RemoteAddress { local_address } => to_json_binary(&accounts::query_account(
            deps.storage,
            deps.api.addr_validate(&local_address)?,
        )?),
        QueryMsg::BlockMaxGas => to_json_binary(&BLOCK_MAX_GAS.load(deps.storage)?),
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn migrate(deps: DepsMut, _env: Env, msg: MigrateMsg) -> Result<Response, ContractError> {
    match msg {
        MigrateMsg::WithUpdate { block_max_gas } => {
            if block_max_gas.u64() <= ERR_GAS_NEEDED {
                return Err(ContractError::GasLimitsMismatch);
            }

            BLOCK_MAX_GAS.save(deps.storage, &block_max_gas.u64())?;
            Ok(Response::default()
                .add_attribute("method", "migrate_with_update")
                .add_attribute("block_max_gas", block_max_gas))
        }
    }
}

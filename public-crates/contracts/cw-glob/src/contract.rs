#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    to_json_binary, Addr, Attribute, Binary, Deps, DepsMut, Env, Event, MessageInfo, Response,
    StdError, StdResult, Storage,
};
use cw2::set_contract_version;

use crate::error::ContractError;
use crate::msg::{ExecuteMsg, Glob, InstantiateMsg, QueryMsg};
use crate::state::GLOBMAP;

// version info for migration info
const CONTRACT_NAME: &str = "crates.io:cw-glob";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;
    cw_ownable::initialize_owner(deps.storage, deps.api, Some(&msg.owner))?;
    Ok(Response::new())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::AddGlob { globs } => add_glob(deps.storage, info.sender, globs),
        ExecuteMsg::TakeGlob {
            sender,
            key,
            memo,
            timeout,
        } => manifest_wasm_blob(
            deps.storage,
            info.sender,
            deps.api.addr_validate(&sender)?,
            key,
            memo,
            timeout,
        ),
    }
}

fn add_glob(
    storage: &mut dyn Storage,
    owner: Addr,
    globs: Vec<Glob>,
) -> Result<Response, ContractError> {
    cw_ownable::assert_owner(storage, &owner)?;
    let mut attrs = vec![];
    for glob in globs {
        if GLOBMAP.has(storage, glob.key.clone()) {
            return Err(ContractError::KeyExists {
                key: glob.key.clone(),
            });
        } else {
            GLOBMAP.save(storage, glob.key.clone(), &glob.blob)?;
            attrs.push(Attribute::new("glob-key", glob.key))
        }
    }
    Ok(Response::new().add_event(Event::new("glob").add_attributes(attrs)))
}

fn manifest_wasm_blob(
    storage: &mut dyn Storage,
    owner: Addr,
    sender: Addr,
    wasm: String,
    memo: Option<String>,
    timeout: Option<u64>,
) -> Result<Response, ContractError> {
    cw_ownable::assert_owner(storage, &owner.clone())?;
    let msg = headstash::take_glob(&wasm)?;
    Ok(Response::new().set_data(msg).add_event(
        Event::new("headstash")
            .add_attribute("sender", sender.to_string())
            .add_attribute("memo", memo.unwrap_or_default())
            .add_attribute("timeout", timeout.unwrap_or(600).to_string()),
    ))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(_deps: Deps, _env: Env, _msg: QueryMsg) -> StdResult<Binary> {
    unimplemented!()
}

mod headstash {
    use super::*;
    use anybuf::Anybuf;

    /// Defines the Stargate msg to upload the nested wasm blobs.
    pub fn take_glob(wasm: &str) -> Result<Vec<u8>, StdError> {
        // define headstash wasm binary
        let headstash_bin = match wasm {
            "cw-headstash" => include_bytes!("../../../../globs/cw_headstash.wasm.gz").to_vec(),
            "snip120u" => include_bytes!("../../../../globs/snip120u_impl.wasm.gz").to_vec(),
            _ => return Err(StdError::generic_err("bad contract upload")),
        };

        Ok(headstash_bin)
    }
}

#[cfg(test)]
mod tests {

    // assure we can grab proper upload msg

    // track gas_consumption
}

#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    to_json_binary, Addr, Attribute, Binary, CosmosMsg, Deps, DepsMut, Env, Event, MessageInfo,
    Response, StdError, StdResult, Storage,
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
        ExecuteMsg::TakeGlob { sender, key, id } => manifest_wasm_blob(
            deps.storage,
            info.sender,
            deps.api.addr_validate(&sender)?,
            key,
            id,
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
    id: u64,
) -> Result<Response, ContractError> {
    cw_ownable::assert_owner(storage, &owner.clone())?;
    let msg = headstash::get_ica_upload_msg(sender.clone(), &wasm)?;
    Ok(Response::new().add_event(
        Event::new("headstash")
            .add_attribute("ica-upload-msg", &to_json_binary(&msg)?.to_base64())
            .add_attribute("sender", sender.to_string())
            .add_attribute("owner", owner.to_string())
            .add_attribute("ica-id", id.to_string()),
    ))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(_deps: Deps, _env: Env, _msg: QueryMsg) -> StdResult<Binary> {
    unimplemented!()
}

#[cfg(test)]
mod tests {}

mod headstash {
    use super::*;
    use anybuf::Anybuf;

    /// Defines the msg to upload the nested wasm blobs.
    pub fn get_ica_upload_msg(
        sender: ::cosmwasm_std::Addr,
        wasm: &str,
    ) -> Result<CosmosMsg, StdError> {
        // define headstash wasm binary
        let headstash_bin = match wasm {
            "cw-headstash" => include_bytes!("../../../../globs/cw_headstash.wasm.gz").to_vec(),
            "snip120u" => include_bytes!("../../../../globs/snip120u_impl.wasm.gz").to_vec(),
            _ => return Err(StdError::generic_err("bad contract upload")),
        };

        Ok(
            #[allow(deprecated)]
            CosmosMsg::Stargate {
                type_url: "/secret.compute.v1beta1.MsgStoreCode".into(),
                value: Anybuf::new()
                    .append_string(1, sender.clone()) // sender (DAO)
                    .append_bytes(2, &headstash_bin) // updated binary of transfer msg.
                    .into_vec()
                    .into(),
            },
        )
    }
}

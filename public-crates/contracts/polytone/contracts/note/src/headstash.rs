use cosmwasm_std::{
    to_json_binary, Addr, Api, Binary, CosmosMsg, Deps, DepsMut, Env, MessageInfo, Reply, Response,
    StdResult, Storage,
};

use crate::{error::ContractError, state::HEADSTASH_PARAMS};

pub fn set_cw_glob(
    storage: &mut dyn Storage,
    api: &dyn Api,
    info: MessageInfo,
    cw_glob: &String,
) -> Result<Response, ContractError> {
    // cw_ownable::assert_owner(deps.storage, &info.sender)?;

    HEADSTASH_PARAMS.update(storage, |mut a| {
        if a.cw_glob.is_none() {
            a.cw_glob = Some(api.addr_validate(&cw_glob)?)
        } else {
            return Err(ContractError::CwGlobExists {});
        }
        Ok(a)
    })?;
    Ok(Response::new())
}

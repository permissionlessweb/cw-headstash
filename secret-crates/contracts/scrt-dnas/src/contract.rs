use crate::error::ContractError;
use crate::msg::{ExecuteMsg, InstantiateMsg, QueryAnswer, QueryMsg};
use crate::state::{
    DaoMemberAuth, DaoMemberData, DaoObject, DefaultAuth, DmAuthSignDoc, DnasKeyObject,
    MiddlewareAuth, MiddlewareData, ACCOUNT_NONE, API_KEY_MAP, API_KEY_RECORD, DNAS_STORE,
    MIDDLEWARE_PUBKEY,
};

#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;

use cosmwasm_std::{
    from_binary, to_binary, Binary, Deps, DepsMut, Env, MessageInfo, Reply, Response, StdError,
    StdResult,
};
use secret_toolkit::crypto::ContractPrng;
use sha2::{Digest, Sha256};

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> StdResult<Response> {
    // `secret1...`
    MIDDLEWARE_PUBKEY.save(
        deps.storage,
        &Binary(deps.api.addr_canonicalize(&msg.dnas_pubkey)?.to_vec()),
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
    let mut rng = ContractPrng::from_env(&env);
    match msg {
        ExecuteMsg::RegisterDnasApi { dnas } => {
            try_add_dnas_api_middlware_entrypoint(deps, env, info, &mut rng, dnas)
        }
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::DnasApiAddr {} => to_binary(&self::queries::dnas_api_addr(deps)?),
        QueryMsg::DnasApiEntrypoint { req } => {
            to_binary(&self::queries::dnas_api_entrypoint(deps, env, req)?)
        }
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn reply(_deps: DepsMut, _env: Env, reply: Reply) -> StdResult<Response> {
    match reply.id {
        _ => {
            return Err(StdError::GenericErr {
                msg: "bad reply".into(),
            })
        }
    }
}

/// entrypoint for AVS to register a dao-members api-key being registered to the dnas.
pub fn try_add_dnas_api_middlware_entrypoint(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    rng: &mut ContractPrng,
    msg: Vec<DnasKeyObject>,
) -> Result<Response, ContractError> {
    let storage = deps.storage;
    let dnas_middlware = MIDDLEWARE_PUBKEY.load(storage)?;

    for dobj in msg {
        let api_key = dobj.api_key_value;
        // middleware
        let DefaultAuth {
            msg: mw_msg,
            sig: mw_sig,
            pubkey: mw_pubkey,
        } = dobj.authentication.mw_auth;
        // dao member
        let DefaultAuth {
            msg: dm_msg,
            sig: dm_sig,
            pubkey: dm_pubkey,
        } = dobj.authentication.dm_auth;

        if dnas_middlware != mw_pubkey.value {
            return Err(ContractError::BloomDuplicate {});
        }

        let mut hash = Sha256::new();
        sha2::Digest::update(&mut hash, dm_msg.as_ref());
        let msg_hash = hash.finalize_reset().to_vec();

        // authenticate the dao member registering
        deps.api
            .secp256k1_verify(&msg_hash, &dm_sig, &dm_pubkey.value)?;

        // the only data expected to be in the offline signature
        let DmAuthSignDoc {
            msgs: mw_data_msgs, ..
        } = from_binary(&mw_msg)?;
        let MiddlewareAuth { data: mw_data } = from_binary(&mw_data_msgs[0])?;
        let MiddlewareData {
            dm_bech32_addr,
            nonce,
        } = from_binary(&mw_data)?;

        let DmAuthSignDoc {
            msgs: dm_data_msgs, ..
        } = from_binary(&dm_msg)?;
        let DaoMemberAuth { data, auth } = from_binary(&dm_data_msgs[0])?;
        let DaoMemberData {
            dao,
            mw_op_addr,
            scrt_dnas_addr,
            dnas,
        } = from_binary(&data)?;

        // hash mw msg signed
        let mut hash = Sha256::new();
        sha2::Digest::update(&mut hash, mw_msg.as_ref());
        let mw_hash = hash.finalize_reset().to_vec();

        // middleware dnas api key signature, used stored public key
        deps.api
            .secp256k1_verify(&mw_hash, &mw_sig, &dnas_middlware)?;
        // confirm dao member authorized middleware
        if mw_op_addr != info.sender.to_string() {
            return Err(ContractError::BloomDisabled {});
        }
        // confirm this contract is one sender wants
        if scrt_dnas_addr != env.contract.address.to_string() {
            return Err(ContractError::BloomDisabled {});
        }

        // replay attack prevention
        let stored_nonce = ACCOUNT_NONE
            .add_suffix(dm_bech32_addr.as_bytes())
            .may_load(storage)?;

        match stored_nonce {
            Some(mut a) => ACCOUNT_NONE
                .add_suffix(dm_bech32_addr.as_bytes())
                .save(storage, {
                    // updating existing record
                    if a != nonce {
                        return Err(ContractError::BloomDisabled {});
                    }
                    a += 1;

                    &a
                })?,
            None => ACCOUNT_NONE
                .add_suffix(dm_bech32_addr.as_bytes())
                .save(storage, &nonce)?,
        };

        // save the dao key
        let mut hash = Sha256::new();
        sha2::Digest::update(&mut hash, api_key.as_ref());
        let apikey_hash = hash.finalize_reset().to_vec();

        API_KEY_RECORD.add_suffix(&apikey_hash).save(
            storage,
            &DaoObject {
                dao,
                member: dm_bech32_addr.clone(),
            },
        )?;
        API_KEY_MAP
            .add_suffix(&apikey_hash)
            .save(storage, &api_key)?;
    }

    Ok(Response::default())
}

// #[cfg_attr(not(feature = "library"), entry_point)]
// pub fn migrate(_deps: DepsMut, _env: Env, msg: MigrateMsg) -> StdResult<Response> {
//     match msg {
//         _ => Err(StdError::generic_err("unimplemented")),
//     }
// }

pub mod queries {

    use cosmwasm_std::Addr;

    use super::*;
    use crate::state::{DefaultAuth, DnasAuth, MemberUseDnasRequestData, MiddlewareUseRequestData};

    pub fn dnas_api_entrypoint(deps: Deps, env: Env, req: DnasAuth) -> StdResult<Binary> {
        // Verify the query comes from the registered middleware
        let middleware_pubkey = MIDDLEWARE_PUBKEY.load(deps.storage)?;

        // Extract and verify middleware authentication
        let DefaultAuth { msg, sig, pubkey } = req.mw_auth;
        if pubkey.value != middleware_pubkey {
            return Err(StdError::generic_err("Unauthorized middleware"));
        }

        // Hash the middleware's message for signature verification
        let mut hash = Sha256::new();
        sha2::Digest::update(&mut hash, msg.as_ref());
        let msg_hash = hash.finalize_reset().to_vec();

        // Verify middleware signature
        deps.api
            .secp256k1_verify(&msg_hash, &sig, &middleware_pubkey)?;

        // Deserialize middleware's signed message
        let MiddlewareUseRequestData {
            nonce,
            dao_member,
            msg_hash: dm_msg_hash,
            dao_addr: mw_dao_addr,
        } = from_binary(&msg)?;

        // Extract and verify DAO member authentication
        let DefaultAuth {
            msg: dm_msg,
            sig: dm_sig,
            pubkey: dm_pubkey,
        } = req.dm_auth;

        // Verify DAO member's signature
        let mut hash = Sha256::new();
        sha2::Digest::update(&mut hash, dm_msg.as_ref());
        let dm_msg_hash_actual = hash.finalize_reset().to_vec();

        // Ensure the middleware provided the correct DAO member message hash
        if dm_msg_hash != dm_msg_hash_actual {
            return Err(StdError::generic_err("Invalid DAO member message hash"));
        }

        // Verify DAO member's signature
        deps.api
            .secp256k1_verify(&dm_msg_hash_actual, &dm_sig, &dm_pubkey.value)?;

        // Deserialize DAO member's signed message
        let MemberUseDnasRequestData {
            nonce: dm_nonce,
            scrt_dnas_addr,
            key_hash,
            dao_addr,
            middleware_operator_addr,
        } = from_binary(&dm_msg)?;

        // Validate request parameters
        if scrt_dnas_addr != env.contract.address {
            return Err(StdError::generic_err("Invalid contract address"));
        }
        if dao_addr != mw_dao_addr {
            return Err(StdError::generic_err("DAO address mismatch"));
        }
        if middleware_operator_addr
            != Addr::unchecked(deps.api.addr_validate(&middleware_pubkey.to_string())?)
        {
            return Err(StdError::generic_err("Invalid middleware operator address"));
        }
        if nonce != dm_nonce {
            return Err(StdError::generic_err(
                "Nonce mismatch between middleware and DAO member",
            ));
        }

        // Verify nonce for replay attack prevention
        if let Some(stored_nonce) = ACCOUNT_NONE
            .add_suffix(dao_member.as_bytes())
            .may_load(deps.storage)?
        {
            if stored_nonce != nonce {
                return Err(StdError::generic_err(
                    "Nonce mismatch, potential replay attack or desync",
                ));
            }
        } else {
            return Err(StdError::generic_err(
                "No nonce found for DAO member, register first",
            ));
        }

        // Verify DAO member is authorized for the API key
        let record: DaoObject = API_KEY_RECORD.add_suffix(&key_hash).load(deps.storage)?;
        if record.member != dao_member || record.dao != dao_addr {
            return Err(StdError::generic_err(
                "DAO member not authorized for this API key",
            ));
        }

        // Retrieve and return the API key
        let api_key = API_KEY_MAP.add_suffix(&key_hash).load(deps.storage)?;

        Ok(api_key)
    }

    pub fn dnas_api_addr(deps: Deps) -> StdResult<Binary> {
        Ok(MIDDLEWARE_PUBKEY.load(deps.storage)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose, Engine};
    use cosmwasm_std::{coin, BankMsg, OwnedDeps, Uint128};
    use cosmwasm_std::{testing::*, Addr};
}

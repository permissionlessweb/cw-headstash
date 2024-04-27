use crate::msg::{ExecuteMsg, Headstash, InstantiateMsg, QueryAnswer, QueryMsg};
use crate::state::{
    claim_status_r, claim_status_w, config, config_r, decay_claimed_r, decay_claimed_w,
    total_claimed_r, total_claimed_w, Config, HEADSTASH_OWNERS,
};
use cosmwasm_std::{
    entry_point, to_binary, Binary, CosmosMsg, Deps, DepsMut, Env, MessageInfo, Response, StdError,
    StdResult, Uint128,
};
use secret_toolkit::snip20::transfer_msg;

#[entry_point]
pub fn instantiate(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> StdResult<Response> {
    let start_date = match msg.start_date {
        None => env.block.time.seconds(),
        Some(date) => date,
    };

    let state = Config {
        admin: msg.admin.unwrap_or(info.sender),
        claim_msg_plaintext: msg.claim_msg_plaintext,
        end_date: msg.end_date,
        merkle_root: msg.merkle_root,
        snip20_1: msg.snip20_1,
        snip20_2: msg.snip20_2,
        start_date: start_date,
        total_amount: msg.total_amount,
        viewing_key: msg.viewing_key,
    };

    // Initialize claim amount
    total_claimed_w(deps.storage).save(&Uint128::zero())?;
    config(deps.storage).save(&state)?;

    Ok(Response::default())
}

#[entry_point]
pub fn execute(deps: DepsMut, env: Env, info: MessageInfo, msg: ExecuteMsg) -> StdResult<Response> {
    match msg {
        ExecuteMsg::Add { headstash } => try_add_headstash(deps, env, info, headstash),
        ExecuteMsg::Claim {
            eth_pubkey,
            eth_sig,
        } => try_claim(deps, env, info, eth_pubkey, eth_sig),
        ExecuteMsg::Clawback {} => try_clawback(deps, env, info),
    }
}

pub fn try_clawback(deps: DepsMut, env: Env, info: MessageInfo) -> StdResult<Response> {
    // ensure sender is admin
    let config = config_r(deps.storage).load()?;
    let admin = config.admin;
    if info.sender != admin {
        return Err(StdError::generic_err(
            "you cannot clawback the headstash, silly!",
        ));
    }

    // ensure clawback can happen, update state
    if let Some(end_date) = config.end_date {
        if env.block.time.seconds() > end_date {
            decay_claimed_w(deps.storage).update(|claimed| {
                if claimed {
                    Err(StdError::generic_err("this jawn already was clawed-back!"))
                } else {
                    Ok(true)
                }
            })?;
        }
        let total_claimed = total_claimed_r(deps.storage).load()?;
        let clawback_total = config.total_amount.checked_sub(total_claimed)?;

        let mut msgs: Vec<CosmosMsg> = vec![];
        let hs1 = transfer_msg(
            admin.to_string(),
            clawback_total,
            None,
            None,
            0,
            config.snip20_1.code_hash,
            config.snip20_1.address.to_string(),
        )?;
        msgs.push(hs1);

        return Ok(Response::default().add_messages(msgs));
    }

    Err(StdError::generic_err(
        "Clawback was not setup for this one, playa!",
    ))
}

pub fn try_add_headstash(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    headstash: Vec<Headstash>,
) -> StdResult<Response> {
    // ensure sender is admin
    let config = config_r(deps.storage).load()?;

    if headstash.is_empty() {
        return Err(StdError::generic_err(
            "the msg you sent contained an empty value!",
        ));
    }

    if info.sender != config.admin {
        return Err(StdError::generic_err(
            "you cannot add an address to the headstash, silly!",
        ));
    }
    // make sure airdrop has not ended
    available(&config, &env)?;

    // ensure eth_pubkey is not already in KeyMap
    for hs in headstash.into_iter() {
        if HEADSTASH_OWNERS.contains(deps.storage, &hs.eth_pubkey) {
            return Err(StdError::generic_err(
                "pubkey already has been added, not adding again",
            ));
        } else {
            // add eth_pubkey & amount to KeyMap
            HEADSTASH_OWNERS.insert(deps.storage, &hs.eth_pubkey, &hs.amount)?;
        }
    }
    Ok(Response::default())
}

pub fn try_claim(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    eth_pubkey: String,
    eth_sig: String,
) -> StdResult<Response> {
    let config = config_r(deps.storage).load()?;

    // make sure airdrop has not ended
    available(&config, &env)?;

    // validate eth_signature comes from eth pubkey.
    // Occurs before claim check to prevent data leak of eth_pubkey claim status.
    validation::validate_claim(
        &deps,
        info.clone(),
        eth_pubkey.to_string(),
        eth_sig.clone(),
        config.clone(),
    )?;

    // check if address has already claimed
    let state = claim_status_r(deps.storage).may_load(eth_pubkey.as_bytes())?;
    if state == Some(true) {
        return Err(StdError::generic_err(
            "You have already claimed your headstash, homie!",
        ));
    }

    // get headstash amount from KeyMap
    let headstash_amount = HEADSTASH_OWNERS
        .get(deps.storage, &eth_pubkey)
        .ok_or_else(|| StdError::generic_err("Ethereum Pubkey not found in the contract state!"))?;

    let mut msgs: Vec<CosmosMsg> = vec![];

    msgs.push(transfer_msg(
        info.sender.to_string(),
        headstash_amount,
        None,
        None,
        0,
        config.snip20_1.code_hash,
        config.snip20_1.address.to_string(),
    )?);

    if !config.snip20_2.is_none() {
        let hs2 = transfer_msg(
            info.sender.to_string(),
            headstash_amount.into(),
            None,
            None,
            0,
            config.snip20_2.clone().unwrap().code_hash,
            config.snip20_2.unwrap().address.to_string(),
        )?;
        msgs.push(hs2);
    };

    // update address as claimed
    claim_status_w(deps.storage).save(eth_pubkey.as_bytes(), &true)?;
    // update total_claimed
    total_claimed_w(deps.storage)
        .update(|claimed| -> StdResult<Uint128> { Ok(claimed + headstash_amount) })?;

    Ok(Response::default().add_messages(msgs))
}

pub fn available(config: &Config, env: &Env) -> StdResult<()> {
    let current_time = env.block.time.seconds();

    // Check if airdrop started
    if current_time < config.start_date {
        return Err(StdError::generic_err("This airdrop has not started yet!"));
    }
    if let Some(end_date) = config.end_date {
        if current_time > end_date {
            return Err(StdError::generic_err("This airdrop has ended!"));
        }
    }

    Ok(())
}

#[entry_point]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::Config {} => to_binary(&query_config(deps)?),
        QueryMsg::Dates {} => to_binary(&query_dates(deps)?),
        QueryMsg::Clawback {} => to_binary(&query_clawback(deps)?),
    }
}

fn query_clawback(deps: Deps) -> StdResult<QueryAnswer> {
    Ok(QueryAnswer::ClawbackResponse {
        bool: decay_claimed_r(deps.storage).load()?,
    })
}

fn query_config(deps: Deps) -> StdResult<QueryAnswer> {
    Ok(QueryAnswer::ConfigResponse {
        config: config_r(deps.storage).load()?,
    })
}

fn query_dates(deps: Deps) -> StdResult<QueryAnswer> {
    let config = config_r(deps.storage).load()?;
    Ok(QueryAnswer::DatesResponse {
        start: config.start_date,
        end: config.end_date,
        // decay_start: config.decay_start,
    })
}

// src: https://github.com/public-awesome/launchpad/blob/main/contracts/sg-eth-airdrop/src/claim_airdrop.rs#L85
pub mod validation {
    use super::*;
    use crate::verify_ethereum_text;

    pub fn validate_instantiation_params(
        _info: MessageInfo,
        msg: InstantiateMsg,
    ) -> Result<(), StdError> {
        // validate_airdrop_amount(msg.airdrop_amount)?;
        validate_plaintext_msg(msg.claim_msg_plaintext)?;
        // validate_instantiate_funds(info)?;
        Ok(())
    }

    pub fn compute_plaintext_msg(config: &Config, info: MessageInfo) -> String {
        str::replace(
            &config.claim_msg_plaintext,
            "{wallet}",
            info.sender.as_ref(),
        )
    }

    pub fn validate_claim(
        deps: &DepsMut,
        info: MessageInfo,
        eth_pubkey: String,
        eth_sig: String,
        config: Config,
    ) -> Result<(), StdError> {
        validate_eth_sig(deps, info, eth_pubkey.clone(), eth_sig, config)?;
        Ok(())
    }

    fn validate_eth_sig(
        deps: &DepsMut,
        info: MessageInfo,
        eth_pubkey: String,
        eth_sig: String,
        config: Config,
    ) -> Result<(), StdError> {
        let valid_eth_sig =
            validate_ethereum_text(deps, info, &config, eth_sig, eth_pubkey.clone())?;
        match valid_eth_sig {
            true => Ok(()),
            false => Err(StdError::generic_err("cannot validate eth_sig")),
        }
    }

    pub fn validate_ethereum_text(
        deps: &DepsMut,
        info: MessageInfo,
        config: &Config,
        eth_sig: String,
        eth_pubkey: String,
    ) -> StdResult<bool> {
        let plaintext_msg = compute_plaintext_msg(config, info);
        match hex::decode(eth_sig.clone()) {
            Ok(eth_sig_hex) => {
                verify_ethereum_text(deps.as_ref(), &plaintext_msg, &eth_sig_hex, &eth_pubkey)
            }
            Err(_) => Err(StdError::InvalidHex {
                msg: format!("Could not decode {eth_sig}"),
            }),
        }
    }

    pub fn validate_plaintext_msg(plaintext_msg: String) -> Result<(), StdError> {
        if !plaintext_msg.contains("{wallet}") {
            return Err(StdError::generic_err(
                "Plaintext message must contain `{{wallet}}` string",
            ));
        }
        if plaintext_msg.len() > 1000 {
            return Err(StdError::generic_err("Plaintext message is too long"));
        }
        Ok(())
    }
}

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use cosmwasm_std::testing::*;
//     use cosmwasm_std::{from_binary, Coin, StdError, Uint128};

//     #[test]
//     fn proper_initialization() {
//         let mut deps = mock_dependencies();
//         let info = mock_info(
//             "creator",
//             &[Coin {
//                 denom: "earth".to_string(),
//                 amount: Uint128::new(1000),
//             }],
//         );
//         let init_msg = InstantiateMsg { count: 17 };

//         // we can just call .unwrap() to assert this was a success
//         let res = instantiate(deps.as_mut(), mock_env(), info, init_msg).unwrap();

//         assert_eq!(0, res.messages.len());

//         // it worked, let's query the state
//         let res = query(deps.as_ref(), mock_env(), QueryMsg::GetCount {}).unwrap();
//         let value: CountResponse = from_binary(&res).unwrap();
//         assert_eq!(17, value.count);
//     }

//     #[test]
//     fn increment() {
//         let mut deps = mock_dependencies_with_balance(&[Coin {
//             denom: "token".to_string(),
//             amount: Uint128::new(2),
//         }]);
//         let info = mock_info(
//             "creator",
//             &[Coin {
//                 denom: "token".to_string(),
//                 amount: Uint128::new(2),
//             }],
//         );
//         let init_msg = InstantiateMsg { count: 17 };

//         let _res = instantiate(deps.as_mut(), mock_env(), info, init_msg).unwrap();

//         // anyone can increment
//         let info = mock_info(
//             "anyone",
//             &[Coin {
//                 denom: "token".to_string(),
//                 amount: Uint128::new(2),
//             }],
//         );

//         let exec_msg = ExecuteMsg::Increment {};
//         let _res = execute(deps.as_mut(), mock_env(), info, exec_msg).unwrap();

//         // should increase counter by 1
//         let res = query(deps.as_ref(), mock_env(), QueryMsg::GetCount {}).unwrap();
//         let value: CountResponse = from_binary(&res).unwrap();
//         assert_eq!(18, value.count);
//     }

//     #[test]
//     fn reset() {
//         let mut deps = mock_dependencies_with_balance(&[Coin {
//             denom: "token".to_string(),
//             amount: Uint128::new(2),
//         }]);
//         let info = mock_info(
//             "creator",
//             &[Coin {
//                 denom: "token".to_string(),
//                 amount: Uint128::new(2),
//             }],
//         );
//         let init_msg = InstantiateMsg { count: 17 };

//         let _res = instantiate(deps.as_mut(), mock_env(), info, init_msg).unwrap();

//         // not anyone can reset
//         let info = mock_info(
//             "anyone",
//             &[Coin {
//                 denom: "token".to_string(),
//                 amount: Uint128::new(2),
//             }],
//         );
//         let exec_msg = ExecuteMsg::Reset { count: 5 };

//         let res = execute(deps.as_mut(), mock_env(), info, exec_msg);

//         match res {
//             Err(StdError::GenericErr { .. }) => {}
//             _ => panic!("Must return unauthorized error"),
//         }

//         // only the original creator can reset the counter
//         let info = mock_info(
//             "creator",
//             &[Coin {
//                 denom: "token".to_string(),
//                 amount: Uint128::new(2),
//             }],
//         );
//         let exec_msg = ExecuteMsg::Reset { count: 5 };

//         let _res = execute(deps.as_mut(), mock_env(), info, exec_msg).unwrap();

//         // should now be 5
//         let res = query(deps.as_ref(), mock_env(), QueryMsg::GetCount {}).unwrap();
//         let value: CountResponse = from_binary(&res).unwrap();
//         assert_eq!(5, value.count);
//     }
// }

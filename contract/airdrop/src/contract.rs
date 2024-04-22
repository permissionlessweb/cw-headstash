use crate::msg::{ConfigResponse, ExecuteMsg, Headstash, InstantiateMsg, QueryMsg};
use crate::state::{
    claim_status_r, claim_status_w, config, config_r, total_claimed_w, Config, HEADSTASH_OWNERS,
};
use cosmwasm_std::{
    entry_point, to_binary, Binary, CosmosMsg, Deps, DepsMut, Env, MessageInfo, Response, StdError,
    StdResult, Uint128,
};
use secret_toolkit::snip20::transfer_msg;

#[entry_point]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> StdResult<Response> {
    let state = Config {
        snip20_1: msg.snip20_1,
        snip20_2: msg.snip20_2,
        merkle_root: msg.merkle_root,
        viewing_key: msg.viewing_key,
        admin: Some(msg.admin.unwrap_or(info.sender)),
        claim_msg_plaintext: msg.claim_msg_plaintext,
    };

    // Initialize claim amount
    // total_claimed_w(deps.storage).save(&Uint128::zero())?;
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
        ExecuteMsg::Clawback {} => todo!(),
    }
}

pub fn try_add_headstash(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    headstash: Vec<Headstash>,
) -> StdResult<Response> {
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
    _env: Env,
    info: MessageInfo,
    eth_pubkey: String,
    eth_sig: String,
) -> StdResult<Response> {
    let config = config_r(deps.storage).load()?;

    let sender = info.sender.to_string();

    // make sure airdrop has not ended

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

    // update address as claimed
    claim_status_w(deps.storage).save(eth_pubkey.as_bytes(), &true)?;
    // update total_claimed
    // total_claimed_w(deps.storage)
    //     .update(|claimed| -> StdResult<Uint128> { Ok(claimed + amount) })?;

    Ok(Response::default().add_messages(msgs))
}

#[entry_point]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::Config {} => to_binary(&query_config(deps)?),
    }
}

fn query_config(deps: Deps) -> StdResult<ConfigResponse> {
    let state = config_r(deps.storage).load()?;
    Ok(ConfigResponse {
        config: config_r(deps.storage).load()?,
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

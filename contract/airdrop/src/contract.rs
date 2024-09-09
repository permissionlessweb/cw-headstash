use crate::msg::{ExecuteMsg, InstantiateMsg, MigrateMsg, QueryAnswer, QueryMsg};
use crate::state::{
    claim_status_r, config, config_r, decay_claimed_r, decay_claimed_w, Config, Headstash,
    HEADSTASH_OWNERS, TOTAL_CLAIMED,
};
use crate::SNIP120U_REPLY;

use cosmwasm_std::{
    entry_point, to_binary, Addr, Binary, CosmosMsg, Deps, DepsMut, Env, MessageInfo, Reply,
    Response, StdError, StdResult, SubMsgResult, Uint128,
};
// use snip20_reference_impl::msg::InitConfig;
// use snip20_reference_impl::msg::InstantiateMsg as Snip120uInitMsg;

#[entry_point]
pub fn instantiate(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> StdResult<Response> {
    // let mut submsg = vec![];
    // let mut attr = vec![];
    let start_date = match msg.start_date {
        None => env.block.time.seconds(),
        Some(date) => date,
    };

    // for each coin sent, we instantiate a custom snip120u contract.
    // sent as submsg to handle reply and save contract addr to state.
    // for coin in info.funds {
    //     for snip120 in &msg.snips {
    //         if coin.denom == snip120.token {
    //             {
    //                 let custom_config = InitConfig::default(); // todo

    //                 let snip20_init = snip20_reference_impl::msg::InstantiateMsg {
    //                     name: snip120.name.clone(),
    //                     admin: Some(info.sender.to_string()),
    //                     symbol: snip120.name.clone(),
    //                     decimals: 6u8,
    //                     initial_balances: None,
    //                     prng_seed: b"skeeeeeeeeeeeerrretrewhjmfgrew234545766uhrgbag3taweu".into(),
    //                     config: Some(custom_config),
    //                     supported_denoms: Some(vec![snip120.token.clone()]),
    //                 };

    //                 let init_msgs = utils::to_cosmos_msg(
    //                     snip20_init,
    //                     msg.snip120u_code_hash.clone(),
    //                     msg.snip120u_code_id,
    //                 )?;

    //                 submsg.push(SubMsg::reply_on_success(init_msgs, SNIP120U_REPLY));
    //                 attr.push(Event::new("snip120u").add_attribute("addr", snip120.token.clone()))
    //             }
    //         }
    //     }
    // }

    let state = Config {
        admin: info.sender,
        claim_msg_plaintext: msg.claim_msg_plaintext,
        end_date: msg.end_date,
        snip120us: msg.snips,
        start_date: start_date,
        viewing_key: msg.viewing_key,
        snip_hash: msg.snip120u_code_hash,
        circuitboard: msg.circuitboard,
    };

    config(deps.storage).save(&state)?;

    Ok(
        Response::default(), // .add_submessages(submsg).add_events(attr)
    )
}

#[entry_point]
pub fn execute(deps: DepsMut, env: Env, info: MessageInfo, msg: ExecuteMsg) -> StdResult<Response> {
    match msg {
        ExecuteMsg::Add { headstash } => {
            self::headstash::try_add_headstash(deps, env, info, headstash)
        }
        ExecuteMsg::Claim {
            eth_pubkey,
            eth_sig,
            heady_wallet,
        } => self::headstash::try_claim(deps, env, info, eth_pubkey, eth_sig, heady_wallet),
        ExecuteMsg::Clawback {} => self::headstash::try_clawback(deps, env, info),
    }
}

#[entry_point]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::Config {} => to_binary(&queries::query_config(deps)?),
        QueryMsg::Dates {} => to_binary(&queries::dates(deps)?),
        QueryMsg::Clawback {} => to_binary(&queries::clawback(deps)?),
    }
}

#[entry_point]
pub fn reply(deps: DepsMut, _env: Env, reply: Reply) -> StdResult<Response> {
    match reply.id {
        SNIP120U_REPLY => {
            match reply.result {
                SubMsgResult::Ok(c) => {
                    let mut origin_key = None;
                    let mut init_addr = None;

                    let mut config = config_r(deps.storage).load()?;

                    for event in c.events {
                        if event.ty == "instantiate" {
                            for attr in &event.attributes {
                                if attr.key == "contract_address" {
                                    init_addr = Some(attr.value.clone());
                                }
                            }
                        }
                        if event.ty == "snip120u" {
                            for attr in &event.attributes {
                                if attr.key == "origin" {
                                    origin_key = Some(attr.value.clone());
                                }
                            }

                            if let Some(coin) = origin_key.clone() {
                                if let Some(addr) = init_addr.clone() {
                                    if let Some(matching_snip120) = config
                                        .snip120us
                                        .iter_mut()
                                        .find(|snip120| snip120.token == coin)
                                    {
                                        matching_snip120.addr = Some(Addr::unchecked(addr.clone()));
                                    }
                                    TOTAL_CLAIMED.insert(deps.storage, &addr, &Uint128::zero())?;
                                }
                            }
                        }
                    }
                }
                SubMsgResult::Err(_) => todo!(),
            }
            Ok(Response::new())
        }
        _ => {
            return Err(StdError::GenericErr {
                msg: "bad reply".into(),
            })
        }
    }
}

#[entry_point]
pub fn migrate(_deps: DepsMut, _env: Env, msg: MigrateMsg) -> StdResult<Response> {
    match msg {
        _ => Err(StdError::generic_err("unimplemented")),
    }
}

pub mod headstash {
    // use crate::state::AllowanceAction;
    // use secret_toolkit::snip20::MintersResponse;

    use crate::state::TOTAL_CLAIMED;

    use super::*;
    use anybuf::Anybuf;

    pub fn try_clawback(deps: DepsMut, env: Env, info: MessageInfo) -> StdResult<Response> {
        let mut msgs: Vec<CosmosMsg> = vec![];
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

            for snip in config.snip120us {
                if let Some(addr) = snip.addr {
                    // get headstash amount from KeyMap
                    let total_claimed = TOTAL_CLAIMED
                        .get(deps.storage, &addr.to_string())
                        .ok_or_else(|| StdError::generic_err("weird bug!"))?;

                    let clawback_total = snip.total_amount.checked_sub(total_claimed)?;

                    let mint_msg = secret_toolkit::snip20::mint_msg(
                        admin.to_string(),
                        clawback_total,
                        None,
                        None,
                        1usize,
                        "".into(),
                        addr.to_string(),
                    )?;
                    let binary = cosmwasm_std::to_binary(&mint_msg)?;

                    msgs.push(CosmosMsg::Stargate {
                        type_url: "/secret.compute.v1beta1.MsgExecuteContract".into(),
                        value: Anybuf::new()
                            .append_string(1, env.contract.address.to_string()) // sender (This contract)
                            .append_string(2, addr.clone()) // SNIP25 contract addr
                            .append_bytes(3, binary.to_vec()) // msg-bytes
                            .append_repeated_message::<Anybuf>(5, &[]) // empty native tokens sent for now.
                            .into_vec()
                            .into(),
                    });
                    // Update total claimed
                    TOTAL_CLAIMED.insert(deps.storage, &addr.to_string(), &clawback_total)?;
                } else {
                }
            }

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
        queries::available(&config, &env)?;

        // ensure eth_pubkey is not already in KeyMap
        for hs in headstash.into_iter() {
            let key = hs.pubkey;
            for snip in hs.snip.into_iter() {
                if HEADSTASH_OWNERS.contains(deps.storage, &(key.clone(), snip.addr.clone())) {
                    return Err(StdError::generic_err(
                        "pubkey already has been added, not adding again",
                    ));
                } else {
                    // add eth_pubkey & amount to KeyMap
                    HEADSTASH_OWNERS.insert(
                        deps.storage,
                        &(key.clone(), snip.addr),
                        &snip.amount,
                    )?;
                }
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
        heady_wallet: String,
    ) -> StdResult<Response> {
        let mut msgs: Vec<CosmosMsg> = vec![];
        let config = config_r(deps.storage).load()?;

        // make sure airdrop has not ended
        queries::available(&config, &env)?;

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

        for snip in config.snip120us {
            if let Some(addr) = snip.addr {
                // // ensure each snip configured has this contract set as minter.
                // let res: Binary = deps.querier.query_wasm_smart(
                //     config.snip_hash.clone(),
                //     addr.clone(),
                //     &snip20_reference_impl::msg::QueryMsg::Minters {},
                // )?;
                // let all: MintersResponse = from_binary(&res)?;
                // if all
                //     .minters
                //     .minters
                //     .into_iter()
                //     .find(|m| m == &env.contract.address.to_string())
                //     .is_none()
                // {
                //     return Err(StdError::generic_err(
                //         ContractError::HeadstashNotSnip120uMinter {}.to_string(),
                //     ));
                // };

                // get headstash amount from KeyMap
                let headstash_amount = HEADSTASH_OWNERS
                    .get(deps.storage, &(eth_pubkey.clone(), addr.to_string()))
                    .ok_or_else(|| {
                        StdError::generic_err("Ethereum Pubkey not found in the contract state!")
                    })?;

                // mint headstash amount to heady wallet.
                // todo: import custom snip120u crate and set alloance on mint
                let mint_msg = secret_toolkit::snip20::mint_msg(
                    deps.api.addr_validate(&heady_wallet)?.to_string(),
                    headstash_amount,
                    None,
                    None,
                    1usize,
                    "".into(),
                    addr.to_string(),
                )?;
                // let mint_msg = snip20_reference_impl::msg::ExecuteMsg::Mint {
                //     recipient: ,
                //     amount: secret_cosmwasm_std::Uint128::from()),
                //     memo: None,
                //     decoys: None, // todo:: generate random decoys
                //     // allowances: Some(
                //     //     vec[
                //     //      AllowanceAction {
                //     //         spender: config.circuitboard,
                //     //         amount: headstash_amount.clone(),
                //     //         expiration: None,
                //     //         memo: None,
                //     //         decoys: todo!(),
                //     //     }],
                //     // ),
                //     entropy: None,
                //     padding: None,
                // };

                msgs.push(CosmosMsg::Stargate {
                    type_url: "/secret.compute.v1beta1.MsgExecuteContract".into(),
                    value: Anybuf::new()
                        .append_string(1, env.contract.address.to_string()) // sender (This contract)
                        .append_string(2, addr.clone()) // SNIP25 contract addr
                        .append_bytes(3, to_binary(&mint_msg)?.to_vec()) // msg-bytes
                        .append_repeated_message::<Anybuf>(5, &[]) // empty native tokens sent for now.
                        .into_vec()
                        .into(),
                });
                // Update total claimed for specific snip20
                TOTAL_CLAIMED.insert(deps.storage, &addr.to_string(), &headstash_amount)?;
            }
        }
        Ok(Response::default().add_messages(msgs))
    }
}

pub mod queries {
    use super::*;

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

    pub fn clawback(deps: Deps) -> StdResult<QueryAnswer> {
        Ok(QueryAnswer::ClawbackResponse {
            bool: decay_claimed_r(deps.storage).load()?,
        })
    }

    pub fn query_config(deps: Deps) -> StdResult<QueryAnswer> {
        Ok(QueryAnswer::ConfigResponse {
            config: config_r(deps.storage).load()?,
        })
    }

    pub fn dates(deps: Deps) -> StdResult<QueryAnswer> {
        let config = config_r(deps.storage).load()?;
        Ok(QueryAnswer::DatesResponse {
            start: config.start_date,
            end: config.end_date,
            // decay_start: config.decay_start,
        })
    }
}
// src: https://github.com/public-awesome/launchpad/blob/main/contracts/sg-eth-airdrop/src/claim_airdrop.rs#L85
pub mod validation {
    use super::*;
    use crate::verify_ethereum_text;

    pub fn validate_instantiation_params(
        _info: MessageInfo,
        msg: InstantiateMsg,
    ) -> Result<(), StdError> {
        validate_plaintext_msg(msg.claim_msg_plaintext)?;
        Ok(())
    }

    /// Validates an ethereum signature comes from a given pubkey.
    pub fn validate_claim(
        deps: &DepsMut,
        info: MessageInfo,
        eth_pubkey: String,
        eth_sig: String,
        config: Config,
    ) -> Result<(), StdError> {
        match validate_ethereum_text(deps, info, &config, eth_sig, eth_pubkey.clone())? {
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

    /// Replaces the compute plain text with the message sender.
    pub fn compute_plaintext_msg(config: &Config, info: MessageInfo) -> String {
        str::replace(
            &config.claim_msg_plaintext,
            "{wallet}",
            info.sender.as_ref(),
        )
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

pub mod utils {
    // use super::*;
    // pub fn to_cosmos_msg(
    //     msg: Snip120uInitMsg,
    //     code_hash: String,
    //     code_id: u64,
    // ) -> StdResult<CosmosMsg> {
    //     let msg = to_binary(&msg)?;

    //     let funds = Vec::new();
    //     let execute = WasmMsg::Instantiate {
    //         code_id,
    //         code_hash,
    //         msg,
    //         label: "instantiate-snip".into(),
    //         funds,
    //         admin: None,
    //     };
    //     Ok(execute.into())
    // }

    // Take a Vec<u8> and pad it up to a multiple of `block_size`, using spaces at the end.
    pub fn space_pad(block_size: usize, message: &mut Vec<u8>) -> &mut Vec<u8> {
        let len = message.len();
        let surplus = len % block_size;
        if surplus == 0 {
            return message;
        }

        let missing = block_size - surplus;
        message.reserve(missing);
        message.extend(std::iter::repeat(b' ').take(missing));
        message
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

use crate::error::ContractError;
use crate::msg::{ExecuteMsg, InstantiateMsg, MigrateMsg, QueryAnswer, QueryMsg};
use crate::state::{
    claim_status_r, config, config_r, decay_claimed_r, decay_claimed_w, Config, Headstash,
    HEADSTASH_OWNERS,
};
use base64::engine::general_purpose;
use base64::Engine;
// use crate::SNIP120U_REPLY;

#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;

use cosmwasm_std::{
    to_binary, Binary, CosmosMsg, Deps, DepsMut, Env, MessageInfo, Reply, Response, StdError,
    StdResult,
};

#[cfg_attr(not(feature = "library"), entry_point)]
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

    validation::validate_plaintext_msg(msg.claim_msg_plaintext.clone())?;

    for snip in msg.snips.clone() {
        let snips = msg.snips.iter();
        if snips
            .clone()
            .any(|a| a.native_token == snip.native_token || a.addr == snip.addr)
        {
            return Err(StdError::generic_err(
                ContractError::DuplicateSnip120u {}.to_string(),
            ));
        }
    }
    let state = Config {
        admin: info.sender,
        claim_msg_plaintext: msg.claim_msg_plaintext,
        end_date: msg.end_date,
        snip120us: msg.snips,
        start_date,
        viewing_key: msg.viewing_key,
        snip_hash: msg.snip120u_code_hash,
        channel_id: msg.channel_id,
    };

    config(deps.storage).save(&state)?;
    Ok(Response::default())
    // for each coin sent, we instantiate a custom snip120u contract.
    // sent as submsg to handle reply and save contract addr to state.
    // let mut submsg = vec![];
    // let mut attr = vec![];
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
    // .add_submessages(submsg).add_events(attr)
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(deps: DepsMut, env: Env, info: MessageInfo, msg: ExecuteMsg) -> StdResult<Response> {
    match msg {
        ExecuteMsg::AddEligibleHeadStash { headstash } => {
            self::headstash::try_add_headstash(deps, env, info, headstash)
        }
        ExecuteMsg::Claim {
            eth_pubkey,
            eth_sig,
            heady_wallet,
        } => self::headstash::try_claim(deps, env, info, eth_pubkey, eth_sig, heady_wallet),
        ExecuteMsg::Clawback {} => self::headstash::try_clawback(deps, env, info),
        ExecuteMsg::IbcBloom {
            destination_addr,
            eth_pubkey,
            eth_sig,
            snip120s,
        } => self::ibc_bloom::try_ibc_bloom(
            deps,
            env,
            info,
            eth_pubkey,
            eth_sig,
            destination_addr,
            snip120s,
        ),
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::Config {} => to_binary(&queries::query_config(deps)?),
        QueryMsg::Dates {} => to_binary(&queries::dates(deps)?),
        QueryMsg::Clawback {} => to_binary(&queries::clawback(deps)?),
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn reply(_deps: DepsMut, _env: Env, reply: Reply) -> StdResult<Response> {
    match reply.id {
        _ => {
            return Err(StdError::GenericErr {
                msg: "bad reply".into(),
            })
        } // SNIP120U_REPLY => {
          //     match reply.result {
          //         SubMsgResult::Ok(c) => {
          //             let mut origin_key = None;
          //             let mut init_addr = None;

          //             let mut config = config_r(deps.storage).load()?;

          //             for event in c.events {
          //                 if event.ty == "instantiate" {
          //                     for attr in &event.attributes {
          //                         if attr.key == "contract_address" {
          //                             init_addr = Some(attr.value.clone());
          //                         }
          //                     }
          //                 }
          //                 if event.ty == "snip120u" {
          //                     for attr in &event.attributes {
          //                         if attr.key == "origin" {
          //                             origin_key = Some(attr.value.clone());
          //                         }
          //                     }

          //                     if let Some(coin) = origin_key.clone() {
          //                         if let Some(addr) = init_addr.clone() {
          //                             if let Some(matching_snip120) = config
          //                                 .snip120us
          //                                 .iter_mut()
          //                                 .find(|snip120| snip120.token == coin)
          //                             {
          //                                 matching_snip120.addr = Some(Addr::unchecked(addr.clone()));
          //                             }
          //                             TOTAL_CLAIMED.insert(deps.storage, &addr, &Uint128::zero())?;
          //                         }
          //                     }
          //                 }
          //             }
          //         }
          //         SubMsgResult::Err(_) => todo!(),
          //     }
          //     Ok(Response::new())
          // }
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn migrate(_deps: DepsMut, _env: Env, msg: MigrateMsg) -> StdResult<Response> {
    match msg {
        _ => Err(StdError::generic_err("unimplemented")),
    }
}

pub mod headstash {

    use super::*;
    use crate::state::{AllowanceAction, TOTAL_CLAIMED};

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
        pubkey: String,
        sig: String,
        heady_wallet: String,
    ) -> StdResult<Response> {
        let mut msgs: Vec<CosmosMsg> = vec![];
        let config = config_r(deps.storage).load()?;

        // make sure airdrop has not ended
        queries::available(&config, &env)?;

        // if pubkey does not start with 0x1, we expect it is a solana wallet and we must verify
        if pubkey.starts_with("0x1") {
            validation::verify_ethereum_claim(
                &deps,
                info.sender.clone(),
                pubkey.to_string(),
                sig.clone(),
                config.claim_msg_plaintext.clone(),
            )?;
        } else {
            validation::verify_solana_wallet(
                &deps,
                info.sender.clone(),
                pubkey.clone(),
                sig,
                config.claim_msg_plaintext,
            )?;
        }

        // check if address has already claimed
        let state = claim_status_r(deps.storage).may_load(pubkey.as_bytes())?;
        if state == Some(true) {
            return Err(StdError::generic_err(
                "You have already claimed your headstash, homie!",
            ));
        }

        for snip in config.snip120us {
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
                .get(deps.storage, &(pubkey.clone(), snip.addr.to_string()))
                .ok_or_else(|| {
                    StdError::generic_err("Ethereum Pubkey not found in the contract state!")
                })?;

            // mint headstash amount to heady wallet. set allowance for circuitboard
            let mint_msg = crate::msg::snip::mint_msg(
                deps.api.addr_validate(&heady_wallet)?.to_string(),
                headstash_amount,
                vec![AllowanceAction {
                    spender: env.contract.address.to_string(),
                    amount: headstash_amount.clone(),
                    expiration: None,
                    memo: None,
                    decoys: None,
                }],
                None,
                None,
                1usize,
                config.snip_hash.clone(),
                snip.addr.to_string(),
            )?;

            msgs.push(mint_msg);
            // Update total claimed for specific snip20
            TOTAL_CLAIMED.insert(deps.storage, &snip.addr.to_string(), &headstash_amount)?;
        }

        Ok(Response::default().add_messages(msgs))
    }

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
                // get headstash amount from KeyMap
                let total_claimed = TOTAL_CLAIMED
                    .get(deps.storage, &snip.addr.to_string())
                    .ok_or_else(|| StdError::generic_err("weird bug!"))?;

                let clawback_total = snip.total_amount.checked_sub(total_claimed)?;

                let mint_msg = crate::msg::snip::mint_msg(
                    admin.to_string(),
                    clawback_total,
                    vec![],
                    None,
                    None,
                    1usize,
                    config.snip_hash.clone(),
                    snip.addr.to_string(),
                )?;

                msgs.push(mint_msg);
                // Update total claimed
                TOTAL_CLAIMED.insert(deps.storage, &snip.addr.to_string(), &clawback_total)?;
            }
        } else {
            return Err(StdError::generic_err(
                "Clawback was not setup for this one, playa!",
            ));
        }

        return Ok(Response::default().add_messages(msgs));
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
        })
    }
}
// src: https://github.com/public-awesome/launchpad/blob/main/contracts/sg-eth-airdrop/src/claim_airdrop.rs#L85
pub mod validation {
    use cosmwasm_std::Addr;

    use super::*;
    use crate::verify_ethereum_text;

    pub fn validate_instantiation_params(
        _info: MessageInfo,
        msg: InstantiateMsg,
    ) -> Result<(), StdError> {
        validate_plaintext_msg(msg.claim_msg_plaintext)?;
        Ok(())
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

    /// Validates an ethereum signature comes from a given pubkey.
    pub fn verify_ethereum_claim(
        deps: &DepsMut,
        sender: Addr,
        eth_pubkey: String,
        eth_sig: String,
        plaintxt: String,
    ) -> Result<(), StdError> {
        match validate_ethereum_text(deps, sender, plaintxt, eth_sig, eth_pubkey.clone())? {
            true => Ok(()),
            false => Err(StdError::generic_err("cannot validate eth_sig")),
        }
    }

    pub fn validate_ethereum_text(
        deps: &DepsMut,
        sender: Addr,
        plaintxt: String,
        eth_sig: String,
        eth_pubkey: String,
    ) -> StdResult<bool> {
        let plaintext_msg = compute_plaintext_msg(plaintxt, sender);
        match hex::decode(eth_sig.clone()) {
            Ok(eth_sig_hex) => {
                verify_ethereum_text(deps.as_ref(), &plaintext_msg, &eth_sig_hex, &eth_pubkey)
            }
            Err(_) => Err(StdError::InvalidHex {
                msg: format!("Could not decode the eth signature"),
            }),
        }
    }

    /// Replaces the compute plain text with the message sender.
    pub fn compute_plaintext_msg(plaintxt: String, sender: Addr) -> String {
        str::replace(&plaintxt, "{wallet}", sender.as_ref())
    }

    // source: https://github.com/SecretSaturn/SecretPath/blob/aae6c61ff755aa22112945eab308e9037044980b/TNLS-Gateways/secret/src/msg.rs#L101
    pub fn verify_solana_wallet(
        deps: &DepsMut,
        sender: Addr,
        pubkey: String,
        signature: String,
        plaintxt: String,
    ) -> Result<(), StdError> {
        let computed_plaintxt = compute_plaintext_msg(plaintxt, sender);
        match deps.api.secp256k1_verify(
            computed_plaintxt.clone().into_bytes().as_slice(),
            signature.clone().into_bytes().as_slice(),
            pubkey.clone().into_bytes().as_slice(),
        ) {
            Ok(true) => Ok(()),
            Ok(false) | Err(_) => deps
                .api
                .ed25519_verify(
                    &general_purpose::STANDARD
                        .encode(computed_plaintxt.into_bytes().as_slice())
                        .as_bytes(),
                    signature.into_bytes().as_slice(),
                    pubkey.into_bytes().as_slice(),
                )
                .map_err(|err| StdError::generic_err(err.to_string()))
                .and_then(|verified| {
                    if verified {
                        Ok(())
                    } else {
                        Err(StdError::generic_err("Verification failed"))
                    }
                }),
        }
    }
}

pub mod ibc_bloom {
    use super::*;

    use cosmwasm_std::{Addr, Coin, DepsMut, IbcMsg, IbcTimeout, StdError};

    use crate::state::{ibc_bloom_status_r, ibc_bloom_status_w};
    use crate::verify::verify_ethereum_text;

    use crate::{msg::snip::into_cosmos_msg, state::BloomSnip120u};

    pub fn try_ibc_bloom(
        deps: DepsMut,
        env: Env,
        info: MessageInfo,
        pubkey: String,
        sig: String,
        destination_addr: String,
        snip120us: Vec<BloomSnip120u>,
    ) -> StdResult<Response> {
        let mut msgs = vec![];
        let config = config_r(deps.storage).load()?;
        // if pubkey does not start with 0x1, we expect it is a solana wallet and we must verify
        if pubkey.starts_with("0x1") {
            verify_bloom_claim(
                &deps,
                info.sender.clone(),
                pubkey.clone(),
                sig.clone(),
                config.claim_msg_plaintext,
                destination_addr.clone(),
            )?;
        } else {
        }

        for snip in snip120us {
            HEADSTASH_OWNERS
                .get(deps.storage, &(pubkey.clone(), snip.address.to_string()))
                .ok_or_else(|| {
                    StdError::generic_err("Ethereum Pubkey not found in the contract state!")
                })?;

            if ibc_bloom_status_r(deps.storage).load(sig.as_bytes())? {
                return Err(StdError::generic_err("already ibc-bloomed"));
            }

            if let Some(address) = config.snip120us.iter().find(|e| e.addr == snip.address) {
                let contract = env.contract.address.clone();
                let transfer_from = crate::msg::snip::TransferFrom {
                    owner: contract.to_string(),
                    recipient: contract.to_string(),
                    amount: snip.amount,
                    memo: None,
                    decoys: None,
                    entropy: None,
                    padding: None,
                };

                let snip120_msg = into_cosmos_msg(
                    transfer_from,
                    1usize,
                    config.snip_hash.clone(),
                    snip.address.to_string(),
                    None,
                )?;

                let ibc_send = IbcMsg::Transfer {
                    channel_id: config.channel_id.clone(),
                    to_address: destination_addr.clone(),
                    amount: Coin::new(snip.amount.u128(), address.native_token.clone()),
                    timeout: IbcTimeout::with_timestamp(env.block.time.plus_seconds(300u64)),
                    memo: "".into(),
                };

                msgs.push(snip120_msg);
                msgs.push(ibc_send.into())
            } else {
                return Err(StdError::generic_err("no snip20 addr provided"));
            }
        }

        // set eth-pubkey to state
        ibc_bloom_status_w(deps.storage).save(pubkey.as_bytes(), &true)?;

        Ok(Response::new().add_messages(msgs))
    }

    // todo: compress into headstash validation also
    pub fn verify_bloom_claim(
        deps: &DepsMut,
        sender: Addr,
        eth_pubkey: String,
        eth_sig: String,
        claim_plaintxt: String,
        secondary_address: String,
    ) -> Result<(), StdError> {
        match validate_bloom_ethereum_text(
            deps,
            sender,
            &claim_plaintxt,
            eth_sig,
            eth_pubkey,
            secondary_address,
        )? {
            true => Ok(()),
            false => Err(StdError::generic_err("cannot validate eth_sig")),
        }
    }

    // will compose the expected message that was signed to verify responding with ibc-msg
    pub fn validate_bloom_ethereum_text(
        deps: &DepsMut,
        sender: Addr,
        claim_plaintxt: &String,
        eth_sig: String,
        eth_pubkey: String,
        secondary_address: String,
    ) -> StdResult<bool> {
        let plaintext_msg = compute_bloom_plaintext_msg(claim_plaintxt, sender, &secondary_address);
        match hex::decode(eth_sig.clone()) {
            Ok(eth_sig_hex) => {
                verify_ethereum_text(deps.as_ref(), &plaintext_msg, &eth_sig_hex, &eth_pubkey)
            }
            Err(_) => Err(StdError::InvalidHex {
                msg: format!("Could not decode {eth_sig}"),
            }),
        }
    }

    // loads the sender and secondary wallet to the claim_plaintxt string.
    pub fn compute_bloom_plaintext_msg(
        claim_plaintxt: &String,
        sender: Addr,
        secondary_address: &String,
    ) -> String {
        let mut plaintext_msg = str::replace(&claim_plaintxt, "{wallet}", sender.as_ref());
        plaintext_msg = str::replace(&plaintext_msg, "{secondary_address}", secondary_address);
        plaintext_msg
    }

    // verifies the computed plaintxt includes both the sender and the destination wallet
    pub fn validate_bloom_plaintext_msg(
        plaintext_msg: String,
        sender: &str,
        secondary: &str,
    ) -> Result<(), StdError> {
        if !plaintext_msg.contains(sender) || !plaintext_msg.contains(secondary) {
            return Err(StdError::generic_err(
                "Plaintext message must contain the sender and destination wallet",
            ));
        }
        if plaintext_msg.len() > 1000 {
            return Err(StdError::generic_err("Plaintext message is too long"));
        }
        Ok(())
    }

    // source: https://github.com/SecretSaturn/SecretPath/blob/aae6c61ff755aa22112945eab308e9037044980b/TNLS-Gateways/secret/src/msg.rs#L101
    pub fn verify_solana_wallet(
        deps: &DepsMut,
        sender: Addr,
        pubkey: String,
        signature: String,
        plaintxt: String,
        secondary_address: &String,
    ) -> Result<(), StdError> {
        let computed_plaintxt = compute_bloom_plaintext_msg(&plaintxt, sender, secondary_address);
        match deps.api.secp256k1_verify(
            computed_plaintxt.clone().into_bytes().as_slice(),
            signature.clone().into_bytes().as_slice(),
            pubkey.clone().into_bytes().as_slice(),
        ) {
            Ok(true) => Ok(()),
            Ok(false) | Err(_) => deps
                .api
                .ed25519_verify(
                    &general_purpose::STANDARD
                        .encode(computed_plaintxt.into_bytes().as_slice())
                        .as_bytes(),
                    signature.into_bytes().as_slice(),
                    pubkey.into_bytes().as_slice(),
                )
                .map_err(|err| StdError::generic_err(err.to_string()))
                .and_then(|verified| {
                    if verified {
                        Ok(())
                    } else {
                        Err(StdError::generic_err("Verification failed"))
                    }
                }),
        }
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

#[cfg(test)]
mod tests {
    use cosmwasm_std::{testing::*, Addr, OwnedDeps};
    use ibc_bloom::compute_bloom_plaintext_msg;

    use super::*;

    pub const PLAINTXT: &str = "H.R.E.A.M. Sender: {wallet} Headstash: {secondary_address}";

    #[test]
    fn test_compute_bloom_plaintext_msg() {
        let expected_result = "H.R.E.A.M. Sender: sender123 Headstash: secondary123";
        // Create test variables

        let sender = Addr::unchecked("sender123");
        let secondary_address = "secondary123".to_string();

        assert_eq!(
            compute_bloom_plaintext_msg(&PLAINTXT.to_string(), sender.clone(), &secondary_address),
            expected_result.to_string()
        );

        let err = compute_bloom_plaintext_msg(
            &PLAINTXT.to_string(),
            Addr::unchecked(secondary_address),
            &sender.to_string(),
        );

        assert_ne!(err, expected_result.to_string());
    }

    fn init_helper() -> (
        StdResult<Response>,
        OwnedDeps<MockStorage, MockApi, MockQuerier>,
    ) {
        let mut deps = mock_dependencies_with_balance(&[]);
        let env = mock_env();
        let info = mock_info("instantiator", &[]);

        // todo: setup snip120u

        let init_msg = crate::msg::InstantiateMsg {
            owner: todo!(),
            claim_msg_plaintext: PLAINTXT.to_string(),
            start_date: None,
            end_date: None,
            // snip120u_code_id: 2,
            snip120u_code_hash: "HASH".into(),
            snips: vec![],
            viewing_key: todo!(),
            channel_id: todo!(),
        };

        (instantiate(deps.as_mut(), env, info, init_msg), deps)
    }
}

use crate::error::ContractError;
use crate::msg::{ExecuteMsg, InstantiateMsg, MigrateMsg, QueryAnswer, QueryMsg};
use crate::state::{Config, Headstash, CONFIG};

#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;

use cosmwasm_std::{
    to_binary, Binary, CosmosMsg, Deps, DepsMut, Env, MessageInfo, Reply, Response, StdError,
    StdResult,
};
use rand_core::RngCore;
use secret_toolkit::crypto::ContractPrng;

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> StdResult<Response> {
    let start_date = match msg.start_date {
        None => env.block.time.seconds(),
        Some(date) => date.into(),
    };

    validation::validate_plaintext_msg(msg.claim_msg_plaintext.clone())?;

    let mut unique_snips: Vec<crate::state::snip::Snip120u> = Vec::new();
    for snip in msg.snips.clone() {
        if unique_snips
            .iter()
            .any(|a| a.native_token == snip.native_token || a.addr == snip.addr)
        {
            return Err(StdError::generic_err(
                ContractError::DuplicateSnip120u {}.to_string(),
            ));
        }
        unique_snips.push(snip);
    }

    let state = Config {
        owner: info.sender,
        claim_msg_plaintext: msg.claim_msg_plaintext,
        end_date: msg.end_date,
        snip120us: msg.snips,
        start_date,
        viewing_key: msg.viewing_key,
        snip_hash: msg.snip120u_code_hash,
        bloom: msg.bloom_config,
        multiplier: msg.multiplier,
    };

    CONFIG.save(deps.storage, &state)?;
    // let mut ica_msg = vec![];
    // if let Some(ica) = msg.channel_open_init_options {
    //     let callback_contract = ContractInfo {
    //         address: env.contract.address.clone(),
    //         code_hash: env.contract.code_hash,
    //     };

    //     // IBC Save the admin. Ica address is determined during handshake. Save headstash params.
    //     STATE.save(deps.storage, &ContractState::new(Some(callback_contract)))?;
    //     CHANNEL_OPEN_INIT_OPTIONS.save(deps.storage, &ica)?;
    //     ALLOW_CHANNEL_OPEN_INIT.save(deps.storage, &true)?;

    //     let ica_channel_open_init_msg = new_ica_channel_open_init_cosmos_msg(
    //         env.contract.address.to_string(),
    //         ica.connection_id,
    //         ica.counterparty_port_id,
    //         ica.counterparty_connection_id,
    //         None,
    //         ica.channel_ordering,
    //     );
    //     ica_msg.push(ica_channel_open_init_msg);
    // } else {
    //     ICA_ENABLED.save(deps.storage, &false)?;
    // }

    Ok(Response::default()) // .add_message(ica_msg[0].clone())
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
        ExecuteMsg::AddEligibleHeadStash { headstash } => {
            self::headstash::try_add_headstash(deps, env, info, &mut rng, headstash)
        }
        ExecuteMsg::Claim { sig_addr, sig } => {
            self::headstash::try_claim(deps, env, info, &mut rng, sig_addr, sig)
        }
        ExecuteMsg::Clawback {} => self::headstash::try_clawback(deps, env, info),
        // ExecuteMsg::Redeem {} => todo!(),
        ExecuteMsg::RegisterBloom { bloom_msg, .. } => {
            self::ibc_bloom::try_ibc_bloom(deps, env, info, bloom_msg)
        }
        ExecuteMsg::PrepareBloom {} => ibc_bloom::prepare_ibc_bloom(deps, env, info),
        ExecuteMsg::ProcessBloom {} => ibc_bloom::process_ibc_bloom(deps, env, info),
        // ExecuteMsg::CreateChannel {
        //     channel_open_init_options,
        // } => ibc::create_channel(deps, env, info, channel_open_init_options),
        // ExecuteMsg::CloseChannel {} => ibc::close_channel(deps, info),
        // ExecuteMsg::ReceiveIcaCallback(ica_controller_callback_msg) => {
        //     ibc::ica_callback_handler(deps, info, ica_controller_callback_msg)
        // }
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
        }
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn migrate(_deps: DepsMut, _env: Env, msg: MigrateMsg) -> StdResult<Response> {
    match msg {
        _ => Err(StdError::generic_err("unimplemented")),
    }
}

pub mod headstash {

    use cosmwasm_std::{Decimal, Uint128};

    use super::*;
    use crate::state::{
        snip::AllowanceAction, HeadstashSig, CLAIMED_HEADSTASH, DECAY_CLAIMED, HEADSTASH_OWNERS,
        HEADSTASH_SIGS, TOTAL_CLAIMED,
    };

    pub fn try_add_headstash(
        deps: DepsMut,
        env: Env,
        info: MessageInfo,
        rng: &mut ContractPrng,
        headstash: Vec<Headstash>,
    ) -> Result<Response, ContractError> {
        // ensure sender is admin
        let config = CONFIG.load(deps.storage)?;

        if headstash.is_empty() {
            return Err(ContractError::EmptyValue {});
        }

        if info.sender != config.owner {
            return Err(ContractError::OwnershipError(
                cw_ownable::OwnershipError::NotOwner,
            ));
        }
        // make sure airdrop has not ended
        queries::available(&config, &env)?;

        add_headstash_to_state(deps, headstash.clone())?;

        Ok(Response::default())
    }

    pub fn add_headstash_to_state(deps: DepsMut, headstash: Vec<Headstash>) -> StdResult<()> {
        // ensure pubkey is not already in KeyMap
        for hs in headstash.into_iter() {
            let key = hs.addr;
            // first key suffix is eligible addr
            let l1 = HEADSTASH_OWNERS.add_suffix(key.as_bytes());
            for snip in hs.snips.into_iter() {
                // second key suffix is snip contract addr
                let l2 = l1.add_suffix(snip.contract.as_bytes());
                if l2.may_load(deps.storage)?.is_some() {
                    return Err(StdError::generic_err(
                        "pubkey already has been added, not adding again",
                    ));
                } else {
                    l2.save(deps.storage, &snip.amount)?
                }
            }
        }
        Ok(())
    }

    pub fn try_claim(
        deps: DepsMut,
        env: Env,
        info: MessageInfo,
        rng: &mut ContractPrng,
        sig_addr: String,
        sig: String,
        // denom: String,
    ) -> Result<Response, ContractError> {
        let mut msgs: Vec<CosmosMsg> = vec![];
        let config = CONFIG.load(deps.storage)?;

        let multiplier: Decimal;

        // make sure airdrop has not ended
        queries::available(&config, &env)?;

        // ensure snip defined is one eligible for this headstash
        // if !config
        //     .snip120us
        //     .iter()
        //     .any(|a| a.native_token.as_str() == denom)
        // {
        //     return Err(ContractError::InvalidSnip120u {});
        // }

        // if pubkey does not start with 0x1, we expect it is a solana wallet and we must verify
        if sig_addr.starts_with("0x") {
            validation::verify_headstash_sig(
                deps.api,
                info.sender.clone(),
                sig_addr.clone(),
                sig.clone(),
                config.claim_msg_plaintext,
                false,
                true,
            )?;
        } else {
            validation::verify_headstash_sig(
                deps.api,
                info.sender.clone(),
                sig_addr.clone(),
                sig.clone(),
                config.claim_msg_plaintext,
                false,
                false,
            )?;
        }

        // check if address has already claimed. This occurs after sig is verified, preventing leakage of claim status for a key.
        let pf = CLAIMED_HEADSTASH.add_suffix(sig_addr.as_bytes());
        if pf.may_load(deps.storage)? == Some(true) {
            return Err(ContractError::AlreadyClaimed {});
        }

        for snip in config.snip120us {
            // check if we apply bonus to claim
            let bonus = self::utils::random_multiplier(rng);

            // get headstash amount from map
            let l1 = HEADSTASH_OWNERS.add_suffix(sig_addr.clone().as_bytes());
            let l2 = l1.add_suffix(snip.addr.as_bytes());
            if let Some(amnt) = l2.may_load(deps.storage)? {
                let headstash_amount = amnt * bonus;
                // mint headstash amount to message signer. set allowance for this contract
                let mint_msg = crate::msg::snip::mint_msg(
                    info.sender.to_string(), // mint to the throwaway key
                    headstash_amount,
                    vec![AllowanceAction {
                        spender: env.contract.address.to_string(),
                        amount: headstash_amount,
                        expiration: config.end_date,
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
                let tc = TOTAL_CLAIMED.add_suffix(snip.addr.as_str().as_bytes());
                tc.save(deps.storage, &Uint128::zero())?;
            }

            CLAIMED_HEADSTASH
                .add_suffix(sig_addr.as_bytes())
                .save(deps.storage, &true)?;
            // msgs sender used as prefix for storage map. Saves addr and signature derived from addr to state for recall during registering a bloom.
            let hs = HEADSTASH_SIGS.add_suffix(info.sender.as_str().as_bytes());
            hs.save(
                deps.storage,
                &HeadstashSig {
                    addr: sig_addr.clone(),
                    sig: sig.clone(),
                },
            )?;
        }
        Ok(Response::default().add_messages(msgs))
    }

    pub fn try_clawback(
        deps: DepsMut,
        env: Env,
        info: MessageInfo,
    ) -> Result<Response, ContractError> {
        let mut msgs: Vec<CosmosMsg> = vec![];
        let config = CONFIG.load(deps.storage)?;

        // ensure sender is admin
        let admin = config.owner;
        if info.sender != admin {
            return Err(ContractError::ClawbackError {});
        }

        // ensure clawback can happen, update state
        if let Some(end_date) = config.end_date {
            if env.block.time.seconds() > end_date {
                DECAY_CLAIMED.update(deps.storage, |claimed| {
                    if claimed {
                        Err(StdError::generic_err("this jawn already was clawed-back!"))
                    } else {
                        Ok(true)
                    }
                })?;
            }

            for snip in config.snip120us {
                // update headstash amount for admin
                let tc = TOTAL_CLAIMED.add_suffix(snip.addr.as_str().as_bytes());
                tc.update(deps.storage, |a| {
                    let new = snip.total_amount.checked_sub(a)?;
                    let mint_msg = crate::msg::snip::mint_msg(
                        admin.to_string(),
                        new,
                        vec![],
                        None,
                        None,
                        1usize,
                        config.snip_hash.clone(),
                        snip.addr.to_string(),
                    )?;
                    msgs.push(mint_msg);
                    Ok(snip.total_amount)
                })?;
            }
        } else {
            return Err(ContractError::ClawbackError {});
        }

        return Ok(Response::default().add_messages(msgs));
    }
}

pub mod queries {
    use crate::state::DECAY_CLAIMED;

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
            bool: DECAY_CLAIMED.load(deps.storage)?,
        })
    }

    pub fn query_config(deps: Deps) -> StdResult<QueryAnswer> {
        Ok(QueryAnswer::ConfigResponse {
            config: CONFIG.load(deps.storage)?,
        })
    }

    pub fn dates(deps: Deps) -> StdResult<QueryAnswer> {
        let config = CONFIG.load(deps.storage)?;
        Ok(QueryAnswer::DatesResponse {
            start: config.start_date,
            end: config.end_date,
        })
    }
}
// src: https://github.com/public-awesome/launchpad/blob/main/contracts/sg-eth-airdrop/src/claim_airdrop.rs#L85
pub mod validation {
    use cosmwasm_std::{Addr, Api};

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

    /// Validates an ethereum signature comes from a given addr.
    pub fn verify_headstash_sig(
        api: &dyn Api,
        sender: Addr,
        signer: String,
        sig: String,
        plaintxt: String,
        bloom: bool,
        eth: bool,
    ) -> Result<(), StdError> {
        // println!("sender: {:#?}", sender);
        // println!("signature: {:#?}", sig);
        // println!("signer: {:#?}", signer);
        // println!("plaintxt: {:#?}", plaintxt);
        // let test = &general_purpose::STANDARD.decode(sig.clone()).unwrap();
        match eth {
            false => {
                let computed_plaintxt = compute_plaintxt_msg(plaintxt, sender);
                let signature = Binary::from_base64(&sig)?;
                let signer = Binary::from_base64(&signer)?;

                match api.secp256k1_verify(
                    computed_plaintxt.clone().into_bytes().as_slice(),
                    Binary::from_base64(&sig)?.as_slice(),
                    signer.clone().as_slice(),
                ) {
                    Ok(true) => Ok(()),
                    Ok(false) | Err(_) => api
                        .ed25519_verify(
                            computed_plaintxt.clone().into_bytes().as_slice(),
                            signature.as_slice(),
                            signer.as_slice(),
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
            true => match validate_ethereum_text(
                api,
                sender.clone(),
                plaintxt,
                sig.clone(),
                signer.clone(),
                // bloom,
            )? {
                true => Ok(()),
                false => Err(StdError::generic_err("cannot validate offline_sig")),
            },
        }
    }

    pub fn validate_ethereum_text(
        api: &dyn Api,
        sender: Addr,
        plaintxt: String,
        offline_sig: String,
        signer: String,
        // bloom: bool,
    ) -> StdResult<bool> {
        let plaintext_msg = compute_plaintxt_msg(plaintxt, sender.clone());
        match hex::decode(offline_sig.clone()) {
            Ok(eth_sig_hex) => verify_ethereum_text(api, &plaintext_msg, &eth_sig_hex, &signer),
            Err(_) => Err(StdError::InvalidHex {
                msg: format!("Could not decode the eth signature"),
            }),
        }
    }

    // ensure blooms are enabled
    pub fn compute_plaintxt_msg(claim_plaintxt: String, sender: Addr) -> String {
        let mut plaintext_msg = str::replace(&claim_plaintxt, "{wallet}", sender.as_ref());
        plaintext_msg
    }
}

pub mod ibc_bloom {
    use std::cmp::min;

    use super::*;

    use cosmwasm_std::{coin, coins, Addr, DepsMut, Empty, IbcTimeout, StdError, Uint128, WasmMsg};
    use utils::contract_randomness;
    use validation::compute_plaintxt_msg;

    use crate::{
        // dwb::BLOOM_DWB,
        // ibc::types::packet::IcaPacketData,
        // transaction_history::{store_register_bloom_action, store_register_headstash_action},
        state::{
            bloom::{BloomBloom, IbcBloomMsg, ProcessingBloomMsg},
            BLOOMSBLOOMS, HEADSTASH_SIGS, PROCESSING_BLOOM_MEMPOOL,
        },
    };

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

    /// Register IBC bloom msgs to one of the dwb's dedicated for IBC-bloom.
    pub fn try_ibc_bloom(
        deps: DepsMut,
        env: Env,
        info: MessageInfo,
        // rng: ContractPrng,
        // addr: String,
        bloom_msg: IbcBloomMsg,
    ) -> Result<Response, ContractError> {
        let config = CONFIG.load(deps.storage)?;
        if config.bloom.is_none() {
            return Err(ContractError::BloomDisabled {});
        }

        // verify msg sender has been authorized with public address signature
        let hs = HEADSTASH_SIGS.add_suffix(info.sender.as_str().as_bytes());
        if let Some(sig) = hs.may_load(deps.storage)? {
            // if sig.addr.ne(info.sender.as_str()) {
            //     return Err(ContractError::BloomMismatchSigner {});
            // }
            if (bloom_msg.bloom.len() as u64)
                .gt(&config.bloom.expect("bloom not setup").max_granularity)
            {
                return Err(ContractError::BloomTooManyGrains {});
            }
            let entropy_key = bloom_msg.entropy_key.clamp(1, 10) as u128;

            // set bloomMsg keyMap key as (b' + entropy_ratio + sender)
            let blooms = BLOOMSBLOOMS.add_suffix(entropy_key.to_string().as_bytes());
            if let Some(bloom) = blooms.get(deps.storage, &info.sender.to_string()) {
                if bloom.msg.source_token == bloom_msg.source_token {
                    return Err(ContractError::BloomDuplicate {});
                }
                blooms.insert(
                    deps.storage,
                    &sig.addr,
                    &BloomBloom {
                        block_height: env.block.height,
                        msg: bloom_msg,
                    },
                )?;
            } else {
                blooms.insert(
                    deps.storage,
                    &sig.addr,
                    &BloomBloom {
                        block_height: env.block.height,
                        msg: bloom_msg,
                    },
                )?;
            };

            // if pubkey does not start with 0x1, we expect it is a solana wallet and we must verify
            // if addr.starts_with("0x1") {
            //     validation::verify_headstash_sig(
            //         deps.api,
            //         info.sender.clone(),
            //         addr.to_string(),
            //         sig.sig.clone(),
            //         config.claim_msg_plaintext.clone(),
            //         true,
            //         false,
            //     )?;
            // } else {
            //     validation::verify_headstash_sig(
            //         deps.api,
            //         info.sender.clone(),
            //         addr.clone(),
            //         sig.sig.clone(),
            //         config.claim_msg_plaintext,
            //         true,
            //         true,
            //     )?;
            // }
        } else {
            return Err(ContractError::BloomNotFound {});
        };

        Ok(Response::new())
        // TODO:
        // a. generate tx-id
        // b. save tx-id to one of bloom dwb's
    }

    /// Choose dwb to load and process redeem msgs.
    pub fn prepare_ibc_bloom(
        deps: DepsMut,
        env: Env,
        info: MessageInfo,
    ) -> Result<Response, ContractError> {
        let mut msgs = vec![];
        // ensure sender is admin
        let config = CONFIG.load(deps.storage)?;
        if info.sender != config.owner {
            return Err(ContractError::BloomDisabled {});
        }

        // get random three digit number
        let rand_bytes = contract_randomness(env.clone());
        let digit1 = (rand_bytes[0] & 0x0F) as u16;
        let digit2 = (rand_bytes[7] & 0x0F) as u16;
        let digit3 = (rand_bytes[10] & 0x0F) as u16;
        let random_number = (digit1 * 100) + (digit2 * 10) + digit3;

        // define map key from random bytes
        let rand_key = utils::weighted_random(random_number as u64);
        let blooms = BLOOMSBLOOMS.add_suffix(rand_key.to_string().as_bytes());

        // grab keys from randomly selected map (addrs that registered ibc-bloom)
        let pending_keys = blooms.paging_keys(deps.storage, 0, 30)?;

        // loop through keys
        for key in pending_keys {
            if let Some(bloom) = blooms.get(deps.storage, &key) {
                let cade = bloom.msg.cadance
                    + config
                        .bloom
                        .clone()
                        .expect("smokin big doinks in amish")
                        .default_cadance;

                if !env.block.height.gt(&(cade + bloom.block_height)) {
                    break;
                };

                let token = bloom.msg.source_token.clone();

                // pop out each granular msg to form snip120u redeem msgs
                let blooms_to_process = bloom.msg.bloom.clone();
                let amnt = min(10, blooms_to_process.len());

                let redeem_msgs = blooms_to_process[..amnt]
                    .iter()
                    .map(|br| {
                        // form redeem msg for this contract to redeem on behalf of bloomer
                        let msg = crate::msg::snip::Redeem {
                            amount: Uint128::from(br.amount),
                            denom: Some(token.clone()),
                            decoys: None,
                            entropy: None,
                            padding: None,
                        };
                        let contract_addr = config
                            .snip120us
                            .iter()
                            .find(|f| f.native_token == token)
                            .map(|f| f.addr.to_string())
                            .unwrap_or_else(|| panic!("No matching contract address found"));

                        // save imment msg to form with owner as map prefix
                        PROCESSING_BLOOM_MEMPOOL
                            .update(deps.storage, |mut a| {
                                a.push(ProcessingBloomMsg {
                                    addr: br.addr.clone(),
                                    amount: br.amount,
                                    token: token.clone(),
                                });
                                Ok(a)
                            })
                            .unwrap();

                        // save granular msgs to imminent mempool
                        CosmosMsg::Wasm(WasmMsg::Execute {
                            contract_addr,
                            msg: to_binary(&msg).unwrap(),
                            funds: vec![],
                            code_hash: config.snip_hash.clone(),
                        })
                    })
                    .collect::<Vec<CosmosMsg>>();

                // push snip120u msgs
                msgs.extend(redeem_msgs);

                // Remove processed blooms from the map
                if amnt == bloom.msg.bloom.len() {
                    blooms.remove(deps.storage, &key).unwrap();
                } else {
                    // Update the blooms map
                    let mut updated_bloom = bloom.clone();
                    updated_bloom.msg.bloom.drain(0..amnt);
                }
            }
        }

        Ok(Response::new().add_messages(msgs))
        // TODO:
        // a. determine which bloom-dwb to load from randomness
        // b. load n # of tx-ids to process
        // c. get tx details for each tx-id to prepare redeem_msg
        // d. save imminent bloom msg to simple map
    }

    pub fn process_ibc_bloom(
        deps: DepsMut,
        env: Env,
        _info: MessageInfo,
    ) -> Result<Response, ContractError> {
        let mut msgs = vec![];

        let rand = (contract_randomness(env.clone())[7] & 0x0f) as u16;

        // load
        PROCESSING_BLOOM_MEMPOOL
            .update(deps.storage, |mut b| {
                let lens = b.len() as u64;
                if lens.lt(&1u64) {
                    return Ok(b);
                }
                let limit = lens.div_ceil(rand.into()).max(5); // TODO: add config to set max tx to process
                let limit = limit as usize;
                let mut drained: Vec<ProcessingBloomMsg> = b.drain(..).collect();
                let unprocessed = drained.split_off(limit);
                drained.iter().for_each(|a| {
                    // form transfer msg
                    let transfer_msg: CosmosMsg<Empty> =
                        CosmosMsg::Bank(cosmwasm_std::BankMsg::Send {
                            to_address: a.addr.clone(),
                            amount: coins(Uint128::from(a.amount).u128(), a.token.clone()),
                        });

                    msgs.push(transfer_msg);
                });
                b.extend(unprocessed);
                Ok(b)
            })
            .unwrap();
        Ok(Response::new().add_messages(msgs))
    }
}

pub mod utils {
    use cosmwasm_std::Decimal;

    use super::*;

    pub fn contract_randomness(env: Env) -> [u8; 32] {
        let mut prng = ContractPrng::from_env(&env);
        let mut random_numbers = vec![0u8; (7 * 32) as usize];
        prng.fill_bytes(&mut random_numbers);
        prng.rand_bytes()
    }

    pub fn random_multiplier(prng: &mut ContractPrng) -> Decimal {
        let mut bonus: Decimal = Decimal::one();
        let mut random_numbers = vec![0u8; (7 * 32) as usize];
        prng.fill_bytes(&mut random_numbers);
        let r = prng.rand_bytes();
        if let Some(x) = r.get(10) {
            if x % 3 == 0 {
                bonus = bonus + Decimal::percent(30) // 1.3x multiplier
            }
        }
        bonus
    }

    pub fn weighted_random(rand: u64) -> u64 {
        if rand < 90 {
            1
        } else if rand < 170 {
            2
        } else if rand < 240 {
            3
        } else if rand < 300 {
            4
        } else if rand < 350 {
            5
        } else if rand < 390 {
            6
        } else if rand < 420 {
            7
        } else if rand < 440 {
            8
        } else if rand < 449 {
            9
        } else {
            10
        }
    }

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

// pub mod ibc {
//     use cosmwasm_std::IbcMsg;

//     use crate::{
//         msg::options::ChannelOpenInitOptions,
//         state::{self, channel::ChannelStatus},
//         types::callbacks::IcaControllerCallbackMsg,
//     };

//     use super::*;
//     /// Submits a stargate `MsgChannelOpenInit` to the chain.
//     /// Can only be called by the contract owner or a whitelisted address.
//     /// Only the contract owner can include the channel open init options.
//     #[allow(clippy::needless_pass_by_value)]
//     pub fn create_channel(
//         deps: DepsMut,
//         env: Env,
//         info: MessageInfo,
//         options: Option<ChannelOpenInitOptions>,
//     ) -> Result<Response, ContractError> {
//         state::assert_owner(deps.storage, info.sender)?;

//         let options = if let Some(new_options) = options {
//             state::CHANNEL_OPEN_INIT_OPTIONS.save(deps.storage, &new_options)?;
//             new_options
//         } else {
//             state::CHANNEL_OPEN_INIT_OPTIONS
//                 .may_load(deps.storage)?
//                 .ok_or(ContractError::NoChannelInitOptions)?
//         };

//         state::ALLOW_CHANNEL_OPEN_INIT.save(deps.storage, &true)?;

//         let ica_channel_open_init_msg = new_ica_channel_open_init_cosmos_msg(
//             env.contract.address.to_string(),
//             options.connection_id,
//             options.counterparty_port_id,
//             options.counterparty_connection_id,
//             options.tx_encoding,
//             options.channel_ordering,
//         );

//         Ok(Response::new().add_message(ica_channel_open_init_msg))
//     }

//     /// Submits a [`IbcMsg::CloseChannel`].
//     #[allow(clippy::needless_pass_by_value)]
//     pub fn close_channel(deps: DepsMut, info: MessageInfo) -> Result<Response, ContractError> {
//         state::assert_owner(deps.storage, info.sender)?;

//         let channel_state = state::CHANNEL_STATE.load(deps.storage)?;
//         if !channel_state.is_open() {
//             return Err(ContractError::InvalidChannelStatus {
//                 expected: ChannelStatus::Open.to_string(),
//                 actual: channel_state.channel_status.to_string(),
//             });
//         }

//         state::ALLOW_CHANNEL_CLOSE_INIT.save(deps.storage, &true)?;

//         let channel_close_msg = CosmosMsg::Ibc(IbcMsg::CloseChannel {
//             channel_id: channel_state.channel.endpoint.channel_id,
//         });

//         Ok(Response::new().add_message(channel_close_msg))
//     }

//     /// Handles ICA controller callback messages.
//     pub fn ica_callback_handler(
//         deps: DepsMut,
//         info: MessageInfo,
//         callback_msg: IcaControllerCallbackMsg,
//     ) -> Result<Response, ContractError> {
//         // if bloom successful, do nothing?
//         // if bloom unsucessful or timeout, use bloomId to save failed bloom to state so owner can reregister tx if desired

//         Ok(Response::default())
//     }
// }

#[cfg(test)]
mod tests {
    use cosmwasm_std::{testing::*, Addr};
    use validation::compute_plaintxt_msg;

    use super::*;

    pub const PLAINTXT: &str = "H.R.E.A.M. Sender: {wallet}";

    #[test]
    fn test_compute_bloom_plaintext_msg() {
        let expected_result = "H.R.E.A.M. Sender: sender123";
        // Create test variables

        let sender = Addr::unchecked("sender123");
        let secondary_address = "secondary123".to_string();

        assert_eq!(
            compute_plaintxt_msg(PLAINTXT.to_string(), sender.clone()),
            expected_result.to_string()
        );

        let err = compute_plaintxt_msg(PLAINTXT.to_string(), Addr::unchecked(secondary_address));

        assert_ne!(err, expected_result.to_string());
    }

    #[cfg(test)]
    mod test {
        use crate::state::{
            bloom::BloomConfig,
            snip::{Snip, Snip120u},
            HEADSTASH_OWNERS,
        };

        use super::*;
        use base64::{engine::general_purpose, Engine};
        use cosmwasm_std::{OwnedDeps, Uint128};

        fn init_helper() -> (
            StdResult<Response>,
            OwnedDeps<MockStorage, MockApi, MockQuerier>,
        ) {
            let mut deps = mock_dependencies_with_balance(&[]);
            let env = mock_env();
            let info = mock_info("instantiator", &[]);

            // todo: setup snip120u
            let fist_eligible_snip = Snip120u {
                native_token: "snip1".into(),
                addr: Addr::unchecked("snip1Addr"),
                total_amount: Uint128::new(420u128),
            };
            let second_eligible_snip = Snip120u {
                native_token: "snip2".into(),
                addr: Addr::unchecked("snip2Addr"),
                total_amount: Uint128::new(710u128),
            };

            let init_msg = crate::msg::InstantiateMsg {
                owner: Addr::unchecked("admin"),
                claim_msg_plaintext: PLAINTXT.to_string(),
                start_date: None,
                end_date: None,
                // snip120u_code_id: 2,
                snip120u_code_hash: "HASH".into(),
                snips: vec![fist_eligible_snip, second_eligible_snip],
                viewing_key: "viewing_key".into(),
                bloom_config: Some(BloomConfig {
                    default_cadance: 5u64,
                    min_cadance: 0u64,
                    max_granularity: 5u64,
                }),
                multiplier: true,
                // channel_open_init_options: None,
            };

            (instantiate(deps.as_mut(), env, info, init_msg), deps)
        }

        // Init test

        #[test]
        fn test_init_sanity() {
            let (init_result, deps) = init_helper();
            assert_eq!(init_result.unwrap(), Response::default());
            let env = mock_env();

            let constants = CONFIG.load(&deps.storage).unwrap();
            assert_eq!(constants.owner.as_str(), "instantiator");
            assert_eq!(constants.claim_msg_plaintext.as_str(), PLAINTXT);
            assert_eq!(
                constants.bloom,
                Some(BloomConfig {
                    default_cadance: 5u64,
                    min_cadance: 0u64,
                    max_granularity: 5u64,
                })
            );
            assert_eq!(constants.end_date, None);
            assert_eq!(constants.start_date, env.block.time.seconds());
            assert_eq!(
                constants.snip120us,
                vec![
                    Snip120u {
                        native_token: "snip1".into(),
                        addr: Addr::unchecked("snip1Addr"),
                        total_amount: Uint128::new(420u128)
                    },
                    Snip120u {
                        native_token: "snip2".into(),
                        addr: Addr::unchecked("snip2Addr"),
                        total_amount: Uint128::new(710u128)
                    }
                ]
            );
            assert_eq!(constants.snip_hash.as_str(), "HASH");
            assert_eq!(constants.viewing_key.as_str(), "viewing_key");
        }

        #[test]
        fn test_init_instanity() {}

        // Handle test
        #[test]
        fn test_headstash_workflow() {
            let (init_result, mut deps) = init_helper();

            assert!(
                init_result.is_ok(),
                "Init failed: {}",
                init_result.err().unwrap()
            );

            // ADD ELIGIBLE ADDRS
            let handle_msg = ExecuteMsg::AddEligibleHeadStash {
                headstash: vec![
                    Headstash {
                        addr: "0xF20B72c0d3992F53D0b28a190D060B6b999d861D".into(),
                        snips: vec![Snip {
                            amount: 100u128.into(),
                            contract: "snip1Addr".into(),
                        }],
                    },
                    Headstash {
                        addr: "vzRrBXAlQ8SJN33bcrzG7biwCMVW3iAOGqj4ekA7EsE=".into(),
                        snips: vec![Snip {
                            amount: 300u128.into(),
                            contract: "snip1Addr".into(),
                        }],
                    },
                    Headstash {
                        addr: "0x5c49a098BFe24cCEA4Aa66ac0416fD3F831Cd007".into(),
                        snips: vec![
                            Snip {
                                amount: 200u128.into(),
                                contract: "snip1Addr".into(),
                            },
                            Snip {
                                amount: 200u128.into(),
                                contract: "snip2Addr".into(),
                            },
                        ],
                    },
                ],
            };
            let info = mock_info("instantiator", &[]);
            let mut env = mock_env();
            env.block.random = Some(Binary::from(&[0u8; 32]));
            let handle_result = execute(deps.as_mut(), env, info, handle_msg);
            handle_result.unwrap();

            // assert eligible map is accurate
            let hs1 = HEADSTASH_OWNERS
                .add_suffix("0xF20B72c0d3992F53D0b28a190D060B6b999d861D".as_bytes())
                .add_suffix("snip1Addr".as_bytes())
                .load(&deps.storage)
                .unwrap();
            let hs2 = HEADSTASH_OWNERS
                .add_suffix("0x5c49a098BFe24cCEA4Aa66ac0416fD3F831Cd007".as_bytes())
                .add_suffix("snip1Addr".as_bytes())
                .load(&deps.storage)
                .unwrap();
            let hs2_1 = HEADSTASH_OWNERS
                .add_suffix("0x5c49a098BFe24cCEA4Aa66ac0416fD3F831Cd007".as_bytes())
                .add_suffix("snip2Addr".as_bytes())
                .load(&deps.storage)
                .unwrap();

            assert_eq!(hs1.u128(), 100u128);
            assert_eq!(hs2.u128(), 200u128);
            assert_eq!(hs2_1.u128(), 200u128);

            // CLAIMING HEADSTASH

            // hs1
            let hs1_claim_msg = ExecuteMsg::Claim {
                sig_addr: "0xF20B72c0d3992F53D0b28a190D060B6b999d861D".into(),
                sig: "e96dfa73bee55043a003440f3a4c2cc04a7bff6ef757539fa58c8d6ffc5ff60d3bd573d05ca10cea57e870c82c1fd40090f08eac9bdc3cfb241f6dd983338ac01c".into(),
            };
            let info = mock_info("hs1", &[]);
            let mut env = mock_env();
            env.block.random = Some(Binary::from(&[0u8; 32]));
            let handle_result = execute(
                deps.as_mut(),
                env.clone(),
                info.clone(),
                hs1_claim_msg.clone(),
            )
            .unwrap();
            assert_eq!(handle_result.messages.len(), 1);

            // ensure cannot be claimed twice
            let info = mock_info("hs1", &[]);
            let bad_claim = execute(
                deps.as_mut(),
                env.clone(),
                info.clone(),
                hs1_claim_msg.clone(),
            );
            bad_claim.expect_err("You have already claimed your headstash, homie");

            // hs2
            let hs2_claim_msg = ExecuteMsg::Claim {
                sig_addr: "0x5c49a098BFe24cCEA4Aa66ac0416fD3F831Cd007".into(),
                sig: "5e5c99e5f361b2c01f7622478f393612ee95faf22c80a3935aed75ecbf22c43d1e2c6fc9e4cb7106d6e16fb5d2a861b6f7fedfc9cdea3fb776a3bdae50c393aa1c".into(),
            };

            // try to claim with someone elses signature
            let env = mock_env();
            let info = mock_info("hs1", &[]);
            let stolen_signature_claim =
                execute(deps.as_mut(), env.clone(), info, hs2_claim_msg.clone());

            stolen_signature_claim.expect_err("cannot validate eth_sig.");

            // ensure all tokens that are eligible are minted
            let new_info = mock_info("hs2", &[]);
            let handle_result = execute(
                deps.as_mut(),
                env.clone(),
                new_info.clone(),
                hs2_claim_msg.clone(),
            )
            .unwrap();
            assert_eq!(handle_result.messages.len(), 2);
            // hs3
            let hs3_claim_msg = ExecuteMsg::Claim {
                sig_addr: "vzRrBXAlQ8SJN33bcrzG7biwCMVW3iAOGqj4ekA7EsE=".into(),
                sig: "bEcF5BOHG0zKvdr02Xy+ZlMyGEkHQR5TweMEWC6pfo+XzdvL5F6az9EZ8ErDh0czYRWluMunKuRveF7N4RDxBw==".into(),
            };
            let new_info = mock_info("hs3", &[]);
            let handle_result =
                execute(deps.as_mut(), env, new_info.clone(), hs3_claim_msg.clone()).unwrap();

            println!("{:#?}", handle_result);
        }

        #[test]
        fn test_claim_headstash_dwb() {

            // assert eligible addr can claim
            // assert cannot claim more than eligilbe
        }

        #[test]
        fn test_register_bloom() {}

        #[test]
        fn test_process_bloom() {}

        #[test]
        fn test_randomness() {
            let mut env = mock_env();

            // get first randomness value
            let mut prng = ContractPrng::from_env(&env.clone());
            let rand1 = prng.rand_bytes();
            let result = general_purpose::STANDARD.encode(rand1.repeat(3).clone());
            let dec1 = self::utils::random_multiplier(&mut prng);

            // simulate new randomness seed from environment1
            env.block.random = Some(Binary::from_base64(&result).unwrap());

            // get second randomness value, should be different with new seed
            prng = ContractPrng::from_env(&env.clone());
            let rand2 = prng.rand_bytes();

            let dec2 = self::utils::random_multiplier(&mut prng);
            // assert not equal
            assert_ne!(rand1, rand2);
            assert_ne!(dec1, dec2);
        }
    }
}

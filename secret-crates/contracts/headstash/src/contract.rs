use crate::error::ContractError;
use crate::msg::{ExecuteMsg, InstantiateMsg, MigrateMsg, QueryAnswer, QueryMsg};
use crate::state::{Config, Headstash, CONFIG, PROCESSING_BLOOM_MEMPOOL, SNIP_COUNT};

#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;

use cosmwasm_std::{
    to_binary, Binary, CosmosMsg, Deps, DepsMut, Env, MessageInfo, Reply, Response, StdError,
    StdResult, Uint128,
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
    if msg.snips.len() == 0 {
        return Err(StdError::generic_err("must provide atleast 1 snip120u"));
    }
    for snip in msg.snips.clone() {
        if unique_snips
            .iter()
            .any(|a| a.native_token == snip.native_token || a.addr == snip.addr)
        {
            return Err(StdError::generic_err(
                ContractError::DuplicateSnip120u {}.to_string(),
            ));
        }
        SNIP_COUNT
            .add_suffix(snip.addr.as_bytes())
            .save(deps.storage, &Uint128::zero())?;
        unique_snips.push(snip);
    }

    if msg.bloom_config.is_some() {
        PROCESSING_BLOOM_MEMPOOL.save(deps.storage, &vec![])?;
    };

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
        ExecuteMsg::RegisterBloom { bloom_msg } => {
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

    use cosmwasm_std::Uint128;

    use super::*;
    use crate::state::{
        snip::{AllowanceAction, Snip120u},
        HeadstashSig, CLAIMED_HEADSTASH, DECAY_CLAIMED, HEADSTASH_OWNERS, HEADSTASH_SIGS,
        SNIP_COUNT, TOTAL_CLAIMED,
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
            return Err(ContractError::OwnershipError());
        }
        // make sure airdrop has not ended
        queries::available(&config, &env)?;
        // randomly select point in headstash array to start from.
        let hsl = headstash.len();

        let rsp = utils::random_starting_point(rng, hsl.clone());
        // println!("hsl: {:#?}", hsl);
        // println!("rsp: {:#?}", rsp);
        
        add_headstash_to_state(deps, hsl, rsp, headstash.clone(), config.snip120us)?;
        
        Ok(Response::default())
    }
    
    pub fn add_headstash_to_state(
        deps: DepsMut,
        hsl: usize,
        rsp: usize,
        headstash: Vec<Headstash>,
        eligible: Vec<Snip120u>,
    ) -> StdResult<()> {
        // ensure pubkey is not already in KeyMap
        for i in 0..hsl {
            let hs: Headstash = headstash[(i + rsp) % hsl].clone();
            // println!("headstash: {:#?},{:#?}", i, hs.clone());
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
                    // match current snip with one in eligible to get the total_amount
                    let matching_snip = eligible
                        .iter()
                        .find(|es| es.addr.to_string() == snip.contract)
                        .ok_or_else(|| StdError::generic_err("No matching snip found"))?;

                    SNIP_COUNT
                        .add_suffix(snip.contract.as_bytes())
                        .update(deps.storage, |a| {
                            // ensure the expected total amount is not exceeded
                            let na = a + snip.amount;
                            if na > matching_snip.total_amount {
                                return Err(StdError::generic_err("Total amount exceeded"));
                            }
                            Ok(na)
                        })?;

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
            )?;
        }

        for snip in config.snip120us {
            // check if address has already claimed. This occurs after sig is verified, preventing leakage of claim status for a key.
            let pf = CLAIMED_HEADSTASH
                .add_suffix(snip.addr.as_bytes())
                .add_suffix(sig_addr.as_bytes());
            if pf.may_load(deps.storage)?.is_some() {
                return Err(ContractError::AlreadyClaimed {});
            }
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

                // update total claimed for specific snip120u
                let tc = TOTAL_CLAIMED.add_suffix(snip.addr.as_str().as_bytes());
                tc.save(deps.storage, &Uint128::zero())?;

                // set signature addr claimed state for snip120u
                CLAIMED_HEADSTASH
                    .add_suffix(snip.addr.as_bytes())
                    .add_suffix(sig_addr.as_bytes())
                    .save(deps.storage, &headstash_amount)?;

                // set signature for snip with sender as key
                let hs = HEADSTASH_SIGS
                    .add_suffix(snip.addr.as_bytes())
                    .add_suffix(info.sender.as_str().as_bytes());
                hs.save(
                    deps.storage,
                    &HeadstashSig {
                        addr: sig_addr.clone(),
                        sig: sig.clone(),
                    },
                )?;
            }
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
        eth: bool,
    ) -> Result<(), StdError> {
        match eth {
            // source: https://github.com/SecretSaturn/SecretPath/blob/aae6c61ff755aa22112945eab308e9037044980b/TNLS-Gateways/secret/src/msg.rs#L109
            false => {
                let computed_plaintxt = compute_plaintxt_msg(plaintxt, sender);
                let signature = Binary::from_base64(&sig)?;
                let signer = Binary::from_base64(&signer)?;

                // match api.secp256k1_verify(
                //     computed_plaintxt.clone().into_bytes().as_slice(),
                //     Binary::from_base64(&sig)?.as_slice(),
                //     signer.clone().as_slice(),
                // ) {
                // Ok(true) => Ok(()),
                // Ok(false) | Err(_) =>
                api.ed25519_verify(
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
                })?;
                // }
                Ok(())
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
        let plaintext_msg = str::replace(&claim_plaintxt, "{wallet}", sender.as_ref());
        plaintext_msg
    }
}

pub mod ibc_bloom {
    use std::cmp::min;

    use super::*;

    use cosmwasm_std::{coins, DepsMut, Empty, StdError, Storage, Uint128, WasmMsg};
    use utils::contract_randomness;

    use crate::state::{
        bloom::{BloomMsg, ProcessingBloomMsg, StoredBlooms},
        CLAIMED_HEADSTASH, HEADSTASH_SIGS, PROCESSING_BLOOM_MEMPOOL, STORED_BLOOMS,
    };

    // ensure total being bloomed is not more than what addr was eligible for
    pub fn validate_bloom(
        storage: &mut dyn Storage,
        snip_addr: String,
        sig_addr: String,
        bloom_total: Uint128,
    ) -> Result<(), StdError> {
        CLAIMED_HEADSTASH
            .add_suffix(snip_addr.as_bytes())
            .add_suffix(sig_addr.as_bytes())
            .update(storage, |a| {
                if a < bloom_total {
                    return Err(StdError::generic_err(
                        "You are trying to bloom more than eligible for this snip120u",
                    ));
                } else {
                    let new = a - bloom_total;
                    Ok(new)
                }
            })?;
        Ok(())
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

    /// 1. register a bloom msg to be processed
    pub fn try_ibc_bloom(
        deps: DepsMut,
        env: Env,
        info: MessageInfo,
        // rng: ContractPrng,
        // addr: String,
        msg: BloomMsg,
    ) -> Result<Response, ContractError> {
        let config = CONFIG.load(deps.storage)?;
        if config.bloom.is_none() {
            return Err(ContractError::BloomDisabled {});
        }

        // verify sender is able to bloom
        let hs = HEADSTASH_SIGS
            .add_suffix(msg.snip120u_addr.as_bytes())
            .add_suffix(info.sender.as_str().as_bytes());

        if let Some(sig) = hs.may_load(deps.storage)? {
            let lens = msg.blooms.len() as u64;
            if lens.gt(&config.bloom.expect("bloom not setup").max_granularity) {
                return Err(ContractError::BloomTooManyGrains {});
            } else if lens == 0u64 {
                return Err(ContractError::BloomNotEnoughGrains {});
            }
            // ensure batch amount <= bloom len
            if msg.batch_amnt > lens || msg.batch_amnt == 0 {
                return Err(ContractError::InvalidBatchAmount {});
            }

            // ensure bloom_msg.total = sum of all amounts in granular msgs
            let total: u64 = msg.blooms.iter().map(|bloom| bloom.amount).sum();
            if Uint128::from(total) != msg.total {
                return Err(ContractError::BloomTotalError {});
            }

            let key = msg.entropy_key.clamp(1, 10) as u64;

            // add default cadance to user defined cadance
            let cadance = match msg.cadance > 0u64 {
                true => config.bloom.unwrap().default_cadance + msg.cadance,
                false => config.bloom.unwrap().min_cadance,
            };

            // set bloomMsg keyMap key as (b' + entropy_ratio + sender)
            let blooms = STORED_BLOOMS.add_suffix(key.to_string().as_bytes());
            if let Some(bloom) = blooms.get(deps.storage, &info.sender.to_string()) {
                // cannot register bloom twice
                if bloom.msg.snip120u_addr == msg.snip120u_addr {
                    return Err(ContractError::BloomDuplicate {});
                }
                validate_bloom(
                    deps.storage,
                    msg.snip120u_addr.clone(),
                    sig.addr,
                    bloom.msg.total,
                )?;
                blooms.insert(
                    deps.storage,
                    &info.sender.to_string(),
                    &StoredBlooms {
                        block_height: env.block.height,
                        msg: BloomMsg {
                            total: msg.total,
                            snip120u_addr: msg.snip120u_addr,
                            cadance,
                            entropy_key: key,
                            blooms: msg.blooms,
                            batch_amnt: msg.batch_amnt,
                            owner: info.sender.to_string(),
                        },
                    },
                )?;
            } else {
                validate_bloom(deps.storage, msg.snip120u_addr.clone(), sig.addr, msg.total)?;
                blooms.insert(
                    deps.storage,
                    &info.sender.to_string(),
                    &StoredBlooms {
                        block_height: env.block.height,
                        msg: BloomMsg {
                            total: msg.total,
                            snip120u_addr: msg.snip120u_addr,
                            cadance,
                            entropy_key: key,
                            blooms: msg.blooms,
                            batch_amnt: msg.batch_amnt,
                            owner: info.sender.to_string(),
                        },
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
    }

    // 2. Randomly select mempool to prepare for bloom. Redeems tokens on behalf of owners.
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
        let digit1 = (rand_bytes[1] % 10) as u16;
        let digit2 = (rand_bytes[7] & 0x0F) as u16;
        let digit3 = (rand_bytes[10] & 0x0F) as u16;
        let random_number = (digit1 * 100) + (digit2 * 10) + digit3;

        // define map key from random bytes
        let rand_key = utils::weighted_random(random_number as u64);
        let blooms = STORED_BLOOMS.add_suffix(rand_key.to_string().as_bytes());

        // grab keys from randomly selected map (addrs that registered ibc-bloom)
        let pending_keys = blooms.paging_keys(deps.storage, 0, 30)?;

        // loop through keys
        for key in pending_keys {
            if let Some(bloom) = blooms.get(deps.storage, &key) {
                let cade = bloom.msg.cadance;

                if !env.block.height.gt(&(cade + bloom.block_height)) {
                    break;
                };

                let token_addr = bloom.msg.snip120u_addr.clone();

                // pop out each granular msg to form snip120u redeem msgs
                let blooms_to_process = bloom.msg.blooms.clone();
                let amnt = min(
                    blooms_to_process.len(),
                    bloom.msg.batch_amnt.try_into().unwrap(),
                );

                let redeem_msgs = blooms_to_process[..amnt]
                    .iter()
                    .map(|br| {
                        let bloom_asset = config
                            .snip120us
                            .iter()
                            .find(|f| f.addr == token_addr)
                            .map(|f| f)
                            .unwrap_or_else(|| panic!("No matching contract address found"));
                        // form redeem msg for this contract to redeem on behalf of bloomer
                        let msg = crate::msg::snip::ExecuteMsg::RedeemFrom {
                            amount: Uint128::from(br.amount),
                            denom: Some(bloom_asset.native_token.clone()),
                            decoys: None,
                            entropy: None,
                            padding: None,
                            owner: bloom.msg.owner.clone(),
                        };

                        // save imment msg to form with owner as map prefix
                        PROCESSING_BLOOM_MEMPOOL
                            .update(deps.storage, |mut a| {
                                a.push(ProcessingBloomMsg {
                                    recipient_addr: br.addr.clone(),
                                    amount: br.amount,
                                    token: bloom_asset.native_token.clone(),
                                });
                                Ok(a)
                            })
                            .unwrap();

                        // save granular msgs to imminent mempool
                        CosmosMsg::Wasm(WasmMsg::Execute {
                            contract_addr: bloom_asset.addr.to_string(),
                            msg: to_binary(&msg).unwrap(),
                            funds: vec![],
                            code_hash: config.snip_hash.clone(),
                        })
                    })
                    .collect::<Vec<CosmosMsg>>();

                // push snip120u msgs
                msgs.extend(redeem_msgs);

                // Remove processed blooms from the map
                if amnt == bloom.msg.blooms.len() {
                    blooms.remove(deps.storage, &key).unwrap();
                } else {
                    // Update the blooms map
                    let mut updated_bloom = bloom.clone();
                    updated_bloom.msg.blooms.drain(0..amnt);
                }
            }
        }

        Ok(Response::new().add_messages(msgs))
    }

    pub fn process_ibc_bloom(
        deps: DepsMut,
        _env: Env,
        _info: MessageInfo,
    ) -> Result<Response, ContractError> {
        let mut msgs = vec![];

        // load
        PROCESSING_BLOOM_MEMPOOL
            .update(deps.storage, |mut b| {
                let lens = b.len() as u64;
                if lens.lt(&1u64) {
                    return Ok(b);
                }

                let max = 5;
                let mut processed = 0;
                while processed < max && !b.is_empty() {
                    let a = b.pop().unwrap(); // remove the last item from the array

                    // form transfer msg
                    let transfer_msg: CosmosMsg<Empty> =
                        CosmosMsg::Bank(cosmwasm_std::BankMsg::Send {
                            to_address: a.recipient_addr.clone(),
                            amount: coins(Uint128::from(a.amount).u128(), a.token.clone()),
                        });

                    // attempt to push transfer_msg
                    msgs.push(transfer_msg);
                    processed += 1;
                }

                Ok(b)
            })
            .unwrap();
        Ok(Response::new().add_messages(msgs))
    }
}

pub mod utils {
    use cosmwasm_std::Decimal;

    use super::*;

    pub fn random_starting_point(prng: &mut ContractPrng, lens: usize) -> usize {
        let mut random_number = [0u8; 8]; // Use 8 bytes to represent a usize
        prng.fill_bytes(&mut random_number);
        let random_usize = usize::from_le_bytes(random_number);
        random_usize % lens
    }

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
            bloom::{BloomConfig, BloomMsg, BloomRecipient},
            snip::{Snip, Snip120u},
            HEADSTASH_OWNERS, STORED_BLOOMS,
        };

        use super::*;
        use base64::{engine::general_purpose, Engine};
        use cosmwasm_std::{coin, BankMsg, OwnedDeps, Uint128};

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
            let info = mock_info("instantiator", &[]);
            let mut env = mock_env();
            env.block.random = Some(Binary::from(&[0u8; 32]));
            let constants = CONFIG.load(&deps.storage).unwrap();

            assert!(
                init_result.is_ok(),
                "Init failed: {}",
                init_result.err().unwrap()
            );

            // ADD ELIGIBLE ADDRS
            let handle_msg = ExecuteMsg::AddEligibleHeadStash {
                headstash: vec![
                    Headstash {
                        addr: "0xF20B72c0d3992F53D0b28a190D060B6b999d861D".into(), // hs1
                        snips: vec![Snip {
                            amount: 100u128.into(),
                            contract: "snip1Addr".into(),
                        }],
                    },
                    Headstash {
                        addr: "vzRrBXAlQ8SJN33bcrzG7biwCMVW3iAOGqj4ekA7EsE=".into(), // hs2
                        snips: vec![Snip {
                            amount: 300u128.into(),
                            contract: "snip1Addr".into(),
                        }],
                    },
                    Headstash {
                        addr: "0x5c49a098BFe24cCEA4Aa66ac0416fD3F831Cd007".into(), // hs3
                        snips: vec![
                            Snip {
                                amount: 20u128.into(),
                                contract: "snip1Addr".into(),
                            },
                            Snip {
                                amount: 200u128.into(),
                                contract: "snip2Addr".into(),
                            },
                        ],
                    },
                    Headstash {
                        addr: "0xdf303dc89E6d4A6122fa2889CCBE923236635b68=".into(), // hs5
                        snips: vec![Snip {
                            amount: 100u128.into(),
                            contract: "snip2Addr".into(),
                        }],
                    },
                ],
            };

            let handle_result = execute(deps.as_mut(), env.clone(), info.clone(), handle_msg);
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
            assert_eq!(hs2.u128(), 20u128);
            assert_eq!(hs2_1.u128(), 200u128);

            // try to add duplicate addr
            let handle_msg = ExecuteMsg::AddEligibleHeadStash {
                headstash: vec![Headstash {
                    addr: "0xF20B72c0d3992F53D0b28a190D060B6b999d861D".into(),
                    snips: vec![Snip {
                        amount: 100u128.into(),
                        contract: "snip1Addr".into(),
                    }],
                }],
            };
            let handle_result = execute(deps.as_mut(), env.clone(), info.clone(), handle_msg);
            handle_result.expect_err("pubkey already has been added, not adding again");

            // try to add more than total expected for a snip
            let bad_msg = ExecuteMsg::AddEligibleHeadStash {
                headstash: vec![Headstash {
                    addr: "0x3498E3F526fD2B482c1DbDC08D1330ebd07Bc178".into(),
                    snips: vec![Snip {
                        amount: 400u128.into(),
                        contract: "snip1Addr".into(),
                    }],
                }],
            };
            let handle_result = execute(deps.as_mut(), env.clone(), info, bad_msg).unwrap_err();
            assert_eq!(
                handle_result,
                ContractError::Std(StdError::generic_err("Total amount exceeded"))
            );

            // CLAIMING HEADSTASH

            // hs1
            let hs1_claim_msg = ExecuteMsg::Claim {
                sig_addr: "0xF20B72c0d3992F53D0b28a190D060B6b999d861D".into(),
                sig: "e96dfa73bee55043a003440f3a4c2cc04a7bff6ef757539fa58c8d6ffc5ff60d3bd573d05ca10cea57e870c82c1fd40090f08eac9bdc3cfb241f6dd983338ac01c".into(),
            };
            let info = mock_info("hs1", &[]);
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
            let hs1 = mock_info("hs1", &[]);
            let stolen_signature_claim = execute(
                deps.as_mut(),
                env.clone(),
                hs1.clone(),
                hs2_claim_msg.clone(),
            );

            assert_eq!(
                stolen_signature_claim.unwrap_err(),
                ContractError::Std(StdError::generic_err("cannot validate offline_sig"))
            );

            // ensure all tokens that are eligible are minted
            let hs2 = mock_info("hs2", &[]);
            let handle_result = execute(
                deps.as_mut(),
                env.clone(),
                hs2.clone(),
                hs2_claim_msg.clone(),
            )
            .unwrap();
            assert_eq!(handle_result.messages.len(), 2);

            // claim with solana wallet (addr & signature is base64 encoded)
            let hs3_claim_msg = ExecuteMsg::Claim {
                sig_addr: "vzRrBXAlQ8SJN33bcrzG7biwCMVW3iAOGqj4ekA7EsE=".into(),
                sig: "bEcF5BOHG0zKvdr02Xy+ZlMyGEkHQR5TweMEWC6pfo+XzdvL5F6az9EZ8ErDh0czYRWluMunKuRveF7N4RDxBw==".into(),
            };

            let hs3 = mock_info("hs3", &[]);
            let handle_result = execute(
                deps.as_mut(),
                env.clone(),
                hs3.clone(),
                hs3_claim_msg.clone(),
            )
            .unwrap();

            assert_eq!(handle_result.messages.len(), 1);

            // cannot claim if not eligible
            let hs69_claim_msg = ExecuteMsg::Claim {
                sig_addr: "0x5f4E77f85212c99Ca4f444663452Fb0bccA3c559".into(),
                sig: "b372207341055a5ddb337b99900466d42b3fc779157dc8004fa3dff71a4d6d647e69323998e9e8ea5bc78f55fcd381ebf145af5364dac4ddf9ba8ddd8a770c9d1c".into(),
            };
            let hs69 = mock_info("hs69", &[]);
            let res = execute(
                deps.as_mut(),
                env.clone(),
                hs69.clone(),
                hs69_claim_msg.clone(),
            )
            .unwrap();
            assert_eq!(res.messages.len(), 0);

            // REGISTER BLOOMS
            let hs5 = mock_info("hs5", &[]);
            // someone who is eligible but has not claimed yet cannot register
            let hs5_register_bloom = ExecuteMsg::RegisterBloom {
                bloom_msg: BloomMsg {
                    total: 99u128.into(),
                    snip120u_addr: "snip2Addr".into(),
                    cadance: 2u64,
                    entropy_key: 10u64,
                    blooms: vec![BloomRecipient {
                        addr: "privateAddr1".into(),
                        amount: 99u64,
                    }],
                    batch_amnt: 1,
                    owner: hs5.sender.to_string(),
                },
            };

            let err = execute(
                deps.as_mut(),
                env.clone(),
                hs5.clone(),
                hs5_register_bloom.clone(),
            )
            .unwrap_err();
            assert_eq!(err, ContractError::BloomNotFound {});

            // someone who is not eligible cannot register
            let hs6 = mock_info("hs6", &[]);
            let hs6_register_bloom = ExecuteMsg::RegisterBloom {
                bloom_msg: BloomMsg {
                    total: 121u128.into(),
                    snip120u_addr: "snip2Addr".into(),
                    cadance: 2u64,
                    entropy_key: 10u64,
                    blooms: vec![BloomRecipient {
                        addr: "privateAddr1".into(),
                        amount: 121u64,
                    }],
                    batch_amnt: 1,
                    owner: hs6.sender.to_string(),
                },
            };
            let err = execute(
                deps.as_mut(),
                env.clone(),
                hs6.clone(),
                hs6_register_bloom.clone(),
            )
            .unwrap_err();
            assert_eq!(err, ContractError::BloomNotFound {});
            // cannot register bloom with total more than allowance

            // cannot register bloom with non-eligible snip120u
            let hs1_register_bloom = ExecuteMsg::RegisterBloom {
                bloom_msg: BloomMsg {
                    total: 123u128.into(),
                    snip120u_addr: "snip666Addr".into(),
                    cadance: 2u64,
                    entropy_key: 0u64,
                    blooms: vec![BloomRecipient {
                        addr: "privateAddr1".into(),
                        amount: 123u64,
                    }],
                    batch_amnt: 1,
                    owner: hs1.sender.to_string(),
                },
            };
            let hs1 = mock_info("hs1", &[]);
            let err = execute(
                deps.as_mut(),
                env.clone(),
                hs1.clone(),
                hs1_register_bloom.clone(),
            )
            .unwrap_err();
            assert_eq!(err, ContractError::BloomNotFound {});

            // needs atleast 1 granular bloom msg in vec to register
            let hs1_register_bloom = ExecuteMsg::RegisterBloom {
                bloom_msg: BloomMsg {
                    total: 101u128.into(),
                    snip120u_addr: "snip1Addr".into(),
                    cadance: 2u64,
                    entropy_key: 0u64,
                    blooms: vec![],
                    batch_amnt: 1,
                    owner: hs1.sender.to_string(),
                },
            };
            let err = execute(
                deps.as_mut(),
                env.clone(),
                hs1.clone(),
                hs1_register_bloom.clone(),
            )
            .unwrap_err();
            assert_eq!(err, ContractError::BloomNotEnoughGrains {});

            // sum of granular bloom msgs cannot be more than total
            let hs1_register_bloom = ExecuteMsg::RegisterBloom {
                bloom_msg: BloomMsg {
                    total: 41u128.into(),
                    snip120u_addr: "snip1Addr".into(),
                    cadance: 2u64,
                    entropy_key: 0u64,
                    blooms: vec![
                        BloomRecipient {
                            addr: "privateAddr1".into(),
                            amount: 19u64,
                        },
                        BloomRecipient {
                            addr: "privateAddr2".into(),
                            amount: 61u64,
                        },
                    ],
                    batch_amnt: 2,
                    owner: hs1.sender.to_string(),
                },
            };
            let err = execute(
                deps.as_mut(),
                env.clone(),
                hs1.clone(),
                hs1_register_bloom.clone(),
            )
            .unwrap_err();
            assert_eq!(err, ContractError::BloomTotalError {});

            // sum of granular bloom msgs must equal total
            let hs1_register_bloom = ExecuteMsg::RegisterBloom {
                bloom_msg: BloomMsg {
                    total: 35u128.into(),
                    snip120u_addr: "snip1Addr".into(),
                    cadance: 2u64,
                    entropy_key: 0u64,
                    blooms: vec![BloomRecipient {
                        addr: "privateAddr1".into(),
                        amount: 34u64,
                    }],
                    batch_amnt: 1,
                    owner: hs1.sender.to_string(),
                },
            };
            let err = execute(
                deps.as_mut(),
                env.clone(),
                hs1.clone(),
                hs1_register_bloom.clone(),
            )
            .unwrap_err();
            assert_eq!(err, ContractError::BloomTotalError {});

            // cannot register for more blooms than eligible for
            let hs2 = mock_info("hs2", &[]);
            let hs2_register_bloom = ExecuteMsg::RegisterBloom {
                bloom_msg: BloomMsg {
                    total: 400u128.into(),
                    snip120u_addr: "snip1Addr".into(),
                    cadance: 2u64,
                    entropy_key: 0u64,
                    blooms: vec![
                        BloomRecipient {
                            addr: "privateAddr1".into(),
                            amount: 300u64,
                        },
                        BloomRecipient {
                            addr: "privateAddr2".into(),
                            amount: 100u64,
                        },
                    ],
                    batch_amnt: 2,
                    owner: hs2.sender.to_string(),
                },
            };

            let err = execute(
                deps.as_mut(),
                env.clone(),
                hs2.clone(),
                hs2_register_bloom.clone(),
            )
            .unwrap_err();
            assert_eq!(
                err,
                ContractError::Std(StdError::generic_err(
                    "You are trying to bloom more than eligible for this snip120u"
                ))
            );

            // someone who has claimed can register
            let hs1_register_bloom = ExecuteMsg::RegisterBloom {
                bloom_msg: BloomMsg {
                    total: 100u128.into(),
                    snip120u_addr: "snip1Addr".into(),
                    cadance: 2u64,
                    entropy_key: 10u64,
                    blooms: vec![
                        BloomRecipient {
                            addr: "privateAddr1".into(),
                            amount: 70u64,
                        },
                        BloomRecipient {
                            addr: "privateAddr2".into(),
                            amount: 30u64,
                        },
                    ],
                    batch_amnt: 1,
                    owner: hs1.sender.to_string(),
                },
            };
            let hs1 = mock_info("hs1", &[]);
            execute(
                deps.as_mut(),
                env.clone(),
                hs1.clone(),
                hs1_register_bloom.clone(),
            )
            .unwrap();

            // cannot set entropy key out of range

            // confirm blooms were set inside the correct mempool
            let blooms = STORED_BLOOMS
                .add_suffix(10u64.to_string().as_bytes())
                .get(&deps.storage, &"hs1".to_string());

            assert!(blooms.is_some());
            let bloom = blooms.unwrap();
            assert_eq!(bloom.block_height, 12345u64);
            assert_eq!(bloom.msg.total, Uint128::new(100u128));
            assert_eq!(
                bloom.msg.cadance,
                constants.bloom.unwrap().default_cadance + 2u64
            );
            assert_eq!(bloom.msg.entropy_key, 10u64);
            assert_eq!(bloom.msg.blooms.len(), 2);

            // someone who has claimed and registered cannot register again
            let res = execute(
                deps.as_mut(),
                env.clone(),
                hs1.clone(),
                hs1_register_bloom.clone(),
            )
            .unwrap_err();

            assert_eq!(res, ContractError::BloomDuplicate {});

            // PREPARE BLOOMS
            let prepare_msg = ExecuteMsg::PrepareBloom {};

            // only specific addr can process blooms
            let not_owner = mock_info("walt", &[]);
            let mut env = mock_env();
            env.block.random = Some(Binary::from(
                hex::decode("12389a43644363633442525252595627890abcde7f").unwrap(),
            ));
            // skip processing pending key (key = 10) due to cadance
            let res = execute(
                deps.as_mut(),
                env.clone(),
                not_owner.clone(),
                prepare_msg.clone(),
            )
            .unwrap_err();
            assert_eq!(res, ContractError::BloomDisabled {});

            // prepare bloom
            let owner = mock_info("instantiator", &[]);
            let prepare_msg = ExecuteMsg::PrepareBloom {};
            let mut env = mock_env();
            env.block.random = Some(Binary::from(
                hex::decode("12389a43644363633442525252595627890abcde7f").unwrap(),
            ));
            // skip processing pending key (key = 10) due to cadance
            let res = execute(
                deps.as_mut(),
                env.clone(),
                owner.clone(),
                prepare_msg.clone(),
            )
            .unwrap();
            assert_eq!(res.messages.len(), 0);

            // move forward minimum cadance, hs1 still should not process

            env.block.height = env.block.height + constants.bloom.unwrap().default_cadance;
            let res = execute(
                deps.as_mut(),
                env.clone(),
                owner.clone(),
                prepare_msg.clone(),
            )
            .unwrap();
            assert_eq!(res.messages.len(), 0);

            // now process bloom msg
            env.block.height = env.block.height + 3;
            let res = execute(
                deps.as_mut(),
                env.clone(),
                owner.clone(),
                prepare_msg.clone(),
            )
            .unwrap();
            assert_eq!(res.messages.len(), 1);

            // assert there is now 1 tx to process
            let pbm = PROCESSING_BLOOM_MEMPOOL.load(&deps.storage).unwrap().len();
            assert_eq!(pbm, 1);

            // PROCESS BLOOM
            let process_bloom_msg = ExecuteMsg::ProcessBloom {};
            let res = execute(
                deps.as_mut(),
                env.clone(),
                hs1.clone(),
                process_bloom_msg.clone(),
            )
            .unwrap();

            // ensure native denom is used in msg
            assert_eq!(
                res.messages[0].msg,
                BankMsg::Send {
                    to_address: "privateAddr1".into(),
                    amount: vec![coin(70u128, "snip1")]
                }
                .into()
            );
        }

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

        #[test]
        fn test_adding_eligible_random_starting_point() {
            let mut deps = mock_dependencies_with_balance(&[]);
            let env = mock_env();
            let info = mock_info("instantiator", &[]);

            // todo: setup snip120u
            let fist_eligible_snip = Snip120u {
                native_token: "snip1".into(),
                addr: Addr::unchecked("snip1Addr"),
                total_amount: Uint128::new(1000000u128),
            };
            let second_eligible_snip = Snip120u {
                native_token: "snip2".into(),
                addr: Addr::unchecked("snip2Addr"),
                total_amount: Uint128::new(1000000u128),
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
            let info = mock_info("instantiator", &[]);
            let mut env = mock_env();
            env.block.random = Some(Binary::from(&[0u8; 32]));

            instantiate(deps.as_mut(), env.clone(), info.clone(), init_msg).unwrap();

            let constants = CONFIG.load(&deps.storage).unwrap();

            let handle_msg = ExecuteMsg::AddEligibleHeadStash {
                headstash: vec![
                    Headstash {
                        addr: "0xF20B72c0d3992F53D0b28a190D060B6b999d861D".into(), // hs1
                        snips: vec![Snip {
                            amount: 100u128.into(),
                            contract: "snip1Addr".into(),
                        }],
                    },
                    Headstash {
                        addr: "vzRrBXAlQ8SJN33bcrzG7biwCMVW3iAOGqj4ekA7EsE=".into(), // hs2
                        snips: vec![Snip {
                            amount: 300u128.into(),
                            contract: "snip1Addr".into(),
                        }],
                    },
                    Headstash {
                        addr: "0x5c49a098BFe24cCEA4Aa66ac0416fD3F831Cd007".into(), // hs3
                        snips: vec![
                            Snip {
                                amount: 20u128.into(),
                                contract: "snip1Addr".into(),
                            },
                            Snip {
                                amount: 200u128.into(),
                                contract: "snip2Addr".into(),
                            },
                        ],
                    },
                    Headstash {
                        addr: "0xdf303dc89E6d4A6122fa2889CCBE923236635b68=".into(), // hs5
                        snips: vec![Snip {
                            amount: 100u128.into(),
                            contract: "snip2Addr".into(),
                        }],
                    },
                    Headstash {
                        addr: "0xF20B72c0d3992F53D0c28a190D060B6b999d861D".into(), // hs1
                        snips: vec![Snip {
                            amount: 100u128.into(),
                            contract: "snip1Addr".into(),
                        }],
                    },
                    Headstash {
                        addr: "vzRrBXAlQ8SJN33bcrzG7biwCMVW3iBOGqj4ekA7EsE=".into(), // hs2
                        snips: vec![Snip {
                            amount: 300u128.into(),
                            contract: "snip1Addr".into(),
                        }],
                    },
                    Headstash {
                        addr: "0x5c49a098BFe24cCEA4Aa66ac0416fD4F831Cd007".into(), // hs3
                        snips: vec![
                            Snip {
                                amount: 20u128.into(),
                                contract: "snip1Addr".into(),
                            },
                            Snip {
                                amount: 200u128.into(),
                                contract: "snip2Addr".into(),
                            },
                        ],
                    },
                    Headstash {
                        addr: "0xdf303dc89E6d4A6122fa2889CCEE923236635b68=".into(), // hs5
                        snips: vec![Snip {
                            amount: 100u128.into(),
                            contract: "snip2Addr".into(),
                        }],
                    },
                    Headstash {
                        addr: "0xF20B72c0d3902F53D0c28a190D060B6b999d861D".into(), // hs1
                        snips: vec![Snip {
                            amount: 100u128.into(),
                            contract: "snip1Addr".into(),
                        }],
                    },
                    Headstash {
                        addr: "vzRrBXAlQ8SJO33bcrzG7biwCMVW3iBOGqj4ekA7EsE=".into(), // hs2
                        snips: vec![Snip {
                            amount: 300u128.into(),
                            contract: "snip1Addr".into(),
                        }],
                    },
                    Headstash {
                        addr: "0x5c49a098BFe24cDEA4Aa66ac0416fD4F831Cd007".into(), // hs3
                        snips: vec![
                            Snip {
                                amount: 20u128.into(),
                                contract: "snip1Addr".into(),
                            },
                            Snip {
                                amount: 200u128.into(),
                                contract: "snip2Addr".into(),
                            },
                        ],
                    },
                    Headstash {
                        addr: "0xdf303dc89E6d4A6122fb2889CCEE923236635b68=".into(), // hs5
                        snips: vec![Snip {
                            amount: 100u128.into(),
                            contract: "snip2Addr".into(),
                        }],
                    },
                ],
            };

            let mut bytes = [0u8; 32];
            env.block.random = Some(Binary::from({
                bytes[..4].copy_from_slice(&12345u32.to_le_bytes());
                &bytes
            }));

            let handle_result = execute(deps.as_mut(), env.clone(), info.clone(), handle_msg);
            handle_result.unwrap();
        }
    }
}

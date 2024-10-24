use crate::btbe::initialize_btbe;
use crate::dwb::{DelayedWriteBuffer, DWB};
use crate::error::ContractError;
use crate::ibc::types::stargate::channel::new_ica_channel_open_init_cosmos_msg;
use crate::msg::{ExecuteMsg, InstantiateMsg, MigrateMsg, QueryAnswer, QueryMsg};
use crate::state::{
    Config, ContractState, Headstash, ALLOW_CHANNEL_OPEN_INIT, CHANNEL_OPEN_INIT_OPTIONS, CONFIG,
    ICA_ENABLED, STATE,
};
use base64::{engine::general_purpose, Engine};
// use crate::SNIP120U_REPLY;

#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;

use cosmwasm_std::{
    to_binary, Binary, ContractInfo, CosmosMsg, Deps, DepsMut, Env, MessageInfo, Reply, Response,
    StdError, StdResult,
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
        owner: info.sender,
        claim_msg_plaintext: msg.claim_msg_plaintext,
        end_date: msg.end_date,
        snip120us: msg.snips,
        start_date,
        viewing_key: msg.viewing_key,
        snip_hash: msg.snip120u_code_hash,
        channel_id: "removing".into(),
        bloom: msg.bloom_config,
    };
    let mut ica_msg = vec![];
    CONFIG.save(deps.storage, &state)?;
    if let Some(ica) = msg.channel_open_init_options {
        let callback_contract = ContractInfo {
            address: env.contract.address.clone(),
            code_hash: env.contract.code_hash,
        };

        // IBC Save the admin. Ica address is determined during handshake. Save headstash params.
        STATE.save(deps.storage, &ContractState::new(Some(callback_contract)))?;
        CHANNEL_OPEN_INIT_OPTIONS.save(deps.storage, &ica)?;
        ALLOW_CHANNEL_OPEN_INIT.save(deps.storage, &true)?;

        let ica_channel_open_init_msg = new_ica_channel_open_init_cosmos_msg(
            env.contract.address.to_string(),
            ica.connection_id,
            ica.counterparty_port_id,
            ica.counterparty_connection_id,
            None,
            ica.channel_ordering,
        );
        ica_msg.push(ica_channel_open_init_msg);
    } else {
        ICA_ENABLED.save(deps.storage, &false)?;
    }

    // initialize the bitwise-trie of bucketed entries
    initialize_btbe(deps.storage)?;

    // initialize the delay write buffer
    DWB.save(deps.storage, &DelayedWriteBuffer::new()?)?;

    Ok(Response::default().add_message(ica_msg[0].clone()))
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
        ExecuteMsg::Claim {
            addr,
            sig,
            amount,
            denom,
        } => self::headstash::try_claim(deps, env, info, &mut rng, addr, sig, denom, amount),
        ExecuteMsg::Clawback {} => self::headstash::try_clawback(deps, env, info),
        // ExecuteMsg::Redeem {} => todo!(),
        // ExecuteMsg::RegisterBloom { addr, bloom_msg } => {
        //     self::ibc_bloom::try_ibc_bloom(deps, env, info, addr, bloom_msg)
        // }
        // ExecuteMsg::PrepareBloom {} => ibc_bloom::handle_ibc_bloom(deps, env, info),
        // ExecuteMsg::ProcessBloom {} => ibc_bloom::process_ibc_bloom(deps, env, info),
        ExecuteMsg::CreateChannel {
            channel_open_init_options,
        } => ibc::create_channel(deps, env, info, channel_open_init_options),
        ExecuteMsg::CloseChannel {} => ibc::close_channel(deps, info),
        ExecuteMsg::ReceiveIcaCallback(ica_controller_callback_msg) => {
            ibc::ica_callback_handler(deps, info, ica_controller_callback_msg)
        }
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

    use cosmwasm_std::{BlockInfo, Uint128};

    use super::*;
    use crate::{
        dwb::DWB,
        state::{
            snip::AllowanceAction, HeadstashSig, CLAIMED_HEADSTASH, DECAY_CLAIMED, HEADSTASH_SIGS,
            TOTAL_CLAIMED,
        },
        transaction_history::{store_claim_headstash_action, store_register_headstash_action},
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

        add_headstash_to_state(deps, &env.block, rng, headstash.clone())?;

        Ok(Response::default())
    }

    pub fn add_headstash_to_state(
        deps: DepsMut,
        block: &BlockInfo,
        rng: &mut ContractPrng,
        headstash: Vec<Headstash>,
    ) -> StdResult<()> {
        for hs in headstash.into_iter() {
            for snip in hs.snips.into_iter() {
                let raw_amount = snip.amount.u128();
                let raw_recipient = deps.api.addr_canonicalize(hs.addr.as_str())?;

                // first store the tx information in the global append list of txs and get the new tx id
                let tx_id = store_register_headstash_action(
                    deps.storage,
                    &raw_recipient,
                    raw_amount,
                    snip.contract,
                    None,
                    block,
                )?;
                // load delayed write buffer
                let mut dwb = DWB.load(deps.storage)?;

                // add the tx info for the recipient to the buffer
                dwb.add_recipient(
                    deps.storage,
                    &mut secret_toolkit_crypto::ContractPrng {
                        rng: rng.rng.clone(),
                    },
                    &raw_recipient,
                    tx_id,
                    raw_amount,
                    #[cfg(feature = "gas_tracking")]
                    tracker,
                )?;
            }
        }

        Ok(())
    }

    pub fn try_claim(
        deps: DepsMut,
        env: Env,
        info: MessageInfo,
        rng: &mut ContractPrng,
        addr: String,
        sig: String,
        denom: String,
        amount: Uint128,
    ) -> Result<Response, ContractError> {
        let mut msgs: Vec<CosmosMsg> = vec![];
        let config = CONFIG.load(deps.storage)?;

        // make sure airdrop has not ended
        queries::available(&config, &env)?;

        // ensure snip defined is one eligible for this headstash
        if !config.snip120us.iter().any(|a| a.addr.as_str() == addr) {
            return Err(ContractError::InvalidSnip120u {});
        }

        // if pubkey does not start with 0x1, we expect it is a solana wallet and we must verify
        if addr.starts_with("0x1") {
            validation::verify_headstash_sig(
                deps.api,
                info.sender.clone(),
                addr.to_string(),
                sig.clone(),
                config.claim_msg_plaintext.clone(),
                false,
                false,
            )?;
        } else {
            validation::verify_headstash_sig(
                deps.api,
                info.sender.clone(),
                addr.clone(),
                sig.clone(),
                config.claim_msg_plaintext,
                false,
                true,
            )?;
        }

        let raw_sender = deps.api.addr_canonicalize(info.sender.as_str())?;
        let headstash_amount = self::utils::random_multiplier(rng) * amount;

        // first store the tx information in the global append list of txs and get the new tx id
        let tx_id = store_claim_headstash_action(
            deps.storage,
            &raw_sender,
            headstash_amount.u128(),
            denom.clone(),
            None,
            &env.block,
        )?;

        // load delayed write buffer
        let mut dwb = DWB.load(deps.storage)?;

        let claim_str = "claim";

        // settle the owner's account.
        dwb.settle_sender_or_owner_account(
            deps.storage,
            &raw_sender,
            tx_id,
            headstash_amount.u128(),
            claim_str,
            &mut secret_toolkit_crypto::ContractPrng {
                rng: rng.rng.clone(),
            },
            #[cfg(feature = "gas_tracking")]
            tracker,
        )?;

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
            denom.clone(),
        )?;

        msgs.push(mint_msg);

        // Update total claimed for specific snip20
        let tc = TOTAL_CLAIMED.add_suffix(denom.as_str().as_bytes());
        tc.update(deps.storage, |a| Ok(a + headstash_amount))?;

        // saves signature w/ key to item in state as info.sender
        let hs = HEADSTASH_SIGS.add_suffix(info.sender.as_str().as_bytes());
        hs.save(
            deps.storage,
            &HeadstashSig {
                addr: addr.clone(),
                sig: sig.clone(),
            },
        )?;

        Ok(Response::default().add_messages(msgs))
    }

    pub fn try_clawback(
        deps: DepsMut,
        env: Env,
        info: MessageInfo,
    ) -> Result<Response, ContractError> {
        let mut msgs: Vec<CosmosMsg> = vec![];
        // ensure sender is admin
        let config = CONFIG.load(deps.storage)?;

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
                    Ok(new)
                })?;

                // Update total claimed
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
        ed25519: bool,
    ) -> Result<(), StdError> {
        match ed25519 {
            true => {
                let computed_plaintxt = compute_plaintxt_msg(plaintxt, sender, false);
                match api.secp256k1_verify(
                    computed_plaintxt.clone().into_bytes().as_slice(),
                    sig.clone().into_bytes().as_slice(),
                    signer.clone().into_bytes().as_slice(),
                ) {
                    Ok(true) => Ok(()),
                    Ok(false) | Err(_) => api
                        .ed25519_verify(
                            &general_purpose::STANDARD
                                .encode(computed_plaintxt.into_bytes().as_slice())
                                .as_bytes(),
                            sig.into_bytes().as_slice(),
                            signer.into_bytes().as_slice(),
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
            false => match validate_ethereum_text(
                api,
                sender.clone(),
                plaintxt,
                sig.clone(),
                signer.clone(),
                bloom,
            )? {
                true => Ok(()),
                false => Err(StdError::generic_err("cannot validate offline_sig")),
            },
        }
    }

    // source: https://github.com/SecretSaturn/SecretPath/blob/aae6c61ff755aa22112945eab308e9037044980b/TNLS-Gateways/secret/src/msg.rs#L101

    pub fn validate_ethereum_text(
        api: &dyn Api,
        sender: Addr,
        plaintxt: String,
        offline_sig: String,
        signer: String,
        bloom: bool,
    ) -> StdResult<bool> {
        let plaintext_msg = compute_plaintxt_msg(plaintxt, sender, bloom);
        match hex::decode(offline_sig.clone()) {
            Ok(eth_sig_hex) => verify_ethereum_text(api, &plaintext_msg, &eth_sig_hex, &signer),
            Err(_) => Err(StdError::InvalidHex {
                msg: format!("Could not decode the eth signature"),
            }),
        }
    }

    // ensure blooms are enabled
    pub fn compute_plaintxt_msg(claim_plaintxt: String, sender: Addr, bloom: bool) -> String {
        let mut plaintext_msg = str::replace(&claim_plaintxt, "{wallet}", sender.as_ref());
        if bloom {
            plaintext_msg = str::replace(&claim_plaintxt, "{bloom_enabled}", sender.as_ref());
        }
        plaintext_msg
    }
}

pub mod ibc_bloom {
    use super::*;

    use cosmwasm_std::{coin, Addr, DepsMut, Empty, IbcTimeout, StdError, Uint128, WasmMsg};
    use utils::contract_randomness;
    use validation::compute_plaintxt_msg;

    use crate::{
        ibc::types::packet::IcaPacketData,
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

    // source: https://github.com/SecretSaturn/SecretPath/blob/aae6c61ff755aa22112945eab308e9037044980b/TNLS-Gateways/secret/src/msg.rs#L101
    pub fn verify_solana_wallet(
        deps: &DepsMut,
        sender: Addr,
        pubkey: String,
        signature: String,
        plaintxt: String,
    ) -> Result<(), StdError> {
        let computed_plaintxt = compute_plaintxt_msg(plaintxt, sender, true);
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

    /// Entry point to register an ibc bloom to be processed
    pub fn try_ibc_bloom(
        deps: DepsMut,
        env: Env,
        info: MessageInfo,
        addr: String,
        bloom_msg: IbcBloomMsg,
    ) -> Result<Response, ContractError> {
        //  TODO: add global bloomId to increment & make use of to handle callback responses.
        let config = CONFIG.load(deps.storage)?;
        if config.bloom.is_none() {
            return Err(ContractError::BloomDisabled {});
        }

        // create new tx id
        // verify msg sender has been authorized with public address signature
        let hs = HEADSTASH_SIGS.add_suffix(info.sender.as_str().as_bytes());
        if let Some(sig) = hs.may_load(deps.storage)? {
            if sig.addr.ne(info.sender.as_str()) {
                return Err(ContractError::BloomMismatchSigner {});
            }
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
                        timestamp: env.block.time,
                        msg: bloom_msg,
                    },
                )?;
            } else {
                blooms.insert(
                    deps.storage,
                    &sig.addr,
                    &BloomBloom {
                        timestamp: env.block.time,
                        msg: bloom_msg,
                    },
                )?;
            };

            // if pubkey does not start with 0x1, we expect it is a solana wallet and we must verify
            if addr.starts_with("0x1") {
                validation::verify_headstash_sig(
                    deps.api,
                    info.sender.clone(),
                    addr.to_string(),
                    sig.sig.clone(),
                    config.claim_msg_plaintext.clone(),
                    true,
                    false,
                )?;
            } else {
                validation::verify_headstash_sig(
                    deps.api,
                    info.sender.clone(),
                    addr.clone(),
                    sig.sig.clone(),
                    config.claim_msg_plaintext,
                    true,
                    true,
                )?;
            }
        } else {
            return Err(ContractError::BloomNotFound {});
        };

        // for snip in snip120us {
        // if ibc_bloom_status_r(deps.storage).load(sig.as_bytes())? {
        //     return Err(StdError::generic_err("already ibc-bloomed"));
        // }

        //     // if let Some(address) = config.snip120us.iter().find(|e| e.addr == snip.address) {
        //     //     let redeem_msg = crate::msg::snip::Redeem {
        //     //         amount: snip.amount,
        //     //         denom: None,
        //     //         decoys: None,
        //     //         entropy: None,
        //     //         padding: None,
        //     //     };
        //     //     let snip120_msg = into_cosmos_msg(
        //     //         redeem_msg,
        //     //         1usize, // ?
        //     //         config.snip_hash.clone(),
        //     //         snip.address.to_string(),
        //     //         None,
        //     //     )?;

        //     //     let ibc_send = IbcMsg::Transfer {
        //     //         channel_id: config.channel_id.clone(),
        //     //         to_address: destination_addr.clone(),
        //     //         amount: Coin::new(snip.amount.u128(), address.native_token.clone()),
        //     //         timeout: IbcTimeout::with_timestamp(env.block.time.plus_seconds(300u64)),
        //     //         memo: "".into(),
        //     //     };

        //     //     msgs.push(snip120_msg);
        //     //     msgs.push(ibc_send.into())
        //     // } else {
        //     //     return Err(StdError::generic_err("no snip20 addr provided"));
        //     // }
        // }

        Ok(Response::new())
    }

    pub fn handle_ibc_bloom(
        deps: DepsMut,
        env: Env,
        info: MessageInfo,
    ) -> Result<Response, ContractError> {
        let mut msgs = vec![];
        // ensure sender is admin
        let config = CONFIG.load(deps.storage)?;
        let admin = config.owner;
        if info.sender != admin {
            return Err(ContractError::BloomDisabled {});
        }

        // get random three digit number
        let rand_bytes = contract_randomness(env.clone());
        let digit1 = (rand_bytes[0] & 0x0F) as u16;
        let digit2 = (rand_bytes[7] & 0x0F) as u16;
        let digit3 = (rand_bytes[10] & 0x0F) as u16;
        let random_number = (digit1 * 100) + (digit2 * 10) + digit3;

        // define map key from random bytes
        let key = utils::weighted_random(random_number as u64);
        let blooms = BLOOMSBLOOMS.add_suffix(key.to_string().as_bytes());

        // grab all map keys
        let pending_keys = blooms.paging_keys(deps.storage, 0, 30)?;

        // loop through keys
        for key in pending_keys {
            if let Some(mut bloom) = blooms.get(deps.storage, &key) {
                let cade = bloom.msg.cadance
                    + config
                        .bloom
                        .clone()
                        .expect("smokin big doinks in amish")
                        .default_cadance;

                if !env
                    .block
                    .time
                    .minus_nanos(bloom.timestamp.nanos())
                    .seconds()
                    .gt(&cade)
                {
                    break;
                };

                let token = bloom.msg.source_token.clone();
                // pop out granular msgs to form snip120u redeem msgs
                let redeem_msgs = bloom
                    .msg
                    .bloom
                    .drain(0..1) // TODO: replace w. variable
                    .map(|br| {
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
                                    addr: br.addr,
                                    amount: br.amount,
                                    token: token.clone(),
                                    channel: config.channel_id.clone(),
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
            }
        }

        Ok(Response::new().add_messages(msgs))
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
                if b.len().lt(&1) {
                    return Ok(b);
                }
                let lens = b.len() as u64;
                let limit = lens.div_ceil(rand.into()).max(1);
                b.drain(0..limit as usize).for_each(|a| {
                    // form ibc msg
                    let ibc_msg: CosmosMsg<Empty> =
                        CosmosMsg::Ibc(cosmwasm_std::IbcMsg::Transfer {
                            channel_id: a.channel, // single transfer channel
                            to_address: a.addr,
                            amount: coin(Uint128::from(a.amount).u128(), a.token),
                            timeout: IbcTimeout::with_timestamp(env.block.time.plus_seconds(60)), // remove hardcode
                            memo: "more life".into(),
                        });

                    msgs.push(ibc_msg);
                });
                Ok(b)
            })
            .unwrap();

        // IBC implementation
        let contract_state = STATE.load(deps.storage)?;
        let ica_packet = IcaPacketData::new(to_binary(&msgs)?.to_vec(), None);
        let ica_info = contract_state.get_ica_info()?;
        let send_packet_msg = ica_packet.to_ibc_msg(&env, ica_info.channel_id, None)?;
        Ok(Response::new().add_message(send_packet_msg))
    }
}

pub mod utils {
    use cosmwasm_std::Decimal;

    use super::*;
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

pub mod ibc {
    use cosmwasm_std::IbcMsg;

    use crate::{
        msg::options::ChannelOpenInitOptions,
        state::{self, channel::ChannelStatus},
        types::callbacks::IcaControllerCallbackMsg,
    };

    use super::*;
    /// Submits a stargate `MsgChannelOpenInit` to the chain.
    /// Can only be called by the contract owner or a whitelisted address.
    /// Only the contract owner can include the channel open init options.
    #[allow(clippy::needless_pass_by_value)]
    pub fn create_channel(
        deps: DepsMut,
        env: Env,
        info: MessageInfo,
        options: Option<ChannelOpenInitOptions>,
    ) -> Result<Response, ContractError> {
        state::assert_owner(deps.storage, info.sender)?;

        let options = if let Some(new_options) = options {
            state::CHANNEL_OPEN_INIT_OPTIONS.save(deps.storage, &new_options)?;
            new_options
        } else {
            state::CHANNEL_OPEN_INIT_OPTIONS
                .may_load(deps.storage)?
                .ok_or(ContractError::NoChannelInitOptions)?
        };

        state::ALLOW_CHANNEL_OPEN_INIT.save(deps.storage, &true)?;

        let ica_channel_open_init_msg = new_ica_channel_open_init_cosmos_msg(
            env.contract.address.to_string(),
            options.connection_id,
            options.counterparty_port_id,
            options.counterparty_connection_id,
            options.tx_encoding,
            options.channel_ordering,
        );

        Ok(Response::new().add_message(ica_channel_open_init_msg))
    }

    /// Submits a [`IbcMsg::CloseChannel`].
    #[allow(clippy::needless_pass_by_value)]
    pub fn close_channel(deps: DepsMut, info: MessageInfo) -> Result<Response, ContractError> {
        state::assert_owner(deps.storage, info.sender)?;

        let channel_state = state::CHANNEL_STATE.load(deps.storage)?;
        if !channel_state.is_open() {
            return Err(ContractError::InvalidChannelStatus {
                expected: ChannelStatus::Open.to_string(),
                actual: channel_state.channel_status.to_string(),
            });
        }

        state::ALLOW_CHANNEL_CLOSE_INIT.save(deps.storage, &true)?;

        let channel_close_msg = CosmosMsg::Ibc(IbcMsg::CloseChannel {
            channel_id: channel_state.channel.endpoint.channel_id,
        });

        Ok(Response::new().add_message(channel_close_msg))
    }

    /// Handles ICA controller callback messages.
    pub fn ica_callback_handler(
        deps: DepsMut,
        info: MessageInfo,
        callback_msg: IcaControllerCallbackMsg,
    ) -> Result<Response, ContractError> {
        // if bloom successful, do nothing?
        // if bloom unsucessful or timeout, use bloomId to save failed bloom to state so owner can reregister tx if desired

        Ok(Response::default())
    }
}

#[cfg(test)]
mod tests {
    use cosmwasm_std::{testing::*, Addr};
    use validation::compute_plaintxt_msg;

    use super::*;

    pub const PLAINTXT: &str = "H.R.E.A.M. Sender: {wallet} Headstash: {secondary_address}";

    #[test]
    fn test_compute_bloom_plaintext_msg() {
        let expected_result = "H.R.E.A.M. Sender: sender123 Headstash: secondary123";
        // Create test variables

        let sender = Addr::unchecked("sender123");
        let secondary_address = "secondary123".to_string();

        assert_eq!(
            compute_plaintxt_msg(PLAINTXT.to_string(), sender.clone(), true),
            expected_result.to_string()
        );

        let err = compute_plaintxt_msg(
            PLAINTXT.to_string(),
            Addr::unchecked(secondary_address),
            true,
        );

        assert_ne!(err, expected_result.to_string());
    }

    #[test]
    fn test_randomness() {
        let mut env = mock_env();

        // get first randomness value
        let mut prng = ContractPrng::from_env(&env.clone());
        let rand1 = prng.rand_bytes();
        let result = general_purpose::STANDARD.encode(rand1.clone());

        let dec1 = self::utils::random_multiplier(&mut prng);

        // simulate new randomness seed from environment
        env.block.random = Some(Binary::from_base64(&result).unwrap());

        // get second randomness value, should be different with new seed
        let mut prng = ContractPrng::from_env(&env.clone());
        let rand2 = prng.rand_bytes();

        let dec2 = self::utils::random_multiplier(&mut prng);
        // assert not equal
        assert_ne!(rand1, rand2);
        assert_ne!(dec1, dec2);
    }

    // fn _init_helper() -> (
    //     StdResult<Response>,
    //     OwnedDeps<MockStorage, MockApi, MockQuerier>,
    // ) {
    //     let mut deps = mock_dependencies_with_balance(&[]);
    //     let env = mock_env();
    //     let info = mock_info("instantiator", &[]);

    //     // todo: setup snip120u

    //     let init_msg = crate::msg::InstantiateMsg {
    //         owner: todo!(),
    //         claim_msg_plaintext: PLAINTXT.to_string(),
    //         start_date: None,
    //         end_date: None,
    //         // snip120u_code_id: 2,
    //         snip120u_code_hash: "HASH".into(),
    //         snips: vec![],
    //         viewing_key: todo!(),
    //         channel_id: todo!(),
    //     };

    //     (instantiate(deps.as_mut(), env, info, init_msg), deps)
    // }
}

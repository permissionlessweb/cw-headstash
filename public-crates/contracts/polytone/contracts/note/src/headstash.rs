use anybuf::Anybuf;
use cosmwasm_std::{
    to_json_binary, Addr, Binary, Coin, CosmosMsg, Env, MessageInfo, QuerierWrapper, Response,
    StdError, Storage, Timestamp, Uint128,
};
use headstash_public::state::{
    Headstash, HeadstashParams, InstantiateMsg as HsInstantiateMsg, Snip120u, GLOB_HEADSTASH_KEY,
};

use polytone::headstash::{constants::*, HEADSTASH_PARAMS, HEADSTASH_SEQUENCE};

use crate::{
    error::ContractError,
    state::{HeadstashSeq, GRANTEE},
};

use cosmos_sdk_proto::{
    cosmos::authz::v1beta1::{GenericAuthorization, Grant, MsgGrant},
    prost, Any,
};
use prost::Message;

pub fn upload_contract_on_secret(
    querier: QuerierWrapper,
    storage: &mut dyn Storage,
    info: &MessageInfo,
) -> Result<CosmosMsg, ContractError> {
    if let Some(remote_addr) = polytone::accounts::query_account(storage, info.sender.clone())? {
        let glob = HEADSTASH_PARAMS.load(storage)?.cw_glob;
        if !HEADSTASH_SEQUENCE.load(storage, HeadstashSeq::UploadSnip.into())? {
            return Err(ContractError::Std(StdError::generic_err(
                "must upload snip120u first",
            )));
        } else if HEADSTASH_SEQUENCE.load(storage, HeadstashSeq::UploadHeadstash.into())? {
            return Err(ContractError::Std(StdError::generic_err(
                "already have set headstash code-id",
            )));
        };

        // headstash key
        let storage_key = Binary::from_base64(&GLOB_HEADSTASH_KEY)?;
        let wasm_blob = match querier.query_wasm_raw(glob, storage_key)? {
            Some(b) => Binary::new(b),
            None => return Err(ContractError::NoPair {}),
        };

        Ok(headstash_anybuf::form_upload_contract_on_secret(
            remote_addr,
            wasm_blob,
        )?)
    } else {
        return Err(ContractError::NoPair {});
    }
}

pub fn set_snip120u_code_id_on_secret(
    storage: &mut dyn Storage,
    info: &MessageInfo,
    code_id: u64,
) -> Result<Response, ContractError> {
    if let Some(_) = polytone::accounts::query_account(storage, info.sender.clone())? {
        let mut state = HEADSTASH_PARAMS.load(storage)?;
        let HeadstashParams {
            snip120u_code_id, ..
        } = state;
        if snip120u_code_id.is_some() {
            return Err(ContractError::SetSnip120uCodeError {});
        } else {
            state.snip120u_code_id = Some(code_id);
            HEADSTASH_SEQUENCE.save(storage, HeadstashSeq::UploadSnip.into(), &true)?;
            HEADSTASH_PARAMS.save(storage, &state)?;
        }
    } else {
        return Err(ContractError::NoPair {});
    }
    Ok(Response::new())
}

pub fn set_headstash_code_id_on_secret(
    storage: &mut dyn Storage,
    info: &MessageInfo,
    code_id: u64,
) -> Result<Response, ContractError> {
    if let Some(_) = polytone::accounts::query_account(storage, info.sender.clone())? {
        let mut state = HEADSTASH_PARAMS.load(storage)?;
        let HeadstashParams {
            headstash_code_id,
            snip120u_code_id,
            ..
        } = state;
        if headstash_code_id.is_some() || snip120u_code_id.is_none() {
            return Err(ContractError::SetSnip120uCodeError {});
        } else {
            state.headstash_code_id = Some(code_id);
            HEADSTASH_SEQUENCE.save(storage, HeadstashSeq::UploadHeadstash.into(), &true)?;
            HEADSTASH_PARAMS.save(storage, &state)?;
        }
    } else {
        return Err(ContractError::NoPair {});
    }
    Ok(Response::new())
}

pub fn set_headstash_addr(
    storage: &mut dyn Storage,
    info: &MessageInfo,
    to_add: String,
) -> Result<Response, ContractError> {
    if let Some(_) = polytone::accounts::query_account(storage, info.sender.clone())? {
        let mut state = HEADSTASH_PARAMS.load(storage)?;

        // ensure snip & headstash code-id upload sequence is set
        let HeadstashParams {
            headstash_addr,
            headstash_code_id,
            snip120u_code_id,
            ..
        } = state;
        if headstash_code_id.is_none() || snip120u_code_id.is_none() || headstash_addr.is_some() {
            return Err(ContractError::SetHeadstashAddrError {});
        } else {
            state.headstash_addr = Some(to_add);
        }

        HEADSTASH_SEQUENCE.save(storage, HeadstashSeq::InitHeadstash.into(), &true)?;
        HEADSTASH_PARAMS.save(storage, &state)?;
    } else {
    }
    Ok(Response::new())
}

pub fn set_snip120u_addr(
    storage: &mut dyn Storage,
    token: String,
    contract_addr: String,
) -> Result<Response, ContractError> {
    let mut state = HEADSTASH_PARAMS.load(storage)?;

    let HeadstashParams {
        headstash_code_id,
        snip120u_code_id,
        ..
    } = state;
    if headstash_code_id.is_none() || snip120u_code_id.is_none() {
        return Err(ContractError::SetInitSnip120uError {});
    } else {
        if let Some((i, a)) = state
            .token_params
            .iter_mut()
            .enumerate()
            .find(|(_, a)| a.symbol == token)
        {
            // println!("found index at {:#?}", i);
            if a.snip_addr.is_none() {
                a.snip_addr = Some(contract_addr);
                HEADSTASH_SEQUENCE.save(storage, HeadstashSeq::InitSnips.indexed_snip(i), &true)?;
            } else {
                return Err(ContractError::Snip120uAddrAlreadySet {});
            }
        }
    }
    HEADSTASH_PARAMS.save(storage, &state)?;
    Ok(Response::new())
}

pub fn create_snip120u_contract(
    storage: &mut dyn Storage,
    info: &MessageInfo,
) -> Result<Vec<CosmosMsg>, ContractError> {
    let mut msgs = vec![];
    if let Some(remote_account) = polytone::accounts::query_account(storage, info.sender.clone())? {
        let hp = HEADSTASH_PARAMS.load(storage)?;

        // if headstash or snip120u is not set, we cannot instantiate snips
        if !HEADSTASH_SEQUENCE.load(storage, HeadstashSeq::UploadSnip.into())?
            && hp.snip120u_code_id.is_none()
        {
            return Err(ContractError::NoSnipCodeId {});
        } else if !HEADSTASH_SEQUENCE.load(storage, HeadstashSeq::UploadHeadstash.into())?
            && hp.headstash_code_id.is_none()
        {
            return Err(ContractError::NoHeadstashCodeId {});
        }
        // define CosmosMsg for each snip120u
        for token in &hp.token_params {
            if hp.token_params.len() != 0 {
                if let Some(t) = hp
                    .token_params
                    .iter()
                    .find(|t| t.native == token.native && t.snip_addr.is_none())
                {
                    let msg = headstash_anybuf::form_instantiate_snip120u(
                        remote_account.to_string(),
                        token.clone(),
                        hp.snip120u_code_hash.clone(),
                        hp.snip120u_code_id.unwrap(),
                        hp.headstash_addr.clone(),
                        t.symbol.clone(),
                    )?;
                    msgs.push(msg);
                }
            } else {
                return Err(ContractError::NoSnip120uParamsSet {});
            }
        }
    } else {
        return Err(ContractError::NoPair {});
    }
    Ok(msgs)
}

pub fn create_headstash_contract(
    env: &Env,
    storage: &mut dyn Storage,
    info: &MessageInfo,
) -> Result<Vec<CosmosMsg>, ContractError> {
    let mut msgs = vec![];
    if let Some(remote_account) = polytone::accounts::query_account(storage, info.sender.clone())? {
        let hp = HEADSTASH_PARAMS.load(storage)?;

        // iterate and enumerate for each snip in snip params, if they deployment sequence is not met, and there is addr for each snip, error.
        for (i, hstp) in hp.token_params.iter().enumerate() {
            // println!("token_param: {i}, {:#?}", param);
            if !HEADSTASH_SEQUENCE.load(storage, HeadstashSeq::InitSnips.indexed_snip(i))?
                && hstp.snip_addr.is_none()
            {
                return Err(ContractError::NoSnip120uContract {});
            }
        }

        // println!("{:#?}", hs_params);
        // cw-headstash code-id must be known
        if let Some(code_id) = hp.headstash_code_id {
            let mut hs_snips = vec![];
            // at least 1 snip120u must exist
            for snip in hp.token_params.clone() {
                // println!("{:#?}", snip.snip_addr);
                if snip.snip_addr.is_none() {
                    return Err(ContractError::NoSnipContractAddr {});
                }
                let snip = Snip120u {
                    token: snip.native,
                    name: snip.name,
                    addr: Some(Addr::unchecked(snip.snip_addr.unwrap())),
                    total_amount: snip.total,
                };
                hs_snips.push(snip);
            }
            // form cw-headstash instantiate msg
            let init_headstash_msg = headstash_anybuf::form_instantiate_headstash_msg(
                code_id,
                &remote_account,
                HsInstantiateMsg {
                    claim_msg_plaintext: hp.headstash_init_config.claim_msg_plaintxt,
                    end_date: Some(
                        hp.headstash_init_config
                            .end_date
                            .unwrap_or(env.block.time.plus_days(365u64).nanos()), // one year
                    ),
                    start_date: hp.headstash_init_config.end_date,
                    random_key: hp.headstash_init_config.random_key,
                    owner: Addr::unchecked(remote_account.clone()), // remote proxy account
                    snip120u_code_hash: hp.snip120u_code_hash,
                    snips: hs_snips,
                    multiplier: hp.multiplier,
                    bloom_config: hp.bloom_config,
                },
            )?;
            // let msg = send_msg_as_ica(vec![init_headstash_msg], cw_ica_contract);
            msgs.push(init_headstash_msg)
        } else {
            return Err(ContractError::BadContractId {});
        }
    } else {
        return Err(ContractError::NoPair {});
    }

    Ok(msgs)
}

pub fn authorize_headstash_as_snip_minter(
    storage: &mut dyn Storage,
    info: &MessageInfo,
) -> Result<Vec<CosmosMsg>, ContractError> {
    let mut msgs = vec![];
    if let Some(remote_account) = polytone::accounts::query_account(storage, info.sender.clone())? {
        let hp = HEADSTASH_PARAMS.load(storage)?;

        if let Some(hs_addr) = hp.headstash_addr {
            // load snip120u's from state
            for snip in hp.token_params {
                if let Some(addr) = snip.snip_addr {
                    // add minter msg
                    let msg = headstash_anybuf::form_authorize_headsdtash_as_snip120u_minter_msg(
                        remote_account.clone(),
                        hs_addr.clone(),
                        addr,
                    )?;
                    msgs.push(msg);
                } else {
                    return Err(ContractError::NoSnip120uContract {});
                }
            }
        } else {
            return Err(ContractError::NoHeadstashContract {});
        }
    } else {
        return Err(ContractError::NoPair {});
    }
    Ok(msgs)
}

pub fn add_headstash_claimers(
    storage: &mut dyn Storage,
    to_add: &Vec<Headstash>,
    info: &MessageInfo,
) -> Result<Vec<CosmosMsg>, ContractError> {
    let mut msgs = vec![];
    if let Some(remote_account) = polytone::accounts::query_account(storage, info.sender.clone())? {
        let hp = HEADSTASH_PARAMS.load(storage)?;
        if let Some(hs_addr) = hp.headstash_addr {
            // add headstash claimers msg
            let msg = headstash_anybuf::form_add_headstashes_msgs(
                remote_account.clone(),
                hs_addr.clone(),
                to_add,
            )?;
            msgs.push(msg);
        } else {
            return Err(ContractError::NoHeadstashContract {});
        }
    } else {
        return Err(ContractError::NoPair {});
    }
    Ok(msgs)
}

pub fn authorize_feegrants(
    storage: &mut dyn Storage,
    info: &MessageInfo,
    to_grant: &Vec<String>,
) -> Result<Vec<CosmosMsg>, ContractError> {
    let mut msgs = vec![];
    if let Some(remote_account) = polytone::accounts::query_account(storage, info.sender.clone())? {
        let hp = HEADSTASH_PARAMS.load(storage)?;
        if let Some(b) = hp.fee_granter {
            if info.sender.to_string() != b {
                return Err(ContractError::NotValidFeegranter {});
            }

            // add headstash claimers msg
            for addr in to_grant {
                let msg = headstash_anybuf::form_authorize_feegrant(remote_account.clone(), addr)?;
                msgs.push(msg);
            }
        }
    } else {
        return Err(ContractError::NoPair {});
    }
    Ok(msgs)
}

pub fn grant_authz_for_deployer(
    storage: &mut dyn Storage,
    info: &MessageInfo,
    grantee: &String,
) -> Result<Vec<CosmosMsg>, ContractError> {
    let mut msgs = vec![];
    if let Some(remote_account) = polytone::accounts::query_account(storage, info.sender.clone())? {
        if GRANTEE.may_load(storage)?.is_some() {
            return Err(ContractError::AuthzGranteeExists {});
        }

        // let hp = HEADSTASH_PARAMS.load(storage)?;

        let grant_msgs: Vec<MsgGrant> = vec![
            SECRET_COMPUTE_STORE_CODE,
            SECRET_COMPUTE_INSTANTIATE,
            SECRET_COMPUTE_EXECUTE,
        ]
        .into_iter()
        .map(|msg| {
            let grant = Grant {
                authorization: Some(Any {
                    type_url: COSMOS_GENERIC_AUTHZ.to_string(),
                    value: GenericAuthorization {
                        msg: msg.to_string(),
                    }
                    .encode_to_vec(),
                }),
                expiration: None,
            };
            MsgGrant {
                granter: remote_account.to_string(),
                grantee: grantee.clone(),
                grant: Some(grant),
            }
        })
        .collect();

        msgs.extend(headstash_anybuf::form_authz_grant_msgs(grant_msgs)?);
    } else {
        return Err(ContractError::NoPair {});
    }
    Ok(msgs)
}

pub fn fund_headstash(
    storage: &mut dyn Storage,
    sender: &Addr,
    funds: Vec<Coin>,
    timestamp: Timestamp,
) -> Result<Vec<CosmosMsg>, ContractError> {
    // Short-circuit if no polytone account
    if polytone::accounts::query_account(storage, sender.clone())?.is_none() {
        return Ok(vec![]);
    }

    let hp = HEADSTASH_PARAMS.load(storage)?;
    let headstash_addr = &hp
        .headstash_addr
        .expect("we expect a headsatsh contract address to have been saved to the notes state.");

    let funds_map: std::collections::HashMap<&str, &Coin> = funds
        .iter()
        .map(|coin| (coin.denom.as_str(), coin))
        .collect();

    let msgs: Result<Vec<_>, _> = hp
        .token_params
        .into_iter()
        .filter_map(|stash| {
            // Only proceed if we have a matching fund
            funds_map.get(stash.native.as_str()).map(|amount| {
                headstash_anybuf::form_fund_headstash_msg(
                    sender.to_string(),
                    headstash_addr,
                    stash.source_channel,
                    amount,
                    timestamp.plus_minutes(10),
                )
            })
        })
        .collect();

    msgs.map_err(Into::into)
}

pub mod headstash_anybuf {
    use cosmwasm_std::{Timestamp, Uint64};
    use headstash_public::{
        snip::AddMintersMsg,
        state::{Headstash, HeadstashTokenParams},
    };

    use super::*;

    pub fn form_upload_contract_on_secret(
        remote_addr: String,
        wasm: Binary,
    ) -> Result<CosmosMsg, ContractError> {
        Ok(
            #[allow(deprecated)]
            // proto ref: https://github.com/scrtlabs/SecretNetwork/blob/master/proto/secret/compute/v1beta1/msg.proto#L33
            CosmosMsg::Stargate {
                type_url: SECRET_COMPUTE_STORE_CODE.into(),
                value: anybuf::Anybuf::new()
                    .append_string(1, remote_addr.to_string()) // sender (ICA Address)
                    .append_bytes(2, wasm) // code-id of snip-25
                    .into_vec()
                    .into(),
            },
        )
    }

    /// Instantiates a snip120u token on Secret Network via Stargate
    pub fn form_instantiate_snip120u(
        sender: String,
        coin: HeadstashTokenParams,
        _code_hash: String,
        code_id: u64,
        headstash: Option<String>,
        symbol: String,
    ) -> Result<CosmosMsg, ContractError> {
        let init_msg = headstash_public::snip::InstantiateMsg {
            name: "Terp Network SNIP120U - ".to_owned() + coin.name.as_str(),
            admin: headstash,
            symbol,
            decimals: 6u8,
            initial_balances: None,
            prng_seed: Binary::new(
                "eretjeretskeretjablereteretjeretskeretjableret"
                    .to_string()
                    .into_bytes(),
            ),
            config: None,
            supported_denoms: Some(vec![coin.ibc.clone()]),
        };

        Ok(
            #[allow(deprecated)]
            // proto ref: https://github.com/scrtlabs/SecretNetwork/blob/master/proto/secret/compute/v1beta1/msg.proto
            CosmosMsg::Stargate {
                type_url: SECRET_COMPUTE_INSTANTIATE.into(),
                value: anybuf::Anybuf::new()
                    .append_string(1, sender.to_string()) // sender (ICA Address)
                    .append_uint64(3, code_id) // code-id of snip-25
                    .append_string(
                        4,
                        "SNIP120U For Secret Network - ".to_owned() + coin.name.as_str(),
                    ) // label of snip20
                    .append_bytes(5, to_json_binary(&init_msg)?.as_slice())
                    .into_vec()
                    .into(),
            },
        )
    }

    pub fn form_instantiate_headstash_msg(
        code_id: u64,
        remote_account: &String,
        scrt_headstash_msg: HsInstantiateMsg,
    ) -> Result<CosmosMsg, ContractError> {
        Ok(
            #[allow(deprecated)]
            // proto ref: https://github.com/scrtlabs/SecretNetwork/blob/master/proto/secret/compute/v1beta1/msg.proto
            CosmosMsg::Stargate {
                type_url: SECRET_COMPUTE_INSTANTIATE.into(),
                value: anybuf::Anybuf::new()
                    .append_string(1, remote_account.to_string()) // remote proxy
                    .append_uint64(3, code_id) // code-id of snip-120u
                    .append_string(
                        4,
                        "Secret-Headstash Airdrop Contract: Terp Network ".to_string(),
                    ) // label of snip20
                    .append_bytes(5, to_json_binary(&scrt_headstash_msg)?.as_slice())
                    .into_vec()
                    .into(),
            },
        )
    }

    // ref: https://github.com/cosmos/cosmos-sdk/blob/v0.45.16/proto/cosmos/authz/v1beta1/tx.proto
    pub fn form_authz_grant_msgs(
        grant_msgs: Vec<MsgGrant>,
    ) -> Result<Vec<CosmosMsg>, ContractError> {
        // form Cosmos messages for ica to broadcasts.
        let msgs: Vec<CosmosMsg> = grant_msgs
            .into_iter()
            .map(|grant| {
                // form ica-msg to grant CosmWasm Actions on behalf of ica
                let msg = Anybuf::new()
                    .append_string(1, grant.granter.clone()) // granter
                    .append_string(2, grant.grantee.clone()) // grantee
                    .append_bytes(
                        3,                                                            // grant
                        Binary::new(grant.grant.expect("grant set").encode_to_vec()), // cw-ica SendCosmosMsgs
                    )
                    .append_repeated_bytes::<Vec<u8>>(5, &[]) // funds
                    .into_vec()
                    .into();

                #[allow(deprecated)]
                CosmosMsg::Stargate {
                    type_url: COSMOS_AUTHZ_GRANT.to_string(),
                    value: msg,
                }
            })
            .collect();
        Ok(msgs)
    }

    pub fn form_add_headstashes_msgs(
        sender: String,
        headstash: String,
        to_add: &Vec<Headstash>,
    ) -> Result<CosmosMsg, ContractError> {
        let msg = crate::state::headstash::ExecuteMsg::AddEligibleHeadStash {
            headstash: to_add.to_vec(),
        };
        Ok(
            #[allow(deprecated)]
            CosmosMsg::Stargate {
                type_url: SECRET_COMPUTE_EXECUTE.into(),
                value: anybuf::Anybuf::new()
                    .append_string(1, sender.to_string()) // sender (DAO)
                    .append_string(2, &headstash.to_string()) // contract
                    .append_bytes(3, to_json_binary(&msg)?.as_slice())
                    .into_vec()
                    .into(),
            },
        )
    }

    pub fn form_authorize_headsdtash_as_snip120u_minter_msg(
        sender: String,
        headstash: String,
        snip120u: String,
    ) -> Result<CosmosMsg, ContractError> {
        let set_minter_msg = AddMintersMsg {
            minters: vec![headstash.clone()],
            padding: None,
        };
        Ok(
            // proto ref: https://github.com/scrtlabs/SecretNetwork/blob/master/proto/secret/compute/v1beta1/msg.proto
            #[allow(deprecated)]
            CosmosMsg::Stargate {
                type_url: SECRET_COMPUTE_EXECUTE.into(),
                value: anybuf::Anybuf::new()
                    .append_string(1, sender.to_string()) // sender (ICA Addr)
                    .append_string(2, &snip120u.to_string()) // contract
                    .append_bytes(3, to_json_binary(&set_minter_msg)?.as_slice())
                    .into_vec()
                    .into(),
            },
        )
    }

    pub fn form_authorize_feegrant(
        sender: String,
        grantee: &String,
    ) -> Result<CosmosMsg, ContractError> {
        // proto ref: https://github.com/cosmos/cosmos-sdk/blob/main/x/feegrant/proto/cosmos/feegrant/v1beta1/feegrant.proto
        let token = Anybuf::new()
            .append_string(1, "uscrt")
            .append_string(2, Uint128::new(1_000_000u128).to_string());
        // basic feegrant
        let basic_allowance = Anybuf::new().append_repeated_message(1, &[token]);
        // FeeAllowanceI implementation
        let allowance = Anybuf::new()
            .append_string(1, COSMOS_GENERIC_FEEGRANT_ALLOWANCE)
            .append_message(2, &basic_allowance);
        Ok(
            // proto ref: https://github.com/cosmos/cosmos-sdk/blob/main/proto/cosmos/feegrant/v1beta1/feegrant.proto
            #[allow(deprecated)]
            CosmosMsg::Stargate {
                type_url: COSMOS_GENERIC_FEEGRANT_MSG.into(),
                value: Anybuf::new()
                    .append_string(1, sender.to_string()) // granter (DAO)
                    .append_string(2, &grantee.to_string()) // grantee
                    .append_message(3, &allowance)
                    .into_vec()
                    .into(),
            },
        )
    }

    pub fn form_fund_headstash_msg(
        sender: String,
        headstash_addr: &String,
        channel_id: String,
        coin: &Coin,
        timeout_timestamp: Timestamp,
    ) -> Result<CosmosMsg, ContractError> {
        let token = Anybuf::new()
            .append_string(1, coin.denom.to_string())
            .append_string(2, coin.amount.to_string());
        // https://github.com/cosmos/ibc-go/blob/main/proto/ibc/core/client/v1/client.proto#L50
        let timeout_height = Anybuf::new()
            .append_string(1, Uint64::zero().to_string())
            .append_string(2, Uint64::zero().to_string());
        Ok(
            // proto ref: https://github.com/cosmos/ibc-go/blob/main/proto/ibc/applications/transfer/v1/tx.proto#L28
            #[allow(deprecated)]
            CosmosMsg::Stargate {
                type_url: COSMOS_GENERIC_IBC_TRANSFER.into(),
                value: Anybuf::new()
                    .append_string(1, "transfer") // source_port
                    .append_string(2, channel_id) // source_channel
                    .append_message(3, &token)
                    .append_string(4, sender) // sender
                    .append_string(5, &headstash_addr) // reciever
                    .append_message(6, &timeout_height)
                    .append_string(7, timeout_timestamp.to_string()) // timeout_timestamp
                    .into_vec()
                    .into(),
            },
        )
    }
}

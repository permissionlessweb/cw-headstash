use anybuf::Anybuf;
use cosmwasm_std::{
    to_json_binary, Addr, Api, Binary, CosmosMsg, Deps, DepsMut, Env, MessageInfo, Reply, Response,
    StdError, StdResult, Storage, Uint128,
};
use polytone::handshake::voice;

use crate::{
    error::ContractError,
    msg::{HeadstashParams, HeadstashTokenParams},
    state::{
        headstash::{Headstash, Snip120u},
        HeadstashSeq, CW_GLOB, GRANTEE, HEADSTASH_PARAMS, HEADSTASH_SEQUENCE,
    },
};

pub mod constants {
    // Stargate (Any) type definitions
    pub const COSMWASM_STORE_CODE: &str = "/cosmwasm.wasm.v1.MsgStoreCode";
    pub const COSMWASM_INSTANTIATE: &str = "/cosmwasm.wasm.v1.MsgInstantiateContract";
    pub const COSMWASM_EXECUTE: &str = "/cosmwasm.wasm.v1.MsgExecuteContract";
    pub const COSMOS_GENERIC_AUTHZ: &str = "/cosmos.authz.v1beta1.GenericAuthorization";
    pub const COSMOS_AUTHZ_GRANT: &str = "/cosmos.authz.v1beta1.MsgGrant";
    pub const SECRET_COMPUTE_STORE_CODE: &str = "/secret.compute.v1beta1.MsgStoreCode";
    pub const SECRET_COMPUTE_INSTANTIATE: &str = "/secret.compute.v1beta1.MsgInstantiateContract";
    pub const SECRET_COMPUTE_EXECUTE: &str = "/secret.compute.v1beta1.MsgExecuteContract";
    pub const COSMOS_GENERIC_FEEGRANT_ALLOWANCE: &str = "/cosmos.feegrant.v1beta1.BasicAllowance";
    pub const COSMOS_GENERIC_FEEGRANT_MSG: &str = "/cosmos.feegrant.v1beta1.MsgGrantAllowance";

    pub const DEFAULT_TIMEOUT: u64 = 10000u64;
}
use constants::*;

use cosmos_sdk_proto::{
    cosmos::authz::v1beta1::{GenericAuthorization, Grant, MsgGrant},
    prost, Any,
};
use prost::Message;

pub fn set_cw_glob(
    storage: &mut dyn Storage,
    api: &dyn Api,
    info: &MessageInfo,
    cw_glob: &String,
) -> Result<Response, ContractError> {
    // cw_ownable::assert_owner(deps.storage, &info.sender)?;
    if let Some(_) = polytone::accounts::query_account(storage, info.sender.clone())? {
        HEADSTASH_PARAMS.update(storage, |mut a| {
            if a.cw_glob.is_none() {
                a.cw_glob = Some(api.addr_validate(&cw_glob)?)
            } else {
                return Err(ContractError::CwGlobExists {});
            }
            Ok(a)
        })?;
    } else {
        return Err(ContractError::NoPair {});
    };
    Ok(Response::new())
}

pub fn upload_contract_on_secret(
    storage: &mut dyn Storage,
    api: &dyn Api,
    info: &MessageInfo,
    key: &String,
    cw_glob: &Option<String>,
) -> Result<Response, ContractError> {
    if let Some(remote_addr) = polytone::accounts::query_account(storage, info.sender.clone())? {
        let glob = match cw_glob.clone() {
            Some(a) => api.addr_validate(&a)?,
            None => HEADSTASH_PARAMS
                .load(storage)?
                .cw_glob
                .expect("no cw-glob. Either set one, or provide one."),
        };

        match key.as_str() {
            "snip120u" => {
                if HEADSTASH_SEQUENCE.load(storage, HeadstashSeq::UploadSnip.into())? {
                    return Err(ContractError::Std(StdError::generic_err(
                        "already have set snip120u code-id",
                    )));
                }
            }
            "cw-headstash" => {
                if !HEADSTASH_SEQUENCE.load(storage, HeadstashSeq::UploadSnip.into())? {
                    return Err(ContractError::Std(StdError::generic_err(
                        "must upload snip120u first",
                    )));
                } else if HEADSTASH_SEQUENCE.load(storage, HeadstashSeq::UploadHeadstash.into())? {
                    return Err(ContractError::Std(StdError::generic_err(
                        "already have set headstash code-id",
                    )));
                };
            }

            _ => return Err(ContractError::BadContractId {}),
        }

        let wasm_blob = Binary(vec![]);
        // msg to trigger ica-controller grabbing the wasm blob
        let upload_msg = headstash_anybuf::form_upload_contract_on_secret(remote_addr, wasm_blob)?;
    } else {
        return Err(ContractError::NoPair {});
    }
    Ok(Response::new())
}

pub fn set_snip120u_code_id_on_secret(
    storage: &mut dyn Storage,
    api: &dyn Api,
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
    api: &dyn Api,
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
    api: &dyn Api,
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
    api: &dyn Api,
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
    api: &dyn Api,
    info: &MessageInfo,
) -> Result<Response, ContractError> {
    let mut msgs = vec![];
    if let Some(remote_account) = polytone::accounts::query_account(storage, info.sender.clone())? {
        let mut hp = HEADSTASH_PARAMS.load(storage)?;

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
                if let Some(t) = hp.token_params.iter().find(|t| t.native == token.native) {
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
    Ok(Response::new().add_messages(msgs))
}

pub fn create_headstash_contract(
    env: &Env,
    storage: &mut dyn Storage,
    api: &dyn Api,
    info: &MessageInfo,
) -> Result<Response, ContractError> {
    let mut msgs = vec![];
    if let Some(remote_account) = polytone::accounts::query_account(storage, info.sender.clone())? {
        let mut hp = HEADSTASH_PARAMS.load(storage)?;

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
                crate::state::headstash::InstantiateMsg {
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

    Ok(Response::new().add_messages(msgs))
}

pub fn authorize_headstash_as_snip_minter(
    storage: &mut dyn Storage,
    api: &dyn Api,
    info: &MessageInfo,
) -> Result<Response, ContractError> {
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
    Ok(Response::new())
}

pub fn add_headstash_claimers(
    storage: &mut dyn Storage,
    api: &dyn Api,
    to_add: &Vec<Headstash>,
    info: &MessageInfo,
) -> Result<Response, ContractError> {
    let mut msgs = vec![];
    if let Some(remote_account) = polytone::accounts::query_account(storage, info.sender.clone())? {
        let mut hp = HEADSTASH_PARAMS.load(storage)?;
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
    Ok(Response::new())
}

pub fn authorize_feegrants(
    storage: &mut dyn Storage,
    api: &dyn Api,
    info: &MessageInfo,
    to_grant: &Vec<String>,
) -> Result<Response, ContractError> {
    let mut msgs = vec![];
    if let Some(remote_account) = polytone::accounts::query_account(storage, info.sender.clone())? {
        let mut hp = HEADSTASH_PARAMS.load(storage)?;
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
    Ok(Response::new().add_messages(msgs))
}

pub fn grant_authz_for_deployer(
    storage: &mut dyn Storage,
    api: &dyn Api,
    info: &MessageInfo,
    grantee: &String,
) -> Result<Response, ContractError> {
    let mut msgs = vec![];
    if let Some(remote_account) = polytone::accounts::query_account(storage, info.sender.clone())? {
        if GRANTEE.may_load(storage)?.is_some() {
            return Err(ContractError::AuthzGranteeExists {});
        }

        let mut hp = HEADSTASH_PARAMS.load(storage)?;

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
    Ok(Response::new().add_messages(msgs))
}

pub fn fund_headstash(storage: &mut dyn Storage, api: &dyn Api) -> Result<Response, ContractError> {
    Ok(Response::new())
}

pub mod callbacks {

    use super::*;
}
pub mod headstash_anybuf {
    use super::*;
    use crate::state::{headstash::Headstash, CW_GLOB};

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
        let init_msg = crate::state::snip120u::InstantiateMsg {
            name: "Terp Network SNIP120U - ".to_owned() + coin.name.as_str(),
            admin: headstash,
            symbol,
            decimals: 6u8,
            initial_balances: None,
            prng_seed: Binary(
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
        scrt_headstash_msg: crate::state::headstash::InstantiateMsg,
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
                        3,                                                       // grant
                        Binary(grant.grant.expect("grant set").encode_to_vec()), // cw-ica SendCosmosMsgs
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
        let set_minter_msg = crate::state::snip120u::AddMintersMsg {
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
            .append_string(2, Uint128::one().to_string());
        // basic feegrant
        let basic_allowance = Anybuf::new().append_repeated_message(1, &[token]);
        // FeeAllowanceI implementation
        let allowance = Anybuf::new()
            .append_string(1, COSMOS_GENERIC_FEEGRANT_ALLOWANCE)
            .append_message(2, &basic_allowance);
        Ok(
            // proto ref: https://github.com/cosmos/cosmos-sdk/blob/main/x/feegrant/proto/cosmos/feegrant/v1beta1/tx.proto
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
}

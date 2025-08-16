use crate::callbacks::CallbackRequest;
use crate::headstash::errors::ContractError;
use cosmwasm_std::{
    to_json_binary, Addr, Binary, Coin, CosmosMsg, Empty, MessageInfo, QuerierWrapper, StdError, Storage, Timestamp, Uint128,
};

use cw_storage_plus::{Item, Map};
use headstash_public::state::{Headstash, HeadstashParams};
use headstash_public::state::{InstantiateMsg as HsInstantiateMsg, Snip120u, GLOB_HEADSTASH_KEY};

pub const HEADSTASH_SEQUENCE: Map<String, bool> = Map::new("hsseq");
pub const HEADSTASH_PARAMS: Item<HeadstashParams> = Item::new("hp");
pub const GRANTEE: Item<String> = Item::new("grantee");

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
    pub const COSMOS_GENERIC_IBC_TRANSFER: &str = "/ibc.applications.transfer.v1.MsgTransfer";

    pub const DEFAULT_TIMEOUT: u64 = 10000u64;
}

/// Objects used to specify how to parse SubMsgResponses of successful cross chain calls.
#[cosmwasm_schema::cw_serde]
pub enum HeadstashCallback {
    UploadedHeadstashCodeId { code_id: u64 },
    CreatedHeadstashContractAddr { addr: String },
    CreatedSnip20ContractAddr { addr: String },
    ConfiguredSnip120uMinter { minter: String },
    AddedHeadstashes { headstashers: Vec<Headstash> },
    AuthorizeFeeGrants {},
    AuthzDeployer {},
    FundedHeadstash { coins: Vec<Coin> },
    GenericMsg { msgs: Vec<CosmosMsg> },
}

impl HeadstashCallback {
    pub fn into_headstash_msg(
        &self,
        info: &MessageInfo,
        storage: &mut dyn Storage,
    ) -> Result<Vec<CosmosMsg<Empty>>, ContractError> {
        Ok(match self {
            HeadstashCallback::UploadedHeadstashCodeId { code_id } => {
                set_headstash_code_id_on_secret(storage, info, code_id)?
            }
            HeadstashCallback::CreatedHeadstashContractAddr { addr } => {
                set_headstash_addr(storage, info, addr)?
            }
            HeadstashCallback::CreatedSnip20ContractAddr { addr } => {
                set_snip120u_addr(storage, addr)?
            }
            HeadstashCallback::ConfiguredSnip120uMinter { minter } => {
                authorize_headstash_as_snip_minter(storage, info)?
            }
            HeadstashCallback::AddedHeadstashes { headstashers } => vec![],
            HeadstashCallback::AuthorizeFeeGrants {} => vec![],
            HeadstashCallback::AuthzDeployer {} => vec![],
            HeadstashCallback::FundedHeadstash { coins } => vec![],
            HeadstashCallback::GenericMsg { msgs } => msgs.to_vec(),
        })
    }

    pub fn into_callback_request(&self, addr: String) -> Result<CallbackRequest, StdError> {
        Ok(CallbackRequest {
            receiver: addr,
            msg: to_json_binary(&self)?,
            headstash_digits: self.callback_digits(),
        })
    }

    // Assign a unique u64 ID to each variant
    pub const fn callback_digits(&self) -> u32 {
        match self {
            HeadstashCallback::UploadedHeadstashCodeId { .. } => 101,
            HeadstashCallback::CreatedSnip20ContractAddr { .. } => 202,
            HeadstashCallback::CreatedHeadstashContractAddr { .. } => 303,
            HeadstashCallback::ConfiguredSnip120uMinter { .. } => 404,
            HeadstashCallback::AddedHeadstashes { .. } => 505,
            HeadstashCallback::AuthorizeFeeGrants {} => 606,
            HeadstashCallback::AuthzDeployer {} => 707,
            HeadstashCallback::FundedHeadstash { .. } => 808,
            HeadstashCallback::GenericMsg { msgs } => 909,
        }
    }
}

use anybuf::Anybuf;
use cosmos_sdk_proto::{
    cosmos::authz::v1beta1::{GenericAuthorization, Grant, MsgGrant},
    prost, Any,
};

use constants::*;
use prost::Message;

pub fn upload_contract_on_secret(
    querier: QuerierWrapper,
    storage: &mut dyn Storage,
    info: &MessageInfo,
) -> Result<CosmosMsg, ContractError> {
    if let Some(remote_addr) = crate::accounts::query_account(storage, info.sender.clone())? {
        let glob = HEADSTASH_PARAMS.load(storage)?.cw_glob;
        if HEADSTASH_SEQUENCE.load(storage, HeadstashSeq::UploadHeadstash.into())? {
            return Err(ContractError::Std(StdError::generic_err(
                "already have set headstash code-id",
            )));
        };

        // headstash key
        let storage_key = Binary::from_base64(GLOB_HEADSTASH_KEY)?;
        let wasm_blob = match querier.query_wasm_raw(glob, storage_key)? {
            Some(b) => Binary::new(b),
            None => return Err(ContractError::NoPair {}),
        };

        Ok(headstash_anybuf::form_upload_contract_on_secret(
            remote_addr,
            wasm_blob,
        )?)
    } else {
        Err(ContractError::NoPair {})
    }
}

// pub fn set_snip120u_code_id_on_secret(
//     storage: &mut dyn Storage,
//     info: &MessageInfo,
//     code_id: u64,
// ) -> Result<Response, ContractError> {
//     if let Some(_) = crate::accounts::query_account(storage, info.sender.clone())? {
//         let mut state = HEADSTASH_PARAMS.load(storage)?;
//         state.snip120u_code_id = code_id;

//         HEADSTASH_PARAMS.save(storage, &state)?;
//     } else {
//         return Err(ContractError::NoPair {});
//     }
//     Ok(Response::new())
// }

pub fn set_headstash_code_id_on_secret(
    storage: &mut dyn Storage,
    info: &MessageInfo,
    code_id: &u64,
) -> Result<Vec<CosmosMsg>, ContractError> {
    if let Some(_) = crate::accounts::query_account(storage, info.sender.clone())? {
        let mut state = HEADSTASH_PARAMS.load(storage)?;
        let HeadstashParams {
            headstash_code_id, ..
        } = state;
        if headstash_code_id.is_some() {
            return Err(ContractError::SetSnip120uCodeError {});
        } else {
            state.headstash_code_id = Some(*code_id);
            HEADSTASH_SEQUENCE.save(storage, HeadstashSeq::UploadHeadstash.into(), &true)?;
            HEADSTASH_PARAMS.save(storage, &state)?;
        }
    } else {
        return Err(ContractError::NoPair {});
    }
    Ok(vec![])
}

pub fn set_headstash_addr(
    storage: &mut dyn Storage,
    info: &MessageInfo,
    to_add: &String,
) -> Result<Vec<CosmosMsg>, ContractError> {
    if let Some(_) = crate::accounts::query_account(storage, info.sender.clone())? {
        let mut state = HEADSTASH_PARAMS.load(storage)?;

        // ensure snip & headstash code-id upload sequence is set
        let HeadstashParams {
            headstash_addr,
            headstash_code_id,
            ..
        } = state;
        if headstash_code_id.is_none() || headstash_addr.is_some() {
            return Err(ContractError::SetHeadstashAddrError {});
        } else {
            state.headstash_addr = Some(to_add.into());
        }

        HEADSTASH_SEQUENCE.save(storage, HeadstashSeq::InitHeadstash.into(), &true)?;
        HEADSTASH_PARAMS.save(storage, &state)?;
    } 
    Ok(vec![])
}

// each instantiate msg has its own callback, so we provide ont at a time.
// TODO: cache addrs un
pub fn set_snip120u_addr(
    storage: &mut dyn Storage,
    contract_addr: &String,
) -> Result<Vec<CosmosMsg>, ContractError> {
    let mut state = HEADSTASH_PARAMS.load(storage)?;
    let len = state.token_params.len();

    // Ensure headstash_code_id is set
    if state.headstash_code_id.is_none() {
        return Err(ContractError::SetInitSnip120uError {});
    }

    // Find the token and its index
    let (index, token_param) = state
        .token_params
        .iter_mut()
        .enumerate()
        .find(|(_, p)| p.snip_addr.is_none())
        .ok_or(ContractError::NoSnip120uContract {})?;

    if token_param.snip_addr.is_some() {
        return Err(ContractError::Snip120uAddrAlreadySet {});
    }

    // opt: ensure sub index from # of tokens in headstash does not error.

    if len.checked_sub(index).is_none() {
        return Err(ContractError::Std(StdError::generic_err(
            "should never have more than expected",
        )));
    };

    token_param.snip_addr = Some(contract_addr.clone());
    HEADSTASH_SEQUENCE.save(storage, HeadstashSeq::InitSnips.indexed_snip(index), &true)?;

    HEADSTASH_PARAMS.save(storage, &state)?;

    Ok(vec![])
}

pub fn create_snip120u_contract(
    storage: &mut dyn Storage,
    info: &MessageInfo,
) -> Result<Vec<CosmosMsg>, ContractError> {
    let mut msgs = vec![];
    if let Some(remote_account) = crate::accounts::query_account(storage, info.sender.clone())? {
        let hp = HEADSTASH_PARAMS.load(storage)?;

        // if headstash isnt uploaded, lets first do that.
        if !HEADSTASH_SEQUENCE.load(storage, HeadstashSeq::UploadHeadstash.into())?
            && hp.headstash_code_id.is_none()
        {
            return Err(ContractError::NoHeadstashCodeId {});
        }
        // define CosmosMsg for each snip120u
        for token in &hp.token_params {
            if !hp.token_params.is_empty() {
                if let Some(t) = hp
                    .token_params
                    .iter()
                    .find(|t| t.native == token.native && t.snip_addr.is_none())
                {
                    let msg = headstash_anybuf::form_instantiate_snip120u(
                        remote_account.to_string(),
                        token.clone(),
                        hp.snip120u_code_hash.clone(),
                        hp.snip120u_code_id,
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
    storage: &mut dyn Storage,
    info: &MessageInfo,
) -> Result<Vec<CosmosMsg>, ContractError> {
    let mut msgs = vec![];
    if let Some(remote_account) = crate::accounts::query_account(storage, info.sender.clone())? {
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
                    end_date: hp.headstash_init_config.end_date,
                    start_date: hp.headstash_init_config.end_date,
                    random_key: hp.headstash_init_config.random_key,
                    owner: Addr::unchecked(remote_account.clone()), // remote proxy account
                    snip120u_code_hash: hp.snip120u_code_hash,
                    snips: hs_snips,
                    multiplier: hp.multiplier,
                    bloom_config: hp.bloom_config,
                },
            )?;
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
    if let Some(remote_account) = crate::accounts::query_account(storage, info.sender.clone())? {
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
    if let Some(remote_account) = crate::accounts::query_account(storage, info.sender.clone())? {
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
    if let Some(remote_account) = crate::accounts::query_account(storage, info.sender.clone())? {
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
    if let Some(remote_account) = crate::accounts::query_account(storage, info.sender.clone())? {
        if GRANTEE.may_load(storage)?.is_some() {
            return Err(ContractError::AuthzGranteeExists {});
        }

        // let hp = HEADSTASH_PARAMS.load(storage)?;

        let grant_msgs: Vec<MsgGrant> = vec![
            SECRET_COMPUTE_STORE_CODE,
            SECRET_COMPUTE_INSTANTIATE,
            SECRET_COMPUTE_STORE_CODE,
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
    if crate::accounts::query_account(storage, sender.clone())?.is_none() {
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

    msgs}

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
                    .append_string(1, &remote_addr) // sender (ICA Address)
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
                    .append_string(1, &sender) // sender (ICA Address)
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
                    .append_string(1, remote_account) // remote proxy
                    .append_uint64(3, code_id) // code-id of snip-120u
                    .append_string(
                        4,
                        "Secret-Headstash Airdrop Contract: Terp Network ",
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
        let msg = ExecuteMsg::AddEligibleHeadStash {
            headstash: to_add.to_vec(),
        };
        Ok(
            #[allow(deprecated)]
            CosmosMsg::Stargate {
                type_url: SECRET_COMPUTE_EXECUTE.into(),
                value: anybuf::Anybuf::new()
                    .append_string(1, &sender) // sender (DAO)
                    .append_string(2, &headstash) // contract
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
                    .append_string(1, &sender) // sender (ICA Addr)
                    .append_string(2, &snip120u) // contract
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
                type_url: COSMOS_GENERIC_FEEGRANT_ALLOWANCE.into(),
                value: Anybuf::new()
                    .append_string(1, &sender) // granter (DAO)
                    .append_string(2, grantee) // grantee
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
            .append_string(1, &coin.denom)
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
                    .append_string(5, headstash_addr) // reciever
                    .append_message(6, &timeout_height)
                    .append_string(7, timeout_timestamp.to_string()) // timeout_timestamp
                    .into_vec()
                    .into(),
            },
        )
    }
}

#[cosmwasm_schema::cw_serde]
/// The sequence of minimum # of steps in a headstash deployment workflow, for determinism in response
pub enum HeadstashSeq {
    UploadSnip,
    UploadHeadstash,
    InitSnips,
    InitHeadstash,
}

impl From<HeadstashSeq> for String {
    fn from(ds: HeadstashSeq) -> Self {
        match ds {
            HeadstashSeq::UploadSnip => "snip120u".to_string(),
            HeadstashSeq::UploadHeadstash => "cw-headstash".to_string(),
            HeadstashSeq::InitSnips => "snip120u-init-".to_string(),
            HeadstashSeq::InitHeadstash => "cw-headstash-init".to_string(),
        }
    }
}
impl HeadstashSeq {
    pub fn indexed_snip(&self, i: usize) -> String {
        match self {
            HeadstashSeq::InitSnips => format!("snip120u-init-{}", i),
            _ => panic!("Invalid HeadstashSequence formatted_str value"),
        }
    }
}

#[cosmwasm_schema::cw_serde]
pub enum ExecuteMsg {
    AddEligibleHeadStash { headstash: Vec<Headstash> },
}

pub mod errors {
    use cosmwasm_std::StdError;
    use thiserror::Error;

    #[derive(Error, Debug, PartialEq)]
    pub enum ContractError {
        #[error(transparent)]
        Std(#[from] StdError),

        #[error(transparent)]
        Handshake(#[from] crate::handshake::error::HandshakeError),

        #[error("contract is already paired with port ({pair_port}) on connection ({pair_connection}), got port ({suggested_port}) on connection ({suggested_connection})")]
        AlreadyPaired {
            suggested_connection: String,
            suggested_port: String,
            pair_connection: String,
            pair_port: String,
        },

        #[error("contract has no pair, establish a channel with a voice module to create one")]
        NoPair,

        #[error("ERR_GAS_NEEDED can't be higher then BLOCK_MAX_GAS")]
        GasLimitsMismatch,

        #[error("channel sequence number overflow, to fix: the contract admin may migrate to close and reopen the channel")]
        SequenceOverflow,

        #[error("CwGlobExists")]
        CwGlobExists {},

        #[error("NoSnip120uParamsSet")]
        NoSnip120uParamsSet {},

        #[error("SetSnip120uCodeError")]
        SetSnip120uCodeError {},

        #[error("SetHeadstashCodeError")]
        SetHeadstashCodeError {},

        #[error("SetHeadstashAddrError.")]
        SetHeadstashAddrError {},

        #[error("SetInitSnip120uError.")]
        SetInitSnip120uError {},

        #[error("Snip120uAddrAlreadySet")]
        Snip120uAddrAlreadySet {},

        #[error("snip code-id not set")]
        NoSnipCodeId {},

        #[error("headstash code-id not set.")]
        NoHeadstashCodeId {},

        #[error("NoSnip120uContract")]
        NoSnip120uContract {},

        #[error("snip token not set")]
        NoSnipContractAddr {},

        #[error("BadContractId")]
        BadContractId {},

        #[error("AuthzGranteeExists")]
        AuthzGranteeExists {},

        #[error("headstash contract addr not set.")]
        NoHeadstashContract {},

        #[error("not a valid feegranter address")]
        NotValidFeegranter {},

        #[error("Unauthorized")]
        Unauthorized {},
    }
}

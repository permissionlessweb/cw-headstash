use cosmwasm_std::{to_json_binary, Binary, Coin, CosmosMsg, Empty, StdError, Storage};
use cw_storage_plus::{Item, Map};
use headstash_public::state::{Headstash, HeadstashParams};

use crate::callbacks::CallbackRequest;

pub const HEADSTASH_SEQUENCE: Map<String, bool> = Map::new("hsseq");
pub const HEADSTASH_PARAMS: Item<HeadstashParams> = Item::new("hp");

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
    CreatedSnip20ContractAddrs { addrs: Vec<String> },
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
        storage: &mut dyn Storage,
    ) -> Result<Vec<CosmosMsg<Empty>>, StdError> {
        let mut msgs = vec![];

        match self {
            HeadstashCallback::UploadedHeadstashCodeId { code_id } => {}
            HeadstashCallback::CreatedHeadstashContractAddr { addr } => {}
            HeadstashCallback::CreatedSnip20ContractAddrs { addrs } => {}
            HeadstashCallback::ConfiguredSnip120uMinter { minter } => {}
            HeadstashCallback::AddedHeadstashes { headstashers } => {}
            HeadstashCallback::AuthorizeFeeGrants {} => {}
            HeadstashCallback::AuthzDeployer {} => {}
            HeadstashCallback::FundedHeadstash { coins } => {}
            HeadstashCallback::GenericMsg { msgs } => {}
        }
        Ok(msgs)
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
            HeadstashCallback::CreatedSnip20ContractAddrs { .. } => 202,
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

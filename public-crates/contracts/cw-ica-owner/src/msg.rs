use cosmwasm_schema::{cw_serde, QueryResponses};
use cw_ica_controller::{
    helpers::ica_callback_execute, types::msg::options::ChannelOpenInitOptions,
};

use crate::state::headstash::{Headstash, HeadstashParams};

#[cw_serde]
pub struct InstantiateMsg {
    /// Owner of this contract, and any ICA account created by this contract.
    pub owner: Option<String>,
    /// Eligible address able to authorize feegrants on behalf of the ICA.
    pub feegranter: Option<String>,
    /// Code-id off the cw-ica-controller contract
    pub ica_controller_code_id: u64,
    /// Parameters for the cw-headstash contract
    pub headstash_params: HeadstashParams,
}

#[ica_callback_execute]
#[cw_ownable::cw_ownable_execute]
#[cw_serde]
pub enum ExecuteMsg {
    CreateIcaContract {
        salt: Option<String>,
        channel_open_init_options: ChannelOpenInitOptions,
        /// If none is set, loads headstash params from contract state.
        headstash_params: Option<HeadstashParams>,
        /// Contract addr of cw-glob
        cw_glob: String,
    },
    /// 1. Upload the following contracts:
    /// a. Headstash
    /// b. Snip120u
    /// c. Headstash Circuitboard
    UploadContractOnSecret {
        /// The ICA ID.
        ica_id: u64,
        /// The wasm blob name to upload
        wasm: String,
    },
    /// 2. Instantiate a snip120u contract for every token defined in tokens.
    InitSnip120u {
        /// The ICA ID.
        ica_id: u64,
    },
    // /// 3. Instantiates the secret headstash contract on Secret Network.
    InitHeadstash {
        /// The ICA ID.
        ica_id: u64,
        // /// Timestamp seconds of when headstash can begin
        // start_date: u64,
    },
    // /// 4. Authorized the headstash contract as a minter for both snip120u contracts.
    AuthorizeMinter {
        ica_id: u64,
    },
    // /// . Transfer each token included in msg over via ics20.
    IBCTransferTokens {
        ica_id: u64,
        channel_id: String,
    },
    // /// 8. Add Eligible Addresses To Headstash
    AddHeadstashClaimers {
        ica_id: u64,
        to_add: Vec<Headstash>,
    },
    // /// 9. Authorize secret network wallet with feegrant
    AuthorizeFeegrant {
        ica_id: u64,
        to_grant: Vec<String>,
        owner: Option<String>,
    },
}
#[cw_serde]
pub enum SudoMsg {
    HandleIbcBloom {},
}

#[cw_ownable::cw_ownable_query]
#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    /// GetContractState returns the contact's state.
    #[returns(crate::state::ContractState)]
    GetContractState {},
    /// GetIcaState returns the ICA state for the given ICA ID.
    #[returns(crate::state::IcaContractState)]
    GetIcaContractState { ica_id: u64 },
    /// GetIcaCount returns the number of ICAs.
    #[returns(u64)]
    GetIcaCount {},
}

#[cw_serde]
pub enum HeadstashCallback {
    UploadHeadstash,
    UploadSnip120u,
    InstantiateHeadstash,
    InstantiateSnip120us,
    SetHeadstashAsSnipMinter,
    AddHeadstashers,
    AuthorizeFeeGrants,
    FundHeadstash,
}

impl From<HeadstashCallback> for String {
    fn from(callback: HeadstashCallback) -> Self {
        match callback {
            HeadstashCallback::UploadHeadstash => "upload_headstash".to_string(),
            HeadstashCallback::UploadSnip120u => "upload_snip120u".to_string(),
            HeadstashCallback::InstantiateHeadstash => "instantiate_headstash".to_string(),
            HeadstashCallback::InstantiateSnip120us => "instantiate_snip120us".to_string(),
            HeadstashCallback::SetHeadstashAsSnipMinter => {
                "set_headstash_as_snip_minter".to_string()
            }
            HeadstashCallback::AddHeadstashers => "add_headstashers".to_string(),
            HeadstashCallback::AuthorizeFeeGrants => "authorize_fee_grants".to_string(),
            HeadstashCallback::FundHeadstash => "fund_headstash".to_string(),
        }
    }
}

impl From<String> for HeadstashCallback {
    fn from(s: String) -> Self {
        match s.as_str() {
            "upload_headstash" => HeadstashCallback::UploadHeadstash,
            "upload_snip120u" => HeadstashCallback::UploadSnip120u,
            "instantiate_headstash" => HeadstashCallback::InstantiateHeadstash,
            "instantiate_snip120us" => HeadstashCallback::InstantiateSnip120us,
            "set_headstash_as_snip_minter" => HeadstashCallback::SetHeadstashAsSnipMinter,
            "add_headstashers" => HeadstashCallback::AddHeadstashers,
            "authorize_fee_grants" => HeadstashCallback::AuthorizeFeeGrants,
            _ => panic!("Invalid HeadstashCallback value"),
        }
    }
}

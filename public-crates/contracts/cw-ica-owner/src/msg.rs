use cosmwasm_schema::{cw_serde, QueryResponses};
use cw_ica_controller::{
    helpers::ica_callback_execute, types::msg::options::ChannelOpenInitOptions,
};
use headstash_public::state::{Headstash, HeadstashParams};

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
    /// Creates the ica-controller & initiates the ica creation workflow
    CreateIcaContract {
        salt: Option<String>,
        channel_open_init_options: ChannelOpenInitOptions,
        /// If none is set, loads headstash params from contract state.
        headstash_params: Option<HeadstashParams>,
    },
    /// Sets the cw-glob contract address to GLOBAL_CONTRACT_STATE
    // SetCwGlob {
    //     /// The storage key set in cw-glob. defaults enabled are either `snip120u` or `cw-headstash`
    //     cw_glob: String,
    // },
    /// 1. Upload the following contracts in the expected sequence:
    /// a. snip120u
    /// b. cw-headstash
    UploadContractOnSecret {
        /// Optional contract address of the cw-glob.
        cw_glob: Option<String>,
        /// The wasm blob name to upload
        wasm: String,
    },
    /// 2. Instantiate a snip120u contract for every token defined in tokens.
    InitSnip120u {},
    /// 3. Instantiates the secret headstash contract on Secret Network.
    InitHeadstash {},
    /// 4. Authorized the headstash contract as a minter for both snip120u contracts.
    AuthorizeHeadstashAsSnipMinter {},
    /// . Transfer each token included in msg over via ics20.
    IbcTransferTokens {
        channel_id: String,
    },
    /// 8. Add Eligible Addresses To Headstash
    AddHeadstashClaimers {
        to_add: Vec<Headstash>,
    },
    /// 9. Authorize secret network wallet with feegrant
    AuthorizeFeegrant {
        to_grant: Vec<String>,
        owner: Option<String>,
    },
    /// 10. Grant authorization to perform actions on behalf of ica-addr
    AuthzDeployer {
        grantee: String,
    },
    // Admin feature to manually set code-id for cw-headstash on Secret.
    SetHeadstashCodeId {
        code_id: u64,
    },
    // Admin feature to manually set code-id for snip120u on Secret.
    SetSnip120uCodeId {
        code_id: u64,
    },
    // Admin feature to manually set contract-addr for cw-headstash on Secret.
    SetHeadstashAddr {
        addr: String,
    },
    // Admin feature to manually set contract-addr for snip120u on Secret.
    SetSnip120uAddr {
        /// token denomination representing snip
        denom: String,
        /// contract addr of snip
        addr: String,
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
    #[returns(String)]
    GetDeploymentState {},
    /// GetIcaState returns the ICA state for the given ICA ID.
    #[returns(crate::state::IcaContractState)]
    GetIcaContractState {},
    #[returns(String)]
    AuthzGrantee {},
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
}

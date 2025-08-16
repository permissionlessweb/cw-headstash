use cosmwasm_schema::cw_serde;
use cosmwasm_std::Addr;
use cw_storage_plus::{Item, Map};

pub use contract::ContractState;
use headstash_public::state::HeadstashParams;
pub use ica::{IcaContractState, IcaState};

/// upload wasm submessage eply id
pub const UPLOAD_REPLY_ID: u64 = 710;

/// The Map used to determine how to handle ica-callbacks.
/// key: snip120u = first action to take. if false, all other prefixes should fail
/// key: cw-headstash = second action to take. if false, cannot init snips.
/// key: snip120u-init-(len()) = third action to take. if false, cannot init headstash.
///      key defined with enumerated object position for each snip.
/// key: cw-headstash-init = fourth action to take.
pub const DEPLOYMENT_SEQUENCE: Map<String, bool> = Map::new("uploaded");
/// The item used to store the state of the IBC application.
pub const GLOBAL_CONTRACT_STATE: Item<ContractState> = Item::new("state");
/// The map used to store the state of the cw-ica-controller contracts.
pub const ICA_STATES: Item<IcaContractState> = Item::new("icas");
/// The map used to store the state of the cw-ica-controller contracts.
pub const HEADSTASH_STATES: Map<u64, HeadstashParams> = Map::new("hsp");
/// The item used to store the count of the cw-ica-controller contracts.
pub const ICA_CREATED: Item<bool> = Item::new("ica");
/// The item used to map contract addresses to ICA IDs.
// pub const CONTRACT_ADDR_TO_ICA_ID: Map<Addr, u64> = Map::new("catia");

pub const GRANTEE: Item<String> = Item::new("grantee");

#[cw_serde]
pub enum DeploymentSeq {
    UploadHeadstash,
    InitSnips,
    InitHeadstash,
}

impl From<DeploymentSeq> for String {
    fn from(ds: DeploymentSeq) -> Self {
        match ds {
            DeploymentSeq::UploadHeadstash => "cw-headstash".to_string(),
            DeploymentSeq::InitSnips => "snip120u-init-".to_string(),
            DeploymentSeq::InitHeadstash => "cw-headstash-init".to_string(),
        }
    }
}
impl DeploymentSeq {
    pub fn indexed_snip(&self, i: usize) -> String {
        match self {
            DeploymentSeq::InitSnips => format!("snip120u-init-{}", i),
            _ => panic!("Invalid DeploymentSequence formatted_str value"),
        }
    }
}

mod contract {
    use super::*;

    /// ContractState is the state of the IBC application.
    #[cw_serde]
    pub struct ContractState {
        /// The code ID of the cw-ica-controller contract.
        pub ica_controller_code_id: u64,
        pub default_hs_params: HeadstashParams,
    }

    impl ContractState {
        /// Creates a new ContractState.
        pub fn new(ica_controller_code_id: u64, default_hs_params: HeadstashParams) -> Self {
            Self {
                ica_controller_code_id,
                default_hs_params,
            }
        }
    }
}

mod ica {
    use super::*;
    use cw_ica_controller::{ibc::types::metadata::TxEncoding, types::state::ChannelState};

    /// IcaContractState is the state of the cw-ica-controller contract.
    #[cw_serde]
    pub struct IcaContractState {
        pub contract_addr: Addr,
        pub ica_state: Option<IcaState>,
        pub headstash_params: HeadstashParams,
    }

    /// IcaState is the state of the ICA.
    #[cw_serde]
    pub struct IcaState {
        pub ica_addr: String,
        pub tx_encoding: TxEncoding,
        pub channel_state: ChannelState,
    }

    impl IcaContractState {
        /// Creates a new [`IcaContractState`].
        pub fn new(contract_addr: Addr, headstash_params: HeadstashParams) -> Self {
            Self {
                contract_addr,
                ica_state: None,
                headstash_params,
            }
        }
    }

    impl IcaState {
        /// Creates a new [`IcaState`].
        pub fn new(ica_addr: String, tx_encoding: TxEncoding, channel_state: ChannelState) -> Self {
            Self {
                ica_addr,
                tx_encoding,
                channel_state,
            }
        }
    }
}

pub mod snip120u {
    use super::*;
    use cosmwasm_std::{Binary, Uint128};
    #[cw_serde]
    pub struct InitialBalance {
        pub address: String,
        pub amount: Uint128,
    }

    #[cw_serde]
    pub struct InstantiateMsg {
        pub name: String,
        pub admin: Option<String>,
        pub symbol: String,
        pub decimals: u8,
        pub initial_balances: Option<Vec<InitialBalance>>,
        pub prng_seed: Binary,
        pub config: Option<InitConfig>,
        pub supported_denoms: Option<Vec<String>>,
    }

    #[cw_serde]
    pub struct AddMinters {
        pub minters: Vec<String>,
        pub padding: Option<String>,
    }
    /// This type represents optional configuration values which can be overridden.
    /// All values are optional and have defaults which are more private by default,
    /// but can be overridden if necessary
    #[cw_serde]
    pub struct InitConfig {
        /// Indicates whether the total supply is public or should be kept secret.
        /// default: False
        public_total_supply: Option<bool>,
        /// Indicates whether deposit functionality should be enabled
        /// default: False
        enable_deposit: Option<bool>,
        /// Indicates whether redeem functionality should be enabled
        /// default: False
        enable_redeem: Option<bool>,
        /// Indicates whether mint functionality should be enabled
        /// default: False
        enable_mint: Option<bool>,
        /// Indicates whether burn functionality should be enabled
        /// default: False
        enable_burn: Option<bool>,
        /// Indicated whether an admin can modify supported denoms
        /// default: False
        can_modify_denoms: Option<bool>,
    }
}

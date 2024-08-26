use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Binary, ContractInfo, Uint128};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::state::{Config, Headstash};

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
pub struct InstantiateMsg {
    pub admin: Addr,
    pub claim_msg_plaintext: String,
    pub end_date: Option<u64>,
    pub snip20_1: ContractInfo,
    pub snip20_2: Option<ContractInfo>,
    pub start_date: Option<u64>,
    pub total_amount: Uint128,
    pub viewing_key: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExecuteMsg {
    Add {
        headstash: Vec<Headstash>,
    },
    Claim {
        eth_pubkey: String,
        eth_sig: String,
        heady_wallet: String,
    },
    Clawback {},
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    Config {},
    Dates {},
    Clawback {},
}

#[cw_serde]
pub enum QueryAnswer {
    ConfigResponse {
        config: Config,
    },
    DatesResponse {
        start: u64,
        end: Option<u64>,
        // decay_start: Option<u64>,
        // decay_factor: Option<Uint128>
    },
    ClawbackResponse {
        bool: bool,
    },
}

mod snip {
    use super::*;

    #[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
    pub struct Snip25InitMsg {
        pub name: String,
        pub admin: Option<String>,
        pub symbol: String,
        pub decimals: u8,
        pub prng_seed: Binary,
        pub config: Option<InitConfig>,
        pub supported_denoms: Option<Vec<String>>,
    }

    #[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]

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

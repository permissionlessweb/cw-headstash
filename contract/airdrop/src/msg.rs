use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Binary, Uint128};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::state::{Config, Headstash};

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
pub struct Snip120u {
    pub token: String,
    pub name: String,
    pub addr: Option<Addr>,
    pub total_amount: Uint128,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
pub struct InstantiateMsg {
    /// owner of contract
    pub owner: Addr,
    /// {wallet}
    pub claim_msg_plaintext: String,
    /// optional date that once reached, will start headstash distribution event.
    pub start_date: Option<u64>,
    /// optional date that once reached, will end headstash distribution event.
    pub end_date: Option<u64>,
    /// code-id of custom snip20 contract for headstashes
    pub snip120u_code_id: u64,
    /// code hash of custom snip20 contract for headstashes
    pub snip120u_code_hash: String,
    /// A list of custom snip20-headstash contracts.
    /// This contract must be set as an authorized minter for each, or else this contract will not work.
    pub snips: Vec<Snip120u>,
    /// Contract addr of headstash circuitboard.
    pub circuitboard: String,
    /// viewing key permit.
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

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MigrateMsg {
    Migrate {},
    StdError {},
}

pub mod snip {
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

use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Binary, ContractInfo, Uint128};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::state::Config;

///
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
pub struct Headstash {
    pub eth_pubkey: String,
    pub amount: Uint128,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
pub struct InstantiateMsg {
    pub admin: Option<Addr>,
    pub claim_msg_plaintext: String,
    pub end_date: Option<u64>,
    pub merkle_root: Binary,
    pub snip20_1: ContractInfo,
    pub snip20_2: Option<ContractInfo>,
    pub start_date: Option<u64>,
    pub total_amount: Uint128,
    pub viewing_key: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExecuteMsg {
    Add { headstash: Vec<Headstash> },
    Claim { eth_pubkey: String, eth_sig: String },
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
    }
}

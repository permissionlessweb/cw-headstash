use cosmwasm_std::{Addr, Binary, ContractInfo, Uint128};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::state::Config;

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
pub struct InstantiateMsg {
    pub snip20_1: ContractInfo,
    pub snip20_2: Option<ContractInfo>,
    pub merkle_root: Binary,
    pub viewing_key: String,
    pub total_amount: Uint128,
    pub claim_msg_plaintext: String,
    pub admin: Option<Addr>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExecuteMsg {
    Claim {
        amount: Uint128,
        eth_pubkey: String,
        eth_sig: String,
        proof: Vec<String>,
    },
    Clawback {},
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    Config {},
}

// We define a custom struct for each query response
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
pub struct ConfigResponse {
    pub config: Config,
}

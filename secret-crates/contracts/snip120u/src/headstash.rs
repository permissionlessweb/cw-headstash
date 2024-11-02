use cosmwasm_std::{Addr, Uint128};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub struct AllowanceAction {
    pub spender: String,
    pub amount: Uint128,
    pub expiration: Option<u64>,
    pub memo: Option<String>,
    pub decoys: Option<Vec<Addr>>,
}

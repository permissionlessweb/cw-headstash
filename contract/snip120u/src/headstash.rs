use cosmwasm_std::{Addr, CosmosMsg, Uint128};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// params for delaying the mint of the
#[derive(Serialize, Debug, Deserialize, Clone, JsonSchema)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct BloomParams {
    /// Desired time for transaction to fully process
    pub cadance: u64,
}

#[derive(Serialize, Debug, Deserialize, Clone, JsonSchema)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct HeadstashMsg {
    /// Cosmos Message to pass to secret cw-ica-controler. Weilter to only allow only specific message for now, but will be able to extend support in future.
    pub msg: CosmosMsg,
    /// params regarding the custom snip20 unwrapping implementation.
    pub bloom_params: BloomParams,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub struct AllowanceAction {
    pub spender: String,
    pub amount: Uint128,
    pub expiration: Option<u64>,
    pub memo: Option<String>,
    pub decoys: Option<Vec<Addr>>,
}

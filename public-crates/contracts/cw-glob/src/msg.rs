use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::Binary;

#[cw_serde]
pub struct InstantiateMsg {
    pub owner: String,
}

#[cw_serde]
pub struct Glob {
    /// The key used to store the blob
    pub key: String,
    /// The wasm
    pub blob: Binary,
}

#[cw_serde]
pub enum ExecuteMsg {
    AddGlob {
        globs: Vec<Glob>,
    },
    TakeGlob {
        /// ica-account id for the cw-ica-owner
        id: u64,
        /// Address to include in the CosmosMsg with the wasm blob.
        /// For cw-headstash, this will be the ica account on the host chain.
        sender: String,
        /// The wasm blob key to upload.
        key: String,
    },
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {}

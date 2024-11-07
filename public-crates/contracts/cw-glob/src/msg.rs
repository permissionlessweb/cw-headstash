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
        /// Address to include in the CosmosMsg with the wasm blob.
        /// For cw-headstash, this will be the ica account on the host chain.
        sender: String,
        /// The wasm blob key to upload.
        key: String,
        /// Optional memo to pass in ica-account
        memo: Option<String>,
     /// Optional timeout in seconds to include with the ibc packet.
        /// If not specified, the [default timeout](crate::ibc::types::packet::DEFAULT_TIMEOUT_SECONDS) is used.
        timeout: Option<u64>
    },
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {}

use cosmwasm_schema::{cw_serde, QueryResponses};

use crate::state::{Glob, GlobHash};

#[cw_serde]
pub struct InstantiateMsg {
    pub owners: Vec<String>,
}

#[cw_serde]
pub enum ExecuteMsg {
    AddGlob {
        globs: Vec<Glob>,
    },
    HashGlob {
        /// glob to generate hash of.
        keys: Vec<String>,
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
        timeout: Option<u64>,
    },
}

#[derive(QueryResponses)]
#[cw_serde]
pub enum QueryMsg {
    /// Retrieves the sha256sum hash of stored globs
    #[returns(GlobHash)]
    GlobHash { keys: Vec<String> },
}

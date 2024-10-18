//! # Commands
//!
//! commands related to powering headstash deployment workflow
use anybuf::Anybuf;
use cosmwasm_std::{CosmosMsg, StdError};

/// Defines the msg to upload the nested wasm blobs.
pub fn upload_contract_msg(
    sender: ::cosmwasm_std::Addr,
    wasm: Vec<u8>,
) -> Result<CosmosMsg, StdError> {
    Ok(
        #[allow(deprecated)]
        CosmosMsg::Stargate {
            type_url: "/secret.compute.v1beta1.MsgStoreCode".into(),
            value: Anybuf::new()
                .append_string(1, sender.clone()) // sender (DAO)
                .append_bytes(2, &wasm) // updated binary of transfer msg.
                .into_vec()
                .into(),
        },
    )
}

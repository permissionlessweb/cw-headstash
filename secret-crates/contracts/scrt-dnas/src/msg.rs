// use cw_ica_controller_derive::ica_callback_execute;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::Binary;

use crate::state::{DefaultAuth, DnasAuth, DnasKeyObject};

#[cw_serde]
pub struct InstantiateMsg {
    /// public key expeccted to be used by the dnas api middleware for signing and authorizing actions.
    pub dnas_pubkey: String,
}
#[cw_serde]
pub enum ExecuteMsg {
    RegisterDnasApi { dnas: Vec<DnasKeyObject> },
}


#[cw_serde]
pub enum QueryMsg {
    DnasApiAddr {},
    /// authenticated query DnasApiAddr uses for retrieval of register api key values
    DnasApiEntrypoint {
        req: DnasAuth,
    },
}

#[cw_serde]
pub enum QueryAnswer {
    DnasApiAddr { addr: String },
    DnasApiEntrypointResponse { dnas_value: Binary },
}

pub mod addrs;
pub mod networks;

pub mod constants {
    // Stargate (Any) type definitions
    pub const COSMWASM_STORE_CODE: &str = "/cosmwasm.wasm.v1.MsgStoreCode";
    pub const COSMWASM_INSTANTIATE: &str = "/cosmwasm.wasm.v1.MsgInstantiateContract";
    pub const COSMWASM_EXECUTE: &str = "/cosmwasm.wasm.v1.MsgExecuteContract";
    pub const COSMOS_GENERIC_AUTHZ: &str = "/cosmos.authz.v1beta1.GenericAuthorization";
    pub const COSMOS_AUTHZ_GRANT: &str = "/cosmos.authz.v1beta1.MsgGrant";
    pub const SECRET_COMPUTE_STORE_CODE: &str = "/secret.compute.v1beta1.MsgStoreCode";
    pub const SECRET_COMPUTE_INSTANTIATE: &str = "/secret.compute.v1beta1.MsgInstantiateContract";
    pub const SECRET_COMPUTE_EXECUTE: &str = "/secret.compute.v1beta1.MsgExecuteContract";
}

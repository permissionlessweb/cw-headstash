use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Binary, Coin, StdResult};
use secret_toolkit::storage::Item;

pub const PREFIX_DNAS_STORE: &[u8] = b"dnas";
pub const PREFIX_DNAS_MIDDLEWARE_KEY: &[u8] = b"dnasmiddlewarekey";
pub const PREFIX_DNAS_KEY_VALUE: &[u8] = b"dnasapikeyvalue";
pub const PREFIX_DNAS_ACCOUNT_NONE: &[u8] = b"dnasaccnonce";
/// Public key used in middle ware db api associated with this contract
pub static MIDDLEWARE_PUBKEY: Item<Binary> = Item::new(PREFIX_DNAS_MIDDLEWARE_KEY);
// Binary value of the objects stored in the db
pub static DNAS_STORE: Item<Binary> = Item::new(PREFIX_DNAS_STORE);

pub static ACCOUNT_NONE: Item<u64> = Item::new(PREFIX_DNAS_ACCOUNT_NONE);
pub static API_KEY_RECORD: Item<DaoObject> = Item::new(PREFIX_DNAS_KEY_VALUE);
/// Keymap for storing API keys
pub static API_KEY_MAP: Item<Binary> = Item::new(PREFIX_DNAS_KEY_VALUE);

/// Called by dnas_pubkey address.
#[cw_serde]
pub struct DnasKeyObject {
    pub api_key_value: Binary,
    pub authentication: DnasAuth,
}
/// Called by dnas_pubkey address.
#[cw_serde]
pub struct DnasAuth {
    pub mw_auth: DefaultAuth,
    pub dm_auth: DefaultAuth,
}

#[cw_serde]
pub struct DefaultAuth {
    /// raw msg signed when middleware logic requires use of dnas keys (when a dao member is making use of middleware)
    pub msg: Binary,
    pub sig: Binary,
    pub pubkey: PubkeyObject,
}

#[cw_serde]
pub struct DaoMemberAuth {
    ///  `SignedDataDaoMember`
    pub data: Binary,
    ///  `Auth`
    pub auth: Binary,
}

#[cw_serde]
pub struct MiddlewareAuth {
    pub data: Binary,
}

#[cw_serde]
pub struct SignedDataDaoMember {
    pub keys: Vec<DaoMemberData>,
}

/// message siged by address using dnas profile widget. Entire message is passed for verification
#[cw_serde]
pub struct DaoMemberData {
    pub dao: String,
    pub mw_op_addr: String,
    pub scrt_dnas_addr: String,
    pub dnas: ProfileDnasKeyWithoutIds,
}

#[cw_serde]
pub struct MiddlewareData {
    pub dm_bech32_addr: String,
    pub nonce: u64,
}

#[cw_serde]
pub struct ProfileDnasKeyWithoutIds {
    storage_type: String,
    key_metadata: String,
    upload_limit: String,
    scrt_dnas: String,
    api_key_value: String,
}

#[cw_serde]
pub struct DmAuthSignDoc {
    pub chain_id: String,
    pub account_number: String,
    pub sequence: String,
    pub fee: StdFee,
    pub msgs: Vec<Binary>,
    pub memo: String,
    pub timeout_height: Option<String>,
}

#[cw_serde]
pub struct Auth {
    pub r#type: String,
    pub nonce: i64,
    pub chain_id: String,
    pub chain_fee_denom: String,
    pub chain_bech32_prefix: String,
    pub public_key_type: String,
    pub public_key_hex: String,
}

#[cw_serde]
pub struct MemberUseDnasRequestData {
    pub nonce: u64,
    pub dao_addr: String,
    pub scrt_dnas_addr: String,
    pub middleware_operator_addr: String,
    pub key_hash: Binary,
}

#[cw_serde]
pub struct MiddlewareUseRequestData {
    pub dao_member: String,
    pub dao_addr: String,
    pub msg_hash: Binary,
    pub nonce: u64,
}

#[cw_serde]
pub struct StdFee {
    pub amount: Vec<Coin>,
    pub gas: String,
}

#[cw_serde]
pub struct PubkeyObject {
    pub ty: String,
    pub value: Binary,
}

// The public address and signature
#[cw_serde]
pub struct DaoObject {
    /// dao bech32 address
    pub dao: String,
    /// dao member bech32 address
    pub member: String,
}

// /// DnasPermitParams
// #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
// #[serde(rename_all = "snake_case")]
// pub struct DnasPermitParams {
//     pub storage_key: DaoObject,
//     pub permit_name: String,
//     pub chain_id: String,
// }

// #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
// #[serde(rename_all = "snake_case")]
// pub struct DnasPermit {
//     #[serde(bound = "")]
//     pub params: DnasPermitParams,
//     pub signature: PermitSignature,
// }

// // The public address and signature

// // The public address and signature
// #[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
// pub struct DnasRegistrationData {
//     /// list of DAOs that are able to make use of keys
//     pub daos: DaoObject,
//     /// hash of api key used as key map.
//     pub apikey_hash: Binary,
//     // Starting nonce for profile if existing before being registered
//     // pub nonce: Option<u64>,
// }

/// dao + dao_member addr bytes as key
pub fn get_dnas_storage_key(dobj: DaoObject) -> StdResult<Vec<u8>> {
    let mut suffix_key = Vec::new();
    suffix_key.extend_from_slice(dobj.dao.as_bytes());
    suffix_key.extend_from_slice(dobj.member.as_bytes());
    Ok(suffix_key)
}

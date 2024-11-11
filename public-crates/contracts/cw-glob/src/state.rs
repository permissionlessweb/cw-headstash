use cosmwasm_schema::cw_serde;
use cosmwasm_std::Binary;
use cw_storage_plus::{Item, Map};

pub const OWNER: Item<Vec<String>> = Item::new("o");
pub const GLOBMAP: Map<String, Binary> = Map::new("g");
pub const HASHMAP: Map<String, String> = Map::new("h");

#[cw_serde]
pub struct Glob {
    /// The key used to store the blob
    pub key: String,
    /// The wasm
    pub blob: Binary,
}

#[cw_serde]
pub struct GlobHash {
    /// The key used to store the blob
    pub key: String,
    /// The hash of the wasm blob
    pub hash: String,
}

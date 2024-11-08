use cosmwasm_std::Binary;
use cw_storage_plus::Map;

pub const GLOBMAP: Map<String, Binary> = Map::new("g");
pub const HASHMAP: Map<String, String> = Map::new("h");

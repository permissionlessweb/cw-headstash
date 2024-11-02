use cosmwasm_std::Binary;
use cw_storage_plus::Map;

pub const GLOBMAP: Map<String, Binary> = Map::new("g");

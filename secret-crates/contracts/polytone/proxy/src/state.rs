use cosmwasm_std::{Addr, SubMsgResponse};
use secret_toolkit::storage::Item;
// use cw_storage_plus::Item;

pub const KEY_INSTANTIATOR: &[u8] = b"owner";
pub const KEY_COLLECTOR: &[u8] = b"callbacks";


/// Stores the instantiator of the contract.
pub const INSTANTIATOR: Item<Addr> = Item::new(KEY_INSTANTIATOR);

/// Stores a list of callback's currently being collected. Has no
/// value if none are being collected.
pub const COLLECTOR: Item<Vec<Option<SubMsgResponse>>> = Item::new(KEY_COLLECTOR);

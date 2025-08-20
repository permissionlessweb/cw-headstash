use cosmwasm_std::{Addr, Binary};
use polytone::msgs::voice::SenderInfo;
use secret_toolkit::storage::{Item, Keymap};

// SENDER_TO_PROXY
pub const KEY_SENDER_TO_PROXY: &[u8] = b"sender_to_proxy";
pub const SENDER_TO_PROXY: Keymap<(String, String, String), Addr> =
    Keymap::new(KEY_SENDER_TO_PROXY);

// PROXY_TO_SENDER
pub const KEY_PROXY_TO_SENDER: &[u8] = b"proxy_to_sender";
pub const PROXY_TO_SENDER: Keymap<Addr, SenderInfo> = Keymap::new(KEY_PROXY_TO_SENDER);

// CHANNEL_TO_CONNECTION
pub const KEY_CHANNEL_TO_CONNECTION: &[u8] = b"channel_to_connection";
pub const CHANNEL_TO_CONNECTION: Keymap<String, String> = Keymap::new(KEY_CHANNEL_TO_CONNECTION);

// PROXY_CODE_ID
pub const KEY_PROXY_CODE_ID: &[u8] = b"proxy_code_id";
pub const PROXY_CODE_ID: Item<u64> = Item::new(KEY_PROXY_CODE_ID);

// BLOCK_MAX_GAS
pub const KEY_BLOCK_MAX_GAS: &[u8] = b"block_max_gas";
pub const BLOCK_MAX_GAS: Item<u64> = Item::new(KEY_BLOCK_MAX_GAS);

// CONTRACT_ADDR_LEN
pub const KEY_CONTRACT_ADDR_LEN: &[u8] = b"contract_addr_len";
pub const CONTRACT_ADDR_LEN: Item<u8> = Item::new(KEY_CONTRACT_ADDR_LEN);

// PENDING PROXY TX
pub const KEY_PENDING_PROXY_TX: &[u8] = b"pending_proxy_tx";
pub const PENDING_PROXY_TXS: Item<Binary> = Item::new(KEY_PENDING_PROXY_TX);

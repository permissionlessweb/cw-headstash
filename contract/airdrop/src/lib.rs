pub mod contract;
pub mod msg;
pub mod state;
pub mod error;

mod verify;
pub use verify::verify_ethereum_text;

pub const SNIP25_REPLY_ID: u64 = 69;

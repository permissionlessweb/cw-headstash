pub mod contract;
pub mod error;
pub mod ibc;
pub mod msg;
pub mod state;
pub mod types;
mod verify;
pub use verify::verify_ethereum_text;

pub const SNIP120U_REPLY: u64 = 120;

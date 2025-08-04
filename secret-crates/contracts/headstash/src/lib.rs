pub mod contract;
pub mod error;

pub mod msg;
pub mod state;
mod verify;
pub use verify::verify_ethereum_text;

pub const SNIP120U_REPLY: u64 = 120;

#[macro_use]
extern crate static_assertions as sa;

mod btbe;
pub mod contract;
pub mod error;
pub mod ibc;
pub mod msg;
pub mod state;
mod transaction_history;
mod gas_tracker;
mod dwb;
pub mod types;
mod verify;
pub use verify::verify_ethereum_text;

pub const SNIP120U_REPLY: u64 = 120;
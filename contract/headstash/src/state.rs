use cosmwasm_std::{Addr, Storage, Uint128};
use cosmwasm_storage::{
    bucket, bucket_read, singleton, singleton_read, Bucket, ReadonlyBucket, ReadonlySingleton,
    Singleton,
};
use schemars::JsonSchema;
use secret_toolkit::storage::Keymap;
use serde::{Deserialize, Serialize};

use crate::msg::Snip120u;

pub const DISTRIBUTION: &[u8] = include_bytes!("./distribution.json");

pub static CONFIG_KEY: &[u8] = b"ck";
pub static ETH_PUBKEY_CLAIMED_KEY: &[u8] = b"epck";
pub static IBC_BLOOM_CLAIMED_KEY: &[u8] = b"ibck";
pub static TOTAL_CLAIMED_KEY: &[u8] = b"tck";
pub static DECAY_CLAIMED_KEY: &[u8] = b"dck";
// key = (owner, snip-addr)
pub static HEADSTASH_OWNERS: Keymap<(String, String), Uint128> = Keymap::new(b"ho");
// key = (snip120, pubkey)
pub static HEADY_CLAIM: Keymap<(String, String), String> = Keymap::new(b"hc");

pub static SNIP120US: Keymap<String, Uint128> = Keymap::new(b"snip");
pub static TOTAL_CLAIMED: Keymap<String, Uint128> = Keymap::new(b"tc");

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
pub struct Snip {
    pub contract: String,
    pub amount: Uint128,
}
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
pub struct Headstash {
    pub addr: String,
    pub headstash: Vec<Snip>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
pub struct Config {
    pub admin: Addr,
    pub claim_msg_plaintext: String,
    pub start_date: u64,
    pub end_date: Option<u64>,
    pub snip120us: Vec<Snip120u>,
    pub snip_hash: String,
    pub viewing_key: String,
    pub channel_id: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
pub struct AllowanceAction {
    pub spender: String,
    pub amount: Uint128,
    pub expiration: Option<u64>,
    pub memo: Option<String>,
    pub decoys: Option<Vec<Addr>>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
pub struct BloomSnip120u {
    pub amount: Uint128,
    pub address: Addr,
}

pub fn config(storage: &mut dyn Storage) -> Singleton<Config> {
    singleton(storage, CONFIG_KEY)
}

pub fn config_r(storage: &dyn Storage) -> ReadonlySingleton<Config> {
    singleton_read(storage, CONFIG_KEY)
}

// If not found then its unrewarded; if true then claimed
pub fn claim_status_r(storage: &dyn Storage) -> ReadonlyBucket<bool> {
    bucket_read(storage, ETH_PUBKEY_CLAIMED_KEY)
}

pub fn claim_status_w(storage: &mut dyn Storage) -> Bucket<bool> {
    bucket(storage, ETH_PUBKEY_CLAIMED_KEY)
}

pub fn decay_claimed_r(storage: &dyn Storage) -> ReadonlySingleton<bool> {
    singleton_read(storage, ETH_PUBKEY_CLAIMED_KEY)
}

// decayed state
pub fn decay_claimed_w(storage: &mut dyn Storage) -> Singleton<bool> {
    singleton(storage, DECAY_CLAIMED_KEY)
}

// If not found then ibc_bloom have not been run; if true then snip120u tokens
pub fn ibc_bloom_status_r(storage: &dyn Storage) -> ReadonlyBucket<bool> {
    bucket_read(storage, IBC_BLOOM_CLAIMED_KEY)
}

// If not found then ibc_bloom has not been run; if true then snip120u tokens
pub fn ibc_bloom_status_w(storage: &mut dyn Storage) -> Bucket<bool> {
    bucket(storage, IBC_BLOOM_CLAIMED_KEY)
}
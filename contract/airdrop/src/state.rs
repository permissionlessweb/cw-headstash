
use cosmwasm_std::{Addr, Binary, ContractInfo, Storage, Uint128};
use cosmwasm_storage::{bucket, bucket_read, singleton, singleton_read, Bucket, ReadonlyBucket, ReadonlySingleton, Singleton};
use schemars::JsonSchema;
use secret_toolkit::storage::Keymap;
use serde::{Deserialize, Serialize};

pub static CONFIG_KEY: &[u8] = b"ck";
pub static ETH_PUBKEY_CLAIMED_KEY: &[u8] = b"epck";
pub static TOTAL_CLAIMED_KEY: &[u8] = b"tck";
pub static DECAY_CLAIMED_KEY: &[u8] = b"dck";
pub static HEADSTASH_OWNERS: Keymap<String, Uint128> = Keymap::new(b"ho");

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
pub enum Token {
    Terp,
    Thiol,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
pub struct Headstash {
    pub eth_pubkey: String,
    pub amount: Uint128,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
pub struct Config {
    pub admin: Addr,
    pub claim_msg_plaintext: String,
    pub start_date: u64,
    pub end_date: Option<u64>,
    pub snip20_1: ContractInfo,
    pub snip20_2: Option<ContractInfo>,
    pub total_amount: Uint128,
    pub viewing_key: String,
}

pub fn config(storage: &mut dyn Storage) -> Singleton<Config> {
    singleton(storage, CONFIG_KEY)
}

pub fn config_r(storage: &dyn Storage) -> ReadonlySingleton<Config> {
    singleton_read(storage, CONFIG_KEY)
}

// Total claimed
pub fn total_claimed_r(storage: &dyn Storage) -> ReadonlySingleton<Uint128> {
    singleton_read(storage, TOTAL_CLAIMED_KEY)
}

pub fn total_claimed_w(storage: &mut dyn Storage) -> Singleton<Uint128> {
    singleton(storage, TOTAL_CLAIMED_KEY)
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
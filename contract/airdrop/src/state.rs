
use cosmwasm_std::{Addr, Binary, ContractInfo, Storage, Uint128};
use cosmwasm_storage::{bucket, bucket_read, singleton, singleton_read, Bucket, ReadonlyBucket, ReadonlySingleton, Singleton};
use schemars::JsonSchema;
use secret_toolkit::storage::Keymap;
use serde::{Deserialize, Serialize};

pub static CONFIG_KEY: &[u8] = b"config";
pub static ETH_PUBKEY_CLAIMED_KEY: &[u8] = b"eth_pubkey_claimed";
pub static TOTAL_CLAIMED_KEY: &[u8] = b"total_claimed";
pub static HEADSTASH_OWNERS: Keymap<String, Uint128> = Keymap::new(b"headstash_owners");

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
pub struct Config {
    pub snip20_1: ContractInfo,
    pub snip20_2: Option<ContractInfo>,
    pub merkle_root: Binary,
    pub viewing_key: String,
    pub claim_msg_plaintext: String,
    pub admin: Option<Addr>,
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
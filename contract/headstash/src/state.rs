use bloom::BloomConfig;
use cosmwasm_std::{Addr, StdError, StdResult, Storage, Uint128};
use schemars::JsonSchema;
use secret_toolkit::storage::{Item, Keymap};
use serde::{Deserialize, Serialize};

pub static SNIP120US: Keymap<String, Uint128> = Keymap::new(b"snip");

pub const KEY_CONFIG: &[u8] = b"c";
pub const KEY_HEADSTASH_OWNERS: &[u8] = b"hso";
pub const KEY_HEADSTASH_SIGS: &[u8] = b"hs";
pub const KEY_DECAY_CLAIMED: &[u8] = b"dc";
pub const KEY_TOTAL_CLAIMED: &[u8] = b"tc";
pub const KEY_CLAIMED_HEADSTASH: &[u8] = b"chs";

pub const KEY_B_CONFIG: &[u8] = b"bc";
pub const KEY_BLOOM_MEMPOOL: &[u8] = b"bpm";
pub const KEY_PROCESSING_BLOOM_MEMPOOL: &[u8] = b"pbmp";
pub const KEY_BLOOM_TX_COUNT_MAP: &[u8] = b"btxcm";
pub const KEY_BLOOM_CLAIMED_KEY: &[u8] = b"bck";

pub const PREFIX_CONFIG: &[u8] = b"c";
pub const PREFIX_HEADSTASH_OWNERS: &[u8] = b"hso";
pub const PREFIX_HEADSTASH_SIGS: &[u8] = b"hs";
pub const PREFIX_DECAY_CLAIMED: &[u8] = b"dc";
pub const PREFIX_TOTAL_CLAIMED: &[u8] = b"tc";
pub const PREFIX_CLAIMED_HEADSTASH: &[u8] = b"chs";

pub const PREFIX_B_CONFIG: &[u8] = b"bc";
pub const PREFIX_BLOOM_MEMPOOL: &[u8] = b"bpm";
pub const PREFIX_PROCESSING_BLOOM_MEMPOOL: &[u8] = b"pbmp";
pub const PREFIX_BLOOM_TX_COUNT_MAP: &[u8] = b"btxcm";
pub const PREFIX_BLOOM_CLAIMED_KEY: &[u8] = b"bck";

pub static CONFIG: Item<Config> = Item::new(KEY_B_CONFIG);
pub static HEADSTASH_OWNERS: Item<Uint128> = Item::new(KEY_HEADSTASH_OWNERS);
pub static HEADSTASH_SIGS: Item<HeadstashSig> = Item::new(KEY_B_CONFIG);
pub static DECAY_CLAIMED: Item<bool> = Item::new(KEY_DECAY_CLAIMED);
pub static TOTAL_CLAIMED: Item<Uint128> = Item::new(KEY_TOTAL_CLAIMED);
pub static CLAIMED_HEADSTASH: Item<bool> = Item::new(KEY_CLAIMED_HEADSTASH);

pub static BLOOM_MEMPOOL: Item<Vec<bloom::IbcBloomMsg>> = Item::new(KEY_BLOOM_MEMPOOL);
pub static PROCESSING_BLOOM_MEMPOOL: Item<Vec<bloom::ProcessingBloomMsg>> =
    Item::new(KEY_BLOOM_MEMPOOL);
pub static BLOOM_TX_COUNT_MAP: Item<bloom::BloomTxCountMap> = Item::new(KEY_BLOOM_TX_COUNT_MAP);
pub static BLOOM_CLAIMED_KEY: Item<bool> = Item::new(KEY_BLOOM_CLAIMED_KEY);
pub static BLOOMSBLOOMS: Keymap<String, bloom::BloomBloom> = Keymap::new(b"blomblom");

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
pub struct Headstash {
    pub addr: String,
    pub snips: Vec<Snip>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
pub struct HeadstashSig {
    pub addr: String,
    pub sig: String,
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
    pub bloom: Option<BloomConfig>,
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
pub struct Snip {
    pub contract: String,
    pub amount: Uint128,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
pub struct Snip120u {
    // native x/bank token for this snip120u
    pub native_token: String,
    // pub name: String,
    pub addr: Addr,
    // total amount of this to be distributed during this headstash
    pub total_amount: Uint128,
}

pub mod bloom {

    use cosmwasm_std::Timestamp;

    use super::*;
    pub struct IbcBloomStore {}
    impl IbcBloomStore {
        // loads pending msgs from store for a given sender
        pub fn load_blooms_in_rango_from_mempool(
            _storage: &dyn Storage,
            _sender: &Addr,
        ) -> Vec<IbcBloomMsg> {
            // todo:
            // - get random entropy_range prefix
            // - get random_addrs in entropy range array
            // - get random # of msg to process for addr. If none, get another random address.
            // - push all msgs

            // // get random entropy_range to use as suffix in KepMap lookup
            // let random_entropy_suffix = utils::weighted_random(rand) as u128;
            // let msgs = BLOOM_MEMPOOL
            //     .add_suffix(&random_entropy_suffix.to_string().into_bytes())
            //     .add_suffix(sender.as_str().as_bytes());

            // return msgs.load(storage).unwrap_or(vec![]);
            return vec![];
        }

        // saves a new pending msg to the store
        pub fn save_bloom_to_mempool(
            storage: &mut dyn Storage,
            sender: &Addr,
            msgs: Vec<IbcBloomMsg>,
        ) -> StdResult<()> {
            let mempool = BLOOM_MEMPOOL.add_suffix(sender.as_str().as_bytes());
            mempool.save(storage, &msgs)
        }

        // updates the amounts
        pub fn update_bloom_msg(
            _store: &mut dyn Storage,
            _sender: &Addr,
            mut old: BloomRecipient,
            new: BloomRecipient,
        ) -> StdResult<()> {
            if let Some(amnt) = old.amount.checked_sub(new.amount) {
                old.amount = amnt
            } else {
                return Err(StdError::generic_err(format!("beat!")));
            }
            Ok(())
        }
    }

    #[derive(Serialize, Debug, Deserialize, Clone, Eq, PartialEq, JsonSchema, Default)]
    pub struct BloomBloom {
        pub timestamp: Timestamp,
        pub msg: IbcBloomMsg,
    }

    #[derive(Serialize, Debug, Deserialize, Clone, Eq, PartialEq, JsonSchema, Default)]
    pub struct IbcBloomMsg {
        pub owner: String,
        // total amount to be sent via ibc-bloom protocol. Must never be > allowance set for headstash contract.
        pub total: Uint128,
        // native token of snip120u being redeemed
        pub source_token: String,
        // additional delay before including blooms into msgs
        pub cadance: u64,
        // ratio used to classify bloom-mempool tx priority
        //  0 == no entropy, most chance of being included in finality process.
        // 10 == maximize entropy, least possible chance of being included in finality process
        pub entropy_key: u64,
        // recipient and amount to send.
        pub bloom: Vec<BloomRecipient>,
    }

    #[derive(Serialize, Debug, Deserialize, Clone, Eq, PartialEq, JsonSchema, Default)]
    pub struct ProcessingBloomMsg {
        // recipient addr
        pub addr: String,
        // amount pending to send to recipient. Owner sets this first, and is update by contract while processing ibc-bloom
        pub amount: u64,
        // Coin token string
        pub token: String,
        // IBC channel id to transfer tokens to
        pub channel: String,
    }

    #[derive(Serialize, Debug, Deserialize, Clone, Eq, PartialEq, JsonSchema, Default)]
    pub struct BloomRecipient {
        // recipient addr
        pub addr: String,
        // amount pending to send to recipient. Owner sets this first, and is update by contract while processing ibc-bloom
        pub amount: u64,
    }
    #[derive(Serialize, Debug, Deserialize, Clone, JsonSchema, Default)]
    #[cfg_attr(test, derive(Eq, PartialEq))]
    pub struct BloomTxCountMap {
        // owner of IbcBloomMsg
        pub owner: String,
        // amount pending to send to recipient. Owner sets this first, and is update by contract while processing ibc-bloom
        pub amount: u64,
    }

    #[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
    pub struct BloomConfig {
        /// minimum cadance before messages are eligible to be added to mempool (in blocks)
        pub default_cadance: u64,
        /// minimum cadance that can be set before messages are eligible for mempool. if 0, default_cadance is set.
        pub min_cadance: u64,
        /// if enabled, randomness seed is used to add random value to cadance.
        pub random_cadance: bool,
        /// maximum number of transactions a bloom msg will process  
        pub max_granularity: u64,
        // /// if enabled, decoy messages are included in batches to create noise
        // pub decoys: bool,
    }

    #[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
    pub struct BloomSnip120u {
        pub amount: Uint128,
        pub address: Addr,
    }
}

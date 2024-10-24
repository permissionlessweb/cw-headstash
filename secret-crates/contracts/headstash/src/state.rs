use crate::error::ContractError;
use bloom::BloomConfig;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, StdError, StdResult, Storage, Uint128};
use schemars::JsonSchema;
use secret_toolkit::storage::{Item, Keymap};
use serde::{Deserialize, Serialize};

#[allow(clippy::module_name_repetitions)]
pub use ibc::State as ContractState;

use crate::msg::options::ChannelOpenInitOptions;
pub static SNIP120US: Keymap<String, Uint128> = Keymap::new(b"snip");

pub const KEY_CONFIG: &[u8] = b"c";
pub const KEY_HEADSTASH_SIGS: &[u8] = b"hs";
pub const KEY_DECAY_CLAIMED: &[u8] = b"dc";
pub const KEY_TOTAL_CLAIMED: &[u8] = b"tc";
pub const KEY_CLAIMED_HEADSTASH: &[u8] = b"chs";

pub const KEY_ICA_ENABLED: &[u8] = b"ibc-enabled";
pub const KEY_B_CONFIG: &[u8] = b"bc";
pub const KEY_BLOOM_MEMPOOL: &[u8] = b"bpm";
pub const KEY_PROCESSING_BLOOM_MEMPOOL: &[u8] = b"pbmp";
pub const KEY_BLOOM_TX_COUNT_MAP: &[u8] = b"btxcm";
pub const KEY_BLOOM_CLAIMED_KEY: &[u8] = b"bck";

pub const KEY_TX_COUNT: &[u8] = b"tx-count";

pub const PREFIX_CONFIG: &[u8] = b"c";
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
pub static HEADSTASH_SIGS: Item<HeadstashSig> = Item::new(KEY_B_CONFIG);
pub static DECAY_CLAIMED: Item<bool> = Item::new(KEY_DECAY_CLAIMED);
pub static TOTAL_CLAIMED: Item<Uint128> = Item::new(KEY_TOTAL_CLAIMED);
pub static CLAIMED_HEADSTASH: Item<bool> = Item::new(KEY_CLAIMED_HEADSTASH);

pub static ICA_ENABLED: Item<bool> = Item::new(KEY_ICA_ENABLED);
pub static BLOOM_MEMPOOL: Item<Vec<bloom::IbcBloomMsg>> = Item::new(KEY_BLOOM_MEMPOOL);
pub static PROCESSING_BLOOM_MEMPOOL: Item<Vec<bloom::ProcessingBloomMsg>> =
    Item::new(KEY_BLOOM_MEMPOOL);
pub static BLOOM_TX_COUNT_MAP: Item<bloom::BloomTxCountMap> = Item::new(KEY_BLOOM_TX_COUNT_MAP);
pub static BLOOM_CLAIMED_KEY: Item<bool> = Item::new(KEY_BLOOM_CLAIMED_KEY);
pub static BLOOMSBLOOMS: Keymap<String, bloom::BloomBloom> = Keymap::new(b"blomblom");

// IBC CONTRACT STATE
pub const STATE: Item<ibc::State> = Item::new(b"state");
pub const CHANNEL_STATE: Item<channel::ChannelState> = Item::new(b"ica_channel");
pub const CHANNEL_OPEN_INIT_OPTIONS: Item<ChannelOpenInitOptions> =
    Item::new(b"channel_open_init_options");
pub const ALLOW_CHANNEL_OPEN_INIT: Item<bool> = Item::new(b"allow_channel_open_init");
pub const ALLOW_CHANNEL_CLOSE_INIT: Item<bool> = Item::new(b"allow_channel_close_init");

// DWB
pub static TX_COUNT: Item<u64> = Item::new(KEY_TX_COUNT);

// An eligible addr, along with a vector of snip120u contracts and their allocations.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
pub struct Headstash {
    pub addr: String,
    pub snips: Vec<snip::Snip>,
}

// The public address and signature
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
pub struct HeadstashSig {
    pub addr: String,
    pub sig: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
pub struct Config {
    pub owner: Addr,
    pub claim_msg_plaintext: String,
    pub start_date: u64,
    pub end_date: Option<u64>,
    pub snip120us: Vec<snip::Snip120u>,
    pub snip_hash: String,
    pub viewing_key: String,
    pub channel_id: String,
    pub bloom: Option<BloomConfig>,
}

pub mod ibc {

    use super::*;
    use crate::ibc::types::metadata::TxEncoding;
    use cosmwasm_std::{ContractInfo, Timestamp};

    /// State is the state of the contract.
    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
    #[allow(clippy::derive_partial_eq_without_eq)]

    pub struct State {
        /// The Interchain Account (ICA) info needed to send packets.
        /// This is set during the handshake.
        #[serde(default)]
        pub ica_info: Option<IcaInfo>,
        /// The address of the callback contract.
        #[serde(default)]
        pub callback_contract: Option<ContractInfo>,
    }

    impl State {
        /// Creates a new [`State`]
        #[must_use]
        pub const fn new(callback_contract: Option<ContractInfo>) -> Self {
            Self {
                ica_info: None,
                callback_contract,
            }
        }

        /// Gets the ICA info
        ///
        /// # Errors
        ///
        /// Returns an error if the ICA info is not set.
        pub fn get_ica_info(&self) -> Result<IcaInfo, ContractError> {
            self.ica_info
                .as_ref()
                .map_or(Err(ContractError::IcaInfoNotSet), |s| Ok(s.clone()))
        }

        /// Sets the ICA info
        pub fn set_ica_info(
            &mut self,
            ica_address: impl Into<String>,
            channel_id: impl Into<String>,
            encoding: TxEncoding,
        ) {
            self.ica_info = Some(IcaInfo::new(ica_address, channel_id, encoding));
        }

        /// Deletes the ICA info
        pub fn delete_ica_info(&mut self) {
            self.ica_info = None;
        }
    }

    #[cw_serde]
    pub struct IcaInfo {
        pub ica_address: String,
        pub channel_id: String,
        pub encoding: TxEncoding,
    }

    impl IcaInfo {
        /// Creates a new [`IcaInfo`]
        pub fn new(
            ica_address: impl Into<String>,
            channel_id: impl Into<String>,
            encoding: TxEncoding,
        ) -> Self {
            Self {
                ica_address: ica_address.into(),
                channel_id: channel_id.into(),
                encoding,
            }
        }
    }
}

pub mod channel {
    use cosmwasm_std::{IbcChannel, IbcOrder};

    use super::*;

    /// Status is the status of an IBC channel.
    #[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
    #[serde(rename_all = "snake_case")]
    pub enum ChannelStatus {
        /// Uninitialized is the default state of the channel.
        #[serde(rename = "STATE_UNINITIALIZED_UNSPECIFIED")]
        Uninitialized,
        /// Init is the state of the channel when it is created.
        #[serde(rename = "STATE_INIT")]
        Init,
        /// TryOpen is the state of the channel when it is trying to open.
        #[serde(rename = "STATE_TRYOPEN")]
        TryOpen,
        /// Open is the state of the channel when it is open.
        #[serde(rename = "STATE_OPEN")]
        Open,
        /// Closed is the state of the channel when it is closed.
        #[serde(rename = "STATE_CLOSED")]
        Closed,
        /// The channel has just accepted the upgrade handshake attempt and
        /// is flushing in-flight packets. Added in `ibc-go` v8.1.0.
        #[serde(rename = "STATE_FLUSHING")]
        Flushing,
        /// The channel has just completed flushing any in-flight packets.
        /// Added in `ibc-go` v8.1.0.
        #[serde(rename = "STATE_FLUSHCOMPLETE")]
        FlushComplete,
    }

    /// This application only supports one channel.
    #[cw_serde]
    pub struct ChannelState {
        /// The IBC channel, as defined by cosmwasm.
        pub channel: IbcChannel,
        /// The status of the channel.
        pub channel_status: ChannelStatus,
    }

    impl ChannelState {
        /// Creates a new [`ChannelState`]
        #[must_use]
        pub const fn new_open_channel(channel: IbcChannel) -> Self {
            Self {
                channel,
                channel_status: ChannelStatus::Open,
            }
        }

        /// Checks if the channel is open
        #[must_use]
        pub const fn is_open(&self) -> bool {
            matches!(self.channel_status, ChannelStatus::Open)
        }

        /// Closes the channel
        pub fn close(&mut self) {
            self.channel_status = ChannelStatus::Closed;
        }

        /// Checks if the channel is [`IbcOrder::Ordered`]
        #[must_use]
        pub const fn is_ordered(&self) -> bool {
            matches!(self.channel.order, IbcOrder::Ordered)
        }
    }

    impl std::fmt::Display for ChannelStatus {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::Uninitialized => write!(f, "STATE_UNINITIALIZED_UNSPECIFIED"),
                Self::Init => write!(f, "STATE_INIT"),
                Self::TryOpen => write!(f, "STATE_TRYOPEN"),
                Self::Open => write!(f, "STATE_OPEN"),
                Self::Closed => write!(f, "STATE_CLOSED"),
                Self::Flushing => write!(f, "STATE_FLUSHING"),
                Self::FlushComplete => write!(f, "STATE_FLUSHCOMPLETE"),
            }
        }
    }
}

pub mod bloom {
    use super::*;
    use cosmwasm_std::Timestamp;

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
        /// Optional timeout in seconds to include with the ibc packet.
        /// If not specified, the [default timeout](crate::ibc::types::packet::DEFAULT_TIMEOUT_SECONDS) is used.
        #[serde(skip_serializing_if = "Option::is_none")]
        timeout_seconds: Option<u64>,
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

/// `assert_owner` asserts that the passed address is the owner of the contract.
///
/// # Errors
///
/// Returns an error if the address is not the owner or if the owner cannot be loaded.
pub fn assert_owner(
    storage: &dyn Storage,
    address: impl Into<String>,
) -> Result<(), ContractError> {
    if CONFIG.load(storage)?.owner != address.into() {
        return Err(ContractError::Unauthorized {});
    }
    Ok(())
}

pub mod snip {
    use super::*;
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
}

// To avoid balance guessing attacks based on balance overflow we need to perform safe addition and don't expose overflows to the caller.
// Assuming that max of u128 is probably an unreachable balance, we want the addition to be bounded the max of u128
// Currently the logic here is very straight forward yet the existence of the function is mandatory for future changes if needed.
pub fn safe_add(balance: &mut u128, amount: u128) -> u128 {
    // Note that new_amount can be equal to base after this operation.
    // Currently we do nothing maybe on other implementations we will have something to add here
    let prev_balance: u128 = *balance;
    *balance = balance.saturating_add(amount);

    // Won't underflow as the minimal value possible is 0
    *balance - prev_balance
}

// To avoid balance guessing attacks based on balance overflow we need to perform safe addition and don't expose overflows to the caller.
// Assuming that max of u64 is probably an unreachable balance, we want the addition to be bounded the max of u64
// Currently the logic here is very straight forward yet the existence of the function is mandatory for future changes if needed.
pub fn safe_add_u64(balance: &mut u64, amount: u64) -> u64 {
    // Note that new_amount can be equal to base after this operation.
    // Currently we do nothing maybe on other implementations we will have something to add here
    let prev_balance: u64 = *balance;
    *balance = balance.saturating_add(amount);

    // Won't underflow as the minimal value possible is 0
    *balance - prev_balance
}

pub static INTERNAL_SECRET: Item<Vec<u8>> = Item::new(b"internal-secret");

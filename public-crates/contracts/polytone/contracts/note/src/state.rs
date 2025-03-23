use cosmwasm_std::{Addr, Binary, Storage};
use cw_storage_plus::{Item, Map};

use crate::{error::ContractError, msg::HeadstashParams};

/// The Map used to determine how to handle ica-callbacks.
/// key: snip120u = first action to take. if false, all other prefixes should fail
/// key: cw-headstash = second action to take. if false, cannot init snips.
/// key: snip120u-init-(len()) = third action to take. if false, cannot init headstash.
///      key defined with enumerated object position for each snip.
/// key: cw-headstash-init = fourth action to take.
pub const HEADSTASH_SEQUENCE: Map<String, bool> = Map::new("");
pub const HEADSTASH_PARAMS: Item<HeadstashParams> = Item::new("hp");
pub const GRANTEE: Item<String> = Item::new("grantee");

/// cw-glob functions
pub const CW_GLOB: Item<Addr> = Item::new("glob");
pub const GLOBMAP: Map<String, Binary> = Map::new("gm");
pub const HASHMAP: Map<String, String> = Map::new("hm");
/// (Connection-ID, Remote port) of this contract's pair.
pub const CONNECTION_REMOTE_PORT: Item<(String, String)> = Item::new("a");

/// Channel-ID of the channel currently connected. Holds no value when
/// no channel is active.
pub const CHANNEL: Item<String> = Item::new("b");

/// Max gas usable in a single block.
pub const BLOCK_MAX_GAS: Item<u64> = Item::new("bmg");

/// (channel_id) -> sequence number. `u64` is the type used in the
/// Cosmos SDK for sequence numbers:
///
/// <https://github.com/cosmos/ibc-go/blob/a25f0d421c32b3a2b7e8168c9f030849797ff2e8/modules/core/02-client/keeper/keeper.go#L116-L125>
const SEQUENCE_NUMBER: Map<String, u64> = Map::new("sn");

/// Increments and returns the next sequence number.
pub(crate) fn increment_sequence_number(
    storage: &mut dyn Storage,
    channel_id: String,
) -> Result<u64, ContractError> {
    let seq = SEQUENCE_NUMBER
        .may_load(storage, channel_id.clone())?
        .unwrap_or_default()
        .checked_add(1)
        .ok_or(ContractError::SequenceOverflow)?;
    SEQUENCE_NUMBER.save(storage, channel_id, &seq)?;
    Ok(seq)
}

#[cosmwasm_schema::cw_serde]
pub enum HeadstashSeq {
    UploadSnip,
    UploadHeadstash,
    InitSnips,
    InitHeadstash,
}

impl From<HeadstashSeq> for String {
    fn from(ds: HeadstashSeq) -> Self {
        match ds {
            HeadstashSeq::UploadSnip => "snip120u".to_string(),
            HeadstashSeq::UploadHeadstash => "cw-headstash".to_string(),
            HeadstashSeq::InitSnips => "snip120u-init-".to_string(),
            HeadstashSeq::InitHeadstash => "cw-headstash-init".to_string(),
        }
    }
}
impl HeadstashSeq {
    pub fn indexed_snip(&self, i: usize) -> String {
        match self {
            HeadstashSeq::InitSnips => format!("snip120u-init-{}", i),
            _ => panic!("Invalid HeadstashSequence formatted_str value"),
        }
    }
}

pub mod headstash {

    use super::{bloom::BloomConfig, *};
    use cosmwasm_std::{Addr, Uint128};

    #[cosmwasm_schema::cw_serde]
    pub struct InstantiateMsg {
        /// owner of contract
        pub owner: Addr,
        /// HREAM ~ {wallet} ~ {secondary_addr} ~ {expiration}
        pub claim_msg_plaintext: String,
        /// optional date that once reached, will start headstash distribution event.
        pub start_date: Option<u64>,
        /// optional date that once reached, will end headstash distribution event.
        pub end_date: Option<u64>,
        /// code hash of custom snip20 contract for headstashes
        pub snip120u_code_hash: String,
        /// A list of custom snip20-headstash contracts.
        /// This contract must be set as an authorized minter for each, or else this contract will not work.
        pub snips: Vec<Snip120u>,
        /// Option to enable contract to add multiplier on allocations when claiming. currently 1.33x.
        pub multiplier: bool,
        /// random seed provided by user.
        pub random_key: String,
        /// optional bloom configuration
        pub bloom_config: Option<BloomConfig>,
        // /// The options to initialize the IBC channel upon contract instantiation.
        // pub channel_open_init_options: Option<options::ChannelOpenInitOptions>,
    }

    #[cosmwasm_schema::cw_serde]
    pub enum ExecuteMsg {
        AddEligibleHeadStash { headstash: Vec<Headstash> },
    }

    #[cosmwasm_schema::cw_serde]
    pub struct Headstash {
        pub pubkey: String,
        pub snips: Vec<Snip>,
    }

    #[cosmwasm_schema::cw_serde]
    pub struct Snip {
        pub addr: String,
        pub amount: Uint128,
    }
    #[cosmwasm_schema::cw_serde]
    pub struct Snip120u {
        /// native token denom of this snip
        pub token: String,
        /// name of token snip represents
        pub name: String,
        /// smart contract addr of snip120u
        pub addr: Option<Addr>,
        /// total amount to distribute for cw-headstash
        pub total_amount: Uint128,
    }
}

pub mod snip120u {
    use cosmwasm_std::{Binary, Uint128};

    use super::*;

    #[cosmwasm_schema::cw_serde]
    pub struct InitialBalance {
        pub address: String,
        pub amount: Uint128,
    }

    #[cosmwasm_schema::cw_serde]
    pub struct InstantiateMsg {
        pub name: String,
        pub admin: Option<String>,
        pub symbol: String,
        pub decimals: u8,
        pub initial_balances: Option<Vec<InitialBalance>>,
        pub prng_seed: Binary,
        pub config: Option<InitConfig>,
        pub supported_denoms: Option<Vec<String>>,
    }

    #[cosmwasm_schema::cw_serde]
    pub struct AddMintersMsg {
        pub minters: Vec<String>,
        pub padding: Option<String>,
    }

    #[cosmwasm_schema::cw_serde]
    pub struct InitConfig {
        /// Indicates whether the total supply is public or should be kept secret.
        /// default: False
        public_total_supply: Option<bool>,
        /// Indicates whether deposit functionality should be enabled
        /// default: False
        enable_deposit: Option<bool>,
        /// Indicates whether redeem functionality should be enabled
        /// default: False
        enable_redeem: Option<bool>,
        /// Indicates whether mint functionality should be enabled
        /// default: False
        enable_mint: Option<bool>,
        /// Indicates whether burn functionality should be enabled
        /// default: False
        enable_burn: Option<bool>,
        /// Indicated whether an admin can modify supported denoms
        /// default: False
        can_modify_denoms: Option<bool>,
    }
}

pub mod bloom {
    use super::*;

    #[cosmwasm_schema::cw_serde]
    pub struct BloomConfig {
        /// minimum cadance before messages are eligible to be added to mempool (in blocks)
        pub default_cadance: u64,
        /// minimum cadance that can be set before messages are eligible for mempool. if 0, default_cadance is set.
        pub min_cadance: u64,
        /// maximum number of transactions a bloom msg will process  
        pub max_granularity: u64,
        // if enabled, randomness seed is used to add random value to cadance.
        // pub starting_interval: Option<u64>,
        // /// if enabled, decoy messages are included in batches to create noise
        // pub decoys: bool,
    }
}

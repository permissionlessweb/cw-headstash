use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Uint128};

pub const GLOB_HEADSTASH_KEY: &str = "AAFoaGVhZHN0YXNo";
#[cw_serde]
pub struct HandleIbcBloom {}

#[cw_serde]
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

#[cw_serde]
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

#[cw_serde]
pub enum ExecuteMsg {
    AddEligibleHeadStash { headstash: Vec<Headstash> },
}

#[cw_serde]
pub enum Lhsm {
    Ibc,
    Local,
    Callback,
}

#[cw_serde]
pub struct Snip {
    pub addr: String,
    pub amount: Uint128,
}

#[cw_serde]
pub struct Headstash {
    pub pubkey: String,
    pub snips: Vec<Snip>,
}

#[cw_serde]
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

#[cw_serde]
pub struct HeadstashInitConfig {
    pub claim_msg_plaintxt: String,
    pub end_date: Option<u64>,
    pub start_date: Option<u64>,
    pub random_key: String,
}

/// Params for Headstash Tokens
#[cw_serde]
pub struct HeadstashTokenParams {
    /// Name to use in snip120u state
    pub name: String,
    /// Symbol to use
    pub symbol: String,
    /// native token name
    pub native: String,
    /// ibc string on Secret
    pub ibc: String,
    /// snip20 addr on Secret
    pub snip_addr: Option<String>,
    /// Total amount for specific snip
    pub total: Uint128,
    /// canonical source channel of token for transfers from source to secret network
    pub source_channel: String,
}

/// Params for Headstash
#[cw_serde]
pub struct HeadstashParams {
    /// The contract addr for cw-glob on the native chain.
    pub cw_glob: Addr,
    /// The code ID of the snip120u contract, on Secret Network.
    pub snip120u_code_id: u64,
    /// The code hash of the snip120u contract, on Secret Network. Not optional for pre-deployment verification
    pub snip120u_code_hash: String,
    /// Code id of Headstash contract on Secret Network
    pub headstash_code_id: Option<u64>,
    /// Params defined by deployer for tokens included.
    pub token_params: Vec<HeadstashTokenParams>,
    /// Headstash contract address this contract is admin of.
    /// We save this address in the first callback msg sent during setup_headstash,
    /// and then use it to set as admin for snip120u of assets after 1st callback.
    pub headstash_addr: Option<String>,
    /// The wallet address able to create feegrant authorizations on behalf of this contract
    pub fee_granter: Option<String>,
    /// Enables reward multiplier for cw-headstash
    pub multiplier: bool,
    /// bloom config
    pub bloom_config: Option<BloomConfig>,
    pub headstash_init_config: HeadstashInitConfig,
}

impl HeadstashParams {
    // /// creates new headstash param instance
    // pub fn new(
    //     cw_glob: Addr,
    //     snip120u_code_id: u64,
    //     headstash_code_id: Option<u64>,
    //     headstash_init_config: HeadstashInitConfig,
    //     snip120u_code_hash: String,
    //     token_params: Vec<HeadstashTokenParams>,
    //     headstash_addr: Option<String>,
    //     fee_granter: Option<String>,
    //     bloom_config: Option<BloomConfig>,
    //     multiplier: bool,
    // ) -> Self {
    //     Self {
    //         cw_glob,
    //         snip120u_code_id,
    //         snip120u_code_hash,
    //         headstash_code_id,
    //         headstash_init_config,
    //         headstash_addr,
    //         token_params,
    //         fee_granter,
    //         multiplier,
    //         bloom_config,
    //     }
    // }
}

use cosmwasm_schema::cw_serde;
use cosmwasm_std::Addr;
use cw_storage_plus::{Item, Map};

pub use contract::ContractState;
use headstash::HeadstashParams;
pub use ica::{IcaContractState, IcaState};

/// The item used to store the state of the IBC application.
pub const STATE: Item<ContractState> = Item::new("state");
/// The map used to store the state of the cw-ica-controller contracts.
pub const ICA_STATES: Map<u64, IcaContractState> = Map::new("icas");
/// The map used to store the state of the cw-ica-controller contracts.
pub const HEADSTASH_STATES: Map<u64, HeadstashParams> = Map::new("hsp");
/// The item used to store the count of the cw-ica-controller contracts.
pub const ICA_COUNT: Item<u64> = Item::new("ica");
/// The item used to map contract addresses to ICA IDs.
pub const CONTRACT_ADDR_TO_ICA_ID: Map<Addr, u64> = Map::new("catia");
/// The item used to store the stat of the snip120u contracts created
pub const SNIP120U_CONTRACTS: Item<Vec<Addr>> = Item::new("snip");

pub const CW_GLOB: Item<Addr> = Item::new("glob");
pub const CLOCK_INTERVAL: Item<u64> = Item::new("tictoc");

mod contract {

    use super::*;

    /// ContractState is the state of the IBC application.
    #[cw_serde]
    pub struct ContractState {
        /// The code ID of the cw-ica-controller contract.
        pub ica_controller_code_id: u64,
        pub headstash_params: HeadstashParams,
    }

    impl ContractState {
        /// Creates a new ContractState.
        pub fn new(ica_controller_code_id: u64, headstash_params: HeadstashParams) -> Self {
            Self {
                ica_controller_code_id,
                headstash_params,
            }
        }
    }
}

mod ica {
    use cw_ica_controller::{ibc::types::metadata::TxEncoding, types::state::ChannelState};

    use super::*;

    /// IcaContractState is the state of the cw-ica-controller contract.
    #[cw_serde]
    pub struct IcaContractState {
        pub contract_addr: Addr,
        pub ica_state: Option<IcaState>,
        pub headstash_params: HeadstashParams,
    }

    /// IcaState is the state of the ICA.
    #[cw_serde]
    pub struct IcaState {
        pub ica_id: u64,
        pub ica_addr: String,
        pub tx_encoding: TxEncoding,
        pub channel_state: ChannelState,
    }

    impl IcaContractState {
        /// Creates a new [`IcaContractState`].
        pub fn new(contract_addr: Addr, headstash_params: HeadstashParams) -> Self {
            Self {
                contract_addr,
                ica_state: None,
                headstash_params,
            }
        }
    }

    impl IcaState {
        /// Creates a new [`IcaState`].
        pub fn new(
            ica_id: u64,
            ica_addr: String,
            tx_encoding: TxEncoding,
            channel_state: ChannelState,
        ) -> Self {
            Self {
                ica_id,
                ica_addr,
                tx_encoding,
                channel_state,
            }
        }
    }
}

/// Headstash specific types
pub mod headstash {
    use crate::ContractError;

    #[cw_serde]
    pub struct HandleIbcBloom {}

    #[cw_serde]
    pub struct Snip120u {
        pub token: String,
        pub name: String,
        pub addr: Option<Addr>,
        pub total_amount: Uint128,
    }

    #[cw_serde]
    pub struct InstantiateMsg {
        /// owner of contract
        pub owner: Addr,
        /// {wallet}
        pub claim_msg_plaintext: String,
        /// optional date that once reached, will start headstash distribution event.
        pub start_date: Option<u64>,
        /// optional date that once reached, will end headstash distribution event.
        pub end_date: Option<u64>,
        /// code-id of custom snip20 contract for headstashes
        pub snip120u_code_id: u64,
        /// code hash of custom snip20 contract for headstashes
        pub snip120u_code_hash: String,
        /// A list of custom snip20-headstash contracts.
        /// This contract must be set as an authorized minter for each, or else this contract will not work.
        pub snips: Vec<Snip120u>,
        /// Contract addr of headstash circuitboard.
        pub circuitboard: String,
        /// viewing key permit.
        pub viewing_key: String,
    }

    use super::{cw_serde, STATE};
    use cosmwasm_std::{Addr, Coin, DepsMut, Uint128};

    #[cw_serde]
    pub struct Add {
        pub headstash: Vec<Headstash>,
    }

    #[cw_serde]
    pub struct Snip {
        pub addr: String,
        pub amount: Uint128,
    }
    #[cw_serde]
    pub struct Headstash {
        pub pubkey: String,
        pub snip: Vec<Snip>,
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
    }
    /// Params for Headstash
    #[cw_serde]
    pub struct HeadstashParams {
        /// The code ID of the snip120u contract, on Secret Network.
        pub cw_glob: String,
        /// The code ID of the snip120u contract, on Secret Network.
        pub snip120u_code_id: u64,
        /// The code hash of the snip120u contract, on Secret Network.
        pub snip120u_code_hash: String,
        /// Code id of Headstash contract on Secret Network
        pub headstash_code_id: Option<u64>,
        /// Params defined by deployer for tokens included
        pub token_params: Vec<HeadstashTokenParams>,
        /// Headstash contract address this contract is admin of.
        /// We save this address in the first callback msg sent during setup_headstash,
        /// and then use it to set as admin for snip120u of assets after 1st callback.
        pub headstash: Option<String>,
        /// The wallet address able to create feegrant authorizations on behalf of this contract
        pub fee_granter: Option<String>,
    }

    impl HeadstashParams {
        /// creates new headstash param instance
        pub fn new(
            cw_glob: String,
            snip120u_code_id: u64,
            snip120u_code_hash: String,
            token_params: Vec<HeadstashTokenParams>,
        ) -> Self {
            Self {
                cw_glob,
                snip120u_code_id,
                snip120u_code_hash,
                headstash_code_id: None,
                token_params,
                headstash: None,
                fee_granter: None,
            }
        }
    }

    impl HeadstashTokenParams {
        /// loads token params for a given coin.
        pub fn from_coin(deps: DepsMut, coin: Coin) -> Result<Self, ContractError> {
            let param = STATE.load(deps.storage).unwrap().headstash_params;
            let token_param = param
                .token_params
                .iter()
                .find(|tp| tp.native == coin.denom || tp.ibc == coin.denom);
            match token_param {
                Some(tp) => {
                    // Create your struct using tp
                    Ok(tp.clone())
                }
                None => {
                    return Err(ContractError::BadHeadstashCoin);
                }
            }
        }
    }

    impl HeadstashParams {}
}

pub mod snip120u {
    use super::*;
    use cosmwasm_std::{Binary, Uint128};
    #[cw_serde]
    pub struct InitialBalance {
        pub address: String,
        pub amount: Uint128,
    }

    #[cw_serde]
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

    #[cw_serde]
    pub struct AddMinters {
        pub minters: Vec<String>,
        pub padding: Option<String>,
    }
    /// This type represents optional configuration values which can be overridden.
    /// All values are optional and have defaults which are more private by default,
    /// but can be overridden if necessary
    #[cw_serde]
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

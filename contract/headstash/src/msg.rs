use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Binary, Uint128};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::state::{Config, Headstash};

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
pub struct Snip120u {
    // native x/bank token for this snip120u
    pub native_token: String,
    // pub name: String,
    pub addr: Addr,
    pub total_amount: Uint128,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
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

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExecuteMsg {
    Add {
        headstash: Vec<Headstash>,
    },
    Claim {
        eth_pubkey: String,
        eth_sig: String,
        heady_wallet: String,
    },
    Clawback {},
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    Config {},
    Dates {},
    Clawback {},
}

#[cw_serde]
pub enum QueryAnswer {
    ConfigResponse {
        config: Config,
    },
    DatesResponse {
        start: u64,
        end: Option<u64>,
        // decay_start: Option<u64>,
        // decay_factor: Option<Uint128>
    },
    ClawbackResponse {
        bool: bool,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MigrateMsg {
    Migrate {},
    StdError {},
}

pub mod snip {
    use cosmwasm_std::{to_binary, Coin, CosmosMsg, StdResult, WasmMsg};

    use crate::{contract::utils::space_pad, state::AllowanceAction};

    use super::*;

    #[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
    pub struct MintMsg {
        pub recipient: String,
        pub amount: Uint128,
        pub allowance: Option<Vec<AllowanceAction>>,
        pub memo: Option<String>,
        pub padding: Option<String>,
    }
    #[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
    pub struct Snip25InitMsg {
        pub name: String,
        pub admin: Option<String>,
        pub symbol: String,
        pub decimals: u8,
        pub prng_seed: Binary,
        pub config: Option<InitConfig>,
        pub supported_denoms: Option<Vec<String>>,
    }

    #[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]

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

    pub fn mint_msg(
        recipient: String,
        amount: Uint128,
        allowance: Vec<AllowanceAction>,
        memo: Option<String>,
        padding: Option<String>,
        block_size: usize,
        callback_code_hash: String,
        contract_addr: String,
    ) -> StdResult<CosmosMsg> {
        to_cosmos_msg(
            MintMsg {
                recipient,
                amount,
                allowance: Some(allowance),
                memo,
                padding,
            },
            block_size,
            callback_code_hash,
            contract_addr,
            None,
        )
    }

    pub fn to_cosmos_msg(
        msg: MintMsg,
        mut block_size: usize,
        code_hash: String,
        contract_addr: String,
        send_amount: Option<Uint128>,
    ) -> StdResult<CosmosMsg> {
        // can not have block size of 0
        if block_size == 0 {
            block_size = 1;
        }
        let mut msg = to_binary(&msg)?;
        space_pad(block_size, &mut msg.0);
        let mut funds = Vec::new();
        if let Some(amount) = send_amount {
            funds.push(Coin {
                amount,
                denom: String::from("uscrt"),
            });
        }
        let execute = WasmMsg::Execute {
            contract_addr,
            code_hash,
            msg,
            funds,
        };
        Ok(execute.into())
    }
}

use crate::types::callbacks;
use crate::{
    state::{
        bloom::{BloomConfig, BloomMsg},
        snip::Snip120u,
        Config, Headstash,
    },
    types::callbacks::IcaControllerCallbackMsg,
};
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Binary, Uint128, Uint64};
use cw_ica_controller_derive::ica_callback_execute;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

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
    /// code-id of custom snip20 contract for headstashes
    // pub snip120u_code_id: u64,
    // /// code hash of custom snip20 contract for headstashes
    pub snip120u_code_hash: String,
    /// A list of custom snip20-headstash contracts.
    /// This contract must be set as an authorized minter for each, or else this contract will not work.
    pub snips: Vec<Snip120u>,
    /// viewing key permit.
    pub viewing_key: String,
    /// Option to enable contract to add multiplier on allocations when claiming. currently 1.33x.
    pub multiplier: bool,
    // /// channel-id used to IBC transfer tokens back to a destination chain.
    // pub channel_id: String,
    /// optional bloom configuration
    pub bloom_config: Option<BloomConfig>,
    // /// The options to initialize the IBC channel upon contract instantiation.
    // pub channel_open_init_options: Option<options::ChannelOpenInitOptions>,
}

/// The info needed to send callbacks
#[cw_serde]
pub struct CallbackInfo {
    /// The address of the callback contract.
    pub address: String,
    /// The code hash of the callback contract.
    pub code_hash: String,
}

#[cw_serde]
pub enum ExecuteMsg {
    AddEligibleHeadStash {
        headstash: Vec<Headstash>,
    },
    Claim {
        sig_addr: String,
        sig: String,
        // amount: Uint128,
    },
    Clawback {},
    // /// Redeems into public versions of the tokens.
    // Redeem {},
    RegisterBloom {
        bloom_msg: BloomMsg,
    },
    PrepareBloom {},
    ProcessBloom {},
    // / `CreateChannel` makes the contract submit a stargate MsgChannelOpenInit to the chain.
    // / This is a wrapper around [`options::ChannelOpenInitOptions`] and thus requires the
    // / same fields. If not specified, then the options specified in the contract instantiation
    // / are used.
    // CreateChannel {
    //     /// The options to initialize the IBC channel.
    //     /// If not specified, the options specified in the last channel creation are used.
    //     /// Must be `None` if the sender is not the owner.
    //     #[serde(skip_serializing_if = "Option::is_none")]
    //     channel_open_init_options: Option<options::ChannelOpenInitOptions>,
    // },
    // /// `CloseChannel` closes the IBC channel.
    // CloseChannel {},
    // /// Recieve callbacks to handle good or bad responses from ibc bloom
    // ReceiveIcaCallback(IcaControllerCallbackMsg),
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

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SudoMsg {
    HandleIbcBloom {},
}

pub mod snip {
    use cosmwasm_std::{to_binary, Coin, CosmosMsg, StdResult, WasmMsg};

    use crate::{contract::utils::space_pad, state::snip::AllowanceAction};

    use super::*;

    #[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
    pub struct Snip120uInitMsg {
        pub name: String,
        pub admin: Option<String>,
        pub symbol: String,
        pub decimals: u8,
        pub prng_seed: Binary,
        pub config: Option<InitConfig>,
        pub supported_denoms: Option<Vec<String>>,
    }

    #[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
    pub struct SetMinters {
        pub minters: Vec<String>,
        pub padding: Option<String>,
    }

    #[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
    pub struct MintMsg {
        pub recipient: String,
        pub amount: Uint128,
        pub allowance: Option<Vec<AllowanceAction>>,
        pub memo: Option<String>,
        pub padding: Option<String>,
    }

    #[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
    pub struct Redeem {
        pub amount: Uint128,
        pub denom: Option<String>,
        pub decoys: Option<Vec<Addr>>,
        pub entropy: Option<Binary>,
        pub padding: Option<String>,
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

    pub fn into_cosmos_msg(
        msg: Redeem,
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

/// Option types for other messages.
pub mod options {
    use crate::ibc::types::{keys::HOST_PORT_ID, metadata::TxEncoding};

    use cosmwasm_std::IbcOrder;

    /// The options needed to initialize the IBC channel.
    #[derive(
        serde::Serialize,
        serde::Deserialize,
        Clone,
        Debug,
        PartialEq,
        cosmwasm_schema::schemars::JsonSchema,
    )]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[schemars(crate = "::cosmwasm_schema::schemars")]
    pub struct ChannelOpenInitOptions {
        /// The connection id on this chain.
        pub connection_id: String,
        /// The counterparty connection id on the counterparty chain.
        pub counterparty_connection_id: String,
        /// The counterparty port id. If not specified, [`crate::ibc::types::keys::HOST_PORT_ID`] is used.
        /// Currently, this contract only supports the host port.
        pub counterparty_port_id: Option<String>,
        /// TxEncoding is the encoding used for the ICA txs. If not specified, [`TxEncoding::Protobuf`] is used.
        pub tx_encoding: Option<TxEncoding>,
        /// The order of the channel. If not specified, [`IbcOrder::Ordered`] is used.
        /// [`IbcOrder::Unordered`] is only supported if the counterparty chain is using `ibc-go`
        /// v8.1.0 or later.
        pub channel_ordering: Option<IbcOrder>,
    }

    impl ChannelOpenInitOptions {
        /// Returns the counterparty port id.
        #[must_use]
        pub fn counterparty_port_id(&self) -> String {
            self.counterparty_port_id
                .clone()
                .unwrap_or_else(|| HOST_PORT_ID.to_string())
        }

        /// Returns the tx encoding.
        #[must_use]
        pub fn tx_encoding(&self) -> TxEncoding {
            self.tx_encoding.clone().unwrap_or(TxEncoding::Protobuf)
        }
    }
}

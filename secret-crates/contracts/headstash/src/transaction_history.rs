use cosmwasm_std::{
    Addr, Api, BlockInfo, CanonicalAddr, Coin, StdError, StdResult, Storage, Uint128,
};
use schemars::JsonSchema;
use secret_toolkit::storage::Item;
use serde::{Deserialize, Serialize};

use crate::state::TX_COUNT;

// Note that id is a globally incrementing counter.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct Tx {
    pub id: u64,
    pub action: TxAction,
    pub coins: Coin,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memo: Option<String>,
    // The block time and block height are optional so that the JSON schema
    // reflects that some SNIP-20 contracts may not include this info.
    pub block_time: u64,
    pub block_height: u64,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TxAction {
    RegisterHeadstash { recipient: Addr },
    Claim { sender: Addr },
    RegisterBloom { sender: Addr },
    Deposit {},
    Redeem {},
}

#[derive(Clone, Copy, Debug)]
#[repr(u8)]
enum TxCode {
    RegisterHeadstash = 0,
    ClaimHeadstash = 1,
    RegisterBloom = 2,
}

impl TxCode {
    fn to_u8(self) -> u8 {
        self as u8
    }

    fn from_u8(n: u8) -> StdResult<Self> {
        use TxCode::*;
        match n {
            0 => Ok(RegisterHeadstash),
            1 => Ok(ClaimHeadstash),
            2 => Ok(RegisterBloom),
            other => Err(StdError::generic_err(format!(
                "Unexpected Tx code in transaction history: {} Storage is corrupted.",
                other
            ))),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub struct StoredTxAction {
    tx_type: u8,
    address1: Option<CanonicalAddr>,
    address2: Option<CanonicalAddr>,
    address3: Option<CanonicalAddr>,
}

impl StoredTxAction {
    pub fn register_headstash(recipient: CanonicalAddr) -> Self {
        Self {
            tx_type: TxCode::RegisterHeadstash.to_u8(),
            address1: Some(recipient),
            address2: None,
            address3: None,
        }
    }
    pub fn claim_headstash(sender: CanonicalAddr) -> Self {
        Self {
            tx_type: TxCode::ClaimHeadstash.to_u8(),
            address1: Some(sender),
            address2: None,
            address3: None,
        }
    }
    pub fn register_ibc_bloom(sender: CanonicalAddr) -> Self {
        Self {
            tx_type: TxCode::RegisterBloom.to_u8(),
            address1: Some(sender),
            address2: None,
            address3: None,
        }
    }

    pub fn into_tx_action(self, api: &dyn Api) -> StdResult<TxAction> {
        let register_headstash_err = || {
            StdError::generic_err(
                "Missing address in stored Transfer transaction. Storage is corrupt",
            )
        };
        let claim_headstash_err = || {
            StdError::generic_err(
                "Missing address in stored Transfer transaction. Storage is corrupt",
            )
        };
        let register_bloom_err = || {
            StdError::generic_err(
                "Missing address in stored Transfer transaction. Storage is corrupt",
            )
        };

        // In all of these, we ignore fields that we don't expect to find populated
        let action = match TxCode::from_u8(self.tx_type)? {
            TxCode::RegisterHeadstash => {
                let recipient = self.address3.ok_or_else(register_headstash_err)?;
                TxAction::RegisterHeadstash {
                    recipient: api.addr_humanize(&recipient)?,
                }
            }
            TxCode::ClaimHeadstash => {
                let sender = self.address1.ok_or_else(claim_headstash_err)?;
                TxAction::Claim {
                    sender: api.addr_humanize(&sender)?,
                }
            }
            TxCode::RegisterBloom => {
                let sender = self.address1.ok_or_else(register_bloom_err)?;
                TxAction::RegisterBloom {
                    sender: api.addr_humanize(&sender)?,
                }
            }
        };

        Ok(action)
    }
}

// Stored types:

#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
pub struct StoredCoin {
    pub denom: String,
    pub amount: u128,
}

impl From<Coin> for StoredCoin {
    fn from(value: Coin) -> Self {
        Self {
            denom: value.denom,
            amount: value.amount.u128(),
        }
    }
}

impl From<StoredCoin> for Coin {
    fn from(value: StoredCoin) -> Self {
        Self {
            denom: value.denom,
            amount: Uint128::new(value.amount),
        }
    }
}

// use with add_suffix tx id (u64 to_be_bytes)
// does not need to be an AppendStore because we never need to iterate over global list of txs
const PREFIX_TXS: &[u8] = b"transactions";
pub static TRANSACTIONS: Item<StoredTx> = Item::new(PREFIX_TXS);

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub struct StoredTx {
    action: StoredTxAction,
    coins: StoredCoin,
    memo: Option<String>,
    block_time: u64,
    block_height: u64,
}

impl StoredTx {
    pub fn into_humanized(self, api: &dyn Api, id: u64) -> StdResult<Tx> {
        Ok(Tx {
            id,
            action: self.action.into_tx_action(api)?,
            coins: self.coins.into(),
            memo: self.memo,
            block_time: self.block_time,
            block_height: self.block_height,
        })
    }
}

// Storage functions:

pub fn append_new_stored_tx(
    store: &mut dyn Storage,
    action: &StoredTxAction,
    amount: u128,
    denom: String,
    memo: Option<String>,
    block: &BlockInfo,
) -> StdResult<u64> {
    // tx ids are serialized starting at 1
    let serial_id = TX_COUNT.load(store).unwrap_or_default() + 1;
    let coins = StoredCoin { denom, amount };
    let stored_tx = StoredTx {
        action: action.clone(),
        coins,
        memo,
        block_time: block.time.seconds(),
        block_height: block.height,
    };

    TRANSACTIONS
        .add_suffix(&serial_id.to_be_bytes())
        .save(store, &stored_tx)?;
    TX_COUNT.save(store, &(serial_id))?;
    Ok(serial_id)
}

#[allow(clippy::too_many_arguments)] // We just need them
pub fn store_register_headstash_action(
    store: &mut dyn Storage,
    receiver: &CanonicalAddr,
    amount: u128,
    denom: String,
    memo: Option<String>,
    block: &BlockInfo,
) -> StdResult<u64> {
    let action = StoredTxAction::register_headstash(receiver.clone());
    append_new_stored_tx(store, &action, amount, denom, memo, block)
}

#[allow(clippy::too_many_arguments)] // We just need them
pub fn store_claim_headstash_action(
    store: &mut dyn Storage,
    sender: &CanonicalAddr,
    amount: u128,
    denom: String,
    memo: Option<String>,
    block: &BlockInfo,
) -> StdResult<u64> {
    let action = StoredTxAction::claim_headstash(sender.clone());
    append_new_stored_tx(store, &action, amount, denom, memo, block)
}

#[allow(clippy::too_many_arguments)] // We just need them
pub fn store_register_bloom_action(
    store: &mut dyn Storage,
    sender: &CanonicalAddr,
    recipient: &CanonicalAddr,
    amount: u128,
    denom: String,
    memo: Option<String>,
    block: &BlockInfo,
) -> StdResult<u64> {
    let action = StoredTxAction::register_ibc_bloom(sender.clone());
    append_new_stored_tx(store, &action, amount, denom, memo, block)
}

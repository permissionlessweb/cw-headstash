use cosmwasm_std::Storage;
use cw_storage_plus::{Item, Map};

use crate::{error::ContractError, msg::HeadstashParams};

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

/// The Map used to determine how to handle ica-callbacks.
/// key: snip120u = first action to take. if false, all other prefixes should fail
/// key: cw-headstash = second action to take. if false, cannot init snips.
/// key: snip120u-init-(len()) = third action to take. if false, cannot init headstash.
///      key defined with enumerated object position for each snip.
/// key: cw-headstash-init = fourth action to take.
pub const HEADSTASH_SEQUENCE: Map<String, bool> = Map::new("");
pub const HEADSTASH_PARAMS: Item<HeadstashParams> = Item::new("hp");

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

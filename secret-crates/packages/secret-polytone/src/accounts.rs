use cosmwasm_std::{Addr, StdResult, Storage};
use secret_toolkit::storage::Keymap;
// use cw_storage_plus::Map;

pub const KEY_PENDING: &[u8] = b"polytone-accounts-pending";
pub const KEY_LOCAL_TO_REMOTE_ACCOUNT: &[u8] = b"polytone-account-map";

/// (channel_id, sequence_number) -> sender
///
/// Maps packets to the address that sent them.
const PENDING: Keymap<(String, u64), Addr> = Keymap::new(KEY_PENDING);

/// (local_account) -> remote_account
///
/// Maps local addresses to their remote counterparts.
const LOCAL_TO_REMOTE_ACCOUNT: Keymap<Addr, String> = Keymap::new(KEY_LOCAL_TO_REMOTE_ACCOUNT);

pub fn on_send_packet(
    storage: &mut dyn Storage,
    channel_id: String,
    sequence_number: u64,
    sender: &Addr,
) -> StdResult<()> {
    PENDING.insert(storage, &(channel_id, sequence_number), sender)
}

pub fn on_ack(
    storage: &mut dyn Storage,
    channel_id: String,
    sequence_number: u64,
    executor: Option<String>,
) {
    let local_account = PENDING
        .get(storage, &(channel_id.clone(), sequence_number))
        .expect("pending was set when sending packet");

    PENDING
        .remove(storage, &(channel_id, sequence_number))
        .expect("should be able to remove");

    if let Some(executor) = executor {
        LOCAL_TO_REMOTE_ACCOUNT
            .insert(storage, &local_account, &executor)
            .expect("strings were loaded from storage, so should serialize");
    }
}

pub fn on_timeout(storage: &mut dyn Storage, channel_id: String, sequence_number: u64) {
    PENDING.remove(storage, &(channel_id, sequence_number));
}

pub fn query_account(storage: &dyn Storage, local_address: Addr) -> StdResult<Option<String>> {
    Ok(LOCAL_TO_REMOTE_ACCOUNT.get(storage, &local_address))
}

#[cfg(test)]
mod tests {
    use cosmwasm_std::testing::mock_dependencies;

    use super::*;

    /// In the event of channel closure, this package will see the
    /// channel ID in packets change. Tests that state is kept
    /// correctly in this event.
    #[test]
    fn test_channel_closure() {
        let mut deps = mock_dependencies();
        let storage = deps.as_mut().storage;

        let channel_id = "channel-0".to_string();
        let sender = Addr::unchecked("sender");

        // send first packet to create account on remote chain.
        on_send_packet(storage, channel_id.clone(), 1, &sender).unwrap();
        on_ack(storage, channel_id, 1, Some("remote".to_string()));

        let remote_account = query_account(storage, sender.clone());

        let channel_id = "channel-1".to_string();

        // send first packet to create account on remote chain.
        on_send_packet(storage, channel_id.clone(), 1, &sender).unwrap();
        on_ack(storage, channel_id, 1, Some("remote".to_string()));

        let new_remote_account = query_account(storage, sender);
        assert_eq!(
            new_remote_account, remote_account,
            "changing the channel shouldn't change the account"
        )
    }
}

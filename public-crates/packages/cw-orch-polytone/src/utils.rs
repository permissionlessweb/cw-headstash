use std::{collections::HashMap, fs::File};

use cosmwasm_std::Addr;
use cw_orch::{core::serde_json, daemon::DeployedChains, prelude::*};

use crate::{
    deploy::{POLYTONE_NOTE, POLYTONE_VOICE},
    interchain::DELIMITER,
    Polytone,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectedPolytone {
    pub chain_id: String,
    pub note: Addr,
    pub voice: Addr,
}

impl<Chain: CwEnv> Polytone<Chain> {
    /// Get list of connected Polytones for chain
    pub fn connected_polytones(&self) -> Vec<ConnectedPolytone> {
        // Get chain id contract addrs
        let state_file = Self::deployed_state_file_path().unwrap();
        let state = if let Ok(module_state_json) = read_json(&state_file) {
            module_state_json
        } else {
            return vec![];
        };
        let env_info = self.note.environment().env_info();
        let contracts: HashMap<String, String> =
            cw_orch::core::serde_json::from_value(state[env_info.chain_id]["default"].clone())
                .unwrap();

        // Sort notes and voices
        let mut notes = HashMap::new();
        let mut voices = HashMap::new();
        for (id, address) in contracts {
            let Some((contract_name, chain_id)) = id.split_once(DELIMITER) else {
                continue;
            };
            if contract_name == POLYTONE_NOTE {
                notes.insert(chain_id.to_owned(), address);
            } else if contract_name == POLYTONE_VOICE {
                voices.insert(chain_id.to_owned(), address);
            }
        }

        // Now if both note and voice have address put it in the list
        let mut result = vec![];
        for (chain_id, note_address) in notes {
            if let Some(voice_address) = voices.get(&chain_id) {
                result.push(ConnectedPolytone {
                    chain_id,
                    note: Addr::unchecked(note_address),
                    voice: Addr::unchecked(voice_address),
                })
            }
        }
        result
    }
}

/// Read a json value from a file
/// Duplicate of `cw_orch::daemon::json_lock::read`, but daemon feature is not enabled on cw_orch
pub(crate) fn read_json(filename: &String) -> cw_orch::anyhow::Result<serde_json::Value> {
    let file = File::open(filename)?;
    let json: serde_json::Value = serde_json::from_reader(file)?;
    Ok(json)
}

#[cfg(test)]
mod tests {
    use super::*;

    use cw_orch::{
        daemon::{networks::XION_TESTNET_1, DaemonBuilder},
        prelude::Deploy,
    };

    use crate::Polytone;

    // From https://github.com/CosmosContracts/juno/blob/32568dba828ff7783aea8cb5bb4b8b5832888255/docker/test-user.env#L2
    const TEST_MNEMONIC: &str = "clip hire initial neck maid actor venue client foam budget lock catalog sweet steak waste crater broccoli pipe steak sister coyote moment obvious choose";

    #[test]
    fn connected_polytones_xion() {
        let daemon = DaemonBuilder::new(XION_TESTNET_1)
            .mnemonic(TEST_MNEMONIC)
            .build()
            .unwrap();
        let polytone = Polytone::load_from(daemon).unwrap();
        let connected_polytones = polytone.connected_polytones();
        assert!(connected_polytones.contains(&ConnectedPolytone {
            chain_id: "pion-1".to_owned(),
            note: Addr::unchecked(
                "xion18eh7m9wdk493y47l0uwc3nqkkxd4qvnsd9t8z80heatyw7j6dd9qdghjsa",
            ),
            voice: Addr::unchecked(
                "xion1hakcf4p6h0urj7nkznm3qvfstdtcw5hsfff2vkzys8fwqw7688vqex5x6w",
            ),
        }));
        assert!(connected_polytones.contains(&ConnectedPolytone {
            chain_id: "osmo-test-5".to_owned(),
            note: Addr::unchecked(
                "xion1865cwl52qzfrcgrzyswxdqhlyuqpyamppr5evj9ja2zy7at8gd6s4u7kd2",
            ),
            voice: Addr::unchecked(
                "xion17dnqgzrd8cq6sph4gmdx4phg47agzkd2mna34hm0xpcumewx0v4s57xhtu",
            ),
        }))
    }
}
use std::path::PathBuf;

use crate::{HeadstashGlob, PolytoneNote, PolytoneProxy, PolytoneVoice};
use cosmwasm_std::Addr;
use cw_orch::{
    contract::Deploy,
    prelude::{
        ConditionalUpload, ContractInstance, CwEnv, CwOrchError, CwOrchInstantiate, CwOrchUpload,
    },
};
use headstash_public::state::HeadstashParams;

use crate::Polytone;

pub const POLYTONE_NOTE: &str = "polytone:note";
pub const POLYTONE_VOICE: &str = "polytone:voice";
pub const POLYTONE_PROXY: &str = "polytone:proxy";
pub const HEADSTASH_GLOB: &str = "headstash:glob";

pub const MAX_BLOCK_GAS: u64 = 100_000_000;

impl<Chain: CwEnv> Deploy<Chain> for Polytone<Chain> {
    type Error = CwOrchError;

    type DeployData = HeadstashParams;

    fn store_on(chain: Chain) -> Result<Self, <Self as Deploy<Chain>>::Error> {
        let polytone = Polytone::new(chain);

        polytone.note.upload()?;
        polytone.voice.upload()?;
        polytone.proxy.upload()?;

        Ok(polytone)
    }

    fn deploy_on(chain: Chain, data: Self::DeployData) -> Result<Self, CwOrchError> {
        // upload
        let deployment = Self::store_on(chain.clone())?;

        deployment.note.instantiate(
            &polytone_note::msg::InstantiateMsg {
                pair: None,
                block_max_gas: MAX_BLOCK_GAS.into(),
                headstash_params: data,
            },
            None,
            &[],
        )?;

        deployment.voice.instantiate(
            &polytone_voice::msg::InstantiateMsg {
                proxy_code_id: deployment.proxy.code_id()?.into(),
                block_max_gas: MAX_BLOCK_GAS.into(),
                contract_addr_len: None,
            },
            None,
            &[],
        )?;

        Ok(deployment)
    }

    fn get_contracts_mut(
        &mut self,
    ) -> Vec<Box<&mut dyn cw_orch::prelude::ContractInstance<Chain>>> {
        vec![
            Box::new(&mut self.note),
            Box::new(&mut self.voice),
            Box::new(&mut self.proxy),
        ]
    }

    fn load_from(_chain: Chain) -> Result<Self, Self::Error> {
        todo!()
        // let mut polytone = Self::new(chain);
        // // We register all the contracts default state
        // polytone.set_contracts_state(None);
        // Ok(polytone)
    }
}

impl<Chain: CwEnv> Polytone<Chain> {
    pub fn new(chain: Chain) -> Self {
        let note = PolytoneNote::new(POLYTONE_NOTE, chain.clone());
        let voice = PolytoneVoice::new(POLYTONE_VOICE, chain.clone());
        let proxy = PolytoneProxy::new(POLYTONE_PROXY, chain.clone());
        let glob = HeadstashGlob::new(HEADSTASH_GLOB, chain.clone());

        Polytone {
            note,
            voice,
            proxy,
            glob,
        }
    }

    pub fn deployed_state_file_path() -> Option<String> {
        let crate_path = env!("CARGO_MANIFEST_DIR");
        Some(
            PathBuf::from(crate_path)
                .join("cw-orch-state.json")
                .display()
                .to_string(),
        )
    }

    pub fn store_if_needed(
        chain: Chain,
        scrt: bool,
    ) -> Result<Self, <Self as Deploy<Chain>>::Error> {
        let polytone = Polytone::load_from(chain.clone())?;
        match scrt {
            true => {
                let sender = chain.sender().clone();
                match polytone.note.latest_is_uploaded()? {
                    true => {}
                    false => {
                        // upload via Any
                    }
                }
                match polytone.proxy.latest_is_uploaded()? {
                    true => {}
                    false => {
                        // upload via Any
                    }
                }
            }

            false => {
                polytone.voice.upload_if_needed()?;
                // polytone.note.upload_if_needed()?;
                // polytone.proxy.upload_if_needed()?;
            }
        }

        Ok(polytone)
    }

    pub(crate) fn instantiate_note(
        &self,
        admin: Option<String>,
        headstash_params: HeadstashParams,
    ) -> Result<Chain::Response, CwOrchError> {
        self.note.instantiate(
            &polytone_note::msg::InstantiateMsg {
                pair: None,
                block_max_gas: MAX_BLOCK_GAS.into(),
                headstash_params,
            },
            admin.map(Addr::unchecked).as_ref(),
            &[],
        )
    }

    /// ONLY USE ON NON SECRET-VM INSTANCES
    pub(crate) fn instantiate_voice(
        &self,
        admin: Option<String>,
    ) -> Result<Chain::Response, CwOrchError> {
        self.voice.instantiate(
            &polytone_voice::msg::InstantiateMsg {
                proxy_code_id: self.proxy.code_id()?.into(),
                block_max_gas: MAX_BLOCK_GAS.into(),
                contract_addr_len: None,
            },
            admin.map(Addr::unchecked).as_ref(),
            &[],
        )
    }
}

// impl<Chain: CwEnv + IbcQueryHandler> Polytone<Chain> {
//     pub fn connect(
//         &self,
//         dst: &Polytone<Chain>,
//         interchain: &impl InterchainEnv<Chain>,
//         headstash_params: HeadstashParams,
//     ) -> Result<PolytoneConnection<Chain>, InterchainError> {
//         // We create a channel between the 2 polytone instances

//         self.instantiate_note(None, headstash_params)?;

//         dst.instantiate_voice(None)?;

//         let polytone_connection = PolytoneConnection::load_from(
//             self.note.environment().clone(),
//             dst.voice.environment().clone(),
//         );

//         polytone_connection.note.set_address(&self.note.address()?);
//         polytone_connection.voice.set_address(&dst.voice.address()?);

//         // We reset the state, this object shouldn't have registered addresses in a normal flow
//         self.note.remove_address();
//         dst.voice.remove_address();

//         // Doing this last as it will has all chances of being cancelled
//         interchain.create_contract_channel(
//             &polytone_connection.note,
//             &polytone_connection.voice,
//             "polytone-1",
//             Some(IbcOrder::Unordered),
//         )?;

//         Ok(polytone_connection)
//     }

//     pub fn connect_if_needed(
//         &self,
//         dst: &Polytone<Chain>,
//         interchain: &impl InterchainEnv<Chain>,
//         hs_params: HeadstashParams,
//     ) -> Result<PolytoneConnection<Chain>, InterchainError> {
//         let polytone_connection = PolytoneConnection::load_from(
//             self.note.environment().clone(),
//             dst.voice.environment().clone(),
//         );
//         if polytone_connection.note.address().is_ok() && polytone_connection.voice.address().is_ok()
//         {
//             return Ok(polytone_connection);
//         }

//         self.connect(dst, interchain, hs_params)
//     }
// }

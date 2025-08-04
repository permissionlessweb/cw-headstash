use std::env;

use anybuf::Anybuf;
use clap::Parser;

use cosmwasm_std::{to_json_binary, Addr, IbcOrder};
use cw_orch_polytone::deploy::MAX_BLOCK_GAS;
use cw_orch_polytone::{PolytoneConnection, PolytoneVoice};
// use cw_ica_controller::types::msg::options::ChannelOpenInitOptions;
use cw_orch::prelude::{ChainInfoOwned, CwOrchInstantiate, Environment};
use cw_orch::{daemon::TxSender, prelude::CwOrchUpload};
use cw_orch_interchain::{
    daemon::{ChannelCreationValidator, DaemonInterchain},
    prelude::*,
};
use cw_orch_polytone::{Polytone, PolytoneNote};
use headstash_public::state::HeadstashParams;
use polytone::headstash::constants::*;
use polytone_voice::msg::ExecuteMsgFns;
use tokio::runtime::Runtime;

pub async fn deploy_polytone(networks: Vec<ChainInfoOwned>) -> anyhow::Result<()> {
    dotenv::from_path(".env").ok();

    // create new cw-orch-interchain object with terp & secret.
    let controller = networks[0].clone();
    let host = networks[1].clone();
    let interchain = DaemonInterchain::new(
        vec![(controller.clone()), (host.clone())],
        &ChannelCreationValidator,
    )?;

    // define chain instance.
    let mut terp = interchain.get_chain(controller.chain_id)?;
    let mut scrt = interchain.get_chain(host.chain_id)?;
    let terp_sender = terp.sender_mut().clone();
    let scrt_sender = scrt.sender_mut().clone();
    let terp_rt = terp.rt_handle.clone();
    let scrt_rt = scrt.rt_handle.clone();

    let mut deployment_owner = terp_sender.pub_addr_str().to_string();
    // use authz if present
    let gov_addr = env::var("GOV_MOD_ADDR")?;
    match gov_addr == "" {
        true => {}
        false => {
            deployment_owner = gov_addr;
            terp.sender_mut()
                .set_authz_granter(&Addr::unchecked(deployment_owner));
        }
    }

    // upload note & listener if code-id's not present
    let terp_polytone = Polytone::new(terp.clone());
    let poly_note_id = env::var("POLYTONE_NOTE_ID")?;
    let pt_listener_id = env::var("POLYTONE_LISTENER_ID")?;
    let mut pt_voice_id = &env::var("POLYTONE_VOICE_ID")?;
    let mut pt_proxy_id = &env::var("POLYTONE_PROXY_ID")?;

    let bytes: Vec<_> = vec![
        include_bytes!("../../../secret-crates/optimized-wasm/polytone_voice.wasm.gz").to_vec(),
        include_bytes!("../../../secret-crates/optimized-wasm/polytone_proxy.wasm.gz").to_vec(),
    ];

    match poly_note_id == "" {
        true => {
            // upload note on controller chain
            terp_polytone.note.upload()?;
            // upload voice & proxy on host chain (secret network)
            for (index, contract) in bytes.iter().enumerate() {
                let res = scrt_rt.block_on(scrt_sender.commit_tx_any(
                    vec![cosmrs::Any {
                        type_url:  SECRET_COMPUTE_STORE_CODE.into(),
                        value: Anybuf::new()
                            .append_string(1, scrt_sender.address().to_string())
                            .append_bytes(2, contract)
                            .append_string(3, "")
                            .append_string(
                                4,
                                "ghcr.io/scrtlabs/secret-contract-optimizer:1.0.13",
                            )
                            .into_vec()
                            .into(),
                    }],
                    None,
                ))?;

                let (_, code_id) = &res.get_attribute_from_logs("compute", "code_id")[0];
                match index {
                    0 => {
                        pt_voice_id = code_id;
                    }
                    1 => {
                        pt_proxy_id = code_id;
                    }
                    _ => {}
                }
            }
        }
        false => {
            // instantiate
        } // create ibc-connections between chains if not existing
    }

    // upload cw-glob on terp

    // instantiate note on terp
    let (_, note_addr) = terp_polytone
        .note
        .instantiate(
            &polytone_note::msg::InstantiateMsg {
                pair: None,
                block_max_gas: MAX_BLOCK_GAS.into(),
                headstash_params: HeadstashParams {
                    cw_glob: todo!(),
                    snip120u_code_id: todo!(),
                    snip120u_code_hash: todo!(),
                    headstash_code_id: todo!(),
                    token_params: todo!(),
                    headstash_addr: todo!(),
                    fee_granter: todo!(),
                    multiplier: todo!(),
                    bloom_config: todo!(),
                    headstash_init_config: todo!(),
                },
            },
            None,
            &[],
        )?
        .get_attribute_from_logs("wasm", "contract_addr")[0];
    // instante voice on scrt
    let init_msg = to_json_binary(&polytone_voice::msg::InstantiateMsg {
        proxy_code_id: u64::from_str_radix(pt_proxy_id.as_str(), 10)?.into(),
        block_max_gas: MAX_BLOCK_GAS.into(),
        contract_addr_len: None,
    })?;
    let res = scrt_rt.block_on(scrt_sender.commit_tx_any(
        vec![cosmrs::Any {
                type_url: SECRET_COMPUTE_INSTANTIATE.into(),
                value: Anybuf::new()
                    .append_string(1, scrt_sender.address().to_string())
                    .append_uint64(3, u64::from_str_radix(pt_voice_id.as_str(), 10)?)
                    .append_string(4, "secret-headstash-polytone-voice")
                    .append_bytes(5, init_msg)
                    .append_repeated_message::<Anybuf>(6, &vec![])
                    // .append_string(8, "secret-admin")
                    .into_vec()
                    .into(),
            }],
        None,
    ))?;
    let (_, voice_addr) = &res.get_attribute_from_logs("compute", "contract_addr")[0];

    let polytone_connection =
        PolytoneConnection::load_from(terp.clone(), scrt.clone(), voice_addr, &note_addr);
    // create contract channel
    let res = interchain.create_contract_channel(
        &polytone_connection.note,
        &polytone_connection.voice,
        "polytone-1",
        Some(IbcOrder::Unordered),
    )?;

    res.interchain_channel.port_a;
    res.interchain_channel.port_b;


    Ok(())
}

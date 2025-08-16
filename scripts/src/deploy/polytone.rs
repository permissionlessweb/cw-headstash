use std::env;
use std::fs::File;
use std::io::Read;

use anybuf::Anybuf;
use clap::Parser;

use cosmwasm_schema::cw_serde;
use cosmwasm_std::{to_json_binary, Addr, IbcOrder};
use cw_glob::msg::InstantiateMsg;
use cw_orch_polytone::deploy::MAX_BLOCK_GAS;
use cw_orch_polytone::{PolytoneConnection, PolytoneVoice};
// use cw_ica_controller::types::msg::options::ChannelOpenInitOptions;
use cw_orch::prelude::{ChainInfo, ChainInfoOwned, CwOrchInstantiate, Environment};
use cw_orch::{daemon::TxSender, prelude::CwOrchUpload};
use cw_orch_interchain::{
    daemon::{ChannelCreationValidator, DaemonInterchain},
    prelude::*,
};
use cw_orch_polytone::{Polytone, PolytoneNote};
use headstash_public::state::{
    BloomConfig, HeadstashInitConfig, HeadstashParams, HeadstashTokenParams,
};
use polytone::headstash::constants::*;
use polytone_voice::msg::ExecuteMsgFns;
use tokio::runtime::Runtime;

#[cw_serde]
pub struct DefaultHeadstashConfig {
    pub token_params: Vec<HeadstashTokenParams>,
    pub bloom_config: Option<BloomConfig>, // Define BloomConfig struct
    pub headstash_init_config: HeadstashInitConfig,
}

use crate::networks::CONTRACT_COMPILER;

pub async fn deploy_polytone(networks: Vec<ChainInfoOwned>) -> anyhow::Result<()> {
    dotenv::from_path(".env").ok();

    let mut file = File::open("headstash_params.json").unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();

    let config: DefaultHeadstashConfig = serde_json::from_str(&contents).unwrap();
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
                .set_authz_granter(&Addr::unchecked(deployment_owner.to_string()));
        }
    }

    // upload note & listener if code-id's not present
    let terp_polytone = Polytone::new(terp.clone());
    let poly_note_id = env::var("POLYTONE_NOTE_ID")?;
    let pt_listener_id = env::var("POLYTONE_LISTENER_ID")?;
    let mut pt_voice_id = env::var("POLYTONE_VOICE_ID")?;
    let mut pt_proxy_id = env::var("POLYTONE_PROXY_ID")?;
    let mut glob_code_id = &env::var("HEADSTASH_GLOB_ID")?;
    let mut snip20_id = &env::var("SNIP20_CODE_ID")?;
    let mut snip20_hash = &env::var("SNIP20_CODE_HASH")?;
    let mut fee_granter = &env::var("HEADSTASH_FEE_GRANTER")?;

    let bytes: Vec<_> = vec![
        include_bytes!("../../../secret-crates/optimized-wasm/polytone_voice.wasm.gz").to_vec(),
        include_bytes!("../../../secret-crates/optimized-wasm/polytone_proxy.wasm.gz").to_vec(),
    ];

    match poly_note_id == "" {
        true => {
            // upload note on controller chain
            terp_polytone.note.upload()?;
        }
        false => {}
    }

    // upload voice & proxy as pair if any are missing
    match pt_voice_id == "" || pt_proxy_id == "" {
        true => {
            // upload voice & proxy on host chain (secret network)
            for (index, contract) in bytes.iter().enumerate() {
                let res = scrt_rt.block_on(scrt_sender.commit_tx_any(
                    vec![cosmrs::Any {
                        type_url:  SECRET_COMPUTE_STORE_CODE.into(),
                        value: Anybuf::new()
                            .append_string(1, scrt_sender.address().to_string())
                            .append_bytes(2, contract)
                            .append_string(3, "")
                            .append_string(4,CONTRACT_COMPILER).into_vec()
                            .into(),
                    }],
                    None,
                ))?;

                let attributes = res.get_attribute_from_logs("compute", "code_id");
                match index {
                    0 => {
                        pt_voice_id = attributes[0].1.clone();
                    }
                    1 => {
                        pt_proxy_id = attributes[0].1.clone();
                    }
                    _ => {}
                }
            }
        }
        false => {}
    }

    // upload cw-glob on terp
    match glob_code_id == "" {
        true => {
            let res = &terp_polytone.glob.upload()?;
            let (_, code_id) = &res.get_attribute_from_logs("wasm", "code_id")[0];
            glob_code_id = &code_id;
        }
        false => {}
    }

    let (_, cw_glob) = &terp_polytone
        .glob
        .instantiate(
            &InstantiateMsg {
                owners: vec![deployment_owner.to_string()],
            },
            Some(&Addr::unchecked(deployment_owner)),
            &[],
        )?
        .get_attribute_from_logs("wasm", "contract_address")[0];

    // instantiate note on terp
    let (_, note_addr) = &terp_polytone
        .note
        .instantiate(
            &polytone_note::msg::InstantiateMsg {
                pair: None,
                block_max_gas: MAX_BLOCK_GAS.into(),
                headstash_params: HeadstashParams {
                    cw_glob: Addr::unchecked(cw_glob),
                    snip120u_code_id: u64::from_str_radix(snip20_id.as_str(), 10)?,
                    snip120u_code_hash: snip20_hash.to_string(),
                    headstash_code_id: None,
                    token_params: config.token_params,
                    headstash_addr: None,
                    fee_granter: Some(fee_granter.to_string()),
                    multiplier: true,
                    bloom_config: config.bloom_config,
                    headstash_init_config: config.headstash_init_config,
                },
            },
            None,
            &[],
        )?
        .get_attribute_from_logs("wasm", "contract_addr")[0];
    // instante voice on scrt
    let init_msg = to_json_binary(&polytone_voice::msg::InstantiateMsg {
        proxy_code_id: u64::from_str_radix(&pt_proxy_id, 10)?.into(),
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

    println!(
        "Contract Channel Creation Acknowledgement Packets: {:#?}",
        res.channel_creation_txs.ack.packets
    );
    println!(
        "Contract Channel Creation Confirmation Packets: {:#?}",
        res.channel_creation_txs.confirm.packets
    );
    println!(
        "Contract Channel Creation Instantiation Packets: {:#?}",
        res.channel_creation_txs.init.packets
    );
    println!("Contract Channel Creation Try Packets (Second step, channel creation open-try (dst_chain)): {:#?}", res.channel_creation_txs.r#try.packets);

    res.interchain_channel.port_a;
    res.interchain_channel.port_b;


    // give cw-glob the secret headstash contract
    // terp_polytone.glob.
    // upload headstash on secret network via our polytone headstash note

    Ok(())
}

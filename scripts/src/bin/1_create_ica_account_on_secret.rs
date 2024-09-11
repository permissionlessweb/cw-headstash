use std::env;

use anybuf::Anybuf;
use clap::Parser;
use cosmwasm_std::{to_json_binary, Addr};
use cw_ica_controller::types::msg::options::ChannelOpenInitOptions;
use cw_orch::daemon::TxSender;
use cw_orch::prelude::ChainInfoOwned;
use cw_orch_interchain::{ChannelCreationValidator, DaemonInterchain, InterchainEnv};
use tokio::runtime::Runtime;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Network to deploy on: main, testnet, local
    #[clap(short, long)]
    network: String,
    /// Address of the x/gov module
    #[clap(short, long)]
    gov_addr: String,
    /// code-id of the cw-ica-controller. This is inferred prior to broadcasting only with permissioned cosmwasm networks.
    #[clap(short, long)]
    code_id: u64,
    #[clap(short, long)]
    controller_connection_id: String,
    #[clap(short, long)]
    host_connection_id: String,
}

pub fn main() {
    let args = Args::parse();
    println!("Step 1: Upload and instantiate the cw-ica-controller account");

    let controller_chain = match args.network.as_str() {
        "main" => headstash_scripts::networks::TERP_MAINNET.to_owned(),
        "testnet" => headstash_scripts::networks::TERP_TESTNET.to_owned(),
        "local" => headstash_scripts::networks::LOCAL_NETWORK1.to_owned(),
        _ => panic!("Invalid network"),
    };
    let host_chain = match args.network.as_str() {
        "main" => headstash_scripts::networks::SECRET_MAINNET.to_owned(),
        "testnet" => headstash_scripts::networks::SECRET_TESTNET.to_owned(),
        "local" => panic!("Invalid network"),
        _ => panic!("Invalid network"),
    };

    if let Err(ref err) = deploy_cw_ica_controller(
        vec![controller_chain.into(), host_chain.into()],
        args.gov_addr,
        args.code_id,
        args.controller_connection_id,
        args.host_connection_id,
    ) {
        log::error!("{}", err);
        err.chain()
            .skip(1)
            .for_each(|cause| log::error!("because: {}", cause));

        ::std::process::exit(1);
    }
}

pub fn deploy_cw_ica_controller(
    networks: Vec<ChainInfoOwned>,
    gov_addr: String,
    cw_ica_code_id: u64,
    controller_connection_id: String,
    host_connection_id: String,
) -> anyhow::Result<()> {
    // create a new runtime instance
    let rt = Runtime::new()?;

    // define env variables
    let mnemonic = env::var("MNEMONIC")?;

    // create new cw-orch-interchain oobject with terp & secret.
    let controller = networks[0].clone();
    let interchain = DaemonInterchain::new(
        vec![(controller.clone(), Some(mnemonic.clone()))],
        &ChannelCreationValidator,
    )?;

    // define chain instance.
    let mut terp = interchain.get_chain(controller.chain_id)?;
    // let mut secret = interchain.get_chain(host.chain_id)?;
    terp.authz_granter(&Addr::unchecked(&gov_addr));

    let terp_sender = terp.sender().clone();

    // upload
    rt.block_on(terp_sender.commit_tx_any(
        vec![cosmrs::Any {
            type_url: "/cosmwasm.wasm.v1.MsgStoreCode".into(),
            value: Anybuf::new()
                .append_string(1, terp.sender().address())
                .append_bytes(2, include_bytes!("../../artifacts/cw_headstash.wasm"))
                .into_vec()
                .into(),
            }],
        "Upload cw-headstash".into(),
    ))?;

    // create cw-ica-controller
    let create_ica = cw_ica_controller::types::msg::InstantiateMsg {
        owner: Some(gov_addr.clone()),
        channel_open_init_options: ChannelOpenInitOptions {
            connection_id: controller_connection_id,
            counterparty_connection_id: host_connection_id,
            counterparty_port_id: None,
            channel_ordering: None,
        },
        send_callbacks_to: None,
    };

    let init = cosmrs::Any {
        type_url: "/cosmwasm.wasm.v1.MsgInstantiateContract".to_string(),
        value: Anybuf::new()
            .append_string(1, terp.sender().address().to_string())
            .append_string(2, gov_addr.clone())
            .append_uint64(3, cw_ica_code_id)
            .append_string(4, "Cw ICA Controller Contract")
            .append_bytes(5, to_json_binary(&create_ica)?.to_vec())
            .append_repeated_message::<Anybuf>(6, &vec![])
            .into_vec()
            .into(),
    };
    let res = rt.block_on(terp_sender.commit_tx_any(vec![init.into()], None))?;
    println!("{:#?}", res);

    Ok(())
}

use std::env;

use anybuf::Anybuf;
use clap::Parser;
use cosmwasm_std::to_json_binary;
use cw_ica_controller::types::msg::options::ChannelOpenInitOptions;
use cw_orch::daemon::TxSender;
use cw_orch::prelude::ChainInfoOwned;
use cw_orch_interchain::{ChannelCreationValidator, DaemonInterchain, InterchainEnv};
use headstash_scripts::constants::*;
use tokio::runtime::Runtime;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Network to deploy on: main, testnet, local
    #[clap(short, long)]
    network: String,
    /// step of ica account creation: upload, instantiate
    #[clap(short, long)]
    step: String,
    /// Address of the x/gov module
    #[clap(short, long)]
    gov_addr: Option<String>,
    /// code-id of the cw-ica-controller. This is inferred prior to broadcasting only with permissioned cosmwasm networks.
    #[clap(long)]
    code_id: Option<u64>,
    #[clap(short, long)]
    controller_connection_id: String,
    #[clap(long)]
    host_connection_id: String,
}

/// Upload and instantiate a cw-instance of an interchain account, between two networks (controller & host)
/// upload example: cargo run --bin ica-controller-deploy -- --network testnet --step upload  --controller-connection-id connection-04 --host-connection-id connection-95 --gov-addr terp123..
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
        args.step,
        args.controller_connection_id,
        args.host_connection_id,
    ) {
        println!("{:#?}", err);
        log::error!("{}", err);
        err.chain()
            .skip(1)
            .for_each(|cause| log::error!("because: {}", cause));

        ::std::process::exit(1);
    }
}

pub fn deploy_cw_ica_controller(
    networks: Vec<ChainInfoOwned>,
    gov_addr: Option<String>,
    cw_ica_code_id: Option<u64>,
    step: String,
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
    let terp = interchain.get_chain(controller.chain_id)?;

    // handle if gov address is provided
    if let Some(addr) = gov_addr {
        terp.authz_granter(&Addr::unchecked(&addr));
    }

    let owner = match gov_addr {
        Some(addr) => Addr::unchecked(&addr),
        None => terp_sender.address(),
    };

    let terp_sender = terp.sender().clone();

    match step.as_str() {
        //
        "upload" => {
            // todo: upload cw-glob, ica-owner, ica-controller
        }
        "instantiate" => {
            // todo: instantiate ica-owner, instantiate cw-glob, set-cw-glob, create ica via executeMsg
        }
        _ => {}
    }

    Ok(())
}

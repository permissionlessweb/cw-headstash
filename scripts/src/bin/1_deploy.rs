use std::env;

use anybuf::Anybuf;
use clap::Parser;
use cosmrs::proto::cosmwasm::wasm::v1::MsgInstantiateContractResponse;
use cosmrs::proto::ibc::applications::interchain_accounts::host;
use cosmwasm_std::to_json_binary;
// use cw_ica_controller::types::msg::options::ChannelOpenInitOptions;
use cw_orch::prelude::{ChainInfoOwned, Environment};
use cw_orch::{daemon::TxSender, prelude::CwOrchUpload};
use cw_orch_interchain::core::InterchainEnv;

use cw_orch_polytone::{Polytone, PolytoneNote};
use headstash_scripts::deploy::polytone::deploy_polytone;
use tokio::runtime::Runtime;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Network to deploy on: main, testnet, local
    #[clap(short, long)]
    network: String,
    /// method to use (ica-controller, polytone, or direct)
    #[clap(short, long)]
    method: String,
}

pub fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    println!("Step 1: Upload and instantiate the contracts");

    let (controller_chain, host_chain) = match args.network.as_str() {
        "main" => (
            headstash_scripts::networks::TERP_MAINNET.to_owned(),
            headstash_scripts::networks::SECRET_MAINNET.to_owned(),
        ),
        "testnet" => (
            headstash_scripts::networks::TERP_TESTNET.to_owned(),
            headstash_scripts::networks::SECRET_TESTNET.to_owned(),
        ),
        "local" => (
            headstash_scripts::networks::TERP_LOCAL.to_owned(),
            headstash_scripts::networks::SECRET_LOCAL.to_owned(),
        ),
        _ => panic!("Invalid network"),
    };

    // 1.
    let rt = Runtime::new()?;
    if let Err(ref err) = match args.method.as_str() {
        "polytone" => rt.block_on(deploy_polytone(vec![
            controller_chain.into(),
            host_chain.into(),
        ])),
        // "ica-controller" => {
        //     deploy_cw_ica_controller(vec![controller_chain.into(), host_chain.into()])
        // }
        "direct" => rt.block_on(deploy_direct(vec![
            controller_chain.into(),
            host_chain.into(),
        ])),
        _ => panic!("Invalid method"),
    } {
        println!("{:#?}", err);
        log::error!("{}", err);
        err.chain()
            .skip(1)
            .for_each(|cause| log::error!("because: {}", cause));

        ::std::process::exit(1);
    } else {
    };
    Ok(())
}

// pub fn deploy_cw_ica_controller(networks: Vec<ChainInfoOwned>) -> anyhow::Result<()> {
//     let rt = Runtime::new()?;
//     dotenv::from_path(".env").ok();
//     let mnemonic = env::var("MNEMONIC")?;

//     // create new cw-orch-interchain object with terp & secret.
//     let controller = networks[0].clone();
//     let interchain = DaemonInterchain::new(
//         vec![(controller.clone(), Some(mnemonic.clone()))],
//         &ChannelCreationValidator,
//     )?;

//     // define chain instance.
//     let terp = interchain.get_chain(controller.chain_id)?;

//     // handle if gov address is provided
//     if let Some(addr) = gov_addr {
//         terp.authz_granter(&Addr::unchecked(&addr));
//     }

//     let owner = match gov_addr {
//         Some(addr) => Addr::unchecked(&addr),
//         None => terp_sender.address(),
//     };

//     let terp_sender = terp.sender().clone();

//     Ok(())
// }

pub async fn deploy_direct(networks: Vec<ChainInfoOwned>) -> anyhow::Result<()> {
    let rt = Runtime::new()?;
    dotenv::from_path(".env").ok();
    let mnemonic = env::var("MNEMONIC")?;

    // upload cw-headstash if non-existing

    // instantiate cw-headstash

    // fund headstash

    // add eligible headstashes

    Ok(())
}

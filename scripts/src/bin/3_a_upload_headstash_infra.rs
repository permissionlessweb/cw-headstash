use std::env;

use anybuf::Anybuf;
use clap::Parser;
use cosmwasm_std::{to_json_binary, Addr};
use cw_headstash::msg::Snip120u;
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
    ///step of the headstash creation workflow (upload, instantiate, authorize)
    #[clap(short, long)]
    step: String,
    /// address of the ica-host account contolled by the cw-ica-controller.
    #[clap(short, long)]
    ica_addr: String,
    /// address of the cw-ica-controller contract.
    #[clap(short, long)]
    cw_ica_addr: Option<String>,
    /// code-id of the headstash contract. only used for step 2 (instantiate)
    #[clap(short, long)]
    gov_addr: Option<String>,
    /// code-id of the headstash contract. only used for step 2 (instantiate)
    #[clap(short, long)]
    headstash_code_id: Option<u64>,
    /// checksum hash of the headstash contract. only used for step 2 (instantiate)
    #[clap(short, long)]
    headstash_code_hash: Option<String>,
    /// code-id of the snip120u contract. only used for step 2 (instantiate)
    #[clap(short, long)]
    snip120u_code_id: Option<u64>,
    /// checksum hash of the snip120u contract. only used for step 2 (instantiate)
    #[clap(short, long)]
    snip120u_code_hash: Option<String>,
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

    //    let msg =  match args.step.as_str() {
    //         "upload" => ,
    //         "instantiate" => {}
    //         "authorize" => {}
    //         _ => panic!("Invalid step"),
    //     }

    if let Err(ref err) = upload_headstash_contracts_as_secret_ica(
        &args.step,
        args.gov_addr,
        vec![controller_chain.into(), host_chain.into()],
        args.cw_ica_addr,
        args.ica_addr,
    ) {
        log::error!("{}", err);
        err.chain()
            .skip(1)
            .for_each(|cause| log::error!("because: {}", cause));

        ::std::process::exit(1);
    }
}

fn upload_headstash_contracts_as_secret_ica(
    step: &str,
    gov_addr: Option<String>,
    networks: Vec<ChainInfoOwned>,
    cw_ica_addr: Option<String>,
    ica_addr: String,
) -> anyhow::Result<()> {
    let rt = Runtime::new()?;
    // define env variables
    let mnemonic = env::var("MNEMONIC")?;

    // create new cw-orch-interchain oobject with terp & secret.
    let controller = networks[0].clone();
    let host = networks[1].clone();
    let mut interchain = DaemonInterchain::new(
        vec![
            (controller.clone(), Some(mnemonic.clone())),
            (host.clone(), Some(mnemonic)),
        ],
        &ChannelCreationValidator,
    )?;
    let terp_ica_addr = Addr::unchecked(ica_addr);

    let mut secret = interchain.get_chain(host.chain_id)?;
    // 5. upload headstash contract on Secret Network, as Terp Network ICA account.

    secret.authz_granter(&terp_ica_addr);
    let secret_sender = secret.sender();

    rt.block_on(secret_sender.commit_tx_any(
        vec![cosmrs::Any {
                    type_url: "/secret.compute.v1beta1.MsgStoreCode".into(),
                    value: Anybuf::new()
                        .append_string(1, secret.sender().address())
                        .append_bytes(2, include_bytes!("../../artifacts/cw_headstash.wasm"))
                        .into_vec()
                        .into(),
                    }],
        "Upload cw-headstash".into(),
    ))?;

    rt.block_on(secret_sender.commit_tx_any(
        vec![cosmrs::Any {
                    type_url: "/secret.compute.v1beta1.MsgStoreCode".into(),
                    value: Anybuf::new()
                        .append_string(1, secret.sender().address())
                        .append_bytes(2, include_bytes!("../../artifacts/snip120u.wasm"))
                        .into_vec()
                        .into(),
                    }],
        "Upload snip120u".into(),
    ))?;

    Ok(())
}

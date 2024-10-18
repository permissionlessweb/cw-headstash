use std::env;

use anybuf::Anybuf;
use clap::Parser;
use cosmwasm_std::{to_json_binary, Addr, CosmosMsg, StdError, Uint128};
use cw_headstash::msg::{snip::Snip120uInitMsg, Snip120u};
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
    /// address of the ica-host account contolled by the cw-ica-controller, on the host chain.
    #[clap(short, long)]
    ica_addr: String,
    /// address of the cw-ica-controller contract, on the controller chain.
    #[clap(short, long)]
    cw_ica_addr: String,
    /// x/gov module addresss, on the controller chain.
    #[clap(short, long)]
    gov_addr: Option<String>,
    /// code-id of headstash on secret network
    #[clap(short, long)]
    snip120u_code_id: u64,
    /// checksum hash of the headstash contract. only used for step 2 (instantiate)
    #[clap(short, long)]
    snip120u_code_hash: String,
    /// JSON string defining the snip120u to init
    #[clap(short, long)]
    snip120u: String,
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

    let snip120u = match serde_json::from_str::<Vec<Snip120uInitMsg>>(&args.snip120u) {
        Ok(token_info) => {
            // Use into_iter to convert each Snip120u struct into the required format
            let result = token_info
                .into_iter()
                .map(|mut snip120u| Snip120uInitMsg::from(snip120u))
                .collect::<Vec<Snip120uInitMsg>>();
            Ok(result)
        }
        Err(err) => {
            // Handle any errors that occur during parsing
            println!("Error parsing JSON: {}", err);
            Err(StdError::generic_err("invalid utf8"))
        }
    }
    .unwrap();

    if let Err(ref err) = create_all_snip120u(
        vec![controller_chain.into(), host_chain.into()],
        args.gov_addr,
        args.snip120u_code_id,
        args.snip120u_code_hash,
        args.cw_ica_addr,
        args.ica_addr,
        snip120u,
    ) {
        log::error!("{}", err);
        err.chain()
            .skip(1)
            .for_each(|cause| log::error!("because: {}", cause));

        ::std::process::exit(1);
    }
}

fn create_all_snip120u(
    networks: Vec<ChainInfoOwned>,
    gov_addr: Option<String>,
    snip120u_code_id: u64,
    snip120u_code_hash: String,
    cw_ica_addr: String,
    ica_addr: String,
    snip120u: Vec<Snip120uInitMsg>,
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

    let mut terp = interchain.get_chain(controller.chain_id)?;
    let mut secret = interchain.get_chain(host.chain_id)?;

    // wrap msgs with authz from the protocol owned ica-account
    secret.authz_granter(&Addr::unchecked(terp_ica_addr));
    
    // wrap the controller msg with authz from x/gov module
    if let Some(addr) = gov_addr {
        terp.authz_granter(&Addr::unchecked(&addr));
    }
    let terp_sender = terp.sender();

    for init_msg in snip120u {
        // msg to run as ica on secret
        let msg_for_ica = cw_ica_controller::types::msg::ExecuteMsg::SendCosmosMsgs {
            messages: vec![CosmosMsg::Stargate {
                type_url: SECRET_COMPUTE_INSTANTIATE.into(),
                value: Anybuf::new()
                    .append_string(1, secret.sender().address())
                    .append_uint64(3, snip120u_code_id.clone())
                    .append_string(4, "Snip120u")
                    .append_bytes(5, to_json_binary(&init_msg)?)
                    .append_repeated_message::<Anybuf>(6, &vec![])
                    // no vm level admin.
                    .into_vec()
                    .into(),
            }],
            packet_memo: None,
            timeout_seconds: None,
        };

        rt.block_on(terp_sender.commit_tx_any(
            vec![cosmrs::Any {
                type_url: COSMWASM_EXECUTE.into(),
                value: Anybuf::new()
                    .append_string(1, terp_sender.address())
                    .append_string(2, cw_ica_addr.clone())
                    .append_bytes(3, to_json_binary(&msg_for_ica)?
                )
                .append_repeated_bytes::<Vec<u8>>(5, &[])
                    .into_vec()
                    .into(),
            }],
            "".into(),
        ))?;
    }

    Ok(())
}

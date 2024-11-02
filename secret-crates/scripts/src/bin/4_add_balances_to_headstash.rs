use std::{env, fs};

use anybuf::Anybuf;
use clap::Parser;
use cosmwasm_std::{to_json_binary, Addr, CosmosMsg};
use cw_headstash::{
    msg::{snip, Snip120u},
    state::Headstash,
};
use cw_ica_controller::types::msg::options::ChannelOpenInitOptions;
use cw_orch::daemon::TxSender;
use cw_orch::prelude::ChainInfoOwned;
use cw_orch_interchain::{ChannelCreationValidator, DaemonInterchain, InterchainEnv};
use headstash_scripts::constants::{COSMWASM_EXECUTE, SECRET_COMPUTE_EXECUTE};
use tokio::{runtime::Runtime, time};

#[cosmwasm_schema::cw_serde]
pub struct AddEligibleHeadStash {
    headstash: Vec<Headstash>,
}

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Network to deploy on: main, testnet, local
    #[clap(short, long)]
    network: String,
    /// address of the ica-host account contolled by the cw-ica-controller.
    #[clap(short, long)]
    ica_addr: String,
    /// address of the cw-ica-controller contract.
    #[clap(short, long)]
    cw_ica_addr: String,
    /// code-id of the headstash contract. only used for step 2 (instantiate)
    #[clap(short, long)]
    gov_addr: Option<String>,
    /// path to JSON file containing eligible headstash claimers & their allocations.
    #[clap(short, long)]
    headstash_addr: String,
    /// path to JSON file containing eligible headstash claimers & their allocations.
    #[clap(short, long)]
    eligible: String,
    /// path to JSON file containing eligible headstash claimers & their allocations.
    #[clap(short, long)]
    batch_size: usize,
}

#[tokio::main]
pub async fn main() {
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

    if let Err(ref err) = batch_add_eligible_headstash_claimers(
        vec![controller_chain.into(), host_chain.into()],
        args.gov_addr,
        args.headstash_addr,
        args.cw_ica_addr,
        args.ica_addr,
        args.batch_size,
    )
    .await
    {
        log::error!("{}", err);
        err.chain()
            .skip(1)
            .for_each(|cause| log::error!("because: {}", cause));

        ::std::process::exit(1);
    }
}

async fn batch_add_eligible_headstash_claimers(
    networks: Vec<ChainInfoOwned>,
    gov_addr: Option<String>,
    headstash_addr: String,
    cw_ica_addr: String,
    ica_addr: String,
    batch_size: usize,
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

    if let Some(addr) = gov_addr {
        terp.authz_granter(&Addr::unchecked(&addr));
    }
    
    let secret_sender = secret.sender();
    let terp_sender = terp.sender();

    let headstash_json = fs::read_to_string("../../example-data/distribution")
        .map_err(|err| format!("Error reading file: {}", err))
        .unwrap();

    let add_eligible_hs_addr: AddEligibleHeadStash = serde_json::from_str(&headstash_json)
        .map_err(|err| format!("Error parsing JSON: {}", err))
        .unwrap();

    let num_batches =
        (add_eligible_hs_addr.headstash.len() as f64 / batch_size as f64).ceil() as usize;

    for index in 0..num_batches {
        let end_index = std::cmp::min(
            (index + 1) * batch_size,
            add_eligible_hs_addr.headstash.len(),
        );

        // Print the current batch of data
        println!(
            "Batch {}: {:?}",
            index,
            &add_eligible_hs_addr.headstash[index * batch_size..end_index]
        );

        let add_hs_msg = cw_headstash::msg::ExecuteMsg::AddEligibleHeadStash {
            headstash: add_eligible_hs_addr.headstash[index * batch_size..end_index].to_vec(),
        };

        let msg_for_ica = cw_ica_controller::types::msg::ExecuteMsg::SendCosmosMsgs {
            messages: vec![CosmosMsg::Stargate {
                type_url: SECRET_COMPUTE_EXECUTE.into(),
                value: Anybuf::new()
                    .append_string(1, secret_sender.address())
                    .append_string(2, headstash_addr.clone())
                    .append_bytes(3, to_json_binary(&add_hs_msg)?)
                    .append_repeated_message::<Anybuf>(5, &vec![])
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
                        )  .append_repeated_bytes::<Vec<u8>>(5, &[])
                            .into_vec()
                            .into(),
                    }],
            "".into(),
        ))?;

        // Wait for 6 seconds before processing the next batch
        tokio::time::sleep(time::Duration::from_millis(6000)).await;
    }

    Ok(())
}

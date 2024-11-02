use std::env;

use anybuf::Anybuf;
use clap::Parser;
use cosmrs::{
    proto::cosmos::authz::v1beta1::{GenericAuthorization, Grant, MsgGrant},
    tx::MessageExt,
    Any,
};
use cosmwasm_std::{to_json_binary, Addr, Binary, CosmosMsg};
use cw_orch::daemon::TxSender;
use cw_orch::prelude::ChainInfoOwned;
use cw_orch_interchain::{ChannelCreationValidator, DaemonInterchain, InterchainEnv};
use headstash_scripts::{constants::*, SECRET_COMPUTE_INSTANTIATE};
use tokio::runtime::Runtime;


#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Network to deploy on: main, testnet, local
    #[clap(short, long)]
    network: String,
    /// Addr of the ica-controller contract, on controller chain.
    #[clap(short, long)]
    cw_ica_addr: String,
    /// Addr of the ICA, on host chain.
    #[clap(short, long)]
    ica_addr: String,
    /// Addr to be authorized by the ICA account
    #[clap(short, long)]
    deployer_addr: String,
    /// Addr of the controller chain x/gov module
    #[clap(short, long)]
    gov_module: Option<String>,
}

/// helper function to grant a wallet authorization to perform functions on behalf of the ICA account, on the Host chain. 
/// This is to avoid the need to include wasm blobs in ibc-packets, greatly increasing the size of packets to chains during ibc lifecycle.
pub fn main() {
    println!("Step 2: Authorize a wallet to upload as the Terp Network ICA account on Secret...",);
    let args = Args::parse();

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

    if let Err(ref err) = authorize_secret_addr_as_terp_ica(
        vec![controller_chain.into(), host_chain.into()],
        args.cw_ica_addr,
        args.ica_addr,
        args.deployer_addr,
        args.gov_module,
    ) {
        log::error!("{}", err);
        err.chain()
            .skip(1)
            .for_each(|cause| log::error!("because: {}", cause));

        ::std::process::exit(1);
    }
}

pub fn authorize_secret_addr_as_terp_ica(
    networks: Vec<ChainInfoOwned>,
    cw_ica_addr: String,
    ica_addr: String,
    deployer_addr: String,
    gov_module: Option<String>,
) -> anyhow::Result<()> {
    let rt = Runtime::new()?;

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

    // handle if gov address is provided
    if let Some(addr) = gov_addr {
        terp.authz_granter(&Addr::unchecked(&addr));
    }
    let terp_sender = terp.sender();
        

    // 1. grant authorizations to secret network deployment address
    let grant_msgs: Vec<MsgGrant> = vec![
        SECRET_COMPUTE_STORE_CODE,
        SECRET_COMPUTE_INSTANTIATE,
        SECRET_COMPUTE_EXECUTE,
    ]
    .into_iter()
    .map(|msg| {
        let authorization = GenericAuthorization {
            msg: msg.to_string(),
        };
        let any_authorization = Any {
            type_url: COSMOS_GENERIC_AUTHZ.to_string(),
            value: authorization.to_bytes().unwrap(),
        };
        let grant = Grant {
            authorization: Some(any_authorization),
            expiration: None,
        };
        MsgGrant {
            granter: terp_ica_addr.to_string(),
            grantee: deployer_addr.clone(),
            grant: Some(grant),
        }
    })
    .collect();

    for grant in grant_msgs {
        // define ica-controller msg
        let msg = cw_ica_controller::types::msg::ExecuteMsg::SendCosmosMsgs {
            messages: vec![CosmosMsg::Stargate {
                type_url: COSMOS_AUTHZ_GRANT.into(),
                value: Binary::new(grant.to_bytes()?),
            }],
            packet_memo: None,
            timeout_seconds: None,
        };

        rt.block_on(terp_sender.commit_tx_any(
            vec![cosmrs::Any {
                    type_url: COSMWASM_EXECUTE.into(),
                    value: Anybuf::new()
                        .append_string(1, terp.sender().address()) // send as wallet authorized by gov
                        .append_string(2, terp_ica_addr.to_string()) // call the ica-account
                        .append_bytes(3, to_json_binary(&msg)? // cw-ica SendCosmosMsgs
                    ).append_repeated_bytes::<Vec<u8>>(5, &[]) // funds
                        .into_vec()
                        .into(),
                }],
            "Grant authorization for secret wasm actions, on behalf of the protocol owned ICA.".into(),
        ))?;
    }

    Ok(())
}

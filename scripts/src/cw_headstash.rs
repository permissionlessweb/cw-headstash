use std::env;

use crate::networks::ping_grpc;
use anybuf::Anybuf;
use clap::Parser;
use cosmwasm_std::{to_json_binary, Addr, CosmosMsg};
use cw_orch::{
    daemon::{DaemonBuilder, TxSender},
    prelude::ChainInfoOwned,
};
use tokio::runtime::Runtime;

//gzip -9 -c snip120u.wasm > snip120u.wasm.gz

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Network to deploy on: main, testnet, local
    #[clap(short, long)]
    network: String,
    /// cw-ica-controller contract address
    #[clap(short, long)]
    ica: String,
}

pub fn main() {
    let args = Args::parse();

    println!("Deploying Headstash Framework As Governance Module...",);
    let bitsong_chain = match args.network.as_str() {
        "main" => crate::networks::TERP_MAINNET.to_owned(),
        "testnet" => crate::networks::TERP_TESTNET.to_owned(),
        "local" => crate::networks::LOCAL_NETWORK1.to_owned(),
        _ => panic!("Invalid network"),
    };

    if let Err(ref err) = deploy_as_gov(bitsong_chain.into(), args.ica) {
        log::error!("{}", err);
        err.chain()
            .skip(1)
            .for_each(|cause| log::error!("because: {}", cause));

        // The backtrace is not always generated. Try to run this example
        // with `$env:RUST_BACKTRACE=1`.
        //    if let Some(backtrace) = e.backtrace() {
        //        log::debug!("backtrace: {:?}", backtrace);
        //    }

        ::std::process::exit(1);
    }
}

fn deploy_as_gov(network: ChainInfoOwned, ica: String) -> anyhow::Result<()> {
    let rt = Runtime::new()?;

    let mnemonic = env::var("MNEMONIC")?;
    let gov_module = env::var("GOV_MODULE").expect("GOV_MODULE must be set");

    // rt.block_on(assert_wallet_balance(vec![network.clone()]));

    let urls = network.grpc_urls.to_vec();
    for url in urls {
        rt.block_on(ping_grpc(&url))?;
    }
    // define chain instance.
    let mut chain = DaemonBuilder::new(network.clone())
        .handle(rt.handle())
        .mnemonic(std::env::var(mnemonic)?)
        .build()?;

    // send message under authorization of governance module
    chain.authz_granter(&Addr::unchecked(gov_module.clone()));
    let wallet = chain.sender();

    #[allow(deprecated)]
    let upload_headstash = cw_ica_controller::types::msg::ExecuteMsg::SendCosmosMsgs {
        messages: vec![CosmosMsg::Stargate {
            type_url: "/cosmwasm.wasm.v1.MsgStoreCode".into(),
            value: Anybuf::new()
                .append_string(1, chain.sender().address())
                .append_bytes(2, include_bytes!("../artifacts/cw_headstash.wasm"))
                .into_vec()
                .into(),
        }],
        packet_memo: None,
        timeout_seconds: Some(60u64),
    };

    rt.block_on(wallet.commit_tx_any(
        vec![cosmrs::Any {
                type_url: "/cosmwasm.wasm.v1beta1.MsgExecuteContract".into(),
                value: Anybuf::new()
                    .append_string(1, chain.sender().address())
                    .append_string(2, ica.clone())
                    .append_bytes(3, to_json_binary(&upload_headstash)?)
                    .into_vec()
                    .into(),
            }],
        "1. upload headstash as cw-ica".into(),
    ))?;

    #[allow(deprecated)]
    let upload_snip120u = cw_ica_controller::types::msg::ExecuteMsg::SendCosmosMsgs {
        messages: vec![CosmosMsg::Stargate {
            type_url: "/cosmwasm.wasm.v1.MsgStoreCode".into(),
            value: Anybuf::new()
                .append_string(1, chain.sender().address())
                .append_bytes(2, include_bytes!("../artifacts/snip120u.wasm"))
                .into_vec()
                .into(),
        }],
        packet_memo: None,
        timeout_seconds: Some(60u64),
    };

    rt.block_on(wallet.commit_tx_any(
        vec![cosmrs::Any {
                type_url: "/cosmwasm.wasm.v1beta1.MsgExecuteContract".into(),
                value: Anybuf::new()
                    .append_string(1, chain.sender().address())
                    .append_string(2,ica.clone()).append_bytes(3, to_json_binary(&upload_snip120u)?)
                    .into_vec()
                    .into(),
            }],
        "2. upload snip120u as cw-ica".into(),
    ))?;

    #[allow(deprecated)]
    let upload_circuitboard = cw_ica_controller::types::msg::ExecuteMsg::SendCosmosMsgs {
        messages: vec![CosmosMsg::Stargate {
            type_url: "/cosmwasm.wasm.v1.MsgStoreCode".into(),
            value: Anybuf::new()
                .append_string(1, chain.sender().address())
                .append_bytes(
                    2,
                    include_bytes!("../artifacts/headstash_circuitboard.wasm"),
                )
                .into_vec()
                .into(),
        }],
        packet_memo: None,
        timeout_seconds: Some(60u64),
    };

    //
    rt.block_on(wallet.commit_tx_any(
        vec![cosmrs::Any {
                type_url: "/cosmwasm.wasm.v1beta1.MsgExecuteContract".into(),
                value: Anybuf::new()
                    .append_string(1, chain.sender().address())
                    .append_string(2, ica.clone())
                    .append_bytes(3, to_json_binary(&upload_circuitboard)?)
                    .into_vec()
                    .into(),
            }],
        "3. upload headstash-circuitboard as cw-ica".into(),
    ))?;
    // 4. instantiate TERP & THIOL snip120u as cw-ica
    // 5. instantiate headstash contract as cw-ica
    // 6. instantiate headstash-circuitboard as cw-ica
    // 7. authorize headstash as snip120u minters
    // 8. fund snip120u contracts
    // 9. add headstash claimers

    Ok(())
}

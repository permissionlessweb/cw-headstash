// use std::env;

// use anybuf::Anybuf;
// use clap::Parser;
// use cosmwasm_std::{to_json_binary, Addr, CosmosMsg};
// use cw_headstash::msg::{snip, Snip120u};
// use cw_ica_controller::types::msg::options::ChannelOpenInitOptions;
// use cw_orch::daemon::TxSender;
// use cw_orch::prelude::ChainInfoOwned;
// use cw_orch_interchain::{ChannelCreationValidator, DaemonInterchain, InterchainEnv};
// use headstash_scripts::constants::{COSMWASM_EXECUTE, SECRET_COMPUTE_EXECUTE};
// use tokio::runtime::Runtime;

// #[derive(Parser, Debug)]
// #[clap(author, version, about, long_about = None)]
// struct Args {
//     /// Network to deploy on: main, testnet, local
//     #[clap(short, long)]
//     network: String,
//     /// address of the ica-host account contolled by the cw-ica-controller.
//     #[clap(short, long)]
//     ica_addr: String,
//     /// address of the cw-ica-controller contract.
//     #[clap(short, long)]
//     cw_ica_addr: String,
//     /// code-id of the headstash contract. only used for step 2 (instantiate)
//     #[clap(short, long)]
//     gov_addr: String,
//     #[clap(short, long)]
//     snip120u_addrs: Vec<String>,
//     /// checksum hash of the snip120u contract. only used for step 2 (instantiate)
//     #[clap(short, long)]
//     snip120u_code_hash: String,

//     #[clap(short, long)]
//     headstash_addr: String,
// }

// pub fn main() {
//     let args = Args::parse();
//     println!("Step 1: Upload and instantiate the cw-ica-controller account");

//     let controller_chain = match args.network.as_str() {
//         "main" => headstash_scripts::networks::TERP_MAINNET.to_owned(),
//         "testnet" => headstash_scripts::networks::TERP_TESTNET.to_owned(),
//         "local" => headstash_scripts::networks::LOCAL_NETWORK1.to_owned(),
//         _ => panic!("Invalid network"),
//     };
//     let host_chain = match args.network.as_str() {
//         "main" => headstash_scripts::networks::SECRET_MAINNET.to_owned(),
//         "testnet" => headstash_scripts::networks::SECRET_TESTNET.to_owned(),
//         "local" => panic!("Invalid network"),
//         _ => panic!("Invalid network"),
//     };

//     //    let msg =  match args.step.as_str() {
//     //         "upload" => ,
//     //         "instantiate" => {}
//     //         "authorize" => {}
//     //         _ => panic!("Invalid step"),
//     //     }

//     if let Err(ref err) = authorize_headstash_as_as_snip120u_minter(
//         vec![controller_chain.into(), host_chain.into()],
//         args.gov_addr,
//         args.headstash_addr,
//         args.snip120u_code_hash,
//         args.snip120u_addrs,
//         args.cw_ica_addr,
//         args.ica_addr,
//     ) {
//         log::error!("{}", err);
//         err.chain()
//             .skip(1)
//             .for_each(|cause| log::error!("because: {}", cause));

//         ::std::process::exit(1);
//     }
// }

// fn authorize_headstash_as_as_snip120u_minter(
//     networks: Vec<ChainInfoOwned>,
//     gov_addr: String,
//     headstash_addr: String,
//     snip120u_code_hash: String,
//     snip120u_addrs: Vec<String>,
//     cw_ica_addr: String,
//     ica_addr: String,
// ) -> anyhow::Result<()> {
//     let rt = Runtime::new()?;
//     // define env variables
//     let mnemonic = env::var("MNEMONIC")?;

//     // create new cw-orch-interchain oobject with terp & secret.
//     let controller = networks[0].clone();
//     let host = networks[1].clone();
//     let mut interchain = DaemonInterchain::new(
//         vec![
//             (controller.clone(), Some(mnemonic.clone())),
//             (host.clone(), Some(mnemonic)),
//         ],
//         &ChannelCreationValidator,
//     )?;

//     let mut terp = interchain.get_chain(controller.chain_id)?;
//     let mut secret = interchain.get_chain(host.chain_id)?;
//     // 5. upload headstash contract on Secret Network, as Terp Network ICA account.

//     if let Some(addr) = gov_addr {
//         terp.authz_granter(&Addr::unchecked(&addr));
//     }
    
//     let secret_sender = secret.sender();
//     let terp_sender = terp.sender();

//     for snip in snip120u_addrs {
//         // authorize minter msg
//         let auth_msg = snip::SetMinters {
//             minters: vec![headstash_addr.clone()],
//             padding: None,
//         };

pub fn main() {}
//         let msg_for_ica = cw_ica_controller::types::msg::ExecuteMsg::SendCosmosMsgs {
//             messages: vec![CosmosMsg::Stargate {
//                 type_url: SECRET_COMPUTE_EXECUTE.into(),
//                 value: Anybuf::new()
//                     .append_string(1, terp_sender.address())
//                     .append_string(2, snip)
//                     .append_bytes(3, to_json_binary(&auth_msg)?)
//                     .append_repeated_message::<Anybuf>(5, &vec![])
//                     // no vm level admin.
//                     .into_vec()
//                     .into(),
//             }],
//             packet_memo: None,
//             timeout_seconds: None,
//         };

//         rt.block_on(terp_sender.commit_tx_any(
//             vec![cosmrs::Any {
//                     type_url: COSMWASM_EXECUTE
//                     .into(),
//                     value: Anybuf::new()
//                         .append_string(1, terp_sender.address())
//                         .append_string(2, cw_ica_addr.clone())
//                         .append_bytes(3, to_json_binary(&msg_for_ica)?
//                     )  .append_repeated_bytes::<Vec<u8>>(5, &[])
//                         .into_vec()
//                         .into(),
//                 }],
//             "".into(),
//         ))?;
//     }

//     Ok(())
// }

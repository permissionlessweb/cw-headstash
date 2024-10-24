import { Wallet, SecretNetworkClient, EncryptionUtilsImpl, MsgExecuteContract, fromUtf8, MsgExecuteContractResponse } from "secretjs";
// import { claim, add_headstash } from './account.js'
// import { printBatch } from './batch-add.js'
import { init_snip120u, deposit_to_snip20, query_token_info, query_token_config, set_viewing_key, query_balance, fund_headstash, upload_snip120u } from './snip20.js'
import * as fs from "fs";

import { upload_headstash_contract, instantiate_headstash_contract } from "./headstash.js";
// wallet
export const wallet = new Wallet("");


// headstash contract
export const headstashCodeId = 1944;
export const headstashCodeHash = "b114f46629664883f51522b0b4ba9a9ea0bf3413f07c09cef76488a8ea5fce55";
export const headstashAddr = "";

// snip-120u
export const snip120uCodeId = 1945;
export const snip120uCodeHash = "fb22a61a6009705137b86bf317c7fe1f62a48440cef73fef23feaf7d1998570c";

// snip-1u20 addrs
export const snip120uAddr1 = "secret1cqwafm8quzaltgtdhcfvm6xp3z9qum4whw08u5";
export const snip120uAddr2 = "secret1k6004d9p8yg754d530jq897d39gjldtnt9sv7p";
"2000000"
// token ONE & TWO denoms.
export const snip120uNative1 = "ibc/AF840D44CC92103AD006850542368B888D29C4D4FFE24086E767F161FBDDCE76";
export const snip120uNative2 = "ibc/7477828AC3E19352BA2D63352EA6D0680E3F29C126B87ACBDC27858CF7AF3A64";

export const counterpartyChannelId = "channel-165"
export const chain_id = "secret-4";
// export const cw_headstash_blob = fs.readFileSync("../../artifacts/cw_headstash.wasm");
// export const snip120u_blob = fs.readFileSync("../../artifacts/snip120u_impl.wasm");
export const entropy = "eretskeretjableret";
export const permitKey = entropy;
export const txEncryptionSeed = EncryptionUtilsImpl.GenerateNewSeed();

export const snip120us = [
  {
    native_token: "uterp",
    addr: snip120uAddr1,
    total_amount: "7100000"
  },
  {
    native_token: "uthiol",
    addr: snip120uAddr2,
    total_amount: "7100000"
  }];

// signing client 
export const secretjs = new SecretNetworkClient({
  chainId: chain_id,
  url: "https://lcd.mainnet.secretsaturn.net",
  wallet: wallet,
  walletAddress: wallet.address,
  txEncryptionSeed: txEncryptionSeed
});

// Process command line arguments
const args = process.argv.slice(2);
if (args.length < 1) {
  console.error('Invalid option.');
} else if (args[0] === '-1') {
  upload_headstash_contract(cw_headstash_blob);
} else if (args[0] === '-2') {
  upload_snip120u(snip120u_blob);
} else if (args[0] === '-3a') {
  // name, symbol, supported-denom
  init_snip120u("secret terp test", "scrtTERP", snip120uNative1)
    .then(() => { console.log("Created the First Snip20!"); })
    .catch((error) => { console.error("Failed:", error); });
} else if (args[0] === '-3b') {
  init_snip120u("secret thioool test", "scrtTHIOL", snip120uNative2)
    .then(() => { console.log("Created the Second Snip20!"); })
    .catch((error) => { console.error("Failed:", error); });
} else if (args[0] === '-4') {
  instantiate_headstash_contract();
  // } else if (args[0] === '-4') {
  //   if (args.length < 2) {
  //     console.error('Usage: -convert-token1 amount');
  //     process.exit(1);
  //   }
  //   const [, a,] = args;
  //   console.log("depositing token ONE")
  //   deposit_to_snip20(snip120uAddr1, a, snip120uNative1)
  //     .then(() => { console.log("Converted token ONE into its secret form!"); })
  //     .catch((error) => { console.error("Failed:", error); });
  // } else if (args[0] === '-convert-token2') {
  //   if (args.length < 2) {
  //     console.error('Usage: -d amount');
  //     process.exit(1);
  //   }
  //   const [, a,] = args;
  //   console.log("depositing token TWO")
  //   deposit_to_snip20(snip120uAddr2, a, snip120uNative2)
  //     .then(() => { console.log("Converted token TWO into its secret form!"); })
  //     .catch((error) => { console.error("Failed:", error); });
} else if (args[0] === '-viewing-key-2') {
  set_viewing_key(snip120uAddr2, entropy)
    .then(() => { console.log("Created viewing-key!"); })
    .catch((error) => { console.error("Failed:", error); });
} else if (args[0] === '-viewing-key-1') {
  set_viewing_key(snip120uAddr1, entropy)
    .then(() => { console.log("Created viewing-key!"); })
    .catch((error) => { console.error("Failed:", error); });
} else if (args[0] === '-feegrant') {
  if (args.length < 2) {
    console.error('Usage: -feegrant <addr-to-feegrant>');
    process.exit(1);
  }
  const [, a,] = args;
  broadcastFeeGrant(a)
    .then(() => { console.log("Created FeeGrant!"); })
    .catch((error) => { console.error("Failed:", error); });
  //////////////////////////////// SNIP20 QUERIES  /////////////////////////////////
} else if (args[0] === '-q-snip1-info') {   // query snip20 1 info
  query_token_info(snip120uAddr1, snip120uCodeHash)
} else if (args[0] === '-q-snip2-info') {   // query snip20 2 info 
  query_token_info(snip120uAddr2, snip120uCodeHash)
} else if (args[0] === '-q-snip1-config') { // query snip20 1 config
  query_token_config(snip120uAddr1, snip120uCodeHash)
} else if (args[0] === '-q-snip2-config') { // query snip20 2 config 
  query_token_config(snip120uAddr2, snip120uCodeHash)
} else if (args[0] === '-q-snip1-bal') {    // query balance snip20 1
  query_balance(snip120uAddr1, entropy)
    .then(() => { console.log("Queried Balance!"); })
    .catch((error) => { console.error("Failed:", error); });
} else if (args[0] === '-q-snip2-bal') {    // query balance snip20 2
  query_balance(snip120uAddr2, entropy)
    .then(() => { console.log("Queried Balance!"); })
    .catch((error) => { console.error("Failed:", error); });


  //////////////////////////////// HEADSTASH ACTIONS ///////////////////////////////
} else if (args[0] === '-claim') { // create an account, claims airdrop 
  claim(args[1])
} else if (args[0] === '-add') {
  printBatch(0)
    .then(() => { console.log("generated them jawns"); })
    .catch((error) => { console.error("Failed:", error); });
} else if (args[0] === '-duplicate-check') { // create an account, claims airdrop 
  claim(args[1])
} else {
  console.error('Invalid option.');
}
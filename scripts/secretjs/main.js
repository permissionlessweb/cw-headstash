import { Wallet, SecretNetworkClient, EncryptionUtilsImpl, MsgExecuteContract, fromUtf8, MsgExecuteContractResponse } from "secretjs";
// import { claim, add_headstash } from './account.js'
// import { printBatch } from './batch-add.js'
import { init_snip120u, deposit_to_snip20, query_token_info, query_token_config, set_viewing_key, query_balance, fund_headstash, upload_snip120u } from './snip20.js'
import * as fs from "fs";

import { upload_headstash_contract,instantiate_headstash_contract } from "./headstash.js";
// wallet
export const wallet = new Wallet("<your-mnemonic-seed>");
export const granteeAddress = "test"
// headstash contract
export const headstashCodeId = 10366;
export const headstashCodeHash = "0fa0106dfd5a9694064467ddd0868633a879a430c9f847a1105397c3476bbd08";
export const headstashAddr = "";

// snip-120u
export const snip120uCodeId = 0;
export const snip120uCodeHash = "c74bc4b0406507257ed033caa922272023ab013b0c74330efc16569528fa34fe";

// snip-1u20 addrs
export const snip120uAddr1 = "test";
export const snip120uAddr2 = "test";
// token ONE & TWO denoms.
export const snip120uNative1 = "test";
export const snip120uNative2 = "testa";

export const chain_id = "pulsar-3";
export const cw_headstash_blob = fs.readFileSync("../../artifacts/cw_headstash.wasm.gz");
export const snip120u_blob = fs.readFileSync("../../artifacts/snip120u.wasm.gz");
export const entropy = "eretskeretjableret";
export const permitKey = entropy;
export const txEncryptionSeed = EncryptionUtilsImpl.GenerateNewSeed();

// json path of headstash allocations
export const ethPubkeysToAdd = fs.readFileSync('../../contract/headstash/src/distribution.json', 'utf8');
export var ethPubkeys = JSON.parse(ethPubkeysToAdd);
export var batchSize = 100;

// signing client 
export const secretjs = new SecretNetworkClient({
  chainId: chain_id,
  url: "https://lcd.testnet.secretsaturn.net",
  wallet: wallet,
  walletAddress: wallet.address,
  txEncryptionSeed: txEncryptionSeed
});

// Process command line arguments
const args = process.argv.slice(2);
if (args.length < 1) {
  console.error('Invalid option.');
} else if (args[0] === '-upload-headstash') {
  upload_headstash_contract(cw_headstash_blob);
} else if (args[0] === '-upload-snip120u') {
  upload_snip120u(snip120u_blob);
} else if (args[0] === '-init-snip120u1') {
  init_snip120u("first-snip20", "ONE", snip120uNative1)
    .then(() => { console.log("Created the First Snip20!"); })
    .catch((error) => { console.error("Failed:", error); });
} else if (args[0] === '-i-snip2') {
  init_snip120u("second-snip20", "TWO", snip120uNative2)
    .then(() => { console.log("Created the Second Snip20!"); })
    .catch((error) => { console.error("Failed:", error); });

} else if (args[0] === '-convert-token1') {
  if (args.length < 2) {
    console.error('Usage: -convert-token1 amount');
    process.exit(1);
  }
  const [, a,] = args;
  console.log("depositing token ONE")
  deposit_to_snip20(snip120uAddr1, a, snip120uNative1)
    .then(() => { console.log("Converted token ONE into its secret form!"); })
    .catch((error) => { console.error("Failed:", error); });
} else if (args[0] === '-convert-token2') {
  if (args.length < 2) {
    console.error('Usage: -d amount');
    process.exit(1);
  }
  const [, a,] = args;
  console.log("depositing token TWO")
  deposit_to_snip20(snip120uAddr2, a, snip120uNative2)
    .then(() => { console.log("Converted token TWO into its secret form!"); })
    .catch((error) => { console.error("Failed:", error); });
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

} else if (args[0] === '-init-headstash') {
  instantiate_headstash_contract();
  //////////////////////////////// HEADSTASH ACTIONS ///////////////////////////////
// } else if (args[0] === '-fund-hs-token1') {
//   if (args.length < 2) {
//     console.error('Usage: -fund-hs-token1 amount');
//     process.exit(1);
//   }
//   const [, a,] = args;
//   fund_headstash(snip120uAddr1, a)
//     .then(() => { console.log("Funded headstash with token ONE!"); })
//     .catch((error) => { console.error("Failed:", error); });
// } else if (args[0] === '-fund-hs-token2') {
//   if (args.length < 2) {
//     console.error('Usage: -fund-hs-token2 amount');
//     process.exit(1);
//   }
//   const [, a,] = args;
//   fund_headstash(snip120uAddr2, a)
//     .then(() => { console.log("Funded headstash with token TWO!"); })
//     .catch((error) => { console.error("Failed:", error); });
} else if (args[0] === '-claim') { // create an account, claims airdrop 
  claim(args[1])
} else if (args[0] === '-add') {
  printBatch(0)
    .then(() => { console.log("generated them jawns"); })
    .catch((error) => { console.error("Failed:", error); });
} else {
  console.error('Invalid option.');
}
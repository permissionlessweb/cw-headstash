import { Wallet, SecretNetworkClient, EncryptionUtilsImpl, MsgExecuteContract, fromUtf8, MsgExecuteContractResponse } from "secretjs";
import { claim, add_headstash } from './account.js'
import { printBatch } from './batch-add.js'
import { i_snip20, deposit_to_snip20, query_token_info, query_token_config, set_viewing_key, query_balance, fund_headstash } from './snip20.js'
import * as fs from "fs";

// wallet
export const chain_id = "pulsar-3";
export const wallet = new Wallet("<your-mnemonic-seed>");
export const txEncryptionSeed = EncryptionUtilsImpl.GenerateNewSeed();
export const contract_wasm = fs.readFileSync("./target/wasm32-unknown-unknown/release/secret_headstash.wasm");

// headstash contract
export const scrtHeadstashCodeId = 9016;
export const scrtHeadstashCodeHash = "f89afb136c18be3d1f008b799ca140f7916a1c62a2fc5c1e8e9e4f14778eafe9";
export const scrtHeadstashContractAddr = "";

// snip-20 
export const scrt20codeId = 5697;
export const scrt20CodeHash = "c74bc4b0406507257ed033caa922272023ab013b0c74330efc16569528fa34fe";
// snip-20 addrs
export const scrtContractAddr1 = "";
export const scrtContractAddr2 = "";
// token ONE & TWO denoms.
export const scrtIBCDenom1 = "";
export const scrtIBCDenom2 = "";

export const entropy = "eretskeretjableret";
export const permitKey = entropy;

// add msgs 
export const ethPubkeysToAdd = fs.readFileSync('./tools/example-data/amounts.json', 'utf8');
export var ethPubkeys = JSON.parse(ethPubkeysToAdd);
export var batchSize = 1600;

// signing client 
export const secretjs = new SecretNetworkClient({
  chainId: chain_id,
  url: "https://lcd.testnet.secretsaturn.net",
  wallet: wallet,
  walletAddress: wallet.address,
  txEncryptionSeed: txEncryptionSeed
});

// generate fee grant
let broadcastFeeGrant = async (cosmos_addr) => {
  let msg = await secretjs.tx.feegrant.grantAllowance({
    granter: wallet.address,
    grantee: cosmos_addr,
    allowance: {
      allowance: { spend_limit: [{ denom: "uscrt", amount: "1000000" }] },
      allowed_messages: ["/secret.compute.v1beta1.MsgExecuteContract"]
    }
  })
  console.log(msg);
}

// stores contract, prints code hash & code id
let upload_contract = async () => {
  let tx = await secretjs.tx.compute.storeCode(
    {
      sender: wallet.address,
      wasm_byte_code: contract_wasm,
      source: "",
      builder: "",
    },
    {
      gasLimit: 4_000_000,
    }
  );

  if (tx.code == 0) {
    const codeId = Number(
      tx.arrayLog.find((log) => log.type === "message" && log.key === "code_id").value
    );
    console.log("codeId: ", codeId);
    const contractCodeHash = (await secretjs.query.compute.codeHashByCodeId({ code_id: codeId })).code_hash;
    console.log(`Contract hash: ${contractCodeHash}`);
  }
}

// initialize a new headstash contract
let instantiate_headstash_contract = async () => {
  let initMsg = {
    admin: wallet.address,
    claim_msg_plaintext: "{wallet}",
    snip20_1: {
      address: scrtContractAddr1,
      code_hash: scrt20CodeHash
    },
    // snip20_3: {
    //   address: scrtContractAddr2,
    //   code_hash: scrt20CodeHash
    // },
    viewing_key: entropy,
    total_amount: "2397983967495",
  };

  let tx = await secretjs.tx.compute.instantiateContract(
    {
      code_id: scrtHeadstashCodeId,
      sender: wallet.address,
      code_hash: scrtHeadstashCodeHash,
      init_msg: initMsg,
      label: "Secret Headstash Patch" + Math.ceil(Math.random() * 10000),
    },
    {
      gasLimit: 400_000,
    }
  );
  //Find the contract_address in the logs
  const contractAddress = tx.arrayLog.find(
    (log) => log.type === "message" && log.key === "contract_address"
  ).value;
  console.log(contractAddress);
}



// Process command line arguments
const args = process.argv.slice(2);
if (args.length < 1) {
  console.error('Invalid option.');
} else if (args[0] === '-s') {
  upload_contract(args[1]);
} else if (args[0] === '-i-snip1') {
  i_snip20("first-snip20", "ONE", scrtIBCDenom1)
    .then(() => { console.log("Created the First Snip20!"); })
    .catch((error) => { console.error("Failed:", error); });
} else if (args[0] === '-i-snip2') {
  i_snip20("second-snip20", "TWO", scrtIBCDenom2)
    .then(() => { console.log("Created the Second Snip20!"); })
    .catch((error) => { console.error("Failed:", error); });

} else if (args[0] === '-convert-token1') {
  if (args.length < 2) {
    console.error('Usage: -convert-token1 amount');
    process.exit(1);
  }
  const [, a,] = args;
  console.log("depositing token ONE")
  deposit_to_snip20(scrtContractAddr1, a, scrtIBCDenom1)
    .then(() => { console.log("Converted token ONE into its secret form!"); })
    .catch((error) => { console.error("Failed:", error); });
} else if (args[0] === '-convert-token2') {
  if (args.length < 2) {
    console.error('Usage: -d amount');
    process.exit(1);
  }
  const [, a,] = args;
  console.log("depositing token TWO")
  deposit_to_snip20(scrtContractAddr2, a, scrtIBCDenom2)
    .then(() => { console.log("Converted token TWO into its secret form!"); })
    .catch((error) => { console.error("Failed:", error); });
} else if (args[0] === '-viewing-key-2') {
  set_viewing_key(scrtContractAddr2, entropy)
    .then(() => { console.log("Created viewing-key!"); })
    .catch((error) => { console.error("Failed:", error); });
} else if (args[0] === '-viewing-key-1') {
  set_viewing_key(scrtContractAddr1, entropy)
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
  query_token_info(scrtContractAddr1, scrt20CodeHash)
} else if (args[0] === '-q-snip2-info') {   // query snip20 2 info 
  query_token_info(scrtContractAddr2, scrt20CodeHash)
} else if (args[0] === '-q-snip1-config') { // query snip20 1 config
  query_token_config(scrtContractAddr1, scrt20CodeHash)
} else if (args[0] === '-q-snip2-config') { // query snip20 2 config 
  query_token_config(scrtContractAddr2, scrt20CodeHash)
} else if (args[0] === '-q-snip1-bal') {    // query balance snip20 1
  query_balance(scrtContractAddr1, entropy)
    .then(() => { console.log("Queried Balance!"); })
    .catch((error) => { console.error("Failed:", error); });
} else if (args[0] === '-q-snip2-bal') {    // query balance snip20 2
  query_balance(scrtContractAddr2, entropy)
    .then(() => { console.log("Queried Balance!"); })
    .catch((error) => { console.error("Failed:", error); });
  
} else if (args[0] === '-init-headstash') { 
  instantiate_headstash_contract();
  //////////////////////////////// HEADSTASH ACTIONS ///////////////////////////////
} else if (args[0] === '-fund-hs-token1') {
  if (args.length < 2) {
    console.error('Usage: -fund-hs-token1 amount');
    process.exit(1);
  }
  const [, a,] = args;
  fund_headstash(scrtContractAddr1, a)
    .then(() => { console.log("Funded headstash with token ONE!"); })
    .catch((error) => { console.error("Failed:", error); });
} else if (args[0] === '-fund-hs-token2') {
  if (args.length < 2) {
    console.error('Usage: -fund-hs-token2 amount');
    process.exit(1);
  }
  const [, a,] = args;
  fund_headstash(scrtContractAddr2, a)
    .then(() => { console.log("Funded headstash with token TWO!"); })
    .catch((error) => { console.error("Failed:", error); });
} else if (args[0] === '-claim') { // create an account, claims airdrop 
  claim(args[1])
} else if (args[0] === '-add') {
  printBatch(0)
    .then(() => { console.log("generated them jawns"); })
    .catch((error) => { console.error("Failed:", error); });
} else {
  console.error('Invalid option.');
}
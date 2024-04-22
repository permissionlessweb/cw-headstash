import { Wallet, SecretNetworkClient, EncryptionUtilsImpl, MsgExecuteContract, fromUtf8, MsgExecuteContractResponse } from "secretjs";
import { create_account, add_headstash } from './account.js'
import { i_snip20, deposit_to_snip20, query_token_info, query_token_config, set_viewing_key, query_balance, fund_headstash } from './snip20.js'
import * as fs from "fs";

// wallet
export const chain_id = "pulsar-3";
export const wallet = new Wallet("goat action fuel major strategy adult kind sand draw amazing pigeon inspire antenna forget six kiss loan script west jaguar again click review have");
export const txEncryptionSeed = EncryptionUtilsImpl.GenerateNewSeed();
export const contract_wasm = fs.readFileSync("./target/wasm32-unknown-unknown/release/secret_contract_example.wasm");

// snip-20
export const scrt20codeId = 5697;
export const scrt20CodeHash = "c74bc4b0406507257ed033caa922272023ab013b0c74330efc16569528fa34fe";
export const scrtTerpContractAddr = "secret1wmp90kd0zsnq3p35m457ufc4p807v3j7tvkhwx";
export const scrtThiolContractAddr = "secret1g6d9cjsw2k9n5xr5u750u8t4v4hvhmcy828q7w";
export const scrtIBCTerpDenom = "ibc/BE5D2CF4CFB043522B95ACAF30113B6DDEDE8FB09B9CFBE4322B70C487781241";
export const scrtIBCThiolDenom = "ibc/07FFE4A5E55AFA423DF355E3138858E6A302909F74595676A9EDC1A76D9511F1";

const entropy = "eretskeretjableret";

// airdrop contract
export const scrtHeadstashCodeId = 6684;
export const scrtHeadstashCodeHash = "9b5d98452b320499b9520e2f062e7f527cbd1d0046b7304bb378d3033438a2b5";
export const scrtHeadstashContractAddr = "secret1qyhpstprdhgdexykrrg538jlg5qtrranfj5tx8";
export const merkle_root = "d599867bdb2ade1e470d9ec9456490adcd9da6e0cfd8f515e2b95d345a5cd92f";

// account stuff
export const cosmos_sig = "oZvPavC1xXLpe3hzurUrBmLWFWZFQi/VF7u5dH7YrUJESeRX0rNB1oKixuVlwSFjh17f1SD/06SWdNzOXyTLDg==";
export const eth_pubkey = "0x254768D47Cf8958a68242ce5AA1aDB401E1feF2B";
export const eth_sig = "0xf7992bd3f7cb1030b5d69d3326c6e2e28bfde2e38cbb8de753d1be7b5a5ecbcf2d3eccd3fe2e1fccb2454c47dcb926bd047ecf5b74c7330584cbfd619248de811b"
export const pubkey = { type: "tendermint/PubKeySecp256k1", value: "AyZtxhLgis4Ec66OVlKDnuzEZqqV641sm46R3mbE2cpO" }
export const partial_tree = ["fbff7c66d3f610bcf8223e61ce12b10bb64a3433622ff39af83443bcec78920a"]
export const permitKey = "eretskeretjableret"

// signing client 
export const secretjs = new SecretNetworkClient({
  chainId: chain_id,
  url: "https://api.pulsar.scrttestnet.com",
  wallet: wallet,
  walletAddress: wallet.address,
  txEncryptionSeed: txEncryptionSeed
});

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
      snip20_1: {
        address: scrtTerpContractAddr,
        code_hash: scrt20CodeHash
      },
      merkle_root: merkle_root,
      admin: wallet.address,
      viewing_key: entropy,
      total_amount: "840",
      claim_msg_plaintext: "{wallet}",
    // dump_address: wallet.address,
    // airdrop_2: {
    //   address: scrtThiolContractAddr,
    //   code_hash: scrt20CodeHash
    // },
    // start_date: 1713386815,
    // end_date: 1744922815,
    // decay_start: 1723927615,
    // total_accounts: 2,
    // max_amount: "420",
    // default_claim: "50",
    // task_claim: [{
    //   address: scrtHeadstashContractAddr,
    //   percent: "50",
    // }],
    // query_rounding: "1"
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

  console.log(tx);
  //Find the contract_address in the logs
  const contractAddress = tx.arrayLog.find(
    (log) => log.type === "message" && log.key === "contract_address"
  ).value;

  console.log(contractAddress);
}



// Process command line arguments
const args = process.argv.slice(2);

// Determine which function to run based on the first argument
if (args.length < 1) {
  console.error('Invalid option. Please provide -s to store the contract, -i to instantiate the snip20 tokens followed by expected values [name] [symbol] [ibc-hash], -h to instantiate the headstash airdrop contract, -a to create the account,');
} else if (args[0] === '-s') {
  upload_contract(args[1]);
} else if (args[0] === '-h') { // instantiate headstash contract
  instantiate_headstash_contract();


  //////////////////////////////// HEADSTASH ACTIONS ///////////////////////////////
} else if (args[0] === '-fund-hs-terp') {
  if (args.length < 2) {
    console.error('Usage: -fund-hs-terp amount');
    process.exit(1);
  }
  const [, a,] = args;
  fund_headstash(scrtTerpContractAddr, a)
    .then(() => { console.log("Funded headstash with TERP!"); })
    .catch((error) => { console.error("Failed:", error); });
} else if (args[0] === '-fund-hs-thiol') {
  if (args.length < 2) {
    console.error('Usage: -fund-hs-thiol amount');
    process.exit(1);
  }
  const [, a,] = args;
  fund_headstash(scrtThiolContractAddr, a)
    .then(() => { console.log("Funded headstash with THIOL!"); })
    .catch((error) => { console.error("Failed:", error); });

} else if (args[0] === '-a') { // create an account, claims airdrop 
  create_account(args[1])
} else if (args[0] === '-add-hs') { // create an account, claims airdrop 
  const jsonData = fs.readFileSync('./tools/headstash/accounts.json')
  add_headstash(jsonData)
  .then(() => { console.log("Added accounts to the heastash!"); })
  //////////////////////////////// SNIP20 ACTIONS //////////////////////////////////
} else if (args[0] === '-i-terp') {
  i_snip20("terp-snip20", "TERP", scrtIBCTerpDenom)
    .then(() => { console.log("Created the Terp Snip20!"); })
    .catch((error) => { console.error("Failed:", error); });
} else if (args[0] === '-i-thiol') {
  i_snip20("thiol-snip20", "THIOL", scrtIBCThiolDenom)
    .then(() => { console.log("Created the Thiol Snip20!"); })
    .catch((error) => { console.error("Failed:", error); });
    
} else if (args[0] === '-deposit-terp') {
  if (args.length < 2) {
    console.error('Usage: -deposit-terp amount');
    process.exit(1);
  }
  const [, a,] = args;
  console.log("depositing TERP")
  deposit_to_snip20(scrtTerpContractAddr, a, scrtIBCTerpDenom)
    .then(() => { console.log("Converted TERP into its secret form!"); })
    .catch((error) => { console.error("Failed:", error); });
} else if (args[0] === '-deposit-thiol') {
  if (args.length < 2) {
    console.error('Usage: -d amount');
    process.exit(1);
  }
  const [, a,] = args;
  console.log("depositing THIOL")
  deposit_to_snip20(scrtThiolContractAddr, a, scrtIBCThiolDenom)
    .then(() => { console.log("Converted THIOL into its secret form!"); })
    .catch((error) => { console.error("Failed:", error); });
} else if (args[0] === '-viewing-key-thiol') {
  set_viewing_key(scrtThiolContractAddr, entropy)
    .then(() => { console.log("Created viewing-key!"); })
    .catch((error) => { console.error("Failed:", error); });
} else if (args[0] === '-viewing-key-terp') {
  set_viewing_key(scrtTerpContractAddr, entropy)
    .then(() => { console.log("Created viewing-key!"); })
    .catch((error) => { console.error("Failed:", error); });
  //////////////////////////////// SNIP20 QUERIES //////////////////////////////////
} else if (args[0] === '-q-snip20-info-terp') { // query terp snip20 info
  query_token_info(scrtTerpContractAddr, scrt20CodeHash)
} else if (args[0] === '-q-snip20-info-thiol') {  // query thiol snip20 info 
  query_token_info(scrtThiolContractAddr, scrt20CodeHash)
} else if (args[0] === '-q-snip20-config-terp') { // query terp snip20 config
  query_token_config(scrtTerpContractAddr, scrt20CodeHash)
} else if (args[0] === '-q-snip20-config-thiol') {  // query thiol snip20 config 
  query_token_config(scrtThiolContractAddr, scrt20CodeHash)
} else if (args[0] === '-q-bal-terp') {
  query_balance(scrtTerpContractAddr, entropy)
    .then(() => { console.log("Queried Balance!"); })
    .catch((error) => { console.error("Failed:", error); });
} else if (args[0] === '-q-bal-thiol') {
  query_balance(scrtThiolContractAddr, entropy)
    .then(() => { console.log("Queried Balance!"); })
    .catch((error) => { console.error("Failed:", error); });
} else {
  console.error('Invalid option.');
}
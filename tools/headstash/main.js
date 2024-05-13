import { Wallet, SecretNetworkClient, EncryptionUtilsImpl, MsgExecuteContract, fromUtf8, MsgExecuteContractResponse } from "secretjs";
import { create_account, add_headstash } from './account.js'
import { printBatch } from './batch-add.js'
import { i_snip20, deposit_to_snip20, query_token_info, query_token_config, set_viewing_key, query_balance, fund_headstash } from './snip20.js'
import * as fs from "fs";

// wallet
export const chain_id = "pulsar-3";
export const wallet = new Wallet(process.env.WALLET_PRIVATE_KEY);
export const txEncryptionSeed = EncryptionUtilsImpl.GenerateNewSeed();
export const contract_wasm = fs.readFileSync(process.env.CONTRACT_WASM_FILE);

// snip-20 details 
export const scrt20codeId = 5697;
export const scrt20CodeHash = "c74bc4b0406507257ed033caa922272023ab013b0c74330efc16569528fa34fe";
// contract address
export const scrtTerpContractAddr = "secret1wmp90kd0zsnq3p35m457ufc4p807v3j7tvkhwx";
export const scrtThiolContractAddr = "secret1g6d9cjsw2k9n5xr5u750u8t4v4hvhmcy828q7w";
// TERP & THIOL ibc-hashes 
export const scrtIBCTerpDenom = "ibc/BE5D2CF4CFB043522B95ACAF30113B6DDEDE8FB09B9CFBE4322B70C487781241";
export const scrtIBCThiolDenom = "ibc/07FFE4A5E55AFA423DF355E3138858E6A302909F74595676A9EDC1A76D9511F1";

const entropy = "eretskeretjableret";

// airdrop contract
export const scrtHeadstashCodeId = 6908;
export const scrtHeadstashCodeHash = "b12ed8795b14346520f7f67e3c74e5601afa585b7c50878c31bd3d3190061130";
export const scrtHeadstashContractAddr = "secret162ygjnc4n0jk4paz7lck8fzpwgd5u3zqguxers";

// account stuff
export const permitKey = "eretskeretjableret"

// signing client 
export const secretjs = new SecretNetworkClient({
  chainId: chain_id,
  url: "https://api.pulsar.scrttestnet.com",
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
    snip20_1: {
      address: scrtTerpContractAddr,
      code_hash: scrt20CodeHash
    },
    merkle_root: merkle_root,
    admin: wallet.address,
    viewing_key: entropy,
    total_amount: "840",
    claim_msg_plaintext: "{wallet}",
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
// -s - stores airdrop contract
// -h - instantiates headstash contract with default settings
// -fund-hs-terp <amount> - funds the headstash contract with scrt TERP tokens.
// -fund-hs-thiol <amount>  - funds the headstash contract with scrt THIOL tokens.
// -a - claims the airdrop with hardcoded eth pubkey and signature
// -deposit-thiol <amount> -  Convert THIOL to snip20 THIOL
// -deposit-terp <amount> - Convert TERP to snip20 TERP
// -viewing-key-thiol - create viewing key for THIOL
// -viewing-key-terp - create viewing key for TERP
// -feegrant <address> - Authorize feegrant to an address
// -q-snip20-info-terp 
// -q-snip20-info-thiol
// -q-snip20-config-terp
// -q-snip20-config-thiol
// -q-snip20-bal-terp
// -q-snip20-bal-thiol
// -gen-msgs - batch add address to an airdrop. 

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
} else if (args[0] === '-feegrant') {
  if (args.length < 2) {
    console.error('Usage: -feegrant address');
    process.exit(1);
  }
  const [, a,] = args;
  broadcastFeeGrant(a)
    .then(() => { console.log("Created FeeGrant!"); })
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
} else if (args[0] === '-q-snip20-bal-terp') {
  query_balance(scrtTerpContractAddr, entropy)
    .then(() => { console.log("Queried Balance!"); })
    .catch((error) => { console.error("Failed:", error); });
} else if (args[0] === '-q-snip20-bal-thiol') {
  query_balance(scrtThiolContractAddr, entropy)
    .then(() => { console.log("Queried Balance!"); })
    .catch((error) => { console.error("Failed:", error); });
} else if (args[0] === '-gen-msgs') {
  printBatch(0)
    .then(() => { console.log("generated them jawns"); })
    .catch((error) => { console.error("Failed:", error); });
} else {
  console.error('Invalid option.');
}
import {  scrtHeadstashCodeHash, scrtHeadstashContractAddr, secretjs, wallet } from "./main.js";

let claim = async (eth_pubkey, eth_sig) => {

  const createAccount = {
    claim: {
      eth_pubkey: eth_pubkey,
      eth_sig: eth_sig.slice(2),
    }
  }

  const tx = await secretjs.tx.compute.executeContract({
    sender: wallet.address,
    contract_address: scrtHeadstashContractAddr,
    msg: createAccount,
    code_hash: scrtHeadstashCodeHash,
  },
    {
      gasLimit: 400_000,
    })

  console.log(encoded_memo);
  console.log(tx);
}

let add_headstash = async (jsonData) => {

  var headstashes = [String];
  headstashes = JSON.parse(jsonData);

  const addMsg = { add: { headstash: headstashes } }
  const tx = await secretjs.tx.compute.executeContract({
    sender: wallet.address,
    contract_address: scrtHeadstashContractAddr,
    msg: addMsg,
    code_hash: scrtHeadstashCodeHash,
  },
    {
      gasLimit: 400_000,
    })
  console.log(tx);
}
export { claim, add_headstash }




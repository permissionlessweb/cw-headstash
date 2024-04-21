import { chain_id, scrtHeadstashCodeHash, scrtHeadstashContractAddr, secretjs, txEncryptionSeed, wallet, permitKey, pubkey, cosmos_sig, eth_pubkey, eth_sig, partial_tree } from "./main.js";

let create_account = async () => {
  const addressProofMsg = {
    address: wallet.address,
    amount: "420",
    contract: scrtHeadstashContractAddr,
    index: 1,
    key: permitKey,
  }
  // encode memo to base64 string
  const encoded_memo = Buffer.from(JSON.stringify(addressProofMsg)).toString('base64');

  const fillerMsg = {
    coins: [],
    contract: scrtHeadstashContractAddr,
    execute_msg: {},
    sender: wallet.address,
  }

  // account
  const permitParams = {
    params: fillerMsg,
    signature: {
      pub_key: pubkey,
      signature: cosmos_sig,
    },
    chain_id: chain_id,
    memo: encoded_memo,
  }

  const createAccount = {
    claim: {
      amount: "420",
      eth_pubkey: eth_pubkey,
      eth_sig: eth_sig.slice(2),
      proof: partial_tree,
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
      // explicitSignerData: {
      //   accountNumber: 22761,
      //   sequence: 191,
      //   chainId: "pulsar-3"
      // }
    })

    console.log(encoded_memo);
  console.log(tx);
}
export { create_account }




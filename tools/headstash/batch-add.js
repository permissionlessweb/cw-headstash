import { wallet, scrtHeadstashContractAddr, secretjs, scrtHeadstashCodeHash, ethPubkeys, batchSize } from './main.js';

let printBatch = async (index) => {
  var batch = ethPubkeys.slice(index * batchSize, (index + 1) * batchSize);
  console.log(batch)
  if (batch.length === 0) {
    return "Batch is empty";
  }
  const addMsg = { add: { headstash: batch } }
  const tx = await secretjs.tx.compute.executeContract({
    sender: wallet.address,
    contract_address: scrtHeadstashContractAddr,
    msg: addMsg,
    code_hash: scrtHeadstashCodeHash,
  },
    {
      gasLimit: 8_000_000,
    })
  console.log(tx);
  if (index * batchSize < ethPubkeys.length) {
    setTimeout(function () {
      printBatch(index + 1);
    }, 6000); // delay next batch
  }
}
export { printBatch }
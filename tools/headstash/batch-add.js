import { exec } from 'child_process';
import { wallet, scrtHeadstashContractAddr, secretjs, scrtHeadstashCodeHash} from './main.js';
import fs from 'fs';

const jsonString = fs.readFileSync('./tools/headstash/amounts.json', 'utf8');
var jsonData = JSON.parse(jsonString);
var batchSize = 1600;


let printBatch = async (index) => {
  var batch = jsonData.slice(index * batchSize, (index + 1) * batchSize);
  console.log(batch)
  
  if (batch.length === 0) {
    throw new Error("Batch is empty");
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
      // explicitSignerData: {
      //   accountNumber: 22761,
      //   sequence: (376 + index + 1),
      //   chainId: "pulsar-3"
      // }
    })
  console.log(tx);
  if (index * batchSize < jsonData.length) {
    setTimeout(function () {
      printBatch(index + 1);
    }, 6000); // delay next batch
  }
}

export { printBatch }
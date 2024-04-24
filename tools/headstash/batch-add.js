import { exec } from 'child_process';
import { wallet, scrtHeadstashContractAddr } from './main.js';
import fs from 'fs';

const jsonString = fs.readFileSync('./tools/headstash/amounts.json', 'utf8');
var jsonData = JSON.parse(jsonString);
var batchSize = 100;

function runCommand(command) {
  exec(command, (error, stdout, stderr) => {
    if (error) {
      console.error(`exec error: ${error}`);
    } else {
      console.log(`stdout: ${stdout}`);
      console.log(`stderr: ${stderr}`);
    }
  });
}

let printBatch = async (index) => {
  // TODO: ensure batch prints remaining accounts if < batchSize
  var batch = jsonData.slice(index * batchSize, (index + 1) * batchSize);
  let value = (index + 1);

  const command = `sc tx wasm execute ${scrtHeadstashContractAddr} '{"add": ${JSON.stringify(batch)}}' --generate-only --from ${wallet.address} --output ./generated/signed-${value}}.json`;

  runCommand(command);

  if (index * batchSize < jsonData.length) {
    setTimeout(function () {
      printBatch(index + 1);
    }, 100); // delay next batch
  }
}

export { printBatch }
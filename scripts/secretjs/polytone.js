import { headstashCodeHash, snip120us, counterpartyChannelId, snip120uCodeHash, entropy, headstashCodeId, headstashAddr } from "./config.js";
import { secretjs, wallet, } from "./main.js";
import * as fs from "fs";

// json path of headstash allocations
// export const ethPubkeysToAdd = fs.readFileSync('../data/distribution.json', 'utf8');
// export var ethPubkeys = JSON.parse(ethPubkeysToAdd);
// export var batchSize = 100;


import { MsgStoreCode, MsgInstantiateContract, MsgExec } from "secretjs";
// stores contract, prints code hash & code id
let upload_polytone_contracts = async (wasm) => {

	 const msgs = new MsgStoreCode({
		  sender: wallet.address, // Your address
		  wasm_byte_code: wasm,
		  source: "",
		  builder: "",
	 })

	 //define the authz msg
	 // const msgExec = new MsgExec({ grantee: granteeAddress, msgs })
	 // const tx = await secretjs.tx.broadcast([msgExec], {
	 //     gasLimit: 5_000_000,
	 // });

	 // broadcast 
	 const tx = await secretjs.tx.broadcast([msgs], {
		  gasLimit: 5_000_000,
	 });

	 if (tx.code == 0) {
		  const codeId = Number(
				tx.arrayLog.find((log) => log.type === "message" && log.key === "code_id").value
		  );
		  console.log("codeId:", codeId);
		  const contractCodeHash = (await secretjs.query.compute.codeHashByCodeId({ code_id: codeId })).code_hash;
		  console.log(`Contract hash: ${contractCodeHash}`);
	 } else
		  console.log(`Tx Error: ${tx.rawLog}`);
}

 
export { upload_polytone_contracts }
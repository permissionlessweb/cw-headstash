import { chain_id, snip120uCodeId, snip120uCodeHash, granteeAddress, secretjs, wallet, entropy, headstashCodeId, headstashAddr } from "./main.js";

import { MsgStoreCode,MsgInstantiateContract,MsgExec } from "secretjs"; 
// stores contract, prints code hash & code id
let upload_headstash_contract = async (wasm) => {

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

const snip120us = [
    {
        native_token: "uterp",
        addr: "snip120uAddr1",
        total_amount: "420"
    },
    {
        native_token: "uthiolx",
        addr: "snip120uAddr2",
        total_amount: "710"
    }];

// initialize a new headstash contract
let instantiate_headstash_contract = async () => {
    let initMsg = {
        owner: wallet.address,
        claim_msg_plaintext: "HREAM ~ Sender: {addr} Secondary: {secondary_addr}",
        start_date: None,
        end_date: None,
        snip120uCodeHash: snip120uCodeHash,
        snips: snip120us,
        viewing_key: entropy,
        channel_id: ""
    };

    const msgInstantiateContract = new MsgInstantiateContract({
        sender: wallet.address, // Your address
        codeId: headstashCodeId, // Code ID of the contract
        code_hash: headstashCodeHash,
        init_msg: initMsg, // Contract initialization message
        label: "Secret Headstash Patch" + Math.ceil(Math.random() * 10000),
    });

    //define the authz msg
    const msgExec = new MsgExec({ grantee: granteeAddress, msgs: [msgInstantiateContract] });

    // broadcast 
    const tx = await secretjs.tx.broadcast(msgExec, {
        gasLimit: 400_000,
    });

    //Find the contract_address in the logs
    const contractAddress = tx.arrayLog.find(
        (log) => log.type === "message" && log.key === "contract_address"
    ).value;
    console.log(contractAddress);
}

export { upload_headstash_contract, instantiate_headstash_contract }
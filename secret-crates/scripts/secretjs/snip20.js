import { NonExistenceProof } from "secretjs/dist/protobuf/confio/proofs.js";
import { chain_id, snip120uCodeHash, snip120uCodeId, secretjs, wallet, headstashAddr } from "./main.js";
import { MsgStoreCode, MsgInstantiateContract } from "secretjs"

// stores contract, prints code hash & code id
let upload_snip120u = async (wasm) => {
    const msgStoreCode = new MsgStoreCode({
        sender: wallet.address, // Your address
        wasm_byte_code: wasm,
        source: "",
        builder: "",
    });

    //define the authz msg
    // const msgExec = new MsgExec({ grantee: granteeAddress, msgs: [msgStoreCode] });
    // const tx = await secretjs.tx.broadcast(msgExec, {
    //     gasLimit: 400_000,
    // });

    // broadcast 
    const tx = await secretjs.tx.broadcast([msgStoreCode], {
        gasLimit: 4_000_000,
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

// initiates a new snip120u, with sender as admin, and single supported denom
let init_snip120u = async (name, symbol, supported_denom) => {
    const initMsg = {
        name: name,
        admin: wallet.address,
        symbol: symbol,
        decimals: 6,
        inital_balances: null,
        prng_seed: Buffer.from("dezayum").toString("base64"),
        config: {
            enable_deposit: true,
            enable_redeem: true,
            enable_burn: true,
        },
        supported_denoms: [supported_denom]
    };

    const msgInstantiateContract = new MsgInstantiateContract({
        code_id: snip120uCodeId,
        sender: wallet.address,
        code_hash: snip120uCodeHash,
        init_msg: initMsg,
        label: " Secret Headstash Snip" + Math.ceil(Math.random() * 10000),
    });

    //broadcast as authz msg
    // const msgExec = new MsgExec({ grantee: granteeAddress, msgs: [msgInstantiateContract] });
    // const tx = await secretjs.tx.broadcast(msgExec, {
    //     gasLimit: 400_000,
    // });

    const tx = await secretjs.tx.broadcast([msgInstantiateContract], {
        gasLimit: 4_000_000,
    });

    if (tx.code == 0) {
        //Find the contract_address in the logs
        const contractAddress = tx.arrayLog.find(
            (log) => log.type === "message" && log.key === "contract_address"
        ).value;

        console.log(contractAddress);
    } else {
        console.log(`Tx Error: ${tx.rawLog}`);
    }
};

let deposit_to_snip20 = async (contract, amount, denom) => {
    const msg = { deposit: {} }
    console.log("values:", contract, amount, denom)
    let tx = await secretjs.tx.compute.executeContract(
        {
            sender: wallet.address,
            contract_address: contract,
            msg: msg,
            sent_funds: [{ amount: amount, denom: denom }]
        },
        {
            gasLimit: 400_000,
        }
    )
    console.log(tx)
}

let set_viewing_key = async (contract, entropy) => {
    const msg = { set_viewing_key: { key: entropy } }
    let tx = await secretjs.tx.compute.executeContract(
        {
            sender: wallet.address,
            contract_address: contract,
            msg: msg,
        },
        { gasLimit: 400_000, }
    )
}

let fund_headstash = async (contract, amount) => {
    const msg = { transfer: { recipient: headstashAddr, amount: amount } }
    let tx = await secretjs.tx.compute.executeContract(
        {
            sender: wallet.address,
            contract_address: contract,
            msg: msg,
        },
        { gasLimit: 400_000, }
    )
    console.log(tx)
}
let set_headstash_as_minter = async (contract) => {
    const msg = { add_minters: { minters: [headstashAddr] } }
    let tx = await secretjs.tx.compute.executeContract(
        {
            sender: wallet.address,
            contract_address: contract,
            msg: msg,
        },
        { gasLimit: 400_000, }
    )
    console.log(tx)
}

let query_token_info = async (contract, code_hash) => {
    const tokenInfoQuery = await secretjs.query.compute.queryContract({
        contract_address: contract,
        query: {
            token_info: {},
        },
        code_hash: code_hash,
    });

    console.log(tokenInfoQuery);
};

let query_token_config = async (contract, code_hash) => {
    const tokenInfoQuery = await secretjs.query.compute.queryContract({
        contract_address: contract,
        query: {
            token_config: {},
        },
        code_hash: code_hash,
    });

    console.log(tokenInfoQuery);
};
let query_balance = async (contract, key) => {
    const tokenInfoQuery = await secretjs.query.compute.queryContract({
        contract_address: contract,
        query: {
            balance: { address: wallet.address, key: key },
        },
        code_hash: null,
    });

    console.log(tokenInfoQuery);
};

export { upload_snip120u, init_snip120u,set_headstash_as_minter, deposit_to_snip20, query_token_info, query_token_config, set_viewing_key, query_balance, fund_headstash }
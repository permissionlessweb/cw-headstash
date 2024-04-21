import { chain_id, scrt20CodeHash, scrt20codeId, secretjs, wallet, scrtHeadstashContractAddr } from "./main.js";

// initiates a new snip-20 
let i_snip20 = async (name, symbol, supported_denom) => {
    const initMsg = {
        name: name,
        symbol: symbol,
        decimals: 6,
        prng_seed: Buffer.from("dezayum").toString("base64"),
        config: {
            enable_deposit: true,
            enable_redeem: true,
            enable_burn: true,
        },
        admin: wallet.address,
        supported_denoms: [supported_denom]
    };
    let tx = await secretjs.tx.compute.instantiateContract(
        {
            code_id: scrt20codeId,
            sender: wallet.address,
            code_hash: scrt20CodeHash,
            init_msg: initMsg,
            label: " Secret Wrapped Terp Network Gas Tokens (THIOL)" + Math.ceil(Math.random() * 10000),
        },
        {
            gasLimit: 400_000,
        }
    );
    if (tx.code == 0) {
        //Find the contract_address in the logs
        const contractAddress = tx.arrayLog.find(
            (log) => log.type === "message" && log.key === "contract_address"
        ).value;

        console.log(contractAddress);
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
    const msg = { transfer: { recipient: scrtHeadstashContractAddr, amount: amount } }
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

export { i_snip20, deposit_to_snip20, query_token_info, query_token_config, set_viewing_key, query_balance, fund_headstash }
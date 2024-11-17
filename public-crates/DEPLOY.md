# Manual Deploy 

| Contract   | Cw-Glob | Cw-ICA-Owner | Cw-ICA-Controller | Snip120u | Cw-Headstash 
|----------|----------|----------|---|---|---|
| juno-1 |  | 4606 | 4607 | 2044 | 2045 | |

headstash-deployer 	   - juno16rf32fw2r4nvmmellcu4c8wn7qrz4qfmtzexmj\
headstash native tokens - 1000000000000factory/juno16rf32fw2r4nvmmellcu4c8wn7qrz4qfmtzexmj/headstash1\
headstash native tokens - 1000000000000factory/juno16rf32fw2r4nvmmellcu4c8wn7qrz4qfmtzexmj/headstash2\
cw-ica-owner 			   - juno1r2cf69mnm82uhnv7r87uuk2g07z27sgcw86s65muemwk6qpwmu3sfkuddk\
cw-ica-controller 		- juno1zhrunluc6ykvl90z4v4fmr0vrkjt35exp7d9aszfhjncjvztqs5shc4t0y\
cw-glob 					   - 


### 0. Build Contracts 
```sh
sh build.sh
```

### 1. Upload Contracts On Secret
```sh 
# install secret-js packages
cd scripts/secretjs && yarn 
```
```sh
# upload snip120u contract
node main.js -1
```
*populate snip120u code-id & code-hash into scripts*

```sh
# upload cw-headstash contract
node main.js -2
```
*populate headstash code-id & code-hash into scripts*

```sh
# upload cw-headstash contract
node main.js -2
```
### 2. Upload Contracts On Source Chain 
```sh
junod tx wasm store ../../public-crates/artifacts/headstash_ica_owner.wasm --from headstash --gas auto --gas-adjustment 1.3 --chain-id juno-1 --fees 1000000ujuno
```
```sh
junod tx wasm store ../../public-crates/artifacts/cw_ica_controller.wasm --from headstash --gas auto --gas-adjustment 1.3 --chain-id juno-1 --fees 1000000ujuno
```
### 2. Instantiate Cw-ICA-Owner
Ensure you provide the code-ids for snip120u & cw-headstash on secret network
```sh
junod tx wasm i 4606 '{"ica_controller_code_id": 4607, "headstash_params": {"snip120u_code_id": 2044, "headstash_code_id": 2045, "snip120u_code_hash": "6874217178fc6550d0753a888a72b56a42dc0f55f76b33219d70895915a1e9a5","token_params": [{"name": "ScrtTerp","symbol": "scrtTERP", "native": "factory/juno16rf32fw2r4nvmmellcu4c8wn7qrz4qfmtzexmj/headstash1", "ibc":"ibc/800860DB61160F1F6A9CBE45695B3900F7F2F1F68595563260EE25FC97969334", "total": "1000000000000"},
{"name":"ScrtThiol","symbol": "scrtTHIOL","native": "factory/juno16rf32fw2r4nvmmellcu4c8wn7qrz4qfmtzexmj/headstash2", "ibc":"ibc/800860DB61160F1F6A9CBE45695B3900F7F2F1F68595563260EE25FC97969334", "total": "1000000000000"}], "multiplier": true, "bloom_config": {"default_cadance": 50, "min_cadance": 0, "max_granularity": 5}, "headstash_init_config":{"claim_msg_plaintxt": "HREAM ~ {wallet} ~ {secondary_addr} ~ {expiration}","viewing_key":"eretskeretjableret"}}}' --from headstash --fees 25000ujuno --label cw-headstash-owner --no-admin
```

### 3. Create ICA 
```sh
junod tx wasm e juno1r2cf69mnm82uhnv7r87uuk2g07z27sgcw86s65muemwk6qpwmu3sfkuddk '{"create_ica_contract":{"channel_open_init_options":{"connection_id":"connection-68", "counterparty_connection_id": "connection-9"}}}' --from headstash --fees 50000ujuno
```

### 4. Query ICA 
```sh
junod q wasm contract-state smart juno1r2cf69mnm82uhnv7r87uuk2g07z27sgcw86s65muemwk6qpwmu3sfkuddk '{"get_ica_contract_state":{"ica_id": 0 }}'
```

### 5. Instantiate Snip120u's
```sh
junod tx wasm e juno1r2cf69mnm82uhnv7r87uuk2g07z27sgcw86s65muemwk6qpwmu3sfkuddk '{"init_snip120u": {"ica_id": 0}}' --from headstash --fees 50000ujuno
```

### 6. Instantiate Cw-Headstash
```sh
junod tx wasm e juno1r2cf69mnm82uhnv7r87uuk2g07z27sgcw86s65muemwk6qpwmu3sfkuddk '{"init_headstash": {"ica_id": 0}}' --from headstash --fees 50000ujuno
```

### 7. Authorize Cw-Headstash as Minter For Snip120u
```sh 
junod tx wasm e juno1r2cf69mnm82uhnv7r87uuk2g07z27sgcw86s65muemwk6qpwmu3sfkuddk '{"authorize_minter": {"ica_id": 0}}' --from headstash --fees 50000ujuno
```

### 7. Fund Cw-Headstash Contract
```sh 
junod tx wasm e juno1r2cf69mnm82uhnv7r87uuk2g07z27sgcw86s65muemwk6qpwmu3sfkuddk '{"ibc_transfer_tokens": {"ica_id": 0}}' --from headstash --fees 50000ujuno
```

### 8. Add Eligible Headstashers
```sh 
junod tx wasm e juno1r2cf69mnm82uhnv7r87uuk2g07z27sgcw86s65muemwk6qpwmu3sfkuddk '{"add_headstash_minters": {"ica_id": 0, "to_add": [{"pubkey": "0x1234", "snips":[{"addr":"secret12345", "amount": "12345"}]},{"pubkey": "0x1234", "snips":[{"addr":"secret19876", "amount": "54321"}]}]}' --from headstash --fees 50000ujuno
```
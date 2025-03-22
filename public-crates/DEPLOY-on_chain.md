| Contract   | Cw-Glob | Cw-ICA-Owner | Cw-ICA-Controller |
|----------|----------|----------|-- |
| juno-1 | 4608 | 4616 | 4617 | |

## Deployment Sequence 

### 0. Build Contracts 
```sh
sh build.sh
```

### 1. Upload 

headstash-deployer 	   - juno16rf32fw2r4nvmmellcu4c8wn7qrz4qfmtzexmj\
headstash native tokens - 1000000000000factory/juno16rf32fw2r4nvmmellcu4c8wn7qrz4qfmtzexmj/headstash1\
headstash native tokens - 1000000000000factory/juno16rf32fw2r4nvmmellcu4c8wn7qrz4qfmtzexmj/headstash2\
cw-ica-owner 			   - juno1w7w2dmccxp6u9plzkczmv3mvulnup7rw6vyf9tw4evtamru69khq6hfsj6\
cw-ica-controller 		- 
cw-glob 					   - 

ica-addr - secret1n7lylcpy3tt3jlyya62a6aq8cfpnfvhhefdhw7znt9eufjelltaq6pdxpe

### 2. Create Tokens to distribute 
```sh
# using x/tokenfactory 
junod tx tokenfactory create-denom headstash1 --from headstash --fees 300000ujuno 
# mint tokens 
 junod tx tokenfactory mint <amount> --from headstash --fees 10000ujuno 
```
## 3. IBC Transfer to generate token hash 

```sh
junod tx ibc-transfer transfer transfer channel-n <sender> <amount> --from headstash --fees 10000ujuno --timeout 21037900
```

### 4. Init Cw-ICA-Owner
```sh
TERP_SNIP_NAME="ScrtTerp"
TERP_SNIP_SYMBOL="scrtTERP"
TERP_SNIP_NATIVE="factory/juno16rf32fw2r4nvmmellcu4c8wn7qrz4qfmtzexmj/headstash1"
TERP_SNIP_IBC="ibc/800860DB61160F1F6A9CBE45695B3900F7F2F1F68595563260EE25FC97969334"
TERP_SNIP_TOTAL="1000000000000"
HEADSTASH_CLAIM_PLAINTXT="HREAM ~ {wallet} ~ {secondary_addr} ~ {expiration}"

junod tx wasm i 4616 '{"owner": "juno16rf32fw2r4nvmmellcu4c8wn7qrz4qfmtzexmj","feegranter": "juno1xxgjfagmpuye0r9ftg8p0aq75jcjnm9yzq6rfm","ica_controller_code_id": 4617,"headstash_params": {"snip120u_code_hash": "3884f72403e5308db76748244d606dd8bfa98eb560b1906d5825fc7dd72f867e","token_params": [{"name": $TERP_SNIP_NAME,"symbol": $TERP_SNIP_SYMBOL,"native": $TERP_SNIP_NATIVE,"ibc": $TERP_SNIP_IBC","total": $TERP_SNIP_TOTAL}],"multiplier": true,"bloom_config": {"default_cadance": 50,"min_cadance": 0,"max_granularity": 5},"headstash_init_config":{"claim_msg_plaintxt": $HEADSTASH_CLAIM_PLAINTXT,"random_key": "encrypted-random-key"}}}' --from headstash --fees 25000ujuno --label cw-headstash-owner --no-admin
```

### 5. Create Ica-Controller 
```sh
# juno -> secret
junod tx wasm e juno1w7w2dmccxp6u9plzkczmv3mvulnup7rw6vyf9tw4evtamru69khq6hfsj6 '{"create_ica_contract":{"channel_open_init_options":{"connection_id":"connection-68", "counterparty_connection_id": "connection-9"}}}' --from headstash2 --fees 50000ujuno
```

### 5.1 Query ICA State For Cw-ICA-Controller Addr 
```sh
junod q wasm contract-state smart juno1w7w2dmccxp6u9plzkczmv3mvulnup7rw6vyf9tw4evtamru69khq6hfsj6 '{"get_ica_contract_state":{ }}'
```
### 6. Initialize Cw-Glob W/ Ica-Controller Addr as admin 
```sh
junod tx wasm i 4603 '{"owners":["juno1j2ffekr62l4cusl3ahjfczgg529kn0t2yeekgdndw4e7xdx3petqazldpx"]}' --from headstash --no-admin --label cw-glob --fees 25000ujuno
```

### 7. Set Cw-Glob Addr To Cw-ICA-Owner 
```sh
junod tx wasm e juno1j2ffekr62l4cusl3ahjfczgg529kn0t2yeekgdndw4e7xdx3petqazldpx '{"set_cw_glob":{"cw_glob": "juno1a2x0ha9tlj4ez0yuyvf4ncw7jgl4ypn5zrfle6tt2tqch6kr5t3qv6zm02"}}' --from headstash --fees 15000ujuno
```

### 8. Upload Snipp120u Wasm From ICA On Secret 
```sh
junod tx wasm e juno1j2ffekr62l4cusl3ahjfczgg529kn0t2yeekgdndw4e7xdx3petqazldpx '{"upload_contract_on_secret": "wasm": "snip120u"}}' --from headstash --fees 200000ujuno
```

### 9. Upload Cw-Headstash Wasm From ICA On Secret 
```sh
junod tx wasm e juno1j2ffekr62l4cusl3ahjfczgg529kn0t2yeekgdndw4e7xdx3petqazldpx '{"upload_contract_on_secret": "wasm": "cw-headstash"}}' --from headstash --fees 200000ujuno
```

### 10. Instantiate Snips 
```sh
junod tx wasm e juno1w7w2dmccxp6u9plzkczmv3mvulnup7rw6vyf9tw4evtamru69khq6hfsj6 '{"init_snip120u": {}}' --from headstash2 --fees 200000ujuno
```

### 11. Instantiate Cw-Headstash
```sh
junod tx wasm e juno1appmdzw8m8nmvs23tcrrvcmxcj8l7kyyyaukqg5cw85sjg2zstms8huhrm '{"init_headstash": {}}' --from headstash --fees 200000ujuno
```

### 12. Authorize Minter
```sh
junod tx wasm e juno1appmdzw8m8nmvs23tcrrvcmxcj8l7kyyyaukqg5cw85sjg2zstms8huhrm '{"authorize_minter": {}}' --from headstash --fees 200000ujuno
```

### 13. Fund Cw-Headstash Contract
```sh 
junod tx wasm e juno1r2cf69mnm82uhnv7r87uuk2g07z27sgcw86s65muemwk6qpwmu3sfkuddk '{"ibc_transfer_tokens": {}}' --from headstash --fees 50000ujuno
```

### 14. Add Headstashers
```sh 
junod tx wasm e juno1r2cf69mnm82uhnv7r87uuk2g07z27sgcw86s65muemwk6qpwmu3sfkuddk '{"add_headstash_minters": "to_add": [{"pubkey": "0x1234", "snips":[{"addr":"secret12345", "amount": "12345"}]},{"pubkey": "0x1234", "snips":[{"addr":"secret19876", "amount": "54321"}]}]}' --from headstash --fees 50000ujuno
```


## Manually Set Logic
### Set Code-ID's
```sh
# set snip120u first
junod tx wasm e juno1w7w2dmccxp6u9plzkczmv3mvulnup7rw6vyf9tw4evtamru69khq6hfsj6 '{"set_snip120u_code_id":{"code_id":2058}}' --from headstash2 --fees 20000ujuno
```
```sh
# set cw-headstash second
junod tx wasm e juno1w7w2dmccxp6u9plzkczmv3mvulnup7rw6vyf9tw4evtamru69khq6hfsj6 '{"set_headstash_code_id":{"code_id":2059}}' --from headstash2 --fees 20000ujuno
```
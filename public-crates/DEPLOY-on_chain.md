| Contract   | Cw-Glob | Cw-ICA-Owner | Cw-ICA-Controller |
|----------|----------|----------|-- |
| juno-1 | 4603 | 4601 | 4600 | |

## Deployment Sequence 

### 0. Build Contracts 
```sh
sh build.sh
```

### 1. Upload 

headstash-deployer 	   - juno16rf32fw2r4nvmmellcu4c8wn7qrz4qfmtzexmj\
headstash native tokens - 1000000000000factory/juno16rf32fw2r4nvmmellcu4c8wn7qrz4qfmtzexmj/headstash1\
headstash native tokens - 1000000000000factory/juno16rf32fw2r4nvmmellcu4c8wn7qrz4qfmtzexmj/headstash2\
cw-ica-owner 			   - juno16hwsz2fgn6eu54kpgwasc7p9h9qzkt84q6hm77qgmsh8s0fhdczslxz45a\
cw-ica-controller 		- juno1t4vx89l4da854f885x9fs7fd4jkqxy2p25z4texd8azsu74rapjsflqe7e
cw-glob 					   - juno1a2x0ha9tlj4ez0yuyvf4ncw7jgl4ypn5zrfle6tt2tqch6kr5t3qv6zm02

### 2. Create Tokens to distribute 
```sh
# using x/tokenfactory 
junod tx tokenfactory create-denom headstash1 --from headstash --fees 300000ujuno 
```
```sh
# mint tokens 
 junod tx tokenfactory mint <amount> --from headstash --fees 10000ujuno 
```

## 3. IBC Transfer to generate token hash 

```sh
junod tx ibc-transfer transfer transfer channel-n <sender> <amount> --from headstash --fees 10000ujuno --timeout 21037900
```

### 4. Init Cw-ICA-Owner
```sh
junod tx wasm i 4601 '{"ica_controller_code_id": 4600, "headstash_params": {"snip120u_code_hash": "cb21cfd39706c719716ffb32175df3754e841966283593adfe952dbc930b9db1","token_params": [{"name": "ScrtTerp","symbol": "scrtTERP", "native": "factory/juno16rf32fw2r4nvmmellcu4c8wn7qrz4qfmtzexmj/headstash1", "ibc":"ibc/800860DB61160F1F6A9CBE45695B3900F7F2F1F68595563260EE25FC97969334", "total": "1000000000000"},
{"name":"ScrtThiol","symbol": "scrtTHIOL","native": "factory/juno16rf32fw2r4nvmmellcu4c8wn7qrz4qfmtzexmj/headstash2", "ibc":"ibc/800860DB61160F1F6A9CBE45695B3900F7F2F1F68595563260EE25FC97969334", "total": "1000000000000"}], "multiplier": true, "bloom_config": {"default_cadance": 50, "min_cadance": 0, "max_granularity": 5}}}' --from headstash --fees 25000ujuno --label cw-headstash-owner --no-admin
```

### 5. Create Ica-Controller 
```sh
# juno -> secret
junod tx wasm e juno16hwsz2fgn6eu54kpgwasc7p9h9qzkt84q6hm77qgmsh8s0fhdczslxz45a '{"create_ica_contract":{"channel_open_init_options":{"connection_id":"connection-68", "counterparty_connection_id": "connection-9"}}}' --from headstash --fees 50000ujuno
```

### 5.1 Query ICA State For Cw-ICA-Controller Addr 
```sh
junod q wasm contract-state smart juno16hwsz2fgn6eu54kpgwasc7p9h9qzkt84q6hm77qgmsh8s0fhdczslxz45a '{"get_ica_contract_state":{"ica_id": 0 }}'
```
### 6. Initialize Cw-Glob W/ Ica-Controller Addr as admin 
```sh
junod tx wasm i 4603 '{"owners":["juno1t4vx89l4da854f885x9fs7fd4jkqxy2p25z4texd8azsu74rapjsflqe7e"]}' --from headstash --no-admin --label cw-glob --fees 25000ujuno
```

### 7. Set Cw-Glob Addr To Cw-ICA-Owner 
```sh
junod tx wasm e juno16hwsz2fgn6eu54kpgwasc7p9h9qzkt84q6hm77qgmsh8s0fhdczslxz45a '{"set_cw_glob":{"cw_glob": "juno1a2x0ha9tlj4ez0yuyvf4ncw7jgl4ypn5zrfle6tt2tqch6kr5t3qv6zm02"}}' --from headstash --fees 15000ujuno
```

### 8. Upload Wasm From ICA On Secret 
```sh
junod tx wasm e juno16hwsz2fgn6eu54kpgwasc7p9h9qzkt84q6hm77qgmsh8s0fhdczslxz45a '{"upload_contract_on_secret": {"ica_id": 0, "wasm": "snip120u"}}' --from headstash --fees 200000ujuno
```
### 8. Upload Wasm From ICA On Secret 
```sh
junod tx wasm e juno1appmdzw8m8nmvs23tcrrvcmxcj8l7kyyyaukqg5cw85sjg2zstms8huhrm '{"upload_contract_on_secret": {"ica_id": 0, "wasm": "snip120u"}}' --from headstash --fees 200000ujuno
```



### Helpful CLI Commands 
```sh
# to grab the gas spent:
wasmd q tx <TX_HASH> | grep -o '"gas_used":"[^"]*' | cut -d'"' -f4
```

```sh
# to grab the code-id:
wasmd q tx <TX_HASH> | sed -n 's/.*"key":"code_id","value":"\([^"]*\)".*/\1/p' 
```

```sh
# to grab the contract-addr 
wasmd q tx <TX_HASH> | sed -n 's/.*"key":"contract_addr","value":"\([^"]*\)".*/\1/p' 
```

```sh
# check the packet acknowledgement 
wasmd q ibc channel  unreceived-acks wasm.juno1hec0dvrqf4tge8ellw3deezuc0zq8kgpea8r70ndgk8wxvaxdrys72pqy0 channel-625 --sequences=1 
```
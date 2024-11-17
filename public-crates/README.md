# Public Crates


## Deployment Details
The following is the estimated gas costs:

| Contract   | Cw-Glob | Cw-ICA-Owner | Cw-ICA-Controller |
|------------|----------|----------|----------|
| Gas Used (upload) |  ~ 6,553,480  |  ~ 3,655,077 |~ 4,394,298 |
| Gas Used (init)   |  ~ 140,523 |----------| |
| Gas Used (hash-globs) |  ~ 140,523 |----------| |
| Gas Used (take snip120u glob) |  ~ 379,641 |----------| |
| Gas Used (take headstash glob) |  ~ 359,842 |----------| |
| Gas Used (init glob) |  ~ 162,937 |----------| |
| Gas Used (init ica-owner) | ------- | ~227,980 |
| Gas Used (hash-glob) | ~153,455  | ------- |
| Gas Used (take-glob) snip120u | ~423,865  | ------- |
| Gas Used (take-glob)  cw-headstash | ~402,206  | ------- |
|----------|----------|----------| |

- cw-ica-owner always will receive callbacks
- a specific sequence is expected for deploying and configuring the contracts on secret, if there are not pre-existing values 


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
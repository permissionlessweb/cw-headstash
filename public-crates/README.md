# Public Crates
 
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
wasmd q tx <TX_HASH>  | sed -n 's/.*"key":"_contract_address","value":"\([^"]*\)".*/\1/p' 
```

```sh
# check the packet acknowledgement 
wasmd q ibc channel  unreceived-acks wasm.<source-contract> channel-<to-destination> --sequences=1
```
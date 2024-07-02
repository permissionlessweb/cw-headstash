
# IBC-Hooks
*https://docs.scrt.network/secret-network-documentation/confidential-computing-layer/ibc/ibc-hooks/auto-wrapping-of-snip-20-tokens-with-ibc-hooks*

## Setup Relayer

## IBC Transfer

### Transfer Tokens
```sh
secretcli tx ibc-transfer transfer transfer channel-0 <your-wallet-addr> 1uscrt --from a
```
### Get IBC Denom 
```sh
secretcli q bank balances secret1ap26qrlp8mcq2pg6r47w43l0y8zkqm8a450s03
```
## Init Wasm Hooks Wrapper
```sh
 secretcli tx compute instantiate <wasm-hooks-code-id> '{}' --from a --label wrap-ibc -y
```

### Auto Wrap SNIP-20
define the memo for the ibc-transfer:
```sh
HUB_CHAIN_ID="secretdev-1"
sSCRT="<snip20-contract-addr>"
WRAP_DEPOSIT_CONTRACT_ADDRESS="<IBC Hooks Wrapper Contract>"
myScrtAddress="secret123"
memo=$(echo -n '{"wasm":{"contract":"'$WRAP_DEPOSIT_CONTRACT_ADDRESS'","msg":{"wrap_deposit":{"snip20_address":"'$sSCRT'","recipient_address":"'$headstashContractAddr'"}}}}' | base64)
```
execute the token transfer:
```sh
secretcli tx ibc-transfer transfer transfer channel-0 "$sSCRT" 1uscrt --memo "$memo" --from a
```
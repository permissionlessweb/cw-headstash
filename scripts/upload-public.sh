# set env variables
CLI=junod
CHAIN_ID=juno-1

junod tx wasm upload public-crates/artifacts/cw_glob.wasm --from headstash --gas auto --gas-adjustment 1.3 --chain-id $CHAIN_ID  --fees 1000000ujuno
sleep
junod tx wasm upload public-crates/artifacts/headstash_ica_owner.wasm --from headstash --gas auto --gas-adjustment 1.3 --chain-id $CHAIN_ID --fees 1000000ujuno

junod tx wasm upload public-crates/artifacts/cw_ica_controller.wasm --from headstash --gas auto --gas-adjustment 1.3 --chain-id $CHAIN_ID --fees 1000000ujuno

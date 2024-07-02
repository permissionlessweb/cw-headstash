#  Secret Headstash

Transparency-minimized airdrop contract for cosmos bech32 addresses to claim via ownership verification of an ethereum account.

## Content

- [Headstash Contract](./contract/airdrop/) - CosmWasm contract that verifies eth signatures and distirbutes snip20 tokens.
- [Headstash Tools](./tools/headstash/README.md) - `secretjs` scripts to deploy & interact with headstash instances.
- [Headstash & Feegrant API](./) - express.js server that provides distribution data to ui, as well as can authorize feegrants by verifying eth signatures.
- [Headstash UI Demo ](./) - webapp for claiming a headstash. 

## Demo 

## Dashboard

## Setup Instructions

#### Constants
Inside of [`main.js`](./tools/headstash/main.js), there are various constant values that we can define for our deployment.

| value | description| 
|-|-|
| `chain_id` | network to deploy to |
| `wallet` | private seed being used to sign & broadcast msgs |
| `scrt20codeId` | code id of snip20 |
| `scrt20CodeHash` | code hash of snip20 |
| `scrtContractAddr1` | snip20 contract addr to be distributed by headstash contract |
| `scrtContractAddr2` | optional second snip20 contract addr to be distributed by headstash contract |
| `scrtHeadstashCodeId` | code id of headstash contract |
| `scrtHeadstashCodeHash` | code hash of headstash contract |
| `scrtHeadstashContractAddr` | contract address of headstash contract |
| `scrtIBCDenom1` | native or ibc denom |
| `scrtIBCDenom2` | native or ibc denom |
| `ethPubkeysToAdd` | file location of eth pubkeys included in headstash instance. see [#6](README.md#6-add-eth-address-able-to-claim) |


## Usage Guidelines 
### 1. Build The Contract Code 
```sh
make build
```
### 2. Deploy Wasm Blob To Secret Network 
We can deploy using the [headstash tools](./tools/headstash/) scripts. Make sure you have build the contract locally, or else the scripts will not work properly.\
To deploy, navigate to the headstash tools, install the node dependencies, and run:
```sh
cd tools/headstash && yarn && node main.js -s
```
*This will store the wasm blob we've built to secret netowrk & return our code-id*

### 3. Prepare SNIP-20
The headstash distributes SNIP20s, so we will need to create an snip20 instance that is for our IBC token to wrap into.

To create our snip20, add your desired ibc token denom to the constants in `main.js`. To review obtaining an ibc-denom, [refer here](./IBC_HOOKS.md) then run:
```sh
node main.js -i-snip1
```
*This will return our contract address, be sure to add this to the constants in `main.js`*

### 4. Create Headstash Instance
Now we can provide the total amount of tokens we expect to distribute to create our headstash contract. The snip20 weve created is set as the token the contract will distribute.
```sh
node main.js -init-headstash
```

### 5. Deploy IBC Hooks For Auto Wrapping
Now we can make converting the ibc token into its snip20 version and funding our airdrop contract happen in one transaction with ibc-hooks. [Refer here](./IBC_HOOKS.md) for guides to deploy ibc hooks.


### 6. Add Eth Address Able To Claim 
to add address that can verify & claim their headstash, our headstash-tools can run a script to batch store addresses in a json file with the following format:
```json
[
    {
    "eth_pubkey": "0x710",
    "amount": "1234567"
    },
    ...
]
```

To add addresses to claim their headstash:
```sh
node tools/headstash/main.js -add
```

## 7. Fund Headstash 
If you decided not to use ibc hooks, or using either an existing snip or native asset, than we need need to fund the contract with the tokens to distribute.

### Wrap Into SNIP20 
```sh
node main.js -convert-token1 432 
```

### Fund Headstash 
To fund the headstash contract:
```sh
node main.js -fund-hs-token1 <amount>
```

## 8. Provide Feegrants
feegrants can be provided to wallet addresses via:
```sh 
node main.js -feegrant <addr-to-feegrant>
```

## 9. Claim Assets
Claiming tokens involves the generation of an eth signature, with the secret pubkey address as the msg string of the signature. This signature is passed to the contract, along with the eth pubkey that generated it. 

```sh
node main.js -claim
```

And thats it! Weve successfully claimed our headstash privately.
## 10. Verify You have claimed
We can query the snip20 contract to confirm our new balance
```sh
node main.js -q-snip1-bal
```


## Additional Information 
### Gas Cost 
The cost to add 200 addresses to the contract map is  ~ 1 SCRT token @ `0.1 SCRT` for Fee Price  [example tx](https://testnet.ping.pub/secret/tx/C54BBEBE5360E98E200DDDA21E69278A05A11C342EDA8798011CA10BB8F0C320)

### Future Goals
- Create merkle tree implementation 
- Define custom value for each token denomination 
- Configure claim hooks 
- Entropy generation contracts for post-claim distortion
- Skip over duplicates when adding new addresses, add config to add or replace value if duplicate is added
- restart airdrop
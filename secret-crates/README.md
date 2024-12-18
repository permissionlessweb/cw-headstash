#  Secret Headstash

Transparency-minimized airdrop contract for cosmos bech32 addresses to claim via ownership verification of an ethereum account.

## Table Of Contents -->
- [Headstash Contract](./contract/headstash/) - CosmWasm contract that verifies eth signatures and distirbutes snip20 tokens.
- [Snip120u](./contract/snip120u/) - Custom snip120u implementation for headstashes.
- [Headstash Scripts](./tools/headstash/README.md) - `secretjs` scripts to deploy & interact with headstash instances.
- [Headstash Feegrant API](https://github.com/hard-nett/community-dashboard/tree/no-merkle/caching-api) - express.js server that provides distribution data to ui, as well as can authorize feegrants by verifying eth signatures.
- [Headstash UI](https://github.com/hard-nett/community-dashboard/tree/no-merkle) - webapp for claiming a headstash.  -->

### Goals
- ica: handle callbacks for ibc packet transfer success & errors.
- feature: Reimplement merkle tree 
- headstash: Skip over duplicates when adding new addresses, OR enable updating total if duplicate is added, and enabled.
- headstash: Update total_amount when additional accepted token is sent, allow claim proportional to distribution amount after each claim.
- headstash: add option to define recipient other than signer during claim.
- headstash: Configure claim hooks 
- headstash: mimic delayed-write-buffer for
    - ~~adding eligible address & amounts~~
    - ~~claiming headstashes~~
    - registering ibc-blooms txs 
    - processing ibc-bloom mempool
- scripts: scramble order of addr registered for eligiblility ()
- headstash: start at random index when adding eligible keys.
- snip120: implement DWB 
- IBC: add support for polytone ( in order to successfully handle cross chain )
- ~~headstash: use dwb for each snip120 total_claim (not needed, non-unique value)~~
- ~~headstash: implement gas_tracker feature~~
- ~~scripts: check and handle and duplicates~~
- ~~Configure IBC/Clock hooks for tx mempool support~~
- ~~On contract init, create snip120u contract for each token sent.~~
- ~~Allow cosmos, eth pubkeys, or solana addr to verify ownership and claim headstash.~~
- ~~Define custom value for each token denomination~~
- ~~Entropy generation contracts for post-claim distortion~~
- ~~Add optional randomness multiplier to airdrop claim.~~

## Delayed Write Buffers


### Registering IBC Blooms

---
## Creating a Headstash 
To create a headstash contract instance, you will need to have ready the following:
| value | description| type |
|-|-|-|
| `owner` | owner of the headstash instance | string | 
| `claim_msg_plaintext` | plaintext message used when signing offline signature | `String` |
| `start_date` | optional, start date where headstash claims can begin | `Option<u64>` |
| `end_date` | option, end date where headstash claims are available | `Option<u64>` |
| `snip120u_code_hash` | code-hash of the custom snip20 contract | `String` |
| `snips` | define each  `Snip120u` token included in a headstash instance | `Vec<Snip120u>` |
| `viewing_key` | a viewing key (may be used in future, not now) | `String` |
| `bloom_config` | optional configuration for the bloom function | `Option<BloomConfig>` |
<!-- | `snip120u_code_id` | code-id of the custom snip20 contract | -->


## Contract Functions

### `AddEligibleHeadStash`
This function is for a headstash deployers to define a list of accepted snip20 tokens and their allocations for each eligible wallet. When an admin registers public wallet addrs for a headstash instance, they first must ensure that there are no duplicate wallet entries in their allocation-file. A simple script is available [here](./scripts/secretjs/check4Duplicates.js) to ensure there are no duplicates, & decide what to do if there are duplicates. For each snip a wallet is eligible for, a unique txid is generated and used in the DWB workflow. This sets the public wallet addresss with a balance for each snip. 

| value | description| type |
|-|-|-|
| `headstash` | a public address (ETH, SOL, COSMOS), along with a list of Snip20 contract `addr` and the respective `amount` eligible to claim | `Vec<Headstash>` |

### Claim 
Claiming a headstash requires an offline signature of the eligible address to be created. This offline signature is generated with a specific text phrase that at minimum must contain the public wallet address that is calling the headstash contract. *More requirements can be added such as signature lifetime, etc*. This signature, along with the public wallet that generated the signature, and also the amount and snip20 address eligible for must be provided to claim a headstash successfully.

The contract will check if claiming is eligible, by ensuring the headstash has started and has not ended, and also ensuring the claimer has not already claimed 100% of their balance. If enabled, a multiplier is randomly chosen to calculate any additional rewards the claimer will be allocated.
| value | description| 
|-|-|
| `eth_pubkey` | the eth wallet address starting with 0x1 that was used to create the offiline signature |
| `eth_sig` | the offline signature hash generated from the message signers wallet |
| `heady_wallet` | a wallet account that snip120u balance will mint to, but not reveal to the public. |

### Clawback
Contract owner function that will clawback any balance this contract has, into the snip120u token form.

### Ibc-Bloom 

Ibc-Bloom is how participants who have claimed a headstash get tokens to their home chains, without revealing the owner of the tokens. Users submit their desired actioms, and the contract stores them to be run for later. A value called `entropy_ratio` is set by the user and is a 1-10 range of the level of entropy users desire to introduce for completing their ibc-bloom process. The lower this value is, the greater the chance your transaction will be included to finalize by the contracts. The contract at random intervals will choose the ibc-bloom specific DWB's to process any transactions involved. 

- decide whether to send locally (same network as contract), or via IBC channel.
- choose which DWB to use for tx (probability gradient for DWB to be chosen to be processed)
- automate DWB processing via external x/clock module 



## Headstash Lifecycle 

### Allocation distribution is prepared 
### IBC infrastructure is prepared
### ICA is deployed on controller network
### Necessary authorizations are granted
### Headstash infrastructure is deployed on host network

## Cw-Orchestrator Scripts
| value | description| 
|-|-|
| `deploy-cw-ica` | - |
| `grant-authz-as-ica` | - |
| `upload-headstash-infra` | - |
| `create-snip120u` | - |
| `create-headstash` | - |
| `authorize-headstash-as-minter` | - |
| `add-eligible-addrs` | - |

## SecretJS scripts
| Command | Description |
| --- | --- |
| `-duplicate-check` | Checks the distribution.json for duplicates |
| `-upload-headstash` | Stores an airdrop contract |
| `-upload-snip120u` | Stores an airdrop contract |
| `-i-snip1` | Instantiates SNIP-20 version of token ONE |
| `-i-snip2` | Optional, Instantiates SNIP-20 version of token TWO |
| `-init-headstash` | Instantiates headstash contract with default settings |
| `-claim` | Claims the airdrop with hardcoded Eth pubkey and signature |
| `-viewing-key-token1` | Creates a viewing key for token TWO |
| `-viewing-key-token2` | Creates a viewing key for token ONE|
| `-feegrant <address>` | Authorizes feegrant to an address |
| `-q-snip1-bal` | Queries SNIP20 balance for token ONE |
| `-q-snip2-bal` | Queries SNIP20 balance for token TWO |
| `-q-snip1-config` | Queries SNIP20 config for token ONE |
| `-q-snip2-config` | Queries SNIP20 config for token TWO |
| `-q-snip1-info` | Queries SNIP20 info for token ONE |
| `-q-snip2-info` | Queries SNIP20 info for token TWO |
| `-add` | Batch adds address to an airdrop |


<!-- ## Setup Instructions -->


<!-- ## Usage Guidelines 
### 1. Build The Contract Code 
```sh
make build
``` -->
<!-- ### 2. Deploy Wasm Blob To Secret Network 
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

https://github.com/hard-nett/secret-airdrop/assets/123711748/8cd1b629-2f04-4ea9-9834-de274e1d6c90


### 4. Create Headstash Instance
Now we can provide the total amount of tokens we expect to distribute to create our headstash contract. The snip20 weve created is set as the token the contract will distribute.
```sh
node main.js -init-headstash
```

https://github.com/hard-nett/secret-airdrop/assets/123711748/b8db775a-b712-45ec-919f-60f143fa1428


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
https://github.com/hard-nett/secret-airdrop/assets/123711748/28f61f24-e1a3-4a03-a2b0-99ec5ece7551

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


https://github.com/hard-nett/secret-airdrop/assets/123711748/131f7631-c6e8-4eb0-9efe-2f4c5649878e

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
``` -->


<!-- ## Additional Information 
### Gas Cost 
The cost to add 200 addresses to the contract map is  ~ 1 SCRT token @ `0.1 SCRT` for Fee Price  [example tx](https://testnet.ping.pub/secret/tx/C54BBEBE5360E98E200DDDA21E69278A05A11C342EDA8798011CA10BB8F0C320) -->


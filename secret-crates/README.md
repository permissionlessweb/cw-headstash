#  Secret Headstash

## POLYTONE TODO:
- custom parse to save proxy in reply handler (replaces instantiate2)


Transparency-minimized airdrop contract for cosmos bech32 addresses to claim via ownership verification of an ethereum account.

## Table Of Contents -->
- [Headstash Contract](./contract/headstash/) - CosmWasm contract that verifies eth signatures and distirbutes snip20 tokens.
- [Snip120u](./contract/snip120u/) - Custom snip120u implementation for headstashes.
- [Headstash Scripts](./tools/headstash/README.md) - `secretjs` scripts to deploy & interact with headstash instances.
- [Headstash Feegrant API](https://github.com/hard-nett/community-dashboard/tree/no-merkle/caching-api) - express.js server that provides distribution data to ui, as well as can authorize feegrants by verifying eth signatures.
- [Headstash UI](https://github.com/hard-nett/community-dashboard/tree/no-merkle) - webapp for claiming a headstash.  -->

### Goals
- feature: Reimplement merkle tree 
- headstash: Skip over duplicates when adding new addresses, OR enable updating total if duplicate is added, and enabled.
- headstash: Update total_amount when additional accepted token is sent, allow claim proportional to distribution amount after each claim.
- headstash: add option to define recipient other than signer during claim.
- headstash: add support for claim and authorization of actions performed by an ica-callback contract. 
- query: permit query if addr has claimed
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
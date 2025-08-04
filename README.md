# The Headstash Contracts: Transparency Minimized Airdrops


## Credits
This implementation extends the features from https://github.com/srdtrk/cw-ica-controller


## Contents

### Public-Crates
Public crates are for cosmos chains without secretVM.

| **Contracts**   |  Description | 
|----------|----------| 
| `polytone` |  |  
| `cw-glob` |  |  
| `cw-ica-controller` |  |  
| `cw-ica-owner` |  |  

|  **Packages**   |  Description | 
|----------|----------| 
| `cw-orch-polytone` |  |  
| `polytone` |  |  
| `headstash-public` |  |  

### Secret-Crates
Public crates are specifically built for secretVM.
| **Contracts**   |  Description | 
|----------|----------| 
| `cw-headstash` |  |  
| `scrt-polytone` |  |  
| `scrt-dnas` |  |  

| **Packages** |  Description | 
|----------|----------| 
| `secret-polytone` |  |   

## Tests

### Unit tests

### Local Secret <-> Local Terp 
1. spin up local testnetworks
2. spin up relayer, connect networks
3. compile and upload contracts
4. proceed with full headstash workflow

## Sequence
1. prepare eligilbe wallet list
2. define how we want to deploy headstashes
	- direct: deploy directly onto Secret Network from deployment wallet. Expects wallet to have funds being used in headstash.
	- polytone: uses custom polytone framework to create path between two blockchains to deploy the contracts. Expects funds to be on home chain. 
	- cw-ica-controller: uses custom cw-ica implementation to create path between two blockchains to deploy the contracts. Expects funds to be on the home chain.
3. Configure smart contract for use
	- creates snip20 contracts for all tokens
- create snip20s
- connect polytone (creates headstash instance)
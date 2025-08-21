# The Secret Garden: Private Implementation of Polytone

## TODO:
- Resolve bug with instantiation of proxy contract

## Credits
This implementation extends the features from https://github.com/da0-da0/polytone


## Contents

### Public-Crates
Public crates are for cosmos chains without secretVM.

| **Contracts**   |  Description | 
|----------|----------| 
| `polytone-note` |  messages to be performed are first sent to. |  
| `polytone-voice` | Receives messages from the note via IBC. |  
| `polytone-proxy` | Recieves messages from the voice, performs them, and sends results backto the note. |  
| `polytone-listener` | Optional, but keeps internal record of the IBC callback data from both successful & unsuccessful messages |  

|  **Packages**   |  Description | 
|----------|----------| 
| `cw-orch-polytone` | Cw-Orchestrator specific libary for convient, rust based scripting |  
| `polytone` | Common polytone logic, used by the public crates |  

### Secret-Crates
Public crates are specifically built for secretVM.
| **Contracts**   |  Description | 
|----------|----------| 
| `scrt-polytone-voice` |  |  
| `scrt-polytone-proxy` |  |  

| **Packages** |  Description | 
|----------|----------| 
| `secret-polytone` |  |   

## Tests
### Unit tests
```sh
just test-unit
```
### Integration Tests
```sh
```
### E2E Tests
```sh
just test-e2e
```


## Building 
### Requirements
- Cargo 
- Docker 

To compile both secret & public contracts:
```sh
just build
```
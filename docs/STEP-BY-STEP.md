# Step by Step Guide

## instantiate note 
```json
{"block_max_gas": "1000000000"}
```

### polytone listener init 
```json
{"note":"cosmos1er5ldgn29rs4vrg4zut7z864waartlvc8png9qs958u48cqc0mtstwmyln"}
```

## polytone voice init
```json
{
  "sender": "secret1sc0cldtf7nznvy6sxfdvngj953e6s0w90w9r4v",
  "code_id": 2333,
  "init_msg": {
	"proxy_code_id": "2328",
	"block_max_gas": "1000000000"
},
  "label": "polytone-voice:the-secret-garden:Where you tend a rose, my lad, A thistle cannot grow",
  "init_funds": "2uscrt",
  "code_hash": ""
}
```

## create polytone channel
```sh
rly tx channel cosmoshub-secretnetwork --src-port wasm.cosmos17mdse4xz7ndrf34d9c2f3q5uqultwa76mrg4l94cfy30uwpm73fqplhcnp --dst-port wasm.secret1g66ptf60kufhhesm3ca4atr5ulg6avz992rjl3 --order unordered --version polytone-1
``` 

## perform action via polytone
```json
{"execute": {
"msgs": [],
"timeout_seconds": "600",
 "callback": {
            "msg": "",
            "receiver": "cosmos1h6h7r3yjmp5z4ll2ec5tzx0apnvn6d3m58e3v79k7zkrcch2kj4shd8kxx"
          }
}}
```

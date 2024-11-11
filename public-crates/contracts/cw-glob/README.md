# Cw-Blob 

Stores compress wasm blobs for reference by an owner.  Only owner can call contract with string of wasm blob to reference, and contract response with blob in data of the response for uploading the desired blob (this example creates msgs for secret network wasm upload). 




## Instantiate
```sh
'{"owner":"terp1..."}'
```

## Execute 

### Hash Glob
```sh
'{"hash_glob":{"keys": ["cw-headstash", "snip120u"]}}'
```

### Take Glob
```sh
'{"take_glob":{"sender":"terp1...","key":"snip120u" }}'
```

## Query 

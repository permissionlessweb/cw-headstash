# Cw-Blob 

Stores compress wasm blobs for reference by an owner.  Only owner can call contract with string of wasm blob to reference, and contract response with base64 encoded string of the CosmosMsg for uploading the desired blob (this example creates msgs for secret network wasm upload). 


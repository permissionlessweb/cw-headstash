#!/bin/sh
public_schema=schemas/public-schemas/
secret_schema=schemas/secret-schemas/

echo "🖊 Generating schema...!"
rm -rf $public_schema
mkdir -p $public_schema
cd public-crates || exit
cargo run --package polytone-note --bin schema
mv schema/*json ../$public_schema
cargo run --package polytone-proxy --bin schema
mv schema/*json ../$public_schema
cargo run --package polytone-voice --bin schema
mv schema/*json ../$public_schema
echo "✅ Schemas generated."
echo "🖊 Generating TypeScript code...!"
(
  cd ts || exit
  yarn
  yarn run codegen
)
echo "✅ TypeScript code generated."
 

echo "🖊 Generating schema...!"
rm -rf $secret_schema
mkdir -p $secret_schema
cd ../secret-crates || exit
cargo run --package scrt-polytone-proxy --bin scrt-polytone-proxy
mv schema/*json ../$secret_schema
cargo run --package scrt-polytone-voice --bin scrt-polytone-voice
mv schema/*json ../$secret_schema
echo "✅ Schemas generated."
# echo "🖊 Generating TypeScript code...!"
# (
#   cd ts || exit
#   yarn
#   yarn run codegen
# )
# echo "✅ TypeScript code generated."
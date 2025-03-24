# 1. build secret-crate contracts
cd secret-crates && rustup target add wasm32-unknown-unknown && RUSTFLAGS='-C link-arg=-s' cargo build  --release --target wasm32-unknown-unknown --no-default-features
# 2. optimize and move wasm binaries into globs folder
mv ./target/wasm32-unknown-unknown/release/cw_headstash.wasm ../public-crates/contracts/cw-glob/src/globs/cw_headstash.wasm &&
mv ./target/wasm32-unknown-unknown/release/snip20_reference_impl.wasm ../public-crates/contracts/cw-glob/src/globs/snip20_reference_impl.wasm &&
cat ../public-crates/contracts/cw-glob/src/globs/cw_headstash.wasm | gzip -9 > ../public-crates/contracts/cw-glob/src/globs/cw_headstash.wasm.gz &&
cat ../public-crates/contracts/cw-glob/src/globs/snip20_reference_impl.wasm | gzip -9 > ../public-crates/contracts/cw-glob/src/globs/snip120u_impl.wasm.gz &&
# sha256sum ../public-crates/contracts/cw-glob/src/globs/cw_headstash.wasm
# sha256sum ../public-crates/contracts/cw-glob/src/globs/snip20_reference_impl.wasm
# sha256sum ../public-crates/contracts/cw-glob/src/globs/cw_headstash.wasm.gz
# sha256sum ../public-crates/contracts/cw-glob/src/globs/snip120u_impl.wasm.gz
# rm ../public-crates/contracts/cw-glob/src/globs/cw_headstash.wasm && rm ../public-crates/contracts/cw-glob/src/globs/snip20_reference_impl.wasm

# 3. build public crates 
cd ../public-crates && docker run --rm -v "$(pwd)":/code \
  --mount type=volume,source="$(basename "$(pwd)")_cache",target=/target \
  --mount type=volume,source=registry_cache,target=/usr/local/cargo/registry \
  cosmwasm/optimizer-arm64:0.16.0


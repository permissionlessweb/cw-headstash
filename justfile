#!/bin/bash

fmt:
  #!/bin/sh
  cd public-crates && cargo fmt --all --check
  cd ../secret-crates && cargo fmt --all --check
  #  cd ../scripts && cargo fmt --all --check

schema:
    #!/usr/bin/env bash
    sh scripts/tools/schema.sh

lint:
  #!/bin/sh
    cd public-crates && cargo clippy --fix --tests -- -D warnings 
    cd ../secret-crates && cargo clippy --fix --tests -- -D warnings
   
build:
    #!/bin/sh
    # a. build private crates first. use workspace optimizer
    cd secret-crates && make build-mainnet-reproducible
    # build public crates
    cd ../public-crates && just optimize

test:
    cargo test --locked

# publish:
#     #!/usr/bin/env bash
#     crates=(
 
#     )

#     for crate in "${crates[@]}"; do
#       cargo publish -p "$crate"
#       echo "Sleeping before publishing the next crate..."
#       sleep 30
#     done


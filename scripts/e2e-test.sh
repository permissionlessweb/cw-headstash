#!/usr/bin/env sh
# ----------------------------------------------------------------------
#  relayer‑setup.sh
#
#  Usage:  ./relayer-setup.sh <TERP_HOST> <SECRET_HOST>
#
#  What it does:
#   1. Compile your contracts (replace the placeholder command).
#   2. Bring up the Terp and Secret local nodes in Docker.
#   3. Patch the rly config (config.yaml) with the correct RPC URLs,
#      chain‑ids, prefixes, gas‑prices and coin‑type.
#   4. Start the rly‑docker container.
#   5. Run the cargo integration test.
#
#  Prerequisites:
#     • Docker + docker‑compose
#     • curl (to fetch yq if it is missing)
# ----------------------------------------------------------------------
TERP_HOST=$1
SECRET_HOST=$2
RLY_DIR="scripts/tools/rly-docker"
CONFIG_EXAMPLE="${RLY_DIR}/config.yaml.example"
CONFIG="${RLY_DIR}/config.yaml"

# ---------- 1. Argument handling ----------
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <TERP_HOST> <SECRET_HOST>"
    exit 1
fi


# If you run the script inside a CI that uses non‑standard RPC ports,
# set these env‑vars before calling the script:
: "${TERP_RPC_PORT:=23657}"
: "${TERP_GRPC_PORT:=9391}"
: "${SECRET_RPC_PORT:=26657}"
: "${SECRET_GRPC_PORT:=9091}"
: "${TERP_FAUCET_PORT:=5300}"
: "${SECRET_FAUCET_PORT:=5000}"

# ----------------------------------------------------------------------
# Helper: download yq if it is not already on the PATH
# ----------------------------------------------------------------------
download_yq() {
    # Detect OS/arch (only linux/amd64, darwin/amd64 and darwin/arm64 are covered)
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m)

    case "$ARCH" in
        x86_64) ARCH=amd64 ;;
        aarch64|arm64) ARCH=arm64 ;;
        *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
    esac

    YQ_URL="https://github.com/mikefarah/yq/releases/latest/download/yq_${OS}_${ARCH}"
    YQ_BIN="$(mktemp)/yq"

    echo "Downloading yq from $YQ_URL ..."
    curl -L -s "$YQ_URL" -o "$YQ_BIN"
    chmod +x "$YQ_BIN"

    echo "$YQ_BIN"
}

# Try to locate yq; if not found, download a temporary copy.
if command -v yq >/dev/null 2>&1; then
    YQ="yq"
else
    YQ=$(download_yq)
fi

# ----------------------------------------------------------------------
# 2. Build contracts (replace this line with your real build command)
# ----------------------------------------------------------------------
echo "=== Building contracts ==="
just build 

# ----------------------------------------------------------------------
# 3. Start the two local blockchain nodes
# ----------------------------------------------------------------------
echo "=== Starting Terp Network container ==="
docker run --rm -d -p "$TERP_RPC_PORT":26657 -p 1317:1317 -p "$TERP_GRPC_PORT":9091 -p "$TERP_FAUCET_PORT":5000\
	--name localterp terpnetwork/terp-core:localterp
	
echo "=== Starting Secret Network container ==="
docker run --rm -d -p "$SECRET_RPC_PORT":26657 -p 1317:1317 -p "$SECRET_GRPC_PORT":9091 -p "$SECRET_FAUCET_PORT":5000\
	 --name localsecret ghcr.io/scrtlabs/localsecret

# Wait a few seconds for the nodes to become ready (you can make this smarter)
echo "Waiting for nodes to start..."
sleep 10

# ----------------------------------------------------------------------
# 4. Patch the relayer configuration
# ----------------------------------------------------------------------


echo "=== Preparing relayer config ==="
cp "${CONFIG_EXAMPLE}" "${CONFIG}"

# ------------------------------------------------------------------
#   Terp chain values
# ------------------------------------------------------------------
$YQ eval ".chains.terpnetwork.value.rpc-addr = \"https://${TERP_HOST}:${TERP_RPC_PORT}\" |
          .chains.terpnetwork.value.chain-id = \"120u-1\" |
          .chains.terpnetwork.value.account-prefix = \"terp\" |
          .chains.terpnetwork.value.gas-prices = \"0.01uterp\" |
          .chains.terpnetwork.value.key-directory = \"/home/relayer/.relayer/.keys/120u-1\" |
          .chains.terpnetwork.value.key = \"relayer_key\" |
          .chains.terpnetwork.value.coin-type = 118" -i "${CONFIG}"

# ------------------------------------------------------------------
#   Secret chain values
# ------------------------------------------------------------------
$YQ eval ".chains.secretnetwork.value.rpc-addr = \"https://${SECRET_HOST}:${SECRET_RPC_PORT}\" |
          .chains.secretnetwork.value.chain-id = \"secretdev-1\" |
          .chains.secretnetwork.value.account-prefix = \"secret\" |
          .chains.secretnetwork.value.gas-prices = \"0.1uosmo\" |
          .chains.secretnetwork.value.key-directory = \"/home/relayer/.relayer/.keys/secret-1\" |
          .chains.secretnetwork.value.key = \"relayer_key\" |
          .chains.secretnetwork.value.coin-type = 529" -i "${CONFIG}"

echo "Patched config.yaml:"
$YQ eval '.' "${CONFIG}" | cat

# ----------------------------------------------------------------------
# 5. Fire up the rly‑docker container (docker‑compose)
# ----------------------------------------------------------------------
echo "=== Starting rly‑docker (docker‑compose) ==="
cd "${RLY_DIR}" && docker compose up -d

# Give the relayer a moment to initialise before we hand over to the test.
sleep 5

# ----------------------------------------------------------------------
# 6. Run the integration test binary
# ----------------------------------------------------------------------
echo "=== Running integration test ==="
cd  scripts || exit
cargo run --bin e2e4_headstash -- \
    --network local \
    --terp-chain-id 120u-1 \
    --terp-gas-denom uterp \
    --terp-grpc http://"$TERP_HOST":"$TERP_GRPC"\
    --secret-chain-id devnet-1 \
    --secret-gas-denom uscrt \
    --secret-grp http://"$SECRET_HOST":"$SECRET_GRPC"\

# ----------------------------------------------------------------------
# 7. Clean‑up (optional)
# ----------------------------------------------------------------------
# Uncomment the lines below if you want the script to stop the containers
# after the test finishes.
echo "Stopping Docker containers..."
docker rm -f localterp localsecret
docker compose -f $RLY_DIR/docker-compose.yml down

echo "=== DONE ==="
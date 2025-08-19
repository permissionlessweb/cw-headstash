#!/usr/bin/env sh
# ----------------------------------------------------------------------
#  relayer‑setup.sh
#
#  Usage:  ./relayer-setup.sh TERP_HOST SECRET_HOST
#
#  What it does (high‑level):
#   1. Build the contracts (placeholder – replace with your real command)
#   2. Spin up local Terp & Secret nodes
#   3. Create a KEY_DIR containing mnemonic files for BOTH chains
#   4. Patch the relayer config (config.yaml) with RPC URLs, chain‑ids, etc.
#   5. Patch the docker‑compose file so the key‑dir is mounted into the container
#   6. Start the rly‑docker container
#   7. Run the integration‑test binary
#
#  Prerequisites:
#     • Docker + docker‑compose
#     • curl (to fetch yq if it is missing)
# ----------------------------------------------------------------------

# -------------------- 0.  INPUT ------------------------------------------------
# cleanup() {
#   echo "Cleaning up containers..."
#   docker stop localterp localsecret rly-docker-relayer || true
#   # If you didn't use --rm, you might need to use docker rm here instead
#   docker rm -f localterp localsecret || true
# }

# # Set the trap to call cleanup on script exit
# trap cleanup EXIT

TERP_HOST=$1
SECRET_HOST=$2

if [ $# -ne 2 ]; then
    echo "Usage: $0 TERP_HOST SECRET_HOST"
    exit 1
fi

# ----------------------------------------------------------------------
# 0.1  Constants / defaults
# ----------------------------------------------------------------------
RLY_DIR=scripts/tools/rly-docker
CONFIG_EXAMPLE=scripts/data/config.yaml.example
CONFIG="scripts/tools/rly-docker/config.yaml"

LOCAL_TERP_IMG=terpnetwork/terp-core:localterp
LOCAL_SCRT_IMG=ghcr.io/scrtlabs/localsecret

TERP_REPO=https://github.com/terpnetwork/terp-core.git
TERP_BRANCH=v050-upgrade

# ----------------------------------------------------------------------
# 0.2  Ports (override with env‑vars if you need something different)
# ----------------------------------------------------------------------
: ${TERP_RPC_PORT:=23657}
: ${TERP_GRPC_PORT:=9391}
: ${TERP_API_PORT:=1337}
: ${SECRET_API_PORT:=1347}
: ${SECRET_RPC_PORT:=26657}
: ${SECRET_GRPC_PORT:=9091}
: ${TERP_FAUCET_PORT:=5300}
: ${SECRET_FAUCET_PORT:=5000}

# ----------------------------------------------------------------------
# 1.  Ensure git submodules (used by the rly‑docker repo) are present
# ----------------------------------------------------------------------
git submodule init
git submodule update --remote

# ----------------------------------------------------------------------
# 2.  Make sure the local Terp Docker image exists (build if it does not)
# ----------------------------------------------------------------------
if ! docker image inspect "$LOCAL_TERP_IMG" > /dev/null 2>&1; then
    echo "⚙️  Local Terp image not found – cloning & building…"
    TMPDIR=$(mktemp -d)
    git clone --depth 1 --branch "$TERP_BRANCH" "$TERP_REPO" "$TMPDIR"
    (cd "$TMPDIR" && make docker-build-localnet)   # repo’s Makefile does the heavy‑lifting
    rm -rf "$TMPDIR"
    echo "✅  Built $LOCAL_TERP_IMG"
else
    echo "✅  Found existing image $LOCAL_TERP_IMG"
fi

# ----------------------------------------------------------------------
# 3.  Helper: download yq if not already on the PATH
# ----------------------------------------------------------------------
sudo snap install yq
# download_yq() {
#     OS=$(uname -s | tr '[:upper:]' '[:lower:]')
#     ARCH=$(uname -m)

#     case $ARCH in
#         x86_64)
#             ARCH=amd64
#             ;;
#         aarch64 | arm64)
#             ARCH=arm64
#             ;;
#         *)
#             echo "❌ Unsupported architecture: $ARCH" >&2
#             exit 1
#             ;;
#     esac

#     YQ_URL="https://github.com/mikefarah/yq/releases/latest/download/yq_${OS}_${ARCH}"
#     YQ_BIN=$(mktemp)/yq

#     echo "⬇️  Downloading yq from $YQ_URL …"
#     curl -L -s "$YQ_URL" -o "$YQ_BIN"
#     chmod +x "$YQ_BIN"
#     echo "$YQ_BIN"
# }

# if command -v yq > /dev/null 2>&1; then
#     YQ=yq
# else
#     YQ=$(download_yq)
# fi

# ----------------------------------------------------------------------
# 4.  Build contracts (replace the placeholder with your real build command)
# ----------------------------------------------------------------------
# echo "=== Building contracts ==="
# sudo apt install just
# just build &&

# ----------------------------------------------------------------------
# 5.  Spin up the two local blockchain nodes
# ----------------------------------------------------------------------
echo "=== Starting Terp container ==="
docker run --rm -d \
    -p "${TERP_RPC_PORT}:26657" -p $TERP_API_PORT:1317 -p "${TERP_GRPC_PORT}:9091" -p "${TERP_FAUCET_PORT}:5000" \
    --name localterp "$LOCAL_TERP_IMG"

echo "=== Starting Secret container ==="
docker run --rm -d \
    -p "${SECRET_RPC_PORT}:26657" -p $SECRET_API_PORT:1317 -p "${SECRET_GRPC_PORT}:9091" -p "${SECRET_FAUCET_PORT}:5000" \
    --name localsecret "$LOCAL_SCRT_IMG"


# ----------------------------------------------------------------------
# 6.  Prepare the relayer configuration (config.yaml)
# ----------------------------------------------------------------------
echo "=== Preparing relayer config ==="
cp "$CONFIG_EXAMPLE" "$CONFIG" 
YQ="yq"

# --------------------------------------------------------------
#  Terp chain values
# --------------------------------------------------------------
$YQ eval \
    ".chains.terpnetwork.value.rpc-addr   = \"http://${TERP_HOST}:${TERP_RPC_PORT}\"" \
    ".chains.terpnetwork.value.chain-id   = \"${TERP_CHAIN_ID}\"" \
    ".chains.terpnetwork.value.account-prefix = \"${TERP_ACCOUNT_PREFIX}\"" \
    ".chains.terpnetwork.value.gas-prices = \"${TERP_GAS_PRICES}\"" \
    ".chains.terpnetwork.value.key-directory = \"/home/relayer/.keys\"" \
    ".chains.terpnetwork.value.key = \"relayer_key\"" \
    ".chains.terpnetwork.value.coin-type = 118" \
    -i "$CONFIG"

# --------------------------------------------------------------
#  Secret chain values
# --------------------------------------------------------------
$YQ eval \
    ".chains.secretnetwork.value.rpc-addr   = \"http://${SECRET_HOST}:${SECRET_RPC_PORT}\"" \
    ".chains.secretnetwork.value.chain-id   = \"${SECRET_CHAIN_ID}\"" \
    ".chains.secretnetwork.value.account-prefix = \"${SECRET_ACCOUNT_PREFIX}\"" \
    ".chains.secretnetwork.value.gas-prices = \"${SECRET_GAS_PRICES}\"" \
    ".chains.secretnetwork.value.key-directory = \"/home/relayer/.keys\"" \
    ".chains.secretnetwork.value.key = \"relayer_key\"" \
    ".chains.secretnetwork.value.coin-type = 529" \
    -i "$CONFIG"

echo "🔧 Patched config.yaml:"
$YQ eval . "$CONFIG"


# --------------------------------------------------------------
# 0.4  Key directory – where the relayer expects to find the files
# --------------------------------------------------------------
KEY_DIR="${RLY_DIR}/.keys"
export KEY_DIR                # so docker‑compose can read it later

mkdir -p "${KEY_DIR}"
chmod +x "${KEY_DIR}" # Add execute permission to the directory
echo "🔑  Created key files in $KEY_DIR:"
: ${MNEMONIC:=jelly shadow frog dirt dragon use armed praise universe win jungle close inmate rain oil canvas beauty pioneer chef soccer icon dizzy thunder meadow}


TERP_KEY_FILE="${KEY_DIR}/terpnetwork"
SECRET_KEY_FILE="${KEY_DIR}/secretnetwork"

# Write the same mnemonic to both files (the relayer treats the whole
# file content as its seed phrase)
printf '%s\n' "$MNEMONIC" | sudo tee "$TERP_KEY_FILE" > /dev/null
printf '%s\n' "$MNEMONIC" | sudo tee "$SECRET_KEY_FILE" > /dev/null

echo "🔑  Created key files in $KEY_DIR:"
echo "   $TERP_KEY_FILE"
echo "   $SECRET_KEY_FILE"



echo "=== Starting rly‑docker (docker‑compose) ==="
cd "$RLY_DIR"
docker compose up -d          # -d = detached
echo "✅ Container is up"
echo "=== Ready to run integration tests ==="


# cd ../../ || exit 1 
# cargo run --bin e2e4_headstash -- \
#     --network local \
#     --terp-chain-id 120u-1 \
#     --terp-gas-denom uterp \
#     --terp-grpc "http://${TERP_HOST}:${TERP_GRPC_PORT}" \
#     --secret-chain-id devnet-1 \
#     --secret-gas-denom uscrt \
#     --secret-grpc "http://${SECRET_HOST}:${SECRET_GRPC_PORT}"

# # ----------------------------------------------------------------------
# # 10.  Clean‑up (optional)
# # ----------------------------------------------------------------------
# echo "Stopping Docker containers..."
# docker rm -f localterp localsecret
# docker compose -f "$COMPOSE_FILE" down
# docker kill $(docker ps -q)
# echo "=== DONE ==="
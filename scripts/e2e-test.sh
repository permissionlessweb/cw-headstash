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
# ----------------------------------------------------------------------
# 0.2  Ports (override with env‑vars if you need something different)
# ----------------------------------------------------------------------
# System and Architecture Variables
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

# Directory and File Paths
: "${RLY_DIR:="scripts/tools/rly-docker"}"
KEY_DIR="${RLY_DIR}/.keys"
: "${CONFIG_EXAMPLE:="scripts/data/config.yaml.example"}"
: "${CONFIG:="${RLY_DIR}/config.yaml"}"
: "${TERP_KEY_FILE:="${KEY_DIR}/terpnetwork"}"
: "${SECRET_KEY_FILE:="${KEY_DIR}/secretnetwork"}"

# Docker and Binary Variables
: "${LOCAL_TERP_IMG:="terpnetwork/terp-core:localterp"}"
: "${LOCAL_SCRT_IMG:="ghcr.io/scrtlabs/localsecret"}"
: "${TERP_BIN:="terpd"}"
: "${SCRT_BIN:="secretcli"}"
: "${TERP_DOCKER_BIN:="docker exec -it localterp terpd"}"
: "${SCRT_DOCKER_BIN:="docker exec -it localsecret secretcli"}"
: "${YQ_URL:="https://github.com/mikefarah/yq/releases/latest/download/yq_${OS}_${ARCH}"}"
: "${YQ_BIN:=$(mktemp)/yq}"
: "${YQ:="yq"}"

# Repository and Branch Variables
: "${TERP_REPO:="https://github.com/terpnetwork/terp-core.git"}"
: "${TERP_BRANCH:="v050-upgrade"}"
: "${TERP_CORE_REPO_URL:="${TERP_REPO}"}"
: "${TERP_CORE_BRANCH:="${TERP_BRANCH}"}"
: "${SECRET_CLI_URL:="https://github.com/scrtlabs/SecretNetwork/releases/download/v1.20.0/secretcli-Linux"}"
: "${SECRETCLI_RELEASE_URL:="${SECRET_CLI_URL}"}"
: "${SECRETCLI_BINARY_NAME:="secretcli-Linux"}"

# Network and Port Variables
: "${TERP_RPC_PORT:="23657"}"
: "${TERP_GRPC_PORT:="9391"}"
: "${TERP_API_PORT:="1337"}"
: "${SECRET_API_PORT:="1347"}"
: "${SECRET_RPC_PORT:="26657"}"
: "${SECRET_GRPC_PORT:="9091"}"
: "${TERP_FAUCET_PORT:="5300"}"
: "${SECRET_FAUCET_PORT:="5000"}"

# Chain and Token Variables
: "${TERP_CHAIN_ID:="120u-1"}"
: "${TERP_ACCOUNT_PREFIX:="terp"}"
: "${SECRET_CHAIN_ID:="devnet-1"}"
: "${SECRET_ACCOUNT_PREFIX:="secret"}"
: "${TERP_FEE_TOKEN:="uterp"}"
: "${SCRT_FEE_TOKEN:="uscrt"}"

# Miscellaneous Variables
: "${TERP_HOST:="${1}"}"
: "${SECRET_HOST:="${2}"}"
: "${MNEMONIC:="jelly shadow frog dirt dragon use armed praise universe win jungle close inmate rain oil canvas beauty pioneer chef soccer icon dizzy thunder meadow"}"

if [ $# -ne 2 ]; then
    echo "Usage: $0 TERP_HOST SECRET_HOST"
    exit 1
fi

# ensure relayer image is present
git submodule init
git submodule update --remote

# ----------------------------------------------------------------------
# 0.1  install terp & secret cli 
# ----------------------------------------------------------------------
if ! command -v secretcli > /dev/null 2>&1; then
  echo "Installing secretcli..."
  wget "${SECRETCLI_RELEASE_URL}" -O "${SECRETCLI_BINARY_NAME}"
  chmod +x "${SECRETCLI_BINARY_NAME}"
  sudo mv "${SECRETCLI_BINARY_NAME}" /usr/local/bin/secretcli
  echo "secretcli installed."
else
  echo "secretcli is already installed."
fi

# Check and install terpd
if ! command -v terpd > /dev/null 2>&1; then
  echo "Installing terpd..."
  git clone "${TERP_CORE_REPO_URL}"
  cd "$(basename "${TERP_CORE_REPO_URL}" .git)" || exit
  git checkout "${TERP_CORE_BRANCH}"
  make install
  cd ..
  echo "terpd installed."
else
  echo "terpd is already installed."
fi


# ----------------------------------------------------------------------
# 2.  Make sure the local Terp Docker image exists (build if it does not)
# ----------------------------------------------------------------------
if ! docker image inspect "$LOCAL_TERP_IMG" > /dev/null 2>&1; then
    echo "⚙️  Local Terp image not found – cloning & building…"
    TMPDIR=$(mktemp -d)
    git clone --depth 1 --branch "$TERP_BRANCH" "$TERP_REPO" "$TMPDIR"
    (cd "$TMPDIR" && make docker-build-localnet)
    rm -rf "$TMPDIR"
    echo "✅  Built $LOCAL_TERP_IMG"
else
    echo "✅  Found existing image $LOCAL_TERP_IMG"
fi

# ----------------------------------------------------------------------
# 3.  Helper: download yq if not already on the PATH
# ----------------------------------------------------------------------
sudo snap install yq
download_yq() {
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m)

    case $ARCH in
        x86_64)
            ARCH=amd64
            ;;
        aarch64 | arm64)
            ARCH=arm64
            ;;
        *)
            echo "❌ Unsupported architecture: $ARCH" >&2
            exit 1
            ;;
    esac
    echo "⬇️  Downloading yq from $YQ_URL …"
    curl -L -s "$YQ_URL" -o "$YQ_BIN"
    chmod +x "$YQ_BIN"
    echo "$YQ_BIN"
}

if command -v yq > /dev/null 2>&1; then
    YQ=yq
else
    YQ=$(download_yq)
fi

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
    -p "${TERP_RPC_PORT}:26657" -p "$TERP_API_PORT":1317 -p "${TERP_GRPC_PORT}:9091" -p "${TERP_FAUCET_PORT}:5000" \
    --name localterp "$LOCAL_TERP_IMG"

echo "=== Starting Secret container ==="
docker run --rm -d \
    -p "${SECRET_RPC_PORT}:26657" -p "$SECRET_API_PORT":1317 -p "${SECRET_GRPC_PORT}:9091" -p "${SECRET_FAUCET_PORT}:5000" \
    --name localsecret "$LOCAL_SCRT_IMG"


# ----------------------------------------------------------------------
# 6.  Prepare the relayer configuration (config.yaml)
# ----------------------------------------------------------------------
echo "=== Preparing relayer config ==="

# Copy the template only the first time (overwrite on each run to be safe)
cp -f "$CONFIG_EXAMPLE" "$CONFIG"

# --------------------------------------------------------------
#  Chain‑specific values (read from the environment)
# --------------------------------------------------------------
# Terp
$YQ eval -i \
  ".chains.terpnetwork.value.rpc-addr        = \"http://${TERP_HOST}:${TERP_RPC_PORT}\" |
   .chains.terpnetwork.value.chain-id        = \"${TERP_CHAIN_ID}\" |
   .chains.terpnetwork.value.account-prefix  = \"${TERP_ACCOUNT_PREFIX}\" |
   .chains.terpnetwork.value.gas-prices      = \"${TERP_GAS_PRICES}\" |
   .chains.terpnetwork.value.key-directory   = \"/home/relayer/.keys\" |
   .chains.terpnetwork.value.key             = \"relayer_key\" |
   .chains.terpnetwork.value.coin-type       = 118" "$CONFIG"

# Secret
$YQ eval -i \
  ".chains.secretnetwork.value.rpc-addr        = \"http://${SECRET_HOST}:${SECRET_RPC_PORT}\" |
   .chains.secretnetwork.value.chain-id        = \"${SECRET_CHAIN_ID}\" |
   .chains.secretnetwork.value.account-prefix  = \"${SECRET_ACCOUNT_PREFIX}\" |
   .chains.secretnetwork.value.gas-prices      = \"${SECRET_GAS_PRICES}\" |
   .chains.secretnetwork.value.key-directory   = \"/home/relayer/.keys\" |
   .chains.secretnetwork.value.key             = \"relayer_key\" |
   .chains.secretnetwork.value.coin-type       = 529" "$CONFIG"

# --------------------------------------------------------------
#  Show the final file (optional, but handy for debugging)
# --------------------------------------------------------------
echo "🔧 Patched $CONFIG:"
yq eval '.' "$CONFIG"

# --------------------------------------------------------------
# 0.4  Key directory – where the relayer expects to find the files
# --------------------------------------------------------------

export KEY_DIR
mkdir -p "${KEY_DIR}"
chmod +x "${KEY_DIR}" # Add execute permission to the directory
echo "🔑  Created key files in $KEY_DIR:"

# Write the same mnemonic to both files (the relayer treats the whole
# file content as its seed phrase)
printf '%s\n' "$MNEMONIC" | sudo tee "$TERP_KEY_FILE" > /dev/null
printf '%s\n' "$MNEMONIC" | sudo tee "$SECRET_KEY_FILE" > /dev/null

echo "🔑  Created key files in $KEY_DIR:"
echo "   $TERP_KEY_FILE"
echo "   $SECRET_KEY_FILE"

echo "=== Starting rly‑docker (docker‑compose) ==="
cd "$RLY_DIR" || exit
docker compose up -d          # -d = detached
echo "✅ Container is up"
echo "=== Ready to run integration tests ==="


## upload contracts on terp 
$TERP_BIN tx wasm upload ../public-crates/artifacts/cw_glob.wasm --from validator --gas auto --gas-adjustment 1.3 --chain-id "$CHAIN_ID"  --fees 1000000"$TERP_FEE_TOKEN"
sleep 6
$TERP_BIN tx wasm upload ../public-crates/artifacts/polytone_proxy.wasm --from validator --gas auto --gas-adjustment 1.3 --chain-id "$CHAIN_ID"  --fees 1000000"$TERP_FEE_TOKEN"

 
## upload contracts on secret
$SCRT_BIN config set client node https://"$SECRET_HOST":"$SECRET_RPC_PORT"
$SCRT_BIN config set client chain-id "$SECRET_CHAIN_ID"
$SCRT_BIN config set client output json
$SCRT_BIN tx compute store secret-crates/optimized-wasm/polytone_proxy.wasm.gz --from validator --source "https://github.com/" --builder "scrtlabs/secret-contract-optimizer:1.0.11" --gas auto --gas-adjustment 1.3   --fees 1000000"$TERP_FEE_TOKEN"
sleep 6
$SCRT_BIN tx compute store secret-crates/optimized-wasm/polytone_voice.wasm.gz --from validator --source "https://github.com/" --builder "scrtlabs/secret-contract-optimizer:1.0.11" --gas auto --gas-adjustment 1.3   --fees 1000000"$TERP_FEE_TOKEN"
sleep 6

## create polytone connection
## run headstash sequence

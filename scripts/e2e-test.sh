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
CONFIG_EXAMPLE=scripts/data2/config.yaml.example
CONFIG=${RLY_DIR}/config.yaml

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
# 0.4  Key directory – where the relayer expects to find the files
# ----------------------------------------------------------------------
# The relayer’s default (`KEY_DIR`) is /home/relayer/.keys.  We create a
# temporary directory on the host, write the two files, and then mount it
# into the container at the same path.
#
# Users can point the script at an existing directory by setting KEY_DIR
# beforehand; otherwise we create a fresh temporary one.
# ----------------------------------------------------------------------
if [ -z "$KEY_DIR" ]; then
    KEY_DIR=$(mktemp -d)               # e.g. /tmp/tmp.XYZ123
    export KEY_DIR                     # make it visible to docker‑compose later
fi

# The file names must match the *chain‑id* (no extension) as described in the
# relayer docs.
: ${MNEMONIC:="jelly shadow frog dirt dragon use armed praise universe win jungle close inmate rain oil canvas beauty pioneer chef soccer icon dizzy thunder meadow"}
TERP_KEY_FILE="${KEY_DIR}/120u-1"
SECRET_KEY_FILE="${KEY_DIR}/secret-1"

# Populate both files with the same mnemonic (the relayer will read the file
# and treat its whole content as the seed phrase).
printf "%s\n" "$MNEMONIC" > "$TERP_KEY_FILE"
printf "%s\n" "$MNEMONIC" > "$SECRET_KEY_FILE"

chmod 600 "$TERP_KEY_FILE" "$SECRET_KEY_FILE"

echo "🔑  Created key files:"
echo "   $TERP_KEY_FILE"
echo "   $SECRET_KEY_FILE"

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
echo "=== Building contracts ==="
sudo apt install just
just build &&

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

echo "⏳ Waiting for nodes to become ready…"
sleep 10   # a smarter health‑check could replace this

# ----------------------------------------------------------------------
# 6.  Prepare the relayer configuration (config.yaml)
# ----------------------------------------------------------------------
echo "=== Preparing relayer config ==="
cp "$CONFIG_EXAMPLE" "$CONFIG"

# ------------------------------------------------------------------
#   Terp chain values
# ------------------------------------------------------------------
$YQ eval \
    .chains.terpnetwork.value.rpc-addr   = "http://${TERP_HOST}:${TERP_RPC_PORT}" \
    .chains.terpnetwork.value.chain-id   = "120u-1" \
    .chains.terpnetwork.value.account-prefix = "terp" \
    .chains.terpnetwork.value.gas-prices = "0.01uterp" \
    .chains.terpnetwork.value.key-directory = "/home/relayer/.keys" \
    .chains.terpnetwork.value.key = "relayer_key" \
    .chains.terpnetwork.value.coin-type = 118 \
    -i "$CONFIG"

# ------------------------------------------------------------------
#   Secret chain values
# ------------------------------------------------------------------
$YQ eval \
    .chains.secretnetwork.value.rpc-addr   = "http://${SECRET_HOST}:${SECRET_RPC_PORT}" \
    .chains.secretnetwork.value.chain-id   = "secretdev-1" \
    .chains.secretnetwork.value.account-prefix = "secret" \
    .chains.secretnetwork.value.gas-prices = "0.1uscrt" \
    .chains.secretnetwork.value.key-directory = "/home/relayer/.keys" \
    .chains.secretnetwork.value.key = "relayer_key" \
    .chains.secretnetwork.value.coin-type = 529 \
    -i "$CONFIG"

echo "🔧 Patched config.yaml:"
$YQ eval . "$CONFIG"

# ----------------------------------------------------------------------
# 7.  Patch docker‑compose so the key‑dir is mounted into the rly container
# ----------------------------------------------------------------------
# The compose file shipped with the repo normally mounts a static volume.
# We inject a temporary bind‑mount that points at $KEY_DIR.
# If you already have a `docker-compose.yml` with a volume named `keys`,
# this will simply overwrite that volume with a host bind‑mount.
# ----------------------------------------------------------------------
COMPOSE_FILE="${RLY_DIR}/docker-compose.yml"

# Ensure the file exists (it should, as it ships with the repo)
if [ ! -f "$COMPOSE_FILE" ]; then
    echo "❌ compose file not found at $COMPOSE_FILE"
    exit 1
fi

# Insert (or replace) the volume definition:
#   volumes:
#     keys:
#       type: bind
#       source: ${KEY_DIR}
#       target: /home/relayer/.keys
#
# Using yq keeps the yaml nicely formatted.
if $YQ eval '.volumes.keys' "$COMPOSE_FILE" > /dev/null 2>&1; then
    # existing volume – replace it
    $YQ eval -i \
        '.volumes.keys = {"type":"bind","source":"'"$KEY_DIR"'","target":"/home/relayer/.keys"}' \
        "$COMPOSE_FILE"
else
    # add a new top‑level `volumes` key if missing, then add `keys`
    $YQ eval -i \
        '.volumes.keys = {"type":"bind","source":"'"$KEY_DIR"'","target":"/home/relayer/.keys"}' \
        "$COMPOSE_FILE"
fi

echo "📦 Updated docker‑compose.yml to bind‑mount $KEY_DIR into the container."

# ----------------------------------------------------------------------
# 8.  Fire up the rly‑docker container (docker‑compose)
# ----------------------------------------------------------------------
echo "=== Starting rly‑docker (docker‑compose) ==="
cd "$RLY_DIR" && docker compose up -d

# Give the relayer a moment to initialise before handing over to the test.
sleep 5

# ----------------------------------------------------------------------
# 9.  Run the integration test binary
# ----------------------------------------------------------------------
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

# echo "=== DONE ==="
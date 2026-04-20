#!/bin/bash
# =============================================================================
# Deploy ZisK Prover
# =============================================================================
# Spins up the ZisK prover container with default chain spec and config,
# warms up the prover (fetches guest_data / vkey), then waits for the real
# chain spec from deploy-surge-full.sh and restarts with updated config.
#
# Usage:
#   ./deploy-zisk-prover.sh                         # interactive
#   ./deploy-zisk-prover.sh --surge-dir ../simple-surge-node --force
#
# Flow:
#   1. Start ZisK container with default chain spec (prover warms up ~4-5 min)
#   2. Fetch guest_data (batch vkey) and display it
#   3. Wait for deploy-surge-full.sh to generate the real chain spec
#   4. Copy the real chain spec + config and restart the container
#
# Prerequisites:
#   - Docker + Docker Compose
#   - NVIDIA drivers + NVIDIA Container Toolkit
#   - ZisK proving keys installed at ~/.zisk (TARGET=zisk make install)
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ─── Colours ────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info()    { echo -e "\n${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "\n${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "\n${YELLOW}[WARNING]${NC} $1"; }
log_error()   { echo -e "\n${RED}[ERROR]${NC} $1" >&2; }

# ─── Defaults ───────────────────────────────────────────────────────────────
COMPOSE_FILE="$SCRIPT_DIR/docker/docker-compose-zk.yml"
CONFIG_DIR="$SCRIPT_DIR/host/config/devnet"
DEFAULT_CHAIN_SPEC="$CONFIG_DIR/chain_spec_list_default.json"
ACTIVE_CHAIN_SPEC="$CONFIG_DIR/chain_spec_list.json"
ACTIVE_CONFIG="$CONFIG_DIR/config.json"
RAIKO_PORT=8080
CONTAINER_NAME="raiko-zk"
surge_dir=""
force=""

# ─── Help ───────────────────────────────────────────────────────────────────
usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Deploy the ZisK prover for Surge devnet.

Options:
  --surge-dir DIR    Path to simple-surge-node (for auto-copying chain spec)
  --port PORT        Raiko listen port on host (default: $RAIKO_PORT)
  -f, --force        Skip confirmations
  -h, --help         Show this help

Examples:
  # Start prover, then manually copy chain spec later
  $(basename "$0")

  # Start prover and auto-sync chain spec from simple-surge-node
  $(basename "$0") --surge-dir ../simple-surge-node --force
EOF
}

# ─── Parse args ─────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --surge-dir)    surge_dir="$2";   shift 2 ;;
        --port)         RAIKO_PORT="$2";  shift 2 ;;
        -f|--force)     force="true";     shift   ;;
        -h|--help)      usage; exit 0 ;;
        *) log_error "Unknown option: $1"; usage; exit 1 ;;
    esac
done

# ─── Prerequisites ──────────────────────────────────────────────────────────
check_prerequisites() {
    log_info "Checking prerequisites..."

    if ! command -v docker &>/dev/null; then
        log_error "Docker is not installed"
        exit 1
    fi

    if ! docker compose version &>/dev/null; then
        log_error "Docker Compose plugin is not installed"
        exit 1
    fi

    if ! nvidia-smi &>/dev/null; then
        log_error "NVIDIA drivers not found (nvidia-smi failed)"
        exit 1
    fi

    if ! docker run --rm --gpus all nvidia/cuda:12.0.0-base-ubuntu22.04 nvidia-smi &>/dev/null; then
        log_warning "NVIDIA Container Toolkit test failed — container GPU access may not work"
    fi

    if [[ ! -d "$HOME/.zisk" ]]; then
        log_error "ZisK proving keys not found at ~/.zisk"
        log_error "Install them first: cd raiko && TARGET=zisk make install"
        exit 1
    fi

    if [[ ! -f "$COMPOSE_FILE" ]]; then
        log_error "Docker compose file not found: $COMPOSE_FILE"
        exit 1
    fi

    log_success "Prerequisites OK"
}

# ─── Step 1: Start with default chain spec ──────────────────────────────────
start_prover() {
    log_info "Starting ZisK prover container..."

    # Use default chain spec if no active one exists
    if [[ ! -f "$ACTIVE_CHAIN_SPEC" ]]; then
        if [[ -f "$DEFAULT_CHAIN_SPEC" ]]; then
            cp "$DEFAULT_CHAIN_SPEC" "$ACTIVE_CHAIN_SPEC"
            log_info "Using default chain spec (will be replaced after deployment)"
        else
            log_error "No chain spec found at $DEFAULT_CHAIN_SPEC"
            exit 1
        fi
    fi

    # Stop existing container if running
    if docker ps -q --filter "name=$CONTAINER_NAME" | grep -q .; then
        log_info "Stopping existing $CONTAINER_NAME..."
        docker compose -f "$COMPOSE_FILE" down 2>/dev/null || true
    fi

    docker compose -f "$COMPOSE_FILE" up -d
    log_success "ZisK prover container started"
}

# ─── Step 2: Wait for prover to be ready and fetch guest_data ───────────────
wait_for_guest_data() {
    log_info "Waiting for ZisK prover to warm up (this takes 4-5 minutes on first run)..."

    local max_attempts=120  # 10 minutes
    local attempt=0

    while true; do
        attempt=$((attempt + 1))
        if [[ $attempt -gt $max_attempts ]]; then
            log_error "Prover did not become ready after $max_attempts attempts"
            log_error "Check logs: docker compose -f $COMPOSE_FILE logs -f"
            exit 1
        fi

        local response
        response=$(curl -s --max-time 10 "http://localhost:${RAIKO_PORT}/guest_data" 2>/dev/null || echo "")

        if [[ -n "$response" ]] && echo "$response" | jq -e '.zisk.batch_vkey' &>/dev/null; then
            local vkey
            vkey=$(echo "$response" | jq -r '.zisk.batch_vkey')
            log_success "ZisK prover is ready"
            echo ""
            echo "╔══════════════════════════════════════════════════════════════╗"
            echo "║                    ZisK Prover Ready                         ║"
            echo "╠══════════════════════════════════════════════════════════════╣"
            echo "║  Endpoint:  http://localhost:${RAIKO_PORT}                           ║"
            printf "║  Batch VKey: %-48s║\n" "$vkey"
            echo "╚══════════════════════════════════════════════════════════════╝"
            echo ""
            return 0
        fi

        if (( attempt % 10 == 0 )); then
            log_info "  Still warming up... (attempt $attempt/$max_attempts)"
        fi
        sleep 5
    done
}

# ─── Step 3: Wait for real chain spec and restart ────────────────────────────
sync_chain_spec() {
    if [[ -z "$surge_dir" ]]; then
        echo ""
        echo "Next steps:"
        echo "  1. Run deploy-surge-full.sh on your Surge devnet"
        echo "  2. Copy the generated chain spec to the prover:"
        echo ""
        echo "     cp <surge-dir>/configs/chain_spec_list.json $ACTIVE_CHAIN_SPEC"
        echo "     cp <surge-dir>/configs/config.json $ACTIVE_CONFIG"
        echo ""
        echo "  3. Restart the prover:"
        echo ""
        echo "     docker compose -f $COMPOSE_FILE restart"
        echo ""
        echo "  Or re-run this script with --surge-dir to auto-sync:"
        echo ""
        echo "     $(basename "$0") --surge-dir ../simple-surge-node --force"
        return 0
    fi

    local surge_chain_spec="$surge_dir/configs/chain_spec_list.json"
    local surge_config="$surge_dir/configs/config.json"

    # Check if the chain spec already exists (deployment already done)
    if [[ -f "$surge_chain_spec" ]]; then
        log_info "Found chain spec at $surge_chain_spec"
    else
        log_info "Waiting for deploy-surge-full.sh to generate chain spec..."
        log_info "  Watching: $surge_chain_spec"
        echo ""
        echo "Run deploy-surge-full.sh now with:"
        echo ""
        echo "  RAIKO_HOST_ZKVM=http://<this-machine-ip>:${RAIKO_PORT} ./deploy-surge-full.sh \\"
        echo "    --environment devnet --deploy-devnet true \\"
        echo "    --deployment local --stack-option 2 --mode silence --force"
        echo ""

        local wait_attempts=0
        while [[ ! -f "$surge_chain_spec" ]]; do
            wait_attempts=$((wait_attempts + 1))
            if [[ $wait_attempts -gt 360 ]]; then  # 30 minutes
                log_error "Timed out waiting for chain spec"
                exit 1
            fi
            sleep 5
        done
    fi

    # Copy chain spec and config
    log_info "Copying chain spec from $surge_dir..."
    cp "$surge_chain_spec" "$ACTIVE_CHAIN_SPEC"
    log_success "Chain spec updated: $ACTIVE_CHAIN_SPEC"

    if [[ -f "$surge_config" ]]; then
        cp "$surge_config" "$ACTIVE_CONFIG"
        log_success "Config updated: $ACTIVE_CONFIG"
    fi

    # Restart container with new config
    log_info "Restarting ZisK prover with updated chain spec..."
    docker compose -f "$COMPOSE_FILE" restart
    log_success "ZisK prover restarted with deployment-specific chain spec"

    # Verify it comes back up
    log_info "Verifying prover is healthy after restart..."
    local attempt=0
    while true; do
        attempt=$((attempt + 1))
        if [[ $attempt -gt 30 ]]; then
            log_error "Prover did not recover after restart"
            exit 1
        fi
        if curl -s --max-time 5 "http://localhost:${RAIKO_PORT}/guest_data" | jq -e '.zisk' &>/dev/null; then
            log_success "ZisK prover is healthy with updated config"
            break
        fi
        sleep 5
    done
}

# ─── Main ────────────────────────────────────────────────────────────────────
check_prerequisites
start_prover
wait_for_guest_data
sync_chain_spec

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║              ZisK Prover Deployment Complete                 ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  Container:  $CONTAINER_NAME                                      ║"
printf "║  Endpoint:   http://localhost:%-30s║\n" "$RAIKO_PORT"
echo "║  Logs:       docker compose -f docker/docker-compose-zk.yml logs -f ║"
echo "╚══════════════════════════════════════════════════════════════╝"

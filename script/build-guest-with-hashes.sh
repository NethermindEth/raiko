#!/bin/bash
#
# build-guest-with-hashes.sh — rebuild the ZisK guest ELFs locally with the
# Surge privacy key hashes baked in, without rebuilding the (much heavier)
# raiko-host image.
#
# Why this exists: the prover-side privacy mode setup used to require a full
# `docker compose -f docker/docker-compose-zk.yml up -d --build`, which does a
# full CUDA-enabled cargo build of raiko-host (multi-minute) every time the
# operator rotates a key. Only the guest ELFs need the hashes baked in
# (`option_env!` in `lib/src/utils/realtime.rs`). This script:
#
#   1. Pulls the prebuilt toolchain image (Rust + ZisK toolchain + raiko src)
#      that CI publishes alongside the runtime image.
#   2. Runs `TARGET=zisk make guest` inside it with the SURGE_PRIVACY_*_HASH
#      values from this VM's docker/.env exported into the container.
#   3. Copies the produced ELFs into ./guest-elfs/ next to docker-compose-zk.yml
#      so the runtime container picks them up via the bind-mount declared in
#      docker-compose-zk.yml.
#
# Usage (run from the raiko repo root on the prover VM):
#   ./script/build-guest-with-hashes.sh           # uses values from docker/.env
#   ./script/build-guest-with-hashes.sh --print-hashes  # debug — show what we'd bake
#
# Idempotency: re-runs are safe. The toolchain image is cached after the first
# pull; the cargo build cache lives inside the container layer too. Identical
# hashes → cargo skips rebuilding the affected crates (option_env! values
# change → guest rebuild only).

set -euo pipefail

cd "$(dirname "$0")/.."
RAIKO_ROOT="$(pwd)"
ENV_FILE="${RAIKO_ROOT}/docker/.env"
OUT_DIR="${RAIKO_ROOT}/docker/guest-elfs"

TOOLCHAIN_IMAGE="${SURGE_RAIKO_TOOLCHAIN_IMAGE:-docker.io/nethermind/surge-raiko-zk-toolchain:latest}"
RUNTIME_IMAGE="${SURGE_RAIKO_RUNTIME_IMAGE:-docker.io/nethermind/surge-raiko-zk:latest}"

red()    { printf '\033[31m%s\033[0m\n' "$*"; }
green()  { printf '\033[32m%s\033[0m\n' "$*"; }
yellow() { printf '\033[33m%s\033[0m\n' "$*"; }
log()    { printf '[build-guest] %s\n' "$*"; }

if [[ ! -f "$ENV_FILE" ]]; then
    red "$ENV_FILE not found."
    red "Copy docker/.env.sample.zk to docker/.env first, then re-run."
    exit 1
fi

# Pull the two hashes from docker/.env. Tolerates the file having other
# settings (RAIKO_CONF_DIR etc.) — we only care about these two.
SYM_HASH=$(grep -E '^SURGE_PRIVACY_SYMMETRIC_KEY_HASH=' "$ENV_FILE" | tail -n1 | cut -d= -f2- | tr -d '"' | tr -d "'")
FI_HASH=$(grep -E '^SURGE_PRIVACY_FI_PRIVKEY_HASH=' "$ENV_FILE"  | tail -n1 | cut -d= -f2- | tr -d '"' | tr -d "'")

if [[ "${1:-}" == "--print-hashes" ]]; then
    echo "SURGE_PRIVACY_SYMMETRIC_KEY_HASH=$SYM_HASH"
    echo "SURGE_PRIVACY_FI_PRIVKEY_HASH=$FI_HASH"
    exit 0
fi

mkdir -p "$OUT_DIR"

# Fast path — when both hashes are empty (privacy mode off), the locally-built
# ELFs would be identical to the ones already baked into the runtime image.
# Skip the multi-minute cargo build and just `docker cp` them out of the
# runtime image into $OUT_DIR. This keeps the compose `volumes:` mounts valid
# without forcing every operator to run the toolchain image once.
if [[ -z "$SYM_HASH" && -z "$FI_HASH" ]]; then
    yellow "Both hashes are empty in $ENV_FILE — privacy mode is OFF."
    log "Extracting default ELFs from the runtime image (no compile)."
    if ! docker image inspect "$RUNTIME_IMAGE" >/dev/null 2>&1; then
        log "Pulling runtime image (one-time) ..."
        docker pull "$RUNTIME_IMAGE"
    fi
    cid=$(docker create "$RUNTIME_IMAGE")
    trap 'docker rm -f "$cid" >/dev/null 2>&1 || true' EXIT
    for elf in zisk-batch zisk-aggregation zisk-shasta-aggregation; do
        if docker cp "$cid:/opt/raiko/bin/$elf" "$OUT_DIR/$elf" 2>/dev/null; then
            sha256sum "$OUT_DIR/$elf" | sed "s|$OUT_DIR/||"
        else
            red "ERROR: $RUNTIME_IMAGE has no /opt/raiko/bin/$elf"
            red "The image may be older than expected; pull a newer tag or run with privacy hashes set."
            exit 1
        fi
    done
    green "Default ELFs extracted to $OUT_DIR — privacy mode stays OFF until hashes are set in $ENV_FILE."
    exit 0
fi

log "Toolchain image: $TOOLCHAIN_IMAGE"
log "Hashes (one or both non-empty → privacy mode ON):"
log "  SURGE_PRIVACY_SYMMETRIC_KEY_HASH=${SYM_HASH:-<empty>}"
log "  SURGE_PRIVACY_FI_PRIVKEY_HASH=${FI_HASH:-<empty>}"
log "Output dir: $OUT_DIR"

# Pull only if missing — saves bandwidth on repeat rotations.
if ! docker image inspect "$TOOLCHAIN_IMAGE" >/dev/null 2>&1; then
    log "Pulling toolchain image (one-time, ~1.5 GiB) ..."
    docker pull "$TOOLCHAIN_IMAGE"
fi

# Run the build inside a one-off container. Mount the source tree read-only so
# repeat runs in different working trees stay isolated; cargo writes to its own
# /opt/raiko target dir inside the container layer. The container exits and is
# removed when the build completes.
#
# Why `--user "$(id -u):$(id -g)"` is NOT used: cargo writes to /opt/raiko/...
# inside the image which is owned by root in the toolchain image. Running as
# the host user breaks that. Instead, we chown the produced ELFs back to the
# host user via `cp` (file-by-file, preserves nothing) so the bind-mount on the
# raiko-zk container side doesn't run into perm issues.
log "Compiling ZisK guest ELFs (this is the only step that rebuilds on key rotation) ..."
docker run --rm \
    -e SURGE_PRIVACY_SYMMETRIC_KEY_HASH="$SYM_HASH" \
    -e SURGE_PRIVACY_FI_PRIVKEY_HASH="$FI_HASH" \
    -v "$OUT_DIR":/out \
    --entrypoint /bin/bash \
    "$TOOLCHAIN_IMAGE" -c '
        set -euo pipefail
        cd /opt/raiko
        TARGET=zisk make guest
        for elf in zisk-batch zisk-aggregation zisk-shasta-aggregation; do
            src=provers/zisk/guest/elf/$elf
            if [[ ! -f "$src" ]]; then
                echo "ERROR: expected ELF not produced: $src"; exit 1
            fi
            cp "$src" /out/
            sha256sum /out/$elf | sed "s|/out/||"
        done
        chmod a+rw /out/*
    '

green "Guest ELFs written to $OUT_DIR (host paths bind-mounted by raiko-zk)"
log "Next: restart the runtime container to pick up the new ELFs:"
log "  docker compose -f docker/docker-compose-zk.yml up -d --force-recreate raiko-zk"
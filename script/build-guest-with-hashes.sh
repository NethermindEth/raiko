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
#   ./script/build-guest-with-hashes.sh           # default: build inside the
#                                                  # surge-raiko-zk-toolchain image
#   ./script/build-guest-with-hashes.sh --local   # build on the host with
#                                                  # ~/.zisk's toolchain instead.
#                                                  # Use this if raiko panics
#                                                  # with pil2-proofman
#                                                  # out-of-bounds at proof time
#                                                  # (ZisK-version drift between
#                                                  # the toolchain image's ZisK
#                                                  # and the proving keys at
#                                                  # ~/.zisk/provingKey).
#                                                  # Also: BUILD_GUEST_LOCAL=true env.
#   ./script/build-guest-with-hashes.sh --print-hashes  # debug
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

# Image pins. Canonical source is simple-surge-node/.env.devnet's IMAGES
# section (RAIKO_ZK_TOOLCHAIN_IMAGE, RAIKO_ZK_IMAGE). deploy-prover.sh exports
# them into the shell before invoking this script. When run standalone from
# the raiko repo (outside simple-surge-node), the fallbacks to :latest apply.
TOOLCHAIN_IMAGE="${RAIKO_ZK_TOOLCHAIN_IMAGE:-docker.io/nethermind/surge-raiko-zk-toolchain:latest}"
RUNTIME_IMAGE="${RAIKO_ZK_IMAGE:-docker.io/nethermind/surge-raiko-zk:latest}"

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

BUILD_LOCAL="${BUILD_GUEST_LOCAL:-false}"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --print-hashes)
            echo "SURGE_PRIVACY_SYMMETRIC_KEY_HASH=$SYM_HASH"
            echo "SURGE_PRIVACY_FI_PRIVKEY_HASH=$FI_HASH"
            exit 0
            ;;
        --local)
            # Build the guest directly on the host (using ~/.zisk + cargo from
            # the host's `TARGET=zisk make install`) instead of inside the
            # surge-raiko-zk-toolchain image. Use this when raiko panics with
            # pil2-proofman out-of-bounds (`len N / index N`) at proof time —
            # that's a signature of ZisK-version drift between the host's
            # proving keys and the guest's compile-time ZisK. A host-side
            # build forces both sides to use the same version.
            BUILD_LOCAL=true
            shift
            ;;
        -h|--help)
            sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'
            echo "Flags: --local  --print-hashes  --help"
            exit 0
            ;;
        *) red "Unknown flag: $1"; exit 2 ;;
    esac
done

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

log "Hashes (one or both non-empty → privacy mode ON):"
log "  SURGE_PRIVACY_SYMMETRIC_KEY_HASH=${SYM_HASH:-<empty>}"
log "  SURGE_PRIVACY_FI_PRIVKEY_HASH=${FI_HASH:-<empty>}"
log "Output dir: $OUT_DIR"

if [[ "$BUILD_LOCAL" == "true" ]]; then
    # Local build mode: skip the toolchain image entirely; compile on the host
    # with whatever ZisK toolchain `TARGET=zisk make install` set up. Matches
    # the ZisK version baked into the host's proving keys (~/.zisk/provingKey)
    # so pil2-proofman doesn't see a version skew between guest verifier
    # circuits and proving keys.
    log "Mode: --local (building on host, NOT inside $TOOLCHAIN_IMAGE)"
    if [[ ! -d "$HOME/.zisk" ]]; then
        red "ERROR: \$HOME/.zisk not found — host doesn't have the ZisK SDK installed."
        red "Run \`TARGET=zisk make install\` first (deploy-prover.sh does this in Step 3)."
        exit 1
    fi
    (
        cd "$RAIKO_ROOT"
        # Surface cargo + zisk-toolchain in PATH for non-interactive shells
        # (deploy-prover.sh runs us under ssh / docker exec etc.).
        # shellcheck disable=SC1091
        [[ -f "$HOME/.cargo/env" ]] && source "$HOME/.cargo/env"
        export PATH="$HOME/.zisk/bin:$HOME/.sp1/bin:$PATH"
        export SURGE_PRIVACY_SYMMETRIC_KEY_HASH="$SYM_HASH"
        export SURGE_PRIVACY_FI_PRIVKEY_HASH="$FI_HASH"
        log "  cargo:        $(command -v cargo || echo MISSING)"
        log "  cargo-zisk:   $(command -v cargo-zisk || echo MISSING)"
        log "  TARGET=zisk make guest ..."
        TARGET=zisk make guest
    ) || { red "Local make guest failed."; exit 1; }
    for elf in zisk-batch zisk-aggregation zisk-shasta-aggregation; do
        src="$RAIKO_ROOT/provers/zisk/guest/elf/$elf"
        if [[ ! -f "$src" ]]; then
            red "ERROR: expected ELF not produced: $src"; exit 1
        fi
        cp "$src" "$OUT_DIR/"
        sha256sum "$OUT_DIR/$elf" | sed "s|$OUT_DIR/||"
    done
    chmod a+rw "$OUT_DIR"/*
    green "Local guest build complete: $OUT_DIR"
    log "Next: restart the runtime container to pick up the new ELFs:"
    log "  docker compose -f docker/docker-compose-zk.yml up -d --force-recreate raiko-zk"
    exit 0
fi

log "Mode: docker toolchain image ($TOOLCHAIN_IMAGE)"

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
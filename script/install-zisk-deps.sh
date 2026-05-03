#!/usr/bin/env bash
set -e

# install-zisk-deps.sh
# Interactive dependency installer for ZisK on Debian/Ubuntu hosts.
# Detects missing binaries, system packages, and the Rust toolchain,
# then prompts before installing each one.
#
# Usage:
#   ./script/install-zisk-deps.sh                # interactive
#   ./script/install-zisk-deps.sh --yes          # auto-confirm every prompt
#   ./script/install-zisk-deps.sh --dry-run      # detect only, install nothing
#   ./script/install-zisk-deps.sh --no-optional  # skip OPTIONAL package prompts
#
# Exit code: 0 if all required deps end up present, 1 otherwise.

ASSUME_YES=0
DRY_RUN=0
SKIP_OPTIONAL=0

while [ $# -gt 0 ]; do
    case "$1" in
        -y|--yes)         ASSUME_YES=1 ;;
        -n|--dry-run)     DRY_RUN=1 ;;
        --no-optional|--required-only) SKIP_OPTIONAL=1 ;;
        -h|--help)
            sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) echo "Unknown flag: $1"; exit 2 ;;
    esac
    shift
done

# ─── helpers ────────────────────────────────────────────────────────────────────

confirm() {
    local question="$1"
    if [ "$ASSUME_YES" = "1" ]; then
        echo "$question [auto-yes]"
        return 0
    fi
    local reply
    if [ -r /dev/tty ]; then
        read -r -p "$question [y/N] " reply </dev/tty
    else
        read -r -p "$question [y/N] " reply
    fi
    case "$reply" in
        [yY]|[yY][eE][sS]) return 0 ;;
        *) return 1 ;;
    esac
}

run_priv() {
    if [ "$DRY_RUN" = "1" ]; then
        echo "DRY-RUN: $*"
        return 0
    fi
    if [ "$(id -u)" = "0" ]; then
        "$@"
    elif command -v sudo >/dev/null 2>&1; then
        sudo "$@"
    else
        echo "Error: not root and sudo unavailable; cannot run: $*"
        return 1
    fi
}

apt_missing() {
    local pkg
    for pkg in "$@"; do
        dpkg -s "$pkg" >/dev/null 2>&1 || echo "$pkg"
    done
}

# ─── distro check ───────────────────────────────────────────────────────────────

if ! command -v dpkg >/dev/null 2>&1 || ! command -v apt-get >/dev/null 2>&1; then
    echo "This script targets Debian/Ubuntu. Detected non-apt host."
    echo "Refer to the README for manual installation steps."
    exit 1
fi

# ─── package lists ──────────────────────────────────────────────────────────────

# Hard requirements for ZisK install (mirrors verify_zisk_prerequisites in
# install.sh: required commands + system libraries).
APT_REQUIRED=(
    build-essential
    cmake
    pkg-config
    libssl-dev
    libclang-dev
    libomp-dev
    libgmp-dev
    libsodium-dev
    libopenmpi-dev
    protobuf-compiler
    curl
    git
)

# Useful for parity with Dockerfile.zk and broader Raiko builds, but not
# strictly required by the host install path.
APT_OPTIONAL=(
    nasm
    jq
    xz-utils
    nlohmann-json3-dev
    uuid-dev
    libgrpc++-dev
    libsecp256k1-dev
    libpqxx-dev
    clang
    gcc-riscv64-unknown-elf
    openmpi-bin
    openmpi-common
)

REQUIRED_MISSING=$(apt_missing "${APT_REQUIRED[@]}")
OPTIONAL_MISSING=$(apt_missing "${APT_OPTIONAL[@]}")

# Tracks whether anything was actually installed; finalizer steps (cargo env
# source, docker restart) only run when state changed, so re-runs of the
# script on a fully-provisioned host stay side-effect-free.
CHANGED=0

# ─── prompts ────────────────────────────────────────────────────────────────────

TO_INSTALL=()

# REQUIRED: single bulk prompt — all-or-nothing, since each is mandatory.
if [ -n "$REQUIRED_MISSING" ]; then
    echo
    echo "[REQUIRED] missing on this host:"
    for p in $REQUIRED_MISSING; do echo "  - $p"; done
    if confirm "Install all required packages?"; then
        for p in $REQUIRED_MISSING; do TO_INSTALL+=("$p"); done
    else
        echo "Required packages declined; cannot proceed."
        echo "Install them manually before running 'TARGET=zisk make install'."
        exit 1
    fi
fi

# OPTIONAL: per-package prompts — user may want some but not others.
if [ -n "$OPTIONAL_MISSING" ]; then
    echo
    echo "[OPTIONAL] missing on this host (parity with Dockerfile.zk):"
    for p in $OPTIONAL_MISSING; do echo "  - $p"; done
    for p in $OPTIONAL_MISSING; do
        if confirm "Install $p?"; then
            TO_INSTALL+=("$p")
        fi
    done
fi

# ─── batch apt install (one transaction, one apt-update) ────────────────────────

if [ ${#TO_INSTALL[@]} -gt 0 ]; then
    echo
    echo "Installing: ${TO_INSTALL[*]}"
    run_priv apt-get update
    run_priv apt-get install -y "${TO_INSTALL[@]}"
    [ "$DRY_RUN" = "1" ] || CHANGED=1
fi

# ─── Rust toolchain ─────────────────────────────────────────────────────────────

if ! command -v cargo >/dev/null 2>&1 || ! command -v rustc >/dev/null 2>&1; then
    echo
    echo "Rust toolchain (cargo / rustc) not found."
    if confirm "Install via rustup (https://rustup.rs)?"; then
        if [ "$DRY_RUN" = "1" ]; then
            echo "DRY-RUN: curl https://sh.rustup.rs | sh -s -- -y"
        else
            curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
            # shellcheck disable=SC1091
            [ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
            CHANGED=1
        fi
    fi
fi

# ─── CUDA / nvcc (optional, large) ──────────────────────────────────────────────

if ! command -v nvcc >/dev/null 2>&1; then
    echo
    echo "nvcc not found (only needed for ZisK GPU build path)."
    echo "  Note: nvidia-cuda-toolkit is ~2 GiB. Skip on hosts without an NVIDIA GPU."
    if confirm "Install nvidia-cuda-toolkit?"; then
        run_priv apt-get install -y nvidia-cuda-toolkit
        [ "$DRY_RUN" = "1" ] || CHANGED=1
    fi
fi

# ─── final verification ─────────────────────────────────────────────────────────

echo
echo "── Final dependency check ──"

STILL_MISSING=$(apt_missing "${APT_REQUIRED[@]}")
if [ -n "$STILL_MISSING" ]; then
    echo "Still missing required packages:"
    for p in $STILL_MISSING; do echo "  - $p"; done
    echo "Re-run this script and confirm installation, or install them manually."
    exit 1
fi

if ! command -v cargo >/dev/null 2>&1 || ! command -v rustc >/dev/null 2>&1; then
    echo "Rust toolchain still missing. Install via:"
    echo "  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y"
    exit 1
fi

echo "All required ZisK dependencies are present."

# ─── finalizers ─────────────────────────────────────────────────────────────────
# Run only when state actually changed in this invocation. Re-runs on an already-
# provisioned host stay side-effect-free.
if [ "$CHANGED" = "1" ] && [ "$DRY_RUN" != "1" ]; then
    echo
    echo "── Finalizing ──"

    # 1. Source the cargo env so this shell sees the toolchain.
    #    (rustup also writes a source line into ~/.bashrc, so new shells inherit it.)
    if [ -f "$HOME/.cargo/env" ]; then
        # shellcheck disable=SC1091
        . "$HOME/.cargo/env"
        echo "Sourced $HOME/.cargo/env"
    fi

    # 2. Restart docker — picks up nvidia-container-runtime changes from the
    #    cuda toolkit install and clears any deferred needrestart on dockerd.
    if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files docker.service >/dev/null 2>&1; then
        echo "Restarting docker.service..."
        run_priv systemctl restart docker
    else
        echo "Skipping docker restart (no systemd docker.service detected)"
    fi
fi

echo
echo "Next: TARGET=zisk make install"
echo "Note: if you open a new shell, cargo PATH is set automatically via ~/.bashrc."
echo "      Within the *current parent shell* (the one that invoked this script),"
echo "      run 'source $HOME/.cargo/env' to pick up cargo without restarting."
exit 0

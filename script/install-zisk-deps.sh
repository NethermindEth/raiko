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

# Hard requirements for ZisK install. Includes packages needed by both the
# CPU-only path and the GPU build path triggered by build_zisk_gpu in
# install.sh — the GPU build pulls in lib-float (needs riscv64-unknown-elf-gcc),
# lib-c (needs nasm), and proofman-starks-lib-c (needs nlohmann/json.hpp).
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
    nasm
    gcc-riscv64-unknown-elf
    nlohmann-json3-dev
    curl
    git
)

# Useful for parity with Dockerfile.zk and broader Raiko builds, but not
# strictly required by the host install path.
APT_OPTIONAL=(
    jq
    xz-utils
    uuid-dev
    libgrpc++-dev
    libsecp256k1-dev
    libpqxx-dev
    clang
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

# ─── CUDA toolkit (optional, large; only useful with an NVIDIA GPU) ────────────
# We deliberately avoid Ubuntu apt's `nvidia-cuda-toolkit` package: on jammy it
# ships CUDA 11.5, whose nvcc only knows up to sm_90 and fails compiling for
# Blackwell (sm_120) GPUs. Use NVIDIA's official repo for cuda-toolkit-12-8,
# which supports Blackwell, Hopper, Ada, Ampere, Turing, and earlier archs.
#
# Env override:
#   CUDA_VERSION=12-8   target cuda-toolkit package suffix (default: 12-8)

CUDA_VERSION="${CUDA_VERSION:-12-8}"

# Decide whether the host needs CUDA action. Three states:
#   - no driver         → skip everything (CPU-only mode)
#   - no nvcc           → install CUDA $CUDA_VERSION
#   - nvcc but stale    → existing nvcc can't compile for the host's GPU arch
#                         (e.g. apt's CUDA 11.5 on a Blackwell sm_120 host).
#                         Offer to replace.
need_cuda_action=""
nvcc_arch_ok=1
if command -v nvidia-smi >/dev/null 2>&1; then
    gpu_name=$(nvidia-smi --query-gpu=name --format=csv,noheader 2>/dev/null | head -n1)
    gpu_cc=$(nvidia-smi --query-gpu=compute_cap --format=csv,noheader 2>/dev/null | head -n1)
    gpu_sm="${gpu_cc//./}"   # "12.0" → "120"

    if ! command -v nvcc >/dev/null 2>&1; then
        need_cuda_action="install"
    elif [ -n "$gpu_sm" ] && ! nvcc --list-gpu-arch 2>/dev/null | grep -q "compute_${gpu_sm}\b"; then
        nvcc_arch_ok=0
        need_cuda_action="upgrade"
    fi
fi

if [ -z "$need_cuda_action" ] && ! command -v nvidia-smi >/dev/null 2>&1; then
    echo
    echo "Skipping CUDA install: nvidia-smi not found (no NVIDIA driver)."
    echo "  ZisK will run in CPU-only mode. Install the NVIDIA driver first if"
    echo "  you intend to use GPU acceleration, then re-run this script."
elif [ -n "$need_cuda_action" ]; then
    echo
    echo "NVIDIA GPU detected: ${gpu_name:-unknown} (compute capability ${gpu_cc:-unknown})"
    if [ "$need_cuda_action" = "upgrade" ]; then
        nvcc_ver=$(nvcc --version 2>/dev/null | grep -oE 'release [0-9]+\.[0-9]+' | head -n1)
        echo "Existing nvcc ($nvcc_ver, $(command -v nvcc)) does NOT support sm_${gpu_sm}."
        echo "ZisK GPU build will fail with 'Unsupported gpu architecture compute_${gpu_sm}'."
        echo "Need to upgrade to a CUDA toolkit that supports your GPU arch."
    else
        echo "nvcc not present."
    fi
    echo "Installing CUDA $CUDA_VERSION from NVIDIA's official repo (~4 GiB)."
    echo "  Why not 'apt install nvidia-cuda-toolkit'? It ships CUDA 11.5 on Ubuntu 22.04,"
    echo "  which can't compile for sm_90+ GPUs (Hopper/Blackwell)."

    if confirm "${need_cuda_action^} CUDA toolkit $CUDA_VERSION?"; then
        if [ "$DRY_RUN" = "1" ]; then
            echo "DRY-RUN: would install cuda-keyring + cuda-toolkit-$CUDA_VERSION"
        else
            # ── 1. Purge any pre-existing CUDA 11.x packages ────────────────────
            # `apt-get remove nvidia-cuda-toolkit` only drops the meta-package;
            # 30+ transitives (libcudart11.0, libcublas11, …) survive and end up
            # ahead of /usr/local/cuda/lib64 in the linker search path, breaking
            # CUDA 12 builds with "undefined symbol: cudaGetDeviceProperties_v2".
            echo "Purging any CUDA 11.x packages so the linker can't pick them up..."
            run_priv apt-get remove --purge -y \
                'nvidia-cuda-toolkit' 'nvidia-cuda-toolkit-doc' \
                'nvidia-cuda-dev' 'nvidia-cuda-gdb' \
                'nvidia-profiler' 'nvidia-visual-profiler' \
                'libcudart11*' \
                'libcublas11*' 'libcublaslt11' \
                'libcufft10' 'libcufftw10' \
                'libcusolver11' 'libcusolvermg11' \
                'libcusparse11' \
                'libcurand10' \
                'libnvjpeg11' \
                'libnvrtc11.2' 'libnvrtc-builtins11.5' \
                'libcupti11.5' \
                'libcuinj64-11.5' \
                'libnvtoolsext1' 'libnvvm4' 'libnvblas11' \
                'libnppc11' 'libnpps11' 'libnppial11' 'libnppicc11' 'libnppidei11' \
                'libnppif11' 'libnppig11' 'libnppim11' 'libnppist11' 'libnppisu11' 'libnppitc11' \
                'libcub-dev' 'libthrust-dev' \
                'libnvidia-ml-dev' 'libaccinj64-11.5' 2>/dev/null || true
            run_priv apt-get autoremove -y --purge

            # ── 2. Install CUDA 12.x from NVIDIA's repo ─────────────────────────
            local_keyring=$(mktemp /tmp/cuda-keyring.XXXXXX.deb)
            curl -fsSL -o "$local_keyring" \
                "https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2204/x86_64/cuda-keyring_1.1-1_all.deb"
            run_priv dpkg -i "$local_keyring"
            rm -f "$local_keyring"
            run_priv apt-get update
            run_priv apt-get install -y "cuda-toolkit-$CUDA_VERSION"

            # ── 3. Pin the linker to CUDA 12.x ──────────────────────────────────
            cuda_prefix="/usr/local/cuda-${CUDA_VERSION/-/.}"
            if [ -d "$cuda_prefix" ]; then
                # Runtime loader: prepend cuda lib64 so `ldconfig -p` resolves to it
                # before any /lib/x86_64-linux-gnu/libcudart.so.* leftover.
                echo "$cuda_prefix/lib64" | run_priv tee /etc/ld.so.conf.d/000-cuda.conf >/dev/null
                run_priv ldconfig

                # Link-time + runtime env for this shell and future shells.
                export PATH="$cuda_prefix/bin:$PATH"
                export LD_LIBRARY_PATH="$cuda_prefix/lib64:${LD_LIBRARY_PATH:-}"
                export LIBRARY_PATH="$cuda_prefix/lib64:${LIBRARY_PATH:-}"
                if ! grep -q "cuda-${CUDA_VERSION/-/.}" "$HOME/.bashrc" 2>/dev/null; then
                    {
                        echo ""
                        echo "# CUDA $CUDA_VERSION (added by install-zisk-deps.sh)"
                        echo "export PATH=$cuda_prefix/bin:\$PATH"
                        echo "export LD_LIBRARY_PATH=$cuda_prefix/lib64:\${LD_LIBRARY_PATH:-}"
                        echo "export LIBRARY_PATH=$cuda_prefix/lib64:\${LIBRARY_PATH:-}"
                    } >> "$HOME/.bashrc"
                    echo "Added CUDA $CUDA_VERSION PATH/LD_LIBRARY_PATH/LIBRARY_PATH to $HOME/.bashrc"
                fi
            fi

            # ── 4. Verify only CUDA 12.x libcudart is reachable ────────────────
            stale=$(ldconfig -p 2>/dev/null | awk '/libcudart\.so/ {print $NF}' | grep -v "$cuda_prefix" || true)
            if [ -n "$stale" ]; then
                echo "Error: libcudart from outside $cuda_prefix is still on the linker path:"
                echo "$stale" | sed 's/^/    /'
                echo "These will shadow CUDA 12 symbols at link time. Manual cleanup needed:"
                echo "    sudo find /usr/lib/x86_64-linux-gnu /lib -name 'libcudart.so*' -ls"
                echo "    (then 'sudo dpkg -S <path>' and 'sudo apt-get remove --purge <pkg>')"
                exit 1
            fi
            stray_files=$(find /usr/lib/x86_64-linux-gnu /lib/x86_64-linux-gnu -maxdepth 1 -name 'libcudart.so*' 2>/dev/null)
            if [ -n "$stray_files" ]; then
                echo "Error: stray libcudart files outside $cuda_prefix:"
                echo "$stray_files" | sed 's/^/    /'
                echo "Run: sudo dpkg -S <one-of-those-paths> to find the offending package and purge it."
                exit 1
            fi
            echo "Linker path clean: only $cuda_prefix/lib64/libcudart.so* will resolve."
            CHANGED=1
        fi
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

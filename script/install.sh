#!/usr/bin/env bash
set -e

# ─── Configuration ─────────────────────────────────────────────────────────────
# ZisK version to install (override via env: ZISK_VERSION=0.16.0)
ZISK_VERSION="${ZISK_VERSION:-0.16.1}"
# ZisK install path (override via env: ZISK_DIR=/ephemeral/.zisk).
# If different from ~/.zisk, a symlink ~/.zisk -> ZISK_DIR is created automatically.
ZISK_DIR="${ZISK_DIR:-$HOME/.zisk}"

# ─── CI check ──────────────────────────────────────────────────────────────────
if [ -n "$CI" ]; then
    source ./script/ci-env-check.sh
fi

# ═══════════════════════════════════════════════════════════════════════════════
# Helper functions
# ═══════════════════════════════════════════════════════════════════════════════

# ─── SP1 ───────────────────────────────────────────────────────────────────────
install_sp1() {
    curl -L https://sp1.succinct.xyz | bash
    echo "SP1 installed"
    source "$HOME/.profile" 2>/dev/null || true
    if command -v sp1up >/dev/null 2>&1; then
        sp1up --c-toolchain
    else
        "$HOME/.sp1/bin/sp1up" --c-toolchain
    fi
}

# ─── ZisK ──────────────────────────────────────────────────────────────────────

# Verify host has the build tools, system libraries, and free disk space needed
# for a full Zisk install (cli, toolchain, proving keys, optional GPU build).
# Fails fast with an actionable error.
#
# Env overrides:
#   ZISK_MIN_DISK_GB   minimum free GiB at ZISK_DIR's filesystem (default: 80)
#   ZISK_SKIP_VERIFY=1 skip all verification checks
verify_zisk_prerequisites() {
    if [ "${ZISK_SKIP_VERIFY:-0}" = "1" ]; then
        echo "Skipping zisk prerequisite verification (ZISK_SKIP_VERIFY=1)"
        return 0
    fi

    local min_gb="${ZISK_MIN_DISK_GB:-150}"
    local missing_cmds=()
    local warn_cmds=()
    local missing_pkgs=()

    echo "Verifying zisk prerequisites..."

    # Required binaries (ziskup download, sp1 install, GPU build, toolchain)
    local required=(curl git gcc g++ make cmake pkg-config cargo rustc)
    for cmd in "${required[@]}"; do
        command -v "$cmd" >/dev/null 2>&1 || missing_cmds+=("$cmd")
    done

    # Optional: nvcc enables GPU build path; absence just means CPU-only
    command -v nvcc >/dev/null 2>&1 || warn_cmds+=("nvcc")

    if [ ${#missing_cmds[@]} -gt 0 ]; then
        echo "Error: missing required commands: ${missing_cmds[*]}"
        echo "  Debian/Ubuntu: sudo apt-get install -y curl git build-essential cmake pkg-config"
        echo "  Rust toolchain: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y"
        return 1
    fi

    # Required system libraries (best-effort dpkg check on Debian/Ubuntu hosts)
    if command -v dpkg >/dev/null 2>&1; then
        local required_pkgs=(build-essential libomp-dev libopenmpi-dev libsodium-dev libgmp-dev libclang-dev libssl-dev pkg-config cmake protobuf-compiler)
        for pkg in "${required_pkgs[@]}"; do
            dpkg -s "$pkg" >/dev/null 2>&1 || missing_pkgs+=("$pkg")
        done
        if [ ${#missing_pkgs[@]} -gt 0 ]; then
            echo "Error: missing required system packages: ${missing_pkgs[*]}"
            echo "  sudo apt-get update && sudo apt-get install -y ${missing_pkgs[*]}"
            return 1
        fi
    else
        echo "Warning: dpkg not available; skipping system-package check (non-Debian host)"
    fi

    # Disk space — check the closest existing path on ZISK_DIR's filesystem.
    # ~/.zisk is often a symlink (e.g. -> /ephemeral/.zisk) from a prior install,
    # so resolve it and report both paths + mount point to avoid confusion.
    local check_path
    if [ -e "$ZISK_DIR" ]; then
        check_path="$ZISK_DIR"
    elif [ -d "$(dirname "$ZISK_DIR")" ]; then
        check_path="$(dirname "$ZISK_DIR")"
    else
        check_path="$HOME"
    fi

    local resolved_path
    resolved_path=$(readlink -f "$check_path" 2>/dev/null || echo "$check_path")
    [ -z "$resolved_path" ] && resolved_path="$check_path"

    local df_line avail_kb avail_gb device mount
    df_line=$(df -Pk "$resolved_path" 2>/dev/null | awk 'NR==2')
    avail_kb=$(echo "$df_line" | awk '{print $4}')
    device=$(echo "$df_line" | awk '{print $1}')
    mount=$(echo "$df_line" | awk '{print $6}')

    local where="$check_path"
    [ "$resolved_path" != "$check_path" ] && where="$check_path -> $resolved_path"
    [ -n "$device" ] && where="$where on $device (mounted at $mount)"

    if [ -z "$avail_kb" ]; then
        echo "Warning: could not determine free disk space at $resolved_path; skipping disk check"
    else
        avail_gb=$((avail_kb / 1024 / 1024))
        if [ "$avail_gb" -lt "$min_gb" ]; then
            echo "Error: insufficient disk space"
            echo "  Path:      $where"
            echo "  Available: ${avail_gb} GiB"
            echo "  Required:  ${min_gb} GiB (override via ZISK_MIN_DISK_GB)"
            echo "  Zisk proving keys (~40-50 GiB) plus toolchain, GPU build artifacts,"
            echo "  and SP1/risc0 deps typically exceed 60 GiB. Free space or set ZISK_DIR"
            echo "  to a larger volume (e.g. ZISK_DIR=/ephemeral/.zisk)."
            return 1
        fi
        echo "Disk space OK: ${avail_gb} GiB available at $where (>= ${min_gb} GiB required)"
    fi

    if [ ${#warn_cmds[@]} -gt 0 ]; then
        echo "Note: optional commands not found: ${warn_cmds[*]}"
        echo "  nvcc absent — Zisk will install CPU-only (GPU acceleration disabled)"
    fi

    echo "All zisk prerequisites satisfied."
    return 0
}

# Create ZISK_DIR and, when using a custom path, symlink ~/.zisk -> ZISK_DIR.
# Must be called before any ziskup/cargo-zisk commands.
setup_zisk_dir() {
    mkdir -p "$ZISK_DIR"
    if [ "$ZISK_DIR" != "$HOME/.zisk" ]; then
        if [ -e "$HOME/.zisk" ] && [ ! -L "$HOME/.zisk" ]; then
            echo "Error: $HOME/.zisk exists and is not a symlink."
            echo "Remove it manually before using a custom ZISK_DIR."
            exit 1
        fi
        ln -sfn "$ZISK_DIR" "$HOME/.zisk"
        echo "Symlinked $HOME/.zisk -> $ZISK_DIR"
    fi
}

# Run ziskup, installing the binary first if not present.
run_ziskup() {
    if [ ! -x "$ZISK_DIR/bin/ziskup" ]; then
        echo "Installing ziskup..."
        mkdir -p "$ZISK_DIR/bin"
        curl -# -L https://raw.githubusercontent.com/0xPolygonHermez/zisk/main/ziskup/ziskup \
            -o "$ZISK_DIR/bin/ziskup"
        chmod +x "$ZISK_DIR/bin/ziskup"
    fi
    ZISK_DIR="$ZISK_DIR" "$ZISK_DIR/bin/ziskup" "$@"
}

install_zisk_cli() {
    if command -v cargo-zisk >/dev/null 2>&1; then
        echo "Zisk already installed: $(cargo-zisk --version)"
        return 0
    fi
    echo "Installing Zisk v$ZISK_VERSION..."

    # Workaround for upstream ZisK v0.16.x: the post-extract "Configuring GPU
    # binaries..." step calls `mv cargo-zisk-gpu ...`, but the CPU release
    # tarball at github.com/0xPolygonHermez/zisk/releases/download/v$VER/
    # cargo_zisk_linux_amd64.tar.gz never ships cargo-zisk-gpu, and no separate
    # GPU asset is published. Tolerate that specific failure: the tarball does
    # extract cargo-zisk before the mv runs, so the binary is usable.
    run_ziskup --version "$ZISK_VERSION" --nokey || true

    # Provide cargo-zisk-gpu so any subsequent invocation of cargo-zisk's
    # GPU-config code path finds the file it expects (idempotent on re-runs).
    if [ -x "$ZISK_DIR/bin/cargo-zisk" ] && [ ! -e "$ZISK_DIR/bin/cargo-zisk-gpu" ]; then
        cp "$ZISK_DIR/bin/cargo-zisk" "$ZISK_DIR/bin/cargo-zisk-gpu"
        echo "Created cargo-zisk-gpu (copy of cargo-zisk) to satisfy ziskup post-install hook"
    fi

    source "$HOME/.bashrc" 2>/dev/null || true
    export PATH="$ZISK_DIR/bin:$PATH"

    # Sanity check — even if ziskup exited non-zero above, the binary must be
    # functional. If `cargo-zisk --version` fails, that's a real install break.
    if ! "$ZISK_DIR/bin/cargo-zisk" --version >/dev/null 2>&1; then
        echo "Error: cargo-zisk installed but not functional. Install manually:"
        echo "  curl https://raw.githubusercontent.com/0xPolygonHermez/zisk/main/ziskup/install.sh | bash"
        exit 1
    fi
    echo "cargo-zisk verified: $("$ZISK_DIR/bin/cargo-zisk" --version)"
}

install_zisk_toolchain() {
    echo "Installing Zisk Rust toolchain..."
    if cargo-zisk sdk install-toolchain; then
        return 0
    fi
    echo "Automatic toolchain installation failed"
	exit 1
}

ensure_zisk_proving_keys() {
    if [ ! -d "$ZISK_DIR/provingKey" ]; then
        echo "Installing Zisk proving key..."
        run_ziskup --version "$ZISK_VERSION" --provingkey
    else
        echo "Zisk proving key already present"
    fi

    if [ ! -d "$ZISK_DIR/provingKeySnark" ]; then
        echo "Installing Zisk SNARK proving key..."
        run_ziskup setup_snark
    else
        echo "Zisk SNARK proving key already present"
    fi
}

run_zisk_check_setup() {
    echo "Regenerating Zisk constant tree files..."
    "$ZISK_DIR/bin/cargo-zisk" check-setup -a --snark 
}

copy_zisk_gpu_binaries() {
    local src="$1"

    mkdir -p "$ZISK_DIR/bin"
    cp "$src/cargo-zisk" "$src/ziskemu" "$src/riscv2zisk" \
       "$src/zisk-coordinator" "$src/zisk-worker" "$src/libziskclib.a" \
       "$ZISK_DIR/bin/"

    mkdir -p "$ZISK_DIR/zisk/emulator-asm"
    cp -r ./emulator-asm/src "$ZISK_DIR/zisk/emulator-asm/"
    cp ./emulator-asm/Makefile "$ZISK_DIR/zisk/emulator-asm/"
    cp -r ./lib-c "$ZISK_DIR/zisk/"
}

build_zisk_gpu() {
    local marker="$ZISK_DIR/.gpu-enabled"
    local built_version
    built_version=$(cat "$marker" 2>/dev/null || echo "")

    if [ "$built_version" = "$ZISK_VERSION" ]; then
        echo "Zisk GPU support already built for v$ZISK_VERSION"
        return 0
    fi

    if [ -n "$built_version" ]; then
        echo "Zisk GPU version mismatch (built: $built_version, wanted: $ZISK_VERSION), rebuilding..."
    fi

    echo "Building Zisk with GPU support (tag v$ZISK_VERSION)..."
    local tmp
    tmp=$(mktemp -d)
    (
        git clone --depth=1 --branch "v$ZISK_VERSION" \
            https://github.com/0xPolygonHermez/zisk.git "$tmp/zisk"
        cd "$tmp/zisk"
        # CARGO_BUILD_JOBS=1 serializes cargo's build-script execution, which
        # avoids the upstream lib-float / lib-c Makefile race that produces
        # "can't create build/<x>.o: No such file or directory" mid-compile.
        # MAKEFLAGS=-j1 alone isn't enough — upstream uses $(MAKE) recursively
        # in places that drop the env flag.
        if CARGO_BUILD_JOBS=1 cargo build --release --features gpu; then
            copy_zisk_gpu_binaries "target/release"
            echo "$ZISK_VERSION" > "$marker"
            echo "Zisk successfully built with GPU support!"
            run_zisk_check_setup
        else
            echo "GPU build failed, continuing with existing binaries"
        fi
    )
    rm -rf "$tmp"
}

# ═══════════════════════════════════════════════════════════════════════════════
# Installation sections
# ═══════════════════════════════════════════════════════════════════════════════

# ─── RISC-V64 bare-metal toolchain (needed by ZisK guest) ──────────────────────
# if [ -z "$1" ] || [ "$1" == "zisk" ]; then
#     if [ -f /opt/riscv/bin/riscv-none-elf-gcc ]; then
#         echo "Checking existing RISC-V toolchain for 64-bit support..."
#         if /opt/riscv/bin/riscv-none-elf-gcc -march=rv64ima -mabi=lp64 -S -o /dev/null -xc /dev/null 2>/dev/null; then
#             echo "Existing RISC-V toolchain supports 64-bit"
#         else
#             echo "Warning: Existing RISC-V toolchain doesn't support 64-bit."
#         fi
#     else
#         echo "Installing bare-metal RISC-V64 cross-compiler toolchain..."
#         if command -v apt-get >/dev/null 2>&1; then
#             sudo apt-get update
#             if ! sudo apt-get install -y gcc-riscv64-unknown-elf 2>/dev/null; then
#                 echo "gcc-riscv64-unknown-elf not available, downloading prebuilt toolchain..."
#                 local riscv_archive="/tmp/riscv64-unknown-elf-gcc.tar.gz"
#                 wget -O "$riscv_archive" \
#                     "https://github.com/riscv-collab/riscv-gnu-toolchain/releases/download/2024.02.02/riscv64-elf-ubuntu-22.04-gcc-nightly-2024.02.02-nightly.tar.gz" \
#                     && sudo mkdir -p /opt/riscv64 \
#                     && sudo tar -xzf "$riscv_archive" -C /opt/riscv64 --strip-components=1 \
#                     || echo "Warning: Could not install RISC-V64 toolchain. Please install manually."
#             fi
#         else
#             echo "Warning: Could not install RISC-V64 toolchain automatically (no apt-get)."
#         fi
#     fi
# fi

# ─── RISC0 ─────────────────────────────────────────────────────────────────────
if [ -z "$1" ] || [ "$1" == "risc0" ]; then
    if [ -z "$TERM" ] || [ "$TERM" = "dumb" ]; then
        export TERM=xterm
    fi
    curl -L https://risczero.com/install | bash

    env_rzup=rzup
    if [ -z "${CI}" ] || ! command -v rzup >/dev/null 2>&1; then
        source "$HOME/.bashrc" 2>/dev/null || true
        if ! command -v rzup >/dev/null 2>&1; then
            export PATH="$HOME/.risc0/bin:$PATH"
            env_rzup="$HOME/.risc0/bin/rzup"
        fi
    else
        echo "/home/runner/.risc0/bin" >> "$GITHUB_PATH"
        echo "/home/runner/.config/.risc0/bin" >> "$GITHUB_PATH"
        env_rzup=/home/runner/.risc0/bin/rzup
    fi

    command -v "$env_rzup" >/dev/null 2>&1 || { echo "Error: rzup not found; please reinstall."; exit 1; }
    $env_rzup install
    $env_rzup install risc0-groth16
fi

# ─── SP1 ───────────────────────────────────────────────────────────────────────
if [ -z "$1" ] || [ "$1" == "sp1" ]; then
    install_sp1
fi

# ─── ZisK ──────────────────────────────────────────────────────────────────────
if [ -z "$1" ] || [ "$1" == "zisk" ]; then
    verify_zisk_prerequisites
    setup_zisk_dir
    install_sp1
    install_zisk_cli
    install_zisk_toolchain

    # Install proving keys unless explicitly disabled (INSTALL_KEYS=false)
    if [ "${INSTALL_KEYS:-true}" != "false" ]; then
        ensure_zisk_proving_keys
    else
        echo "Skipping Zisk proving key installation (INSTALL_KEYS=false)"
    fi

    if command -v nvcc >/dev/null 2>&1; then
        echo "CUDA toolkit detected, building Zisk with GPU support..."
        build_zisk_gpu
    fi
fi

# ─── TDX ───────────────────────────────────────────────────────────────────────
if [ -z "$1" ] || [ "$1" == "tdx" ]; then
    echo "TDX prover doesn't require additional toolchain installation"
fi

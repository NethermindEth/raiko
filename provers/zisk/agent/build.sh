#!/bin/bash
set -e

# ZISK Agent Consolidated Build Script
# This script handles building all ZISK components in the consolidated structure

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RAIKO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

# Default CUDA arch for L4 GPUs; allow override via environment.
if [ -z "${CUDA_ARCH}" ]; then
    export CUDA_ARCH=sm_89
fi

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log() {
    echo -e "${GREEN}[ZISK Agent]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[ZISK Agent]${NC} $1"
}

error() {
    echo -e "${RED}[ZISK Agent]${NC} $1"
}

# Locate the ZisK custom rustc.  When cargo-zisk is installed the toolchain
# lives under ~/.zisk/toolchains/<hash>/bin/rustc.  In Docker we may have
# downloaded it directly to $ZISK_TOOLCHAIN_DIR.  Sets ZISK_RUSTC.
find_zisk_rustc() {
    # 1. Explicit override (e.g. set by Dockerfile)
    if [ -n "$ZISK_RUSTC" ] && [ -x "$ZISK_RUSTC" ]; then
        log "Using ZISK_RUSTC from environment: $ZISK_RUSTC"
        return 0
    fi

    # 2. Toolchain downloaded to a well-known directory
    local zisk_dir="${ZISK_DIR:-$HOME/.zisk}"
    if [ -n "$ZISK_TOOLCHAIN_DIR" ] && [ -x "$ZISK_TOOLCHAIN_DIR/bin/rustc" ]; then
        ZISK_RUSTC="$ZISK_TOOLCHAIN_DIR/bin/rustc"
        log "Using ZISK rustc from ZISK_TOOLCHAIN_DIR: $ZISK_RUSTC"
        return 0
    fi

    # 3. Installed via cargo-zisk sdk install-toolchain (hash-named dirs)
    for tc_dir in "$zisk_dir"/toolchains/*/bin/rustc; do
        if [ -x "$tc_dir" ]; then
            ZISK_RUSTC="$tc_dir"
            log "Using ZISK rustc from toolchains: $ZISK_RUSTC"
            return 0
        fi
    done

    error "ZisK Rust toolchain not found."
    echo "  Install via: cargo-zisk sdk install-toolchain"
    echo "  Or set ZISK_RUSTC=/path/to/zisk/rustc"
    exit 1
}

# Check if cargo-zisk is installed (optional — only needed outside Docker)
check_zisk_toolchain() {
    find_zisk_rustc

    # Verify the rustc knows the zisk target
    if ! "$ZISK_RUSTC" --print target-list | grep -q "riscv64ima-zisk-zkvm-elf"; then
        error "ZISK rustc at $ZISK_RUSTC does not support riscv64ima-zisk-zkvm-elf target"
        exit 1
    fi
    log "ZISK rustc supports riscv64ima-zisk-zkvm-elf target"
}

# Build ZISK guest programs (batch and aggregation)
build_guest_programs() {
    log "Building ZISK guest programs..."
    
    # Navigate to guest directory (now inside agent)
    cd "$SCRIPT_DIR/guest"
    
    # Check if guest directory exists
    if [ ! -f "Cargo.toml" ]; then
        error "ZISK guest Cargo.toml not found at $(pwd)"
        exit 1
    fi
    
    # Clear RISC-V related environment variables
    unset TARGET_CC

    # Detect riscv sysroot for C includes.
    # Preference order:
    #   1. SP1 bundled gcc (~/.sp1/riscv/bin/riscv64-unknown-elf-gcc) — has newlib sysroot
    #   2. SP1 newlib headers directly (~/.sp1/riscv/riscv64-unknown-elf/include)
    #   3. System riscv64-unknown-elf-gcc sysroot
    SYSROOT=""
    SP1_GCC="$HOME/.sp1/riscv/bin/riscv64-unknown-elf-gcc"
    SP1_INCLUDE="$HOME/.sp1/riscv/riscv64-unknown-elf/include"

    if [ -x "$SP1_GCC" ] && "$SP1_GCC" --version &>/dev/null; then
        SYSROOT="$($SP1_GCC -print-sysroot)/include"
        log "Using SP1 bundled gcc sysroot: $SYSROOT"
    elif [ -d "$SP1_INCLUDE" ] && [ -n "$(ls -A "$SP1_INCLUDE" 2>/dev/null)" ]; then
        SYSROOT="$SP1_INCLUDE"
        log "Using SP1 newlib headers: $SYSROOT"
    elif command -v riscv64-unknown-elf-gcc &> /dev/null; then
        CANDIDATE="$(riscv64-unknown-elf-gcc -print-sysroot)/include"
        if [ -d "$CANDIDATE" ]; then
            SYSROOT="$CANDIDATE"
            log "Using system riscv64 sysroot: $SYSROOT"
        else
            SYSROOT="$SP1_INCLUDE"
            log "System gcc has no sysroot, falling back to SP1 headers: $SYSROOT"
        fi
    fi

    if [ -z "$SYSROOT" ] || [ ! -d "$SYSROOT" ]; then
        warn "No riscv sysroot found. C dependencies may fail to compile."
        warn "Install SP1 toolchain (sp1up) or riscv64-unknown-elf-gcc."
    fi

    # Build guest programs using the ZisK custom rustc + cargo
    log "Building with ZISK rustc for riscv64ima-zisk-zkvm-elf target..."
    log "RUSTC=$ZISK_RUSTC"

    # Pick the gcc binary: prefer SP1 bundled (if usable), fall back to system.
    if [ -x "$SP1_GCC" ] && "$SP1_GCC" --version &>/dev/null; then
        RISCV_GCC="$SP1_GCC"
    else
        RISCV_GCC="riscv64-unknown-elf-gcc"
    fi

    RUSTC="$ZISK_RUSTC" \
        CC_riscv64ima_zisk_zkvm_elf="$RISCV_GCC -march=rv64ima -mabi=lp64 -mstrict-align -falign-functions=2" \
        CFLAGS_riscv64ima_zisk_zkvm_elf="${SYSROOT:+-isystem $SYSROOT}" \
        RUSTFLAGS='--cfg getrandom_backend="custom"' \
        cargo build --target riscv64ima-zisk-zkvm-elf --release
    
    # Create ELF directory in guest if it doesn't exist
    mkdir -p "$SCRIPT_DIR/guest/elf"
    
    # Copy ELF files to guest/elf directory
    # cargo-zisk might use a different output structure, check both possibilities
    ELF_SOURCE_DIR="target/riscv64ima-zisk-zkvm-elf/release"
    FALLBACK_ELF_DIR="target/release"
    
    # Function to find and copy ELF file
    copy_elf() {
        local elf_name="$1"
        local found=false
        
        for search_dir in "$ELF_SOURCE_DIR" "$FALLBACK_ELF_DIR"; do
            if [ -f "$search_dir/$elf_name" ]; then
                cp "$search_dir/$elf_name" "$SCRIPT_DIR/guest/elf/"
                log "Copied $elf_name ELF from $search_dir/ to guest/elf/"
                found=true
                break
            fi
        done
        
        if [ "$found" = false ]; then
            error "$elf_name ELF not found in $ELF_SOURCE_DIR or $FALLBACK_ELF_DIR"
            log "Available files in target directories:"
            find target -name "$elf_name" 2>/dev/null || echo "  No $elf_name files found"
            return 1
        fi
    }
    
    copy_elf "zisk-batch"
    copy_elf "zisk-aggregation"
    copy_elf "zisk-shasta-aggregation"
    
    log "Guest programs built successfully"
}

# Build the agent service
build_agent() {
    warn "zisk-agent-service is deprecated and replaced by raiko-agent."
    warn "Use the raiko-agent repository for the HTTP service."
    exit 1
}

# Build the driver
build_driver() {
    log "Building ZISK agent driver..."
    
    cd "$SCRIPT_DIR"
    
    # Set CC to clang for ZISK compilation and clear RISC-V related environment variables
    export CC=clang
    unset TARGET_CC
    
    # Build the driver
    cargo build --release -p zisk-agent-driver
    
    log "Driver built successfully"
}

# Clean build artifacts
clean() {
    log "Cleaning build artifacts..."
    
    # Clean guest build
    cd "$SCRIPT_DIR/guest"
    cargo clean
    
    # Clean workspace builds
    cd "$SCRIPT_DIR"
    cargo clean
    
    # Remove ELF files
    rm -rf "$SCRIPT_DIR/guest/elf"
    
    log "Clean completed"
}

# Check CUDA availability for GPU support
check_gpu_support() {
    if command -v nvcc &> /dev/null; then
        log "CUDA toolkit found: $(nvcc --version | head -1)"
        export ZISK_GPU_SUPPORT=1
    else
        warn "CUDA toolkit not found - GPU acceleration disabled"
        export ZISK_GPU_SUPPORT=0
    fi
}

# Display help
show_help() {
    echo "ZISK Agent Build Script"
    echo ""
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  guest     Build only guest programs (ELF files)"
    echo "  agent     Deprecated (use raiko-agent)"
    echo "  driver    Build only driver component"
    echo "  workspace Build workspace components (driver only)"
    echo "  all       Build everything (guest + driver) (default)"
    echo "  clean     Clean build artifacts"
    echo "  check     Check toolchain and dependencies"
    echo "  help      Show this help message"
    echo ""
    echo "Environment Variables:"
    echo "  CARGO_TARGET_DIR    Override cargo target directory"
    echo "  RUST_LOG           Set logging level (default: info)"
    echo ""
}

# Check dependencies and environment
check_dependencies() {
    log "Checking dependencies..."
    
    # Check Rust toolchain
    if ! command -v cargo &> /dev/null; then
        error "Rust/Cargo not found"
        exit 1
    fi
    
    
    check_zisk_toolchain
    check_gpu_support
    
    log "All dependencies satisfied"
}

# Main script logic
main() {
    case "${1:-all}" in
        guest)
            check_dependencies
            build_guest_programs
            ;;
        agent)
            build_agent
            ;;
        driver)
            build_driver
            ;;
        workspace)
            warn "Skipping deprecated zisk-agent-service build."
            build_driver
            ;;
        all)
            check_dependencies
            build_guest_programs
            build_driver
            ;;
        clean)
            clean
            ;;
        check)
            check_dependencies
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            error "Unknown command: $1"
            show_help
            exit 1
            ;;
    esac
}

# Run main function
main "$@"

#!/usr/bin/env bash

# Script to automatically update RISC0 image IDs, SP1 VK hashes, SGX MRENCLAVE, and SGXGETH MRENCLAVE in .env file
# by reading from build output or extracting MRENCLAVE directly
#
# Usage:
#   ./script/update_imageid.sh risc0 [output_file]    # Update RISC0 image IDs from file or temp
#   ./script/update_imageid.sh sp1 [output_file]      # Update SP1 VK hashes from file or temp
#   ./script/update_imageid.sh sgx_direct <image>     # Extract SGX MRENCLAVE by calling gramine tools directly on container
#   ./script/update_imageid.sh sgxgeth_direct <image> # Extract SGXGETH MRENCLAVE from container (reads from pre-generated file)
#   ./script/update_imageid.sh update_sgx_mrenclave <value>     # Update SGX MRENCLAVE with provided value
#   ./script/update_imageid.sh update_sgxgeth_mrenclave <value> # Update SGXGETH MRENCLAVE with provided value
#
# This script is automatically called by build.sh after building RISC0 or SP1 provers,
# or can be used to extract MRENCLAVE values directly from Docker containers.
#
# If no output_file is provided for RISC0/SP1 modes, it will look for temp files:
#   /tmp/risc0_build_output.txt for RISC0
#   /tmp/sp1_build_output.txt for SP1
# For MRENCLAVE extraction, it calls tools directly on Docker containers.

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to extract RISC0 image ID from build output
extract_risc0_image_id() {
    local build_output="$1"
    local binary_name="$2"
    
    # Look for the pattern "risc0 elf image id: <hex_string>" before the binary path
    local image_id=""
    
    # Find the image ID that appears before the specific binary path
    if [ "$binary_name" = "risc0-aggregation" ]; then
        # Get the image ID that appears before risc0-aggregation path
        image_id=$(echo "$build_output" | grep -B1 "risc0-aggregation" | grep "risc0 elf image id:" | sed 's/.*risc0 elf image id: //' | head -1)
    elif [ "$binary_name" = "risc0-batch" ]; then
        # Get the image ID that appears before risc0-batch path  
        image_id=$(echo "$build_output" | grep -B1 "risc0-batch" | grep "risc0 elf image id:" | sed 's/.*risc0 elf image id: //' | head -1)
    fi
    
    # Fallback: if context search fails, try sequential search based on order
    if [ -z "$image_id" ]; then
        if [ "$binary_name" = "risc0-aggregation" ]; then
            # Get first image ID for aggregation
            image_id=$(echo "$build_output" | grep "risc0 elf image id:" | sed 's/.*risc0 elf image id: //' | head -1)
        elif [ "$binary_name" = "risc0-batch" ]; then
            # Get second image ID for batch
            image_id=$(echo "$build_output" | grep "risc0 elf image id:" | sed 's/.*risc0 elf image id: //' | tail -1)
        fi
    fi
    
    if [ -z "$image_id" ]; then
        print_error "Failed to extract RISC0 image ID for $binary_name"
        return 1
    fi
    
    echo "$image_id"
}

# Function to extract SP1 VK hash from build output
extract_sp1_vk_hash() {
    local build_output="$1"
    local binary_name="$2"
    
    # Extract VK hash based on binary order (aggregation first, batch second)
    local vk_hash=""
    if [ "$binary_name" = "sp1-aggregation" ]; then
        vk_hash=$(echo "$build_output" | grep "sp1 elf vk hash_bytes is:" | sed 's/.*sp1 elf vk hash_bytes is: //' | head -1)
    elif [ "$binary_name" = "sp1-batch" ]; then
        vk_hash=$(echo "$build_output" | grep "sp1 elf vk hash_bytes is:" | sed 's/.*sp1 elf vk hash_bytes is: //' | tail -1)
    fi
    
    if [ -z "$vk_hash" ]; then
        print_error "Failed to extract SP1 VK hash for $binary_name"
        return 1
    fi
    
    echo "$vk_hash"
}

# Function to check if Gramine tools are available
check_gramine_tools() {
    if ! command -v gramine-manifest &> /dev/null; then
        return 1
    fi
    if ! command -v gramine-sgx-sign &> /dev/null; then
        return 1
    fi
    if ! command -v gramine-sgx-sigstruct-view &> /dev/null; then
        return 1
    fi
    return 0
}

# Function to check if EGO tools are available
check_ego_tools() {
    if ! command -v ego &> /dev/null; then
        return 1
    fi
    return 0
}



# Function to update .env file with MRENCLAVE value
update_env_mrenclave() {
    local MRENCLAVE=$1
    local ENV_FILE=".env"
    
    # Check if file exists, create if not
    if [ ! -f "$ENV_FILE" ]; then
        print_status "Creating .env file..."
        touch "$ENV_FILE"
    fi
    
    # Update or add SGX_MRENCLAVE in the file
    if grep -q "^SGX_MRENCLAVE=" "$ENV_FILE"; then
        # Update existing entry
        sed -i "s/^SGX_MRENCLAVE=.*/SGX_MRENCLAVE=$MRENCLAVE/" "$ENV_FILE"
        print_status "Updated SGX_MRENCLAVE in $ENV_FILE: $MRENCLAVE"
    else
        # Add new entry
        echo "SGX_MRENCLAVE=$MRENCLAVE" >> "$ENV_FILE"
        print_status "Added SGX_MRENCLAVE to $ENV_FILE: $MRENCLAVE"
    fi
}


# Function to extract SGX MRENCLAVE by calling gramine tools directly on container
extract_sgx_mrenclave_direct() {
    local image_name="$1"
    print_status "Extracting SGX MRENCLAVE by running gramine tools directly on container..."

    # Check if Docker is available
    if ! command -v docker &> /dev/null; then
        print_error "Docker command not found"
        return 1
    fi

    # Run gramine-sgx-sigstruct-view directly on the container
    local mrenclave_output
    mrenclave_output=$(docker run --rm --entrypoint gramine-sgx-sigstruct-view "$image_name" /opt/raiko/bin/sgx-guest.sig 2>/dev/null | grep "mr_enclave:" | grep -o '[a-fA-F0-9]\{64\}' | head -1)

    if [ -n "$mrenclave_output" ] && [ ${#mrenclave_output} -eq 64 ]; then
        print_status "Extracted SGX_MRENCLAVE: $mrenclave_output"
        update_env_mrenclave "$mrenclave_output"
    else
        print_error "Failed to extract SGX MRENCLAVE from container"
        return 1
    fi
}

# Function to extract SGXGETH MRENCLAVE from container
extract_sgxgeth_mrenclave_direct() {
    local image_name="$1"
    print_status "Extracting SGXGETH MRENCLAVE from container..."

    # Check if Docker is available
    if ! command -v docker &> /dev/null; then
        print_error "Docker command not found"
        return 1
    fi

    # Extract SGXGETH MRENCLAVE from the container
    local mrenclave_output
    # First try to run ego command (in case it's available in the container)
    mrenclave_output=$(docker run --rm --entrypoint ego "$image_name" uniqueid /opt/raiko/bin/gaiko 2>/dev/null | grep -o '[a-fA-F0-9]\{64\}' | head -1)

    # If ego command is not available (typical in runtime container), read from the saved uniqueid log file
    # This file was generated during the build stage and copied to the runtime container
    if [ -z "$mrenclave_output" ]; then
        mrenclave_output=$(docker run --rm --entrypoint cat "$image_name" /tmp/gaiko_uniqueid.log 2>/dev/null | grep -o '[a-fA-F0-9]\{64\}' | head -1)
    fi

    if [ -n "$mrenclave_output" ] && [ ${#mrenclave_output} -eq 64 ]; then
        print_status "Extracted SGXGETH_MRENCLAVE: $mrenclave_output"
        update_env_sgxgeth_mrenclave "$mrenclave_output"
    else
        print_error "Failed to extract SGXGETH MRENCLAVE from container"
        return 1
    fi
}


# Function to update .env file with SGXGETH_MRENCLAVE value
update_env_sgxgeth_mrenclave() {
    local MRENCLAVE=$1
    local ENV_FILE=".env"
    
    # Check if file exists, create if not
    if [ ! -f "$ENV_FILE" ]; then
        print_status "Creating .env file..."
        touch "$ENV_FILE"
    fi
    
    # Update or add SGXGETH_MRENCLAVE in the file
    if grep -q "^SGXGETH_MRENCLAVE=" "$ENV_FILE"; then
        # Update existing entry
        sed -i "s/^SGXGETH_MRENCLAVE=.*/SGXGETH_MRENCLAVE=$MRENCLAVE/" "$ENV_FILE"
        print_status "Updated SGXGETH_MRENCLAVE in $ENV_FILE: $MRENCLAVE"
    else
        # Add new entry
        echo "SGXGETH_MRENCLAVE=$MRENCLAVE" >> "$ENV_FILE"
        print_status "Added SGXGETH_MRENCLAVE to $ENV_FILE: $MRENCLAVE"
    fi
}

# Function to update .env file
update_env_file() {
    local env_file=".env"
    
    # Check if file exists
    if [ ! -f "$env_file" ]; then
        print_error ".env file not found in current directory"
        return 1
    fi
    
    # Update RISC0 image IDs if provided
    if [ -n "$RISC0_AGGREGATION_ID" ]; then
        if grep -q "^RISC0_AGGREGATION_ID=" "$env_file"; then
            # Update existing entry
            sed -i "s/^RISC0_AGGREGATION_ID=.*/RISC0_AGGREGATION_ID=$RISC0_AGGREGATION_ID/" "$env_file"
        else
            # Add new entry
            echo "RISC0_AGGREGATION_ID=$RISC0_AGGREGATION_ID" >> "$env_file"
        fi
        print_status "Updated RISC0_AGGREGATION_ID in $env_file: $RISC0_AGGREGATION_ID"
    fi
    
    if [ -n "$RISC0_BATCH_ID" ]; then
        if grep -q "^RISC0_BATCH_ID=" "$env_file"; then
            # Update existing entry
            sed -i "s/^RISC0_BATCH_ID=.*/RISC0_BATCH_ID=$RISC0_BATCH_ID/" "$env_file"
        else
            # Add new entry
            echo "RISC0_BATCH_ID=$RISC0_BATCH_ID" >> "$env_file"
        fi
        print_status "Updated RISC0_BATCH_ID in $env_file: $RISC0_BATCH_ID"
    fi
    
    # Update SP1 VK hashes if provided
    if [ -n "$SP1_AGGREGATION_VK_HASH" ]; then
        if grep -q "^SP1_AGGREGATION_VK_HASH=" "$env_file"; then
            # Update existing entry
            sed -i "s/^SP1_AGGREGATION_VK_HASH=.*/SP1_AGGREGATION_VK_HASH=$SP1_AGGREGATION_VK_HASH/" "$env_file"
        else
            # Add new entry
            echo "SP1_AGGREGATION_VK_HASH=$SP1_AGGREGATION_VK_HASH" >> "$env_file"
        fi
        print_status "Updated SP1_AGGREGATION_VK_HASH in $env_file: $SP1_AGGREGATION_VK_HASH"
    fi
    
    if [ -n "$SP1_BATCH_VK_HASH" ]; then
        if grep -q "^SP1_BATCH_VK_HASH=" "$env_file"; then
            # Update existing entry
            sed -i "s/^SP1_BATCH_VK_HASH=.*/SP1_BATCH_VK_HASH=$SP1_BATCH_VK_HASH/" "$env_file"
        else
            # Add new entry
            echo "SP1_BATCH_VK_HASH=$SP1_BATCH_VK_HASH" >> "$env_file"
        fi
        print_status "Updated SP1_BATCH_VK_HASH in $env_file: $SP1_BATCH_VK_HASH"
    fi
    
    print_status "Successfully updated $env_file"
}

# Function to extract RISC0 image IDs from build output file or stdin
extract_risc0_ids_from_output() {
    local build_output=""
    
    # Read from file if provided, otherwise from stdin
    if [ -n "$1" ] && [ -f "$1" ]; then
        build_output=$(cat "$1")
        print_status "Reading RISC0 build output from file: $1"
    else
        # Try to read the latest build output from a temp file if it exists
        local temp_file="/tmp/risc0_build_output.txt"
        if [ -f "$temp_file" ]; then
            build_output=$(cat "$temp_file")
            print_status "Reading RISC0 build output from temp file: $temp_file"
        else
            print_error "No RISC0 build output available. Please run the RISC0 builder first."
            return 1
        fi
    fi
    
    # Extract image IDs
    local aggregation_id=$(extract_risc0_image_id "$build_output" "risc0-aggregation")
    local batch_id=$(extract_risc0_image_id "$build_output" "risc0-batch")
    
    if [ -n "$aggregation_id" ] && [ -n "$batch_id" ]; then
        RISC0_AGGREGATION_ID="$aggregation_id"
        RISC0_BATCH_ID="$batch_id"
        print_status "Extracted RISC0 image IDs:"
        print_status "  Aggregation: $aggregation_id"
        print_status "  Batch: $batch_id"
    else
        print_error "Failed to extract RISC0 image IDs from build output"
        return 1
    fi
}

# Function to extract SP1 VK hashes from build output file or stdin
extract_sp1_hashes_from_output() {
    local build_output=""
    
    # Read from file if provided, otherwise from stdin
    if [ -n "$1" ] && [ -f "$1" ]; then
        build_output=$(cat "$1")
        print_status "Reading SP1 build output from file: $1"
    else
        # Try to read the latest build output from a temp file if it exists
        local temp_file="/tmp/sp1_build_output.txt"
        if [ -f "$temp_file" ]; then
            build_output=$(cat "$temp_file")
            print_status "Reading SP1 build output from temp file: $temp_file"
        else
            print_error "No SP1 build output available. Please run the SP1 builder first."
            return 1
        fi
    fi
    
    # Extract VK hashes
    local aggregation_vk_hash=$(extract_sp1_vk_hash "$build_output" "sp1-aggregation")
    local batch_vk_hash=$(extract_sp1_vk_hash "$build_output" "sp1-batch")
    
    if [ -n "$aggregation_vk_hash" ] && [ -n "$batch_vk_hash" ]; then
        SP1_AGGREGATION_VK_HASH="$aggregation_vk_hash"
        SP1_BATCH_VK_HASH="$batch_vk_hash"
        print_status "Extracted SP1 VK hashes:"
        print_status "  Aggregation: $aggregation_vk_hash"
        print_status "  Batch: $batch_vk_hash"
    else
        print_error "Failed to extract SP1 VK hashes from build output"
        return 1
    fi
}

# Main function
main() {
    print_status "Starting automatic environment update..."
    
    # Initialize variables
    RISC0_AGGREGATION_ID=""
    RISC0_BATCH_ID=""
    SP1_AGGREGATION_VK_HASH=""
    SP1_BATCH_VK_HASH=""
    
    # Check if we're in the right directory
    if [ ! -f "Cargo.toml" ]; then
        print_error "This script must be run from the project root directory"
        exit 1
    fi
    
    # Parse command line arguments
    local mode=""
    if [ $# -gt 0 ]; then
        case "$1" in
            "risc0")
                mode="risc0"
                ;;
            "sp1")
                mode="sp1"
                ;;
            "sgx_direct")
                mode="sgx_direct"
                ;;
            "sgxgeth_direct")
                mode="sgxgeth_direct"
                ;;
            "update_sgx_mrenclave")
                mode="update_sgx_mrenclave"
                ;;
            "update_sgxgeth_mrenclave")
                mode="update_sgxgeth_mrenclave"
                ;;
            *)
                print_error "Unknown mode: $1. Use 'risc0', 'sp1', 'sgx_direct', 'sgxgeth_direct', 'update_sgx_mrenclave', or 'update_sgxgeth_mrenclave'"
                exit 1
                ;;
        esac
    else
        print_error "Mode must be specified. Use 'risc0', 'sp1', 'sgx_direct', 'sgxgeth_direct', 'update_sgx_mrenclave', or 'update_sgxgeth_mrenclave'"
        exit 1
    fi
    
    # Extract RISC0 image IDs from output
    if [ "$mode" = "risc0" ]; then
        if extract_risc0_ids_from_output "$2"; then
            print_status "RISC0 image IDs extracted successfully"
        else
            print_error "Failed to extract RISC0 image IDs"
            exit 1
        fi
    fi
    
    # Extract SP1 VK hashes from output
    if [ "$mode" = "sp1" ]; then
        if extract_sp1_hashes_from_output "$2"; then
            print_status "SP1 VK hashes extracted successfully"
        else
            print_error "Failed to extract SP1 VK hashes"
            exit 1
        fi
    fi
    

    # Extract SGX MRENCLAVE by calling tools directly on container
    if [ "$mode" = "sgx_direct" ]; then
        if extract_sgx_mrenclave_direct "$2"; then
            print_status "SGX MRENCLAVE extracted directly from container"
        else
            print_error "Failed to extract SGX MRENCLAVE directly"
            exit 1
        fi
    fi

    # Extract SGXGETH MRENCLAVE by calling tools directly on container
    if [ "$mode" = "sgxgeth_direct" ]; then
        if extract_sgxgeth_mrenclave_direct "$2"; then
            print_status "SGXGETH MRENCLAVE extracted directly from container"
        else
            print_error "Failed to extract SGXGETH MRENCLAVE directly"
            exit 1
        fi
    fi

    # Update SGX MRENCLAVE directly
    if [ "$mode" = "update_sgx_mrenclave" ]; then
        if [ -n "$2" ]; then
            update_env_mrenclave "$2"
            print_status "SGX MRENCLAVE updated to: $2"
        else
            print_error "MRENCLAVE value required for update_sgx_mrenclave mode"
            exit 1
        fi
    fi

    # Update SGXGETH MRENCLAVE directly
    if [ "$mode" = "update_sgxgeth_mrenclave" ]; then
        if [ -n "$2" ]; then
            update_env_sgxgeth_mrenclave "$2"
            print_status "SGXGETH MRENCLAVE updated to: $2"
        else
            print_error "MRENCLAVE value required for update_sgxgeth_mrenclave mode"
            exit 1
        fi
    fi
    
    # Update .env file (only for risc0 and sp1 modes, other modes handle their own .env updates)
    if [ "$mode" = "risc0" ] || [ "$mode" = "sp1" ]; then
        if update_env_file; then
            print_status "Environment file updated successfully"
        else
            print_error "Failed to update .env file"
            exit 1
        fi
    fi
    
    print_status "Automatic environment update completed successfully!"
}

# Run main function
main "$@" 
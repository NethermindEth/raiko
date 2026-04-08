#!/usr/bin/env bash

# Script to automatically update RISC0 image IDs, SP1 VK hashes, and Zisk image IDs in .env file
# by reading from build output
#
# Usage:
#   ./script/update_imageid.sh risc0 [output_file]    # Update RISC0 image IDs from file or temp
#   ./script/update_imageid.sh sp1 [output_file]      # Update SP1 VK hashes from file or temp
#   ./script/update_imageid.sh zisk                   # Set default Zisk image IDs
#
# This script is automatically called by build.sh after building RISC0 or SP1 provers.
#
# If no output_file is provided for RISC0/SP1 modes, it will look for temp files:
#   /tmp/risc0_build_output.txt for RISC0
#   /tmp/sp1_build_output.txt for SP1

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
    
    local image_id=""

    # Find the image ID that appears before the specific binary path
    image_id=$(echo "$build_output" | awk -v name="$binary_name" '
        /risc0 elf image id:/ {id=$NF}
        $0 ~ name {if (id != "") {print id; exit}}
    ')

    # Fallback: if context search fails, try sequential search based on build order
    if [ -z "$image_id" ]; then
        local all_ids
        local id_count
        all_ids=$(echo "$build_output" | grep "risc0 elf image id:" | sed 's/.*risc0 elf image id: //')
        id_count=$(echo "$all_ids" | grep -c . || true)
        if [ "$id_count" -ge 6 ]; then
            case "$binary_name" in
                risc0-aggregation)
                    image_id=$(echo "$all_ids" | sed -n '1p')
                    ;;
                risc0-batch)
                    image_id=$(echo "$all_ids" | sed -n '2p')
                    ;;
                boundless-aggregation)
                    image_id=$(echo "$all_ids" | sed -n '3p')
                    ;;
                boundless-batch)
                    image_id=$(echo "$all_ids" | sed -n '4p')
                    ;;
                risc0-shasta-aggregation)
                    image_id=$(echo "$all_ids" | sed -n '5p')
                    ;;
                boundless-shasta-aggregation)
                    image_id=$(echo "$all_ids" | sed -n '6p')
                    ;;
            esac
        else
            case "$binary_name" in
                risc0-aggregation)
                    image_id=$(echo "$all_ids" | sed -n '1p')
                    ;;
                risc0-batch)
                    image_id=$(echo "$all_ids" | sed -n '2p')
                    ;;
                risc0-shasta-aggregation)
                    image_id=$(echo "$all_ids" | sed -n '3p')
                    ;;
            esac
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
    
    # Extract VK hash based on binary order (aggregation first, batch second, shasta aggregation third)
    local vk_hash=""
    if [ "$binary_name" = "sp1-aggregation" ]; then
        vk_hash=$(echo "$build_output" | grep "sp1 elf vk hash_bytes is:" | sed 's/.*sp1 elf vk hash_bytes is: //' | head -1)
    elif [ "$binary_name" = "sp1-batch" ]; then
        vk_hash=$(echo "$build_output" | grep "sp1 elf vk hash_bytes is:" | sed 's/.*sp1 elf vk hash_bytes is: //' | sed -n '2p')
    elif [ "$binary_name" = "sp1-shasta-aggregation" ]; then
        vk_hash=$(echo "$build_output" | grep "sp1 elf vk hash_bytes is:" | sed 's/.*sp1 elf vk hash_bytes is: //' | tail -1)
    fi
    
    if [ -z "$vk_hash" ]; then
        print_error "Failed to extract SP1 VK hash for $binary_name"
        return 1
    fi
    
    echo "$vk_hash"
}

# Function to set default Zisk image IDs
set_zisk_default_ids() {
    print_status "Setting default Zisk image IDs for consistency with other zkVMs"
    
    # Set default values - these can be updated in the future when Zisk implements native image IDs
    ZISK_AGGREGATION_ID="0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    ZISK_BATCH_ID="0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    
    print_status "Using default Zisk image IDs:"
    print_status "  Aggregation: $ZISK_AGGREGATION_ID"
    print_status "  Batch: $ZISK_BATCH_ID"
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
            sed -i "s/^RISC0_BATCH_ID=.*/RISC0_BATCH_ID=$RISC0_BATCH_ID/" "$env_file"
        else
            echo "RISC0_BATCH_ID=$RISC0_BATCH_ID" >> "$env_file"
        fi
        print_status "Updated RISC0_BATCH_ID in $env_file: $RISC0_BATCH_ID"
    fi

    if [ -n "$RISC0_SHASTA_AGGREGATION_ID" ]; then
        if grep -q "^RISC0_SHASTA_AGGREGATION_ID=" "$env_file"; then
            sed -i "s/^RISC0_SHASTA_AGGREGATION_ID=.*/RISC0_SHASTA_AGGREGATION_ID=$RISC0_SHASTA_AGGREGATION_ID/" "$env_file"
        elif grep -q "^RISC0_BATCH_ID=" "$env_file"; then
            tmp_file=$(mktemp)
            awk -v kv="RISC0_SHASTA_AGGREGATION_ID=$RISC0_SHASTA_AGGREGATION_ID" '
                {print}
                $0 ~ "^RISC0_BATCH_ID=" {print kv}
            ' "$env_file" > "$tmp_file"
            mv "$tmp_file" "$env_file"
        else
            echo "RISC0_SHASTA_AGGREGATION_ID=$RISC0_SHASTA_AGGREGATION_ID" >> "$env_file"
        fi
        print_status "Updated RISC0_SHASTA_AGGREGATION_ID in $env_file: $RISC0_SHASTA_AGGREGATION_ID"
    fi

    if [ -n "$BOUNDLESS_AGGREGATION_ID" ]; then
        if grep -q "^BOUNDLESS_AGGREGATION_ID=" "$env_file"; then
            sed -i "s/^BOUNDLESS_AGGREGATION_ID=.*/BOUNDLESS_AGGREGATION_ID=$BOUNDLESS_AGGREGATION_ID/" "$env_file"
        elif grep -q "^RISC0_SHASTA_AGGREGATION_ID=" "$env_file"; then
            tmp_file=$(mktemp)
            awk -v kv="BOUNDLESS_AGGREGATION_ID=$BOUNDLESS_AGGREGATION_ID" '
                {print}
                $0 ~ "^RISC0_SHASTA_AGGREGATION_ID=" {print kv}
            ' "$env_file" > "$tmp_file"
            mv "$tmp_file" "$env_file"
        elif grep -q "^RISC0_BATCH_ID=" "$env_file"; then
            tmp_file=$(mktemp)
            awk -v kv="BOUNDLESS_AGGREGATION_ID=$BOUNDLESS_AGGREGATION_ID" '
                {print}
                $0 ~ "^RISC0_BATCH_ID=" {print kv}
            ' "$env_file" > "$tmp_file"
            mv "$tmp_file" "$env_file"
        else
            echo "BOUNDLESS_AGGREGATION_ID=$BOUNDLESS_AGGREGATION_ID" >> "$env_file"
        fi
        print_status "Updated BOUNDLESS_AGGREGATION_ID in $env_file: $BOUNDLESS_AGGREGATION_ID"
    fi

    if [ -n "$BOUNDLESS_BATCH_ID" ]; then
        if grep -q "^BOUNDLESS_BATCH_ID=" "$env_file"; then
            sed -i "s/^BOUNDLESS_BATCH_ID=.*/BOUNDLESS_BATCH_ID=$BOUNDLESS_BATCH_ID/" "$env_file"
        elif grep -q "^BOUNDLESS_AGGREGATION_ID=" "$env_file"; then
            tmp_file=$(mktemp)
            awk -v kv="BOUNDLESS_BATCH_ID=$BOUNDLESS_BATCH_ID" '
                {print}
                $0 ~ "^BOUNDLESS_AGGREGATION_ID=" {print kv}
            ' "$env_file" > "$tmp_file"
            mv "$tmp_file" "$env_file"
        elif grep -q "^RISC0_SHASTA_AGGREGATION_ID=" "$env_file"; then
            tmp_file=$(mktemp)
            awk -v kv="BOUNDLESS_BATCH_ID=$BOUNDLESS_BATCH_ID" '
                {print}
                $0 ~ "^RISC0_SHASTA_AGGREGATION_ID=" {print kv}
            ' "$env_file" > "$tmp_file"
            mv "$tmp_file" "$env_file"
        else
            echo "BOUNDLESS_BATCH_ID=$BOUNDLESS_BATCH_ID" >> "$env_file"
        fi
        print_status "Updated BOUNDLESS_BATCH_ID in $env_file: $BOUNDLESS_BATCH_ID"
    fi

    if [ -n "$BOUNDLESS_SHASTA_AGGREGATION_ID" ]; then
        if grep -q "^BOUNDLESS_SHASTA_AGGREGATION_ID=" "$env_file"; then
            sed -i "s/^BOUNDLESS_SHASTA_AGGREGATION_ID=.*/BOUNDLESS_SHASTA_AGGREGATION_ID=$BOUNDLESS_SHASTA_AGGREGATION_ID/" "$env_file"
        elif grep -q "^BOUNDLESS_BATCH_ID=" "$env_file"; then
            tmp_file=$(mktemp)
            awk -v kv="BOUNDLESS_SHASTA_AGGREGATION_ID=$BOUNDLESS_SHASTA_AGGREGATION_ID" '
                {print}
                $0 ~ "^BOUNDLESS_BATCH_ID=" {print kv}
            ' "$env_file" > "$tmp_file"
            mv "$tmp_file" "$env_file"
        elif grep -q "^BOUNDLESS_AGGREGATION_ID=" "$env_file"; then
            tmp_file=$(mktemp)
            awk -v kv="BOUNDLESS_SHASTA_AGGREGATION_ID=$BOUNDLESS_SHASTA_AGGREGATION_ID" '
                {print}
                $0 ~ "^BOUNDLESS_AGGREGATION_ID=" {print kv}
            ' "$env_file" > "$tmp_file"
            mv "$tmp_file" "$env_file"
        else
            echo "BOUNDLESS_SHASTA_AGGREGATION_ID=$BOUNDLESS_SHASTA_AGGREGATION_ID" >> "$env_file"
        fi
        print_status "Updated BOUNDLESS_SHASTA_AGGREGATION_ID in $env_file: $BOUNDLESS_SHASTA_AGGREGATION_ID"
    fi
    
    # Update SP1 VK hashes if provided
    if [ -n "$SP1_AGGREGATION_VK_HASH" ]; then
        if grep -q "^SP1_AGGREGATION_VK_HASH=" "$env_file"; then
            sed -i "s/^SP1_AGGREGATION_VK_HASH=.*/SP1_AGGREGATION_VK_HASH=$SP1_AGGREGATION_VK_HASH/" "$env_file"
        else
            echo "SP1_AGGREGATION_VK_HASH=$SP1_AGGREGATION_VK_HASH" >> "$env_file"
        fi
        print_status "Updated SP1_AGGREGATION_VK_HASH in $env_file: $SP1_AGGREGATION_VK_HASH"
    fi
    
    if [ -n "$SP1_BATCH_VK_HASH" ]; then
        if grep -q "^SP1_BATCH_VK_HASH=" "$env_file"; then
            sed -i "s/^SP1_BATCH_VK_HASH=.*/SP1_BATCH_VK_HASH=$SP1_BATCH_VK_HASH/" "$env_file"
        else
            echo "SP1_BATCH_VK_HASH=$SP1_BATCH_VK_HASH" >> "$env_file"
        fi
        print_status "Updated SP1_BATCH_VK_HASH in $env_file: $SP1_BATCH_VK_HASH"
    fi


    if [ -n "$SP1_SHASTA_AGGREGATION_VK_HASH" ]; then
        if grep -q "^SP1_SHASTA_AGGREGATION_VK_HASH=" "$env_file"; then
            sed -i "s/^SP1_SHASTA_AGGREGATION_VK_HASH=.*/SP1_SHASTA_AGGREGATION_VK_HASH=$SP1_SHASTA_AGGREGATION_VK_HASH/" "$env_file"
        elif grep -q "^SP1_BATCH_VK_HASH=" "$env_file"; then
            tmp_file=$(mktemp)
            awk -v kv="SP1_SHASTA_AGGREGATION_VK_HASH=$SP1_SHASTA_AGGREGATION_VK_HASH" '
                {print}
                $0 ~ "^SP1_BATCH_VK_HASH=" {print kv}
            ' "$env_file" > "$tmp_file"
            mv "$tmp_file" "$env_file"
        else
            echo "SP1_SHASTA_AGGREGATION_VK_HASH=$SP1_SHASTA_AGGREGATION_VK_HASH" >> "$env_file"
        fi
        print_status "Updated SP1_SHASTA_AGGREGATION_VK_HASH in $env_file: $SP1_SHASTA_AGGREGATION_VK_HASH"
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
    local shasta_id=$(extract_risc0_image_id "$build_output" "risc0-shasta-aggregation")
    local boundless_aggregation_id=$(extract_risc0_image_id "$build_output" "boundless-aggregation")
    local boundless_batch_id=$(extract_risc0_image_id "$build_output" "boundless-batch")
    local boundless_shasta_id=$(extract_risc0_image_id "$build_output" "boundless-shasta-aggregation")

    if [ -z "$aggregation_id" ] || [ -z "$batch_id" ]; then
        print_error "Failed to extract RISC0 image IDs from build output"
        return 1
    fi

    RISC0_AGGREGATION_ID="$aggregation_id"
    RISC0_BATCH_ID="$batch_id"
    RISC0_SHASTA_AGGREGATION_ID="$shasta_id"
    BOUNDLESS_AGGREGATION_ID="$boundless_aggregation_id"
    BOUNDLESS_BATCH_ID="$boundless_batch_id"
    BOUNDLESS_SHASTA_AGGREGATION_ID="$boundless_shasta_id"
    print_status "Extracted RISC0 image IDs:"
    print_status "  Aggregation: $aggregation_id"
    if [ -n "$shasta_id" ]; then
        print_status "  Shasta Aggregation: $shasta_id"
    fi
    print_status "  Batch: $batch_id"
    if [ -n "$boundless_aggregation_id" ]; then
        print_status "Extracted RISC0 boundless image IDs:"
        print_status "  Aggregation: $boundless_aggregation_id"
        if [ -n "$boundless_shasta_id" ]; then
            print_status "  Shasta Aggregation: $boundless_shasta_id"
        fi
        print_status "  Batch: $boundless_batch_id"
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
    local shasta_vk_hash=$(extract_sp1_vk_hash "$build_output" "sp1-shasta-aggregation")

    if [ -z "$aggregation_vk_hash" ] || [ -z "$batch_vk_hash" ]; then
        print_error "Failed to extract SP1 VK hashes from build output"
        return 1
    fi

    SP1_AGGREGATION_VK_HASH="$aggregation_vk_hash"
    SP1_SHASTA_AGGREGATION_VK_HASH="$shasta_vk_hash"
    SP1_BATCH_VK_HASH="$batch_vk_hash"
    print_status "Extracted SP1 VK hashes:"
    print_status "  Aggregation: $aggregation_vk_hash"
    if [ -n "$shasta_vk_hash" ]; then
        print_status "  Shasta Aggregation: $shasta_vk_hash"
    fi
    print_status "  Batch: $batch_vk_hash"
}

# Main function
main() {
    print_status "Starting automatic environment update..."
    
    # Initialize variables
    RISC0_AGGREGATION_ID=""
    RISC0_BATCH_ID=""
    RISC0_SHASTA_AGGREGATION_ID=""
    BOUNDLESS_AGGREGATION_ID=""
    BOUNDLESS_BATCH_ID=""
    BOUNDLESS_SHASTA_AGGREGATION_ID=""
    SP1_AGGREGATION_VK_HASH=""
    SP1_BATCH_VK_HASH=""
    ZISK_AGGREGATION_ID=""
    ZISK_BATCH_ID=""
    SP1_SHASTA_AGGREGATION_VK_HASH=""
    
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
            "zisk")
                mode="zisk"
                ;;
            *)
                print_error "Unknown mode: $1. Use 'risc0', 'sp1', or 'zisk'"
                exit 1
                ;;
        esac
    else
        print_error "Mode must be specified. Use 'risc0', 'sp1', or 'zisk'"
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
    
    # Set default Zisk image IDs
    if [ "$mode" = "zisk" ]; then
        set_zisk_default_ids
        print_status "Zisk image IDs set successfully"
    fi
    
    # Update .env file (only for risc0 and sp1 modes)
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

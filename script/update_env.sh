#!/bin/bash

echo "choose env"
select net in tolba hekla mainnet devnet others; do
  case $net in
    tolba|hekla|mainnet|devnet)
      network=$net
      break
      ;;
    others)
      read -p "Input customized env: " custom_net
      network=$custom_net
      break
      ;;
    *)
      echo "unknown option"
      ;;
  esac
done

# input version
read -p "Input version (e.g., 1.9.0-rc.1): " version

# check base directory exists
base_dir=${network}/${version}
if [ ! -d "$base_dir" ]; then
  echo "Directory $base_dir does not exist. Please run the prepare-deploy.sh script first."
  exit 1
fi

echo "Environment update complete for $network/$version"

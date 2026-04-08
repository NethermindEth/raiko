#!/usr/bin/env bash

exec 2>&1
set -xeo pipefail

export IN_CONTAINER=1

# the config file & chain spec used inside raiko
BASE_CONFIG_FILE=${BASE_CONFIG_FILE:-config.json}
BASE_CHAINSPEC_FILE=${BASE_CHAINSPEC_FILE:-chain_spec_list.docker.json}
RAIKO_DOCKER_VOLUME_PATH=${RAIKO_DOCKER_VOLUME_PATH:-"/root/.config/raiko"}
RAIKO_DOCKER_VOLUME_CONFIG_PATH="$RAIKO_DOCKER_VOLUME_PATH/config"
RAIKO_DOCKER_VOLUME_SECRETS_PATH="$RAIKO_DOCKER_VOLUME_PATH/secrets"
RAIKO_DOCKER_VOLUME_PRIV_KEY_PATH="$RAIKO_DOCKER_VOLUME_SECRETS_PATH/priv.key"
RAIKO_APP_DIR=${RAIKO_APP_DIR:-"/opt/raiko/bin"}
RAIKO_CONF_DIR=${RAIKO_CONF_DIR:-"/etc/raiko"}
RAIKO_CONF_BASE_CONFIG="$RAIKO_CONF_DIR/$BASE_CONFIG_FILE"
RAIKO_CONF_CHAIN_SPECS="$RAIKO_CONF_DIR/$BASE_CHAINSPEC_FILE"

function update_raiko_tdx_instance_id() {
    CONFIG_FILE=$1
    if [[ -n $TDX_INSTANCE_ID ]]; then
        jq \
            --arg update_value "$TDX_INSTANCE_ID" \
            '.tdx.instance_ids.HEKLA = ($update_value | tonumber)' $CONFIG_FILE \
            >/tmp/config_tmp.json && mv /tmp/config_tmp.json $CONFIG_FILE
        echo "Update hekla tdx instance id to $TDX_INSTANCE_ID"
    fi
    if [[ -n $TDX_ONTAKE_INSTANCE_ID ]]; then
        jq \
            --arg update_value "$TDX_ONTAKE_INSTANCE_ID" \
            '.tdx.instance_ids.ONTAKE = ($update_value | tonumber)' $CONFIG_FILE \
            >/tmp/config_tmp.json && mv /tmp/config_tmp.json $CONFIG_FILE
        echo "Update ontake tdx instance id to $TDX_ONTAKE_INSTANCE_ID"
    fi
    if [[ -n $TDX_PACAYA_INSTANCE_ID ]]; then
        jq \
            --arg update_value "$TDX_PACAYA_INSTANCE_ID" \
            '.tdx.instance_ids.PACAYA = ($update_value | tonumber)' $CONFIG_FILE \
            >/tmp/config_tmp.json && mv /tmp/config_tmp.json $CONFIG_FILE
        echo "Update pacaya tdx instance id to $TDX_PACAYA_INSTANCE_ID"
    fi
    if [[ -n $TDX_SHASTA_INSTANCE_ID ]]; then
        jq \
            --arg update_value "$TDX_SHASTA_INSTANCE_ID" \
            '.tdx.instance_ids.SHASTA = ($update_value | tonumber)' $CONFIG_FILE \
            >/tmp/config_tmp.json && mv /tmp/config_tmp.json $CONFIG_FILE
        echo "Update shasta tdx instance id to $TDX_SHASTA_INSTANCE_ID"
    fi
}

if [[ -n $TEST ]]; then
    echo "TEST mode, to test bash functions."
    return 0
fi

echo $#

if [[ -n $ZK ]]; then
    echo "running raiko in zk mode"
    if [ ! -f $RAIKO_CONF_BASE_CONFIG ]; then
        echo "$RAIKO_CONF_BASE_CONFIG file not found."
        exit 1
    fi
    /opt/raiko/bin/raiko-host  --config-path=$RAIKO_CONF_BASE_CONFIG --chain-spec-path=$RAIKO_CONF_CHAIN_SPECS "$@"
fi

if [[ -n $TDX ]]; then
    echo "running raiko in tdx mode"
    if [ ! -f $RAIKO_CONF_BASE_CONFIG ]; then
        echo "$RAIKO_CONF_BASE_CONFIG file not found."
        exit 1
    fi

    update_raiko_tdx_instance_id $RAIKO_CONF_BASE_CONFIG

    /opt/raiko/bin/raiko-host  --config-path=$RAIKO_CONF_BASE_CONFIG --chain-spec-path=$RAIKO_CONF_CHAIN_SPECS "$@"
fi

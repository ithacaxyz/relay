#!/usr/bin/env bash
set -eo pipefail

usage()
{
    echo "Usage: $0 -r <rpc url> -b <bundle id>"
    exit 1
}

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

while getopts ":b:r:" opt; do
  case ${opt} in
    b ) bundle_id=$OPTARG;;
    r ) rpc_url=$OPTARG;;
    \? ) usage;;
  esac
done

rpc_url=${rpc_url:-${ETH_RPC_URL:-http://localhost:8545}}

if [ -z "$bundle_id" ] || [ -z "$rpc_url" ]; then
  usage
fi

if ! command -v cast help 2>&1 >/dev/null
then
    echo "Please install cast"
    exit 1
fi

if ! command -v jq 2>&1 >/dev/null
then
    echo "Please install jq"
    exit 1
fi

bundle="$(cast rpc wallet_getCallsStatus -r $rpc_url $bundle_id)"
status=$(echo "${bundle}" | jq '.status')

case $status in
    100 ) human_status="Pending";;
    200 ) human_status="Confirmed";;
    300 ) human_status="Failed offchain";;
    400 ) human_status="Reverted";;
    500 ) human_status="Partially reverted";;
    *) human_status="Unknown";;
esac

echo "Bundle ${bundle_id} on ${rpc_url}"
echo
echo "Bundle status: ${human_status} (${status})"
echo "Receipts:"

for receipt in $(echo "${bundle}" | jq -c '.receipts[]'); do
    tx_status=$(echo "${receipt}" | jq -r '.status')

    echo -n "- "
    if [ $tx_status = "0x1" ]; then
        echo -en $GREEN
    else
        echo -en $RED
    fi
    echo "${receipt}" | jq -r '.transactionHash + " (" + (.chainId | tostring) + ")"'
    echo -en $NC
done

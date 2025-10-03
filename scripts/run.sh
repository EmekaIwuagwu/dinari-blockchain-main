#!/bin/bash

# DinariBlockchain Node Runner Script

set -e

echo "Starting DinariBlockchain Node..."

# Default values
DATA_DIR="./data"
RPC_ADDR="localhost:8545"
P2P_ADDR="/ip4/0.0.0.0/tcp/9000"
MINER_ADDR=""
AUTO_MINE=false
LOG_LEVEL="info"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --datadir)
            DATA_DIR="$2"
            shift 2
            ;;
        --rpc)
            RPC_ADDR="$2"
            shift 2
            ;;
        --p2p)
            P2P_ADDR="$2"
            shift 2
            ;;
        --miner)
            MINER_ADDR="$2"
            shift 2
            ;;
        --mine)
            AUTO_MINE=true
            shift
            ;;
        --loglevel)
            LOG_LEVEL="$2"
            shift 2
            ;;
        --create-wallet)
            ./bin/dinari-node --create-wallet
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Build if binary doesn't exist
if [ ! -f "./bin/dinari-node" ]; then
    echo "Building dinari-node..."
    make build
fi

# Create data directory
mkdir -p "$DATA_DIR"

# Run the node
CMD="./bin/dinari-node --datadir=$DATA_DIR --rpc=$RPC_ADDR --p2p=$P2P_ADDR --loglevel=$LOG_LEVEL"

if [ -n "$MINER_ADDR" ]; then
    CMD="$CMD --miner=$MINER_ADDR"
fi

if [ "$AUTO_MINE" = true ]; then
    CMD="$CMD --mine"
fi

echo "Command: $CMD"
echo ""

exec $CMD
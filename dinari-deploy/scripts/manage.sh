#!/bin/bash
set -e

case "$1" in
    start-node)
        systemctl start dinari-node
        echo "✓ Node started"
        ;;
    stop-node)
        systemctl stop dinari-node
        echo "✓ Node stopped"
        ;;
    status-node)
        systemctl status dinari-node
        ;;
    logs-node)
        journalctl -u dinari-node -f
        ;;
    start-miner)
        systemctl start dinari-miner
        echo "✓ Miner started"
        ;;
    stop-miner)
        systemctl stop dinari-miner
        echo "✓ Miner stopped"
        ;;
    status-miner)
        systemctl status dinari-miner
        ;;
    logs-miner)
        journalctl -u dinari-miner -f
        ;;
    *)
        echo "Usage: $0 {start-node|stop-node|status-node|logs-node|start-miner|stop-miner|status-miner|logs-miner}"
        exit 1
        ;;
esac

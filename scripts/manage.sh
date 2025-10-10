#!/bin/bash
# Dinari Blockchain - Management Script
# Quick commands for managing node/miner

set -e

INSTALL_DIR="/opt/dinari"
DATA_DIR="/var/lib/dinari"

show_help() {
    echo "Dinari Blockchain Management Script"
    echo ""
    echo "Usage: sudo bash manage.sh [command]"
    echo ""
    echo "Commands:"
    echo "  start-node       Start the node service"
    echo "  stop-node        Stop the node service"
    echo "  restart-node     Restart the node service"
    echo "  status-node      Check node status"
    echo "  logs-node        View node logs (live)"
    echo ""
    echo "  start-miner      Start the miner service"
    echo "  stop-miner       Stop the miner service"
    echo "  restart-miner    Restart the miner service"
    echo "  status-miner     Check miner status"
    echo "  logs-miner       View miner logs (live)"
    echo ""
    echo "  create-wallet    Create a new wallet"
    echo "  backup           Backup blockchain data"
    echo "  health           Check system health"
    echo "  version          Show version info"
    echo ""
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "ERROR: Please run as root (sudo bash manage.sh)"
    exit 1
fi

case "$1" in
    start-node)
        systemctl start dinari-node
        echo "✓ Node started"
        ;;
    stop-node)
        systemctl stop dinari-node
        echo "✓ Node stopped"
        ;;
    restart-node)
        systemctl restart dinari-node
        echo "✓ Node restarted"
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
    restart-miner)
        systemctl restart dinari-miner
        echo "✓ Miner restarted"
        ;;
    status-miner)
        systemctl status dinari-miner
        ;;
    logs-miner)
        journalctl -u dinari-miner -f
        ;;
        
    create-wallet)
        echo "Creating new wallet..."
        sudo -u dinari $INSTALL_DIR/bin/dinari-node --create-wallet
        echo ""
        echo "⚠️  SAVE THIS INFORMATION SECURELY!"
        ;;
        
    backup)
        BACKUP_DIR="$DATA_DIR/backups/backup-$(date +%Y%m%d-%H%M%S)"
        mkdir -p $BACKUP_DIR
        echo "Creating backup to $BACKUP_DIR..."
        cp -r $DATA_DIR/data $BACKUP_DIR/
        tar -czf $BACKUP_DIR.tar.gz -C $DATA_DIR/backups $(basename $BACKUP_DIR)
        rm -rf $BACKUP_DIR
        echo "✓ Backup created: $BACKUP_DIR.tar.gz"
        ;;
        
    health)
        echo "=== Dinari Blockchain Health Check ==="
        echo ""
        echo "Node Status:"
        systemctl is-active dinari-node && echo "✓ Running" || echo "✗ Stopped"
        echo ""
        echo "Miner Status:"
        systemctl is-active dinari-miner && echo "✓ Running" || echo "✗ Stopped"
        echo ""
        echo "Disk Usage:"
        df -h $DATA_DIR | tail -1
        echo ""
        echo "Memory Usage:"
        free -h | grep Mem
        echo ""
        echo "RPC Endpoint:"
        curl -s http://localhost:8545/health && echo "✓ Healthy" || echo "✗ Unreachable"
        ;;
        
    version)
        $INSTALL_DIR/bin/dinari-node --version 2>/dev/null || echo "Version info not available"
        ;;
        
    *)
        show_help
        exit 1
        ;;
esac
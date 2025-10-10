#!/bin/bash
# Dinari Blockchain - Cloud Deployment Script
# Uploads and installs on remote Linux server

set -e

echo "============================================"
echo "  Dinari Blockchain - Cloud Deployment"
echo "============================================"
echo ""

# Configuration
read -p "Enter server IP/hostname: " SERVER
read -p "Enter SSH user (default: root): " SSH_USER
SSH_USER=${SSH_USER:-root}
read -p "Enter SSH port (default: 22): " SSH_PORT
SSH_PORT=${SSH_PORT:-22}

PACKAGE="dinari-blockchain-linux-amd64.tar.gz"

# Check if package exists
if [ ! -f "$PACKAGE" ]; then
    echo "ERROR: Package not found: $PACKAGE"
    echo "Run: tar -czf $PACKAGE dinari-deploy/"
    exit 1
fi

echo ""
echo "[1/4] Uploading package to server..."
scp -P $SSH_PORT $PACKAGE $SSH_USER@$SERVER:/tmp/
echo "✓ Package uploaded"

echo "[2/4] Extracting on server..."
ssh -p $SSH_PORT $SSH_USER@$SERVER << 'ENDSSH'
cd /tmp
tar -xzf dinari-blockchain-linux-amd64.tar.gz
cd dinari-deploy
echo "✓ Package extracted"
ENDSSH

echo "[3/4] Running installation..."
ssh -p $SSH_PORT $SSH_USER@$SERVER << 'ENDSSH'
cd /tmp/dinari-deploy
chmod +x scripts/install.sh
bash scripts/install.sh
ENDSSH

echo "[4/4] Cleaning up..."
ssh -p $SSH_PORT $SSH_USER@$SERVER << 'ENDSSH'
rm -rf /tmp/dinari-blockchain-linux-amd64.tar.gz /tmp/dinari-deploy
ENDSSH

echo ""
echo "============================================"
echo "  Deployment Complete!"
echo "============================================"
echo ""
echo "Connect to server and complete setup:"
echo "  ssh -p $SSH_PORT $SSH_USER@$SERVER"
echo ""
echo "Then run:"
echo "  1. Create wallet: sudo -u dinari /opt/dinari/bin/dinari-node --create-wallet"
echo "  2. Edit miner service with your address"
echo "  3. Start services: systemctl start dinari-node"
echo ""
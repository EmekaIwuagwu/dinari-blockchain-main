#!/bin/bash
set -e

echo "============================================"
echo "  Dinari Blockchain - Cloud Deployment"
echo "============================================"

read -p "Enter server IP: " SERVER
read -p "Enter SSH user (default: root): " SSH_USER
SSH_USER=${SSH_USER:-root}

PACKAGE="dinari-blockchain-linux-amd64.tar.gz"

if [ ! -f "$PACKAGE" ]; then
    echo "ERROR: Package not found: $PACKAGE"
    exit 1
fi

echo "[1/3] Uploading..."
scp $PACKAGE $SSH_USER@$SERVER:/tmp/

echo "[2/3] Installing..."
ssh $SSH_USER@$SERVER << 'ENDSSH'
cd /tmp
tar -xzf dinari-blockchain-linux-amd64.tar.gz
cd dinari-deploy
bash scripts/install.sh
rm -rf /tmp/dinari-blockchain-linux-amd64.tar.gz /tmp/dinari-deploy
ENDSSH

echo "✅ Deployment complete!"

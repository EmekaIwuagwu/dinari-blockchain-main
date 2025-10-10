#!/bin/bash
set -e

echo "============================================"
echo "  Dinari Blockchain - Installation"
echo "============================================"

if [ "$EUID" -ne 0 ]; then 
    echo "ERROR: Run as root (sudo bash install.sh)"
    exit 1
fi

DINARI_USER="dinari"
INSTALL_DIR="/opt/dinari"
DATA_DIR="/var/lib/dinari"
LOG_DIR="/var/log/dinari"

echo "[1/6] Creating user..."
if ! id "$DINARI_USER" &>/dev/null; then
    useradd -r -s /bin/bash -d /opt/dinari -m $DINARI_USER
fi

echo "[2/6] Creating directories..."
mkdir -p $INSTALL_DIR/{bin,config}
mkdir -p $DATA_DIR/{data,miner-data}
mkdir -p $LOG_DIR

echo "[3/6] Installing binaries..."
cp bin/dinari-node $INSTALL_DIR/bin/
cp bin/dinari-wallet $INSTALL_DIR/bin/
chmod +x $INSTALL_DIR/bin/*

echo "[4/6] Installing configs..."
cp config/node.yaml $INSTALL_DIR/config/
cp config/production.yaml $INSTALL_DIR/config/ 2>/dev/null || true

echo "[5/6] Setting permissions..."
chown -R $DINARI_USER:$DINARI_GROUP $INSTALL_DIR
chown -R $DINARI_USER:$DINARI_GROUP $DATA_DIR
chown -R $DINARI_USER:$DINARI_GROUP $LOG_DIR

echo "[6/6] Installing services..."
cp systemd/dinari-node.service /etc/systemd/system/
cp systemd/dinari-miner.service /etc/systemd/system/
systemctl daemon-reload

echo ""
echo "✅ Installation complete!"
echo ""
echo "Next steps:"
echo "  systemctl start dinari-node"
echo "  systemctl enable dinari-node"
echo "  systemctl status dinari-node"

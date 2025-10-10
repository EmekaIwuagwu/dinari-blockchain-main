#!/bin/bash
# Dinari Blockchain - Linux Cloud Installation Script
# Run as root: sudo bash install.sh

set -e

echo "============================================"
echo "  Dinari Blockchain - Linux Installation"
echo "============================================"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "ERROR: Please run as root (sudo bash install.sh)"
    exit 1
fi

# Variables
DINARI_USER="dinari"
DINARI_GROUP="dinari"
INSTALL_DIR="/opt/dinari"
DATA_DIR="/var/lib/dinari"
LOG_DIR="/var/log/dinari"

echo "[1/7] Creating user and directories..."
# Create user
if ! id "$DINARI_USER" &>/dev/null; then
    useradd -r -s /bin/bash -d /opt/dinari -m $DINARI_USER
    echo "✓ Created user: $DINARI_USER"
else
    echo "✓ User already exists: $DINARI_USER"
fi

# Create directories
mkdir -p $INSTALL_DIR/{bin,config}
mkdir -p $DATA_DIR/{data,miner-data,backups}
mkdir -p $LOG_DIR

echo "[2/7] Installing binaries..."
# Copy binaries (assumes you're in dinari-deploy/ directory)
if [ -f "bin/dinari-node" ]; then
    cp bin/dinari-node $INSTALL_DIR/bin/
    cp bin/dinari-wallet $INSTALL_DIR/bin/
    chmod +x $INSTALL_DIR/bin/*
    echo "✓ Binaries installed to $INSTALL_DIR/bin/"
else
    echo "ERROR: Binaries not found. Run from dinari-deploy/ directory"
    exit 1
fi

echo "[3/7] Installing configuration..."
if [ -f "config/node.yaml" ]; then
    cp config/node.yaml $INSTALL_DIR/config/
    cp config/production.yaml $INSTALL_DIR/config/ 2>/dev/null || true
    echo "✓ Configuration files installed"
else
    echo "WARNING: Config files not found"
fi

echo "[4/7] Setting permissions..."
chown -R $DINARI_USER:$DINARI_GROUP $INSTALL_DIR
chown -R $DINARI_USER:$DINARI_GROUP $DATA_DIR
chown -R $DINARI_USER:$DINARI_GROUP $LOG_DIR
chmod 750 $DATA_DIR
echo "✓ Permissions set"

echo "[5/7] Installing systemd services..."
# Copy service files
if [ -f "systemd/dinari-node.service" ]; then
    cp systemd/dinari-node.service /etc/systemd/system/
    cp systemd/dinari-miner.service /etc/systemd/system/ 2>/dev/null || true
    systemctl daemon-reload
    echo "✓ Systemd services installed"
else
    echo "WARNING: Service files not found"
fi

echo "[6/7] Configuring firewall..."
if command -v ufw &> /dev/null; then
    ufw allow 8545/tcp comment 'Dinari RPC'
    ufw allow 9000/tcp comment 'Dinari P2P'
    echo "✓ Firewall rules added (UFW)"
else
    echo "⚠ UFW not found, configure firewall manually:"
    echo "  - Allow port 8545/tcp (RPC)"
    echo "  - Allow port 9000/tcp (P2P)"
fi

echo "[7/7] Creating wallet..."
echo ""
echo "IMPORTANT: Create a production wallet now!"
echo "Run: sudo -u dinari $INSTALL_DIR/bin/dinari-node --create-wallet"
echo ""
echo "Save the output (address starts with D1...) in a SECURE location!"
echo ""

echo "============================================"
echo "  Installation Complete!"
echo "============================================"
echo ""
echo "Next steps:"
echo "  1. Create wallet: sudo -u dinari $INSTALL_DIR/bin/dinari-node --create-wallet"
echo "  2. Edit miner service: nano /etc/systemd/system/dinari-miner.service"
echo "     Replace D1YourMinerAddressHere with your real address"
echo "  3. Start node: systemctl start dinari-node"
echo "  4. Enable on boot: systemctl enable dinari-node"
echo "  5. Check status: systemctl status dinari-node"
echo "  6. View logs: journalctl -u dinari-node -f"
echo ""
#!/bin/bash
# scripts/deploy-aws.sh

set -e

echo "=========================================="
echo "Dinari Blockchain Testnet - AWS Deployment"
echo "=========================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Please run as root (use sudo)${NC}"
    exit 1
fi

echo -e "${GREEN}Step 1: Updating system packages...${NC}"
apt-get update
apt-get upgrade -y

echo -e "${GREEN}Step 2: Setting up SWAP (2GB)...${NC}"
# Check if swap already exists
if [ -f /swapfile ]; then
    echo "SWAP file already exists, skipping..."
else
    echo "Creating 2GB swap file..."
    fallocate -l 2G /swapfile
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile
    
    # Make swap permanent
    if ! grep -q '/swapfile' /etc/fstab; then
        echo '/swapfile none swap sw 0 0' >> /etc/fstab
    fi
    
    echo -e "${GREEN}✓ SWAP configured successfully${NC}"
    free -h
fi

echo -e "${GREEN}Step 3: Installing Docker...${NC}"
# Remove old versions
apt-get remove -y docker docker-engine docker.io containerd runc || true

# Install dependencies
apt-get install -y \
    ca-certificates \
    curl \
    gnupg \
    lsb-release

# Add Docker's official GPG key
mkdir -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg

# Set up repository
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null

# Install Docker Engine
apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Start and enable Docker
systemctl start docker
systemctl enable docker

echo -e "${GREEN}Step 4: Installing Docker Compose...${NC}"
apt-get install -y docker-compose

echo -e "${GREEN}Step 5: Configuring firewall...${NC}"
# Allow SSH, RPC, and P2P ports
ufw allow 22/tcp
ufw allow 8545/tcp
ufw allow 9000/tcp
ufw --force enable

echo -e "${GREEN}Step 6: Creating project directory...${NC}"
mkdir -p /opt/dinari-blockchain
cd /opt/dinari-blockchain

echo -e "${GREEN}Step 7: Optimizing system for 1GB RAM...${NC}"
# Adjust swappiness (how aggressively system uses swap)
sysctl vm.swappiness=10
echo "vm.swappiness=10" >> /etc/sysctl.conf

echo ""
echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║            Installation complete!                          ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "System Resources:"
free -h
echo ""
echo "SWAP Status:"
swapon --show
echo ""
echo -e "${YELLOW}Next Steps:${NC}"
echo "1. Copy your project files to /opt/dinari-blockchain/"
echo "2. Ensure you have: Dockerfile, docker-compose.yml, config/, cmd/, internal/, pkg/"
echo ""
echo "Then run:"
echo "  cd /opt/dinari-blockchain"
echo "  docker-compose up -d"
echo ""
echo "Useful commands:"
echo "  docker-compose up -d          # Start node"
echo "  docker-compose down           # Stop node"
echo "  docker-compose logs -f        # View logs"
echo "  docker-compose ps             # Check status"
echo "  free -h                       # Check memory usage"
echo "  swapon --show                 # Check swap usage"
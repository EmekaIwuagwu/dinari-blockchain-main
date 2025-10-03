#!/bin/bash
# scripts/update-node.sh

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║        Dinari Blockchain - Update Node Script             ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Check if running in correct directory
if [ ! -f "docker-compose.yml" ]; then
    echo -e "${RED}Error: docker-compose.yml not found${NC}"
    echo "Please run this script from /opt/dinari-blockchain"
    exit 1
fi

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Please run as root (use sudo)${NC}"
    exit 1
fi

echo -e "${YELLOW}Step 1: Backing up current data...${NC}"
# Create backup directory if not exists
mkdir -p /opt/dinari-backups

# Backup current data
BACKUP_FILE="/opt/dinari-backups/backup-$(date +%Y%m%d-%H%M%S).tar.gz"
echo "Creating backup: $BACKUP_FILE"
docker run --rm \
    -v dinari-blockchain_dinari-data:/data \
    -v /opt/dinari-backups:/backup \
    alpine tar czf /backup/$(basename $BACKUP_FILE) -C /data .

echo -e "${GREEN}✓ Backup created: $BACKUP_FILE${NC}"

echo ""
echo -e "${YELLOW}Step 2: Stopping current node...${NC}"
docker-compose down

echo ""
echo -e "${YELLOW}Step 3: Pulling latest code...${NC}"
git fetch origin
git pull origin main

echo ""
echo -e "${YELLOW}Step 4: Rebuilding Docker image...${NC}"
docker-compose build --no-cache

echo ""
echo -e "${YELLOW}Step 5: Starting updated node...${NC}"
docker-compose up -d

echo ""
echo -e "${YELLOW}Step 6: Waiting for node to start...${NC}"
sleep 10

echo ""
echo -e "${YELLOW}Step 7: Verifying node status...${NC}"

# Check if container is running
if docker ps | grep -q dinari-testnet-node; then
    echo -e "${GREEN}✓ Container is running${NC}"
else
    echo -e "${RED}✗ Container is not running${NC}"
    echo "Check logs with: docker-compose logs"
    exit 1
fi

# Check health endpoint
if curl -s http://localhost:8545/health > /dev/null; then
    echo -e "${GREEN}✓ Health endpoint responding${NC}"
else
    echo -e "${RED}✗ Health endpoint not responding${NC}"
    echo "Check logs with: docker-compose logs"
    exit 1
fi

echo ""
echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║              Update completed successfully!                ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "Backup location: $BACKUP_FILE"
echo ""
echo "Useful commands:"
echo "  docker-compose logs -f    # View logs"
echo "  docker-compose ps         # Check status"
echo "  bash scripts/monitor.sh   # Real-time monitoring"
echo ""
#!/bin/bash
# scripts/health-check.sh

set -e

# Configuration
RPC_URL="http://localhost:8545"
LOG_FILE="/var/log/dinari-health.log"
ALERT_EMAIL=""  # Optional: Add email for alerts

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Function to log messages
log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Function to check if node is running (Docker)
check_docker_container() {
    if docker ps | grep -q dinari-testnet-node; then
        return 0
    else
        return 1
    fi
}

# Function to check RPC endpoint
check_rpc() {
    response=$(curl -s -X POST "$RPC_URL" \
        -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","method":"chain_getHeight","params":{},"id":1}' \
        --max-time 10)
    
    if [ -z "$response" ]; then
        return 1
    fi
    
    if echo "$response" | grep -q '"result"'; then
        return 0
    else
        return 1
    fi
}

# Function to get blockchain height
get_chain_height() {
    response=$(curl -s -X POST "$RPC_URL" \
        -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","method":"chain_getHeight","params":{},"id":1}')
    
    height=$(echo "$response" | grep -o '"height":[0-9]*' | grep -o '[0-9]*')
    echo "$height"
}

# Function to get mempool size
get_mempool_size() {
    response=$(curl -s -X POST "$RPC_URL" \
        -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","method":"mempool_stats","params":{},"id":1}')
    
    size=$(echo "$response" | grep -o '"size":[0-9]*' | grep -o '[0-9]*')
    echo "$size"
}

# Function to check system resources
check_resources() {
    # Memory usage
    mem_usage=$(free | grep Mem | awk '{printf "%.0f", $3/$2 * 100}')
    
    # Disk usage
    disk_usage=$(df -h /opt/dinari-blockchain 2>/dev/null | tail -1 | awk '{print $5}' | sed 's/%//')
    
    # CPU usage
    cpu_usage=$(top -bn1 | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | awk '{print 100 - $1}')
    
    echo "Memory: ${mem_usage}% | Disk: ${disk_usage}% | CPU: ${cpu_usage}%"
}

# Function to restart node if needed
restart_node() {
    log_message "Attempting to restart node..."
    cd /opt/dinari-blockchain
    docker-compose restart
    sleep 30
}

# Main health check
echo -e "${GREEN}=== Dinari Node Health Check ===${NC}"
log_message "Starting health check..."

# Check if container is running
if check_docker_container; then
    echo -e "${GREEN}✓ Docker container is running${NC}"
    log_message "Docker container: OK"
else
    echo -e "${RED}✗ Docker container is NOT running${NC}"
    log_message "ERROR: Docker container not running"
    restart_node
    exit 1
fi

# Check RPC endpoint
if check_rpc; then
    echo -e "${GREEN}✓ RPC endpoint is responding${NC}"
    log_message "RPC endpoint: OK"
else
    echo -e "${RED}✗ RPC endpoint is NOT responding${NC}"
    log_message "ERROR: RPC endpoint not responding"
    restart_node
    exit 1
fi

# Get blockchain height
height=$(get_chain_height)
if [ -n "$height" ]; then
    echo -e "${GREEN}✓ Blockchain height: $height${NC}"
    log_message "Blockchain height: $height"
else
    echo -e "${YELLOW}⚠ Could not retrieve blockchain height${NC}"
    log_message "WARNING: Could not get blockchain height"
fi

# Get mempool size
mempool=$(get_mempool_size)
if [ -n "$mempool" ]; then
    echo -e "${GREEN}✓ Mempool size: $mempool transactions${NC}"
    log_message "Mempool size: $mempool"
else
    echo -e "${YELLOW}⚠ Could not retrieve mempool size${NC}"
fi

# Check system resources
resources=$(check_resources)
echo -e "${GREEN}✓ System resources: $resources${NC}"
log_message "System resources: $resources"

# Check if blockchain is syncing (compare height with previous check)
PREV_HEIGHT_FILE="/tmp/dinari-prev-height"
if [ -f "$PREV_HEIGHT_FILE" ]; then
    prev_height=$(cat "$PREV_HEIGHT_FILE")
    if [ "$height" -gt "$prev_height" ]; then
        echo -e "${GREEN}✓ Blockchain is syncing (prev: $prev_height, current: $height)${NC}"
        log_message "Blockchain syncing: OK (gained $((height - prev_height)) blocks)"
    elif [ "$height" -eq "$prev_height" ]; then
        echo -e "${YELLOW}⚠ Blockchain height unchanged (might be fully synced or stalled)${NC}"
        log_message "WARNING: Height unchanged - $height"
    fi
fi
echo "$height" > "$PREV_HEIGHT_FILE"

echo -e "${GREEN}=== Health Check Complete ===${NC}"
log_message "Health check completed successfully"
#!/bin/bash
# scripts/monitor.sh

set -e

# Configuration
RPC_URL="http://localhost:8545"
CHECK_INTERVAL=60  # Check every 60 seconds
LOG_FILE="/var/log/dinari-monitor.log"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Function to log messages
log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Function to display dashboard
display_dashboard() {
    clear
    echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║         Dinari Blockchain Testnet - Live Monitor          ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${GREEN}Timestamp: $(date '+%Y-%m-%d %H:%M:%S')${NC}"
    echo ""
}

# Function to get node status
get_node_status() {
    if docker ps | grep -q dinari-testnet-node; then
        status_response=$(curl -s "$RPC_URL/health" --max-time 5)
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}● RUNNING${NC}"
        else
            echo -e "${YELLOW}● DEGRADED${NC}"
        fi
    else
        echo -e "${RED}● STOPPED${NC}"
    fi
}

# Function to get blockchain info
get_blockchain_info() {
    response=$(curl -s -X POST "$RPC_URL" \
        -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","method":"chain_getHeight","params":{},"id":1}' \
        --max-time 5)
    
    if [ $? -eq 0 ] && [ -n "$response" ]; then
        height=$(echo "$response" | grep -o '"height":[0-9]*' | grep -o '[0-9]*')
        hash=$(echo "$response" | grep -o '"hash":"[^"]*"' | cut -d'"' -f4)
        difficulty=$(echo "$response" | grep -o '"difficulty":"[^"]*"' | cut -d'"' -f4)
        
        echo "Height:     $height"
        echo "Hash:       ${hash:0:16}..."
        echo "Difficulty: $difficulty"
    else
        echo "Unable to fetch blockchain info"
    fi
}

# Function to get mempool info
get_mempool_info() {
    response=$(curl -s -X POST "$RPC_URL" \
        -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","method":"mempool_stats","params":{},"id":1}' \
        --max-time 5)
    
    if [ $? -eq 0 ] && [ -n "$response" ]; then
        size=$(echo "$response" | grep -o '"size":[0-9]*' | grep -o '[0-9]*')
        added=$(echo "$response" | grep -o '"added":[0-9]*' | grep -o '[0-9]*')
        rejected=$(echo "$response" | grep -o '"rejected":[0-9]*' | grep -o '[0-9]*')
        
        echo "Pending Txs:  $size"
        echo "Total Added:  $added"
        echo "Rejected:     $rejected"
    else
        echo "Unable to fetch mempool info"
    fi
}

# Function to get miner status
get_miner_status() {
    response=$(curl -s -X POST "$RPC_URL" \
        -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","method":"miner_status","params":{},"id":1}' \
        --max-time 5)
    
    if [ $? -eq 0 ] && [ -n "$response" ]; then
        mining=$(echo "$response" | grep -o '"mining":[a-z]*' | cut -d':' -f2)
        blocks=$(echo "$response" | grep -o '"blocksMinedCount":[0-9]*' | grep -o '[0-9]*')
        address=$(echo "$response" | grep -o '"minerAddress":"[^"]*"' | cut -d'"' -f4)
        
        if [ "$mining" = "true" ]; then
            echo -e "Status:       ${GREEN}MINING${NC}"
        else
            echo -e "Status:       ${YELLOW}IDLE${NC}"
        fi
        echo "Blocks Mined: $blocks"
        echo "Address:      ${address:0:20}..."
    else
        echo "Unable to fetch miner status"
    fi
}

# Function to get system resources
get_system_resources() {
    # Memory
    mem_total=$(free -m | awk 'NR==2{print $2}')
    mem_used=$(free -m | awk 'NR==2{print $3}')
    mem_percent=$(awk "BEGIN {printf \"%.1f\", ($mem_used/$mem_total)*100}")
    
    # Disk
    disk_usage=$(df -h /opt/dinari-blockchain 2>/dev/null | tail -1 | awk '{print $5}')
    disk_avail=$(df -h /opt/dinari-blockchain 2>/dev/null | tail -1 | awk '{print $4}')
    
    # CPU
    cpu_usage=$(top -bn1 | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | awk '{printf "%.1f", 100 - $1}')
    
    # Container stats (if running)
    if docker ps | grep -q dinari-testnet-node; then
        container_mem=$(docker stats --no-stream --format "{{.MemUsage}}" dinari-testnet-node | awk '{print $1}')
        container_cpu=$(docker stats --no-stream --format "{{.CPUPerc}}" dinari-testnet-node)
    else
        container_mem="N/A"
        container_cpu="N/A"
    fi
    
    echo "Memory:       ${mem_used}MB / ${mem_total}MB (${mem_percent}%)"
    echo "Disk:         $disk_usage used, $disk_avail available"
    echo "CPU:          ${cpu_usage}%"
    echo "Container:    Mem: $container_mem | CPU: $container_cpu"
}

# Function to get network info
get_network_info() {
    # Get peer count (if available in your RPC)
    # For now, show docker network info
    container_ip=$(docker inspect dinari-testnet-node 2>/dev/null | grep '"IPAddress"' | head -1 | awk '{print $2}' | tr -d ',"')
    
    echo "Container IP: $container_ip"
    echo "RPC Port:     8545"
    echo "P2P Port:     9000"
}

# Function to get recent logs
get_recent_logs() {
    docker logs --tail 5 dinari-testnet-node 2>&1 | tail -5
}

# Main monitoring loop
log_message "Monitor started"

while true; do
    display_dashboard
    
    echo -e "${BLUE}┌─ Node Status ────────────────────────────────────────────┐${NC}"
    echo -n "Status: "
    get_node_status
    echo -e "${BLUE}└──────────────────────────────────────────────────────────┘${NC}"
    echo ""
    
    echo -e "${BLUE}┌─ Blockchain Info ────────────────────────────────────────┐${NC}"
    get_blockchain_info
    echo -e "${BLUE}└──────────────────────────────────────────────────────────┘${NC}"
    echo ""
    
    echo -e "${BLUE}┌─ Mempool ────────────────────────────────────────────────┐${NC}"
    get_mempool_info
    echo -e "${BLUE}└──────────────────────────────────────────────────────────┘${NC}"
    echo ""
    
    echo -e "${BLUE}┌─ Miner Status ───────────────────────────────────────────┐${NC}"
    get_miner_status
    echo -e "${BLUE}└──────────────────────────────────────────────────────────┘${NC}"
    echo ""
    
    echo -e "${BLUE}┌─ System Resources ───────────────────────────────────────┐${NC}"
    get_system_resources
    echo -e "${BLUE}└──────────────────────────────────────────────────────────┘${NC}"
    echo ""
    
    echo -e "${BLUE}┌─ Network ────────────────────────────────────────────────┐${NC}"
    get_network_info
    echo -e "${BLUE}└──────────────────────────────────────────────────────────┘${NC}"
    echo ""
    
    echo -e "${BLUE}┌─ Recent Logs ────────────────────────────────────────────┐${NC}"
    get_recent_logs
    echo -e "${BLUE}└──────────────────────────────────────────────────────────┘${NC}"
    echo ""
    
    echo -e "${YELLOW}Press Ctrl+C to exit. Refreshing in ${CHECK_INTERVAL}s...${NC}"
    
    sleep $CHECK_INTERVAL
done
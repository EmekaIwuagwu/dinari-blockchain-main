#!/bin/bash
# scripts/verify-setup.sh

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║     Dinari Blockchain - Setup Verification Script         ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

PASS_COUNT=0
FAIL_COUNT=0

# Function to check and report
check_item() {
    local name=$1
    local command=$2
    
    echo -n "Checking $name... "
    
    if eval "$command" > /dev/null 2>&1; then
        echo -e "${GREEN}✓ PASS${NC}"
        ((PASS_COUNT++))
        return 0
    else
        echo -e "${RED}✗ FAIL${NC}"
        ((FAIL_COUNT++))
        return 1
    fi
}

# Check Docker
check_item "Docker" "docker --version"

# Check Docker Compose
check_item "Docker Compose" "docker-compose --version"

# Check if running as root/sudo
check_item "Root/Sudo access" "[ \$EUID -eq 0 ]"

# Check required files
check_item "Dockerfile" "[ -f Dockerfile ]"
check_item "docker-compose.yml" "[ -f docker-compose.yml ]"
check_item "go.mod" "[ -f go.mod ]"
check_item "main.go" "[ -f cmd/dinari-node/main.go ]"

# Check required directories
check_item "config directory" "[ -d config ]"
check_item "internal directory" "[ -d internal ]"
check_item "pkg directory" "[ -d pkg ]"
check_item "cmd directory" "[ -d cmd ]"

# Check scripts
check_item "deploy-aws.sh" "[ -f scripts/deploy-aws.sh ]"
check_item "health-check.sh" "[ -f scripts/health-check.sh ]"
check_item "monitor.sh" "[ -f scripts/monitor.sh ]"

# Check ports are available
check_item "Port 8545 available" "! nc -z localhost 8545"
check_item "Port 9000 available" "! nc -z localhost 9000"

# Check disk space (at least 10GB free)
check_item "Sufficient disk space" "[ \$(df -BG . | tail -1 | awk '{print \$4}' | sed 's/G//') -ge 10 ]"

# Check memory (at least 512MB available)
check_item "Sufficient memory" "[ \$(free -m | awk 'NR==2{print \$7}') -ge 512 ]"

echo ""
echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"
echo -e "Results: ${GREEN}$PASS_COUNT passed${NC}, ${RED}$FAIL_COUNT failed${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"
echo ""

if [ $FAIL_COUNT -eq 0 ]; then
    echo -e "${GREEN}✓ All checks passed! Ready to deploy.${NC}"
    echo ""
    echo "Next steps:"
    echo "  1. Build: sudo docker-compose build"
    echo "  2. Start: sudo docker-compose up -d"
    echo "  3. Check: sudo docker-compose ps"
    echo ""
    exit 0
else
    echo -e "${RED}✗ Some checks failed. Please fix the issues above.${NC}"
    echo ""
    
    if ! command -v docker &> /dev/null; then
        echo "To install Docker: sudo bash scripts/deploy-aws.sh"
    fi
    
    echo ""
    exit 1
fi
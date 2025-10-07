#!/bin/bash
# scripts/deploy_production.sh
# Production deployment script for Dinari Blockchain

set -e  # Exit on error
set -u  # Exit on undefined variable

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
DINARI_VERSION="1.0.0-secure"
INSTALL_DIR="/opt/dinari"
DATA_DIR="/var/dinari/data"
LOG_DIR="/var/log/dinari"
BACKUP_DIR="/var/dinari/backups"
SERVICE_NAME="dinari-node"
USER="dinari"
GROUP="dinari"

echo -e "${BLUE}╔═══════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  DINARI BLOCKCHAIN - PRODUCTION DEPLOYMENT SCRIPT    ║${NC}"
echo -e "${BLUE}║  Version: ${DINARI_VERSION}                                    ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════════════╝${NC}"
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}❌ This script must be run as root${NC}" 
   exit 1
fi

# Function to print step
print_step() {
    echo -e "\n${GREEN}▶ $1${NC}"
}

# Function to print warning
print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

# Function to print error
print_error() {
    echo -e "${RED}❌ $1${NC}"
}

# System requirements check
print_step "Checking system requirements..."

# Check OS
if ! command -v lsb_release &> /dev/null; then
    print_error "lsb_release not found. Please install lsb-release package."
    exit 1
fi

OS=$(lsb_release -si)
VERSION=$(lsb_release -sr)
echo "Operating System: $OS $VERSION"

# Check minimum disk space (100GB)
AVAILABLE_SPACE=$(df -BG / | awk 'NR==2 {print $4}' | sed 's/G//')
if [ "$AVAILABLE_SPACE" -lt 100 ]; then
    print_warning "Low disk space: ${AVAILABLE_SPACE}GB available. Minimum 100GB recommended."
    read -p "Continue anyway? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Check RAM (minimum 4GB)
TOTAL_RAM=$(free -g | awk '/^Mem:/{print $2}')
if [ "$TOTAL_RAM" -lt 4 ]; then
    print_warning "Insufficient RAM: ${TOTAL_RAM}GB. Minimum 4GB recommended."
fi

echo -e "${GREEN}✅ System requirements check passed${NC}"

# Install dependencies
print_step "Installing system dependencies..."

apt-get update
apt-get install -y \
    build-essential \
    git \
    curl \
    wget \
    jq \
    htop \
    ufw \
    fail2ban \
    logrotate \
    supervisor \
    ca-certificates

# Install Go if not present
if ! command -v go &> /dev/null; then
    print_step "Installing Go 1.22..."
    GO_VERSION="1.22.0"
    wget -q "https://golang.org/dl/go${GO_VERSION}.linux-amd64.tar.gz"
    rm -rf /usr/local/go
    tar -C /usr/local -xzf "go${GO_VERSION}.linux-amd64.tar.gz"
    rm "go${GO_VERSION}.linux-amd64.tar.gz"
    
    echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile
    export PATH=$PATH:/usr/local/go/bin
    
    echo -e "${GREEN}✅ Go installed: $(go version)${NC}"
else
    echo -e "${GREEN}✅ Go already installed: $(go version)${NC}"
fi

# Create dinari user
print_step "Creating dinari user and group..."

if ! id "$USER" &>/dev/null; then
    useradd -r -m -d /home/$USER -s /bin/bash $USER
    echo -e "${GREEN}✅ User $USER created${NC}"
else
    echo -e "${GREEN}✅ User $USER already exists${NC}"
fi

# Create directories
print_step "Creating directories..."

mkdir -p $INSTALL_DIR
mkdir -p $DATA_DIR/{chaindata,backups,tmp}
mkdir -p $LOG_DIR
mkdir -p $BACKUP_DIR
mkdir -p /etc/dinari

chown -R $USER:$GROUP $DATA_DIR
chown -R $USER:$GROUP $LOG_DIR
chown -R $USER:$GROUP $BACKUP_DIR

echo -e "${GREEN}✅ Directories created${NC}"

# Build Dinari node
print_step "Building Dinari node..."

cd $INSTALL_DIR

# Clone or pull latest
if [ ! -d "dinari-blockchain" ]; then
    git clone https://github.com/EmekaIwuagwu/dinari-blockchain-main.git dinari-blockchain
else
    cd dinari-blockchain
    git pull origin main
    cd ..
fi

cd dinari-blockchain

# Build
make clean
make build

if [ -f "bin/dinari-node" ]; then
    cp bin/dinari-node /usr/local/bin/
    chmod +x /usr/local/bin/dinari-node
    echo -e "${GREEN}✅ Dinari node built successfully${NC}"
else
    print_error "Build failed. Check logs."
    exit 1
fi

# Generate encryption key
print_step "Generating encryption key..."

ENCRYPTION_KEY=$(openssl rand -hex 32)
echo "DINARI_ENCRYPTION_KEY=$ENCRYPTION_KEY" > /etc/dinari/.env
chmod 600 /etc/dinari/.env
chown $USER:$GROUP /etc/dinari/.env

echo -e "${GREEN}✅ Encryption key generated${NC}"
print_warning "Encryption key saved to: /etc/dinari/.env"

# Setup configuration
print_step "Setting up configuration..."

cp config/production.yaml /etc/dinari/config.yaml
chown $USER:$GROUP /etc/dinari/config.yaml

echo -e "${GREEN}✅ Configuration set up${NC}"

# Setup systemd service
print_step "Setting up systemd service..."

cat > /etc/systemd/system/$SERVICE_NAME.service <<EOF
[Unit]
Description=Dinari Blockchain Node
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=$USER
Group=$GROUP
WorkingDirectory=$DATA_DIR
EnvironmentFile=/etc/dinari/.env
ExecStart=/usr/local/bin/dinari-node \\
    --datadir=$DATA_DIR \\
    --config=/etc/dinari/config.yaml \\
    --production \\
    --loglevel=info
Restart=always
RestartSec=10
StandardOutput=append:$LOG_DIR/node.log
StandardError=append:$LOG_DIR/error.log
LimitNOFILE=65536
LimitNPROC=4096

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$DATA_DIR $LOG_DIR $BACKUP_DIR

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable $SERVICE_NAME

echo -e "${GREEN}✅ Systemd service configured${NC}"

# Setup firewall
print_step "Configuring firewall..."

ufw --force enable
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp comment 'SSH'
ufw allow 8545/tcp comment 'Dinari RPC'
ufw allow 9000/tcp comment 'Dinari P2P'
ufw allow 9090/tcp comment 'Metrics'

echo -e "${GREEN}✅ Firewall configured${NC}"

# Setup log rotation
print_step "Setting up log rotation..."

cat > /etc/logrotate.d/dinari <<EOF
$LOG_DIR/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0640 $USER $GROUP
    sharedscripts
    postrotate
        systemctl reload $SERVICE_NAME > /dev/null 2>&1 || true
    endscript
}
EOF

echo -e "${GREEN}✅ Log rotation configured${NC}"

# Setup fail2ban
print_step "Configuring fail2ban..."

cat > /etc/fail2ban/filter.d/dinari.conf <<EOF
[Definition]
failregex = .*FAILED AUTH.*<HOST>.*
ignoreregex =
EOF

cat > /etc/fail2ban/jail.d/dinari.conf <<EOF
[dinari]
enabled = true
port = 8545,9000
filter = dinari
logpath = $LOG_DIR/node.log
maxretry = 5
findtime = 600
bantime = 3600
EOF

systemctl restart fail2ban

echo -e "${GREEN}✅ Fail2ban configured${NC}"

# Setup monitoring
print_step "Setting up monitoring..."

# Create monitoring script
cat > /usr/local/bin/dinari-monitor.sh <<'EOF'
#!/bin/bash

LOG_FILE="/var/log/dinari/monitor.log"
ALERT_WEBHOOK="${ALERT_WEBHOOK:-}"

check_service() {
    if ! systemctl is-active --quiet dinari-node; then
        echo "$(date): Service is down. Attempting restart..." >> $LOG_FILE
        systemctl restart dinari-node
        
        if [ -n "$ALERT_WEBHOOK" ]; then
            curl -X POST $ALERT_WEBHOOK \
                -H "Content-Type: application/json" \
                -d '{"text":"⚠️ Dinari node was down and has been restarted"}'
        fi
    fi
}

check_disk() {
    USAGE=$(df -h / | awk 'NR==2 {print $5}' | sed 's/%//')
    if [ "$USAGE" -gt 80 ]; then
        echo "$(date): Disk usage critical: ${USAGE}%" >> $LOG_FILE
        
        if [ -n "$ALERT_WEBHOOK" ]; then
            curl -X POST $ALERT_WEBHOOK \
                -H "Content-Type: application/json" \
                -d "{\"text\":\"⚠️ Disk usage critical: ${USAGE}%\"}"
        fi
    fi
}

check_memory() {
    USAGE=$(free | awk '/Mem:/ {printf "%.0f", $3/$2 * 100}')
    if [ "$USAGE" -gt 90 ]; then
        echo "$(date): Memory usage high: ${USAGE}%" >> $LOG_FILE
    fi
}

check_service
check_disk
check_memory
EOF

chmod +x /usr/local/bin/dinari-monitor.sh

# Add cron job
(crontab -u $USER -l 2>/dev/null; echo "*/5 * * * * /usr/local/bin/dinari-monitor.sh") | crontab -u $USER -

echo -e "${GREEN}✅ Monitoring configured${NC}"

# Setup backup script
print_step "Setting up automated backups..."

cat > /usr/local/bin/dinari-backup.sh <<EOF
#!/bin/bash

BACKUP_DIR="$BACKUP_DIR"
DATA_DIR="$DATA_DIR"
TIMESTAMP=\$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="\$BACKUP_DIR/dinari_backup_\$TIMESTAMP.tar.gz"

echo "\$(date): Starting backup..." >> $LOG_DIR/backup.log

tar -czf "\$BACKUP_FILE" -C "\$DATA_DIR" chaindata

if [ \$? -eq 0 ]; then
    echo "\$(date): Backup completed: \$BACKUP_FILE" >> $LOG_DIR/backup.log
    
    # Remove backups older than 30 days
    find "\$BACKUP_DIR" -name "dinari_backup_*.tar.gz" -mtime +30 -delete
else
    echo "\$(date): Backup failed" >> $LOG_DIR/backup.log
fi
EOF

chmod +x /usr/local/bin/dinari-backup.sh

# Add backup cron job (daily at 2 AM)
(crontab -u $USER -l 2>/dev/null; echo "0 2 * * * /usr/local/bin/dinari-backup.sh") | crontab -u $USER -

echo -e "${GREEN}✅ Backup configured${NC}"

# Final security hardening
print_step "Applying security hardening..."

# Disable root SSH login
sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/^PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
systemctl reload sshd

# Set secure file permissions
chmod 700 $DATA_DIR
chmod 700 $LOG_DIR
chmod 700 /etc/dinari

echo -e "${GREEN}✅ Security hardening applied${NC}"

# Summary
echo ""
echo -e "${BLUE}╔═══════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║          DEPLOYMENT COMPLETED SUCCESSFULLY            ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${GREEN}📁 Installation Directory:${NC} $INSTALL_DIR"
echo -e "${GREEN}📁 Data Directory:${NC} $DATA_DIR"
echo -e "${GREEN}📁 Log Directory:${NC} $LOG_DIR"
echo -e "${GREEN}📁 Backup Directory:${NC} $BACKUP_DIR"
echo -e "${GREEN}🔐 Config File:${NC} /etc/dinari/config.yaml"
echo -e "${GREEN}🔐 Environment File:${NC} /etc/dinari/.env"
echo ""
echo -e "${YELLOW}⚠️  IMPORTANT NEXT STEPS:${NC}"
echo ""
echo "1. Review and update configuration:"
echo "   sudo nano /etc/dinari/config.yaml"
echo ""
echo "2. Set your miner address (if mining):"
echo "   Edit 'miner_address' in config.yaml"
echo ""
echo "3. Start the node:"
echo "   sudo systemctl start $SERVICE_NAME"
echo ""
echo "4. Check node status:"
echo "   sudo systemctl status $SERVICE_NAME"
echo ""
echo "5. View logs:"
echo "   sudo journalctl -u $SERVICE_NAME -f"
echo "   or: tail -f $LOG_DIR/node.log"
echo ""
echo "6. Monitor the node:"
echo "   watch -n 5 'systemctl status $SERVICE_NAME'"
echo ""
echo -e "${YELLOW}🔒 SECURITY REMINDERS:${NC}"
echo ""
echo "• Backup your encryption key: /etc/dinari/.env"
echo "• Store the key in a secure location OFF the server"
echo "• Enable 2FA on your server SSH access"
echo "• Regularly update the system: apt-get update && apt-get upgrade"
echo "• Monitor logs for suspicious activity"
echo "• Set up external monitoring/alerting"
echo ""
echo -e "${GREEN}✅ For support: https://github.com/EmekaIwuagwu/dinari-blockchain${NC}"
echo ""
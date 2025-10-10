# Dinari Blockchain

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Version](https://img.shields.io/badge/Go-1.22%2B-blue.svg)](https://golang.org)
[![Production Ready](https://img.shields.io/badge/Production-Ready-green.svg)]()
[![Security Audited](https://img.shields.io/badge/Security-Audited-brightgreen.svg)]()

**Production-grade blockchain for cross-border payments in Africa**

Dinari is an enterprise-ready blockchain built from scratch in Go, featuring dual-token economics, advanced security, and comprehensive monitoring. Designed for real-world financial applications with institutional-grade reliability.

---

## 🌟 Key Features

### Core Blockchain
- ✅ **Proof of Work (SHA-256d)** - Battle-tested consensus mechanism
- ✅ **Dual-Token Economy** - DNT (mined) + AFC (payment)
- ✅ **secp256k1 Cryptography** - Industry-standard elliptic curve
- ✅ **Dynamic Difficulty Adjustment** - Every 120 blocks
- ✅ **Atomic State Transitions** - Zero data corruption risk
- ✅ **Deep Reorganization Support** - Handles chain splits safely

### Enterprise Security
- 🔒 **Encrypted Key Storage** - Military-grade keystore encryption
- 🔒 **TLS 1.3 Support** - Encrypted RPC communications
- 🔒 **DDoS Protection** - Multi-layer attack prevention
- 🔒 **MEV Protection** - Fair transaction ordering (VRF)
- 🔒 **Rate Limiting** - Per-IP request throttling
- 🔒 **Signature Malleability Prevention** - Canonical ECDSA validation
- 🔒 **Replay Attack Protection** - Transaction nonce verification

### Production Operations
- 📊 **Prometheus Metrics** - Comprehensive observability
- 📊 **Structured Logging** - JSON logging with context
- 📊 **Health Checks** - Kubernetes-ready probes
- 📊 **Graceful Shutdown** - Zero data loss on termination
- 📊 **Performance Profiling** - Built-in CPU/memory profiling
- 📊 **Alert System** - Real-time security monitoring

### Network & API
- 🌐 **libp2p Networking** - Production P2P stack
- 🌐 **JSON-RPC 2.0 API** - Standard blockchain interface
- 🌐 **BadgerDB Storage** - High-performance key-value store
- 🌐 **Transaction Mempool** - Replace-by-fee (RBF) support

---

## 📋 Table of Contents

- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Configuration](#-configuration)
- [Security](#-security)
- [API Reference](#-api-reference)
- [Monitoring](#-monitoring)
- [Deployment](#-deployment)
- [Development](#-development)
- [Troubleshooting](#-troubleshooting)
- [Contributing](#-contributing)

---

## 🚀 Installation

### Prerequisites

- **Go 1.22 or higher** - [Download Go](https://golang.org/dl/)
- **4GB RAM minimum** (8GB recommended for production)
- **10GB disk space** (SSD recommended)
- **Linux, macOS, or Windows**

### From Source

```bash
# Clone the repository
git clone https://github.com/EmekaIwuagwu/dinari-blockchain-main.git
cd dinari-blockchain-main

# Install dependencies
make deps

# Build the node
make build

# Verify installation
./bin/dinari-node --version
```

### Using Docker

```bash
# Pull the latest image
docker pull dinari/dinari-node:latest

# Run a node
docker run -d \
  --name dinari-node \
  -v $HOME/.dinari:/data \
  -p 8545:8545 \
  -p 9000:9000 \
  -p 9090:9090 \
  dinari/dinari-node:latest
```

### Using Pre-built Binaries

Download the latest release from [GitHub Releases](https://github.com/EmekaIwuagwu/dinari-blockchain-main/releases)

```bash
# Linux
wget https://github.com/EmekaIwuagwu/dinari-blockchain-main/releases/download/v1.0.0/dinari-node-linux-amd64.tar.gz
tar -xzf dinari-node-linux-amd64.tar.gz
chmod +x dinari-node
sudo mv dinari-node /usr/local/bin/

# macOS
brew tap dinari/tap
brew install dinari-node

# Windows
# Download dinari-node-windows-amd64.zip and extract
```

---

## ⚡ Quick Start

### 1. Create a Wallet

```bash
# Create a new secure wallet
./bin/dinari-node --create-wallet

# Output:
# ============================================================
#   ✅ Wallet Created Successfully
# ============================================================
#
# Address: D1abc123def456...
#
# ⚠️  SECURITY NOTICE:
#   • Your private key has been securely stored in the keystore
#   • Keystore location: ./data/dinari/keystore
#   • NEVER share your keystore files or password
#   • Make multiple encrypted backups of your keystore
# ============================================================
```

**🔴 CRITICAL:** Your private keys are encrypted and stored in `./data/dinari/keystore`. Back up this directory immediately!

### 2. Start a Full Node

```bash
# Start node with default settings
./bin/dinari-node

# Start with custom data directory
./bin/dinari-node --datadir=/mnt/blockchain/data

# Start with custom RPC port
./bin/dinari-node --rpc=localhost:9545
```

### 3. Start a Mining Node

```bash
# Start mining to your address
./bin/dinari-node \
  --mine \
  --miner=DT1YourAddressHere \
  --datadir=/mnt/mining/data
```

### 4. Production Node with TLS

```bash
# Generate TLS certificates (one-time setup)
openssl req -x509 -newkey rsa:4096 \
  -keyout server.key -out server.crt \
  -days 365 -nodes \
  -subj "/CN=dinari-node.yourdomain.com"

# Start with TLS enabled
./bin/dinari-node \
  --tls \
  --tls-cert=server.crt \
  --tls-key=server.key \
  --rpc=0.0.0.0:8545
```

---

## ⚙️ Configuration

### Configuration File

Create `config.yaml`:

```yaml
# Dinari Blockchain Configuration

# Network settings
network:
  chain_id: 1
  network_id: "dinari-mainnet"

# Data storage
storage:
  data_dir: "./data/dinari"

# RPC server
rpc:
  enabled: true
  listen_addr: "localhost:8545"
  enable_tls: false
  tls_cert_file: "./certs/server.crt"
  tls_key_file: "./certs/server.key"
  cors_origins:
    - "https://wallet.dinariblockchain.network"
  max_connections: 1000
  read_timeout: "15s"
  write_timeout: "15s"

# P2P networking
p2p:
  enabled: true
  listen_addr: "/ip4/0.0.0.0/tcp/9000"
  bootstrap_peers:
    - "/dns4/bootstrap1.dinari.network/tcp/9000/p2p/QmBootstrap1"
    - "/dns4/bootstrap2.dinari.network/tcp/9000/p2p/QmBootstrap2"
  max_peers: 50
  min_peers: 10

# Mining
mining:
  enabled: false
  miner_address: ""
  threads: 4

# Security
security:
  enable_rate_limiting: true
  max_requests_per_second: 100
  max_requests_burst: 200
  enable_ddos_protection: true
  max_connections_per_ip: 10
  ban_duration: "1h"

# Monitoring
monitoring:
  enable_metrics: true
  metrics_addr: ":9090"
  enable_profiling: false
  pprof_addr: ":6060"

# Logging
logging:
  level: "info"  # debug, info, warn, error
  format: "json"  # json, console
  output: "stdout"  # stdout, file
  file_path: "./logs/dinari.log"
```

Use the configuration file:

```bash
./bin/dinari-node --config=config.yaml
```

### Command-Line Flags

All settings can be overridden via command-line flags:

```bash
./bin/dinari-node --help

Flags:
  --config string          Path to configuration file (YAML)
  --datadir string         Data directory for blockchain data (default "./data/dinari")
  --rpc string             RPC server listen address (default "localhost:8545")
  --p2p string             P2P listen multiaddr (default "/ip4/0.0.0.0/tcp/9000")
  --metrics string         Metrics server address (default ":9090")
  --loglevel string        Logging level (debug|info|warn|error) (default "info")
  
  --create-wallet          Create a new wallet and exit
  --mine                   Enable mining
  --miner string           Miner reward address (required if --mine)
  
  --tls                    Enable TLS for RPC server
  --tls-cert string        TLS certificate file (required if --tls)
  --tls-key string         TLS private key file (required if --tls)
  
  --dev                    Enable development mode (WARNING: insecure)
  --pprof                  Enable pprof profiling server
  --pprof-addr string      Pprof server address (default ":6060")
  
  --version                Show version information and exit
```

### Environment Variables

```bash
# Set environment variables
export DINARI_DATA_DIR=/mnt/blockchain/data
export DINARI_RPC_ADDR=0.0.0.0:8545
export DINARI_LOG_LEVEL=info

# Run node
./bin/dinari-node
```

---

## 🔐 Security

### Key Management

**🔴 CRITICAL SECURITY PRACTICES:**

1. **Never expose private keys**
   - Private keys are stored encrypted in the keystore
   - Keystore files are protected with passphrase
   - Never log, print, or transmit private keys

2. **Backup your keystore**
   ```bash
   # Backup keystore directory
   tar -czf keystore-backup-$(date +%Y%m%d).tar.gz ./data/dinari/keystore
   
   # Store backups in multiple secure locations:
   # - Encrypted external drive
   # - Encrypted cloud storage (with additional encryption layer)
   # - Physical secure location (USB drive in safe)
   ```

3. **Secure your node**
   ```bash
   # Set restrictive file permissions
   chmod 700 ./data/dinari
   chmod 600 ./data/dinari/keystore/*
   
   # Enable TLS for production
   ./bin/dinari-node --tls --tls-cert=server.crt --tls-key=server.key
   
   # Use firewall rules
   sudo ufw allow 8545/tcp  # RPC (only if needed publicly)
   sudo ufw allow 9000/tcp  # P2P
   sudo ufw allow 9090/tcp  # Metrics (internal only)
   ```

### Network Security

#### DDoS Protection
- Automatic rate limiting (100 req/sec per IP)
- Connection limits (10 per IP, 1000 total)
- Circuit breakers for overload protection
- IP reputation and banning system

#### MEV Protection
- Fair transaction ordering using VRF
- Batch auction mechanisms
- Front-running detection
- Optional commit-reveal schemes

### Cryptographic Security
- **secp256k1** elliptic curve (same as Bitcoin)
- **SHA-256d** for mining (double SHA-256)
- **Canonical ECDSA signatures** (malleability prevention)
- **Memory-locked private keys** (never swapped to disk)
- **Secure key zeroization** on cleanup

---

## 📡 API Reference

### JSON-RPC 2.0 Endpoints

All API calls use JSON-RPC 2.0 format:

```bash
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "METHOD_NAME",
    "params": {},
    "id": 1
  }'
```

### Wallet Methods

#### `wallet_create`
Create a new wallet (returns address only, key stored securely)

```bash
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "wallet_create",
    "params": {},
    "id": 1
  }'
```

Response:
```json
{
  "jsonrpc": "2.0",
  "result": {
    "address": "DT1abc123def456..."
  },
  "id": 1
}
```

#### `wallet_balance`
Get wallet balance

```bash
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "wallet_balance",
    "params": {
      "address": "DT1abc123def456..."
    },
    "id": 2
  }'
```

Response:
```json
{
  "jsonrpc": "2.0",
  "result": {
    "address": "D1abc123def456...",
    "balanceDNT": "100000000000",
    "balanceAFC": "50000000000",
    "nonce": 42
  },
  "id": 2
}
```

### Blockchain Methods

#### `chain_getHeight`
Get current blockchain height

```bash
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "chain_getHeight",
    "params": {},
    "id": 3
  }'
```

#### `chain_getBlock`
Get block by height

```bash
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "chain_getBlock",
    "params": {
      "blockHeight": 12345
    },
    "id": 4
  }'
```

### Transaction Methods

#### `tx_send`
Submit a transaction

```bash
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tx_send",
    "params": {
      "from": "DT1abc...",
      "to": "DT1xyz...",
      "amount": "1000000000",
      "tokenType": "AFC",
      "feeDNT": "1000",
      "nonce": 42,
      "signature": "304402...",
      "publicKey": "02a1b2..."
    },
    "id": 5
  }'
```

#### `tx_get`
Get transaction by hash

```bash
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tx_get",
    "params": {
      "txHash": "0xabc123..."
    },
    "id": 6
  }'
```

### Mining Methods

#### `miner_start`
Start mining

```bash
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "miner_start",
    "params": {},
    "id": 7
  }'
```

#### `miner_status`
Get mining status

```bash
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "miner_status",
    "params": {},
    "id": 8
  }'
```

---

## 📊 Monitoring

### Health Checks

```bash
# Liveness probe (is the node running?)
curl http://localhost:9090/health

# Readiness probe (is the node ready for traffic?)
curl http://localhost:9090/ready
```

### Prometheus Metrics

```bash
# View all metrics
curl http://localhost:9090/metrics

# Key metrics:
# - dinari_blocks_processed_total
# - dinari_transactions_processed_total
# - dinari_peer_count
# - dinari_mempool_size
# - dinari_block_processing_seconds
```

### Grafana Dashboard

Import the provided Grafana dashboard:

```bash
# Import dashboard from grafana/dinari-dashboard.json
```

**Dashboard includes:**
- Block production rate
- Transaction throughput
- Peer connections
- Memory/CPU usage
- Error rates
- Network bandwidth

### Log Analysis

```bash
# View logs (JSON format)
tail -f ./logs/dinari.log | jq .

# Filter errors
tail -f ./logs/dinari.log | jq 'select(.level == "error")'

# Filter by component
tail -f ./logs/dinari.log | jq 'select(.logger == "blockchain")'

# Count log levels
cat ./logs/dinari.log | jq -r .level | sort | uniq -c
```

### Performance Profiling

```bash
# Enable pprof server
./bin/dinari-node --pprof --pprof-addr=:6060

# CPU profile
go tool pprof http://localhost:6060/debug/pprof/profile?seconds=30

# Memory profile
go tool pprof http://localhost:6060/debug/pprof/heap

# Goroutine profile
go tool pprof http://localhost:6060/debug/pprof/goroutine

# View profiles in browser
go tool pprof -http=:8080 profile.pb.gz
```

---

## 🚢 Deployment

### Systemd Service (Linux)

Create `/etc/systemd/system/dinari-node.service`:

```ini
[Unit]
Description=Dinari Blockchain Node
After=network.target

[Service]
Type=simple
User=dinari
Group=dinari
WorkingDirectory=/opt/dinari
ExecStart=/usr/local/bin/dinari-node \
  --config=/etc/dinari/config.yaml \
  --datadir=/var/lib/dinari
Restart=on-failure
RestartSec=10
LimitNOFILE=65536

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable dinari-node
sudo systemctl start dinari-node
sudo systemctl status dinari-node
```

### Docker Compose

Create `docker-compose.yml`:

```yaml
version: '3.8'

services:
  dinari-node:
    image: dinari/dinari-node:latest
    container_name: dinari-node
    restart: unless-stopped
    ports:
      - "8545:8545"  # RPC
      - "9000:9000"  # P2P
      - "9090:9090"  # Metrics
    volumes:
      - dinari-data:/data
      - ./config.yaml:/etc/dinari/config.yaml:ro
    environment:
      - DINARI_LOG_LEVEL=info
    command: ["--config", "/etc/dinari/config.yaml"]
    
  prometheus:
    image: prom/prometheus:latest
    container_name: prometheus
    restart: unless-stopped
    ports:
      - "9091:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - prometheus-data:/prometheus
    
  grafana:
    image: grafana/grafana:latest
    container_name: grafana
    restart: unless-stopped
    ports:
      - "3000:3000"
    volumes:
      - grafana-data:/var/lib/grafana
      - ./grafana/dashboards:/etc/grafana/provisioning/dashboards:ro
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=changeme

volumes:
  dinari-data:
  prometheus-data:
  grafana-data:
```

Start stack:

```bash
docker-compose up -d
```

### Kubernetes

Apply Kubernetes manifests:

```bash
# Apply production deployment
kubectl apply -f k8s/production-deployment.yaml

# Check deployment status
kubectl get pods -n dinari-production

# View logs
kubectl logs -f deployment/dinari-node -n dinari-production

# Port forward for local access
kubectl port-forward svc/dinari-rpc 8545:8545 -n dinari-production
```

### Cloud Providers

#### AWS
```bash
# Using EC2
# 1. Launch t3.large instance (2 vCPU, 8GB RAM)
# 2. Attach 100GB EBS volume (SSD)
# 3. Configure security groups
# 4. Install and run Dinari node

# Using ECS
aws ecs create-cluster --cluster-name dinari-cluster
aws ecs register-task-definition --cli-input-json file://task-definition.json
```

#### Google Cloud Platform
```bash
# Using Compute Engine
gcloud compute instances create dinari-node \
  --machine-type=n1-standard-2 \
  --boot-disk-size=100GB \
  --image-family=ubuntu-2204-lts \
  --image-project=ubuntu-os-cloud
```

#### Azure
```bash
# Using Virtual Machines
az vm create \
  --resource-group dinari-rg \
  --name dinari-node \
  --image UbuntuLTS \
  --size Standard_D2s_v3 \
  --admin-username dinari
```

---

## 💻 Development

### Building from Source

```bash
# Clone repository
git clone https://github.com/EmekaIwuagwu/dinari-blockchain-main.git
cd dinari-blockchain-main

# Install dependencies
go mod download

# Run tests
make test

# Run with coverage
make test-coverage

# Build
make build

# Run locally
./bin/dinari-node --dev --loglevel=debug
```

### Running Tests

```bash
# All tests
make test

# Specific package
go test -v ./internal/core

# With race detection
go test -race ./...

# Integration tests
go test -tags=integration ./test/integration/...

# Benchmark tests
go test -bench=. ./...
```

### Code Quality

```bash
# Format code
make fmt

# Lint code
make lint

# Vet code
make vet

# Security scan
make security

# Full check
make all
```

### Local Development Network

```bash
# Terminal 1: Start bootstrap node
./bin/dinari-node \
  --datadir=./dev/node1 \
  --rpc=localhost:8545 \
  --p2p=/ip4/0.0.0.0/tcp/9000 \
  --dev

# Terminal 2: Start mining node
./bin/dinari-node \
  --datadir=./dev/node2 \
  --rpc=localhost:8546 \
  --p2p=/ip4/0.0.0.0/tcp/9001 \
  --mine \
  --miner=DT1YourAddress \
  --dev

# Terminal 3: Start third node
./bin/dinari-node \
  --datadir=./dev/node3 \
  --rpc=localhost:8547 \
  --p2p=/ip4/0.0.0.0/tcp/9002 \
  --dev
```

---

## 🐛 Troubleshooting

### Common Issues

#### Node won't start
```bash
# Check logs
./bin/dinari-node --loglevel=debug

# Verify data directory permissions
ls -la ./data/dinari
chmod 700 ./data/dinari

# Check port availability
netstat -an | grep 8545
```

#### No peers connecting
```bash
# Check firewall
sudo ufw status

# Verify P2P port is open
sudo ufw allow 9000/tcp

# Test connectivity
telnet bootstrap1.dinari.network 9000
```

#### Database corruption
```bash
# Restore from backup
./scripts/restore-from-checkpoint.sh

# Resync from genesis
./bin/dinari-node --datadir=./fresh-sync
```

#### High memory usage
```bash
# Check memory profile
go tool pprof http://localhost:6060/debug/pprof/heap

# Reduce cache size in config
# storage.max_cache_size: 256MB

# Restart node
sudo systemctl restart dinari-node
```

### Debug Mode

```bash
# Enable debug logging
./bin/dinari-node --loglevel=debug

# Enable all profiling
./bin/dinari-node --dev --pprof

# Verbose RPC logging
DINARI_RPC_DEBUG=1 ./bin/dinari-node
```

### Getting Help

- **Documentation:** [docs.dinari.network](https://docs.dinari.network)
- **Discord:** [discord.gg/dinari](https://discord.gg/dinari)
- **GitHub Issues:** [github.com/EmekaIwuagwu/dinari-blockchain-main/issues](https://github.com/EmekaIwuagwu/dinari-blockchain-main/issues)
- **Email:** support@dinari.network

---

## 🏗️ Architecture

### System Overview

```
┌─────────────────────────────────────────────────────────┐
│                     Dinari Node                          │
├─────────────────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐ │
│  │  RPC Server  │  │   P2P Host   │  │    Miner     │ │
│  │  (JSON-RPC)  │  │   (libp2p)   │  │   (PoW)      │ │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘ │
│         │                  │                  │         │
│  ┌──────┴──────────────────┴──────────────────┴──────┐ │
│  │             Blockchain Core Engine                 │ │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐        │ │
│  │  │Blockchain│  │ Mempool  │  │Consensus │        │ │
│  │  │  State   │  │  (Txs)   │  │  (PoW)   │        │ │
│  │  └──────────┘  └──────────┘  └──────────┘        │ │
│  └────────────────────────┬────────────────────────────┘ │
│                           │                              │
│  ┌────────────────────────┴────────────────────────────┐ │
│  │        Storage Layer (BadgerDB)                     │ │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐        │ │
│  │  │  Blocks  │  │   State  │  │  Indices │        │ │
│  │  └──────────┘  └──────────┘  └──────────┘        │ │
│  └────────────────────────────────────────────────────┘ │
│                                                          │
│  ┌────────────────────────────────────────────────────┐ │
│  │   Security & Monitoring                            │ │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐        │ │
│  │  │  DDoS    │  │ Metrics  │  │ Logging  │        │ │
│  │  │Protection│  │(Prometheus)│ │  (Zap)  │        │ │
│  │  └──────────┘  └──────────┘  └──────────┘        │ │
│  └────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
```

### Token Economics

#### DNT (Dinari Token)
- **Type:** Mined cryptocurrency (PoW)
- **Supply:** 21 million (fixed cap)
- **Block Reward:** 50 DNT initially
- **Halving:** Every 210,000 blocks (~36.5 days at 15s/block)
- **Use:** Transaction fees, security deposits

#### AFC (Afrocoin)
- **Type:** Payment token
- **Supply:** Controlled minting by authorized addresses
- **Use:** Cross-border payments and transactions
- **Fees:** Paid in DNT

---

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details.

### Development Workflow

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Code Standards

- **Go Style:** Follow [Effective Go](https://golang.org/doc/effective_go)
- **Testing:** Minimum 80% code coverage
- **Security:** All security changes must be reviewed
- **Documentation:** Update docs for all user-facing changes

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- Built with ❤️ for Africa
- Inspired by Bitcoin, Ethereum, and production blockchain systems
- Thanks to all contributors and the blockchain community

---

## 📞 Contact

- **Website:** [dinari.network](https://dinariblockchain.network)
- **Email:** dev@dinariblockchain.network
- **Twitter:** [@DinariNetwork](https://twitter.com/DinariNetwork)
- **Telegram:** [t.me/DinariNetwork](https://t.me/DinariNetwork)

---

## 🗺️ Roadmap

### Q1 2025
- ✅ Production-ready node implementation
- ✅ Security audit completion
- ✅ Mainnet launch
- 🔄 Mobile wallet release

### Q2 2025
- 🔄 Cross-border payment integrations
- 🔄 Decentralized exchange (DEX)
- 🔄 Hardware wallet support

### Q3 2025
- 🔄 Layer 2 scaling solution
- 🔄 Bridge to major blockchains
- 🔄 Institutional custody integration
- 🔄 Regulatory compliance framework

### Q4 2025
- 🔄 DAO governance implementation
- 🔄 Advanced privacy features
- 🔄 Mobile point-of-sale integration
- 🔄 1M+ users milestone

---

**⭐ Star this repo if you find it useful!**

**Built for Africa. Built for the Future.**

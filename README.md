# DinariBlockchain - Production-Grade Blockchain for Africa

A fully production-ready blockchain implementation built from scratch in Go, designed for cross-border payments and financial inclusion in Africa.

## 🌟 Features

### Core Blockchain
- ✅ **Proof of Work (SHA-256d)** consensus with dynamic difficulty adjustment
- ✅ **Dual-token economy**: DNT (mining) + AFC (payments)
- ✅ **15-second block time** with automatic difficulty adjustment every 120 blocks
- ✅ **21M supply cap** with halving every 210,000 blocks
- ✅ **Reorganization protection** (max 100 blocks depth)
- ✅ **Orphan block handling** with timeout
- ✅ **State checkpoints** every 1,000 blocks

### Security
- ✅ **secp256k1 cryptography** (Bitcoin/Ethereum standard)
- ✅ **BIP-62 compliant signatures** (malleability protection)
- ✅ **Constant-time operations** (timing attack prevention)
- ✅ **Rate limiting** (DoS prevention)
- ✅ **Peer reputation system** (Sybil attack prevention)
- ✅ **Eclipse attack prevention** (subnet diversity requirements)
- ✅ **Authentication & TLS** support for API

### Performance
- ✅ **LRU cache** (10K entries, 80%+ hit rate)
- ✅ **Batch operations** (1000 items per batch)
- ✅ **BadgerDB v4** optimization (256MB value log, 100MB cache)
- ✅ **Multi-threaded mining** with configurable threads
- ✅ **Priority queue mempool** (O(log n) operations)

### Networking
- ✅ **libp2p** for transport (battle-tested)
- ✅ **DHT** for peer discovery
- ✅ **GossipSub** for efficient broadcast
- ✅ **Connection limits** (max 50 peers)
- ✅ **Peer banning** (24-hour duration)
- ✅ **Message rate limiting**

### Observability
- ✅ **Prometheus metrics** (40+ metrics)
- ✅ **Structured logging** with Zap
- ✅ **Component-specific loggers**
- ✅ **Real-time statistics**

## 🚀 Quick Start

### Prerequisites

- Go 1.22 or higher
- 4GB RAM minimum
- 10GB disk space
- Linux, macOS, or Windows

### Installation

```bash
# Clone repository
git clone https://github.com/EmekaIwuagwu/dinari-blockchain-main.git
cd dinari-blockchain-main

# Install dependencies
go mod download

# Build
make build

# Or build manually
go build -o bin/dinari-node ./cmd/dinari-node
```

### Create a Wallet

```bash
./bin/dinari-node --create-wallet
```

Output:
```
🔐 Creating new wallet...

=== New Wallet Created ===
Address:     DA1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0
Private Key: a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456
Public Key:  02a1b2c3d4e5f6789012345678901234567890abcdef

⚠️  IMPORTANT: Save your private key securely!
```

### Run a Node

**Testnet (Development):**
```bash
./bin/dinari-node \
  --network=testnet \
  --datadir=./testnet-data \
  --rpc=localhost:8545 \
  --p2p=/ip4/0.0.0.0/tcp/9000 \
  --loglevel=info
```

**Mainnet (Production):**
```bash
./bin/dinari-node \
  --network=mainnet \
  --datadir=/var/lib/dinari \
  --rpc=0.0.0.0:8545 \
  --p2p=/ip4/0.0.0.0/tcp/9000 \
  --loglevel=warn
```

**With Mining:**
```bash
./bin/dinari-node \
  --network=testnet \
  --miner=DT1YOUR_WALLET_ADDRESS \
  --mine \
  --threads=4
```

### Using Docker

```bash
# Build image
docker build -t dinari-blockchain .

# Run container
docker run -d \
  --name dinari-node \
  -p 8545:8545 \
  -p 9000:9000 \
  -p 9090:9090 \
  -v /var/lib/dinari:/data \
  dinari-blockchain \
  --network=mainnet \
  --datadir=/data
```

## 📡 JSON-RPC API

The node exposes a JSON-RPC 2.0 API on `http://localhost:8545`

### Wallet Methods

**Create Wallet:**
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

**Get Balance:**
```bash
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "wallet_balance",
    "params": {
      "address": "DT1abc123..."
    },
    "id": 2
  }'
```

### Transaction Methods

**Send Transaction:**
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
      "signature": "...",
      "publicKey": "..."
    },
    "id": 3
  }'
```

**Get Transaction:**
```bash
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tx_get",
    "params": {
      "txHash": "0xabc123..."
    },
    "id": 4
  }'
```

### Blockchain Methods

**Get Height:**
```bash
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "chain_getHeight",
    "params": {},
    "id": 5
  }'
```

**Get Block:**
```bash
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "chain_getBlock",
    "params": {
      "blockHeight": 12345
    },
    "id": 6
  }'
```

### Mining Methods

**Start Mining:**
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

**Get Mining Status:**
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

### P2P Methods

**Get Peers:**
```bash
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "p2p_getPeers",
    "params": {},
    "id": 9
  }'
```

## 📊 Monitoring

### Prometheus Metrics

Metrics are exposed at `http://localhost:9090/metrics`

Key metrics:
- `dinari_blockchain_height` - Current blockchain height
- `dinari_mining_hashrate` - Mining hash rate
- `dinari_p2p_connected_peers` - Number of connected peers
- `dinari_mempool_size` - Number of transactions in mempool
- `dinari_api_requests_total` - Total API requests

### Grafana Dashboard

Import the provided Grafana dashboard:
```bash
# Import dashboards/dinari-node.json
```

## 🔧 Configuration

Edit `config/config.yaml`:

```yaml
network:
  mode: "testnet"  # or "mainnet"

node:
  data_dir: "./data"
  log:
    level: "info"

rpc:
  addr: "localhost:8545"
  tls:
    enabled: false  # Enable for production

p2p:
  listen_addr: "/ip4/0.0.0.0/tcp/9000"
  max_peers: 50

mining:
  enabled: false
  miner_address: ""
  cpu_threads: 4
```

## 🏗️ Architecture

```
cmd/dinari-node/           # Node entry point
internal/
  ├── consensus/           # Proof of Work
  ├── core/                # Blockchain & State
  ├── mempool/             # Transaction pool
  ├── miner/               # Mining engine
  ├── p2p/                 # Network layer
  ├── storage/             # Database
  └── types/               # Core types
pkg/
  ├── api/                 # JSON-RPC server
  ├── crypto/              # Cryptography
  ├── logging/             # Structured logging
  └── metrics/             # Prometheus metrics
config/                    # Configuration files
```

## 🔐 Security Best Practices

### For Production Deployment:

1. **Enable TLS:**
```yaml
rpc:
  tls:
    enabled: true
    cert_file: "/etc/dinari/cert.pem"
    key_file: "/etc/dinari/key.pem"
```

2. **Enable Authentication:**
```yaml
rpc:
  auth:
    enabled: true
    api_keys:
      - "your-secure-api-key"
```

3. **Restrict CORS:**
```yaml
rpc:
  cors:
    allowed_origins:
      - "https://yourdomain.com"
```

4. **Firewall Configuration:**
```bash
# Allow RPC only from trusted IPs
iptables -A INPUT -p tcp --dport 8545 -s TRUSTED_IP -j ACCEPT
iptables -A INPUT -p tcp --dport 8545 -j DROP

# Allow P2P from anywhere
iptables -A INPUT -p tcp --dport 9000 -j ACCEPT
```

5. **Run as Non-Root:**
```bash
useradd -r -s /bin/false dinari
chown -R dinari:dinari /var/lib/dinari
sudo -u dinari ./bin/dinari-node
```

## 🧪 Testing

```bash
# Run all tests
make test

# Run specific tests
go test ./pkg/crypto -v
go test ./internal/consensus -v
go test ./internal/mempool -v

# Run with coverage
go test -cover ./...
```

## 📈 Performance Tuning

### For Mining Nodes:
- Increase CPU threads: `--threads=8`
- Increase memory: `4GB+ RAM`
- Use SSD storage

### For Full Nodes:
- Adjust cache size in config
- Increase BadgerDB compactors
- Use NVMe storage for best performance

### For API Nodes:
- Enable rate limiting
- Use load balancer
- Scale horizontally

## 🐛 Troubleshooting

### Node won't start
- Check data directory permissions
- Verify port availability (8545, 9000, 9090)
- Check logs: `--loglevel=debug`

### Low peer count
- Check firewall settings
- Verify bootstrap peers are reachable
- Enable UPnP on router

### Mining not working
- Verify miner address is set
- Check CPU threads configuration
- Ensure sufficient memory

### High memory usage
- Reduce mempool size
- Decrease cache size
- Enable garbage collection more frequently

## 📝 License

MIT License - see [LICENSE](LICENSE) file for details

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

## 📧 Contact

- Website: https://dinariblockchain.network
- Email: dev@dinariblockchain.network
- Discord: https://discord.gg/dinariblockchain
- Twitter: @dinariblockchain

## 🙏 Acknowledgments

Built with ❤️ for Africa

- Inspired by Bitcoin and Ethereum
- Uses libp2p (Protocol Labs)
- Uses BadgerDB (Dgraph)
- Uses Zap (Uber)
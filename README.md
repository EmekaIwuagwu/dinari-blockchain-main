# 🚀 DinariBlockchain

A production-grade blockchain built from scratch in Go for cross-border payments in Africa.

## 🎯 Overview

DinariBlockchain implements a Proof-of-Work consensus mechanism with two native tokens:

- **DINARI (DNT)** - Main PoW-mined coin (like Bitcoin), 21M supply cap
- **Afrocoin (AFC)** - Payment token for real-world transactions, controlled minting

## ✨ Features

- ✅ Proof of Work (SHA-256d) consensus
- ✅ Dual-token economy (DNT + AFC)
- ✅ secp256k1 cryptography with DT-prefixed addresses
- ✅ libp2p peer-to-peer networking
- ✅ BadgerDB for state storage
- ✅ JSON-RPC 2.0 API
- ✅ Dynamic difficulty adjustment (every 120 blocks)
- ✅ Transaction mempool with replace-by-fee (RBF)
- ✅ Blockchain reorganization support

## 📋 Requirements

- Go 1.22 or higher
- 4GB RAM minimum
- 10GB disk space

## 🚀 Quick Start

### 1. Clone and Build

```bash
git clone https://github.com/EmekaIwuagwu/dinari-blockchain.git
cd dinari-blockchain

# Initialize and build
make init
make build
```

### 2. Create a Wallet

```bash
./bin/dinari-node --create-wallet
```

This will output:
```
=== New Wallet Created ===
Address:         DT1abc123def456...
Private Key:     a1b2c3d4e5f6...
WIF:             L5oLkpV...
Public Key:      02a1b2c3...

IMPORTANT: Save your private key securely!
```

### 3. Run a Node

**Simple run (no mining):**
```bash
make run
```

**Run with mining:**
```bash
./bin/dinari-node --miner=DT1abc123def456... --mine
```

**Run with custom settings:**
```bash
./bin/dinari-node \
  --datadir=./mydata \
  --rpc=localhost:8545 \
  --p2p=/ip4/0.0.0.0/tcp/9000 \
  --miner=DT1abc123... \
  --mine \
  --loglevel=debug
```

**Windows:**
```cmd
scripts\run.bat --miner=DT1abc123... --mine
```

**Linux/Mac:**
```bash
./scripts/run.sh --miner=DT1abc123... --mine
```

## 📚 API Documentation

The node exposes a JSON-RPC 2.0 API on `http://localhost:8545`

### Wallet Methods

#### Create Wallet
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
    "address": "DT1abc123...",
    "privateKeyHex": "a1b2c3...",
    "privateKeyWIF": "L5oLkpV...",
    "publicKeyHex": "02a1b2..."
  },
  "id": 1
}
```

#### Check Balance
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

Response:
```json
{
  "jsonrpc": "2.0",
  "result": {
    "address": "DT1abc123...",
    "balanceDNT": "100000000000",
    "balanceAFC": "50000000000",
    "nonce": 42
  },
  "id": 2
}
```

### Transaction Methods

#### Send Transaction
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
    "id": 3
  }'
```

#### Get Transaction
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

### Chain Methods

#### Get Block
```bash
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "chain_getBlock",
    "params": {
      "blockHeight": 12345
    },
    "id": 5
  }'
```

#### Get Chain Height
```bash
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "chain_getHeight",
    "params": {},
    "id": 6
  }'
```

### Miner Methods

#### Start Mining
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

#### Stop Mining
```bash
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "miner_stop",
    "params": {},
    "id": 8
  }'
```

#### Miner Status
```bash
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "miner_status",
    "params": {},
    "id": 9
  }'
```

## 🛠️ Development

### Project Structure

```
dinari-blockchain/
├── cmd/dinari-node/          # Node binary
├── internal/
│   ├── core/                 # Blockchain core logic
│   ├── consensus/            # PoW implementation
│   ├── mempool/              # Transaction pool
│   ├── miner/                # Mining engine
│   ├── p2p/                  # Networking
│   ├── storage/              # Database wrapper
│   └── types/                # Common types
├── pkg/
│   ├── api/                  # JSON-RPC server
│   └── crypto/               # Cryptography
├── config/                   # Configuration files
├── scripts/                  # Helper scripts
└── test/                     # Tests
```

### Running Tests

```bash
# All tests
make test

# Specific package
go test ./pkg/crypto -v
go test ./internal/consensus -v
```

### Building

```bash
# Development build
make build

# Clean build artifacts
make clean
```

## 🔐 Security

- Private keys use secp256k1 elliptic curve cryptography
- Addresses are Base58Check encoded with DT prefix
- Transaction signatures use ECDSA
- Nonce-based replay protection
- Never share your private key or WIF

## 📊 Token Economics

### DINARI (DNT)
- Initial block reward: 50 DNT
- Halving every 210,000 blocks (~36.5 days at 15s/block)
- Total supply cap: 21 million DNT
- Block time: ~15 seconds
- Difficulty adjustment: Every 120 blocks

### Afrocoin (AFC)
- Controlled minting by authorized addresses
- Used for cross-border payments
- All fees paid in DNT

## 🌐 Network Setup

### Running Multiple Nodes

**Node 1 (Miner):**
```bash
./bin/dinari-node \
  --datadir=./node1 \
  --rpc=localhost:8545 \
  --p2p=/ip4/0.0.0.0/tcp/9000 \
  --miner=DT1... \
  --mine
```

**Node 2 (Full Node):**
```bash
./bin/dinari-node \
  --datadir=./node2 \
  --rpc=localhost:8546 \
  --p2p=/ip4/0.0.0.0/tcp/9001
```

Nodes will discover each other via mDNS on the local network.

## 🐛 Troubleshooting

### Port Already in Use
Change the RPC or P2P port:
```bash
./bin/dinari-node --rpc=localhost:8546 --p2p=/ip4/0.0.0.0/tcp/9001
```

### Database Locked
Ensure no other node is using the same data directory.

### Mining Not Starting
Ensure you've specified a valid miner address with `--miner=DT1...`

## 🤝 Contributing

Contributions welcome! Please open an issue or submit a pull request.

## 📄 License

MIT License - see LICENSE file for details

## 🔗 Links

- Documentation: [Coming Soon]
- Explorer: [Coming Soon]
- Discord: [Coming Soon]

---

Built with ❤️ for Africa

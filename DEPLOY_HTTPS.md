# Deploy HTTPS-Enabled Dinari Node

## Quick Deploy (Copy & Paste)

Run these commands on your server as the `dinari` user:

```bash
# Step 1: Navigate to project directory
cd ~/dinari-blockchain-main

# Step 2: Get latest code (with HTTPS support)
git fetch origin
git checkout claude/blockchain-transaction-mining-011CURqd9aKuH4T5opD8qdxg
git pull origin claude/blockchain-transaction-mining-011CURqd9aKuH4T5opD8qdxg

# Step 3: Generate SSL certificate
chmod +x scripts/generate-ssl-cert.sh
echo "52.241.1.239" | ./scripts/generate-ssl-cert.sh ./certs

# Step 4: Rebuild binary with latest code
go build -o ./bin/dinari-node ./cmd/dinari-node

# Step 5: Copy updated service file
sudo cp dinari-node.service /etc/systemd/system/dinari-node.service

# Step 6: Reload and restart
sudo systemctl daemon-reload
sudo systemctl stop dinari-node
sudo systemctl start dinari-node

# Step 7: Check status
sudo systemctl status dinari-node

# Step 8: Watch logs
tail -f ~/dinari-node.log
```

---

## What Changed

### Added to systemd service:
```ini
# HTTPS/TLS Configuration
Environment="RPC_TLS_ENABLED=true"
Environment="RPC_TLS_CERT=/home/dinari/dinari-blockchain-main/certs/server.crt"
Environment="RPC_TLS_KEY=/home/dinari/dinari-blockchain-main/certs/server.key"
```

### Added resource limit:
```ini
LimitNOFILE=65536
```

### All your existing settings preserved:
- ✅ Dev mode (`--dev`)
- ✅ Mining (`--mine`)
- ✅ Miner address (`--miner=DF9CM1gPNpPkE6xUN6A1JUtz2vSygXvtLT`)
- ✅ Validation (`--validate`)
- ✅ Metrics (`--metrics=:9090`)
- ✅ Logging to `/home/dinari/dinari-node.log`
- ✅ Restart policy
- ✅ User/group settings

---

## Verify HTTPS is Working

### Test 1: Check service status
```bash
sudo systemctl status dinari-node
```

**Expected output:**
```
● dinari-node.service - Dinari Blockchain Node
   Loaded: loaded (/etc/systemd/system/dinari-node.service; enabled)
   Active: active (running) since ...
```

### Test 2: Check logs for TLS
```bash
tail -50 ~/dinari-node.log | grep -i tls
```

**Expected output:**
```
✅ RPC server initialized with all handlers
   Protocol: HTTPS (TLS 1.3)
```

### Test 3: Test HTTPS endpoint
```bash
curl -k https://52.241.1.239:8545/ -X POST \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"chain_getHeight","params":{},"id":1}'
```

**Expected response:**
```json
{"jsonrpc":"2.0","result":{"height":1},"id":1}
```

### Test 4: Test from remote (your local machine)
```bash
curl -k https://52.241.1.239:8545/ -X POST \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"miner_status","params":{},"id":1}'
```

---

## Update Blockchain Explorer

Change your explorer's API endpoint:

**Before:**
```javascript
const API_URL = "http://52.241.1.239:8545/";
```

**After:**
```javascript
const API_URL = "https://52.241.1.239:8545/";
```

**Browser Warning:** Self-signed certificates will show a security warning. Click "Advanced" → "Proceed to 52.241.1.239 (unsafe)". This is normal for self-signed certs.

---

## Troubleshooting

### Error: "certificate signed by unknown authority"

**For curl:** Use `-k` flag (already in examples above)

**For Postman:**
1. Settings → General
2. Turn OFF "SSL certificate verification"

**For browsers:** Click "Advanced" → "Proceed anyway"

### Error: "bind: address already in use"

Check what's using port 8545:
```bash
sudo netstat -tlnp | grep 8545
```

Kill the old process if needed:
```bash
sudo pkill dinari-node
sudo systemctl start dinari-node
```

### Error: "permission denied" reading cert files

Fix permissions:
```bash
sudo chown dinari:dinari ~/dinari-blockchain-main/certs/server.crt
sudo chown dinari:dinari ~/dinari-blockchain-main/certs/server.key
chmod 644 ~/dinari-blockchain-main/certs/server.crt
chmod 600 ~/dinari-blockchain-main/certs/server.key
```

### Mining still not working (timestamp errors)

Clean database and restart:
```bash
sudo systemctl stop dinari-node
rm -rf /home/dinari/.dinari/data
rm -rf /home/dinari/.dinari/state
sudo systemctl start dinari-node
tail -f ~/dinari-node.log
```

### Check all files are in place

```bash
# Check SSL certificates exist
ls -la ~/dinari-blockchain-main/certs/server.crt
ls -la ~/dinari-blockchain-main/certs/server.key

# Check binary exists
ls -lh ~/dinari-blockchain-main/bin/dinari-node

# Check service file
cat /etc/systemd/system/dinari-node.service | grep TLS
```

---

## Firewall Configuration

If you have a firewall enabled, allow HTTPS:

```bash
# UFW
sudo ufw allow 8545/tcp

# iptables
sudo iptables -A INPUT -p tcp --dport 8545 -j ACCEPT
sudo netfilter-persistent save
```

---

## Files Created

After deployment, you should have:

```
/home/dinari/dinari-blockchain-main/
├── certs/
│   ├── server.crt          # SSL certificate
│   └── server.key          # Private key
├── bin/
│   └── dinari-node         # Latest binary (with HTTPS + timestamp fix)
├── scripts/
│   └── generate-ssl-cert.sh # SSL generation script
└── docs/
    └── HTTPS_SETUP.md      # Complete HTTPS guide

/etc/systemd/system/
└── dinari-node.service     # Updated service file (with TLS vars)

/home/dinari/
├── dinari-node.log         # Standard output logs
└── dinari-error.log        # Error logs
```

---

## Success Indicators

When everything is working correctly, you should see:

### In logs:
```
✅ RPC server initialized with all handlers
   Protocol: HTTPS (TLS 1.3)
   CORS: Enabled
⛏️  Starting production miner with 2 workers
📋 Template ready: height=1, difficulty=16777216
🎉 VALID BLOCK FOUND!
✅ Block #1 accepted!
💰 Miner reward: 50.00000000 DNT
```

### From curl test:
```json
{"jsonrpc":"2.0","result":{"height":5},"id":1}
```

### In browser (https://52.241.1.239:8545/):
- Shows security warning (normal for self-signed)
- After clicking "Proceed", API responds

---

## Production Upgrade (Let's Encrypt)

For a trusted certificate without browser warnings:

```bash
# Install certbot
sudo apt-get install certbot

# Get domain name certificate
sudo certbot certonly --standalone -d blockchain.yourdomain.com

# Update service file
sudo nano /etc/systemd/system/dinari-node.service

# Change to:
Environment="RPC_TLS_CERT=/etc/letsencrypt/live/blockchain.yourdomain.com/fullchain.pem"
Environment="RPC_TLS_KEY=/etc/letsencrypt/live/blockchain.yourdomain.com/privkey.pem"

# Reload
sudo systemctl daemon-reload
sudo systemctl restart dinari-node
```

---

## Summary

**Old endpoint:** `http://52.241.1.239:8545/`
**New endpoint:** `https://52.241.1.239:8545/`

**Changes:**
- ✅ HTTPS/TLS 1.3 encryption
- ✅ CORS enabled for blockchain explorer
- ✅ Self-signed certificate generated
- ✅ All your existing settings preserved
- ✅ Timestamp validation fixed (24-hour window)
- ✅ Mining APIs enabled
- ✅ Transaction history fixed

**Next:** Update your blockchain explorer to use the HTTPS endpoint!

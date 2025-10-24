# HTTPS Setup Guide for Dinari Blockchain RPC

This guide explains how to enable HTTPS for your Dinari Blockchain RPC server.

## Quick Setup (Self-Signed Certificate)

### Step 1: Generate SSL Certificate

```bash
cd /home/dinari/dinari-blockchain-main
./scripts/generate-ssl-cert.sh ./certs
```

When prompted, enter your server IP: `52.241.1.239`

This creates:
- `./certs/server.crt` - SSL certificate
- `./certs/server.key` - Private key

### Step 2: Update Systemd Service

Edit `/etc/systemd/system/dinari-node.service`:

```ini
[Unit]
Description=Dinari Blockchain Node
After=network.target

[Service]
Type=simple
User=dinari
WorkingDirectory=/home/dinari/dinari-blockchain-main
Environment="RPC_TLS_ENABLED=true"
Environment="RPC_TLS_CERT=/home/dinari/dinari-blockchain-main/certs/server.crt"
Environment="RPC_TLS_KEY=/home/dinari/dinari-blockchain-main/certs/server.key"
ExecStart=/home/dinari/dinari-blockchain-main/bin/dinari-node \
    --datadir=/home/dinari/.dinari \
    --rpc=0.0.0.0:8545 \
    --p2p=/ip4/0.0.0.0/tcp/9000 \
    --mine \
    --miner=YOUR_WALLET_ADDRESS
Restart=always
RestartSec=10
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

### Step 3: Reload and Restart

```bash
sudo systemctl daemon-reload
sudo systemctl restart dinari-node
sudo systemctl status dinari-node
```

### Step 4: Test HTTPS

```bash
# Should work with HTTPS now
curl -k https://52.241.1.239:8545/ -X POST \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"chain_getHeight","params":{},"id":1}'
```

Note: `-k` flag skips certificate verification (needed for self-signed certs)

---

## Production Setup (Let's Encrypt)

For production with a domain name, use Let's Encrypt for a trusted certificate:

### Step 1: Install Certbot

```bash
sudo apt-get update
sudo apt-get install certbot
```

### Step 2: Get Certificate

```bash
# Stop the node temporarily
sudo systemctl stop dinari-node

# Get certificate (replace with your domain)
sudo certbot certonly --standalone -d blockchain.yourdomain.com

# Certificates will be at:
# /etc/letsencrypt/live/blockchain.yourdomain.com/fullchain.pem
# /etc/letsencrypt/live/blockchain.yourdomain.com/privkey.pem
```

### Step 3: Update Service

```ini
Environment="RPC_TLS_ENABLED=true"
Environment="RPC_TLS_CERT=/etc/letsencrypt/live/blockchain.yourdomain.com/fullchain.pem"
Environment="RPC_TLS_KEY=/etc/letsencrypt/live/blockchain.yourdomain.com/privkey.pem"
```

### Step 4: Auto-Renewal

```bash
# Test renewal
sudo certbot renew --dry-run

# Add to crontab for auto-renewal
sudo crontab -e

# Add this line:
0 0 * * * certbot renew --post-hook "systemctl restart dinari-node"
```

---

## Troubleshooting

### Error: "certificate signed by unknown authority"

**For browsers**: Click "Advanced" → "Proceed Anyway" (self-signed only)

**For curl**: Use `-k` flag to skip verification

**For Postman**:
1. Settings → General
2. Turn OFF "SSL certificate verification"

### Error: "bind: address already in use"

Another service is using port 8545. Check with:
```bash
sudo netstat -tlnp | grep 8545
```

### Error: "permission denied" reading cert files

Fix permissions:
```bash
sudo chown dinari:dinari ./certs/server.crt ./certs/server.key
chmod 600 ./certs/server.key
chmod 644 ./certs/server.crt
```

---

## Firewall Configuration

Allow HTTPS traffic:

```bash
# UFW
sudo ufw allow 8545/tcp

# iptables
sudo iptables -A INPUT -p tcp --dport 8545 -j ACCEPT
sudo iptables-save > /etc/iptables/rules.v4
```

---

## Testing from Blockchain Explorer

Update your explorer's API endpoint:

**Old**: `http://52.241.1.239:8545/`
**New**: `https://52.241.1.239:8545/`

If using self-signed certificate, the browser will show a warning. Click "Advanced" → "Proceed".

---

## Security Notes

### Self-Signed Certificates
- ⚠️ Not trusted by browsers (shows warning)
- ⚠️ Vulnerable to man-in-the-middle attacks
- ✅ Good for: Testing, internal networks
- ❌ Bad for: Public production

### Let's Encrypt Certificates
- ✅ Trusted by all browsers
- ✅ Free and auto-renewable
- ✅ Production-ready
- ⚠️ Requires a domain name
- ⚠️ Cannot use with IP addresses

### Additional Hardening

1. **Disable TLS 1.0/1.1**: Already done (TLS 1.3 enforced)
2. **Use strong ciphers**: Already configured
3. **Enable HSTS**: Add reverse proxy (nginx) with HSTS headers
4. **Rate limiting**: Already enabled in production mode
5. **Authentication**: Enable with JWT tokens

---

## CORS Configuration

CORS is already enabled to allow your blockchain explorer to make API calls from the browser.

If you need to restrict origins:

1. Edit `cmd/dinari-node/main.go`
2. Change:
   ```go
   CORSAllowedOrigins: []string{"*"},
   ```
   to:
   ```go
   CORSAllowedOrigins: []string{
       "https://your-explorer-domain.com",
       "https://52.241.1.239",
   },
   ```
3. Rebuild and restart

---

## Summary

✅ **Quick start**: Self-signed certificate with `generate-ssl-cert.sh`
✅ **Production**: Let's Encrypt for trusted certificates
✅ **CORS**: Already enabled for blockchain explorer
✅ **Firewall**: Allow port 8545

Your RPC endpoint is now: `https://52.241.1.239:8545/`

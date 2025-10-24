#!/bin/bash
# Generate self-signed SSL certificate for Dinari Blockchain RPC Server
# Usage: ./scripts/generate-ssl-cert.sh [output-directory]

set -e

OUTPUT_DIR="${1:-./certs}"
CERT_FILE="$OUTPUT_DIR/server.crt"
KEY_FILE="$OUTPUT_DIR/server.key"
DAYS_VALID=365

# Get server IP or hostname
read -p "Enter your server IP or domain (default: 52.241.1.239): " SERVER_HOST
SERVER_HOST=${SERVER_HOST:-52.241.1.239}

echo "🔐 Generating SSL certificate for Dinari Blockchain RPC Server"
echo "   Host: $SERVER_HOST"
echo "   Output directory: $OUTPUT_DIR"
echo ""

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Generate private key and certificate
openssl req -x509 -newkey rsa:4096 -nodes \
    -keyout "$KEY_FILE" \
    -out "$CERT_FILE" \
    -days $DAYS_VALID \
    -subj "/C=US/ST=State/L=City/O=Dinari Blockchain/OU=RPC/CN=$SERVER_HOST" \
    -addext "subjectAltName=IP:$SERVER_HOST,DNS:localhost" \
    2>/dev/null

# Set proper permissions
chmod 600 "$KEY_FILE"
chmod 644 "$CERT_FILE"

echo "✅ SSL certificate generated successfully!"
echo ""
echo "📁 Files created:"
echo "   Certificate: $CERT_FILE"
echo "   Private Key: $KEY_FILE"
echo ""
echo "📋 Next steps:"
echo "   1. Update your config to enable TLS:"
echo "      export RPC_TLS_ENABLED=true"
echo "      export RPC_TLS_CERT=$CERT_FILE"
echo "      export RPC_TLS_KEY=$KEY_FILE"
echo ""
echo "   2. Or use command-line flags:"
echo "      ./dinari-node --tls --tls-cert=$CERT_FILE --tls-key=$KEY_FILE"
echo ""
echo "⚠️  Note: This is a self-signed certificate. Browsers will show a warning."
echo "   For production, use a certificate from a trusted CA (Let's Encrypt, etc.)"

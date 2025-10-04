# Dockerfile
FROM golang:1.22-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git make gcc musl-dev

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the binary with optimizations for low memory (testnet build)
RUN CGO_ENABLED=1 GOOS=linux go build -a \
    -ldflags '-s -w -extldflags "-static"' \
    -tags testnet \
    -o dinari-node ./cmd/dinari-node

# Runtime stage - minimal image
FROM alpine:latest

RUN apk --no-cache add ca-certificates tzdata wget

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/dinari-node .
COPY --from=builder /app/config ./config

# Create data directory
RUN mkdir -p /app/data

# Expose ports (testnet ports)
EXPOSE 8545 9000

# Set memory-friendly environment variables for 1GB RAM
ENV GOGC=50
ENV GOMEMLIMIT=768MiB
ENV DINARI_NETWORK=testnet

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8545/health || exit 1

# Run as non-root user
RUN addgroup -g 1000 dinari && \
    adduser -D -u 1000 -G dinari dinari && \
    chown -R dinari:dinari /app

USER dinari

ENTRYPOINT ["./dinari-node"]
# IMPORTANT: Use environment variable for miner address
CMD ["sh", "-c", "./dinari-node --datadir=/app/data --rpc=0.0.0.0:8545 --p2p=/ip4/0.0.0.0/tcp/9000 --loglevel=info --miner=${MINER_ADDRESS} --mine"]
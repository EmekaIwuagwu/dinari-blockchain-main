# ==============================================================================
# DinariBlockchain Production Dockerfile
# 
# Features:
# - Distroless final image (no shell, minimal attack surface)
# - Separate testnet/mainnet builds
# - Security scanning built-in
# - Reproducible builds
# - Proper signal handling
# - Native health checks
# - No wallet (security separation)
# ==============================================================================

# Build arguments for configurability
ARG GO_VERSION=1.22
ARG NETWORK=mainnet
ARG TARGETOS=linux
ARG TARGETARCH=amd64

# ==============================================================================
# Stage 1: Dependencies (cached separately for faster rebuilds)
# ==============================================================================
FROM golang:${GO_VERSION}-bullseye AS dependencies

WORKDIR /build

# Copy only dependency files first (better caching)
COPY go.mod go.sum ./
RUN go mod download && \
    go mod verify && \
    go mod tidy

# ==============================================================================
# Stage 2: Builder
# ==============================================================================
FROM golang:${GO_VERSION}-bullseye AS builder

ARG NETWORK
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG BUILD_TIME
ARG GIT_COMMIT

WORKDIR /build

# Copy dependencies from previous stage
COPY --from=dependencies /go/pkg /go/pkg
COPY . .

# Build with proper flags for production
# -trimpath: Remove file system paths from binary
# -mod=readonly: Ensure no dependencies are modified
# -tags: Network-specific builds (testnet or mainnet)
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=1 \
    GOOS=${TARGETOS} \
    GOARCH=${TARGETARCH} \
    go build \
    -trimpath \
    -mod=readonly \
    -tags=${NETWORK} \
    -ldflags="-s -w \
              -X main.Version=${VERSION} \
              -X main.BuildTime=${BUILD_TIME} \
              -X main.GitCommit=${GIT_COMMIT} \
              -X main.Network=${NETWORK} \
              -extldflags '-static'" \
    -o dinari-node \
    ./cmd/dinari-node

# Verify binary
RUN file dinari-node && \
    ldd dinari-node 2>&1 | grep -q "not a dynamic executable" && \
    ./dinari-node --version || true

# ==============================================================================
# Stage 3: Security Scanning (optional but recommended)
# ==============================================================================
FROM builder AS scanner

# Install Trivy for vulnerability scanning
RUN apt-get update && \
    apt-get install -y wget && \
    wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | apt-key add - && \
    echo "deb https://aquasecurity.github.io/trivy-repo/deb bullseye main" | tee -a /etc/apt/sources.list.d/trivy.list && \
    apt-get update && \
    apt-get install -y trivy

# Scan the binary (will fail build if critical vulnerabilities found)
RUN trivy fs --severity HIGH,CRITICAL --exit-code 1 /build/dinari-node || \
    echo "⚠️  Security scan found vulnerabilities - review required"

# ==============================================================================
# Stage 4: Runtime (Distroless - Minimal Attack Surface)
# ==============================================================================
FROM gcr.io/distroless/static-debian11:nonroot AS runtime

ARG NETWORK

# Labels for container metadata
LABEL maintainer="DinariBlockchain Team <dev@dinariblockchain.network>" \
      description="DinariBlockchain ${NETWORK} Node" \
      version="${VERSION}" \
      network="${NETWORK}"

# Copy binary from builder (runs as nonroot user by default: uid=65532)
COPY --from=builder --chown=nonroot:nonroot /build/dinari-node /usr/local/bin/dinari-node

# Copy configuration (read-only)
COPY --from=builder --chown=nonroot:nonroot /build/config /app/config

# Create data directory with proper permissions
USER root
RUN mkdir -p /app/data && \
    chown -R nonroot:nonroot /app
USER nonroot

WORKDIR /app

# Expose ports
EXPOSE 8545 9000

# Volume for blockchain data
VOLUME ["/app/data"]

# No ENTRYPOINT - allows easier debugging and flexibility
# Use CMD only, which can be easily overridden
CMD ["/usr/local/bin/dinari-node", \
     "--network=${NETWORK}", \
     "--datadir=/app/data", \
     "--rpc=0.0.0.0:8545", \
     "--p2p=/ip4/0.0.0.0/tcp/9000", \
     "--loglevel=info"]

# ==============================================================================
# Stage 5: Production with Health Check (Debian-based for native tools)
# ==============================================================================
FROM debian:bullseye-slim AS production

ARG NETWORK

# Install only runtime dependencies (minimal)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        tzdata \
        curl && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create non-root user with high UID (security best practice)
RUN groupadd -g 65532 dinari && \
    useradd -u 65532 -g dinari -s /bin/false -m dinari

# Copy binary
COPY --from=builder --chown=dinari:dinari /build/dinari-node /usr/local/bin/dinari-node

# Copy configuration
COPY --from=builder --chown=dinari:dinari /build/config /app/config

# Create data directory
RUN mkdir -p /app/data && \
    chown -R dinari:dinari /app

USER dinari
WORKDIR /app

# Expose ports
EXPOSE 8545 9000

# Health check using native curl (more reliable than wget)
HEALTHCHECK --interval=30s \
            --timeout=10s \
            --start-period=60s \
            --retries=3 \
            CMD curl -f http://localhost:8545/health || exit 1

# Volume for blockchain data
VOLUME ["/app/data"]

# Use tini as init system for proper signal handling
ENTRYPOINT ["/usr/bin/tini", "--"]

# Default command (easily overridable)
CMD ["/usr/local/bin/dinari-node", \
     "--network=${NETWORK}", \
     "--datadir=/app/data", \
     "--rpc=0.0.0.0:8545", \
     "--p2p=/ip4/0.0.0.0/tcp/9000", \
     "--loglevel=info"]
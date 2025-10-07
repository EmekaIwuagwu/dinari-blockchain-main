# DinariBlockchain Makefile

.PHONY: help init build build-linux build-windows build-all clean test run wallet

# Binary names
BINARY_NAME=dinari-node
WALLET_BINARY=dinari-wallet
BUILD_DIR=./bin
MAIN_PATH=./cmd/dinari-node
WALLET_PATH=./cmd/dinari-wallet

# Detect OS
ifeq ($(OS),Windows_NT)
    DETECTED_OS := Windows
    BINARY_EXT=.exe
    RM=powershell -Command Remove-Item -Recurse -Force
else
    DETECTED_OS := $(shell uname -s)
    BINARY_EXT=
    RM=rm -rf
endif

BINARY_FULL=$(BINARY_NAME)$(BINARY_EXT)
WALLET_BINARY_FULL=$(WALLET_BINARY)$(BINARY_EXT)

# Build information (optional - for version tracking)
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME=$(shell date -u '+%Y-%m-%d_%H:%M:%S')
LDFLAGS=-ldflags "-X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME)"

## help: Display available commands
help:
	@echo "DinariBlockchain - Build Commands"
	@echo ""
	@echo "  make init            - Initialize project and install dependencies"
	@echo "  make build           - Build for current OS ($(DETECTED_OS))"
	@echo "  make build-linux     - Build for Linux (64-bit)"
	@echo "  make build-windows   - Build for Windows (64-bit)"
	@echo "  make build-all       - Build for all platforms"
	@echo "  make test            - Run all tests"
	@echo "  make test-coverage   - Run tests with coverage report"
	@echo "  make clean           - Clean build artifacts"
	@echo "  make run             - Build and run node"
	@echo "  make wallet          - Run wallet CLI"
	@echo "  make lint            - Run code linters (requires golangci-lint)"
	@echo "  make fmt             - Format code"
	@echo ""

## init: Initialize project and download dependencies
init:
	@echo "Initializing DinariBlockchain..."
	@go mod download
	@go mod verify
	@mkdir -p $(BUILD_DIR)
	@echo "✅ Project initialized successfully"

## build: Build for current OS (both node and wallet)
build:
	@echo "Building for $(DETECTED_OS)..."
	@mkdir -p $(BUILD_DIR)
	@echo "Building dinari-node..."
	@go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_FULL) $(MAIN_PATH)
	@echo "Building dinari-wallet..."
	@go build $(LDFLAGS) -o $(BUILD_DIR)/$(WALLET_BINARY_FULL) $(WALLET_PATH)
	@echo "✅ Build complete:"
	@echo "   - $(BUILD_DIR)/$(BINARY_FULL)"
	@echo "   - $(BUILD_DIR)/$(WALLET_BINARY_FULL)"

## build-linux: Build for Linux (64-bit)
build-linux:
	@echo "Building for Linux (amd64)..."
	@mkdir -p $(BUILD_DIR)/linux
	@echo "Building dinari-node for Linux..."
	@GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/linux/$(BINARY_NAME) $(MAIN_PATH)
	@echo "Building dinari-wallet for Linux..."
	@GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/linux/$(WALLET_BINARY) $(WALLET_PATH)
	@echo "✅ Linux build complete:"
	@echo "   - $(BUILD_DIR)/linux/$(BINARY_NAME)"
	@echo "   - $(BUILD_DIR)/linux/$(WALLET_BINARY)"

## build-windows: Build for Windows (64-bit)
build-windows:
	@echo "Building for Windows (amd64)..."
	@mkdir -p $(BUILD_DIR)/windows
	@echo "Building dinari-node for Windows..."
	@GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/windows/$(BINARY_NAME).exe $(MAIN_PATH)
	@echo "Building dinari-wallet for Windows..."
	@GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/windows/$(WALLET_BINARY).exe $(WALLET_PATH)
	@echo "✅ Windows build complete:"
	@echo "   - $(BUILD_DIR)/windows/$(BINARY_NAME).exe"
	@echo "   - $(BUILD_DIR)/windows/$(WALLET_BINARY).exe"

## build-all: Build for all platforms
build-all: build-linux build-windows
	@echo ""
	@echo "✅ All platforms built successfully!"
	@echo ""
	@echo "Linux binaries:"
	@ls -lh $(BUILD_DIR)/linux/ 2>/dev/null || echo "  (build with 'make build-linux')"
	@echo ""
	@echo "Windows binaries:"
	@ls -lh $(BUILD_DIR)/windows/ 2>/dev/null || echo "  (build with 'make build-windows')"
	@echo ""

## test: Run all tests
test:
	@echo "Running tests..."
	@go test -v ./...
	@echo "✅ Tests complete"

## test-coverage: Run tests with coverage report
test-coverage:
	@echo "Running tests with coverage..."
	@go test -v -coverprofile=coverage.out ./...
	@go tool cover -html=coverage.out -o coverage.html
	@echo "✅ Coverage report generated: coverage.html"

## fmt: Format code
fmt:
	@echo "Formatting code..."
	@go fmt ./...
	@echo "✅ Code formatted"

## lint: Run linters (requires golangci-lint)
lint:
	@echo "Running linters..."
	@which golangci-lint > /dev/null || (echo "golangci-lint not installed. Install: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest" && exit 1)
	@golangci-lint run ./...
	@echo "✅ Linting complete"

## clean: Remove build artifacts
clean:
	@echo "Cleaning build artifacts..."
	@$(RM) $(BUILD_DIR)
	@go clean
	@echo "✅ Clean complete"

## run: Build and run the node
run: build
	@echo "Starting DinariBlockchain node..."
	@$(BUILD_DIR)/$(BINARY_FULL)

## wallet: Build and run wallet CLI
wallet: build
	@echo "Starting Dinari Wallet..."
	@$(BUILD_DIR)/$(WALLET_BINARY_FULL)

## docker-build: Build Docker image
docker-build:
	@echo "Building Docker image..."
	@docker build -t dinari-blockchain:latest .
	@echo "✅ Docker image built: dinari-blockchain:latest"

## docker-run: Run node in Docker
docker-run:
	@echo "Starting node in Docker..."
	@docker-compose up -d
	@echo "✅ Node started. Check logs: docker-compose logs -f"

## docker-stop: Stop Docker container
docker-stop:
	@docker-compose down
	@echo "✅ Docker containers stopped"
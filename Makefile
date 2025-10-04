# DinariBlockchain Makefile

.PHONY: help init build build-linux build-windows build-all clean test run

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
	@echo "  make clean           - Clean build artifacts"
	@echo "  make run             - Build and run node"
	@echo ""

## init: Initialize project and download dependencies
init:
	@echo "Initializing DinariBlockchain..."
	@go mod download
	@go mod verify
	@echo "✅ Project initialized successfully"

## build: Build for current OS
build:
	@echo "Building for $(DETECTED_OS)..."
	@mkdir -p $(BUILD_DIR)
	@echo "Building dinari-node..."
	@go build -o $(BUILD_DIR)/$(BINARY_FULL) $(MAIN_PATH)
	@echo "Building dinari-wallet..."
	@go build -o $(BUILD_DIR)/$(WALLET_BINARY_FULL) $(WALLET_PATH)
	@echo "✅ Build complete:"
	@echo "   - $(BUILD_DIR)/$(BINARY_FULL)"
	@echo "   - $(BUILD_DIR)/$(WALLET_BINARY_FULL)"

## build-linux: Build for Linux (64-bit)
build-linux:
	@echo "Building for Linux (amd64)..."
	@mkdir -p $(BUILD_DIR)/linux
	@echo "Building dinari-node for Linux..."
	@GOOS=linux GOARCH=amd64 go build -o $(BUILD_DIR)/linux/$(BINARY_NAME) $(MAIN_PATH)
	@echo "Building dinari-wallet for Linux..."
	@GOOS=linux GOARCH=amd64 go build -o $(BUILD_DIR)/linux/$(WALLET_BINARY) $(WALLET_PATH)
	@echo "✅ Linux build complete:"
	@echo "   - $(BUILD_DIR)/linux/$(BINARY_NAME)"
	@echo "   - $(BUILD_DIR)/linux/$(WALLET_BINARY)"

## build-windows: Build for Windows (64-bit)
build-windows:
	@echo "Building for Windows (amd64)..."
	@mkdir -p $(BUILD_DIR)/windows
	@echo "Building dinari-node for Windows..."
	@GOOS=windows GOARCH=amd64 go build -o $(BUILD_DIR)/windows/$(BINARY_NAME).exe $(MAIN_PATH)
	@echo "Building dinari-wallet for Windows..."
	@GOOS=windows GOARCH=amd64 go build -o $(BUILD_DIR)/windows/$(WALLET_BINARY).exe $(WALLET_PATH)
	@echo "✅ Windows build complete:"
	@echo "   - $(BUILD_DIR)/windows/$(BINARY_NAME).exe"
	@echo "   - $(BUILD_DIR)/windows/$(WALLET_BINARY).exe"

## build-all: Build for all platforms
build-all: build-linux build-windows
	@echo ""
	@echo "✅ All platforms built successfully!"
	@echo ""
	@echo "Linux binaries:"
	@ls -lh $(BUILD_DIR)/linux/
	@echo ""
	@echo "Windows binaries:"
	@ls -lh $(BUILD_DIR)/windows/ || dir $(BUILD_DIR)\windows\
	@echo ""

## test: Run all tests
test:
	@echo "Running tests..."
	@go test -v ./...

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
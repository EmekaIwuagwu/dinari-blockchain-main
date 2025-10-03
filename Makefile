# DinariBlockchain Makefile

.PHONY: help init build run test clean

BINARY_NAME=dinari-node
BUILD_DIR=./bin
MAIN_PATH=./cmd/dinari-node

# Detect Windows and add .exe extension
ifeq ($(OS),Windows_NT)
    BINARY_EXT=.exe
    RM=powershell -Command Remove-Item -Recurse -Force
else
    BINARY_EXT=
    RM=rm -rf
endif

BINARY_FULL=$(BINARY_NAME)$(BINARY_EXT)

## help: Display available commands
help:
	@echo "DinariBlockchain - Available Commands:"
	@echo ""
	@echo "  make init      - Initialize project and install dependencies"
	@echo "  make build     - Build the dinari-node binary"
	@echo "  make run       - Run node with default config"
	@echo "  make test      - Run all tests"
	@echo "  make clean     - Clean build artifacts"
	@echo ""

## init: Initialize project and download dependencies
init:
	@echo "Initializing DinariBlockchain..."
	@go mod download
	@go mod verify
	@echo "Project initialized successfully"

## build: Build the dinari-node binary

## build-wallet: Build the wallet CLI
build-wallet:
	@echo "Building dinari-wallet..."
	@go build -o ./bin/dinari-wallet.exe ./cmd/dinari-wallet
	@echo "Build complete: ./bin/dinari-wallet.exe"

build:
	@echo "Building dinari-node..."
	@go build -o $(BUILD_DIR)/$(BINARY_FULL) $(MAIN_PATH)
	@echo "Build complete: $(BUILD_DIR)/$(BINARY_FULL)"

## run: Run the node
run: build
	@echo "Starting DinariBlockchain node..."
	@$(BUILD_DIR)/$(BINARY_FULL)

## test: Run all tests
test:
	@echo "Running tests..."
	@go test -v ./...

## clean: Remove build artifacts
clean:
	@echo "Cleaning..."
	@$(RM) $(BUILD_DIR)
	@go clean
	@echo "Clean complete"
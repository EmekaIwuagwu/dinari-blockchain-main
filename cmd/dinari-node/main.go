package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/EmekaIwuagwu/dinari-blockchain/internal/core"
	"github.com/EmekaIwuagwu/dinari-blockchain/internal/mempool"
	"github.com/EmekaIwuagwu/dinari-blockchain/internal/miner"
	"github.com/EmekaIwuagwu/dinari-blockchain/internal/p2p"
	"github.com/EmekaIwuagwu/dinari-blockchain/internal/storage"
	"github.com/EmekaIwuagwu/dinari-blockchain/pkg/api"
	"github.com/EmekaIwuagwu/dinari-blockchain/pkg/crypto"
	"go.uber.org/zap"
)

const (
	defaultDataDir    = "./data"
	defaultRPCAddr    = "localhost:8545"
	defaultP2PAddr    = "/ip4/0.0.0.0/tcp/9000"
	defaultLogLevel   = "info"
)

var (
	// Command-line flags
	dataDir      = flag.String("datadir", defaultDataDir, "Data directory")
	rpcAddr      = flag.String("rpc", defaultRPCAddr, "RPC server address")
	p2pAddr      = flag.String("p2p", defaultP2PAddr, "P2P listen address")
	minerAddr    = flag.String("miner", "", "Miner address (D-prefixed)")
	autoMine     = flag.Bool("mine", false, "Start mining automatically")
	logLevel     = flag.String("loglevel", defaultLogLevel, "Log level (debug, info, warn, error)")
	bootNodes    = flag.String("bootnodes", "", "Comma-separated list of boot nodes")
	createWallet = flag.Bool("create-wallet", false, "Create a new wallet and exit")
)

// GenesisConfig represents the genesis configuration structure
type GenesisConfig struct {
	MintAuthorities struct {
		AFC []string `json:"afc"`
	} `json:"mintAuthorities"`
}

func main() {
	flag.Parse()

	// Handle wallet creation
	if *createWallet {
		handleCreateWallet()
		return
	}

	// Initialize logger
	logger, err := initLogger(*logLevel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	defer logger.Sync()

	// Validate miner configuration
	if err := validateMinerConfig(logger); err != nil {
		logger.Fatal("❌ Invalid miner configuration", zap.Error(err))
	}

	logger.Info("🚀 Starting DinariBlockchain node",
		zap.String("dataDir", *dataDir),
		zap.String("rpcAddr", *rpcAddr),
		zap.String("p2pAddr", *p2pAddr),
		zap.String("minerAddr", *minerAddr),
		zap.Bool("autoMine", *autoMine),
		zap.String("logLevel", *logLevel))

	// Initialize storage
	db, err := storage.NewDB(&storage.Config{
		Path:   *dataDir + "/blockchain",
		Logger: logger,
	})
	if err != nil {
		logger.Fatal("Failed to initialize database", zap.Error(err))
	}
	defer db.Close()

	// Load genesis configuration to get mint authorities
	mintAuthorities := loadMintAuthorities(logger)
	if len(mintAuthorities) > 0 {
		logger.Info("✅ Loaded mint authorities from genesis",
			zap.Int("count", len(mintAuthorities)),
			zap.Strings("addresses", mintAuthorities))
	} else {
		logger.Warn("⚠️  No mint authorities loaded - AFC minting will be disabled")
	}

	// Initialize blockchain
	blockchain, err := core.NewBlockchain(&core.Config{
		DB:              db,
		Logger:          logger,
		MintAuthorities: mintAuthorities,
	})
	if err != nil {
		logger.Fatal("Failed to initialize blockchain", zap.Error(err))
	}

	// Initialize mempool
	mp := mempool.NewMempool(blockchain.GetState(), logger)

	// Initialize miner
	if *minerAddr == "" {
		logger.Warn("⚠️  No miner address specified, mining will be disabled")
	} else {
		logger.Info("✅ Miner configured",
			zap.String("address", *minerAddr),
			zap.Bool("autoStart", *autoMine))
	}

	minerInstance := miner.NewMiner(&miner.Config{
		Blockchain:   blockchain,
		Mempool:      mp,
		Logger:       logger,
		MinerAddress: *minerAddr,
	})

	// Start mining if requested
	if *autoMine && *minerAddr != "" {
		logger.Info("⛏️  Starting mining...")
		if err := minerInstance.Start(); err != nil {
			logger.Fatal("Failed to start miner", zap.Error(err))
		}
		logger.Info("✅ Mining started successfully",
			zap.String("miner", *minerAddr))
	}

	// Initialize P2P node
	var bootNodeList []string
	if *bootNodes != "" {
		// TODO: Parse comma-separated boot nodes
		bootNodeList = []string{}
	}

	p2pNode, err := p2p.NewNode(&p2p.Config{
		ListenAddr: *p2pAddr,
		Blockchain: blockchain,
		Mempool:    mp,
		Logger:     logger,
		BootNodes:  bootNodeList,
	})
	if err != nil {
		logger.Fatal("Failed to initialize P2P node", zap.Error(err))
	}
	defer p2pNode.Stop()

	// Initialize RPC server
	rpcServer := api.NewRPCServer(&api.Config{
		Blockchain: blockchain,
		Mempool:    mp,
		Miner:      minerInstance,
		Logger:     logger,
		Address:    *rpcAddr,
	})

	// Start RPC server in goroutine
	go func() {
		logger.Info("🌐 Starting RPC server", zap.String("address", *rpcAddr))
		if err := rpcServer.Start(*rpcAddr); err != nil {
			logger.Error("RPC server error", zap.Error(err))
		}
	}()

	// Print node info
	logger.Info("✅ Node started successfully",
		zap.Uint64("chainHeight", blockchain.GetHeight()),
		zap.Int("peerCount", p2pNode.GetPeerCount()))

	// Print banner with useful information
	printBanner(logger, *minerAddr, *autoMine, blockchain.GetHeight())

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	sig := <-sigChan
	logger.Info("📡 Received shutdown signal", zap.String("signal", sig.String()))

	// Graceful shutdown
	logger.Info("🛑 Shutting down...")

	if minerInstance.IsRunning() {
		logger.Info("Stopping miner...")
		minerInstance.Stop()
	}

	if err := rpcServer.Stop(); err != nil {
		logger.Error("Error stopping RPC server", zap.Error(err))
	}

	logger.Info("👋 Node stopped successfully")
}

// validateMinerConfig validates miner configuration
func validateMinerConfig(logger *zap.Logger) error {
	// If mining is enabled, miner address is required
	if *autoMine && *minerAddr == "" {
		return fmt.Errorf("mining enabled but no miner address specified. Use --miner=<D-address> flag")
	}

	// If miner address is provided, validate it
	if *minerAddr != "" {
		// Check if it's a valid D-prefix address
		if err := crypto.ValidateAddress(*minerAddr); err != nil {
			return fmt.Errorf("invalid miner address format: %w (expected D-prefix address like D61GJ9HxAz...)", err)
		}

		// Check if address starts with 'D'
		if len(*minerAddr) < 1 || (*minerAddr)[0] != 'D' {
			return fmt.Errorf("miner address must start with 'D', got: %s", *minerAddr)
		}

		logger.Info("✅ Miner address validated successfully",
			zap.String("address", *minerAddr))
	}

	return nil
}

// loadMintAuthorities loads mint authorities from genesis.json
func loadMintAuthorities(logger *zap.Logger) []string {
	genesisFile := "./config/genesis.json"

	// Read genesis file
	genesisData, err := os.ReadFile(genesisFile)
	if err != nil {
		logger.Warn("Could not read genesis file, no mint authorities loaded",
			zap.String("file", genesisFile),
			zap.Error(err))
		return []string{}
	}

	// Parse genesis config
	var genesisConfig GenesisConfig
	if err := json.Unmarshal(genesisData, &genesisConfig); err != nil {
		logger.Warn("Could not parse genesis file",
			zap.String("file", genesisFile),
			zap.Error(err))
		return []string{}
	}

	// Validate all mint authority addresses
	validAuthorities := []string{}
	for _, addr := range genesisConfig.MintAuthorities.AFC {
		if err := crypto.ValidateAddress(addr); err != nil {
			logger.Warn("Invalid mint authority address in genesis, skipping",
				zap.String("address", addr),
				zap.Error(err))
			continue
		}
		validAuthorities = append(validAuthorities, addr)
	}

	return validAuthorities
}

// initLogger initializes the logger with the specified level
func initLogger(level string) (*zap.Logger, error) {
	var zapLevel zap.AtomicLevel

	switch level {
	case "debug":
		zapLevel = zap.NewAtomicLevelAt(zap.DebugLevel)
	case "info":
		zapLevel = zap.NewAtomicLevelAt(zap.InfoLevel)
	case "warn":
		zapLevel = zap.NewAtomicLevelAt(zap.WarnLevel)
	case "error":
		zapLevel = zap.NewAtomicLevelAt(zap.ErrorLevel)
	default:
		zapLevel = zap.NewAtomicLevelAt(zap.InfoLevel)
	}

	config := zap.Config{
		Level:            zapLevel,
		Development:      false,
		Encoding:         "console",
		EncoderConfig:    zap.NewDevelopmentEncoderConfig(),
		OutputPaths:      []string{"stdout"},
		ErrorOutputPaths: []string{"stderr"},
	}

	return config.Build()
}

// handleCreateWallet creates a new wallet and prints the details
func handleCreateWallet() {
	// Generate private key
	privKey, err := crypto.GeneratePrivateKey()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to generate private key: %v\n", err)
		os.Exit(1)
	}

	// Derive public key
	pubKey := crypto.DerivePublicKey(privKey)

	// Generate address (should be D-prefix)
	address := crypto.PublicKeyToAddress(pubKey)

	// Validate generated address
	if len(address) < 1 || address[0] != 'D' {
		fmt.Fprintf(os.Stderr, "Warning: Generated address doesn't start with 'D': %s\n", address)
		fmt.Fprintf(os.Stderr, "This might indicate an issue with address generation.\n")
	}

	// Convert to WIF
	wif, err := crypto.PrivateKeyToWIF(privKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to convert to WIF: %v\n", err)
		os.Exit(1)
	}

	// Print wallet details
	fmt.Println("╔════════════════════════════════════════════════════════════╗")
	fmt.Println("║          🎉 New Wallet Created Successfully! 🎉            ║")
	fmt.Println("╚════════════════════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Printf("Address (D-prefix):  %s\n", address)
	fmt.Printf("Private Key (Hex):   %s\n", crypto.PrivateKeyToHex(privKey))
	fmt.Printf("Private Key (WIF):   %s\n", wif)
	fmt.Printf("Public Key:          %s\n", crypto.PublicKeyToHex(pubKey))
	fmt.Println()
	fmt.Println("╔════════════════════════════════════════════════════════════╗")
	fmt.Println("║                    ⚠️  IMPORTANT! ⚠️                        ║")
	fmt.Println("╚════════════════════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Println("1. SAVE YOUR PRIVATE KEY SECURELY!")
	fmt.Println("2. Never share your private key with anyone")
	fmt.Println("3. Store it in a secure password manager")
	fmt.Println("4. Losing your private key means losing access to your funds")
	fmt.Println()
	fmt.Println("To use this wallet for mining, run:")
	fmt.Printf("  ./dinari-node --miner=%s --mine\n", address)
	fmt.Println()
}

// printBanner prints a helpful banner with node information
func printBanner(logger *zap.Logger, minerAddr string, mining bool, height uint64) {
	fmt.Println()
	fmt.Println("╔════════════════════════════════════════════════════════════╗")
	fmt.Println("║         DinariBlockchain Node - Running Successfully       ║")
	fmt.Println("╚════════════════════════════════════════════════════════════╝")
	fmt.Println()
	
	fmt.Printf("📊 Blockchain Height: %d\n", height)
	fmt.Printf("🌐 RPC Endpoint:      http://%s\n", *rpcAddr)
	fmt.Printf("🔗 P2P Address:       %s\n", *p2pAddr)
	
	if minerAddr != "" {
		fmt.Printf("⛏️  Miner Address:     %s\n", minerAddr)
		if mining {
			fmt.Println("✅ Mining Status:     ACTIVE")
		} else {
			fmt.Println("⏸️  Mining Status:     READY (use --mine to start)")
		}
	} else {
		fmt.Println("⚠️  Mining Status:     DISABLED (no miner address)")
	}
	
	fmt.Println()
	fmt.Println("Useful Commands:")
	fmt.Println("────────────────────────────────────────────────────────────")
	fmt.Println()
	
	// Check balance
	fmt.Println("Check Balance:")
	if minerAddr != "" {
		fmt.Printf("  curl -X POST http://%s \\\n", *rpcAddr)
		fmt.Println("    -H \"Content-Type: application/json\" \\")
		fmt.Printf("    -d '{\"jsonrpc\":\"2.0\",\"method\":\"wallet_balance\",\"params\":{\"address\":\"%s\"},\"id\":1}'\n", minerAddr)
	} else {
		fmt.Printf("  curl -X POST http://%s \\\n", *rpcAddr)
		fmt.Println("    -H \"Content-Type: application/json\" \\")
		fmt.Println("    -d '{\"jsonrpc\":\"2.0\",\"method\":\"wallet_balance\",\"params\":{\"address\":\"YOUR_D_ADDRESS\"},\"id\":1}'")
	}
	
	fmt.Println()
	
	// Chain height
	fmt.Println("Get Chain Height:")
	fmt.Printf("  curl -X POST http://%s \\\n", *rpcAddr)
	fmt.Println("    -H \"Content-Type: application/json\" \\")
	fmt.Println("    -d '{\"jsonrpc\":\"2.0\",\"method\":\"chain_getHeight\",\"params\":{},\"id\":1}'")
	
	fmt.Println()
	
	// Miner status
	fmt.Println("Check Miner Status:")
	fmt.Printf("  curl -X POST http://%s \\\n", *rpcAddr)
	fmt.Println("    -H \"Content-Type: application/json\" \\")
	fmt.Println("    -d '{\"jsonrpc\":\"2.0\",\"method\":\"miner_status\",\"params\":{},\"id\":1}'")
	
	fmt.Println()
	fmt.Println("╔════════════════════════════════════════════════════════════╗")
	fmt.Println("║                Press Ctrl+C to stop the node               ║")
	fmt.Println("╚════════════════════════════════════════════════════════════╝")
	fmt.Println()
}
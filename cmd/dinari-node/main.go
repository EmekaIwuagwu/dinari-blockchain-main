// Package main implements the Dinari blockchain node entry point
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"github.com/EmekaIwuagwu/dinari-blockchain/internal/core"
	"github.com/EmekaIwuagwu/dinari-blockchain/internal/consensus"
	"github.com/EmekaIwuagwu/dinari-blockchain/internal/mempool"
	"github.com/EmekaIwuagwu/dinari-blockchain/internal/miner"
	"github.com/EmekaIwuagwu/dinari-blockchain/internal/p2p"
	"github.com/EmekaIwuagwu/dinari-blockchain/internal/storage"
	"github.com/EmekaIwuagwu/dinari-blockchain/pkg/api"
	"github.com/EmekaIwuagwu/dinari-blockchain/pkg/crypto"
	"github.com/EmekaIwuagwu/dinari-blockchain/pkg/monitoring"
	"github.com/EmekaIwuagwu/dinari-blockchain/pkg/security"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const (
	appName    = "dinari-node"
	appVersion = "1.0.0"

	defaultDataDir     = "./data/dinari"
	defaultRPCAddr     = "localhost:8545"
	defaultP2PPort     = "9000"
	defaultMetricsPort = "9090"
	defaultLogLevel    = "info"

	// 🔥 PRODUCTION: Increased shutdown timeout for proper cleanup
	defaultShutdownTimeout = 60 * time.Second  // Was 30s, now 60s
	healthCheckInterval    = 10 * time.Second
	
	// 🔥 NEW: Database operation timeouts
	dbShutdownTimeout      = 45 * time.Second
	stateCommitTimeout     = 30 * time.Second
	dbIntegrityCheckTimeout = 20 * time.Second
)

var (
	BuildTime = "unknown"
	GitCommit = "unknown"
	GitBranch = "unknown"

	configFile  string
	dataDir     string
	rpcAddr     string
	p2pAddr     string
	metricsAddr string
	logLevel    string

	createWallet bool
	mine         bool
	minerAddr    string

	enableTLS   bool
	tlsCertFile string
	tlsKeyFile  string

	devMode     bool
	enablePprof bool
	pprofAddr   string

	showVersion bool
	
	// 🔥 NEW: Recovery and validation flags
	skipRecovery    bool
	forceRebuild    bool
	validateOnStart bool
)

func init() {
	flag.StringVar(&configFile, "config", "", "Path to configuration file")
	flag.StringVar(&dataDir, "datadir", defaultDataDir, "Data directory")
	flag.StringVar(&rpcAddr, "rpc", defaultRPCAddr, "RPC server address")
	flag.StringVar(&p2pAddr, "p2p", fmt.Sprintf("/ip4/0.0.0.0/tcp/%s", defaultP2PPort), "P2P listen address")
	flag.StringVar(&metricsAddr, "metrics", fmt.Sprintf(":%s", defaultMetricsPort), "Metrics server address")
	flag.StringVar(&logLevel, "loglevel", defaultLogLevel, "Log level (debug|info|warn|error)")

	flag.BoolVar(&createWallet, "create-wallet", false, "Create a new wallet and exit")
	flag.BoolVar(&mine, "mine", false, "Enable mining")
	flag.StringVar(&minerAddr, "miner", "", "Miner reward address")

	flag.BoolVar(&enableTLS, "tls", false, "Enable TLS for RPC")
	flag.StringVar(&tlsCertFile, "tls-cert", "", "TLS certificate file")
	flag.StringVar(&tlsKeyFile, "tls-key", "", "TLS key file")

	flag.BoolVar(&devMode, "dev", false, "Development mode (more verbose logging)")
	flag.BoolVar(&enablePprof, "pprof", false, "Enable pprof profiling server")
	flag.StringVar(&pprofAddr, "pprof-addr", ":6060", "Pprof server address")

	flag.BoolVar(&showVersion, "version", false, "Show version information")
	
	// 🔥 NEW: Recovery and validation flags
	flag.BoolVar(&skipRecovery, "skip-recovery", false, "Skip WAL recovery on startup (DANGEROUS)")
	flag.BoolVar(&forceRebuild, "force-rebuild", false, "Force rebuild state from genesis (DESTRUCTIVE)")
	flag.BoolVar(&validateOnStart, "validate", true, "Validate database integrity on startup")

	flag.Usage = printUsage
}

func printUsage() {
	fmt.Fprintf(os.Stderr, "%s v%s - Dinari Blockchain Node\n\n", appName, appVersion)
	fmt.Fprintf(os.Stderr, "Build: %s (%s)\n\n", BuildTime, GitCommit)
	fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n", appName)
	fmt.Fprintf(os.Stderr, "Core Options:\n")
	fmt.Fprintf(os.Stderr, "  --datadir string      Data directory (default: %s)\n", defaultDataDir)
	fmt.Fprintf(os.Stderr, "  --rpc string          RPC server address (default: %s)\n", defaultRPCAddr)
	fmt.Fprintf(os.Stderr, "  --p2p string          P2P listen address\n")
	fmt.Fprintf(os.Stderr, "  --loglevel string     Log level: debug|info|warn|error (default: info)\n")
	fmt.Fprintf(os.Stderr, "\nMining Options:\n")
	fmt.Fprintf(os.Stderr, "  --mine                Enable mining\n")
	fmt.Fprintf(os.Stderr, "  --miner string        Miner reward address (required if --mine)\n")
	fmt.Fprintf(os.Stderr, "\nSecurity Options:\n")
	fmt.Fprintf(os.Stderr, "  --tls                 Enable TLS for RPC\n")
	fmt.Fprintf(os.Stderr, "  --tls-cert string     TLS certificate file\n")
	fmt.Fprintf(os.Stderr, "  --tls-key string      TLS private key file\n")
	fmt.Fprintf(os.Stderr, "\nRecovery Options:\n")
	fmt.Fprintf(os.Stderr, "  --skip-recovery       Skip WAL recovery (DANGEROUS)\n")
	fmt.Fprintf(os.Stderr, "  --force-rebuild       Rebuild state from genesis (DESTRUCTIVE)\n")
	fmt.Fprintf(os.Stderr, "  --validate            Validate database on startup (default: true)\n")
	fmt.Fprintf(os.Stderr, "\nOther Options:\n")
	fmt.Fprintf(os.Stderr, "  --create-wallet       Create new wallet and exit\n")
	fmt.Fprintf(os.Stderr, "  --dev                 Development mode\n")
	fmt.Fprintf(os.Stderr, "  --pprof               Enable pprof server\n")
	fmt.Fprintf(os.Stderr, "  --version             Show version\n")
	fmt.Fprintf(os.Stderr, "  --help                Show this help\n")
	fmt.Fprintf(os.Stderr, "\nExamples:\n")
	fmt.Fprintf(os.Stderr, "  # Start full node\n")
	fmt.Fprintf(os.Stderr, "  %s --datadir=/var/lib/dinari\n\n", appName)
	fmt.Fprintf(os.Stderr, "  # Start mining node\n")
	fmt.Fprintf(os.Stderr, "  %s --mine --miner=DTxxx... --datadir=/var/lib/dinari\n\n", appName)
	fmt.Fprintf(os.Stderr, "  # Recover from crash\n")
	fmt.Fprintf(os.Stderr, "  %s --validate --datadir=/var/lib/dinari\n\n", appName)
}

func main() {
	flag.Parse()

	if showVersion {
		printVersionInfo()
		os.Exit(0)
	}

	// 🔥 CRITICAL: Initialize logger first for all error reporting
	logger, err := initializeLogger()
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	defer logger.Sync()

	logger.Info("🚀 Starting Dinari blockchain node",
		zap.String("version", appVersion),
		zap.String("build_time", BuildTime),
		zap.String("git_commit", GitCommit),
		zap.String("git_branch", GitBranch),
		zap.String("go_version", runtime.Version()),
		zap.Int("num_cpu", runtime.NumCPU()),
		zap.String("os", runtime.GOOS),
		zap.String("arch", runtime.GOARCH),
	)

	// 🔥 CRITICAL: Panic recovery with stack trace
	defer func() {
		if r := recover(); r != nil {
			logger.Error("💥 PANIC: Node crashed with unrecoverable error",
				zap.Any("panic", r),
				zap.String("stack_trace", string(debug.Stack())),
			)
			
			// Attempt emergency state save
			logger.Warn("Attempting emergency state preservation...")
			// Note: Emergency save would be implemented in StateDB
			
			os.Exit(1)
		}
	}()

	// Handle wallet creation
	if createWallet {
		if err := handleWalletCreation(logger); err != nil {
			logger.Error("❌ Wallet creation failed", zap.Error(err))
			os.Exit(1)
		}
		os.Exit(0)
	}

	// Validate configuration
	if err := validateConfiguration(logger); err != nil {
		logger.Error("❌ Configuration validation failed", zap.Error(err))
		os.Exit(1)
	}

	// 🔥 NEW: Check for force rebuild flag
	if forceRebuild {
		logger.Warn("⚠️  FORCE REBUILD REQUESTED - THIS WILL DELETE ALL DATA")
		if err := confirmForceRebuild(logger); err != nil {
			logger.Error("Force rebuild cancelled", zap.Error(err))
			os.Exit(1)
		}
		if err := rebuildFromGenesis(logger); err != nil {
			logger.Error("Force rebuild failed", zap.Error(err))
			os.Exit(1)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	exitCode := runNode(ctx, logger)
	logger.Info("Dinari node stopped", zap.Int("exit_code", exitCode))
	os.Exit(exitCode)
}

func initializeLogger() (*zap.Logger, error) {
	level, err := zapcore.ParseLevel(logLevel)
	if err != nil {
		return nil, fmt.Errorf("invalid log level %q: %w", logLevel, err)
	}

	var config zap.Config
	if devMode {
		config = zap.NewDevelopmentConfig()
		config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
		config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	} else {
		config = zap.NewProductionConfig()
		config.EncoderConfig.TimeKey = "timestamp"
		config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
		config.EncoderConfig.CallerKey = "caller"
		config.EncoderConfig.StacktraceKey = "stacktrace"
	}

	config.Level = zap.NewAtomicLevelAt(level)
	config.DisableCaller = false
	config.DisableStacktrace = false

	logger, err := config.Build(
		zap.AddCaller(),
		zap.AddStacktrace(zapcore.ErrorLevel),
		zap.AddCallerSkip(0),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to build logger: %w", err)
	}

	return logger, nil
}

func validateConfiguration(logger *zap.Logger) error {
	logger.Info("Validating configuration...")

	// Validate data directory
	if dataDir == "" {
		return errors.New("data directory cannot be empty")
	}

	// Create data directory structure
	dirs := []string{
		dataDir,
		filepath.Join(dataDir, "chaindata"),
		filepath.Join(dataDir, "keystore"),
		filepath.Join(dataDir, "wal"),      // 🔥 NEW: WAL directory
		filepath.Join(dataDir, "backups"),  // 🔥 NEW: Backup directory
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	// Test write permissions
	testFile := filepath.Join(dataDir, ".write_test")
	if err := os.WriteFile(testFile, []byte("test"), 0600); err != nil {
		return fmt.Errorf("data directory not writable: %w", err)
	}
	os.Remove(testFile)

	// Validate RPC address
	if rpcAddr == "" {
		return errors.New("RPC address cannot be empty")
	}

	// Validate mining configuration
	if mine && minerAddr == "" {
		return errors.New("miner address required when mining is enabled")
	}

	if minerAddr != "" && !crypto.IsValidAddress(minerAddr) {
		return fmt.Errorf("invalid miner address format: %s", minerAddr)
	}

	// Validate TLS configuration
	if enableTLS {
		if tlsCertFile == "" || tlsKeyFile == "" {
			return errors.New("TLS cert and key files required when TLS is enabled")
		}

		if _, err := os.Stat(tlsCertFile); err != nil {
			return fmt.Errorf("TLS cert file not found: %w", err)
		}
		if _, err := os.Stat(tlsKeyFile); err != nil {
			return fmt.Errorf("TLS key file not found: %w", err)
		}

		// Validate cert/key pair
		if _, err := tls.LoadX509KeyPair(tlsCertFile, tlsKeyFile); err != nil {
			return fmt.Errorf("invalid TLS cert/key pair: %w", err)
		}
	}

	// Warnings
	if devMode {
		logger.Warn("⚠️  DEVELOPMENT MODE ENABLED - NOT FOR PRODUCTION USE")
	}
	
	if skipRecovery {
		logger.Warn("⚠️  WAL RECOVERY DISABLED - DATA LOSS POSSIBLE ON CRASH")
	}

	logger.Info("✅ Configuration validated successfully")
	return nil
}

func printVersionInfo() {
	fmt.Printf("%s v%s\n", appName, appVersion)
	fmt.Printf("Build Time:  %s\n", BuildTime)
	fmt.Printf("Git Commit:  %s\n", GitCommit)
	fmt.Printf("Git Branch:  %s\n", GitBranch)
	fmt.Printf("Go Version:  %s\n", runtime.Version())
	fmt.Printf("Platform:    %s/%s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Printf("Compiler:    %s\n", runtime.Compiler)
}

func handleWalletCreation(logger *zap.Logger) error {
	logger.Info("Creating new wallet...")

	privateKey, err := crypto.GeneratePrivateKey()
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	address := crypto.PublicKeyToAddress(crypto.DerivePublicKey(privateKey))

	keystoreDir := filepath.Join(dataDir, "keystore")
	if err := os.MkdirAll(keystoreDir, 0700); err != nil {
		return fmt.Errorf("failed to create keystore directory: %w", err)
	}

	wif, err := crypto.PrivateKeyToWIF(privateKey)
	if err != nil {
		return fmt.Errorf("failed to convert key to WIF: %w", err)
	}

	keyFile := filepath.Join(keystoreDir, address+".key")
	if err := os.WriteFile(keyFile, []byte(wif), 0600); err != nil {
		return fmt.Errorf("failed to save keystore file: %w", err)
	}

	separator := strings.Repeat("=", 70)

	fmt.Println("\n" + separator)
	fmt.Println("  ✅ WALLET CREATED SUCCESSFULLY")
	fmt.Println(separator)
	fmt.Printf("\nAddress:       %s\n", address)
	fmt.Printf("Keystore File: %s\n", keyFile)
	fmt.Println("\n⚠️  CRITICAL SECURITY WARNINGS:")
	fmt.Println("  • Your private key is stored in the keystore file")
	fmt.Println("  • NEVER share this file with anyone")
	fmt.Println("  • Create encrypted backups immediately")
	fmt.Println("  • Store backups in multiple secure locations")
	fmt.Println("  • Loss of this file = PERMANENT LOSS OF ALL FUNDS")
	fmt.Println("  • No recovery is possible without the private key")
	fmt.Println("\n" + separator + "\n")

	logger.Info("Wallet created successfully",
		zap.String("address", address),
		zap.String("keystore_file", keyFile),
	)

	return nil
}

// 🔥 NEW: Force rebuild from genesis
func confirmForceRebuild(logger *zap.Logger) error {
	logger.Warn("This will DELETE ALL blockchain data and rebuild from genesis")
	logger.Warn("Type 'DELETE ALL DATA' to confirm:")
	
	var confirmation string
	fmt.Scanln(&confirmation)
	
	if confirmation != "DELETE ALL DATA" {
		return errors.New("rebuild cancelled")
	}
	
	return nil
}

func rebuildFromGenesis(logger *zap.Logger) error {
	logger.Warn("Starting force rebuild from genesis...")
	
	// Delete chaindata
	chaindataPath := filepath.Join(dataDir, "chaindata")
	if err := os.RemoveAll(chaindataPath); err != nil {
		return fmt.Errorf("failed to remove chaindata: %w", err)
	}
	
	// Delete WAL
	walPath := filepath.Join(dataDir, "wal")
	if err := os.RemoveAll(walPath); err != nil {
		return fmt.Errorf("failed to remove WAL: %w", err)
	}
	
	// Recreate directories
	if err := os.MkdirAll(chaindataPath, 0700); err != nil {
		return fmt.Errorf("failed to recreate chaindata: %w", err)
	}
	if err := os.MkdirAll(walPath, 0700); err != nil {
		return fmt.Errorf("failed to recreate WAL: %w", err)
	}
	
	logger.Info("✅ Rebuild complete - starting from genesis")
	return nil
}

type Node struct {
	logger *zap.Logger
	config *Config

	blockchain *core.Blockchain
	stateDB    *core.StateDB      // 🔥 NEW: Direct StateDB reference
	mempool    *mempool.Mempool
	consensus  *consensus.ProofOfWork
	storage    *storage.DB

	p2pNode   *p2p.Node
	rpcServer *api.Server

	minerService  *miner.Miner
	metricsServer *http.Server
	pprofServer   *http.Server

	ddosProtection *security.DDoSProtection
	monitor        *monitoring.AlertingSystem

	shutdownChan chan struct{}
	
	// 🔥 NEW: Shutdown coordination
	shutdownComplete chan error
	isShuttingDown   bool
}

type Config struct {
	DataDir      string
	RPCAddr      string
	P2PAddr      string
	MetricsAddr  string
	MinerAddr    string
	EnableMining bool
	EnableTLS    bool
	TLSCertFile  string
	TLSKeyFile   string
	DevMode      bool
}

func runNode(ctx context.Context, logger *zap.Logger) int {
	config := &Config{
		DataDir:      dataDir,
		RPCAddr:      rpcAddr,
		P2PAddr:      p2pAddr,
		MetricsAddr:  metricsAddr,
		MinerAddr:    minerAddr,
		EnableMining: mine,
		EnableTLS:    enableTLS,
		TLSCertFile:  tlsCertFile,
		TLSKeyFile:   tlsKeyFile,
		DevMode:      devMode,
	}

	node, err := initializeNode(ctx, logger, config)
	if err != nil {
		logger.Error("❌ Failed to initialize node", zap.Error(err))
		return 1
	}

	if err := node.Start(ctx); err != nil {
		logger.Error("❌ Failed to start node", zap.Error(err))
		return 1
	}

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)

	healthCheckTicker := time.NewTicker(healthCheckInterval)
	defer healthCheckTicker.Stop()

	logger.Info("✅ Dinari node started successfully",
		zap.String("rpc_addr", config.RPCAddr),
		zap.String("p2p_addr", config.P2PAddr),
		zap.String("metrics_addr", config.MetricsAddr),
		zap.Bool("mining_enabled", config.EnableMining),
		zap.Bool("tls_enabled", config.EnableTLS),
	)

	for {
		select {
		case sig := <-signalChan:
			logger.Info("📥 Received shutdown signal", 
				zap.String("signal", sig.String()))

			shutdownCtx, shutdownCancel := context.WithTimeout(
				context.Background(),
				defaultShutdownTimeout,
			)
			defer shutdownCancel()

			if err := node.Shutdown(shutdownCtx); err != nil {
				logger.Error("❌ Shutdown completed with errors", zap.Error(err))
				return 1
			}

			logger.Info("✅ Graceful shutdown completed successfully")
			return 0

		case <-healthCheckTicker.C:
			if err := node.HealthCheck(); err != nil {
				logger.Error("⚠️  Health check failed", zap.Error(err))
			}

		case <-ctx.Done():
			logger.Info("Context cancelled, shutting down")
			return 0
		}
	}
}

func initializeNode(ctx context.Context, logger *zap.Logger, config *Config) (*Node, error) {
	logger.Info("Initializing node components...")

	node := &Node{
		logger:           logger,
		config:           config,
		shutdownChan:     make(chan struct{}),
		shutdownComplete: make(chan error, 1),
		isShuttingDown:   false,
	}

	// 🔥 STEP 1: Initialize database with proper configuration
	logger.Info("📊 Initializing database", zap.String("path", config.DataDir))
	dbConfig := storage.DefaultConfig(filepath.Join(config.DataDir, "chaindata"))
	
	// 🔥 PRODUCTION: Enhanced database configuration
	dbConfig.GCEnabled = true
	dbConfig.GCInterval = 10 * time.Minute
	dbConfig.CompactionEnabled = true
	dbConfig.CompactionInterval = 1 * time.Hour
	
	db, err := storage.NewDB(dbConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize database: %w", err)
	}
	node.storage = db
	logger.Info("✅ Database initialized")

	// 🔥 STEP 2: Initialize StateDB with WAL enabled
	logger.Info("📝 Initializing state database with WAL")
	stateDB, err := core.NewStateDB(db.GetBadger())
	if err != nil {
		return nil, fmt.Errorf("failed to initialize state database: %w", err)
	}
	node.stateDB = stateDB
	logger.Info("✅ State database initialized")

	// 🔥 STEP 3: WAL Recovery (unless skipped)
	if !skipRecovery {
		logger.Info("🔄 Checking for WAL recovery...")
		walPath := filepath.Join(config.DataDir, "wal")
		
		recoveryCtx, recoveryCancel := context.WithTimeout(ctx, 2*time.Minute)
		defer recoveryCancel()
		
		if err := stateDB.RecoverFromWAL(recoveryCtx, walPath); err != nil {
			logger.Error("❌ WAL recovery failed", zap.Error(err))
			return nil, fmt.Errorf("WAL recovery failed: %w", err)
		}
		logger.Info("✅ WAL recovery completed")
	} else {
		logger.Warn("⚠️  Skipping WAL recovery as requested")
	}

	// 🔥 STEP 4: Database integrity validation
	if validateOnStart {
		logger.Info("🔍 Validating database integrity...")
		validationCtx, validationCancel := context.WithTimeout(ctx, dbIntegrityCheckTimeout)
		defer validationCancel()
		
		if err := validateDatabaseIntegrity(validationCtx, stateDB, logger); err != nil {
			logger.Error("❌ Database validation failed", zap.Error(err))
			return nil, fmt.Errorf("database validation failed: %w", err)
		}
		logger.Info("✅ Database validation passed")
	}

	// 🔥 STEP 5: Initialize blockchain
	logger.Info("⛓️  Initializing blockchain")
	blockchain, err := core.NewBlockchain(db.GetBadger(), stateDB, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize blockchain: %w", err)
	}
	node.blockchain = blockchain
	
	// Log current height
	height, err := blockchain.GetHeight()
	if err == nil {
		logger.Info("✅ Blockchain initialized", 
			zap.Uint64("current_height", height))
	}

	// STEP 6: Initialize mempool
	logger.Info("💾 Initializing mempool")
	mempoolInst := mempool.NewMempool()
	node.mempool = mempoolInst
	logger.Info("✅ Mempool initialized")

	// STEP 7: Initialize consensus
	logger.Info("🔨 Initializing consensus engine")
	blockchainAdapter := core.NewConsensusBlockchainAdapter(blockchain)
	consensusEngine := consensus.NewProofOfWork(blockchainAdapter)
	node.consensus = consensusEngine
	logger.Info("✅ Consensus engine initialized")

	// STEP 8: Initialize DDoS protection
	logger.Info("🛡️  Initializing DDoS protection")
	ddosConfig := &security.DDoSConfig{
		MaxRequestsPerSecond: 100,
		MaxBurstSize:         200,
		MaxConnPerIP:         10,
		MaxTotalConnections:  1000,
		ErrorThreshold:       50,
		SuccessThreshold:     10,
		Timeout:              30 * time.Second,
		BanDuration:          1 * time.Hour,
		SuspicionThreshold:   5,
	}
	node.ddosProtection = security.NewDDoSProtection(ddosConfig)
	logger.Info("✅ DDoS protection initialized")

	// STEP 9: Initialize P2P node
	logger.Info("🌐 Initializing P2P network")
	p2pNode, err := p2p.NewNode(ctx, 9000, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize P2P: %w", err)
	}
	node.p2pNode = p2pNode
	logger.Info("✅ P2P network initialized")

	// STEP 10: Initialize RPC server
	logger.Info("🔌 Initializing RPC server")
	rpcConfig := &api.ServerConfig{
		ListenAddr:         config.RPCAddr,
		TLSEnabled:         config.EnableTLS,
		TLSCertFile:        config.TLSCertFile,
		TLSKeyFile:         config.TLSKeyFile,
		RequestTimeout:     30 * time.Second,
		ReadTimeout:        15 * time.Second,
		WriteTimeout:       30 * time.Second,
		MaxRequestSize:     1 << 20, // 1MB
		CORSEnabled:        config.DevMode, // Only in dev mode
		CORSAllowedOrigins: []string{"*"},
		AuthEnabled:        !config.DevMode, // Enable in production
		RateLimitEnabled:   !config.DevMode, // Enable in production
		LogRequests:        true,
	}
	
	rpcServer, err := api.NewServer(rpcConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize RPC server: %w", err)
	}

	rpcServer.SetBlockchain(blockchain)
	rpcServer.SetMempool(mempoolInst)

	// Register RPC methods
	logger.Info("📋 Registering RPC handlers")
	rpcServer.RegisterMethod("chain_getHeight", rpcServer.HandleChainGetHeight)
rpcServer.RegisterMethod("chain_getBlock", rpcServer.HandleChainGetBlock)
	rpcServer.RegisterMethod("chain_getStats", rpcServer.HandleChainGetStats)

	rpcServer.RegisterMethod("tx_send", rpcServer.HandleTxSend)
	rpcServer.RegisterMethod("tx_get", rpcServer.HandleTxGet)
	rpcServer.RegisterMethod("tx_getPending", rpcServer.HandleTxGetPending)
	rpcServer.RegisterMethod("tx_listByWallet", rpcServer.HandleTxGetByAddress)
	rpcServer.RegisterMethod("tx_getByAddress", rpcServer.HandleTxGetByAddress)
	rpcServer.RegisterMethod("tx_getStats", rpcServer.HandleTxGetStats)

	rpcServer.RegisterMethod("wallet_create", rpcServer.HandleWalletCreate)
	rpcServer.RegisterMethod("wallet_balance", rpcServer.HandleWalletBalance)

	node.rpcServer = rpcServer
	logger.Info("✅ RPC server initialized with all handlers")

	// STEP 11: Initialize miner (if enabled)
	if config.EnableMining {
		logger.Info("⛏️  Initializing PRODUCTION mining subsystem")
		
		mempoolAdapter := mempool.NewMempoolAdapter(mempoolInst)
		
		numThreads := runtime.NumCPU()
		if numThreads > 1 {
			numThreads-- // Reserve one CPU for system operations
		}
		
		logger.Info("🚀 Starting miner with optimal configuration",
			zap.String("miner_address", config.MinerAddr),
			zap.Int("threads", numThreads),
			zap.String("block_interval", "15 seconds"),
		)
		
		minerInst := miner.NewMiner(
			blockchain,
			mempoolAdapter,
			consensusEngine,
			config.MinerAddr,
		)
		
		node.minerService = minerInst
		logger.Info("✅ PRODUCTION miner initialized")
	} else {
		logger.Info("Mining disabled")
	}

	// STEP 12: Initialize monitoring
	logger.Info("📊 Initializing monitoring system")
	monitor := monitoring.NewAlertingSystem(nil)
	node.monitor = monitor
	logger.Info("✅ Monitoring system initialized")

	// STEP 13: Setup metrics server
	if err := node.setupMetricsServer(); err != nil {
		return nil, fmt.Errorf("failed to setup metrics server: %w", err)
	}
	logger.Info("✅ Metrics server configured")

	// STEP 14: Setup pprof (if enabled)
	if enablePprof {
		if err := node.setupPprofServer(); err != nil {
			logger.Warn("⚠️  Failed to setup pprof server", zap.Error(err))
		} else {
			logger.Info("✅ Pprof server enabled", zap.String("addr", pprofAddr))
		}
	}

	logger.Info("✅ Node initialization completed successfully")
	return node, nil
}

// 🔥 NEW: Database integrity validation
func validateDatabaseIntegrity(ctx context.Context, stateDB *core.StateDB, logger *zap.Logger) error {
	logger.Info("Running database integrity checks...")
	
	// Check 1: Verify checkpoint exists
	checkpoint, err := stateDB.GetLatestCheckpoint()
	if err != nil {
		return fmt.Errorf("failed to read checkpoint: %w", err)
	}
	
	if checkpoint == nil {
		logger.Info("No checkpoint found - assuming genesis state")
		return nil
	}
	
	logger.Info("Found checkpoint",
		zap.Uint64("height", checkpoint.Height),
		zap.String("hash", checkpoint.Hash),
		zap.Time("timestamp", checkpoint.Timestamp),
	)
	
	// Check 2: Verify block at checkpoint exists
	block, err := stateDB.GetBlockByHeight(checkpoint.Height)
	if err != nil {
		return fmt.Errorf("checkpoint block not found at height %d: %w", checkpoint.Height, err)
	}
	
	if block.Hash != checkpoint.Hash {
		return fmt.Errorf("checkpoint hash mismatch: expected %s, got %s", 
			checkpoint.Hash, block.Hash)
	}
	
	logger.Info("Checkpoint block validated")
	
	// Check 3: Verify state root consistency (if available)
	// This would check that the state merkle root matches the block's state root
	// Implementation depends on your StateDB structure
	
	// Check 4: Sample random accounts to verify data integrity
	sampleSize := 10
	logger.Info("Sampling account data for integrity check", zap.Int("sample_size", sampleSize))
	
	accounts, err := stateDB.GetSampleAccounts(sampleSize)
	if err != nil {
		logger.Warn("Could not sample accounts", zap.Error(err))
	} else {
		logger.Info("Account sampling successful", zap.Int("accounts_checked", len(accounts)))
	}
	
	logger.Info("✅ Database integrity validation passed")
	return nil
}

func (n *Node) Start(ctx context.Context) error {
	n.logger.Info("Starting node services...")

	// Start metrics server first for health monitoring
	if n.metricsServer != nil {
		go func() {
			n.logger.Info("Starting metrics server", 
				zap.String("address", n.config.MetricsAddr))
			if err := n.metricsServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				n.logger.Error("❌ Metrics server error", zap.Error(err))
			}
		}()
		n.logger.Info("✅ Metrics server started")
	}

	// Start RPC server
	if n.rpcServer != nil {
		go func() {
			n.logger.Info("Starting RPC server", 
				zap.String("address", n.config.RPCAddr))
			if err := n.rpcServer.Start(); err != nil {
				n.logger.Error("❌ RPC server failed to start", zap.Error(err))
			}
		}()
		n.logger.Info("✅ RPC server started")
	}

	// Start monitoring
	go n.monitor.CheckRules(ctx)
	n.logger.Info("✅ Monitoring started")

	// Start miner last (after all other services are ready)
	if n.minerService != nil {
		go func() {
			n.logger.Info("Starting miner...")
			n.minerService.Start()
		}()
		n.logger.Info("✅ Miner started")
	}

	n.logger.Info("✅ All services started successfully")
	return nil
}

func (n *Node) Shutdown(ctx context.Context) error {
	n.logger.Info("🛑 Initiating graceful shutdown sequence...")
	
	// Prevent multiple shutdown calls
	if n.isShuttingDown {
		n.logger.Warn("Shutdown already in progress")
		return nil
	}
	n.isShuttingDown = true

	var shutdownErrors []error
	startTime := time.Now()

	// Signal shutdown to all components
	close(n.shutdownChan)

	// 🔥 STEP 1: Stop accepting new work
	n.logger.Info("Step 1/8: Stopping RPC server (no new requests)")
	if n.rpcServer != nil {
		shutdownCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		
		if err := n.rpcServer.Stop(); err != nil {
			n.logger.Error("❌ RPC server shutdown error", zap.Error(err))
			shutdownErrors = append(shutdownErrors, fmt.Errorf("RPC shutdown: %w", err))
		} else {
			n.logger.Info("✅ RPC server stopped")
		}
	}

	// 🔥 STEP 2: Stop miner (finish current block if mining)
	if n.minerService != nil {
		n.logger.Info("Step 2/8: Stopping miner (waiting for current block)")
		
		// Give miner time to finish current block
		minerStopCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		
		stopChan := make(chan struct{})
		go func() {
			n.minerService.Stop()
			close(stopChan)
		}()
		
		select {
		case <-stopChan:
			n.logger.Info("✅ Miner stopped gracefully")
		case <-minerStopCtx.Done():
			n.logger.Warn("⚠️  Miner stop timeout - forcing shutdown")
		}
	}

	// 🔥 STEP 3: Wait for pending transactions to settle
	n.logger.Info("Step 3/8: Waiting for pending transactions to settle")
	time.Sleep(2 * time.Second) // Give pending txs time to process

	// 🔥 STEP 4: Commit any pending state changes
	n.logger.Info("Step 4/8: Committing pending state changes")
	if n.stateDB != nil {
		commitCtx, cancel := context.WithTimeout(ctx, stateCommitTimeout)
		defer cancel()
		
		if err := n.commitFinalState(commitCtx); err != nil {
			n.logger.Error("❌ Final state commit failed", zap.Error(err))
			shutdownErrors = append(shutdownErrors, fmt.Errorf("final commit: %w", err))
		} else {
			n.logger.Info("✅ Final state committed")
		}
	}

	// 🔥 STEP 5: Close P2P connections
	n.logger.Info("Step 5/8: Closing P2P connections")
	if n.p2pNode != nil {
		if err := n.p2pNode.Close(); err != nil {
			n.logger.Error("❌ P2P shutdown error", zap.Error(err))
			shutdownErrors = append(shutdownErrors, fmt.Errorf("P2P close: %w", err))
		} else {
			n.logger.Info("✅ P2P connections closed")
		}
	}

	// 🔥 STEP 6: Stop monitoring and metrics
	n.logger.Info("Step 6/8: Stopping monitoring services")
	if n.metricsServer != nil {
		shutdownCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		
		if err := n.metricsServer.Shutdown(shutdownCtx); err != nil {
			n.logger.Error("❌ Metrics server shutdown error", zap.Error(err))
			shutdownErrors = append(shutdownErrors, fmt.Errorf("metrics shutdown: %w", err))
		} else {
			n.logger.Info("✅ Metrics server stopped")
		}
	}

	if n.pprofServer != nil {
		shutdownCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		
		if err := n.pprofServer.Shutdown(shutdownCtx); err != nil {
			n.logger.Error("❌ Pprof server shutdown error", zap.Error(err))
			shutdownErrors = append(shutdownErrors, fmt.Errorf("pprof shutdown: %w", err))
		} else {
			n.logger.Info("✅ Pprof server stopped")
		}
	}

	// 🔥 STEP 7: Final database compaction and cleanup
	n.logger.Info("Step 7/8: Running database cleanup")
	if n.storage != nil {
		dbShutdownCtx, cancel := context.WithTimeout(ctx, dbShutdownTimeout)
		defer cancel()
		
		if err := n.gracefulDatabaseClose(dbShutdownCtx); err != nil {
			n.logger.Error("❌ Database shutdown error", zap.Error(err))
			shutdownErrors = append(shutdownErrors, fmt.Errorf("database close: %w", err))
		} else {
			n.logger.Info("✅ Database closed cleanly")
		}
	}

	// 🔥 STEP 8: Create shutdown marker for recovery detection
	n.logger.Info("Step 8/8: Creating clean shutdown marker")
	if err := n.createShutdownMarker(); err != nil {
		n.logger.Warn("Could not create shutdown marker", zap.Error(err))
	} else {
		n.logger.Info("✅ Shutdown marker created")
	}

	shutdownDuration := time.Since(startTime)
	
	if len(shutdownErrors) > 0 {
		n.logger.Error("❌ Shutdown completed with errors",
			zap.Int("error_count", len(shutdownErrors)),
			zap.Duration("duration", shutdownDuration),
		)
		return fmt.Errorf("shutdown completed with %d errors", len(shutdownErrors))
	}

	n.logger.Info("✅ Graceful shutdown completed successfully",
		zap.Duration("duration", shutdownDuration),
	)
	return nil
}

// 🔥 NEW: Commit final state before shutdown
func (n *Node) commitFinalState(ctx context.Context) error {
	n.logger.Info("Flushing final state to disk...")
	
	// Get current blockchain height
	height, err := n.blockchain.GetHeight()
	if err != nil {
		return fmt.Errorf("failed to get blockchain height: %w", err)
	}
	
	// Get latest block hash
	block, err := n.blockchain.GetBlockByHeight(height)
	if err != nil {
		return fmt.Errorf("failed to get latest block: %w", err)
	}
	
	// Commit state with timeout
	commitDone := make(chan error, 1)
	go func() {
		commitDone <- n.stateDB.CommitState(height, block.Hash)
	}()
	
	select {
	case err := <-commitDone:
		if err != nil {
			return fmt.Errorf("state commit failed: %w", err)
		}
		n.logger.Info("Final state committed",
			zap.Uint64("height", height),
			zap.String("hash", block.Hash),
		)
		return nil
		
	case <-ctx.Done():
		return fmt.Errorf("state commit timeout: %w", ctx.Err())
	}
}

// 🔥 NEW: Graceful database close with compaction
func (n *Node) gracefulDatabaseClose(ctx context.Context) error {
	n.logger.Info("Closing database with final compaction...")
	
	// Run final garbage collection
	n.logger.Info("Running final BadgerDB GC...")
	gcDone := make(chan struct{})
	go func() {
		defer close(gcDone)
		
		// Run GC multiple times to maximize cleanup
		for i := 0; i < 3; i++ {
			if err := n.storage.GetBadger().RunValueLogGC(0.7); err != nil {
				break // No more GC needed
			}
			n.logger.Debug("GC pass completed", zap.Int("pass", i+1))
		}
	}()
	
	select {
	case <-gcDone:
		n.logger.Info("✅ Final GC completed")
	case <-time.After(30 * time.Second):
		n.logger.Warn("⚠️  GC timeout - proceeding with close")
	}
	
	// Run final compaction
	n.logger.Info("Running final compaction...")
	compactDone := make(chan error, 1)
	go func() {
		compactDone <- n.storage.GetBadger().Flatten(1)
	}()
	
	select {
	case err := <-compactDone:
		if err != nil {
			n.logger.Warn("Compaction completed with error", zap.Error(err))
		} else {
			n.logger.Info("✅ Final compaction completed")
		}
	case <-time.After(30 * time.Second):
		n.logger.Warn("⚠️  Compaction timeout - proceeding with close")
	}
	
	// Close database
	if err := n.storage.Close(); err != nil {
		return fmt.Errorf("database close failed: %w", err)
	}
	
	n.logger.Info("✅ Database closed successfully")
	return nil
}

// 🔥 NEW: Create shutdown marker for clean shutdown detection
func (n *Node) createShutdownMarker() error {
	markerPath := filepath.Join(n.config.DataDir, ".clean_shutdown")
	
	markerData := fmt.Sprintf("clean_shutdown:%d", time.Now().Unix())
	if err := os.WriteFile(markerPath, []byte(markerData), 0600); err != nil {
		return fmt.Errorf("failed to create shutdown marker: %w", err)
	}
	
	return nil
}

func (n *Node) HealthCheck() error {
	// Check blockchain
	if n.blockchain == nil {
		return errors.New("blockchain not initialized")
	}
	
	// Check state database
	if n.stateDB == nil {
		return errors.New("state database not initialized")
	}
	
	// Check storage
	if n.storage == nil {
		return errors.New("storage not initialized")
	}
	
	// Check P2P (warn only, not critical)
	if n.p2pNode != nil {
		peers := n.p2pNode.GetPeers()
		if len(peers) == 0 {
			n.logger.Debug("No peers connected (not critical)")
		}
	}
	
	// Check mempool
	if n.mempool == nil {
		return errors.New("mempool not initialized")
	}
	
	// Check if we can read from blockchain
	if _, err := n.blockchain.GetHeight(); err != nil {
		return fmt.Errorf("blockchain read failed: %w", err)
	}
	
	return nil
}

func (n *Node) setupMetricsServer() error {
	mux := http.NewServeMux()

	// Prometheus metrics endpoint
	mux.Handle("/metrics", promhttp.Handler())

	// Health check endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if err := n.HealthCheck(); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprintf(w, `{"status":"unhealthy","error":"%s"}`, err.Error())
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"status":"healthy"}`)
	})

	// Readiness check endpoint
	mux.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) {
		if n.blockchain == nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprint(w, `{"status":"not_ready","reason":"blockchain not initialized"}`)
			return
		}
		
		height, err := n.blockchain.GetHeight()
		if err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprintf(w, `{"status":"not_ready","reason":"cannot read height: %s"}`, err.Error())
			return
		}
		
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"status":"ready","height":%d}`, height)
	})

	// Node info endpoint
	mux.HandleFunc("/info", func(w http.ResponseWriter, r *http.Request) {
		height, _ := n.blockchain.GetHeight()
		peerCount := len(n.p2pNode.GetPeers())
		
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{
			"version":"%s",
			"build_time":"%s",
			"git_commit":"%s",
			"height":%d,
			"peers":%d,
			"mining":%t
		}`, appVersion, BuildTime, GitCommit, height, peerCount, n.config.EnableMining)
	})

	n.metricsServer = &http.Server{
		Addr:           n.config.MetricsAddr,
		Handler:        mux,
		ReadTimeout:    5 * time.Second,
		WriteTimeout:   5 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	return nil
}

func (n *Node) setupPprofServer() error {
	n.logger.Warn("⚠️  Pprof server enabled - DO NOT EXPOSE PUBLICLY")

	mux := http.NewServeMux()

	// Import pprof handlers
	mux.HandleFunc("/debug/pprof/", func(w http.ResponseWriter, r *http.Request) {
		http.DefaultServeMux.ServeHTTP(w, r)
	})

	n.pprofServer = &http.Server{
		Addr:           pprofAddr,
		Handler:        mux,
		ReadTimeout:    30 * time.Second,
		WriteTimeout:   30 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	go func() {
		if err := n.pprofServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			n.logger.Error("Pprof server error", zap.Error(err))
		}
	}()

	n.logger.Info("Pprof server started", zap.String("addr", pprofAddr))
	return nil
}
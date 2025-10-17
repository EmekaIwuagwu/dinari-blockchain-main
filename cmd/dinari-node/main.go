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
	"github.com/EmekaIwuagwu/dinari-blockchain/internal/types"
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

	defaultShutdownTimeout = 30 * time.Second
	healthCheckInterval    = 10 * time.Second
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
)

func init() {
	flag.StringVar(&configFile, "config", "", "Path to configuration file")
	flag.StringVar(&dataDir, "datadir", defaultDataDir, "Data directory")
	flag.StringVar(&rpcAddr, "rpc", defaultRPCAddr, "RPC server address")
	flag.StringVar(&p2pAddr, "p2p", fmt.Sprintf("/ip4/0.0.0.0/tcp/%s", defaultP2PPort), "P2P listen address")
	flag.StringVar(&metricsAddr, "metrics", fmt.Sprintf(":%s", defaultMetricsPort), "Metrics server address")
	flag.StringVar(&logLevel, "loglevel", defaultLogLevel, "Log level")

	flag.BoolVar(&createWallet, "create-wallet", false, "Create a new wallet and exit")
	flag.BoolVar(&mine, "mine", false, "Enable mining")
	flag.StringVar(&minerAddr, "miner", "", "Miner reward address")

	flag.BoolVar(&enableTLS, "tls", false, "Enable TLS for RPC")
	flag.StringVar(&tlsCertFile, "tls-cert", "", "TLS certificate file")
	flag.StringVar(&tlsKeyFile, "tls-key", "", "TLS key file")

	flag.BoolVar(&devMode, "dev", false, "Development mode")
	flag.BoolVar(&enablePprof, "pprof", false, "Enable pprof")
	flag.StringVar(&pprofAddr, "pprof-addr", ":6060", "Pprof address")

	flag.BoolVar(&showVersion, "version", false, "Show version")

	flag.Usage = printUsage
}

func printUsage() {
	fmt.Fprintf(os.Stderr, "%s v%s - Dinari Blockchain Node\n\n", appName, appVersion)
	fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n", appName)
	fmt.Fprintf(os.Stderr, "Options:\n")
	flag.PrintDefaults()
}

func main() {
	flag.Parse()

	if showVersion {
		printVersionInfo()
		os.Exit(0)
	}

	logger, err := initializeLogger()
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	defer logger.Sync()

	logger.Info("Starting Dinari blockchain node",
		zap.String("version", appVersion),
		zap.String("build_time", BuildTime),
		zap.String("git_commit", GitCommit),
		zap.String("go_version", runtime.Version()),
		zap.Int("cpus", runtime.NumCPU()),
	)

	defer func() {
		if r := recover(); r != nil {
			logger.Error("PANIC: Node crashed",
				zap.Any("panic", r),
				zap.String("stack", string(debug.Stack())),
			)
			os.Exit(1)
		}
	}()

	if createWallet {
		if err := handleWalletCreation(logger); err != nil {
			logger.Error("Wallet creation failed", zap.Error(err))
			os.Exit(1)
		}
		os.Exit(0)
	}

	if err := validateConfiguration(logger); err != nil {
		logger.Error("Configuration validation failed", zap.Error(err))
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	exitCode := runNode(ctx, logger)
	logger.Info("Dinari node stopped", zap.Int("exit_code", exitCode))
	os.Exit(exitCode)
}

func initializeLogger() (*zap.Logger, error) {
	level, err := zap.ParseAtomicLevel(logLevel)
	if err != nil {
		return nil, fmt.Errorf("invalid log level %q: %w", logLevel, err)
	}

	var config zap.Config
	if devMode {
		config = zap.NewDevelopmentConfig()
		config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	} else {
		config = zap.NewProductionConfig()
		config.EncoderConfig.TimeKey = "timestamp"
		config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	}

	config.Level = level

	if !devMode {
		config.DisableCaller = false
		config.DisableStacktrace = false
	}

	logger, err := config.Build(
		zap.AddCaller(),
		zap.AddStacktrace(zap.ErrorLevel),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to build logger: %w", err)
	}

	return logger, nil
}

func validateConfiguration(logger *zap.Logger) error {
	logger.Info("Validating configuration")

	if dataDir == "" {
		return errors.New("data directory cannot be empty")
	}

	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return fmt.Errorf("failed to create data directory: %w", err)
	}

	testFile := filepath.Join(dataDir, ".write_test")
	if err := os.WriteFile(testFile, []byte("test"), 0600); err != nil {
		return fmt.Errorf("data directory not writable: %w", err)
	}
	os.Remove(testFile)

	if rpcAddr == "" {
		return errors.New("RPC address cannot be empty")
	}

	if mine && minerAddr == "" {
		return errors.New("miner address required when mining enabled")
	}

	if minerAddr != "" && !crypto.IsValidAddress(minerAddr) {
		return fmt.Errorf("invalid miner address: %s", minerAddr)
	}

	if enableTLS {
		if tlsCertFile == "" || tlsKeyFile == "" {
			return errors.New("TLS cert and key files required when TLS enabled")
		}

		if _, err := os.Stat(tlsCertFile); err != nil {
			return fmt.Errorf("TLS cert file error: %w", err)
		}
		if _, err := os.Stat(tlsKeyFile); err != nil {
			return fmt.Errorf("TLS key file error: %w", err)
		}

		if _, err := tls.LoadX509KeyPair(tlsCertFile, tlsKeyFile); err != nil {
			return fmt.Errorf("failed to load TLS cert pair: %w", err)
		}
	}

	if devMode {
		logger.Warn("⚠️  DEVELOPMENT MODE ENABLED - NOT FOR PRODUCTION")
	}

	logger.Info("Configuration validated successfully")
	return nil
}

func printVersionInfo() {
	fmt.Printf("%s v%s\n", appName, appVersion)
	fmt.Printf("Build Time: %s\n", BuildTime)
	fmt.Printf("Git Commit: %s\n", GitCommit)
	fmt.Printf("Git Branch: %s\n", GitBranch)
	fmt.Printf("Go Version: %s\n", runtime.Version())
	fmt.Printf("OS/Arch:    %s/%s\n", runtime.GOOS, runtime.GOARCH)
}

func handleWalletCreation(logger *zap.Logger) error {
	logger.Info("Creating new wallet")

	// Generate private key using YOUR crypto package
	privateKey, err := crypto.GeneratePrivateKey()
	if err != nil {
		return fmt.Errorf("failed to generate key: %w", err)
	}

	// Derive address using YOUR crypto package
	address := crypto.PublicKeyToAddress(crypto.DerivePublicKey(privateKey))

	// Save to keystore directory
	keystoreDir := filepath.Join(dataDir, "keystore")
	if err := os.MkdirAll(keystoreDir, 0700); err != nil {
		return fmt.Errorf("failed to create keystore: %w", err)
	}

	// Convert to WIF for storage
	wif, err := crypto.PrivateKeyToWIF(privateKey)
	if err != nil {
		return fmt.Errorf("failed to convert key to WIF: %w", err)
	}

	// Save WIF to file
	keyFile := filepath.Join(keystoreDir, address+".key")
	if err := os.WriteFile(keyFile, []byte(wif), 0600); err != nil {
		return fmt.Errorf("failed to save key: %w", err)
	}

	separator := strings.Repeat("=", 60)

	fmt.Println("\n" + separator)
	fmt.Println("  ✅ Wallet Created Successfully")
	fmt.Println(separator)
	fmt.Printf("\nAddress: %s\n", address)
	fmt.Printf("Keystore: %s\n", keyFile)
	fmt.Println("\n⚠️  SECURITY NOTICE:")
	fmt.Println("  • Your private key is stored in the keystore")
	fmt.Println("  • Keystore location: " + keystoreDir)
	fmt.Println("  • NEVER share your keystore files")
	fmt.Println("  • Make encrypted backups")
	fmt.Println("  • Loss of keystore = PERMANENT LOSS OF FUNDS")
	fmt.Println("\n" + separator + "\n")

	logger.Info("Wallet created successfully",
		zap.String("address", address),
		zap.String("keystore_dir", keystoreDir),
	)

	return nil
}

type Node struct {
	logger *zap.Logger
	config *Config

	blockchain *core.Blockchain
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
		logger.Error("Failed to initialize node", zap.Error(err))
		return 1
	}

	if err := node.Start(ctx); err != nil {
		logger.Error("Failed to start node", zap.Error(err))
		return 1
	}

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)

	healthCheckTicker := time.NewTicker(healthCheckInterval)
	defer healthCheckTicker.Stop()

	logger.Info("🚀 Dinari node started successfully",
		zap.String("rpc_addr", config.RPCAddr),
		zap.String("p2p_addr", config.P2PAddr),
		zap.Bool("mining", config.EnableMining),
	)

	for {
		select {
		case sig := <-signalChan:
			logger.Info("Received shutdown signal", zap.String("signal", sig.String()))

			shutdownCtx, shutdownCancel := context.WithTimeout(
				context.Background(),
				defaultShutdownTimeout,
			)
			defer shutdownCancel()

			if err := node.Shutdown(shutdownCtx); err != nil {
				logger.Error("Shutdown errors", zap.Error(err))
				return 1
			}

			logger.Info("Graceful shutdown completed")
			return 0

		case <-healthCheckTicker.C:
			if err := node.HealthCheck(); err != nil {
				logger.Error("Health check failed", zap.Error(err))
			}

		case <-ctx.Done():
			logger.Info("Context cancelled")
			return 0
		}
	}
}

func initializeNode(ctx context.Context, logger *zap.Logger, config *Config) (*Node, error) {
	logger.Info("Initializing node components")

	node := &Node{
		logger:       logger,
		config:       config,
		shutdownChan: make(chan struct{}),
	}

	// Initialize database
	logger.Info("Initializing database", zap.String("path", config.DataDir))
	dbConfig := storage.DefaultConfig(filepath.Join(config.DataDir, "chaindata"))
	db, err := storage.NewDB(dbConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize database: %w", err)
	}
	node.storage = db

	// Initialize state database
	logger.Info("Initializing state database")
	stateDB, err := core.NewStateDB(db.GetBadger())
	if err != nil {
		return nil, fmt.Errorf("failed to initialize state: %w", err)
	}

	// Create genesis block
	logger.Info("Creating genesis block")
	genesisBlock := &core.Block{
	Header: &core.BlockHeader{
		Version:       1,
		Height:        0,
		PrevBlockHash: []byte{},
		MerkleRoot:    []byte{},
		Timestamp:     time.Now().Unix(),
		Difficulty:    16777216, // MUCH HIGHER - should take ~15 seconds
		Nonce:         0,
		Hash:          []byte{},
		StateRoot:     []byte{},
	},
	Transactions: []*types.Transaction{},
}

	// Initialize blockchain with genesis block
	logger.Info("Initializing blockchain")
	blockchain, err := core.NewBlockchain(db.GetBadger(), stateDB, genesisBlock)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize blockchain: %w", err)
	}
	node.blockchain = blockchain

	// Initialize mempool
	logger.Info("Initializing mempool")
	mempoolInst := mempool.NewMempool()
	node.mempool = mempoolInst

	// Initialize consensus
	// Initialize consensus - needs blockchain for difficulty calculation
	logger.Info("Initializing consensus engine")
	blockchainAdapter := core.NewConsensusBlockchainAdapter(blockchain)
	consensusEngine := consensus.NewProofOfWork(blockchainAdapter)
	node.consensus = consensusEngine
	logger.Info("Consensus engine initialized")

	// Initialize DDoS protection
	logger.Info("Initializing DDoS protection")
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

	// Initialize P2P node
	logger.Info("Initializing P2P network")
	p2pNode, err := p2p.NewNode(ctx, 9000, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize P2P: %w", err)
	}
	node.p2pNode = p2pNode

	// Initialize RPC server with CORS enabled for development
	logger.Info("Initializing RPC server")
	rpcConfig := &api.ServerConfig{
		ListenAddr:         config.RPCAddr,
		TLSEnabled:         config.EnableTLS,
		TLSCertFile:        config.TLSCertFile,
		TLSKeyFile:         config.TLSKeyFile,
		RequestTimeout:     30 * time.Second,
		ReadTimeout:        15 * time.Second,
		WriteTimeout:       30 * time.Second,
		MaxRequestSize:     1 << 20, // 1MB
		CORSEnabled:        true,
		CORSAllowedOrigins: []string{"*"}, // Allow all origins for development
		AuthEnabled:        false,          // Disable auth for development
		RateLimitEnabled:   false,          // Disable rate limiting for development
		LogRequests:        true,
	}
	
	rpcServer, err := api.NewServer(rpcConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize RPC: %w", err)
	}

	// Set blockchain and mempool on the RPC server
	rpcServer.SetBlockchain(blockchain)
	rpcServer.SetMempool(mempoolInst)

	// Register all RPC handlers
// Register all RPC handlers
	logger.Info("Registering RPC handlers")
	rpcServer.RegisterMethod("chain_getHeight", rpcServer.HandleChainGetHeight)
	rpcServer.RegisterMethod("chain_getBlock", rpcServer.HandleChainGetBlock)
	rpcServer.RegisterMethod("chain_getStats", rpcServer.HandleChainGetStats)

	rpcServer.RegisterMethod("tx_send", rpcServer.HandleTxSend)
	rpcServer.RegisterMethod("tx_get", rpcServer.HandleTxGet)
	rpcServer.RegisterMethod("tx_getPending", rpcServer.HandleTxGetPending)
	// NEW: Transaction history methods for wallet and explorer integration
	rpcServer.RegisterMethod("tx_listByWallet", rpcServer.HandleTxGetByAddress)  // Primary method for wallet
	rpcServer.RegisterMethod("tx_getByAddress", rpcServer.HandleTxGetByAddress) // Alias for compatibility
	rpcServer.RegisterMethod("tx_getStats", rpcServer.HandleTxGetStats)          // Mempool statistics

	rpcServer.RegisterMethod("wallet_create", rpcServer.HandleWalletCreate)
	rpcServer.RegisterMethod("wallet_balance", rpcServer.HandleWalletBalance)

	node.rpcServer = rpcServer

	// ✅ PRODUCTION-READY MINER INITIALIZATION WITH BLOCK INTERVAL ENFORCEMENT
	if config.EnableMining {
		logger.Info("🔥 Initializing PRODUCTION mining subsystem with strict 15-second block intervals")
		
		// Create mempool adapter
		mempoolAdapter := mempool.NewMempoolAdapter(mempoolInst)
		logger.Info("Created mempool adapter for miner")
		
		// Calculate optimal thread count
		numThreads := runtime.NumCPU()
		if numThreads > 1 {
			numThreads-- // Leave one CPU for other operations
		}
		
		logger.Info("🚀 Starting miner",
			zap.String("miner_address", config.MinerAddr),
			zap.Int("threads", numThreads),
			zap.String("enforcement", "STRICT 15-second block intervals"),
		)
		
		// Create miner instance with correct arguments
		// NewMiner(blockchain BlockchainInterface, mempool MempoolInterface, pow POWInterface, minerAddr string)
		minerInst := miner.NewMiner(
			blockchain,      // Implements BlockchainInterface
			mempoolAdapter,  // Implements MempoolInterface  
			consensusEngine, // Implements POWInterface
			config.MinerAddr,
		)
		
		node.minerService = minerInst
		logger.Info("✅ PRODUCTION miner initialized with block interval enforcement")
	} else {
		logger.Info("Mining disabled")
	}

	// Initialize monitoring
	logger.Info("Initializing monitoring")
	monitor := monitoring.NewAlertingSystem(nil)
	node.monitor = monitor

	// Setup metrics server
	if err := node.setupMetricsServer(); err != nil {
		return nil, fmt.Errorf("failed to setup metrics: %w", err)
	}

	// Setup pprof if enabled
	if enablePprof {
		if err := node.setupPprofServer(); err != nil {
			logger.Warn("Failed to setup pprof", zap.Error(err))
		}
	}

	logger.Info("✅ Node initialization completed successfully")
	return node, nil
}

func (n *Node) Start(ctx context.Context) error {
	n.logger.Info("Starting node services")

	// Start RPC server if initialized
	if n.rpcServer != nil {
		go func() {
			if err := n.rpcServer.Start(); err != nil {
				n.logger.Error("Failed to start RPC server", zap.Error(err))
			}
		}()
		n.logger.Info("RPC server configured", zap.String("address", n.config.RPCAddr))
	}

	// Start miner if enabled
	if n.minerService != nil {
		go n.minerService.Start()
		n.logger.Info("Miner started")
	}

	if n.metricsServer != nil {
		go func() {
			if err := n.metricsServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				n.logger.Error("Metrics server error", zap.Error(err))
			}
		}()
		n.logger.Info("Metrics server started", zap.String("address", n.config.MetricsAddr))
	}

	go n.monitor.CheckRules(ctx)

	return nil
}

func (n *Node) Shutdown(ctx context.Context) error {
	n.logger.Info("Initiating graceful shutdown")

	var shutdownErrors []error

	close(n.shutdownChan)

	// Shutdown RPC server
	if n.rpcServer != nil {
		n.logger.Info("Shutting down RPC server")
		if err := n.rpcServer.Stop(); err != nil {
			n.logger.Error("RPC shutdown error", zap.Error(err))
			shutdownErrors = append(shutdownErrors, fmt.Errorf("RPC shutdown: %w", err))
		}
	}

	if n.minerService != nil {
		n.logger.Info("Stopping miner")
		n.minerService.Stop()
	}

	if n.p2pNode != nil {
		n.logger.Info("Stopping P2P node")
		if err := n.p2pNode.Close(); err != nil {
			n.logger.Error("P2P stop error", zap.Error(err))
			shutdownErrors = append(shutdownErrors, fmt.Errorf("P2P stop: %w", err))
		}
	}

	if n.metricsServer != nil {
		n.logger.Info("Shutting down metrics server")
		if err := n.metricsServer.Shutdown(ctx); err != nil {
			n.logger.Error("Metrics shutdown error", zap.Error(err))
			shutdownErrors = append(shutdownErrors, fmt.Errorf("metrics shutdown: %w", err))
		}
	}

	if n.pprofServer != nil {
		n.logger.Info("Shutting down pprof server")
		if err := n.pprofServer.Shutdown(ctx); err != nil {
			n.logger.Error("Pprof shutdown error", zap.Error(err))
			shutdownErrors = append(shutdownErrors, fmt.Errorf("pprof shutdown: %w", err))
		}
	}

	if n.storage != nil {
		n.logger.Info("Closing database")
		if err := n.storage.Close(); err != nil {
			n.logger.Error("Database close error", zap.Error(err))
			shutdownErrors = append(shutdownErrors, fmt.Errorf("database close: %w", err))
		}
	}

	if len(shutdownErrors) > 0 {
		return fmt.Errorf("shutdown completed with %d errors", len(shutdownErrors))
	}

	n.logger.Info("Shutdown completed")
	return nil
}

func (n *Node) HealthCheck() error {
	if n.blockchain == nil {
		return errors.New("blockchain not initialized")
	}

	peers := n.p2pNode.GetPeers()
	if len(peers) == 0 {
		n.logger.Warn("No peers connected")
	}

	if n.storage == nil {
		return errors.New("database not initialized")
	}

	return nil
}

func (n *Node) setupMetricsServer() error {
	mux := http.NewServeMux()

	mux.Handle("/metrics", promhttp.Handler())

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if err := n.HealthCheck(); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprintf(w, "unhealthy: %v", err)
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "healthy")
	})

	mux.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) {
		if n.blockchain == nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprint(w, "not ready: blockchain not initialized")
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ready")
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
	n.logger.Warn("⚠️  Pprof server enabled - should not be exposed publicly")

	mux := http.NewServeMux()

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

	return nil
}
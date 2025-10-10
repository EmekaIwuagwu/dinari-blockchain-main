// Package main implements the Dinari blockchain node entry point with
// production-grade error handling, graceful shutdown, monitoring, and security.
//
// This is the main entry point for the Dinari blockchain node. It handles:
// - Configuration loading and validation
// - Secure wallet operations
// - P2P network initialization
// - RPC server setup with TLS
// - Graceful shutdown on signals
// - Health checks and metrics
// - Structured logging
// - Panic recovery
//
// Architecture:
// The node is structured as a collection of services that can be started
// and stopped independently:
//   - BlockchainService: Core blockchain logic
//   - RPCService: JSON-RPC API server
//   - P2PService: Peer-to-peer networking
//   - MinerService: Block mining (optional)
//   - MetricsService: Prometheus metrics
//
// Usage:
//   dinari-node [flags]
//   dinari-node --config=/path/to/config.yaml
//   dinari-node --create-wallet
//   dinari-node --datadir=/custom/path --rpc=localhost:8545
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
	"github.com/EmekaIwuagwu/dinari-blockchain/pkg/logging"
	"github.com/EmekaIwuagwu/dinari-blockchain/pkg/monitoring"
	"github.com/EmekaIwuagwu/dinari-blockchain/pkg/security"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
)

const (
	// Application metadata
	appName    = "dinari-node"
	appVersion = "1.0.0"
	
	// Default configuration values
	defaultDataDir     = "./data/dinari"
	defaultRPCAddr     = "localhost:8545"
	defaultP2PPort     = "9000"
	defaultMetricsPort = "9090"
	defaultLogLevel    = "info"
	
	// Timeouts and limits
	defaultShutdownTimeout = 30 * time.Second
	maxShutdownTimeout     = 60 * time.Second
	healthCheckInterval    = 10 * time.Second
)

var (
	// Build information (set via ldflags during build)
	BuildTime   = "unknown"
	GitCommit   = "unknown"
	GitBranch   = "unknown"
	
	// Command-line flags
	configFile      string
	dataDir         string
	rpcAddr         string
	p2pAddr         string
	metricsAddr     string
	logLevel        string
	
	// Operational flags
	createWallet    bool
	mine            bool
	minerAddr       string
	
	// TLS/Security flags
	enableTLS       bool
	tlsCertFile     string
	tlsKeyFile      string
	
	// Development flags
	devMode         bool
	enablePprof     bool
	pprofAddr       string
	
	// Version flag
	showVersion     bool
)

// init initializes command-line flags with validation
func init() {
	// Configuration
	flag.StringVar(&configFile, "config", "", "Path to configuration file (YAML)")
	flag.StringVar(&dataDir, "datadir", defaultDataDir, "Data directory for blockchain data")
	flag.StringVar(&rpcAddr, "rpc", defaultRPCAddr, "RPC server listen address (host:port)")
	flag.StringVar(&p2pAddr, "p2p", fmt.Sprintf("/ip4/0.0.0.0/tcp/%s", defaultP2PPort), "P2P listen multiaddr")
	flag.StringVar(&metricsAddr, "metrics", fmt.Sprintf(":%s", defaultMetricsPort), "Metrics server address")
	flag.StringVar(&logLevel, "loglevel", defaultLogLevel, "Logging level (debug|info|warn|error)")
	
	// Operations
	flag.BoolVar(&createWallet, "create-wallet", false, "Create a new wallet and exit")
	flag.BoolVar(&mine, "mine", false, "Enable mining")
	flag.StringVar(&minerAddr, "miner", "", "Miner reward address (required if --mine is set)")
	
	// Security/TLS
	flag.BoolVar(&enableTLS, "tls", false, "Enable TLS for RPC server")
	flag.StringVar(&tlsCertFile, "tls-cert", "", "TLS certificate file (required if --tls)")
	flag.StringVar(&tlsKeyFile, "tls-key", "", "TLS private key file (required if --tls)")
	
	// Development
	flag.BoolVar(&devMode, "dev", false, "Enable development mode (WARNING: insecure)")
	flag.BoolVar(&enablePprof, "pprof", false, "Enable pprof profiling server")
	flag.StringVar(&pprofAddr, "pprof-addr", ":6060", "Pprof server address")
	
	// Version
	flag.BoolVar(&showVersion, "version", false, "Show version information and exit")
	
	// Custom usage message
	flag.Usage = printUsage
}

// printUsage prints detailed usage information
func printUsage() {
	fmt.Fprintf(os.Stderr, "%s v%s - Dinari Blockchain Node\n\n", appName, appVersion)
	fmt.Fprintf(os.Stderr, "Usage:\n")
	fmt.Fprintf(os.Stderr, "  %s [options]\n\n", appName)
	fmt.Fprintf(os.Stderr, "Options:\n")
	flag.PrintDefaults()
	fmt.Fprintf(os.Stderr, "\nExamples:\n")
	fmt.Fprintf(os.Stderr, "  # Start node with default settings\n")
	fmt.Fprintf(os.Stderr, "  %s\n\n", appName)
	fmt.Fprintf(os.Stderr, "  # Create a new wallet\n")
	fmt.Fprintf(os.Stderr, "  %s --create-wallet\n\n", appName)
	fmt.Fprintf(os.Stderr, "  # Start mining node\n")
	fmt.Fprintf(os.Stderr, "  %s --mine --miner=DT1abc123...\n\n", appName)
	fmt.Fprintf(os.Stderr, "  # Use custom configuration\n")
	fmt.Fprintf(os.Stderr, "  %s --config=/etc/dinari/config.yaml\n\n", appName)
	fmt.Fprintf(os.Stderr, "  # Enable TLS for production\n")
	fmt.Fprintf(os.Stderr, "  %s --tls --tls-cert=server.crt --tls-key=server.key\n\n", appName)
}

// main is the application entry point with comprehensive error handling
func main() {
	// Parse command-line flags
	flag.Parse()
	
	// Show version and exit if requested
	if showVersion {
		printVersionInfo()
		os.Exit(0)
	}
	
	// Initialize logger first for error reporting
	logger, err := initializeLogger()
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	defer logger.Sync() // Flush any buffered log entries
	
	// Log startup information
	logger.Info("Starting Dinari blockchain node",
		zap.String("version", appVersion),
		zap.String("build_time", BuildTime),
		zap.String("git_commit", GitCommit),
		zap.String("go_version", runtime.Version()),
		zap.Int("cpus", runtime.NumCPU()),
	)
	
	// Set up global panic recovery
	defer func() {
		if r := recover(); r != nil {
			logger.Error("PANIC: Node crashed with panic",
				zap.Any("panic", r),
				zap.String("stack", string(debug.Stack())),
			)
			os.Exit(1)
		}
	}()
	
	// Handle wallet creation as special case
	if createWallet {
		if err := handleWalletCreation(logger); err != nil {
			logger.Error("Wallet creation failed", zap.Error(err))
			os.Exit(1)
		}
		os.Exit(0)
	}
	
	// Validate configuration before proceeding
	if err := validateConfiguration(logger); err != nil {
		logger.Error("Configuration validation failed", zap.Error(err))
		os.Exit(1)
	}
	
	// Create main application context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	
	// Run the node with proper error handling
	exitCode := runNode(ctx, logger)
	
	// Log shutdown
	logger.Info("Dinari node stopped", zap.Int("exit_code", exitCode))
	os.Exit(exitCode)
}

// initializeLogger creates and configures the structured logger
func initializeLogger() (*zap.Logger, error) {
	// Parse log level
	level, err := zap.ParseAtomicLevel(logLevel)
	if err != nil {
		return nil, fmt.Errorf("invalid log level %q: %w", logLevel, err)
	}
	
	// Configure logger based on environment
	var config zap.Config
	if devMode {
		config = zap.NewDevelopmentConfig()
		config.EncoderConfig.EncodeLevel = zap.CapitalColorLevelEncoder
	} else {
		config = zap.NewProductionConfig()
		config.EncoderConfig.TimeKey = "timestamp"
		config.EncoderConfig.EncodeTime = zap.ISO8601TimeEncoder
	}
	
	config.Level = level
	
	// Add caller information in production
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

// validateConfiguration validates all configuration parameters
func validateConfiguration(logger *zap.Logger) error {
	logger.Info("Validating configuration")
	
	// Validate data directory
	if dataDir == "" {
		return errors.New("data directory cannot be empty")
	}
	
	// Check if data directory exists, create if not
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return fmt.Errorf("failed to create data directory: %w", err)
	}
	
	// Validate data directory is writable
	testFile := filepath.Join(dataDir, ".write_test")
	if err := os.WriteFile(testFile, []byte("test"), 0600); err != nil {
		return fmt.Errorf("data directory not writable: %w", err)
	}
	os.Remove(testFile)
	
	// Validate RPC address format
	if rpcAddr == "" {
		return errors.New("RPC address cannot be empty")
	}
	
	// Validate mining configuration
	if mine && minerAddr == "" {
		return errors.New("miner address is required when mining is enabled (use --miner)")
	}
	
	if minerAddr != "" && !crypto.IsValidAddress(minerAddr) {
		return fmt.Errorf("invalid miner address format: %s", minerAddr)
	}
	
	// Validate TLS configuration
	if enableTLS {
		if tlsCertFile == "" || tlsKeyFile == "" {
			return errors.New("TLS certificate and key files are required when TLS is enabled")
		}
		
		// Verify TLS files exist and are readable
		if _, err := os.Stat(tlsCertFile); err != nil {
			return fmt.Errorf("TLS certificate file error: %w", err)
		}
		if _, err := os.Stat(tlsKeyFile); err != nil {
			return fmt.Errorf("TLS key file error: %w", err)
		}
		
		// Validate TLS files can be loaded
		if _, err := tls.LoadX509KeyPair(tlsCertFile, tlsKeyFile); err != nil {
			return fmt.Errorf("failed to load TLS certificate pair: %w", err)
		}
	}
	
	// Warn about development mode in production
	if devMode {
		logger.Warn("⚠️  DEVELOPMENT MODE ENABLED - NOT FOR PRODUCTION USE")
	}
	
	logger.Info("Configuration validated successfully")
	return nil
}

// printVersionInfo displays version information
func printVersionInfo() {
	fmt.Printf("%s v%s\n", appName, appVersion)
	fmt.Printf("Build Time: %s\n", BuildTime)
	fmt.Printf("Git Commit: %s\n", GitCommit)
	fmt.Printf("Git Branch: %s\n", GitBranch)
	fmt.Printf("Go Version: %s\n", runtime.Version())
	fmt.Printf("OS/Arch:    %s/%s\n", runtime.GOOS, runtime.GOARCH)
}

// handleWalletCreation handles the wallet creation flow
func handleWalletCreation(logger *zap.Logger) error {
	logger.Info("Creating new wallet")
	
	// Initialize secure key store
	keyStore, err := crypto.NewKeyStore(dataDir)
	if err != nil {
		return fmt.Errorf("failed to initialize key store: %w", err)
	}
	defer keyStore.Close()
	
	// Create new wallet
	wallet, err := keyStore.CreateWallet()
	if err != nil {
		return fmt.Errorf("failed to create wallet: %w", err)
	}
	
	// CRITICAL: Never log or print private keys
	// Only show the address to the user
	fmt.Println("\n" + "="*60)
	fmt.Println("  ✅ Wallet Created Successfully")
	fmt.Println("="*60)
	fmt.Printf("\nAddress: %s\n", wallet.Address)
	fmt.Println("\n⚠️  SECURITY NOTICE:")
	fmt.Println("  • Your private key has been securely stored in the keystore")
	fmt.Println("  • Keystore location: " + filepath.Join(dataDir, "keystore"))
	fmt.Println("  • NEVER share your keystore files or password")
	fmt.Println("  • Make multiple encrypted backups of your keystore")
	fmt.Println("  • If you lose your keystore, your funds are PERMANENTLY LOST")
	fmt.Println("\n" + "="*60 + "\n")
	
	logger.Info("Wallet created successfully",
		zap.String("address", wallet.Address),
		zap.String("keystore_dir", filepath.Join(dataDir, "keystore")),
	)
	
	return nil
}

// Node represents the main blockchain node with all services
type Node struct {
	logger          *zap.Logger
	config          *Config
	
	// Core services
	blockchain      *core.Blockchain
	mempool         *mempool.Mempool
	consensus       *consensus.PoW
	storage         *storage.Database
	
	// Network services
	p2pHost         *p2p.Host
	rpcServer       *api.Server
	
	// Optional services
	minerService    *miner.Miner
	metricsServer   *http.Server
	pprofServer     *http.Server
	
	// Security
	ddosProtection  *security.DDoSProtection
	
	// Monitoring
	monitor         *monitoring.AlertingSystem
	profiler        *monitoring.PerformanceProfiler
	
	// Shutdown coordination
	shutdownChan    chan struct{}
}

// Config holds all node configuration
type Config struct {
	DataDir         string
	RPCAddr         string
	P2PAddr         string
	MetricsAddr     string
	MinerAddr       string
	EnableMining    bool
	EnableTLS       bool
	TLSCertFile     string
	TLSKeyFile      string
	DevMode         bool
}

// runNode is the main node execution function with graceful shutdown
func runNode(ctx context.Context, logger *zap.Logger) int {
	// Create node configuration
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
	
	// Initialize node
	node, err := initializeNode(ctx, logger, config)
	if err != nil {
		logger.Error("Failed to initialize node", zap.Error(err))
		return 1
	}
	
	// Start all services
	if err := node.Start(ctx); err != nil {
		logger.Error("Failed to start node", zap.Error(err))
		return 1
	}
	
	// Setup signal handling for graceful shutdown
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)
	
	// Setup health check
	healthCheckTicker := time.NewTicker(healthCheckInterval)
	defer healthCheckTicker.Stop()
	
	logger.Info("🚀 Dinari node started successfully",
		zap.String("rpc_addr", config.RPCAddr),
		zap.String("p2p_addr", config.P2PAddr),
		zap.Bool("mining", config.EnableMining),
	)
	
	// Main event loop
	for {
		select {
		case sig := <-signalChan:
			logger.Info("Received shutdown signal",
				zap.String("signal", sig.String()),
			)
			
			// Graceful shutdown
			shutdownCtx, shutdownCancel := context.WithTimeout(
				context.Background(),
				defaultShutdownTimeout,
			)
			defer shutdownCancel()
			
			if err := node.Shutdown(shutdownCtx); err != nil {
				logger.Error("Shutdown encountered errors", zap.Error(err))
				return 1
			}
			
			logger.Info("Graceful shutdown completed")
			return 0
			
		case <-healthCheckTicker.C:
			// Perform health check
			if err := node.HealthCheck(); err != nil {
				logger.Error("Health check failed", zap.Error(err))
				// Could trigger alerts or automated recovery here
			}
			
		case <-ctx.Done():
			logger.Info("Context cancelled, shutting down")
			return 0
		}
	}
}

// initializeNode initializes all node components
func initializeNode(ctx context.Context, logger *zap.Logger, config *Config) (*Node, error) {
	logger.Info("Initializing node components")
	
	node := &Node{
		logger:       logger,
		config:       config,
		shutdownChan: make(chan struct{}),
	}
	
	// Initialize database
	logger.Info("Initializing database", zap.String("path", config.DataDir))
	db, err := storage.NewDatabase(filepath.Join(config.DataDir, "chaindata"))
	if err != nil {
		return nil, fmt.Errorf("failed to initialize database: %w", err)
	}
	node.storage = db
	
	// Initialize blockchain
	logger.Info("Initializing blockchain")
	blockchain, err := core.NewBlockchain(db, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize blockchain: %w", err)
	}
	node.blockchain = blockchain
	
	// Initialize mempool
	logger.Info("Initializing mempool")
	mempool, err := mempool.NewMempool(logger)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize mempool: %w", err)
	}
	node.mempool = mempool
	
	// Initialize consensus
	logger.Info("Initializing consensus engine")
	consensus := consensus.NewPoW(blockchain, logger)
	node.consensus = consensus
	
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
	
	// Initialize P2P host
	logger.Info("Initializing P2P network")
	p2pHost, err := p2p.NewHost(config.P2PAddr, blockchain, mempool, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize P2P host: %w", err)
	}
	node.p2pHost = p2pHost
	
	// Initialize RPC server
	logger.Info("Initializing RPC server")
	rpcConfig := &api.ServerConfig{
		Addr:           config.RPCAddr,
		EnableTLS:      config.EnableTLS,
		TLSCertFile:    config.TLSCertFile,
		TLSKeyFile:     config.TLSKeyFile,
		ReadTimeout:    15 * time.Second,
		WriteTimeout:   15 * time.Second,
		MaxHeaderBytes: 1 << 20, // 1 MB
	}
	rpcServer, err := api.NewServer(rpcConfig, blockchain, mempool, p2pHost, node.ddosProtection, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize RPC server: %w", err)
	}
	node.rpcServer = rpcServer
	
	// Initialize miner if enabled
	if config.EnableMining {
		logger.Info("Initializing miner", zap.String("miner_address", config.MinerAddr))
		miner := miner.NewMiner(blockchain, mempool, consensus, config.MinerAddr, logger)
		node.minerService = miner
	}
	
	// Initialize monitoring
	logger.Info("Initializing monitoring")
	monitor := monitoring.NewAlertingSystem(nil) // Pass SIEM exporter if configured
	node.monitor = monitor
	
	// Initialize performance profiler
	profilerConfig := &monitoring.ProfilerConfig{
		EnableCPUProfiling:    true,
		EnableMemoryProfiling: true,
		EnableTracing:         false,
		ProfileOutputDir:      filepath.Join(config.DataDir, "profiles"),
		SampleRate:            1 * time.Second,
		EnableBottleneckDetect: true,
	}
	profiler := monitoring.NewPerformanceProfiler(profilerConfig)
	node.profiler = profiler
	
	// Start profiler
	if err := profiler.Start(ctx); err != nil {
		logger.Warn("Failed to start performance profiler", zap.Error(err))
	}
	
	// Setup metrics server
	if err := node.setupMetricsServer(); err != nil {
		return nil, fmt.Errorf("failed to setup metrics server: %w", err)
	}
	
	// Setup pprof if enabled
	if enablePprof {
		if err := node.setupPprofServer(); err != nil {
			logger.Warn("Failed to setup pprof server", zap.Error(err))
		}
	}
	
	logger.Info("Node initialization completed successfully")
	return node, nil
}

// Start starts all node services
func (n *Node) Start(ctx context.Context) error {
	n.logger.Info("Starting node services")
	
	// Start P2P host
	if err := n.p2pHost.Start(ctx); err != nil {
		return fmt.Errorf("failed to start P2P host: %w", err)
	}
	n.logger.Info("P2P host started", zap.String("peer_id", n.p2pHost.ID().String()))
	
	// Start RPC server
	go func() {
		if err := n.rpcServer.Start(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			n.logger.Error("RPC server error", zap.Error(err))
		}
	}()
	n.logger.Info("RPC server started", zap.String("address", n.config.RPCAddr))
	
	// Start miner if enabled
	if n.minerService != nil {
		if err := n.minerService.Start(ctx); err != nil {
			return fmt.Errorf("failed to start miner: %w", err)
		}
		n.logger.Info("Miner started")
	}
	
	// Start metrics server
	if n.metricsServer != nil {
		go func() {
			if err := n.metricsServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				n.logger.Error("Metrics server error", zap.Error(err))
			}
		}()
		n.logger.Info("Metrics server started", zap.String("address", n.config.MetricsAddr))
	}
	
	// Start monitoring
	go n.monitor.CheckRules(ctx)
	
	return nil
}

// Shutdown gracefully shuts down all node services
func (n *Node) Shutdown(ctx context.Context) error {
	n.logger.Info("Initiating graceful shutdown")
	
	var shutdownErrors []error
	
	// Stop accepting new requests
	close(n.shutdownChan)
	
	// Shutdown RPC server
	if n.rpcServer != nil {
		n.logger.Info("Shutting down RPC server")
		if err := n.rpcServer.Shutdown(ctx); err != nil {
			n.logger.Error("RPC server shutdown error", zap.Error(err))
			shutdownErrors = append(shutdownErrors, fmt.Errorf("RPC shutdown: %w", err))
		}
	}
	
	// Stop miner
	if n.minerService != nil {
		n.logger.Info("Stopping miner")
		if err := n.minerService.Stop(); err != nil {
			n.logger.Error("Miner stop error", zap.Error(err))
			shutdownErrors = append(shutdownErrors, fmt.Errorf("miner stop: %w", err))
		}
	}
	
	// Stop P2P host
	if n.p2pHost != nil {
		n.logger.Info("Stopping P2P host")
		if err := n.p2pHost.Stop(); err != nil {
			n.logger.Error("P2P host stop error", zap.Error(err))
			shutdownErrors = append(shutdownErrors, fmt.Errorf("P2P stop: %w", err))
		}
	}
	
	// Shutdown metrics server
	if n.metricsServer != nil {
		n.logger.Info("Shutting down metrics server")
		if err := n.metricsServer.Shutdown(ctx); err != nil {
			n.logger.Error("Metrics server shutdown error", zap.Error(err))
			shutdownErrors = append(shutdownErrors, fmt.Errorf("metrics shutdown: %w", err))
		}
	}
	
	// Shutdown pprof server
	if n.pprofServer != nil {
		n.logger.Info("Shutting down pprof server")
		if err := n.pprofServer.Shutdown(ctx); err != nil {
			n.logger.Error("Pprof server shutdown error", zap.Error(err))
			shutdownErrors = append(shutdownErrors, fmt.Errorf("pprof shutdown: %w", err))
		}
	}
	
	// Close database
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
	
	n.logger.Info("Shutdown completed successfully")
	return nil
}

// HealthCheck performs a health check on all services
func (n *Node) HealthCheck() error {
	// Check blockchain
	if n.blockchain.GetHeight() == 0 {
		return errors.New("blockchain not initialized")
	}
	
	// Check P2P connectivity
	if n.p2pHost.PeerCount() == 0 {
		n.logger.Warn("No peers connected")
	}
	
	// Check database
	if !n.storage.IsHealthy() {
		return errors.New("database unhealthy")
	}
	
	return nil
}

// setupMetricsServer initializes the Prometheus metrics server
func (n *Node) setupMetricsServer() error {
	mux := http.NewServeMux()
	
	// Prometheus metrics endpoint
	mux.Handle("/metrics", promhttp.Handler())
	
	// Health check endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if err := n.HealthCheck(); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprintf(w, "unhealthy: %v", err)
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "healthy")
	})
	
	// Readiness check endpoint
	mux.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) {
		// Check if node is ready to accept traffic
		if n.blockchain.GetHeight() == 0 {
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

// setupPprofServer initializes the pprof profiling server
func (n *Node) setupPprofServer() error {
	n.logger.Warn("⚠️  Pprof server enabled - should not be exposed publicly")
	
	mux := http.NewServeMux()
	
	// Register pprof handlers
	mux.HandleFunc("/debug/pprof/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.DefaultServeMux.ServeHTTP(w, r)
	}))
	
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
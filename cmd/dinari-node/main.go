package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/EmekaIwuagwu/dinari-blockchain/internal/consensus"
	"github.com/EmekaIwuagwu/dinari-blockchain/internal/core"
	"github.com/EmekaIwuagwu/dinari-blockchain/internal/mempool"
	"github.com/EmekaIwuagwu/dinari-blockchain/internal/miner"
	"github.com/EmekaIwuagwu/dinari-blockchain/internal/p2p"
	"github.com/EmekaIwuagwu/dinari-blockchain/internal/storage"
	"github.com/EmekaIwuagwu/dinari-blockchain/internal/types"
	"github.com/EmekaIwuagwu/dinari-blockchain/pkg/api"
	"github.com/EmekaIwuagwu/dinari-blockchain/pkg/crypto"
	"github.com/EmekaIwuagwu/dinari-blockchain/pkg/logging"
	"github.com/EmekaIwuagwu/dinari-blockchain/pkg/metrics"
)

const (
	Version = "1.0.0"
	Banner  = `
╔══════════════════════════════════════════════════════════╗
║                                                          ║
║   ██████╗ ██╗███╗   ██╗ █████╗ ██████╗ ██╗             ║
║   ██╔══██╗██║████╗  ██║██╔══██╗██╔══██╗██║             ║
║   ██║  ██║██║██╔██╗ ██║███████║██████╔╝██║             ║
║   ██║  ██║██║██║╚██╗██║██╔══██║██╔══██╗██║             ║
║   ██████╔╝██║██║ ╚████║██║  ██║██║  ██║██║             ║
║   ╚═════╝ ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝             ║
║                                                          ║
║   DinariBlockchain v%s                              ║
║   Production-Grade Blockchain for Africa                ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝
`
)

// CLI flags
var (
	configFile      = flag.String("config", "config/config.yaml", "Path to config file")
	dataDir         = flag.String("datadir", "./data", "Data directory")
	network         = flag.String("network", "testnet", "Network: mainnet or testnet")
	rpcAddr         = flag.String("rpc", "localhost:8545", "JSON-RPC server address")
	p2pAddr         = flag.String("p2p", "/ip4/0.0.0.0/tcp/9000", "P2P listen address")
	minerAddr       = flag.String("miner", "", "Miner address (enables mining)")
	mine            = flag.Bool("mine", false, "Enable mining")
	createWallet    = flag.Bool("create-wallet", false, "Create new wallet and exit")
	logLevel        = flag.String("loglevel", "info", "Log level: debug, info, warn, error")
	metricsPort     = flag.Int("metrics-port", 9090, "Prometheus metrics port")
	enableMetrics   = flag.Bool("metrics", true, "Enable Prometheus metrics")
	bootstrapPeers  = flag.String("bootstrap", "", "Comma-separated bootstrap peer addresses")
	cpuThreads      = flag.Int("threads", 4, "Number of mining threads")
)

// Node represents the complete blockchain node
type Node struct {
	// Core components
	config     *Config
	db         *storage.DB
	state      *core.StateDB
	blockchain *core.Blockchain
	mempool    *mempool.Mempool
	consensus  *consensus.ProofOfWork
	
	// Network
	p2pNode *p2p.Node
	
	// Mining
	miner *miner.Miner
	
	// API
	apiServer *api.Server
	
	// Metrics
	metricsServer *metrics.MetricsServer
	
	// Logger
	logger *logging.Logger
	
	// Context
	ctx    context.Context
	cancel context.CancelFunc
}

// Config holds node configuration
type Config struct {
	Network        string
	DataDir        string
	RPCAddr        string
	P2PAddr        string
	MinerAddress   string
	EnableMining   bool
	LogLevel       string
	MetricsPort    int
	EnableMetrics  bool
	CPUThreads     int
}

func main() {
	flag.Parse()
	
	// Print banner
	fmt.Printf(Banner, Version)
	fmt.Println()
	
	// Handle wallet creation
	if *createWallet {
		createWalletAndExit()
		return
	}
	
	// Load configuration
	config := loadConfig()
	
	// Initialize logger
	if err := initLogger(config); err != nil {
		fmt.Printf("Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	
	logger := logging.GetGlobalLogger()
	logger.Info("Starting Dinari Blockchain Node",
		logging.String("version", Version),
		logging.String("network", config.Network),
		logging.String("datadir", config.DataDir),
	)
	
	// Create and start node
	node, err := NewNode(config)
	if err != nil {
		logger.Fatal("Failed to create node", logging.Error(err))
	}
	
	if err := node.Start(); err != nil {
		logger.Fatal("Failed to start node", logging.Error(err))
	}
	
	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	
	<-sigChan
	
	logger.Info("Shutdown signal received, stopping node...")
	
	if err := node.Stop(); err != nil {
		logger.Error("Error during shutdown", logging.Error(err))
	}
	
	logger.Info("Node stopped gracefully")
}

// NewNode creates a new blockchain node
func NewNode(config *Config) (*Node, error) {
	ctx, cancel := context.WithCancel(context.Background())
	
	logger := logging.GetGlobalLogger()
	
	// Ensure data directory exists
	if err := os.MkdirAll(config.DataDir, 0755); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create data directory: %w", err)
	}
	
	// Initialize database
	logger.Info("Initializing database...")
	dbPath := filepath.Join(config.DataDir, "blockchain.db")
	dbConfig := storage.DefaultConfig(dbPath)
	db, err := storage.NewDB(dbConfig)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to open database: %w", err)
	}
	
	// Initialize state database
	logger.Info("Initializing state database...")
	state, err := core.NewStateDB(db.UnderlyingDB()) // Expose underlying BadgerDB
	if err != nil {
		db.Close()
		cancel()
		return nil, fmt.Errorf("failed to create state DB: %w", err)
	}
	
	// Create genesis block if needed
	logger.Info("Loading blockchain...")
	genesisBlock := createGenesisBlock(config.Network)
	blockchain, err := core.NewBlockchain(db.UnderlyingDB(), state, genesisBlock)
	if err != nil {
		db.Close()
		cancel()
		return nil, fmt.Errorf("failed to create blockchain: %w", err)
	}
	
	// Initialize mempool
	logger.Info("Initializing mempool...")
	mp := mempool.NewMempool()
	
	// Initialize consensus
	logger.Info("Initializing consensus engine...")
	pow := consensus.NewProofOfWork()
	
	// Initialize P2P node
	logger.Info("Initializing P2P network...")
	p2pConfig := &p2p.NodeConfig{
		ListenAddrs:     parseMultiaddrs(config.P2PAddr),
		NetworkID:       config.Network,
		EnableDHT:       true,
		EnablePubSub:    true,
		MaxPeers:        50,
		MinPeers:        5,
		ProtocolVersion: "/dinari/1.0.0",
	}
	p2pNode, err := p2p.NewNode(p2pConfig)
	if err != nil {
		db.Close()
		cancel()
		return nil, fmt.Errorf("failed to create P2P node: %w", err)
	}
	
	// Initialize miner if enabled
	var minerInstance *miner.Miner
	if config.EnableMining && config.MinerAddress != "" {
		logger.Info("Initializing miner...", logging.String("address", config.MinerAddress))
		minerConfig := &miner.MinerConfig{
			MinerAddress:    config.MinerAddress,
			NumThreads:      config.CPUThreads,
			CoinbaseMessage: []byte("Dinari - Blockchain for Africa"),
			CPUPriority:     100,
		}
		
		minerInstance, err = miner.NewMiner(
			minerConfig,
			blockchain,
			mp,
			pow,
		)
		if err != nil {
			db.Close()
			cancel()
			return nil, fmt.Errorf("failed to create miner: %w", err)
		}
	}
	
	// Initialize API server
	logger.Info("Initializing JSON-RPC API server...")
	apiConfig := &api.ServerConfig{
		ListenAddr:         config.RPCAddr,
		TLSEnabled:         false, // Enable in production with certs
		AuthEnabled:        false, // Enable in production with API keys
		CORSEnabled:        true,
		CORSAllowedOrigins: []string{"*"}, // Restrict in production
		RateLimitEnabled:   true,
		RateLimit:          100,
		RateBurst:          20,
		RequestTimeout:     api.RequestTimeout,
		ReadTimeout:        api.ReadTimeout,
		WriteTimeout:       api.WriteTimeout,
		MaxRequestSize:     api.MaxRequestSize,
		LogRequests:        true,
	}
	apiServer, err := api.NewServer(apiConfig)
	if err != nil {
		db.Close()
		cancel()
		return nil, fmt.Errorf("failed to create API server: %w", err)
	}
	
	// Register API handlers
	registerAPIHandlers(apiServer, blockchain, mp, minerInstance, p2pNode, state)
	
	// Initialize metrics server if enabled
	var metricsServer *metrics.MetricsServer
	if config.EnableMetrics {
		logger.Info("Initializing metrics server...", logging.Int("port", config.MetricsPort))
		metricsServer = metrics.NewMetricsServer(config.MetricsPort)
	}
	
	node := &Node{
		config:        config,
		db:            db,
		state:         state,
		blockchain:    blockchain,
		mempool:       mp,
		consensus:     pow,
		p2pNode:       p2pNode,
		miner:         minerInstance,
		apiServer:     apiServer,
		metricsServer: metricsServer,
		logger:        logger,
		ctx:           ctx,
		cancel:        cancel,
	}
	
	return node, nil
}

// Start starts all node components
func (n *Node) Start() error {
	// Start P2P node
	n.logger.Info("Starting P2P network...")
	if err := n.p2pNode.Start(); err != nil {
		return fmt.Errorf("failed to start P2P node: %w", err)
	}
	
	// Start metrics server
	if n.metricsServer != nil {
		go func() {
			if err := n.metricsServer.Start(); err != nil {
				n.logger.Error("Metrics server error", logging.Error(err))
			}
		}()
	}
	
	// Start API server
	n.logger.Info("Starting JSON-RPC API server...")
	go func() {
		if err := n.apiServer.Start(); err != nil {
			n.logger.Error("API server error", logging.Error(err))
		}
	}()
	
	// Start miner if enabled
	if n.miner != nil {
		n.logger.Info("Starting miner...")
		if err := n.miner.Start(); err != nil {
			return fmt.Errorf("failed to start miner: %w", err)
		}
	}
	
	// Start background tasks
	go n.syncLoop()
	go n.metricsUpdateLoop()
	
	n.logger.Info("✅ Node started successfully")
	n.printNodeInfo()
	
	return nil
}

// Stop stops all node components gracefully
func (n *Node) Stop() error {
	n.logger.Info("Stopping node components...")
	
	// Stop miner
	if n.miner != nil {
		n.logger.Info("Stopping miner...")
		if err := n.miner.Stop(); err != nil {
			n.logger.Error("Error stopping miner", logging.Error(err))
		}
	}
	
	// Stop API server
	n.logger.Info("Stopping API server...")
	if err := n.apiServer.Stop(); err != nil {
		n.logger.Error("Error stopping API server", logging.Error(err))
	}
	
	// Stop P2P node
	n.logger.Info("Stopping P2P network...")
	if err := n.p2pNode.Stop(); err != nil {
		n.logger.Error("Error stopping P2P node", logging.Error(err))
	}
	
	// Stop metrics server
	if n.metricsServer != nil {
		n.logger.Info("Stopping metrics server...")
		if err := n.metricsServer.Stop(); err != nil {
			n.logger.Error("Error stopping metrics server", logging.Error(err))
		}
	}
	
	// Close database
	n.logger.Info("Closing database...")
	if err := n.db.Close(); err != nil {
		n.logger.Error("Error closing database", logging.Error(err))
	}
	
	// Cancel context
	n.cancel()
	
	// Flush logs
	logging.Sync()
	
	return nil
}

// syncLoop handles blockchain synchronization
func (n *Node) syncLoop() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-n.ctx.Done():
			return
		case <-ticker.C:
			// Perform sync operations
			// Check for new blocks from peers
			// Update metrics
		}
	}
}

// metricsUpdateLoop periodically updates metrics
func (n *Node) metricsUpdateLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-n.ctx.Done():
			return
		case <-ticker.C:
			n.updateMetrics()
		}
	}
}

// updateMetrics updates Prometheus metrics
func (n *Node) updateMetrics() {
	// Update blockchain metrics
	height := n.blockchain.GetHeight()
	metrics.BlockHeight.Set(float64(height))
	
	// Update mempool metrics
	mempoolStats := n.mempool.GetStats()
	metrics.UpdateMempoolStats(mempoolStats.TotalTxs, mempoolStats.TotalSize)
	
	// Update P2P metrics
	p2pStats := n.p2pNode.GetStats()
	metrics.ConnectedPeers.Set(float64(p2pStats.ConnectedPeers))
	
	// Update mining metrics if active
	if n.miner != nil && n.miner.IsRunning() {
		miningStats := n.miner.GetStats()
		metrics.RecordHashRate(miningStats.CurrentHashRate)
		metrics.MiningActive.Set(1)
	} else {
		metrics.MiningActive.Set(0)
	}
}

// printNodeInfo prints node information
func (n *Node) printNodeInfo() {
	fmt.Println("\n📊 Node Information:")
	fmt.Printf("   Network:         %s\n", n.config.Network)
	fmt.Printf("   Data Directory:  %s\n", n.config.DataDir)
	fmt.Printf("   Blockchain Height: %d\n", n.blockchain.GetHeight())
	fmt.Printf("   RPC Endpoint:    http://%s\n", n.config.RPCAddr)
	if n.config.EnableMetrics {
		fmt.Printf("   Metrics:         http://localhost:%d/metrics\n", n.config.MetricsPort)
	}
	if n.miner != nil {
		fmt.Printf("   Mining:          ENABLED (%d threads)\n", n.config.CPUThreads)
		fmt.Printf("   Miner Address:   %s\n", n.config.MinerAddress)
	} else {
		fmt.Printf("   Mining:          DISABLED\n")
	}
	fmt.Printf("   Connected Peers: %d\n", len(n.p2pNode.GetPeers()))
	fmt.Println()
}

// Helper functions

func loadConfig() *Config {
	return &Config{
		Network:       *network,
		DataDir:       *dataDir,
		RPCAddr:       *rpcAddr,
		P2PAddr:       *p2pAddr,
		MinerAddress:  *minerAddr,
		EnableMining:  *mine && *minerAddr != "",
		LogLevel:      *logLevel,
		MetricsPort:   *metricsPort,
		EnableMetrics: *enableMetrics,
		CPUThreads:    *cpuThreads,
	}
}

func initLogger(config *Config) error {
	logConfig := &logging.LogConfig{
		Level:          config.LogLevel,
		OutputPath:     "stdout",
		Development:    config.Network == "testnet",
		DisableCaller:  false,
		EnableRotation: false,
	}
	
	return logging.InitGlobalLogger(logConfig)
}

func createGenesisBlock(network string) *types.Block {
	var timestamp int64
	var difficulty uint32
	
	if network == "mainnet" {
		timestamp = 1704067200 // 2024-01-01 00:00:00 UTC
		difficulty = 10000
	} else {
		timestamp = time.Now().Unix()
		difficulty = 1000 // Easier for testnet
	}
	
	// Create coinbase transaction
	coinbaseTx := &types.Transaction{
		From:      "COINBASE",
		To:        "DT0000000000000000000000000000000000000000",
		Amount:    big.NewInt(50 * 1e8),
		TokenType: types.TokenDNT,
		FeeDNT:    big.NewInt(0),
		Nonce:     0,
		Timestamp: timestamp,
		Data:      []byte("Genesis Block - Dinari Blockchain for Africa"),
	}
	coinbaseTx.Hash = coinbaseTx.CalculateHash()
	
	// Create genesis header
	header := &types.BlockHeader{
		Version:       1,
		Height:        0,
		PrevBlockHash: make([]byte, 32),
		MerkleRoot:    types.CalculateMerkleRoot([]*types.Transaction{coinbaseTx}),
		Timestamp:     timestamp,
		Difficulty:    difficulty,
		Nonce:         0,
		StateRoot:     make([]byte, 32),
		Miner:         "GENESIS",
	}
	
	// Calculate genesis hash (must meet difficulty)
	// In production, this would be pre-computed
	header.Hash = make([]byte, 32)
	
	return &types.Block{
		Header:       header,
		Transactions: []*types.Transaction{coinbaseTx},
	}
}

func createWalletAndExit() {
	fmt.Println("🔐 Creating new wallet...\n")
	
	privKey, err := crypto.GenerateKey()
	if err != nil {
		fmt.Printf("Error generating key: %v\n", err)
		os.Exit(1)
	}
	
	pubKey := privKey.PublicKey()
	address := crypto.PublicKeyToAddress(pubKey)
	
	fmt.Println("=== New Wallet Created ===")
	fmt.Printf("Address:     %s\n", address)
	fmt.Printf("Private Key: %s\n", privKey.Hex())
	fmt.Printf("Public Key:  %s\n", pubKey.Hex())
	fmt.Println("\n⚠️  IMPORTANT: Save your private key securely!")
	fmt.Println("⚠️  Never share your private key with anyone!")
	fmt.Println("⚠️  Loss of private key means loss of funds!")
	
	os.Exit(0)
}

func registerAPIHandlers(server *api.Server, blockchain *core.Blockchain, mempool *mempool.Mempool, miner *miner.Miner, p2pNode *p2p.Node, state *core.StateDB) {
	// Wallet methods
	server.RegisterMethod("wallet_create", handleWalletCreate)
	server.RegisterMethod("wallet_balance", handleWalletBalance(state))
	
	// Transaction methods
	server.RegisterMethod("tx_send", handleTxSend(mempool, p2pNode))
	server.RegisterMethod("tx_get", handleTxGet(mempool, blockchain))
	
	// Blockchain methods
	server.RegisterMethod("chain_getHeight", handleGetHeight(blockchain))
	server.RegisterMethod("chain_getBlock", handleGetBlock(blockchain))
	server.RegisterMethod("chain_getBestHash", handleGetBestHash(blockchain))
	
	// Miner methods
	if miner != nil {
		server.RegisterMethod("miner_start", handleMinerStart(miner))
		server.RegisterMethod("miner_stop", handleMinerStop(miner))
		server.RegisterMethod("miner_status", handleMinerStatus(miner))
	}
	
	// P2P methods
	server.RegisterMethod("p2p_getPeers", handleGetPeers(p2pNode))
	server.RegisterMethod("p2p_getStats", handleGetP2PStats(p2pNode))
}

// API Handler implementations
func handleWalletCreate(ctx context.Context, params json.RawMessage) (interface{}, error) {
	privKey, _ := crypto.GenerateKey()
	pubKey := privKey.PublicKey()
	address := crypto.PublicKeyToAddress(pubKey)
	
	return map[string]string{
		"address":       address,
		"privateKeyHex": privKey.Hex(),
		"publicKeyHex":  pubKey.Hex(),
	}, nil
}

func handleWalletBalance(state *core.StateDB) api.HandlerFunc {
	return func(ctx context.Context, params json.RawMessage) (interface{}, error) {
		var req struct {
			Address string `json:"address"`
		}
		if err := json.Unmarshal(params, &req); err != nil {
			return nil, err
		}
		
		balanceDNT, _ := state.GetBalance(req.Address, core.TokenDNT)
		balanceAFC, _ := state.GetBalance(req.Address, core.TokenAFC)
		nonce, _ := state.GetNonce(req.Address)
		
		return map[string]interface{}{
			"address":    req.Address,
			"balanceDNT": balanceDNT.String(),
			"balanceAFC": balanceAFC.String(),
			"nonce":      nonce,
		}, nil
	}
}

func handleTxSend(mempool *mempool.Mempool, p2pNode *p2p.Node) api.HandlerFunc {
	return func(ctx context.Context, params json.RawMessage) (interface{}, error) {
		var tx types.Transaction
		if err := json.Unmarshal(params, &tx); err != nil {
			return nil, err
		}
		
		// Add to mempool
		if err := mempool.AddTransaction(&tx); err != nil {
			return nil, err
		}
		
		// Broadcast to network
		txData, _ := json.Marshal(tx)
		p2pNode.BroadcastTransaction(txData)
		
		return map[string]string{
			"txHash": hex.EncodeToString(tx.Hash),
		}, nil
	}
}

func handleTxGet(mempool *mempool.Mempool, blockchain *core.Blockchain) api.HandlerFunc {
	return func(ctx context.Context, params json.RawMessage) (interface{}, error) {
		var req struct {
			TxHash string `json:"txHash"`
		}
		if err := json.Unmarshal(params, &req); err != nil {
			return nil, err
		}
		
		// Try mempool first
		tx, err := mempool.GetTransaction(req.TxHash)
		if err == nil {
			return tx, nil
		}
		
		// Try blockchain
		// Implementation would search blockchain
		
		return nil, errors.New("transaction not found")
	}
}

func handleGetHeight(blockchain *core.Blockchain) api.HandlerFunc {
	return func(ctx context.Context, params json.RawMessage) (interface{}, error) {
		return map[string]uint64{
			"height": blockchain.GetHeight(),
		}, nil
	}
}

func handleGetBlock(blockchain *core.Blockchain) api.HandlerFunc {
	return func(ctx context.Context, params json.RawMessage) (interface{}, error) {
		var req struct {
			Height uint64 `json:"blockHeight"`
		}
		if err := json.Unmarshal(params, &req); err != nil {
			return nil, err
		}
		
		block, err := blockchain.GetBlockByHeight(req.Height)
		if err != nil {
			return nil, err
		}
		
		return block, nil
	}
}

func handleGetBestHash(blockchain *core.Blockchain) api.HandlerFunc {
	return func(ctx context.Context, params json.RawMessage) (interface{}, error) {
		return map[string]string{
			"hash": hex.EncodeToString(blockchain.GetBestHash()),
		}, nil
	}
}

func handleMinerStart(miner *miner.Miner) api.HandlerFunc {
	return func(ctx context.Context, params json.RawMessage) (interface{}, error) {
		if err := miner.Start(); err != nil {
			return nil, err
		}
		return map[string]string{"status": "mining started"}, nil
	}
}

func handleMinerStop(miner *miner.Miner) api.HandlerFunc {
	return func(ctx context.Context, params json.RawMessage) (interface{}, error) {
		if err := miner.Stop(); err != nil {
			return nil, err
		}
		return map[string]string{"status": "mining stopped"}, nil
	}
}

func handleMinerStatus(miner *miner.Miner) api.HandlerFunc {
	return func(ctx context.Context, params json.RawMessage) (interface{}, error) {
		stats := miner.GetStats()
		return stats, nil
	}
}

func handleGetPeers(p2pNode *p2p.Node) api.HandlerFunc {
	return func(ctx context.Context, params json.RawMessage) (interface{}, error) {
		peers := p2pNode.GetPeers()
		peerList := make([]string, len(peers))
		for i, p := range peers {
			peerList[i] = p.String()
		}
		return map[string]interface{}{
			"peers": peerList,
			"count": len(peers),
		}, nil
	}
}

func handleGetP2PStats(p2pNode *p2p.Node) api.HandlerFunc {
	return func(ctx context.Context, params json.RawMessage) (interface{}, error) {
		return p2pNode.GetStats(), nil
	}
}

func parseMultiaddrs(addr string) []multiaddr.Multiaddr {
	// Parse multiaddr string
	// Simplified implementation
	return nil
}
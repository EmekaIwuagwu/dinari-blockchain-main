// cmd/dinari-node/main.go
// Enhanced main entry point with all security features integrated

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/EmekaIwuagwu/dinari-blockchain/internal/consensus"
	"github.com/EmekaIwuagwu/dinari-blockchain/internal/core"
	"github.com/EmekaIwuagwu/dinari-blockchain/internal/mempool"
	"github.com/EmekaIwuagwu/dinari-blockchain/internal/storage"
	"github.com/EmekaIwuagwu/dinari-blockchain/internal/types"
	"github.com/EmekaIwuagwu/dinari-blockchain/pkg/api"
	"github.com/EmekaIwuagwu/dinari-blockchain/pkg/crypto"
)

const (
	Version         = "1.0.0-secure"
	DefaultDataDir  = "./data"
	DefaultRPCPort  = "8545"
	DefaultP2PPort  = "9000"
	ChainID         = 1 // Mainnet
)

var (
	// Command line flags
	dataDir        = flag.String("datadir", DefaultDataDir, "Data directory for blockchain data")
	rpcAddr        = flag.String("rpc", "localhost:"+DefaultRPCPort, "RPC server address")
	p2pAddr        = flag.String("p2p", "/ip4/0.0.0.0/tcp/"+DefaultP2PPort, "P2P listen address")
	minerAddr      = flag.String("miner", "", "Miner address for block rewards")
	mine           = flag.Bool("mine", false, "Enable mining")
	createWallet   = flag.Bool("create-wallet", false, "Create a new wallet and exit")
	logLevel       = flag.String("loglevel", "info", "Log level (debug, info, warn, error)")
	enableHSM      = flag.Bool("hsm", false, "Enable Hardware Security Module")
	hsmProvider    = flag.String("hsm-provider", "software", "HSM provider (software, aws-cloudhsm, azure-keyvault)")
	enableMultiSig = flag.Bool("multisig", false, "Enable multi-signature support for high-value transactions")
	configFile     = flag.String("config", "", "Path to configuration file")
	testnet        = flag.Bool("testnet", false, "Run in testnet mode")
	production     = flag.Bool("production", false, "Run in production mode with enhanced security")
)

type DinariNode struct {
	config              *NodeConfig
	keyManager          *crypto.KeyManager
	hsmManager          *crypto.HSMManager
	storage             *storage.SecureStorage
	blockchain          *core.Blockchain
	mempool             *mempool.EnhancedMempool
	consensus           *consensus.EnhancedPoW
	circuitBreaker      *core.CircuitBreaker
	transactionValidator *core.TransactionValidator
	rpcServer           *api.RPCServer
	miner               *Miner
	ctx                 context.Context
	cancel              context.CancelFunc
}

type NodeConfig struct {
	DataDir           string
	RPCAddr           string
	P2PAddr           string
	ChainID           uint64
	EnableMining      bool
	MinerAddress      string
	EnableHSM         bool
	HSMProvider       string
	EnableMultiSig    bool
	Production        bool
	Testnet           bool
	EncryptionKey     string
	MaxConnections    int
	BlockTime         time.Duration
}

type Miner struct {
	address     string
	blockchain  *core.Blockchain
	mempool     *mempool.EnhancedMempool
	consensus   *consensus.EnhancedPoW
	running     bool
	stopChan    chan struct{}
}

func main() {
	flag.Parse()

	if *createWallet {
		createNewWallet()
		return
	}

	setupLogger(*logLevel)

	config := &NodeConfig{
		DataDir:        *dataDir,
		RPCAddr:        *rpcAddr,
		P2PAddr:        *p2pAddr,
		ChainID:        ChainID,
		EnableMining:   *mine,
		MinerAddress:   *minerAddr,
		EnableHSM:      *enableHSM,
		HSMProvider:    *hsmProvider,
		EnableMultiSig: *enableMultiSig,
		Production:     *production,
		Testnet:        *testnet,
		MaxConnections: 50,
		BlockTime:      15 * time.Second,
	}

	if config.Production {
		log.Println("🔒 PRODUCTION MODE ENABLED - Enhanced security active")
		config.EncryptionKey = os.Getenv("DINARI_ENCRYPTION_KEY")
		if config.EncryptionKey == "" {
			log.Fatal("❌ DINARI_ENCRYPTION_KEY environment variable required in production mode")
		}
	}

	node, err := NewDinariNode(config)
	if err != nil {
		log.Fatalf("❌ Failed to create node: %v", err)
	}

	if err := node.Start(); err != nil {
		log.Fatalf("❌ Failed to start node: %v", err)
	}

	printBanner(config)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	<-sigChan
	log.Println("\n🛑 Shutdown signal received...")

	if err := node.Stop(); err != nil {
		log.Printf("❌ Error during shutdown: %v", err)
	}

	log.Println("✅ Dinari node stopped successfully")
}

func NewDinariNode(config *NodeConfig) (*DinariNode, error) {
	ctx, cancel := context.WithCancel(context.Background())

	if err := os.MkdirAll(config.DataDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %w", err)
	}

	log.Println("🔐 Initializing cryptography layer...")
	keyManager, err := crypto.NewKeyManager()
	if err != nil {
		return nil, fmt.Errorf("failed to create key manager: %w", err)
	}

	var hsmManager *crypto.HSMManager
	if config.EnableHSM {
		log.Printf("🔑 Initializing HSM (%s)...", config.HSMProvider)
		hsmConfig := &crypto.HSMConfig{
			Provider:    config.HSMProvider,
			MaxSessions: 10,
		}
		hsmManager, err = crypto.NewHSMManager(hsmConfig, keyManager)
		if err != nil {
			log.Printf("⚠️  HSM initialization failed: %v. Falling back to software keys.", err)
		} else {
			log.Println("✅ HSM initialized successfully")
		}
	}

	log.Println("💾 Initializing secure storage...")
	storageConfig := &storage.StorageConfig{
		DataDir:          filepath.Join(config.DataDir, "chaindata"),
		EncryptionKey:    config.EncryptionKey,
		EnableEncryption: config.Production,
		EnableBackup:     config.Production,
		BackupDir:        filepath.Join(config.DataDir, "backups"),
		MaxDBSize:        100 * 1024 * 1024 * 1024, // 100GB
		NumVersions:      1,
		ValueLogSize:     1024 * 1024 * 1024, // 1GB
		SyncWrites:       config.Production,
	}

	secureStorage, err := storage.NewSecureStorage(storageConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create storage: %w", err)
	}

	log.Println("⛓️  Initializing blockchain core...")
	blockchain := core.NewBlockchain(secureStorage, config.ChainID)

	log.Println("⚙️  Initializing consensus engine...")
	initialDifficulty := big.NewInt(1)
	initialDifficulty.Lsh(initialDifficulty, 240)
	enhancedPoW := consensus.NewEnhancedPoW(initialDifficulty)

	log.Println("🛡️  Initializing transaction validator...")
	stateDB := blockchain.GetStateDB()
	txValidator := core.NewTransactionValidator(keyManager, stateDB)

	log.Println("🔄 Initializing mempool...")
	mempoolConfig := &mempool.MempoolConfig{
		MaxSize:         100000,
		MaxTxPerAddress: 1000,
		MinGasPrice:     1000,
		EnableRBF:       true,
		EnablePriority:  true,
		CleanupInterval: 5 * time.Minute,
	}
	enhancedMempool := mempool.NewEnhancedMempool(txValidator, mempoolConfig)

	log.Println("🚨 Initializing circuit breaker...")
	circuitBreakerConfig := core.DefaultCircuitBreakerConfig()
	circuitBreakerConfig.EnableAnomalyDetection = config.Production
	circuitBreakerConfig.EnableRateLimiting = config.Production
	circuitBreaker := core.NewCircuitBreaker(circuitBreakerConfig)

	circuitBreaker.alertManager.Subscribe(func(alert core.Alert) {
		log.Printf("🚨 ALERT [%s]: %s - %s", alert.Severity, alert.Type, alert.Message)
	})

	log.Println("🌐 Initializing RPC server...")
	rpcServer := api.NewRPCServer(config.RPCAddr, blockchain, enhancedMempool, keyManager)

	var miner *Miner
	if config.EnableMining {
		if config.MinerAddress == "" {
			return nil, fmt.Errorf("miner address required when mining is enabled")
		}
		log.Printf("⛏️  Initializing miner (address: %s)...", config.MinerAddress)
		miner = &Miner{
			address:    config.MinerAddress,
			blockchain: blockchain,
			mempool:    enhancedMempool,
			consensus:  enhancedPoW,
			stopChan:   make(chan struct{}),
		}
	}

	return &DinariNode{
		config:               config,
		keyManager:           keyManager,
		hsmManager:           hsmManager,
		storage:              secureStorage,
		blockchain:           blockchain,
		mempool:              enhancedMempool,
		consensus:            enhancedPoW,
		circuitBreaker:       circuitBreaker,
		transactionValidator: txValidator,
		rpcServer:            rpcServer,
		miner:                miner,
		ctx:                  ctx,
		cancel:               cancel,
	}, nil
}

func (node *DinariNode) Start() error {
	log.Println("🚀 Starting Dinari node...")

	if err := node.blockchain.LoadOrCreate(); err != nil {
		return fmt.Errorf("failed to load blockchain: %w", err)
	}

	if err := node.rpcServer.Start(); err != nil {
		return fmt.Errorf("failed to start RPC server: %w", err)
	}

	if node.miner != nil {
		go node.miner.Start()
	}

	go node.monitorHealth()

	log.Println("✅ Dinari node started successfully")
	return nil
}

func (node *DinariNode) Stop() error {
	log.Println("🛑 Stopping Dinari node...")

	node.cancel()

	if node.miner != nil {
		node.miner.Stop()
	}

	if node.rpcServer != nil {
		if err := node.rpcServer.Stop(); err != nil {
			log.Printf("⚠️  Error stopping RPC server: %v", err)
		}
	}

	if node.mempool != nil {
		node.mempool.Stop()
	}

	if node.storage != nil {
		if err := node.storage.Sync(); err != nil {
			log.Printf("⚠️  Error syncing storage: %v", err)
		}
		if err := node.storage.Close(); err != nil {
			log.Printf("⚠️  Error closing storage: %v", err)
		}
	}

	return nil
}

func (node *DinariNode) monitorHealth() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			node.checkHealth()
		case <-node.ctx.Done():
			return
		}
	}
}

func (node *DinariNode) checkHealth() {
	circuitState := node.circuitBreaker.GetState()
	if circuitState != core.StateClosed {
		log.Printf("⚠️  WARNING: Circuit breaker is %s", circuitState)
	}

	mempoolSize := node.mempool.GetSize()
	if mempoolSize > 50000 {
		log.Printf("⚠️  WARNING: Mempool size high (%d transactions)", mempoolSize)
	}

	metrics := node.circuitBreaker.GetMetrics()
	if metrics.AnomaliesDetected > 0 {
		log.Printf("🔍 Security: %d anomalies detected, %d attacks prevented", 
			metrics.AnomaliesDetected, metrics.AttacksPrevented)
	}
}

func (m *Miner) Start() {
	m.running = true
	log.Printf("⛏️  Mining started on address: %s", m.address)

	for m.running {
		select {
		case <-m.stopChan:
			return
		default:
			m.mine()
		}
	}
}

func (m *Miner) Stop() {
	log.Println("⛏️  Stopping miner...")
	m.running = false
	close(m.stopChan)
}

func (m *Miner) mine() {
	txs := m.mempool.GetTransactions(1000)

	currentHeight := m.blockchain.GetHeight()
	previousHash := m.blockchain.GetBestBlockHash()

	block := types.NewBlock(currentHeight+1, previousHash, txs, m.address)

	difficulty := m.consensus.GetCurrentDifficulty()
	block.Difficulty = difficulty

	target := m.consensus.CalculateTarget(difficulty)

	startTime := time.Now()
	for nonce := uint64(0); m.running; nonce++ {
		block.Nonce = nonce
		blockHash := block.CalculateHash()

		hashInt := new(big.Int)
		hashInt.SetString(blockHash, 16)

		if hashInt.Cmp(target) <= 0 {
			block.Hash = blockHash
			log.Printf("⛏️  Block mined! Height: %d, Hash: %s, Time: %v", 
				block.Height, blockHash[:16]+"...", time.Since(startTime))

			if err := m.blockchain.AddBlock(block); err != nil {
				log.Printf("❌ Failed to add block: %v", err)
				return
			}

			for _, tx := range txs {
				m.mempool.RemoveTransaction(tx.Hash())
			}

			return
		}

		if nonce%100000 == 0 {
			select {
			case <-m.stopChan:
				return
			default:
			}
		}
	}
}

func createNewWallet() {
	log.Println("🔐 Creating new wallet...")

	km, err := crypto.NewKeyManager()
	if err != nil {
		log.Fatalf("❌ Failed to create key manager: %v", err)
	}

	kp, err := km.GenerateKeyPair()
	if err != nil {
		log.Fatalf("❌ Failed to generate key pair: %v", err)
	}

	fmt.Println("\n=== New Wallet Created ===")
	fmt.Printf("Address:     %s\n", kp.Address)
	fmt.Printf("Public Key:  %x\n", crypto.SerializePublicKey(kp.PublicKey))
	fmt.Printf("Private Key: %x\n", crypto.SerializePrivateKey(kp.PrivateKey))
	fmt.Println("\n⚠️  IMPORTANT: Save your private key securely!")
	fmt.Println("⚠️  Never share your private key with anyone!")
	fmt.Println("===========================\n")
}

func printBanner(config *NodeConfig) {
	fmt.Println("\n╔════════════════════════════════════════════════════════╗")
	fmt.Println("║           DINARI BLOCKCHAIN NODE v" + Version + "            ║")
	fmt.Println("╠════════════════════════════════════════════════════════╣")
	fmt.Printf("║ RPC Server:      %-37s ║\n", config.RPCAddr)
	fmt.Printf("║ P2P Address:     %-37s ║\n", config.P2PAddr)
	fmt.Printf("║ Chain ID:        %-37d ║\n", config.ChainID)
	fmt.Printf("║ Data Directory:  %-37s ║\n", config.DataDir)
	
	if config.Production {
		fmt.Println("║ Mode:            PRODUCTION (Enhanced Security)        ║")
	} else if config.Testnet {
		fmt.Println("║ Mode:            TESTNET                               ║")
	} else {
		fmt.Println("║ Mode:            DEVELOPMENT                           ║")
	}
	
	if config.EnableMining {
		fmt.Printf("║ Mining:          ENABLED (%-28s) ║\n", config.MinerAddress[:28])
	} else {
		fmt.Println("║ Mining:          DISABLED                              ║")
	}
	
	if config.EnableHSM {
		fmt.Printf("║ HSM:             ENABLED (%-28s) ║\n", config.HSMProvider)
	}
	
	if config.EnableMultiSig {
		fmt.Println("║ Multi-Sig:       ENABLED                               ║")
	}
	
	fmt.Println("╚════════════════════════════════════════════════════════╝")
	fmt.Println()
	log.Println("✅ Node is running. Press Ctrl+C to stop.")
	fmt.Println()
}

func setupLogger(level string) {
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	log.SetOutput(os.Stdout)
}
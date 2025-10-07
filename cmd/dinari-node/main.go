// cmd/dinari-node/main.go
package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/dgraph-io/badger/v4"
	"github.com/EmekaIwuagwu/dinari-blockchain/internal/core"
	"github.com/EmekaIwuagwu/dinari-blockchain/internal/mempool"
	"github.com/EmekaIwuagwu/dinari-blockchain/internal/types"
	"github.com/EmekaIwuagwu/dinari-blockchain/pkg/api"
	"github.com/EmekaIwuagwu/dinari-blockchain/pkg/crypto"
)

const (
	Version        = "1.0.0"
	DefaultDataDir = "./data"
	DefaultRPCPort = "8545"
	ChainID        = 1
)

var (
	dataDir      = flag.String("datadir", DefaultDataDir, "Data directory for blockchain data")
	rpcAddr      = flag.String("rpc", "localhost:"+DefaultRPCPort, "RPC server address")
	minerAddr    = flag.String("miner", "", "Miner address for block rewards")
	mine         = flag.Bool("mine", false, "Enable mining")
	createWallet = flag.Bool("create-wallet", false, "Create a new wallet and exit")
)

type DinariNode struct {
	config     *NodeConfig
	db         *badger.DB
	blockchain *core.Blockchain
	mempool    *mempool.Mempool
	rpcServer  *api.Server
	miner      *Miner
	ctx        context.Context
	cancel     context.CancelFunc
}

type NodeConfig struct {
	DataDir      string
	RPCAddr      string
	ChainID      uint64
	EnableMining bool
	MinerAddress string
}

type Miner struct {
	address    string
	blockchain *core.Blockchain
	mempool    *mempool.Mempool
	running    bool
	stopChan   chan struct{}
}

func main() {
	flag.Parse()

	if *createWallet {
		createNewWallet()
		return
	}

	config := &NodeConfig{
		DataDir:      *dataDir,
		RPCAddr:      *rpcAddr,
		ChainID:      ChainID,
		EnableMining: *mine,
		MinerAddress: *minerAddr,
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

	// Create data directory
	if err := os.MkdirAll(config.DataDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %w", err)
	}

	// Initialize database
	log.Println("💾 Initializing database...")
	dbPath := filepath.Join(config.DataDir, "chaindata")
	opts := badger.DefaultOptions(dbPath)
	opts.Logger = nil
	
	db, err := badger.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Initialize state with error handling
	log.Println("🔄 Initializing state...")
	stateDB, err := core.NewStateDB(db)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to create state: %w", err)
	}

	// Create genesis block
	log.Println("⛓️  Creating genesis block...")
	genesisBlock := createGenesisBlock()

	// Initialize blockchain
	log.Println("⛓️  Initializing blockchain...")
	blockchain, err := core.NewBlockchain(db, stateDB, genesisBlock)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to create blockchain: %w", err)
	}

	// Initialize mempool
	log.Println("🔄 Initializing mempool...")
	mempoolInstance := mempool.NewMempool()

	// Initialize RPC server
	log.Println("🌐 Initializing RPC server...")
	serverConfig := api.DefaultConfig()
	serverConfig.ListenAddr = config.RPCAddr
	serverConfig.TLSEnabled = false
	serverConfig.AuthEnabled = false
	
	rpcServer, err := api.NewServer(serverConfig)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to create RPC server: %w", err)
	}

	// Set blockchain and mempool
	rpcServer.SetBlockchain(blockchain)
	rpcServer.SetMempool(mempoolInstance)

	// Register RPC methods
	registerRPCMethods(rpcServer)

	// Initialize miner if enabled
	var miner *Miner
	if config.EnableMining {
		if config.MinerAddress == "" {
			db.Close()
			return nil, fmt.Errorf("miner address required when mining is enabled")
		}
		log.Printf("⛏️  Initializing miner (address: %s)...", config.MinerAddress)
		miner = &Miner{
			address:    config.MinerAddress,
			blockchain: blockchain,
			mempool:    mempoolInstance,
			stopChan:   make(chan struct{}),
		}
	}

	return &DinariNode{
		config:     config,
		db:         db,
		blockchain: blockchain,
		mempool:    mempoolInstance,
		rpcServer:  rpcServer,
		miner:      miner,
		ctx:        ctx,
		cancel:     cancel,
	}, nil
}

func (node *DinariNode) Start() error {
	log.Println("🚀 Starting Dinari node...")

	if err := node.rpcServer.Start(); err != nil {
		return fmt.Errorf("failed to start RPC server: %w", err)
	}

	if node.miner != nil {
		go node.miner.Start()
	}

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

	if node.db != nil {
		if err := node.db.Close(); err != nil {
			log.Printf("⚠️  Error closing database: %v", err)
		}
	}

	return nil
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
	// Get pending transactions (returns []*mempool.Transaction)
	mempoolTxs := m.mempool.GetPendingTransactions(1000)

	// Convert mempool transactions to types.Transaction
	txs := make([]*types.Transaction, 0, len(mempoolTxs))
	for _, mTx := range mempoolTxs {
		tx := convertMempoolTxToTypesTx(mTx)
		txs = append(txs, tx)
	}

	currentHeight := m.blockchain.GetHeight()
	prevHash := m.blockchain.GetBestHash()

	// Create coinbase transaction
	coinbaseTx := &types.Transaction{
		From:      "COINBASE",
		To:        m.address,
		Amount:    big.NewInt(5000000000),
		TokenType: string(types.TokenDNT),
		FeeDNT:    big.NewInt(0),
		Nonce:     0,
		Timestamp: time.Now().Unix(),
	}
	coinbaseTx.Hash = coinbaseTx.ComputeHash()

	// Combine transactions
	allTxs := append([]*types.Transaction{coinbaseTx}, txs...)

	// Create block
	block := &core.Block{
		Header: &core.BlockHeader{
			Version:       1,
			Height:        currentHeight + 1,
			PrevBlockHash: prevHash,
			Timestamp:     time.Now().Unix(),
			Difficulty:    1000,
			Nonce:         0,
		},
		Transactions: allTxs,
	}

	// Mine the block
	target := calculateTarget(block.Header.Difficulty)
	startTime := time.Now()

	for nonce := uint64(0); m.running; nonce++ {
		block.Header.Nonce = nonce
		hash := m.blockchain.CalculateBlockHash(block.Header)
		
		hashInt := new(big.Int).SetBytes(hash)
		if hashInt.Cmp(target) <= 0 {
			block.Header.Hash = hash
			log.Printf("⛏️  Block mined! Height: %d, Time: %v", 
				block.Header.Height, time.Since(startTime))

			if err := m.blockchain.AddBlock(block); err != nil {
				log.Printf("❌ Failed to add block: %v", err)
				return
			}

			// Remove mined transactions from mempool
			for _, mTx := range mempoolTxs {
				m.mempool.RemoveTransaction(mTx.Hash)
			}

			return
		}

		if nonce%10000 == 0 {
			select {
			case <-m.stopChan:
				return
			default:
			}
		}
	}
}

// convertMempoolTxToTypesTx converts mempool.Transaction to types.Transaction
func convertMempoolTxToTypesTx(mTx *mempool.Transaction) *types.Transaction {
	hash, _ := hex.DecodeString(mTx.Hash)
	var hashArray [32]byte
	copy(hashArray[:], hash)
	
	return &types.Transaction{
		Hash:      hashArray,
		From:      mTx.From,
		To:        mTx.To,
		Amount:    mTx.Amount,
		TokenType: mTx.TokenType,
		FeeDNT:    mTx.FeeDNT,
		Nonce:     mTx.Nonce,
		Timestamp: mTx.Timestamp,
		Signature: mTx.Signature,
		PublicKey: mTx.PublicKey,
	}
}

func calculateTarget(difficulty uint32) *big.Int {
	maxTarget := new(big.Int).Lsh(big.NewInt(1), 256)
	target := new(big.Int).Div(maxTarget, big.NewInt(int64(difficulty)))
	return target
}

func createGenesisBlock() *core.Block {
	genesisTx := &types.Transaction{
		From:      "GENESIS",
		To:        "D1000000000000000000000000000000000000",
		Amount:    big.NewInt(21000000 * 1e8),
		TokenType: string(types.TokenDNT),
		FeeDNT:    big.NewInt(0),
		Nonce:     0,
		Timestamp: 1704067200,
	}
	genesisTx.Hash = genesisTx.ComputeHash()

	genesis := &core.Block{
		Header: &core.BlockHeader{
			Version:       1,
			Height:        0,
			PrevBlockHash: make([]byte, 32),
			Timestamp:     1704067200,
			Difficulty:    1000,
			Nonce:         0,
			MerkleRoot:    make([]byte, 32),
			StateRoot:     make([]byte, 32),
		},
		Transactions: []*types.Transaction{genesisTx},
	}

	return genesis
}

func registerRPCMethods(server *api.Server) {
	server.RegisterMethod("tx.send", server.HandleTxSend)
	server.RegisterMethod("tx.get", server.HandleTxGet)
	server.RegisterMethod("tx.getPending", server.HandleTxGetPending)
	server.RegisterMethod("wallet.create", server.HandleWalletCreate)
	server.RegisterMethod("wallet.balance", server.HandleWalletBalance)
	server.RegisterMethod("chain.getBlock", server.HandleChainGetBlock)
	server.RegisterMethod("chain.getHeight", server.HandleChainGetHeight)
	server.RegisterMethod("chain.getStats", server.HandleChainGetStats)
}

func createNewWallet() {
	log.Println("🔐 Creating new wallet...")

	privKey, err := crypto.GeneratePrivateKey()
	if err != nil {
		log.Fatalf("❌ Failed to generate private key: %v", err)
	}

	pubKey := crypto.DerivePublicKey(privKey)
	address := crypto.PublicKeyToAddress(pubKey)

	fmt.Println("\n=== New Wallet Created ===")
	fmt.Printf("Address:     %s\n", address)
	fmt.Printf("Private Key: %s\n", crypto.PrivateKeyToHex(privKey))
	fmt.Println("\n⚠️  IMPORTANT: Save your private key securely!")
	fmt.Println("===========================\n")
}

func printBanner(config *NodeConfig) {
	fmt.Println("\n╔════════════════════════════════════════════════════════╗")
	fmt.Println("║           DINARI BLOCKCHAIN NODE v" + Version + "               ║")
	fmt.Println("╠════════════════════════════════════════════════════════╣")
	fmt.Printf("║ RPC Server:      %-37s ║\n", config.RPCAddr)
	fmt.Printf("║ Chain ID:        %-37d ║\n", config.ChainID)
	fmt.Printf("║ Data Directory:  %-37s ║\n", config.DataDir)
	
	if config.EnableMining {
		addrLen := len(config.MinerAddress)
		if addrLen > 28 {
			addrLen = 28
		}
		fmt.Printf("║ Mining:          ENABLED (%-28s) ║\n", config.MinerAddress[:addrLen])
	} else {
		fmt.Println("║ Mining:          DISABLED                              ║")
	}
	
	fmt.Println("╚════════════════════════════════════════════════════════╝")
	fmt.Println()
	log.Println("✅ Node is running. Press Ctrl+C to stop.")
	fmt.Println()
}
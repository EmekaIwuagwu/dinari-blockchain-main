package miner

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// Mining configuration
	DefaultNumThreads = 4
	MaxNumThreads     = 32
	
	// Block template refresh interval
	TemplateRefreshInterval = 10 * time.Second
	
	// Mining statistics update interval
	StatsUpdateInterval = 5 * time.Second
	
	// Transaction selection limits
	MaxTransactionsPerBlock = 5000
	MaxBlockSize            = 1 << 20 // 1MB
	
	// Mining parameters
	NonceRangePerThread = 0x100000 // 1M nonces per thread
	
	// Reward parameters
	InitialBlockReward = 50 * 1e8        // 50 DNT with 8 decimals
	HalvingInterval    = 210000          // Halve reward every 210,000 blocks
	MaxSupply          = 21000000 * 1e8  // 21M DNT total
	
	// Auto-restart settings
	MaxRestartAttempts = 3
	RestartDelay       = 5 * time.Second
)

var (
	ErrMinerNotRunning = errors.New("miner is not running")
	ErrMinerRunning    = errors.New("miner is already running")
	ErrInvalidAddress  = errors.New("invalid miner address")
	ErrNoTransactions  = errors.New("no transactions available")
)

// Block represents a mined block
type Block struct {
	Header       *BlockHeader
	Transactions []*Transaction
}

// BlockHeader represents block header
type BlockHeader struct {
	Version       uint32
	Height        uint64
	PrevBlockHash []byte
	MerkleRoot    []byte
	Timestamp     int64
	Difficulty    uint32
	Nonce         uint64
	Hash          []byte
	StateRoot     []byte
}

// Transaction represents a transaction
type Transaction struct {
	Hash      []byte
	From      string
	To        string
	Amount    *big.Int
	TokenType string
	FeeDNT    *big.Int
	Nonce     uint64
	Timestamp int64
	Signature []byte
	PublicKey []byte
	Data      []byte
}

// Miner manages the mining process
type Miner struct {
	// Configuration
	config *MinerConfig
	
	// External dependencies
	blockchain BlockchainInterface
	mempool    MempoolInterface
	consensus  ConsensusInterface
	
	// Mining state
	running   atomic.Bool
	mining    atomic.Bool
	stopChan  chan struct{}
	pauseChan chan struct{}
	
	// Worker management
	workers   []*MiningWorker
	workersMu sync.RWMutex
	
	// Statistics
	stats      *MiningStats
	statsMu    sync.RWMutex
	lastUpdate time.Time
	
	// Current mining job
	currentTemplate *BlockTemplate
	templateMu      sync.RWMutex
	
	// Lifecycle
	wg sync.WaitGroup
}

// MinerConfig contains miner configuration
type MinerConfig struct {
	MinerAddress    string
	NumThreads      int
	CoinbaseMessage []byte
	CPUPriority     int // 0-100, percentage of CPU to use
}

// MiningStats tracks mining statistics
type MiningStats struct {
	BlocksMined      uint64
	TotalHashes      uint64
	CurrentHashRate  float64
	AverageHashRate  float64
	StartTime        time.Time
	LastBlockTime    time.Time
	Uptime           time.Duration
	BlocksRejected   uint64
	
	// Economic stats
	TotalReward      *big.Int
	TotalFees        *big.Int
	EstimatedRevenue *big.Int
}

// BlockTemplate represents a template for mining
type BlockTemplate struct {
	Header       *BlockHeader
	Transactions []*Transaction
	TotalFees    *big.Int
	BlockReward  *big.Int
}

// MiningWorker represents a mining thread
type MiningWorker struct {
	id          int
	miner       *Miner
	stopChan    chan struct{}
	hashCounter uint64
}

// Interfaces for external dependencies
type BlockchainInterface interface {
	GetHeight() uint64
	GetBestHash() []byte
	GetDifficulty() uint32
	AddBlock(block *Block) error
	ValidateBlock(block *Block) error
}

type MempoolInterface interface {
	GetPendingTransactions(limit int) []*Transaction
	RemoveTransactions(hashes []string) error
}

type ConsensusInterface interface {
	CalculateHash(header *BlockHeader) []byte
	ValidateProofOfWork(header *BlockHeader) error
	CalculateNextDifficulty(prevHeight uint64) uint32
}

// NewMiner creates a new miner instance
func NewMiner(config *MinerConfig, blockchain BlockchainInterface, mempool MempoolInterface, consensus ConsensusInterface) (*Miner, error) {
	if err := validateMinerConfig(config); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	
	if blockchain == nil || mempool == nil || consensus == nil {
		return nil, errors.New("dependencies cannot be nil")
	}
	
	miner := &Miner{
		config:     config,
		blockchain: blockchain,
		mempool:    mempool,
		consensus:  consensus,
		stopChan:   make(chan struct{}),
		pauseChan:  make(chan struct{}),
		stats: &MiningStats{
			StartTime:        time.Now(),
			TotalReward:      big.NewInt(0),
			TotalFees:        big.NewInt(0),
			EstimatedRevenue: big.NewInt(0),
		},
		lastUpdate: time.Now(),
	}
	
	return miner, nil
}

// Start starts the mining process
func (m *Miner) Start() error {
	if m.running.Load() {
		return ErrMinerRunning
	}
	
	fmt.Printf("⛏️  Starting miner with %d threads\n", m.config.NumThreads)
	fmt.Printf("   Miner address: %s\n", m.config.MinerAddress)
	
	m.running.Store(true)
	m.stats.StartTime = time.Now()
	
	// Start mining coordinator
	m.wg.Add(1)
	go m.miningCoordinator()
	
	// Start statistics updater
	m.wg.Add(1)
	go m.statsUpdater()
	
	fmt.Println("✅ Miner started")
	
	return nil
}

// Stop gracefully stops the mining process
func (m *Miner) Stop() error {
	if !m.running.Load() {
		return ErrMinerNotRunning
	}
	
	fmt.Println("🛑 Stopping miner...")
	
	// Signal stop
	close(m.stopChan)
	
	// Stop all workers
	m.stopAllWorkers()
	
	// Wait for goroutines to finish
	m.wg.Wait()
	
	m.running.Store(false)
	m.mining.Store(false)
	
	// Print final statistics
	m.printFinalStats()
	
	fmt.Println("✅ Miner stopped")
	
	return nil
}

// Pause temporarily pauses mining
func (m *Miner) Pause() error {
	if !m.running.Load() {
		return ErrMinerNotRunning
	}
	
	if !m.mining.Load() {
		return errors.New("miner is not mining")
	}
	
	m.stopAllWorkers()
	m.mining.Store(false)
	
	fmt.Println("⏸️  Mining paused")
	
	return nil
}

// Resume resumes mining after pause
func (m *Miner) Resume() error {
	if !m.running.Load() {
		return ErrMinerNotRunning
	}
	
	if m.mining.Load() {
		return errors.New("miner is already mining")
	}
	
	m.mining.Store(true)
	m.startWorkers()
	
	fmt.Println("▶️  Mining resumed")
	
	return nil
}

// IsRunning returns whether the miner is running
func (m *Miner) IsRunning() bool {
	return m.running.Load()
}

// IsMining returns whether the miner is actively mining
func (m *Miner) IsMining() bool {
	return m.mining.Load()
}

// GetStats returns current mining statistics
func (m *Miner) GetStats() MiningStats {
	m.statsMu.RLock()
	defer m.statsMu.RUnlock()
	
	stats := *m.stats
	stats.Uptime = time.Since(stats.StartTime)
	
	return stats
}

// miningCoordinator manages the mining process
func (m *Miner) miningCoordinator() {
	defer m.wg.Done()
	
	templateTicker := time.NewTicker(TemplateRefreshInterval)
	defer templateTicker.Stop()
	
	for {
		select {
		case <-m.stopChan:
			return
			
		case <-templateTicker.C:
			// Refresh block template
			if err := m.refreshBlockTemplate(); err != nil {
				fmt.Printf("Failed to refresh template: %v\n", err)
				continue
			}
			
			// Start workers if not mining
			if !m.mining.Load() {
				m.mining.Store(true)
				m.startWorkers()
			}
		}
	}
}

// refreshBlockTemplate creates a new block template
func (m *Miner) refreshBlockTemplate() error {
	// Get blockchain state
	height := m.blockchain.GetHeight()
	prevHash := m.blockchain.GetBestHash()
	difficulty := m.blockchain.GetDifficulty()
	
	// Get pending transactions
	transactions := m.mempool.GetPendingTransactions(MaxTransactionsPerBlock)
	
	// Select best transactions by fee
	selectedTxs, totalFees := m.selectTransactions(transactions)
	
	// Calculate block reward
	blockReward := m.calculateBlockReward(height + 1)
	
	// Create coinbase transaction
	coinbaseTx := m.createCoinbaseTransaction(height+1, blockReward, totalFees)
	
	// Prepend coinbase
	allTxs := append([]*Transaction{coinbaseTx}, selectedTxs...)
	
	// Calculate merkle root
	merkleRoot := m.calculateMerkleRoot(allTxs)
	
	// Create block header
	header := &BlockHeader{
		Version:       1,
		Height:        height + 1,
		PrevBlockHash: prevHash,
		MerkleRoot:    merkleRoot,
		Timestamp:     time.Now().Unix(),
		Difficulty:    difficulty,
		Nonce:         0,
	}
	
	// Store template
	template := &BlockTemplate{
		Header:       header,
		Transactions: allTxs,
		TotalFees:    totalFees,
		BlockReward:  blockReward,
	}
	
	m.templateMu.Lock()
	m.currentTemplate = template
	m.templateMu.Unlock()
	
	fmt.Printf("📋 Block template refreshed: height=%d, txs=%d, fees=%s DNT\n",
		header.Height, len(selectedTxs), formatAmount(totalFees))
	
	return nil
}

// selectTransactions selects transactions based on fees
func (m *Miner) selectTransactions(txs []*Transaction) ([]*Transaction, *big.Int) {
	// Sort by fee per byte (already done in mempool)
	selected := make([]*Transaction, 0)
	totalFees := big.NewInt(0)
	totalSize := 0
	
	for _, tx := range txs {
		// Calculate transaction size
		txSize := m.estimateTransactionSize(tx)
		
		// Check if adding this tx would exceed block size
		if totalSize+txSize > MaxBlockSize {
			break
		}
		
		selected = append(selected, tx)
		totalFees.Add(totalFees, tx.FeeDNT)
		totalSize += txSize
	}
	
	return selected, totalFees
}

// startWorkers starts mining worker threads
func (m *Miner) startWorkers() {
	m.workersMu.Lock()
	defer m.workersMu.Unlock()
	
	// Clear existing workers
	m.workers = make([]*MiningWorker, 0, m.config.NumThreads)
	
	// Start new workers
	for i := 0; i < m.config.NumThreads; i++ {
		worker := &MiningWorker{
			id:       i,
			miner:    m,
			stopChan: make(chan struct{}),
		}
		
		m.workers = append(m.workers, worker)
		
		m.wg.Add(1)
		go worker.mine()
	}
	
	fmt.Printf("🔨 Started %d mining workers\n", m.config.NumThreads)
}

// stopAllWorkers stops all mining workers
func (m *Miner) stopAllWorkers() {
	m.workersMu.Lock()
	defer m.workersMu.Unlock()
	
	for _, worker := range m.workers {
		close(worker.stopChan)
	}
	
	m.workers = nil
}

// mine performs the actual mining work
func (w *MiningWorker) mine() {
	defer w.miner.wg.Done()
	
	for {
		select {
		case <-w.stopChan:
			return
			
		default:
			// Get current template
			w.miner.templateMu.RLock()
			template := w.miner.currentTemplate
			w.miner.templateMu.RUnlock()
			
			if template == nil {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			
			// Mine a nonce range
			if nonce, hash := w.mineNonceRange(template.Header); nonce > 0 {
				// Found valid block!
				w.handleBlockFound(template, nonce, hash)
				return
			}
		}
	}
}

// mineNonceRange tries to find a valid nonce in a range
func (w *MiningWorker) mineNonceRange(header *BlockHeader) (uint64, []byte) {
	// Calculate nonce range for this worker
	startNonce := uint64(w.id) * NonceRangePerThread
	endNonce := startNonce + NonceRangePerThread
	
	// Create a copy of header for this worker
	localHeader := &BlockHeader{
		Version:       header.Version,
		Height:        header.Height,
		PrevBlockHash: header.PrevBlockHash,
		MerkleRoot:    header.MerkleRoot,
		Timestamp:     time.Now().Unix(), // Fresh timestamp
		Difficulty:    header.Difficulty,
	}
	
	// Calculate target
	target := w.miner.difficultyToTarget(header.Difficulty)
	
	// Try nonces in range
	for nonce := startNonce; nonce < endNonce; nonce++ {
		// Check if we should stop
		select {
		case <-w.stopChan:
			return 0, nil
		default:
		}
		
		localHeader.Nonce = nonce
		hash := w.miner.consensus.CalculateHash(localHeader)
		
		// Increment hash counter
		atomic.AddUint64(&w.hashCounter, 1)
		w.miner.stats.TotalHashes++
		
		// Check if hash meets target
		hashInt := new(big.Int).SetBytes(hash)
		if hashInt.Cmp(target) <= 0 {
			return nonce, hash
		}
	}
	
	return 0, nil
}

// handleBlockFound processes a successfully mined block
func (w *MiningWorker) handleBlockFound(template *BlockTemplate, nonce uint64, hash []byte) {
	fmt.Printf("\n🎉 BLOCK FOUND! Height: %d, Nonce: %d\n", template.Header.Height, nonce)
	
	// Update header with winning nonce and hash
	template.Header.Nonce = nonce
	template.Header.Hash = hash
	
	// Create block
	block := &Block{
		Header:       template.Header,
		Transactions: template.Transactions,
	}
	
	// Submit block to blockchain
	if err := w.miner.blockchain.AddBlock(block); err != nil {
		fmt.Printf("❌ Block rejected: %v\n", err)
		w.miner.statsMu.Lock()
		w.miner.stats.BlocksRejected++
		w.miner.statsMu.Unlock()
		return
	}
	
	// Remove mined transactions from mempool
	txHashes := make([]string, 0, len(template.Transactions))
	for _, tx := range template.Transactions[1:] { // Skip coinbase
		txHashes = append(txHashes, string(tx.Hash))
	}
	w.miner.mempool.RemoveTransactions(txHashes)
	
	// Update statistics
	w.miner.statsMu.Lock()
	w.miner.stats.BlocksMined++
	w.miner.stats.LastBlockTime = time.Now()
	w.miner.stats.TotalReward.Add(w.miner.stats.TotalReward, template.BlockReward)
	w.miner.stats.TotalFees.Add(w.miner.stats.TotalFees, template.TotalFees)
	w.miner.statsMu.Unlock()
	
	fmt.Printf("💰 Reward: %s DNT + %s DNT fees\n",
		formatAmount(template.BlockReward),
		formatAmount(template.TotalFees))
}

// statsUpdater periodically updates mining statistics
func (m *Miner) statsUpdater() {
	defer m.wg.Done()
	
	ticker := time.NewTicker(StatsUpdateInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-m.stopChan:
			return
			
		case <-ticker.C:
			m.updateHashRate()
		}
	}
}

// updateHashRate calculates and updates hash rate
func (m *Miner) updateHashRate() {
	now := time.Now()
	duration := now.Sub(m.lastUpdate)
	
	if duration == 0 {
		return
	}
	
	m.workersMu.RLock()
	totalHashes := uint64(0)
	for _, worker := range m.workers {
		totalHashes += atomic.LoadUint64(&worker.hashCounter)
		atomic.StoreUint64(&worker.hashCounter, 0) // Reset counter
	}
	m.workersMu.RUnlock()
	
	hashRate := float64(totalHashes) / duration.Seconds()
	
	m.statsMu.Lock()
	m.stats.CurrentHashRate = hashRate
	
	// Update average hash rate
	if m.stats.AverageHashRate == 0 {
		m.stats.AverageHashRate = hashRate
	} else {
		// Exponential moving average
		alpha := 0.2
		m.stats.AverageHashRate = alpha*hashRate + (1-alpha)*m.stats.AverageHashRate
	}
	m.statsMu.Unlock()
	
	m.lastUpdate = now
	
	// Print status
	if m.mining.Load() {
		fmt.Printf("⛏️  Mining: %.2f kH/s (avg: %.2f kH/s) | Blocks: %d\n",
			hashRate/1000, m.stats.AverageHashRate/1000, m.stats.BlocksMined)
	}
}

// Helper methods

func (m *Miner) createCoinbaseTransaction(height uint64, reward, fees *big.Int) *Transaction {
	totalReward := new(big.Int).Add(reward, fees)
	
	tx := &Transaction{
		From:      "DINARIBASE",
		To:        m.config.MinerAddress,
		Amount:    totalReward,
		TokenType: "DNT",
		FeeDNT:    big.NewInt(0),
		Nonce:     height, // Use height as nonce for coinbase
		Timestamp: time.Now().Unix(),
		Data:      m.config.CoinbaseMessage,
	}
	
	// Calculate hash for coinbase transaction
	tx.Hash = HashTransaction(tx)
	
	return tx
}

func (m *Miner) calculateBlockReward(height uint64) *big.Int {
	halvings := height / HalvingInterval
	if halvings >= 64 {
		return big.NewInt(0) // All coins mined
	}
	
	reward := big.NewInt(InitialBlockReward)
	reward.Rsh(reward, uint(halvings)) // Divide by 2^halvings
	
	return reward
}

func (m *Miner) calculateMerkleRoot(txs []*Transaction) []byte {
	if len(txs) == 0 {
		return make([]byte, 32)
	}
	
	hashes := make([][]byte, len(txs))
	for i, tx := range txs {
		hashes[i] = tx.Hash
	}
	
	// Build merkle tree
	for len(hashes) > 1 {
		if len(hashes)%2 != 0 {
			hashes = append(hashes, hashes[len(hashes)-1])
		}
		
		newLevel := make([][]byte, 0, len(hashes)/2)
		for i := 0; i < len(hashes); i += 2 {
			combined := append(hashes[i], hashes[i+1]...)
			hash := sha256.Sum256(combined)
			newLevel = append(newLevel, hash[:])
		}
		hashes = newLevel
	}
	
	return hashes[0]
}

func (m *Miner) difficultyToTarget(difficulty uint32) *big.Int {
	maxTarget := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
	target := new(big.Int).Div(maxTarget, big.NewInt(int64(difficulty)))
	return target
}

func (m *Miner) estimateTransactionSize(tx *Transaction) int {
	// Rough estimate: 250 bytes per transaction
	return 250
}

func (m *Miner) printFinalStats() {
	stats := m.GetStats()
	
	fmt.Println("\n📊 Final Mining Statistics:")
	fmt.Printf("   Blocks Mined: %d\n", stats.BlocksMined)
	fmt.Printf("   Blocks Rejected: %d\n", stats.BlocksRejected)
	fmt.Printf("   Total Hashes: %d\n", stats.TotalHashes)
	fmt.Printf("   Average Hash Rate: %.2f kH/s\n", stats.AverageHashRate/1000)
	fmt.Printf("   Total Reward: %s DNT\n", formatAmount(stats.TotalReward))
	fmt.Printf("   Total Fees: %s DNT\n", formatAmount(stats.TotalFees))
	fmt.Printf("   Uptime: %v\n", stats.Uptime)
}

func validateMinerConfig(config *MinerConfig) error {
	if config.MinerAddress == "" {
		return ErrInvalidAddress
	}
	
	if config.NumThreads <= 0 {
		config.NumThreads = runtime.NumCPU()
	}
	
	if config.NumThreads > MaxNumThreads {
		config.NumThreads = MaxNumThreads
	}
	
	if config.CPUPriority < 0 || config.CPUPriority > 100 {
		config.CPUPriority = 100
	}
	
	return nil
}

func formatAmount(amount *big.Int) string {
	// Convert from smallest unit (8 decimals) to DNT
	divisor := big.NewInt(1e8)
	dnt := new(big.Int).Div(amount, divisor)
	remainder := new(big.Int).Mod(amount, divisor)
	
	if remainder.Sign() == 0 {
		return dnt.String()
	}
	
	return fmt.Sprintf("%s.%08d", dnt.String(), remainder.Uint64())
}

// HashTransaction creates a hash for a transaction
func HashTransaction(tx *Transaction) []byte {
	h := sha256.New()
	h.Write([]byte(tx.From))
	h.Write([]byte(tx.To))
	h.Write(tx.Amount.Bytes())
	h.Write([]byte(tx.TokenType))
	h.Write(tx.FeeDNT.Bytes())
	h.Write([]byte(fmt.Sprintf("%d", tx.Nonce)))
	h.Write([]byte(fmt.Sprintf("%d", tx.Timestamp)))
	if len(tx.Data) > 0 {
		h.Write(tx.Data)
	}
	return h.Sum(nil)
}
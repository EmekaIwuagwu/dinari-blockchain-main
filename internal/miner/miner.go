// internal/miner/miner.go
// PRODUCTION-GRADE MINING - NO CIRCULAR DEPENDENCIES

package miner

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/EmekaIwuagwu/dinari-blockchain/internal/types"
)

const (
	MaxTransactionsPerBlock = 5000
	NonceRange              = 1000000
	TargetBlockTime         = 15 * time.Second

	// Consensus constants (replicated to avoid import)
	DifficultyAdjustmentInterval = 120
	MinDifficulty                = 1000
	MaxDifficulty                = 0xFFFFFFFF
)

// BlockchainInterface defines what miner needs from blockchain
type BlockchainInterface interface {
	GetBlockByHeight(height uint64) (*types.Block, error)
	GetBlockByHash(hash []byte) (*types.Block, error)
	GetHeight() uint64
	GetBestHash() []byte
	GetDifficulty() uint32
	AddBlock(block *types.Block) error
	CalculateBlockHash(header *types.BlockHeader) []byte
}

// MempoolInterface defines what miner needs from mempool
type MempoolInterface interface {
	GetPendingTransactions(max int) []*types.Transaction
	RemoveTransactions(hashes []string)
}

// POWInterface defines what miner needs from consensus
type POWInterface interface {
	DifficultyToTarget(difficulty uint32) *big.Int
}

type Miner struct {
	blockchain BlockchainInterface
	mempool    MempoolInterface
	pow        POWInterface

	// Mining state
	mining     atomic.Bool
	workers    []*MiningWorker
	numWorkers int

	// Block template
	currentTemplate *BlockTemplate
	templateMu      sync.RWMutex

	// Submission control
	lastSubmitted     uint64
	lastSubmittedTime time.Time
	submitMu          sync.Mutex

	// Mining reward address
	minerAddress string

	// Control
	stopChan chan struct{}
	wg       sync.WaitGroup

	// Statistics
	stats   MiningStats
	statsMu sync.Mutex
}

type BlockTemplate struct {
	Header       *types.BlockHeader
	Transactions []*types.Transaction
	TotalFees    *big.Int
	BlockReward  *big.Int
}

type MiningStats struct {
	BlocksMined         uint64
	BlocksRejected      uint64
	TimestampRejections uint64 // 🔥 NEW
	TotalHashrate       uint64
	LastBlockTime       time.Time
	TotalReward         *big.Int
	TotalFees           *big.Int
	AverageBlockTime    time.Duration
}

type MiningWorker struct {
	id       int
	miner    *Miner
	stopChan chan struct{}
	hashrate uint64
}

func NewMiner(blockchain BlockchainInterface, mempool MempoolInterface, pow POWInterface, minerAddr string) *Miner {
	return &Miner{
		blockchain:   blockchain,
		mempool:      mempool,
		pow:          pow,
		minerAddress: minerAddr,
		numWorkers:   runtime.NumCPU(),
		stopChan:     make(chan struct{}),
		stats: MiningStats{
			TotalReward: big.NewInt(0),
			TotalFees:   big.NewInt(0),
		},
	}
}

func (m *Miner) Start() error {
	if m.mining.Load() {
		return errors.New("miner already running")
	}

	fmt.Printf("⛏️  Starting production miner with %d workers\n", m.numWorkers)
	fmt.Printf("📏 Enforcing strict %d second block intervals\n", int(TargetBlockTime.Seconds()))

	m.mining.Store(true)

	m.wg.Add(1)
	go m.miningCoordinator()

	return nil
}

func (m *Miner) miningCoordinator() {
	defer m.wg.Done()

	// 🔥 CRITICAL: Refresh every 5 seconds for template freshness
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopChan:
			m.stopWorkers()
			return

		case <-ticker.C:
			if !m.canMineNewBlock() {
				continue
			}

			// 🔥 CRITICAL: Always try to refresh on each tick
			if err := m.refreshBlockTemplate(); err != nil {
				if !strings.Contains(err.Error(), "too early") {
					fmt.Printf("⚠️  Template refresh error: %v\n", err)
				}
				continue
			}

			// 🔥 NEW: Check if template is stale before starting workers
			if m.isTemplateStale() {
				fmt.Printf("⚠️  Template is stale, forcing refresh...\n")
				continue
			}

			if m.currentTemplate != nil && !m.hasActiveWorkers() {
				m.startWorkers()
			}
		}
	}
}

func (m *Miner) isTemplateStale() bool {
	m.templateMu.RLock()
	template := m.currentTemplate
	m.templateMu.RUnlock()

	if template == nil {
		return true
	}

	// Template is stale if timestamp is more than 10 seconds old
	age := time.Now().Unix() - template.Header.Timestamp
	if age > 10 {
		fmt.Printf("🕐 Template age: %d seconds (stale threshold: 10 sec)\n", age)
		return true
	}

	return false
}

func (m *Miner) canMineNewBlock() bool {
	m.submitMu.Lock()
	defer m.submitMu.Unlock()

	if !m.lastSubmittedTime.IsZero() {
		elapsed := time.Since(m.lastSubmittedTime)
		if elapsed < TargetBlockTime {
			remaining := TargetBlockTime - elapsed
			if remaining > time.Second {
				fmt.Printf("⏳ Waiting %d seconds before next block (interval enforcement)\n",
					int(remaining.Seconds()))
			}
			return false
		}
	}

	currentHeight := m.blockchain.GetHeight()
	if currentHeight > 0 {
		prevBlock, err := m.blockchain.GetBlockByHeight(currentHeight)
		if err == nil && prevBlock != nil {
			minTimestamp := prevBlock.Header.Timestamp + int64(TargetBlockTime.Seconds())
			currentTime := time.Now().Unix()

			if currentTime < minTimestamp {
				remaining := minTimestamp - currentTime
				if remaining > 1 {
					fmt.Printf("⏳ Chain enforces wait: %d seconds until next valid timestamp\n", remaining)
				}
				return false
			}
		}
	}

	return true
}

func (m *Miner) refreshBlockTemplate() error {
	m.templateMu.Lock()
	defer m.templateMu.Unlock()

	height := m.blockchain.GetHeight()
	prevHash := m.blockchain.GetBestHash()

	var minValidTimestamp int64
	if height > 0 {
		prevBlock, err := m.blockchain.GetBlockByHeight(height)
		if err != nil {
			return fmt.Errorf("failed to get previous block: %w", err)
		}

		minValidTimestamp = prevBlock.Header.Timestamp + int64(TargetBlockTime.Seconds())
		currentTime := time.Now().Unix()

		if currentTime < minValidTimestamp {
			return fmt.Errorf("too early to mine: %d seconds remaining", minValidTimestamp-currentTime)
		}

		if currentTime >= minValidTimestamp {
			minValidTimestamp = currentTime
		}
	} else {
		minValidTimestamp = time.Now().Unix()
	}

	difficulty := m.calculateNextDifficulty(height + 1)

	transactions := m.mempool.GetPendingTransactions(MaxTransactionsPerBlock)
	selectedTxs, totalFees := m.selectTransactions(transactions)

	blockReward := m.calculateBlockReward(height + 1)
	totalReward := new(big.Int).Add(blockReward, totalFees)
	coinbaseTx := m.createCoinbaseTransaction(height+1, totalReward)

	allTxs := append([]*types.Transaction{coinbaseTx}, selectedTxs...)
	merkleRoot := m.calculateMerkleRoot(allTxs)

	header := &types.BlockHeader{
		Version:       1,
		Height:        height + 1,
		PrevBlockHash: prevHash,
		MerkleRoot:    merkleRoot,
		Timestamp:     minValidTimestamp,
		Difficulty:    difficulty,
		Nonce:         0,
	}

	m.currentTemplate = &BlockTemplate{
		Header:       header,
		Transactions: allTxs,
		TotalFees:    totalFees,
		BlockReward:  blockReward,
	}

	fmt.Printf("📋 Template ready: height=%d, difficulty=%d, timestamp=%d (enforced)\n",
		header.Height, difficulty, minValidTimestamp)

	return nil
}

func (m *Miner) calculateNextDifficulty(nextHeight uint64) uint32 {
	currentDifficulty := m.blockchain.GetDifficulty()

	if nextHeight%DifficultyAdjustmentInterval != 0 {
		return currentDifficulty
	}

	if nextHeight < DifficultyAdjustmentInterval {
		return currentDifficulty
	}

	startHeight := nextHeight - DifficultyAdjustmentInterval
	endHeight := nextHeight - 1

	startBlock, err1 := m.blockchain.GetBlockByHeight(startHeight)
	endBlock, err2 := m.blockchain.GetBlockByHeight(endHeight)

	if err1 != nil || err2 != nil {
		fmt.Printf("⚠️  Cannot calculate difficulty adjustment, using current\n")
		return currentDifficulty
	}

	actualTime := endBlock.Header.Timestamp - startBlock.Header.Timestamp
	expectedTime := int64(DifficultyAdjustmentInterval) * int64(TargetBlockTime.Seconds())

	if actualTime <= 0 {
		return currentDifficulty
	}

	ratio := float64(expectedTime) / float64(actualTime)

	if ratio > 4.0 {
		ratio = 4.0
	}
	if ratio < 0.25 {
		ratio = 0.25
	}

	newDifficulty := uint32(float64(currentDifficulty) * ratio)

	if newDifficulty < MinDifficulty {
		newDifficulty = MinDifficulty
	}
	if newDifficulty > MaxDifficulty {
		newDifficulty = MaxDifficulty
	}

	fmt.Printf("📊 DIFFICULTY ADJUSTMENT at height %d:\n", nextHeight)
	fmt.Printf("   Actual time: %d sec | Expected: %d sec\n", actualTime, expectedTime)
	fmt.Printf("   Ratio: %.4f | Old difficulty: %d → New: %d\n", ratio, currentDifficulty, newDifficulty)

	return newDifficulty
}

func (m *Miner) startWorkers() {
	if m.hasActiveWorkers() {
		return
	}

	m.workers = make([]*MiningWorker, m.numWorkers)
	for i := 0; i < m.numWorkers; i++ {
		worker := &MiningWorker{
			id:       i,
			miner:    m,
			stopChan: make(chan struct{}),
		}
		m.workers[i] = worker

		m.wg.Add(1)
		go worker.mine()
	}

	fmt.Printf("🚀 Started %d mining workers\n", m.numWorkers)
}

func (m *Miner) stopWorkers() {
	for _, worker := range m.workers {
		if worker != nil {
			close(worker.stopChan)
		}
	}
	m.workers = nil
}

func (m *Miner) hasActiveWorkers() bool {
	return len(m.workers) > 0
}

// internal/miner/miner.go

func (w *MiningWorker) mine() {
	defer w.miner.wg.Done()

	lastTemplateCheck := time.Now()

	for {
		select {
		case <-w.stopChan:
			return

		default:
			// 🔥 NEW: Check template freshness every 5 seconds
			if time.Since(lastTemplateCheck) > 5*time.Second {
				lastTemplateCheck = time.Now()

				w.miner.templateMu.RLock()
				template := w.miner.currentTemplate
				w.miner.templateMu.RUnlock()

				if template == nil {
					time.Sleep(100 * time.Millisecond)
					continue
				}

				// 🔥 CRITICAL: Abandon if template is >10 seconds old
				templateAge := time.Now().Unix() - template.Header.Timestamp
				if templateAge > 10 {
					fmt.Printf("⏰ Worker %d: Template stale (%d sec old), waiting for refresh\n",
						w.id, templateAge)
					time.Sleep(time.Second)
					continue
				}
			}

			w.miner.templateMu.RLock()
			template := w.miner.currentTemplate
			w.miner.templateMu.RUnlock()

			if template == nil {
				time.Sleep(100 * time.Millisecond)
				continue
			}

			// 🔥 Double-check validity before mining
			if !w.isTimestampStillValid(template) {
				time.Sleep(time.Second)
				continue
			}

			if nonce, hash := w.mineNonceRange(template.Header); nonce > 0 {
				w.handleBlockFound(template, nonce, hash)
			}
		}
	}
}

func (w *MiningWorker) isTimestampStillValid(template *BlockTemplate) bool {
	if template.Header.Height <= 1 {
		return true
	}

	prevBlock, err := w.miner.blockchain.GetBlockByHeight(template.Header.Height - 1)
	if err != nil {
		return false
	}

	minTime := prevBlock.Header.Timestamp + int64(TargetBlockTime.Seconds())
	return template.Header.Timestamp >= minTime
}

func (w *MiningWorker) mineNonceRange(header *types.BlockHeader) (uint64, []byte) {
	startNonce := uint64(w.id) * NonceRange
	endNonce := startNonce + NonceRange

	target := w.miner.pow.DifficultyToTarget(header.Difficulty)

	for nonce := startNonce; nonce < endNonce; nonce++ {
		header.Nonce = nonce
		hash := w.miner.blockchain.CalculateBlockHash(header)

		hashInt := new(big.Int).SetBytes(hash)
		if hashInt.Cmp(target) <= 0 {
			return nonce, hash
		}

		if nonce%10000 == 0 {
			select {
			case <-w.stopChan:
				return 0, nil
			default:
			}
		}
	}

	return 0, nil
}

func (w *MiningWorker) handleBlockFound(template *BlockTemplate, nonce uint64, hash []byte) {
	w.miner.submitMu.Lock()
	defer w.miner.submitMu.Unlock()

	if template.Header.Height <= w.miner.lastSubmitted {
		return
	}

	// 🔥 CRITICAL: Validate timestamp BEFORE using the nonce
	// The nonce was found for the template's original timestamp
	// We can only adjust the timestamp within valid ranges

	finalTimestamp := template.Header.Timestamp // Start with template timestamp

	// For blocks after genesis, enforce timestamp rules
	if template.Header.Height > 1 {
		prevBlock, err := w.miner.blockchain.GetBlockByHeight(template.Header.Height - 1)
		if err != nil {
			fmt.Printf("❌ Could not get previous block: %v\n", err)
			return
		}

		minTime := prevBlock.Header.Timestamp + int64(TargetBlockTime.Seconds())
		maxTime := prevBlock.Header.Timestamp + int64(300) // 5 minutes max

		// 🔥 IMPORTANT: Use template timestamp, not current time
		// because the nonce was mined with that timestamp
		templateTime := template.Header.Timestamp

		// Validate template timestamp is within range
		if templateTime < minTime {
			fmt.Printf("❌ Template timestamp %d is before minimum %d\n", templateTime, minTime)
			return
		}

		if templateTime > maxTime {
			fmt.Printf("❌ Template timestamp %d exceeds maximum %d\n", templateTime, maxTime)
			return
		}

		// Calculate actual interval that will be used
		timeDiff := templateTime - prevBlock.Header.Timestamp

		// 🔥 DEFENSIVE: Double-check interval is valid before submission
		if timeDiff < int64(TargetBlockTime.Seconds()) {
			fmt.Printf("❌ BLOCK REJECTED: Interval too small (%d sec, min required: %d)\n",
				timeDiff, int(TargetBlockTime.Seconds()))
			return
		}

		if timeDiff > int64(300) {
			fmt.Printf("❌ BLOCK REJECTED: Interval too large (%d sec, max allowed: 300)\n", timeDiff)
			return
		}

		fmt.Printf("✅ Valid interval: %d seconds (range: 15-300 sec)\n", timeDiff)
		finalTimestamp = templateTime
	}

	// 🔥 CRITICAL: Keep the header timestamp as-is for hash verification
	// The nonce was found with this timestamp, so the hash must be valid
	template.Header.Nonce = nonce

	// Verify the hash with original timestamp and nonce
	verifyHash := w.miner.blockchain.CalculateBlockHash(template.Header)

	// 🔥 CRITICAL: Verify hash still meets difficulty
	target := w.miner.pow.DifficultyToTarget(template.Header.Difficulty)
	hashInt := new(big.Int).SetBytes(verifyHash)

	if hashInt.Cmp(target) > 0 {
		fmt.Printf("⚠️  Hash verification failed - doesn't meet difficulty target\n")
		return
	}

	fmt.Printf("\n🎉 VALID BLOCK FOUND!\n")
	fmt.Printf("   Height: %d | Nonce: %d | Timestamp: %d\n",
		template.Header.Height, nonce, finalTimestamp)

	// Create final header with verified data
	finalHeader := &types.BlockHeader{
		Version:       template.Header.Version,
		Height:        template.Header.Height,
		PrevBlockHash: template.Header.PrevBlockHash,
		MerkleRoot:    template.Header.MerkleRoot,
		Timestamp:     finalTimestamp, // Use the validated template timestamp
		Difficulty:    template.Header.Difficulty,
		Nonce:         nonce,
		Hash:          verifyHash, // Use the verified hash
		StateRoot:     template.Header.StateRoot,
	}

	block := &types.Block{
		Header:       finalHeader,
		Transactions: template.Transactions,
	}

	if err := w.miner.blockchain.AddBlock(block); err != nil {
		fmt.Printf("❌ Block rejected: %v\n", err)

		// 🔥 MONITORING: Track timestamp rejections
		if strings.Contains(err.Error(), "timestamp") {
			w.miner.statsMu.Lock()
			w.miner.stats.TimestampRejections++
			rejections := w.miner.stats.TimestampRejections
			w.miner.statsMu.Unlock()

			// 🔥 ALERT: Too many timestamp rejections
			if rejections > 5 {
				fmt.Printf("🚨 ALERT: %d consecutive timestamp rejections!\n", rejections)
				fmt.Printf("🚨 This indicates timestamp validation is still failing!\n")
			}

			// 🔥 Force template refresh on timestamp rejection
			fmt.Printf("🔄 Timestamp rejection - forcing template refresh\n")
			go w.miner.forceTemplateRefresh()
		}

		w.miner.statsMu.Lock()
		w.miner.stats.BlocksRejected++
		w.miner.statsMu.Unlock()
		return
	}

	// ✅ SUCCESS PATH
	w.miner.lastSubmitted = template.Header.Height
	w.miner.lastSubmittedTime = time.Now()

	// 🔥 CRITICAL: Remove mined transactions from mempool
	txHashes := make([]string, 0, len(template.Transactions))
	for _, tx := range template.Transactions {
		// Skip coinbase transaction (index 0)
		if !tx.IsCoinbase() {
			txHashes = append(txHashes, hex.EncodeToString(tx.Hash[:]))
		}
	}
	if len(txHashes) > 0 {
		w.miner.mempool.RemoveTransactions(txHashes)
		fmt.Printf("🗑️  Removed %d mined transactions from mempool\n", len(txHashes))
	}

	// 🔥 Reset timestamp rejection counter on success
	w.miner.statsMu.Lock()
	w.miner.stats.BlocksMined++
	w.miner.stats.LastBlockTime = time.Now()
	w.miner.stats.TotalReward.Add(w.miner.stats.TotalReward, template.BlockReward)
	w.miner.stats.TotalFees.Add(w.miner.stats.TotalFees, template.TotalFees)
	w.miner.stats.TimestampRejections = 0 // 🔥 Reset counter on success
	w.miner.statsMu.Unlock()

	fmt.Printf("✅ Block #%d ACCEPTED and added to chain\n", template.Header.Height)
	fmt.Printf("   📦 Block Hash:    %x\n", verifyHash)
	fmt.Printf("   🔗 Previous Hash: %x\n", template.Header.PrevBlockHash)
	fmt.Printf("   💰 Reward: %s DNT | Fees: %s DNT\n",
		formatAmount(template.BlockReward), formatAmount(template.TotalFees))
	fmt.Printf("   ⛏️  Nonce: %d | Difficulty: %d\n", nonce, template.Header.Difficulty)
	fmt.Printf("   ⏱️  Timestamp: %d\n\n", finalTimestamp)

	w.miner.stopWorkers()
}

// 🔥 NEW: Force template refresh (called on rejection)
func (m *Miner) forceTemplateRefresh() {
	time.Sleep(100 * time.Millisecond) // Brief pause to avoid race
	if err := m.refreshBlockTemplate(); err != nil {
		fmt.Printf("⚠️  Force refresh failed: %v\n", err)
	} else {
		fmt.Printf("✅ Template forcibly refreshed\n")
	}
}

func (m *Miner) selectTransactions(txs []*types.Transaction) ([]*types.Transaction, *big.Int) {
	totalFees := big.NewInt(0)
	return txs, totalFees
}

func (m *Miner) createCoinbaseTransaction(height uint64, reward *big.Int) *types.Transaction {
	return &types.Transaction{
		From:   "COINBASE",
		To:     m.minerAddress,
		Amount: reward,
	}
}

func (m *Miner) calculateBlockReward(height uint64) *big.Int {
	const InitialReward = 50 * 1e8
	const HalvingInterval = 210000

	halvings := height / HalvingInterval
	if halvings >= 64 {
		return big.NewInt(0)
	}

	reward := big.NewInt(InitialReward)
	reward.Rsh(reward, uint(halvings))
	return reward
}

func (m *Miner) calculateMerkleRoot(txs []*types.Transaction) []byte {
	if len(txs) == 0 {
		return make([]byte, 32)
	}

	var hashes [][]byte
	for _, tx := range txs {
		hashes = append(hashes, tx.Hash[:])
	}

	for len(hashes) > 1 {
		if len(hashes)%2 != 0 {
			hashes = append(hashes, hashes[len(hashes)-1])
		}

		var newLevel [][]byte
		for i := 0; i < len(hashes); i += 2 {
			combined := append(hashes[i], hashes[i+1]...)
			hash := sha256.Sum256(combined)
			newLevel = append(newLevel, hash[:])
		}
		hashes = newLevel
	}

	return hashes[0]
}

func (m *Miner) Stop() {
	if !m.mining.Load() {
		return
	}

	fmt.Println("🛑 Stopping miner...")
	m.mining.Store(false)
	close(m.stopChan)
	m.wg.Wait()
	fmt.Println("✅ Miner stopped")
}

func formatAmount(amount *big.Int) string {
	if amount == nil {
		return "0"
	}
	// Convert to DNT with 8 decimals
	// Amount is stored as smallest unit (satoshis)
	divisor := big.NewInt(100000000) // 1e8
	quotient := new(big.Int).Div(amount, divisor)
	remainder := new(big.Int).Mod(amount, divisor)

	if remainder.Sign() == 0 {
		return quotient.String()
	}

	// Format with decimals
	return fmt.Sprintf("%s.%08d", quotient.String(), remainder.Int64())
}

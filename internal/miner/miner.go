package miner

import (
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/EmekaIwuagwu/dinari-blockchain/internal/consensus"
	"github.com/EmekaIwuagwu/dinari-blockchain/internal/core"
	"github.com/EmekaIwuagwu/dinari-blockchain/internal/mempool"
	"github.com/EmekaIwuagwu/dinari-blockchain/internal/types"
	"go.uber.org/zap"
)

const (
	// MaxBlockSize is the maximum size of a block in bytes
	MaxBlockSize = 1024 * 1024 // 1MB

	// MaxTxPerBlock is the maximum number of transactions per block
	MaxTxPerBlock = 10000
)

// Miner handles block mining
type Miner struct {
	blockchain   *core.Blockchain
	mempool      *mempool.Mempool
	pow          *consensus.ProofOfWork
	rewardCalc   *consensus.RewardCalculator
	diffAdjust   *consensus.DifficultyAdjuster
	logger       *zap.Logger
	minerAddress string

	// Mining control
	mining   bool
	stopChan chan struct{}
	mu       sync.RWMutex

	// Statistics
	blocksMinedCount uint64
	hashesComputed   uint64
}

// Config contains miner configuration
type Config struct {
	Blockchain   *core.Blockchain
	Mempool      *mempool.Mempool
	Logger       *zap.Logger
	MinerAddress string
}

// NewMiner creates a new miner instance
func NewMiner(config *Config) *Miner {
	return &Miner{
		blockchain:   config.Blockchain,
		mempool:      config.Mempool,
		pow:          consensus.NewProofOfWork(consensus.TargetBlockTime),
		rewardCalc:   consensus.NewRewardCalculator(),
		diffAdjust:   consensus.NewDifficultyAdjuster(),
		logger:       config.Logger,
		minerAddress: config.MinerAddress,
		stopChan:     make(chan struct{}),
	}
}

// Start starts the mining process
func (m *Miner) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.mining {
		return fmt.Errorf("miner already running")
	}

	m.mining = true
	m.stopChan = make(chan struct{})

	go m.miningLoop()

	m.logger.Info("Miner started", zap.String("address", m.minerAddress))
	return nil
}

// Stop stops the mining process
func (m *Miner) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.mining {
		return
	}

	m.mining = false
	close(m.stopChan)

	m.logger.Info("Miner stopped")
}

// IsRunning returns true if miner is currently mining
func (m *Miner) IsRunning() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.mining
}

// miningLoop is the main mining loop
// miningLoop is the main mining loop
func (m *Miner) miningLoop() {
	for {
		select {
		case <-m.stopChan:
			return
		default:
			// Mine a block
			block, err := m.mineBlock()
			if err != nil {
				m.logger.Error("Mining failed", zap.Error(err))
				time.Sleep(time.Second)
				continue
			}

			if block != nil {
				// Calculate reward info for logging
				baseReward := m.rewardCalc.CalculateBlockReward(block.Header.Number)
				totalFees := big.NewInt(0)
				for _, tx := range block.Transactions[1:] {
					totalFees.Add(totalFees, tx.FeeDNT)
				}
				totalReward := new(big.Int).Add(baseReward, totalFees)

				// Add block to blockchain
				if err := m.blockchain.AddBlock(block); err != nil {
					m.logger.Error("Failed to add mined block", zap.Error(err))
					continue
				}

				m.blocksMinedCount++

				m.logger.Info("🎉 BLOCK MINED SUCCESSFULLY! 🎉",
					zap.Uint64("height", block.Header.Number),
					zap.String("hash", fmt.Sprintf("%x", block.Hash[:16])),
					zap.Uint32("txCount", block.Header.TxCount),
					zap.String("miner", m.minerAddress),
					zap.String("baseReward", baseReward.String()),
					zap.String("fees", totalFees.String()),
					zap.String("totalReward", totalReward.String()),
					zap.Uint64("nonce", block.Header.Nonce))

				// Remove mined transactions from mempool
				for _, tx := range block.Transactions {
					if !tx.IsCoinbase() {
						m.mempool.RemoveTransaction(tx.Hash)
					}
				}
			}
		}
	}
}

// mineBlock creates and mines a new block
func (m *Miner) mineBlock() (*types.Block, error) {
	// Get current chain state
	height := m.blockchain.GetHeight()
	tip := m.blockchain.GetTip()

	// Calculate difficulty for next block
	difficulty := m.calculateNextDifficulty()

	// Assemble block
	block, err := m.assembleBlock(height+1, tip, difficulty)
	if err != nil {
		return nil, fmt.Errorf("failed to assemble block: %w", err)
	}

	// Mine the block (find valid nonce)
	m.logger.Debug("Mining block",
		zap.Uint64("height", block.Header.Number),
		zap.String("difficulty", difficulty.String()))

	startTime := time.Now()
	nonce, found := m.pow.MineBlock(block, m.stopChan)

	if !found {
		// Mining was stopped
		return nil, nil
	}

	duration := time.Since(startTime)

	block.Header.Nonce = nonce
	block.Hash = block.ComputeHash()

	m.logger.Info("Valid nonce found",
		zap.Uint64("nonce", nonce),
		zap.Duration("duration", duration))

	return block, nil
}

// assembleBlock assembles a new block with transactions from mempool
func (m *Miner) assembleBlock(number uint64, parentHash [32]byte, difficulty *big.Int) (*types.Block, error) {
	// Get transactions from mempool (sorted by priority)
	pendingTxs := m.mempool.GetTransactions(MaxTxPerBlock)

	// Create coinbase transaction
	blockReward := m.rewardCalc.CalculateBlockReward(number)
	coinbaseTx := types.NewCoinbaseTransaction(m.minerAddress, blockReward, number)

	// Calculate total fees
	totalFees := big.NewInt(0)
	transactions := []*types.Transaction{coinbaseTx}
	blockSize := coinbaseTx.Size()

	// Add transactions while respecting limits
	for _, tx := range pendingTxs {
		txSize := tx.Size()

		// Check block size limit
		if blockSize+txSize > MaxBlockSize {
			break
		}

		// Check tx count limit
		if len(transactions) >= MaxTxPerBlock {
			break
		}

		// Validate transaction against current state
		if err := m.validateTxForBlock(tx); err != nil {
			m.logger.Debug("Skipping invalid transaction",
				zap.String("hash", fmt.Sprintf("%x", tx.Hash[:8])),
				zap.Error(err))
			continue
		}

		transactions = append(transactions, tx)
		totalFees.Add(totalFees, tx.FeeDNT)
		blockSize += txSize
	}

	// Add total fees to coinbase
	coinbaseTx.Amount.Add(coinbaseTx.Amount, totalFees)

	// Create block
	block := types.NewBlock(parentHash, number, transactions, m.minerAddress, difficulty)

	return block, nil
}

// validateTxForBlock validates a transaction for inclusion in a block
// validateTxForBlock validates a transaction for inclusion in a block
func (m *Miner) validateTxForBlock(tx *types.Transaction) error {
	// Special handling for mint transactions
	if tx.IsMint() {
		// Mint transactions create new tokens, so they don't need balance checks
		// Just do basic validation
		if tx.TokenType != string(types.TokenAFC) {
			return types.ErrMintOnlyAFC
		}
		if tx.FeeDNT.Cmp(big.NewInt(0)) != 0 {
			return types.ErrInvalidMintTx
		}
		// Mint is valid
		return nil
	}

	// Basic validation
	if err := tx.Validate(); err != nil {
		return err
	}

	// Get account state
	account, err := m.blockchain.GetState().GetAccount(tx.From)
	if err != nil {
		return err
	}

	// Verify nonce
	if tx.Nonce != account.Nonce {
		return types.ErrInvalidNonce
	}

	// Verify balances
	requiredDNT := new(big.Int).Set(tx.FeeDNT)
	if tx.TokenType == string(types.TokenDNT) {
		requiredDNT.Add(requiredDNT, tx.Amount)
	}

	if account.BalanceDNT.Cmp(requiredDNT) < 0 {
		return types.ErrInsufficientBalance
	}

	if tx.TokenType == string(types.TokenAFC) {
		if account.BalanceAFC.Cmp(tx.Amount) < 0 {
			return types.ErrInsufficientBalance
		}
	}

	return nil
}

// calculateNextDifficulty calculates the difficulty for the next block
func (m *Miner) calculateNextDifficulty() *big.Int {
	height := m.blockchain.GetHeight()
	nextHeight := height + 1

	// Check if difficulty adjustment should occur
	if !m.diffAdjust.ShouldAdjustDifficulty(nextHeight) {
		// Use current difficulty
		currentBlock, err := m.blockchain.GetBlock(height)
		if err != nil {
			return big.NewInt(consensus.MinDifficulty)
		}
		return currentBlock.Header.Difficulty
	}

	// Get recent blocks for difficulty calculation
	recentBlocks := make([]*types.BlockHeader, 0, consensus.DifficultyWindow)
	for i := uint64(0); i < consensus.DifficultyWindow && i <= height; i++ {
		blockHeight := height - i
		block, err := m.blockchain.GetBlock(blockHeight)
		if err != nil {
			break
		}
		recentBlocks = append([]*types.BlockHeader{block.Header}, recentBlocks...)
	}

	// Calculate new difficulty
	return m.diffAdjust.CalculateNextDifficulty(recentBlocks)
}

// Stats returns miner statistics
func (m *Miner) Stats() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return map[string]interface{}{
		"mining":      m.mining,
		"blocksMinedCount": m.blocksMinedCount,
		"minerAddress": m.minerAddress,
	}
}

// SetMinerAddress updates the miner address
func (m *Miner) SetMinerAddress(address string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.minerAddress = address
	m.logger.Info("Miner address updated", zap.String("address", address))
}

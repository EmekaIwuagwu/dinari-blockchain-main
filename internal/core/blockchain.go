// internal/core/blockchain.go
package core

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/EmekaIwuagwu/dinari-blockchain/internal/consensus"
	"github.com/EmekaIwuagwu/dinari-blockchain/internal/storage"
	"github.com/EmekaIwuagwu/dinari-blockchain/internal/types"
	"go.uber.org/zap"
)

const (
	// MaxBlockSize is the maximum size of a block in bytes
	MaxBlockSize = 2 * 1024 * 1024 // 2MB

	// MaxReorgDepth is the maximum depth for chain reorganization
	MaxReorgDepth = 100

	// BlockValidationTimeout is the timeout for validating a single block
	BlockValidationTimeout = 30 * time.Second

	// StateCommitTimeout is the timeout for committing state changes
	StateCommitTimeout = 60 * time.Second

	// MaxConcurrentValidations is the maximum number of concurrent block validations
	MaxConcurrentValidations = 10

	// MinConfirmations is the minimum number of confirmations considered safe
	MinConfirmations = 6

	// OrphanBlockTTL is how long to keep orphan blocks
	OrphanBlockTTL = 24 * time.Hour

	// MaxOrphanBlocks is the maximum number of orphan blocks to store
	MaxOrphanBlocks = 100
)

// Blockchain manages the chain of blocks with production-grade safety
type Blockchain struct {
	// Core components
	db     *storage.DB
	state  *State
	logger *zap.Logger

	// Consensus components
	pow              *consensus.ProofOfWork
	difficultyAdjust *consensus.DifficultyAdjuster
	rewardCalc       *consensus.RewardCalculator

	// Chain metadata (protected by mutex)
	tip    [32]byte
	height uint64
	mu     sync.RWMutex

	// Mint authorities for AFC (immutable after initialization)
	mintAuthorities map[string]bool

	// Orphan block management
	orphanBlocks      map[[32]byte]*OrphanBlock
	orphanBlocksMutex sync.RWMutex

	// Validation rate limiting
	validationSemaphore chan struct{}

	// Metrics
	metrics *BlockchainMetrics

	// Shutdown management
	ctx        context.Context
	cancelFunc context.CancelFunc
	wg         sync.WaitGroup
}

// OrphanBlock represents a block waiting for its parent
type OrphanBlock struct {
	Block     *types.Block
	ReceivedAt time.Time
}

// BlockchainMetrics tracks blockchain performance and health
type BlockchainMetrics struct {
	TotalBlocks           uint64
	TotalTransactions     uint64
	ValidationErrors      uint64
	StateCommitErrors     uint64
	OrphanBlocksReceived  uint64
	ReorganizationsCount  uint64
	AverageBlockTime      time.Duration
	LastBlockTime         time.Time
	mu                    sync.RWMutex
}

// Config contains blockchain configuration
type Config struct {
	DB              *storage.DB
	Logger          *zap.Logger
	MintAuthorities []string
	// Future: Add more config options like network ID, chain ID, etc.
}

// NewBlockchain creates a new blockchain instance with full validation
func NewBlockchain(config *Config) (*Blockchain, error) {
	// Validate configuration
	if err := validateBlockchainConfig(config); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())

	bc := &Blockchain{
		db:                  config.DB,
		state:               NewState(config.DB, config.Logger),
		logger:              config.Logger,
		pow:                 consensus.NewProofOfWork(consensus.TargetBlockTime),
		difficultyAdjust:    consensus.NewDifficultyAdjuster(),
		rewardCalc:          consensus.NewRewardCalculator(),
		mintAuthorities:     make(map[string]bool),
		orphanBlocks:        make(map[[32]byte]*OrphanBlock),
		validationSemaphore: make(chan struct{}, MaxConcurrentValidations),
		metrics:             &BlockchainMetrics{},
		ctx:                 ctx,
		cancelFunc:          cancel,
	}

	// Set mint authorities (immutable)
	for _, auth := range config.MintAuthorities {
		bc.mintAuthorities[auth] = true
	}

	// Load or create genesis block
	if err := bc.initializeChain(); err != nil {
		cancel()
		return nil, fmt.Errorf("chain initialization failed: %w", err)
	}

	// Start background maintenance tasks
	bc.startBackgroundTasks()

	config.Logger.Info("✅ Blockchain initialized successfully",
		zap.Uint64("height", bc.height),
		zap.String("tip", fmt.Sprintf("%x", bc.tip[:8])),
		zap.Int("mintAuthorities", len(bc.mintAuthorities)))

	return bc, nil
}

// initializeChain loads existing chain or creates genesis
func (bc *Blockchain) initializeChain() error {
	// Try to load existing chain
	genesisKey := storage.GenesisKey()
	genesisHashData, err := bc.db.Get(genesisKey)

	if err != nil {
		// Genesis doesn't exist - create it
		bc.logger.Info("Creating genesis block...")
		
		genesis := types.NewGenesisBlock()
		
		// Validate genesis block
		if err := bc.validateGenesisBlock(genesis); err != nil {
			return fmt.Errorf("invalid genesis block: %w", err)
		}

		// Store genesis block atomically
		if err := bc.storeGenesisBlock(genesis); err != nil {
			return fmt.Errorf("failed to store genesis: %w", err)
		}

		bc.tip = genesis.Hash
		bc.height = 0
		bc.metrics.TotalBlocks = 1

		bc.logger.Info("✅ Genesis block created",
			zap.String("hash", fmt.Sprintf("%x", genesis.Hash[:8])))

		return nil
	}

	// Load existing chain
	var genesisHash [32]byte
	copy(genesisHash[:], genesisHashData)

	// Load chain metadata
	if err := bc.loadChainMetadata(); err != nil {
		return fmt.Errorf("failed to load chain metadata: %w", err)
	}

	// Validate chain integrity on startup
	if err := bc.validateChainIntegrity(); err != nil {
		bc.logger.Error("⚠️ Chain integrity check failed", zap.Error(err))
		// Don't fail startup, but log the error prominently
	}

	bc.logger.Info("✅ Loaded existing blockchain",
		zap.Uint64("height", bc.height),
		zap.String("tip", fmt.Sprintf("%x", bc.tip[:8])))

	return nil
}

// AddBlock adds a new block to the chain with comprehensive validation
func (bc *Blockchain) AddBlock(block *types.Block) error {
	// Check if shutdown in progress
	select {
	case <-bc.ctx.Done():
		return fmt.Errorf("blockchain is shutting down")
	default:
	}

	// Acquire validation semaphore to limit concurrent validations
	select {
	case bc.validationSemaphore <- struct{}{}:
		defer func() { <-bc.validationSemaphore }()
	case <-bc.ctx.Done():
		return fmt.Errorf("blockchain is shutting down")
	}

	startTime := time.Now()
	defer func() {
		duration := time.Since(startTime)
		bc.logger.Debug("Block processing completed",
			zap.Uint64("height", block.Header.Number),
			zap.Duration("duration", duration))
	}()

	// Create validation context with timeout
	ctx, cancel := context.WithTimeout(bc.ctx, BlockValidationTimeout)
	defer cancel()

	// Validate block with context
	if err := bc.validateBlockWithContext(ctx, block); err != nil {
		bc.metrics.mu.Lock()
		bc.metrics.ValidationErrors++
		bc.metrics.mu.Unlock()
		
		bc.logger.Warn("❌ Block validation failed",
			zap.Uint64("height", block.Header.Number),
			zap.String("hash", fmt.Sprintf("%x", block.Hash[:8])),
			zap.Error(err))
		
		return fmt.Errorf("block validation failed: %w", err)
	}

	// Lock for chain modification
	bc.mu.Lock()
	defer bc.mu.Unlock()

	// Check if block is orphan
	if block.Header.ParentHash != bc.tip {
		return bc.handleOrphanBlock(block)
	}

	// Apply block atomically
	if err := bc.applyBlockAtomic(ctx, block); err != nil {
		bc.metrics.mu.Lock()
		bc.metrics.StateCommitErrors++
		bc.metrics.mu.Unlock()
		
		return fmt.Errorf("failed to apply block: %w", err)
	}

	// Update metrics
	bc.updateMetrics(block)

	bc.logger.Info("✅ Block added to chain",
		zap.Uint64("height", block.Header.Number),
		zap.String("hash", fmt.Sprintf("%x", block.Hash[:8])),
		zap.Uint32("txCount", block.Header.TxCount),
		zap.Int("orphansResolved", bc.tryResolveOrphans(block.Hash)))

	return nil
}

// validateBlockWithContext validates a block with cancellation support
func (bc *Blockchain) validateBlockWithContext(ctx context.Context, block *types.Block) error {
	// Check context before expensive operations
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	// Basic structure validation
	if err := bc.validateBlockStructure(block); err != nil {
		return fmt.Errorf("structure validation failed: %w", err)
	}

	// Check context again
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	// Validate proof of work
	if !bc.pow.ValidateProofOfWork(block) {
		return types.ErrInvalidPoW
	}

	// Check context again
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	// Validate difficulty
	if err := bc.validateBlockDifficulty(block); err != nil {
		return fmt.Errorf("difficulty validation failed: %w", err)
	}

	// Check context again
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	// Validate transactions
	if err := bc.validateBlockTransactions(block); err != nil {
		return fmt.Errorf("transaction validation failed: %w", err)
	}

	return nil
}

// validateBlockStructure performs basic structural validation
func (bc *Blockchain) validateBlockStructure(block *types.Block) error {
	if block == nil {
		return fmt.Errorf("block is nil")
	}

	if block.Header == nil {
		return fmt.Errorf("block header is nil")
	}

	// Validate block size
	blockSize := block.Size()
	if blockSize > MaxBlockSize {
		return fmt.Errorf("block size %d exceeds maximum %d", blockSize, MaxBlockSize)
	}

	// Validate timestamp (not too far in future)
	maxFutureTime := time.Now().Unix() + 7200 // 2 hours tolerance
	if block.Header.Timestamp > maxFutureTime {
		return fmt.Errorf("%w: timestamp %d is too far in future", 
			types.ErrInvalidTimestamp, block.Header.Timestamp)
	}

	// Validate timestamp is not before genesis
	if block.Header.Number > 0 && block.Header.Timestamp < 1704067200 {
		return fmt.Errorf("%w: timestamp %d is before genesis", 
			types.ErrInvalidTimestamp, block.Header.Timestamp)
	}

	// Basic block validation
	if err := block.Validate(); err != nil {
		return err
	}

	// Validate block number sequence (if not orphan)
	bc.mu.RLock()
	expectedNumber := bc.height + 1
	bc.mu.RUnlock()

	if block.Header.Number > expectedNumber+MaxReorgDepth {
		return fmt.Errorf("block number %d is too far ahead (current: %d)", 
			block.Header.Number, expectedNumber-1)
	}

	return nil
}

// validateBlockDifficulty validates the block's difficulty
func (bc *Blockchain) validateBlockDifficulty(block *types.Block) error {
	if block.Header.Number == 0 {
		// Genesis block - just check minimum
		if block.Header.Difficulty.Cmp(big.NewInt(consensus.MinDifficulty)) < 0 {
			return types.ErrInvalidDifficulty
		}
		return nil
	}

	// Get recent blocks for difficulty calculation
	recentBlocks, err := bc.getRecentBlocksForValidation(block.Header.Number - 1)
	if err != nil {
		return fmt.Errorf("failed to get recent blocks: %w", err)
	}

	// Validate difficulty
	if err := bc.difficultyAdjust.ValidateDifficulty(
		block.Header.Number, 
		block.Header.Difficulty, 
		recentBlocks,
	); err != nil {
		return fmt.Errorf("difficulty validation failed: %w", err)
	}

	return nil
}

// validateBlockTransactions validates all transactions in a block
func (bc *Blockchain) validateBlockTransactions(block *types.Block) error {
	if len(block.Transactions) == 0 {
		return types.ErrMissingCoinbase
	}

	// First transaction must be coinbase
	coinbaseTx := block.Transactions[0]
	if !coinbaseTx.IsCoinbase() {
		return types.ErrMissingCoinbase
	}

	// Validate coinbase reward
	baseReward := bc.rewardCalc.CalculateBlockReward(block.Header.Number)

	// Calculate total fees from non-coinbase transactions
	totalFees := big.NewInt(0)
	for _, tx := range block.Transactions[1:] {
		if tx.FeeDNT != nil {
			totalFees.Add(totalFees, tx.FeeDNT)
		}
	}

	// Expected reward = base reward + all transaction fees
	expectedReward := new(big.Int).Add(baseReward, totalFees)

	// Validate coinbase amount
	if coinbaseTx.Amount.Cmp(expectedReward) != 0 {
		bc.logger.Error("❌ Invalid block reward",
			zap.String("expected", expectedReward.String()),
			zap.String("actual", coinbaseTx.Amount.String()),
			zap.String("baseReward", baseReward.String()),
			zap.String("totalFees", totalFees.String()),
			zap.Uint64("blockNumber", block.Header.Number))
		return types.ErrInvalidReward
	}

	bc.logger.Debug("✅ Coinbase validated",
		zap.Uint64("blockNumber", block.Header.Number),
		zap.String("miner", coinbaseTx.To),
		zap.String("reward", expectedReward.String()),
		zap.String("baseReward", baseReward.String()),
		zap.String("fees", totalFees.String()))

	// Validate mint transactions
	for i, tx := range block.Transactions[1:] {
		if tx.IsMint() {
			// Verify it's AFC being minted
			if tx.TokenType != string(types.TokenAFC) {
				bc.logger.Error("❌ Invalid mint token type",
					zap.Int("txIndex", i+1),
					zap.String("tokenType", tx.TokenType))
				return types.ErrMintOnlyAFC
			}

			// Mint transactions should have zero fee
			if tx.FeeDNT.Cmp(big.NewInt(0)) != 0 {
				bc.logger.Error("❌ Mint transaction has non-zero fee",
					zap.Int("txIndex", i+1),
					zap.String("fee", tx.FeeDNT.String()))
				return types.ErrInvalidMintTx
			}
		}
	}

	// Ensure only one coinbase
	for i := 1; i < len(block.Transactions); i++ {
		if block.Transactions[i].IsCoinbase() {
			return types.ErrMultipleCoinbase
		}
	}

	// Validate each transaction's basic structure
	for i, tx := range block.Transactions {
		if err := tx.Validate(); err != nil {
			return fmt.Errorf("transaction %d invalid: %w", i, err)
		}
	}

	return nil
}

// applyBlockAtomic applies a block atomically with rollback on failure
func (bc *Blockchain) applyBlockAtomic(ctx context.Context, block *types.Block) error {
	// Create a state snapshot for rollback
	stateSnapshot := bc.state.Copy()

	// Apply all transactions
	for i, tx := range block.Transactions {
		// Check context
		select {
		case <-ctx.Done():
			// Rollback state
			bc.state = stateSnapshot
			return fmt.Errorf("block application cancelled: %w", ctx.Err())
		default:
		}

		if err := bc.state.ApplyTransaction(tx); err != nil {
			// Rollback state on error
			bc.state = stateSnapshot
			return fmt.Errorf("failed to apply tx %d: %w", i, err)
		}
	}

	// Commit state changes with timeout
	commitCtx, commitCancel := context.WithTimeout(ctx, StateCommitTimeout)
	defer commitCancel()

	// Create a channel to handle commit result
	commitErr := make(chan error, 1)
	go func() {
		commitErr <- bc.state.Commit()
	}()

	// Wait for commit or timeout
	select {
	case err := <-commitErr:
		if err != nil {
			// Rollback state on commit failure
			bc.state = stateSnapshot
			return fmt.Errorf("state commit failed: %w", err)
		}
	case <-commitCtx.Done():
		// Rollback state on timeout
		bc.state = stateSnapshot
		return fmt.Errorf("state commit timeout: %w", commitCtx.Err())
	}

	// Store block in database
	if err := bc.storeBlock(block); err != nil {
		// Critical: State committed but block storage failed
		// Log error but don't rollback state (would cause inconsistency)
		bc.logger.Error("🚨 CRITICAL: Block storage failed after state commit",
			zap.Uint64("height", block.Header.Number),
			zap.Error(err))
		return fmt.Errorf("block storage failed: %w", err)
	}

	// Update chain metadata
	if err := bc.updateChainMetadataAtomic(block); err != nil {
		bc.logger.Error("Failed to update chain metadata", zap.Error(err))
		// Not critical - metadata can be rebuilt
	}

	// Update tip and height
	bc.tip = block.Hash
	bc.height = block.Header.Number

	return nil
}

// handleOrphanBlock handles a block whose parent is not the current tip
func (bc *Blockchain) handleOrphanBlock(block *types.Block) error {
	// Check if this is too far ahead
	if block.Header.Number > bc.height+MaxReorgDepth {
		return fmt.Errorf("block %d is too far ahead (current height: %d)", 
			block.Header.Number, bc.height)
	}

	// Check if parent exists in database
	parentExists, err := bc.db.Has(storage.BlockHashKey(block.Header.ParentHash))
	if err != nil {
		return fmt.Errorf("failed to check parent existence: %w", err)
	}

	if !parentExists {
		// True orphan - store for later
		bc.storeOrphanBlock(block)
		bc.logger.Info("Stored orphan block",
			zap.Uint64("height", block.Header.Number),
			zap.String("hash", fmt.Sprintf("%x", block.Hash[:8])),
			zap.String("parent", fmt.Sprintf("%x", block.Header.ParentHash[:8])))
		return types.ErrOrphanBlock
	}

	// Parent exists but it's not our tip - potential reorg
	return bc.attemptReorganization(block)
}

// storeOrphanBlock stores an orphan block temporarily
func (bc *Blockchain) storeOrphanBlock(block *types.Block) {
	bc.orphanBlocksMutex.Lock()
	defer bc.orphanBlocksMutex.Unlock()

	// Enforce max orphan blocks
	if len(bc.orphanBlocks) >= MaxOrphanBlocks {
		// Remove oldest orphan
		var oldestHash [32]byte
		var oldestTime time.Time
		first := true

		for hash, orphan := range bc.orphanBlocks {
			if first || orphan.ReceivedAt.Before(oldestTime) {
				oldestHash = hash
				oldestTime = orphan.ReceivedAt
				first = false
			}
		}

		delete(bc.orphanBlocks, oldestHash)
		bc.logger.Debug("Removed oldest orphan block", 
			zap.String("hash", fmt.Sprintf("%x", oldestHash[:8])))
	}

	bc.orphanBlocks[block.Hash] = &OrphanBlock{
		Block:      block,
		ReceivedAt: time.Now(),
	}

	bc.metrics.mu.Lock()
	bc.metrics.OrphanBlocksReceived++
	bc.metrics.mu.Unlock()
}

// tryResolveOrphans attempts to resolve orphan blocks after adding a new block
func (bc *Blockchain) tryResolveOrphans(parentHash [32]byte) int {
	bc.orphanBlocksMutex.Lock()
	defer bc.orphanBlocksMutex.Unlock()

	resolved := 0
	for hash, orphan := range bc.orphanBlocks {
		if orphan.Block.Header.ParentHash == parentHash {
			// Try to add this orphan
			bc.logger.Info("Attempting to resolve orphan",
				zap.String("hash", fmt.Sprintf("%x", hash[:8])))

			// Remove from orphans first
			delete(bc.orphanBlocks, hash)

			// Try to add (without holding orphan mutex)
			bc.orphanBlocksMutex.Unlock()
			err := bc.AddBlock(orphan.Block)
			bc.orphanBlocksMutex.Lock()

			if err != nil {
				bc.logger.Warn("Failed to resolve orphan",
					zap.String("hash", fmt.Sprintf("%x", hash[:8])),
					zap.Error(err))
			} else {
				resolved++
			}
		}
	}

	return resolved
}

// attemptReorganization attempts a blockchain reorganization
func (bc *Blockchain) attemptReorganization(block *types.Block) error {
	bc.logger.Warn("⚠️ Chain reorganization required",
		zap.Uint64("currentHeight", bc.height),
		zap.Uint64("newBlockHeight", block.Header.Number))

	// For now, reject reorganizations (implement in Phase 2)
	// Full reorg implementation requires careful handling of state and transactions
	return fmt.Errorf("reorganization not yet implemented: depth would be %d", 
		bc.height-block.Header.Number+1)
}

// storeGenesisBlock stores the genesis block atomically
func (bc *Blockchain) storeGenesisBlock(genesis *types.Block) error {
	batch := bc.db.NewBatch()
	defer batch.Cancel()

	// Serialize genesis block
	genesisData, err := genesis.Serialize()
	if err != nil {
		return fmt.Errorf("failed to serialize genesis: %w", err)
	}

	// Store genesis block by height
	if err := batch.Set(storage.BlockHeightKey(0), genesisData); err != nil {
		return err
	}

	// Store hash -> height mapping
	heightBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(heightBytes, 0)
	if err := batch.Set(storage.BlockHashKey(genesis.Hash), heightBytes); err != nil {
		return err
	}

	// Store genesis hash reference
	if err := batch.Set(storage.GenesisKey(), genesis.Hash[:]); err != nil {
		return err
	}

	// Initialize chain metadata
	if err := batch.Set(storage.ChainTipKey(), genesis.Hash[:]); err != nil {
		return err
	}

	heightBytesChain := make([]byte, 8)
	binary.BigEndian.PutUint64(heightBytesChain, 0)
	if err := batch.Set(storage.ChainHeightKey(), heightBytesChain); err != nil {
		return err
	}

	// Flush all changes atomically
	if err := batch.Flush(); err != nil {
		return fmt.Errorf("failed to flush genesis batch: %w", err)
	}

	bc.logger.Info("Genesis block stored successfully")
	return nil
}

// storeBlock stores a block in the database with all indexes
func (bc *Blockchain) storeBlock(block *types.Block) error {
	batch := bc.db.NewBatch()
	defer batch.Cancel()

	// Serialize block
	blockData, err := block.Serialize()
	if err != nil {
		return fmt.Errorf("serialization failed: %w", err)
	}

	// Store by height
	heightKey := storage.BlockHeightKey(block.Header.Number)
	if err := batch.Set(heightKey, blockData); err != nil {
		return fmt.Errorf("failed to store block by height: %w", err)
	}

	// Store hash -> height mapping
	hashKey := storage.BlockHashKey(block.Hash)
	heightBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(heightBytes, block.Header.Number)
	if err := batch.Set(hashKey, heightBytes); err != nil {
		return fmt.Errorf("failed to store hash mapping: %w", err)
	}

	// Store transactions and receipts
	for i, tx := range block.Transactions {
		if err := bc.storeTransactionWithReceipt(batch, tx, block, uint32(i)); err != nil {
			return fmt.Errorf("failed to store transaction %d: %w", i, err)
		}
	}

	// Flush batch atomically
	if err := batch.Flush(); err != nil {
		return fmt.Errorf("batch flush failed: %w", err)
	}

	return nil
}

// storeTransactionWithReceipt stores a transaction and its receipt
func (bc *Blockchain) storeTransactionWithReceipt(batch *storage.Batch, tx *types.Transaction, block *types.Block, txIndex uint32) error {
	// Serialize and store transaction
	txData, err := tx.Serialize()
	if err != nil {
		return fmt.Errorf("tx serialization failed: %w", err)
	}

	txKey := storage.TxKey(tx.Hash)
	if err := batch.Set(txKey, txData); err != nil {
		return fmt.Errorf("failed to store transaction: %w", err)
	}

	// Create and store receipt
	receipt := types.NewSuccessReceipt(tx.Hash, block.Hash, block.Header.Number, txIndex, tx.FeeDNT)
	receiptData, err := receipt.Serialize()
	if err != nil {
		return fmt.Errorf("receipt serialization failed: %w", err)
	}

	receiptKey := storage.ReceiptKey(tx.Hash)
	if err := batch.Set(receiptKey, receiptData); err != nil {
		return fmt.Errorf("failed to store receipt: %w", err)
	}

	// Index transaction by address
	if !tx.IsCoinbase() {
		if err := bc.indexTransactionForAddress(batch, tx.From, tx.Hash); err != nil {
			return fmt.Errorf("failed to index sender: %w", err)
		}
	}

	if err := bc.indexTransactionForAddress(batch, tx.To, tx.Hash); err != nil {
		return fmt.Errorf("failed to index recipient: %w", err)
	}

	return nil
}

// indexTransactionForAddress adds a transaction to an address's index
func (bc *Blockchain) indexTransactionForAddress(batch *storage.Batch, address string, txHash [32]byte) error {
	indexKey := storage.AddressTxIndexKey(address)

	// Get existing index
	var txHashes [][32]byte
	indexData, err := bc.db.Get(indexKey)
	if err == nil {
		if err := json.Unmarshal(indexData, &txHashes); err != nil {
			return fmt.Errorf("failed to unmarshal index: %w", err)
		}
	}

	// Append new transaction
	txHashes = append(txHashes, txHash)

	// Store updated index
	indexData, err = json.Marshal(txHashes)
	if err != nil {
		return fmt.Errorf("failed to marshal index: %w", err)
	}

	return batch.Set(indexKey, indexData)
}

// updateChainMetadataAtomic atomically updates chain tip and height
func (bc *Blockchain) updateChainMetadataAtomic(block *types.Block) error {
	batch := bc.db.NewBatch()
	defer batch.Cancel()

	// Update tip
	if err := batch.Set(storage.ChainTipKey(), block.Hash[:]); err != nil {
		return err
	}

	// Update height
	heightBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(heightBytes, block.Header.Number)
	if err := batch.Set(storage.ChainHeightKey(), heightBytes); err != nil {
		return err
	}

	return batch.Flush()
}

// loadChainMetadata loads chain tip and height from database
func (bc *Blockchain) loadChainMetadata() error {
	// Load tip
	tipKey := storage.ChainTipKey()
	tipData, err := bc.db.Get(tipKey)
	if err != nil {
		return fmt.Errorf("failed to load chain tip: %w", err)
	}
	copy(bc.tip[:], tipData)

	// Load height
	heightKey := storage.ChainHeightKey()
	heightData, err := bc.db.Get(heightKey)
	if err != nil {
		return fmt.Errorf("failed to load chain height: %w", err)
	}
	bc.height = binary.BigEndian.Uint64(heightData)

	return nil
}

// validateGenesisBlock validates the genesis block
func (bc *Blockchain) validateGenesisBlock(genesis *types.Block) error {
	if genesis.Header.Number != 0 {
		return fmt.Errorf("genesis block must have number 0, got %d", genesis.Header.Number)
	}

	if genesis.Header.ParentHash != [32]byte{} {
		return fmt.Errorf("genesis block must have zero parent hash")
	}

	// Validate difficulty is reasonable
	if genesis.Header.Difficulty.Cmp(big.NewInt(0)) <= 0 {
		return fmt.Errorf("genesis difficulty must be positive")
	}

	return nil
}

// validateChainIntegrity performs integrity check on the blockchain
func (bc *Blockchain) validateChainIntegrity() error {
	bc.logger.Info("Validating chain integrity...")

	// Validate last N blocks
	blocksToCheck := uint64(10)
	if bc.height < blocksToCheck {
		blocksToCheck = bc.height + 1
	}

	for i := uint64(0); i < blocksToCheck; i++ {
		height := bc.height - i
		block, err := bc.GetBlock(height)
		if err != nil {
			return fmt.Errorf("failed to load block %d: %w", height, err)
		}

		// Verify hash
		computedHash := block.ComputeHash()
		if computedHash != block.Hash {
			return fmt.Errorf("block %d hash mismatch", height)
		}

		// Verify parent link (except genesis)
		if height > 0 {
			parentBlock, err := bc.GetBlock(height - 1)
			if err != nil {
				return fmt.Errorf("failed to load parent block %d: %w", height-1, err)
			}

			if block.Header.ParentHash != parentBlock.Hash {
				return fmt.Errorf("block %d parent hash mismatch", height)
			}
		}
	}

	bc.logger.Info("✅ Chain integrity validated", 
		zap.Uint64("blocksChecked", blocksToCheck))
	return nil
}

// getRecentBlocksForValidation gets recent blocks for validation
func (bc *Blockchain) getRecentBlocksForValidation(upToHeight uint64) ([]*types.BlockHeader, error) {
	count := consensus.DifficultyWindow
	if upToHeight+1 < uint64(count) {
		count = int(upToHeight + 1)
	}

	blocks := make([]*types.BlockHeader, 0, count)
	for i := 0; i < count; i++ {
		height := upToHeight - uint64(i)
		block, err := bc.GetBlock(height)
		if err != nil {
			return nil, fmt.Errorf("failed to get block %d: %w", height, err)
		}
		blocks = append([]*types.BlockHeader{block.Header}, blocks...)
	}

	return blocks, nil
}

// GetBlock retrieves a block by height
func (bc *Blockchain) GetBlock(height uint64) (*types.Block, error) {
	key := storage.BlockHeightKey(height)
	data, err := bc.db.Get(key)
	if err != nil {
		return nil, types.ErrBlockNotFound
	}

	return types.DeserializeBlock(data)
}

// GetBlockByHash retrieves a block by hash
func (bc *Blockchain) GetBlockByHash(hash [32]byte) (*types.Block, error) {
	// Get height from hash
	hashKey := storage.BlockHashKey(hash)
	heightData, err := bc.db.Get(hashKey)
	if err != nil {
		return nil, types.ErrBlockNotFound
	}

	height := binary.BigEndian.Uint64(heightData)
	return bc.GetBlock(height)
}

// GetTransaction retrieves a transaction by hash
func (bc *Blockchain) GetTransaction(txHash [32]byte) (*types.Transaction, error) {
	txKey := storage.TxKey(txHash)
	txData, err := bc.db.Get(txKey)
	if err != nil {
		return nil, types.ErrTxNotFound
	}

	return types.DeserializeTransaction(txData)
}

// GetTransactionReceipt retrieves a transaction receipt
func (bc *Blockchain) GetTransactionReceipt(txHash [32]byte) (*types.Receipt, error) {
	receiptKey := storage.ReceiptKey(txHash)
	receiptData, err := bc.db.Get(receiptKey)
	if err != nil {
		return nil, types.ErrReceiptNotFound
	}

	return types.DeserializeReceipt(receiptData)
}

// GetTransactionsByAddress retrieves all transactions for an address
func (bc *Blockchain) GetTransactionsByAddress(address string, limit int) ([]*types.Transaction, error) {
	indexKey := storage.AddressTxIndexKey(address)
	indexData, err := bc.db.Get(indexKey)
	if err != nil {
		return []*types.Transaction{}, nil
	}

	var txHashes [][32]byte
	if err := json.Unmarshal(indexData, &txHashes); err != nil {
		return nil, fmt.Errorf("failed to unmarshal index: %w", err)
	}

	// Apply limit
	if limit > 0 && limit < len(txHashes) {
		txHashes = txHashes[len(txHashes)-limit:]
	}

	// Retrieve transactions
	txs := make([]*types.Transaction, 0, len(txHashes))
	for _, txHash := range txHashes {
		tx, err := bc.GetTransaction(txHash)
		if err != nil {
			continue
		}
		txs = append(txs, tx)
	}

	return txs, nil
}

// GetHeight returns the current chain height (thread-safe)
func (bc *Blockchain) GetHeight() uint64 {
	bc.mu.RLock()
	defer bc.mu.RUnlock()
	return bc.height
}

// GetTip returns the current chain tip hash (thread-safe)
func (bc *Blockchain) GetTip() [32]byte {
	bc.mu.RLock()
	defer bc.mu.RUnlock()
	return bc.tip
}

// GetState returns the state manager
func (bc *Blockchain) GetState() *State {
	return bc.state
}

// IsAuthorizedMinter checks if an address is authorized to mint AFC
func (bc *Blockchain) IsAuthorizedMinter(address string) bool {
	return bc.mintAuthorities[address]
}

// GetMintAuthorities returns the list of authorized minters
func (bc *Blockchain) GetMintAuthorities() []string {
	authorities := make([]string, 0, len(bc.mintAuthorities))
	for addr := range bc.mintAuthorities {
		authorities = append(authorities, addr)
	}
	return authorities
}

// updateMetrics updates blockchain metrics
func (bc *Blockchain) updateMetrics(block *types.Block) {
	bc.metrics.mu.Lock()
	defer bc.metrics.mu.Unlock()

	bc.metrics.TotalBlocks++
	bc.metrics.TotalTransactions += uint64(len(block.Transactions))
	bc.metrics.LastBlockTime = time.Now()

	// Update average block time
	if bc.metrics.TotalBlocks > 1 {
		// Simple moving average
		duration := time.Since(bc.metrics.LastBlockTime)
		bc.metrics.AverageBlockTime = (bc.metrics.AverageBlockTime*time.Duration(bc.metrics.TotalBlocks-1) + duration) / time.Duration(bc.metrics.TotalBlocks)
	}
}

// GetMetrics returns current blockchain metrics (thread-safe)
func (bc *Blockchain) GetMetrics() map[string]interface{} {
	bc.metrics.mu.RLock()
	defer bc.metrics.mu.RUnlock()

	bc.mu.RLock()
	currentHeight := bc.height
	bc.mu.RUnlock()

	bc.orphanBlocksMutex.RLock()
	orphanCount := len(bc.orphanBlocks)
	bc.orphanBlocksMutex.RUnlock()

	return map[string]interface{}{
		"height":              currentHeight,
		"total_blocks":        bc.metrics.TotalBlocks,
		"total_transactions":  bc.metrics.TotalTransactions,
		"validation_errors":   bc.metrics.ValidationErrors,
		"state_commit_errors": bc.metrics.StateCommitErrors,
		"orphan_blocks":       orphanCount,
		"reorganizations":     bc.metrics.ReorganizationsCount,
		"avg_block_time_sec":  bc.metrics.AverageBlockTime.Seconds(),
	}
}

// startBackgroundTasks starts background maintenance tasks
func (bc *Blockchain) startBackgroundTasks() {
	// Orphan cleanup task
	bc.wg.Add(1)
	go bc.orphanCleanupTask()
}

// orphanCleanupTask periodically cleans up old orphan blocks
func (bc *Blockchain) orphanCleanupTask() {
	defer bc.wg.Done()

	ticker := time.NewTicker(30 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			bc.cleanupOrphanBlocks()
		case <-bc.ctx.Done():
			return
		}
	}
}

// cleanupOrphanBlocks removes orphan blocks that are too old
func (bc *Blockchain) cleanupOrphanBlocks() {
	bc.orphanBlocksMutex.Lock()
	defer bc.orphanBlocksMutex.Unlock()

	now := time.Now()
	removed := 0

	for hash, orphan := range bc.orphanBlocks {
		if now.Sub(orphan.ReceivedAt) > OrphanBlockTTL {
			delete(bc.orphanBlocks, hash)
			removed++
		}
	}

	if removed > 0 {
		bc.logger.Info("Cleaned up old orphan blocks",
			zap.Int("removed", removed),
			zap.Int("remaining", len(bc.orphanBlocks)))
	}
}

// Shutdown gracefully shuts down the blockchain
func (bc *Blockchain) Shutdown() error {
	bc.logger.Info("🛑 Shutting down blockchain...")

	// Cancel context to stop background tasks
	bc.cancelFunc()

	// Wait for background tasks to complete
	bc.wg.Wait()

	bc.logger.Info("✅ Blockchain shut down successfully")
	return nil
}

// validateBlockchainConfig validates blockchain configuration
func validateBlockchainConfig(config *Config) error {
	if config == nil {
		return fmt.Errorf("config is nil")
	}
	if config.DB == nil {
		return fmt.Errorf("database is required")
	}
	if config.Logger == nil {
		return fmt.Errorf("logger is required")
	}
	return nil
}
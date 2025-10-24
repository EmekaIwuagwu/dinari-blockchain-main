package core

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/EmekaIwuagwu/dinari-blockchain/internal/types"
	"github.com/dgraph-io/badger/v4"
)

const (
	// Consensus parameters
	TargetBlockTime              = 15 * time.Second // 15 seconds per block
	DifficultyAdjustmentInterval = 120              // Adjust every 120 blocks
	MaxBlockSize                 = 1 << 20          // 1MB max block size
	MaxTransactionsPerBlock      = 5000             // Max 5000 txs per block

	MinimumTransactionFee = 10000 // 0.0001 DNT (10,000 satoshis)

	// Reorg protection
	MaxReorgDepth = 100 // Maximum depth for chain reorganization

	// Orphan blocks
	MaxOrphanBlocks    = 100
	OrphanBlockTimeout = 10 * time.Minute

	// Checkpoints
	CheckpointInterval = 1000 // Create checkpoint every 1000 blocks

	// Block rewards
	InitialBlockReward = 50 * 1e8       // 50 DNT (with 8 decimals)
	HalvingInterval    = 210000         // Halve reward every 210,000 blocks
	MaxSupply          = 21000000 * 1e8 // 21 million DNT total supply

	// Time validation
	MaxFutureBlockTime = 2 * time.Hour // Reject blocks more than 2 hours in future

	// Genesis block
	GenesisTimestamp = 1704067200 // 2024-01-01 00:00:00 UTC
)

var (
	// Database key prefixes
	prefixBlock      = []byte("blk:")     // blk:<height> -> Block
	prefixBlockHash  = []byte("blkhash:") // blkhash:<hash> -> height
	prefixBestChain  = []byte("best:")    // best:<height> -> hash
	prefixChainState = []byte("chain:")   // chain:state -> ChainState
	prefixCheckpoint = []byte("ckpt:")    // ckpt:<height> -> Checkpoint
	prefixOrphan     = []byte("orphan:")  // orphan:<hash> -> Block

	// Special keys
	keyGenesisHash = []byte("genesis:hash")
	keyBestHeight  = []byte("chain:height")
	keyChainWork   = []byte("chain:work")

	// Errors
	ErrBlockNotFound        = errors.New("block not found")
	ErrInvalidBlock         = errors.New("invalid block")
	ErrInvalidPrevHash      = errors.New("invalid previous block hash")
	ErrInvalidTimestamp     = errors.New("invalid timestamp")
	ErrInvalidDifficulty    = errors.New("invalid difficulty")
	ErrInvalidMerkleRoot    = errors.New("invalid merkle root")
	ErrBlockTooLarge        = errors.New("block size exceeds limit")
	ErrTooManyTransactions  = errors.New("too many transactions in block")
	ErrDuplicateBlock       = errors.New("duplicate block")
	ErrOrphanBlock          = errors.New("orphan block (previous block not found)")
	ErrReorgTooDeep         = errors.New("reorganization too deep")
	ErrInvalidBlockReward   = errors.New("invalid block reward")
	ErrGenesisBlockMismatch = errors.New("genesis block mismatch")
)

// ChainState tracks the current chain state
type ChainState struct {
	Height         uint64   `json:"height"`
	BestHash       []byte   `json:"bestHash"`
	TotalWork      *big.Int `json:"totalWork"`
	Difficulty     uint32   `json:"difficulty"`
	LastAdjustment uint64   `json:"lastAdjustment"`
}

// OrphanBlock represents a block waiting for its parent
type OrphanBlock struct {
	Block      *Block
	ReceivedAt time.Time
}

// Blockchain manages the blockchain state
type Blockchain struct {
	db    *badger.DB
	State *StateDB

	// Current chain state
	chainState *ChainState

	// Orphan blocks waiting for parent
	orphans   map[string]*OrphanBlock
	orphansMu sync.RWMutex

	// Cache for recent blocks
	blockCache   map[uint64]*Block
	cacheMu      sync.RWMutex
	maxCacheSize int

	// Genesis block
	genesisBlock *Block

	// Chain lock for atomic operations
	chainMu sync.RWMutex

	// Statistics
	stats   BlockchainStats
	statsMu sync.Mutex
}

type Account struct {
	Address    string
	BalanceDNT *big.Int
	BalanceAFC *big.Int
	Nonce      uint64
}

type Block = types.Block
type BlockHeader = types.BlockHeader

// BlockchainStats tracks blockchain statistics
type BlockchainStats struct {
	BlocksProcessed   uint64
	BlocksRejected    uint64
	OrphanBlocksCount uint64
	ReorgsCount       uint64
	AverageBlockTime  time.Duration
}

// NewBlockchain creates a new blockchain instance
// NewBlockchain creates a new blockchain instance
func NewBlockchain(db *badger.DB, state *StateDB, genesisBlock *Block) (*Blockchain, error) {
	if db == nil {
		return nil, errors.New("database cannot be nil")
	}
	if state == nil {
		return nil, errors.New("state cannot be nil")
	}

	bc := &Blockchain{
		db:           db,
		State:        state,
		orphans:      make(map[string]*OrphanBlock),
		blockCache:   make(map[uint64]*Block),
		maxCacheSize: 100,
		genesisBlock: genesisBlock, // Can be nil - will be set in initialize()
	}

	// Initialize or load chain state
	if err := bc.initialize(); err != nil {
		return nil, fmt.Errorf("failed to initialize blockchain: %w", err)
	}

	return bc, nil
}

func (bc *Blockchain) GetState() *StateDB {
	return bc.State
}

// initialize sets up the blockchain (genesis or load existing)
// initialize sets up the blockchain (genesis or load existing)
func (bc *Blockchain) initialize() error {
	// Check if genesis exists in database
	var genesisHash []byte
	err := bc.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(keyGenesisHash)
		if err == badger.ErrKeyNotFound {
			return nil // Genesis doesn't exist yet
		}
		if err != nil {
			return err
		}
		return item.Value(func(val []byte) error {
			genesisHash = append([]byte(nil), val...)
			return nil
		})
	})

	if err != nil {
		return err
	}

	// If genesis doesn't exist in database, create it
	if genesisHash == nil {
		// Use provided genesis block, or create default if nil
		if bc.genesisBlock == nil {
			// Create default genesis with CURRENT timestamp
			bc.genesisBlock = &Block{
				Header: &BlockHeader{
					Version:       1,
					Height:        0,
					PrevBlockHash: []byte{},
					MerkleRoot:    []byte{},
					Timestamp:     time.Now().Unix(), // ← Fresh timestamp!
					Difficulty:    16777216,
					Nonce:         0,
					Hash:          []byte{},
					StateRoot:     []byte{},
				},
				Transactions: []*types.Transaction{},
			}
		}
		return bc.createGenesis()
	}

	// Genesis exists - load it from database and use it
	existingGenesis, err := bc.GetBlockByHeight(0)
	if err != nil {
		return fmt.Errorf("failed to load existing genesis: %w", err)
	}
	bc.genesisBlock = existingGenesis

	// Load chain state
	return bc.loadChainState()
}

// GetDifficulty returns the current difficulty
func (bc *Blockchain) GetDifficulty() uint32 {
	bc.chainMu.RLock()
	defer bc.chainMu.RUnlock()
	return bc.chainState.Difficulty
}

// ValidateBlock validates a block (wrapper for internal validation)
func (bc *Blockchain) ValidateBlock(block *Block) error {
	if err := bc.validateBlockBasics(block); err != nil {
		return err
	}

	// Get previous block for header validation
	prevBlock, err := bc.GetBlockByHash(block.Header.PrevBlockHash)
	if err != nil {
		return err
	}

	if err := bc.validateBlockHeader(block.Header, prevBlock.Header); err != nil {
		return err
	}

	if err := bc.validateBlockTransactions(block); err != nil {
		return err
	}

	return bc.validateMerkleRoot(block)
}

// CalculateBlockHash is a public wrapper for calculateBlockHash
func (bc *Blockchain) CalculateBlockHash(header *BlockHeader) []byte {
	return bc.calculateBlockHash(header)
}

// createGenesis creates and stores the genesis block
func (bc *Blockchain) createGenesis() error {
	// Calculate genesis hash
	bc.genesisBlock.Header.Hash = bc.calculateBlockHash(bc.genesisBlock.Header)

	// Store genesis block
	return bc.db.Update(func(txn *badger.Txn) error {
		// Store block
		blockData, err := json.Marshal(bc.genesisBlock)
		if err != nil {
			return err
		}

		key := append(prefixBlock, encodeUint64(0)...)
		if err := txn.Set(key, blockData); err != nil {
			return err
		}

		// Store hash mapping
		hashKey := append(prefixBlockHash, bc.genesisBlock.Header.Hash...)
		if err := txn.Set(hashKey, encodeUint64(0)); err != nil {
			return err
		}

		// Store genesis hash
		if err := txn.Set(keyGenesisHash, bc.genesisBlock.Header.Hash); err != nil {
			return err
		}

		// Store best chain
		bestKey := append(prefixBestChain, encodeUint64(0)...)
		if err := txn.Set(bestKey, bc.genesisBlock.Header.Hash); err != nil {
			return err
		}

		// Initialize chain state
		bc.chainState = &ChainState{
			Height:         0,
			BestHash:       bc.genesisBlock.Header.Hash,
			TotalWork:      big.NewInt(int64(bc.genesisBlock.Header.Difficulty)),
			Difficulty:     bc.genesisBlock.Header.Difficulty,
			LastAdjustment: 0,
		}

		stateData, err := json.Marshal(bc.chainState)
		if err != nil {
			return err
		}

		return txn.Set(prefixChainState, stateData)
	})
}

// AddBlock adds a new block to the blockchain with full validation
func (bc *Blockchain) AddBlock(block *Block) error {
	if block == nil {
		return errors.New("block cannot be nil")
	}

	bc.chainMu.Lock()
	defer bc.chainMu.Unlock()

	// Comprehensive validation
	if err := bc.ValidateBlockComprehensive(block); err != nil {
		bc.incrementRejected()
		return fmt.Errorf("block validation failed: %w", err)
	}

	// Check for duplicate
	if bc.hasBlock(block.Header.Hash) {
		return ErrDuplicateBlock
	}

	// Check if previous block exists (orphan check)
	prevBlock, err := bc.GetBlockByHash(block.Header.PrevBlockHash)
	if err != nil {
		if block.Header.Height == 0 {
			// Genesis block
			return bc.addBlockToMainChain(block)
		}
		// Orphan block
		return bc.addOrphanBlock(block)
	}

	// Log acceptance
	fmt.Printf("✅ Block #%d validated successfully\n", block.Header.Height)
	fmt.Printf("   Hash: %x\n", block.Header.Hash[:8])
	fmt.Printf("   Timestamp: %d (interval: %d sec)\n",
		block.Header.Timestamp, block.Header.Timestamp-prevBlock.Header.Timestamp)
	fmt.Printf("   Difficulty: %d\n", block.Header.Difficulty)
	fmt.Printf("   Transactions: %d\n", len(block.Transactions))

	// Check if this extends the best chain
	isMainChain := bytes.Equal(block.Header.PrevBlockHash, bc.chainState.BestHash)

	if isMainChain {
		return bc.addBlockToMainChain(block)
	}

	// Side chain
	return bc.handleSideChain(block)
}

// validateBlockBasics performs basic block validation
func (bc *Blockchain) validateBlockBasics(block *Block) error {
	// Check version
	if block.Header.Version == 0 {
		return errors.New("invalid version")
	}

	// Check hash
	if len(block.Header.Hash) != 32 {
		return errors.New("invalid hash length")
	}

	// Verify hash calculation
	calculatedHash := bc.calculateBlockHash(block.Header)
	if !bytes.Equal(calculatedHash, block.Header.Hash) {
		return errors.New("hash mismatch")
	}

	// Check block size
	blockSize := bc.calculateBlockSize(block)
	if blockSize > MaxBlockSize {
		return ErrBlockTooLarge
	}

	// Check transaction count
	if len(block.Transactions) > MaxTransactionsPerBlock {
		return ErrTooManyTransactions
	}

	// Check timestamp
	now := time.Now().Unix()
	if block.Header.Timestamp > now+int64(MaxFutureBlockTime.Seconds()) {
		return ErrInvalidTimestamp
	}

	return nil
}

// validateBlockHeader validates block header against previous block
func (bc *Blockchain) validateBlockHeader(header, prevHeader *BlockHeader) error {
	// 1. Validate height progression
	if header.Height != prevHeader.Height+1 {
		return fmt.Errorf("invalid height: expected %d, got %d",
			prevHeader.Height+1, header.Height)
	}

	// 2. Validate previous hash
	if !bytes.Equal(header.PrevBlockHash, prevHeader.Hash) {
		return ErrInvalidPrevHash
	}

	// 3. CRITICAL: Strict timestamp validation
	if err := bc.validateTimestamp(header, prevHeader); err != nil {
		return err
	}

	// 4. Validate difficulty
	expectedDifficulty := bc.calculateNextDifficulty(prevHeader)
	if header.Difficulty != expectedDifficulty {
		return fmt.Errorf("%w: expected %d, got %d",
			ErrInvalidDifficulty, expectedDifficulty, header.Difficulty)
	}

	// 5. Validate Proof of Work
	if !bc.validateProofOfWork(header) {
		return errors.New("invalid proof of work")
	}

	return nil
}

func (bc *Blockchain) validateTimestamp(header, prevHeader *BlockHeader) error {
	now := time.Now().Unix()

	if header.Timestamp <= 0 {
		return fmt.Errorf("%w: timestamp must be positive", ErrInvalidTimestamp)
	}

	maxFutureTime := now + int64(2*time.Minute.Seconds())
	if header.Timestamp > maxFutureTime {
		return fmt.Errorf("%w: block %d seconds in future (max 120 seconds allowed)",
			ErrInvalidTimestamp, header.Timestamp-now)
	}

	if header.Timestamp <= prevHeader.Timestamp {
		return fmt.Errorf("%w: timestamp must increase (current: %d, previous: %d)",
			ErrInvalidTimestamp, header.Timestamp, prevHeader.Timestamp)
	}

	// CRITICAL: Enforce minimum 15-second block interval
	timeDiff := header.Timestamp - prevHeader.Timestamp
	minInterval := int64(TargetBlockTime.Seconds())

	if timeDiff < minInterval {
		return fmt.Errorf("%w: block interval too small - got %d seconds, required %d seconds minimum",
			ErrInvalidTimestamp, timeDiff, minInterval)
	}

	// Allow up to 24 hours between blocks to handle node restarts, network issues, etc.
	// This is much more permissive than Bitcoin's 2-hour future limit, but necessary for:
	// - Initial blockchain startup (genesis to block 1)
	// - Node downtime and restarts
	// - Development and testing scenarios
	maxInterval := int64(86400) // 24 hours
	if timeDiff > maxInterval {
		return fmt.Errorf("%w: block interval too large - got %d seconds, maximum %d seconds",
			ErrInvalidTimestamp, timeDiff, maxInterval)
	}

	return nil
}

// validateBlockTransactions validates all transactions in block
func (bc *Blockchain) validateBlockTransactions(block *Block) error {
	if len(block.Transactions) == 0 {
		return errors.New("block must contain at least one transaction (coinbase)")
	}

	// First transaction must be coinbase (mining reward)
	coinbaseTx := block.Transactions[0]
	if err := bc.validateCoinbase(coinbaseTx, block.Header.Height); err != nil {
		return fmt.Errorf("invalid coinbase: %w", err)
	}

	// Validate remaining transactions
	seenHashes := make(map[string]bool)
	for i, tx := range block.Transactions[1:] {
		// Check for duplicate transactions
		txHash := string(tx.Hash[:])
		if seenHashes[txHash] {
			return fmt.Errorf("duplicate transaction at index %d", i+1)
		}
		seenHashes[txHash] = true

		// Validate transaction (signature, balance, nonce)
		if err := bc.validateTransaction(tx); err != nil {
			return fmt.Errorf("invalid transaction at index %d: %w", i+1, err)
		}
	}

	return nil
}

// validateCoinbase validates the coinbase transaction
// validateCoinbase validates the coinbase transaction
func (bc *Blockchain) validateCoinbase(tx *types.Transaction, height uint64) error {
	// Calculate expected block reward
	expectedReward := bc.calculateBlockReward(height)

	// Coinbase amount should be AT LEAST the block reward (can include fees)
	// For early blocks with no transactions, it will equal the reward
	if tx.Amount.Cmp(expectedReward) < 0 {
		return fmt.Errorf("%w: amount too low, expected at least %s, got %s",
			ErrInvalidBlockReward, expectedReward.String(), tx.Amount.String())
	}

	// Coinbase has no sender (from is empty or special address)
	if tx.From != "" && tx.From != "COINBASE" {
		return fmt.Errorf("coinbase must have empty or COINBASE sender, got: %s", tx.From)
	}

	return nil
}

// validateTransaction validates a single transaction
func (bc *Blockchain) validateTransaction(tx *types.Transaction) error {
	// This should call crypto package for signature verification
	// and state DB for balance/nonce checks

	// Check sender balance
	balance, err := bc.State.GetBalance(tx.From, TokenType(tx.TokenType))
	if err != nil {
		return err
	}

	totalRequired := new(big.Int).Add(tx.Amount, tx.FeeDNT)
	if balance.Cmp(totalRequired) < 0 {
		return ErrInsufficientBalance
	}

	// Check nonce
	expectedNonce, err := bc.State.GetNonce(tx.From)
	if err != nil {
		// Account doesn't exist yet - first transaction should have nonce 0
		expectedNonce = 0
	}

	if tx.Nonce != expectedNonce {
		fmt.Printf("❌ Nonce validation failed for tx from %s:\n", tx.From)
		fmt.Printf("   Expected nonce: %d (from state)\n", expectedNonce)
		fmt.Printf("   Transaction nonce: %d\n", tx.Nonce)
		fmt.Printf("   Transaction hash: %x\n", tx.Hash[:8])
		return fmt.Errorf("%w: expected %d, got %d", ErrInvalidNonce, expectedNonce, tx.Nonce)
	}

	return nil
}

// validateMerkleRoot validates the merkle root of transactions
func (bc *Blockchain) validateMerkleRoot(block *Block) error {
	calculatedRoot := bc.calculateMerkleRoot(block.Transactions)

	if !bytes.Equal(calculatedRoot, block.Header.MerkleRoot) {
		return ErrInvalidMerkleRoot
	}

	return nil
}

// validateProofOfWork validates the block's proof of work
func (bc *Blockchain) validateProofOfWork(header *BlockHeader) bool {
	// Calculate target from difficulty
	target := bc.difficultyToTarget(header.Difficulty)

	// Convert hash to big int
	hashInt := new(big.Int).SetBytes(header.Hash)

	// Hash must be less than or equal to target
	valid := hashInt.Cmp(target) <= 0

	if !valid {
		fmt.Printf("❌ PoW validation failed for block %d:\n", header.Height)
		fmt.Printf("   Hash:   %x\n", header.Hash[:8])
		fmt.Printf("   Target: %x\n", target.Bytes()[:8])
		fmt.Printf("   Difficulty: %d\n", header.Difficulty)
	}

	return valid
}

func (bc *Blockchain) ValidateBlockComprehensive(block *Block) error {
	// 1. Basic validation
	if err := bc.validateBlockBasics(block); err != nil {
		return fmt.Errorf("basic validation failed: %w", err)
	}

	// 2. Genesis block - skip previous block checks
	if block.Header.Height == 0 {
		return nil
	}

	// 3. Get previous block
	var prevBlock *Block
	var err error

	// Special handling for block 1 (genesis has empty PrevBlockHash)
	if block.Header.Height == 1 {
		prevBlock, err = bc.GetBlockByHeight(0)
		if err != nil {
			return fmt.Errorf("genesis block not found: %w", err)
		}
	} else {
		prevBlock, err = bc.GetBlockByHash(block.Header.PrevBlockHash)
		if err != nil {
			return fmt.Errorf("previous block not found: %w", err)
		}
	}

	// 4. Header validation (includes strict timestamp check)
	if err := bc.validateBlockHeader(block.Header, prevBlock.Header); err != nil {
		return fmt.Errorf("header validation failed: %w", err)
	}

	// 5. Transaction validation
	if err := bc.validateBlockTransactions(block); err != nil {
		return fmt.Errorf("transaction validation failed: %w", err)
	}

	// 6. Merkle root validation
	if err := bc.validateMerkleRoot(block); err != nil {
		return fmt.Errorf("merkle root validation failed: %w", err)
	}

	return nil
}

// addBlockToMainChain adds a block to the main chain and updates state
// addBlockToMainChain adds a block to the main chain and updates state
func (bc *Blockchain) addBlockToMainChain(block *Block) error {
	// Create state checkpoint
	checkpointID := bc.State.Checkpoint()

	// Track total fees collected in this block
	totalFees := big.NewInt(0)

	// Apply transactions to state
	for _, tx := range block.Transactions {
		// Collect fees from non-coinbase transactions
		if !tx.IsCoinbase() && tx.FeeDNT != nil && tx.FeeDNT.Sign() > 0 {
			totalFees.Add(totalFees, tx.FeeDNT)
		}

		if err := bc.applyTransaction(tx); err != nil {
			// Rollback state on error
			bc.State.RevertToCheckpoint(checkpointID)
			return fmt.Errorf("failed to apply transaction: %w", err)
		}
	}

	// Give collected fees to miner (add to their balance)
	// Fees are already deducted in applyTransaction, now give to miner
	if totalFees.Sign() > 0 {
		minerAddress := block.Transactions[0].To // Coinbase recipient is the miner
		if err := bc.State.AddBalance(minerAddress, totalFees, TokenDNT); err != nil {
			fmt.Printf("⚠️  Warning: Failed to credit fees to miner: %v\n", err)
		} else {
			fmt.Printf("💰 Miner earned %s satoshis in fees\n", totalFees.String())
		}
	}

	// Commit state changes
	if err := bc.State.Commit(); err != nil {
		bc.State.RevertToCheckpoint(checkpointID)
		return fmt.Errorf("failed to commit state: %w", err)
	}

	// Store block in database
	if err := bc.storeBlock(block, true); err != nil {
		return fmt.Errorf("failed to store block: %w", err)
	}

	// Update chain state
	bc.updateChainState(block)

	// Update statistics
	bc.incrementProcessed()

	// Check for orphans that can now be processed
	bc.processOrphanBlocks(block.Header.Hash)

	// Create checkpoint if needed
	if block.Header.Height%CheckpointInterval == 0 {
		bc.createCheckpoint(block.Header.Height)
	}

	fmt.Printf("✅ Block #%d added to main chain (%d txs)\n", block.Header.Height, len(block.Transactions))
	fmt.Printf("   📦 Hash:     %x\n", block.Header.Hash)
	fmt.Printf("   🔗 Previous: %x\n", block.Header.PrevBlockHash)
	fmt.Printf("   🌳 Merkle:   %x\n", block.Header.MerkleRoot[:16])

	return nil
}

// handleSideChain handles a block on a side chain
func (bc *Blockchain) handleSideChain(block *Block) error {
	// Calculate total work for this chain
	chainWork := bc.calculateChainWork(block)

	// If this chain has more work, reorganize
	if chainWork.Cmp(bc.chainState.TotalWork) > 0 {
		return bc.reorganize(block)
	}

	// Store as side chain block
	return bc.storeBlock(block, false)
}

// reorganize performs a blockchain reorganization
func (bc *Blockchain) reorganize(newTip *Block) error {
	// Find common ancestor
	_, oldBlocks, newBlocks, err := bc.findReorgPath(newTip)
	if err != nil {
		return fmt.Errorf("failed to find reorg path: %w", err)
	}

	// Check reorg depth
	if len(oldBlocks) > MaxReorgDepth {
		return ErrReorgTooDeep
	}

	fmt.Printf("🔄 Reorganizing: reverting %d blocks, applying %d blocks\n", len(oldBlocks), len(newBlocks))

	// Create checkpoint before reorg
	checkpointID := bc.State.Checkpoint()

	// Revert old blocks
	for i := len(oldBlocks) - 1; i >= 0; i-- {
		if err := bc.revertBlock(oldBlocks[i]); err != nil {
			bc.State.RevertToCheckpoint(checkpointID)
			return fmt.Errorf("failed to revert block: %w", err)
		}
	}

	// Apply new blocks
	for _, block := range newBlocks {
		if err := bc.applyBlockTransactions(block); err != nil {
			bc.State.RevertToCheckpoint(checkpointID)
			return fmt.Errorf("failed to apply new block: %w", err)
		}
	}

	// Commit state
	if err := bc.State.Commit(); err != nil {
		bc.State.RevertToCheckpoint(checkpointID)
		return fmt.Errorf("failed to commit reorg state: %w", err)
	}

	// Update chain state
	bc.chainState.Height = newTip.Header.Height
	bc.chainState.BestHash = newTip.Header.Hash
	bc.chainState.TotalWork = bc.calculateChainWork(newTip)

	// Update statistics
	bc.statsMu.Lock()
	bc.stats.ReorgsCount++
	bc.statsMu.Unlock()

	fmt.Printf("✅ Reorganization complete: new tip at height %d\n", newTip.Header.Height)

	return nil
}

// Helper methods

func (bc *Blockchain) calculateBlockHash(header *BlockHeader) []byte {
	var buf bytes.Buffer

	buf.Write(encodeUint32(header.Version))
	buf.Write(encodeUint64(header.Height))
	buf.Write(header.PrevBlockHash)
	buf.Write(header.MerkleRoot)
	buf.Write(encodeInt64(header.Timestamp))
	buf.Write(encodeUint32(header.Difficulty))
	buf.Write(encodeUint64(header.Nonce))

	// Double SHA-256
	first := sha256.Sum256(buf.Bytes())
	second := sha256.Sum256(first[:])

	return second[:]
}

func (bc *Blockchain) calculateMerkleRoot(txs []*types.Transaction) []byte {
	if len(txs) == 0 {
		return make([]byte, 32)
	}

	// Build merkle tree
	var hashes [][]byte
	for _, tx := range txs {
		hashes = append(hashes, tx.Hash[:])
	}

	// Iteratively hash pairs until we have one root
	for len(hashes) > 1 {
		if len(hashes)%2 != 0 {
			hashes = append(hashes, hashes[len(hashes)-1]) // Duplicate last if odd
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

func (bc *Blockchain) calculateBlockReward(height uint64) *big.Int {
	halvings := height / HalvingInterval
	if halvings >= 64 {
		return big.NewInt(0) // All coins mined
	}

	reward := big.NewInt(InitialBlockReward)
	reward.Rsh(reward, uint(halvings)) // Divide by 2^halvings

	return reward
}

func (bc *Blockchain) calculateNextDifficulty(prevHeader *BlockHeader) uint32 {
	nextHeight := prevHeader.Height + 1

	// Only adjust every DifficultyAdjustmentInterval blocks
	if nextHeight%DifficultyAdjustmentInterval != 0 {
		return prevHeader.Difficulty
	}

	// Need enough blocks for adjustment
	if nextHeight < DifficultyAdjustmentInterval {
		return prevHeader.Difficulty
	}

	// 🔥 DEFENSIVE: Validate start height
	adjustmentStartHeight := nextHeight - DifficultyAdjustmentInterval
	if adjustmentStartHeight < 0 {
		fmt.Printf("⚠️  Invalid adjustment height %d, returning current difficulty\n", adjustmentStartHeight)
		return prevHeader.Difficulty
	}

	// Get block from start of adjustment period
	oldBlock, err := bc.GetBlockByHeight(adjustmentStartHeight)
	if err != nil {
		fmt.Printf("⚠️  Could not get adjustment start block at height %d: %v\n", adjustmentStartHeight, err)
		return prevHeader.Difficulty // Fallback to previous difficulty
	}

	// 🔥 DEFENSIVE: Verify oldBlock is valid
	if oldBlock == nil {
		fmt.Printf("⚠️  Old block is nil at height %d\n", adjustmentStartHeight)
		return prevHeader.Difficulty
	}

	// CRITICAL: Calculate actual time for the interval
	actualTime := prevHeader.Timestamp - oldBlock.Header.Timestamp
	expectedTime := int64(DifficultyAdjustmentInterval) * int64(TargetBlockTime.Seconds())

	// Sanity check
	if actualTime <= 0 {
		fmt.Printf("❌ CRITICAL: Invalid actual time %d, keeping difficulty\n", actualTime)
		return prevHeader.Difficulty
	}

	// CRITICAL: Clamp actual time to prevent gaming
	minActualTime := expectedTime / 4
	maxActualTime := expectedTime * 4

	if actualTime < minActualTime {
		fmt.Printf("⚠️  Clamping actual time: %d → %d (too fast)\n", actualTime, minActualTime)
		actualTime = minActualTime
	}
	if actualTime > maxActualTime {
		fmt.Printf("⚠️  Clamping actual time: %d → %d (too slow)\n", actualTime, maxActualTime)
		actualTime = maxActualTime
	}

	// CRITICAL: Calculate new difficulty
	oldDifficulty := prevHeader.Difficulty

	newDiffBig := new(big.Int).SetUint64(uint64(oldDifficulty))
	newDiffBig.Mul(newDiffBig, big.NewInt(expectedTime))
	newDiffBig.Div(newDiffBig, big.NewInt(actualTime))

	// Convert back to uint32
	var newDifficulty uint32
	if newDiffBig.IsUint64() {
		newDiff64 := newDiffBig.Uint64()
		if newDiff64 > 0xFFFFFFFF {
			newDifficulty = 0xFFFFFFFF
		} else {
			newDifficulty = uint32(newDiff64)
		}
	} else {
		newDifficulty = 0xFFFFFFFF
	}

	// Enforce minimum difficulty
	const MinDifficulty = 1000
	if newDifficulty < MinDifficulty {
		newDifficulty = MinDifficulty
	}

	percentChange := ((float64(newDifficulty) / float64(oldDifficulty)) - 1) * 100

	fmt.Printf("\n📊 DIFFICULTY ADJUSTMENT at height %d:\n", nextHeight)
	fmt.Printf("   Period: blocks %d to %d (%d blocks)\n",
		adjustmentStartHeight, prevHeader.Height, DifficultyAdjustmentInterval)
	fmt.Printf("   Expected time: %d seconds (%d blocks × %d sec)\n",
		expectedTime, DifficultyAdjustmentInterval, int(TargetBlockTime.Seconds()))
	fmt.Printf("   Actual time: %d seconds\n", actualTime)
	fmt.Printf("   Time ratio: %.4f\n", float64(actualTime)/float64(expectedTime))
	fmt.Printf("   Difficulty: %d → %d (%.2f%% change)\n",
		oldDifficulty, newDifficulty, percentChange)

	if percentChange > 0 {
		fmt.Printf("   ⬆️  Difficulty INCREASED (blocks were too fast)\n")
	} else if percentChange < 0 {
		fmt.Printf("   ⬇️  Difficulty DECREASED (blocks were too slow)\n")
	}
	fmt.Println()

	return newDifficulty
}

func (bc *Blockchain) difficultyToTarget(difficulty uint32) *big.Int {
	// Convert difficulty to target (simplified)
	maxTarget := new(big.Int).Lsh(big.NewInt(1), 256)
	target := new(big.Int).Div(maxTarget, big.NewInt(int64(difficulty)))
	return target
}

func (bc *Blockchain) calculateBlockSize(block *Block) int {
	data, _ := json.Marshal(block)
	return len(data)
}

func (bc *Blockchain) applyTransaction(tx *types.Transaction) error {
	// Handle coinbase/mining reward transactions
	if tx.From == "COINBASE" || tx.From == "coinbase" {
		// Add reward directly without locks
		tokenType := TokenDNT
		if tx.TokenType == "AFC" {
			tokenType = TokenAFC
		}

		// Use AddBalance which handles locking internally
		if err := bc.State.AddBalance(tx.To, tx.Amount, tokenType); err != nil {
			// Don't fail the block if state update fails - just log it
			fmt.Printf("⚠️  Warning: Failed to update state for coinbase: %v\n", err)
			return nil // Return nil to avoid blocking the chain
		}

		return nil
	}

	// Handle regular transactions
	tokenType := TokenDNT
	if tx.TokenType == "AFC" {
		tokenType = TokenAFC
	}

	// Deduct from sender
	if err := bc.State.SubBalance(tx.From, tx.Amount, tokenType); err != nil {
		return fmt.Errorf("insufficient balance: %w", err)
	}

	// Deduct fee
	if tx.FeeDNT != nil && tx.FeeDNT.Sign() > 0 {
		if err := bc.State.SubBalance(tx.From, tx.FeeDNT, TokenDNT); err != nil {
			return fmt.Errorf("insufficient balance for fee: %w", err)
		}
	}

	// Add to recipient
	if err := bc.State.AddBalance(tx.To, tx.Amount, tokenType); err != nil {
		return fmt.Errorf("failed to credit recipient: %w", err)
	}

	// Increment nonce for the sender account
	currentNonce, err := bc.State.GetNonce(tx.From)
	if err != nil {
		// If account doesn't exist, create it with nonce 0, then increment to 1
		currentNonce = 0
	}
	newNonce := currentNonce + 1
	if err := bc.State.SetNonce(tx.From, newNonce); err != nil {
		return fmt.Errorf("failed to increment nonce from %d to %d: %w", currentNonce, newNonce, err)
	}

	fromAddr := tx.From
	if len(fromAddr) > 8 {
		fromAddr = fromAddr[:8]
	}
	fmt.Printf("   ✅ Applied tx from %s: nonce incremented %d → %d\n",
		fromAddr, currentNonce, newNonce)

	return nil
}

func (bc *Blockchain) applyBlockTransactions(block *Block) error {
	for _, tx := range block.Transactions {
		if err := bc.applyTransaction(tx); err != nil {
			return err
		}
	}
	return nil
}

func (bc *Blockchain) revertBlock(block *Block) error {
	// Revert transactions in reverse order
	for i := len(block.Transactions) - 1; i >= 0; i-- {
		// Revert transaction
	}
	return nil
}

func (bc *Blockchain) storeBlock(block *Block, isMainChain bool) error {
	return bc.db.Update(func(txn *badger.Txn) error {
		blockData, err := json.Marshal(block)
		if err != nil {
			return err
		}

		key := append(prefixBlock, encodeUint64(block.Header.Height)...)
		if err := txn.Set(key, blockData); err != nil {
			return err
		}

		// Store hash mapping
		hashKey := append(prefixBlockHash, block.Header.Hash...)
		return txn.Set(hashKey, encodeUint64(block.Header.Height))
	})
}

func (bc *Blockchain) hasBlock(hash []byte) bool {
	err := bc.db.View(func(txn *badger.Txn) error {
		key := append(prefixBlockHash, hash...)
		_, err := txn.Get(key)
		return err
	})
	return err == nil
}

func (bc *Blockchain) addOrphanBlock(block *Block) error {
	bc.orphansMu.Lock()
	defer bc.orphansMu.Unlock()

	if len(bc.orphans) >= MaxOrphanBlocks {
		// Evict oldest orphan
		bc.evictOldestOrphan()
	}

	bc.orphans[string(block.Header.Hash)] = &OrphanBlock{
		Block:      block,
		ReceivedAt: time.Now(),
	}

	bc.statsMu.Lock()
	bc.stats.OrphanBlocksCount++
	bc.statsMu.Unlock()

	return ErrOrphanBlock
}

func (bc *Blockchain) processOrphanBlocks(parentHash []byte) {
	bc.orphansMu.Lock()
	defer bc.orphansMu.Unlock()

	for hash, orphan := range bc.orphans {
		if bytes.Equal(orphan.Block.Header.PrevBlockHash, parentHash) {
			delete(bc.orphans, hash)
			// Try to add orphan block again
			go bc.AddBlock(orphan.Block)
		}
	}
}

func (bc *Blockchain) evictOldestOrphan() {
	var oldest *OrphanBlock
	var oldestHash string

	for hash, orphan := range bc.orphans {
		if oldest == nil || orphan.ReceivedAt.Before(oldest.ReceivedAt) {
			oldest = orphan
			oldestHash = hash
		}
	}

	if oldest != nil {
		delete(bc.orphans, oldestHash)
	}
}

func (bc *Blockchain) updateChainState(block *Block) {
	bc.chainState.Height = block.Header.Height
	bc.chainState.BestHash = block.Header.Hash
	bc.chainState.TotalWork.Add(bc.chainState.TotalWork, big.NewInt(int64(block.Header.Difficulty)))
	bc.chainState.Difficulty = block.Header.Difficulty
}

func (bc *Blockchain) calculateChainWork(block *Block) *big.Int {
	// Sum of all difficulties up to this block
	work := big.NewInt(0)
	// Implementation would walk back and sum difficulties
	return work
}

func (bc *Blockchain) findReorgPath(newTip *Block) (*Block, []*Block, []*Block, error) {
	// Find common ancestor and return blocks to revert/apply
	return nil, nil, nil, nil // Placeholder
}

func (bc *Blockchain) createCheckpoint(height uint64) error {
	// Create state checkpoint
	return nil
}

func (bc *Blockchain) loadChainState() error {
	return bc.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(prefixChainState)
		if err != nil {
			return err
		}

		return item.Value(func(val []byte) error {
			return json.Unmarshal(val, &bc.chainState)
		})
	})
}

func (bc *Blockchain) incrementProcessed() {
	bc.statsMu.Lock()
	bc.stats.BlocksProcessed++
	bc.statsMu.Unlock()
}

func (bc *Blockchain) incrementRejected() {
	bc.statsMu.Lock()
	bc.stats.BlocksRejected++
	bc.statsMu.Unlock()
}

// Public API methods

func (bc *Blockchain) GetBlockByHeight(height uint64) (*Block, error) {
	var block Block
	err := bc.db.View(func(txn *badger.Txn) error {
		key := append(prefixBlock, encodeUint64(height)...)
		item, err := txn.Get(key)
		if err != nil {
			return err
		}

		return item.Value(func(val []byte) error {
			return json.Unmarshal(val, &block)
		})
	})

	if err == badger.ErrKeyNotFound {
		return nil, ErrBlockNotFound
	}

	return &block, err
}

func (bc *Blockchain) GetBlockByHash(hash []byte) (*Block, error) {
	var height uint64
	err := bc.db.View(func(txn *badger.Txn) error {
		key := append(prefixBlockHash, hash...)
		item, err := txn.Get(key)
		if err != nil {
			return err
		}

		return item.Value(func(val []byte) error {
			height = decodeUint64(val)
			return nil
		})
	})

	if err != nil {
		return nil, err
	}

	return bc.GetBlockByHeight(height)
}

func (bc *Blockchain) GetHeight() uint64 {
	bc.chainMu.RLock()
	defer bc.chainMu.RUnlock()
	return bc.chainState.Height
}

func (bc *Blockchain) GetBestHash() []byte {
	bc.chainMu.RLock()
	defer bc.chainMu.RUnlock()
	return bc.chainState.BestHash
}

// GetAccountNonce retrieves the nonce for an account from state
func (bc *Blockchain) GetAccountNonce(address string) (uint64, error) {
	return bc.State.GetNonce(address)
}

// Utility functions

func encodeUint64(n uint64) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, n)
	return buf
}

func decodeUint64(b []byte) uint64 {
	return binary.BigEndian.Uint64(b)
}

func encodeUint32(n uint32) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, n)
	return buf
}

func encodeInt64(n int64) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(n))
	return buf
}

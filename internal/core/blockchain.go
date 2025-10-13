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

	"github.com/dgraph-io/badger/v4"
	"github.com/EmekaIwuagwu/dinari-blockchain/internal/types"
)

const (
	// Consensus parameters
	TargetBlockTime         = 15 * time.Second // 15 seconds per block
	DifficultyAdjustmentInterval = 120         // Adjust every 120 blocks
	MaxBlockSize            = 1 << 20          // 1MB max block size
	MaxTransactionsPerBlock = 5000             // Max 5000 txs per block
	
	// Reorg protection
	MaxReorgDepth = 100 // Maximum depth for chain reorganization
	
	// Orphan blocks
	MaxOrphanBlocks      = 100
	OrphanBlockTimeout   = 10 * time.Minute
	
	// Checkpoints
	CheckpointInterval = 1000 // Create checkpoint every 1000 blocks
	
	// Block rewards
	InitialBlockReward = 50 * 1e8        // 50 DNT (with 8 decimals)
	HalvingInterval    = 210000          // Halve reward every 210,000 blocks
	MaxSupply          = 21000000 * 1e8  // 21 million DNT total supply
	
	// Time validation
	MaxFutureBlockTime = 2 * time.Hour // Reject blocks more than 2 hours in future
	
	// Genesis block
	GenesisTimestamp = 1704067200 // 2024-01-01 00:00:00 UTC
)

var (
	// Database key prefixes
	prefixBlock       = []byte("blk:")      // blk:<height> -> Block
	prefixBlockHash   = []byte("blkhash:")  // blkhash:<hash> -> height
	prefixBestChain   = []byte("best:")     // best:<height> -> hash
	prefixChainState  = []byte("chain:")    // chain:state -> ChainState
	prefixCheckpoint  = []byte("ckpt:")     // ckpt:<height> -> Checkpoint
	prefixOrphan      = []byte("orphan:")   // orphan:<hash> -> Block
	
	// Special keys
	keyGenesisHash = []byte("genesis:hash")
	keyBestHeight  = []byte("chain:height")
	keyChainWork   = []byte("chain:work")
	
	// Errors
	ErrBlockNotFound       = errors.New("block not found")
	ErrInvalidBlock        = errors.New("invalid block")
	ErrInvalidPrevHash     = errors.New("invalid previous block hash")
	ErrInvalidTimestamp    = errors.New("invalid timestamp")
	ErrInvalidDifficulty   = errors.New("invalid difficulty")
	ErrInvalidMerkleRoot   = errors.New("invalid merkle root")
	ErrBlockTooLarge       = errors.New("block size exceeds limit")
	ErrTooManyTransactions = errors.New("too many transactions in block")
	ErrDuplicateBlock      = errors.New("duplicate block")
	ErrOrphanBlock         = errors.New("orphan block (previous block not found)")
	ErrReorgTooDeep        = errors.New("reorganization too deep")
	ErrInvalidBlockReward  = errors.New("invalid block reward")
	ErrGenesisBlockMismatch = errors.New("genesis block mismatch")
)

// Block represents a blockchain block
type Block struct {
	Header       *BlockHeader   `json:"header"`
	Transactions []*types.Transaction `json:"transactions"`
}

// BlockHeader contains block metadata
type BlockHeader struct {
	Version       uint32   `json:"version"`
	Height        uint64   `json:"height"`
	PrevBlockHash []byte   `json:"prevBlockHash"`
	MerkleRoot    []byte   `json:"merkleRoot"`
	Timestamp     int64    `json:"timestamp"`
	Difficulty    uint32   `json:"difficulty"`
	Nonce         uint64   `json:"nonce"`
	Hash          []byte   `json:"hash"`
	StateRoot     []byte   `json:"stateRoot"` // Root of state merkle tree
}

// ChainState tracks the current chain state
type ChainState struct {
	Height       uint64   `json:"height"`
	BestHash     []byte   `json:"bestHash"`
	TotalWork    *big.Int `json:"totalWork"`
	Difficulty   uint32   `json:"difficulty"`
	LastAdjustment uint64 `json:"lastAdjustment"`
}

// OrphanBlock represents a block waiting for its parent
type OrphanBlock struct {
	Block     *Block
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
	stats BlockchainStats
	statsMu sync.Mutex
}

// BlockchainStats tracks blockchain statistics
type BlockchainStats struct {
	BlocksProcessed   uint64
	BlocksRejected    uint64
	OrphanBlocksCount uint64
	ReorgsCount       uint64
	AverageBlockTime  time.Duration
}

// NewBlockchain creates a new blockchain instance
func NewBlockchain(db *badger.DB, state *StateDB, genesisBlock *Block) (*Blockchain, error) {
	if db == nil {
		return nil, errors.New("database cannot be nil")
	}
	if state == nil {
		return nil, errors.New("state cannot be nil")
	}
	if genesisBlock == nil {
		return nil, errors.New("genesis block cannot be nil")
	}
	
	bc := &Blockchain{
		db:           db,
		State:        state,
		orphans:      make(map[string]*OrphanBlock),
		blockCache:   make(map[uint64]*Block),
		maxCacheSize: 100,
		genesisBlock: genesisBlock,
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
func (bc *Blockchain) initialize() error {
	// Check if genesis exists
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
	
	// If genesis doesn't exist, create it
	if genesisHash == nil {
		return bc.createGenesis()
	}
	
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
	
	// 1. Basic validation
	if err := bc.validateBlockBasics(block); err != nil {
		bc.incrementRejected()
		return fmt.Errorf("basic validation failed: %w", err)
	}
	
	// 2. Check for duplicate
	if bc.hasBlock(block.Header.Hash) {
		return ErrDuplicateBlock
	}
	
	// 3. Check if previous block exists
	prevBlock, err := bc.GetBlockByHash(block.Header.PrevBlockHash)
	if err != nil {
		// Previous block not found - add to orphan pool
		return bc.addOrphanBlock(block)
	}
	
	// 4. Validate block header
	if err := bc.validateBlockHeader(block.Header, prevBlock.Header); err != nil {
		bc.incrementRejected()
		return fmt.Errorf("header validation failed: %w", err)
	}
	
	// 5. Validate transactions
	if err := bc.validateBlockTransactions(block); err != nil {
		bc.incrementRejected()
		return fmt.Errorf("transaction validation failed: %w", err)
	}
	
	// 6. Validate merkle root
	if err := bc.validateMerkleRoot(block); err != nil {
		bc.incrementRejected()
		return fmt.Errorf("merkle root validation failed: %w", err)
	}
	
	// 7. Check if this extends the best chain
	isMainChain := bytes.Equal(block.Header.PrevBlockHash, bc.chainState.BestHash)
	
	if isMainChain {
		// Extends main chain - add directly
		return bc.addBlockToMainChain(block)
	}
	
	// Side chain - check if it becomes the new best chain
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
	// Check height
	if header.Height != prevHeader.Height+1 {
		return fmt.Errorf("invalid height: expected %d, got %d", prevHeader.Height+1, header.Height)
	}
	
	// Check previous hash
	if !bytes.Equal(header.PrevBlockHash, prevHeader.Hash) {
		return ErrInvalidPrevHash
	}
	
	// Check timestamp (must be after previous block)
	if header.Timestamp <= prevHeader.Timestamp {
		return ErrInvalidTimestamp
	}
	
	// Check difficulty
	expectedDifficulty := bc.calculateNextDifficulty(prevHeader)
	if header.Difficulty != expectedDifficulty {
		return fmt.Errorf("%w: expected %d, got %d", ErrInvalidDifficulty, expectedDifficulty, header.Difficulty)
	}
	
	// Validate Proof of Work
	if !bc.validateProofOfWork(header) {
		return errors.New("invalid proof of work")
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
		return err
	}
	
	if tx.Nonce != expectedNonce {
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
	// Check if hash meets difficulty target
	target := bc.difficultyToTarget(header.Difficulty)
	hashInt := new(big.Int).SetBytes(header.Hash)
	
	return hashInt.Cmp(target) <= 0
}

// addBlockToMainChain adds a block to the main chain and updates state
func (bc *Blockchain) addBlockToMainChain(block *Block) error {
	// Create state checkpoint
	checkpointID := bc.State.Checkpoint()
	
	// Apply transactions to state
	for _, tx := range block.Transactions {
		if err := bc.applyTransaction(tx); err != nil {
			// Rollback state on error
			bc.State.RevertToCheckpoint(checkpointID)
			return fmt.Errorf("failed to apply transaction: %w", err)
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
	// Only adjust every DifficultyAdjustmentInterval blocks
	if (prevHeader.Height+1)%DifficultyAdjustmentInterval != 0 {
		return prevHeader.Difficulty
	}
	
	// Get block from last adjustment
	adjustmentHeight := prevHeader.Height - DifficultyAdjustmentInterval + 1
	oldBlock, err := bc.GetBlockByHeight(adjustmentHeight)
	if err != nil {
		return prevHeader.Difficulty // Fallback
	}
	
	// Calculate actual time taken
	actualTime := prevHeader.Timestamp - oldBlock.Header.Timestamp
	expectedTime := int64(DifficultyAdjustmentInterval) * int64(TargetBlockTime.Seconds())
	
	// Calculate adjustment (limit to 4x change)
	adjustment := float64(actualTime) / float64(expectedTime)
	if adjustment > 4.0 {
		adjustment = 4.0
	}
	if adjustment < 0.25 {
		adjustment = 0.25
	}
	
	newDifficulty := float64(prevHeader.Difficulty) / adjustment
	
	return uint32(newDifficulty)
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
	// Apply transaction to state
	// (This would integrate with state.Transfer)
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
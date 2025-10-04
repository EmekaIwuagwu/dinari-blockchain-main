package core

import (
	"encoding/binary"
	"fmt"
	"math/big" 
	"encoding/json"
	"sync"

	"github.com/EmekaIwuagwu/dinari-blockchain/internal/consensus"
	"github.com/EmekaIwuagwu/dinari-blockchain/internal/storage"
	"github.com/EmekaIwuagwu/dinari-blockchain/internal/types"
	"go.uber.org/zap"
)

// Blockchain manages the chain of blocks
type Blockchain struct {
	db               *storage.DB
	state            *State
	logger           *zap.Logger
	pow              *consensus.ProofOfWork
	difficultyAdjust *consensus.DifficultyAdjuster
	rewardCalc       *consensus.RewardCalculator

	// Chain metadata
	tip    [32]byte
	height uint64
	mu     sync.RWMutex

	// Mint authorities for AFC
	mintAuthorities map[string]bool
}

// Config contains blockchain configuration
type Config struct {
	DB              *storage.DB
	Logger          *zap.Logger
	MintAuthorities []string
}

// NewBlockchain creates a new blockchain instance
func NewBlockchain(config *Config) (*Blockchain, error) {
	bc := &Blockchain{
		db:               config.DB,
		state:            NewState(config.DB, config.Logger),
		logger:           config.Logger,
		pow:              consensus.NewProofOfWork(consensus.TargetBlockTime),
		difficultyAdjust: consensus.NewDifficultyAdjuster(),
		rewardCalc:       consensus.NewRewardCalculator(),
		mintAuthorities:  make(map[string]bool),
	}

	// Set mint authorities
	for _, auth := range config.MintAuthorities {
		bc.mintAuthorities[auth] = true
	}

	// Load or create genesis
	if err := bc.loadOrCreateGenesis(); err != nil {
		return nil, err
	}

	bc.logger.Info("Blockchain initialized",
		zap.Uint64("height", bc.height),
		zap.String("tip", fmt.Sprintf("%x", bc.tip)))

	return bc, nil
}

// loadOrCreateGenesis loads existing genesis or creates new one
// loadOrCreateGenesis loads existing genesis or creates new one
func (bc *Blockchain) loadOrCreateGenesis() error {
	// Try to load genesis
	genesisKey := storage.GenesisKey()
	genesisHashData, err := bc.db.Get(genesisKey)

	if err != nil {
		// Genesis doesn't exist, create it
		bc.logger.Info("Creating genesis block")
		genesis := types.NewGenesisBlock()

		if err := bc.storeBlock(genesis); err != nil {
			return fmt.Errorf("failed to store genesis: %w", err)
		}

		// Store genesis hash
		if err := bc.db.Set(genesisKey, genesis.Hash[:]); err != nil {
			return err
		}

		bc.tip = genesis.Hash
		bc.height = 0

		return nil
	}

	// Load existing chain
	var genesisHash [32]byte
	copy(genesisHash[:], genesisHashData)

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

	bc.logger.Info("Loaded existing blockchain",
		zap.Uint64("height", bc.height))

	return nil
}

// AddBlock adds a new block to the chain
func (bc *Blockchain) AddBlock(block *types.Block) error {
	bc.mu.Lock()
	defer bc.mu.Unlock()

	// Validate block
	if err := bc.ValidateBlock(block); err != nil {
		return fmt.Errorf("block validation failed: %w", err)
	}

	// Apply block
	if err := bc.applyBlock(block); err != nil {
		return fmt.Errorf("failed to apply block: %w", err)
	}

	bc.logger.Info("Block added",
		zap.Uint64("height", block.Header.Number),
		zap.String("hash", fmt.Sprintf("%x", block.Hash[:8])),
		zap.Uint32("txCount", block.Header.TxCount))

	return nil
}

// ValidateBlock performs full validation on a block
func (bc *Blockchain) ValidateBlock(block *types.Block) error {
	// Basic structure validation
	if err := block.Validate(); err != nil {
		return err
	}

	// Check parent exists
	if block.Header.Number > 0 {
		parentExists, err := bc.db.Has(storage.BlockHashKey(block.Header.ParentHash))
		if err != nil {
			return err
		}
		if !parentExists {
			return types.ErrOrphanBlock
		}

		// Verify parent hash matches current tip
		if block.Header.ParentHash != bc.tip {
			return types.ErrInvalidParentHash
		}

		// Verify block number is sequential
		if block.Header.Number != bc.height+1 {
			return fmt.Errorf("invalid block number: expected %d, got %d", bc.height+1, block.Header.Number)
		}
	}

	// Validate proof of work
	if !bc.pow.ValidateProofOfWork(block) {
		return types.ErrInvalidPoW
	}

	// Validate difficulty
	if err := bc.validateDifficulty(block); err != nil {
		return err
	}

	// Validate transactions
	if err := bc.validateBlockTransactions(block); err != nil {
		return err
	}

	return nil
}

// validateDifficulty checks if the block difficulty is correct
func (bc *Blockchain) validateDifficulty(block *types.Block) error {
	if block.Header.Number == 0 {
		return nil // Genesis block
	}

	// Get recent blocks for difficulty calculation
	recentBlocks, err := bc.getRecentBlocks(consensus.DifficultyWindow)
	if err != nil {
		return err
	}

	return bc.difficultyAdjust.ValidateDifficulty(block.Header.Number, block.Header.Difficulty, recentBlocks)
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

	// Validate coinbase reward (base reward + transaction fees)
	baseReward := bc.rewardCalc.CalculateBlockReward(block.Header.Number)

	// Calculate total fees from all transactions (excluding coinbase)
	totalFees := big.NewInt(0)
	for _, tx := range block.Transactions[1:] {
		if tx.FeeDNT != nil {
			totalFees.Add(totalFees, tx.FeeDNT)
		}
	}

	// Expected reward = base reward + all transaction fees
	expectedReward := new(big.Int).Add(baseReward, totalFees)

	// Validate coinbase amount matches expected reward
	if coinbaseTx.Amount.Cmp(expectedReward) != 0 {
		bc.logger.Error("Invalid block reward",
			zap.String("expected", expectedReward.String()),
			zap.String("actual", coinbaseTx.Amount.String()),
			zap.String("baseReward", baseReward.String()),
			zap.String("totalFees", totalFees.String()))
		return types.ErrInvalidReward
	}

	// ADD THIS: Log successful coinbase validation with D-address
	bc.logger.Info("✅ Coinbase transaction validated",
		zap.Uint64("blockNumber", block.Header.Number),
		zap.String("miner", coinbaseTx.To),
		zap.String("reward", expectedReward.String()),
		zap.String("baseReward", baseReward.String()),
		zap.String("fees", totalFees.String()))

	for _, tx := range block.Transactions[1:] {
		if tx.IsMint() {
			// Verify it's AFC being minted
			if tx.TokenType != string(types.TokenAFC) {
				bc.logger.Error("Invalid mint token type", 
					zap.String("tokenType", tx.TokenType))
				return types.ErrMintOnlyAFC
			}
			
			// Mint transactions should have zero fee
			if tx.FeeDNT.Cmp(big.NewInt(0)) != 0 {
				bc.logger.Error("Mint transaction has non-zero fee",
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

	return nil
}

// GetTransaction retrieves a transaction from the blockchain by hash
func (bc *Blockchain) GetTransaction(txHash [32]byte) (*types.Transaction, error) {
	bc.mu.RLock()
	defer bc.mu.RUnlock()

	// Try to get from database
	txKey := storage.TxKey(txHash)
	txData, err := bc.db.Get(txKey)
	if err != nil {
		return nil, types.ErrTxNotFound
	}

	return types.DeserializeTransaction(txData)
}

// GetTransactionReceipt retrieves a transaction receipt by hash
func (bc *Blockchain) GetTransactionReceipt(txHash [32]byte) (*types.Receipt, error) {
	bc.mu.RLock()
	defer bc.mu.RUnlock()

	receiptKey := storage.ReceiptKey(txHash)
	receiptData, err := bc.db.Get(receiptKey)
	if err != nil {
		return nil, types.ErrReceiptNotFound
	}

	return types.DeserializeReceipt(receiptData)
}

// GetTransactionsByAddress retrieves all transactions for an address
func (bc *Blockchain) GetTransactionsByAddress(address string, limit int) ([]*types.Transaction, error) {
	bc.mu.RLock()
	defer bc.mu.RUnlock()

	// Get the address index key
	indexKey := storage.AddressTxIndexKey(address)
	indexData, err := bc.db.Get(indexKey)
	if err != nil {
		// Address has no transactions
		return []*types.Transaction{}, nil
	}

	// Deserialize transaction hashes
	var txHashes [][32]byte
	if err := json.Unmarshal(indexData, &txHashes); err != nil {
		return nil, err
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
			continue // Skip if transaction not found
		}
		txs = append(txs, tx)
	}

	return txs, nil
}

// applyBlock applies a block to the blockchain state
func (bc *Blockchain) applyBlock(block *types.Block) error {
	// Apply all transactions
	for _, tx := range block.Transactions {
		if err := bc.state.ApplyTransaction(tx); err != nil {
			return fmt.Errorf("failed to apply tx %x: %w", tx.Hash[:8], err)
		}
	}

	// Commit state changes
	if err := bc.state.Commit(); err != nil {
		return err
	}

	// Store block
	if err := bc.storeBlock(block); err != nil {
		return err
	}

	// Update chain metadata
	bc.tip = block.Hash
	bc.height = block.Header.Number

	// Update metadata in database
	if err := bc.updateChainMetadata(); err != nil {
		return err
	}

	return nil
}

// storeBlock stores a block in the database
func (bc *Blockchain) storeBlock(block *types.Block) error {
	batch := bc.db.NewBatch()
	defer batch.Cancel()

	// Serialize block
	blockData, err := block.Serialize()
	if err != nil {
		return err
	}

	// Store by height
	heightKey := storage.BlockHeightKey(block.Header.Number)
	if err := batch.Set(heightKey, blockData); err != nil {
		return err
	}

	// Store hash -> height mapping
	hashKey := storage.BlockHashKey(block.Hash)
	heightBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(heightBytes, block.Header.Number)
	if err := batch.Set(hashKey, heightBytes); err != nil {
		return err
	}

	// Store transactions
	for i, tx := range block.Transactions {
		txData, err := tx.Serialize()
		if err != nil {
			return err
		}

		txKey := storage.TxKey(tx.Hash)
		if err := batch.Set(txKey, txData); err != nil {
			return err
		}

		// Store receipt
		receipt := types.NewSuccessReceipt(tx.Hash, block.Hash, block.Header.Number, uint32(i), tx.FeeDNT)
		receiptData, err := receipt.Serialize()
		if err != nil {
			return err
		}

		receiptKey := storage.ReceiptKey(tx.Hash)
		if err := batch.Set(receiptKey, receiptData); err != nil {
			return err
		}

		// ADD THIS: Store address indexes for transaction lookup
		if !tx.IsCoinbase() {
			// Index for sender
			if err := bc.indexTransactionForAddress(batch, tx.From, tx.Hash); err != nil {
				return err
			}
		}
		
		// Index for receiver (including coinbase)
		if err := bc.indexTransactionForAddress(batch, tx.To, tx.Hash); err != nil {
			return err
		}
	}

	return batch.Flush()
}

// indexTransactionForAddress adds a transaction to an address's index
func (bc *Blockchain) indexTransactionForAddress(batch *storage.Batch, address string, txHash [32]byte) error {
	indexKey := storage.AddressTxIndexKey(address)
	
	// Get existing index
	var txHashes [][32]byte
	indexData, err := bc.db.Get(indexKey)
	if err == nil {
		if err := json.Unmarshal(indexData, &txHashes); err != nil {
			return err
		}
	}
	
	// Append new transaction
	txHashes = append(txHashes, txHash)
	
	// Store updated index
	indexData, err = json.Marshal(txHashes)
	if err != nil {
		return err
	}
	
	// ADD THIS LOG
	bc.logger.Info("Indexing transaction for address",
		zap.String("address", address),
		zap.String("txHash", fmt.Sprintf("%x", txHash[:8])),
		zap.Int("totalTxs", len(txHashes)))
	
	return batch.Set(indexKey, indexData)
}

// updateChainMetadata updates chain tip and height in database
func (bc *Blockchain) updateChainMetadata() error {
	batch := bc.db.NewBatch()
	defer batch.Cancel()

	// Update tip
	if err := batch.Set(storage.ChainTipKey(), bc.tip[:]); err != nil {
		return err
	}

	// Update height
	heightBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(heightBytes, bc.height)
	if err := batch.Set(storage.ChainHeightKey(), heightBytes); err != nil {
		return err
	}

	return batch.Flush()
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

// GetHeight returns the current chain height
func (bc *Blockchain) GetHeight() uint64 {
	bc.mu.RLock()
	defer bc.mu.RUnlock()
	return bc.height
}

// GetTip returns the current chain tip hash
func (bc *Blockchain) GetTip() [32]byte {
	bc.mu.RLock()
	defer bc.mu.RUnlock()
	return bc.tip
}

// getRecentBlocks returns the most recent N block headers
func (bc *Blockchain) getRecentBlocks(n uint64) ([]*types.BlockHeader, error) {
	count := n
	if bc.height+1 < n {
		count = bc.height + 1
	}

	blocks := make([]*types.BlockHeader, count)
	for i := uint64(0); i < count; i++ {
		height := bc.height - i
		block, err := bc.GetBlock(height)
		if err != nil {
			return nil, err
		}
		blocks[count-1-i] = block.Header
	}

	return blocks, nil
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

// GetState returns the state manager
func (bc *Blockchain) GetState() *State {
	return bc.state
}

// internal/state/checkpoint.go
package state

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/dgraph-io/badger/v3"
	"go.uber.org/zap"
)

// StateManager manages blockchain state and checkpoints
type StateManager struct {
	db             *badger.DB
	checkpointDir  string
	currentState   *State
	pendingState   *State
	checkpoints    map[uint64]*Checkpoint
	lastCheckpoint uint64
	snapshotHeight uint64
	stateLock      sync.RWMutex
	checkpointLock sync.RWMutex
	logger         *zap.Logger
	metrics        StateMetrics
	pruneHeight    uint64
	archiveMode    bool
}

// State represents the complete blockchain state at a given height
type State struct {
	Height         uint64                     `json:"height"`
	Hash           []byte                     `json:"hash"`
	PrevHash       []byte                     `json:"prev_hash"`
	Timestamp      int64                      `json:"timestamp"`
	Accounts       map[string]*AccountState   `json:"accounts"`
	Validators     map[string]*ValidatorState `json:"validators"`
	Contracts      map[string]*ContractState  `json:"contracts"`
	UTXOSet        map[string]*UTXO           `json:"utxo_set"`
	TotalSupplyDNT uint64                     `json:"total_supply_dnt"`
	TotalSupplyAFC uint64                     `json:"total_supply_afc"`
	MerkleRoot     []byte                     `json:"merkle_root"`
	StateRoot      []byte                     `json:"state_root"`
	ReceiptsRoot   []byte                     `json:"receipts_root"`
	Bloom          []byte                     `json:"bloom"`
	GasUsed        uint64                     `json:"gas_used"`
	BaseFee        uint64                     `json:"base_fee"`
	lock           sync.RWMutex
}

// AccountState represents an account's state
type AccountState struct {
	Address      string            `json:"address"`
	BalanceDNT   uint64            `json:"balance_dnt"`
	BalanceAFC   uint64            `json:"balance_afc"`
	Nonce        uint64            `json:"nonce"`
	CodeHash     []byte            `json:"code_hash,omitempty"`
	StorageRoot  []byte            `json:"storage_root,omitempty"`
	Permissions  []string          `json:"permissions,omitempty"`
	LastActivity int64             `json:"last_activity"`
	Frozen       bool              `json:"frozen"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

// ValidatorState represents a validator's state
type ValidatorState struct {
	Address         string       `json:"address"`
	PublicKey       []byte       `json:"public_key"`
	Stake           uint64       `json:"stake"`
	Commission      uint32       `json:"commission"`
	LastProposal    uint64       `json:"last_proposal"`
	MissedBlocks    uint64       `json:"missed_blocks"`
	SlashingHistory []SlashEvent `json:"slashing_history,omitempty"`
	Active          bool         `json:"active"`
	JoinedHeight    uint64       `json:"joined_height"`
}

// ContractState represents a smart contract's state
type ContractState struct {
	Address     string                 `json:"address"`
	Code        []byte                 `json:"code"`
	Storage     map[string][]byte      `json:"storage"`
	Creator     string                 `json:"creator"`
	CreatedAt   uint64                 `json:"created_at"`
	LastUpdated uint64                 `json:"last_updated"`
	Version     uint32                 `json:"version"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// UTXO represents an unspent transaction output
type UTXO struct {
	TxHash      []byte `json:"tx_hash"`
	OutputIndex uint32 `json:"output_index"`
	Amount      uint64 `json:"amount"`
	TokenType   string `json:"token_type"`
	Address     string `json:"address"`
	Height      uint64 `json:"height"`
	Spent       bool   `json:"spent"`
	SpentTxHash []byte `json:"spent_tx_hash,omitempty"`
	SpentHeight uint64 `json:"spent_height,omitempty"`
}

// Checkpoint represents a state checkpoint
type Checkpoint struct {
	Height     uint64    `json:"height"`
	Hash       []byte    `json:"hash"`
	StateRoot  []byte    `json:"state_root"`
	Timestamp  int64     `json:"timestamp"`
	Size       uint64    `json:"size"`
	Accounts   uint64    `json:"accounts"`
	UTXOs      uint64    `json:"utxos"`
	FilePath   string    `json:"file_path"`
	Verified   bool      `json:"verified"`
	VerifiedBy []string  `json:"verified_by"`
	CreatedAt  time.Time `json:"created_at"`
	Finalized  bool      `json:"finalized"`
	Signature  []byte    `json:"signature"`
}

// SlashEvent represents a slashing event
type SlashEvent struct {
	Height uint64 `json:"height"`
	Reason string `json:"reason"`
	Amount uint64 `json:"amount"`
	TxHash []byte `json:"tx_hash"`
}

// StateMetrics tracks state management metrics
type StateMetrics struct {
	StateReads        uint64
	StateWrites       uint64
	CheckpointsSaved  uint64
	CheckpointsLoaded uint64
	PruneOperations   uint64
	StateSize         uint64
}

// NewStateManager creates a new state manager
func NewStateManager(db *badger.DB, checkpointDir string, archiveMode bool, logger *zap.Logger) (*StateManager, error) {
	if err := os.MkdirAll(checkpointDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create checkpoint directory: %w", err)
	}

	sm := &StateManager{
		db:            db,
		checkpointDir: checkpointDir,
		checkpoints:   make(map[uint64]*Checkpoint),
		logger:        logger,
		archiveMode:   archiveMode,
	}

	// Load existing checkpoints
	if err := sm.loadCheckpoints(); err != nil {
		return nil, fmt.Errorf("failed to load checkpoints: %w", err)
	}

	// Initialize state
	if err := sm.initializeState(); err != nil {
		return nil, fmt.Errorf("failed to initialize state: %w", err)
	}

	return sm, nil
}

// initializeState initializes the blockchain state
func (sm *StateManager) initializeState() error {
	// Try to load from latest checkpoint
	if sm.lastCheckpoint > 0 {
		checkpoint := sm.checkpoints[sm.lastCheckpoint]
		if err := sm.loadStateFromCheckpoint(checkpoint); err != nil {
			sm.logger.Warn("Failed to load from checkpoint", zap.Error(err))
		} else {
			sm.logger.Info("State loaded from checkpoint",
				zap.Uint64("height", checkpoint.Height))
			return nil
		}
	}

	// Initialize empty state
	sm.currentState = &State{
		Height:     0,
		Timestamp:  time.Now().Unix(),
		Accounts:   make(map[string]*AccountState),
		Validators: make(map[string]*ValidatorState),
		Contracts:  make(map[string]*ContractState),
		UTXOSet:    make(map[string]*UTXO),
	}

	return sm.saveStateToDB()
}

// GetState returns a copy of the current state
func (sm *StateManager) GetState() *State {
	sm.stateLock.RLock()
	defer sm.stateLock.RUnlock()

	return sm.cloneState(sm.currentState)
}

// BeginStateTransition begins a new state transition
func (sm *StateManager) BeginStateTransition() (*State, error) {
	sm.stateLock.Lock()
	defer sm.stateLock.Unlock()

	if sm.pendingState != nil {
		return nil, fmt.Errorf("state transition already in progress")
	}

	sm.pendingState = sm.cloneState(sm.currentState)
	return sm.pendingState, nil
}

// CommitStateTransition commits the pending state transition
func (sm *StateManager) CommitStateTransition(height uint64, blockHash []byte) error {
	sm.stateLock.Lock()
	defer sm.stateLock.Unlock()

	if sm.pendingState == nil {
		return fmt.Errorf("no pending state transition")
	}

	// Update state metadata
	sm.pendingState.Height = height
	sm.pendingState.Hash = blockHash
	sm.pendingState.PrevHash = sm.currentState.Hash
	sm.pendingState.Timestamp = time.Now().Unix()

	// Calculate state roots
	if err := sm.calculateStateRoots(sm.pendingState); err != nil {
		return fmt.Errorf("failed to calculate state roots: %w", err)
	}

	// Save to database
	if err := sm.saveStateToDB(); err != nil {
		return fmt.Errorf("failed to save state: %w", err)
	}

	// Swap states
	sm.currentState = sm.pendingState
	sm.pendingState = nil

	// Create checkpoint if needed
	if height > 0 && height%1000 == 0 {
		if err := sm.createCheckpoint(height); err != nil {
			sm.logger.Warn("Failed to create checkpoint", zap.Error(err))
		}
	}

	// Prune old state if not in archive mode
	if !sm.archiveMode && height > sm.pruneHeight+10000 {
		go sm.pruneOldState(height - 10000)
	}

	sm.metrics.StateWrites++
	return nil
}

// RollbackStateTransition rolls back the pending state transition
func (sm *StateManager) RollbackStateTransition() {
	sm.stateLock.Lock()
	defer sm.stateLock.Unlock()

	sm.pendingState = nil
}

// GetAccount returns an account state
func (sm *StateManager) GetAccount(address string) (*AccountState, error) {
	sm.stateLock.RLock()
	defer sm.stateLock.RUnlock()

	account, exists := sm.currentState.Accounts[address]
	if !exists {
		return nil, fmt.Errorf("account not found: %s", address)
	}

	sm.metrics.StateReads++
	return account, nil
}

// UpdateAccount updates an account state
func (sm *StateManager) UpdateAccount(account *AccountState) error {
	sm.stateLock.Lock()
	defer sm.stateLock.Unlock()

	if sm.pendingState == nil {
		return fmt.Errorf("no pending state transition")
	}

	account.LastActivity = time.Now().Unix()
	sm.pendingState.Accounts[account.Address] = account

	sm.metrics.StateWrites++
	return nil
}

// GetUTXO returns a UTXO by key
func (sm *StateManager) GetUTXO(key string) (*UTXO, error) {
	sm.stateLock.RLock()
	defer sm.stateLock.RUnlock()

	utxo, exists := sm.currentState.UTXOSet[key]
	if !exists {
		return nil, fmt.Errorf("UTXO not found: %s", key)
	}

	sm.metrics.StateReads++
	return utxo, nil
}

// AddUTXO adds a new UTXO
func (sm *StateManager) AddUTXO(utxo *UTXO) error {
	sm.stateLock.Lock()
	defer sm.stateLock.Unlock()

	if sm.pendingState == nil {
		return fmt.Errorf("no pending state transition")
	}

	key := fmt.Sprintf("%x:%d", utxo.TxHash, utxo.OutputIndex)
	sm.pendingState.UTXOSet[key] = utxo

	sm.metrics.StateWrites++
	return nil
}

// SpendUTXO marks a UTXO as spent
func (sm *StateManager) SpendUTXO(key string, spentTxHash []byte, spentHeight uint64) error {
	sm.stateLock.Lock()
	defer sm.stateLock.Unlock()

	if sm.pendingState == nil {
		return fmt.Errorf("no pending state transition")
	}

	utxo, exists := sm.pendingState.UTXOSet[key]
	if !exists {
		return fmt.Errorf("UTXO not found: %s", key)
	}

	utxo.Spent = true
	utxo.SpentTxHash = spentTxHash
	utxo.SpentHeight = spentHeight

	sm.metrics.StateWrites++
	return nil
}

// createCheckpoint creates a new checkpoint
func (sm *StateManager) createCheckpoint(height uint64) error {
	sm.checkpointLock.Lock()
	defer sm.checkpointLock.Unlock()

	fileName := fmt.Sprintf("checkpoint_%d.dat", height)
	filePath := filepath.Join(sm.checkpointDir, fileName)

	// Create checkpoint file
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create checkpoint file: %w", err)
	}
	defer file.Close()

	// Serialize current state
	data, err := sm.serializeState(sm.currentState)
	if err != nil {
		return fmt.Errorf("failed to serialize state: %w", err)
	}

	// Write to file
	if _, err := file.Write(data); err != nil {
		return fmt.Errorf("failed to write checkpoint: %w", err)
	}

	// Create checkpoint metadata
	checkpoint := &Checkpoint{
		Height:    height,
		Hash:      sm.currentState.Hash,
		StateRoot: sm.currentState.StateRoot,
		Timestamp: sm.currentState.Timestamp,
		Size:      uint64(len(data)),
		Accounts:  uint64(len(sm.currentState.Accounts)),
		UTXOs:     uint64(len(sm.currentState.UTXOSet)),
		FilePath:  filePath,
		CreatedAt: time.Now(),
	}

	// Sign checkpoint
	checkpoint.Signature = sm.signCheckpoint(checkpoint)

	// Save checkpoint metadata
	sm.checkpoints[height] = checkpoint
	sm.lastCheckpoint = height

	sm.metrics.CheckpointsSaved++
	sm.logger.Info("Checkpoint created",
		zap.Uint64("height", height),
		zap.Uint64("size", checkpoint.Size))

	return sm.saveCheckpointMetadata(checkpoint)
}

// loadStateFromCheckpoint loads state from a checkpoint
func (sm *StateManager) loadStateFromCheckpoint(checkpoint *Checkpoint) error {
	file, err := os.Open(checkpoint.FilePath)
	if err != nil {
		return fmt.Errorf("failed to open checkpoint file: %w", err)
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return fmt.Errorf("failed to read checkpoint: %w", err)
	}

	state, err := sm.deserializeState(data)
	if err != nil {
		return fmt.Errorf("failed to deserialize state: %w", err)
	}

	// Verify checkpoint
	if !sm.verifyCheckpoint(checkpoint, state) {
		return fmt.Errorf("checkpoint verification failed")
	}

	sm.currentState = state
	sm.snapshotHeight = checkpoint.Height

	sm.metrics.CheckpointsLoaded++
	return nil
}

// loadCheckpoints loads existing checkpoint metadata
func (sm *StateManager) loadCheckpoints() error {
	pattern := filepath.Join(sm.checkpointDir, "checkpoint_*.json")
	files, err := filepath.Glob(pattern)
	if err != nil {
		return err
	}

	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			sm.logger.Warn("Failed to read checkpoint metadata", zap.String("file", file))
			continue
		}

		var checkpoint Checkpoint
		if err := json.Unmarshal(data, &checkpoint); err != nil {
			sm.logger.Warn("Failed to unmarshal checkpoint", zap.String("file", file))
			continue
		}

		sm.checkpoints[checkpoint.Height] = &checkpoint
		if checkpoint.Height > sm.lastCheckpoint {
			sm.lastCheckpoint = checkpoint.Height
		}
	}

	sm.logger.Info("Checkpoints loaded",
		zap.Int("count", len(sm.checkpoints)),
		zap.Uint64("latest", sm.lastCheckpoint))

	return nil
}

// saveCheckpointMetadata saves checkpoint metadata to file
func (sm *StateManager) saveCheckpointMetadata(checkpoint *Checkpoint) error {
	fileName := fmt.Sprintf("checkpoint_%d.json", checkpoint.Height)
	filePath := filepath.Join(sm.checkpointDir, fileName)

	data, err := json.MarshalIndent(checkpoint, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filePath, data, 0644)
}

// pruneOldState prunes old state data
func (sm *StateManager) pruneOldState(beforeHeight uint64) {
	sm.stateLock.Lock()
	defer sm.stateLock.Unlock()

	var keysToDelete [][]byte

	err := sm.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false
		it := txn.NewIterator(opts)
		defer it.Close()

		prefix := []byte("state:")
		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			key := item.Key()

			// Parse height from key
			var height uint64
			if err := binary.Read(bytes.NewReader(key[6:14]), binary.BigEndian, &height); err != nil {
				continue
			}

			if height < beforeHeight {
				keysToDelete = append(keysToDelete, item.KeyCopy(nil))
			}
		}
		return nil
	})

	if err != nil {
		sm.logger.Error("Failed to scan for pruning", zap.Error(err))
		return
	}

	// Delete old keys
	err = sm.db.Update(func(txn *badger.Txn) error {
		for _, key := range keysToDelete {
			if err := txn.Delete(key); err != nil {
				return err
			}
		}
		return nil
	})

	if err != nil {
		sm.logger.Error("Failed to prune state", zap.Error(err))
	} else {
		sm.pruneHeight = beforeHeight
		sm.metrics.PruneOperations++
		sm.logger.Info("State pruned",
			zap.Uint64("beforeHeight", beforeHeight),
			zap.Int("keysDeleted", len(keysToDelete)))
	}
}

// saveStateToDB saves current state to database
func (sm *StateManager) saveStateToDB() error {
	batch := sm.db.NewWriteBatch()
	defer batch.Cancel()

	// Save state header
	headerKey := fmt.Sprintf("state:header:%d", sm.currentState.Height)
	headerData, err := json.Marshal(sm.currentState)
	if err != nil {
		return err
	}
	if err := batch.Set([]byte(headerKey), headerData); err != nil {
		return err
	}

	// Save accounts
	for address, account := range sm.currentState.Accounts {
		key := fmt.Sprintf("state:account:%d:%s", sm.currentState.Height, address)
		data, err := json.Marshal(account)
		if err != nil {
			return err
		}
		if err := batch.Set([]byte(key), data); err != nil {
			return err
		}
	}

	// Save UTXOs
	for utxoKey, utxo := range sm.currentState.UTXOSet {
		key := fmt.Sprintf("state:utxo:%d:%s", sm.currentState.Height, utxoKey)
		data, err := json.Marshal(utxo)
		if err != nil {
			return err
		}
		if err := batch.Set([]byte(key), data); err != nil {
			return err
		}
	}

	return batch.Flush()
}

// calculateStateRoots calculates various state roots
func (sm *StateManager) calculateStateRoots(state *State) error {
	// Calculate account state root
	accountHashes := make([][]byte, 0, len(state.Accounts))
	for _, account := range state.Accounts {
		data, _ := json.Marshal(account)
		hash := sha256.Sum256(data)
		accountHashes = append(accountHashes, hash[:])
	}
	state.StateRoot = sm.calculateMerkleRoot(accountHashes)

	// Calculate UTXO merkle root
	utxoHashes := make([][]byte, 0, len(state.UTXOSet))
	for _, utxo := range state.UTXOSet {
		data, _ := json.Marshal(utxo)
		hash := sha256.Sum256(data)
		utxoHashes = append(utxoHashes, hash[:])
	}
	state.MerkleRoot = sm.calculateMerkleRoot(utxoHashes)

	return nil
}

// calculateMerkleRoot calculates merkle root from hashes
func (sm *StateManager) calculateMerkleRoot(hashes [][]byte) []byte {
	if len(hashes) == 0 {
		return nil
	}

	// Sort hashes for deterministic root
	sort.Slice(hashes, func(i, j int) bool {
		return bytes.Compare(hashes[i], hashes[j]) < 0
	})

	for len(hashes) > 1 {
		var newLevel [][]byte
		for i := 0; i < len(hashes); i += 2 {
			if i+1 < len(hashes) {
				combined := append(hashes[i], hashes[i+1]...)
				hash := sha256.Sum256(combined)
				newLevel = append(newLevel, hash[:])
			} else {
				newLevel = append(newLevel, hashes[i])
			}
		}
		hashes = newLevel
	}

	return hashes[0]
}

// cloneState creates a deep copy of a state
func (sm *StateManager) cloneState(state *State) *State {
	newState := &State{
		Height:         state.Height,
		Hash:           append([]byte{}, state.Hash...),
		PrevHash:       append([]byte{}, state.PrevHash...),
		Timestamp:      state.Timestamp,
		Accounts:       make(map[string]*AccountState),
		Validators:     make(map[string]*ValidatorState),
		Contracts:      make(map[string]*ContractState),
		UTXOSet:        make(map[string]*UTXO),
		TotalSupplyDNT: state.TotalSupplyDNT,
		TotalSupplyAFC: state.TotalSupplyAFC,
		MerkleRoot:     append([]byte{}, state.MerkleRoot...),
		StateRoot:      append([]byte{}, state.StateRoot...),
		ReceiptsRoot:   append([]byte{}, state.ReceiptsRoot...),
		Bloom:          append([]byte{}, state.Bloom...),
		GasUsed:        state.GasUsed,
		BaseFee:        state.BaseFee,
	}

	// Deep copy accounts
	for k, v := range state.Accounts {
		newState.Accounts[k] = &AccountState{
			Address:      v.Address,
			BalanceDNT:   v.BalanceDNT,
			BalanceAFC:   v.BalanceAFC,
			Nonce:        v.Nonce,
			CodeHash:     append([]byte{}, v.CodeHash...),
			StorageRoot:  append([]byte{}, v.StorageRoot...),
			Permissions:  append([]string{}, v.Permissions...),
			LastActivity: v.LastActivity,
			Frozen:       v.Frozen,
		}
		if v.Metadata != nil {
			newState.Accounts[k].Metadata = make(map[string]string)
			for mk, mv := range v.Metadata {
				newState.Accounts[k].Metadata[mk] = mv
			}
		}
	}

	// Deep copy UTXOs
	for k, v := range state.UTXOSet {
		newState.UTXOSet[k] = &UTXO{
			TxHash:      append([]byte{}, v.TxHash...),
			OutputIndex: v.OutputIndex,
			Amount:      v.Amount,
			TokenType:   v.TokenType,
			Address:     v.Address,
			Height:      v.Height,
			Spent:       v.Spent,
			SpentTxHash: append([]byte{}, v.SpentTxHash...),
			SpentHeight: v.SpentHeight,
		}
	}

	return newState
}

// serializeState serializes state to bytes
func (sm *StateManager) serializeState(state *State) ([]byte, error) {
	return json.Marshal(state)
}

// deserializeState deserializes state from bytes
func (sm *StateManager) deserializeState(data []byte) (*State, error) {
	var state State
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, err
	}
	return &state, nil
}

// signCheckpoint signs a checkpoint
func (sm *StateManager) signCheckpoint(checkpoint *Checkpoint) []byte {
	data := fmt.Sprintf("%d:%x:%x:%d",
		checkpoint.Height,
		checkpoint.Hash,
		checkpoint.StateRoot,
		checkpoint.Timestamp)
	hash := sha256.Sum256([]byte(data))
	return hash[:]
}

// verifyCheckpoint verifies a checkpoint
func (sm *StateManager) verifyCheckpoint(checkpoint *Checkpoint, state *State) bool {
	if checkpoint.Height != state.Height {
		return false
	}
	if !bytes.Equal(checkpoint.Hash, state.Hash) {
		return false
	}
	if !bytes.Equal(checkpoint.StateRoot, state.StateRoot) {
		return false
	}
	return true
}

// GetMetrics returns state management metrics
func (sm *StateManager) GetMetrics() StateMetrics {
	sm.stateLock.RLock()
	defer sm.stateLock.RUnlock()

	sm.metrics.StateSize = uint64(len(sm.currentState.Accounts) + len(sm.currentState.UTXOSet))
	return sm.metrics
}

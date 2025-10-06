package core

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sync"

	"github.com/dgraph-io/badger/v3"
)

var (
	// State key prefixes for BadgerDB
	prefixAccount  = []byte("acc:")  // acc:<address> -> AccountState
	prefixNonce    = []byte("nonce:") // nonce:<address> -> uint64
	prefixCode     = []byte("code:")  // code:<address> -> bytecode (for future smart contracts)
	prefixStateRoot = []byte("stateroot:") // stateroot:<height> -> merkle root
	
	// Special keys
	keyLatestState = []byte("state:latest")
	keyStateVersion = []byte("state:version")
	
	// State version for compatibility
	currentStateVersion = uint64(1)
	
	// Errors
	ErrAccountNotFound    = errors.New("account not found")
	ErrInsufficientBalance = errors.New("insufficient balance")
	ErrInvalidNonce       = errors.New("invalid nonce")
	ErrStateCorrupted     = errors.New("state corrupted")
	ErrNegativeBalance    = errors.New("balance cannot be negative")
	ErrCheckpointNotFound = errors.New("checkpoint not found")
)

// TokenType represents the type of token
type TokenType string

const (
	TokenDNT TokenType = "DNT"
	TokenAFC TokenType = "AFC"
)

// AccountState represents an account's state
type AccountState struct {
	Address    string   `json:"address"`
	BalanceDNT *big.Int `json:"balanceDNT"` // DINARI balance
	BalanceAFC *big.Int `json:"balanceAFC"` // Afrocoin balance
	Nonce      uint64   `json:"nonce"`
	CodeHash   []byte   `json:"codeHash,omitempty"` // For smart contracts (future)
	
	// Metadata
	CreatedAt  int64 `json:"createdAt"`
	UpdatedAt  int64 `json:"updatedAt"`
}

// NewAccountState creates a new account state
func NewAccountState(address string) *AccountState {
	return &AccountState{
		Address:    address,
		BalanceDNT: big.NewInt(0),
		BalanceAFC: big.NewInt(0),
		Nonce:      0,
		CreatedAt:  0,
		UpdatedAt:  0,
	}
}

// Copy creates a deep copy of account state
func (a *AccountState) Copy() *AccountState {
	return &AccountState{
		Address:    a.Address,
		BalanceDNT: new(big.Int).Set(a.BalanceDNT),
		BalanceAFC: new(big.Int).Set(a.BalanceAFC),
		Nonce:      a.Nonce,
		CodeHash:   append([]byte(nil), a.CodeHash...),
		CreatedAt:  a.CreatedAt,
		UpdatedAt:  a.UpdatedAt,
	}
}

// StateDB manages the blockchain state with atomic operations
type StateDB struct {
	db *badger.DB
	
	// In-memory cache for performance
	cache map[string]*AccountState
	cacheMu sync.RWMutex
	
	// Dirty accounts (modified but not committed)
	dirty map[string]*AccountState
	dirtyMu sync.RWMutex
	
	// Checkpoint system for rollbacks
	checkpoints []map[string]*AccountState
	checkpointMu sync.Mutex
	
	// Global state lock for atomic operations
	stateMu sync.RWMutex
	
	// Merkle tree for state verification
	merkleTree *StateMerkleTree
}

// NewStateDB creates a new state database
func NewStateDB(db *badger.DB) (*StateDB, error) {
	if db == nil {
		return nil, errors.New("database cannot be nil")
	}
	
	state := &StateDB{
		db:          db,
		cache:       make(map[string]*AccountState),
		dirty:       make(map[string]*AccountState),
		checkpoints: make([]map[string]*AccountState, 0),
		merkleTree:  NewStateMerkleTree(),
	}
	
	// Verify state version compatibility
	if err := state.verifyVersion(); err != nil {
		return nil, fmt.Errorf("state version check failed: %w", err)
	}
	
	// Load initial state into merkle tree
	if err := state.rebuildMerkleTree(); err != nil {
		return nil, fmt.Errorf("failed to rebuild merkle tree: %w", err)
	}
	
	return state, nil
}

// GetAccount retrieves an account's state (thread-safe)
func (s *StateDB) GetAccount(address string) (*AccountState, error) {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	
	// Check dirty accounts first
	s.dirtyMu.RLock()
	if acc, exists := s.dirty[address]; exists {
		s.dirtyMu.RUnlock()
		return acc.Copy(), nil
	}
	s.dirtyMu.RUnlock()
	
	// Check cache
	s.cacheMu.RLock()
	if acc, exists := s.cache[address]; exists {
		s.cacheMu.RUnlock()
		return acc.Copy(), nil
	}
	s.cacheMu.RUnlock()
	
	// Load from database
	acc, err := s.loadAccount(address)
	if err != nil {
		if err == badger.ErrKeyNotFound {
			return nil, ErrAccountNotFound
		}
		return nil, fmt.Errorf("failed to load account: %w", err)
	}
	
	// Add to cache
	s.cacheMu.Lock()
	s.cache[address] = acc.Copy()
	s.cacheMu.Unlock()
	
	return acc.Copy(), nil
}

// GetBalance retrieves an account's balance for a specific token
func (s *StateDB) GetBalance(address string, tokenType TokenType) (*big.Int, error) {
	acc, err := s.GetAccount(address)
	if err != nil {
		if err == ErrAccountNotFound {
			return big.NewInt(0), nil
		}
		return nil, err
	}
	
	switch tokenType {
	case TokenDNT:
		return new(big.Int).Set(acc.BalanceDNT), nil
	case TokenAFC:
		return new(big.Int).Set(acc.BalanceAFC), nil
	default:
		return nil, fmt.Errorf("invalid token type: %s", tokenType)
	}
}

// GetNonce retrieves an account's nonce
func (s *StateDB) GetNonce(address string) (uint64, error) {
	acc, err := s.GetAccount(address)
	if err != nil {
		if err == ErrAccountNotFound {
			return 0, nil
		}
		return 0, err
	}
	return acc.Nonce, nil
}

// AddBalance adds to an account's balance (creates account if doesn't exist)
func (s *StateDB) AddBalance(address string, amount *big.Int, tokenType TokenType) error {
	if amount.Sign() < 0 {
		return ErrNegativeBalance
	}
	
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	
	return s.modifyBalance(address, amount, tokenType, true)
}

// SubBalance subtracts from an account's balance
func (s *StateDB) SubBalance(address string, amount *big.Int, tokenType TokenType) error {
	if amount.Sign() < 0 {
		return ErrNegativeBalance
	}
	
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	
	return s.modifyBalance(address, amount, tokenType, false)
}

// SetNonce sets an account's nonce
func (s *StateDB) SetNonce(address string, nonce uint64) error {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	
	acc, err := s.getOrCreateAccount(address)
	if err != nil {
		return err
	}
	
	acc.Nonce = nonce
	s.markDirty(address, acc)
	
	return nil
}

// Transfer transfers tokens between accounts atomically
func (s *StateDB) Transfer(from, to string, amount *big.Int, tokenType TokenType) error {
	if amount.Sign() <= 0 {
		return errors.New("transfer amount must be positive")
	}
	if from == to {
		return errors.New("cannot transfer to self")
	}
	
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	
	// Check sender balance
	if err := s.modifyBalance(from, amount, tokenType, false); err != nil {
		return fmt.Errorf("failed to deduct from sender: %w", err)
	}
	
	// Add to recipient
	if err := s.modifyBalance(to, amount, tokenType, true); err != nil {
		// This should never fail, but if it does, we need to panic
		// because state is now inconsistent
		panic(fmt.Sprintf("CRITICAL: failed to add to recipient after deducting from sender: %v", err))
	}
	
	return nil
}

// Checkpoint creates a state checkpoint for rollback
func (s *StateDB) Checkpoint() int {
	s.checkpointMu.Lock()
	defer s.checkpointMu.Unlock()
	
	// Create snapshot of dirty state
	snapshot := make(map[string]*AccountState)
	
	s.dirtyMu.RLock()
	for addr, acc := range s.dirty {
		snapshot[addr] = acc.Copy()
	}
	s.dirtyMu.RUnlock()
	
	s.checkpoints = append(s.checkpoints, snapshot)
	return len(s.checkpoints) - 1
}

// RevertToCheckpoint reverts state to a checkpoint
func (s *StateDB) RevertToCheckpoint(checkpointID int) error {
	s.checkpointMu.Lock()
	defer s.checkpointMu.Unlock()
	
	if checkpointID < 0 || checkpointID >= len(s.checkpoints) {
		return ErrCheckpointNotFound
	}
	
	// Restore snapshot
	snapshot := s.checkpoints[checkpointID]
	
	s.dirtyMu.Lock()
	s.dirty = make(map[string]*AccountState)
	for addr, acc := range snapshot {
		s.dirty[addr] = acc.Copy()
	}
	s.dirtyMu.Unlock()
	
	// Remove checkpoints after this one
	s.checkpoints = s.checkpoints[:checkpointID]
	
	return nil
}

// DiscardCheckpoint removes a checkpoint
func (s *StateDB) DiscardCheckpoint(checkpointID int) {
	s.checkpointMu.Lock()
	defer s.checkpointMu.Unlock()
	
	if checkpointID >= 0 && checkpointID < len(s.checkpoints) {
		s.checkpoints = s.checkpoints[:checkpointID]
	}
}

// Commit atomically commits all dirty state to database
func (s *StateDB) Commit() error {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	
	s.dirtyMu.Lock()
	defer s.dirtyMu.Unlock()
	
	if len(s.dirty) == 0 {
		return nil // Nothing to commit
	}
	
	// Use BadgerDB transaction for atomicity
	err := s.db.Update(func(txn *badger.Txn) error {
		for address, acc := range s.dirty {
			// Validate account before committing
			if err := s.validateAccount(acc); err != nil {
				return fmt.Errorf("invalid account state for %s: %w", address, err)
			}
			
			// Serialize account
			data, err := json.Marshal(acc)
			if err != nil {
				return fmt.Errorf("failed to marshal account: %w", err)
			}
			
			// Write to database
			key := append(prefixAccount, []byte(address)...)
			if err := txn.Set(key, data); err != nil {
				return fmt.Errorf("failed to write account: %w", err)
			}
			
			// Update merkle tree
			s.merkleTree.Update(address, acc)
		}
		
		// Save merkle root
		root := s.merkleTree.Root()
		if err := txn.Set(keyLatestState, root); err != nil {
			return fmt.Errorf("failed to save state root: %w", err)
		}
		
		return nil
	})
	
	if err != nil {
		return fmt.Errorf("commit failed: %w", err)
	}
	
	// Update cache and clear dirty
	s.cacheMu.Lock()
	for address, acc := range s.dirty {
		s.cache[address] = acc.Copy()
	}
	s.cacheMu.Unlock()
	
	s.dirty = make(map[string]*AccountState)
	
	// Clear checkpoints after successful commit
	s.checkpointMu.Lock()
	s.checkpoints = make([]map[string]*AccountState, 0)
	s.checkpointMu.Unlock()
	
	return nil
}

// GetStateRoot returns the current merkle root of the state
func (s *StateDB) GetStateRoot() []byte {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	
	return s.merkleTree.Root()
}

// ValidateState performs comprehensive state validation
func (s *StateDB) ValidateState() error {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	
	var totalDNT, totalAFC big.Int
	accountCount := 0
	
	err := s.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = prefixAccount
		it := txn.NewIterator(opts)
		defer it.Close()
		
		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()
			
			err := item.Value(func(val []byte) error {
				var acc AccountState
				if err := json.Unmarshal(val, &acc); err != nil {
					return fmt.Errorf("corrupted account data: %w", err)
				}
				
				// Validate account
				if err := s.validateAccount(&acc); err != nil {
					return err
				}
				
				// Sum totals
				totalDNT.Add(&totalDNT, acc.BalanceDNT)
				totalAFC.Add(&totalAFC, acc.BalanceAFC)
				accountCount++
				
				return nil
			})
			
			if err != nil {
				return err
			}
		}
		
		return nil
	})
	
	if err != nil {
		return fmt.Errorf("state validation failed: %w", err)
	}
	
	fmt.Printf("✅ State validation passed: %d accounts, Total DNT: %s, Total AFC: %s\n",
		accountCount, totalDNT.String(), totalAFC.String())
	
	return nil
}

// Internal helper methods

func (s *StateDB) loadAccount(address string) (*AccountState, error) {
	var acc AccountState
	
	err := s.db.View(func(txn *badger.Txn) error {
		key := append(prefixAccount, []byte(address)...)
		item, err := txn.Get(key)
		if err != nil {
			return err
		}
		
		return item.Value(func(val []byte) error {
			return json.Unmarshal(val, &acc)
		})
	})
	
	if err != nil {
		return nil, err
	}
	
	return &acc, nil
}

func (s *StateDB) getOrCreateAccount(address string) (*AccountState, error) {
	// Check dirty first
	s.dirtyMu.RLock()
	if acc, exists := s.dirty[address]; exists {
		s.dirtyMu.RUnlock()
		return acc, nil
	}
	s.dirtyMu.RUnlock()
	
	// Try to load existing
	acc, err := s.GetAccount(address)
	if err == nil {
		return acc, nil
	}
	
	if err != ErrAccountNotFound {
		return nil, err
	}
	
	// Create new account
	acc = NewAccountState(address)
	s.markDirty(address, acc)
	
	return acc, nil
}

func (s *StateDB) modifyBalance(address string, amount *big.Int, tokenType TokenType, add bool) error {
	acc, err := s.getOrCreateAccount(address)
	if err != nil {
		return err
	}
	
	var balance *big.Int
	switch tokenType {
	case TokenDNT:
		balance = acc.BalanceDNT
	case TokenAFC:
		balance = acc.BalanceAFC
	default:
		return fmt.Errorf("invalid token type: %s", tokenType)
	}
	
	if add {
		balance.Add(balance, amount)
	} else {
		// Check sufficient balance
		if balance.Cmp(amount) < 0 {
			return ErrInsufficientBalance
		}
		balance.Sub(balance, amount)
	}
	
	s.markDirty(address, acc)
	return nil
}

func (s *StateDB) markDirty(address string, acc *AccountState) {
	s.dirtyMu.Lock()
	s.dirty[address] = acc.Copy()
	s.dirtyMu.Unlock()
}

func (s *StateDB) validateAccount(acc *AccountState) error {
	if acc.Address == "" {
		return errors.New("empty address")
	}
	if acc.BalanceDNT == nil || acc.BalanceDNT.Sign() < 0 {
		return ErrNegativeBalance
	}
	if acc.BalanceAFC == nil || acc.BalanceAFC.Sign() < 0 {
		return ErrNegativeBalance
	}
	return nil
}

func (s *StateDB) verifyVersion() error {
	var version uint64
	
	err := s.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(keyStateVersion)
		if err == badger.ErrKeyNotFound {
			// First time, set version
			return nil
		}
		if err != nil {
			return err
		}
		
		return item.Value(func(val []byte) error {
			if len(val) == 8 {
				version = uint64(val[0])<<56 | uint64(val[1])<<48 |
					uint64(val[2])<<40 | uint64(val[3])<<32 |
					uint64(val[4])<<24 | uint64(val[5])<<16 |
					uint64(val[6])<<8 | uint64(val[7])
			}
			return nil
		})
	})
	
	if err != nil {
		return err
	}
	
	if version != 0 && version != currentStateVersion {
		return fmt.Errorf("incompatible state version: got %d, expected %d", version, currentStateVersion)
	}
	
	// Set version if not set
	if version == 0 {
		return s.db.Update(func(txn *badger.Txn) error {
			versionBytes := make([]byte, 8)
			versionBytes[7] = byte(currentStateVersion)
			return txn.Set(keyStateVersion, versionBytes)
		})
	}
	
	return nil
}

func (s *StateDB) rebuildMerkleTree() error {
	return s.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = prefixAccount
		it := txn.NewIterator(opts)
		defer it.Close()
		
		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()
			
			err := item.Value(func(val []byte) error {
				var acc AccountState
				if err := json.Unmarshal(val, &acc); err != nil {
					return err
				}
				s.merkleTree.Update(acc.Address, &acc)
				return nil
			})
			
			if err != nil {
				return err
			}
		}
		
		return nil
	})
}

// StateMerkleTree provides merkle tree for state verification
type StateMerkleTree struct {
	nodes map[string][]byte
	mu    sync.RWMutex
}

func NewStateMerkleTree() *StateMerkleTree {
	return &StateMerkleTree{
		nodes: make(map[string][]byte),
	}
}

func (t *StateMerkleTree) Update(address string, acc *AccountState) {
	t.mu.Lock()
	defer t.mu.Unlock()
	
	// Hash account state
	data, _ := json.Marshal(acc)
	hash := sha256.Sum256(data)
	t.nodes[address] = hash[:]
}

func (t *StateMerkleTree) Root() []byte {
	t.mu.RLock()
	defer t.mu.RUnlock()
	
	if len(t.nodes) == 0 {
		return make([]byte, 32)
	}
	
	// Simple merkle root: hash of all sorted account hashes
	var combined bytes.Buffer
	for _, hash := range t.nodes {
		combined.Write(hash)
	}
	
	root := sha256.Sum256(combined.Bytes())
	return root[:]
}
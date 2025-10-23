package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dgraph-io/badger/v4"
	"go.uber.org/zap"
)

var (
	// State key prefixes for BadgerDB
	prefixAccount   = []byte("acc:")       // acc:<address> -> AccountState
	prefixNonce     = []byte("nonce:")     // nonce:<address> -> uint64
	prefixCode      = []byte("code:")      // code:<address> -> bytecode (for future smart contracts)
	prefixStateRoot = []byte("stateroot:") // stateroot:<height> -> merkle root

	// Special keys
	keyLatestState  = []byte("state:latest")
	keyStateVersion = []byte("state:version")

	// State version for compatibility
	currentStateVersion = uint64(1)

	// Errors
	ErrAccountNotFound     = errors.New("account not found")
	ErrInsufficientBalance = errors.New("insufficient balance")
	ErrInvalidNonce        = errors.New("invalid nonce")
	ErrStateCorrupted      = errors.New("state corrupted")
	ErrNegativeBalance     = errors.New("balance cannot be negative")
	ErrCheckpointNotFound  = errors.New("checkpoint not found")
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
	BalanceDNT *big.Int `json:"balanceDNT"`
	BalanceAFC *big.Int `json:"balanceAFC"`
	Nonce      uint64   `json:"nonce"`
	CodeHash   []byte   `json:"codeHash,omitempty"`
	CreatedAt  int64    `json:"createdAt"`
	UpdatedAt  int64    `json:"updatedAt"`
}

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

type WALEntry struct {
	BlockHeight uint64                  `json:"block_height"`
	BlockHash   string                  `json:"block_hash"`
	Accounts    map[string]AccountState `json:"accounts"`
	Timestamp   int64                   `json:"timestamp"`
}

type Checkpoint struct {
	Height    uint64    `json:"height"`
	Hash      string    `json:"hash"`
	Timestamp time.Time `json:"timestamp"`
}

type StateDB struct {
	db            *badger.DB
	logger        *zap.Logger
	stateMu       sync.RWMutex
	cache         map[string]*AccountState
	dirty         map[string]*AccountState
	checkpoints   []map[string]*AccountState
	merkleTree    *StateMerkleTree
	commitMu      sync.Mutex
	dirtyAccounts map[string]bool
	walPath       string
	walEnabled    bool
}

func NewStateDB(db *badger.DB) (*StateDB, error) {
	if db == nil {
		return nil, errors.New("database cannot be nil")
	}
	logger, _ := zap.NewProduction()
	state := &StateDB{
		db:            db,
		logger:        logger,
		cache:         make(map[string]*AccountState),
		dirty:         make(map[string]*AccountState),
		checkpoints:   make([]map[string]*AccountState, 0),
		merkleTree:    NewStateMerkleTree(),
		dirtyAccounts: make(map[string]bool),
		walEnabled:    true,
		walPath:       "./data/dinari/wal",
	}
	if err := state.verifyVersion(); err != nil {
		return nil, fmt.Errorf("state version check failed: %w", err)
	}
	if err := state.rebuildMerkleTree(); err != nil {
		return nil, fmt.Errorf("failed to rebuild merkle tree: %w", err)
	}
	return state, nil
}

func (s *StateDB) GetAccount(address string) (*AccountState, error) {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	return s.getAccountUnsafe(address)
}

func (s *StateDB) GetBalance(address string, tokenType TokenType) (*big.Int, error) {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	acc, err := s.getAccountUnsafe(address)
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

func (s *StateDB) GetNonce(address string) (uint64, error) {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	acc, err := s.getAccountUnsafe(address)
	if err != nil {
		if err == ErrAccountNotFound {
			return 0, nil
		}
		return 0, err
	}
	return acc.Nonce, nil
}

func (s *StateDB) AddBalance(address string, amount *big.Int, tokenType TokenType) error {
	if amount.Sign() < 0 {
		return ErrNegativeBalance
	}
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	return s.modifyBalanceUnsafe(address, amount, tokenType, true)
}

func (s *StateDB) SubBalance(address string, amount *big.Int, tokenType TokenType) error {
	if amount.Sign() < 0 {
		return ErrNegativeBalance
	}
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	return s.modifyBalanceUnsafe(address, amount, tokenType, false)
}

func (s *StateDB) SetNonce(address string, nonce uint64) error {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	acc, err := s.getOrCreateAccountUnsafe(address)
	if err != nil {
		return err
	}
	acc.Nonce = nonce
	s.markDirtyUnsafe(address, acc)
	return nil
}

func (s *StateDB) Transfer(from, to string, amount *big.Int, tokenType TokenType) error {
	if amount.Sign() <= 0 {
		return errors.New("transfer amount must be positive")
	}
	if from == to {
		return errors.New("cannot transfer to self")
	}
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	if err := s.modifyBalanceUnsafe(from, amount, tokenType, false); err != nil {
		return fmt.Errorf("failed to deduct from sender: %w", err)
	}
	if err := s.modifyBalanceUnsafe(to, amount, tokenType, true); err != nil {
		panic(fmt.Sprintf("CRITICAL: failed to add to recipient after deducting from sender: %v", err))
	}
	return nil
}

func (s *StateDB) Checkpoint() int {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	return s.checkpointUnsafe()
}

func (s *StateDB) RevertToCheckpoint(checkpointID int) error {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	return s.revertToCheckpointUnsafe(checkpointID)
}

func (s *StateDB) DiscardCheckpoint(checkpointID int) {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	s.discardCheckpointUnsafe(checkpointID)
}

func (s *StateDB) Commit() error {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	return s.commitUnsafe()
}

func (s *StateDB) CommitState(blockHeight uint64, blockHash string) error {
	s.commitMu.Lock()
	defer s.commitMu.Unlock()
	s.stateMu.Lock()
	if len(s.dirty) == 0 {
		s.stateMu.Unlock()
		s.logger.Debug("No dirty state to commit")
		return nil
	}
	accountsForWAL := make(map[string]AccountState)
	for addr, acc := range s.dirty {
		accountsForWAL[addr] = *acc
		s.dirtyAccounts[addr] = true
	}
	s.stateMu.Unlock()
	if err := s.writeWAL(blockHeight, blockHash, accountsForWAL); err != nil {
		s.logger.Error("WAL write failed", zap.Error(err))
		return fmt.Errorf("WAL write failed: %w", err)
	}
	s.stateMu.Lock()
	err := s.commitUnsafe()
	s.stateMu.Unlock()
	if err != nil {
		return err
	}
	s.clearWAL()
	s.stateMu.Lock()
	s.dirtyAccounts = make(map[string]bool)
	s.stateMu.Unlock()
	s.logger.Info("State committed successfully", zap.Uint64("height", blockHeight), zap.Int("accounts", len(accountsForWAL)))
	return nil
}

func (s *StateDB) GetStateRoot() []byte {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	return s.merkleTree.Root()
}

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
				if err := s.validateAccountUnsafe(&acc); err != nil {
					return err
				}
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
	fmt.Printf("✅ State validation passed: %d accounts, Total DNT: %s, Total AFC: %s\n", accountCount, totalDNT.String(), totalAFC.String())
	return nil
}

func (s *StateDB) RecoverFromWAL(ctx context.Context, walPath string) error {
	s.walPath = walPath
	walFile := filepath.Join(walPath, "pending.wal")
	if _, err := os.Stat(walFile); os.IsNotExist(err) {
		s.logger.Info("No WAL found - clean startup")
		return nil
	}
	s.logger.Warn("⚠️  WAL file found - recovering from unclean shutdown")
	data, err := os.ReadFile(walFile)
	if err != nil {
		return fmt.Errorf("failed to read WAL: %w", err)
	}
	var entry WALEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		s.logger.Error("WAL corrupted, removing", zap.Error(err))
		return os.Remove(walFile)
	}
	age := time.Now().Unix() - entry.Timestamp
	if age > 600 {
		s.logger.Warn("WAL is stale, discarding", zap.Int64("age_seconds", age))
		return os.Remove(walFile)
	}
	s.stateMu.Lock()
	for addr, acc := range entry.Accounts {
		accCopy := acc.Copy()
		s.dirty[addr] = accCopy
		s.dirtyAccounts[addr] = true
	}
	s.stateMu.Unlock()
	s.logger.Info("✅ WAL recovery successful", zap.Uint64("height", entry.BlockHeight), zap.Int("accounts", len(entry.Accounts)))
	if err := s.CommitState(entry.BlockHeight, entry.BlockHash); err != nil {
		return fmt.Errorf("failed to commit recovered state: %w", err)
	}
	return os.Remove(walFile)
}

func (s *StateDB) writeWAL(blockHeight uint64, blockHash string, accounts map[string]AccountState) error {
	if !s.walEnabled {
		return nil
	}
	if err := os.MkdirAll(s.walPath, 0700); err != nil {
		return fmt.Errorf("failed to create WAL dir: %w", err)
	}
	walFile := filepath.Join(s.walPath, "pending.wal")
	entry := WALEntry{
		BlockHeight: blockHeight,
		BlockHash:   blockHash,
		Accounts:    accounts,
		Timestamp:   time.Now().Unix(),
	}
	data, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		return fmt.Errorf("WAL marshal failed: %w", err)
	}
	tempFile := walFile + ".tmp"
	if err := os.WriteFile(tempFile, data, 0600); err != nil {
		return fmt.Errorf("WAL temp write failed: %w", err)
	}
	if err := os.Rename(tempFile, walFile); err != nil {
		return fmt.Errorf("WAL rename failed: %w", err)
	}
	return nil
}

func (s *StateDB) clearWAL() error {
	if !s.walEnabled {
		return nil
	}
	walFile := filepath.Join(s.walPath, "pending.wal")
	if err := os.Remove(walFile); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func (s *StateDB) GetLatestCheckpoint() (*Checkpoint, error) {
	key := []byte("checkpoint:latest")
	var checkpoint *Checkpoint
	err := s.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(key)
		if err == badger.ErrKeyNotFound {
			return nil
		}
		if err != nil {
			return err
		}
		return item.Value(func(val []byte) error {
			parts := strings.Split(string(val), ":")
			if len(parts) != 3 {
				return fmt.Errorf("invalid checkpoint format")
			}
			height, err := strconv.ParseUint(parts[0], 10, 64)
			if err != nil {
				return err
			}
			timestamp, err := strconv.ParseInt(parts[2], 10, 64)
			if err != nil {
				return err
			}
			checkpoint = &Checkpoint{
				Height:    height,
				Hash:      parts[1],
				Timestamp: time.Unix(timestamp, 0),
			}
			return nil
		})
	})
	return checkpoint, err
}

func (s *StateDB) GetBlockByHeight(height uint64) (*Block, error) {
	return nil, fmt.Errorf("not implemented - query blockchain instead")
}

func (s *StateDB) GetSampleAccounts(n int) ([]string, error) {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	accounts := make([]string, 0, n)
	count := 0
	for addr := range s.cache {
		accounts = append(accounts, addr)
		count++
		if count >= n {
			break
		}
	}
	return accounts, nil
}

func (s *StateDB) getAccountUnsafe(address string) (*AccountState, error) {
	if acc, exists := s.dirty[address]; exists {
		return acc.Copy(), nil
	}
	if acc, exists := s.cache[address]; exists {
		return acc.Copy(), nil
	}
	acc, err := s.loadAccountFromDB(address)
	if err != nil {
		if err == badger.ErrKeyNotFound {
			return nil, ErrAccountNotFound
		}
		return nil, fmt.Errorf("failed to load account: %w", err)
	}
	s.cache[address] = acc.Copy()
	return acc.Copy(), nil
}

func (s *StateDB) getOrCreateAccountUnsafe(address string) (*AccountState, error) {
	if acc, exists := s.dirty[address]; exists {
		return acc, nil
	}
	acc, err := s.getAccountUnsafe(address)
	if err == nil {
		return acc, nil
	}
	if err != ErrAccountNotFound {
		return nil, err
	}
	acc = NewAccountState(address)
	s.markDirtyUnsafe(address, acc)
	return acc, nil
}

func (s *StateDB) modifyBalanceUnsafe(address string, amount *big.Int, tokenType TokenType, add bool) error {
	acc, err := s.getOrCreateAccountUnsafe(address)
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
		if balance.Cmp(amount) < 0 {
			return ErrInsufficientBalance
		}
		balance.Sub(balance, amount)
	}
	s.markDirtyUnsafe(address, acc)
	return nil
}

func (s *StateDB) markDirtyUnsafe(address string, acc *AccountState) {
	s.dirty[address] = acc.Copy()
}

func (s *StateDB) checkpointUnsafe() int {
	snapshot := make(map[string]*AccountState)
	for addr, acc := range s.dirty {
		snapshot[addr] = acc.Copy()
	}
	s.checkpoints = append(s.checkpoints, snapshot)
	return len(s.checkpoints) - 1
}

func (s *StateDB) revertToCheckpointUnsafe(checkpointID int) error {
	if checkpointID < 0 || checkpointID >= len(s.checkpoints) {
		return ErrCheckpointNotFound
	}
	snapshot := s.checkpoints[checkpointID]
	s.dirty = make(map[string]*AccountState)
	for addr, acc := range snapshot {
		s.dirty[addr] = acc.Copy()
	}
	s.checkpoints = s.checkpoints[:checkpointID]
	return nil
}

func (s *StateDB) discardCheckpointUnsafe(checkpointID int) {
	if checkpointID >= 0 && checkpointID < len(s.checkpoints) {
		s.checkpoints = s.checkpoints[:checkpointID]
	}
}

func (s *StateDB) commitUnsafe() error {
	if len(s.dirty) == 0 {
		return nil
	}
	err := s.db.Update(func(txn *badger.Txn) error {
		for address, acc := range s.dirty {
			if err := s.validateAccountUnsafe(acc); err != nil {
				return fmt.Errorf("invalid account state for %s: %w", address, err)
			}
			data, err := json.Marshal(acc)
			if err != nil {
				return fmt.Errorf("failed to marshal account: %w", err)
			}
			key := append(prefixAccount, []byte(address)...)
			if err := txn.Set(key, data); err != nil {
				return fmt.Errorf("failed to write account: %w", err)
			}
			s.merkleTree.Update(address, acc)
		}
		root := s.merkleTree.Root()
		if root == nil || len(root) == 0 {
			root = make([]byte, 32)
		}
		if err := txn.Set(keyLatestState, root); err != nil {
			return fmt.Errorf("failed to save state root: %w", err)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("commit failed: %w", err)
	}
	// Add safety check before clearing
	if len(s.dirty) > 0 {
		for address, acc := range s.dirty {
			if acc != nil {
				s.cache[address] = acc.Copy()
			}
		}
	}
	s.dirty = make(map[string]*AccountState)
	s.checkpoints = make([]map[string]*AccountState, 0) // This is fine, but ensure dirty is cleared first
	return nil
}

func (s *StateDB) validateAccountUnsafe(acc *AccountState) error {
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

func (s *StateDB) loadAccountFromDB(address string) (*AccountState, error) {
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

func (s *StateDB) verifyVersion() error {
	var version uint64
	err := s.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(keyStateVersion)
		if err == badger.ErrKeyNotFound {
			return nil
		}
		if err != nil {
			return err
		}
		return item.Value(func(val []byte) error {
			if len(val) == 8 {
				version = uint64(val[0])<<56 | uint64(val[1])<<48 | uint64(val[2])<<40 | uint64(val[3])<<32 | uint64(val[4])<<24 | uint64(val[5])<<16 | uint64(val[6])<<8 | uint64(val[7])
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
	var combined bytes.Buffer
	for _, hash := range t.nodes {
		combined.Write(hash)
	}
	root := sha256.Sum256(combined.Bytes())
	return root[:]
}

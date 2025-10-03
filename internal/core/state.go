package core

import (
	"fmt"
	"math/big"
	"sync"

	"github.com/EmekaIwuagwu/dinari-blockchain/internal/storage"
	"github.com/EmekaIwuagwu/dinari-blockchain/internal/types"
	"go.uber.org/zap"
)

// State manages the blockchain state (account balances, nonces)
type State struct {
	db     *storage.DB
	logger *zap.Logger

	// In-memory cache for performance
	cache map[string]*types.Account
	mu    sync.RWMutex

	// Track state changes for atomic commits
	dirty map[string]*types.Account
}

// NewState creates a new state manager
func NewState(db *storage.DB, logger *zap.Logger) *State {
	return &State{
		db:     db,
		logger: logger,
		cache:  make(map[string]*types.Account),
		dirty:  make(map[string]*types.Account),
	}
}

// GetAccount retrieves an account by address
func (s *State) GetAccount(address string) (*types.Account, error) {
	s.mu.RLock()

	// Check dirty state first (uncommitted changes)
	if account, exists := s.dirty[address]; exists {
		s.mu.RUnlock()
		return account.Copy(), nil
	}

	// Check cache
	if account, exists := s.cache[address]; exists {
		s.mu.RUnlock()
		return account.Copy(), nil
	}

	s.mu.RUnlock()

	// Load from database
	key := storage.AccountKey(address)
	data, err := s.db.Get(key)
	if err != nil {
		// Account doesn't exist, return new account with zero balances
		return types.NewAccount(address), nil
	}

	account, err := types.DeserializeAccount(data)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize account: %w", err)
	}

	// Cache it
	s.mu.Lock()
	s.cache[address] = account.Copy()
	s.mu.Unlock()

	return account, nil
}

// SetAccount updates an account (staged, not committed)
func (s *State) SetAccount(account *types.Account) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Stage the change
	s.dirty[account.Address] = account.Copy()
	return nil
}

// Transfer transfers tokens between accounts
func (s *State) Transfer(from, to string, amount *big.Int, tokenType string) error {
	// Get sender account
	sender, err := s.GetAccount(from)
	if err != nil {
		return err
	}

	// Check sufficient balance
	if !sender.HasSufficientBalance(tokenType, amount) {
		return types.ErrInsufficientBalance
	}

	// Get recipient account
	recipient, err := s.GetAccount(to)
	if err != nil {
		return err
	}

	// Subtract from sender
	if err := sender.SubBalance(tokenType, amount); err != nil {
		return err
	}

	// Add to recipient
	recipient.AddBalance(tokenType, amount)

	// Update both accounts
	if err := s.SetAccount(sender); err != nil {
		return err
	}
	if err := s.SetAccount(recipient); err != nil {
		return err
	}

	return nil
}

// AddBalance adds balance to an account
func (s *State) AddBalance(address string, amount *big.Int, tokenType string) error {
	account, err := s.GetAccount(address)
	if err != nil {
		return err
	}

	account.AddBalance(tokenType, amount)
	return s.SetAccount(account)
}

// SubBalance subtracts balance from an account
func (s *State) SubBalance(address string, amount *big.Int, tokenType string) error {
	account, err := s.GetAccount(address)
	if err != nil {
		return err
	}

	if err := account.SubBalance(tokenType, amount); err != nil {
		return err
	}

	return s.SetAccount(account)
}

// GetBalance returns the balance for an account
func (s *State) GetBalance(address string, tokenType string) (*big.Int, error) {
	account, err := s.GetAccount(address)
	if err != nil {
		return nil, err
	}

	return account.GetBalance(tokenType), nil
}

// GetNonce returns the nonce for an account
func (s *State) GetNonce(address string) (uint64, error) {
	account, err := s.GetAccount(address)
	if err != nil {
		return 0, err
	}

	return account.Nonce, nil
}

// IncrementNonce increments the nonce for an account
func (s *State) IncrementNonce(address string) error {
	account, err := s.GetAccount(address)
	if err != nil {
		return err
	}

	account.IncrementNonce()
	return s.SetAccount(account)
}

// Commit writes all pending state changes to the database
func (s *State) Commit() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.dirty) == 0 {
		return nil // Nothing to commit
	}

	batch := s.db.NewBatch()
	defer batch.Cancel()

	// Write all dirty accounts
	for address, account := range s.dirty {
		data, err := account.Serialize()
		if err != nil {
			return fmt.Errorf("failed to serialize account %s: %w", address, err)
		}

		key := storage.AccountKey(address)
		if err := batch.Set(key, data); err != nil {
			return err
		}

		// Update cache
		s.cache[address] = account.Copy()
	}

	// Flush batch
	if err := batch.Flush(); err != nil {
		return fmt.Errorf("failed to commit state: %w", err)
	}

	// Clear dirty map
	s.dirty = make(map[string]*types.Account)

	return nil
}

// Revert discards all pending state changes
func (s *State) Revert() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.dirty = make(map[string]*types.Account)
}

// Copy creates a snapshot of the current state
func (s *State) Copy() *State {
	s.mu.RLock()
	defer s.mu.RUnlock()

	newState := &State{
		db:     s.db,
		logger: s.logger,
		cache:  make(map[string]*types.Account),
		dirty:  make(map[string]*types.Account),
	}

	// Copy cache
	for addr, account := range s.cache {
		newState.cache[addr] = account.Copy()
	}

	// Copy dirty state
	for addr, account := range s.dirty {
		newState.dirty[addr] = account.Copy()
	}

	return newState
}

// ApplyTransaction applies a transaction to the state (staged, not committed)
func (s *State) ApplyTransaction(tx *types.Transaction) error {
	// Handle coinbase transaction
	if tx.IsCoinbase() {
		return s.AddBalance(tx.To, tx.Amount, string(types.TokenDNT))
	}

	// Handle mint transaction
	if tx.IsMint() {
		return s.AddBalance(tx.To, tx.Amount, string(types.TokenAFC))
	}

	// Verify nonce
	currentNonce, err := s.GetNonce(tx.From)
	if err != nil {
		return err
	}
	if tx.Nonce != currentNonce {
		return types.ErrInvalidNonce
	}

	// Transfer tokens
	if err := s.Transfer(tx.From, tx.To, tx.Amount, tx.TokenType); err != nil {
		return err
	}

	// Deduct fee (always in DNT)
	if err := s.SubBalance(tx.From, tx.FeeDNT, string(types.TokenDNT)); err != nil {
		return err
	}

	// Increment nonce
	if err := s.IncrementNonce(tx.From); err != nil {
		return err
	}

	return nil
}

// Clear clears the cache (useful for testing)
func (s *State) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.cache = make(map[string]*types.Account)
	s.dirty = make(map[string]*types.Account)
}

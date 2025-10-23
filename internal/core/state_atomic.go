package core

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

// StateSnapshot represents a point-in-time state snapshot
type StateSnapshot struct {
	Height    uint64
	StateRoot []byte
	Timestamp time.Time
	Data      map[string][]byte
}

// StateTransition represents a pending state change
type StateTransition struct {
	ID         string
	Operations []StateOperation
	Snapshot   *StateSnapshot
	Committed  bool
	RolledBack bool
	CreatedAt  time.Time
	mu         sync.Mutex
}

// StateOperation represents a single state change
type StateOperation struct {
	Type     OperationType
	Key      string
	OldValue []byte
	NewValue []byte
}

type OperationType int

const (
	OpSet OperationType = iota
	OpDelete
	OpUpdateBalance
	OpUpdateNonce
)

// AtomicState provides atomic, rollback-capable state management
type AtomicState struct {
	currentState map[string][]byte
	pendingTxns  map[string]*StateTransition
	snapshots    []*StateSnapshot
	maxSnapshots int
	mu           sync.RWMutex
	db           Database
	auditLog     []AuditEntry
}

// Database interface for persistence
type Database interface {
	Get(key string) ([]byte, error)
	Set(key string, value []byte) error
	Delete(key string) error
	BatchWrite(ops []BatchOp) error
	Close() error
}

// BatchOp represents a batch operation
type BatchOp struct {
	Type  string // "set" or "delete"
	Key   string
	Value []byte
}

// AuditEntry represents a state change audit entry
type AuditEntry struct {
	Timestamp   time.Time
	Operation   string
	Key         string
	OldValue    []byte
	NewValue    []byte
	BlockHeight uint64
	TxHash      string
	Success     bool
	Error       string
}

// NewAtomicState creates a new atomic state manager
func NewAtomicState(db Database, maxSnapshots int) *AtomicState {
	return &AtomicState{
		currentState: make(map[string][]byte),
		pendingTxns:  make(map[string]*StateTransition),
		snapshots:    make([]*StateSnapshot, 0, maxSnapshots),
		maxSnapshots: maxSnapshots,
		db:           db,
		auditLog:     make([]AuditEntry, 0),
	}
}

// BeginTransaction starts a new atomic transaction
func (s *AtomicState) BeginTransaction(id string, height uint64) (*StateTransition, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.pendingTxns[id]; exists {
		return nil, fmt.Errorf("transaction %s already exists", id)
	}

	// Create snapshot of current state
	snapshot := s.createSnapshot(height)

	txn := &StateTransition{
		ID:         id,
		Operations: make([]StateOperation, 0),
		Snapshot:   snapshot,
		CreatedAt:  time.Now(),
	}

	s.pendingTxns[id] = txn
	return txn, nil
}

// createSnapshot creates a snapshot of current state
func (s *AtomicState) createSnapshot(height uint64) *StateSnapshot {
	snapshot := &StateSnapshot{
		Height:    height,
		Timestamp: time.Now(),
		Data:      make(map[string][]byte),
	}

	// Deep copy current state
	for k, v := range s.currentState {
		valueCopy := make([]byte, len(v))
		copy(valueCopy, v)
		snapshot.Data[k] = valueCopy
	}

	// Calculate state root (Merkle root)
	snapshot.StateRoot = s.calculateStateRoot(snapshot.Data)

	return snapshot
}

// calculateStateRoot computes Merkle root of state
func (s *AtomicState) calculateStateRoot(data map[string][]byte) []byte {
	// Implementation of Merkle tree state root
	// For production, use proper Merkle tree implementation
	h := sha256.New()
	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		h.Write([]byte(k))
		h.Write(data[k])
	}

	return h.Sum(nil)
}

// Set adds a set operation to the transaction
func (txn *StateTransition) Set(s *AtomicState, key string, value []byte) error {
	txn.mu.Lock()
	defer txn.mu.Unlock()

	if txn.Committed || txn.RolledBack {
		return errors.New("transaction already finalized")
	}

	s.mu.RLock()
	oldValue, _ := s.currentState[key]
	s.mu.RUnlock()

	op := StateOperation{
		Type:     OpSet,
		Key:      key,
		OldValue: oldValue,
		NewValue: value,
	}

	txn.Operations = append(txn.Operations, op)
	return nil
}

// Delete adds a delete operation to the transaction
func (txn *StateTransition) Delete(s *AtomicState, key string) error {
	txn.mu.Lock()
	defer txn.mu.Unlock()

	if txn.Committed || txn.RolledBack {
		return errors.New("transaction already finalized")
	}

	s.mu.RLock()
	oldValue, _ := s.currentState[key]
	s.mu.RUnlock()

	op := StateOperation{
		Type:     OpDelete,
		Key:      key,
		OldValue: oldValue,
		NewValue: nil,
	}

	txn.Operations = append(txn.Operations, op)
	return nil
}

// Commit applies all operations atomically
func (s *AtomicState) Commit(txnID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	txn, exists := s.pendingTxns[txnID]
	if !exists {
		return fmt.Errorf("transaction %s not found", txnID)
	}

	txn.mu.Lock()
	defer txn.mu.Unlock()

	if txn.Committed {
		return errors.New("transaction already committed")
	}
	if txn.RolledBack {
		return errors.New("transaction was rolled back")
	}

	// Prepare batch operations for database
	batchOps := make([]BatchOp, 0, len(txn.Operations))

	// Apply operations to in-memory state and prepare DB batch
	for _, op := range txn.Operations {
		switch op.Type {
		case OpSet:
			s.currentState[op.Key] = op.NewValue
			batchOps = append(batchOps, BatchOp{
				Type:  "set",
				Key:   op.Key,
				Value: op.NewValue,
			})

			// Audit log
			s.auditLog = append(s.auditLog, AuditEntry{
				Timestamp: time.Now(),
				Operation: "SET",
				Key:       op.Key,
				OldValue:  op.OldValue,
				NewValue:  op.NewValue,
				Success:   true,
			})

		case OpDelete:
			delete(s.currentState, op.Key)
			batchOps = append(batchOps, BatchOp{
				Type: "delete",
				Key:  op.Key,
			})

			// Audit log
			s.auditLog = append(s.auditLog, AuditEntry{
				Timestamp: time.Now(),
				Operation: "DELETE",
				Key:       op.Key,
				OldValue:  op.OldValue,
				Success:   true,
			})
		}
	}

	// Write to database atomically
	if err := s.db.BatchWrite(batchOps); err != nil {
		// Rollback in-memory changes
		s.rollbackMemoryState(txn)
		return fmt.Errorf("database commit failed: %w", err)
	}

	txn.Committed = true
	delete(s.pendingTxns, txnID)

	// Add snapshot to history
	s.addSnapshot(txn.Snapshot)

	return nil
}

// Rollback reverts all operations
func (s *AtomicState) Rollback(txnID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	txn, exists := s.pendingTxns[txnID]
	if !exists {
		return fmt.Errorf("transaction %s not found", txnID)
	}

	txn.mu.Lock()
	defer txn.mu.Unlock()

	if txn.Committed {
		return errors.New("cannot rollback committed transaction")
	}
	if txn.RolledBack {
		return errors.New("transaction already rolled back")
	}

	// Restore snapshot
	s.rollbackMemoryState(txn)

	txn.RolledBack = true
	delete(s.pendingTxns, txnID)

	// Audit log
	s.auditLog = append(s.auditLog, AuditEntry{
		Timestamp: time.Now(),
		Operation: "ROLLBACK",
		Success:   true,
	})

	return nil
}

// rollbackMemoryState restores state from snapshot
func (s *AtomicState) rollbackMemoryState(txn *StateTransition) {
	// Clear current state
	s.currentState = make(map[string][]byte)

	// Restore from snapshot
	for k, v := range txn.Snapshot.Data {
		valueCopy := make([]byte, len(v))
		copy(valueCopy, v)
		s.currentState[k] = valueCopy
	}
}

// addSnapshot adds a snapshot to history with rotation
func (s *AtomicState) addSnapshot(snapshot *StateSnapshot) {
	s.snapshots = append(s.snapshots, snapshot)

	// Rotate old snapshots
	if len(s.snapshots) > s.maxSnapshots {
		s.snapshots = s.snapshots[1:]
	}
}

// RollbackToHeight rolls back state to a specific block height
func (s *AtomicState) RollbackToHeight(height uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Find snapshot at or before the target height
	var targetSnapshot *StateSnapshot
	for i := len(s.snapshots) - 1; i >= 0; i-- {
		if s.snapshots[i].Height <= height {
			targetSnapshot = s.snapshots[i]
			break
		}
	}

	if targetSnapshot == nil {
		return fmt.Errorf("no snapshot found for height %d", height)
	}

	// Restore state from snapshot
	s.currentState = make(map[string][]byte)
	for k, v := range targetSnapshot.Data {
		valueCopy := make([]byte, len(v))
		copy(valueCopy, v)
		s.currentState[k] = valueCopy
	}

	// Remove snapshots after target height
	newSnapshots := make([]*StateSnapshot, 0)
	for _, snap := range s.snapshots {
		if snap.Height <= height {
			newSnapshots = append(newSnapshots, snap)
		}
	}
	s.snapshots = newSnapshots

	return nil
}

// GetAuditLog returns the audit log for compliance
func (s *AtomicState) GetAuditLog() []AuditEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()

	logCopy := make([]AuditEntry, len(s.auditLog))
	copy(logCopy, s.auditLog)
	return logCopy
}

// ExportAuditLog exports audit log in JSON format
func (s *AtomicState) ExportAuditLog() ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return json.Marshal(s.auditLog)
}

package core

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"go.uber.org/zap"
)

type WALEntry struct {
	BlockHeight uint64            `json:"block_height"`
	BlockHash   string            `json:"block_hash"`
	StateRoot   string            `json:"state_root"`
	Accounts    map[string]Balance `json:"accounts"`
	Timestamp   int64             `json:"timestamp"`
}

// writeWAL writes uncommitted state to disk for crash recovery
func (s *StateDB) writeWAL(blockHeight uint64, blockHash string) error {
	walPath := filepath.Join(s.walPath, "pending.wal")
	
	// Gather all dirty accounts
	s.cacheMu.RLock()
	accounts := make(map[string]Balance)
	for addr := range s.dirtyAccounts {
		if bal, exists := s.balanceCache[addr]; exists {
			accounts[addr] = *bal
		}
	}
	s.cacheMu.RUnlock()
	
	entry := WALEntry{
		BlockHeight: blockHeight,
		BlockHash:   blockHash,
		Accounts:    accounts,
		Timestamp:   time.Now().Unix(),
	}
	
	// Marshal to JSON
	data, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		return fmt.Errorf("WAL marshal failed: %w", err)
	}
	
	// Atomic write with temp file + rename
	tempPath := walPath + ".tmp"
	if err := ioutil.WriteFile(tempPath, data, 0600); err != nil {
		return fmt.Errorf("WAL temp write failed: %w", err)
	}
	
	if err := os.Rename(tempPath, walPath); err != nil {
		return fmt.Errorf("WAL rename failed: %w", err)
	}
	
	if err := syncDir(filepath.Dir(walPath)); err != nil {
		return fmt.Errorf("WAL fsync failed: %w", err)
	}
	
	s.logger.Debug("WAL written", zap.Uint64("height", blockHeight))
	return nil
}

// recoverFromWAL replays pending state after crash
func (s *StateDB) recoverFromWAL() error {
	walPath := filepath.Join(s.walPath, "pending.wal")
	
	// Check if WAL exists
	if _, err := os.Stat(walPath); os.IsNotExist(err) {
		s.logger.Info("No WAL found, clean startup")
		return nil
	}
	
	s.logger.Warn("WAL found - recovering from crash")
	
	// Read WAL
	data, err := ioutil.ReadFile(walPath)
	if err != nil {
		return fmt.Errorf("WAL read failed: %w", err)
	}
	
	var entry WALEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return fmt.Errorf("WAL unmarshal failed: %w", err)
	}
	
	// Validate WAL is not too old (>10 minutes = likely stale)
	age := time.Now().Unix() - entry.Timestamp
	if age > 600 {
		s.logger.Warn("WAL is stale, discarding",
			zap.Int64("age_seconds", age))
		return os.Remove(walPath)
	}
	
	// Replay state changes
	s.cacheMu.Lock()
	for addr, bal := range entry.Accounts {
		s.balanceCache[addr] = &Balance{
			DNT:   bal.DNT,
			AFC:   bal.AFC,
			Nonce: bal.Nonce,
		}
		s.dirtyAccounts[addr] = true
	}
	s.cacheMu.Unlock()
	
	s.logger.Info("WAL recovery completed",
		zap.Uint64("height", entry.BlockHeight),
		zap.Int("accounts", len(entry.Accounts)))
	
	// Re-attempt commit
	return s.CommitState(entry.BlockHeight, entry.BlockHash)
}

// clearWAL removes WAL after successful commit
func (s *StateDB) clearWAL() error {
	walPath := filepath.Join(s.walPath, "pending.wal")
	return os.Remove(walPath)
}

// syncDir forces directory metadata to disk
func syncDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
// internal/consensus/checkpoints.go
package consensus

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"go.uber.org/zap"
)

// Checkpoint represents a hardcoded blockchain checkpoint
type Checkpoint struct {
	Height    uint64 `json:"height"`
	Hash      string `json:"hash"` // Hex string for JSON compatibility
	Timestamp int64  `json:"timestamp"`
}

// CheckpointManager manages blockchain checkpoints for security
type CheckpointManager struct {
	checkpoints      map[uint64]*Checkpoint
	latestCheckpoint *Checkpoint
	mu               sync.RWMutex
	logger           *zap.Logger
	checkpointFile   string
}

// NewCheckpointManager creates a new checkpoint manager
func NewCheckpointManager(logger *zap.Logger, checkpointFile string) *CheckpointManager {
	cm := &CheckpointManager{
		checkpoints:    make(map[uint64]*Checkpoint),
		logger:         logger,
		checkpointFile: checkpointFile,
	}

	// Load checkpoints from file
	if err := cm.loadCheckpoints(); err != nil {
		logger.Warn("Failed to load checkpoints, using hardcoded defaults",
			zap.Error(err))
		cm.initializeDefaultCheckpoints()
	}

	return cm
}

// initializeDefaultCheckpoints sets up hardcoded checkpoints for mainnet
func (cm *CheckpointManager) initializeDefaultCheckpoints() {
	// Genesis checkpoint (height 0)
	genesisCheckpoint := &Checkpoint{
		Height:    0,
		Hash:      "0000000000000000000000000000000000000000000000000000000000000000",
		Timestamp: 1704067200, // 2024-01-01
	}

	cm.checkpoints[0] = genesisCheckpoint
	cm.latestCheckpoint = genesisCheckpoint

	// Add more checkpoints every 10,000 blocks (updated by governance)
	// These would be updated in production based on actual mainnet blocks
	cm.logger.Info("Initialized default checkpoints",
		zap.Int("count", len(cm.checkpoints)))
}

// loadCheckpoints loads checkpoints from file
func (cm *CheckpointManager) loadCheckpoints() error {
	data, err := os.ReadFile(cm.checkpointFile)
	if err != nil {
		return fmt.Errorf("failed to read checkpoint file: %w", err)
	}

	var checkpoints []*Checkpoint
	if err := json.Unmarshal(data, &checkpoints); err != nil {
		return fmt.Errorf("failed to unmarshal checkpoints: %w", err)
	}

	for _, cp := range checkpoints {
		cm.checkpoints[cp.Height] = cp
		if cm.latestCheckpoint == nil || cp.Height > cm.latestCheckpoint.Height {
			cm.latestCheckpoint = cp
		}
	}

	cm.logger.Info("Loaded checkpoints from file",
		zap.Int("count", len(cm.checkpoints)),
		zap.Uint64("latestHeight", cm.latestCheckpoint.Height))

	return nil
}

// SaveCheckpoints saves checkpoints to file
func (cm *CheckpointManager) SaveCheckpoints() error {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	var checkpoints []*Checkpoint
	for _, cp := range cm.checkpoints {
		checkpoints = append(checkpoints, cp)
	}

	data, err := json.MarshalIndent(checkpoints, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal checkpoints: %w", err)
	}

	if err := os.WriteFile(cm.checkpointFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write checkpoint file: %w", err)
	}

	return nil
}

// IsCheckpoint returns true if the given height is a checkpoint
func (cm *CheckpointManager) IsCheckpoint(height uint64) bool {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	_, exists := cm.checkpoints[height]
	return exists
}

// ValidateCheckpoint validates a block hash against a checkpoint
func (cm *CheckpointManager) ValidateCheckpoint(height uint64, hash [32]byte) error {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	checkpoint, exists := cm.checkpoints[height]
	if !exists {
		// Not a checkpoint, nothing to validate
		return nil
	}

	// Convert hash to hex string
	hashHex := hex.EncodeToString(hash[:])

	if checkpoint.Hash != hashHex {
		return fmt.Errorf("checkpoint validation failed at height %d: expected %s, got %s",
			height, checkpoint.Hash, hashHex)
	}

	cm.logger.Info("Checkpoint validated",
		zap.Uint64("height", height),
		zap.String("hash", hashHex))

	return nil
}

// AddCheckpoint adds a new checkpoint (requires authority)
func (cm *CheckpointManager) AddCheckpoint(height uint64, hash [32]byte, timestamp int64) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	hashHex := hex.EncodeToString(hash[:])

	checkpoint := &Checkpoint{
		Height:    height,
		Hash:      hashHex,
		Timestamp: timestamp,
	}

	cm.checkpoints[height] = checkpoint

	if cm.latestCheckpoint == nil || height > cm.latestCheckpoint.Height {
		cm.latestCheckpoint = checkpoint
	}

	// Save to file
	go func() {
		if err := cm.SaveCheckpoints(); err != nil {
			cm.logger.Error("Failed to save checkpoints", zap.Error(err))
		}
	}()

	cm.logger.Info("Checkpoint added",
		zap.Uint64("height", height),
		zap.String("hash", hashHex))

	return nil
}

// GetLatestCheckpoint returns the latest checkpoint
func (cm *CheckpointManager) GetLatestCheckpoint() *Checkpoint {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	if cm.latestCheckpoint == nil {
		return nil
	}

	return &Checkpoint{
		Height:    cm.latestCheckpoint.Height,
		Hash:      cm.latestCheckpoint.Hash,
		Timestamp: cm.latestCheckpoint.Timestamp,
	}
}

// GetCheckpointAtHeight returns checkpoint at specific height
func (cm *CheckpointManager) GetCheckpointAtHeight(height uint64) *Checkpoint {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	cp, exists := cm.checkpoints[height]
	if !exists {
		return nil
	}

	return &Checkpoint{
		Height:    cp.Height,
		Hash:      cp.Hash,
		Timestamp: cp.Timestamp,
	}
}

// GetAllCheckpoints returns all checkpoints
func (cm *CheckpointManager) GetAllCheckpoints() []*Checkpoint {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	checkpoints := make([]*Checkpoint, 0, len(cm.checkpoints))
	for _, cp := range cm.checkpoints {
		checkpoints = append(checkpoints, &Checkpoint{
			Height:    cp.Height,
			Hash:      cp.Hash,
			Timestamp: cp.Timestamp,
		})
	}

	return checkpoints
}

// IsBeyondLatestCheckpoint checks if height is beyond latest checkpoint
func (cm *CheckpointManager) IsBeyondLatestCheckpoint(height uint64) bool {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	if cm.latestCheckpoint == nil {
		return true
	}

	return height > cm.latestCheckpoint.Height
}

// AutoCheckpoint automatically creates checkpoints at intervals
func (cm *CheckpointManager) AutoCheckpoint(currentHeight uint64, currentHash [32]byte, interval uint64) {
	if interval == 0 {
		return
	}

	// Only create checkpoint at specified intervals
	if currentHeight%interval != 0 {
		return
	}

	// Don't create checkpoint if one already exists at this height
	if cm.IsCheckpoint(currentHeight) {
		return
	}

	// Create checkpoint
	timestamp := time.Now().Unix()
	if err := cm.AddCheckpoint(currentHeight, currentHash, timestamp); err != nil {
		cm.logger.Error("Failed to auto-create checkpoint",
			zap.Uint64("height", currentHeight),
			zap.Error(err))
	} else {
		cm.logger.Info("Auto-created checkpoint",
			zap.Uint64("height", currentHeight))
	}
}
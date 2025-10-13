package consensus

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"math/big"
	
	"github.com/EmekaIwuagwu/dinari-blockchain/internal/miner"
)

// ConsensusAdapter adapts consensus.ProofOfWork to miner.ConsensusInterface
type ConsensusAdapter struct {
	consensus  *ProofOfWork
	// Store references needed for difficulty calculation
	getBlockByHeight func(height uint64) (BlockData, error)
	getCurrentHeight func() uint64
}

// BlockData contains the data we need from a block
type BlockData struct {
	Height     uint64
	Timestamp  int64
	Difficulty uint32
}

// NewConsensusAdapter creates a new consensus adapter
// Pass in functions from blockchain to avoid circular dependencies
func NewConsensusAdapter(
	pow *ProofOfWork,
	getBlockByHeight func(height uint64) (BlockData, error),
	getCurrentHeight func() uint64,
) *ConsensusAdapter {
	return &ConsensusAdapter{
		consensus:        pow,
		getBlockByHeight: getBlockByHeight,
		getCurrentHeight: getCurrentHeight,
	}
}

// CalculateHash computes the hash of a block header
func (a *ConsensusAdapter) CalculateHash(header *miner.BlockHeader) []byte {
	var buf bytes.Buffer
	
	// Serialize header fields in the same order as blockchain does
	buf.Write(encodeUint32(header.Version))
	buf.Write(encodeUint64(header.Height))
	buf.Write(header.PrevBlockHash)
	buf.Write(header.MerkleRoot)
	buf.Write(encodeInt64(header.Timestamp))
	buf.Write(encodeUint32(header.Difficulty))
	buf.Write(encodeUint64(header.Nonce))
	
	// Double SHA-256 (Bitcoin-style)
	first := sha256.Sum256(buf.Bytes())
	second := sha256.Sum256(first[:])
	
	return second[:]
}

// ValidateProofOfWork validates that the block hash meets the difficulty target
func (a *ConsensusAdapter) ValidateProofOfWork(header *miner.BlockHeader) error {
	// Calculate target from difficulty
	target := a.difficultyToTarget(header.Difficulty)
	
	// Convert hash to big int
	hashInt := new(big.Int).SetBytes(header.Hash)
	
	// Check if hash meets target (hash <= target)
	if hashInt.Cmp(target) > 0 {
		return ErrInvalidProofOfWork
	}
	
	return nil
}

// CalculateNextDifficulty calculates the next block's difficulty based on blockchain history
func (a *ConsensusAdapter) CalculateNextDifficulty(prevHeight uint64) uint32 {
	const (
		TargetBlockTime                  = 15 // seconds
		DifficultyAdjustmentInterval     = 120
		MinDifficultyAdjustment          = 0.25 // 25% of previous
		MaxDifficultyAdjustment          = 4.0  // 400% of previous
	)
	
	// Get current height (which will be prevHeight + 1)
	nextHeight := prevHeight + 1
	
	// Only adjust every DifficultyAdjustmentInterval blocks
	if nextHeight%DifficultyAdjustmentInterval != 0 {
		// Not time to adjust, get previous block's difficulty
		prevBlock, err := a.getBlockByHeight(prevHeight)
		if err != nil {
			// Fallback to default difficulty if we can't get previous block
			return 4096 // Default difficulty
		}
		return prevBlock.Difficulty
	}
	
	// Get the block from the last adjustment period
	adjustmentHeight := nextHeight - DifficultyAdjustmentInterval
	if adjustmentHeight == 0 {
		adjustmentHeight = 1 // Can't go below genesis
	}
	
	// Get blocks at adjustment boundaries
	oldBlock, err := a.getBlockByHeight(adjustmentHeight)
	if err != nil {
		// Fallback
		prevBlock, err := a.getBlockByHeight(prevHeight)
		if err != nil {
			return 4096
		}
		return prevBlock.Difficulty
	}
	
	currentBlock, err := a.getBlockByHeight(prevHeight)
	if err != nil {
		return oldBlock.Difficulty // Fallback
	}
	
	// Calculate actual time taken for the interval
	actualTime := currentBlock.Timestamp - oldBlock.Timestamp
	expectedTime := int64(DifficultyAdjustmentInterval * TargetBlockTime)
	
	// Prevent division by zero
	if actualTime <= 0 {
		actualTime = 1
	}
	
	// Calculate adjustment ratio
	adjustment := float64(expectedTime) / float64(actualTime)
	
	// Limit adjustment to prevent wild swings
	if adjustment > MaxDifficultyAdjustment {
		adjustment = MaxDifficultyAdjustment
	}
	if adjustment < MinDifficultyAdjustment {
		adjustment = MinDifficultyAdjustment
	}
	
	// Calculate new difficulty
	currentDifficulty := float64(currentBlock.Difficulty)
	newDifficulty := currentDifficulty * adjustment
	
	// Ensure difficulty doesn't go too low
	if newDifficulty < 1 {
		newDifficulty = 1
	}
	
	return uint32(newDifficulty)
}

// Helper methods

func (a *ConsensusAdapter) difficultyToTarget(difficulty uint32) *big.Int {
	// Convert difficulty to target
	// target = max_target / difficulty
	// max_target = 2^256 - 1
	maxTarget := new(big.Int).Sub(
		new(big.Int).Lsh(big.NewInt(1), 256),
		big.NewInt(1),
	)
	
	target := new(big.Int).Div(maxTarget, big.NewInt(int64(difficulty)))
	return target
}

// Encoding helper functions
func encodeUint32(n uint32) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, n)
	return buf
}

func encodeUint64(n uint64) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, n)
	return buf
}

func encodeInt64(n int64) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(n))
	return buf
}
// internal/consensus/pow.go
// PRODUCTION-GRADE PROOF OF WORK AND DIFFICULTY ADJUSTMENT

package consensus

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"math/big"
	"sync"
	"time"

	"github.com/EmekaIwuagwu/dinari-blockchain/internal/types"
	// IMPORTANT: Remove any imports to "miner" or "core" packages
)

const (
	// Core consensus parameters - PRODUCTION VALUES
	TargetBlockTime              = 15 * time.Second  // ← ADD THIS LINE
	DifficultyAdjustmentInterval = 120 // Adjust every 120 blocks
	
	// Difficulty bounds
	MinDifficulty = 1000          // ← ADD THIS LINE
	MaxDifficulty = 0xFFFFFFFF    // Maximum difficulty
	
	// CRITICAL: Adjustment limits to prevent gaming
	MaxDifficultyIncrease = 4.0   // Max 4x increase per adjustment
	MaxDifficultyDecrease = 0.25  // Max 4x decrease per adjustment
	
	// Time validation - STRICT for production
	MaxFutureBlockTime   = 2 * time.Minute    // Only 2 minutes in future
	MinBlockTimeInterval = 15 * time.Second   // ENFORCE 15 second minimum
	MaxBlockTimeInterval = 10 * 15 * time.Second // Max 10x target time
	
	// Mining parameters
	MaxNonce = 0xFFFFFFFFFFFFFFFF
)

type BlockHeader = types.BlockHeader
// BlockchainInterface defines methods needed from blockchain
type BlockchainInterface interface {
	GetBlockByHeight(height uint64) (*BlockHeader, error)
}

// ProofOfWork manages consensus rules
type ProofOfWork struct {
	blockchain                   BlockchainInterface
	targetBlockTime              time.Duration
	difficultyAdjustmentInterval uint64
	minDifficulty                uint32
	maxDifficulty                uint32
	
	// Statistics
	stats   POWStats
	statsMu sync.Mutex
}

type POWStats struct {
	BlocksValidated      uint64
	BlocksRejected       uint64
	LastAdjustmentHeight uint64
	LastAdjustmentTime   time.Time
	CurrentDifficulty    uint32
	AverageBlockTime     time.Duration
}

// NewProofOfWork creates a new PoW instance
func NewProofOfWork(blockchain BlockchainInterface) *ProofOfWork {
	return &ProofOfWork{
		blockchain:                   blockchain,
		targetBlockTime:              TargetBlockTime,
		difficultyAdjustmentInterval: DifficultyAdjustmentInterval,
		minDifficulty:                MinDifficulty,
		maxDifficulty:                MaxDifficulty,
	}
}

// CRITICAL: Production-grade difficulty calculation
func (pow *ProofOfWork) CalculateNextDifficulty(prevHeader *BlockHeader, nextHeight uint64) uint32 {
	// Only adjust at interval boundaries
	if nextHeight%pow.difficultyAdjustmentInterval != 0 {
		return prevHeader.Difficulty
	}
	
	// CRITICAL: Ensure we have enough blocks for adjustment
	if nextHeight < pow.difficultyAdjustmentInterval {
		return prevHeader.Difficulty
	}
	
	// Get the first block of the current adjustment period
	adjustmentStartHeight := nextHeight - pow.difficultyAdjustmentInterval
	
	adjustmentStartBlock, err := pow.blockchain.GetBlockByHeight(adjustmentStartHeight)
	if err != nil || adjustmentStartBlock == nil {
		fmt.Printf("⚠️  Could not get block at height %d for difficulty adjustment: %v\n", 
			adjustmentStartHeight, err)
		return prevHeader.Difficulty
	}
	
	// CRITICAL: Calculate actual time for the interval
	actualTime := prevHeader.Timestamp - adjustmentStartBlock.Timestamp
	expectedTime := int64(pow.difficultyAdjustmentInterval) * int64(pow.targetBlockTime.Seconds())
	
	// Sanity checks for production
	if actualTime <= 0 {
		fmt.Printf("❌ CRITICAL: Invalid actual time %d seconds, keeping difficulty\n", actualTime)
		return prevHeader.Difficulty
	}
	
	// CRITICAL: Prevent time warp attacks - clamp actual time
	minActualTime := expectedTime / 4  // Can't be faster than 4x
	maxActualTime := expectedTime * 4  // Can't be slower than 4x
	
	clampedTime := actualTime
	if actualTime < minActualTime {
		fmt.Printf("⚠️  Actual time %d < minimum %d, clamping to prevent attack\n", 
			actualTime, minActualTime)
		clampedTime = minActualTime
	}
	if actualTime > maxActualTime {
		fmt.Printf("⚠️  Actual time %d > maximum %d, clamping\n", actualTime, maxActualTime)
		clampedTime = maxActualTime
	}
	
	// CRITICAL: Calculate new difficulty
	// Formula: newDifficulty = oldDifficulty * (expectedTime / actualTime)
	// If blocks came too fast → actualTime < expectedTime → ratio > 1 → difficulty increases
	// If blocks came too slow → actualTime > expectedTime → ratio < 1 → difficulty decreases
	oldDifficulty := prevHeader.Difficulty
	
	// Use big integers for precision
	newDiffBig := new(big.Int).SetUint64(uint64(oldDifficulty))
	newDiffBig.Mul(newDiffBig, big.NewInt(expectedTime))
	newDiffBig.Div(newDiffBig, big.NewInt(clampedTime))
	
	// Convert back to uint32
	var newDifficulty uint32
	if newDiffBig.IsUint64() {
		newDiff64 := newDiffBig.Uint64()
		if newDiff64 > uint64(pow.maxDifficulty) {
			newDifficulty = pow.maxDifficulty
		} else {
			newDifficulty = uint32(newDiff64)
		}
	} else {
		newDifficulty = pow.maxDifficulty
	}
	
	// Ensure within bounds
	if newDifficulty < pow.minDifficulty {
		newDifficulty = pow.minDifficulty
	}
	
	// Calculate percentage change for logging
	percentChange := ((float64(newDifficulty) / float64(oldDifficulty)) - 1) * 100
	timeRatio := float64(actualTime) / float64(expectedTime)
	
	fmt.Printf("\n" + strings.Repeat("=", 80) + "\n") 
	fmt.Printf("📊 PRODUCTION DIFFICULTY ADJUSTMENT at height %d\n", nextHeight)
	fmt.Printf(strings.Repeat("=", 80) + "\n\n") 
	fmt.Printf("Period: blocks %d to %d (%d blocks)\n", 
		adjustmentStartHeight, nextHeight-1, pow.difficultyAdjustmentInterval)
	fmt.Printf("\n")
	fmt.Printf("TIME ANALYSIS:\n")
	fmt.Printf("  Expected time:    %d seconds (%d blocks × %d sec)\n", 
		expectedTime, pow.difficultyAdjustmentInterval, int(pow.targetBlockTime.Seconds()))
	fmt.Printf("  Actual time:      %d seconds (%.2f hours)\n", 
		actualTime, float64(actualTime)/3600.0)
	fmt.Printf("  Time ratio:       %.4f (actual/expected)\n", timeRatio)
	if clampedTime != actualTime {
		fmt.Printf("  Clamped time:     %d seconds (anti-gaming protection)\n", clampedTime)
	}
	fmt.Printf("\n")
	fmt.Printf("DIFFICULTY CHANGE:\n")
	fmt.Printf("  Old difficulty:   %d\n", oldDifficulty)
	fmt.Printf("  New difficulty:   %d\n", newDifficulty)
	fmt.Printf("  Change:           %.2f%%\n", percentChange)
	if percentChange > 0 {
		fmt.Printf("  Direction:        ⬆️  INCREASED (blocks were too fast)\n")
	} else if percentChange < 0 {
		fmt.Printf("  Direction:        ⬇️  DECREASED (blocks were too slow)\n")
	} else {
		fmt.Printf("  Direction:        ➡️  UNCHANGED\n")
	}
	fmt.Printf(strings.Repeat("=", 80) + "\n\n")
	
	// Record adjustment in statistics
	pow.statsMu.Lock()
	pow.stats.LastAdjustmentHeight = nextHeight
	pow.stats.LastAdjustmentTime = time.Now()
	pow.stats.CurrentDifficulty = newDifficulty
	pow.statsMu.Unlock()
	
	return newDifficulty
}

// CRITICAL: Strict timestamp validation for production
func (pow *ProofOfWork) ValidateTimestamp(header *BlockHeader, prevHeader *BlockHeader) error {
	now := time.Now().Unix()
	
	// 1. Check timestamp is positive
	if header.Timestamp <= 0 {
		return errors.New("timestamp cannot be zero or negative")
	}
	
	// 2. STRICT: Check timestamp is not too far in future (2 minutes max)
	maxFutureTime := now + int64(MaxFutureBlockTime.Seconds())
	if header.Timestamp > maxFutureTime {
		return fmt.Errorf("REJECTED: block timestamp %d is %d seconds in the future (max allowed: %d seconds)",
			header.Timestamp, header.Timestamp-now, int64(MaxFutureBlockTime.Seconds()))
	}
	
	// 3. If we have previous block, enforce strict timing rules
	if prevHeader != nil {
		// CRITICAL: Timestamp must be after previous block
		if header.Timestamp <= prevHeader.Timestamp {
			return fmt.Errorf("REJECTED: timestamp not increasing - current %d <= previous %d",
				header.Timestamp, prevHeader.Timestamp)
		}
		
		// CRITICAL: Enforce minimum block interval for production
		timeDiff := header.Timestamp - prevHeader.Timestamp
		minInterval := int64(MinBlockTimeInterval.Seconds())
		
		if timeDiff < minInterval {
			return fmt.Errorf("PRODUCTION VIOLATION: block interval %d seconds < minimum %d seconds (STRICT ENFORCEMENT)",
				timeDiff, minInterval)
		}
		
		// CRITICAL: Prevent timestamp manipulation (max 10x target time)
		maxInterval := int64(MaxBlockTimeInterval.Seconds())
		if timeDiff > maxInterval {
			return fmt.Errorf("REJECTED: block interval too large - %d seconds > maximum %d seconds",
				timeDiff, maxInterval)
		}
	}
	
	return nil
}

// CRITICAL: Enhanced difficulty validation for production
func (pow *ProofOfWork) ValidateDifficulty(header *BlockHeader, prevHeader *BlockHeader) error {
	// 1. Check difficulty bounds
	if header.Difficulty < pow.minDifficulty {
		return fmt.Errorf("difficulty %d below minimum %d", header.Difficulty, pow.minDifficulty)
	}
	
	if header.Difficulty > pow.maxDifficulty {
		return fmt.Errorf("difficulty %d above maximum %d", header.Difficulty, pow.maxDifficulty)
	}
	
	// 2. Genesis block special case
	if prevHeader == nil {
		if header.Height != 0 {
			return errors.New("non-genesis block without previous header")
		}
		return nil
	}
	
	// 3. Check if difficulty should be adjusted
	shouldAdjust := (header.Height % pow.difficultyAdjustmentInterval) == 0
	
	if !shouldAdjust {
		// Difficulty MUST remain the same between adjustments
		if header.Difficulty != prevHeader.Difficulty {
			return fmt.Errorf("REJECTED: difficulty changed at non-adjustment height %d: got %d, expected %d",
				header.Height, header.Difficulty, prevHeader.Difficulty)
		}
		return nil
	}
	
	// 4. Validate difficulty adjustment
	expectedDifficulty := pow.CalculateNextDifficulty(prevHeader, header.Height)
	
	// Allow small rounding tolerance (0.1%)
	tolerance := uint32(float64(expectedDifficulty) * 0.001)
	if tolerance < 1 {
		tolerance = 1
	}
	
	diffDelta := int64(header.Difficulty) - int64(expectedDifficulty)
	if diffDelta < 0 {
		diffDelta = -diffDelta
	}
	
	if uint32(diffDelta) > tolerance {
		return fmt.Errorf("REJECTED: incorrect difficulty adjustment at height %d: expected %d (±%d), got %d",
			header.Height, expectedDifficulty, tolerance, header.Difficulty)
	}
	
	return nil
}

// CRITICAL: Validate proof of work
func (pow *ProofOfWork) ValidateProofOfWork(header *BlockHeader) error {
	// Calculate target from difficulty
	target := pow.DifficultyToTarget(header.Difficulty)
	
	// Recalculate hash to verify
	calculatedHash := pow.CalculateBlockHash(header)
	
	// Verify hash matches header
	if !bytes.Equal(calculatedHash, header.Hash) {
		return fmt.Errorf("REJECTED: hash mismatch - calculated %x != header %x", 
			calculatedHash[:8], header.Hash[:8])
	}
	
	// Convert hash to big int
	hashInt := new(big.Int).SetBytes(header.Hash)
	
	// Hash must be less than or equal to target
	if hashInt.Cmp(target) > 0 {
		return fmt.Errorf("REJECTED: hash %x does not meet difficulty target (difficulty: %d)",
			header.Hash[:8], header.Difficulty)
	}
	
	return nil
}

// CRITICAL: Comprehensive block validation for production
func (pow *ProofOfWork) ValidateBlock(header *BlockHeader, prevHeader *BlockHeader) error {
	if header == nil {
		return errors.New("header cannot be nil")
	}
	
	// 1. Validate timestamp with STRICT rules
	if err := pow.ValidateTimestamp(header, prevHeader); err != nil {
		pow.incrementRejected()
		return fmt.Errorf("TIMESTAMP VALIDATION FAILED: %w", err)
	}
	
	// 2. Validate difficulty with STRICT rules
	if err := pow.ValidateDifficulty(header, prevHeader); err != nil {
		pow.incrementRejected()
		return fmt.Errorf("DIFFICULTY VALIDATION FAILED: %w", err)
	}
	
	// 3. Validate proof of work
	if err := pow.ValidateProofOfWork(header); err != nil {
		pow.incrementRejected()
		return fmt.Errorf("PROOF OF WORK VALIDATION FAILED: %w", err)
	}
	
	// 4. Additional production checks
	if prevHeader != nil {
		// Check block height progression
		if header.Height != prevHeader.Height+1 {
			pow.incrementRejected()
			return fmt.Errorf("REJECTED: invalid height progression - expected %d, got %d",
				prevHeader.Height+1, header.Height)
		}
		
		// Verify previous block hash
		if !bytes.Equal(header.PrevBlockHash, prevHeader.Hash) {
			pow.incrementRejected()
			return fmt.Errorf("REJECTED: previous block hash mismatch")
		}
	}
	
	// 5. Update statistics
	pow.incrementValidated()
	
	fmt.Printf("✅ Block #%d VALIDATED (timestamp=%d, difficulty=%d, interval=%d sec)\n",
		header.Height, header.Timestamp, header.Difficulty,
		func() int64 {
			if prevHeader != nil {
				return header.Timestamp - prevHeader.Timestamp
			}
			return 0
		}())
	
	return nil
}

// DifficultyToTarget converts difficulty to target
func (pow *ProofOfWork) DifficultyToTarget(difficulty uint32) *big.Int {
	// Target = MaxTarget / difficulty
	// MaxTarget = 2^256 - 1
	maxTarget := new(big.Int).Lsh(big.NewInt(1), 256)
	maxTarget.Sub(maxTarget, big.NewInt(1))
	
	target := new(big.Int).Div(maxTarget, big.NewInt(int64(difficulty)))
	return target
}

// CalculateBlockHash calculates the hash of a block header
func (pow *ProofOfWork) CalculateBlockHash(header *BlockHeader) []byte {
	var buf bytes.Buffer
	
	binary.Write(&buf, binary.BigEndian, header.Version)
	binary.Write(&buf, binary.BigEndian, header.Height)
	buf.Write(header.PrevBlockHash)
	buf.Write(header.MerkleRoot)
	binary.Write(&buf, binary.BigEndian, header.Timestamp)
	binary.Write(&buf, binary.BigEndian, header.Difficulty)
	binary.Write(&buf, binary.BigEndian, header.Nonce)
	
	// Double SHA-256
	first := sha256.Sum256(buf.Bytes())
	second := sha256.Sum256(first[:])
	
	return second[:]
}

// Statistics helpers
func (pow *ProofOfWork) incrementValidated() {
	pow.statsMu.Lock()
	pow.stats.BlocksValidated++
	pow.statsMu.Unlock()
}

func (pow *ProofOfWork) incrementRejected() {
	pow.statsMu.Lock()
	pow.stats.BlocksRejected++
	pow.statsMu.Unlock()
}

func (pow *ProofOfWork) GetStats() POWStats {
	pow.statsMu.Lock()
	defer pow.statsMu.Unlock()
	return pow.stats
}

// Additional helper functions
func (pow *ProofOfWork) GetMinDifficulty() uint32 {
	return pow.minDifficulty
}

func (pow *ProofOfWork) GetMaxDifficulty() uint32 {
	return pow.maxDifficulty
}

func (pow *ProofOfWork) GetTargetBlockTime() time.Duration {
	return pow.targetBlockTime
}

func (pow *ProofOfWork) GetDifficultyAdjustmentInterval() uint64 {
	return pow.difficultyAdjustmentInterval
}
package consensus

import (
	"math/big"

	"github.com/EmekaIwuagwu/dinari-blockchain/internal/types"
)

const (
	// DifficultyWindow is the number of blocks used for difficulty adjustment
	DifficultyWindow = 120

	// TargetBlockTime is the desired time between blocks in seconds
	TargetBlockTime = 15

	// MinDifficulty is the minimum difficulty to prevent chain from becoming too easy
	MinDifficulty = 0x1000 // 4096

	// MaxDifficultyAdjustment limits how much difficulty can change (4x max)
	MaxDifficultyAdjustment = 4.0

	// MinDifficultyAdjustment limits how much difficulty can decrease (0.25x min)
	MinDifficultyAdjustment = 0.25
)

// DifficultyAdjuster handles dynamic difficulty adjustments
type DifficultyAdjuster struct {
	targetBlockTime int64
	window          uint64
	minDifficulty   *big.Int
}

// NewDifficultyAdjuster creates a new difficulty adjuster
func NewDifficultyAdjuster() *DifficultyAdjuster {
	return &DifficultyAdjuster{
		targetBlockTime: TargetBlockTime,
		window:          DifficultyWindow,
		minDifficulty:   big.NewInt(MinDifficulty),
	}
}

// CalculateNextDifficulty calculates the difficulty for the next block
// based on the recent block times
func (da *DifficultyAdjuster) CalculateNextDifficulty(blocks []*types.BlockHeader) *big.Int {
	// Not enough blocks yet, keep current difficulty
	if len(blocks) < int(da.window) {
		if len(blocks) == 0 {
			return big.NewInt(MinDifficulty)
		}
		return blocks[len(blocks)-1].Difficulty
	}

	// Get the first and last block in the adjustment window
	firstBlock := blocks[len(blocks)-int(da.window)]
	lastBlock := blocks[len(blocks)-1]

	// Calculate actual time taken for the window
	actualTime := lastBlock.Timestamp - firstBlock.Timestamp

	// Calculate expected time for the window
	expectedTime := int64(da.window) * da.targetBlockTime

	// Prevent division by zero
	if actualTime <= 0 {
		actualTime = 1
	}

	// Calculate adjustment ratio
	ratio := float64(actualTime) / float64(expectedTime)

	// Clamp ratio to prevent wild swings
	if ratio > MaxDifficultyAdjustment {
		ratio = MaxDifficultyAdjustment
	}
	if ratio < MinDifficultyAdjustment {
		ratio = MinDifficultyAdjustment
	}

	// Calculate new difficulty = old difficulty / ratio
	// If blocks came faster than expected (ratio < 1), difficulty increases
	// If blocks came slower than expected (ratio > 1), difficulty decreases
	oldDifficulty := lastBlock.Difficulty
	newDifficulty := new(big.Int).Mul(oldDifficulty, big.NewInt(1000))
	newDifficulty.Div(newDifficulty, big.NewInt(int64(ratio*1000)))

	// Enforce minimum difficulty
	if newDifficulty.Cmp(da.minDifficulty) < 0 {
		return new(big.Int).Set(da.minDifficulty)
	}

	return newDifficulty
}

// ShouldAdjustDifficulty returns true if difficulty should be adjusted at this block
func (da *DifficultyAdjuster) ShouldAdjustDifficulty(blockNumber uint64) bool {
	if blockNumber == 0 {
		return false
	}
	return blockNumber%da.window == 0
}

// GetAdjustmentRatio calculates how much the difficulty changed
func (da *DifficultyAdjuster) GetAdjustmentRatio(oldDiff, newDiff *big.Int) float64 {
	if oldDiff.Sign() == 0 {
		return 1.0
	}

	oldFloat := new(big.Float).SetInt(oldDiff)
	newFloat := new(big.Float).SetInt(newDiff)

	ratio := new(big.Float).Quo(newFloat, oldFloat)
	result, _ := ratio.Float64()
	return result
}

// EstimateNextDifficulty estimates what the next difficulty will be
// based on recent block times (for informational purposes)
func (da *DifficultyAdjuster) EstimateNextDifficulty(recentBlocks []*types.BlockHeader, currentDifficulty *big.Int) *big.Int {
	if len(recentBlocks) < 2 {
		return currentDifficulty
	}

	// Calculate average block time from recent blocks
	totalTime := int64(0)
	for i := 1; i < len(recentBlocks); i++ {
		timeDiff := recentBlocks[i].Timestamp - recentBlocks[i-1].Timestamp
		totalTime += timeDiff
	}

	avgBlockTime := totalTime / int64(len(recentBlocks)-1)

	// Calculate estimated adjustment ratio
	ratio := float64(avgBlockTime) / float64(da.targetBlockTime)

	// Clamp ratio
	if ratio > MaxDifficultyAdjustment {
		ratio = MaxDifficultyAdjustment
	}
	if ratio < MinDifficultyAdjustment {
		ratio = MinDifficultyAdjustment
	}

	// Calculate estimated new difficulty
	estimatedDifficulty := new(big.Int).Mul(currentDifficulty, big.NewInt(1000))
	estimatedDifficulty.Div(estimatedDifficulty, big.NewInt(int64(ratio*1000)))

	// Enforce minimum
	if estimatedDifficulty.Cmp(da.minDifficulty) < 0 {
		return new(big.Int).Set(da.minDifficulty)
	}

	return estimatedDifficulty
}

// ValidateDifficulty checks if the difficulty is valid for the given block
func (da *DifficultyAdjuster) ValidateDifficulty(blockNumber uint64, difficulty *big.Int, prevBlocks []*types.BlockHeader) error {
	// Genesis block
	if blockNumber == 0 {
		if difficulty.Cmp(da.minDifficulty) < 0 {
			return types.ErrInvalidDifficulty
		}
		return nil
	}

	// Check if difficulty adjustment should happen
	if !da.ShouldAdjustDifficulty(blockNumber) {
		// Difficulty should match previous block
		if len(prevBlocks) > 0 {
			prevDiff := prevBlocks[len(prevBlocks)-1].Difficulty
			if difficulty.Cmp(prevDiff) != 0 {
				return types.ErrInvalidDifficulty
			}
		}
		return nil
	}

	// Calculate expected difficulty
	expectedDifficulty := da.CalculateNextDifficulty(prevBlocks)

	// Verify it matches
	if difficulty.Cmp(expectedDifficulty) != 0 {
		return types.ErrInvalidDifficulty
	}

	return nil
}

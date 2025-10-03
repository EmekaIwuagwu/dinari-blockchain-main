package consensus

import (
	"math/big"
)

const (
	// InitialReward is the block reward for the first blocks (50 DNT in satoshis)
	InitialReward = 50 * 1e8

	// HalvingInterval is the number of blocks between halvings
	HalvingInterval = 210000

	// MaxSupply is the maximum supply of DNT (21 million in satoshis)
	MaxSupply = 21000000 * 1e8
)

// RewardCalculator handles mining reward calculations
type RewardCalculator struct {
	initialReward   *big.Int
	halvingInterval uint64
	maxSupply       *big.Int
}

// NewRewardCalculator creates a new reward calculator
func NewRewardCalculator() *RewardCalculator {
	return &RewardCalculator{
		initialReward:   big.NewInt(InitialReward),
		halvingInterval: HalvingInterval,
		maxSupply:       big.NewInt(MaxSupply),
	}
}

// CalculateBlockReward calculates the mining reward for a given block number
func (rc *RewardCalculator) CalculateBlockReward(blockNumber uint64) *big.Int {
	// Calculate number of halvings that have occurred
	halvings := blockNumber / rc.halvingInterval

	// After 64 halvings, reward is effectively zero
	if halvings >= 64 {
		return big.NewInt(0)
	}

	// Calculate reward = initialReward / (2^halvings)
	reward := new(big.Int).Set(rc.initialReward)
	reward.Rsh(reward, uint(halvings)) // Right shift = divide by 2^halvings

	return reward
}

// GetHalvingNumber returns which halving period the block is in
func (rc *RewardCalculator) GetHalvingNumber(blockNumber uint64) uint64 {
	return blockNumber / rc.halvingInterval
}

// BlocksUntilHalving returns how many blocks until the next halving
func (rc *RewardCalculator) BlocksUntilHalving(blockNumber uint64) uint64 {
	nextHalving := ((blockNumber / rc.halvingInterval) + 1) * rc.halvingInterval
	return nextHalving - blockNumber
}

// EstimateTotalSupply estimates the total supply at a given block
func (rc *RewardCalculator) EstimateTotalSupply(blockNumber uint64) *big.Int {
	totalSupply := big.NewInt(0)

	// Sum rewards for each halving period up to current block
	for halvingNum := uint64(0); halvingNum <= blockNumber/rc.halvingInterval; halvingNum++ {
		// Calculate reward for this halving period
		reward := new(big.Int).Set(rc.initialReward)
		reward.Rsh(reward, uint(halvingNum))

		// Calculate blocks in this halving period
		startBlock := halvingNum * rc.halvingInterval
		endBlock := (halvingNum + 1) * rc.halvingInterval
		if endBlock > blockNumber {
			endBlock = blockNumber + 1
		}
		blocksInPeriod := endBlock - startBlock

		// Add to total supply
		periodSupply := new(big.Int).Mul(reward, big.NewInt(int64(blocksInPeriod)))
		totalSupply.Add(totalSupply, periodSupply)
	}

	return totalSupply
}

// ValidateBlockReward checks if the block reward is correct
func (rc *RewardCalculator) ValidateBlockReward(blockNumber uint64, reward *big.Int) bool {
	expectedReward := rc.CalculateBlockReward(blockNumber)
	return reward.Cmp(expectedReward) == 0
}

// GetCurrentReward returns the current block reward
func (rc *RewardCalculator) GetCurrentReward(blockNumber uint64) *big.Int {
	return rc.CalculateBlockReward(blockNumber)
}

// CalculateTotalReward calculates total fees + block reward for a block
func (rc *RewardCalculator) CalculateTotalReward(blockNumber uint64, totalFees *big.Int) *big.Int {
	blockReward := rc.CalculateBlockReward(blockNumber)
	total := new(big.Int).Add(blockReward, totalFees)
	return total
}

// IsSupplyCapReached checks if max supply has been reached
func (rc *RewardCalculator) IsSupplyCapReached(totalSupply *big.Int) bool {
	return totalSupply.Cmp(rc.maxSupply) >= 0
}

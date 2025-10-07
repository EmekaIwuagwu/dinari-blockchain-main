package consensus

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/big"
	"sort"
	"sync"
	"time"
)

const (
	// Target block time - 15 seconds
	
	// Difficulty adjustment parameters
	DifficultyAdjustmentInterval = 120 // Adjust every 120 blocks (~30 minutes)
	DifficultyAdjustmentWindow   = 11  // Use median of last 11 blocks for timestamp
	
	// Difficulty bounds
	MaxDifficulty = 0xFFFFFFFF  // Maximum difficulty (32-bit limit)
	
	// Difficulty adjustment limits (prevent extreme changes)
	MaxDifficultyAdjustmentUp   = 4.0  // Max 4x increase
	MaxDifficultyAdjustmentDown = 0.25 // Max 4x decrease (1/4)
	
	// Time validation
	MaxFutureBlockTime      = 2 * time.Hour    // Reject blocks > 2 hours in future
	MinBlockTimeInterval    = 1 * time.Second  // Minimum time between blocks
	MaxBlockTimeDeviation   = 7200             // 2 hours in seconds
	
	// Mining parameters
	MaxNonce = 0xFFFFFFFFFFFFFFFF // 64-bit nonce space
	
	// Hash rate calculation
	HashRateWindow = 100 // Calculate hash rate over last 100 blocks
)

var (
	// Errors
	ErrInvalidDifficulty   = errors.New("invalid difficulty")
	ErrInvalidTimestamp    = errors.New("invalid timestamp")
	ErrInsufficientWork    = errors.New("block hash does not meet difficulty target")
	ErrTimestampTooOld     = errors.New("timestamp too old")
	ErrTimestampTooNew     = errors.New("timestamp too far in future")
	ErrDifficultyTooLow    = errors.New("difficulty below minimum")
	ErrDifficultyTooHigh   = errors.New("difficulty above maximum")
	ErrInvalidPrevBlock    = errors.New("invalid previous block")
	
	// Target for difficulty 1 (maximum target)
	MaxTarget = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
)

// ProofOfWork implements the Proof of Work consensus algorithm
type ProofOfWork struct {
	// Configuration
	targetBlockTime              time.Duration
	difficultyAdjustmentInterval uint64
	minDifficulty                uint32
	maxDifficulty                uint32
	
	// Statistics
	stats      *ConsensusStats
	statsMu    sync.RWMutex
	
	// Block time history for hash rate calculation
	blockTimes []BlockTimeRecord
	timeMu     sync.RWMutex
}

// ConsensusStats tracks consensus statistics
type ConsensusStats struct {
	TotalBlocksValidated uint64
	TotalHashesComputed  uint64
	AverageHashRate      float64
	CurrentDifficulty    uint32
	LastAdjustmentHeight uint64
	LastAdjustmentTime   time.Time
	RejectedBlocks       uint64
}

// BlockTimeRecord stores block timing information
type BlockTimeRecord struct {
	Height    uint64
	Timestamp int64
	Difficulty uint32
}

// BlockHeader represents the block header for PoW
type BlockHeader struct {
	Version       uint32
	Height        uint64
	PrevBlockHash []byte
	MerkleRoot    []byte
	Timestamp     int64
	Difficulty    uint32
	Nonce         uint64
	Hash          []byte
}

// NewProofOfWork creates a new PoW consensus engine
func NewProofOfWork() *ProofOfWork {
	return &ProofOfWork{
		targetBlockTime:              TargetBlockTime,
		difficultyAdjustmentInterval: DifficultyAdjustmentInterval,
		minDifficulty:                MinDifficulty,
		maxDifficulty:                MaxDifficulty,
		stats: &ConsensusStats{
			CurrentDifficulty: MinDifficulty,
		},
		blockTimes: make([]BlockTimeRecord, 0, HashRateWindow),
	}
}

// ValidateBlock performs comprehensive PoW validation on a block
func (pow *ProofOfWork) ValidateBlock(header *BlockHeader, prevHeader *BlockHeader) error {
	if header == nil {
		return errors.New("header cannot be nil")
	}
	
	// 1. Validate timestamp
	if err := pow.ValidateTimestamp(header, prevHeader); err != nil {
		pow.incrementRejected()
		return fmt.Errorf("timestamp validation failed: %w", err)
	}
	
	// 2. Validate difficulty
	if err := pow.ValidateDifficulty(header, prevHeader); err != nil {
		pow.incrementRejected()
		return fmt.Errorf("difficulty validation failed: %w", err)
	}
	
	// 3. Validate proof of work
	if err := pow.ValidateProofOfWork(header); err != nil {
		pow.incrementRejected()
		return fmt.Errorf("proof of work validation failed: %w", err)
	}
	
	// 4. Record block time for statistics
	pow.recordBlockTime(header)
	
	// 5. Update statistics
	pow.incrementValidated()
	
	return nil
}

// ValidateTimestamp validates block timestamp against various rules
func (pow *ProofOfWork) ValidateTimestamp(header *BlockHeader, prevHeader *BlockHeader) error {
	now := time.Now().Unix()
	
	// 1. Check timestamp is not zero
	if header.Timestamp <= 0 {
		return errors.New("timestamp cannot be zero or negative")
	}
	
	// 2. Check timestamp is not too far in future
	if header.Timestamp > now+int64(MaxFutureBlockTime.Seconds()) {
		return fmt.Errorf("%w: block time %d is %d seconds in future",
			ErrTimestampTooNew, header.Timestamp, header.Timestamp-now)
	}
	
	// 3. If we have previous block, ensure timestamp moves forward
	if prevHeader != nil {
		// Timestamp must be after previous block
		if header.Timestamp <= prevHeader.Timestamp {
			return fmt.Errorf("%w: current %d <= previous %d",
				ErrInvalidTimestamp, header.Timestamp, prevHeader.Timestamp)
		}
		
		// Check minimum time interval
		timeDiff := header.Timestamp - prevHeader.Timestamp
		if timeDiff < int64(MinBlockTimeInterval.Seconds()) {
			return fmt.Errorf("block time interval too small: %d seconds", timeDiff)
		}
		
		// Check reasonable maximum interval (prevent timestamp manipulation)
		if timeDiff > MaxBlockTimeDeviation {
			return fmt.Errorf("block time interval too large: %d seconds", timeDiff)
		}
	}
	
	return nil
}

// ValidateTimestampMedian validates timestamp against median of previous blocks
// This prevents miners from manipulating timestamps
func (pow *ProofOfWork) ValidateTimestampMedian(header *BlockHeader, previousHeaders []*BlockHeader) error {
	if len(previousHeaders) < DifficultyAdjustmentWindow {
		return nil // Not enough blocks for median calculation
	}
	
	// Get last N block timestamps
	timestamps := make([]int64, 0, DifficultyAdjustmentWindow)
	for i := 0; i < DifficultyAdjustmentWindow && i < len(previousHeaders); i++ {
		timestamps = append(timestamps, previousHeaders[i].Timestamp)
	}
	
	// Calculate median
	sort.Slice(timestamps, func(i, j int) bool {
		return timestamps[i] < timestamps[j]
	})
	
	median := timestamps[len(timestamps)/2]
	
	// Block timestamp must be greater than median
	if header.Timestamp <= median {
		return fmt.Errorf("%w: timestamp %d not greater than median %d",
			ErrInvalidTimestamp, header.Timestamp, median)
	}
	
	return nil
}

// ValidateDifficulty validates the difficulty target
func (pow *ProofOfWork) ValidateDifficulty(header *BlockHeader, prevHeader *BlockHeader) error {
	// 1. Check difficulty bounds
	if header.Difficulty < pow.minDifficulty {
		return fmt.Errorf("%w: %d < %d", ErrDifficultyTooLow, header.Difficulty, pow.minDifficulty)
	}
	
	if header.Difficulty > pow.maxDifficulty {
		return fmt.Errorf("%w: %d > %d", ErrDifficultyTooHigh, header.Difficulty, pow.maxDifficulty)
	}
	
	// 2. If no previous block (genesis), accept difficulty
	if prevHeader == nil {
		return nil
	}
	
	// 3. Check if difficulty should be adjusted
	shouldAdjust := (header.Height % pow.difficultyAdjustmentInterval) == 0
	
	if !shouldAdjust {
		// Difficulty should remain the same
		if header.Difficulty != prevHeader.Difficulty {
			return fmt.Errorf("%w: difficulty changed at non-adjustment height", ErrInvalidDifficulty)
		}
		return nil
	}
	
	// 4. Calculate and validate expected difficulty
	expectedDifficulty := pow.CalculateNextDifficulty(prevHeader, header.Height)
	
	if header.Difficulty != expectedDifficulty {
		return fmt.Errorf("%w: expected %d, got %d",
			ErrInvalidDifficulty, expectedDifficulty, header.Difficulty)
	}
	
	return nil
}

// CalculateNextDifficulty calculates the difficulty for the next adjustment period
func (pow *ProofOfWork) CalculateNextDifficulty(prevHeader *BlockHeader, nextHeight uint64) uint32 {
	// If not at adjustment interval, return previous difficulty
	if (nextHeight % pow.difficultyAdjustmentInterval) != 0 {
		return prevHeader.Difficulty
	}
	
	// Get the block from the start of this adjustment period
	// In production, this would query the blockchain
	// For now, we'll use a simplified calculation
	
	// Calculate expected time for interval
	expectedTime := int64(pow.difficultyAdjustmentInterval) * int64(pow.targetBlockTime.Seconds())
	
	// Calculate actual time (would need to get block from interval start)
	// For this implementation, we'll use a placeholder
	actualTime := expectedTime // Placeholder - should be: prevHeader.Timestamp - adjustmentStartBlock.Timestamp
	
	// Calculate adjustment ratio
	ratio := float64(actualTime) / float64(expectedTime)
	
	// Clamp adjustment to prevent extreme changes
	if ratio > MaxDifficultyAdjustmentUp {
		ratio = MaxDifficultyAdjustmentUp
	}
	if ratio < MaxDifficultyAdjustmentDown {
		ratio = MaxDifficultyAdjustmentDown
	}
	
	// Calculate new difficulty
	// If blocks were mined too fast (ratio < 1), increase difficulty
	// If blocks were mined too slow (ratio > 1), decrease difficulty
	newDifficulty := float64(prevHeader.Difficulty) / ratio
	
	// Round to nearest integer
	difficulty := uint32(math.Round(newDifficulty))
	
	// Ensure within bounds
	if difficulty < pow.minDifficulty {
		difficulty = pow.minDifficulty
	}
	if difficulty > pow.maxDifficulty {
		difficulty = pow.maxDifficulty
	}
	
	return difficulty
}

// ValidateProofOfWork validates that the block hash meets the difficulty target
func (pow *ProofOfWork) ValidateProofOfWork(header *BlockHeader) error {
	// 1. Calculate block hash
	hash := pow.CalculateHash(header)
	
	// 2. Verify hash matches header
	if !bytes.Equal(hash, header.Hash) {
		return errors.New("block hash mismatch")
	}
	
	// 3. Convert hash to big integer
	hashInt := new(big.Int).SetBytes(hash)
	
	// 4. Calculate target from difficulty
	target := pow.DifficultyToTarget(header.Difficulty)
	
	// 5. Validate hash is below target
	if hashInt.Cmp(target) > 0 {
		return fmt.Errorf("%w: hash %s > target %s",
			ErrInsufficientWork,
			hashInt.Text(16),
			target.Text(16))
	}
	
	return nil
}

// CalculateHash computes the double SHA-256 hash of a block header
func (pow *ProofOfWork) CalculateHash(header *BlockHeader) []byte {
	// Serialize header
	data := pow.SerializeHeader(header)
	
	// Double SHA-256
	firstHash := sha256.Sum256(data)
	secondHash := sha256.Sum256(firstHash[:])
	
	return secondHash[:]
}

// SerializeHeader serializes a block header for hashing
func (pow *ProofOfWork) SerializeHeader(header *BlockHeader) []byte {
	var buf bytes.Buffer
	
	// Write all fields in deterministic order
	binary.Write(&buf, binary.BigEndian, header.Version)
	binary.Write(&buf, binary.BigEndian, header.Height)
	buf.Write(header.PrevBlockHash)
	buf.Write(header.MerkleRoot)
	binary.Write(&buf, binary.BigEndian, header.Timestamp)
	binary.Write(&buf, binary.BigEndian, header.Difficulty)
	binary.Write(&buf, binary.BigEndian, header.Nonce)
	
	return buf.Bytes()
}

// DifficultyToTarget converts difficulty to target hash value
func (pow *ProofOfWork) DifficultyToTarget(difficulty uint32) *big.Int {
	if difficulty == 0 {
		return MaxTarget
	}
	
	// Target = MaxTarget / difficulty
	target := new(big.Int).Div(MaxTarget, big.NewInt(int64(difficulty)))
	
	return target
}

// TargetToDifficulty converts target hash value to difficulty
func (pow *ProofOfWork) TargetToDifficulty(target *big.Int) uint32 {
	if target.Sign() <= 0 {
		return pow.maxDifficulty
	}
	
	// Difficulty = MaxTarget / target
	difficulty := new(big.Int).Div(MaxTarget, target)
	
	// Convert to uint32 with bounds checking
	if difficulty.Cmp(big.NewInt(int64(pow.maxDifficulty))) > 0 {
		return pow.maxDifficulty
	}
	
	if difficulty.Cmp(big.NewInt(int64(pow.minDifficulty))) < 0 {
		return pow.minDifficulty
	}
	
	return uint32(difficulty.Uint64())
}

// Mine attempts to find a valid nonce for a block header
func (pow *ProofOfWork) Mine(header *BlockHeader, stopChan <-chan struct{}) (uint64, []byte, error) {
	target := pow.DifficultyToTarget(header.Difficulty)
	
	var nonce uint64
	var hash []byte
	hashesComputed := uint64(0)
	
	startTime := time.Now()
	
	// Try different nonces
	for nonce = 0; nonce <= MaxNonce; nonce++ {
		// Check if we should stop
		select {
		case <-stopChan:
			return 0, nil, errors.New("mining stopped")
		default:
		}
		
		// Set nonce and calculate hash
		header.Nonce = nonce
		hash = pow.CalculateHash(header)
		hashesComputed++
		
		// Check if hash meets target
		hashInt := new(big.Int).SetBytes(hash)
		if hashInt.Cmp(target) <= 0 {
			// Found valid nonce!
			duration := time.Since(startTime)
			hashRate := float64(hashesComputed) / duration.Seconds()
			
			fmt.Printf("⛏️  Block mined! Nonce: %d, Hashes: %d, Rate: %.2f H/s\n",
				nonce, hashesComputed, hashRate)
			
			// Update statistics
			pow.statsMu.Lock()
			pow.stats.TotalHashesComputed += hashesComputed
			pow.statsMu.Unlock()
			
			return nonce, hash, nil
		}
		
		// Progress update every million hashes
		if hashesComputed%1000000 == 0 {
			duration := time.Since(startTime)
			hashRate := float64(hashesComputed) / duration.Seconds()
			fmt.Printf("Mining... %d hashes, %.2f kH/s\n", hashesComputed, hashRate/1000)
		}
	}
	
	return 0, nil, errors.New("nonce space exhausted")
}

// CalculateHashRate calculates the network hash rate based on recent blocks
func (pow *ProofOfWork) CalculateHashRate() float64 {
	pow.timeMu.RLock()
	defer pow.timeMu.RUnlock()
	
	if len(pow.blockTimes) < 2 {
		return 0
	}
	
	// Get first and last block
	first := pow.blockTimes[0]
	last := pow.blockTimes[len(pow.blockTimes)-1]
	
	// Calculate time span
	timeSpan := last.Timestamp - first.Timestamp
	if timeSpan == 0 {
		return 0
	}
	
	// Calculate average difficulty
	totalDifficulty := uint64(0)
	for _, record := range pow.blockTimes {
		totalDifficulty += uint64(record.Difficulty)
	}
	avgDifficulty := float64(totalDifficulty) / float64(len(pow.blockTimes))
	
	// Estimate hashes per block (rough approximation)
	target := pow.DifficultyToTarget(uint32(avgDifficulty))
	hashesPerBlock := new(big.Int).Div(MaxTarget, target)
	
	// Calculate hash rate
	blockCount := len(pow.blockTimes)
	totalHashes := new(big.Int).Mul(hashesPerBlock, big.NewInt(int64(blockCount)))
	hashRate := new(big.Int).Div(totalHashes, big.NewInt(timeSpan))
	
	return float64(hashRate.Uint64())
}

// GetDifficulty returns the current difficulty
func (pow *ProofOfWork) GetDifficulty() uint32 {
	pow.statsMu.RLock()
	defer pow.statsMu.RUnlock()
	return pow.stats.CurrentDifficulty
}

// GetStats returns consensus statistics
func (pow *ProofOfWork) GetStats() ConsensusStats {
	pow.statsMu.RLock()
	defer pow.statsMu.RUnlock()
	
	stats := *pow.stats
	stats.AverageHashRate = pow.CalculateHashRate()
	
	return stats
}

// ValidateGenesisBlock validates the genesis block
func (pow *ProofOfWork) ValidateGenesisBlock(header *BlockHeader) error {
	// Genesis block special validation
	if header.Height != 0 {
		return errors.New("genesis block must have height 0")
	}
	
	if len(header.PrevBlockHash) != 0 {
		return errors.New("genesis block must have empty previous hash")
	}
	
	// Validate proof of work
	return pow.ValidateProofOfWork(header)
}

// Internal helper methods

func (pow *ProofOfWork) recordBlockTime(header *BlockHeader) {
	pow.timeMu.Lock()
	defer pow.timeMu.Unlock()
	
	record := BlockTimeRecord{
		Height:     header.Height,
		Timestamp:  header.Timestamp,
		Difficulty: header.Difficulty,
	}
	
	pow.blockTimes = append(pow.blockTimes, record)
	
	// Keep only last N blocks
	if len(pow.blockTimes) > HashRateWindow {
		pow.blockTimes = pow.blockTimes[1:]
	}
	
	// Update current difficulty
	pow.statsMu.Lock()
	pow.stats.CurrentDifficulty = header.Difficulty
	pow.statsMu.Unlock()
}

func (pow *ProofOfWork) incrementValidated() {
	pow.statsMu.Lock()
	defer pow.statsMu.Unlock()
	pow.stats.TotalBlocksValidated++
}

func (pow *ProofOfWork) incrementRejected() {
	pow.statsMu.Lock()
	defer pow.statsMu.Unlock()
	pow.stats.RejectedBlocks++
}

// CalculateWorkRequired calculates work required for a given difficulty
func (pow *ProofOfWork) CalculateWorkRequired(difficulty uint32) *big.Int {
	target := pow.DifficultyToTarget(difficulty)
	work := new(big.Int).Div(MaxTarget, target)
	return work
}

// CompareChainWork compares the total work of two chains
func (pow *ProofOfWork) CompareChainWork(work1, work2 *big.Int) int {
	return work1.Cmp(work2)
}

// EstimateTimeToBlock estimates time to mine next block at current hash rate
func (pow *ProofOfWork) EstimateTimeToBlock(hashRate float64, difficulty uint32) time.Duration {
	if hashRate == 0 {
		return 0
	}
	
	target := pow.DifficultyToTarget(difficulty)
	expectedHashes := new(big.Int).Div(MaxTarget, target)
	
	seconds := float64(expectedHashes.Uint64()) / hashRate
	return time.Duration(seconds * float64(time.Second))
}

// VerifyChainWork verifies the total work claimed for a chain
func (pow *ProofOfWork) VerifyChainWork(blocks []*BlockHeader) (*big.Int, error) {
	totalWork := big.NewInt(0)
	
	for i, header := range blocks {
		// Validate each block's PoW
		var prevHeader *BlockHeader
		if i > 0 {
			prevHeader = blocks[i-1]
		}
		
		if err := pow.ValidateBlock(header, prevHeader); err != nil {
			return nil, fmt.Errorf("invalid block at height %d: %w", header.Height, err)
		}
		
		// Add work
		blockWork := pow.CalculateWorkRequired(header.Difficulty)
		totalWork.Add(totalWork, blockWork)
	}
	
	return totalWork, nil
}

// IsValidDifficultyTransition checks if difficulty transition is valid
func (pow *ProofOfWork) IsValidDifficultyTransition(oldDifficulty, newDifficulty uint32) bool {
	ratio := float64(newDifficulty) / float64(oldDifficulty)
	
	// Check if ratio is within acceptable bounds
	return ratio <= MaxDifficultyAdjustmentUp && ratio >= MaxDifficultyAdjustmentDown
}

package consensus

import (
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"
)

// AttackPrevention provides protection against consensus attacks
type AttackPrevention struct {
	// Selfish mining detection
	selfishMiningDetector *SelfishMiningDetector
	
	// 51% attack detection
	hashRateMonitor *HashRateMonitor
	
	// Timestamp manipulation detection
	timestampValidator *TimestampValidator
	
	// Long-range attack prevention
	checkpointSystem *CheckpointSystem
	
	// Eclipse attack prevention
	peerDiversityChecker *PeerDiversityChecker
	
	config *AttackPreventionConfig
	mu     sync.RWMutex
}

// AttackPreventionConfig contains attack prevention parameters
type AttackPreventionConfig struct {
	// Selfish mining
	EnableSelfishMiningDetection bool
	OrphanRateThreshold          float64 // Suspicious if > 5%
	PrivateChainMaxLength        int     // Alert if > 6 blocks
	
	// Hash rate monitoring
	EnableHashRateMonitoring   bool
	HashRateWindowSize         int
	SuspiciousHashRateChange   float64 // Alert if > 30% change
	
	// Timestamp validation
	MaxTimestampDrift          time.Duration
	MaxTimestampBackward       time.Duration
	MedianTimeSpanBlocks       int
	
	// Checkpoints
	CheckpointInterval         uint64
	MinConfirmationsForFinality int
	
	// Peer diversity
	MinimumUniquePeerASNs      int
	MaxPeersPerASN             int
}

// SelfishMiningDetector detects selfish mining attacks
type SelfishMiningDetector struct {
	orphanBlocks     []*OrphanBlock
	orphanRate       float64
	privateChainLen  int
	suspiciousMiners map[string]*MinerBehavior
	mu               sync.RWMutex
}

// OrphanBlock represents a block that became orphaned
type OrphanBlock struct {
	Height    uint64
	Hash      string
	Miner     string
	Timestamp time.Time
	Replaced  bool
}

// MinerBehavior tracks individual miner behavior
type MinerBehavior struct {
	Address           string
	BlocksProduced    int
	OrphansProduced   int
	AverageBlockTime  time.Duration
	SuspicionScore    float64
	LastActivity      time.Time
}

// HashRateMonitor monitors network hash rate
type HashRateMonitor struct {
	samples          []HashRateSample
	windowSize       int
	currentHashRate  *big.Int
	previousHashRate *big.Int
	mu               sync.RWMutex
}

// HashRateSample represents a hash rate measurement
type HashRateSample struct {
	Timestamp time.Time
	HashRate  *big.Int
	BlockHeight uint64
}

// TimestampValidator prevents timestamp manipulation
type TimestampValidator struct {
	blockTimestamps []time.Time
	medianTimeSpan  int
	mu              sync.RWMutex
}

// CheckpointSystem prevents long-range attacks
type CheckpointSystem struct {
	checkpoints      map[uint64]string // height -> block hash
	lastCheckpoint   uint64
	checkpointInterval uint64
	mu               sync.RWMutex
}

// PeerDiversityChecker ensures network decentralization
type PeerDiversityChecker struct {
	peersByASN map[string]int
	uniqueASNs int
	mu         sync.RWMutex
}

// NewAttackPrevention creates a new attack prevention system
func NewAttackPrevention(config *AttackPreventionConfig) *AttackPrevention {
	return &AttackPrevention{
		selfishMiningDetector: &SelfishMiningDetector{
			orphanBlocks:     make([]*OrphanBlock, 0),
			suspiciousMiners: make(map[string]*MinerBehavior),
		},
		hashRateMonitor: &HashRateMonitor{
			samples:    make([]HashRateSample, 0),
			windowSize: config.HashRateWindowSize,
		},
		timestampValidator: &TimestampValidator{
			blockTimestamps: make([]time.Time, 0),
			medianTimeSpan:  config.MedianTimeSpanBlocks,
		},
		checkpointSystem: &CheckpointSystem{
			checkpoints:        make(map[uint64]string),
			checkpointInterval: config.CheckpointInterval,
		},
		peerDiversityChecker: &PeerDiversityChecker{
			peersByASN: make(map[string]int),
		},
		config: config,
	}
}

// ValidateBlock performs comprehensive block validation
func (ap *AttackPrevention) ValidateBlock(block *Block, prevBlock *Block) error {
	// Timestamp validation
	if err := ap.validateBlockTimestamp(block, prevBlock); err != nil {
		return fmt.Errorf("timestamp validation failed: %w", err)
	}
	
	// Difficulty validation
	if err := ap.validateDifficulty(block, prevBlock); err != nil {
		return fmt.Errorf("difficulty validation failed: %w", err)
	}
	
	// Checkpoint validation
	if err := ap.validateAgainstCheckpoints(block); err != nil {
		return fmt.Errorf("checkpoint validation failed: %w", err)
	}
	
	// Hash rate analysis
	ap.analyzeHashRate(block)
	
	// Selfish mining detection
	ap.detectSelfishMining(block)
	
	return nil
}

// validateBlockTimestamp prevents timestamp manipulation attacks
func (ap *AttackPrevention) validateBlockTimestamp(block, prevBlock *Block) error {
	ap.timestampValidator.mu.Lock()
	defer ap.timestampValidator.mu.Unlock()
	
	blockTime := time.Unix(block.Timestamp, 0)
	now := time.Now()
	
	// Check if timestamp is too far in the future
	if blockTime.After(now.Add(ap.config.MaxTimestampDrift)) {
		return fmt.Errorf("block timestamp too far in future: %v > %v", 
			blockTime, now.Add(ap.config.MaxTimestampDrift))
	}
	
	// Check if timestamp is before previous block
	if prevBlock != nil {
		prevTime := time.Unix(prevBlock.Timestamp, 0)
		if blockTime.Before(prevTime) {
			return fmt.Errorf("block timestamp before previous block: %v < %v", 
				blockTime, prevTime)
		}
	}
	
	// Median time validation (prevents time-warp attacks)
	if len(ap.timestampValidator.blockTimestamps) >= ap.timestampValidator.medianTimeSpan {
		medianTime := ap.calculateMedianTime()
		if blockTime.Before(medianTime) {
			return fmt.Errorf("block timestamp before median time: %v < %v", 
				blockTime, medianTime)
		}
	}
	
	// Add to history
	ap.timestampValidator.blockTimestamps = append(
		ap.timestampValidator.blockTimestamps, 
		blockTime,
	)
	
	// Keep only recent timestamps
	if len(ap.timestampValidator.blockTimestamps) > ap.timestampValidator.medianTimeSpan*2 {
		ap.timestampValidator.blockTimestamps = ap.timestampValidator.blockTimestamps[1:]
	}
	
	return nil
}

// calculateMedianTime calculates median of recent block timestamps
func (ap *AttackPrevention) calculateMedianTime() time.Time {
	timestamps := make([]time.Time, len(ap.timestampValidator.blockTimestamps))
	copy(timestamps, ap.timestampValidator.blockTimestamps)
	
	// Sort timestamps
	for i := 0; i < len(timestamps); i++ {
		for j := i + 1; j < len(timestamps); j++ {
			if timestamps[i].After(timestamps[j]) {
				timestamps[i], timestamps[j] = timestamps[j], timestamps[i]
			}
		}
	}
	
	// Return median
	mid := len(timestamps) / 2
	return timestamps[mid]
}

// validateDifficulty prevents difficulty manipulation
func (ap *AttackPrevention) validateDifficulty(block, prevBlock *Block) error {
	// Calculate expected difficulty
	expectedDifficulty := ap.calculateExpectedDifficulty(prevBlock)
	
	// Verify block meets difficulty target
	blockHash := new(big.Int).SetBytes([]byte(block.Hash))
	target := new(big.Int).SetUint64(block.Target)
	
	if blockHash.Cmp(target) > 0 {
		return fmt.Errorf("block does not meet difficulty target")
	}
	
	// Check difficulty is within acceptable range
	maxDiffChange := new(big.Int).Div(expectedDifficulty, big.NewInt(4)) // ±25%
	minDiff := new(big.Int).Sub(expectedDifficulty, maxDiffChange)
	maxDiff := new(big.Int).Add(expectedDifficulty, maxDiffChange)
	
	if target.Cmp(minDiff) < 0 || target.Cmp(maxDiff) > 0 {
		return fmt.Errorf("difficulty change too large")
	}
	
	return nil
}

// calculateExpectedDifficulty calculates expected difficulty for next block
func (ap *AttackPrevention) calculateExpectedDifficulty(prevBlock *Block) *big.Int {
	// Implement difficulty adjustment algorithm
	// This is simplified - actual implementation should match consensus rules
	return big.NewInt(int64(prevBlock.Target))
}

// validateAgainstCheckpoints prevents long-range attacks
func (ap *AttackPrevention) validateAgainstCheckpoints(block *Block) error {
	ap.checkpointSystem.mu.RLock()
	defer ap.checkpointSystem.mu.RUnlock()
	
	// Check if block height has a checkpoint
	if checkpointHash, exists := ap.checkpointSystem.checkpoints[block.Height]; exists {
		if block.Hash != checkpointHash {
			return fmt.Errorf("block hash does not match checkpoint: %s != %s", 
				block.Hash, checkpointHash)
		}
	}
	
	return nil
}

// AddCheckpoint adds a new checkpoint
func (ap *AttackPrevention) AddCheckpoint(height uint64, blockHash string) error {
	ap.checkpointSystem.mu.Lock()
	defer ap.checkpointSystem.mu.Unlock()
	
	// Verify checkpoint interval
	if height < ap.checkpointSystem.lastCheckpoint + ap.checkpointSystem.checkpointInterval {
		return errors.New("checkpoint too soon")
	}
	
	ap.checkpointSystem.checkpoints[height] = blockHash
	ap.checkpointSystem.lastCheckpoint = height
	
	return nil
}

// detectSelfishMining detects selfish mining behavior
func (ap *AttackPrevention) detectSelfishMining(block *Block) {
	if !ap.config.EnableSelfishMiningDetection {
		return
	}
	
	ap.selfishMiningDetector.mu.Lock()
	defer ap.selfishMiningDetector.mu.Unlock()
	
	// Track miner behavior
	behavior, exists := ap.selfishMiningDetector.suspiciousMiners[block.Miner]
	if !exists {
		behavior = &MinerBehavior{
			Address:      block.Miner,
			LastActivity: time.Now(),
		}
		ap.selfishMiningDetector.suspiciousMiners[block.Miner] = behavior
	}
	
	behavior.BlocksProduced++
	behavior.LastActivity = time.Now()
	
	// Calculate orphan rate for this miner
	if behavior.BlocksProduced > 10 {
		orphanRate := float64(behavior.OrphansProduced) / float64(behavior.BlocksProduced)
		
		// High orphan rate is suspicious
		if orphanRate > ap.config.OrphanRateThreshold {
			behavior.SuspicionScore += 10
			
			// Alert if suspicion is high
			if behavior.SuspicionScore > 50 {
				ap.alertSelfishMining(behavior)
			}
		}
	}
}

// RecordOrphanBlock records an orphaned block
func (ap *AttackPrevention) RecordOrphanBlock(block *Block) {
	ap.selfishMiningDetector.mu.Lock()
	defer ap.selfishMiningDetector.mu.Unlock()
	
	orphan := &OrphanBlock{
		Height:    block.Height,
		Hash:      block.Hash,
		Miner:     block.Miner,
		Timestamp: time.Now(),
	}
	
	ap.selfishMiningDetector.orphanBlocks = append(
		ap.selfishMiningDetector.orphanBlocks,
		orphan,
	)
	
	// Update miner behavior
	if behavior, exists := ap.selfishMiningDetector.suspiciousMiners[block.Miner]; exists {
		behavior.OrphansProduced++
	}
	
	// Calculate global orphan rate
	ap.calculateOrphanRate()
}

// calculateOrphanRate calculates global orphan rate
func (ap *AttackPrevention) calculateOrphanRate() {
	if len(ap.selfishMiningDetector.orphanBlocks) == 0 {
		return
	}
	
	// Count orphans in last 1000 blocks
	recentOrphans := 0
	cutoff := time.Now().Add(-24 * time.Hour)
	
	for _, orphan := range ap.selfishMiningDetector.orphanBlocks {
		if orphan.Timestamp.After(cutoff) {
			recentOrphans++
		}
	}
	
	// Estimate total blocks (simplified)
	estimatedBlocks := 1000
	ap.selfishMiningDetector.orphanRate = float64(recentOrphans) / float64(estimatedBlocks)
}

// alertSelfishMining raises an alert for selfish mining
func (ap *AttackPrevention) alertSelfishMining(behavior *MinerBehavior) {
	// Log alert
	fmt.Printf("⚠️  ALERT: Potential selfish mining detected from miner %s\n", 
		behavior.Address)
	fmt.Printf("   Blocks: %d, Orphans: %d, Suspicion Score: %.2f\n",
		behavior.BlocksProduced, behavior.OrphansProduced, behavior.SuspicionScore)
	
	// Trigger monitoring system
	// This should integrate with alerting system
}

// analyzeHashRate monitors network hash rate for anomalies
func (ap *AttackPrevention) analyzeHashRate(block *Block) {
	if !ap.config.EnableHashRateMonitoring {
		return
	}
	
	ap.hashRateMonitor.mu.Lock()
	defer ap.hashRateMonitor.mu.Unlock()
	
	// Calculate hash rate from difficulty and block time
	hashRate := ap.estimateHashRate(block)
	
	sample := HashRateSample{
		Timestamp:   time.Now(),
		HashRate:    hashRate,
		BlockHeight: block.Height,
	}
	
	ap.hashRateMonitor.samples = append(ap.hashRateMonitor.samples, sample)
	
	// Keep only recent samples
	if len(ap.hashRateMonitor.samples) > ap.hashRateMonitor.windowSize {
		ap.hashRateMonitor.samples = ap.hashRateMonitor.samples[1:]
	}
	
	// Detect sudden hash rate changes (potential 51% attack)
	if len(ap.hashRateMonitor.samples) >= 2 {
		prevHashRate := ap.hashRateMonitor.samples[len(ap.hashRateMonitor.samples)-2].HashRate
		currentHashRate := hashRate
		
		// Calculate percentage change
		diff := new(big.Float).SetInt(new(big.Int).Sub(currentHashRate, prevHashRate))
		prevFloat := new(big.Float).SetInt(prevHashRate)
		changePercent, _ := new(big.Float).Quo(diff, prevFloat).Float64()
		
		// Alert if change is suspicious
		if changePercent > ap.config.SuspiciousHashRateChange {
			ap.alertHashRateAnomaly(changePercent)
		}
	}
}

// estimateHashRate estimates network hash rate
func (ap *AttackPrevention) estimateHashRate(block *Block) *big.Int {
	// Simplified hash rate estimation
	// Hash rate ≈ Difficulty / Block Time
	difficulty := new(big.Int).SetUint64(uint64(block.Target))
	blockTime := big.NewInt(15) // 15 second target
	
	hashRate := new(big.Int).Div(difficulty, blockTime)
	return hashRate
}

// alertHashRateAnomaly raises an alert for hash rate anomalies
func (ap *AttackPrevention) alertHashRateAnomaly(changePercent float64) {
	fmt.Printf("⚠️  ALERT: Suspicious hash rate change: %.2f%%\n", changePercent*100)
	fmt.Println("   Possible 51% attack or major miner joining/leaving network")
}

// DetectLongRangeAttack detects long-range attacks
func (ap *AttackPrevention) DetectLongRangeAttack(chain []*Block) bool {
	// Check if chain attempts to rewrite history beyond checkpoints
	for _, block := range chain {
		if err := ap.validateAgainstCheckpoints(block); err != nil {
			fmt.Printf("⚠️  ALERT: Long-range attack detected at height %d\n", block.Height)
			return true
		}
	}
	
	return false
}

// GetAttackStatistics returns current attack statistics
func (ap *AttackPrevention) GetAttackStatistics() map[string]interface{} {
	ap.mu.RLock()
	defer ap.mu.RUnlock()
	
	return map[string]interface{}{
		"orphan_rate":        ap.selfishMiningDetector.orphanRate,
		"suspicious_miners":  len(ap.selfishMiningDetector.suspiciousMiners),
		"checkpoints":        len(ap.checkpointSystem.checkpoints),
		"hash_rate_samples":  len(ap.hashRateMonitor.samples),
	}
}

// Block represents a blockchain block (placeholder)
type Block struct {
	Height    uint64
	Hash      string
	Timestamp int64
	Target    uint32
	Miner     string
}
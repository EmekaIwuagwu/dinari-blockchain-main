// internal/consensus/enhanced_pow.go
// Enhanced Proof of Work with finality guarantees for high-value transactions

package consensus

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/EmekaIwuagwu/dinari-blockchain/internal/types"
)

const (
	// Finality parameters
	ConfirmationDepth       = 12 // Blocks needed for finality
	HighValueConfirmations  = 24 // Extra confirmations for high-value tx
	MaxOrphanBlocks         = 100
	
	// Fork handling
	MaxForkLength          = 50
	ForkResolutionTimeout  = 30 * time.Minute
	
	// Checkpointing
	CheckpointInterval     = 1000 // Every 1000 blocks
	MinCheckpointAge       = 24 * time.Hour
)

var (
	ErrInvalidBlock          = errors.New("invalid block")
	ErrInvalidProofOfWork    = errors.New("invalid proof of work")
	ErrBlockTooOld           = errors.New("block too old")
	ErrOrphanBlock           = errors.New("orphan block")
	ErrForkTooLong           = errors.New("fork exceeds maximum length")
	ErrCheckpointViolation   = errors.New("block violates checkpoint")
)

type EnhancedPoW struct {
	currentDifficulty    *big.Int
	difficultyAdjustment *DifficultyAdjuster
	finalityTracker      *FinalityTracker
	checkpointManager    *CheckpointManager
	forkResolver         *ForkResolver
	orphanPool           *OrphanPool
	mu                   sync.RWMutex
}

type DifficultyAdjuster struct {
	targetBlockTime      time.Duration
	adjustmentInterval   int64
	minDifficulty        *big.Int
	maxDifficulty        *big.Int
	recentBlockTimes     []time.Duration
	mu                   sync.RWMutex
}

type FinalityTracker struct {
	finalizedBlocks      map[string]*FinalizedBlock
	pendingBlocks        map[string]*PendingBlock
	highValueTxTracker   map[string]*HighValueTxStatus
	mu                   sync.RWMutex
}

type FinalizedBlock struct {
	Hash            string
	Height          uint64
	FinalizedAt     time.Time
	ConfirmationCount int
}

type PendingBlock struct {
	Hash               string
	Height             uint64
	ConfirmationCount  int
	FirstSeen          time.Time
}

type HighValueTxStatus struct {
	TxHash             string
	BlockHash          string
	RequiredConf       int
	CurrentConf        int
	Finalized          bool
}

type CheckpointManager struct {
	checkpoints        map[uint64]Checkpoint
	lastCheckpoint     *Checkpoint
	mu                 sync.RWMutex
}

type Checkpoint struct {
	Height     uint64
	BlockHash  string
	Timestamp  time.Time
	Signatures []CheckpointSignature
}

type CheckpointSignature struct {
	ValidatorID string
	Signature   []byte
	PublicKey   []byte
}

type ForkResolver struct {
	activeForks        map[string]*Fork
	mainChainTip       string
	mu                 sync.RWMutex
}

type Fork struct {
	ID              string
	StartHeight     uint64
	CurrentHeight   uint64
	Blocks          []*types.Block
	TotalWork       *big.Int
	CreatedAt       time.Time
}

type OrphanPool struct {
	orphans            map[string]*types.Block
	orphansByParent    map[string][]string
	mu                 sync.RWMutex
}

func NewEnhancedPoW(initialDifficulty *big.Int) *EnhancedPoW {
	return &EnhancedPoW{
		currentDifficulty:    initialDifficulty,
		difficultyAdjustment: NewDifficultyAdjuster(),
		finalityTracker:      NewFinalityTracker(),
		checkpointManager:    NewCheckpointManager(),
		forkResolver:         NewForkResolver(),
		orphanPool:           NewOrphanPool(),
	}
}

func NewDifficultyAdjuster() *DifficultyAdjuster {
	minDiff := new(big.Int)
	minDiff.SetString("00000000FFFF0000000000000000000000000000000000000000000000000000", 16)
	
	maxDiff := new(big.Int)
	maxDiff.SetString("0000000000000001000000000000000000000000000000000000000000000000", 16)

	return &DifficultyAdjuster{
		targetBlockTime:    15 * time.Second,
		adjustmentInterval: 120,
		minDifficulty:      minDiff,
		maxDifficulty:      maxDiff,
		recentBlockTimes:   make([]time.Duration, 0, 120),
	}
}

func NewFinalityTracker() *FinalityTracker {
	return &FinalityTracker{
		finalizedBlocks:    make(map[string]*FinalizedBlock),
		pendingBlocks:      make(map[string]*PendingBlock),
		highValueTxTracker: make(map[string]*HighValueTxStatus),
	}
}

func NewCheckpointManager() *CheckpointManager {
	return &CheckpointManager{
		checkpoints: make(map[uint64]Checkpoint),
	}
}

func NewForkResolver() *ForkResolver {
	return &ForkResolver{
		activeForks: make(map[string]*Fork),
	}
}

func NewOrphanPool() *OrphanPool {
	return &OrphanPool{
		orphans:         make(map[string]*types.Block),
		orphansByParent: make(map[string][]string),
	}
}

func (epow *EnhancedPoW) ValidateBlock(block *types.Block, parentBlock *types.Block) error {
	epow.mu.RLock()
	defer epow.mu.RUnlock()

	if err := epow.validateBasicStructure(block); err != nil {
		return err
	}

	if err := epow.validateProofOfWork(block); err != nil {
		return err
	}

	if parentBlock != nil {
		if err := epow.validateParentLink(block, parentBlock); err != nil {
			return err
		}
	}

	if err := epow.checkpointManager.ValidateAgainstCheckpoint(block); err != nil {
		return err
	}

	return nil
}

func (epow *EnhancedPoW) validateBasicStructure(block *types.Block) error {
	if block == nil {
		return ErrInvalidBlock
	}

	if block.Height == 0 && block.PreviousHash != "0000000000000000000000000000000000000000000000000000000000000000" {
		return errors.New("genesis block must have zero previous hash")
	}

	if block.Timestamp.After(time.Now().Add(2 * time.Hour)) {
		return errors.New("block timestamp too far in future")
	}

	if len(block.Transactions) == 0 {
		return errors.New("block must contain at least coinbase transaction")
	}

	return nil
}

func (epow *EnhancedPoW) validateProofOfWork(block *types.Block) error {
	target := epow.calculateTarget(epow.currentDifficulty)

	blockHash := epow.calculateBlockHash(block)
	
	hashInt := new(big.Int)
	hashInt.SetBytes(blockHash)

	if hashInt.Cmp(target) > 0 {
		return ErrInvalidProofOfWork
	}

	return nil
}

func (epow *EnhancedPoW) calculateBlockHash(block *types.Block) []byte {
	data := []byte{}
	
	data = append(data, []byte(block.PreviousHash)...)
	
	heightBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(heightBytes, block.Height)
	data = append(data, heightBytes...)
	
	timestampBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timestampBytes, uint64(block.Timestamp.Unix()))
	data = append(data, timestampBytes...)
	
	data = append(data, []byte(block.MerkleRoot)...)
	
	nonceBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(nonceBytes, block.Nonce)
	data = append(data, nonceBytes...)
	
	difficultyBytes := epow.currentDifficulty.Bytes()
	data = append(data, difficultyBytes...)

	firstHash := sha256.Sum256(data)
	secondHash := sha256.Sum256(firstHash[:])
	
	return secondHash[:]
}

func (epow *EnhancedPoW) calculateTarget(difficulty *big.Int) *big.Int {
	maxTarget := new(big.Int)
	maxTarget.SetString("00000000FFFF0000000000000000000000000000000000000000000000000000", 16)

	target := new(big.Int).Div(maxTarget, difficulty)
	return target
}

func (epow *EnhancedPoW) validateParentLink(block, parent *types.Block) error {
	if block.Height != parent.Height+1 {
		return errors.New("invalid block height")
	}

	if block.PreviousHash != parent.Hash {
		return errors.New("previous hash mismatch")
	}

	minTimestamp := parent.Timestamp.Add(1 * time.Second)
	if block.Timestamp.Before(minTimestamp) {
		return errors.New("block timestamp too early")
	}

	return nil
}

func (epow *EnhancedPoW) ProcessBlock(block *types.Block, parentBlock *types.Block) error {
	if err := epow.ValidateBlock(block, parentBlock); err != nil {
		if errors.Is(err, ErrOrphanBlock) {
			return epow.orphanPool.AddOrphan(block)
		}
		return err
	}

	epow.finalityTracker.AddPendingBlock(block)

	if block.Height%CheckpointInterval == 0 {
		epow.checkpointManager.ProposeCheckpoint(block)
	}

	epow.difficultyAdjustment.RecordBlockTime(time.Since(parentBlock.Timestamp))

	if block.Height%epow.difficultyAdjustment.adjustmentInterval == 0 {
		newDifficulty := epow.difficultyAdjustment.AdjustDifficulty(epow.currentDifficulty)
		epow.updateDifficulty(newDifficulty)
	}

	return nil
}

func (epow *EnhancedPoW) UpdateConfirmations(blockHash string) {
	epow.finalityTracker.IncrementConfirmations(blockHash)
}

func (epow *EnhancedPoW) IsFinalized(blockHash string) bool {
	return epow.finalityTracker.IsFinalized(blockHash)
}

func (epow *EnhancedPoW) GetRequiredConfirmations(isHighValue bool) int {
	if isHighValue {
		return HighValueConfirmations
	}
	return ConfirmationDepth
}

func (epow *EnhancedPoW) updateDifficulty(newDifficulty *big.Int) {
	epow.mu.Lock()
	defer epow.mu.Unlock()

	epow.currentDifficulty = newDifficulty
}

func (epow *EnhancedPoW) GetCurrentDifficulty() *big.Int {
	epow.mu.RLock()
	defer epow.mu.RUnlock()

	return new(big.Int).Set(epow.currentDifficulty)
}

func (da *DifficultyAdjuster) RecordBlockTime(duration time.Duration) {
	da.mu.Lock()
	defer da.mu.Unlock()

	da.recentBlockTimes = append(da.recentBlockTimes, duration)

	if len(da.recentBlockTimes) > int(da.adjustmentInterval) {
		da.recentBlockTimes = da.recentBlockTimes[1:]
	}
}

func (da *DifficultyAdjuster) AdjustDifficulty(currentDifficulty *big.Int) *big.Int {
	da.mu.RLock()
	defer da.mu.RUnlock()

	if len(da.recentBlockTimes) < int(da.adjustmentInterval) {
		return currentDifficulty
	}

	var totalTime time.Duration
	for _, duration := range da.recentBlockTimes {
		totalTime += duration
	}

	averageTime := totalTime / time.Duration(len(da.recentBlockTimes))
	
	ratio := float64(averageTime) / float64(da.targetBlockTime)

	newDifficulty := new(big.Int).Set(currentDifficulty)

	if ratio > 1.0 {
		adjustment := new(big.Int).Div(currentDifficulty, big.NewInt(int64(ratio*100)))
		newDifficulty.Sub(newDifficulty, adjustment)
	} else {
		adjustment := new(big.Int).Div(currentDifficulty, big.NewInt(int64((1/ratio)*100)))
		newDifficulty.Add(newDifficulty, adjustment)
	}

	if newDifficulty.Cmp(da.minDifficulty) < 0 {
		newDifficulty = da.minDifficulty
	}
	if newDifficulty.Cmp(da.maxDifficulty) > 0 {
		newDifficulty = da.maxDifficulty
	}

	return newDifficulty
}

func (ft *FinalityTracker) AddPendingBlock(block *types.Block) {
	ft.mu.Lock()
	defer ft.mu.Unlock()

	pending := &PendingBlock{
		Hash:              block.Hash,
		Height:            block.Height,
		ConfirmationCount: 0,
		FirstSeen:         time.Now(),
	}

	ft.pendingBlocks[block.Hash] = pending
}

func (ft *FinalityTracker) IncrementConfirmations(blockHash string) {
	ft.mu.Lock()
	defer ft.mu.Unlock()

	pending, exists := ft.pendingBlocks[blockHash]
	if !exists {
		return
	}

	pending.ConfirmationCount++

	if pending.ConfirmationCount >= ConfirmationDepth {
		finalized := &FinalizedBlock{
			Hash:              pending.Hash,
			Height:            pending.Height,
			FinalizedAt:       time.Now(),
			ConfirmationCount: pending.ConfirmationCount,
		}

		ft.finalizedBlocks[blockHash] = finalized
		delete(ft.pendingBlocks, blockHash)
	}
}

func (ft *FinalityTracker) IsFinalized(blockHash string) bool {
	ft.mu.RLock()
	defer ft.mu.RUnlock()

	_, finalized := ft.finalizedBlocks[blockHash]
	return finalized
}

func (ft *FinalityTracker) TrackHighValueTx(txHash, blockHash string, isHighValue bool) {
	ft.mu.Lock()
	defer ft.mu.Unlock()

	requiredConf := ConfirmationDepth
	if isHighValue {
		requiredConf = HighValueConfirmations
	}

	status := &HighValueTxStatus{
		TxHash:       txHash,
		BlockHash:    blockHash,
		RequiredConf: requiredConf,
		CurrentConf:  0,
		Finalized:    false,
	}

	ft.highValueTxTracker[txHash] = status
}

func (cm *CheckpointManager) ValidateAgainstCheckpoint(block *types.Block) error {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	checkpoint, exists := cm.checkpoints[block.Height]
	if !exists {
		return nil
	}

	if block.Hash != checkpoint.BlockHash {
		return ErrCheckpointViolation
	}

	return nil
}

func (cm *CheckpointManager) ProposeCheckpoint(block *types.Block) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	checkpoint := Checkpoint{
		Height:     block.Height,
		BlockHash:  block.Hash,
		Timestamp:  time.Now(),
		Signatures: make([]CheckpointSignature, 0),
	}

	cm.checkpoints[block.Height] = checkpoint
	cm.lastCheckpoint = &checkpoint
}

func (cm *CheckpointManager) AddCheckpointSignature(height uint64, sig CheckpointSignature) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	checkpoint, exists := cm.checkpoints[height]
	if !exists {
		return errors.New("checkpoint not found")
	}

	checkpoint.Signatures = append(checkpoint.Signatures, sig)
	cm.checkpoints[height] = checkpoint

	return nil
}

func (fr *ForkResolver) DetectFork(block *types.Block, mainChainTip string) bool {
	fr.mu.RLock()
	defer fr.mu.RUnlock()

	return block.PreviousHash != mainChainTip
}

func (fr *ForkResolver) ResolveFork() (string, error) {
	fr.mu.Lock()
	defer fr.mu.Unlock()

	var longestFork *Fork
	maxWork := new(big.Int)

	for _, fork := range fr.activeForks {
		if fork.TotalWork.Cmp(maxWork) > 0 {
			maxWork = fork.TotalWork
			longestFork = fork
		}
	}

	if longestFork == nil {
		return "", errors.New("no fork to resolve")
	}

	return longestFork.ID, nil
}

func (op *OrphanPool) AddOrphan(block *types.Block) error {
	op.mu.Lock()
	defer op.mu.Unlock()

	if len(op.orphans) >= MaxOrphanBlocks {
		return errors.New("orphan pool full")
	}

	op.orphans[block.Hash] = block
	
	op.orphansByParent[block.PreviousHash] = append(
		op.orphansByParent[block.PreviousHash],
		block.Hash,
	)

	return nil
}

func (op *OrphanPool) GetOrphansByParent(parentHash string) []*types.Block {
	op.mu.RLock()
	defer op.mu.RUnlock()

	orphanHashes := op.orphansByParent[parentHash]
	orphans := make([]*types.Block, 0, len(orphanHashes))

	for _, hash := range orphanHashes {
		if block, exists := op.orphans[hash]; exists {
			orphans = append(orphans, block)
		}
	}

	return orphans
}

func (op *OrphanPool) RemoveOrphan(blockHash string) {
	op.mu.Lock()
	defer op.mu.Unlock()

	block, exists := op.orphans[blockHash]
	if !exists {
		return
	}

	delete(op.orphans, blockHash)

	parentOrphans := op.orphansByParent[block.PreviousHash]
	for i, hash := range parentOrphans {
		if hash == blockHash {
			op.orphansByParent[block.PreviousHash] = append(
				parentOrphans[:i],
				parentOrphans[i+1:]...,
			)
			break
		}
	}
}
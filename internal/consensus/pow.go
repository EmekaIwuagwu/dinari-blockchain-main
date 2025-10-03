package consensus

import (
	"crypto/sha256"
	"math/big"

	"github.com/EmekaIwuagwu/dinari-blockchain/internal/types"
)

// ProofOfWork implements the Proof of Work consensus algorithm
type ProofOfWork struct {
	targetBlockTime int64 // Target block time in seconds
}

// NewProofOfWork creates a new PoW instance
func NewProofOfWork(targetBlockTime int64) *ProofOfWork {
	return &ProofOfWork{
		targetBlockTime: targetBlockTime,
	}
}

// ValidateProofOfWork verifies that a block satisfies the PoW requirement
func (pow *ProofOfWork) ValidateProofOfWork(block *types.Block) bool {
	// Compute block hash
	hash := ComputeBlockHash(block.Header)

	// Convert hash to big.Int
	hashInt := new(big.Int).SetBytes(hash[:])

	// Convert difficulty to target
	target := DifficultyToTarget(block.Header.Difficulty)

	// Check: hash < target
	return hashInt.Cmp(target) < 0
}

// ComputeBlockHash calculates the double SHA-256 hash of a block header
func ComputeBlockHash(header *types.BlockHeader) [32]byte {
	// Serialize header
	data := serializeHeaderForHashing(header)

	// Double SHA-256
	first := sha256.Sum256(data)
	second := sha256.Sum256(first[:])

	return second
}

// serializeHeaderForHashing creates the canonical byte representation for hashing
func serializeHeaderForHashing(header *types.BlockHeader) []byte {
	// This should match the SerializeHeader method in types.Block
	var result []byte

	// Add number (8 bytes)
	numBytes := make([]byte, 8)
	for i := uint(0); i < 8; i++ {
		numBytes[7-i] = byte(header.Number >> (i * 8))
	}
	result = append(result, numBytes...)

	// Add parent hash (32 bytes)
	result = append(result, header.ParentHash[:]...)

	// Add timestamp (8 bytes)
	tsBytes := make([]byte, 8)
	for i := uint(0); i < 8; i++ {
		tsBytes[7-i] = byte(header.Timestamp >> (i * 8))
	}
	result = append(result, tsBytes...)

	// Add difficulty (32 bytes, padded)
	diffBytes := header.Difficulty.Bytes()
	diffPadded := make([]byte, 32)
	copy(diffPadded[32-len(diffBytes):], diffBytes)
	result = append(result, diffPadded...)

	// Add nonce (8 bytes)
	nonceBytes := make([]byte, 8)
	for i := uint(0); i < 8; i++ {
		nonceBytes[7-i] = byte(header.Nonce >> (i * 8))
	}
	result = append(result, nonceBytes...)

	// Add merkle root (32 bytes)
	result = append(result, header.MerkleRoot[:]...)

	// Add state root (32 bytes)
	result = append(result, header.StateRoot[:]...)

	// Add miner address hash (32 bytes)
	minerHash := sha256.Sum256([]byte(header.MinerAddress))
	result = append(result, minerHash[:]...)

	// Add tx count (4 bytes)
	txCountBytes := make([]byte, 4)
	for i := uint(0); i < 4; i++ {
		txCountBytes[3-i] = byte(header.TxCount >> (i * 8))
	}
	result = append(result, txCountBytes...)

	return result
}

// DifficultyToTarget converts difficulty to target threshold
// Target = MAX_TARGET / difficulty
// Where MAX_TARGET = 2^256 - 1
func DifficultyToTarget(difficulty *big.Int) *big.Int {
	if difficulty.Sign() <= 0 {
		// Invalid difficulty, return max target
		maxTarget := new(big.Int).Lsh(big.NewInt(1), 256)
		maxTarget.Sub(maxTarget, big.NewInt(1))
		return maxTarget
	}

	// Calculate: target = (2^256 - 1) / difficulty
	maxTarget := new(big.Int).Lsh(big.NewInt(1), 256)
	maxTarget.Sub(maxTarget, big.NewInt(1))

	target := new(big.Int).Div(maxTarget, difficulty)
	return target
}

// TargetToDifficulty converts target to difficulty
func TargetToDifficulty(target *big.Int) *big.Int {
	if target.Sign() <= 0 {
		return big.NewInt(1)
	}

	// Calculate: difficulty = (2^256 - 1) / target
	maxTarget := new(big.Int).Lsh(big.NewInt(1), 256)
	maxTarget.Sub(maxTarget, big.NewInt(1))

	difficulty := new(big.Int).Div(maxTarget, target)
	return difficulty
}

// MineBlock attempts to find a valid nonce for the block
// This is the actual mining process
func (pow *ProofOfWork) MineBlock(block *types.Block, stopChan <-chan struct{}) (uint64, bool) {
	target := DifficultyToTarget(block.Header.Difficulty)
	var nonce uint64

	for {
		// Check if mining should stop
		select {
		case <-stopChan:
			return 0, false
		default:
		}

		// Set nonce
		block.Header.Nonce = nonce

		// Compute hash
		hash := ComputeBlockHash(block.Header)
		hashInt := new(big.Int).SetBytes(hash[:])

		// Check if valid
		if hashInt.Cmp(target) < 0 {
			block.Hash = hash
			return nonce, true
		}

		nonce++

		// Prevent overflow (extremely unlikely but safe)
		if nonce == 0 {
			return 0, false
		}
	}
}

// VerifyWork verifies that the work meets the difficulty requirement
func (pow *ProofOfWork) VerifyWork(hash [32]byte, difficulty *big.Int) bool {
	hashInt := new(big.Int).SetBytes(hash[:])
	target := DifficultyToTarget(difficulty)
	return hashInt.Cmp(target) < 0
}

// GetHashRate estimates the hash rate required for a given difficulty
func (pow *ProofOfWork) GetHashRate(difficulty *big.Int) *big.Int {
	// Estimated hashes per block = 2^256 / (difficulty * 2^32)
	// This is a rough approximation
	expectedHashes := new(big.Int).Lsh(big.NewInt(1), 224) // 2^224
	expectedHashes.Div(expectedHashes, difficulty)
	return expectedHashes
}

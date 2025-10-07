package mempool

import (
	"math/big"
	"sort"

	"github.com/EmekaIwuagwu/dinari-blockchain/internal/types"
)

const (
	// BaseFee is the minimum base fee for any transaction
	BaseFee = 1000 // 0.00001 DNT (1000 satoshis)

	// FeePerKB is the fee per kilobyte of transaction size
	FeePerKB = 100000 // 0.001 DNT per KB
)

// CalculateMinimumFee calculates the minimum fee required for a transaction
func CalculateMinimumFee(tx *types.Transaction) *big.Int {
	// Calculate size in KB
	sizeBytes := float64(tx.Size())
	sizeKB := sizeBytes / 1024.0

	// Calculate size-based fee
	sizeFee := int64(float64(FeePerKB) * sizeKB)

	// Total fee = base fee + size fee
	totalFee := BaseFee + sizeFee

	return big.NewInt(totalFee)
}

// sortByPriority sorts transaction entries by priority
// Priority: highest fee per byte first, then oldest first
func sortByPriority(entries []*MempoolTx) {
	sort.Slice(entries, func(i, j int) bool {
		// Compare fee per byte
		if entries[i].Tx.FeePerByte != entries[j].Tx.FeePerByte {
			return entries[i].Tx.FeePerByte.Cmp(entries[j].Tx.FeePerByte) > 0
		}

		// If equal fee, oldest first
		return entries[i].AddedAt.Before(entries[j].AddedAt)
	})
}

// CanReplace checks if a new transaction can replace an old one via RBF
func CanReplace(oldTx, newTx *types.Transaction) bool {
	// Must have same sender and nonce
	if oldTx.From != newTx.From || oldTx.Nonce != newTx.Nonce {
		return false
	}

	// New fee must be at least 25% higher
	minNewFee := new(big.Int).Mul(oldTx.FeeDNT, big.NewInt(125))
	minNewFee.Div(minNewFee, big.NewInt(100))

	return newTx.FeeDNT.Cmp(minNewFee) >= 0
}

// EstimateFeeForPriority estimates the fee needed for a given priority level
func EstimateFeeForPriority(txSize int, priorityLevel string) *big.Int {
	baseFee := CalculateMinimumFee(&types.Transaction{})

	switch priorityLevel {
	case "low":
		// Just above minimum
		return new(big.Int).Mul(baseFee, big.NewInt(110))
	case "medium":
		// 1.5x minimum
		return new(big.Int).Mul(baseFee, big.NewInt(150))
	case "high":
		// 2x minimum
		return new(big.Int).Mul(baseFee, big.NewInt(200))
	default:
		return baseFee
	}
}

package mempool

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"sync"
	"time"
)

// MEVProtection provides protection against MEV attacks
type MEVProtection struct {
	// Fair ordering mechanism
	orderingStrategy OrderingStrategy

	// Transaction commitments
	commitments map[string]*TxCommitment

	// VRF for random ordering
	vrfKey []byte

	// Configuration
	config *MEVConfig

	mu sync.RWMutex
}

// MEVConfig contains MEV protection parameters
type MEVConfig struct {
	EnableFairOrdering     bool
	EnableCommitReveal     bool
	CommitmentWindow       time.Duration
	RevealWindow           time.Duration
	EnableVRF              bool
	EnableBatchAuction     bool
	BatchInterval          time.Duration
	MaxPriorityFeeVariance float64
}

// OrderingStrategy defines transaction ordering approach
type OrderingStrategy int

const (
	FIFO         OrderingStrategy = iota // First In First Out
	FairRandom                           // Random with VRF
	BatchAuction                         // Batch auctions
	CommitReveal                         // Commit-reveal scheme
)

// TxCommitment represents a committed transaction
type TxCommitment struct {
	Commitment []byte
	Timestamp  time.Time
	Revealed   bool
	TxData     []byte
	Salt       []byte
}

// TransactionBatch represents a batch for fair ordering
type TransactionBatch struct {
	ID           string
	Transactions []*PendingTransaction
	CreatedAt    time.Time
	SealedAt     time.Time
	RandomSeed   []byte
	Sealed       bool
}

// PendingTransaction represents a transaction pending ordering
type PendingTransaction struct {
	Hash      string
	Data      []byte
	GasPrice  *big.Int
	Timestamp time.Time
	Priority  int
}

// NewMEVProtection creates a new MEV protection system
func NewMEVProtection(config *MEVConfig) (*MEVProtection, error) {
	mev := &MEVProtection{
		commitments:      make(map[string]*TxCommitment),
		orderingStrategy: FIFO,
		config:           config,
	}

	// Generate VRF key if enabled
	if config.EnableVRF {
		vrfKey := make([]byte, 32)
		if _, err := rand.Read(vrfKey); err != nil {
			return nil, fmt.Errorf("failed to generate VRF key: %w", err)
		}
		mev.vrfKey = vrfKey
	}

	// Determine ordering strategy
	if config.EnableBatchAuction {
		mev.orderingStrategy = BatchAuction
	} else if config.EnableCommitReveal {
		mev.orderingStrategy = CommitReveal
	} else if config.EnableVRF {
		mev.orderingStrategy = FairRandom
	}

	return mev, nil
}

// OrderTransactions orders transactions using the configured strategy
func (mev *MEVProtection) OrderTransactions(txs []*PendingTransaction) ([]*PendingTransaction, error) {
	switch mev.orderingStrategy {
	case FIFO:
		return mev.orderFIFO(txs), nil
	case FairRandom:
		return mev.orderFairRandom(txs)
	case BatchAuction:
		return mev.orderBatchAuction(txs), nil
	case CommitReveal:
		return mev.orderCommitReveal(txs)
	default:
		return txs, nil
	}
}

// orderFIFO orders transactions by timestamp (simplest, but MEV vulnerable)
func (mev *MEVProtection) orderFIFO(txs []*PendingTransaction) []*PendingTransaction {
	ordered := make([]*PendingTransaction, len(txs))
	copy(ordered, txs)

	sort.Slice(ordered, func(i, j int) bool {
		return ordered[i].Timestamp.Before(ordered[j].Timestamp)
	})

	return ordered
}

// orderFairRandom uses VRF for random but deterministic ordering
func (mev *MEVProtection) orderFairRandom(txs []*PendingTransaction) ([]*PendingTransaction, error) {
	if len(txs) == 0 {
		return txs, nil
	}

	// Generate VRF seed from block data
	seed := mev.generateVRFSeed()

	// Assign random priorities using VRF
	type txWithRand struct {
		tx      *PendingTransaction
		randVal *big.Int
	}

	rankedTxs := make([]txWithRand, len(txs))
	for i, tx := range txs {
		// Generate deterministic random value for this transaction
		randVal := mev.vrfDeterministicRandom(seed, []byte(tx.Hash))
		rankedTxs[i] = txWithRand{
			tx:      tx,
			randVal: randVal,
		}
	}

	// Sort by random value
	sort.Slice(rankedTxs, func(i, j int) bool {
		return rankedTxs[i].randVal.Cmp(rankedTxs[j].randVal) < 0
	})

	// Extract ordered transactions
	ordered := make([]*PendingTransaction, len(txs))
	for i, ranked := range rankedTxs {
		ordered[i] = ranked.tx
	}

	return ordered, nil
}

// orderBatchAuction implements batch auction ordering
func (mev *MEVProtection) orderBatchAuction(txs []*PendingTransaction) []*PendingTransaction {
	if len(txs) == 0 {
		return txs
	}

	// Group transactions by price bands to prevent extreme priority fee variance
	priceBands := mev.groupByPriceBands(txs)

	ordered := make([]*PendingTransaction, 0, len(txs))

	// Process each price band
	for _, band := range priceBands {
		// Within each band, use fair random ordering
		bandOrdered, _ := mev.orderFairRandom(band)
		ordered = append(ordered, bandOrdered...)
	}

	return ordered
}

// groupByPriceBands groups transactions by gas price bands
func (mev *MEVProtection) groupByPriceBands(txs []*PendingTransaction) [][]*PendingTransaction {
	if len(txs) == 0 {
		return nil
	}

	// Find min and max gas prices
	minPrice := new(big.Int).Set(txs[0].GasPrice)
	maxPrice := new(big.Int).Set(txs[0].GasPrice)

	for _, tx := range txs {
		if tx.GasPrice.Cmp(minPrice) < 0 {
			minPrice.Set(tx.GasPrice)
		}
		if tx.GasPrice.Cmp(maxPrice) > 0 {
			maxPrice.Set(tx.GasPrice)
		}
	}

	// Create price bands (e.g., 10% variance bands)
	variance := mev.config.MaxPriorityFeeVariance
	if variance == 0 {
		variance = 0.1 // Default 10%
	}

	// Simple banding: group transactions within variance threshold
	bands := make(map[int][]*PendingTransaction)

	for _, tx := range txs {
		// Calculate band index based on price
		bandIdx := mev.calculateBandIndex(tx.GasPrice, minPrice, maxPrice, variance)
		bands[bandIdx] = append(bands[bandIdx], tx)
	}

	// Convert map to slice and sort by band index
	bandIndices := make([]int, 0, len(bands))
	for idx := range bands {
		bandIndices = append(bandIndices, idx)
	}
	sort.Ints(bandIndices)

	result := make([][]*PendingTransaction, len(bandIndices))
	for i, idx := range bandIndices {
		result[i] = bands[idx]
	}

	return result
}

// calculateBandIndex calculates which price band a transaction belongs to
func (mev *MEVProtection) calculateBandIndex(price, minPrice, maxPrice *big.Int, variance float64) int {
	if maxPrice.Cmp(minPrice) == 0 {
		return 0
	}

	// Calculate price range
	priceRange := new(big.Int).Sub(maxPrice, minPrice)
	bandWidth := new(big.Int).Div(priceRange, big.NewInt(10)) // 10 bands

	// Calculate position in range
	position := new(big.Int).Sub(price, minPrice)

	// Determine band
	if bandWidth.Sign() == 0 {
		return 0
	}

	bandIdx := new(big.Int).Div(position, bandWidth)
	return int(bandIdx.Int64())
}

// orderCommitReveal implements commit-reveal ordering
func (mev *MEVProtection) orderCommitReveal(txs []*PendingTransaction) ([]*PendingTransaction, error) {
	mev.mu.RLock()
	defer mev.mu.RUnlock()

	// Only include transactions that have been revealed
	revealed := make([]*PendingTransaction, 0)
	for _, tx := range txs {
		if commitment, exists := mev.commitments[tx.Hash]; exists && commitment.Revealed {
			revealed = append(revealed, tx)
		}
	}

	// Order revealed transactions fairly
	return mev.orderFairRandom(revealed)
}

// CommitTransaction commits a transaction hash before revealing
func (mev *MEVProtection) CommitTransaction(txHash string, salt []byte) ([]byte, error) {
	mev.mu.Lock()
	defer mev.mu.Unlock()

	// Create commitment: H(txHash || salt)
	h := sha256.New()
	h.Write([]byte(txHash))
	h.Write(salt)
	commitment := h.Sum(nil)

	mev.commitments[txHash] = &TxCommitment{
		Commitment: commitment,
		Timestamp:  time.Now(),
		Salt:       salt,
		Revealed:   false,
	}

	return commitment, nil
}

// RevealTransaction reveals a committed transaction
func (mev *MEVProtection) RevealTransaction(txHash string, txData, salt []byte) error {
	mev.mu.Lock()
	defer mev.mu.Unlock()

	commitment, exists := mev.commitments[txHash]
	if !exists {
		return errors.New("no commitment found for transaction")
	}

	// Verify commitment timing
	if time.Since(commitment.Timestamp) < mev.config.CommitmentWindow {
		return errors.New("commitment window not elapsed")
	}

	if time.Since(commitment.Timestamp) > mev.config.CommitmentWindow+mev.config.RevealWindow {
		return errors.New("reveal window expired")
	}

	// Verify commitment matches
	h := sha256.New()
	h.Write([]byte(txHash))
	h.Write(salt)
	expectedCommitment := h.Sum(nil)

	if !bytesEqual(commitment.Commitment, expectedCommitment) {
		return errors.New("commitment mismatch")
	}

	// Mark as revealed
	commitment.Revealed = true
	commitment.TxData = txData

	return nil
}

// generateVRFSeed generates a VRF seed
func (mev *MEVProtection) generateVRFSeed() []byte {
	h := sha256.New()
	h.Write(mev.vrfKey)
	h.Write([]byte(time.Now().String()))
	return h.Sum(nil)
}

// vrfDeterministicRandom generates deterministic random value using VRF
func (mev *MEVProtection) vrfDeterministicRandom(seed, input []byte) *big.Int {
	h := sha256.New()
	h.Write(seed)
	h.Write(input)
	hash := h.Sum(nil)

	return new(big.Int).SetBytes(hash)
}

// DetectFrontRunning detects potential front-running attempts
func (mev *MEVProtection) DetectFrontRunning(txs []*PendingTransaction) []Alert {
	alerts := make([]Alert, 0)

	// Group transactions by recipient and amount patterns
	patterns := make(map[string][]*PendingTransaction)

	for _, tx := range txs {
		// Simple pattern: hash recipient address and amount range
		patternKey := mev.generatePatternKey(tx)
		patterns[patternKey] = append(patterns[patternKey], tx)
	}

	// Check for suspicious patterns
	for pattern, group := range patterns {
		if len(group) >= 2 {
			// Check if transactions are submitted in quick succession
			for i := 1; i < len(group); i++ {
				timeDiff := group[i].Timestamp.Sub(group[i-1].Timestamp)
				if timeDiff < 1*time.Second {
					// Potential front-running
					alerts = append(alerts, Alert{
						Type:      "POTENTIAL_FRONTRUNNING",
						Severity:  "HIGH",
						Message:   fmt.Sprintf("Similar transactions submitted within %v", timeDiff),
						Pattern:   pattern,
						TxHashes:  []string{group[i-1].Hash, group[i].Hash},
						Timestamp: time.Now(),
					})
				}
			}
		}
	}

	return alerts
}

// generatePatternKey generates a pattern key for transaction analysis
func (mev *MEVProtection) generatePatternKey(tx *PendingTransaction) string {
	// Simple implementation - can be enhanced
	h := sha256.New()
	h.Write(tx.Data[:10]) // First 10 bytes (simplified)
	return fmt.Sprintf("%x", h.Sum(nil)[:8])
}

// Alert represents a MEV-related alert
type Alert struct {
	Type      string
	Severity  string
	Message   string
	Pattern   string
	TxHashes  []string
	Timestamp time.Time
}

// CleanupExpiredCommitments removes expired commitments
func (mev *MEVProtection) CleanupExpiredCommitments() {
	mev.mu.Lock()
	defer mev.mu.Unlock()

	now := time.Now()
	maxAge := mev.config.CommitmentWindow + mev.config.RevealWindow + 1*time.Hour

	for hash, commitment := range mev.commitments {
		if now.Sub(commitment.Timestamp) > maxAge {
			delete(mev.commitments, hash)
		}
	}
}

// bytesEqual compares two byte slices in constant time
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}

	result := byte(0)
	for i := range a {
		result |= a[i] ^ b[i]
	}

	return result == 0
}

// GetStatistics returns MEV protection statistics
func (mev *MEVProtection) GetStatistics() map[string]interface{} {
	mev.mu.RLock()
	defer mev.mu.RUnlock()

	return map[string]interface{}{
		"ordering_strategy":     mev.orderingStrategy.String(),
		"pending_commitments":   len(mev.commitments),
		"vrf_enabled":           mev.config.EnableVRF,
		"batch_auction_enabled": mev.config.EnableBatchAuction,
	}
}

func (os OrderingStrategy) String() string {
	switch os {
	case FIFO:
		return "FIFO"
	case FairRandom:
		return "FairRandom"
	case BatchAuction:
		return "BatchAuction"
	case CommitReveal:
		return "CommitReveal"
	default:
		return "Unknown"
	}
}

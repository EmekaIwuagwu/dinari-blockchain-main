package mempool

import (
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/EmekaIwuagwu/dinari-blockchain/internal/core"
	"github.com/EmekaIwuagwu/dinari-blockchain/internal/types"
	"go.uber.org/zap"
)

const (
	// MaxMempoolSize is the maximum number of transactions in mempool
	MaxMempoolSize = 10000

	// TxTTL is the time-to-live for transactions in mempool (24 hours)
	TxTTL = 24 * time.Hour

	// MaxTxSize is the maximum size of a single transaction
	MaxTxSize = 32 * 1024 // 32KB
)

// Mempool manages pending transactions waiting to be mined
type Mempool struct {
	state  *core.State
	logger *zap.Logger

	// Transaction storage
	txs     map[[32]byte]*TxEntry
	byNonce map[string]map[uint64]*TxEntry // address -> nonce -> tx
	mu      sync.RWMutex

	// Metrics
	addedCount   uint64
	rejectedCount uint64
}

// TxEntry represents a transaction in the mempool
type TxEntry struct {
	Tx         *types.Transaction
	AddedAt    time.Time
	FeePerByte float64
}

// NewMempool creates a new mempool instance
func NewMempool(state *core.State, logger *zap.Logger) *Mempool {
	mp := &Mempool{
		state:   state,
		logger:  logger,
		txs:     make(map[[32]byte]*TxEntry),
		byNonce: make(map[string]map[uint64]*TxEntry),
	}

	// Start cleanup goroutine
	go mp.cleanupLoop()

	return mp
}

// AddTransaction adds a transaction to the mempool
func (mp *Mempool) AddTransaction(tx *types.Transaction) error {
	mp.mu.Lock()
	defer mp.mu.Unlock()

	// Check if already in mempool
	if _, exists := mp.txs[tx.Hash]; exists {
		mp.rejectedCount++
		return types.ErrTxAlreadyInMempool
	}

	if tx.IsMint() {
		// Skip balance checks for mint transactions
		// They create new tokens, so balance isn't checked
		entry := &TxEntry{
			Tx:         tx,
			AddedAt:    time.Now(),
			FeePerByte: 0, // Mint transactions have zero fee
		}
		
		mp.txs[tx.Hash] = entry
		mp.addedCount++
		
		return nil
	}

	// Check mempool size
	if len(mp.txs) >= MaxMempoolSize {
		mp.rejectedCount++
		return types.ErrMempoolFull
	}

	// Validate transaction
	if err := mp.validateTransaction(tx); err != nil {
		mp.rejectedCount++
		return err
	}

	// Calculate fee per byte
	feePerByte := tx.FeePerByte()

	// Check for replace-by-fee (RBF)
	if err := mp.checkReplaceByFee(tx); err != nil {
		mp.rejectedCount++
		return err
	}

	// Add to mempool
	entry := &TxEntry{
		Tx:         tx,
		AddedAt:    time.Now(),
		FeePerByte: feePerByte,
	}

	mp.txs[tx.Hash] = entry

	// Index by nonce
	if mp.byNonce[tx.From] == nil {
		mp.byNonce[tx.From] = make(map[uint64]*TxEntry)
	}
	mp.byNonce[tx.From][tx.Nonce] = entry

	mp.addedCount++

	mp.logger.Debug("Transaction added to mempool",
		zap.String("hash", fmt.Sprintf("%x", tx.Hash[:8])),
		zap.String("from", tx.From),
		zap.Uint64("nonce", tx.Nonce),
		zap.Float64("feePerByte", feePerByte))

	return nil
}

// validateTransaction performs validation on a transaction
func (mp *Mempool) validateTransaction(tx *types.Transaction) error {
	// Basic validation
	if err := tx.Validate(); err != nil {
		return err
	}

	// Size check
	if tx.Size() > MaxTxSize {
		return types.ErrTxTooLarge
	}

	// Get account state
	account, err := mp.state.GetAccount(tx.From)
	if err != nil {
		return err
	}

	// Nonce check (must equal current nonce)
	if tx.Nonce != account.Nonce {
		return types.ErrInvalidNonce
	}

	// Balance check for DNT (fee always paid in DNT)
	requiredDNT := new(big.Int).Set(tx.FeeDNT)
	if tx.TokenType == string(types.TokenDNT) {
		requiredDNT.Add(requiredDNT, tx.Amount)
	}
	if account.BalanceDNT.Cmp(requiredDNT) < 0 {
		return types.ErrInsufficientBalance
	}

	// Balance check for AFC (if transferring AFC)
	if tx.TokenType == string(types.TokenAFC) {
		if account.BalanceAFC.Cmp(tx.Amount) < 0 {
			return types.ErrInsufficientBalance
		}
	}

	// Fee check
	minFee := CalculateMinimumFee(tx)
	if tx.FeeDNT.Cmp(minFee) < 0 {
		return types.ErrFeeTooLow
	}

	return nil
}

// checkReplaceByFee checks if a transaction can replace an existing one
func (mp *Mempool) checkReplaceByFee(newTx *types.Transaction) error {
	// Check if there's an existing tx with same from + nonce
	if nonceMap, exists := mp.byNonce[newTx.From]; exists {
		if oldEntry, exists := nonceMap[newTx.Nonce]; exists {
			oldTx := oldEntry.Tx

			// Calculate minimum new fee (125% of old fee)
			minNewFee := new(big.Int).Mul(oldTx.FeeDNT, big.NewInt(125))
			minNewFee.Div(minNewFee, big.NewInt(100))

			if newTx.FeeDNT.Cmp(minNewFee) < 0 {
				return types.ErrRBFNotAllowed
			}

			// Remove old transaction
			delete(mp.txs, oldTx.Hash)

			mp.logger.Info("Transaction replaced (RBF)",
				zap.String("old", fmt.Sprintf("%x", oldTx.Hash[:8])),
				zap.String("new", fmt.Sprintf("%x", newTx.Hash[:8])))
		}
	}

	return nil
}

// RemoveTransaction removes a transaction from mempool
func (mp *Mempool) RemoveTransaction(txHash [32]byte) {
	mp.mu.Lock()
	defer mp.mu.Unlock()

	entry, exists := mp.txs[txHash]
	if !exists {
		return
	}

	tx := entry.Tx

	// Remove from main map
	delete(mp.txs, txHash)

	// Remove from nonce index
	if nonceMap, exists := mp.byNonce[tx.From]; exists {
		delete(nonceMap, tx.Nonce)
		if len(nonceMap) == 0 {
			delete(mp.byNonce, tx.From)
		}
	}
}

// GetTransaction retrieves a transaction by hash
func (mp *Mempool) GetTransaction(txHash [32]byte) (*types.Transaction, bool) {
	mp.mu.RLock()
	defer mp.mu.RUnlock()

	entry, exists := mp.txs[txHash]
	if !exists {
		return nil, false
	}

	return entry.Tx, true
}

// GetTransactions returns all transactions sorted by priority
func (mp *Mempool) GetTransactions(limit int) []*types.Transaction {
	mp.mu.RLock()
	defer mp.mu.RUnlock()

	// Collect all entries
	entries := make([]*TxEntry, 0, len(mp.txs))
	for _, entry := range mp.txs {
		entries = append(entries, entry)
	}

	// Sort by priority
	sortByPriority(entries)

	// Return up to limit
	if limit > 0 && limit < len(entries) {
		entries = entries[:limit]
	}

	// Extract transactions
	txs := make([]*types.Transaction, len(entries))
	for i, entry := range entries {
		txs[i] = entry.Tx
	}

	return txs
}

// Size returns the number of transactions in mempool
func (mp *Mempool) Size() int {
	mp.mu.RLock()
	defer mp.mu.RUnlock()
	return len(mp.txs)
}

// cleanupLoop periodically removes expired transactions
func (mp *Mempool) cleanupLoop() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		mp.cleanup()
	}
}

// cleanup removes expired transactions
func (mp *Mempool) cleanup() {
	mp.mu.Lock()
	defer mp.mu.Unlock()

	now := time.Now()
	expiredCount := 0

	for txHash, entry := range mp.txs {
		if now.Sub(entry.AddedAt) > TxTTL {
			tx := entry.Tx

			// Remove from maps
			delete(mp.txs, txHash)
			if nonceMap, exists := mp.byNonce[tx.From]; exists {
				delete(nonceMap, tx.Nonce)
				if len(nonceMap) == 0 {
					delete(mp.byNonce, tx.From)
				}
			}

			expiredCount++
		}
	}

	if expiredCount > 0 {
		mp.logger.Info("Cleaned up expired transactions",
			zap.Int("count", expiredCount),
			zap.Int("remaining", len(mp.txs)))
	}
}

// Clear removes all transactions from mempool
func (mp *Mempool) Clear() {
	mp.mu.Lock()
	defer mp.mu.Unlock()

	mp.txs = make(map[[32]byte]*TxEntry)
	mp.byNonce = make(map[string]map[uint64]*TxEntry)
}

// Stats returns mempool statistics
func (mp *Mempool) Stats() map[string]interface{} {
	mp.mu.RLock()
	defer mp.mu.RUnlock()

	return map[string]interface{}{
		"size":          len(mp.txs),
		"added":         mp.addedCount,
		"rejected":      mp.rejectedCount,
		"maxSize":       MaxMempoolSize,
		"utilizationPct": float64(len(mp.txs)) / float64(MaxMempoolSize) * 100,
	}
}

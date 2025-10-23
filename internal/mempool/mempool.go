package mempool

import (
	"container/heap"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"
)

const (
	// MaxMempoolSize is the maximum number of transactions in mempool
	MaxMempoolSize = 10000

	// MaxTxSize is the maximum size of a single transaction in bytes
	MaxTxSize = 100 * 1024 // 100KB

	// TxExpiryTime is how long a transaction stays in mempool
	TxExpiryTime = 24 * time.Hour

	// MaxTxPerAddress limits transactions per address to prevent spam
	MaxTxPerAddress = 100

	// MinFeePerByte is the minimum fee per byte (in smallest unit)
	MinFeePerByte = 1

	// EvictionBatchSize for batch eviction operations
	EvictionBatchSize = 100
)

var (
	ErrMempoolFull          = errors.New("mempool is full")
	ErrDuplicateTransaction = errors.New("duplicate transaction")
	ErrTransactionExpired   = errors.New("transaction expired")
	ErrInvalidNonce         = errors.New("invalid nonce: must be sequential")
	ErrFeeTooLow            = errors.New("fee too low")
	ErrTransactionTooLarge  = errors.New("transaction too large")
	ErrTooManyTxFromAddr    = errors.New("too many pending transactions from address")
	ErrReplaceByFeeTooLow   = errors.New("replacement fee too low (needs +10%)")
)

// Transaction represents a mempool transaction
type Transaction struct {
	Hash      string
	From      string
	To        string
	Amount    *big.Int
	TokenType string
	FeeDNT    *big.Int
	Nonce     uint64
	Timestamp int64
	Signature []byte
	PublicKey []byte
	Data      []byte
	Size      int // Transaction size in bytes

	// Mempool metadata
	AddedAt    time.Time
	FeePerByte *big.Int // For priority calculation
}

// MempoolTx wraps a transaction with mempool-specific data
type MempoolTx struct {
	Tx       *Transaction
	AddedAt  time.Time
	Priority *big.Int // Higher is better (fee per byte)
	Index    int      // Index in priority queue
}

// Mempool manages pending transactions
type Mempool struct {
	// Core data structures
	txByHash    map[string]*MempoolTx            // hash -> tx (O(1) lookup)
	txByAddress map[string]map[uint64]*MempoolTx // address -> nonce -> tx

	// Priority queue for mining selection
	priorityQueue *TxPriorityQueue

	// Configuration
	maxSize         int
	maxTxPerAddress int
	minFeePerByte   *big.Int
	txExpiryTime    time.Duration

	// Statistics
	stats MempoolStats

	// Thread safety
	mu sync.RWMutex

	// Eviction
	lastEviction time.Time
}

// MempoolStats tracks mempool statistics
type MempoolStats struct {
	TotalTxs          int
	TotalSize         int64
	TxsByAddress      map[string]int
	AcceptedCount     uint64
	RejectedCount     uint64
	EvictedCount      uint64
	ReplaceByFeeCount uint64
}

// NewMempool creates a new mempool
func NewMempool() *Mempool {
	pq := make(TxPriorityQueue, 0)
	heap.Init(&pq)

	return &Mempool{
		txByHash:        make(map[string]*MempoolTx),
		txByAddress:     make(map[string]map[uint64]*MempoolTx),
		priorityQueue:   &pq,
		maxSize:         MaxMempoolSize,
		maxTxPerAddress: MaxTxPerAddress,
		minFeePerByte:   big.NewInt(MinFeePerByte),
		txExpiryTime:    TxExpiryTime,
		stats: MempoolStats{
			TxsByAddress: make(map[string]int),
		},
		lastEviction: time.Now(),
	}
}

// AddTransaction adds a transaction to the mempool with validation
func (mp *Mempool) AddTransaction(tx *Transaction) error {
	// 1. Check if transaction is nil first
	if tx == nil {
		return errors.New("transaction cannot be nil")
	}

	// 2. CRITICAL FIX: Validate transaction size BEFORE any division operations
	if tx.Size <= 0 {
		mp.mu.Lock()
		mp.stats.RejectedCount++
		mp.mu.Unlock()
		return errors.New("transaction size must be greater than zero")
	}

	if tx.Size > MaxTxSize {
		mp.mu.Lock()
		mp.stats.RejectedCount++
		mp.mu.Unlock()
		return ErrTransactionTooLarge
	}

	mp.mu.Lock()
	defer mp.mu.Unlock()

	// 3. Check for duplicate
	if _, exists := mp.txByHash[tx.Hash]; exists {
		mp.stats.RejectedCount++
		return ErrDuplicateTransaction
	}

	// 4. Calculate fee per byte (NOW SAFE - tx.Size is guaranteed > 0)
	feePerByte := new(big.Int).Div(tx.FeeDNT, big.NewInt(int64(tx.Size)))
	if feePerByte.Cmp(mp.minFeePerByte) < 0 {
		mp.stats.RejectedCount++
		return ErrFeeTooLow
	}
	tx.FeePerByte = feePerByte

	// 5. Check address transaction limit
	addrTxs := mp.txByAddress[tx.From]
	if len(addrTxs) >= mp.maxTxPerAddress {
		// Try to evict lowest fee tx from same address
		if !mp.tryEvictLowFeeTx(tx.From, feePerByte) {
			mp.stats.RejectedCount++
			return ErrTooManyTxFromAddr
		}
	}

	// 6. Check for Replace-By-Fee (RBF)
	if existingTx, exists := mp.getTxByNonce(tx.From, tx.Nonce); exists {
		if err := mp.handleReplaceByFee(existingTx.Tx, tx); err != nil {
			mp.stats.RejectedCount++
			return err
		}
		// RBF successful, old tx already removed
	}

	// 7. Check if mempool is full
	if mp.stats.TotalTxs >= mp.maxSize {
		// Try to evict lowest priority transaction
		if !mp.evictLowestPriority(feePerByte) {
			mp.stats.RejectedCount++
			return ErrMempoolFull
		}
	}

	// 8. Add transaction to mempool
	mempoolTx := &MempoolTx{
		Tx:       tx,
		AddedAt:  time.Now(),
		Priority: feePerByte,
	}

	// Add to hash index
	mp.txByHash[tx.Hash] = mempoolTx

	// Add to address/nonce index
	if mp.txByAddress[tx.From] == nil {
		mp.txByAddress[tx.From] = make(map[uint64]*MempoolTx)
	}
	mp.txByAddress[tx.From][tx.Nonce] = mempoolTx

	// Add to priority queue
	heap.Push(mp.priorityQueue, mempoolTx)

	// Update statistics
	mp.stats.TotalTxs++
	mp.stats.TotalSize += int64(tx.Size)
	mp.stats.TxsByAddress[tx.From]++
	mp.stats.AcceptedCount++

	return nil
}

// RemoveTransaction removes a transaction from mempool (after mining)
func (mp *Mempool) RemoveTransaction(txHash string) error {
	mp.mu.Lock()
	defer mp.mu.Unlock()

	return mp.removeTransactionUnsafe(txHash)
}

// RemoveTransactions removes multiple transactions (batch operation)
func (mp *Mempool) RemoveTransactions(txHashes []string) error {
	mp.mu.Lock()
	defer mp.mu.Unlock()

	for _, hash := range txHashes {
		if err := mp.removeTransactionUnsafe(hash); err != nil {
			// Log but don't fail entire batch
			fmt.Printf("Warning: failed to remove tx %s: %v\n", hash, err)
		}
	}

	return nil
}

// GetTransaction retrieves a transaction by hash
func (mp *Mempool) GetTransaction(txHash string) (*Transaction, error) {
	mp.mu.RLock()
	defer mp.mu.RUnlock()

	mempoolTx, exists := mp.txByHash[txHash]
	if !exists {
		return nil, errors.New("transaction not found in mempool")
	}

	return mempoolTx.Tx, nil
}

// GetTransactionsByAddress retrieves all transactions from an address
func (mp *Mempool) GetTransactionsByAddress(address string) []*Transaction {
	mp.mu.RLock()
	defer mp.mu.RUnlock()

	txs := make([]*Transaction, 0)
	if addrTxs, exists := mp.txByAddress[address]; exists {
		for _, mempoolTx := range addrTxs {
			txs = append(txs, mempoolTx.Tx)
		}
	}

	return txs
}

// GetPendingTransactions returns transactions ordered by priority for mining
func (mp *Mempool) GetPendingTransactions(limit int) []*Transaction {
	mp.mu.RLock()
	defer mp.mu.RUnlock()

	if limit <= 0 || limit > mp.stats.TotalTxs {
		limit = mp.stats.TotalTxs
	}

	txs := make([]*Transaction, 0, limit)

	// Get transactions from priority queue (highest fee first)
	pqCopy := make(TxPriorityQueue, len(*mp.priorityQueue))
	copy(pqCopy, *mp.priorityQueue)

	for len(txs) < limit && len(pqCopy) > 0 {
		mempoolTx := heap.Pop(&pqCopy).(*MempoolTx)

		// Validate nonce ordering for this address
		if mp.isNonceValid(mempoolTx.Tx.From, mempoolTx.Tx.Nonce) {
			txs = append(txs, mempoolTx.Tx)
		}
	}

	return txs
}

// ValidateNonceSequence checks if transactions from an address have sequential nonces
func (mp *Mempool) ValidateNonceSequence(address string, currentNonce uint64) error {
	mp.mu.RLock()
	defer mp.mu.RUnlock()

	addrTxs, exists := mp.txByAddress[address]
	if !exists {
		return nil // No pending transactions
	}

	// Check that nonces are sequential starting from currentNonce
	expectedNonce := currentNonce
	for {
		if _, exists := addrTxs[expectedNonce]; !exists {
			break
		}
		expectedNonce++
	}

	// Check for gaps
	for nonce := range addrTxs {
		if nonce < currentNonce {
			return fmt.Errorf("nonce %d is below current nonce %d", nonce, currentNonce)
		}
		if nonce >= expectedNonce {
			return fmt.Errorf("nonce gap detected: expected %d, found %d", expectedNonce, nonce)
		}
	}

	return nil
}

// EvictExpiredTransactions removes transactions older than expiry time
func (mp *Mempool) EvictExpiredTransactions() int {
	mp.mu.Lock()
	defer mp.mu.Unlock()

	now := time.Now()
	evicted := 0

	// Find expired transactions
	expiredHashes := make([]string, 0)
	for hash, mempoolTx := range mp.txByHash {
		if now.Sub(mempoolTx.AddedAt) > mp.txExpiryTime {
			expiredHashes = append(expiredHashes, hash)
		}
	}

	// Remove expired transactions
	for _, hash := range expiredHashes {
		if err := mp.removeTransactionUnsafe(hash); err == nil {
			evicted++
			mp.stats.EvictedCount++
		}
	}

	mp.lastEviction = now

	return evicted
}

// GetStats returns mempool statistics
func (mp *Mempool) GetStats() MempoolStats {
	mp.mu.RLock()
	defer mp.mu.RUnlock()

	return mp.stats
}

// Size returns the number of transactions in mempool
func (mp *Mempool) Size() int {
	mp.mu.RLock()
	defer mp.mu.RUnlock()

	return mp.stats.TotalTxs
}

// Clear removes all transactions from mempool
func (mp *Mempool) Clear() {
	mp.mu.Lock()
	defer mp.mu.Unlock()

	mp.txByHash = make(map[string]*MempoolTx)
	mp.txByAddress = make(map[string]map[uint64]*MempoolTx)
	pq := make(TxPriorityQueue, 0)
	mp.priorityQueue = &pq
	heap.Init(mp.priorityQueue)

	mp.stats = MempoolStats{
		TxsByAddress:      make(map[string]int),
		AcceptedCount:     mp.stats.AcceptedCount,
		RejectedCount:     mp.stats.RejectedCount,
		EvictedCount:      mp.stats.EvictedCount,
		ReplaceByFeeCount: mp.stats.ReplaceByFeeCount,
	}
}

// Internal helper methods (must be called with lock held)

func (mp *Mempool) removeTransactionUnsafe(txHash string) error {
	mempoolTx, exists := mp.txByHash[txHash]
	if !exists {
		return errors.New("transaction not found")
	}

	tx := mempoolTx.Tx

	// Remove from hash index
	delete(mp.txByHash, txHash)

	// Remove from address/nonce index
	if addrTxs, exists := mp.txByAddress[tx.From]; exists {
		delete(addrTxs, tx.Nonce)
		if len(addrTxs) == 0 {
			delete(mp.txByAddress, tx.From)
		}
	}

	// Remove from priority queue (mark as removed, actual removal happens during heap operations)
	mempoolTx.Tx = nil // Mark as removed

	// Update statistics
	mp.stats.TotalTxs--
	mp.stats.TotalSize -= int64(tx.Size)
	mp.stats.TxsByAddress[tx.From]--
	if mp.stats.TxsByAddress[tx.From] == 0 {
		delete(mp.stats.TxsByAddress, tx.From)
	}

	return nil
}

func (mp *Mempool) getTxByNonce(address string, nonce uint64) (*MempoolTx, bool) {
	if addrTxs, exists := mp.txByAddress[address]; exists {
		if tx, exists := addrTxs[nonce]; exists {
			return tx, true
		}
	}
	return nil, false
}

func (mp *Mempool) handleReplaceByFee(oldTx, newTx *Transaction) error {
	// RBF requires at least 10% higher fee
	minNewFee := new(big.Int).Mul(oldTx.FeeDNT, big.NewInt(110))
	minNewFee.Div(minNewFee, big.NewInt(100))

	if newTx.FeeDNT.Cmp(minNewFee) < 0 {
		return ErrReplaceByFeeTooLow
	}

	// Remove old transaction
	if err := mp.removeTransactionUnsafe(oldTx.Hash); err != nil {
		return fmt.Errorf("failed to remove old transaction: %w", err)
	}

	mp.stats.ReplaceByFeeCount++

	return nil
}

func (mp *Mempool) evictLowestPriority(minPriority *big.Int) bool {
	if mp.priorityQueue.Len() == 0 {
		return false
	}

	// Peek at lowest priority transaction
	lowestPriorityTx := (*mp.priorityQueue)[mp.priorityQueue.Len()-1]

	// Only evict if new transaction has higher priority
	if lowestPriorityTx.Priority.Cmp(minPriority) >= 0 {
		return false
	}

	// Remove lowest priority transaction
	mp.removeTransactionUnsafe(lowestPriorityTx.Tx.Hash)
	mp.stats.EvictedCount++

	return true
}

func (mp *Mempool) tryEvictLowFeeTx(address string, newFeePerByte *big.Int) bool {
	addrTxs := mp.txByAddress[address]
	if len(addrTxs) == 0 {
		return false
	}

	// Find lowest fee transaction from this address
	var lowestFeeTx *MempoolTx
	var lowestFee *big.Int

	for _, tx := range addrTxs {
		if lowestFeeTx == nil || tx.Priority.Cmp(lowestFee) < 0 {
			lowestFeeTx = tx
			lowestFee = tx.Priority
		}
	}

	// Only evict if new tx has higher fee
	if lowestFee.Cmp(newFeePerByte) >= 0 {
		return false
	}

	mp.removeTransactionUnsafe(lowestFeeTx.Tx.Hash)
	mp.stats.EvictedCount++

	return true
}

func (mp *Mempool) isNonceValid(address string, nonce uint64) bool {
	// This should check against blockchain state
	// For now, just check mempool consistency
	addrTxs := mp.txByAddress[address]
	if len(addrTxs) == 0 {
		return true
	}

	// Find lowest nonce for this address
	minNonce := ^uint64(0)
	for n := range addrTxs {
		if n < minNonce {
			minNonce = n
		}
	}

	// Check for gaps
	for i := minNonce; i < nonce; i++ {
		if _, exists := addrTxs[i]; !exists {
			return false // Gap detected
		}
	}

	return true
}

// TxPriorityQueue implements heap.Interface for priority queue
type TxPriorityQueue []*MempoolTx

func (pq TxPriorityQueue) Len() int { return len(pq) }

func (pq TxPriorityQueue) Less(i, j int) bool {
	// Higher priority (higher fee per byte) comes first
	return pq[i].Priority.Cmp(pq[j].Priority) > 0
}

func (pq TxPriorityQueue) Swap(i, j int) {
	pq[i], pq[j] = pq[j], pq[i]
	pq[i].Index = i
	pq[j].Index = j
}

func (pq *TxPriorityQueue) Push(x interface{}) {
	n := len(*pq)
	item := x.(*MempoolTx)
	item.Index = n
	*pq = append(*pq, item)
}

func (pq *TxPriorityQueue) Pop() interface{} {
	old := *pq
	n := len(old)
	item := old[n-1]
	old[n-1] = nil  // avoid memory leak
	item.Index = -1 // for safety
	*pq = old[0 : n-1]
	return item
}

// HashTransaction creates a deterministic hash for a transaction
func HashTransaction(tx *Transaction) string {
	h := sha256.New()
	h.Write([]byte(tx.From))
	h.Write([]byte(tx.To))
	h.Write(tx.Amount.Bytes())
	h.Write([]byte(tx.TokenType))
	h.Write(tx.FeeDNT.Bytes())
	h.Write([]byte(fmt.Sprintf("%d", tx.Nonce)))
	h.Write(tx.Signature)
	if len(tx.Data) > 0 {
		h.Write(tx.Data)
	}
	return hex.EncodeToString(h.Sum(nil))
}

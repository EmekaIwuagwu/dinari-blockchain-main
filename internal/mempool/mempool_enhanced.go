// internal/mempool/mempool_enhanced.go
// Production-grade mempool with intelligent prioritization and attack prevention

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

	"github.com/EmekaIwuagwu/dinari-blockchain/internal/types"
)

const (
	MaxMempoolSize          = 100000
	MaxTxPerAddress         = 1000
	MinGasPriceMultiplier   = 1.1
	TxExpirationTime        = 24 * time.Hour
	CleanupInterval         = 5 * time.Minute
	MaxOrphanTxs            = 10000
	HighPriorityThreshold   = 100000000000 // 100 DNT
	MaxPendingNonceGap      = 10
	MaxReplacementAttempts  = 5
)

var (
	ErrMempoolFull          = errors.New("mempool is full")
	ErrTxAlreadyExists      = errors.New("transaction already in mempool")
	ErrInvalidNonce         = errors.New("invalid nonce")
	ErrGasPriceTooLow       = errors.New("gas price too low")
	ErrTxExpired            = errors.New("transaction expired")
	ErrAddressLimitReached  = errors.New("address transaction limit reached")
	ErrDoubleSpend          = errors.New("potential double spend detected")
	ErrInsufficientFee      = errors.New("insufficient fee for replacement")
)

type EnhancedMempool struct {
	transactions     map[string]*MempoolTransaction
	addressTxs       map[string][]*MempoolTransaction
	priorityQueue    *PriorityQueue
	orphanTxs        map[string]*MempoolTransaction
	doubleSpendCache map[string]bool
	validator        TransactionValidator
	mu               sync.RWMutex
	metrics          *MempoolMetrics
	config           *MempoolConfig
	stopCleanup      chan struct{}
}

type MempoolConfig struct {
	MaxSize            int
	MaxTxPerAddress    int
	MinGasPrice        uint64
	EnableRBF          bool
	EnablePriority     bool
	CleanupInterval    time.Duration
}

type MempoolTransaction struct {
	Tx              *types.Transaction
	AddedAt         time.Time
	Priority        int
	GasPrice        uint64
	Size            int
	Replacements    int
	HighValue       bool
	Verified        bool
}

type TransactionValidator interface {
	ValidateTransaction(tx *types.Transaction) error
	CheckDoubleSpend(tx *types.Transaction) error
	VerifyNonce(address string, nonce uint64) error
}

type MempoolMetrics struct {
	TotalTransactions   uint64
	AcceptedTxs         uint64
	RejectedTxs         uint64
	ReplacedTxs         uint64
	ExpiredTxs          uint64
	DoubleSpendBlocked  uint64
	AverageGasPrice     uint64
	HighValueTxCount    uint64
	mu                  sync.RWMutex
}

type PriorityQueue []*MempoolTransaction

func (pq PriorityQueue) Len() int { return len(pq) }

func (pq PriorityQueue) Less(i, j int) bool {
	// Higher priority first
	if pq[i].Priority != pq[j].Priority {
		return pq[i].Priority > pq[j].Priority
	}
	// Then higher gas price
	if pq[i].GasPrice != pq[j].GasPrice {
		return pq[i].GasPrice > pq[j].GasPrice
	}
	// Then older transactions
	return pq[i].AddedAt.Before(pq[j].AddedAt)
}

func (pq PriorityQueue) Swap(i, j int) {
	pq[i], pq[j] = pq[j], pq[i]
}

func (pq *PriorityQueue) Push(x interface{}) {
	item := x.(*MempoolTransaction)
	*pq = append(*pq, item)
}

func (pq *PriorityQueue) Pop() interface{} {
	old := *pq
	n := len(old)
	item := old[n-1]
	old[n-1] = nil
	*pq = old[0 : n-1]
	return item
}

func NewEnhancedMempool(validator TransactionValidator, config *MempoolConfig) *EnhancedMempool {
	if config == nil {
		config = DefaultMempoolConfig()
	}

	pq := make(PriorityQueue, 0)
	heap.Init(&pq)

	mp := &EnhancedMempool{
		transactions:     make(map[string]*MempoolTransaction),
		addressTxs:       make(map[string][]*MempoolTransaction),
		priorityQueue:    &pq,
		orphanTxs:        make(map[string]*MempoolTransaction),
		doubleSpendCache: make(map[string]bool),
		validator:        validator,
		metrics:          NewMempoolMetrics(),
		config:           config,
		stopCleanup:      make(chan struct{}),
	}

	go mp.startCleanupRoutine()

	return mp
}

func DefaultMempoolConfig() *MempoolConfig {
	return &MempoolConfig{
		MaxSize:         MaxMempoolSize,
		MaxTxPerAddress: MaxTxPerAddress,
		MinGasPrice:     1000,
		EnableRBF:       true,
		EnablePriority:  true,
		CleanupInterval: CleanupInterval,
	}
}

func NewMempoolMetrics() *MempoolMetrics {
	return &MempoolMetrics{}
}

func (mp *EnhancedMempool) AddTransaction(tx *types.Transaction) error {
	mp.mu.Lock()
	defer mp.mu.Unlock()

	mp.metrics.TotalTransactions++

	if len(mp.transactions) >= mp.config.MaxSize {
		mp.metrics.RejectedTxs++
		return ErrMempoolFull
	}

	txHash := tx.Hash()
	txHashStr := hex.EncodeToString(txHash)

	if _, exists := mp.transactions[txHashStr]; exists {
		return mp.handleReplacement(tx, txHashStr)
	}

	if err := mp.validator.ValidateTransaction(tx); err != nil {
		mp.metrics.RejectedTxs++
		return fmt.Errorf("validation failed: %w", err)
	}

	if err := mp.validator.CheckDoubleSpend(tx); err != nil {
		mp.metrics.DoubleSpendBlocked++
		return ErrDoubleSpend
	}

	if err := mp.checkAddressLimit(tx.From); err != nil {
		mp.metrics.RejectedTxs++
		return err
	}

	if err := mp.checkNonceGap(tx); err != nil {
		mp.addOrphanTransaction(tx)
		return err
	}

	mempoolTx := mp.createMempoolTransaction(tx)

	mp.transactions[txHashStr] = mempoolTx
	mp.addressTxs[tx.From] = append(mp.addressTxs[tx.From], mempoolTx)

	if mp.config.EnablePriority {
		heap.Push(mp.priorityQueue, mempoolTx)
	}

	mp.metrics.AcceptedTxs++

	if mempoolTx.HighValue {
		mp.metrics.HighValueTxCount++
	}

	mp.tryProcessOrphans(tx.From)

	return nil
}

func (mp *EnhancedMempool) createMempoolTransaction(tx *types.Transaction) *MempoolTransaction {
	amount := new(big.Int).SetBytes(tx.Amount)
	isHighValue := amount.Cmp(big.NewInt(HighPriorityThreshold)) >= 0

	priority := mp.calculatePriority(tx, isHighValue)

	return &MempoolTransaction{
		Tx:           tx,
		AddedAt:      time.Now(),
		Priority:     priority,
		GasPrice:     tx.GasPrice,
		Size:         tx.Size(),
		Replacements: 0,
		HighValue:    isHighValue,
		Verified:     true,
	}
}

func (mp *EnhancedMempool) calculatePriority(tx *types.Transaction, isHighValue bool) int {
	priority := 0

	gasPriceScore := int(tx.GasPrice / mp.config.MinGasPrice)
	priority += gasPriceScore

	if isHighValue {
		priority += 1000
	}

	if tx.GasPrice > mp.config.MinGasPrice*10 {
		priority += 500
	}

	return priority
}

func (mp *EnhancedMempool) handleReplacement(tx *types.Transaction, txHashStr string) error {
	if !mp.config.EnableRBF {
		return ErrTxAlreadyExists
	}

	existingTx := mp.transactions[txHashStr]

	if existingTx.Replacements >= MaxReplacementAttempts {
		return errors.New("max replacement attempts exceeded")
	}

	minNewGasPrice := uint64(float64(existingTx.GasPrice) * MinGasPriceMultiplier)
	if tx.GasPrice < minNewGasPrice {
		return ErrInsufficientFee
	}

	mp.removeTransaction(txHashStr)

	mp.metrics.ReplacedTxs++

	return nil
}

func (mp *EnhancedMempool) checkAddressLimit(address string) error {
	if len(mp.addressTxs[address]) >= mp.config.MaxTxPerAddress {
		return ErrAddressLimitReached
	}
	return nil
}

func (mp *EnhancedMempool) checkNonceGap(tx *types.Transaction) error {
	addressTxs := mp.addressTxs[tx.From]
	if len(addressTxs) == 0 {
		return nil
	}

	highestNonce := uint64(0)
	for _, mempoolTx := range addressTxs {
		if mempoolTx.Tx.Nonce > highestNonce {
			highestNonce = mempoolTx.Tx.Nonce
		}
	}

	if tx.Nonce > highestNonce+MaxPendingNonceGap {
		return ErrInvalidNonce
	}

	return nil
}

func (mp *EnhancedMempool) addOrphanTransaction(tx *types.Transaction) {
	if len(mp.orphanTxs) >= MaxOrphanTxs {
		return
	}

	txHash := hex.EncodeToString(tx.Hash())
	mempoolTx := mp.createMempoolTransaction(tx)
	mp.orphanTxs[txHash] = mempoolTx
}

func (mp *EnhancedMempool) tryProcessOrphans(address string) {
	toProcess := make([]*types.Transaction, 0)

	for txHash, orphanTx := range mp.orphanTxs {
		if orphanTx.Tx.From == address {
			if mp.checkNonceGap(orphanTx.Tx) == nil {
				toProcess = append(toProcess, orphanTx.Tx)
				delete(mp.orphanTxs, txHash)
			}
		}
	}

	for _, tx := range toProcess {
		mp.AddTransaction(tx)
	}
}

func (mp *EnhancedMempool) RemoveTransaction(txHash []byte) error {
	mp.mu.Lock()
	defer mp.mu.Unlock()

	txHashStr := hex.EncodeToString(txHash)
	return mp.removeTransaction(txHashStr)
}

func (mp *EnhancedMempool) removeTransaction(txHashStr string) error {
	mempoolTx, exists := mp.transactions[txHashStr]
	if !exists {
		return errors.New("transaction not found")
	}

	delete(mp.transactions, txHashStr)

	addressTxs := mp.addressTxs[mempoolTx.Tx.From]
	for i, tx := range addressTxs {
		if hex.EncodeToString(tx.Tx.Hash()) == txHashStr {
			mp.addressTxs[mempoolTx.Tx.From] = append(addressTxs[:i], addressTxs[i+1:]...)
			break
		}
	}

	if len(mp.addressTxs[mempoolTx.Tx.From]) == 0 {
		delete(mp.addressTxs, mempoolTx.Tx.From)
	}

	return nil
}

func (mp *EnhancedMempool) GetTransaction(txHash []byte) (*types.Transaction, error) {
	mp.mu.RLock()
	defer mp.mu.RUnlock()

	txHashStr := hex.EncodeToString(txHash)
	mempoolTx, exists := mp.transactions[txHashStr]
	if !exists {
		return nil, errors.New("transaction not found")
	}

	return mempoolTx.Tx, nil
}

func (mp *EnhancedMempool) GetTransactions(maxCount int) []*types.Transaction {
	mp.mu.RLock()
	defer mp.mu.RUnlock()

	if !mp.config.EnablePriority {
		return mp.getTransactionsSimple(maxCount)
	}

	return mp.getTransactionsByPriority(maxCount)
}

func (mp *EnhancedMempool) getTransactionsSimple(maxCount int) []*types.Transaction {
	txs := make([]*types.Transaction, 0, maxCount)

	count := 0
	for _, mempoolTx := range mp.transactions {
		if count >= maxCount {
			break
		}
		txs = append(txs, mempoolTx.Tx)
		count++
	}

	return txs
}

func (mp *EnhancedMempool) getTransactionsByPriority(maxCount int) []*types.Transaction {
	txs := make([]*types.Transaction, 0, maxCount)

	tempQueue := make(PriorityQueue, len(*mp.priorityQueue))
	copy(tempQueue, *mp.priorityQueue)
	heap.Init(&tempQueue)

	count := 0
	for tempQueue.Len() > 0 && count < maxCount {
		mempoolTx := heap.Pop(&tempQueue).(*MempoolTransaction)
		txs = append(txs, mempoolTx.Tx)
		count++
	}

	return txs
}

func (mp *EnhancedMempool) GetTransactionsByAddress(address string) []*types.Transaction {
	mp.mu.RLock()
	defer mp.mu.RUnlock()

	mempoolTxs := mp.addressTxs[address]
	txs := make([]*types.Transaction, len(mempoolTxs))

	for i, mempoolTx := range mempoolTxs {
		txs[i] = mempoolTx.Tx
	}

	return txs
}

func (mp *EnhancedMempool) GetPendingNonce(address string) (uint64, error) {
	mp.mu.RLock()
	defer mp.mu.RUnlock()

	addressTxs := mp.addressTxs[address]
	if len(addressTxs) == 0 {
		return 0, errors.New("no transactions for address")
	}

	highestNonce := uint64(0)
	for _, mempoolTx := range addressTxs {
		if mempoolTx.Tx.Nonce > highestNonce {
			highestNonce = mempoolTx.Tx.Nonce
		}
	}

	return highestNonce + 1, nil
}

func (mp *EnhancedMempool) HasTransaction(txHash []byte) bool {
	mp.mu.RLock()
	defer mp.mu.RUnlock()

	txHashStr := hex.EncodeToString(txHash)
	_, exists := mp.transactions[txHashStr]
	return exists
}

func (mp *EnhancedMempool) GetSize() int {
	mp.mu.RLock()
	defer mp.mu.RUnlock()

	return len(mp.transactions)
}

func (mp *EnhancedMempool) GetTotalSize() int {
	mp.mu.RLock()
	defer mp.mu.RUnlock()

	totalSize := 0
	for _, mempoolTx := range mp.transactions {
		totalSize += mempoolTx.Size
	}

	return totalSize
}

func (mp *EnhancedMempool) startCleanupRoutine() {
	ticker := time.NewTicker(mp.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			mp.cleanup()
		case <-mp.stopCleanup:
			return
		}
	}
}

func (mp *EnhancedMempool) cleanup() {
	mp.mu.Lock()
	defer mp.mu.Unlock()

	now := time.Now()
	toRemove := make([]string, 0)

	for txHashStr, mempoolTx := range mp.transactions {
		if now.Sub(mempoolTx.AddedAt) > TxExpirationTime {
			toRemove = append(toRemove, txHashStr)
		}
	}

	for _, txHashStr := range toRemove {
		mp.removeTransaction(txHashStr)
		mp.metrics.ExpiredTxs++
	}

	mp.cleanupOrphans(now)

	mp.cleanupDoubleSpendCache()
}

func (mp *EnhancedMempool) cleanupOrphans(now time.Time) {
	toRemove := make([]string, 0)

	for txHashStr, orphanTx := range mp.orphanTxs {
		if now.Sub(orphanTx.AddedAt) > TxExpirationTime {
			toRemove = append(toRemove, txHashStr)
		}
	}

	for _, txHashStr := range toRemove {
		delete(mp.orphanTxs, txHashStr)
	}
}

func (mp *EnhancedMempool) cleanupDoubleSpendCache() {
	if len(mp.doubleSpendCache) > 100000 {
		mp.doubleSpendCache = make(map[string]bool)
	}
}

func (mp *EnhancedMempool) Clear() {
	mp.mu.Lock()
	defer mp.mu.Unlock()

	mp.transactions = make(map[string]*MempoolTransaction)
	mp.addressTxs = make(map[string][]*MempoolTransaction)
	mp.orphanTxs = make(map[string]*MempoolTransaction)
	mp.doubleSpendCache = make(map[string]bool)

	pq := make(PriorityQueue, 0)
	heap.Init(&pq)
	mp.priorityQueue = &pq
}

func (mp *EnhancedMempool) Stop() {
	close(mp.stopCleanup)
}

func (mp *EnhancedMempool) GetMetrics() *MempoolMetrics {
	mp.metrics.mu.RLock()
	defer mp.metrics.mu.RUnlock()

	metricsCopy := &MempoolMetrics{}
	*metricsCopy = *mp.metrics
	return metricsCopy
}

func (mp *EnhancedMempool) GetStatistics() map[string]interface{} {
	mp.mu.RLock()
	metrics := mp.GetMetrics()
	mp.mu.RUnlock()

	avgGasPrice := uint64(0)
	if len(mp.transactions) > 0 {
		totalGas := uint64(0)
		for _, mempoolTx := range mp.transactions {
			totalGas += mempoolTx.GasPrice
		}
		avgGasPrice = totalGas / uint64(len(mp.transactions))
	}

	return map[string]interface{}{
		"total_transactions":    len(mp.transactions),
		"orphan_transactions":   len(mp.orphanTxs),
		"unique_addresses":      len(mp.addressTxs),
		"average_gas_price":     avgGasPrice,
		"total_accepted":        metrics.AcceptedTxs,
		"total_rejected":        metrics.RejectedTxs,
		"total_replaced":        metrics.ReplacedTxs,
		"total_expired":         metrics.ExpiredTxs,
		"double_spend_blocked":  metrics.DoubleSpendBlocked,
		"high_value_tx_count":   metrics.HighValueTxCount,
	}
}

func (mp *EnhancedMempool) ValidateMempool() error {
	mp.mu.RLock()
	defer mp.mu.RUnlock()

	for txHashStr, mempoolTx := range mp.transactions {
		if err := mp.validator.ValidateTransaction(mempoolTx.Tx); err != nil {
			return fmt.Errorf("invalid transaction %s in mempool: %w", txHashStr, err)
		}
	}

	return nil
}

func (mp *EnhancedMempool) GetHighValueTransactions() []*types.Transaction {
	mp.mu.RLock()
	defer mp.mu.RUnlock()

	highValueTxs := make([]*types.Transaction, 0)

	for _, mempoolTx := range mp.transactions {
		if mempoolTx.HighValue {
			highValueTxs = append(highValueTxs, mempoolTx.Tx)
		}
	}

	return highValueTxs
}

func (mp *EnhancedMempool) GetTransactionAge(txHash []byte) (time.Duration, error) {
	mp.mu.RLock()
	defer mp.mu.RUnlock()

	txHashStr := hex.EncodeToString(txHash)
	mempoolTx, exists := mp.transactions[txHashStr]
	if !exists {
		return 0, errors.New("transaction not found")
	}

	return time.Since(mempoolTx.AddedAt), nil
}

func (mp *EnhancedMempool) MarkDoubleSpend(txHash []byte) {
	mp.mu.Lock()
	defer mp.mu.Unlock()

	txHashStr := hex.EncodeToString(txHash)
	mp.doubleSpendCache[txHashStr] = true
}

func (mp *EnhancedMempool) IsDoubleSpend(txHash []byte) bool {
	mp.mu.RLock()
	defer mp.mu.RUnlock()

	txHashStr := hex.EncodeToString(txHash)
	return mp.doubleSpendCache[txHashStr]
}

func (mp *EnhancedMempool) GetLowestGasPrice() uint64 {
	mp.mu.RLock()
	defer mp.mu.RUnlock()

	if len(mp.transactions) == 0 {
		return mp.config.MinGasPrice
	}

	lowest := uint64(^uint64(0))
	for _, mempoolTx := range mp.transactions {
		if mempoolTx.GasPrice < lowest {
			lowest = mempoolTx.GasPrice
		}
	}

	return lowest
}

func (mp *EnhancedMempool) GetHighestGasPrice() uint64 {
	mp.mu.RLock()
	defer mp.mu.RUnlock()

	if len(mp.transactions) == 0 {
		return mp.config.MinGasPrice
	}

	highest := uint64(0)
	for _, mempoolTx := range mp.transactions {
		if mempoolTx.GasPrice > highest {
			highest = mempoolTx.GasPrice
		}
	}

	return highest
}

func GenerateTxID(tx *types.Transaction) string {
	data := fmt.Sprintf("%s:%s:%d:%s", 
		tx.From, 
		tx.To, 
		tx.Nonce,
		hex.EncodeToString(tx.Amount))
	
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}
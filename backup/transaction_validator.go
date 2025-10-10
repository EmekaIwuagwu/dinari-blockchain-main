// internal/core/transaction_validator.go
// Battle-tested transaction validation for high-value transfers

package core

import (
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/EmekaIwuagwu/dinari-blockchain/internal/types"
	"github.com/EmekaIwuagwu/dinari-blockchain/pkg/crypto"
)

const (
	MaxTransactionSize      = 100 * 1024 // 100 KB
	MaxTransactionAge       = 24 * time.Hour
	MinGasPrice             = 1000
	MaxGasLimit             = 10000000
	HighValueThreshold      = 10000000000000 // 10M DNT (atomic units)
	VeryHighValueThreshold  = 100000000000000 // 100M DNT
	MaxDailyVelocity        = 1000000000000000 // 1B DNT per address per day
	MaxOutputs              = 100
	MaxInputs               = 100
)

var (
	ErrInvalidTransaction     = errors.New("invalid transaction")
	ErrInsufficientFunds      = errors.New("insufficient funds")
	ErrInvalidSignature       = errors.New("invalid signature")
	ErrInvalidPublicKey       = errors.New("invalid public key")
	ErrNonceTooLow            = errors.New("nonce too low")
	ErrNonceTooHigh           = errors.New("nonce too high")
	ErrTransactionTooLarge    = errors.New("transaction size exceeds limit")
	ErrTransactionExpired     = errors.New("transaction expired")
	ErrInvalidAmount          = errors.New("invalid amount")
	ErrInsufficientGas        = errors.New("insufficient gas")
	ErrVelocityLimitExceeded  = errors.New("daily velocity limit exceeded")
	ErrDoubleSpend            = errors.New("double spend detected")
	ErrHighValueNoMultiSig    = errors.New("high value transaction requires multisig")
	ErrInvalidRecipient       = errors.New("invalid recipient address")
	ErrSelfTransfer           = errors.New("self transfer not allowed for high value")
	ErrBlacklistedAddress     = errors.New("address is blacklisted")
)

type TransactionValidator struct {
	km                *crypto.KeyManager
	stateDB           StateDB
	velocityTracker   *VelocityTracker
	blacklistManager  *BlacklistManager
	multiSigManager   *MultiSigManager
	riskScorer        *RiskScorer
	mu                sync.RWMutex
}

type VelocityTracker struct {
	dailyVolumes map[string]*DailyVolume
	mu           sync.RWMutex
}

type DailyVolume struct {
	Date       time.Time
	Amount     *big.Int
	TxCount    int
}

type BlacklistManager struct {
	blacklist map[string]BlacklistEntry
	mu        sync.RWMutex
}

type BlacklistEntry struct {
	Address    string
	Reason     string
	AddedAt    time.Time
	ExpiresAt  *time.Time
}

type MultiSigManager struct {
	wallets map[string]*crypto.MultiSigWallet
	mu      sync.RWMutex
}

type RiskScorer struct {
	patterns map[string]int
	mu       sync.RWMutex
}

type ValidationContext struct {
	ChainID           uint64
	CurrentHeight     uint64
	CurrentTime       time.Time
	RequireMultiSig   bool
	RequireCompliance bool
}

type ValidationResult struct {
	Valid            bool
	Error            error
	RiskScore        int
	RequiresMultiSig bool
	Warnings         []string
	GasEstimate      uint64
}

func NewTransactionValidator(km *crypto.KeyManager, stateDB StateDB) *TransactionValidator {
	return &TransactionValidator{
		km:               km,
		stateDB:          stateDB,
		velocityTracker:  NewVelocityTracker(),
		blacklistManager: NewBlacklistManager(),
		multiSigManager:  NewMultiSigManager(),
		riskScorer:       NewRiskScorer(),
	}
}

func NewVelocityTracker() *VelocityTracker {
	return &VelocityTracker{
		dailyVolumes: make(map[string]*DailyVolume),
	}
}

func NewBlacklistManager() *BlacklistManager {
	return &BlacklistManager{
		blacklist: make(map[string]BlacklistEntry),
	}
}

func NewMultiSigManager() *MultiSigManager {
	return &MultiSigManager{
		wallets: make(map[string]*crypto.MultiSigWallet),
	}
}

func NewRiskScorer() *RiskScorer {
	return &RiskScorer{
		patterns: make(map[string]int),
	}
}

func (tv *TransactionValidator) ValidateTransaction(tx *types.Transaction, ctx *ValidationContext) *ValidationResult {
	result := &ValidationResult{
		Valid:       true,
		Warnings:    make([]string, 0),
		RiskScore:   0,
	}

	if err := tv.validateBasicStructure(tx); err != nil {
		result.Valid = false
		result.Error = err
		return result
	}

	if err := tv.validateBlacklist(tx); err != nil {
		result.Valid = false
		result.Error = err
		return result
	}

	if err := tv.validateSignature(tx, ctx.ChainID); err != nil {
		result.Valid = false
		result.Error = err
		return result
	}

	if err := tv.validateNonce(tx); err != nil {
		result.Valid = false
		result.Error = err
		return result
	}

	if err := tv.validateBalance(tx); err != nil {
		result.Valid = false
		result.Error = err
		return result
	}

	if err := tv.validateAmount(tx); err != nil {
		result.Valid = false
		result.Error = err
		return result
	}

	if err := tv.validateVelocity(tx); err != nil {
		result.Valid = false
		result.Error = err
		return result
	}

	result.RiskScore = tv.calculateRiskScore(tx)

	if tv.requiresMultiSig(tx) {
		result.RequiresMultiSig = true
		if !tv.hasValidMultiSig(tx) {
			result.Valid = false
			result.Error = ErrHighValueNoMultiSig
			return result
		}
	}

	if result.RiskScore > 70 {
		result.Warnings = append(result.Warnings, "High risk score - additional monitoring recommended")
	}

	result.GasEstimate = tv.estimateGas(tx)

	return result
}

func (tv *TransactionValidator) validateBasicStructure(tx *types.Transaction) error {
	if tx == nil {
		return ErrInvalidTransaction
	}

	if len(tx.To) == 0 {
		return ErrInvalidRecipient
	}

	if tx.From == tx.To {
		amount := tx.Amount
		if amount.Cmp(big.NewInt(HighValueThreshold)) > 0 {
			return ErrSelfTransfer
		}
	}

	txSize := tx.Size()
	if txSize > MaxTransactionSize {
		return ErrTransactionTooLarge
	}

	if time.Since(time.Unix(tx.Timestamp, 0)) > MaxTransactionAge {
		return ErrTransactionExpired
	}

	return nil
}

func (tv *TransactionValidator) validateBlacklist(tx *types.Transaction) error {
	if tv.blacklistManager.IsBlacklisted(tx.From) {
		return fmt.Errorf("%w: from address blacklisted", ErrBlacklistedAddress)
	}

	if tv.blacklistManager.IsBlacklisted(tx.To) {
		return fmt.Errorf("%w: to address blacklisted", ErrBlacklistedAddress)
	}

	return nil
}

func (tv *TransactionValidator) validateSignature(tx *types.Transaction, chainID uint64) error {
	if len(tx.Signature) == 0 {
		return ErrInvalidSignature
	}

	if len(tx.PublicKey) == 0 {
		return ErrInvalidPublicKey
	}

	txHash := tx.Hash[:]
	
	err := tv.km.VerifySignature(tx.PublicKey, txHash, tx.Signature, tx.Nonce, chainID)
	if err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	return nil
}

func (tv *TransactionValidator) validateNonce(tx *types.Transaction) error {
	expectedNonce, err := tv.stateDB.GetNonce(tx.From)
	if err != nil {
		return fmt.Errorf("failed to get nonce: %w", err)
	}

	if tx.Nonce < expectedNonce {
		return ErrNonceTooLow
	}

	if tx.Nonce > expectedNonce+100 {
		return ErrNonceTooHigh
	}

	return nil
}

func (tv *TransactionValidator) validateBalance(tx *types.Transaction) error {
	balance, err := tv.stateDB.GetBalance(tx.From, TokenType(tx.TokenType))
	if err != nil {
		return fmt.Errorf("failed to get balance: %w", err)
	}

	amount := tx.Amount
	fee := tx.FeeDNT
	
	totalRequired := new(big.Int).Add(amount, fee)

	if balance.Cmp(totalRequired) < 0 {
		return ErrInsufficientFunds
	}

	return nil
}

func (tv *TransactionValidator) validateAmount(tx *types.Transaction) error {
	amount := tx.Amount

	if amount.Sign() <= 0 {
		return ErrInvalidAmount
	}

	maxAmount := new(big.Int).Exp(big.NewInt(10), big.NewInt(30), nil)
	if amount.Cmp(maxAmount) > 0 {
		return errors.New("amount exceeds maximum allowed")
	}

	return nil
}

func (tv *TransactionValidator) validateVelocity(tx *types.Transaction) error {
	amount := tx.Amount
	
	dailyTotal := tv.velocityTracker.GetDailyVolume(tx.From)
	newTotal := new(big.Int).Add(dailyTotal, amount)

	maxVelocity := new(big.Int).SetUint64(MaxDailyVelocity)
	
	if newTotal.Cmp(maxVelocity) > 0 {
		return ErrVelocityLimitExceeded
	}

	return nil
}

func (tv *TransactionValidator) requiresMultiSig(tx *types.Transaction) bool {
	amount := tx.Amount
	threshold := new(big.Int).SetInt64(VeryHighValueThreshold)
	
	return amount.Cmp(threshold) >= 0
}

func (tv *TransactionValidator) hasValidMultiSig(tx *types.Transaction) bool {
	if tx.MultiSig == nil {
		return false
	}

	// Check if multisig has required signatures
	return tx.HasSufficientSignatures()
}

func (tv *TransactionValidator) calculateRiskScore(tx *types.Transaction) int {
	score := 0

	amount := tx.Amount
	
	if amount.Cmp(big.NewInt(HighValueThreshold)) > 0 {
		score += 20
	}
	if amount.Cmp(big.NewInt(VeryHighValueThreshold)) > 0 {
		score += 30
	}

	if time.Since(time.Unix(tx.Timestamp, 0)) < 1*time.Minute {
		score += 10
	}

	isNewFrom := tv.riskScorer.IsNewAddress(tx.From)
	isNewTo := tv.riskScorer.IsNewAddress(tx.To)
	if isNewFrom && isNewTo {
		score += 15
	}

	dailyVolume := tv.velocityTracker.GetDailyVolume(tx.From)
	if dailyVolume.Cmp(big.NewInt(HighValueThreshold*10)) > 0 {
		score += 10
	}

	return score
}

func (tv *TransactionValidator) estimateGas(tx *types.Transaction) uint64 {
	baseGas := uint64(21000)
	
	// Estimate data gas (if tx has Data field)
	dataGas := uint64(0)
	
	if tx.MultiSig != nil {
		baseGas += 50000
	}
	
	return baseGas + dataGas
}

func (vt *VelocityTracker) GetDailyVolume(address string) *big.Int {
	vt.mu.RLock()
	defer vt.mu.RUnlock()

	today := time.Now().Truncate(24 * time.Hour)
	key := fmt.Sprintf("%s:%s", address, today.Format("2006-01-02"))

	if vol, exists := vt.dailyVolumes[key]; exists {
		return new(big.Int).Set(vol.Amount)
	}

	return big.NewInt(0)
}

func (vt *VelocityTracker) AddTransaction(address string, amount *big.Int) {
	vt.mu.Lock()
	defer vt.mu.Unlock()

	today := time.Now().Truncate(24 * time.Hour)
	key := fmt.Sprintf("%s:%s", address, today.Format("2006-01-02"))

	if vol, exists := vt.dailyVolumes[key]; exists {
		vol.Amount = new(big.Int).Add(vol.Amount, amount)
		vol.TxCount++
	} else {
		vt.dailyVolumes[key] = &DailyVolume{
			Date:    today,
			Amount:  new(big.Int).Set(amount),
			TxCount: 1,
		}
	}

	vt.cleanupOldEntries()
}

func (vt *VelocityTracker) cleanupOldEntries() {
	cutoff := time.Now().AddDate(0, 0, -7)
	
	for key, vol := range vt.dailyVolumes {
		if vol.Date.Before(cutoff) {
			delete(vt.dailyVolumes, key)
		}
	}
}

func (bm *BlacklistManager) IsBlacklisted(address string) bool {
	bm.mu.RLock()
	defer bm.mu.RUnlock()

	entry, exists := bm.blacklist[address]
	if !exists {
		return false
	}

	if entry.ExpiresAt != nil && time.Now().After(*entry.ExpiresAt) {
		return false
	}

	return true
}

func (bm *BlacklistManager) AddToBlacklist(address, reason string, duration *time.Duration) {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	entry := BlacklistEntry{
		Address: address,
		Reason:  reason,
		AddedAt: time.Now(),
	}

	if duration != nil {
		expiresAt := time.Now().Add(*duration)
		entry.ExpiresAt = &expiresAt
	}

	bm.blacklist[address] = entry
}

func (bm *BlacklistManager) RemoveFromBlacklist(address string) {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	delete(bm.blacklist, address)
}

func (mm *MultiSigManager) GetWallet(policyID string) (*crypto.MultiSigWallet, bool) {
	mm.mu.RLock()
	defer mm.mu.RUnlock()

	wallet, exists := mm.wallets[policyID]
	return wallet, exists
}

func (mm *MultiSigManager) AddWallet(policyID string, wallet *crypto.MultiSigWallet) {
	mm.mu.Lock()
	defer mm.mu.Unlock()

	mm.wallets[policyID] = wallet
}

func (rs *RiskScorer) IsNewAddress(address string) bool {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	count, exists := rs.patterns[address]
	return !exists || count < 5
}

func (rs *RiskScorer) RecordAddress(address string) {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	rs.patterns[address]++
}

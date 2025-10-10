package core

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// ValidationConfig contains validation parameters
type ValidationConfig struct {
	MaxTxSize              int
	MaxBlockSize           int
	MaxGasLimit            uint64
	MinGasPrice            *big.Int
	MaxTimestampDrift      time.Duration
	EnableStrictSigCheck   bool
	EnableReplayProtection bool
	ChainID                *big.Int
}

// TransactionValidator provides comprehensive transaction validation
type TransactionValidator struct {
	config      *ValidationConfig
	nonceTracker map[string]uint64 // address -> highest nonce
	seenTxs     map[string]bool    // tx hash -> seen
	mu          sync.RWMutex
}

// NewTransactionValidator creates a new validator
func NewTransactionValidator(config *ValidationConfig) *TransactionValidator {
	return &TransactionValidator{
		config:       config,
		nonceTracker: make(map[string]uint64),
		seenTxs:      make(map[string]bool),
	}
}

// ValidateTransaction performs comprehensive transaction validation
func (tv *TransactionValidator) ValidateTransaction(tx *Transaction, currentTime time.Time) error {
	// 1. Basic structure validation
	if err := tv.validateStructure(tx); err != nil {
		return fmt.Errorf("structure validation failed: %w", err)
	}

	// 2. Size check
	if err := tv.validateSize(tx); err != nil {
		return fmt.Errorf("size validation failed: %w", err)
	}

	// 3. Timestamp validation
	if err := tv.validateTimestamp(tx, currentTime); err != nil {
		return fmt.Errorf("timestamp validation failed: %w", err)
	}

	// 4. Amount and overflow checks
	if err := tv.validateAmounts(tx); err != nil {
		return fmt.Errorf("amount validation failed: %w", err)
	}

	// 5. Signature validation (critical!)
	if err := tv.validateSignature(tx); err != nil {
		return fmt.Errorf("signature validation failed: %w", err)
	}

	// 6. Nonce validation
	if err := tv.validateNonce(tx); err != nil {
		return fmt.Errorf("nonce validation failed: %w", err)
	}

	// 7. Replay protection
	if tv.config.EnableReplayProtection {
		if err := tv.checkReplayProtection(tx); err != nil {
			return fmt.Errorf("replay protection failed: %w", err)
		}
	}

	// 8. Malleability checks
	if err := tv.checkMalleability(tx); err != nil {
		return fmt.Errorf("malleability check failed: %w", err)
	}

	return nil
}

// validateStructure checks basic transaction structure
func (tv *TransactionValidator) validateStructure(tx *Transaction) error {
	if tx == nil {
		return errors.New("transaction is nil")
	}

	if tx.From == "" {
		return errors.New("missing sender address")
	}

	if tx.To == "" {
		return errors.New("missing recipient address")
	}

	if tx.From == tx.To {
		return errors.New("sender and recipient are the same")
	}

	if !tv.isValidAddress(tx.From) {
		return errors.New("invalid sender address format")
	}

	if !tv.isValidAddress(tx.To) {
		return errors.New("invalid recipient address format")
	}

	if tx.Signature == nil || len(tx.Signature) == 0 {
		return errors.New("missing signature")
	}

	if tx.PublicKey == nil || len(tx.PublicKey) == 0 {
		return errors.New("missing public key")
	}

	return nil
}

// isValidAddress checks if address has correct format
func (tv *TransactionValidator) isValidAddress(addr string) bool {
	// Check DT prefix for Dinari addresses
	if len(addr) < 3 || addr[:2] != "DT" {
		return false
	}

	// Check length (Base58Check encoded)
	if len(addr) < 26 || len(addr) > 35 {
		return false
	}

	// Verify Base58 characters
	const base58Chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	for _, c := range addr[2:] {
		if !bytes.ContainsRune([]byte(base58Chars), c) {
			return false
		}
	}

	return true
}

// validateSize checks transaction size limits
func (tv *TransactionValidator) validateSize(tx *Transaction) error {
	txSize := tv.calculateTxSize(tx)
	
	if txSize > tv.config.MaxTxSize {
		return fmt.Errorf("transaction size %d exceeds maximum %d", txSize, tv.config.MaxTxSize)
	}

	// Check signature size (should be 64-65 bytes for ECDSA)
	if len(tx.Signature) < 64 || len(tx.Signature) > 65 {
		return fmt.Errorf("invalid signature size: %d", len(tx.Signature))
	}

	// Check public key size (should be 33 or 65 bytes)
	if len(tx.PublicKey) != 33 && len(tx.PublicKey) != 65 {
		return fmt.Errorf("invalid public key size: %d", len(tx.PublicKey))
	}

	return nil
}

// calculateTxSize estimates transaction size
func (tv *TransactionValidator) calculateTxSize(tx *Transaction) int {
	size := 0
	size += len(tx.From)
	size += len(tx.To)
	size += 8 // Amount (uint64)
	size += len(tx.TokenType)
	size += 8 // Fee (uint64)
	size += 8 // Nonce (uint64)
	size += 8 // Timestamp (int64)
	size += len(tx.Signature)
	size += len(tx.PublicKey)
	size += 32 // Hash
	return size
}

// validateTimestamp checks timestamp validity
func (tv *TransactionValidator) validateTimestamp(tx *Transaction, currentTime time.Time) error {
	txTime := time.Unix(tx.Timestamp, 0)

	// Check if timestamp is too far in the future
	if txTime.After(currentTime.Add(tv.config.MaxTimestampDrift)) {
		return fmt.Errorf("timestamp too far in future: %v vs %v", txTime, currentTime)
	}

	// Check if timestamp is too far in the past (older than 1 hour)
	if txTime.Before(currentTime.Add(-1 * time.Hour)) {
		return fmt.Errorf("timestamp too old: %v vs %v", txTime, currentTime)
	}

	return nil
}

// validateAmounts checks for overflows and valid amounts
func (tv *TransactionValidator) validateAmounts(tx *Transaction) error {
	// Check amount is positive
	if tx.Amount == 0 {
		return errors.New("transaction amount must be positive")
	}

	// Check fee is positive
	if tx.Fee == 0 {
		return errors.New("transaction fee must be positive")
	}

	// Check for overflow: amount + fee
	maxUint64 := ^uint64(0)
	if tx.Amount > maxUint64-tx.Fee {
		return errors.New("amount + fee overflow")
	}

	// Check reasonable limits (prevent dust attacks)
	if tx.Amount < 1000 { // Minimum 1000 units
		return errors.New("amount too small (dust)")
	}

	if tx.Fee < 100 { // Minimum fee 100 units
		return errors.New("fee too small")
	}

	return nil
}

// validateSignature verifies ECDSA signature
func (tv *TransactionValidator) validateSignature(tx *Transaction) error {
	// Reconstruct transaction hash for signing
	txHash := tv.calculateTxHashForSigning(tx)

	// Parse public key
	pubKey, err := tv.parsePublicKey(tx.PublicKey)
	if err != nil {
		return fmt.Errorf("invalid public key: %w", err)
	}

	// Verify address matches public key
	derivedAddr := tv.deriveAddress(pubKey)
	if derivedAddr != tx.From {
		return errors.New("public key does not match sender address")
	}

	// Parse signature (r, s components)
	if len(tx.Signature) < 64 {
		return errors.New("signature too short")
	}

	r := new(big.Int).SetBytes(tx.Signature[:32])
	s := new(big.Int).SetBytes(tx.Signature[32:64])

	// CRITICAL: Check for signature malleability (s should be in lower half of curve order)
	if tv.config.EnableStrictSigCheck {
		if !tv.isCanonicalSignature(r, s) {
			return errors.New("non-canonical signature detected (malleability)")
		}
	}

	// Verify signature
	valid := ecdsa.Verify(pubKey, txHash, r, s)
	if !valid {
		return errors.New("invalid signature")
	}

	return nil
}

// isCanonicalSignature checks if signature is canonical (prevents malleability)
func (tv *TransactionValidator) isCanonicalSignature(r, s *big.Int) bool {
	// secp256k1 curve order
	curveOrder, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
	halfOrder := new(big.Int).Div(curveOrder, big.NewInt(2))

	// r must be in [1, n-1]
	if r.Sign() <= 0 || r.Cmp(curveOrder) >= 0 {
		return false
	}

	// s must be in [1, n/2] (lower half to prevent malleability)
	if s.Sign() <= 0 || s.Cmp(halfOrder) > 0 {
		return false
	}

	return true
}

// calculateTxHashForSigning creates hash for signature verification
func (tv *TransactionValidator) calculateTxHashForSigning(tx *Transaction) []byte {
	h := sha256.New()
	
	// Include chain ID for replay protection
	if tv.config.EnableReplayProtection && tv.config.ChainID != nil {
		h.Write(tv.config.ChainID.Bytes())
	}

	h.Write([]byte(tx.From))
	h.Write([]byte(tx.To))
	
	amountBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(amountBytes, tx.Amount)
	h.Write(amountBytes)
	
	h.Write([]byte(tx.TokenType))
	
	feeBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(feeBytes, tx.Fee)
	h.Write(feeBytes)
	
	nonceBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(nonceBytes, tx.Nonce)
	h.Write(nonceBytes)
	
	timestampBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timestampBytes, uint64(tx.Timestamp))
	h.Write(timestampBytes)
	
	return h.Sum(nil)
}

// parsePublicKey parses compressed or uncompressed public key
func (tv *TransactionValidator) parsePublicKey(pubKeyBytes []byte) (*ecdsa.PublicKey, error) {
	// Implementation depends on crypto library
	// This is a placeholder - use actual secp256k1 parsing
	return nil, errors.New("implement secp256k1 public key parsing")
}

// deriveAddress derives address from public key
func (tv *TransactionValidator) deriveAddress(pubKey *ecdsa.PublicKey) string {
	// Implementation should match wallet address derivation
	// This is a placeholder
	return ""
}

// validateNonce checks nonce ordering
func (tv *TransactionValidator) validateNonce(tx *Transaction) error {
	tv.mu.RLock()
	expectedNonce, exists := tv.nonceTracker[tx.From]
	tv.mu.RUnlock()

	if exists && tx.Nonce <= expectedNonce {
		return fmt.Errorf("nonce too low: got %d, expected > %d", tx.Nonce, expectedNonce)
	}

	// Gap check (nonce shouldn't be too far ahead)
	if exists && tx.Nonce > expectedNonce+100 {
		return fmt.Errorf("nonce gap too large: got %d, expected around %d", tx.Nonce, expectedNonce)
	}

	return nil
}

// checkReplayProtection prevents transaction replay
func (tv *TransactionValidator) checkReplayProtection(tx *Transaction) error {
	tv.mu.RLock()
	seen := tv.seenTxs[tx.Hash]
	tv.mu.RUnlock()

	if seen {
		return errors.New("transaction already seen (replay attempt)")
	}

	return nil
}

// checkMalleability performs additional malleability checks
func (tv *TransactionValidator) checkMalleability(tx *Transaction) error {
	// Check for signature malleability (already done in validateSignature)
	
	// Check for zero-value attacks
	if tx.Amount == 0 && tx.Fee == 0 {
		return errors.New("zero-value transaction")
	}

	// Check for integer overflow in calculations
	totalValue := new(big.Int).SetUint64(tx.Amount)
	totalValue.Add(totalValue, new(big.Int).SetUint64(tx.Fee))
	
	maxUint64 := new(big.Int).SetUint64(^uint64(0))
	if totalValue.Cmp(maxUint64) > 0 {
		return errors.New("total value overflow")
	}

	return nil
}

// MarkTransactionSeen marks a transaction as seen
func (tv *TransactionValidator) MarkTransactionSeen(txHash string) {
	tv.mu.Lock()
	defer tv.mu.Unlock()
	tv.seenTxs[txHash] = true
}

// UpdateNonce updates the nonce tracker after transaction processing
func (tv *TransactionValidator) UpdateNonce(address string, nonce uint64) {
	tv.mu.Lock()
	defer tv.mu.Unlock()
	tv.nonceTracker[address] = nonce
}

// ClearOldTransactions removes old seen transactions to prevent memory bloat
func (tv *TransactionValidator) ClearOldTransactions(maxAge time.Duration) {
	tv.mu.Lock()
	defer tv.mu.Unlock()
	
	// In production, implement LRU cache or time-based expiration
	if len(tv.seenTxs) > 100000 {
		tv.seenTxs = make(map[string]bool)
	}
}
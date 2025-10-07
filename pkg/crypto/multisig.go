// pkg/crypto/multisig.go
// Multi-signature implementation for high-value transaction security

package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
)

const (
	MaxMultisigParticipants = 15
	MinMultisigThreshold    = 2
	MaxMultisigThreshold    = 15
	SignatureExpiryTime     = 30 * time.Minute
)

var (
	ErrInsufficientSignatures = errors.New("insufficient signatures for threshold")
	ErrDuplicateSignature     = errors.New("duplicate signature detected")
	ErrInvalidThreshold       = errors.New("invalid threshold configuration")
	ErrExpiredSignature       = errors.New("signature has expired")
	ErrMaxParticipants        = errors.New("exceeded maximum participants")
	ErrSignerNotAuthorized    = errors.New("signer not in authorized list")
)

type MultiSigConfig struct {
	RequiredSignatures uint8
	TotalParticipants  uint8
	PublicKeys         [][]byte
	Addresses          []string
	PolicyID           string
	CreatedAt          time.Time
	ExpiresAt          time.Time
}

type MultiSigWallet struct {
	config        *MultiSigConfig
	pendingTxs    map[string]*PendingMultiSigTx
	completedTxs  map[string]*CompletedMultiSigTx
	mu            sync.RWMutex
	auditLog      []MultiSigAuditEntry
}

type PendingMultiSigTx struct {
	TxHash         []byte
	Signatures     []MultiSigSignature
	CreatedAt      time.Time
	ExpiresAt      time.Time
	SignersRemaining []string
	Metadata       map[string]string
}

type MultiSigSignature struct {
	PublicKey  []byte
	Signature  []byte
	Address    string
	SignedAt   time.Time
}

type CompletedMultiSigTx struct {
	TxHash       []byte
	Signatures   []MultiSigSignature
	CompletedAt  time.Time
	ExecutedBy   string
}

type MultiSigAuditEntry struct {
	Timestamp  time.Time
	TxHash     string
	Operation  string
	Signer     string
	Success    bool
	Details    string
}

func NewMultiSigWallet(requiredSigs, totalParticipants uint8, publicKeys [][]byte, addresses []string) (*MultiSigWallet, error) {
	if requiredSigs < MinMultisigThreshold || requiredSigs > MaxMultisigThreshold {
		return nil, ErrInvalidThreshold
	}
	if totalParticipants > MaxMultisigParticipants {
		return nil, ErrMaxParticipants
	}
	if requiredSigs > totalParticipants {
		return nil, ErrInvalidThreshold
	}
	if len(publicKeys) != int(totalParticipants) || len(addresses) != int(totalParticipants) {
		return nil, errors.New("public keys and addresses count mismatch")
	}

	policyID := generatePolicyID(publicKeys, requiredSigs)

	config := &MultiSigConfig{
		RequiredSignatures: requiredSigs,
		TotalParticipants:  totalParticipants,
		PublicKeys:         publicKeys,
		Addresses:          addresses,
		PolicyID:           policyID,
		CreatedAt:          time.Now(),
		ExpiresAt:          time.Now().Add(365 * 24 * time.Hour),
	}

	return &MultiSigWallet{
		config:       config,
		pendingTxs:   make(map[string]*PendingMultiSigTx),
		completedTxs: make(map[string]*CompletedMultiSigTx),
		auditLog:     make([]MultiSigAuditEntry, 0, 10000),
	}, nil
}

func generatePolicyID(publicKeys [][]byte, threshold uint8) string {
	data := []byte(fmt.Sprintf("threshold:%d", threshold))
	sortedKeys := make([][]byte, len(publicKeys))
	copy(sortedKeys, publicKeys)
	
	sort.Slice(sortedKeys, func(i, j int) bool {
		return hex.EncodeToString(sortedKeys[i]) < hex.EncodeToString(sortedKeys[j])
	})

	for _, key := range sortedKeys {
		data = append(data, key...)
	}

	hash := sha256.Sum256(data)
	return "MSP" + hex.EncodeToString(hash[:16])
}

func (msw *MultiSigWallet) InitiateTransaction(txHash []byte, metadata map[string]string) error {
	msw.mu.Lock()
	defer msw.mu.Unlock()

	txHashStr := hex.EncodeToString(txHash)

	if _, exists := msw.pendingTxs[txHashStr]; exists {
		return errors.New("transaction already initiated")
	}

	if _, completed := msw.completedTxs[txHashStr]; completed {
		return errors.New("transaction already completed")
	}

	signers := make([]string, len(msw.config.Addresses))
	copy(signers, msw.config.Addresses)

	pendingTx := &PendingMultiSigTx{
		TxHash:           txHash,
		Signatures:       make([]MultiSigSignature, 0, msw.config.TotalParticipants),
		CreatedAt:        time.Now(),
		ExpiresAt:        time.Now().Add(SignatureExpiryTime),
		SignersRemaining: signers,
		Metadata:         metadata,
	}

	msw.pendingTxs[txHashStr] = pendingTx

	msw.addAuditEntry(txHashStr, "INITIATE", "", true, "Transaction initiated for multisig")

	return nil
}

func (msw *MultiSigWallet) AddSignature(txHash, signature, publicKey []byte, signerAddress string) error {
	msw.mu.Lock()
	defer msw.mu.Unlock()

	txHashStr := hex.EncodeToString(txHash)

	pendingTx, exists := msw.pendingTxs[txHashStr]
	if !exists {
		return errors.New("transaction not found or already completed")
	}

	if time.Now().After(pendingTx.ExpiresAt) {
		delete(msw.pendingTxs, txHashStr)
		msw.addAuditEntry(txHashStr, "EXPIRED", signerAddress, false, "Transaction signature window expired")
		return ErrExpiredSignature
	}

	if !msw.isAuthorizedSigner(signerAddress) {
		msw.addAuditEntry(txHashStr, "UNAUTHORIZED", signerAddress, false, "Signer not authorized")
		return ErrSignerNotAuthorized
	}

	for _, sig := range pendingTx.Signatures {
		if sig.Address == signerAddress {
			msw.addAuditEntry(txHashStr, "DUPLICATE", signerAddress, false, "Duplicate signature attempt")
			return ErrDuplicateSignature
		}
	}

	x, y := elliptic.Unmarshal(btcec.S256(), publicKey)
	if x == nil {
		msw.addAuditEntry(txHashStr, "INVALID_KEY", signerAddress, false, "Invalid public key")
		return ErrInvalidPublicKey
	}

	pubKey := &ecdsa.PublicKey{
		Curve: btcec.S256(),
		X:     x,
		Y:     y,
	}

	finalHash := sha256.Sum256(txHash)

	if !ecdsa.VerifyASN1(pubKey, finalHash[:], signature) {
		msw.addAuditEntry(txHashStr, "INVALID_SIG", signerAddress, false, "Signature verification failed")
		return ErrInvalidSignature
	}

	multiSig := MultiSigSignature{
		PublicKey: publicKey,
		Signature: signature,
		Address:   signerAddress,
		SignedAt:  time.Now(),
	}

	pendingTx.Signatures = append(pendingTx.Signatures, multiSig)

	for i, addr := range pendingTx.SignersRemaining {
		if addr == signerAddress {
			pendingTx.SignersRemaining = append(pendingTx.SignersRemaining[:i], pendingTx.SignersRemaining[i+1:]...)
			break
		}
	}

	msw.addAuditEntry(txHashStr, "SIGNATURE_ADDED", signerAddress, true, 
		fmt.Sprintf("Signature %d of %d collected", len(pendingTx.Signatures), msw.config.RequiredSignatures))

	if uint8(len(pendingTx.Signatures)) >= msw.config.RequiredSignatures {
		msw.completeTransaction(txHashStr, pendingTx, signerAddress)
	}

	return nil
}

func (msw *MultiSigWallet) completeTransaction(txHashStr string, pendingTx *PendingMultiSigTx, executedBy string) {
	completedTx := &CompletedMultiSigTx{
		TxHash:      pendingTx.TxHash,
		Signatures:  pendingTx.Signatures,
		CompletedAt: time.Now(),
		ExecutedBy:  executedBy,
	}

	msw.completedTxs[txHashStr] = completedTx
	delete(msw.pendingTxs, txHashStr)

	msw.addAuditEntry(txHashStr, "COMPLETED", executedBy, true, 
		fmt.Sprintf("Transaction completed with %d signatures", len(completedTx.Signatures)))
}

func (msw *MultiSigWallet) isAuthorizedSigner(address string) bool {
	for _, addr := range msw.config.Addresses {
		if addr == address {
			return true
		}
	}
	return false
}

func (msw *MultiSigWallet) IsTransactionReady(txHash []byte) (bool, error) {
	msw.mu.RLock()
	defer msw.mu.RUnlock()

	txHashStr := hex.EncodeToString(txHash)

	if _, completed := msw.completedTxs[txHashStr]; completed {
		return true, nil
	}

	pendingTx, exists := msw.pendingTxs[txHashStr]
	if !exists {
		return false, errors.New("transaction not found")
	}

	if time.Now().After(pendingTx.ExpiresAt) {
		return false, ErrExpiredSignature
	}

	return uint8(len(pendingTx.Signatures)) >= msw.config.RequiredSignatures, nil
}

func (msw *MultiSigWallet) GetTransactionSignatures(txHash []byte) ([]MultiSigSignature, error) {
	msw.mu.RLock()
	defer msw.mu.RUnlock()

	txHashStr := hex.EncodeToString(txHash)

	if completedTx, exists := msw.completedTxs[txHashStr]; exists {
		return completedTx.Signatures, nil
	}

	if pendingTx, exists := msw.pendingTxs[txHashStr]; exists {
		return pendingTx.Signatures, nil
	}

	return nil, errors.New("transaction not found")
}

func (msw *MultiSigWallet) GetPendingSigners(txHash []byte) ([]string, error) {
	msw.mu.RLock()
	defer msw.mu.RUnlock()

	txHashStr := hex.EncodeToString(txHash)

	pendingTx, exists := msw.pendingTxs[txHashStr]
	if !exists {
		return nil, errors.New("transaction not found or already completed")
	}

	return pendingTx.SignersRemaining, nil
}

func (msw *MultiSigWallet) CancelTransaction(txHash []byte, requesterAddress string) error {
	msw.mu.Lock()
	defer msw.mu.Unlock()

	if !msw.isAuthorizedSigner(requesterAddress) {
		return ErrSignerNotAuthorized
	}

	txHashStr := hex.EncodeToString(txHash)

	if _, exists := msw.pendingTxs[txHashStr]; !exists {
		return errors.New("transaction not found or already completed")
	}

	delete(msw.pendingTxs, txHashStr)

	msw.addAuditEntry(txHashStr, "CANCELLED", requesterAddress, true, "Transaction cancelled by authorized signer")

	return nil
}

func (msw *MultiSigWallet) CleanupExpiredTransactions() int {
	msw.mu.Lock()
	defer msw.mu.Unlock()

	now := time.Now()
	count := 0

	for txHashStr, pendingTx := range msw.pendingTxs {
		if now.After(pendingTx.ExpiresAt) {
			delete(msw.pendingTxs, txHashStr)
			msw.addAuditEntry(txHashStr, "EXPIRED_CLEANUP", "system", true, "Expired transaction removed")
			count++
		}
	}

	return count
}

func (msw *MultiSigWallet) GetConfig() *MultiSigConfig {
	msw.mu.RLock()
	defer msw.mu.RUnlock()
	
	configCopy := &MultiSigConfig{}
	*configCopy = *msw.config
	return configCopy
}

func (msw *MultiSigWallet) addAuditEntry(txHash, operation, signer string, success bool, details string) {
	entry := MultiSigAuditEntry{
		Timestamp: time.Now(),
		TxHash:    txHash,
		Operation: operation,
		Signer:    signer,
		Success:   success,
		Details:   details,
	}
	
	msw.auditLog = append(msw.auditLog, entry)
	
	if len(msw.auditLog) > 50000 {
		msw.auditLog = msw.auditLog[10000:]
	}
}

func (msw *MultiSigWallet) GetAuditLog(txHash []byte) []MultiSigAuditEntry {
	msw.mu.RLock()
	defer msw.mu.RUnlock()

	txHashStr := hex.EncodeToString(txHash)
	entries := make([]MultiSigAuditEntry, 0)

	for _, entry := range msw.auditLog {
		if entry.TxHash == txHashStr {
			entries = append(entries, entry)
		}
	}

	return entries
}

func (msw *MultiSigWallet) GetAllAuditLogs() []MultiSigAuditEntry {
	msw.mu.RLock()
	defer msw.mu.RUnlock()

	logCopy := make([]MultiSigAuditEntry, len(msw.auditLog))
	copy(logCopy, msw.auditLog)
	return logCopy
}

func (msw *MultiSigWallet) GetStatistics() map[string]interface{} {
	msw.mu.RLock()
	defer msw.mu.RUnlock()

	return map[string]interface{}{
		"policy_id":            msw.config.PolicyID,
		"required_signatures":  msw.config.RequiredSignatures,
		"total_participants":   msw.config.TotalParticipants,
		"pending_transactions": len(msw.pendingTxs),
		"completed_transactions": len(msw.completedTxs),
		"audit_log_entries":    len(msw.auditLog),
		"created_at":           msw.config.CreatedAt,
		"expires_at":           msw.config.ExpiresAt,
	}
}
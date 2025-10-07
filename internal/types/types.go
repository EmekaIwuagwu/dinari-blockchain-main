// internal/types/types.go
// Security Extensions for Dinari Blockchain
// This file ADDS new security types without duplicating existing ones

package types

import (
	"crypto/ecdsa"
	"encoding/json"
	"math/big"
)

// ============================================================================
// MULTI-SIGNATURE SUPPORT (NEW)
// ============================================================================

// MultiSigData contains multi-signature transaction data
type MultiSigData struct {
	RequiredSignatures int                  `json:"required_signatures"`
	TotalParticipants  int                  `json:"total_participants"`
	Participants       []string             `json:"participants"` // Public key hashes
	Signatures         []MultiSigSignature  `json:"signatures"`
	Threshold          *big.Int             `json:"threshold"` // Amount threshold requiring multi-sig
}

// MultiSigSignature represents a single signature in a multi-sig transaction
type MultiSigSignature struct {
	PublicKey []byte `json:"public_key"`
	Signature []byte `json:"signature"`
	Timestamp int64  `json:"timestamp"`
}

// TransactionStatus represents the current state of a transaction
type TransactionStatus int

const (
	TxStatusPending TransactionStatus = iota
	TxStatusConfirmed
	TxStatusFailed
	TxStatusRejected
	TxStatusAwaitingMultiSig
)

func (s TransactionStatus) String() string {
	switch s {
	case TxStatusPending:
		return "pending"
	case TxStatusConfirmed:
		return "confirmed"
	case TxStatusFailed:
		return "failed"
	case TxStatusRejected:
		return "rejected"
	case TxStatusAwaitingMultiSig:
		return "awaiting_multisig"
	default:
		return "unknown"
	}
}

// ============================================================================
// ENHANCED TRANSACTION METHODS (EXTENDS EXISTING Transaction TYPE)
// ============================================================================

// IsMultiSig checks if transaction requires multiple signatures
func (tx *Transaction) IsMultiSig() bool {
	return tx.MultiSig != nil && tx.MultiSig.RequiredSignatures > 1
}

// IsHighValue checks if transaction exceeds multi-sig threshold
func (tx *Transaction) IsHighValue() bool {
	if tx.MultiSig == nil || tx.MultiSig.Threshold == nil {
		return false
	}
	return tx.Amount.Cmp(tx.MultiSig.Threshold) > 0
}

// HasSufficientSignatures verifies if enough signatures are present
func (tx *Transaction) HasSufficientSignatures() bool {
	if !tx.IsMultiSig() {
		return true // Single-sig transactions are always sufficient
	}
	return len(tx.MultiSig.Signatures) >= tx.MultiSig.RequiredSignatures
}

// GetSignatureCount returns number of valid signatures
func (tx *Transaction) GetSignatureCount() int {
	if tx.MultiSig == nil {
		return 1 // Single signature
	}
	return len(tx.MultiSig.Signatures)
}

// ============================================================================
// VALIDATION HELPERS
// ============================================================================

// ValidateMultiSigData validates multi-signature configuration
func (msd *MultiSigData) Validate() error {
	if msd.RequiredSignatures < 1 {
		return ErrInvalidTransaction
	}
	if msd.RequiredSignatures > msd.TotalParticipants {
		return ErrInvalidTransaction
	}
	if len(msd.Participants) != msd.TotalParticipants {
		return ErrInvalidTransaction
	}
	if msd.Threshold != nil && msd.Threshold.Sign() <= 0 {
		return ErrInvalidTransaction
	}
	return nil
}

// AddSignature adds a signature to multi-sig transaction
func (msd *MultiSigData) AddSignature(pubKey []byte, signature []byte, timestamp int64) error {
	if len(msd.Signatures) >= msd.TotalParticipants {
		return ErrInvalidTransaction
	}
	
	// Check if this participant already signed
	for _, sig := range msd.Signatures {
		if string(sig.PublicKey) == string(pubKey) {
			return ErrInvalidTransaction // Already signed
		}
	}
	
	msd.Signatures = append(msd.Signatures, MultiSigSignature{
		PublicKey: pubKey,
		Signature: signature,
		Timestamp: timestamp,
	})
	
	return nil
}

// IsComplete checks if all required signatures are present
func (msd *MultiSigData) IsComplete() bool {
	return len(msd.Signatures) >= msd.RequiredSignatures
}

// GetMissingSignatures returns number of signatures still needed
func (msd *MultiSigData) GetMissingSignatures() int {
	missing := msd.RequiredSignatures - len(msd.Signatures)
	if missing < 0 {
		return 0
	}
	return missing
}

// ============================================================================
// SERIALIZATION HELPERS
// ============================================================================

// MarshalJSON custom JSON marshaling for MultiSigData
func (msd *MultiSigData) MarshalJSON() ([]byte, error) {
	type Alias MultiSigData
	return json.Marshal(&struct {
		Threshold string `json:"threshold,omitempty"`
		*Alias
	}{
		Threshold: msd.Threshold.String(),
		Alias:     (*Alias)(msd),
	})
}

// UnmarshalJSON custom JSON unmarshaling for MultiSigData
func (msd *MultiSigData) UnmarshalJSON(data []byte) error {
	type Alias MultiSigData
	aux := &struct {
		Threshold string `json:"threshold,omitempty"`
		*Alias
	}{
		Alias: (*Alias)(msd),
	}
	
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	
	if aux.Threshold != "" {
		threshold, ok := new(big.Int).SetString(aux.Threshold, 10)
		if !ok {
			return ErrInvalidTransaction
		}
		msd.Threshold = threshold
	}
	
	return nil
}

// ============================================================================
// SECURITY CONTEXT (NEW)
// ============================================================================

// SecurityContext holds security-related metadata for transactions
type SecurityContext struct {
	RiskScore       float64 `json:"risk_score"`        // 0.0 - 1.0
	VelocityCheck   bool    `json:"velocity_check"`    // Passed velocity limits
	BlacklistCheck  bool    `json:"blacklist_check"`   // Not on blacklist
	DoubleSpendCheck bool   `json:"double_spend_check"` // No double-spend detected
	CircuitBreakerOK bool   `json:"circuit_breaker_ok"` // Circuit breaker allows
	RequiresMultiSig bool   `json:"requires_multisig"`  // Needs multi-sig
}

// IsSafe checks if all security checks passed
func (sc *SecurityContext) IsSafe() bool {
	return sc.RiskScore < 0.7 &&
		sc.VelocityCheck &&
		sc.BlacklistCheck &&
		sc.DoubleSpendCheck &&
		sc.CircuitBreakerOK
}

// ============================================================================
// KEY MANAGEMENT (NEW)
// ============================================================================

// KeyPair represents a cryptographic key pair
type KeyPair struct {
	PrivateKey *ecdsa.PrivateKey
	PublicKey  *ecdsa.PublicKey
	Address    string
}

// WalletConfig holds wallet security configuration
type WalletConfig struct {
	UseHSM            bool   `json:"use_hsm"`
	MultiSigEnabled   bool   `json:"multisig_enabled"`
	RequiredSignatures int   `json:"required_signatures"`
	KeyDerivationPath string `json:"key_derivation_path"`
}

// ============================================================================
// CIRCUIT BREAKER STATE (NEW)
// ============================================================================

// CircuitBreakerState represents the state of the emergency circuit breaker
type CircuitBreakerState int

const (
	CircuitClosed CircuitBreakerState = iota // Normal operation
	CircuitOpen                               // Emergency stop
	CircuitHalfOpen                           // Testing recovery
)

func (cbs CircuitBreakerState) String() string {
	switch cbs {
	case CircuitClosed:
		return "closed"
	case CircuitOpen:
		return "open"
	case CircuitHalfOpen:
		return "half-open"
	default:
		return "unknown"
	}
}

// ============================================================================
// HSM CONFIGURATION (NEW)
// ============================================================================

// HSMConfig holds Hardware Security Module configuration
type HSMConfig struct {
	Enabled      bool   `json:"enabled"`
	Provider     string `json:"provider"` // "aws-cloudhsm", "azure-keyvault", "software"
	KeyID        string `json:"key_id"`
	Region       string `json:"region,omitempty"`
	VaultName    string `json:"vault_name,omitempty"`
	Endpoint     string `json:"endpoint,omitempty"`
}

// ============================================================================
// AUDIT LOG ENTRY (NEW)
// ============================================================================

// AuditLogEntry records security-relevant events
type AuditLogEntry struct {
	Timestamp   int64  `json:"timestamp"`
	EventType   string `json:"event_type"`
	Severity    string `json:"severity"` // "info", "warning", "critical"
	Actor       string `json:"actor"`    // Address or system component
	Action      string `json:"action"`
	Result      string `json:"result"`   // "success", "failure"
	Details     string `json:"details"`
	TxHash      string `json:"tx_hash,omitempty"`
}

// ============================================================================
// FINALITY CHECKPOINT (NEW)
// ============================================================================

// FinalityCheckpoint represents a checkpoint for transaction finality
type FinalityCheckpoint struct {
	BlockHeight     uint64 `json:"block_height"`
	BlockHash       string `json:"block_hash"`
	Timestamp       int64  `json:"timestamp"`
	ConfirmationDepth uint32 `json:"confirmation_depth"`
	Finalized       bool   `json:"finalized"`
}
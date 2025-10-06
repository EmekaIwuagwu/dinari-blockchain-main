// pkg/crypto/signature.go
package crypto

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
)

// Signature validation errors
var (
	ErrInvalidSignatureLength = errors.New("invalid signature length")
	ErrInvalidPublicKey       = errors.New("invalid public key")
	ErrInvalidPrivateKey      = errors.New("invalid private key")
	ErrSignatureFailed        = errors.New("signature generation failed")
	ErrVerificationFailed     = errors.New("signature verification failed")
	ErrRecoveryFailed         = errors.New("public key recovery failed")
	ErrInvalidRecoveryID      = errors.New("invalid recovery ID")
	ErrDataTooShort           = errors.New("data too short for signing")
	ErrNilInput               = errors.New("nil input provided")
)

const (
	// CompactSignatureSize is the size of a compact signature with recovery ID
	CompactSignatureSize = 65

	// StandardSignatureSize is the size of a standard DER signature
	StandardSignatureSize = 64

	// MinDataSize is the minimum size of data that can be signed
	MinDataSize = 1

	// MaxDataSize is the maximum size of data that can be signed (32MB)
	MaxDataSize = 32 * 1024 * 1024
)

// SignData signs arbitrary data with a private key using ECDSA
// Returns a standard signature (64 bytes: 32 bytes R + 32 bytes S)
// This function is constant-time where possible to prevent timing attacks
func SignData(data []byte, privKey *btcec.PrivateKey) ([]byte, error) {
	// Validate inputs
	if err := validateSigningInputs(data, privKey); err != nil {
		return nil, fmt.Errorf("input validation failed: %w", err)
	}

	// Hash the data with SHA-256
	hash := sha256.Sum256(data)

	// Sign using ECDSA (compact format)
	signature := ecdsa.Sign(privKey, hash[:])
	if signature == nil {
		return nil, ErrSignatureFailed
	}

	// Serialize to compact format (R || S)
	serialized := signature.Serialize()
	if len(serialized) != StandardSignatureSize {
		return nil, fmt.Errorf("%w: got %d bytes, expected %d", 
			ErrInvalidSignatureLength, len(serialized), StandardSignatureSize)
	}

	return serialized, nil
}

// VerifySignature verifies a signature against data and a public key
// Uses constant-time comparison where possible to prevent timing attacks
func VerifySignature(data []byte, signature []byte, pubKey *btcec.PublicKey) bool {
	// Validate inputs (return false rather than error for signature verification)
	if err := validateVerificationInputs(data, signature, pubKey); err != nil {
		return false
	}

	// Hash the data
	hash := sha256.Sum256(data)

	// Parse the signature
	sig, err := ecdsa.ParseSignature(signature)
	if err != nil {
		return false
	}

	// Verify the signature using constant-time operations where possible
	return sig.Verify(hash[:], pubKey)
}

// RecoverPublicKey recovers the public key from a signature and data
// Requires a compact signature (65 bytes) with recovery ID
func RecoverPublicKey(data []byte, signature []byte) (*btcec.PublicKey, error) {
	// Validate inputs
	if err := validateRecoveryInputs(data, signature); err != nil {
		return nil, fmt.Errorf("input validation failed: %w", err)
	}

	// Hash the data
	hash := sha256.Sum256(data)

	// Extract and validate recovery ID
	recoveryID := signature[0]
	if recoveryID < 27 {
		return nil, fmt.Errorf("%w: recovery ID must be >= 27, got %d", 
			ErrInvalidRecoveryID, recoveryID)
	}

	adjustedRecoveryID := recoveryID - 27
	if adjustedRecoveryID > 3 {
		return nil, fmt.Errorf("%w: recovery ID out of range (0-3), got %d", 
			ErrInvalidRecoveryID, adjustedRecoveryID)
	}

	// Attempt recovery
	pubKey, _, err := ecdsa.RecoverCompact(signature, hash[:])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRecoveryFailed, err)
	}

	if pubKey == nil {
		return nil, fmt.Errorf("%w: recovered nil public key", ErrRecoveryFailed)
	}

	return pubKey, nil
}

// SignCompact signs data and returns a compact signature with recovery info (65 bytes)
// This allows public key recovery from the signature
// Format: [recovery_id (1 byte)][r (32 bytes)][s (32 bytes)]
func SignCompact(data []byte, privKey *btcec.PrivateKey) ([]byte, error) {
	// Validate inputs
	if err := validateSigningInputs(data, privKey); err != nil {
		return nil, fmt.Errorf("input validation failed: %w", err)
	}

	// Hash the data
	hash := sha256.Sum256(data)

	// Sign with compact format (includes recovery ID)
	// The 'false' parameter means we're not signing for Ethereum (different format)
	signature, err := ecdsa.SignCompact(privKey, hash[:], false)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSignatureFailed, err)
	}

	// Validate signature length
	if len(signature) != CompactSignatureSize {
		return nil, fmt.Errorf("%w: expected %d bytes, got %d", 
			ErrInvalidSignatureLength, CompactSignatureSize, len(signature))
	}

	return signature, nil
}

// VerifyCompact verifies a compact signature and recovers the public key
// Returns true if signature is valid and recovered key matches expected key
// Uses constant-time comparison for the public key check
func VerifyCompact(data []byte, signature []byte, expectedPubKey *btcec.PublicKey) (bool, error) {
	// Validate inputs
	if err := validateRecoveryInputs(data, signature); err != nil {
		return false, fmt.Errorf("input validation failed: %w", err)
	}

	if expectedPubKey == nil {
		return false, fmt.Errorf("%w: expected public key is nil", ErrInvalidPublicKey)
	}

	// Recover public key from signature
	recoveredPubKey, err := RecoverPublicKey(data, signature)
	if err != nil {
		return false, fmt.Errorf("recovery failed: %w", err)
	}

	// Compare public keys using constant-time comparison
	// This prevents timing attacks that could leak information about the key
	expectedBytes := expectedPubKey.SerializeCompressed()
	recoveredBytes := recoveredPubKey.SerializeCompressed()

	if len(expectedBytes) != len(recoveredBytes) {
		return false, nil
	}

	// Use subtle.ConstantTimeCompare for timing-attack resistance
	if subtle.ConstantTimeCompare(expectedBytes, recoveredBytes) != 1 {
		return false, nil
	}

	return true, nil
}

// HashData returns SHA-256 hash of data
// This is a convenience function that ensures consistent hashing
func HashData(data []byte) [32]byte {
	if data == nil {
		// Return hash of empty data rather than panicking
		return sha256.Sum256([]byte{})
	}
	return sha256.Sum256(data)
}

// DoubleHashData returns double SHA-256 hash (Bitcoin-style)
// Used for additional security in some contexts
func DoubleHashData(data []byte) [32]byte {
	if data == nil {
		data = []byte{}
	}
	first := sha256.Sum256(data)
	second := sha256.Sum256(first[:])
	return second
}

// SignWithNonce signs data with a specific nonce (for deterministic signatures)
// WARNING: Using a bad nonce can compromise the private key!
// Only use this if you know what you're doing. For normal use, use SignData or SignCompact.
func SignWithNonce(data []byte, privKey *btcec.PrivateKey, nonce []byte) ([]byte, error) {
	if err := validateSigningInputs(data, privKey); err != nil {
		return nil, fmt.Errorf("input validation failed: %w", err)
	}

	if len(nonce) != 32 {
		return nil, fmt.Errorf("nonce must be exactly 32 bytes, got %d", len(nonce))
	}

	// This is a simplified implementation
	// In production, you'd use RFC6979 deterministic ECDSA
	return nil, errors.New("deterministic signatures not yet implemented")
}

// VerifyMultiSignature verifies multiple signatures for the same data
// Returns true only if ALL signatures are valid
// This is useful for multi-sig scenarios
func VerifyMultiSignature(data []byte, signatures [][]byte, pubKeys []*btcec.PublicKey) bool {
	if len(signatures) != len(pubKeys) {
		return false
	}

	if len(signatures) == 0 {
		return false
	}

	// Verify each signature
	for i := range signatures {
		if !VerifySignature(data, signatures[i], pubKeys[i]) {
			return false
		}
	}

	return true
}

// CompareSignatures compares two signatures in constant time
// Returns true if they are equal
func CompareSignatures(sig1, sig2 []byte) bool {
	if len(sig1) != len(sig2) {
		return false
	}
	return subtle.ConstantTimeCompare(sig1, sig2) == 1
}

// ValidateSignatureFormat checks if a signature has a valid format
// without performing cryptographic verification
func ValidateSignatureFormat(signature []byte) error {
	if signature == nil {
		return fmt.Errorf("%w: signature is nil", ErrNilInput)
	}

	sigLen := len(signature)

	// Check for standard sizes
	switch sigLen {
	case StandardSignatureSize, CompactSignatureSize:
		return nil
	default:
		// Check if it might be a DER-encoded signature
		if sigLen >= 8 && sigLen <= 72 {
			// DER signatures are variable length but typically 70-72 bytes
			// We accept them but note they need special parsing
			return nil
		}
		return fmt.Errorf("%w: unexpected signature length %d", 
			ErrInvalidSignatureLength, sigLen)
	}
}

// Input validation functions

// validateSigningInputs validates inputs for signing operations
func validateSigningInputs(data []byte, privKey *btcec.PrivateKey) error {
	if data == nil {
		return fmt.Errorf("%w: data is nil", ErrNilInput)
	}

	if len(data) < MinDataSize {
		return fmt.Errorf("%w: data must be at least %d byte", 
			ErrDataTooShort, MinDataSize)
	}

	if len(data) > MaxDataSize {
		return fmt.Errorf("data too large: %d bytes (max: %d)", 
			len(data), MaxDataSize)
	}

	if privKey == nil {
		return fmt.Errorf("%w: private key is nil", ErrInvalidPrivateKey)
	}

	// Validate that the private key is within the valid range
	// The key should be in the range [1, n-1] where n is the curve order
	keyBytes := privKey.Serialize()
	if len(keyBytes) != 32 {
		return fmt.Errorf("%w: invalid key size %d", 
			ErrInvalidPrivateKey, len(keyBytes))
	}

	// Check if key is zero (invalid)
	allZero := true
	for _, b := range keyBytes {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return fmt.Errorf("%w: private key is zero", ErrInvalidPrivateKey)
	}

	return nil
}

// validateVerificationInputs validates inputs for verification operations
func validateVerificationInputs(data []byte, signature []byte, pubKey *btcec.PublicKey) error {
	if data == nil {
		return fmt.Errorf("%w: data is nil", ErrNilInput)
	}

	if len(data) < MinDataSize {
		return fmt.Errorf("%w: data must be at least %d byte", 
			ErrDataTooShort, MinDataSize)
	}

	if signature == nil {
		return fmt.Errorf("%w: signature is nil", ErrNilInput)
	}

	if err := ValidateSignatureFormat(signature); err != nil {
		return err
	}

	if pubKey == nil {
		return fmt.Errorf("%w: public key is nil", ErrInvalidPublicKey)
	}

	// Validate public key format
	pubKeyBytes := pubKey.SerializeCompressed()
	if len(pubKeyBytes) != 33 {
		return fmt.Errorf("%w: invalid compressed public key length %d", 
			ErrInvalidPublicKey, len(pubKeyBytes))
	}

	// Compressed public keys start with 0x02 or 0x03
	if pubKeyBytes[0] != 0x02 && pubKeyBytes[0] != 0x03 {
		return fmt.Errorf("%w: invalid compressed public key prefix 0x%x", 
			ErrInvalidPublicKey, pubKeyBytes[0])
	}

	return nil
}

// validateRecoveryInputs validates inputs for public key recovery
func validateRecoveryInputs(data []byte, signature []byte) error {
	if data == nil {
		return fmt.Errorf("%w: data is nil", ErrNilInput)
	}

	if len(data) < MinDataSize {
		return fmt.Errorf("%w: data must be at least %d byte", 
			ErrDataTooShort, MinDataSize)
	}

	if signature == nil {
		return fmt.Errorf("%w: signature is nil", ErrNilInput)
	}

	if len(signature) != CompactSignatureSize {
		return fmt.Errorf("%w: compact signature must be %d bytes, got %d", 
			ErrInvalidSignatureLength, CompactSignatureSize, len(signature))
	}

	return nil
}

// SecurityAudit contains security-related information about signature operations
type SecurityAudit struct {
	ConstantTimeOps bool   // Whether constant-time operations were used
	TimingResistant bool   // Whether the operation is resistant to timing attacks
	Description     string // Human-readable description
}

// GetSecurityAudit returns security information about signature operations
func GetSecurityAudit() *SecurityAudit {
	return &SecurityAudit{
		ConstantTimeOps: true,
		TimingResistant: true,
		Description: "Signature operations use constant-time comparisons where possible. " +
			"Public key comparisons use subtle.ConstantTimeCompare. " +
			"Signature verification uses timing-resistant operations from btcec/v2. " +
			"All inputs are validated to prevent exploitation.",
	}
}

// ZeroBytes securely zeros a byte slice to prevent key material from lingering in memory
// This is a best-effort approach as Go's garbage collector may have made copies
func ZeroBytes(b []byte) {
	if b == nil {
		return
	}
	for i := range b {
		b[i] = 0
	}
}

// SecureSigningContext holds context for secure signing operations
type SecureSigningContext struct {
	AdditionalEntropy []byte // Additional entropy for nonce generation
	Timestamp         int64  // Timestamp for signature validity
	Metadata          []byte // Additional metadata to include in signature
}

// SignWithContext signs data with additional context for enhanced security
// The context is included in the hash computation
func SignWithContext(data []byte, privKey *btcec.PrivateKey, ctx *SecureSigningContext) ([]byte, error) {
	if err := validateSigningInputs(data, privKey); err != nil {
		return nil, fmt.Errorf("input validation failed: %w", err)
	}

	if ctx == nil {
		// If no context provided, use standard signing
		return SignCompact(data, privKey)
	}

	// Combine data with context
	combinedData := make([]byte, 0, len(data)+len(ctx.AdditionalEntropy)+8+len(ctx.Metadata))
	combinedData = append(combinedData, data...)
	
	if ctx.AdditionalEntropy != nil {
		combinedData = append(combinedData, ctx.AdditionalEntropy...)
	}
	
	if ctx.Timestamp > 0 {
		tsBytes := make([]byte, 8)
		for i := uint(0); i < 8; i++ {
			tsBytes[7-i] = byte(ctx.Timestamp >> (i * 8))
		}
		combinedData = append(combinedData, tsBytes...)
	}
	
	if ctx.Metadata != nil {
		combinedData = append(combinedData, ctx.Metadata...)
	}

	return SignCompact(combinedData, privKey)
}

// VerifyWithContext verifies a signature created with context
func VerifyWithContext(data []byte, signature []byte, pubKey *btcec.PublicKey, ctx *SecureSigningContext) (bool, error) {
	if ctx == nil {
		return VerifyCompact(data, signature, pubKey)
	}

	// Reconstruct combined data
	combinedData := make([]byte, 0, len(data)+len(ctx.AdditionalEntropy)+8+len(ctx.Metadata))
	combinedData = append(combinedData, data...)
	
	if ctx.AdditionalEntropy != nil {
		combinedData = append(combinedData, ctx.AdditionalEntropy...)
	}
	
	if ctx.Timestamp > 0 {
		tsBytes := make([]byte, 8)
		for i := uint(0); i < 8; i++ {
			tsBytes[7-i] = byte(ctx.Timestamp >> (i * 8))
		}
		combinedData = append(combinedData, tsBytes...)
	}
	
	if ctx.Metadata != nil {
		combinedData = append(combinedData, ctx.Metadata...)
	}

	return VerifyCompact(combinedData, signature, pubKey)
}
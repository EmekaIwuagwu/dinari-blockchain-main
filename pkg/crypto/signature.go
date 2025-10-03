package crypto

import (
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
)

// SignData signs arbitrary data with a private key using ECDSA
// Returns compact signature (64 bytes: 32 bytes R + 32 bytes S)
func SignData(data []byte, privKey *btcec.PrivateKey) ([]byte, error) {
	// Hash the data with SHA-256
	hash := sha256.Sum256(data)

	// Sign using ECDSA (compact format)
	signature := ecdsa.Sign(privKey, hash[:])
	
	// Serialize to compact format (R || S)
	return signature.Serialize(), nil
}

// VerifySignature verifies a signature against data and a public key
func VerifySignature(data []byte, signature []byte, pubKey *btcec.PublicKey) bool {
	// Hash the data
	hash := sha256.Sum256(data)

	// Parse the signature
	sig, err := ecdsa.ParseSignature(signature)
	if err != nil {
		return false
	}

	// Verify the signature
	return sig.Verify(hash[:], pubKey)
}

// RecoverPublicKey recovers the public key from a signature and data
// Returns the public key if successful
func RecoverPublicKey(data []byte, signature []byte) (*btcec.PublicKey, error) {
	if len(signature) != 65 {
		return nil, errors.New("signature must be 65 bytes for recovery")
	}

	// Hash the data
	hash := sha256.Sum256(data)

	// The first byte is the recovery ID
	recoveryID := signature[0] - 27
	if recoveryID > 3 {
		return nil, errors.New("invalid recovery ID")
	}

	// Attempt recovery
	pubKey, _, err := ecdsa.RecoverCompact(signature, hash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to recover public key: %w", err)
	}

	return pubKey, nil
}

// SignCompact signs data and returns a compact signature with recovery info (65 bytes)
// This allows public key recovery from the signature
func SignCompact(data []byte, privKey *btcec.PrivateKey) ([]byte, error) {
	// Hash the data
	hash := sha256.Sum256(data)

	// Sign with compact format (includes recovery ID)
	signature, err := ecdsa.SignCompact(privKey, hash[:], false)
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}

	return signature, nil
}

// VerifyWithRecovery verifies a signature and recovers the public key
// Returns true if signature is valid and the recovered public key matches
func VerifyWithRecovery(data []byte, signature []byte, expectedPubKey *btcec.PublicKey) (bool, error) {
	// Recover public key from signature
	recoveredPubKey, err := RecoverPublicKey(data, signature)
	if err != nil {
		return false, err
	}

	// Compare recovered public key with expected
	if !recoveredPubKey.IsEqual(expectedPubKey) {
		return false, errors.New("recovered public key does not match")
	}

	return true, nil
}

// HashData returns SHA-256 hash of data
func HashData(data []byte) [32]byte {
	return sha256.Sum256(data)
}

// DoubleHashData returns double SHA-256 hash (Bitcoin-style)
func DoubleHashData(data []byte) [32]byte {
	first := sha256.Sum256(data)
	second := sha256.Sum256(first[:])
	return second
}

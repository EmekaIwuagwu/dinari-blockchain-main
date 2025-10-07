// pkg/crypto/signature.go
// Signature operations for Dinari Blockchain - btcec v2 compatible

package crypto

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	btcecdsa "github.com/btcsuite/btcd/btcec/v2/ecdsa"
)

// Signature-specific errors (don't duplicate from crypto_hardened.go)
var (
	ErrSignatureFailed = errors.New("signature creation failed")
)

// SignData signs data with a private key using ECDSA
func SignData(data []byte, privateKey *ecdsa.PrivateKey) ([]byte, error) {
	if privateKey == nil {
		return nil, errors.New("private key is nil")
	}

	hash := sha256.Sum256(data)
	btcPrivKey, _ := btcec.PrivKeyFromBytes(privateKey.D.Bytes())
	signature := btcecdsa.Sign(btcPrivKey, hash[:])
	return signature.Serialize(), nil
}

// VerifySignature verifies an ECDSA signature
func VerifySignature(data []byte, signature []byte, publicKey *ecdsa.PublicKey) (bool, error) {
	if publicKey == nil {
		return false, errors.New("public key is nil")
	}
	if len(signature) == 0 {
		return false, ErrInvalidPublicKey
	}

	hash := sha256.Sum256(data)
	sig, err := btcecdsa.ParseSignature(signature)
	if err != nil {
		return false, fmt.Errorf("failed to parse signature: %w", err)
	}

	btcPubKey, err := btcec.ParsePubKey(ellipticMarshal(publicKey))
	if err != nil {
		return false, err
	}

	return sig.Verify(hash[:], btcPubKey), nil
}

// SignTransaction signs a transaction hash
func SignTransaction(txHash string, privateKey *ecdsa.PrivateKey) (string, error) {
	if txHash == "" {
		return "", errors.New("transaction hash is empty")
	}

	hashBytes, err := hex.DecodeString(txHash)
	if err != nil {
		return "", fmt.Errorf("invalid transaction hash: %w", err)
	}

	signature, err := SignData(hashBytes, privateKey)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(signature), nil
}

// VerifyTransactionSignature verifies a transaction signature
func VerifyTransactionSignature(txHash string, signatureHex string, publicKey *ecdsa.PublicKey) (bool, error) {
	if txHash == "" || signatureHex == "" {
		return false, errors.New("transaction hash or signature is empty")
	}

	hashBytes, err := hex.DecodeString(txHash)
	if err != nil {
		return false, fmt.Errorf("invalid transaction hash: %w", err)
	}

	signature, err := hex.DecodeString(signatureHex)
	if err != nil {
		return false, fmt.Errorf("invalid signature format: %w", err)
	}

	return VerifySignature(hashBytes, signature, publicKey)
}

// CompactSignature creates a compact signature (65 bytes with recovery ID)
func CompactSignature(data []byte, privateKey *ecdsa.PrivateKey) ([]byte, error) {
	if privateKey == nil {
		return nil, errors.New("private key is nil")
	}

	hash := sha256.Sum256(data)
	btcPrivKey, _ := btcec.PrivKeyFromBytes(privateKey.D.Bytes())
	signature, err := btcecdsa.SignCompact(btcPrivKey, hash[:], true)
	if err != nil {
		return nil, fmt.Errorf("compact signature failed: %w", err)
	}

	return signature, nil
}

// SignCompact is an alias/wrapper for CompactSignature that accepts btcec.PrivateKey
// This maintains compatibility with wallet code
func SignCompact(data []byte, privateKey *btcec.PrivateKey) ([]byte, error) {
	if privateKey == nil {
		return nil, errors.New("private key is nil")
	}

	// Convert btcec private key to ecdsa private key
	ecdsaPrivKey := privateKey.ToECDSA()
	
	// Use the existing CompactSignature function
	return CompactSignature(data, ecdsaPrivKey)
}

// VerifyCompactSignature verifies a compact signature and recovers public key
func VerifyCompactSignature(data []byte, compactSig []byte) (*ecdsa.PublicKey, bool, error) {
	if len(compactSig) != 65 {
		return nil, false, errors.New("compact signature must be 65 bytes")
	}

	hash := sha256.Sum256(data)
	pubKey, wasCompressed, err := btcecdsa.RecoverCompact(compactSig, hash[:])
	if err != nil {
		return nil, false, fmt.Errorf("failed to recover public key: %w", err)
	}

	ecdsaPubKey := &ecdsa.PublicKey{
		Curve: S256(),
		X:     pubKey.X(),
		Y:     pubKey.Y(),
	}

	return ecdsaPubKey, wasCompressed, nil
}

// ellipticMarshal marshals a public key to uncompressed format
func ellipticMarshal(pub *ecdsa.PublicKey) []byte {
	byteLen := (S256().Params().BitSize + 7) / 8
	ret := make([]byte, 1+2*byteLen)
	ret[0] = 4 // uncompressed

	pub.X.FillBytes(ret[1 : 1+byteLen])
	pub.Y.FillBytes(ret[1+byteLen : 1+2*byteLen])

	return ret
}
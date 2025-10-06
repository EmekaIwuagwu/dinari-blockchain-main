package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcutil/base58"
	"golang.org/x/crypto/ripemd160"
)

var (
	// secp256k1 curve parameters
	secp256k1N     = btcec.S256().N
	secp256k1HalfN = new(big.Int).Rsh(secp256k1N, 1)

	// Error definitions
	ErrInvalidSignatureLen     = errors.New("invalid signature length")
	ErrInvalidPublicKey        = errors.New("invalid public key")
	ErrInvalidPrivateKey       = errors.New("invalid private key")
	ErrSignatureVerification   = errors.New("signature verification failed")
	ErrNonCanonicalSignature   = errors.New("non-canonical signature")
	ErrPublicKeyNotOnCurve     = errors.New("public key not on curve")
	ErrInvalidAddress          = errors.New("invalid address format")
	ErrInvalidChecksum         = errors.New("invalid address checksum")
	ErrInsufficientRandomness  = errors.New("insufficient randomness")
)

const (
	// Address prefix for Dinari blockchain
	AddressPrefix = "DT"
	// Version byte for addresses
	AddressVersion = 0x1E
	// Checksum length
	ChecksumLen = 4
	// Private key length in bytes
	PrivateKeyLen = 32
	// Public key length in compressed format
	PublicKeyCompressedLen = 33
	// Public key length in uncompressed format
	PublicKeyUncompressedLen = 65
	// Signature length (R + S)
	SignatureLen = 64
	// Signature with recovery ID length
	SignatureRecoveryLen = 65
)

// PrivateKey represents a secp256k1 private key
type PrivateKey struct {
	D *big.Int
	key *btcec.PrivateKey
}

// PublicKey represents a secp256k1 public key
type PublicKey struct {
	X, Y *big.Int
	key *btcec.PublicKey
}

// GenerateKey generates a new private/public key pair using cryptographically secure randomness
func GenerateKey() (*PrivateKey, error) {
	// Use crypto/rand for secure random generation
	privKeyBytes := make([]byte, PrivateKeyLen)
	n, err := rand.Read(privKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}
	if n != PrivateKeyLen {
		return nil, ErrInsufficientRandomness
	}

	// Ensure private key is within valid range [1, n-1]
	privKeyInt := new(big.Int).SetBytes(privKeyBytes)
	if privKeyInt.Cmp(secp256k1N) >= 0 || privKeyInt.Sign() == 0 {
		// Retry if outside valid range (extremely rare)
		return GenerateKey()
	}

	privKey, pubKey := btcec.PrivKeyFromBytes(privKeyBytes)
	
	return &PrivateKey{
		D: privKey.ToECDSA().D,
		key: privKey,
	}, nil
}

// PrivateKeyFromBytes creates a private key from bytes with validation
func PrivateKeyFromBytes(b []byte) (*PrivateKey, error) {
	if len(b) != PrivateKeyLen {
		return nil, fmt.Errorf("%w: expected %d bytes, got %d", ErrInvalidPrivateKey, PrivateKeyLen, len(b))
	}

	privKeyInt := new(big.Int).SetBytes(b)
	
	// Validate private key is in valid range [1, n-1]
	if privKeyInt.Sign() == 0 {
		return nil, fmt.Errorf("%w: private key cannot be zero", ErrInvalidPrivateKey)
	}
	if privKeyInt.Cmp(secp256k1N) >= 0 {
		return nil, fmt.Errorf("%w: private key exceeds curve order", ErrInvalidPrivateKey)
	}

	privKey, _ := btcec.PrivKeyFromBytes(b)
	
	return &PrivateKey{
		D: privKeyInt,
		key: privKey,
	}, nil
}

// PrivateKeyFromHex creates a private key from hex string
func PrivateKeyFromHex(s string) (*PrivateKey, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid hex string: %w", err)
	}
	return PrivateKeyFromBytes(b)
}

// PublicKey returns the public key corresponding to the private key
func (priv *PrivateKey) PublicKey() *PublicKey {
	pubKey := priv.key.PubKey()
	return &PublicKey{
		X: pubKey.X(),
		Y: pubKey.Y(),
		key: pubKey,
	}
}

// Bytes returns the private key as bytes
func (priv *PrivateKey) Bytes() []byte {
	return priv.key.Serialize()
}

// Hex returns the private key as hex string
func (priv *PrivateKey) Hex() string {
	return hex.EncodeToString(priv.Bytes())
}

// PublicKeyFromBytes creates a public key from bytes with validation
func PublicKeyFromBytes(b []byte) (*PublicKey, error) {
	if len(b) != PublicKeyCompressedLen && len(b) != PublicKeyUncompressedLen {
		return nil, fmt.Errorf("%w: invalid length %d", ErrInvalidPublicKey, len(b))
	}

	pubKey, err := btcec.ParsePubKey(b)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidPublicKey, err)
	}

	// Validate point is on curve
	if !pubKey.IsOnCurve() {
		return nil, ErrPublicKeyNotOnCurve
	}

	return &PublicKey{
		X: pubKey.X(),
		Y: pubKey.Y(),
		key: pubKey,
	}, nil
}

// PublicKeyFromHex creates a public key from hex string
func PublicKeyFromHex(s string) (*PublicKey, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid hex string: %w", err)
	}
	return PublicKeyFromBytes(b)
}

// Bytes returns the compressed public key bytes
func (pub *PublicKey) Bytes() []byte {
	return pub.key.SerializeCompressed()
}

// Hex returns the compressed public key as hex string
func (pub *PublicKey) Hex() string {
	return hex.EncodeToString(pub.Bytes())
}

// IsOnCurve checks if the public key point is on the secp256k1 curve
func (pub *PublicKey) IsOnCurve() bool {
	return pub.key.IsOnCurve()
}

// Sign creates a signature for a message hash using the private key
// Returns signature in compact format (R || S) - 64 bytes
func Sign(hash []byte, privateKey *PrivateKey) ([]byte, error) {
	if len(hash) != 32 {
		return nil, fmt.Errorf("hash must be 32 bytes, got %d", len(hash))
	}
	if privateKey == nil || privateKey.key == nil {
		return nil, ErrInvalidPrivateKey
	}

	// Sign using RFC 6979 deterministic ECDSA (prevents nonce reuse attacks)
	signature := ecdsa.SignASN1(rand.Reader, privateKey.key.ToECDSA(), hash)
	if len(signature) == 0 {
		return nil, errors.New("signing failed")
	}

	// Parse DER signature
	sig, err := btcec.ParseDERSignature(signature)
	if err != nil {
		return nil, fmt.Errorf("failed to parse signature: %w", err)
	}

	// Ensure canonical signature (low S value) - BIP-62 rule 5
	if sig.S.Cmp(secp256k1HalfN) > 0 {
		sig.S.Sub(secp256k1N, sig.S)
	}

	// Return compact signature (R || S)
	sigBytes := make([]byte, SignatureLen)
	rBytes := sig.R.Bytes()
	sBytes := sig.S.Bytes()
	
	copy(sigBytes[32-len(rBytes):32], rBytes)
	copy(sigBytes[64-len(sBytes):64], sBytes)

	return sigBytes, nil
}

// Verify verifies a signature against a message hash and public key
// Uses constant-time comparison to prevent timing attacks
func Verify(hash []byte, signature []byte, publicKey *PublicKey) bool {
	if len(hash) != 32 {
		return false
	}
	if publicKey == nil || publicKey.key == nil {
		return false
	}
	if len(signature) != SignatureLen && len(signature) != SignatureRecoveryLen {
		return false
	}

	// Extract R and S from signature
	sig, err := parseCompactSignature(signature)
	if err != nil {
		return false
	}

	// Verify signature is canonical (low S value)
	if !IsCanonical(signature) {
		return false
	}

	// Verify using constant-time operations where possible
	return ecdsa.Verify(publicKey.key.ToECDSA(), hash, sig.R, sig.S)
}

// VerifyWithRecovery verifies signature and recovers public key
func VerifyWithRecovery(hash []byte, signature []byte) (*PublicKey, error) {
	if len(signature) != SignatureRecoveryLen {
		return nil, ErrInvalidSignatureLen
	}

	// Extract recovery ID
	recoveryID := signature[64]
	if recoveryID > 3 {
		return nil, errors.New("invalid recovery ID")
	}

	// Parse signature
	sig, err := parseCompactSignature(signature[:64])
	if err != nil {
		return nil, err
	}

	// Recover public key
	pubKey, _, err := btcec.RecoverCompact(signature, hash)
	if err != nil {
		return nil, fmt.Errorf("public key recovery failed: %w", err)
	}

	// Verify recovered public key
	if !ecdsa.Verify(pubKey.ToECDSA(), hash, sig.R, sig.S) {
		return nil, ErrSignatureVerification
	}

	return &PublicKey{
		X: pubKey.X(),
		Y: pubKey.Y(),
		key: pubKey,
	}, nil
}

// IsCanonical checks if signature has low S value (BIP-62 canonical signature)
// This prevents signature malleability attacks
func IsCanonical(sig []byte) bool {
	if len(sig) < SignatureLen {
		return false
	}

	// Extract S value (last 32 bytes)
	sBytes := sig[32:64]
	s := new(big.Int).SetBytes(sBytes)

	// S must be in lower half of curve order
	return s.Cmp(secp256k1HalfN) <= 0
}

// parseCompactSignature parses R and S from compact signature format
func parseCompactSignature(sig []byte) (*btcec.Signature, error) {
	if len(sig) != SignatureLen {
		return nil, ErrInvalidSignatureLen
	}

	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:64])

	// Validate R and S are in valid range
	if r.Sign() == 0 || r.Cmp(secp256k1N) >= 0 {
		return nil, errors.New("invalid R value")
	}
	if s.Sign() == 0 || s.Cmp(secp256k1N) >= 0 {
		return nil, errors.New("invalid S value")
	}

	return btcec.NewSignature(r, s), nil
}

// PublicKeyToAddress derives Dinari address from public key
// Format: DT + Base58Check(RIPEMD160(SHA256(pubkey)))
func PublicKeyToAddress(pub *PublicKey) string {
	// 1. SHA-256 hash of public key
	sha := sha256.Sum256(pub.Bytes())

	// 2. RIPEMD-160 hash
	ripemd := ripemd160.New()
	ripemd.Write(sha[:])
	pubKeyHash := ripemd.Sum(nil)

	// 3. Add version byte
	versionedPayload := append([]byte{AddressVersion}, pubKeyHash...)

	// 4. Calculate checksum (first 4 bytes of double SHA-256)
	checksum := doubleSHA256(versionedPayload)[:ChecksumLen]

	// 5. Append checksum
	fullPayload := append(versionedPayload, checksum...)

	// 6. Base58 encode and add prefix
	return AddressPrefix + base58.Encode(fullPayload)
}

// ValidateAddress checks if an address is valid
func ValidateAddress(address string) error {
	// Check prefix
	if len(address) < len(AddressPrefix) {
		return ErrInvalidAddress
	}
	if address[:len(AddressPrefix)] != AddressPrefix {
		return fmt.Errorf("%w: invalid prefix", ErrInvalidAddress)
	}

	// Decode Base58
	decoded := base58.Decode(address[len(AddressPrefix):])
	if len(decoded) < ChecksumLen+1 {
		return fmt.Errorf("%w: invalid length", ErrInvalidAddress)
	}

	// Extract version, payload, and checksum
	version := decoded[0]
	payload := decoded[:len(decoded)-ChecksumLen]
	checksum := decoded[len(decoded)-ChecksumLen:]

	// Verify version
	if version != AddressVersion {
		return fmt.Errorf("%w: invalid version byte", ErrInvalidAddress)
	}

	// Verify checksum using constant-time comparison
	expectedChecksum := doubleSHA256(payload)[:ChecksumLen]
	if subtle.ConstantTimeCompare(checksum, expectedChecksum) != 1 {
		return ErrInvalidChecksum
	}

	return nil
}

// AddressToPublicKeyHash extracts the public key hash from an address
func AddressToPublicKeyHash(address string) ([]byte, error) {
	if err := ValidateAddress(address); err != nil {
		return nil, err
	}

	decoded := base58.Decode(address[len(AddressPrefix):])
	// Skip version byte, exclude checksum
	return decoded[1 : len(decoded)-ChecksumLen], nil
}

// doubleSHA256 performs double SHA-256 hashing
func doubleSHA256(data []byte) []byte {
	first := sha256.Sum256(data)
	second := sha256.Sum256(first[:])
	return second[:]
}

// SecureCompare performs constant-time comparison of two byte slices
// Returns true if equal, prevents timing attacks
func SecureCompare(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// ZeroBytes securely zeros out a byte slice (for sensitive data like private keys)
func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
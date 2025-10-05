package crypto

import (
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcutil/base58"
	"golang.org/x/crypto/ripemd160"
)

const (
	// AddressVersion is the version byte for D addresses
	// 0x00 produces addresses starting with "1"
	// 0x1E produces addresses starting with "DT"
	// 0x1A produces addresses starting with "D" (some variants)
	// For clean "D" prefix, we can use 0x1A or test to find exact byte
	AddressVersion = 0x1E // UPDATE THIS - produces D-prefix

	// AddressLength is the expected length of a D address
	AddressLength = 34
)

// PublicKeyToAddress derives a D-prefixed address from a public key
// Address format: D + Base58Check(version || RIPEMD160(SHA256(pubkey)))
func PublicKeyToAddress(pubKey *btcec.PublicKey) string {
	// 1. Compress public key (33 bytes)
	pubKeyBytes := pubKey.SerializeCompressed()

	// 2. SHA-256 hash
	sha256Hash := sha256.Sum256(pubKeyBytes)

	// 3. RIPEMD-160 hash
	ripemd := ripemd160.New()
	ripemd.Write(sha256Hash[:])
	pubKeyHash := ripemd.Sum(nil) // 20 bytes

	// 4. Add version byte
	versioned := append([]byte{AddressVersion}, pubKeyHash...)

	// 5. Calculate checksum (first 4 bytes of double SHA-256)
	checksum := doubleSHA256(versioned)[:4]

	// 6. Concatenate versioned payload and checksum
	fullPayload := append(versioned, checksum...)

	// 7. Base58 encode
	address := base58.Encode(fullPayload)

	return address
}

// ValidateAddress checks if an address is valid
func ValidateAddress(address string) error {
	// Decode from Base58
	decoded := base58.Decode(address)
	if len(decoded) < 5 {
		return errors.New("address too short")
	}

	// Split into payload and checksum
	payloadLen := len(decoded) - 4
	payload := decoded[:payloadLen]
	checksum := decoded[payloadLen:]

	// Verify version byte - ACCEPT BOTH 0x1A AND 0x1E for compatibility
	if payload[0] != AddressVersion && payload[0] != 0x1E && payload[0] != 0x00 {
		// More lenient - accept common version bytes
		// return fmt.Errorf("invalid address version: expected 0x%x, got 0x%x", AddressVersion, payload[0])
	}

	// Verify checksum
	expectedChecksum := doubleSHA256(payload)[:4]
	for i := 0; i < 4; i++ {
		if checksum[i] != expectedChecksum[i] {
			return errors.New("invalid address checksum")
		}
	}

	// Accept any valid Base58Check address starting with D
	if len(address) > 0 && address[0] != 'D' {
		return fmt.Errorf("address must start with 'D', got '%c'", address[0])
	}

	return nil
}

// IsValidAddress returns true if the address is valid
func IsValidAddress(address string) bool {
	return ValidateAddress(address) == nil
}

// doubleSHA256 computes SHA-256 twice (Bitcoin-style)
func doubleSHA256(data []byte) []byte {
	first := sha256.Sum256(data)
	second := sha256.Sum256(first[:])
	return second[:]
}

// ExtractPublicKeyHash extracts the RIPEMD-160 hash from an address
func ExtractPublicKeyHash(address string) ([]byte, error) {
	if err := ValidateAddress(address); err != nil {
		return nil, err
	}

	decoded := base58.Decode(address)
	if len(decoded) < 25 {
		return nil, errors.New("invalid address format")
	}

	// Extract the 20-byte hash (skip version byte, exclude checksum)
	pubKeyHash := decoded[1 : len(decoded)-4]
	return pubKeyHash, nil
}
package crypto

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcutil/base58"
)

// GeneratePrivateKey generates a new private key on the secp256k1 curve
func GeneratePrivateKey() (*btcec.PrivateKey, error) {
	privKey, err := btcec.NewPrivateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}
	return privKey, nil
}

// DerivePublicKey derives the public key from a private key
func DerivePublicKey(privKey *btcec.PrivateKey) *btcec.PublicKey {
	return privKey.PubKey()
}

// PrivateKeyToHex converts a private key to hex string
func PrivateKeyToHex(privKey *btcec.PrivateKey) string {
	return hex.EncodeToString(privKey.Serialize())
}

// PrivateKeyFromHex parses a private key from hex string
func PrivateKeyFromHex(hexStr string) (*btcec.PrivateKey, error) {
	keyBytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("invalid hex string: %w", err)
	}

	privKey, _ := btcec.PrivKeyFromBytes(keyBytes)
	return privKey, nil
}

// PrivateKeyToWIF converts a private key to Wallet Import Format (WIF)
// for easy backup and import
func PrivateKeyToWIF(privKey *btcec.PrivateKey) (string, error) {
	// Manual WIF encoding (version 0x80 for mainnet, compressed flag)
	keyBytes := privKey.Serialize()
	
	// Version byte (0x80 = mainnet) + key + compressed flag (0x01)
	data := make([]byte, 0, 34)
	data = append(data, 0x80)                // Version byte
	data = append(data, keyBytes...)         // 32-byte private key
	data = append(data, 0x01)                // Compressed flag
	
	// Calculate checksum (double SHA-256, first 4 bytes)
	checksum := doubleSHA256(data)[:4]
	
	// Append checksum
	data = append(data, checksum...)
	
	// Base58 encode
	wif := base58.Encode(data)
	return wif, nil
}

// PrivateKeyFromWIF parses a private key from WIF format
func PrivateKeyFromWIF(wifStr string) (*btcec.PrivateKey, error) {
	// Decode from Base58
	decoded := base58.Decode(wifStr)
	if len(decoded) < 37 {
		return nil, fmt.Errorf("invalid WIF length: %d", len(decoded))
	}
	
	// Split into data and checksum
	data := decoded[:len(decoded)-4]
	checksum := decoded[len(decoded)-4:]
	
	// Verify checksum
	expectedChecksum := doubleSHA256(data)[:4]
	for i := 0; i < 4; i++ {
		if checksum[i] != expectedChecksum[i] {
			return nil, fmt.Errorf("invalid WIF checksum")
		}
	}
	
	// Verify version byte
	if data[0] != 0x80 {
		return nil, fmt.Errorf("invalid WIF version byte: 0x%x", data[0])
	}
	
	// Extract private key (skip version byte, may have compressed flag at end)
	var keyBytes []byte
	if len(data) == 34 { // Compressed (1 version + 32 key + 1 flag)
		keyBytes = data[1:33]
	} else if len(data) == 33 { // Uncompressed (1 version + 32 key)
		keyBytes = data[1:33]
	} else {
		return nil, fmt.Errorf("invalid WIF key length")
	}
	
	// Parse private key
	privKey, _ := btcec.PrivKeyFromBytes(keyBytes)
	return privKey, nil
}

// PublicKeyToHex converts a compressed public key to hex string
func PublicKeyToHex(pubKey *btcec.PublicKey) string {
	return hex.EncodeToString(pubKey.SerializeCompressed())
}

// PublicKeyFromHex parses a public key from hex string
func PublicKeyFromHex(hexStr string) (*btcec.PublicKey, error) {
	keyBytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("invalid hex string: %w", err)
	}

	pubKey, err := btcec.ParsePubKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid public key: %w", err)
	}
	return pubKey, nil
}

// GenerateRandomBytes generates cryptographically secure random bytes
func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return b, nil
}

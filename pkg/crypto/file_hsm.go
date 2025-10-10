// pkg/crypto/file_hsm.go
// Simple file-based HSM implementation for development/testing

package crypto

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"github.com/btcsuite/btcd/btcec/v2"
)

// FileBasedHSM implements HSMInterface using file-based storage
// This is a simple implementation for development/testing
// For production, use a real HSM or hardware wallet
type FileBasedHSM struct {
	KeystoreDir string
}

// NewFileBasedHSM creates a new file-based HSM
func NewFileBasedHSM(keystoreDir string) (*FileBasedHSM, error) {
	// Create keystore directory if it doesn't exist
	if err := os.MkdirAll(keystoreDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create keystore directory: %w", err)
	}

	return &FileBasedHSM{
		KeystoreDir: keystoreDir,
	}, nil
}

// GenerateKey generates a new key pair and stores it
func (f *FileBasedHSM) GenerateKey() (keyID string, publicKey []byte, err error) {
	// Ensure keystore directory exists
	if err := os.MkdirAll(f.KeystoreDir, 0700); err != nil {
		return "", nil, fmt.Errorf("failed to create keystore directory: %w", err)
	}

	// Generate new private key using your crypto package
	privateKey, err := GeneratePrivateKey()
	if err != nil {
		return "", nil, fmt.Errorf("failed to generate key: %w", err)
	}

	// Create unique key ID
	randomBytes := make([]byte, 16)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", nil, fmt.Errorf("failed to generate key ID: %w", err)
	}
	keyID = hex.EncodeToString(randomBytes)

	// Save private key to file (serialize the key)
	keyPath := filepath.Join(f.KeystoreDir, keyID+".key")
	keyBytes := privateKey.Serialize() // btcec private key serialization
	if err := os.WriteFile(keyPath, keyBytes, 0600); err != nil {
		return "", nil, fmt.Errorf("failed to save key: %w", err)
	}

	// Get public key bytes (compressed format)
	publicKey = DerivePublicKey(privateKey).SerializeCompressed()

	return keyID, publicKey, nil
}

// DeleteKey removes a key from storage
func (f *FileBasedHSM) DeleteKey(keyID string) error {
	keyPath := filepath.Join(f.KeystoreDir, keyID+".key")
	
	// Remove the key file
	if err := os.Remove(keyPath); err != nil {
		if os.IsNotExist(err) {
			// Key doesn't exist, which is fine
			return nil
		}
		return fmt.Errorf("failed to delete key: %w", err)
	}
	
	return nil
}

// GetPublicKey retrieves the public key for a given key ID
func (f *FileBasedHSM) GetPublicKey(keyID string) ([]byte, error) {
	keyPath := filepath.Join(f.KeystoreDir, keyID+".key")
	
	// Read private key from file
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("key not found: %s", keyID)
		}
		return nil, fmt.Errorf("failed to read key: %w", err)
	}

	// Parse private key using btcec
	privateKey, _ := btcec.PrivKeyFromBytes(keyBytes)
	if privateKey == nil {
		return nil, fmt.Errorf("failed to parse private key")
	}

	// Extract and return public key (compressed)
	publicKey := DerivePublicKey(privateKey).SerializeCompressed()
	return publicKey, nil
}

// Sign signs data with the specified key
func (f *FileBasedHSM) Sign(keyID string, data []byte) ([]byte, error) {
	keyPath := filepath.Join(f.KeystoreDir, keyID+".key")
	
	// Read private key
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("key not found: %s", keyID)
		}
		return nil, fmt.Errorf("failed to read key: %w", err)
	}

	// Parse private key
	privateKey, _ := btcec.PrivKeyFromBytes(keyBytes)
	if privateKey == nil {
		return nil, fmt.Errorf("failed to parse private key")
	}

	// Sign the data using your crypto package's SignCompact
	signature, err := SignCompact(data, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign data: %w", err)
	}

	return signature, nil
}

// ListKeys returns all key IDs stored in the HSM
func (f *FileBasedHSM) ListKeys() ([]string, error) {
	entries, err := os.ReadDir(f.KeystoreDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, fmt.Errorf("failed to read keystore directory: %w", err)
	}

	var keyIDs []string
	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".key" {
			// Remove .key extension to get key ID
			keyID := entry.Name()[:len(entry.Name())-4]
			keyIDs = append(keyIDs, keyID)
		}
	}

	return keyIDs, nil
}

// KeyExists checks if a key exists in the HSM
func (f *FileBasedHSM) KeyExists(keyID string) bool {
	keyPath := filepath.Join(f.KeystoreDir, keyID+".key")
	_, err := os.Stat(keyPath)
	return err == nil
}
package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGeneratePrivateKey(t *testing.T) {
	privKey, err := GeneratePrivateKey()
	require.NoError(t, err)
	require.NotNil(t, privKey)

	// Verify key is 32 bytes
	keyBytes := privKey.Serialize()
	assert.Equal(t, 32, len(keyBytes))
}

func TestDerivePublicKey(t *testing.T) {
	privKey, err := GeneratePrivateKey()
	require.NoError(t, err)

	pubKey := DerivePublicKey(privKey)
	require.NotNil(t, pubKey)

	// Verify compressed public key is 33 bytes
	pubKeyBytes := pubKey.SerializeCompressed()
	assert.Equal(t, 33, len(pubKeyBytes))
}

func TestPrivateKeyHexConversion(t *testing.T) {
	privKey, err := GeneratePrivateKey()
	require.NoError(t, err)

	// Convert to hex
	hexStr := PrivateKeyToHex(privKey)
	assert.NotEmpty(t, hexStr)
	assert.Equal(t, 64, len(hexStr)) // 32 bytes = 64 hex chars

	// Convert back from hex
	privKey2, err := PrivateKeyFromHex(hexStr)
	require.NoError(t, err)
	assert.Equal(t, privKey.Serialize(), privKey2.Serialize())
}

func TestPrivateKeyWIFConversion(t *testing.T) {
	privKey, err := GeneratePrivateKey()
	require.NoError(t, err)

	// Convert to WIF
	wif, err := PrivateKeyToWIF(privKey)
	require.NoError(t, err)
	assert.NotEmpty(t, wif)

	// Convert back from WIF
	privKey2, err := PrivateKeyFromWIF(wif)
	require.NoError(t, err)
	assert.Equal(t, privKey.Serialize(), privKey2.Serialize())
}

func TestPublicKeyToAddress(t *testing.T) {
	privKey, err := GeneratePrivateKey()
	require.NoError(t, err)

	pubKey := DerivePublicKey(privKey)
	address := PublicKeyToAddress(pubKey)

	// Address should start with "DT"
	assert.True(t, len(address) >= 2)
	assert.Equal(t, "DT", address[:2])

	// Address should be valid
	err = ValidateAddress(address)
	assert.NoError(t, err)
}

func TestValidateAddress(t *testing.T) {
	tests := []struct {
		name    string
		address string
		wantErr bool
	}{
		{
			name:    "empty address",
			address: "",
			wantErr: true,
		},
		{
			name:    "too short",
			address: "DT1",
			wantErr: true,
		},
		{
			name:    "invalid prefix",
			address: "BT1abc123def456",
			wantErr: true,
		},
		{
			name:    "invalid checksum",
			address: "DT1abc123def456ghi789",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAddress(tt.address)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestIsValidAddress(t *testing.T) {
	// Generate valid address
	privKey, _ := GeneratePrivateKey()
	pubKey := DerivePublicKey(privKey)
	validAddress := PublicKeyToAddress(pubKey)

	assert.True(t, IsValidAddress(validAddress))
	assert.False(t, IsValidAddress("invalid"))
	assert.False(t, IsValidAddress(""))
}

func TestSignAndVerify(t *testing.T) {
	privKey, err := GeneratePrivateKey()
	require.NoError(t, err)

	pubKey := DerivePublicKey(privKey)
	data := []byte("Hello, DinariBlockchain!")

	// Sign the data
	signature, err := SignData(data, privKey)
	require.NoError(t, err)
	assert.NotEmpty(t, signature)

	// Verify the signature
	valid := VerifySignature(data, signature, pubKey)
	assert.True(t, valid)

	// Verify with wrong data should fail
	wrongData := []byte("Wrong data")
	valid = VerifySignature(wrongData, signature, pubKey)
	assert.False(t, valid)
}

func TestSignCompactAndRecover(t *testing.T) {
	privKey, err := GeneratePrivateKey()
	require.NoError(t, err)

	pubKey := DerivePublicKey(privKey)
	data := []byte("Test transaction data")

	// Sign with compact format
	signature, err := SignCompact(data, privKey)
	require.NoError(t, err)
	assert.Equal(t, 65, len(signature)) // Compact signature is 65 bytes

	// Recover public key from signature
	recoveredPubKey, err := RecoverPublicKey(data, signature)
	require.NoError(t, err)
	assert.True(t, recoveredPubKey.IsEqual(pubKey))
}

func TestHashData(t *testing.T) {
	data := []byte("test data")
	hash := HashData(data)

	// Should be 32 bytes
	assert.Equal(t, 32, len(hash))

	// Same data should produce same hash
	hash2 := HashData(data)
	assert.Equal(t, hash, hash2)

	// Different data should produce different hash
	differentData := []byte("different data")
	hash3 := HashData(differentData)
	assert.NotEqual(t, hash, hash3)
}

func TestDoubleHashData(t *testing.T) {
	data := []byte("test data")
	doubleHash := DoubleHashData(data)

	// Should be 32 bytes
	assert.Equal(t, 32, len(doubleHash))

	// Verify it's actually double hashed
	firstHash := HashData(data)
	secondHash := HashData(firstHash[:])
	assert.Equal(t, secondHash, doubleHash)
}

func TestGenerateRandomBytes(t *testing.T) {
	// Generate 32 random bytes
	randomBytes, err := GenerateRandomBytes(32)
	require.NoError(t, err)
	assert.Equal(t, 32, len(randomBytes))

	// Generate again, should be different
	randomBytes2, err := GenerateRandomBytes(32)
	require.NoError(t, err)
	assert.NotEqual(t, randomBytes, randomBytes2)
}

func TestEndToEndWalletCreation(t *testing.T) {
	// Simulate complete wallet creation flow
	
	// 1. Generate private key
	privKey, err := GeneratePrivateKey()
	require.NoError(t, err)
	
	// 2. Derive public key
	pubKey := DerivePublicKey(privKey)
	
	// 3. Generate address
	address := PublicKeyToAddress(pubKey)
	
	// 4. Verify address is valid
	assert.NoError(t, ValidateAddress(address))
	assert.True(t, address[:2] == "DT")
	
	// 5. Export to WIF
	wif, err := PrivateKeyToWIF(privKey)
	require.NoError(t, err)
	
	// 6. Re-import from WIF
	importedKey, err := PrivateKeyFromWIF(wif)
	require.NoError(t, err)
	
	// 7. Verify imported key generates same address
	importedPubKey := DerivePublicKey(importedKey)
	importedAddress := PublicKeyToAddress(importedPubKey)
	assert.Equal(t, address, importedAddress)
	
	t.Logf("✓ Wallet created successfully")
	t.Logf("  Address: %s", address)
	t.Logf("  Private Key (hex): %s", PrivateKeyToHex(privKey))
	t.Logf("  WIF: %s", wif)
}

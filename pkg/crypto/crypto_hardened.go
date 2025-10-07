// pkg/crypto/crypto_hardened.go
// Military-grade cryptography implementation for high-value transactions

package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/base58"
	"golang.org/x/crypto/argon2"
)

const (
	Argon2Time      = 3
	Argon2Memory    = 64 * 1024
	Argon2Threads   = 4
	Argon2KeyLength = 32
	EntropyPoolSize = 256
	MaxNonceRetries = 100
	SignatureTimeout = 5 * time.Second
)

var (
	ErrInvalidSignature     = errors.New("invalid signature")
	ErrInvalidPublicKey     = errors.New("invalid public key")
	ErrWeakEntropy          = errors.New("insufficient entropy")
	ErrSignatureTimeout     = errors.New("signature generation timeout")
	ErrReplayProtection     = errors.New("replay protection check failed")
)

type SecureRandom struct {
	reader      io.Reader
	mu          sync.Mutex
	entropyPool []byte
	lastReseed  time.Time
}

func NewSecureRandom() (*SecureRandom, error) {
	sr := &SecureRandom{
		reader:      rand.Reader,
		entropyPool: make([]byte, EntropyPoolSize),
		lastReseed:  time.Now(),
	}
	if err := sr.reseedEntropyPool(); err != nil {
		return nil, err
	}
	return sr, nil
}

func (sr *SecureRandom) reseedEntropyPool() error {
	_, err := io.ReadFull(sr.reader, sr.entropyPool)
	if err != nil {
		return fmt.Errorf("entropy pool reseed failed: %w", err)
	}
	sr.lastReseed = time.Now()
	return nil
}

func (sr *SecureRandom) GenerateRandomBytes(n int) ([]byte, error) {
	sr.mu.Lock()
	defer sr.mu.Unlock()

	if time.Since(sr.lastReseed) > 10*time.Minute {
		if err := sr.reseedEntropyPool(); err != nil {
			return nil, err
		}
	}

	b := make([]byte, n)
	if _, err := io.ReadFull(sr.reader, b); err != nil {
		return nil, fmt.Errorf("random generation failed: %w", err)
	}

	if !sr.checkEntropyQuality(b) {
		return nil, ErrWeakEntropy
	}
	return b, nil
}

func (sr *SecureRandom) checkEntropyQuality(data []byte) bool {
	if len(data) < 32 {
		return true
	}
	freq := make(map[byte]int)
	for _, b := range data {
		freq[b]++
	}
	for _, count := range freq {
		if count > len(data)/4 {
			return false
		}
	}
	return true
}

type HardenedKeyPair struct {
	PrivateKey    *ecdsa.PrivateKey
	PublicKey     *ecdsa.PublicKey
	Address       string
	CreatedAt     time.Time
	Version       uint8
	DerivationKey []byte
	mu            sync.RWMutex
}

type AuditEntry struct {
	Timestamp time.Time
	Operation string
	KeyID     string
	Success   bool
	Metadata  map[string]string
}

type KeyManager struct {
	secureRandom *SecureRandom
	keyStore     map[string]*HardenedKeyPair
	mu           sync.RWMutex
	auditLog     []AuditEntry
}

func NewKeyManager() (*KeyManager, error) {
	sr, err := NewSecureRandom()
	if err != nil {
		return nil, err
	}
	return &KeyManager{
		secureRandom: sr,
		keyStore:     make(map[string]*HardenedKeyPair),
		auditLog:     make([]AuditEntry, 0, 10000),
	}, nil
}

func (km *KeyManager) GenerateKeyPair() (*HardenedKeyPair, error) {
	km.mu.Lock()
	defer km.mu.Unlock()

	var privKey *btcec.PrivateKey
	for attempt := 0; attempt < MaxNonceRetries; attempt++ {
		privKeyBytes, err := km.secureRandom.GenerateRandomBytes(32)
		if err != nil {
			continue
		}
		privKey, _ = btcec.PrivKeyFromBytes(privKeyBytes)
		if privKey != nil {
			break
		}
	}

	if privKey == nil {
		return nil, errors.New("failed to generate valid private key")
	}

	ecdsaPrivKey := privKey.ToECDSA()
	pubKey := &ecdsaPrivKey.PublicKey

	address, err := km.generateAddress(pubKey)
	if err != nil {
		return nil, err
	}

	derivationKey, err := km.secureRandom.GenerateRandomBytes(32)
	if err != nil {
		return nil, err
	}

	kp := &HardenedKeyPair{
		PrivateKey:    ecdsaPrivKey,
		PublicKey:     pubKey,
		Address:       address,
		CreatedAt:     time.Now(),
		Version:       1,
		DerivationKey: derivationKey,
	}

	km.keyStore[address] = kp
	km.addAuditEntry("KEY_GENERATION", address, true, nil)
	return kp, nil
}

func (km *KeyManager) generateAddress(pubKey *ecdsa.PublicKey) (string, error) {
	pubKeyBytes := elliptic.Marshal(pubKey.Curve, pubKey.X, pubKey.Y)
	hash1 := sha256.Sum256(pubKeyBytes)
	hash2 := sha256.Sum256(hash1[:])
	checksum := hash2[:4]
	addressBytes := append([]byte{0x1E}, hash2[:]...)
	addressBytes = append(addressBytes, checksum...)
	return "DT" + base58.Encode(addressBytes), nil
}

func (km *KeyManager) SignTransaction(kp *HardenedKeyPair, txHash []byte, nonce uint64, chainID uint64) ([]byte, error) {
	kp.mu.RLock()
	defer kp.mu.RUnlock()

	if len(txHash) != 32 {
		return nil, errors.New("transaction hash must be 32 bytes")
	}

	replayProtection := make([]byte, 16)
	big.NewInt(int64(nonce)).FillBytes(replayProtection[:8])
	big.NewInt(int64(chainID)).FillBytes(replayProtection[8:])
	
	messageHash := append(txHash, replayProtection...)
	finalHash := sha256.Sum256(messageHash)

	signature, err := signWithTimeout(kp.PrivateKey, finalHash[:], SignatureTimeout)
	if err != nil {
		km.addAuditEntry("SIGNATURE_FAILED", kp.Address, false, map[string]string{"error": err.Error()})
		return nil, err
	}

	if !ecdsa.VerifyASN1(kp.PublicKey, finalHash[:], signature) {
		km.addAuditEntry("SIGNATURE_VERIFICATION_FAILED", kp.Address, false, nil)
		return nil, ErrInvalidSignature
	}

	km.addAuditEntry("SIGNATURE_CREATED", kp.Address, true, map[string]string{
		"nonce": fmt.Sprintf("%d", nonce),
		"chainID": fmt.Sprintf("%d", chainID),
	})
	return signature, nil
}

func signWithTimeout(privKey *ecdsa.PrivateKey, hash []byte, timeout time.Duration) ([]byte, error) {
	type result struct {
		sig []byte
		err error
	}
	resultChan := make(chan result, 1)
	go func() {
		sig, err := ecdsa.SignASN1(rand.Reader, privKey, hash)
		resultChan <- result{sig: sig, err: err}
	}()
	select {
	case res := <-resultChan:
		return res.sig, res.err
	case <-time.After(timeout):
		return nil, ErrSignatureTimeout
	}
}

func (km *KeyManager) VerifySignature(pubKeyBytes, txHash, signature []byte, nonce, chainID uint64) error {
	if len(txHash) != 32 {
		return errors.New("transaction hash must be 32 bytes")
	}

	x, y := elliptic.Unmarshal(btcec.S256(), pubKeyBytes)
	if x == nil {
		return ErrInvalidPublicKey
	}

	pubKey := &ecdsa.PublicKey{
		Curve: btcec.S256(),
		X:     x,
		Y:     y,
	}

	replayProtection := make([]byte, 16)
	big.NewInt(int64(nonce)).FillBytes(replayProtection[:8])
	big.NewInt(int64(chainID)).FillBytes(replayProtection[8:])
	
	messageHash := append(txHash, replayProtection...)
	finalHash := sha256.Sum256(messageHash)

	if !ecdsa.VerifyASN1(pubKey, finalHash[:], signature) {
		return ErrInvalidSignature
	}
	return nil
}

func (km *KeyManager) DeriveChildKey(parent *HardenedKeyPair, index uint32) (*HardenedKeyPair, error) {
	km.mu.Lock()
	defer km.mu.Unlock()

	indexBytes := make([]byte, 4)
	big.NewInt(int64(index)).FillBytes(indexBytes)
	
	seed := append(parent.DerivationKey, indexBytes...)
	childKeyMaterial := argon2.IDKey(seed, []byte("dinari-hd-derivation"), Argon2Time, Argon2Memory, Argon2Threads, 32)

	privKey, _ := btcec.PrivKeyFromBytes(childKeyMaterial)
	if privKey == nil {
		return nil, errors.New("failed to derive child key")
	}

	ecdsaPrivKey := privKey.ToECDSA()
	pubKey := &ecdsaPrivKey.PublicKey

	address, err := km.generateAddress(pubKey)
	if err != nil {
		return nil, err
	}

	childKP := &HardenedKeyPair{
		PrivateKey:    ecdsaPrivKey,
		PublicKey:     pubKey,
		Address:       address,
		CreatedAt:     time.Now(),
		Version:       1,
		DerivationKey: childKeyMaterial,
	}

	km.keyStore[address] = childKP
	km.addAuditEntry("KEY_DERIVATION", address, true, map[string]string{
		"parent": parent.Address,
		"index":  fmt.Sprintf("%d", index),
	})
	return childKP, nil
}

func (km *KeyManager) addAuditEntry(operation, keyID string, success bool, metadata map[string]string) {
	entry := AuditEntry{
		Timestamp: time.Now(),
		Operation: operation,
		KeyID:     keyID,
		Success:   success,
		Metadata:  metadata,
	}
	km.auditLog = append(km.auditLog, entry)
	
	if len(km.auditLog) > 100000 {
		km.auditLog = km.auditLog[10000:]
	}
}

func (km *KeyManager) GetAuditLog() []AuditEntry {
	km.mu.RLock()
	defer km.mu.RUnlock()
	logCopy := make([]AuditEntry, len(km.auditLog))
	copy(logCopy, km.auditLog)
	return logCopy
}

func HashSHA256(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

func DoubleSHA256(data []byte) []byte {
	first := sha256.Sum256(data)
	second := sha256.Sum256(first[:])
	return second[:]
}

func HMACSHA512(key, data []byte) []byte {
	h := hmac.New(sha512.New, key)
	h.Write(data)
	return h.Sum(nil)
}
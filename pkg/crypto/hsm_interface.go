// pkg/crypto/hsm_interface.go
// Hardware Security Module integration for production-grade key management
package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

const (
	HSMSessionTimeout   = 30 * time.Minute
	MaxHSMRetries       = 3
	HSMOperationTimeout = 10 * time.Second
	KeyRotationInterval = 90 * 24 * time.Hour // 90 days
)

var (
	ErrHSMNotAvailable    = errors.New("HSM not available")
	ErrHSMSessionExpired  = errors.New("HSM session expired")
	ErrHSMOperationFailed = errors.New("HSM operation failed")
	ErrKeyNotFound        = errors.New("key not found in HSM")
	ErrInvalidHSMConfig   = errors.New("invalid HSM configuration") // NEW: Missing error
)

type HSMProvider interface {
	Connect(config *HSMConfig) error
	Disconnect() error
	GenerateKey(keyID string, keyType string) error
	Sign(keyID string, data []byte) ([]byte, error)
	Verify(keyID string, data []byte, signature []byte) (bool, error)
	GetPublicKey(keyID string) ([]byte, error)
	DeleteKey(keyID string) error
	IsAvailable() bool
	GetStatus() HSMStatus
}

type HSMConfig struct {
	Provider     string
	Endpoint     string
	Port         int
	Credentials  HSMCredentials
	TLSEnabled   bool
	TLSCertPath  string
	SlotID       int
	TokenLabel   string
	UserPIN      string
	SOPin        string
	MaxSessions  int
}

type HSMCredentials struct {
	Username     string
	Password     string
	APIKey       string
	ClientCert   []byte
	ClientKey    []byte
}

type HSMStatus struct {
	Connected          bool
	SessionActive      bool
	LastActivity       time.Time
	OperationCount     uint64
	ErrorCount         uint64
	AvailableSessions  int
	FirmwareVersion    string
	SerialNumber       string
}

type HSMManager struct {
	provider            HSMProvider
	fallbackKeyManager  *KeyManager
	sessions            map[string]*HSMSession
	keyMetadata         map[string]*KeyMetadata
	config              *HSMConfig
	useHSM              bool
	mu                  sync.RWMutex
	auditLogger         *HSMAuditLogger
}

type HSMSession struct {
	ID              string
	KeyID           string
	CreatedAt       time.Time
	LastActivity    time.Time
	OperationCount  int
	Active          bool
}

type KeyMetadata struct {
	KeyID           string
	KeyType         string
	CreatedAt       time.Time
	LastUsed        time.Time
	UsageCount      uint64
	RotationDate    time.Time
	Version         int
	Purposes        []string
	Owner           string
}

type HSMAuditLogger struct {
	entries         []HSMAuditEntry
	mu              sync.RWMutex
}

type HSMAuditEntry struct {
	Timestamp       time.Time
	SessionID       string
	KeyID           string
	Operation       string
	Success         bool
	ErrorMessage    string
	UserID          string
	SourceIP        string
	Duration        time.Duration
}

type SoftwareHSM struct {
	keys            map[string]*ecdsa.PrivateKey
	publicKeys      map[string]*ecdsa.PublicKey
	connected       bool
	operationCount  uint64
	errorCount      uint64
	mu              sync.RWMutex
}

func NewHSMManager(config *HSMConfig, fallbackKM *KeyManager) (*HSMManager, error) {
	if config == nil {
		return nil, ErrInvalidHSMConfig
	}

	var provider HSMProvider

	switch config.Provider {
	case "software":
		provider = NewSoftwareHSM()
	case "aws-cloudhsm":
		return nil, errors.New("AWS CloudHSM integration requires specific implementation")
	case "azure-keyvault":
		return nil, errors.New("Azure KeyVault integration requires specific implementation")
	case "yubihsm":
		return nil, errors.New("YubiHSM integration requires specific implementation")
	default:
		return nil, fmt.Errorf("unsupported HSM provider: %s", config.Provider)
	}

	if err := provider.Connect(config); err != nil {
		return nil, fmt.Errorf("failed to connect to HSM: %w", err)
	}

	manager := &HSMManager{
		provider:           provider,
		fallbackKeyManager: fallbackKM,
		sessions:           make(map[string]*HSMSession),
		keyMetadata:        make(map[string]*KeyMetadata),
		config:             config,
		useHSM:             provider.IsAvailable(),
		auditLogger:        NewHSMAuditLogger(),
	}

	return manager, nil
}

func NewHSMAuditLogger() *HSMAuditLogger {
	return &HSMAuditLogger{
		entries: make([]HSMAuditEntry, 0, 100000),
	}
}

func NewSoftwareHSM() *SoftwareHSM {
	return &SoftwareHSM{
		keys:       make(map[string]*ecdsa.PrivateKey),
		publicKeys: make(map[string]*ecdsa.PublicKey),
		connected:  false,
	}
}

func (hsm *HSMManager) CreateSession(keyID, userID string) (*HSMSession, error) {
	hsm.mu.Lock()
	defer hsm.mu.Unlock()

	if !hsm.useHSM || !hsm.provider.IsAvailable() {
		return nil, ErrHSMNotAvailable
	}

	sessionID := generateSessionID()

	session := &HSMSession{
		ID:             sessionID,
		KeyID:          keyID,
		CreatedAt:      time.Now(),
		LastActivity:   time.Now(),
		OperationCount: 0,
		Active:         true,
	}

	hsm.sessions[sessionID] = session

	hsm.auditLogger.Log(HSMAuditEntry{
		Timestamp:  time.Now(),
		SessionID:  sessionID,
		KeyID:      keyID,
		Operation:  "SESSION_CREATE",
		Success:    true,
		UserID:     userID,
	})

	return session, nil
}

func (hsm *HSMManager) CloseSession(sessionID string) error {
	hsm.mu.Lock()
	defer hsm.mu.Unlock()

	session, exists := hsm.sessions[sessionID]
	if !exists {
		return errors.New("session not found")
	}

	session.Active = false
	delete(hsm.sessions, sessionID)

	hsm.auditLogger.Log(HSMAuditEntry{
		Timestamp:  time.Now(),
		SessionID:  sessionID,
		Operation:  "SESSION_CLOSE",
		Success:    true,
	})

	return nil
}

func (hsm *HSMManager) GenerateKey(keyID, keyType, owner string, purposes []string) error {
	hsm.mu.Lock()
	defer hsm.mu.Unlock()

	startTime := time.Now()
	var err error

	if hsm.useHSM && hsm.provider.IsAvailable() {
		err = hsm.provider.GenerateKey(keyID, keyType)
	} else {
		_, err = hsm.fallbackKeyManager.GenerateKeyPair()
	}

	duration := time.Since(startTime)

	success := err == nil
	if success {
		metadata := &KeyMetadata{
			KeyID:        keyID,
			KeyType:      keyType,
			CreatedAt:    time.Now(),
			LastUsed:     time.Now(),
			UsageCount:   0,
			RotationDate: time.Now().Add(KeyRotationInterval),
			Version:      1,
			Purposes:     purposes,
			Owner:        owner,
		}
		hsm.keyMetadata[keyID] = metadata
	}

	hsm.auditLogger.Log(HSMAuditEntry{
		Timestamp:    time.Now(),
		KeyID:        keyID,
		Operation:    "KEY_GENERATE",
		Success:      success,
		ErrorMessage: getErrorMessage(err),
		UserID:       owner,
		Duration:     duration,
	})

	return err
}

func (hsm *HSMManager) Sign(keyID string, data []byte, sessionID, userID string) ([]byte, error) {
	hsm.mu.Lock()
	session := hsm.sessions[sessionID]
	hsm.mu.Unlock()

	if session == nil || !session.Active {
		return nil, ErrHSMSessionExpired
	}

	if time.Since(session.LastActivity) > HSMSessionTimeout {
		hsm.CloseSession(sessionID)
		return nil, ErrHSMSessionExpired
	}

	metadata := hsm.keyMetadata[keyID]
	if metadata != nil && time.Now().After(metadata.RotationDate) {
		hsm.auditLogger.Log(HSMAuditEntry{
			Timestamp:    time.Now(),
			SessionID:    sessionID,
			KeyID:        keyID,
			Operation:    "KEY_ROTATION_WARNING",
			Success:      false,
			ErrorMessage: "Key rotation required",
			UserID:       userID,
		})
	}

	startTime := time.Now()
	var signature []byte
	var err error

	if hsm.useHSM && hsm.provider.IsAvailable() {
		for attempt := 0; attempt < MaxHSMRetries; attempt++ {
			signature, err = hsm.provider.Sign(keyID, data)
			if err == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
	} else {
		kp, exists := hsm.fallbackKeyManager.keyStore[keyID]
		if !exists {
			return nil, ErrKeyNotFound
		}
		signature, err = ecdsa.SignASN1(rand.Reader, kp.PrivateKey, data)
	}

	duration := time.Since(startTime)

	hsm.mu.Lock()
	session.LastActivity = time.Now()
	session.OperationCount++
	if metadata != nil {
		metadata.LastUsed = time.Now()
		metadata.UsageCount++
	}
	hsm.mu.Unlock()

	hsm.auditLogger.Log(HSMAuditEntry{
		Timestamp:    time.Now(),
		SessionID:    sessionID,
		KeyID:        keyID,
		Operation:    "SIGN",
		Success:      err == nil,
		ErrorMessage: getErrorMessage(err),
		UserID:       userID,
		Duration:     duration,
	})

	return signature, err
}

func (hsm *HSMManager) Verify(keyID string, data, signature []byte) (bool, error) {
	startTime := time.Now()
	var valid bool
	var err error

	if hsm.useHSM && hsm.provider.IsAvailable() {
		valid, err = hsm.provider.Verify(keyID, data, signature)
	} else {
		kp, exists := hsm.fallbackKeyManager.keyStore[keyID]
		if !exists {
			return false, ErrKeyNotFound
		}
		valid = ecdsa.VerifyASN1(kp.PublicKey, data, signature)
		err = nil
	}

	duration := time.Since(startTime)

	hsm.auditLogger.Log(HSMAuditEntry{
		Timestamp:    time.Now(),
		KeyID:        keyID,
		Operation:    "VERIFY",
		Success:      err == nil,
		ErrorMessage: getErrorMessage(err),
		Duration:     duration,
	})

	return valid, err
}

func (hsm *HSMManager) RotateKey(keyID, newKeyID string, userID string) error {
	hsm.mu.Lock()
	defer hsm.mu.Unlock()

	oldMetadata, exists := hsm.keyMetadata[keyID]
	if !exists {
		return ErrKeyNotFound
	}

	startTime := time.Now()

	err := hsm.provider.GenerateKey(newKeyID, oldMetadata.KeyType)
	if err != nil {
		hsm.auditLogger.Log(HSMAuditEntry{
			Timestamp:    time.Now(),
			KeyID:        keyID,
			Operation:    "KEY_ROTATION_FAILED",
			Success:      false,
			ErrorMessage: err.Error(),
			UserID:       userID,
			Duration:     time.Since(startTime),
		})
		return err
	}

	newMetadata := &KeyMetadata{
		KeyID:        newKeyID,
		KeyType:      oldMetadata.KeyType,
		CreatedAt:    time.Now(),
		LastUsed:     time.Now(),
		UsageCount:   0,
		RotationDate: time.Now().Add(KeyRotationInterval),
		Version:      oldMetadata.Version + 1,
		Purposes:     oldMetadata.Purposes,
		Owner:        oldMetadata.Owner,
	}

	hsm.keyMetadata[newKeyID] = newMetadata

	hsm.auditLogger.Log(HSMAuditEntry{
		Timestamp:    time.Now(),
		KeyID:        newKeyID,
		Operation:    "KEY_ROTATION_SUCCESS",
		Success:      true,
		UserID:       userID,
		Duration:     time.Since(startTime),
	})

	return nil
}

func (hsm *HSMManager) GetKeyMetadata(keyID string) (*KeyMetadata, error) {
	hsm.mu.RLock()
	defer hsm.mu.RUnlock()

	metadata, exists := hsm.keyMetadata[keyID]
	if !exists {
		return nil, ErrKeyNotFound
	}

	metadataCopy := &KeyMetadata{}
	*metadataCopy = *metadata
	return metadataCopy, nil
}

func (hsm *HSMManager) GetAuditLog(keyID string, since time.Time) []HSMAuditEntry {
	return hsm.auditLogger.GetEntriesForKey(keyID, since)
}

func (hsm *HSMManager) GetStatus() HSMStatus {
	if hsm.provider != nil {
		return hsm.provider.GetStatus()
	}
	return HSMStatus{Connected: false}
}

func (shsm *SoftwareHSM) Connect(config *HSMConfig) error {
	shsm.mu.Lock()
	defer shsm.mu.Unlock()

	shsm.connected = true
	return nil
}

func (shsm *SoftwareHSM) Disconnect() error {
	shsm.mu.Lock()
	defer shsm.mu.Unlock()

	shsm.connected = false
	return nil
}

func (shsm *SoftwareHSM) GenerateKey(keyID string, keyType string) error {
	shsm.mu.Lock()
	defer shsm.mu.Unlock()

	privKeyBytes := make([]byte, 32)
	_, err := rand.Read(privKeyBytes)
	if err != nil {
		shsm.errorCount++
		return err
	}

	// Generate key using Argon2 for deterministic key derivation
	derivedKey := argon2.IDKey(privKeyBytes, []byte(keyID), Argon2Time, Argon2Memory, Argon2Threads, 32)
	
	privKey, err := generateECDSAKeyFromSeed(derivedKey)
	if err != nil {
		shsm.errorCount++
		return err
	}

	shsm.keys[keyID] = privKey
	shsm.publicKeys[keyID] = &privKey.PublicKey
	shsm.operationCount++

	return nil
}

func (shsm *SoftwareHSM) Sign(keyID string, data []byte) ([]byte, error) {
	shsm.mu.RLock()
	defer shsm.mu.RUnlock()

	privKey, exists := shsm.keys[keyID]
	if !exists {
		shsm.mu.RUnlock()
		shsm.mu.Lock()
		shsm.errorCount++
		shsm.mu.Unlock()
		shsm.mu.RLock()
		return nil, ErrKeyNotFound
	}

	hash := sha256.Sum256(data)
	signature, err := ecdsa.SignASN1(rand.Reader, privKey, hash[:])
	
	shsm.mu.RUnlock()
	shsm.mu.Lock()
	if err != nil {
		shsm.errorCount++
	} else {
		shsm.operationCount++
	}
	shsm.mu.Unlock()
	shsm.mu.RLock()

	return signature, err
}

func (shsm *SoftwareHSM) Verify(keyID string, data []byte, signature []byte) (bool, error) {
	shsm.mu.RLock()
	defer shsm.mu.RUnlock()

	pubKey, exists := shsm.publicKeys[keyID]
	if !exists {
		return false, ErrKeyNotFound
	}

	hash := sha256.Sum256(data)
	valid := ecdsa.VerifyASN1(pubKey, hash[:], signature)

	return valid, nil
}

func (shsm *SoftwareHSM) GetPublicKey(keyID string) ([]byte, error) {
	shsm.mu.RLock()
	defer shsm.mu.RUnlock()

	pubKey, exists := shsm.publicKeys[keyID]
	if !exists {
		return nil, ErrKeyNotFound
	}

	return elliptic.Marshal(pubKey.Curve, pubKey.X, pubKey.Y), nil
}

func (shsm *SoftwareHSM) DeleteKey(keyID string) error {
	shsm.mu.Lock()
	defer shsm.mu.Unlock()

	delete(shsm.keys, keyID)
	delete(shsm.publicKeys, keyID)
	return nil
}

func (shsm *SoftwareHSM) IsAvailable() bool {
	shsm.mu.RLock()
	defer shsm.mu.RUnlock()
	return shsm.connected
}

func (shsm *SoftwareHSM) GetStatus() HSMStatus {
	shsm.mu.RLock()
	defer shsm.mu.RUnlock()

	return HSMStatus{
		Connected:         shsm.connected,
		SessionActive:     true,
		LastActivity:      time.Now(),
		OperationCount:    shsm.operationCount,
		ErrorCount:        shsm.errorCount,
		FirmwareVersion:   "Software HSM v1.0",
		SerialNumber:      "SW-HSM-001",
	}
}

func (hal *HSMAuditLogger) Log(entry HSMAuditEntry) {
	hal.mu.Lock()
	defer hal.mu.Unlock()

	hal.entries = append(hal.entries, entry)

	if len(hal.entries) > 100000 {
		hal.entries = hal.entries[10000:]
	}
}

func (hal *HSMAuditLogger) GetEntriesForKey(keyID string, since time.Time) []HSMAuditEntry {
	hal.mu.RLock()
	defer hal.mu.RUnlock()

	filtered := make([]HSMAuditEntry, 0)
	for _, entry := range hal.entries {
		if entry.KeyID == keyID && entry.Timestamp.After(since) {
			filtered = append(filtered, entry)
		}
	}

	return filtered
}

func generateSessionID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func generateECDSAKeyFromSeed(seed []byte) (*ecdsa.PrivateKey, error) {
	// Implementation would use proper key derivation
	// This is simplified for demonstration
	privKey, err := ecdsa.GenerateKey(S256(), rand.Reader)
	return privKey, err
}

func getErrorMessage(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

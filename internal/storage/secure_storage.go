// internal/storage/secure_storage.go
// Encrypted database layer with backup and recovery for production systems
package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/dgraph-io/badger/v4"
)

const (
	EncryptionEnabled   = true
	CompressionEnabled  = true
	BackupInterval      = 6 * time.Hour
	BackupRetentionDays = 30
	MaxValueSize        = 10 * 1024 * 1024 // 10MB
	GCInterval          = 5 * time.Minute
	SyncWrites          = true // Force sync for critical data
	// Note: MaxBatchSize is already defined in db.go
	MaxBatchDelaySecure = 100 * time.Millisecond
)

// Secure storage specific errors (don't duplicate from db.go)
var (
	ErrValueTooLarge    = errors.New("value exceeds maximum size")
	ErrEncryptionFailed = errors.New("encryption failed")
	ErrDecryptionFailed = errors.New("decryption failed")
	ErrBackupFailed     = errors.New("backup failed")
	ErrCorruptedData    = errors.New("data corruption detected")
)

type SecureStorage struct {
	db             *badger.DB
	encryptionKey  []byte
	backupManager  *BackupManager
	integrityCheck *IntegrityChecker
	mu             sync.RWMutex
	closed         bool
}

type BackupManager struct {
	backupDir     string
	interval      time.Duration
	retention     int // days
	lastBackup    time.Time
	backupRunning bool
	mu            sync.Mutex
}

type IntegrityChecker struct {
	checksums map[string]string // key -> checksum
	mu        sync.RWMutex
}

// NewSecureStorage creates a new encrypted storage instance
func NewSecureStorage(dataDir string, encryptionKey []byte) (*SecureStorage, error) {
	if len(encryptionKey) != 32 {
		return nil, errors.New("encryption key must be 32 bytes")
	}

	// Create badger options for v4
	opts := badger.DefaultOptions(dataDir)
	opts = opts.WithLoggingLevel(badger.WARNING)
	opts = opts.WithSyncWrites(SyncWrites)

	
	// Open database using v4 API
	db, err := badger.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	backupDir := filepath.Join(dataDir, "backups")
	if err := os.MkdirAll(backupDir, 0700); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to create backup directory: %w", err)
	}

	ss := &SecureStorage{
		db:            db,
		encryptionKey: encryptionKey,
		backupManager: &BackupManager{
			backupDir: backupDir,
			interval:  BackupInterval,
			retention: BackupRetentionDays,
		},
		integrityCheck: &IntegrityChecker{
			checksums: make(map[string]string),
		},
	}

	// Start background tasks
	go ss.startBackupRoutine()
	go ss.startGarbageCollection()

	return ss, nil
}

// Put stores encrypted data
func (ss *SecureStorage) Put(key, value []byte) error {
	ss.mu.RLock()
	if ss.closed {
		ss.mu.RUnlock()
		return ErrDatabaseClosed
	}
	ss.mu.RUnlock()

	if len(value) > MaxValueSize {
		return ErrValueTooLarge
	}

	// Encrypt the value
	encryptedValue, err := ss.encrypt(value)
	if err != nil {
		return fmt.Errorf("encryption failed: %w", err)
	}

	// Store checksum
	checksum := ss.calculateChecksum(value)
	ss.integrityCheck.mu.Lock()
	ss.integrityCheck.checksums[string(key)] = checksum
	ss.integrityCheck.mu.Unlock()

	// Write to database
	err = ss.db.Update(func(txn *badger.Txn) error {
		return txn.Set(key, encryptedValue)
	})

	return err
}

// Get retrieves and decrypts data
func (ss *SecureStorage) Get(key []byte) ([]byte, error) {
	ss.mu.RLock()
	if ss.closed {
		ss.mu.RUnlock()
		return nil, ErrDatabaseClosed
	}
	ss.mu.RUnlock()

	var encryptedValue []byte
	err := ss.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(key)
		if err != nil {
			return err
		}

		return item.Value(func(val []byte) error {
			encryptedValue = append([]byte{}, val...)
			return nil
		})
	})

	if err == badger.ErrKeyNotFound {
		return nil, ErrKeyNotFound
	}
	if err != nil {
		return nil, err
	}

	// Decrypt
	decryptedValue, err := ss.decrypt(encryptedValue)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	// Verify integrity
	expectedChecksum := ss.integrityCheck.getChecksum(string(key))
	actualChecksum := ss.calculateChecksum(decryptedValue)
	if expectedChecksum != "" && expectedChecksum != actualChecksum {
		return nil, ErrCorruptedData
	}

	return decryptedValue, nil
}

// Delete removes a key
func (ss *SecureStorage) Delete(key []byte) error {
	ss.mu.RLock()
	if ss.closed {
		ss.mu.RUnlock()
		return ErrDatabaseClosed
	}
	ss.mu.RUnlock()

	// Remove checksum
	ss.integrityCheck.mu.Lock()
	delete(ss.integrityCheck.checksums, string(key))
	ss.integrityCheck.mu.Unlock()

	return ss.db.Update(func(txn *badger.Txn) error {
		return txn.Delete(key)
	})
}

// Close closes the database
func (ss *SecureStorage) Close() error {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	if ss.closed {
		return nil
	}

	ss.closed = true
	return ss.db.Close()
}

// encrypt encrypts data using AES-256-GCM
func (ss *SecureStorage) encrypt(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(ss.encryptionKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// decrypt decrypts AES-256-GCM encrypted data
func (ss *SecureStorage) decrypt(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(ss.encryptionKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, ErrDecryptionFailed
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	return plaintext, nil
}

// calculateChecksum creates a SHA-256 checksum
func (ss *SecureStorage) calculateChecksum(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// getChecksum retrieves stored checksum
func (ic *IntegrityChecker) getChecksum(key string) string {
	ic.mu.RLock()
	defer ic.mu.RUnlock()
	return ic.checksums[key]
}

// Backup creates a database backup
func (ss *SecureStorage) Backup() error {
	ss.backupManager.mu.Lock()
	if ss.backupManager.backupRunning {
		ss.backupManager.mu.Unlock()
		return errors.New("backup already in progress")
	}
	ss.backupManager.backupRunning = true
	ss.backupManager.mu.Unlock()

	defer func() {
		ss.backupManager.mu.Lock()
		ss.backupManager.backupRunning = false
		ss.backupManager.lastBackup = time.Now()
		ss.backupManager.mu.Unlock()
	}()

	timestamp := time.Now().Format("2006-01-02_15-04-05")
	backupPath := filepath.Join(ss.backupManager.backupDir, fmt.Sprintf("backup_%s.db", timestamp))

	// Create backup file
	f, err := os.Create(backupPath)
	if err != nil {
		return fmt.Errorf("failed to create backup file: %w", err)
	}
	defer f.Close()

	// Backup using Badger v4 API
	_, err = ss.db.Backup(f, 0)
	if err != nil {
		os.Remove(backupPath)
		return fmt.Errorf("backup failed: %w", err)
	}

	// Clean old backups
	ss.cleanOldBackups()

	return nil
}

// startBackupRoutine runs periodic backups
func (ss *SecureStorage) startBackupRoutine() {
	ticker := time.NewTicker(ss.backupManager.interval)
	defer ticker.Stop()

	for range ticker.C {
		if ss.closed {
			return
		}
		if err := ss.Backup(); err != nil {
			// Log error (in production, use proper logger)
			fmt.Printf("Backup failed: %v\n", err)
		}
	}
}

// startGarbageCollection runs periodic GC
func (ss *SecureStorage) startGarbageCollection() {
	ticker := time.NewTicker(GCInterval)
	defer ticker.Stop()

	for range ticker.C {
		if ss.closed {
			return
		}
		err := ss.db.RunValueLogGC(0.5)
		if err != nil && err != badger.ErrNoRewrite {
			// Log error (in production, use proper logger)
			fmt.Printf("GC failed: %v\n", err)
		}
	}
}

// cleanOldBackups removes backups older than retention period
func (ss *SecureStorage) cleanOldBackups() {
	entries, err := os.ReadDir(ss.backupManager.backupDir)
	if err != nil {
		return
	}

	cutoff := time.Now().AddDate(0, 0, -ss.backupManager.retention)

	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			continue
		}

		if info.ModTime().Before(cutoff) {
			path := filepath.Join(ss.backupManager.backupDir, entry.Name())
			os.Remove(path)
		}
	}
}

// BatchWrite performs batch write operations
func (ss *SecureStorage) BatchWrite(operations map[string][]byte) error {
	ss.mu.RLock()
	if ss.closed {
		ss.mu.RUnlock()
		return ErrDatabaseClosed
	}
	ss.mu.RUnlock()

	return ss.db.Update(func(txn *badger.Txn) error {
		for key, value := range operations {
			encrypted, err := ss.encrypt(value)
			if err != nil {
				return err
			}
			if err := txn.Set([]byte(key), encrypted); err != nil {
				return err
			}
		}
		return nil
	})
}

// GetStats returns database statistics
func (ss *SecureStorage) GetStats() map[string]interface{} {
	lsm, vlog := ss.db.Size()
	
	return map[string]interface{}{
		"lsm_size":     lsm,
		"vlog_size":    vlog,
		"total_size":   lsm + vlog,
		"last_backup":  ss.backupManager.lastBackup,
		"closed":       ss.closed,
	}
}

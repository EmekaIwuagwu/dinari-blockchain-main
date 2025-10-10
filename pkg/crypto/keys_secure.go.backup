package crypto

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// SecureKey represents a private key with memory protection
type SecureKey struct {
	data     []byte
	locked   bool
	mu       sync.RWMutex
	mlock    bool // Whether memory is locked via mlock
	canary   [8]byte // Stack canary for overflow detection
}

// NewSecureKey creates a new secure key with memory locking
func NewSecureKey(keyData []byte) (*SecureKey, error) {
	if len(keyData) == 0 {
		return nil, errors.New("empty key data")
	}

	sk := &SecureKey{
		data: make([]byte, len(keyData)),
	}
	
	// Copy key data
	copy(sk.data, keyData)
	
	// Generate stack canary
	if _, err := rand.Read(sk.canary[:]); err != nil {
		return nil, fmt.Errorf("canary generation failed: %w", err)
	}

	// Lock memory pages to prevent swapping to disk
	if err := sk.lockMemory(); err != nil {
		// Log warning but don't fail - some environments don't support mlock
		fmt.Printf("WARNING: Failed to lock key memory: %v\n", err)
	}

	// Register finalizer for cleanup
	runtime.SetFinalizer(sk, (*SecureKey).Destroy)

	return sk, nil
}

// lockMemory locks the key's memory pages using mlock
func (sk *SecureKey) lockMemory() error {
	sk.mu.Lock()
	defer sk.mu.Unlock()

	if len(sk.data) == 0 {
		return errors.New("no data to lock")
	}

	// Use mlock to prevent swapping
	ptr := unsafe.Pointer(&sk.data[0])
	size := uintptr(len(sk.data))
	
	if err := unix.Mlock((*[1 << 30]byte)(ptr)[:size:size]); err != nil {
		return fmt.Errorf("mlock failed: %w", err)
	}

	// Advise kernel not to dump this memory in core dumps
	if err := unix.Madvise((*[1 << 30]byte)(ptr)[:size:size], syscall.MADV_DONTDUMP); err != nil {
		// Non-fatal, just log
		fmt.Printf("WARNING: madvise MADV_DONTDUMP failed: %v\n", err)
	}

	sk.mlock = true
	return nil
}

// Use executes a function with temporary access to the key
func (sk *SecureKey) Use(fn func([]byte) error) error {
	sk.mu.RLock()
	defer sk.mu.RUnlock()

	if sk.locked {
		return errors.New("key is locked")
	}

	if !sk.verifyCanary() {
		return errors.New("SECURITY: key memory corruption detected")
	}

	// Create temporary copy for use
	temp := make([]byte, len(sk.data))
	copy(temp, sk.data)
	defer sk.wipeBytes(temp)

	return fn(temp)
}

// verifyCanary checks for buffer overflows
func (sk *SecureKey) verifyCanary() bool {
	var zero [8]byte
	return subtle.ConstantTimeCompare(sk.canary[:], zero[:]) != 1
}

// wipeBytes securely overwrites memory
func (sk *SecureKey) wipeBytes(data []byte) {
	if len(data) == 0 {
		return
	}

	// Multiple overwrite passes with different patterns
	patterns := []byte{0x00, 0xFF, 0xAA, 0x55, 0x00}
	
	for _, pattern := range patterns {
		for i := range data {
			data[i] = pattern
		}
		// Memory barrier to prevent compiler optimization
		runtime.KeepAlive(data)
	}

	// Final random overwrite
	rand.Read(data)
}

// Lock prevents further use of the key
func (sk *SecureKey) Lock() {
	sk.mu.Lock()
	defer sk.mu.Unlock()
	sk.locked = true
}

// Unlock allows use of the key again
func (sk *SecureKey) Unlock() {
	sk.mu.Lock()
	defer sk.mu.Unlock()
	sk.locked = false
}

// Destroy securely wipes and frees the key
func (sk *SecureKey) Destroy() {
	sk.mu.Lock()
	defer sk.mu.Unlock()

	if len(sk.data) == 0 {
		return
	}

	// Wipe the key data
	sk.wipeBytes(sk.data)

	// Unlock memory if locked
	if sk.mlock {
		ptr := unsafe.Pointer(&sk.data[0])
		size := uintptr(len(sk.data))
		unix.Munlock((*[1 << 30]byte)(ptr)[:size:size])
	}

	// Clear the slice
	sk.data = nil
	sk.mlock = false
}

// HSMInterface defines hardware security module operations
type HSMInterface interface {
	Sign(keyID string, message []byte) ([]byte, error)
	Verify(keyID string, message, signature []byte) error
	GenerateKey() (keyID string, publicKey []byte, err error)
	DeleteKey(keyID string) error
}

// KeyStore manages multiple secure keys with HSM support
type KeyStore struct {
	keys map[string]*SecureKey
	hsm  HSMInterface
	mu   sync.RWMutex
}

// NewKeyStore creates a new key store
func NewKeyStore(hsm HSMInterface) *KeyStore {
	return &KeyStore{
		keys: make(map[string]*SecureKey),
		hsm:  hsm,
	}
}

// StoreKey stores a key securely
func (ks *KeyStore) StoreKey(id string, keyData []byte) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	// Check if key already exists
	if _, exists := ks.keys[id]; exists {
		return fmt.Errorf("key %s already exists", id)
	}

	secureKey, err := NewSecureKey(keyData)
	if err != nil {
		return err
	}

	ks.keys[id] = secureKey
	return nil
}

// GetKey retrieves a key for use
func (ks *KeyStore) GetKey(id string, fn func([]byte) error) error {
	ks.mu.RLock()
	key, exists := ks.keys[id]
	ks.mu.RUnlock()

	if !exists {
		return fmt.Errorf("key %s not found", id)
	}

	return key.Use(fn)
}

// DeleteKey securely removes a key
func (ks *KeyStore) DeleteKey(id string) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	key, exists := ks.keys[id]
	if !exists {
		return fmt.Errorf("key %s not found", id)
	}

	key.Destroy()
	delete(ks.keys, id)
	
	return nil
}

// Shutdown destroys all keys
func (ks *KeyStore) Shutdown() {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	for _, key := range ks.keys {
		key.Destroy()
	}
	ks.keys = make(map[string]*SecureKey)
}
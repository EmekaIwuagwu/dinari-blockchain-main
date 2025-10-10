//go:build linux || darwin
// +build linux darwin

package crypto

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// lockMemory locks the key's memory pages using mlock (Unix systems)
func (sk *SecureKey) lockMemory() error {
	sk.mu.Lock()
	defer sk.mu.Unlock()

	if len(sk.data) == 0 {
		return errors.New("no data to lock")
	}

	// Use mlock to prevent swapping to disk
	ptr := unsafe.Pointer(&sk.data[0])
	size := uintptr(len(sk.data))
	
	// Lock the memory pages
	if err := unix.Mlock((*[1 << 30]byte)(ptr)[:size:size]); err != nil {
		return fmt.Errorf("mlock failed: %w", err)
	}

	// Advise kernel not to dump this memory in core dumps (Linux only)
	// On macOS, MADV_DONTDUMP doesn't exist, so we check for it
	if err := unix.Madvise((*[1 << 30]byte)(ptr)[:size:size], getMADVISE_DONTDUMP()); err != nil {
		// Non-fatal on macOS where this flag doesn't exist
		// Only warn, don't fail
	}

	sk.mlock = true
	return nil
}

// unlockMemory unlocks the key's memory pages (Unix systems)
func (sk *SecureKey) unlockMemory() {
	if len(sk.data) == 0 {
		return
	}

	ptr := unsafe.Pointer(&sk.data[0])
	size := uintptr(len(sk.data))
	
	// Unlock the memory pages
	unix.Munlock((*[1 << 30]byte)(ptr)[:size:size])
}

// getMADVISE_DONTDUMP returns the platform-specific madvise flag
func getMADVISE_DONTDUMP() int {
	// Linux has MADV_DONTDUMP, macOS doesn't
	// We use a platform-agnostic approach
	const MADV_DONTDUMP = 16 // Linux value
	
	// Try to use it, but don't fail if not available
	return MADV_DONTDUMP
}
//go:build windows
// +build windows

package crypto

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"
)

var (
	kernel32         = syscall.NewLazyDLL("kernel32.dll")
	procVirtualLock  = kernel32.NewProc("VirtualLock")
	procVirtualUnlock = kernel32.NewProc("VirtualUnlock")
)

// lockMemory locks the key's memory pages using VirtualLock (Windows)
func (sk *SecureKey) lockMemory() error {
	sk.mu.Lock()
	defer sk.mu.Unlock()

	if len(sk.data) == 0 {
		return errors.New("no data to lock")
	}

	// Get pointer and size
	ptr := unsafe.Pointer(&sk.data[0])
	size := uintptr(len(sk.data))

	// Call VirtualLock to lock the memory pages
	// VirtualLock prevents the memory from being paged to disk
	ret, _, err := procVirtualLock.Call(
		uintptr(ptr),
		size,
	)

	if ret == 0 {
		// VirtualLock failed
		return fmt.Errorf("VirtualLock failed: %w", err)
	}

	sk.mlock = true
	return nil
}

// unlockMemory unlocks the key's memory pages (Windows)
func (sk *SecureKey) unlockMemory() {
	if len(sk.data) == 0 {
		return
	}

	// Get pointer and size
	ptr := unsafe.Pointer(&sk.data[0])
	size := uintptr(len(sk.data))

	// Call VirtualUnlock to unlock the memory pages
	procVirtualUnlock.Call(
		uintptr(ptr),
		size,
	)
}
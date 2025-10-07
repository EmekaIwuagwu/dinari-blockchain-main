// pkg/crypto/utils.go
// Utility functions for cryptographic operations

package crypto

import (
	"crypto/elliptic"
	
	"github.com/btcsuite/btcd/btcec/v2"
)

// S256 returns the secp256k1 elliptic curve
func S256() elliptic.Curve {
	return btcec.S256()
}
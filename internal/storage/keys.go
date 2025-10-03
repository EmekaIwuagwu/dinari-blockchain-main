package storage

import (
	"encoding/hex"
	"fmt"
)

// Key prefixes for different data types in BadgerDB
const (
	// Blocks
	PrefixBlockByHeight = "b:h:" // b:h:<height> → Block
	PrefixBlockByHash   = "b:x:" // b:x:<hash> → height

	// Transactions
	PrefixTx      = "t:x:" // t:x:<txhash> → Transaction
	PrefixReceipt = "t:r:" // t:r:<txhash> → Receipt

	// Accounts
	PrefixAccount     = "a:s:" // a:s:<address> → Account
	PrefixAddrTxIndex = "a:t:" // a:t:<address>:<txhash> → timestamp

	// Metadata
	PrefixChainTip    = "m:tip"     // → latest block hash
	PrefixChainHeight = "m:height"  // → latest height
	PrefixGenesis     = "m:genesis" // → genesis block hash
	PrefixDifficulty  = "m:diff"    // → current difficulty

	// Mempool (optional persistence)
	PrefixMempool = "p:" // p:<txhash> → Transaction
)

// BlockHeightKey generates a key for storing a block by height
func BlockHeightKey(height uint64) []byte {
	return []byte(fmt.Sprintf("%s%d", PrefixBlockByHeight, height))
}

// BlockHashKey generates a key for storing height by block hash
func BlockHashKey(hash [32]byte) []byte {
	return []byte(fmt.Sprintf("%s%s", PrefixBlockByHash, hex.EncodeToString(hash[:])))
}

// TxKey generates a key for storing a transaction
func TxKey(txHash [32]byte) []byte {
	return []byte(fmt.Sprintf("%s%s", PrefixTx, hex.EncodeToString(txHash[:])))
}

// ReceiptKey generates a key for storing a transaction receipt
func ReceiptKey(txHash [32]byte) []byte {
	return []byte(fmt.Sprintf("%s%s", PrefixReceipt, hex.EncodeToString(txHash[:])))
}

// AccountKey generates a key for storing an account
func AccountKey(address string) []byte {
	return []byte(fmt.Sprintf("%s%s", PrefixAccount, address))
}

// AddressTxIndexKey generates a key for indexing transactions by address
func AddressTxIndexKey(address string) []byte {
    return []byte(fmt.Sprintf("%s%s", PrefixAddrTxIndex, address))
}

// MempoolKey generates a key for storing a transaction in mempool
func MempoolKey(txHash [32]byte) []byte {
	return []byte(fmt.Sprintf("%s%s", PrefixMempool, hex.EncodeToString(txHash[:])))
}

// ChainTipKey returns the key for the chain tip
func ChainTipKey() []byte {
	return []byte(PrefixChainTip)
}

// ChainHeightKey returns the key for the chain height
func ChainHeightKey() []byte {
	return []byte(PrefixChainHeight)
}

// GenesisKey returns the key for the genesis block hash
func GenesisKey() []byte {
	return []byte(PrefixGenesis)
}

// DifficultyKey returns the key for the current difficulty
func DifficultyKey() []byte {
	return []byte(PrefixDifficulty)
}

// ParseBlockHashFromKey extracts the block hash from a block hash key
func ParseBlockHashFromKey(key []byte) ([32]byte, error) {
	keyStr := string(key)
	if len(keyStr) < len(PrefixBlockByHash)+64 {
		return [32]byte{}, fmt.Errorf("invalid block hash key")
	}

	hashStr := keyStr[len(PrefixBlockByHash):]
	hashBytes, err := hex.DecodeString(hashStr)
	if err != nil {
		return [32]byte{}, err
	}

	var hash [32]byte
	copy(hash[:], hashBytes)
	return hash, nil
}

// ParseTxHashFromKey extracts the transaction hash from a transaction key
func ParseTxHashFromKey(key []byte) ([32]byte, error) {
	keyStr := string(key)
	if len(keyStr) < len(PrefixTx)+64 {
		return [32]byte{}, fmt.Errorf("invalid tx key")
	}

	hashStr := keyStr[len(PrefixTx):]
	hashBytes, err := hex.DecodeString(hashStr)
	if err != nil {
		return [32]byte{}, err
	}

	var hash [32]byte
	copy(hash[:], hashBytes)
	return hash, nil
}

// ParseAddressFromKey extracts the address from an account key
func ParseAddressFromKey(key []byte) (string, error) {
	keyStr := string(key)
	if len(keyStr) < len(PrefixAccount)+1 {
		return "", fmt.Errorf("invalid account key")
	}

	address := keyStr[len(PrefixAccount):]
	return address, nil
}

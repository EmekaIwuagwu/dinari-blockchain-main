package types

import "errors"

// Block validation errors
var (
	ErrInvalidBlockHash  = errors.New("invalid block hash")
	ErrInvalidParentHash = errors.New("invalid parent hash")
	ErrInvalidTimestamp  = errors.New("invalid timestamp")
	ErrInvalidDifficulty = errors.New("invalid difficulty")
	ErrInvalidMerkleRoot = errors.New("invalid merkle root")
	ErrInvalidStateRoot  = errors.New("invalid state root")
	ErrInvalidTxCount    = errors.New("transaction count mismatch")
	ErrBlockTooLarge     = errors.New("block exceeds maximum size")
	ErrInvalidPoW        = errors.New("invalid proof of work")
)

// Transaction validation errors
var (
	ErrInvalidTransaction   = errors.New("invalid transaction") // NEW: General transaction error
	ErrInvalidTxHash        = errors.New("invalid transaction hash")
	ErrInvalidFromAddress   = errors.New("invalid from address")
	ErrInvalidToAddress     = errors.New("invalid to address")
	ErrInvalidAmount        = errors.New("invalid amount")
	ErrInvalidFee           = errors.New("invalid fee")
	ErrInvalidTokenType     = errors.New("invalid token type")
	ErrInvalidNonce         = errors.New("invalid nonce")
	ErrInvalidSignature     = errors.New("invalid signature")
	ErrMissingSignature     = errors.New("missing signature")
	ErrMissingPublicKey     = errors.New("missing public key")
	ErrInvalidTxSize        = errors.New("invalid transaction size: must be greater than zero")
	ErrTxTooLarge           = errors.New("transaction exceeds maximum size")
	ErrFeeTooLow            = errors.New("fee too low")
	ErrInsufficientBalance  = errors.New("insufficient balance")
	ErrDuplicateTransaction = errors.New("duplicate transaction")
	ErrTxNotFound           = errors.New("transaction not found")
	ErrReceiptNotFound      = errors.New("receipt not found")
)

// Account errors
var (
	ErrAccountNotFound = errors.New("account not found")
	ErrInvalidAddress  = errors.New("invalid address")
)

// State errors
var (
	ErrStateNotFound   = errors.New("state not found")
	ErrStateCorrupted  = errors.New("state corrupted")
	ErrInvalidStateKey = errors.New("invalid state key")
)

// Blockchain errors
var (
	ErrBlockNotFound    = errors.New("block not found")
	ErrInvalidChain     = errors.New("invalid blockchain")
	ErrOrphanBlock      = errors.New("orphan block")
	ErrReorgTooDeep     = errors.New("reorganization too deep")
	ErrGenesisNotFound  = errors.New("genesis block not found")
	ErrChainTipNotFound = errors.New("chain tip not found")
)

// Mempool errors
var (
	ErrMempoolFull        = errors.New("mempool is full")
	ErrTxAlreadyInMempool = errors.New("transaction already in mempool")
	ErrTxExpired          = errors.New("transaction expired")
	ErrRBFNotAllowed      = errors.New("replace-by-fee not allowed")
)

// Consensus errors
var (
	ErrInvalidReward    = errors.New("invalid block reward")
	ErrInvalidCoinbase  = errors.New("invalid coinbase transaction")
	ErrMultipleCoinbase = errors.New("multiple coinbase transactions")
	ErrMissingCoinbase  = errors.New("missing coinbase transaction")
)

// Mint errors
var (
	ErrUnauthorizedMint = errors.New("unauthorized mint operation")
	ErrInvalidMintTx    = errors.New("invalid mint transaction")
	ErrMintOnlyAFC      = errors.New("only AFC can be minted")
)

// Network errors
var (
	ErrInvalidPeer      = errors.New("invalid peer")
	ErrPeerDisconnected = errors.New("peer disconnected")
	ErrNetworkTimeout   = errors.New("network timeout")
	ErrInvalidMessage   = errors.New("invalid message")
)

// Storage errors
var (
	ErrDatabaseClosed = errors.New("database is closed")
	ErrKeyNotFound    = errors.New("key not found")
	ErrWriteFailed    = errors.New("write operation failed")
	ErrReadFailed     = errors.New("read operation failed")
)

// internal/types/types.go
// Core type definitions for the Dinari blockchain

package types

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"time"
)

const (
	TokenTypeDNT = "DNT" // Main PoW-mined coin
	TokenTypeAFC = "AFC" // Payment token for transactions
)

// Block represents a block in the blockchain
type Block struct {
	Height        uint64        `json:"height"`
	Timestamp     time.Time     `json:"timestamp"`
	PreviousHash  string        `json:"previous_hash"`
	Hash          string        `json:"hash"`
	MerkleRoot    string        `json:"merkle_root"`
	Nonce         uint64        `json:"nonce"`
	Difficulty    *big.Int      `json:"difficulty"`
	Transactions  []*Transaction `json:"transactions"`
	Miner         string        `json:"miner"`
	Reward        uint64        `json:"reward"`
	Size          int           `json:"size"`
	Version       uint32        `json:"version"`
	StateRoot     string        `json:"state_root"`
	GasUsed       uint64        `json:"gas_used"`
	GasLimit      uint64        `json:"gas_limit"`
}

// Transaction represents a transaction in the blockchain
type Transaction struct {
	Hash         []byte                 `json:"hash"`
	From         string                 `json:"from"`
	To           string                 `json:"to"`
	Amount       []byte                 `json:"amount"`
	TokenType    string                 `json:"token_type"`
	Nonce        uint64                 `json:"nonce"`
	GasPrice     uint64                 `json:"gas_price"`
	GasLimit     uint64                 `json:"gas_limit"`
	Data         []byte                 `json:"data"`
	Signature    []byte                 `json:"signature"`
	PublicKey    []byte                 `json:"public_key"`
	Timestamp    time.Time              `json:"timestamp"`
	MultiSigData *MultiSigData          `json:"multisig_data,omitempty"`
	Status       TransactionStatus      `json:"status"`
	BlockHash    string                 `json:"block_hash,omitempty"`
	BlockHeight  uint64                 `json:"block_height,omitempty"`
	Version      uint32                 `json:"version"`
}

// MultiSigData contains multi-signature information
type MultiSigData struct {
	PolicyID         string              `json:"policy_id"`
	RequiredSigs     uint8               `json:"required_sigs"`
	Signatures       []MultiSigSignature `json:"signatures"`
	Complete         bool                `json:"complete"`
}

// MultiSigSignature represents a single signature in multisig
type MultiSigSignature struct {
	PublicKey []byte    `json:"public_key"`
	Signature []byte    `json:"signature"`
	Address   string    `json:"address"`
	SignedAt  time.Time `json:"signed_at"`
}

// TransactionStatus represents the status of a transaction
type TransactionStatus int

const (
	TxStatusPending TransactionStatus = iota
	TxStatusConfirmed
	TxStatusFailed
	TxStatusFinalized
)

func (ts TransactionStatus) String() string {
	switch ts {
	case TxStatusPending:
		return "PENDING"
	case TxStatusConfirmed:
		return "CONFIRMED"
	case TxStatusFailed:
		return "FAILED"
	case TxStatusFinalized:
		return "FINALIZED"
	default:
		return "UNKNOWN"
	}
}

// Account represents an account in the state
type Account struct {
	Address      string    `json:"address"`
	BalanceDNT   *big.Int  `json:"balance_dnt"`
	BalanceAFC   *big.Int  `json:"balance_afc"`
	Nonce        uint64    `json:"nonce"`
	CodeHash     string    `json:"code_hash,omitempty"`
	StorageRoot  string    `json:"storage_root,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// BlockHeader contains the header information of a block
type BlockHeader struct {
	Height       uint64    `json:"height"`
	Timestamp    time.Time `json:"timestamp"`
	PreviousHash string    `json:"previous_hash"`
	MerkleRoot   string    `json:"merkle_root"`
	StateRoot    string    `json:"state_root"`
	Difficulty   *big.Int  `json:"difficulty"`
	Nonce        uint64    `json:"nonce"`
	Version      uint32    `json:"version"`
}

// ChainConfig represents the blockchain configuration
type ChainConfig struct {
	ChainID                uint64        `json:"chain_id"`
	NetworkName            string        `json:"network_name"`
	BlockTime              time.Duration `json:"block_time"`
	DifficultyAdjustment   int64         `json:"difficulty_adjustment"`
	InitialDifficulty      *big.Int      `json:"initial_difficulty"`
	BlockReward            uint64        `json:"block_reward"`
	HalvingInterval        uint64        `json:"halving_interval"`
	MaxSupplyDNT           uint64        `json:"max_supply_dnt"`
	GenesisTimestamp       time.Time     `json:"genesis_timestamp"`
	ConfirmationDepth      int           `json:"confirmation_depth"`
	MaxBlockSize           int           `json:"max_block_size"`
	MaxTransactionsPerBlock int          `json:"max_transactions_per_block"`
}

// PeerInfo represents information about a peer
type PeerInfo struct {
	ID            string    `json:"id"`
	Address       string    `json:"address"`
	Port          int       `json:"port"`
	Version       string    `json:"version"`
	LastSeen      time.Time `json:"last_seen"`
	Height        uint64    `json:"height"`
	Connected     bool      `json:"connected"`
	Latency       int64     `json:"latency_ms"`
}

// NetworkMessage represents a message on the P2P network
type NetworkMessage struct {
	Type      string    `json:"type"`
	Payload   []byte    `json:"payload"`
	Sender    string    `json:"sender"`
	Timestamp time.Time `json:"timestamp"`
	Signature []byte    `json:"signature"`
}

// UTXOSet represents unspent transaction outputs
type UTXOSet struct {
	TxHash  string   `json:"tx_hash"`
	Index   uint32   `json:"index"`
	Amount  *big.Int `json:"amount"`
	Address string   `json:"address"`
	Spent   bool     `json:"spent"`
}

// Hash calculates the hash of a transaction
func (tx *Transaction) Hash() []byte {
	if len(tx.Hash) > 0 {
		return tx.Hash
	}

	data, _ := json.Marshal(struct {
		From      string `json:"from"`
		To        string `json:"to"`
		Amount    []byte `json:"amount"`
		TokenType string `json:"token_type"`
		Nonce     uint64 `json:"nonce"`
		GasPrice  uint64 `json:"gas_price"`
		GasLimit  uint64 `json:"gas_limit"`
		Data      []byte `json:"data"`
		Timestamp int64  `json:"timestamp"`
	}{
		From:      tx.From,
		To:        tx.To,
		Amount:    tx.Amount,
		TokenType: tx.TokenType,
		Nonce:     tx.Nonce,
		GasPrice:  tx.GasPrice,
		GasLimit:  tx.GasLimit,
		Data:      tx.Data,
		Timestamp: tx.Timestamp.Unix(),
	})

	hash := sha256.Sum256(data)
	return hash[:]
}

// Size returns the size of the transaction in bytes
func (tx *Transaction) Size() int {
	data, _ := json.Marshal(tx)
	return len(data)
}

// GetAmount returns the transaction amount as big.Int
func (tx *Transaction) GetAmount() *big.Int {
	return new(big.Int).SetBytes(tx.Amount)
}

// SetAmount sets the transaction amount from big.Int
func (tx *Transaction) SetAmount(amount *big.Int) {
	tx.Amount = amount.Bytes()
}

// IsCoinbase checks if the transaction is a coinbase transaction
func (tx *Transaction) IsCoinbase() bool {
	return tx.From == "" || tx.From == "0000000000000000000000000000000000000000"
}

// CalculateHash calculates the hash of a block
func (b *Block) CalculateHash() string {
	data, _ := json.Marshal(struct {
		Height       uint64    `json:"height"`
		Timestamp    int64     `json:"timestamp"`
		PreviousHash string    `json:"previous_hash"`
		MerkleRoot   string    `json:"merkle_root"`
		Nonce        uint64    `json:"nonce"`
		Difficulty   string    `json:"difficulty"`
		Miner        string    `json:"miner"`
	}{
		Height:       b.Height,
		Timestamp:    b.Timestamp.Unix(),
		PreviousHash: b.PreviousHash,
		MerkleRoot:   b.MerkleRoot,
		Nonce:        b.Nonce,
		Difficulty:   b.Difficulty.String(),
		Miner:        b.Miner,
	})

	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// CalculateMerkleRoot calculates the Merkle root of transactions
func (b *Block) CalculateMerkleRoot() string {
	if len(b.Transactions) == 0 {
		return ""
	}

	var hashes [][]byte
	for _, tx := range b.Transactions {
		hashes = append(hashes, tx.Hash())
	}

	return hex.EncodeToString(buildMerkleTree(hashes))
}

func buildMerkleTree(hashes [][]byte) []byte {
	if len(hashes) == 0 {
		return nil
	}

	if len(hashes) == 1 {
		return hashes[0]
	}

	var newLevel [][]byte

	for i := 0; i < len(hashes); i += 2 {
		if i+1 < len(hashes) {
			combined := append(hashes[i], hashes[i+1]...)
			hash := sha256.Sum256(combined)
			newLevel = append(newLevel, hash[:])
		} else {
			combined := append(hashes[i], hashes[i]...)
			hash := sha256.Sum256(combined)
			newLevel = append(newLevel, hash[:])
		}
	}

	return buildMerkleTree(newLevel)
}

// GetHeader returns the block header
func (b *Block) GetHeader() *BlockHeader {
	return &BlockHeader{
		Height:       b.Height,
		Timestamp:    b.Timestamp,
		PreviousHash: b.PreviousHash,
		MerkleRoot:   b.MerkleRoot,
		StateRoot:    b.StateRoot,
		Difficulty:   b.Difficulty,
		Nonce:        b.Nonce,
		Version:      b.Version,
	}
}

// ValidateBasic performs basic validation on the block
func (b *Block) ValidateBasic() error {
	if b.Height < 0 {
		return ErrInvalidBlockHeight
	}

	if b.PreviousHash == "" && b.Height != 0 {
		return ErrInvalidPreviousHash
	}

	if len(b.Transactions) == 0 {
		return ErrNoTransactions
	}

	if b.MerkleRoot != b.CalculateMerkleRoot() {
		return ErrInvalidMerkleRoot
	}

	return nil
}

// NewTransaction creates a new transaction
func NewTransaction(from, to string, amount *big.Int, tokenType string, nonce uint64) *Transaction {
	return &Transaction{
		From:      from,
		To:        to,
		Amount:    amount.Bytes(),
		TokenType: tokenType,
		Nonce:     nonce,
		Timestamp: time.Now(),
		Status:    TxStatusPending,
		Version:   1,
	}
}

// NewBlock creates a new block
func NewBlock(height uint64, previousHash string, transactions []*Transaction, miner string) *Block {
	block := &Block{
		Height:       height,
		Timestamp:    time.Now(),
		PreviousHash: previousHash,
		Transactions: transactions,
		Miner:        miner,
		Version:      1,
		GasLimit:     10000000,
	}

	block.MerkleRoot = block.CalculateMerkleRoot()
	block.Hash = block.CalculateHash()

	return block
}

// NewAccount creates a new account
func NewAccount(address string) *Account {
	return &Account{
		Address:    address,
		BalanceDNT: big.NewInt(0),
		BalanceAFC: big.NewInt(0),
		Nonce:      0,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}
}

// Clone creates a deep copy of the transaction
func (tx *Transaction) Clone() *Transaction {
	clone := &Transaction{
		Hash:        make([]byte, len(tx.Hash)),
		From:        tx.From,
		To:          tx.To,
		Amount:      make([]byte, len(tx.Amount)),
		TokenType:   tx.TokenType,
		Nonce:       tx.Nonce,
		GasPrice:    tx.GasPrice,
		GasLimit:    tx.GasLimit,
		Data:        make([]byte, len(tx.Data)),
		Signature:   make([]byte, len(tx.Signature)),
		PublicKey:   make([]byte, len(tx.PublicKey)),
		Timestamp:   tx.Timestamp,
		Status:      tx.Status,
		BlockHash:   tx.BlockHash,
		BlockHeight: tx.BlockHeight,
		Version:     tx.Version,
	}

	copy(clone.Hash, tx.Hash)
	copy(clone.Amount, tx.Amount)
	copy(clone.Data, tx.Data)
	copy(clone.Signature, tx.Signature)
	copy(clone.PublicKey, tx.PublicKey)

	if tx.MultiSigData != nil {
		clone.MultiSigData = &MultiSigData{
			PolicyID:     tx.MultiSigData.PolicyID,
			RequiredSigs: tx.MultiSigData.RequiredSigs,
			Signatures:   make([]MultiSigSignature, len(tx.MultiSigData.Signatures)),
			Complete:     tx.MultiSigData.Complete,
		}
		copy(clone.MultiSigData.Signatures, tx.MultiSigData.Signatures)
	}

	return clone
}

// Errors
var (
	ErrInvalidBlockHeight   = NewError("invalid block height")
	ErrInvalidPreviousHash  = NewError("invalid previous hash")
	ErrNoTransactions       = NewError("block has no transactions")
	ErrInvalidMerkleRoot    = NewError("invalid merkle root")
	ErrInvalidTransaction   = NewError("invalid transaction")
	ErrInsufficientBalance  = NewError("insufficient balance")
	ErrInvalidNonce         = NewError("invalid nonce")
	ErrInvalidSignature     = NewError("invalid signature")
)

type BlockchainError struct {
	Message string
}

func (e *BlockchainError) Error() string {
	return e.Message
}

func NewError(message string) error {
	return &BlockchainError{Message: message}
}

// BlockchainInfo represents current blockchain information
type BlockchainInfo struct {
	Height              uint64    `json:"height"`
	BestBlockHash       string    `json:"best_block_hash"`
	Difficulty          *big.Int  `json:"difficulty"`
	TotalTransactions   uint64    `json:"total_transactions"`
	ChainWork           *big.Int  `json:"chain_work"`
	MedianBlockTime     int64     `json:"median_block_time"`
	VerificationProgress float64  `json:"verification_progress"`
	Pruned              bool      `json:"pruned"`
	SizeOnDisk          int64     `json:"size_on_disk"`
	Warnings            []string  `json:"warnings"`
}

// MiningInfo represents mining information
type MiningInfo struct {
	CurrentBlockSize    int       `json:"current_block_size"`
	CurrentBlockWeight  int       `json:"current_block_weight"`
	CurrentBlockTx      int       `json:"current_block_tx"`
	Difficulty          *big.Int  `json:"difficulty"`
	NetworkHashRate     *big.Int  `json:"network_hash_rate"`
	PooledTx            int       `json:"pooled_tx"`
	Chain               string    `json:"chain"`
	Warnings            []string  `json:"warnings"`
}

// NodeInfo represents node information
type NodeInfo struct {
	Version         string    `json:"version"`
	ProtocolVersion int       `json:"protocol_version"`
	Blocks          uint64    `json:"blocks"`
	TimeOffset      int64     `json:"time_offset"`
	Connections     int       `json:"connections"`
	Difficulty      *big.Int  `json:"difficulty"`
	Testnet         bool      `json:"testnet"`
	RelayFee        uint64    `json:"relay_fee"`
	LocalAddresses  []string  `json:"local_addresses"`
	Warnings        []string  `json:"warnings"`
}

// WalletInfo represents wallet information
type WalletInfo struct {
	Address         string    `json:"address"`
	BalanceDNT      *big.Int  `json:"balance_dnt"`
	BalanceAFC      *big.Int  `json:"balance_afc"`
	UnconfirmedDNT  *big.Int  `json:"unconfirmed_dnt"`
	UnconfirmedAFC  *big.Int  `json:"unconfirmed_afc"`
	TxCount         uint64    `json:"tx_count"`
	ImmatureBalance *big.Int  `json:"immature_balance"`
}
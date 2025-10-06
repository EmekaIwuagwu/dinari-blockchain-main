package types

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"time"
)

const (
	// Address format
	AddressLength = 42 // D + 40 hex chars
	AddressPrefix = "D"
	
	// Hash lengths
	HashLength = 32
	
	// Transaction limits
	MaxTransactionSize = 100 * 1024 // 100KB
	MaxDataSize        = 64 * 1024  // 64KB
	
	// Block limits
	MaxBlockSize            = 1 << 20 // 1MB
	MaxTransactionsPerBlock = 5000
)

var (
	ErrInvalidAddress      = errors.New("invalid address format")
	ErrInvalidHash         = errors.New("invalid hash")
	ErrInvalidSignature    = errors.New("invalid signature")
	ErrInvalidAmount       = errors.New("invalid amount")
	ErrTransactionTooLarge = errors.New("transaction too large")
	ErrInvalidNonce        = errors.New("invalid nonce")
	ErrInvalidTimestamp    = errors.New("invalid timestamp")
)

// TokenType represents the type of token
type TokenType string

const (
	TokenDNT TokenType = "DNT" // Mining token
	TokenAFC TokenType = "AFC" // Payment token
)

// Transaction represents a blockchain transaction
type Transaction struct {
	Hash      []byte    `json:"hash"`
	From      string    `json:"from"`
	To        string    `json:"to"`
	Amount    *big.Int  `json:"amount"`
	TokenType TokenType `json:"tokenType"`
	FeeDNT    *big.Int  `json:"feeDNT"`
	Nonce     uint64    `json:"nonce"`
	Timestamp int64     `json:"timestamp"`
	Signature []byte    `json:"signature"`
	PublicKey []byte    `json:"publicKey"`
	Data      []byte    `json:"data,omitempty"`
}

// NewTransaction creates a new transaction
func NewTransaction(from, to string, amount *big.Int, tokenType TokenType, feeDNT *big.Int, nonce uint64) *Transaction {
	return &Transaction{
		From:      from,
		To:        to,
		Amount:    new(big.Int).Set(amount),
		TokenType: tokenType,
		FeeDNT:    new(big.Int).Set(feeDNT),
		Nonce:     nonce,
		Timestamp: time.Now().Unix(),
	}
}

// CalculateHash computes the hash of the transaction
func (tx *Transaction) CalculateHash() []byte {
	data := tx.SerializeForSigning()
	hash := sha256.Sum256(data)
	finalHash := sha256.Sum256(hash[:])
	return finalHash[:]
}

// SerializeForSigning prepares transaction data for signing
func (tx *Transaction) SerializeForSigning() []byte {
	var buf bytes.Buffer
	
	buf.WriteString(tx.From)
	buf.WriteString(tx.To)
	buf.Write(tx.Amount.Bytes())
	buf.WriteString(string(tx.TokenType))
	buf.Write(tx.FeeDNT.Bytes())
	binary.Write(&buf, binary.BigEndian, tx.Nonce)
	binary.Write(&buf, binary.BigEndian, tx.Timestamp)
	if len(tx.Data) > 0 {
		buf.Write(tx.Data)
	}
	
	return buf.Bytes()
}

// Validate performs comprehensive transaction validation
func (tx *Transaction) Validate() error {
	// Validate addresses
	if !IsValidAddress(tx.From) {
		return fmt.Errorf("%w: from address %s", ErrInvalidAddress, tx.From)
	}
	if !IsValidAddress(tx.To) {
		return fmt.Errorf("%w: to address %s", ErrInvalidAddress, tx.To)
	}
	if tx.From == tx.To {
		return errors.New("sender and recipient cannot be the same")
	}
	
	// Validate amount
	if tx.Amount == nil || tx.Amount.Sign() <= 0 {
		return errors.New("amount must be positive")
	}
	
	// Validate fee
	if tx.FeeDNT == nil || tx.FeeDNT.Sign() < 0 {
		return errors.New("fee cannot be negative")
	}
	
	// Validate token type
	if tx.TokenType != TokenDNT && tx.TokenType != TokenAFC {
		return fmt.Errorf("invalid token type: %s", tx.TokenType)
	}
	
	// Validate timestamp
	now := time.Now().Unix()
	if tx.Timestamp > now+3600 { // Max 1 hour in future
		return ErrInvalidTimestamp
	}
	if tx.Timestamp < now-86400 { // Max 1 day in past
		return ErrInvalidTimestamp
	}
	
	// Validate signature
	if len(tx.Signature) == 0 {
		return errors.New("missing signature")
	}
	if len(tx.Signature) != 64 && len(tx.Signature) != 65 {
		return ErrInvalidSignature
	}
	
	// Validate public key
	if len(tx.PublicKey) == 0 {
		return errors.New("missing public key")
	}
	if len(tx.PublicKey) != 33 && len(tx.PublicKey) != 65 {
		return errors.New("invalid public key length")
	}
	
	// Validate data size
	if len(tx.Data) > MaxDataSize {
		return errors.New("data field too large")
	}
	
	// Validate hash
	if len(tx.Hash) != HashLength {
		return ErrInvalidHash
	}
	
	return nil
}

// Size returns the approximate size of the transaction in bytes
func (tx *Transaction) Size() int {
	data, _ := json.Marshal(tx)
	return len(data)
}

// Copy creates a deep copy of the transaction
func (tx *Transaction) Copy() *Transaction {
	return &Transaction{
		Hash:      append([]byte(nil), tx.Hash...),
		From:      tx.From,
		To:        tx.To,
		Amount:    new(big.Int).Set(tx.Amount),
		TokenType: tx.TokenType,
		FeeDNT:    new(big.Int).Set(tx.FeeDNT),
		Nonce:     tx.Nonce,
		Timestamp: tx.Timestamp,
		Signature: append([]byte(nil), tx.Signature...),
		PublicKey: append([]byte(nil), tx.PublicKey...),
		Data:      append([]byte(nil), tx.Data...),
	}
}

// Block represents a blockchain block
type Block struct {
	Header       *BlockHeader   `json:"header"`
	Transactions []*Transaction `json:"transactions"`
}

// BlockHeader contains block metadata
type BlockHeader struct {
	Version       uint32   `json:"version"`
	Height        uint64   `json:"height"`
	PrevBlockHash []byte   `json:"prevBlockHash"`
	MerkleRoot    []byte   `json:"merkleRoot"`
	Timestamp     int64    `json:"timestamp"`
	Difficulty    uint32   `json:"difficulty"`
	Nonce         uint64   `json:"nonce"`
	Hash          []byte   `json:"hash"`
	StateRoot     []byte   `json:"stateRoot"`
	Miner         string   `json:"miner"`
}

// NewBlock creates a new block
func NewBlock(header *BlockHeader, transactions []*Transaction) *Block {
	return &Block{
		Header:       header,
		Transactions: transactions,
	}
}

// Validate performs comprehensive block validation
func (b *Block) Validate() error {
	// Validate header
	if err := b.Header.Validate(); err != nil {
		return fmt.Errorf("invalid header: %w", err)
	}
	
	// Validate block size
	if b.Size() > MaxBlockSize {
		return errors.New("block exceeds maximum size")
	}
	
	// Validate transaction count
	if len(b.Transactions) == 0 {
		return errors.New("block must contain at least one transaction")
	}
	if len(b.Transactions) > MaxTransactionsPerBlock {
		return errors.New("too many transactions in block")
	}
	
	// First transaction must be coinbase
	if b.Transactions[0].From != "COINBASE" {
		return errors.New("first transaction must be coinbase")
	}
	
	// Validate all transactions
	seenHashes := make(map[string]bool)
	for i, tx := range b.Transactions {
		// Validate transaction
		if err := tx.Validate(); err != nil {
			return fmt.Errorf("invalid transaction at index %d: %w", i, err)
		}
		
		// Check for duplicates
		hashStr := hex.EncodeToString(tx.Hash)
		if seenHashes[hashStr] {
			return fmt.Errorf("duplicate transaction at index %d", i)
		}
		seenHashes[hashStr] = true
		
		// Non-coinbase transactions cannot have COINBASE as sender
		if i > 0 && tx.From == "COINBASE" {
			return fmt.Errorf("non-coinbase transaction cannot have COINBASE sender at index %d", i)
		}
	}
	
	// Validate merkle root
	calculatedMerkleRoot := CalculateMerkleRoot(b.Transactions)
	if !bytes.Equal(calculatedMerkleRoot, b.Header.MerkleRoot) {
		return errors.New("merkle root mismatch")
	}
	
	return nil
}

// Size returns the size of the block in bytes
func (b *Block) Size() int {
	data, _ := json.Marshal(b)
	return len(data)
}

// Validate performs block header validation
func (h *BlockHeader) Validate() error {
	// Validate version
	if h.Version == 0 {
		return errors.New("invalid version")
	}
	
	// Validate height
	if h.Height < 0 {
		return errors.New("invalid height")
	}
	
	// Validate hashes
	if len(h.Hash) != HashLength {
		return errors.New("invalid hash length")
	}
	if h.Height > 0 && len(h.PrevBlockHash) != HashLength {
		return errors.New("invalid previous block hash length")
	}
	if len(h.MerkleRoot) != HashLength {
		return errors.New("invalid merkle root length")
	}
	if len(h.StateRoot) != HashLength {
		return errors.New("invalid state root length")
	}
	
	// Validate timestamp
	now := time.Now().Unix()
	if h.Timestamp > now+7200 { // Max 2 hours in future
		return errors.New("timestamp too far in future")
	}
	
	// Validate difficulty
	if h.Difficulty == 0 {
		return errors.New("difficulty cannot be zero")
	}
	
	// Validate miner address
	if h.Miner != "" && !IsValidAddress(h.Miner) {
		return errors.New("invalid miner address")
	}
	
	return nil
}

// CalculateMerkleRoot calculates the merkle root of transactions
func CalculateMerkleRoot(txs []*Transaction) []byte {
	if len(txs) == 0 {
		return make([]byte, HashLength)
	}
	
	// Build merkle tree
	hashes := make([][]byte, len(txs))
	for i, tx := range txs {
		hashes[i] = tx.Hash
	}
	
	for len(hashes) > 1 {
		// Duplicate last hash if odd number
		if len(hashes)%2 != 0 {
			hashes = append(hashes, hashes[len(hashes)-1])
		}
		
		newLevel := make([][]byte, 0, len(hashes)/2)
		for i := 0; i < len(hashes); i += 2 {
			combined := append(hashes[i], hashes[i+1]...)
			hash := sha256.Sum256(combined)
			newLevel = append(newLevel, hash[:])
		}
		hashes = newLevel
	}
	
	return hashes[0]
}

// IsValidAddress validates a Dinari address format
func IsValidAddress(addr string) bool {
	if len(addr) != AddressLength {
		return false
	}
	if addr[:2] != AddressPrefix {
		return false
	}
	// Validate hex characters
	_, err := hex.DecodeString(addr[2:])
	return err == nil
}

// IsValidHash validates a hash
func IsValidHash(hash []byte) bool {
	return len(hash) == HashLength
}

// FormatAmount formats an amount with 8 decimals
func FormatAmount(amount *big.Int) string {
	if amount == nil {
		return "0.00000000"
	}
	
	divisor := big.NewInt(1e8)
	whole := new(big.Int).Div(amount, divisor)
	remainder := new(big.Int).Mod(amount, divisor)
	
	if remainder.Sign() == 0 {
		return whole.String() + ".00000000"
	}
	
	return fmt.Sprintf("%s.%08d", whole.String(), remainder.Uint64())
}

// ParseAmount parses an amount string with decimals
func ParseAmount(s string) (*big.Int, error) {
	// Implementation would parse "123.45678900" to big.Int
	// For now, simple implementation
	amount := new(big.Int)
	_, ok := amount.SetString(s, 10)
	if !ok {
		return nil, errors.New("invalid amount format")
	}
	return amount, nil
}
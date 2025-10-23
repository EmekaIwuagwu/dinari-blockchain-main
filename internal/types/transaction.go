package types

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"math/big"
	"time"
)

// TokenType represents the type of token being transferred
type TokenType string

const (
	TokenDNT TokenType = "DNT" // DINARI - mined coin
	TokenAFC TokenType = "AFC" // Afrocoin - payment token
)

// Transaction represents a transfer of tokens between addresses
type Transaction struct {
	Hash      [32]byte      `json:"hash"`
	From      string        `json:"from"`
	To        string        `json:"to"`
	Amount    *big.Int      `json:"amount"`
	TokenType string        `json:"tokenType"`
	FeeDNT    *big.Int      `json:"fee"`
	Nonce     uint64        `json:"nonce"`
	Timestamp int64         `json:"timestamp"`
	Signature []byte        `json:"signature"`
	PublicKey []byte        `json:"publicKey"`
	MultiSig  *MultiSigData `json:"multisig,omitempty"` // NEW: Multi-signature support
}

// NewTransaction creates a new transaction
func NewTransaction(from, to string, amount *big.Int, tokenType string, fee *big.Int, nonce uint64) *Transaction {
	tx := &Transaction{
		From:      from,
		To:        to,
		Amount:    amount,
		TokenType: tokenType,
		FeeDNT:    fee,
		Nonce:     nonce,
		Timestamp: time.Now().Unix(),
	}
	return tx
}

// NewCoinbaseTransaction creates a coinbase (mining reward) transaction
func NewCoinbaseTransaction(minerAddress string, reward *big.Int, blockNumber uint64) *Transaction {
	tx := &Transaction{
		From:      "coinbase",
		To:        minerAddress,
		Amount:    reward,
		TokenType: string(TokenDNT),
		FeeDNT:    big.NewInt(0),
		Nonce:     blockNumber, // Use block number as nonce for coinbase
		Timestamp: time.Now().Unix(),
		Signature: []byte{},
		PublicKey: []byte{},
	}
	tx.Hash = tx.ComputeHash()
	return tx
}

// ComputeHash calculates the transaction hash (excludes signature)
func (tx *Transaction) ComputeHash() [32]byte {
	data := tx.SerializeForSigning()
	return sha256.Sum256(data)
}

// SerializeForSigning returns the canonical serialization used for signing
// This excludes the signature field itself
func (tx *Transaction) SerializeForSigning() []byte {
	var buf bytes.Buffer

	// From address
	buf.WriteString(tx.From)

	// To address
	buf.WriteString(tx.To)

	// Amount (32 bytes, big-endian)
	amountBytes := tx.Amount.Bytes()
	amountPadded := make([]byte, 32)
	copy(amountPadded[32-len(amountBytes):], amountBytes)
	buf.Write(amountPadded)

	// Token type
	buf.WriteString(tx.TokenType)

	// Fee (32 bytes, big-endian)
	feeBytes := tx.FeeDNT.Bytes()
	feePadded := make([]byte, 32)
	copy(feePadded[32-len(feeBytes):], feeBytes)
	buf.Write(feePadded)

	// Nonce (8 bytes)
	binary.Write(&buf, binary.BigEndian, tx.Nonce)

	// Timestamp (8 bytes)
	binary.Write(&buf, binary.BigEndian, tx.Timestamp)

	return buf.Bytes()
}

// Serialize converts the transaction to JSON bytes
func (tx *Transaction) Serialize() ([]byte, error) {
	return json.Marshal(tx)
}

// DeserializeTransaction reconstructs a transaction from bytes
func DeserializeTransaction(data []byte) (*Transaction, error) {
	var tx Transaction
	if err := json.Unmarshal(data, &tx); err != nil {
		return nil, err
	}
	return &tx, nil
}

// Size returns the size of the transaction in bytes by serializing it to JSON.
// This size is used by the mempool for fee calculation and transaction validation.
// The returned size is always greater than zero for valid transactions.
//
// IMPORTANT: This method must be called to set the Size field when converting
// transactions to mempool format. Transactions with zero size will be rejected
// by the mempool.
func (tx *Transaction) Size() int {
	data, _ := tx.Serialize()
	return len(data)
}

// IsCoinbase returns true if this is a coinbase transaction
func (tx *Transaction) IsCoinbase() bool {
	return tx.From == "coinbase"
}

// IsMint returns true if this is a mint transaction (AFC creation)
func (tx *Transaction) IsMint() bool {
	return tx.From == "mint" && tx.TokenType == string(TokenAFC)
}

// Validate performs basic validation on transaction structure
func (tx *Transaction) Validate() error {
	// Check addresses are not empty (unless coinbase/mint)
	if !tx.IsCoinbase() && !tx.IsMint() {
		if tx.From == "" {
			return ErrInvalidFromAddress
		}
	}

	if tx.To == "" {
		return ErrInvalidToAddress
	}

	// Check amount is positive
	if tx.Amount == nil || tx.Amount.Sign() <= 0 {
		return ErrInvalidAmount
	}

	// Check fee is non-negative
	if tx.FeeDNT == nil || tx.FeeDNT.Sign() < 0 {
		return ErrInvalidFee
	}

	// Check token type is valid
	if tx.TokenType != string(TokenDNT) && tx.TokenType != string(TokenAFC) {
		return ErrInvalidTokenType
	}

	// Check signature exists (except for coinbase/mint)
	if !tx.IsCoinbase() && !tx.IsMint() {
		if len(tx.Signature) == 0 {
			return ErrMissingSignature
		}
		if len(tx.PublicKey) == 0 {
			return ErrMissingPublicKey
		}
	}

	// Check timestamp is reasonable
	maxFutureTime := time.Now().Unix() + 300 // 5 minutes tolerance
	if tx.Timestamp > maxFutureTime {
		return ErrInvalidTimestamp
	}

	// Verify hash is correct
	calculatedHash := tx.ComputeHash()
	if calculatedHash != tx.Hash {
		return ErrInvalidTxHash
	}

	// Validate that transaction has a valid non-zero size
	// This ensures the transaction can be properly serialized
	txSize := tx.Size()
	if txSize <= 0 {
		return ErrInvalidTxSize
	}

	return nil
}

// String returns a human-readable representation
func (tx *Transaction) String() string {
	data, _ := json.MarshalIndent(tx, "", "  ")
	return string(data)
}

// Copy creates a deep copy of the transaction
func (tx *Transaction) Copy() *Transaction {
	newTx := &Transaction{
		Hash:      tx.Hash,
		From:      tx.From,
		To:        tx.To,
		Amount:    new(big.Int).Set(tx.Amount),
		TokenType: tx.TokenType,
		FeeDNT:    new(big.Int).Set(tx.FeeDNT),
		Nonce:     tx.Nonce,
		Timestamp: tx.Timestamp,
		Signature: append([]byte{}, tx.Signature...),
		PublicKey: append([]byte{}, tx.PublicKey...),
	}

	// Copy MultiSig if present
	if tx.MultiSig != nil {
		newTx.MultiSig = &MultiSigData{
			RequiredSignatures: tx.MultiSig.RequiredSignatures,
			TotalParticipants:  tx.MultiSig.TotalParticipants,
			Participants:       append([]string{}, tx.MultiSig.Participants...),
			Signatures:         append([]MultiSigSignature{}, tx.MultiSig.Signatures...),
		}
		if tx.MultiSig.Threshold != nil {
			newTx.MultiSig.Threshold = new(big.Int).Set(tx.MultiSig.Threshold)
		}
	}

	return newTx
}

// FeePerByte calculates the fee per byte for priority sorting
func (tx *Transaction) FeePerByte() float64 {
	size := float64(tx.Size())
	if size == 0 {
		return 0
	}
	feeFloat := new(big.Float).SetInt(tx.FeeDNT)
	feePerByte, _ := feeFloat.Float64()
	return feePerByte / size
}

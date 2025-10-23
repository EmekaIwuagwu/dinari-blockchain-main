package types

import (
	"encoding/json"
	"math/big"
)

// TxStatus represents the status of a transaction
type TxStatus string

const (
	StatusPending TxStatus = "pending"
	StatusSuccess TxStatus = "success"
	StatusFailed  TxStatus = "failed"
)

// Receipt represents the result of a transaction execution
type Receipt struct {
	TxHash      [32]byte `json:"txHash"`
	Status      TxStatus `json:"status"`
	BlockHash   [32]byte `json:"blockHash"`
	BlockNumber uint64   `json:"blockNumber"`
	TxIndex     uint32   `json:"txIndex"`
	FeePaid     *big.Int `json:"feePaid"`
	GasUsed     uint64   `json:"gasUsed"`
	ErrorMsg    string   `json:"errorMsg,omitempty"`
}

// NewReceipt creates a new transaction receipt
func NewReceipt(txHash [32]byte, status TxStatus, blockHash [32]byte, blockNumber uint64, txIndex uint32, feePaid *big.Int) *Receipt {
	return &Receipt{
		TxHash:      txHash,
		Status:      status,
		BlockHash:   blockHash,
		BlockNumber: blockNumber,
		TxIndex:     txIndex,
		FeePaid:     feePaid,
		GasUsed:     0, // For future use
		ErrorMsg:    "",
	}
}

// NewPendingReceipt creates a receipt for a pending transaction
func NewPendingReceipt(txHash [32]byte) *Receipt {
	return &Receipt{
		TxHash:      txHash,
		Status:      StatusPending,
		BlockHash:   [32]byte{},
		BlockNumber: 0,
		TxIndex:     0,
		FeePaid:     big.NewInt(0),
		GasUsed:     0,
	}
}

// NewSuccessReceipt creates a receipt for a successful transaction
func NewSuccessReceipt(txHash [32]byte, blockHash [32]byte, blockNumber uint64, txIndex uint32, feePaid *big.Int) *Receipt {
	return &Receipt{
		TxHash:      txHash,
		Status:      StatusSuccess,
		BlockHash:   blockHash,
		BlockNumber: blockNumber,
		TxIndex:     txIndex,
		FeePaid:     feePaid,
		GasUsed:     0,
	}
}

// NewFailedReceipt creates a receipt for a failed transaction
func NewFailedReceipt(txHash [32]byte, blockHash [32]byte, blockNumber uint64, txIndex uint32, errorMsg string) *Receipt {
	return &Receipt{
		TxHash:      txHash,
		Status:      StatusFailed,
		BlockHash:   blockHash,
		BlockNumber: blockNumber,
		TxIndex:     txIndex,
		FeePaid:     big.NewInt(0),
		GasUsed:     0,
		ErrorMsg:    errorMsg,
	}
}

// Serialize converts the receipt to JSON bytes
func (r *Receipt) Serialize() ([]byte, error) {
	return json.Marshal(r)
}

// DeserializeReceipt reconstructs a receipt from bytes
func DeserializeReceipt(data []byte) (*Receipt, error) {
	var receipt Receipt
	if err := json.Unmarshal(data, &receipt); err != nil {
		return nil, err
	}
	return &receipt, nil
}

// IsSuccess returns true if transaction was successful
func (r *Receipt) IsSuccess() bool {
	return r.Status == StatusSuccess
}

// IsFailed returns true if transaction failed
func (r *Receipt) IsFailed() bool {
	return r.Status == StatusFailed
}

// IsPending returns true if transaction is pending
func (r *Receipt) IsPending() bool {
	return r.Status == StatusPending
}

// String returns a human-readable representation
func (r *Receipt) String() string {
	data, _ := json.MarshalIndent(r, "", "  ")
	return string(data)
}

// pkg/api/converters.go
package api

import (
	"encoding/hex"
	"github.com/EmekaIwuagwu/dinari-blockchain/internal/mempool"
	"github.com/EmekaIwuagwu/dinari-blockchain/internal/types"
)

// convertToMempoolTx converts a types.Transaction to a mempool.Transaction
// and ensures the Size field is set to the correct serialized byte length.
// This prevents transactions with zero size from being added to the mempool.
func convertToMempoolTx(tx *types.Transaction) *mempool.Transaction {
	if tx == nil {
		return nil
	}

	// Calculate the actual transaction size by serializing it
	// This ensures the Size field is always set to a valid non-zero value
	txSize := tx.Size()

	return &mempool.Transaction{
		Hash:      hex.EncodeToString(tx.Hash[:]),
		From:      tx.From,
		To:        tx.To,
		Amount:    tx.Amount,
		TokenType: tx.TokenType,
		FeeDNT:    tx.FeeDNT,
		Nonce:     tx.Nonce,
		Timestamp: tx.Timestamp,
		Signature: tx.Signature,
		PublicKey: tx.PublicKey,
		Size:      txSize, // Set the actual serialized size
	}
}

func formatMempoolTransaction(tx *mempool.Transaction) map[string]interface{} {
	return map[string]interface{}{
		"hash":      "0x" + tx.Hash,
		"from":      tx.From,
		"to":        tx.To,
		"amount":    tx.Amount.String(),
		"tokenType": tx.TokenType,
		"fee":       tx.FeeDNT.String(),
		"nonce":     tx.Nonce,
		"timestamp": tx.Timestamp,
	}
}

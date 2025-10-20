// pkg/api/converters.go
package api

import (
"encoding/hex"
"github.com/EmekaIwuagwu/dinari-blockchain/internal/mempool"
"github.com/EmekaIwuagwu/dinari-blockchain/internal/types"
)

func convertToMempoolTx(tx *types.Transaction) *mempool.Transaction {
	if tx == nil {
		return nil
	}
	
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

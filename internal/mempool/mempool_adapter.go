package mempool

import (
	"github.com/EmekaIwuagwu/dinari-blockchain/internal/types"
)

// MempoolAdapter adapts mempool.Mempool to provide miner interface
type MempoolAdapter struct {
	mempool *Mempool
}

func NewMempoolAdapter(mp *Mempool) *MempoolAdapter {
	return &MempoolAdapter{mempool: mp}
}

func (a *MempoolAdapter) GetPendingTransactions(limit int) []*types.Transaction {
	mempoolTxs := a.mempool.GetPendingTransactions(limit)
	
	// Convert mempool.Transaction to types.Transaction
	result := make([]*types.Transaction, len(mempoolTxs))
	for i, tx := range mempoolTxs {
		// Convert string hash to [32]byte
		var hash [32]byte
		if len(tx.Hash) >= 64 {
			// Hash is hex string, convert first 32 bytes
			for j := 0; j < 32 && j*2 < len(tx.Hash); j++ {
				hash[j] = byte(tx.Hash[j])
			}
		}
		
		result[i] = &types.Transaction{
			Hash:      hash,
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
	
	return result
}

func (a *MempoolAdapter) RemoveTransactions(hashes []string) {
	a.mempool.RemoveTransactions(hashes)
	// Ignore error - miner interface doesn't expect return value
}
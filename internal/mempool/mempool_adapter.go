package mempool

import (
	"github.com/EmekaIwuagwu/dinari-blockchain/internal/miner"
)

// MempoolAdapter adapts mempool.Mempool to miner.MempoolInterface
type MempoolAdapter struct {
	mempool *Mempool
}

func NewMempoolAdapter(mp *Mempool) *MempoolAdapter {
	return &MempoolAdapter{mempool: mp}
}

func (a *MempoolAdapter) GetPendingTransactions(limit int) []*miner.Transaction {
	mempoolTxs := a.mempool.GetPendingTransactions(limit)
	
	// Convert to miner.Transaction
	result := make([]*miner.Transaction, len(mempoolTxs))
	for i, tx := range mempoolTxs {
		result[i] = &miner.Transaction{
			Hash:      []byte(tx.Hash),
			From:      tx.From,
			To:        tx.To,
			Amount:    tx.Amount,
			TokenType: tx.TokenType,
			FeeDNT:    tx.FeeDNT,
			Nonce:     tx.Nonce,
			Timestamp: tx.Timestamp,
			Signature: tx.Signature,
			PublicKey: tx.PublicKey,
			Data:      tx.Data,
		}
	}
	
	return result
}

func (a *MempoolAdapter) RemoveTransactions(hashes []string) error {
	return a.mempool.RemoveTransactions(hashes)
}
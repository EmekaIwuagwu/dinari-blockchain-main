package core

import (
	"github.com/EmekaIwuagwu/dinari-blockchain/internal/miner"
	"github.com/EmekaIwuagwu/dinari-blockchain/internal/types"
)

// BlockchainAdapter adapts core.Blockchain to miner.BlockchainInterface
type BlockchainAdapter struct {
	blockchain *Blockchain
}

func NewBlockchainAdapter(bc *Blockchain) *BlockchainAdapter {
	return &BlockchainAdapter{blockchain: bc}
}

func (a *BlockchainAdapter) GetHeight() uint64 {
	return a.blockchain.GetHeight()
}

func (a *BlockchainAdapter) GetBestHash() []byte {
	return a.blockchain.GetBestHash()
}

func (a *BlockchainAdapter) GetDifficulty() uint32 {
	return a.blockchain.GetDifficulty()
}

func (a *BlockchainAdapter) AddBlock(block *miner.Block) error {
	// Convert miner.Block to core.Block
	coreBlock := &Block{
		Header: &BlockHeader{
			Version:       block.Header.Version,
			Height:        block.Header.Height,
			PrevBlockHash: block.Header.PrevBlockHash,
			MerkleRoot:    block.Header.MerkleRoot,
			Timestamp:     block.Header.Timestamp,
			Difficulty:    block.Header.Difficulty,
			Nonce:         block.Header.Nonce,
			Hash:          block.Header.Hash,
			StateRoot:     block.Header.StateRoot,
		},
		Transactions: convertMinerTxsToTypes(block.Transactions),
	}
	
	return a.blockchain.AddBlock(coreBlock)
}

func (a *BlockchainAdapter) ValidateBlock(block *miner.Block) error {
	coreBlock := &Block{
		Header: &BlockHeader{
			Version:       block.Header.Version,
			Height:        block.Header.Height,
			PrevBlockHash: block.Header.PrevBlockHash,
			MerkleRoot:    block.Header.MerkleRoot,
			Timestamp:     block.Header.Timestamp,
			Difficulty:    block.Header.Difficulty,
			Nonce:         block.Header.Nonce,
			Hash:          block.Header.Hash,
			StateRoot:     block.Header.StateRoot,
		},
		Transactions: convertMinerTxsToTypes(block.Transactions),
	}
	
	return a.blockchain.ValidateBlock(coreBlock)
}

func convertMinerTxsToTypes(minerTxs []*miner.Transaction) []*types.Transaction {
	result := make([]*types.Transaction, len(minerTxs))
	for i, tx := range minerTxs {
		// Convert []byte to [32]byte for Hash
		var hash [32]byte
		copy(hash[:], tx.Hash)
		
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
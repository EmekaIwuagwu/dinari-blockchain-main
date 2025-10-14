// internal/core/consensus_adapter.go
package core

import (
	"github.com/EmekaIwuagwu/dinari-blockchain/internal/types"
)

// ConsensusBlockchainAdapter adapts Blockchain to consensus.BlockchainInterface
type ConsensusBlockchainAdapter struct {
	blockchain *Blockchain
}

func NewConsensusBlockchainAdapter(bc *Blockchain) *ConsensusBlockchainAdapter {
	return &ConsensusBlockchainAdapter{blockchain: bc}
}

func (a *ConsensusBlockchainAdapter) GetBlockByHeight(height uint64) (*types.BlockHeader, error) {
	block, err := a.blockchain.GetBlockByHeight(height)
	if err != nil {
		return nil, err
	}
	return block.Header, nil
}
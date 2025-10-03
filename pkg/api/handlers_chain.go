package api

import (
	"encoding/hex"
	"encoding/json"
	
	"github.com/EmekaIwuagwu/dinari-blockchain/internal/types"
)

// handleChainGetBlock retrieves a block by hash or height
func (s *RPCServer) handleChainGetBlock(params json.RawMessage) (interface{}, *RPCError) {
	var req struct {
		BlockHash   string `json:"blockHash,omitempty"`
		BlockHeight *uint64 `json:"blockHeight,omitempty"`
	}

	if err := json.Unmarshal(params, &req); err != nil {
		return nil, &RPCError{Code: -32602, Message: "invalid params"}
	}

	var block *types.Block
	var err error

	// Get by hash if provided
	if req.BlockHash != "" {
		hashStr := req.BlockHash
		if len(hashStr) > 2 && hashStr[:2] == "0x" {
			hashStr = hashStr[2:]
		}

		hashBytes, err := hex.DecodeString(hashStr)
		if err != nil || len(hashBytes) != 32 {
			return nil, &RPCError{Code: -32602, Message: "invalid block hash"}
		}

		var hash [32]byte
		copy(hash[:], hashBytes)

		block, err = s.blockchain.GetBlockByHash(hash)
	} else if req.BlockHeight != nil {
		// Get by height
		block, err = s.blockchain.GetBlock(*req.BlockHeight)
	} else {
		return nil, &RPCError{Code: -32602, Message: "must provide blockHash or blockHeight"}
	}

	if err != nil {
		return nil, &RPCError{Code: -32004, Message: "block not found"}
	}

	// Calculate confirmations
	currentHeight := s.blockchain.GetHeight()
	confirmations := uint64(0)
	if block.Header.Number <= currentHeight {
		confirmations = currentHeight - block.Header.Number + 1
	}

	// Format transactions
	txs := make([]interface{}, len(block.Transactions))
	for i, tx := range block.Transactions {
		txs[i] = formatTransaction(tx)
	}

	return map[string]interface{}{
		"header": map[string]interface{}{
			"number":       block.Header.Number,
			"parentHash":   "0x" + hex.EncodeToString(block.Header.ParentHash[:]),
			"timestamp":    block.Header.Timestamp,
			"difficulty":   block.Header.Difficulty.String(),
			"nonce":        block.Header.Nonce,
			"merkleRoot":   "0x" + hex.EncodeToString(block.Header.MerkleRoot[:]),
			"stateRoot":    "0x" + hex.EncodeToString(block.Header.StateRoot[:]),
			"miner":        block.Header.MinerAddress,
			"txCount":      block.Header.TxCount,
		},
		"hash":          "0x" + hex.EncodeToString(block.Hash[:]),
		"transactions":  txs,
		"confirmations": confirmations,
	}, nil
}

// handleChainGetHeight returns the current blockchain height
func (s *RPCServer) handleChainGetHeight(params json.RawMessage) (interface{}, *RPCError) {
	height := s.blockchain.GetHeight()
	tip := s.blockchain.GetTip()

	// Get current block
	block, err := s.blockchain.GetBlock(height)
	if err != nil {
		return nil, &RPCError{Code: -32000, Message: "failed to get current block"}
	}

	return map[string]interface{}{
		"height":     height,
		"hash":       "0x" + hex.EncodeToString(tip[:]),
		"difficulty": block.Header.Difficulty.String(),
		"timestamp":  block.Header.Timestamp,
	}, nil
}

// handleChainGetTip returns the current chain tip
func (s *RPCServer) handleChainGetTip(params json.RawMessage) (interface{}, *RPCError) {
	tip := s.blockchain.GetTip()
	height := s.blockchain.GetHeight()

	return map[string]interface{}{
		"hash":   "0x" + hex.EncodeToString(tip[:]),
		"height": height,
	}, nil
}

// handleMempoolStats returns mempool statistics
func (s *RPCServer) handleMempoolStats(params json.RawMessage) (interface{}, *RPCError) {
	stats := s.mempool.Stats()
	return stats, nil
}

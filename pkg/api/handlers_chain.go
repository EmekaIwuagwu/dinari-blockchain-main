package api

import (
	"strconv"
	"fmt"
)

import (
	"encoding/hex"
	"encoding/json"
	
	"github.com/EmekaIwuagwu/dinari-blockchain/internal/types"
	"github.com/EmekaIwuagwu/dinari-blockchain/internal/core"
)

// handleChainGetBlock retrieves a block by hash or height
func (s *Server) handleChainGetBlock(params json.RawMessage) (interface{}, *RPCError) {
	var req struct {
		BlockHash   string `json:"blockHash,omitempty"`
		BlockHeight *uint64 `json:"blockHeight,omitempty"`
	}

	if err := json.Unmarshal(params, &req); err != nil {
		return nil, &RPCError{Code: -32602, Message: "invalid params"}
	}

	var block *core.Block
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

		block, err = s.blockchain.GetBlockByHash(hash[:])
	} else if req.BlockHeight != nil {
		// Get by height
		block, err = s.blockchain.GetBlockByHeight(*req.BlockHeight)
	} else {
		return nil, &RPCError{Code: -32602, Message: "must provide blockHash or blockHeight"}
	}

	if err != nil {
		return nil, &RPCError{Code: -32004, Message: "block not found"}
	}

	// Calculate confirmations
	currentHeight := s.blockchain.GetHeight()
	confirmations := uint64(0)
	if block.Header.Height <= currentHeight {
		confirmations = currentHeight - block.Header.Height + 1
	}

	// Format transactions
	txs := make([]interface{}, len(block.Transactions))
	for i, tx := range block.Transactions {
		txs[i] = formatTransaction(tx)
	}

	return map[string]interface{}{
		"header": map[string]interface{}{
			"number":       block.Header.Height,
			"parentHash":   "0x" + hex.EncodeToString(block.Header.PrevBlockHash[:]),
			"timestamp":    block.Header.Timestamp,
			"difficulty":   block.Header.Difficulty,
			"nonce":        block.Header.Nonce,
			"merkleRoot":   "0x" + hex.EncodeToString(block.Header.MerkleRoot[:]),
			"stateRoot":    "0x" + hex.EncodeToString(block.Header.StateRoot[:]),
			"miner":        "coinbase",
			"txCount":      len(block.Transactions),
		},
		"hash":          "0x" + hex.EncodeToString(block.Header.Hash[:]),
		"transactions":  txs,
		"confirmations": confirmations,
	}, nil
}

// handleChainGetHeight returns the current blockchain height
func (s *Server) handleChainGetHeight(params json.RawMessage) (interface{}, *RPCError) {
	height := s.blockchain.GetHeight()
	tip := s.blockchain.GetHeight()

	// Get current block
	block, err := s.blockchain.GetBlockByHeight(height)
	if err != nil {
		return nil, &RPCError{Code: -32000, Message: "failed to get current block"}
	}

	return map[string]interface{}{
		"height":     height,
		"hash":       "0x" + strconv.FormatUint(tip, 16),
		"difficulty": block.Header.Difficulty,
		"timestamp":  block.Header.Timestamp,
	}, nil
}

// handleChainGetTip returns the current chain tip
func (s *Server) handleChainGetTip(params json.RawMessage) (interface{}, *RPCError) {
	tip := s.blockchain.GetHeight()
	height := s.blockchain.GetHeight()

	return map[string]interface{}{
		"hash":   "0x" + strconv.FormatUint(tip, 16),
		"height": height,
	}, nil
}

// handleMempoolStats returns mempool statistics
func (s *Server) handleMempoolStats(params json.RawMessage) (interface{}, *RPCError) {
	stats := s.mempool.GetStats()
	return stats, nil
}

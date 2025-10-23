package api

import (
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/EmekaIwuagwu/dinari-blockchain/internal/core"
)

// handleChainGetBlock returns a block by height or hash
func (s *Server) handleChainGetBlock(params json.RawMessage) (interface{}, *RPCError) {
	var req struct {
		BlockHeight *uint64 `json:"blockHeight"`
		Height      *uint64 `json:"height"`
		BlockHash   string  `json:"blockHash"`
	}

	if err := json.Unmarshal(params, &req); err != nil {
		return nil, &RPCError{Code: -32602, Message: "invalid params"}
	}

	// Support both "height" and "blockHeight" parameters
	var height *uint64
	if req.BlockHeight != nil {
		height = req.BlockHeight
	} else if req.Height != nil {
		height = req.Height
	}

	// Must provide either height or hash
	if height == nil && req.BlockHash == "" {
		return nil, &RPCError{Code: -32602, Message: "must provide blockHash or blockHeight"}
	}

	var block *core.Block
	var err error

	if req.BlockHash != "" {
		// Get by hash
		hashBytes, decodeErr := hex.DecodeString(strings.TrimPrefix(req.BlockHash, "0x"))
		if decodeErr != nil {
			return nil, &RPCError{Code: -32602, Message: "invalid block hash"}
		}
		block, err = s.blockchain.GetBlockByHash(hashBytes)
	} else {
		// Get by height
		block, err = s.blockchain.GetBlockByHeight(*height)
	}

	if err != nil {
		return nil, &RPCError{Code: -32004, Message: "block not found"}
	}

	if block == nil {
		return nil, &RPCError{Code: -32004, Message: "block not found"}
	}

	// Format the block response
	return formatBlock(block), nil
}

// Helper function to format block data
func formatBlock(block *core.Block) map[string]interface{} {
	// Format transactions
	txs := make([]map[string]interface{}, len(block.Transactions))
	for i, tx := range block.Transactions {
		txs[i] = map[string]interface{}{
			"hash":      "0x" + hex.EncodeToString(tx.Hash[:]),
			"from":      tx.From,
			"to":        tx.To,
			"amount":    tx.Amount.String(),
			"tokenType": tx.TokenType,
			"fee":       tx.FeeDNT.String(),
			"nonce":     tx.Nonce,
			"timestamp": tx.Timestamp,
		}
	}

	// Get miner address - use empty string if not available
	minerAddr := ""
	if len(block.Transactions) > 0 {
		// Typically the first transaction is the coinbase/reward transaction
		minerAddr = block.Transactions[0].To
	}

	return map[string]interface{}{
		"hash":         "0x" + hex.EncodeToString(block.Header.Hash),
		"height":       block.Header.Height,
		"timestamp":    block.Header.Timestamp,
		"difficulty":   block.Header.Difficulty,
		"nonce":        block.Header.Nonce,
		"prevHash":     "0x" + hex.EncodeToString(block.Header.PrevBlockHash),
		"merkleRoot":   "0x" + hex.EncodeToString(block.Header.MerkleRoot),
		"stateRoot":    "0x" + hex.EncodeToString(block.Header.StateRoot),
		"miner":        minerAddr, // FIXED: Use derived miner address
		"transactions": txs,
		"txCount":      len(block.Transactions),
	}
}

// handleChainGetHeight returns the current blockchain height
func (s *Server) handleChainGetHeight(params json.RawMessage) (interface{}, *RPCError) {
	height := s.blockchain.GetHeight()
	return map[string]interface{}{
		"height": height,
	}, nil
}

// handleMempoolStats returns mempool statistics
func (s *Server) handleMempoolStats(params json.RawMessage) (interface{}, *RPCError) {
	stats := s.mempool.GetStats()
	return stats, nil
}

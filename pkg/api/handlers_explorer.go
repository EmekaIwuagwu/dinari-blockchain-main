package api

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
	"strconv"

	"github.com/EmekaIwuagwu/dinari-blockchain/internal/core"
	"github.com/EmekaIwuagwu/dinari-blockchain/internal/types"
)

// handleChainGetBlocks returns multiple blocks in a range
func (s *Server) handleChainGetBlocks(params json.RawMessage) (interface{}, *RPCError) {
	var req struct {
		From  uint64 `json:"from"`
		To    uint64 `json:"to"`
		Limit int    `json:"limit"`
	}

	if err := json.Unmarshal(params, &req); err != nil {
		return nil, &RPCError{Code: -32602, Message: "invalid params"}
	}

	if req.Limit == 0 || req.Limit > 100 {
		req.Limit = 20
	}

	currentHeight := s.blockchain.GetHeight()
	if req.To > currentHeight {
		req.To = currentHeight
	}
	if req.From > req.To {
		req.From = req.To
	}

	count := req.To - req.From + 1
	if count > uint64(req.Limit) {
		count = uint64(req.Limit)
	}

	blocks := make([]interface{}, 0, count)
	for i := uint64(0); i < count; i++ {
		height := req.To - i

		block, err := s.blockchain.GetBlockByHeight(height)
		if err != nil {
			continue
		}

		blocks = append(blocks, map[string]interface{}{
			"number":     block.Header.Height,
			"hash":       "0x" + hex.EncodeToString(block.Header.Hash),
			"parentHash": "0x" + hex.EncodeToString(block.Header.PrevBlockHash),
			"timestamp":  block.Header.Timestamp,
			"difficulty": block.Header.Difficulty,
			"txCount":    len(block.Transactions),
			"size":       calculateBlockSize(block),
		})
	}

	return map[string]interface{}{
		"blocks": blocks,
		"total":  count,
		"from":   req.From,
		"to":     req.To,
	}, nil
}

// handleChainGetStats returns blockchain statistics
func (s *Server) handleChainGetStats(params json.RawMessage) (interface{}, *RPCError) {
	height := s.blockchain.GetHeight()

	latestBlock, err := s.blockchain.GetBlockByHeight(height)
	if err != nil {
		return nil, &RPCError{Code: -32000, Message: "failed to get latest block"}
	}

	totalSupply := new(big.Int).Mul(big.NewInt(int64(height+1)), big.NewInt(5000000000))

	return map[string]interface{}{
		"height":          height,
		"tipHash":         "0x" + strconv.FormatUint(height, 10),
		"difficulty":      latestBlock.Header.Difficulty,
		"totalBlocks":     height + 1,
		"totalSupplyDNT":  totalSupply.String(),
		"avgBlockTime":    15,
		"networkHashRate": "calculating",
		"mempoolSize":     s.mempool.Size(),
		"miningActive":    false,
	}, nil
}

// handleChainSearch searches for blocks, transactions, or addresses
func (s *Server) handleChainSearch(params json.RawMessage) (interface{}, *RPCError) {
	var req struct {
		Query string `json:"query"`
	}

	if err := json.Unmarshal(params, &req); err != nil {
		return nil, &RPCError{Code: -32602, Message: "invalid params"}
	}

	query := req.Query

	// Try as block height
	var blockHeight uint64
	if err := json.Unmarshal([]byte(query), &blockHeight); err == nil {
		block, err := s.blockchain.GetBlockByHeight(blockHeight)
		if err == nil {
			return map[string]interface{}{
				"type": "block",
				"result": map[string]interface{}{
					"number":    block.Header.Height,
					"hash":      "0x" + hex.EncodeToString(block.Header.Hash),
					"timestamp": block.Header.Timestamp,
					"txCount":   len(block.Transactions),
				},
			}, nil
		}
	}

	// Try as block hash
	if len(query) > 2 && query[:2] == "0x" {
		hashStr := query[2:]
		if len(hashStr) == 64 {
			hashBytes, err := hex.DecodeString(hashStr)
			if err == nil && len(hashBytes) == 32 {
				block, err := s.blockchain.GetBlockByHash(hashBytes)
				if err == nil {
					return map[string]interface{}{
						"type": "block",
						"result": map[string]interface{}{
							"number":    block.Header.Height,
							"hash":      "0x" + hex.EncodeToString(block.Header.Hash),
							"timestamp": block.Header.Timestamp,
							"txCount":   len(block.Transactions),
						},
					}, nil
				}
			}
		}

		// Try as transaction hash
		if len(hashStr) >= 16 {
			hashBytes, err := hex.DecodeString(hashStr)
			if err == nil && len(hashBytes) == 32 {
				tx, err := s.mempool.GetTransaction(hex.EncodeToString(hashBytes))
				if err == nil {
					return map[string]interface{}{
						"type":   "transaction",
						"result": formatMempoolTransaction(tx), // Use the mempool formatter
					}, nil
				}
			}
		}
	}

	// Address lookup not available in this configuration
	return nil, &RPCError{Code: -32004, Message: "not found"}
}

// handleChainGetRecentBlocks returns the most recent blocks
func (s *Server) handleChainGetRecentBlocks(params json.RawMessage) (interface{}, *RPCError) {
	var req struct {
		Limit int `json:"limit"`
	}

	if err := json.Unmarshal(params, &req); err != nil {
		req.Limit = 20
	}

	if req.Limit <= 0 || req.Limit > 100 {
		req.Limit = 20
	}

	currentHeight := s.blockchain.GetHeight()
	fromHeight := uint64(0)
	if currentHeight >= uint64(req.Limit-1) {
		fromHeight = currentHeight - uint64(req.Limit-1)
	}

	reqJSON, _ := json.Marshal(map[string]interface{}{
		"from":  fromHeight,
		"to":    currentHeight,
		"limit": req.Limit,
	})

	return s.handleChainGetBlocks(reqJSON)
}

// calculateBlockSize estimates block size
func calculateBlockSize(block *core.Block) int {
	return len(block.Transactions) * 250
}

// formatTransaction formats a transaction for JSON response
func formatTransaction(tx *types.Transaction) map[string]interface{} {
	return map[string]interface{}{
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
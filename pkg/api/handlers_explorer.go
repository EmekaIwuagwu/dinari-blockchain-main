package api

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
)

// handleChainGetBlocks returns multiple blocks in a range
func (s *RPCServer) handleChainGetBlocks(params json.RawMessage) (interface{}, *RPCError) {
	var req struct {
		From  uint64 `json:"from"`
		To    uint64 `json:"to"`
		Limit int    `json:"limit"`
	}

	if err := json.Unmarshal(params, &req); err != nil {
		return nil, &RPCError{Code: -32602, Message: "invalid params"}
	}

	// Default limit
	if req.Limit == 0 || req.Limit > 100 {
		req.Limit = 20
	}

	// Validate range
	currentHeight := s.blockchain.GetHeight()
	if req.To > currentHeight {
		req.To = currentHeight
	}
	if req.From > req.To {
		req.From = req.To
	}

	// Calculate actual range
	count := req.To - req.From + 1
	if count > uint64(req.Limit) {
		count = uint64(req.Limit)
	}

	// Fetch blocks
	blocks := make([]interface{}, 0, count)
	for i := uint64(0); i < count; i++ {
		height := req.To - i // Start from newest

		block, err := s.blockchain.GetBlock(height)
		if err != nil {
			continue
		}

		blocks = append(blocks, map[string]interface{}{
			"number":      block.Header.Number,
			"hash":        "0x" + hex.EncodeToString(block.Hash[:]),
			"parentHash":  "0x" + hex.EncodeToString(block.Header.ParentHash[:]),
			"timestamp":   block.Header.Timestamp,
			"difficulty":  block.Header.Difficulty.String(),
			"miner":       block.Header.MinerAddress,
			"txCount":     block.Header.TxCount,
			"size":        block.Size(),
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
func (s *RPCServer) handleChainGetStats(params json.RawMessage) (interface{}, *RPCError) {
	height := s.blockchain.GetHeight()
	tip := s.blockchain.GetTip()

	// Get latest block for additional info
	latestBlock, err := s.blockchain.GetBlock(height)
	if err != nil {
		return nil, &RPCError{Code: -32000, Message: "failed to get latest block"}
	}

	// Calculate total supply (approximate based on blocks mined)
	// Each block has 50 DNT reward (simplified, not accounting for halving yet)
	totalSupply := new(big.Int).Mul(big.NewInt(int64(height+1)), big.NewInt(5000000000))

	return map[string]interface{}{
		"height":           height,
		"tipHash":          "0x" + hex.EncodeToString(tip[:]),
		"difficulty":       latestBlock.Header.Difficulty.String(),
		"totalBlocks":      height + 1,
		"totalSupplyDNT":   totalSupply.String(),
		"avgBlockTime":     15,
		"networkHashRate":  "N/A",
		"mempoolSize":      s.mempool.Size(),
		"miningActive":     s.miner.IsRunning(),
	}, nil
}

// handleChainSearch searches for blocks, transactions, or addresses
func (s *RPCServer) handleChainSearch(params json.RawMessage) (interface{}, *RPCError) {
	var req struct {
		Query string `json:"query"`
	}

	if err := json.Unmarshal(params, &req); err != nil {
		return nil, &RPCError{Code: -32602, Message: "invalid params"}
	}

	query := req.Query

	// Try as block height (numeric)
	var blockHeight uint64
	if err := json.Unmarshal([]byte(query), &blockHeight); err == nil {
		block, err := s.blockchain.GetBlock(blockHeight)
		if err == nil {
			return map[string]interface{}{
				"type": "block",
				"result": map[string]interface{}{
					"number":     block.Header.Number,
					"hash":       "0x" + hex.EncodeToString(block.Hash[:]),
					"timestamp":  block.Header.Timestamp,
					"txCount":    block.Header.TxCount,
					"miner":      block.Header.MinerAddress,
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
				var blockHash [32]byte
				copy(blockHash[:], hashBytes)

				block, err := s.blockchain.GetBlockByHash(blockHash)
				if err == nil {
					return map[string]interface{}{
						"type": "block",
						"result": map[string]interface{}{
							"number":     block.Header.Number,
							"hash":       "0x" + hex.EncodeToString(block.Hash[:]),
							"timestamp":  block.Header.Timestamp,
							"txCount":    block.Header.TxCount,
							"miner":      block.Header.MinerAddress,
						},
					}, nil
				}
			}
		}

		// Try as transaction hash
		if len(hashStr) >= 16 {
			hashBytes, err := hex.DecodeString(hashStr)
			if err == nil && len(hashBytes) == 32 {
				var txHash [32]byte
				copy(txHash[:], hashBytes)

				if tx, found := s.mempool.GetTransaction(txHash); found {
					return map[string]interface{}{
						"type":   "transaction",
						"result": formatTransaction(tx),
					}, nil
				}
			}
		}
	}

	// Try as address
	account, err := s.blockchain.GetState().GetAccount(query)
	if err == nil && (account.BalanceDNT.Sign() > 0 || account.BalanceAFC.Sign() > 0 || account.Nonce > 0) {
		return map[string]interface{}{
			"type": "address",
			"result": map[string]interface{}{
				"address":    account.Address,
				"balanceDNT": account.BalanceDNT.String(),
				"balanceAFC": account.BalanceAFC.String(),
				"nonce":      account.Nonce,
			},
		}, nil
	}

	return nil, &RPCError{Code: -32004, Message: "not found"}
}

// handleChainGetRecentBlocks returns the most recent blocks
func (s *RPCServer) handleChainGetRecentBlocks(params json.RawMessage) (interface{}, *RPCError) {
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

	return s.handleChainGetBlocks(json.RawMessage(`{"from":` + json.Number(fromHeight).String() + `,"to":` + json.Number(currentHeight).String() + `,"limit":` + json.Number(req.Limit).String() + `}`))
}
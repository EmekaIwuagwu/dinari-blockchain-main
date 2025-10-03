package api

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/EmekaIwuagwu/dinari-blockchain/internal/types"
	"github.com/EmekaIwuagwu/dinari-blockchain/pkg/crypto"
	"go.uber.org/zap"
)

// handleTxSend submits a transaction to the mempool
func (s *RPCServer) handleTxSend(params json.RawMessage) (interface{}, *RPCError) {
	var req struct {
		From      string `json:"from"`
		To        string `json:"to"`
		Amount    string `json:"amount"`
		TokenType string `json:"tokenType"`
		FeeDNT    string `json:"feeDNT"`
		Nonce     uint64 `json:"nonce"`
		Signature string `json:"signature"`
		PublicKey string `json:"publicKey"`
	}

	if err := json.Unmarshal(params, &req); err != nil {
		return nil, &RPCError{Code: -32602, Message: "invalid params"}
	}

	amount, ok := new(big.Int).SetString(req.Amount, 10)
	if !ok {
		return nil, &RPCError{Code: -32602, Message: "invalid amount"}
	}

	fee, ok := new(big.Int).SetString(req.FeeDNT, 10)
	if !ok {
		return nil, &RPCError{Code: -32602, Message: "invalid fee"}
	}

	signature, err := hex.DecodeString(req.Signature)
	if err != nil {
		return nil, &RPCError{Code: -32602, Message: "invalid signature hex"}
	}

	publicKey, err := hex.DecodeString(req.PublicKey)
	if err != nil {
		return nil, &RPCError{Code: -32602, Message: "invalid public key hex"}
	}

	tx := types.NewTransaction(req.From, req.To, amount, req.TokenType, fee, req.Nonce)
	tx.Signature = signature
	tx.PublicKey = publicKey
	tx.Hash = tx.ComputeHash()

	if err := s.mempool.AddTransaction(tx); err != nil {
		return nil, &RPCError{Code: -32003, Message: fmt.Sprintf("transaction rejected: %v", err)}
	}

	s.logger.Info("Transaction added to mempool",
		zap.String("hash", fmt.Sprintf("%x", tx.Hash[:8])),
		zap.String("from", req.From),
		zap.String("to", req.To))

	return map[string]interface{}{
		"txHash": "0x" + hex.EncodeToString(tx.Hash[:]),
	}, nil
}

// handleTxGet retrieves a transaction by hash
func (s *RPCServer) handleTxGet(params json.RawMessage) (interface{}, *RPCError) {
	var req struct {
		TxHash string `json:"txHash"`
	}

	if err := json.Unmarshal(params, &req); err != nil {
		return nil, &RPCError{Code: -32602, Message: "invalid params"}
	}

	hashStr := req.TxHash
	if len(hashStr) > 2 && hashStr[:2] == "0x" {
		hashStr = hashStr[2:]
	}

	hashBytes, err := hex.DecodeString(hashStr)
	if err != nil || len(hashBytes) != 32 {
		return nil, &RPCError{Code: -32602, Message: "invalid transaction hash"}
	}

	var txHash [32]byte
	copy(txHash[:], hashBytes)

	// First check mempool for pending transactions
	if tx, found := s.mempool.GetTransaction(txHash); found {
		return map[string]interface{}{
			"transaction": formatTransaction(tx),
			"receipt": map[string]interface{}{
				"status": "pending",
			},
		}, nil
	}

	// Check blockchain for confirmed transactions
	tx, err := s.blockchain.GetTransaction(txHash)
	if err != nil {
		return nil, &RPCError{Code: -32004, Message: "transaction not found"}
	}

	// Get receipt
	receipt, err := s.blockchain.GetTransactionReceipt(txHash)
	if err != nil {
		// Transaction exists but no receipt
		return map[string]interface{}{
			"transaction": formatTransaction(tx),
			"receipt":     nil,
		}, nil
	}

	return map[string]interface{}{
		"transaction": formatTransaction(tx),
		"receipt":     formatReceipt(receipt),
	}, nil
}

// handleTxListByWallet lists transactions for a wallet address
func (s *RPCServer) handleTxListByWallet(params json.RawMessage) (interface{}, *RPCError) {
	var req struct {
		Address  string `json:"address"`
		Page     int    `json:"page"`
		PageSize int    `json:"pageSize"`
	}

	if err := json.Unmarshal(params, &req); err != nil {
		return nil, &RPCError{Code: -32602, Message: "invalid params"}
	}

	if err := crypto.ValidateAddress(req.Address); err != nil {
		return nil, &RPCError{Code: -32602, Message: "invalid address"}
	}

	if req.PageSize <= 0 {
		req.PageSize = 50
	}
	if req.Page <= 0 {
		req.Page = 1
	}

	// Get ALL transactions for this address from blockchain
	// Note: GetTransactionsByAddress returns up to 'limit' transactions
	// We fetch more than needed to check if there are more pages
	fetchLimit := req.PageSize * req.Page + 1

	allTxs, err := s.blockchain.GetTransactionsByAddress(req.Address, fetchLimit)
	if err != nil {
		s.logger.Error("Failed to get transactions for address",
			zap.String("address", req.Address),
			zap.Error(err))
		return nil, &RPCError{Code: -32005, Message: "failed to retrieve transactions"}
	}

	// Calculate pagination
	totalTxs := len(allTxs)
	startIdx := (req.Page - 1) * req.PageSize
	endIdx := startIdx + req.PageSize

	// Check if we're beyond the available transactions
	if startIdx >= totalTxs {
		return map[string]interface{}{
			"address":      req.Address,
			"total":        totalTxs,
			"page":         req.Page,
			"pageSize":     req.PageSize,
			"transactions": []interface{}{},
			"hasMore":      false,
		}, nil
	}

	// Adjust endIdx if it exceeds total
	if endIdx > totalTxs {
		endIdx = totalTxs
	}

	// Get the page slice
	pageTxs := allTxs[startIdx:endIdx]

	// Format transactions for response
	formattedTxs := make([]interface{}, len(pageTxs))
	for i, tx := range pageTxs {
		formattedTxs[i] = formatTransaction(tx)
	}

	// Determine if there are more pages
	hasMore := endIdx < totalTxs

	s.logger.Info("Retrieved transactions for address",
		zap.String("address", req.Address),
		zap.Int("total", totalTxs),
		zap.Int("page", req.Page),
		zap.Int("returned", len(formattedTxs)))

	return map[string]interface{}{
		"address":      req.Address,
		"total":        totalTxs,
		"page":         req.Page,
		"pageSize":     req.PageSize,
		"transactions": formattedTxs,
		"hasMore":      hasMore,
	}, nil
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

// formatReceipt formats a receipt for JSON response
func formatReceipt(receipt *types.Receipt) map[string]interface{} {
	return map[string]interface{}{
		"status":      receipt.Status,
		"blockHash":   "0x" + hex.EncodeToString(receipt.BlockHash[:]),
		"blockNumber": receipt.BlockNumber,
		"txIndex":     receipt.TxIndex,
		"feePaid":     receipt.FeePaid.String(),
	}
}
package api

import (
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"time"

	"github.com/EmekaIwuagwu/dinari-blockchain/internal/types"
	"github.com/EmekaIwuagwu/dinari-blockchain/pkg/crypto"
)

// handleTxSend sends a new transaction
func (s *Server) handleTxSend(params json.RawMessage) (interface{}, *RPCError) {
	var req struct {
		From       string `json:"from"`
		To         string `json:"to"`
		Amount     string `json:"amount"`
		TokenType  string `json:"tokenType"`
		Fee        string `json:"fee"`
		PrivateKey string `json:"privateKey"`
	}

	if err := json.Unmarshal(params, &req); err != nil {
		return nil, &RPCError{Code: -32602, Message: "invalid params"}
	}

	amount, ok := new(big.Int).SetString(req.Amount, 10)
	if !ok || amount.Cmp(big.NewInt(0)) <= 0 {
		return nil, &RPCError{Code: -32602, Message: "invalid amount"}
	}

	fee, ok := new(big.Int).SetString(req.Fee, 10)
	if !ok {
		return nil, &RPCError{Code: -32602, Message: "invalid fee"}
	}

	privKey, err := crypto.PrivateKeyFromHex(req.PrivateKey)
	if err != nil {
		return nil, &RPCError{Code: -32602, Message: "invalid private key"}
	}

	pubKey := crypto.DerivePublicKey(privKey)
	
	tx := &types.Transaction{
		From:      req.From,
		To:        req.To,
		Amount:    amount,
		TokenType: req.TokenType,
		FeeDNT:    fee,
		Nonce:     0,
		Timestamp: time.Now().Unix(),
		PublicKey: ellipticMarshal(pubKey),
	}

	tx.Hash = tx.ComputeHash()
	signature, err := crypto.SignData(tx.Hash[:], privKey)
	if err != nil {
		return nil, &RPCError{Code: -32000, Message: "failed to sign: " + err.Error()}
	}
	tx.Signature = signature

	if err := s.mempool.AddTransaction(convertToMempoolTx(tx)); err != nil {
		return nil, &RPCError{Code: -32003, Message: "transaction rejected: " + err.Error()}
	}

	return map[string]interface{}{
		"txHash": "0x" + hex.EncodeToString(tx.Hash[:]),
	}, nil
}

// handleTxGet retrieves a transaction by hash
func (s *Server) handleTxGet(params json.RawMessage) (interface{}, *RPCError) {
	var req struct {
		TxHash string `json:"txHash"`
	}

	if err := json.Unmarshal(params, &req); err != nil {
		return nil, &RPCError{Code: -32602, Message: "invalid params"}
	}

	if len(req.TxHash) < 2 || req.TxHash[:2] != "0x" {
		return nil, &RPCError{Code: -32602, Message: "invalid transaction hash format"}
	}

	hashBytes, err := hex.DecodeString(req.TxHash[2:])
	if err != nil || len(hashBytes) != 32 {
		return nil, &RPCError{Code: -32602, Message: "invalid transaction hash"}
	}

	tx, err := s.mempool.GetTransaction(hex.EncodeToString(hashBytes))
	if err != nil {
		return nil, &RPCError{Code: -32004, Message: "transaction not found"}
	}

	return formatMempoolTransaction(tx), nil
}

// handleTxGetPending returns pending transactions
func (s *Server) handleTxGetPending(params json.RawMessage) (interface{}, *RPCError) {
	var req struct {
		Limit int `json:"limit"`
	}

	if err := json.Unmarshal(params, &req); err != nil {
		req.Limit = 20
	}

	if req.Limit <= 0 || req.Limit > 100 {
		req.Limit = 20
	}

	allTxs := s.mempool.GetAllTransactions()
	
	limit := req.Limit
	if len(allTxs) < limit {
		limit = len(allTxs)
	}

	txs := make([]interface{}, limit)
	for i := 0; i < limit; i++ {
		txs[i] = formatMempoolTransaction(allTxs[i])
	}

	return map[string]interface{}{
		"transactions": txs,
		"total":        len(allTxs),
		"returned":     limit,
	}, nil
}

// handleTxGetByAddress returns transactions for an address
func (s *Server) handleTxGetByAddress(params json.RawMessage) (interface{}, *RPCError) {
	var req struct {
		Address string `json:"address"`
		Limit   int    `json:"limit"`
	}

	if err := json.Unmarshal(params, &req); err != nil {
		return nil, &RPCError{Code: -32602, Message: "invalid params"}
	}

	if req.Limit <= 0 || req.Limit > 100 {
		req.Limit = 20
	}

	txs := s.mempool.GetTransactionsByAddress(req.Address)
	
	limit := req.Limit
	if len(txs) < limit {
		limit = len(txs)
	}

	result := make([]interface{}, limit)
	for i := 0; i < limit; i++ {
		result[i] = formatMempoolTransaction(txs[i])
	}

	return map[string]interface{}{
		"transactions": result,
		"total":        len(txs),
		"returned":     limit,
	}, nil
}

// handleTxGetStats returns mempool statistics
func (s *Server) handleTxGetStats(params json.RawMessage) (interface{}, *RPCError) {
	stats := s.mempool.GetStats()
	return stats, nil
}

// ellipticMarshal marshals a public key to uncompressed format
func ellipticMarshal(pub *ecdsa.PublicKey) []byte {
	byteLen := (pub.Curve.Params().BitSize + 7) / 8
	ret := make([]byte, 1+2*byteLen)
	ret[0] = 4
	pub.X.FillBytes(ret[1 : 1+byteLen])
	pub.Y.FillBytes(ret[1+byteLen : 1+2*byteLen])
	return ret
}
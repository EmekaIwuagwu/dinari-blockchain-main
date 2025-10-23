package api

import (
	"encoding/json"
	"github.com/EmekaIwuagwu/dinari-blockchain/pkg/crypto"
	"go.uber.org/zap"
)

// handleWalletCreate creates a new wallet
func (s *Server) handleWalletCreate(params json.RawMessage) (interface{}, *RPCError) {
	// Generate private key
	privKey, err := crypto.GeneratePrivateKey()
	if err != nil {
		return nil, &RPCError{Code: -32000, Message: "failed to generate key"}
	}

	// Derive public key
	pubKey := crypto.DerivePublicKey(privKey)

	// Generate address
	address := crypto.PublicKeyToAddress(pubKey)

	// Convert to WIF
	wif, err := crypto.PrivateKeyToWIF(privKey)
	if err != nil {
		return nil, &RPCError{Code: -32000, Message: "failed to convert to WIF"}
	}

	return map[string]interface{}{
		"address":       address,
		"privateKeyHex": crypto.PrivateKeyToHex(privKey),
		"privateKeyWIF": wif,
		"publicKeyHex":  crypto.PublicKeyToHex(pubKey),
	}, nil
}

// handleWalletBalance returns the balance for an address
// handleWalletBalance returns the balance for an address
func (s *Server) handleWalletBalance(params json.RawMessage) (interface{}, *RPCError) {
	var req struct {
		Address string `json:"address"`
	}

	if err := json.Unmarshal(params, &req); err != nil {
		return nil, &RPCError{Code: -32602, Message: "invalid params"}
	}

	// Validate D-prefix address
	if err := crypto.ValidateAddress(req.Address); err != nil {
		s.logger.Warn("❌ Invalid D-address in balance request",
			zap.String("address", req.Address),
			zap.Error(err))
		return nil, &RPCError{Code: -32602, Message: "invalid D-address format"}
	}

	// Get account - handle case where account doesn't exist yet
	account, err := s.blockchain.State.GetAccount(req.Address)
	if err != nil {
		// If account doesn't exist, return zero balance instead of error
		s.logger.Info("📭 Account not found, returning zero balance",
			zap.String("address", req.Address))

		return map[string]interface{}{
			"address":    req.Address,
			"balanceDNT": "0",
			"balanceAFC": "0",
			"nonce":      0,
		}, nil
	}

	// Log balance query
	s.logger.Info("💰 Balance queried",
		zap.String("address", req.Address),
		zap.String("balanceDNT", account.BalanceDNT.String()),
		zap.String("balanceAFC", account.BalanceAFC.String()),
		zap.Uint64("nonce", account.Nonce))

	return map[string]interface{}{
		"address":    account.Address,
		"balanceDNT": account.BalanceDNT.String(),
		"balanceAFC": account.BalanceAFC.String(),
		"nonce":      account.Nonce,
	}, nil
}

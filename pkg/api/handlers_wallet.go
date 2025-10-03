package api

import (
	"encoding/json"

	"github.com/EmekaIwuagwu/dinari-blockchain/pkg/crypto"
)

// handleWalletCreate creates a new wallet
func (s *RPCServer) handleWalletCreate(params json.RawMessage) (interface{}, *RPCError) {
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
		"address":        address,
		"privateKeyHex":  crypto.PrivateKeyToHex(privKey),
		"privateKeyWIF":  wif,
		"publicKeyHex":   crypto.PublicKeyToHex(pubKey),
	}, nil
}

// handleWalletBalance returns the balance for an address
func (s *RPCServer) handleWalletBalance(params json.RawMessage) (interface{}, *RPCError) {
	var req struct {
		Address string `json:"address"`
	}

	if err := json.Unmarshal(params, &req); err != nil {
		return nil, &RPCError{Code: -32602, Message: "invalid params"}
	}

	// Validate address
	if err := crypto.ValidateAddress(req.Address); err != nil {
		return nil, &RPCError{Code: -32602, Message: "invalid address"}
	}

	// Get account
	account, err := s.blockchain.GetState().GetAccount(req.Address)
	if err != nil {
		return nil, &RPCError{Code: -32000, Message: "failed to get account"}
	}

	return map[string]interface{}{
		"address":    account.Address,
		"balanceDNT": account.BalanceDNT.String(),
		"balanceAFC": account.BalanceAFC.String(),
		"nonce":      account.Nonce,
	}, nil
}

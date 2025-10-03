package api

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
	"time"

	"github.com/EmekaIwuagwu/dinari-blockchain/internal/types"
	"github.com/EmekaIwuagwu/dinari-blockchain/pkg/crypto"
	"go.uber.org/zap"
)

func (s *RPCServer) handleMintAFC(params json.RawMessage) (interface{}, *RPCError) {
	var req struct {
		To         string `json:"to"`
		Amount     string `json:"amount"`
		PrivateKey string `json:"privateKey"`
	}

	if err := json.Unmarshal(params, &req); err != nil {
		return nil, &RPCError{Code: -32602, Message: "invalid params"}
	}

	amount, ok := new(big.Int).SetString(req.Amount, 10)
	if !ok || amount.Cmp(big.NewInt(0)) <= 0 {
		return nil, &RPCError{Code: -32602, Message: "invalid amount"}
	}

	privKey, err := crypto.PrivateKeyFromHex(req.PrivateKey)
	if err != nil {
		return nil, &RPCError{Code: -32602, Message: "invalid private key"}
	}

	pubKey := crypto.DerivePublicKey(privKey)
	minterAddr := crypto.PublicKeyToAddress(pubKey)

	if !s.blockchain.IsAuthorizedMinter(minterAddr) {
		s.logger.Warn("Unauthorized mint attempt", 
			zap.String("minter", minterAddr),
			zap.String("to", req.To))
		return nil, &RPCError{Code: -32003, Message: "unauthorized: address not in mint authority list"}
	}

	tx := &types.Transaction{
		From:      "mint",
		To:        req.To,
		Amount:    amount,
		TokenType: string(types.TokenAFC),
		FeeDNT:    big.NewInt(0),
		Nonce:     0,
		Timestamp: time.Now().Unix(),
		PublicKey: pubKey.SerializeCompressed(),
	}

	tx.Hash = tx.ComputeHash()

	signature, err := crypto.SignData(tx.Hash[:], privKey)
	if err != nil {
		return nil, &RPCError{Code: -32000, Message: "failed to sign: " + err.Error()}
	}
	tx.Signature = signature

	if err := s.mempool.AddTransaction(tx); err != nil {
		s.logger.Error("Failed to add mint transaction",
			zap.Error(err),
			zap.String("to", req.To))
		return nil, &RPCError{Code: -32003, Message: "transaction rejected: " + err.Error()}
	}

	s.logger.Info("AFC minted",
		zap.String("hash", hex.EncodeToString(tx.Hash[:8])),
		zap.String("minter", minterAddr),
		zap.String("to", req.To),
		zap.String("amount", amount.String()))

	return map[string]interface{}{
		"txHash":  "0x" + hex.EncodeToString(tx.Hash[:]),
		"to":      req.To,
		"amount":  amount.String(),
		"success": true,
	}, nil
}
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

// handleMintAFC handles AFC token minting
func (s *Server) handleMintAFC(params json.RawMessage) (interface{}, *RPCError) {
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

	// Authorization check - in production, implement proper authorization
	authorizedMinters := map[string]bool{
		// Add authorized minter addresses here
	}

	if !authorizedMinters[minterAddr] && len(authorizedMinters) > 0 {
		return nil, &RPCError{
			Code:    -32003,
			Message: "unauthorized: address not in mint authority list",
		}
	}

	// Convert to ECDSA types
	ecdsaPrivKey := privKey.ToECDSA()
	ecdsaPubKey := &ecdsaPrivKey.PublicKey

	tx := &types.Transaction{
		From:      "mint",
		To:        req.To,
		Amount:    amount,
		TokenType: string(types.TokenAFC),
		FeeDNT:    big.NewInt(0),
		Nonce:     0,
		Timestamp: time.Now().Unix(),
		PublicKey: ellipticMarshal(ecdsaPubKey),
	}

	tx.Hash = tx.ComputeHash()

	txHashBytes := tx.Hash[:]
	signature, err := crypto.SignData(txHashBytes, ecdsaPrivKey)
	if err != nil {
		return nil, &RPCError{Code: -32000, Message: "failed to sign: " + err.Error()}
	}
	tx.Signature = signature

	if err := s.mempool.AddTransaction(convertToMempoolTx(tx)); err != nil {
		return nil, &RPCError{Code: -32003, Message: "transaction rejected: " + err.Error()}
	}

	return map[string]interface{}{
		"txHash":  "0x" + hex.EncodeToString(tx.Hash[:]),
		"to":      req.To,
		"amount":  amount.String(),
		"minter":  minterAddr,
		"success": true,
	}, nil
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
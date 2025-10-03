package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	"github.com/EmekaIwuagwu/dinari-blockchain/internal/types"
	"github.com/EmekaIwuagwu/dinari-blockchain/pkg/crypto"
)

func buildAndSignTransaction(fromAddr, toAddr string, amount *big.Int, tokenType string, fee *big.Int, nonce uint64, privKeyHex string) (map[string]interface{}, error) {
	// Parse private key
	privKey, err := crypto.PrivateKeyFromHex(privKeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid private key: %w", err)
	}

	// Create transaction
	tx := types.NewTransaction(fromAddr, toAddr, amount, tokenType, fee, nonce)
	tx.Timestamp = time.Now().Unix()

	// Get public key
	pubKey := crypto.DerivePublicKey(privKey)
	tx.PublicKey = pubKey.SerializeCompressed()

	// Sign transaction
	txData := tx.SerializeForSigning()
	signature, err := crypto.SignCompact(txData, privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign transaction: %w", err)
	}

	tx.Signature = signature
	tx.Hash = tx.ComputeHash()

	// Build RPC params
	params := map[string]interface{}{
		"from":      tx.From,
		"to":        tx.To,
		"amount":    tx.Amount.String(),
		"tokenType": tx.TokenType,
		"feeDNT":    tx.FeeDNT.String(),
		"nonce":     tx.Nonce,
		"signature": hex.EncodeToString(tx.Signature),
		"publicKey": hex.EncodeToString(tx.PublicKey),
	}

	return params, nil
}

func getNonce(client *RPCClient, address string) (uint64, error) {
	params := map[string]string{"address": address}
	result, err := client.Call("wallet_balance", params)
	if err != nil {
		return 0, err
	}

	var balance struct {
		Nonce uint64 `json:"nonce"`
	}

	if err := json.Unmarshal(result, &balance); err != nil {
		return 0, err
	}

	return balance.Nonce, nil
}
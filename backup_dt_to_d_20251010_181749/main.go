package main

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"

	"github.com/EmekaIwuagwu/dinari-blockchain/pkg/crypto"
)

const defaultNodeURL = "http://localhost:8545"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "create":
		handleCreate()
	case "import":
		handleImport()
	case "balance":
		handleBalance()
	case "send":
		handleSend()
	case "mint":
		handleMint()
	default:
		fmt.Printf("Unknown command: %s\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("DinariBlockchain Wallet CLI")
	fmt.Println("\nUsage:")
	fmt.Println("  dinari-wallet create                                      - Create a new wallet")
	fmt.Println("  dinari-wallet import <private-key>                        - Import wallet from private key (hex)")
	fmt.Println("  dinari-wallet balance <address>                           - Check wallet balance")
	fmt.Println("  dinari-wallet send <priv-key> <to> <amount> <type> <fee> - Send tokens")
	fmt.Println("\nExamples:")
	fmt.Println("  dinari-wallet create")
	fmt.Println("  dinari-wallet balance DFSVTrx1N3SSeF1KKXRUyWCZRvmaAzxzoU")
	fmt.Println("  dinari-wallet send f1b07e32... D8GpLCt4... 100000000 DNT 1000")
}

func handleCreate() {
	privKey, err := crypto.GeneratePrivateKey()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	pubKey := crypto.DerivePublicKey(privKey)
	address := crypto.PublicKeyToAddress(pubKey)

	wif, err := crypto.PrivateKeyToWIF(privKey)
	if err != nil {
		fmt.Printf("Error creating WIF: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("=== New Wallet Created ===")
	fmt.Printf("Address:     %s\n", address)
	fmt.Printf("Private Key: %s\n", crypto.PrivateKeyToHex(privKey))
	fmt.Printf("WIF:         %s\n", wif)
	fmt.Printf("Public Key:  %s\n", crypto.PublicKeyToHex(pubKey))
	fmt.Println("\nIMPORTANT: Save your private key securely!")
	fmt.Println("Never share your private key with anyone.")
}


func handleSend() {
	if len(os.Args) < 7 {
		fmt.Println("Usage: dinari-wallet send <private-key> <to-address> <amount> <token-type> <fee>")
		fmt.Println("\nExample:")
		fmt.Println("  dinari-wallet send f1b07e32f1f1bdaf... D8GpLCt4DyvT... 100000000 DNT 1000")
		fmt.Println("\nNote:")
		fmt.Println("  - Amount and fee are in satoshis (1 DNT = 100,000,000 satoshis)")
		fmt.Println("  - Token type: DNT or AFC")
		os.Exit(1)
	}

	privKeyHex := os.Args[2]
	toAddr := os.Args[3]
	amountStr := os.Args[4]
	tokenType := os.Args[5]
	feeStr := os.Args[6]

	// Parse amounts
	amount, ok := new(big.Int).SetString(amountStr, 10)
	if !ok {
		fmt.Println("Error: Invalid amount")
		os.Exit(1)
	}

	fee, ok := new(big.Int).SetString(feeStr, 10)
	if !ok {
		fmt.Println("Error: Invalid fee")
		os.Exit(1)
	}

	// Derive from address
	privKey, err := crypto.PrivateKeyFromHex(privKeyHex)
	if err != nil {
		fmt.Printf("Error: Invalid private key: %v\n", err)
		os.Exit(1)
	}

	pubKey := crypto.DerivePublicKey(privKey)
	fromAddr := crypto.PublicKeyToAddress(pubKey)

	// Create RPC client
	client := NewRPCClient(defaultNodeURL)

	// Get current nonce
	nonce, err := getNonce(client, fromAddr)
	if err != nil {
		fmt.Printf("Error getting nonce: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Building transaction...")
	fmt.Printf("From:   %s\n", fromAddr)
	fmt.Printf("To:     %s\n", toAddr)
	fmt.Printf("Amount: %s %s\n", amount.String(), tokenType)
	fmt.Printf("Fee:    %s DNT\n", fee.String())
	fmt.Printf("Nonce:  %d\n", nonce)

	// Build and sign transaction
	params, err := buildAndSignTransaction(fromAddr, toAddr, amount, tokenType, fee, nonce, privKeyHex)
	if err != nil {
		fmt.Printf("Error building transaction: %v\n", err)
		os.Exit(1)
	}

	// Submit transaction
	fmt.Println("\nSubmitting transaction...")
	result, err := client.Call("tx_send", params)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	var response struct {
		TxHash string `json:"txHash"`
	}

	if err := json.Unmarshal(result, &response); err != nil {
		fmt.Printf("Error parsing response: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("\n=== Transaction Sent Successfully ===")
	fmt.Printf("Transaction Hash: %s\n", response.TxHash)
	fmt.Println("\nNote: Transaction is now in mempool. It will be mined in the next block.")
}


func handleImport() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: dinari-wallet import <private-key-hex>")
		os.Exit(1)
	}

	privKeyHex := os.Args[2]
	privKey, err := crypto.PrivateKeyFromHex(privKeyHex)
	if err != nil {
		fmt.Printf("Error: Invalid private key: %v\n", err)
		os.Exit(1)
	}

	pubKey := crypto.DerivePublicKey(privKey)
	address := crypto.PublicKeyToAddress(pubKey)

	fmt.Println("=== Wallet Imported ===")
	fmt.Printf("Address:     %s\n", address)
	fmt.Printf("Public Key:  %s\n", crypto.PublicKeyToHex(pubKey))
}

func handleBalance() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: dinari-wallet balance <address>")
		os.Exit(1)
	}

	address := os.Args[2]
	client := NewRPCClient(defaultNodeURL)

	params := map[string]string{"address": address}
	result, err := client.Call("wallet_balance", params)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	var balance struct {
		Address    string `json:"address"`
		BalanceDNT string `json:"balanceDNT"`
		BalanceAFC string `json:"balanceAFC"`
		Nonce      uint64 `json:"nonce"`
	}

	if err := json.Unmarshal(result, &balance); err != nil {
		fmt.Printf("Error parsing response: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("=== Wallet Balance ===")
	fmt.Printf("Address:     %s\n", balance.Address)
	fmt.Printf("DNT Balance: %s satoshis\n", balance.BalanceDNT)
	fmt.Printf("AFC Balance: %s satoshis\n", balance.BalanceAFC)
	fmt.Printf("Nonce:       %d\n", balance.Nonce)
}

func handleMint() {
    if len(os.Args) < 5 {
        fmt.Println("Usage: dinari-wallet mint <private-key> <to-address> <amount>")
        fmt.Println("\nExample:")
        fmt.Println("  dinari-wallet mint abc123... DT1address... 1000000000")
        fmt.Println("\nNote:")
        fmt.Println("  - Amount is in satoshis (1 AFC = 100,000,000 satoshis)")
        fmt.Println("  - Only authorized mint authorities can mint AFC")
        os.Exit(1)
    }

    privKeyHex := os.Args[2]
    toAddr := os.Args[3]
    amountStr := os.Args[4]

    // Parse amount
    amount, ok := new(big.Int).SetString(amountStr, 10)
    if !ok {
        fmt.Println("Error: Invalid amount")
        os.Exit(1)
    }

    // Derive minter address
    privKey, err := crypto.PrivateKeyFromHex(privKeyHex)
    if err != nil {
        fmt.Printf("Error: Invalid private key: %v\n", err)
        os.Exit(1)
    }

    pubKey := crypto.DerivePublicKey(privKey)
    minterAddr := crypto.PublicKeyToAddress(pubKey)

    fmt.Println("Minting AFC tokens...")
    fmt.Printf("Minter: %s\n", minterAddr)
    fmt.Printf("To:     %s\n", toAddr)
    fmt.Printf("Amount: %s AFC\n", amount.String())

    // Create RPC client
    client := NewRPCClient(defaultNodeURL)

    // Build mint request
    params := map[string]string{
        "to":         toAddr,
        "amount":     amountStr,
        "privateKey": privKeyHex,
    }

    // Submit mint request
    fmt.Println("\nSubmitting mint request...")
    result, err := client.Call("afc_mint", params)
    if err != nil {
        fmt.Printf("Error: %v\n", err)
        os.Exit(1)
    }

    var response struct {
        TxHash  string `json:"txHash"`
        To      string `json:"to"`
        Amount  string `json:"amount"`
        Success bool   `json:"success"`
    }

    if err := json.Unmarshal(result, &response); err != nil {
        fmt.Printf("Error parsing response: %v\n", err)
        os.Exit(1)
    }

    fmt.Println("\n=== AFC Minted Successfully ===")
    fmt.Printf("Transaction Hash: %s\n", response.TxHash)
    fmt.Printf("Recipient:        %s\n", response.To)
    fmt.Printf("Amount:           %s satoshis\n", response.Amount)
    fmt.Println("\nNote: Transaction is now in mempool. It will be mined in the next block.")
}


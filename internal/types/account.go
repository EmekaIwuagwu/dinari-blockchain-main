package types

import (
	"encoding/json"
	"math/big"
)

// Account represents the state of a blockchain account
type Account struct {
	Address    string   `json:"address"`
	Nonce      uint64   `json:"nonce"`
	BalanceDNT *big.Int `json:"balanceDNT"`
	BalanceAFC *big.Int `json:"balanceAFC"`
}

// NewAccount creates a new account with zero balances
func NewAccount(address string) *Account {
	return &Account{
		Address:    address,
		Nonce:      0,
		BalanceDNT: big.NewInt(0),
		BalanceAFC: big.NewInt(0),
	}
}

// Serialize converts the account to JSON bytes
func (a *Account) Serialize() ([]byte, error) {
	return json.Marshal(a)
}

// DeserializeAccount reconstructs an account from bytes
func DeserializeAccount(data []byte) (*Account, error) {
	var account Account
	if err := json.Unmarshal(data, &account); err != nil {
		return nil, err
	}
	return &account, nil
}

// Copy creates a deep copy of the account
func (a *Account) Copy() *Account {
	return &Account{
		Address:    a.Address,
		Nonce:      a.Nonce,
		BalanceDNT: new(big.Int).Set(a.BalanceDNT),
		BalanceAFC: new(big.Int).Set(a.BalanceAFC),
	}
}

// AddBalance adds amount to the specified token balance
func (a *Account) AddBalance(tokenType string, amount *big.Int) {
	if tokenType == string(TokenDNT) {
		a.BalanceDNT = new(big.Int).Add(a.BalanceDNT, amount)
	} else if tokenType == string(TokenAFC) {
		a.BalanceAFC = new(big.Int).Add(a.BalanceAFC, amount)
	}
}

// SubBalance subtracts amount from the specified token balance
func (a *Account) SubBalance(tokenType string, amount *big.Int) error {
	var balance *big.Int

	if tokenType == string(TokenDNT) {
		balance = a.BalanceDNT
	} else if tokenType == string(TokenAFC) {
		balance = a.BalanceAFC
	} else {
		return ErrInvalidTokenType
	}

	// Check sufficient balance
	if balance.Cmp(amount) < 0 {
		return ErrInsufficientBalance
	}

	// Subtract
	if tokenType == string(TokenDNT) {
		a.BalanceDNT = new(big.Int).Sub(a.BalanceDNT, amount)
	} else {
		a.BalanceAFC = new(big.Int).Sub(a.BalanceAFC, amount)
	}

	return nil
}

// GetBalance returns the balance for the specified token type
func (a *Account) GetBalance(tokenType string) *big.Int {
	if tokenType == string(TokenDNT) {
		return new(big.Int).Set(a.BalanceDNT)
	} else if tokenType == string(TokenAFC) {
		return new(big.Int).Set(a.BalanceAFC)
	}
	return big.NewInt(0)
}

// HasSufficientBalance checks if account has enough balance
func (a *Account) HasSufficientBalance(tokenType string, amount *big.Int) bool {
	balance := a.GetBalance(tokenType)
	return balance.Cmp(amount) >= 0
}

// IncrementNonce increases the account nonce by 1
func (a *Account) IncrementNonce() {
	a.Nonce++
}

// String returns a human-readable representation
func (a *Account) String() string {
	data, _ := json.MarshalIndent(a, "", "  ")
	return string(data)
}

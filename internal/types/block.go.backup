package types

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"math/big"
	"time"
)

// BlockHeader contains the metadata of a block
type BlockHeader struct {
	Number       uint64   `json:"number"`
	ParentHash   [32]byte `json:"parentHash"`
	Timestamp    int64    `json:"timestamp"`
	Difficulty   *big.Int `json:"difficulty"`
	Nonce        uint64   `json:"nonce"`
	MerkleRoot   [32]byte `json:"merkleRoot"`
	StateRoot    [32]byte `json:"stateRoot"`
	MinerAddress string   `json:"miner"`
	TxCount      uint32   `json:"txCount"`
}

// Block represents a complete block in the blockchain
type Block struct {
	Header       *BlockHeader   `json:"header"`
	Transactions []*Transaction `json:"transactions"`
	Hash         [32]byte       `json:"hash"`
}

// NewBlock creates a new block with the given parameters
func NewBlock(parentHash [32]byte, number uint64, transactions []*Transaction, miner string, difficulty *big.Int) *Block {
	header := &BlockHeader{
		Number:       number,
		ParentHash:   parentHash,
		Timestamp:    time.Now().Unix(),
		Difficulty:   difficulty,
		Nonce:        0,
		MerkleRoot:   CalculateMerkleRoot(transactions),
		StateRoot:    [32]byte{}, // Will be set after state changes
		MinerAddress: miner,
		TxCount:      uint32(len(transactions)),
	}

	block := &Block{
		Header:       header,
		Transactions: transactions,
	}

	block.Hash = block.ComputeHash()
	return block
}

// NewGenesisBlock creates the genesis (first) block
func NewGenesisBlock() *Block {
	header := &BlockHeader{
		Number:       0,
		ParentHash:   [32]byte{},
		Timestamp:    time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC).Unix(),
		Difficulty:   big.NewInt(0x1000), // Initial difficulty
		Nonce:        0,
		MerkleRoot:   [32]byte{},
		StateRoot:    [32]byte{},
		MinerAddress: "genesis",
		TxCount:      0,
	}

	block := &Block{
		Header:       header,
		Transactions: []*Transaction{},
	}

	block.Hash = block.ComputeHash()
	return block
}

// ComputeHash calculates the block hash using SHA-256d (double SHA-256)
func (b *Block) ComputeHash() [32]byte {
	data := b.SerializeHeader()
	first := sha256.Sum256(data)
	second := sha256.Sum256(first[:])
	return second
}

// SerializeHeader serializes the block header for hashing
func (b *Block) SerializeHeader() []byte {
	var buf bytes.Buffer

	// Number (8 bytes)
	binary.Write(&buf, binary.BigEndian, b.Header.Number)

	// ParentHash (32 bytes)
	buf.Write(b.Header.ParentHash[:])

	// Timestamp (8 bytes)
	binary.Write(&buf, binary.BigEndian, b.Header.Timestamp)

	// Difficulty (variable length, but use fixed 32 bytes)
	diffBytes := b.Header.Difficulty.Bytes()
	diffPadded := make([]byte, 32)
	copy(diffPadded[32-len(diffBytes):], diffBytes)
	buf.Write(diffPadded)

	// Nonce (8 bytes)
	binary.Write(&buf, binary.BigEndian, b.Header.Nonce)

	// MerkleRoot (32 bytes)
	buf.Write(b.Header.MerkleRoot[:])

	// StateRoot (32 bytes)
	buf.Write(b.Header.StateRoot[:])

	// MinerAddress (hash it to fixed size)
	minerHash := sha256.Sum256([]byte(b.Header.MinerAddress))
	buf.Write(minerHash[:])

	// TxCount (4 bytes)
	binary.Write(&buf, binary.BigEndian, b.Header.TxCount)

	return buf.Bytes()
}

// Serialize converts the entire block to bytes (including transactions)
func (b *Block) Serialize() ([]byte, error) {
	return json.Marshal(b)
}

// Deserialize reconstructs a block from bytes
func DeserializeBlock(data []byte) (*Block, error) {
	var block Block
	if err := json.Unmarshal(data, &block); err != nil {
		return nil, err
	}
	return &block, nil
}

// CalculateMerkleRoot computes the merkle root of transactions
func CalculateMerkleRoot(transactions []*Transaction) [32]byte {
	if len(transactions) == 0 {
		return [32]byte{}
	}

	// Collect transaction hashes
	hashes := make([][32]byte, len(transactions))
	for i, tx := range transactions {
		hashes[i] = tx.Hash
	}

	// Build merkle tree bottom-up
	for len(hashes) > 1 {
		var newLevel [][32]byte

		// Process pairs
		for i := 0; i < len(hashes); i += 2 {
			if i+1 < len(hashes) {
				// Hash pair
				combined := append(hashes[i][:], hashes[i+1][:]...)
				newLevel = append(newLevel, sha256.Sum256(combined))
			} else {
				// Odd one out, hash with itself
				combined := append(hashes[i][:], hashes[i][:]...)
				newLevel = append(newLevel, sha256.Sum256(combined))
			}
		}

		hashes = newLevel
	}

	return hashes[0]
}

// IsGenesis returns true if this is the genesis block
func (b *Block) IsGenesis() bool {
	return b.Header.Number == 0
}

// Size returns the approximate size of the block in bytes
func (b *Block) Size() int {
	data, _ := b.Serialize()
	return len(data)
}

// Validate performs basic validation on the block structure
func (b *Block) Validate() error {
	// Check timestamp is reasonable (not too far in future)
	maxFutureTime := time.Now().Unix() + 7200 // 2 hours tolerance
	if b.Header.Timestamp > maxFutureTime {
		return ErrInvalidTimestamp
	}

	// Check transaction count matches
	if b.Header.TxCount != uint32(len(b.Transactions)) {
		return ErrInvalidTxCount
	}

	// Verify merkle root
	calculatedRoot := CalculateMerkleRoot(b.Transactions)
	if calculatedRoot != b.Header.MerkleRoot {
		return ErrInvalidMerkleRoot
	}

	// Verify block hash
	calculatedHash := b.ComputeHash()
	if calculatedHash != b.Hash {
		return ErrInvalidBlockHash
	}

	return nil
}

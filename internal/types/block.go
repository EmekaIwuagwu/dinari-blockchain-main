package types

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"time"
)

// BlockHeader contains the metadata of a block
type BlockHeader struct {
	Version       uint32 `json:"version"`
	Height        uint64 `json:"height"`
	PrevBlockHash []byte `json:"prevBlockHash"`
	MerkleRoot    []byte `json:"merkleRoot"`
	Timestamp     int64  `json:"timestamp"`
	Difficulty    uint32 `json:"difficulty"`
	Nonce         uint64 `json:"nonce"`
	Hash          []byte `json:"hash"`
	StateRoot     []byte `json:"stateRoot"`
}

// Block represents a complete block in the blockchain
type Block struct {
	Header       *BlockHeader   `json:"header"`
	Transactions []*Transaction `json:"transactions"`
}

// NewBlock creates a new block with the given parameters
func NewBlock(prevHash []byte, height uint64, transactions []*Transaction, difficulty uint32) *Block {
	header := &BlockHeader{
		Version:       1,
		Height:        height,
		PrevBlockHash: prevHash,
		Timestamp:     time.Now().Unix(),
		Difficulty:    difficulty,
		Nonce:         0,
		MerkleRoot:    CalculateMerkleRoot(transactions),
		StateRoot:     []byte{},
	}

	block := &Block{
		Header:       header,
		Transactions: transactions,
	}

	block.Header.Hash = ComputeBlockHash(header)
	return block
}

// NewGenesisBlock creates the genesis (first) block
func NewGenesisBlock() *Block {
	header := &BlockHeader{
		Version:       1,
		Height:        0,
		PrevBlockHash: []byte{},
		Timestamp:     time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC).Unix(),
		Difficulty:    1000, // Initial difficulty
		Nonce:         0,
		MerkleRoot:    []byte{},
		StateRoot:     []byte{},
	}

	block := &Block{
		Header:       header,
		Transactions: []*Transaction{},
	}

	block.Header.Hash = ComputeBlockHash(header)
	return block
}

// ComputeBlockHash calculates the block hash using double SHA-256
func ComputeBlockHash(header *BlockHeader) []byte {
	var buf bytes.Buffer

	binary.Write(&buf, binary.BigEndian, header.Version)
	binary.Write(&buf, binary.BigEndian, header.Height)
	buf.Write(header.PrevBlockHash)
	buf.Write(header.MerkleRoot)
	binary.Write(&buf, binary.BigEndian, header.Timestamp)
	binary.Write(&buf, binary.BigEndian, header.Difficulty)
	binary.Write(&buf, binary.BigEndian, header.Nonce)

	first := sha256.Sum256(buf.Bytes())
	second := sha256.Sum256(first[:])

	return second[:]
}

// SerializeHeader serializes the block header for hashing
func (b *Block) SerializeHeader() []byte {
	var buf bytes.Buffer

	binary.Write(&buf, binary.BigEndian, b.Header.Version)
	binary.Write(&buf, binary.BigEndian, b.Header.Height)
	buf.Write(b.Header.PrevBlockHash)
	buf.Write(b.Header.MerkleRoot)
	binary.Write(&buf, binary.BigEndian, b.Header.Timestamp)
	binary.Write(&buf, binary.BigEndian, b.Header.Difficulty)
	binary.Write(&buf, binary.BigEndian, b.Header.Nonce)

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
func CalculateMerkleRoot(transactions []*Transaction) []byte {
	if len(transactions) == 0 {
		return make([]byte, 32)
	}

	// Collect transaction hashes
	hashes := make([][]byte, len(transactions))
	for i, tx := range transactions {
		hashes[i] = tx.Hash[:]
	}

	// Build merkle tree bottom-up
	for len(hashes) > 1 {
		if len(hashes)%2 != 0 {
			hashes = append(hashes, hashes[len(hashes)-1])
		}

		var newLevel [][]byte
		for i := 0; i < len(hashes); i += 2 {
			combined := append(hashes[i], hashes[i+1]...)
			hash := sha256.Sum256(combined)
			newLevel = append(newLevel, hash[:])
		}

		hashes = newLevel
	}

	return hashes[0]
}

// IsGenesis returns true if this is the genesis block
func (b *Block) IsGenesis() bool {
	return b.Header.Height == 0
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

	// Verify merkle root
	calculatedRoot := CalculateMerkleRoot(b.Transactions)
	if !bytes.Equal(calculatedRoot, b.Header.MerkleRoot) {
		return ErrInvalidMerkleRoot
	}

	// Verify block hash
	calculatedHash := ComputeBlockHash(b.Header)
	if !bytes.Equal(calculatedHash, b.Header.Hash) {
		return ErrInvalidBlockHash
	}

	return nil
}

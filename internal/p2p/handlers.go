package p2p

import (
	"encoding/json"
	"fmt"

	"github.com/EmekaIwuagwu/dinari-blockchain/internal/types"
	"go.uber.org/zap"
)

// Message types
type MessageType string

const (
	MsgTypeNewBlock MessageType = "new_block"
	MsgTypeNewTx    MessageType = "new_tx"
)

// Message represents a P2P message
type Message struct {
	Type MessageType     `json:"type"`
	Data json.RawMessage `json:"data"`
}

// NewBlockMessage represents a new block announcement
type NewBlockMessage struct {
	Block *types.Block `json:"block"`
}

// NewTxMessage represents a new transaction announcement
type NewTxMessage struct {
	Tx *types.Transaction `json:"tx"`
}

// handleBlockMessages handles incoming block messages
func (n *Node) handleBlockMessages() {
	for {
		msg, err := n.blockSub.Next(n.ctx)
		if err != nil {
			n.logger.Error("Error reading block message", zap.Error(err))
			return
		}

		if msg.ReceivedFrom == n.host.ID() {
			continue
		}

		var blockMsg NewBlockMessage
		if err := json.Unmarshal(msg.Data, &blockMsg); err != nil {
			n.logger.Warn("Failed to unmarshal block message", zap.Error(err))
			continue
		}

		if err := n.handleNewBlock(blockMsg.Block); err != nil {
			n.logger.Warn("Failed to handle new block",
				zap.Uint64("height", blockMsg.Block.Header.Number),
				zap.Error(err))
		}
	}
}

// handleTxMessages handles incoming transaction messages
func (n *Node) handleTxMessages() {
	for {
		msg, err := n.txSub.Next(n.ctx)
		if err != nil {
			n.logger.Error("Error reading tx message", zap.Error(err))
			return
		}

		if msg.ReceivedFrom == n.host.ID() {
			continue
		}

		var txMsg NewTxMessage
		if err := json.Unmarshal(msg.Data, &txMsg); err != nil {
			n.logger.Warn("Failed to unmarshal tx message", zap.Error(err))
			continue
		}

		if err := n.handleNewTx(txMsg.Tx); err != nil {
			n.logger.Debug("Failed to handle new transaction",
				zap.String("hash", fmt.Sprintf("%x", txMsg.Tx.Hash[:8])),
				zap.Error(err))
		}
	}
}

// handleNewBlock processes a newly received block
func (n *Node) handleNewBlock(block *types.Block) error {
	n.logger.Info("Received new block",
		zap.Uint64("height", block.Header.Number),
		zap.String("hash", fmt.Sprintf("%x", block.Hash[:8])))

	if err := n.blockchain.ValidateBlock(block); err != nil {
		return err
	}

	if err := n.blockchain.AddBlock(block); err != nil {
		return err
	}

	n.logger.Info("Block added to chain", zap.Uint64("height", block.Header.Number))
	return nil
}

// handleNewTx processes a newly received transaction
func (n *Node) handleNewTx(tx *types.Transaction) error {
	if err := n.mempool.AddTransaction(tx); err != nil {
		return err
	}

	n.logger.Debug("Transaction added to mempool",
		zap.String("hash", fmt.Sprintf("%x", tx.Hash[:8])))

	return nil
}

// BroadcastBlock broadcasts a block to the network
func (n *Node) BroadcastBlock(block *types.Block) error {
	msg := NewBlockMessage{Block: block}
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	if err := n.blockTopic.Publish(n.ctx, data); err != nil {
		return err
	}

	n.logger.Debug("Block broadcast", zap.Uint64("height", block.Header.Number))
	return nil
}

// BroadcastTransaction broadcasts a transaction to the network
func (n *Node) BroadcastTransaction(tx *types.Transaction) error {
	msg := NewTxMessage{Tx: tx}
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	if err := n.txTopic.Publish(n.ctx, data); err != nil {
		return err
	}

	n.logger.Debug("Transaction broadcast",
		zap.String("hash", fmt.Sprintf("%x", tx.Hash[:8])))

	return nil
}
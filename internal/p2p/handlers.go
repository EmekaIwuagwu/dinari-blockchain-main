// internal/p2p/handlers.go
package p2p

import (
	"encoding/json"
	"fmt"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
)

// MessageType represents the type of P2P message
type MessageType int

const (
	MsgTypeBlock MessageType = iota
	MsgTypeTransaction
	MsgTypePeerDiscovery
	MsgTypeSync
)

// Message represents a P2P network message
type Message struct {
	Type      MessageType     `json:"type"`
	Data      []byte          `json:"data"`
	Sender    string          `json:"sender"`
	Timestamp int64           `json:"timestamp"`
}

// handleBlockMessages processes incoming block messages
func (n *Node) handleBlockMessages(s network.Stream) error {
	defer s.Close()

	buf := make([]byte, 1024*1024)
	bytesRead, err := s.Read(buf)
	if err != nil {
		return fmt.Errorf("error reading block message: %w", err)
	}

	var msg Message
	if err := json.Unmarshal(buf[:bytesRead], &msg); err != nil {
		return fmt.Errorf("error unmarshaling block message: %w", err)
	}

	if msg.Type != MsgTypeBlock {
		return fmt.Errorf("invalid message type: expected block")
	}

	if n.blockHandler != nil {
		if err := n.blockHandler.HandleBlock(msg.Data); err != nil {
			return fmt.Errorf("error handling block: %w", err)
		}
	}

	return nil
}

// handleTxMessages processes incoming transaction messages
func (n *Node) handleTxMessages(s network.Stream) error {
	defer s.Close()

	buf := make([]byte, 1024*1024)
	bytesRead, err := s.Read(buf)
	if err != nil {
		return fmt.Errorf("error reading transaction message: %w", err)
	}

	var msg Message
	if err := json.Unmarshal(buf[:bytesRead], &msg); err != nil {
		return fmt.Errorf("error unmarshaling transaction message: %w", err)
	}

	if msg.Type != MsgTypeTransaction {
		return fmt.Errorf("invalid message type: expected transaction")
	}

	if n.txHandler != nil {
		if err := n.txHandler.HandleTransaction(msg.Data); err != nil {
			return fmt.Errorf("error handling transaction: %w", err)
		}
	}

	return nil
}

// BroadcastBlock broadcasts a block to all connected peers
func (n *Node) BroadcastBlock(blockData []byte) error {
	msg := Message{
		Type:      MsgTypeBlock,
		Data:      blockData,
		Sender:    n.Host.ID().String(),
		Timestamp: getCurrentTimestamp(),
	}

	return n.broadcastMessage(msg)
}

// BroadcastTransaction broadcasts a transaction to all connected peers
func (n *Node) BroadcastTransaction(txData []byte) error {
	msg := Message{
		Type:      MsgTypeTransaction,
		Data:      txData,
		Sender:    n.Host.ID().String(),
		Timestamp: getCurrentTimestamp(),
	}

	return n.broadcastMessage(msg)
}

// broadcastMessage sends a message to all connected peers
func (n *Node) broadcastMessage(msg Message) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	peers := n.GetPeers()
	for _, peerID := range peers {
		go func(pid peer.ID) {
			stream, err := n.Host.NewStream(n.ctx, pid, protocol.ID(ProtocolID))
			if err != nil {
				fmt.Printf("Failed to open stream to peer %s: %v\n", pid, err)
				return
			}
			defer stream.Close()

			if _, err := stream.Write(data); err != nil {
				fmt.Printf("Failed to write to stream for peer %s: %v\n", pid, err)
			}
		}(peerID)
	}

	return nil
}

// getCurrentTimestamp returns the current Unix timestamp
func getCurrentTimestamp() int64 {
	return 0 // TODO: Implement proper timestamp
}
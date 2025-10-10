// internal/p2p/node.go
package p2p

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/multiformats/go-multiaddr"
)

const (
	ProtocolID = "/dinari/1.0.0"
	DHTPrefix  = "/dinari/kad/1.0.0"
)

type Node struct {
	Host         host.Host
	DHT          *dht.IpfsDHT // Changed from dht.IKadDHT to dht.IpfsDHT
	ctx          context.Context
	cancel       context.CancelFunc
	peers        map[peer.ID]*PeerInfo
	peersMu      sync.RWMutex
	blockHandler BlockHandler
	txHandler    TxHandler
}

type PeerInfo struct {
	ID          peer.ID
	Addrs       []multiaddr.Multiaddr
	Connected   bool
	LastSeen    time.Time
	Reputation  int
	mu          sync.RWMutex
}

type BlockHandler interface {
	HandleBlock(data []byte) error
}

type TxHandler interface {
	HandleTransaction(data []byte) error
}

func NewNode(ctx context.Context, port int, privateKey crypto.PrivKey) (*Node, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	
	ctx, cancel := context.WithCancel(ctx)

	listen, err := multiaddr.NewMultiaddr(fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", port))
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create multiaddr: %w", err)
	}

	opts := []libp2p.Option{
		libp2p.ListenAddrs(listen),
		libp2p.Identity(privateKey),
		libp2p.DefaultTransports,
		libp2p.DefaultMuxers,
		libp2p.DefaultSecurity,
	}

	h, err := libp2p.New(opts...)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create libp2p host: %w", err)
	}

	// Initialize DHT
	kadDHT, err := dht.New(ctx, h, dht.Mode(dht.ModeServer))
	if err != nil {
		h.Close()
		cancel()
		return nil, fmt.Errorf("failed to create DHT: %w", err)
	}

	if err = kadDHT.Bootstrap(ctx); err != nil {
		h.Close()
		cancel()
		return nil, fmt.Errorf("failed to bootstrap DHT: %w", err)
	}

	node := &Node{
		Host:   h,
		DHT:    kadDHT,
		ctx:    ctx,
		cancel: cancel,
		peers:  make(map[peer.ID]*PeerInfo),
	}

	h.SetStreamHandler(protocol.ID(ProtocolID), node.handleStream)

	return node, nil
}

func (n *Node) handleStream(s network.Stream) {
	defer s.Close()

	buf := make([]byte, 1024*1024) // 1MB buffer
	bytesRead, err := s.Read(buf)
	if err != nil {
		fmt.Printf("Error reading from stream: %v\n", err)
		return
	}

	var msg Message
	if err := json.Unmarshal(buf[:bytesRead], &msg); err != nil {
		fmt.Printf("Error unmarshaling message: %v\n", err)
		return
	}

	switch msg.Type {
	case MsgTypeBlock:
		if n.blockHandler != nil {
			if err := n.blockHandler.HandleBlock(msg.Data); err != nil {
				fmt.Printf("Error handling block: %v\n", err)
			}
		}
	case MsgTypeTransaction:
		if n.txHandler != nil {
			if err := n.txHandler.HandleTransaction(msg.Data); err != nil {
				fmt.Printf("Error handling transaction: %v\n", err)
			}
		}
	}
}

func (n *Node) SetBlockHandler(handler BlockHandler) {
	n.blockHandler = handler
}

func (n *Node) SetTxHandler(handler TxHandler) {
	n.txHandler = handler
}

func (n *Node) Connect(peerAddr string) error {
	maddr, err := multiaddr.NewMultiaddr(peerAddr)
	if err != nil {
		return fmt.Errorf("invalid multiaddr: %w", err)
	}

	peerInfo, err := peer.AddrInfoFromP2pAddr(maddr)
	if err != nil {
		return fmt.Errorf("failed to get peer info: %w", err)
	}

	if err := n.Host.Connect(n.ctx, *peerInfo); err != nil {
		return fmt.Errorf("failed to connect to peer: %w", err)
	}

	n.peersMu.Lock()
	n.peers[peerInfo.ID] = &PeerInfo{
		ID:         peerInfo.ID,
		Addrs:      peerInfo.Addrs,
		Connected:  true,
		LastSeen:   time.Now(),
		Reputation: 100,
	}
	n.peersMu.Unlock()

	return nil
}

func (n *Node) GetPeers() []peer.ID {
	n.peersMu.RLock()
	defer n.peersMu.RUnlock()

	peers := make([]peer.ID, 0, len(n.peers))
	for id := range n.peers {
		peers = append(peers, id)
	}
	return peers
}

func (n *Node) Close() error {
	n.cancel()
	if n.DHT != nil {
		if err := n.DHT.Close(); err != nil {
			return err
		}
	}
	return n.Host.Close()
}

func (n *Node) ID() peer.ID {
	return n.Host.ID()
}

func (n *Node) Addrs() []multiaddr.Multiaddr {
	return n.Host.Addrs()
}

// Message broadcasting methods are in handlers.go - don't duplicate them here
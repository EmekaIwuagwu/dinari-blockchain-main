package p2p

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/p2p/discovery/mdns"
	"go.uber.org/zap"

	"github.com/EmekaIwuagwu/dinari-blockchain/internal/core"
	"github.com/EmekaIwuagwu/dinari-blockchain/internal/mempool"
)

const (
	// Protocol topics
	TopicBlocks = "/dinari/blocks/1.0.0"
	TopicTxs    = "/dinari/txs/1.0.0"

	// Discovery service tag
	DiscoveryServiceTag = "dinari-blockchain"
)

// Node represents a P2P network node
type Node struct {
	host       host.Host
	pubsub     *pubsub.PubSub
	blockchain *core.Blockchain
	mempool    *mempool.Mempool
	logger     *zap.Logger

	// Topics
	blockTopic *pubsub.Topic
	txTopic    *pubsub.Topic

	// Subscriptions
	blockSub *pubsub.Subscription
	txSub    *pubsub.Subscription

	// Peer management
	peers map[peer.ID]bool
	mu    sync.RWMutex

	ctx    context.Context
	cancel context.CancelFunc
}

// Config contains P2P node configuration
type Config struct {
	ListenAddr string
	Blockchain *core.Blockchain
	Mempool    *mempool.Mempool
	Logger     *zap.Logger
	BootNodes  []string
}

// NewNode creates a new P2P node
func NewNode(config *Config) (*Node, error) {
	ctx, cancel := context.WithCancel(context.Background())

	// Create libp2p host
	h, err := libp2p.New(
		libp2p.ListenAddrStrings(config.ListenAddr),
		libp2p.DefaultTransports,
		libp2p.DefaultMuxers,
		libp2p.DefaultSecurity,
	)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create libp2p host: %w", err)
	}

	// Create pubsub
	ps, err := pubsub.NewGossipSub(ctx, h)
	if err != nil {
		h.Close()
		cancel()
		return nil, fmt.Errorf("failed to create pubsub: %w", err)
	}

	node := &Node{
		host:       h,
		pubsub:     ps,
		blockchain: config.Blockchain,
		mempool:    config.Mempool,
		logger:     config.Logger,
		peers:      make(map[peer.ID]bool),
		ctx:        ctx,
		cancel:     cancel,
	}

	// Join topics
	if err := node.joinTopics(); err != nil {
		node.Stop()
		return nil, err
	}

	// Setup mDNS discovery
	if err := node.setupDiscovery(); err != nil {
		node.logger.Warn("Failed to setup discovery", zap.Error(err))
	}

	// Connect to boot nodes
	if len(config.BootNodes) > 0 {
		go node.connectToBootNodes(config.BootNodes)
	}

	// Start message handlers
	go node.handleBlockMessages()
	go node.handleTxMessages()

	node.logger.Info("P2P node started",
		zap.String("id", h.ID().String()),
		zap.Strings("addresses", getHostAddresses(h)))

	return node, nil
}

// Stop stops the P2P node
func (n *Node) Stop() error {
	n.cancel()

	if n.blockSub != nil {
		n.blockSub.Cancel()
	}
	if n.txSub != nil {
		n.txSub.Cancel()
	}

	if n.host != nil {
		return n.host.Close()
	}

	n.logger.Info("P2P node stopped")
	return nil
}

// joinTopics joins the pubsub topics
func (n *Node) joinTopics() error {
	var err error

	// Join block topic
	n.blockTopic, err = n.pubsub.Join(TopicBlocks)
	if err != nil {
		return fmt.Errorf("failed to join block topic: %w", err)
	}

	n.blockSub, err = n.blockTopic.Subscribe()
	if err != nil {
		return fmt.Errorf("failed to subscribe to block topic: %w", err)
	}

	// Join transaction topic
	n.txTopic, err = n.pubsub.Join(TopicTxs)
	if err != nil {
		return fmt.Errorf("failed to join tx topic: %w", err)
	}

	n.txSub, err = n.txTopic.Subscribe()
	if err != nil {
		return fmt.Errorf("failed to subscribe to tx topic: %w", err)
	}

	return nil
}

// setupDiscovery sets up mDNS peer discovery
func (n *Node) setupDiscovery() error {
	discoveryHandler := &discoveryNotifee{node: n}
	service := mdns.NewMdnsService(n.host, DiscoveryServiceTag, discoveryHandler)
	return service.Start()
}

// connectToBootNodes connects to bootstrap nodes
func (n *Node) connectToBootNodes(bootNodes []string) {
	for _, addrStr := range bootNodes {
		addr, err := peer.AddrInfoFromString(addrStr)
		if err != nil {
			n.logger.Error("Invalid boot node address", zap.String("addr", addrStr), zap.Error(err))
			continue
		}

		if err := n.host.Connect(n.ctx, *addr); err != nil {
			n.logger.Warn("Failed to connect to boot node",
				zap.String("peer", addr.ID.String()),
				zap.Error(err))
		} else {
			n.logger.Info("Connected to boot node", zap.String("peer", addr.ID.String()))
			n.addPeer(addr.ID)
		}
	}
}

// addPeer adds a peer to the peer list
func (n *Node) addPeer(peerID peer.ID) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.peers[peerID] = true
}

// removePeer removes a peer from the peer list
func (n *Node) removePeer(peerID peer.ID) {
	n.mu.Lock()
	defer n.mu.Unlock()
	delete(n.peers, peerID)
}

// GetPeerCount returns the number of connected peers
func (n *Node) GetPeerCount() int {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return len(n.peers)
}

// GetPeers returns the list of connected peers
func (n *Node) GetPeers() []peer.ID {
	n.mu.RLock()
	defer n.mu.RUnlock()

	peers := make([]peer.ID, 0, len(n.peers))
	for p := range n.peers {
		peers = append(peers, p)
	}
	return peers
}

// discoveryNotifee handles peer discovery events
type discoveryNotifee struct {
	node *Node
}

func (n *discoveryNotifee) HandlePeerFound(peerInfo peer.AddrInfo) {
	// Don't connect to ourselves
	if peerInfo.ID == n.node.host.ID() {
		return
	}

	n.node.logger.Debug("Discovered peer", zap.String("peer", peerInfo.ID.String()))

	// Connect to the peer
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := n.node.host.Connect(ctx, peerInfo); err != nil {
		n.node.logger.Debug("Failed to connect to discovered peer",
			zap.String("peer", peerInfo.ID.String()),
			zap.Error(err))
		return
	}

	n.node.logger.Info("Connected to peer", zap.String("peer", peerInfo.ID.String()))
	n.node.addPeer(peerInfo.ID)
}

// getHostAddresses returns the multiaddresses of the host
func getHostAddresses(h host.Host) []string {
	addrs := h.Addrs()
	addrStrs := make([]string, len(addrs))
	for i, addr := range addrs {
		addrStrs[i] = fmt.Sprintf("%s/p2p/%s", addr.String(), h.ID().String())
	}
	return addrStrs
}

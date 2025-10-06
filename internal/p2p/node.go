package p2p

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/multiformats/go-multiaddr"
)

const (
	// Protocol version
	ProtocolVersion = "/dinari/1.0.0"
	ProtocolID      = protocol.ID(ProtocolVersion)
	
	// Connection limits
	MaxPeers           = 50
	MaxInboundPeers    = 30
	MaxOutboundPeers   = 20
	MinPeers           = 5
	TargetPeers        = 20
	
	// Peer diversity (eclipse attack prevention)
	MinDiverseSubnets  = 5  // Require peers from at least 5 different /24 subnets
	MaxPeersPerSubnet  = 10 // Max peers from same /24 subnet
	
	// Reputation system
	InitialPeerScore      = 50
	MaxPeerScore          = 100
	MinPeerScore          = -100
	BanThreshold          = -50
	DisconnectThreshold   = 0
	
	// Score adjustments
	ScoreBlockReceived    = 5
	ScoreTxReceived       = 1
	ScoreInvalidBlock     = -20
	ScoreInvalidTx        = -5
	ScoreTimeout          = -10
	ScoreProtocolViolation = -30
	
	// Timeouts and intervals
	PeerDiscoveryInterval  = 30 * time.Second
	PeerCleanupInterval    = 60 * time.Second
	HandshakeTimeout       = 10 * time.Second
	MessageTimeout         = 30 * time.Second
	PingInterval           = 60 * time.Second
	BanDuration            = 24 * time.Hour
	
	// Message rate limits
	MaxBlocksPerMinute = 10
	MaxTxsPerMinute    = 1000
	MaxMessagesPerMinute = 100
	
	// Network topics
	TopicBlocks       = "dinari-blocks"
	TopicTransactions = "dinari-transactions"
	TopicPeerInfo     = "dinari-peers"
)

var (
	ErrPeerBanned        = errors.New("peer is banned")
	ErrMaxPeersReached   = errors.New("maximum peers reached")
	ErrInvalidProtocol   = errors.New("invalid protocol version")
	ErrHandshakeFailed   = errors.New("handshake failed")
	ErrMessageRateLimit  = errors.New("message rate limit exceeded")
	ErrInvalidMessage    = errors.New("invalid message")
)

// Node represents a P2P node
type Node struct {
	// libp2p host
	host   host.Host
	dht    *dht.IKadDHT
	pubsub *pubsub.PubSub
	
	// Configuration
	config *NodeConfig
	
	// Peer management
	peers      map[peer.ID]*PeerInfo
	peersMu    sync.RWMutex
	
	// Banned peers
	banned     map[peer.ID]*BanInfo
	bannedMu   sync.RWMutex
	
	// Subnet tracking (eclipse attack prevention)
	subnets    map[string][]peer.ID // subnet -> peer IDs
	subnetsMu  sync.RWMutex
	
	// Message handlers
	handlers   map[MessageType]MessageHandler
	handlersMu sync.RWMutex
	
	// PubSub subscriptions
	blockSub *pubsub.Subscription
	txSub    *pubsub.Subscription
	
	// Statistics
	stats   *NetworkStats
	statsMu sync.RWMutex
	
	// Lifecycle
	ctx        context.Context
	cancel     context.CancelFunc
	running    bool
	runningMu  sync.RWMutex
}

// NodeConfig contains node configuration
type NodeConfig struct {
	ListenAddrs     []multiaddr.Multiaddr
	BootstrapPeers  []peer.AddrInfo
	ProtocolVersion string
	NetworkID       string // "mainnet" or "testnet"
	EnableDHT       bool
	EnablePubSub    bool
	MaxPeers        int
	MinPeers        int
}

// PeerInfo tracks information about a peer
type PeerInfo struct {
	ID              peer.ID
	Addrs           []multiaddr.Multiaddr
	ProtocolVersion string
	UserAgent       string
	Score           int32
	ConnectionTime  time.Time
	LastSeen        time.Time
	Direction       network.Direction
	
	// Message rate tracking
	blockCount      int
	txCount         int
	messageCount    int
	lastRateReset   time.Time
	
	// Statistics
	BlocksReceived  uint64
	BlocksSent      uint64
	TxsReceived     uint64
	TxsSent         uint64
	BytesReceived   uint64
	BytesSent       uint64
	Latency         time.Duration
}

// BanInfo tracks banned peer information
type BanInfo struct {
	Reason     string
	BannedAt   time.Time
	ExpiresAt  time.Time
	Violations int
}

// NetworkStats tracks network statistics
type NetworkStats struct {
	ConnectedPeers     int
	InboundPeers       int
	OutboundPeers      int
	TotalBlocksReceived uint64
	TotalBlocksSent     uint64
	TotalTxsReceived    uint64
	TotalTxsSent        uint64
	TotalBytesReceived  uint64
	TotalBytesSent      uint64
	BannedPeersCount    int
}

// MessageType represents different message types
type MessageType uint8

const (
	MsgTypeBlock MessageType = iota
	MsgTypeTransaction
	MsgTypeGetBlocks
	MsgTypeGetBlockHeaders
	MsgTypePing
	MsgTypePong
)

// MessageHandler is a function that handles incoming messages
type MessageHandler func(peerID peer.ID, msg []byte) error

// NewNode creates a new P2P node
func NewNode(config *NodeConfig) (*Node, error) {
	if err := validateNodeConfig(config); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	// Generate node key
	priv, _, err := generateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}
	
	// Create libp2p host
	h, err := libp2p.New(
		libp2p.Identity(priv),
		libp2p.ListenAddrs(config.ListenAddrs...),
		libp2p.DefaultTransports,
		libp2p.DefaultMuxers,
		libp2p.DefaultSecurity,
		libp2p.NATPortMap(),
		libp2p.EnableNATService(),
	)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create host: %w", err)
	}
	
	node := &Node{
		host:     h,
		config:   config,
		ctx:      ctx,
		cancel:   cancel,
		peers:    make(map[peer.ID]*PeerInfo),
		banned:   make(map[peer.ID]*BanInfo),
		subnets:  make(map[string][]peer.ID),
		handlers: make(map[MessageType]MessageHandler),
		stats:    &NetworkStats{},
	}
	
	// Initialize DHT if enabled
	if config.EnableDHT {
		if err := node.initDHT(); err != nil {
			h.Close()
			cancel()
			return nil, fmt.Errorf("failed to init DHT: %w", err)
		}
	}
	
	// Initialize PubSub if enabled
	if config.EnablePubSub {
		if err := node.initPubSub(); err != nil {
			h.Close()
			cancel()
			return nil, fmt.Errorf("failed to init pubsub: %w", err)
		}
	}
	
	// Set stream handler
	h.SetStreamHandler(ProtocolID, node.handleStream)
	
	// Set connection handlers
	h.Network().Notify(&network.NotifyBundle{
		ConnectedF:    node.handleConnected,
		DisconnectedF: node.handleDisconnected,
	})
	
	return node, nil
}

// Start starts the P2P node
func (n *Node) Start() error {
	n.runningMu.Lock()
	if n.running {
		n.runningMu.Unlock()
		return errors.New("node already running")
	}
	n.running = true
	n.runningMu.Unlock()
	
	fmt.Printf("🌐 Starting P2P node\n")
	fmt.Printf("   Peer ID: %s\n", n.host.ID().String())
	fmt.Printf("   Addresses:\n")
	for _, addr := range n.host.Addrs() {
		fmt.Printf("      %s/p2p/%s\n", addr, n.host.ID())
	}
	
	// Bootstrap DHT
	if n.config.EnableDHT && n.dht != nil {
		if err := n.dht.Bootstrap(n.ctx); err != nil {
			return fmt.Errorf("failed to bootstrap DHT: %w", err)
		}
	}
	
	// Connect to bootstrap peers
	if err := n.connectToBootstrapPeers(); err != nil {
		fmt.Printf("Warning: failed to connect to some bootstrap peers: %v\n", err)
	}
	
	// Start background tasks
	go n.peerDiscoveryLoop()
	go n.peerCleanupLoop()
	go n.pingLoop()
	
	// Subscribe to topics if pubsub enabled
	if n.config.EnablePubSub {
		if err := n.subscribeToTopics(); err != nil {
			return fmt.Errorf("failed to subscribe to topics: %w", err)
		}
	}
	
	fmt.Println("✅ P2P node started")
	
	return nil
}

// Stop stops the P2P node
func (n *Node) Stop() error {
	n.runningMu.Lock()
	if !n.running {
		n.runningMu.Unlock()
		return errors.New("node not running")
	}
	n.running = false
	n.runningMu.Unlock()
	
	fmt.Println("🛑 Stopping P2P node...")
	
	// Cancel context
	n.cancel()
	
	// Close DHT
	if n.dht != nil {
		n.dht.Close()
	}
	
	// Close host
	if err := n.host.Close(); err != nil {
		return fmt.Errorf("failed to close host: %w", err)
	}
	
	fmt.Println("✅ P2P node stopped")
	
	return nil
}

// ConnectToPeer connects to a specific peer
func (n *Node) ConnectToPeer(peerInfo peer.AddrInfo) error {
	// Check if banned
	if n.isPeerBanned(peerInfo.ID) {
		return ErrPeerBanned
	}
	
	// Check peer limit
	if n.getPeerCount() >= n.config.MaxPeers {
		return ErrMaxPeersReached
	}
	
	// Check if already connected
	if n.host.Network().Connectedness(peerInfo.ID) == network.Connected {
		return nil // Already connected
	}
	
	// Connect with timeout
	ctx, cancel := context.WithTimeout(n.ctx, HandshakeTimeout)
	defer cancel()
	
	if err := n.host.Connect(ctx, peerInfo); err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}
	
	// Perform handshake
	if err := n.performHandshake(peerInfo.ID); err != nil {
		n.host.Network().ClosePeer(peerInfo.ID)
		return fmt.Errorf("handshake failed: %w", err)
	}
	
	fmt.Printf("✅ Connected to peer: %s\n", peerInfo.ID.ShortString())
	
	return nil
}

// DisconnectPeer disconnects from a peer
func (n *Node) DisconnectPeer(peerID peer.ID, reason string) error {
	n.peersMu.Lock()
	delete(n.peers, peerID)
	n.peersMu.Unlock()
	
	return n.host.Network().ClosePeer(peerID)
}

// BanPeer bans a peer
func (n *Node) BanPeer(peerID peer.ID, reason string) error {
	fmt.Printf("🚫 Banning peer %s: %s\n", peerID.ShortString(), reason)
	
	n.bannedMu.Lock()
	n.banned[peerID] = &BanInfo{
		Reason:    reason,
		BannedAt:  time.Now(),
		ExpiresAt: time.Now().Add(BanDuration),
	}
	n.bannedMu.Unlock()
	
	// Disconnect peer
	return n.DisconnectPeer(peerID, reason)
}

// AdjustPeerScore adjusts a peer's reputation score
func (n *Node) AdjustPeerScore(peerID peer.ID, adjustment int32) {
	n.peersMu.Lock()
	defer n.peersMu.Unlock()
	
	peerInfo, exists := n.peers[peerID]
	if !exists {
		return
	}
	
	peerInfo.Score += adjustment
	
	// Clamp score
	if peerInfo.Score > MaxPeerScore {
		peerInfo.Score = MaxPeerScore
	}
	if peerInfo.Score < MinPeerScore {
		peerInfo.Score = MinPeerScore
	}
	
	// Check if should ban
	if peerInfo.Score <= BanThreshold {
		go n.BanPeer(peerID, "low reputation score")
		return
	}
	
	// Check if should disconnect
	if peerInfo.Score <= DisconnectThreshold {
		go n.DisconnectPeer(peerID, "negative reputation")
	}
}

// BroadcastBlock broadcasts a block to all peers
func (n *Node) BroadcastBlock(blockData []byte) error {
	if !n.config.EnablePubSub || n.pubsub == nil {
		return n.broadcastDirect(MsgTypeBlock, blockData)
	}
	
	topic, err := n.pubsub.Join(TopicBlocks)
	if err != nil {
		return err
	}
	defer topic.Close()
	
	return topic.Publish(n.ctx, blockData)
}

// BroadcastTransaction broadcasts a transaction to all peers
func (n *Node) BroadcastTransaction(txData []byte) error {
	if !n.config.EnablePubSub || n.pubsub == nil {
		return n.broadcastDirect(MsgTypeTransaction, txData)
	}
	
	topic, err := n.pubsub.Join(TopicTransactions)
	if err != nil {
		return err
	}
	defer topic.Close()
	
	return topic.Publish(n.ctx, txData)
}

// RegisterHandler registers a message handler
func (n *Node) RegisterHandler(msgType MessageType, handler MessageHandler) {
	n.handlersMu.Lock()
	defer n.handlersMu.Unlock()
	n.handlers[msgType] = handler
}

// GetPeers returns list of connected peers
func (n *Node) GetPeers() []peer.ID {
	n.peersMu.RLock()
	defer n.peersMu.RUnlock()
	
	peers := make([]peer.ID, 0, len(n.peers))
	for id := range n.peers {
		peers = append(peers, id)
	}
	return peers
}

// GetPeerInfo returns information about a peer
func (n *Node) GetPeerInfo(peerID peer.ID) (*PeerInfo, error) {
	n.peersMu.RLock()
	defer n.peersMu.RUnlock()
	
	info, exists := n.peers[peerID]
	if !exists {
		return nil, errors.New("peer not found")
	}
	
	return info, nil
}

// GetStats returns network statistics
func (n *Node) GetStats() NetworkStats {
	n.statsMu.RLock()
	defer n.statsMu.RUnlock()
	
	stats := *n.stats
	stats.ConnectedPeers = n.getPeerCount()
	stats.BannedPeersCount = len(n.banned)
	
	return stats
}

// Internal methods

func (n *Node) initDHT() error {
	var err error
	n.dht, err = dht.New(n.ctx, n.host)
	return err
}

func (n *Node) initPubSub() error {
	var err error
	n.pubsub, err = pubsub.NewGossipSub(n.ctx, n.host)
	return err
}

func (n *Node) subscribeToTopics() error {
	// Subscribe to blocks
	var err error
	n.blockSub, err = n.pubsub.Subscribe(TopicBlocks)
	if err != nil {
		return err
	}
	go n.handleBlockMessages()
	
	// Subscribe to transactions
	n.txSub, err = n.pubsub.Subscribe(TopicTransactions)
	if err != nil {
		return err
	}
	go n.handleTxMessages()
	
	return nil
}

func (n *Node) handleBlockMessages() {
	for {
		msg, err := n.blockSub.Next(n.ctx)
		if err != nil {
			if n.ctx.Err() != nil {
				return // Context cancelled
			}
			continue
		}
		
		// Handle block
		n.handleIncomingMessage(msg.ReceivedFrom, MsgTypeBlock, msg.Data)
	}
}

func (n *Node) handleTxMessages() {
	for {
		msg, err := n.txSub.Next(n.ctx)
		if err != nil {
			if n.ctx.Err() != nil {
				return // Context cancelled
			}
			continue
		}
		
		// Handle transaction
		n.handleIncomingMessage(msg.ReceivedFrom, MsgTypeTransaction, msg.Data)
	}
}

func (n *Node) handleStream(s network.Stream) {
	defer s.Close()
	
	peerID := s.Conn().RemotePeer()
	
	// Check if banned
	if n.isPeerBanned(peerID) {
		return
	}
	
	// Read message with timeout
	// Implementation would read and process message
}

func (n *Node) handleConnected(net network.Network, conn network.Conn) {
	peerID := conn.RemotePeer()
	
	// Check if banned
	if n.isPeerBanned(peerID) {
		conn.Close()
		return
	}
	
	// Check subnet diversity
	subnet := getSubnet(conn.RemoteMultiaddr())
	if !n.checkSubnetDiversity(subnet, peerID) {
		conn.Close()
		return
	}
	
	// Add peer
	n.addPeer(peerID, conn)
}

func (n *Node) handleDisconnected(net network.Network, conn network.Conn) {
	peerID := conn.RemotePeer()
	n.removePeer(peerID)
}

func (n *Node) addPeer(peerID peer.ID, conn network.Conn) {
	n.peersMu.Lock()
	defer n.peersMu.Unlock()
	
	if _, exists := n.peers[peerID]; exists {
		return // Already tracked
	}
	
	n.peers[peerID] = &PeerInfo{
		ID:             peerID,
		Addrs:          n.host.Peerstore().Addrs(peerID),
		Score:          InitialPeerScore,
		ConnectionTime: time.Now(),
		LastSeen:       time.Now(),
		Direction:      conn.Stat().Direction,
		lastRateReset:  time.Now(),
	}
	
	// Track subnet
	subnet := getSubnet(conn.RemoteMultiaddr())
	n.subnetsMu.Lock()
	n.subnets[subnet] = append(n.subnets[subnet], peerID)
	n.subnetsMu.Unlock()
}

func (n *Node) removePeer(peerID peer.ID) {
	n.peersMu.Lock()
	delete(n.peers, peerID)
	n.peersMu.Unlock()
	
	// Remove from subnet tracking
	n.subnetsMu.Lock()
	for subnet, peers := range n.subnets {
		for i, id := range peers {
			if id == peerID {
				n.subnets[subnet] = append(peers[:i], peers[i+1:]...)
				break
			}
		}
	}
	n.subnetsMu.Unlock()
}

func (n *Node) isPeerBanned(peerID peer.ID) bool {
	n.bannedMu.RLock()
	defer n.bannedMu.RUnlock()
	
	ban, exists := n.banned[peerID]
	if !exists {
		return false
	}
	
	// Check if ban expired
	if time.Now().After(ban.ExpiresAt) {
		delete(n.banned, peerID)
		return false
	}
	
	return true
}

func (n *Node) checkSubnetDiversity(subnet string, peerID peer.ID) bool {
	n.subnetsMu.RLock()
	defer n.subnetsMu.RUnlock()
	
	// Check if too many peers from this subnet
	if len(n.subnets[subnet]) >= MaxPeersPerSubnet {
		return false
	}
	
	// Check subnet diversity
	if len(n.subnets) < MinDiverseSubnets {
		return true // Need more diversity
	}
	
	return true
}

func (n *Node) performHandshake(peerID peer.ID) error {
	// Handshake implementation
	// Would exchange protocol version, network ID, etc.
	return nil
}

func (n *Node) handleIncomingMessage(peerID peer.ID, msgType MessageType, data []byte) {
	// Check rate limit
	if !n.checkRateLimit(peerID, msgType) {
		n.AdjustPeerScore(peerID, ScoreProtocolViolation)
		return
	}
	
	// Get handler
	n.handlersMu.RLock()
	handler, exists := n.handlers[msgType]
	n.handlersMu.RUnlock()
	
	if !exists {
		return
	}
	
	// Execute handler
	if err := handler(peerID, data); err != nil {
		// Adjust score based on error
		if errors.Is(err, ErrInvalidMessage) {
			n.AdjustPeerScore(peerID, ScoreInvalidBlock)
		}
	}
}

func (n *Node) checkRateLimit(peerID peer.ID, msgType MessageType) bool {
	n.peersMu.Lock()
	defer n.peersMu.Unlock()
	
	peerInfo, exists := n.peers[peerID]
	if !exists {
		return false
	}
	
	// Reset counters if needed
	if time.Since(peerInfo.lastRateReset) > time.Minute {
		peerInfo.blockCount = 0
		peerInfo.txCount = 0
		peerInfo.messageCount = 0
		peerInfo.lastRateReset = time.Now()
	}
	
	// Check limits
	switch msgType {
	case MsgTypeBlock:
		if peerInfo.blockCount >= MaxBlocksPerMinute {
			return false
		}
		peerInfo.blockCount++
	case MsgTypeTransaction:
		if peerInfo.txCount >= MaxTxsPerMinute {
			return false
		}
		peerInfo.txCount++
	default:
		if peerInfo.messageCount >= MaxMessagesPerMinute {
			return false
		}
		peerInfo.messageCount++
	}
	
	return true
}

func (n *Node) broadcastDirect(msgType MessageType, data []byte) error {
	peers := n.GetPeers()
	
	for _, peerID := range peers {
		// Send to each peer
		// Implementation would open stream and send
	}
	
	return nil
}

func (n *Node) connectToBootstrapPeers() error {
	for _, peerInfo := range n.config.BootstrapPeers {
		if err := n.ConnectToPeer(peerInfo); err != nil {
			fmt.Printf("Failed to connect to bootstrap peer %s: %v\n", 
				peerInfo.ID.ShortString(), err)
		}
	}
	return nil
}

func (n *Node) peerDiscoveryLoop() {
	ticker := time.NewTicker(PeerDiscoveryInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-n.ctx.Done():
			return
		case <-ticker.C:
			n.discoverPeers()
		}
	}
}

func (n *Node) discoverPeers() {
	// Use DHT to discover peers
	if n.dht != nil {
		// Find peers using DHT
	}
	
	// Check if need more peers
	if n.getPeerCount() < n.config.MinPeers {
		fmt.Printf("⚠️  Low peer count: %d (target: %d)\n", 
			n.getPeerCount(), TargetPeers)
	}
}

func (n *Node) peerCleanupLoop() {
	ticker := time.NewTicker(PeerCleanupInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-n.ctx.Done():
			return
		case <-ticker.C:
			n.cleanupPeers()
		}
	}
}

func (n *Node) cleanupPeers() {
	n.peersMu.Lock()
	defer n.peersMu.Unlock()
	
	for peerID, info := range n.peers {
		// Remove stale peers
		if time.Since(info.LastSeen) > 5*time.Minute {
			delete(n.peers, peerID)
		}
	}
	
	// Clean expired bans
	n.bannedMu.Lock()
	for peerID, ban := range n.banned {
		if time.Now().After(ban.ExpiresAt) {
			delete(n.banned, peerID)
		}
	}
	n.bannedMu.Unlock()
}

func (n *Node) pingLoop() {
	ticker := time.NewTicker(PingInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-n.ctx.Done():
			return
		case <-ticker.C:
			n.pingPeers()
		}
	}
}

func (n *Node) pingPeers() {
	peers := n.GetPeers()
	
	for _, peerID := range peers {
		// Send ping to check connectivity
		// Implementation would measure latency
	}
}

func (n *Node) getPeerCount() int {
	n.peersMu.RLock()
	defer n.peersMu.RUnlock()
	return len(n.peers)
}

// Helper functions

func validateNodeConfig(config *NodeConfig) error {
	if len(config.ListenAddrs) == 0 {
		return errors.New("no listen addresses specified")
	}
	
	if config.MaxPeers <= 0 {
		config.MaxPeers = MaxPeers
	}
	
	if config.MinPeers <= 0 {
		config.MinPeers = MinPeers
	}
	
	return nil
}

func generateKey() (interface{}, interface{}, error) {
	// Generate Ed25519 key pair
	// Implementation would use crypto/ed25519
	return nil, nil, nil
}

func getSubnet(addr multiaddr.Multiaddr) string {
	// Extract /24 subnet from multiaddr
	// Implementation would parse IP and mask
	return "0.0.0.0/24"
}
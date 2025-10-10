package p2p

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
)

// P2PSecurityManager manages P2P network security
type P2PSecurityManager struct {
	// Peer reputation system
	peerScores map[peer.ID]*PeerScore
	
	// Connection limits
	maxPeersPerIP   int
	maxTotalPeers   int
	ipToPeers       map[string][]peer.ID
	
	// Peer banning
	bannedPeers     map[peer.ID]time.Time
	bannedIPs       map[string]time.Time
	
	// Message rate limiting
	peerRateLimits  map[peer.ID]*PeerRateLimit
	
	// Eclipse attack prevention
	diversityChecker *DiversityChecker
	
	// Sybil attack detection
	sybilDetector   *SybilDetector
	
	config          *P2PSecurityConfig
	mu              sync.RWMutex
}

// P2PSecurityConfig contains security parameters
type P2PSecurityConfig struct {
	MaxPeersPerIP       int
	MaxTotalPeers       int
	MinPeerScore        int
	BanDuration         time.Duration
	MessageRateLimit    int
	BurstLimit          int
	EnableDiversityCheck bool
	EnableSybilDetection bool
	MaxPeersPerASN      int
	RequireMinDiversity float64
}

// PeerScore tracks peer reputation
type PeerScore struct {
	PeerID           peer.ID
	Score            int
	LastSeen         time.Time
	ValidMessages    int
	InvalidMessages  int
	Violations       []PeerViolation
	ConnectionTime   time.Time
	BytesSent        uint64
	BytesReceived    uint64
	LatencyMs        float64
}

// PeerViolation represents a peer misbehavior
type PeerViolation struct {
	Type      ViolationType
	Timestamp time.Time
	Severity  int
	Details   string
}

type ViolationType int

const (
	ViolationInvalidBlock ViolationType = iota
	ViolationInvalidTx
	ViolationRateLimit
	ViolationProtocol
	ViolationEclipse
	ViolationSybil
	ViolationFlood
	ViolationMalformed
)

// PeerRateLimit tracks per-peer message rates
type PeerRateLimit struct {
	PeerID          peer.ID
	MessageCount    int
	LastReset       time.Time
	ViolationCount  int
	Blocked         bool
}

// DiversityChecker ensures peer diversity to prevent eclipse attacks
type DiversityChecker struct {
	peersByASN      map[string][]peer.ID
	peersByCountry  map[string][]peer.ID
	peersByPrefix   map[string][]peer.ID // IP prefix (/16)
	mu              sync.RWMutex
}

// SybilDetector detects Sybil attacks
type SybilDetector struct {
	suspiciousClusters map[string]*SybilCluster
	mu                 sync.RWMutex
}

// SybilCluster represents a group of potentially related peers
type SybilCluster struct {
	PeerIDs      []peer.ID
	CommonTraits []string
	Confidence   float64
	DetectedAt   time.Time
}

// NewP2PSecurityManager creates a new P2P security manager
func NewP2PSecurityManager(config *P2PSecurityConfig) *P2PSecurityManager {
	return &P2PSecurityManager{
		peerScores:       make(map[peer.ID]*PeerScore),
		ipToPeers:        make(map[string][]peer.ID),
		bannedPeers:      make(map[peer.ID]time.Time),
		bannedIPs:        make(map[string]time.Time),
		peerRateLimits:   make(map[peer.ID]*PeerRateLimit),
		diversityChecker: newDiversityChecker(),
		sybilDetector:    newSybilDetector(),
		config:           config,
	}
}

func newDiversityChecker() *DiversityChecker {
	return &DiversityChecker{
		peersByASN:     make(map[string][]peer.ID),
		peersByCountry: make(map[string][]peer.ID),
		peersByPrefix:  make(map[string][]peer.ID),
	}
}

func newSybilDetector() *SybilDetector {
	return &SybilDetector{
		suspiciousClusters: make(map[string]*SybilCluster),
	}
}

// ValidateConnection validates a new peer connection
func (psm *P2PSecurityManager) ValidateConnection(peerID peer.ID, ipAddr string) error {
	psm.mu.RLock()
	defer psm.mu.RUnlock()

	// Check if peer is banned
	if banExpiry, banned := psm.bannedPeers[peerID]; banned {
		if time.Now().Before(banExpiry) {
			return fmt.Errorf("peer is banned until %v", banExpiry)
		}
	}

	// Check if IP is banned
	if banExpiry, banned := psm.bannedIPs[ipAddr]; banned {
		if time.Now().Before(banExpiry) {
			return fmt.Errorf("IP is banned until %v", banExpiry)
		}
	}

	// Check max peers per IP
	if peers, exists := psm.ipToPeers[ipAddr]; exists {
		if len(peers) >= psm.config.MaxPeersPerIP {
			return fmt.Errorf("max peers per IP (%d) exceeded", psm.config.MaxPeersPerIP)
		}
	}

	// Check total peer count
	if len(psm.peerScores) >= psm.config.MaxTotalPeers {
		return fmt.Errorf("max total peers (%d) reached", psm.config.MaxTotalPeers)
	}

	// Check peer score
	if score, exists := psm.peerScores[peerID]; exists {
		if score.Score < psm.config.MinPeerScore {
			return fmt.Errorf("peer score too low: %d", score.Score)
		}
	}

	return nil
}

// RegisterPeer registers a new peer connection
func (psm *P2PSecurityManager) RegisterPeer(peerID peer.ID, ipAddr string) {
	psm.mu.Lock()
	defer psm.mu.Unlock()

	// Initialize peer score
	if _, exists := psm.peerScores[peerID]; !exists {
		psm.peerScores[peerID] = &PeerScore{
			PeerID:         peerID,
			Score:          100, // Starting score
			ConnectionTime: time.Now(),
			Violations:     make([]PeerViolation, 0),
		}
	}

	// Track IP to peer mapping
	psm.ipToPeers[ipAddr] = append(psm.ipToPeers[ipAddr], peerID)

	// Initialize rate limiter
	psm.peerRateLimits[peerID] = &PeerRateLimit{
		PeerID:    peerID,
		LastReset: time.Now(),
	}
}

// UnregisterPeer removes a peer
func (psm *P2PSecurityManager) UnregisterPeer(peerID peer.ID, ipAddr string) {
	psm.mu.Lock()
	defer psm.mu.Unlock()

	// Remove from IP tracking
	if peers, exists := psm.ipToPeers[ipAddr]; exists {
		filtered := make([]peer.ID, 0)
		for _, p := range peers {
			if p != peerID {
				filtered = append(filtered, p)
			}
		}
		if len(filtered) > 0 {
			psm.ipToPeers[ipAddr] = filtered
		} else {
			delete(psm.ipToPeers, ipAddr)
		}
	}

	// Don't delete peer score - keep for reputation history
	if score, exists := psm.peerScores[peerID]; exists {
		score.LastSeen = time.Now()
	}

	// Clean up rate limiter
	delete(psm.peerRateLimits, peerID)
}

// ValidateMessage validates an incoming P2P message
func (psm *P2PSecurityManager) ValidateMessage(peerID peer.ID, msgType string, msgSize int) error {
	psm.mu.Lock()
	defer psm.mu.Unlock()

	// Check rate limit
	rateLimit, exists := psm.peerRateLimits[peerID]
	if !exists {
		return errors.New("peer not registered")
	}

	// Check if peer is blocked
	if rateLimit.Blocked {
		return errors.New("peer is rate limited")
	}

	// Reset counter if needed
	if time.Since(rateLimit.LastReset) > time.Second {
		rateLimit.MessageCount = 0
		rateLimit.LastReset = time.Now()
	}

	// Check rate limit
	if rateLimit.MessageCount >= psm.config.MessageRateLimit {
		rateLimit.ViolationCount++
		
		// Block after multiple violations
		if rateLimit.ViolationCount >= 5 {
			rateLimit.Blocked = true
			psm.recordViolation(peerID, ViolationRateLimit, 3, "Excessive rate limit violations")
			return errors.New("peer blocked for rate limit violations")
		}
		
		return errors.New("rate limit exceeded")
	}

	// Check message size (prevent memory exhaustion)
	maxMsgSize := 10 * 1024 * 1024 // 10MB
	if msgSize > maxMsgSize {
		psm.recordViolation(peerID, ViolationFlood, 2, fmt.Sprintf("Oversized message: %d bytes", msgSize))
		return errors.New("message too large")
	}

	// Increment counter
	rateLimit.MessageCount++

	return nil
}

// RecordValidMessage records a valid message from a peer
func (psm *P2PSecurityManager) RecordValidMessage(peerID peer.ID) {
	psm.mu.Lock()
	defer psm.mu.Unlock()

	if score, exists := psm.peerScores[peerID]; exists {
		score.ValidMessages++
		score.Score += 1 // Small reward
		if score.Score > 100 {
			score.Score = 100 // Cap at 100
		}
	}
}

// RecordInvalidMessage records an invalid message from a peer
func (psm *P2PSecurityManager) RecordInvalidMessage(peerID peer.ID, violationType ViolationType, details string) {
	psm.mu.Lock()
	defer psm.mu.Unlock()

	if score, exists := psm.peerScores[peerID]; exists {
		score.InvalidMessages++
		
		// Determine severity and penalty
		severity := 2
		penalty := 10
		
		switch violationType {
		case ViolationInvalidBlock, ViolationInvalidTx:
			severity = 3
			penalty = 20
		case ViolationProtocol, ViolationMalformed:
			severity = 2
			penalty = 15
		case ViolationFlood:
			severity = 2
			penalty = 10
		}

		// Apply penalty
		score.Score -= penalty
		
		// Record violation
		psm.recordViolation(peerID, violationType, severity, details)

		// Auto-ban if score too low
		if score.Score <= 0 {
			psm.bannedPeers[peerID] = time.Now().Add(psm.config.BanDuration)
		}
	}
}

// recordViolation records a peer violation
func (psm *P2PSecurityManager) recordViolation(peerID peer.ID, violationType ViolationType, severity int, details string) {
	if score, exists := psm.peerScores[peerID]; exists {
		violation := PeerViolation{
			Type:      violationType,
			Timestamp: time.Now(),
			Severity:  severity,
			Details:   details,
		}
		score.Violations = append(score.Violations, violation)
		
		// Keep only recent violations
		if len(score.Violations) > 100 {
			score.Violations = score.Violations[1:]
		}
	}
}

// BanPeer explicitly bans a peer
func (psm *P2PSecurityManager) BanPeer(peerID peer.ID, duration time.Duration, reason string) {
	psm.mu.Lock()
	defer psm.mu.Unlock()

	psm.bannedPeers[peerID] = time.Now().Add(duration)
	psm.recordViolation(peerID, ViolationProtocol, 3, fmt.Sprintf("Banned: %s", reason))
}

// CheckEclipseAttack checks for potential eclipse attack
func (psm *P2PSecurityManager) CheckEclipseAttack() (bool, string) {
	if !psm.config.EnableDiversityCheck {
		return false, ""
	}

	psm.diversityChecker.mu.RLock()
	defer psm.diversityChecker.mu.RUnlock()

	// Check ASN diversity
	if len(psm.diversityChecker.peersByASN) == 0 {
		return false, ""
	}

	// If more than 50% peers from same ASN, potential eclipse
	totalPeers := 0
	maxASNCount := 0
	maxASN := ""

	for asn, peers := range psm.diversityChecker.peersByASN {
		count := len(peers)
		totalPeers += count
		if count > maxASNCount {
			maxASNCount = count
			maxASN = asn
		}
	}

	if totalPeers > 0 {
		concentration := float64(maxASNCount) / float64(totalPeers)
		if concentration > 0.5 {
			return true, fmt.Sprintf("Eclipse attack suspected: %.1f%% peers from ASN %s", 
				concentration*100, maxASN)
		}
	}

	return false, ""
}

// DetectSybilAttack detects potential Sybil attacks
func (psm *P2PSecurityManager) DetectSybilAttack() []SybilCluster {
	if !psm.config.EnableSybilDetection {
		return nil
	}

	psm.mu.RLock()
	defer psm.mu.RUnlock()

	// Group peers by similar behavior patterns
	suspiciousClusters := make([]SybilCluster, 0)

	// Simple heuristic: peers connecting at same time with similar patterns
	connectionTimes := make(map[int64][]peer.ID)
	
	for peerID, score := range psm.peerScores {
		// Group by connection time (rounded to minute)
		connTime := score.ConnectionTime.Unix() / 60
		connectionTimes[connTime] = append(connectionTimes[connTime], peerID)
	}

	// Flag clusters with many peers connecting simultaneously
	for _, peers := range connectionTimes {
		if len(peers) >= 5 { // 5+ peers at same time is suspicious
			cluster := SybilCluster{
				PeerIDs:      peers,
				CommonTraits: []string{"simultaneous_connection"},
				Confidence:   0.7,
				DetectedAt:   time.Now(),
			}
			suspiciousClusters = append(suspiciousClusters, cluster)
		}
	}

	return suspiciousClusters
}

// GetPeerScore returns the score for a peer
func (psm *P2PSecurityManager) GetPeerScore(peerID peer.ID) (int, error) {
	psm.mu.RLock()
	defer psm.mu.RUnlock()

	if score, exists := psm.peerScores[peerID]; exists {
		return score.Score, nil
	}

	return 0, errors.New("peer not found")
}

// GetTopPeers returns peers with highest scores
func (psm *P2PSecurityManager) GetTopPeers(limit int) []peer.ID {
	psm.mu.RLock()
	defer psm.mu.RUnlock()

	type scoredPeer struct {
		id    peer.ID
		score int
	}

	peers := make([]scoredPeer, 0, len(psm.peerScores))
	for id, score := range psm.peerScores {
		// Only include currently connected peers
		if time.Since(score.LastSeen) < 1*time.Minute || score.LastSeen.IsZero() {
			peers = append(peers, scoredPeer{id: id, score: score.Score})
		}
	}

	// Sort by score descending
	for i := 0; i < len(peers); i++ {
		for j := i + 1; j < len(peers); j++ {
			if peers[j].score > peers[i].score {
				peers[i], peers[j] = peers[j], peers[i]
			}
		}
	}

	// Return top N
	if limit > len(peers) {
		limit = len(peers)
	}

	result := make([]peer.ID, limit)
	for i := 0; i < limit; i++ {
		result[i] = peers[i].id
	}

	return result
}

// CleanupStaleData removes old peer data
func (psm *P2PSecurityManager) CleanupStaleData(maxAge time.Duration) {
	psm.mu.Lock()
	defer psm.mu.Unlock()

	now := time.Now()

	// Clean up old peer scores
	for peerID, score := range psm.peerScores {
		if !score.LastSeen.IsZero() && now.Sub(score.LastSeen) > maxAge {
			delete(psm.peerScores, peerID)
		}
	}

	// Clean up expired bans
	for peerID, expiry := range psm.bannedPeers {
		if now.After(expiry) {
			delete(psm.bannedPeers, peerID)
		}
	}

	for ip, expiry := range psm.bannedIPs {
		if now.After(expiry) {
			delete(psm.bannedIPs, ip)
		}
	}
}

// GetStatistics returns security statistics
func (psm *P2PSecurityManager) GetStatistics() map[string]interface{} {
	psm.mu.RLock()
	defer psm.mu.RUnlock()

	totalViolations := 0
	avgScore := 0
	
	for _, score := range psm.peerScores {
		totalViolations += len(score.Violations)
		avgScore += score.Score
	}

	if len(psm.peerScores) > 0 {
		avgScore /= len(psm.peerScores)
	}

	return map[string]interface{}{
		"total_peers":       len(psm.peerScores),
		"banned_peers":      len(psm.bannedPeers),
		"banned_ips":        len(psm.bannedIPs),
		"average_score":     avgScore,
		"total_violations":  totalViolations,
		"rate_limited":      psm.countRateLimited(),
	}
}

func (psm *P2PSecurityManager) countRateLimited() int {
	count := 0
	for _, limit := range psm.peerRateLimits {
		if limit.Blocked {
			count++
		}
	}
	return count
}
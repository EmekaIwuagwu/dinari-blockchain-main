package security

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// DDoSProtection provides multi-layer DDoS protection
type DDoSProtection struct {
	// Rate limiters per IP
	ipLimiters map[string]*IPLimiter
	
	// Connection tracking
	connTracker *ConnectionTracker
	
	// Circuit breaker
	circuitBreaker *CircuitBreaker
	
	// IP reputation system
	reputationSystem *IPReputationSystem
	
	// Configuration
	config *DDoSConfig
	
	mu sync.RWMutex
}

// DDoSConfig contains DDoS protection parameters
type DDoSConfig struct {
	// Rate limiting
	MaxRequestsPerSecond int
	MaxBurstSize         int
	
	// Connection limits
	MaxConnPerIP         int
	MaxTotalConnections  int
	
	// Circuit breaker
	ErrorThreshold       int
	SuccessThreshold     int
	Timeout              time.Duration
	
	// IP reputation
	BanDuration          time.Duration
	SuspicionThreshold   int
	
	// Attack detection
	EnableFloodDetection bool
	FloodThreshold       int
	FloodWindow          time.Duration
}

// IPLimiter tracks rate limits for a single IP
type IPLimiter struct {
	limiter      *rate.Limiter
	lastSeen     time.Time
	violations   int
	banned       bool
	banExpiry    time.Time
}

// ConnectionTracker tracks active connections
type ConnectionTracker struct {
	connections     map[string]int // IP -> count
	totalCount      int
	mu              sync.RWMutex
}

// CircuitBreaker implements circuit breaker pattern
type CircuitBreaker struct {
	maxFailures   int
	successCount  int
	failureCount  int
	state         CircuitState
	lastStateTime time.Time
	timeout       time.Duration
	mu            sync.RWMutex
}

type CircuitState int

const (
	StateClosed CircuitState = iota
	StateOpen
	StateHalfOpen
)

// IPReputationSystem tracks IP reputation
type IPReputationSystem struct {
	scores         map[string]*ReputationScore
	blacklist      map[string]time.Time
	whitelist      map[string]bool
	mu             sync.RWMutex
}

// ReputationScore tracks reputation metrics for an IP
type ReputationScore struct {
	Score          int
	LastUpdate     time.Time
	FailedAttempts int
	SuccessCount   int
	Violations     []Violation
}

// Violation represents a security violation
type Violation struct {
	Type      string
	Timestamp time.Time
	Severity  int
}

// NewDDoSProtection creates a new DDoS protection system
func NewDDoSProtection(config *DDoSConfig) *DDoSProtection {
	return &DDoSProtection{
		ipLimiters: make(map[string]*IPLimiter),
		connTracker: &ConnectionTracker{
			connections: make(map[string]int),
		},
		circuitBreaker: &CircuitBreaker{
			maxFailures: config.ErrorThreshold,
			timeout:     config.Timeout,
			state:       StateClosed,
		},
		reputationSystem: &IPReputationSystem{
			scores:    make(map[string]*ReputationScore),
			blacklist: make(map[string]time.Time),
			whitelist: make(map[string]bool),
		},
		config: config,
	}
}

// AllowRequest checks if a request from an IP should be allowed
func (d *DDoSProtection) AllowRequest(ip string) (bool, error) {
	// 1. Check circuit breaker state
	if !d.circuitBreaker.Allow() {
		return false, fmt.Errorf("circuit breaker open")
	}

	// 2. Check IP reputation
	if d.isBlacklisted(ip) {
		d.circuitBreaker.RecordFailure()
		return false, fmt.Errorf("IP blacklisted")
	}

	// Skip rate limiting for whitelisted IPs
	if d.isWhitelisted(ip) {
		return true, nil
	}

	// 3. Check rate limit
	limiter := d.getOrCreateLimiter(ip)
	
	// Check if IP is temporarily banned
	if limiter.banned && time.Now().Before(limiter.banExpiry) {
		return false, fmt.Errorf("IP temporarily banned until %v", limiter.banExpiry)
	}

	// Clear ban if expired
	if limiter.banned && time.Now().After(limiter.banExpiry) {
		limiter.banned = false
		limiter.violations = 0
	}

	// Check rate limit
	if !limiter.limiter.Allow() {
		limiter.violations++
		
		// Ban after threshold violations
		if limiter.violations >= d.config.SuspicionThreshold {
			limiter.banned = true
			limiter.banExpiry = time.Now().Add(d.config.BanDuration)
			d.addViolation(ip, "RATE_LIMIT_EXCEEDED", 3)
			return false, fmt.Errorf("too many violations - IP banned")
		}
		
		d.circuitBreaker.RecordFailure()
		return false, fmt.Errorf("rate limit exceeded")
	}

	limiter.lastSeen = time.Now()
	d.circuitBreaker.RecordSuccess()
	return true, nil
}

// getOrCreateLimiter gets or creates a rate limiter for an IP
func (d *DDoSProtection) getOrCreateLimiter(ip string) *IPLimiter {
	d.mu.Lock()
	defer d.mu.Unlock()

	limiter, exists := d.ipLimiters[ip]
	if !exists {
		limiter = &IPLimiter{
			limiter:  rate.NewLimiter(rate.Limit(d.config.MaxRequestsPerSecond), d.config.MaxBurstSize),
			lastSeen: time.Now(),
		}
		d.ipLimiters[ip] = limiter
	}

	return limiter
}

// TrackConnection tracks a new connection
func (d *DDoSProtection) TrackConnection(ip string) error {
	d.connTracker.mu.Lock()
	defer d.connTracker.mu.Unlock()

	// Check total connection limit
	if d.connTracker.totalCount >= d.config.MaxTotalConnections {
		return fmt.Errorf("max total connections reached")
	}

	// Check per-IP limit
	count := d.connTracker.connections[ip]
	if count >= d.config.MaxConnPerIP {
		d.addViolation(ip, "MAX_CONNECTIONS_EXCEEDED", 2)
		return fmt.Errorf("max connections per IP reached")
	}

	d.connTracker.connections[ip]++
	d.connTracker.totalCount++
	
	return nil
}

// ReleaseConnection releases a tracked connection
func (d *DDoSProtection) ReleaseConnection(ip string) {
	d.connTracker.mu.Lock()
	defer d.connTracker.mu.Unlock()

	if count := d.connTracker.connections[ip]; count > 0 {
		d.connTracker.connections[ip]--
		d.connTracker.totalCount--
		
		if d.connTracker.connections[ip] == 0 {
			delete(d.connTracker.connections, ip)
		}
	}
}

// isBlacklisted checks if an IP is blacklisted
func (d *DDoSProtection) isBlacklisted(ip string) bool {
	d.reputationSystem.mu.RLock()
	defer d.reputationSystem.mu.RUnlock()

	banExpiry, exists := d.reputationSystem.blacklist[ip]
	if !exists {
		return false
	}

	// Check if ban has expired
	if time.Now().After(banExpiry) {
		return false
	}

	return true
}

// isWhitelisted checks if an IP is whitelisted
func (d *DDoSProtection) isWhitelisted(ip string) bool {
	d.reputationSystem.mu.RLock()
	defer d.reputationSystem.mu.RUnlock()

	return d.reputationSystem.whitelist[ip]
}

// BlacklistIP adds an IP to the blacklist
func (d *DDoSProtection) BlacklistIP(ip string, duration time.Duration) {
	d.reputationSystem.mu.Lock()
	defer d.reputationSystem.mu.Unlock()

	d.reputationSystem.blacklist[ip] = time.Now().Add(duration)
}

// WhitelistIP adds an IP to the whitelist
func (d *DDoSProtection) WhitelistIP(ip string) {
	d.reputationSystem.mu.Lock()
	defer d.reputationSystem.mu.Unlock()

	d.reputationSystem.whitelist[ip] = true
}

// addViolation records a security violation
func (d *DDoSProtection) addViolation(ip, violationType string, severity int) {
	d.reputationSystem.mu.Lock()
	defer d.reputationSystem.mu.Unlock()

	score, exists := d.reputationSystem.scores[ip]
	if !exists {
		score = &ReputationScore{
			Score:      100,
			LastUpdate: time.Now(),
			Violations: make([]Violation, 0),
		}
		d.reputationSystem.scores[ip] = score
	}

	// Add violation
	violation := Violation{
		Type:      violationType,
		Timestamp: time.Now(),
		Severity:  severity,
	}
	score.Violations = append(score.Violations, violation)
	
	// Decrease reputation score
	score.Score -= severity * 10
	score.LastUpdate = time.Now()

	// Auto-blacklist if score is too low
	if score.Score <= 0 {
		d.reputationSystem.blacklist[ip] = time.Now().Add(d.config.BanDuration)
	}
}

// Allow checks circuit breaker state
func (cb *CircuitBreaker) Allow() bool {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	switch cb.state {
	case StateClosed:
		return true
	case StateOpen:
		// Check if timeout has passed
		if time.Since(cb.lastStateTime) > cb.timeout {
			cb.mu.RUnlock()
			cb.mu.Lock()
			cb.state = StateHalfOpen
			cb.failureCount = 0
			cb.mu.Unlock()
			cb.mu.RLock()
			return true
		}
		return false
	case StateHalfOpen:
		return true
	}

	return false
}

// RecordSuccess records a successful operation
func (cb *CircuitBreaker) RecordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if cb.state == StateHalfOpen {
		cb.successCount++
		if cb.successCount >= 3 { // Success threshold
			cb.state = StateClosed
			cb.failureCount = 0
			cb.successCount = 0
		}
	}
}

// RecordFailure records a failed operation
func (cb *CircuitBreaker) RecordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.failureCount++
	cb.lastStateTime = time.Now()

	if cb.state == StateHalfOpen || cb.failureCount >= cb.maxFailures {
		cb.state = StateOpen
		cb.successCount = 0
	}
}

// CleanupStaleEntries removes old limiters and reputation data
func (d *DDoSProtection) CleanupStaleEntries(maxAge time.Duration) {
	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now()
	
	// Clean up stale IP limiters
	for ip, limiter := range d.ipLimiters {
		if now.Sub(limiter.lastSeen) > maxAge {
			delete(d.ipLimiters, ip)
		}
	}

	// Clean up expired blacklist entries
	d.reputationSystem.mu.Lock()
	for ip, expiry := range d.reputationSystem.blacklist {
		if now.After(expiry) {
			delete(d.reputationSystem.blacklist, ip)
		}
	}
	d.reputationSystem.mu.Unlock()
}

// GetStats returns current protection statistics
func (d *DDoSProtection) GetStats() map[string]interface{} {
	d.mu.RLock()
	defer d.mu.RUnlock()

	d.connTracker.mu.RLock()
	totalConns := d.connTracker.totalCount
	d.connTracker.mu.RUnlock()

	d.reputationSystem.mu.RLock()
	blacklistedCount := len(d.reputationSystem.blacklist)
	whitelistedCount := len(d.reputationSystem.whitelist)
	d.reputationSystem.mu.RUnlock()

	return map[string]interface{}{
		"total_connections":  totalConns,
		"tracked_ips":        len(d.ipLimiters),
		"blacklisted_ips":    blacklistedCount,
		"whitelisted_ips":    whitelistedCount,
		"circuit_breaker":    d.circuitBreaker.state.String(),
	}
}

func (cs CircuitState) String() string {
	switch cs {
	case StateClosed:
		return "CLOSED"
	case StateOpen:
		return "OPEN"
	case StateHalfOpen:
		return "HALF_OPEN"
	default:
		return "UNKNOWN"
	}
}
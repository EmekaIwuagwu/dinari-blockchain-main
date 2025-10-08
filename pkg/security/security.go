// pkg/security/security.go
package security

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/dgrijalva/jwt-go"
	"go.uber.org/zap"
	"golang.org/x/crypto/argon2"
	"golang.org/x/time/rate"
)

// SecurityManager handles all security aspects of the blockchain
type SecurityManager struct {
	config         *SecurityConfig
	ipRateLimiters map[string]*rate.Limiter
	bannedIPs      map[string]time.Time
	whitelistIPs   map[string]bool
	blacklistIPs   map[string]bool
	apiKeys        map[string]*APIKeyInfo
	jwtSecret      []byte
	ddosProtection *DDoSProtection
	firewall       *Firewall
	logger         *zap.Logger
	metrics        *SecurityMetrics
	mu             sync.RWMutex
}

// SecurityConfig contains security configuration
type SecurityConfig struct {
	EnableTLS            bool
	TLSMinVersion        string
	EnableFirewall       bool
	MaxRequestsPerIP     int
	BanDuration          time.Duration
	EnableDDoSProtection bool
	JWTSecret            string
	APIRateLimit         int
	WhitelistIPs         []string
	BlacklistIPs         []string
	APIKeys              []string
	MaxConnectionsPerIP  int
	RequestSizeLimit     int64
	HeaderSizeLimit      int
	ConnectionTimeout    time.Duration
	IdleTimeout          time.Duration
	SuspiciousPatterns   []string
}

// DDoSProtection handles DDoS attack mitigation
type DDoSProtection struct {
	connectionTracker map[string]*ConnectionInfo
	requestPatterns   map[string]*PatternInfo
	suspiciousIPs     map[string]*SuspiciousActivity
	synCookies        bool
	challengeMode     bool
	emergencyMode     bool
	mu                sync.RWMutex
}

// Firewall manages network-level security
type Firewall struct {
	rules          []*FirewallRule
	geoBlockList   map[string]bool
	asnBlockList   map[uint32]bool
	portWhitelist  []int
	protocolFilter map[string]bool
	logger         *zap.Logger
	mu             sync.RWMutex
}

// FirewallRule represents a firewall rule
type FirewallRule struct {
	ID          string
	Priority    int
	Type        string // ALLOW, DENY, RATE_LIMIT
	Source      string // IP, CIDR, ASN, COUNTRY
	Target      string // PORT, PROTOCOL, PATH
	Action      string
	RateLimit   int
	Expiry      time.Time
	Enabled     bool
	Description string
}

// ConnectionInfo tracks connection information
type ConnectionInfo struct {
	IP              string
	FirstSeen       time.Time
	LastSeen        time.Time
	ConnectionCount int
	RequestCount    int
	BytesReceived   int64
	BytesSent       int64
	UserAgent       string
	Fingerprint     string
	Score           int
}

// PatternInfo tracks request patterns
type PatternInfo struct {
	Pattern         string
	Count           int
	LastSeen        time.Time
	Sources         map[string]int
	AverageInterval time.Duration
}

// SuspiciousActivity tracks suspicious behavior
type SuspiciousActivity struct {
	IP            string
	FirstDetected time.Time
	LastDetected  time.Time
	ActivityCount int
	Types         []string
	Score         int
	Blocked       bool
	BlockedUntil  time.Time
	Evidence      []string
}

// APIKeyInfo contains API key metadata
type APIKeyInfo struct {
	Key         string
	Name        string
	CreatedAt   time.Time
	LastUsed    time.Time
	RateLimit   int
	Permissions []string
	Active      bool
}

// SecurityMetrics tracks security events
type SecurityMetrics struct {
	TotalRequests       uint64
	BlockedRequests     uint64
	RateLimitedRequests uint64
	DDoSAttacks         uint64
	AuthFailures        uint64
	SuspiciousActivity  uint64
	BannedIPs           uint64
	ActiveConnections   uint64
}

// NewSecurityManager creates a new security manager
func NewSecurityManager(config *SecurityConfig, logger *zap.Logger) (*SecurityManager, error) {
	jwtSecret, err := hex.DecodeString(config.JWTSecret)
	if err != nil {
		return nil, fmt.Errorf("invalid JWT secret: %w", err)
	}

	sm := &SecurityManager{
		config:         config,
		ipRateLimiters: make(map[string]*rate.Limiter),
		bannedIPs:      make(map[string]time.Time),
		whitelistIPs:   make(map[string]bool),
		blacklistIPs:   make(map[string]bool),
		apiKeys:        make(map[string]*APIKeyInfo),
		jwtSecret:      jwtSecret,
		logger:         logger,
		metrics:        &SecurityMetrics{},
	}

	// Initialize whitelist
	for _, ip := range config.WhitelistIPs {
		sm.whitelistIPs[ip] = true
	}

	// Initialize blacklist
	for _, ip := range config.BlacklistIPs {
		sm.blacklistIPs[ip] = true
	}

	// Initialize API keys
	for _, key := range config.APIKeys {
		sm.apiKeys[key] = &APIKeyInfo{
			Key:       key,
			CreatedAt: time.Now(),
			RateLimit: config.APIRateLimit,
			Active:    true,
		}
	}

	// Initialize DDoS protection
	if config.EnableDDoSProtection {
		sm.ddosProtection = &DDoSProtection{
			connectionTracker: make(map[string]*ConnectionInfo),
			requestPatterns:   make(map[string]*PatternInfo),
			suspiciousIPs:     make(map[string]*SuspiciousActivity),
		}
	}

	// Initialize firewall
	if config.EnableFirewall {
		sm.firewall = &Firewall{
			rules:          make([]*FirewallRule, 0),
			geoBlockList:   make(map[string]bool),
			asnBlockList:   make(map[uint32]bool),
			portWhitelist:  []int{8545, 9000, 9090}, // RPC, P2P, Metrics
			protocolFilter: map[string]bool{"tcp": true, "udp": false},
			logger:         logger,
		}
		sm.initializeFirewallRules()
	}

	// Start cleanup routines
	go sm.cleanupRoutine()
	go sm.monitoringRoutine()

	return sm, nil
}

// ValidateRequest validates an incoming request
func (sm *SecurityManager) ValidateRequest(r *http.Request) error {
	ip := sm.getClientIP(r)

	// Check whitelist
	if sm.isWhitelisted(ip) {
		return nil
	}

	// Check blacklist
	if sm.isBlacklisted(ip) {
		sm.metrics.BlockedRequests++
		return fmt.Errorf("IP blacklisted: %s", ip)
	}

	// Check if banned
	if sm.isBanned(ip) {
		sm.metrics.BlockedRequests++
		return fmt.Errorf("IP banned: %s", ip)
	}

	// Rate limiting
	if !sm.checkRateLimit(ip) {
		sm.metrics.RateLimitedRequests++
		return fmt.Errorf("rate limit exceeded for IP: %s", ip)
	}

	// DDoS protection
	if sm.config.EnableDDoSProtection {
		if err := sm.checkDDoSProtection(r); err != nil {
			sm.metrics.DDoSAttacks++
			return err
		}
	}

	// Firewall check
	if sm.config.EnableFirewall {
		if err := sm.firewall.ValidateRequest(r); err != nil {
			sm.metrics.BlockedRequests++
			return err
		}
	}

	// Request size check
	if r.ContentLength > sm.config.RequestSizeLimit {
		return fmt.Errorf("request size exceeds limit")
	}

	// Header validation
	if err := sm.validateHeaders(r); err != nil {
		return err
	}

	sm.metrics.TotalRequests++
	return nil
}

// ValidateConnection validates a P2P connection
func (sm *SecurityManager) ValidateConnection(conn net.Conn) error {
	ip, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return err
	}

	// Check whitelist
	if sm.isWhitelisted(ip) {
		return nil
	}

	// Check blacklist
	if sm.isBlacklisted(ip) {
		return fmt.Errorf("IP blacklisted: %s", ip)
	}

	// Check if banned
	if sm.isBanned(ip) {
		return fmt.Errorf("IP banned: %s", ip)
	}

	// Connection limit per IP
	if sm.getConnectionCount(ip) >= sm.config.MaxConnectionsPerIP {
		return fmt.Errorf("connection limit exceeded for IP: %s", ip)
	}

	// DDoS protection
	if sm.config.EnableDDoSProtection {
		if sm.ddosProtection.isUnderAttack(ip) {
			return fmt.Errorf("potential DDoS from IP: %s", ip)
		}
	}

	sm.trackConnection(ip, conn)
	return nil
}

// AuthenticateAPIKey authenticates an API key
func (sm *SecurityManager) AuthenticateAPIKey(key string) (*APIKeyInfo, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	keyInfo, exists := sm.apiKeys[key]
	if !exists || !keyInfo.Active {
		sm.metrics.AuthFailures++
		return nil, fmt.Errorf("invalid or inactive API key")
	}

	keyInfo.LastUsed = time.Now()
	return keyInfo, nil
}

// GenerateJWT generates a JWT token
func (sm *SecurityManager) GenerateJWT(claims jwt.MapClaims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(sm.jwtSecret)
}

// ValidateJWT validates a JWT token
func (sm *SecurityManager) ValidateJWT(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return sm.jwtSecret, nil
	})

	if err != nil {
		sm.metrics.AuthFailures++
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}

	sm.metrics.AuthFailures++
	return nil, fmt.Errorf("invalid token")
}

// BanIP bans an IP address
func (sm *SecurityManager) BanIP(ip string, duration time.Duration) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.bannedIPs[ip] = time.Now().Add(duration)
	sm.metrics.BannedIPs++

	sm.logger.Warn("IP banned",
		zap.String("ip", ip),
		zap.Duration("duration", duration))
}

// UnbanIP unbans an IP address
func (sm *SecurityManager) UnbanIP(ip string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	delete(sm.bannedIPs, ip)
	sm.logger.Info("IP unbanned", zap.String("ip", ip))
}

// checkRateLimit checks if IP has exceeded rate limit
func (sm *SecurityManager) checkRateLimit(ip string) bool {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	limiter, exists := sm.ipRateLimiters[ip]
	if !exists {
		limiter = rate.NewLimiter(rate.Limit(sm.config.MaxRequestsPerIP), sm.config.MaxRequestsPerIP)
		sm.ipRateLimiters[ip] = limiter
	}

	return limiter.Allow()
}

// isWhitelisted checks if IP is whitelisted
func (sm *SecurityManager) isWhitelisted(ip string) bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.whitelistIPs[ip]
}

// isBlacklisted checks if IP is blacklisted
func (sm *SecurityManager) isBlacklisted(ip string) bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.blacklistIPs[ip]
}

// isBanned checks if IP is currently banned
func (sm *SecurityManager) isBanned(ip string) bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	banTime, exists := sm.bannedIPs[ip]
	if !exists {
		return false
	}

	if time.Now().After(banTime) {
		delete(sm.bannedIPs, ip)
		return false
	}

	return true
}

// checkDDoSProtection checks for DDoS patterns
func (sm *SecurityManager) checkDDoSProtection(r *http.Request) error {
	if sm.ddosProtection == nil {
		return nil
	}

	ip := sm.getClientIP(r)

	// Check emergency mode
	if sm.ddosProtection.emergencyMode {
		if !sm.isWhitelisted(ip) {
			return fmt.Errorf("emergency mode: blocking non-whitelisted traffic")
		}
	}

	// Check challenge mode
	if sm.ddosProtection.challengeMode {
		if !sm.validateChallenge(r) {
			return fmt.Errorf("challenge validation failed")
		}
	}

	// Analyze request patterns
	if sm.ddosProtection.detectAnomalousPattern(r) {
		sm.recordSuspiciousActivity(ip, "anomalous_pattern", r.URL.Path)
		return fmt.Errorf("anomalous request pattern detected")
	}

	// Check for amplification attacks
	if sm.detectAmplificationAttack(r) {
		sm.recordSuspiciousActivity(ip, "amplification_attack", "")
		return fmt.Errorf("potential amplification attack")
	}

	// Check for slowloris attacks
	if sm.detectSlowlorisAttack(ip) {
		sm.recordSuspiciousActivity(ip, "slowloris_attack", "")
		return fmt.Errorf("potential slowloris attack")
	}

	return nil
}

// DDoS detection methods
func (dp *DDoSProtection) isUnderAttack(ip string) bool {
	dp.mu.RLock()
	defer dp.mu.RUnlock()

	if activity, exists := dp.suspiciousIPs[ip]; exists {
		return activity.Blocked && time.Now().Before(activity.BlockedUntil)
	}
	return false
}

func (dp *DDoSProtection) detectAnomalousPattern(r *http.Request) bool {
	dp.mu.Lock()
	defer dp.mu.Unlock()

	pattern := fmt.Sprintf("%s:%s", r.Method, r.URL.Path)
	info, exists := dp.requestPatterns[pattern]

	if !exists {
		dp.requestPatterns[pattern] = &PatternInfo{
			Pattern:  pattern,
			Count:    1,
			LastSeen: time.Now(),
			Sources:  map[string]int{r.RemoteAddr: 1},
		}
		return false
	}

	info.Count++
	info.Sources[r.RemoteAddr]++

	// Calculate request rate
	interval := time.Since(info.LastSeen)
	if interval < time.Second && info.Count > 100 {
		return true // More than 100 requests per second for same pattern
	}

	info.LastSeen = time.Now()
	info.AverageInterval = interval / time.Duration(info.Count)

	return false
}

// validateChallenge validates proof-of-work challenge
func (sm *SecurityManager) validateChallenge(r *http.Request) bool {
	challenge := r.Header.Get("X-Challenge-Response")
	if challenge == "" {
		return false
	}

	// Validate the challenge response
	expected := sm.generateChallenge(sm.getClientIP(r))
	return hmac.Equal([]byte(challenge), []byte(expected))
}

// generateChallenge generates a proof-of-work challenge
func (sm *SecurityManager) generateChallenge(ip string) string {
	data := fmt.Sprintf("%s:%d", ip, time.Now().Unix())
	h := hmac.New(sha256.New, sm.jwtSecret)
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

// detectAmplificationAttack detects amplification attacks
func (sm *SecurityManager) detectAmplificationAttack(r *http.Request) bool {
	// Check for small request with large expected response
	if r.ContentLength < 100 && r.URL.Query().Get("limit") == "999999" {
		return true
	}

	// Check for reflection attack patterns
	if r.Header.Get("X-Forwarded-For") != "" && r.Method == "GET" {
		paths := []string{"/api/blocks", "/api/transactions", "/api/mempool"}
		for _, path := range paths {
			if r.URL.Path == path && r.URL.Query().Get("full") == "true" {
				return true
			}
		}
	}

	return false
}

// detectSlowlorisAttack detects slowloris attacks
func (sm *SecurityManager) detectSlowlorisAttack(ip string) bool {
	connInfo := sm.getConnectionInfo(ip)
	if connInfo == nil {
		return false
	}

	// Check for many slow connections
	if connInfo.ConnectionCount > 10 {
		avgBytesPerConn := connInfo.BytesReceived / int64(connInfo.ConnectionCount)
		if avgBytesPerConn < 100 && time.Since(connInfo.FirstSeen) > 30*time.Second {
			return true
		}
	}

	return false
}

// validateHeaders validates request headers
func (sm *SecurityManager) validateHeaders(r *http.Request) error {
	// Check header size
	headerSize := 0
	for key, values := range r.Header {
		headerSize += len(key)
		for _, value := range values {
			headerSize += len(value)
		}
	}

	if headerSize > sm.config.HeaderSizeLimit {
		return fmt.Errorf("header size exceeds limit")
	}

	// Check for malicious headers
	suspiciousHeaders := []string{
		"X-Forwarded-Host",
		"X-Original-URL",
		"X-Rewrite-URL",
	}

	for _, header := range suspiciousHeaders {
		if value := r.Header.Get(header); value != "" {
			// Check for path traversal attempts
			if containsPathTraversal(value) {
				return fmt.Errorf("potential path traversal in header")
			}
		}
	}

	return nil
}

// Helper functions
func (sm *SecurityManager) getClientIP(r *http.Request) string {
	// Try X-Real-IP first
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}

	// Try X-Forwarded-For
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		// Take the first IP in the chain
		if idx := len(ip) - 1; idx >= 0 {
			return ip[:idx]
		}
	}

	// Fall back to RemoteAddr
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	return ip
}

func (sm *SecurityManager) getConnectionInfo(ip string) *ConnectionInfo {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	if sm.ddosProtection == nil {
		return nil
	}

	return sm.ddosProtection.connectionTracker[ip]
}

func (sm *SecurityManager) getConnectionCount(ip string) int {
	info := sm.getConnectionInfo(ip)
	if info == nil {
		return 0
	}
	return info.ConnectionCount
}

func (sm *SecurityManager) trackConnection(ip string, conn net.Conn) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sm.ddosProtection == nil {
		return
	}

	info, exists := sm.ddosProtection.connectionTracker[ip]
	if !exists {
		info = &ConnectionInfo{
			IP:        ip,
			FirstSeen: time.Now(),
		}
		sm.ddosProtection.connectionTracker[ip] = info
	}

	info.ConnectionCount++
	info.LastSeen = time.Now()
	sm.metrics.ActiveConnections++
}

func (sm *SecurityManager) recordSuspiciousActivity(ip, activityType, evidence string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sm.ddosProtection == nil {
		return
	}

	activity, exists := sm.ddosProtection.suspiciousIPs[ip]
	if !exists {
		activity = &SuspiciousActivity{
			IP:            ip,
			FirstDetected: time.Now(),
			Types:         []string{},
			Evidence:      []string{},
		}
		sm.ddosProtection.suspiciousIPs[ip] = activity
	}

	activity.LastDetected = time.Now()
	activity.ActivityCount++
	activity.Types = append(activity.Types, activityType)
	if evidence != "" {
		activity.Evidence = append(activity.Evidence, evidence)
	}
	activity.Score += 10

	// Auto-ban if score is too high
	if activity.Score >= 100 {
		activity.Blocked = true
		activity.BlockedUntil = time.Now().Add(sm.config.BanDuration)
		sm.BanIP(ip, sm.config.BanDuration)
	}

	sm.metrics.SuspiciousActivity++
}

// Firewall methods
func (sm *SecurityManager) initializeFirewallRules() {
	// Default firewall rules
	rules := []*FirewallRule{
		{
			ID:          "rule-1",
			Priority:    1,
			Type:        "ALLOW",
			Source:      "WHITELIST",
			Target:      "ALL",
			Action:      "ACCEPT",
			Enabled:     true,
			Description: "Allow whitelisted IPs",
		},
		{
			ID:          "rule-2",
			Priority:    2,
			Type:        "DENY",
			Source:      "BLACKLIST",
			Target:      "ALL",
			Action:      "DROP",
			Enabled:     true,
			Description: "Block blacklisted IPs",
		},
		{
			ID:          "rule-3",
			Priority:    10,
			Type:        "RATE_LIMIT",
			Source:      "ALL",
			Target:      "RPC",
			Action:      "LIMIT",
			RateLimit:   100,
			Enabled:     true,
			Description: "Rate limit RPC endpoints",
		},
	}

	sm.firewall.rules = rules
}

func (fw *Firewall) ValidateRequest(r *http.Request) error {
	fw.mu.RLock()
	defer fw.mu.RUnlock()

	ip, _, _ := net.SplitHostPort(r.RemoteAddr)

	// Check firewall rules
	for _, rule := range fw.rules {
		if !rule.Enabled {
			continue
		}

		if fw.matchRule(rule, ip, r) {
			switch rule.Action {
			case "DROP":
				return fmt.Errorf("firewall: connection dropped by rule %s", rule.ID)
			case "REJECT":
				return fmt.Errorf("firewall: connection rejected by rule %s", rule.ID)
			case "LIMIT":
				// Rate limiting handled elsewhere
				continue
			}
		}
	}

	return nil
}

func (fw *Firewall) matchRule(rule *FirewallRule, ip string, r *http.Request) bool {
	// Simple rule matching logic
	switch rule.Source {
	case "ALL":
		return true
	case "BLACKLIST":
		// Check against blacklist
		return false
	case "WHITELIST":
		// Check against whitelist
		return false
	default:
		// Check specific IP or CIDR
		return rule.Source == ip
	}
}

// cleanupRoutine cleans up expired bans and old data
func (sm *SecurityManager) cleanupRoutine() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		sm.mu.Lock()

		// Clean expired bans
		now := time.Now()
		for ip, banTime := range sm.bannedIPs {
			if now.After(banTime) {
				delete(sm.bannedIPs, ip)
				sm.logger.Info("Ban expired", zap.String("ip", ip))
			}
		}

		// Clean old rate limiters
		for ip, limiter := range sm.ipRateLimiters {
			if limiter.Tokens() == float64(sm.config.MaxRequestsPerIP) {
				delete(sm.ipRateLimiters, ip)
			}
		}

		sm.mu.Unlock()
	}
}

// monitoringRoutine monitors security metrics
func (sm *SecurityManager) monitoringRoutine() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		sm.mu.RLock()

		// Log security metrics
		sm.logger.Info("Security metrics",
			zap.Uint64("total_requests", sm.metrics.TotalRequests),
			zap.Uint64("blocked_requests", sm.metrics.BlockedRequests),
			zap.Uint64("rate_limited", sm.metrics.RateLimitedRequests),
			zap.Uint64("ddos_attacks", sm.metrics.DDoSAttacks),
			zap.Uint64("auth_failures", sm.metrics.AuthFailures),
			zap.Int("banned_ips", len(sm.bannedIPs)),
			zap.Uint64("active_connections", sm.metrics.ActiveConnections),
		)

		// Check for attack patterns
		if sm.metrics.DDoSAttacks > 10 && !sm.ddosProtection.emergencyMode {
			sm.ddosProtection.emergencyMode = true
			sm.logger.Warn("Emergency mode activated due to DDoS attacks")
		}

		sm.mu.RUnlock()
	}
}

// Utility functions
func containsPathTraversal(s string) bool {
	dangerous := []string{"../", "..\\", "%2e%2e", "..%2F", "..%5C"}
	for _, pattern := range dangerous {
		if len(s) >= len(pattern) && s[:len(pattern)] == pattern {
			return true
		}
	}
	return false
}

// HashPassword hashes a password using Argon2
func HashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	hash := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)

	return fmt.Sprintf("%x:%x", salt, hash), nil
}

// VerifyPassword verifies a password against its hash
func VerifyPassword(password, hashStr string) bool {
	parts := make([]string, 2)
	fmt.Sscanf(hashStr, "%s:%s", &parts[0], &parts[1])

	salt, _ := hex.DecodeString(parts[0])
	hash, _ := hex.DecodeString(parts[1])

	computedHash := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)

	return hmac.Equal(hash, computedHash)
}

// GenerateSecureToken generates a secure random token
func GenerateSecureToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// GetMetrics returns security metrics
func (sm *SecurityManager) GetMetrics() *SecurityMetrics {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.metrics
}

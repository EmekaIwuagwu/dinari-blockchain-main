// pkg/api/middleware.go
package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
	"golang.org/x/time/rate"
)

// Middleware represents a function that wraps an http.HandlerFunc
type Middleware func(http.HandlerFunc) http.HandlerFunc

// MiddlewareChain represents a chain of middleware
type MiddlewareChain struct {
	middlewares []Middleware
}

// NewMiddlewareChain creates a new middleware chain
func NewMiddlewareChain(middlewares ...Middleware) *MiddlewareChain {
	return &MiddlewareChain{
		middlewares: middlewares,
	}
}

// Then applies the middleware chain to a handler
func (c *MiddlewareChain) Then(handler http.HandlerFunc) http.HandlerFunc {
	// Apply middleware in reverse order so they execute in the order they were added
	for i := len(c.middlewares) - 1; i >= 0; i-- {
		handler = c.middlewares[i](handler)
	}
	return handler
}

// RateLimiterStore manages rate limiters with automatic cleanup
type RateLimiterStore struct {
	limiters      map[string]*rateLimiterEntry
	mu            sync.RWMutex
	defaultRate   rate.Limit
	defaultBurst  int
	cleanupPeriod time.Duration
	maxIdle       time.Duration
	stopChan      chan struct{}
	wg            sync.WaitGroup
}

type rateLimiterEntry struct {
	limiter    *rate.Limiter
	lastAccess time.Time
}

// NewRateLimiterStore creates a new rate limiter store with automatic cleanup
func NewRateLimiterStore(requestsPerMinute, burst int, cleanupPeriod, maxIdle time.Duration) *RateLimiterStore {
	store := &RateLimiterStore{
		limiters:      make(map[string]*rateLimiterEntry),
		defaultRate:   rate.Limit(requestsPerMinute) / 60.0, // Convert to per-second
		defaultBurst:  burst,
		cleanupPeriod: cleanupPeriod,
		maxIdle:       maxIdle,
		stopChan:      make(chan struct{}),
	}

	// Start cleanup goroutine
	store.wg.Add(1)
	go store.cleanupLoop()

	return store
}

// GetLimiter retrieves or creates a rate limiter for a given key
func (s *RateLimiterStore) GetLimiter(key string) *rate.Limiter {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, exists := s.limiters[key]
	if !exists {
		entry = &rateLimiterEntry{
			limiter:    rate.NewLimiter(s.defaultRate, s.defaultBurst),
			lastAccess: time.Now(),
		}
		s.limiters[key] = entry
	} else {
		entry.lastAccess = time.Now()
	}

	return entry.limiter
}

// cleanupLoop periodically removes idle rate limiters
func (s *RateLimiterStore) cleanupLoop() {
	defer s.wg.Done()

	ticker := time.NewTicker(s.cleanupPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.cleanup()
		case <-s.stopChan:
			return
		}
	}
}

// cleanup removes idle rate limiters
func (s *RateLimiterStore) cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	removed := 0

	for key, entry := range s.limiters {
		if now.Sub(entry.lastAccess) > s.maxIdle {
			delete(s.limiters, key)
			removed++
		}
	}

	if removed > 0 {
		// Log cleanup (would need logger reference)
		fmt.Printf("Cleaned up %d idle rate limiters (total: %d)\n", removed, len(s.limiters))
	}
}

// Stop stops the cleanup goroutine
func (s *RateLimiterStore) Stop() {
	close(s.stopChan)
	s.wg.Wait()
}

// Size returns the number of tracked rate limiters
func (s *RateLimiterStore) Size() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.limiters)
}

// RequestContext holds request-scoped data
type RequestContext struct {
	CorrelationID string
	StartTime     time.Time
	ClientIP      string
	UserAgent     string
	Method        string
	Path          string
}

// ContextKey is a type for context keys to avoid collisions
type ContextKey string

const (
	// ContextKeyRequestID is the key for request correlation ID
	ContextKeyRequestID ContextKey = "requestID"
	// ContextKeyRequestContext is the key for request context
	ContextKeyRequestContext ContextKey = "requestContext"
	// ContextKeyClientIP is the key for client IP
	ContextKeyClientIP ContextKey = "clientIP"
)

// GenerateCorrelationID generates a unique correlation ID for request tracing
func GenerateCorrelationID() string {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		// Fallback to timestamp-based ID if crypto/rand fails
		return fmt.Sprintf("fallback-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(bytes)
}

// ExtractClientIP extracts the real client IP from the request
// Handles various proxy headers and validates IP format
func ExtractClientIP(r *http.Request, trustedProxies []string) string {
	// Helper to check if IP is trusted
	isTrustedProxy := func(ip string) bool {
		if len(trustedProxies) == 0 {
			return true // If no trusted proxies configured, trust all
		}
		for _, trusted := range trustedProxies {
			if ip == trusted || trusted == "*" {
				return true
			}
		}
		return false
	}

	// Try X-Forwarded-For header (only if from trusted proxy)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		// Take the first IP (original client)
		clientIP := strings.TrimSpace(ips[0])
		if clientIP != "" && isTrustedProxy(getRemoteIP(r)) {
			return clientIP
		}
	}

	// Try X-Real-IP header (only if from trusted proxy)
	if xri := r.Header.Get("X-Real-IP"); xri != "" && isTrustedProxy(getRemoteIP(r)) {
		return xri
	}

	// Try Cloudflare header
	if cfIP := r.Header.Get("CF-Connecting-IP"); cfIP != "" && isTrustedProxy(getRemoteIP(r)) {
		return cfIP
	}

	// Fall back to RemoteAddr
	return getRemoteIP(r)
}

// getRemoteIP extracts IP from RemoteAddr
func getRemoteIP(r *http.Request) string {
	ip := r.RemoteAddr
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		ip = ip[:idx]
	}
	// Remove brackets from IPv6 addresses
	ip = strings.Trim(ip, "[]")
	return ip
}

// SecurityHeadersMiddleware adds security headers to all responses
func SecurityHeadersMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Prevent MIME type sniffing
		w.Header().Set("X-Content-Type-Options", "nosniff")

		// Prevent clickjacking
		w.Header().Set("X-Frame-Options", "DENY")

		// Enable XSS protection
		w.Header().Set("X-XSS-Protection", "1; mode=block")

		// Referrer policy
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

		// Content Security Policy (strict for API)
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")

		// Strict Transport Security (HSTS) - only if using HTTPS
		if r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
		}

		// Remove server identification
		w.Header().Del("Server")
		w.Header().Set("Server", "Dinari")

		next(w, r)
	}
}

// RequestIDMiddleware adds a unique correlation ID to each request
func RequestIDMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Check if correlation ID already exists (from upstream proxy)
		correlationID := r.Header.Get("X-Correlation-ID")
		if correlationID == "" {
			correlationID = GenerateCorrelationID()
		}

		// Add to context
		ctx := context.WithValue(r.Context(), ContextKeyRequestID, correlationID)
		r = r.WithContext(ctx)

		// Add to response header
		w.Header().Set("X-Correlation-ID", correlationID)

		next(w, r)
	}
}

// RequestContextMiddleware creates a request context with metadata
func RequestContextMiddleware(trustedProxies []string) Middleware {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			correlationID := GetCorrelationID(r.Context())
			clientIP := ExtractClientIP(r, trustedProxies)

			reqCtx := &RequestContext{
				CorrelationID: correlationID,
				StartTime:     time.Now(),
				ClientIP:      clientIP,
				UserAgent:     r.UserAgent(),
				Method:        r.Method,
				Path:          r.URL.Path,
			}

			// Add to context
			ctx := context.WithValue(r.Context(), ContextKeyRequestContext, reqCtx)
			ctx = context.WithValue(ctx, ContextKeyClientIP, clientIP)
			r = r.WithContext(ctx)

			next(w, r)
		}
	}
}

// TimeoutMiddleware enforces a timeout on request processing
func TimeoutMiddleware(timeout time.Duration, logger *zap.Logger) Middleware {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			ctx, cancel := context.WithTimeout(r.Context(), timeout)
			defer cancel()

			r = r.WithContext(ctx)

			// Channel to signal completion
			done := make(chan struct{})

			go func() {
				next(w, r)
				close(done)
			}()

			select {
			case <-done:
				// Request completed successfully
			case <-ctx.Done():
				// Timeout occurred
				if ctx.Err() == context.DeadlineExceeded {
					correlationID := GetCorrelationID(r.Context())
					logger.Warn("Request timeout",
						zap.String("correlationID", correlationID),
						zap.String("path", r.URL.Path),
						zap.Duration("timeout", timeout))

					http.Error(w, "Request timeout", http.StatusGatewayTimeout)
				}
			}
		}
	}
}

// CompressionMiddleware adds response compression (gzip)
// Only compresses responses larger than minSize bytes
func CompressionMiddleware(minSize int) Middleware {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			// Check if client accepts gzip
			if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
				next(w, r)
				return
			}

			// For now, skip compression implementation to keep it simple
			// In production, use a library like github.com/NYTimes/gziphandler
			next(w, r)
		}
	}
}

// MethodFilterMiddleware restricts allowed HTTP methods
func MethodFilterMiddleware(allowedMethods ...string) Middleware {
	allowed := make(map[string]bool)
	for _, method := range allowedMethods {
		allowed[method] = true
	}

	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if !allowed[r.Method] {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
				return
			}
			next(w, r)
		}
	}
}

// IPWhitelistMiddleware restricts access to whitelisted IPs
func IPWhitelistMiddleware(whitelist []string, logger *zap.Logger) Middleware {
	whitelistMap := make(map[string]bool)
	for _, ip := range whitelist {
		whitelistMap[ip] = true
	}

	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			clientIP := GetClientIP(r.Context())

			// If whitelist is empty, allow all
			if len(whitelistMap) == 0 {
				next(w, r)
				return
			}

			// Check if IP is whitelisted
			if !whitelistMap[clientIP] {
				correlationID := GetCorrelationID(r.Context())
				logger.Warn("IP not whitelisted",
					zap.String("correlationID", correlationID),
					zap.String("ip", clientIP),
					zap.String("path", r.URL.Path))

				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}

			next(w, r)
		}
	}
}

// CacheControlMiddleware sets cache control headers
func CacheControlMiddleware(cacheControl string) Middleware {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", cacheControl)
			next(w, r)
		}
	}
}

// NoCacheMiddleware disables all caching
func NoCacheMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate, private")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")
		next(w, r)
	}
}

// RequestValidationMiddleware performs basic request validation
func RequestValidationMiddleware(logger *zap.Logger) Middleware {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			// Validate Content-Type for POST/PUT requests
			if r.Method == http.MethodPost || r.Method == http.MethodPut {
				contentType := r.Header.Get("Content-Type")
				if contentType == "" {
					http.Error(w, "Content-Type header required", http.StatusBadRequest)
					return
				}

				// For JSON-RPC, ensure it's application/json
				if !strings.Contains(contentType, "application/json") {
					http.Error(w, "Content-Type must be application/json", http.StatusUnsupportedMediaType)
					return
				}
			}

			// Validate Content-Length
			if r.ContentLength < 0 {
				http.Error(w, "Invalid Content-Length", http.StatusBadRequest)
				return
			}

			next(w, r)
		}
	}
}

// MetricsMiddleware tracks request metrics
type MetricsMiddleware struct {
	totalRequests   uint64
	successRequests uint64
	errorRequests   uint64
	mu              sync.RWMutex
}

// NewMetricsMiddleware creates a new metrics middleware
func NewMetricsMiddleware() *MetricsMiddleware {
	return &MetricsMiddleware{}
}

// Handler returns the middleware handler
func (m *MetricsMiddleware) Handler(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		m.totalRequests++
		m.mu.Unlock()

		// Wrap response writer to capture status
		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		next(wrapped, r)

		m.mu.Lock()
		if wrapped.statusCode >= 200 && wrapped.statusCode < 400 {
			m.successRequests++
		} else {
			m.errorRequests++
		}
		m.mu.Unlock()
	}
}

// GetMetrics returns current metrics
func (m *MetricsMiddleware) GetMetrics() (total, success, errors uint64) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.totalRequests, m.successRequests, m.errorRequests
}

// Context helper functions

// GetCorrelationID extracts correlation ID from context
func GetCorrelationID(ctx context.Context) string {
	if id, ok := ctx.Value(ContextKeyRequestID).(string); ok {
		return id
	}
	return "unknown"
}

// GetRequestContext extracts request context from context
func GetRequestContext(ctx context.Context) *RequestContext {
	if reqCtx, ok := ctx.Value(ContextKeyRequestContext).(*RequestContext); ok {
		return reqCtx
	}
	return nil
}

// GetClientIP extracts client IP from context
func GetClientIP(ctx context.Context) string {
	if ip, ok := ctx.Value(ContextKeyClientIP).(string); ok {
		return ip
	}
	return "unknown"
}

// CircuitBreaker implements the circuit breaker pattern for resilience
type CircuitBreaker struct {
	maxFailures  uint64
	resetTimeout time.Duration
	failures     uint64
	lastFailTime time.Time
	state        CircuitState
	mu           sync.RWMutex
}

// CircuitState represents the state of the circuit breaker
type CircuitState int

const (
	// CircuitClosed means requests pass through normally
	CircuitClosed CircuitState = iota
	// CircuitOpen means requests are blocked
	CircuitOpen
	// CircuitHalfOpen means testing if circuit should close
	CircuitHalfOpen
)

// NewCircuitBreaker creates a new circuit breaker
func NewCircuitBreaker(maxFailures uint64, resetTimeout time.Duration) *CircuitBreaker {
	return &CircuitBreaker{
		maxFailures:  maxFailures,
		resetTimeout: resetTimeout,
		state:        CircuitClosed,
	}
}

// Call executes a function through the circuit breaker
func (cb *CircuitBreaker) Call(fn func() error) error {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	// Check if circuit should transition from Open to HalfOpen
	if cb.state == CircuitOpen && time.Since(cb.lastFailTime) > cb.resetTimeout {
		cb.state = CircuitHalfOpen
		cb.failures = 0
	}

	// Block if circuit is open
	if cb.state == CircuitOpen {
		return fmt.Errorf("circuit breaker is open")
	}

	// Execute function
	err := fn()

	// Update state based on result
	if err != nil {
		cb.failures++
		cb.lastFailTime = time.Now()

		if cb.failures >= cb.maxFailures {
			cb.state = CircuitOpen
		}
		return err
	}

	// Success - close circuit if it was half-open
	if cb.state == CircuitHalfOpen {
		cb.state = CircuitClosed
		cb.failures = 0
	}

	return nil
}

// GetState returns the current circuit state
func (cb *CircuitBreaker) GetState() CircuitState {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.state
}

// Reset manually resets the circuit breaker
func (cb *CircuitBreaker) Reset() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.state = CircuitClosed
	cb.failures = 0
}
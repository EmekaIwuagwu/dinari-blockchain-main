// pkg/api/server.go
package api

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/EmekaIwuagwu/dinari-blockchain/internal/core"
	"github.com/EmekaIwuagwu/dinari-blockchain/internal/mempool"
	"github.com/EmekaIwuagwu/dinari-blockchain/internal/miner"
	"go.uber.org/zap"
	"golang.org/x/time/rate"
)

const (
	// Server limits
	MaxRequestSize        = 1 * 1024 * 1024 // 1MB
	MaxConcurrentRequests = 1000
	ReadTimeout           = 15 * time.Second
	WriteTimeout          = 30 * time.Second
	IdleTimeout           = 120 * time.Second
	ShutdownTimeout       = 30 * time.Second

	// Rate limiting defaults (can be overridden by config)
	DefaultRateLimit       = 100  // requests per minute per IP
	DefaultRateLimitBurst  = 20   // burst capacity
	DefaultGlobalRateLimit = 5000 // total requests per minute

	// Security
	DefaultAuthTokenHeader = "X-Dinari-Auth-Token"
	MinAuthTokenLength     = 32
)

// RPCServer implements a production-grade JSON-RPC 2.0 API server
type RPCServer struct {
	// Core components
	blockchain *core.Blockchain
	mempool    *mempool.Mempool
	miner      *miner.Miner
	logger     *zap.Logger

	// HTTP server
	server *http.Server

	// Configuration
	config *ServerConfig

	// Rate limiting
	rateLimiters     map[string]*rate.Limiter // Per-IP rate limiters
	globalLimiter    *rate.Limiter            // Global rate limiter
	rateLimiterMutex sync.RWMutex
	cleanupTicker    *time.Ticker

	// Security
	authToken      string
	tlsConfig      *tls.Config
	allowedOrigins map[string]bool

	// Metrics
	metrics *ServerMetrics

	// Graceful shutdown
	shutdownChan chan struct{}
	wg           sync.WaitGroup
}

// ServerConfig contains production server configuration
type ServerConfig struct {
	// Network
	Address       string
	TLSEnabled    bool
	TLSCertFile   string
	TLSKeyFile    string
	AutoTLS       bool // Auto-generate self-signed cert for development

	// Security
	AuthToken          string
	AuthTokenHeader    string
	RequireAuth        bool
	AllowedOrigins     []string
	TrustedProxies     []string

	// Rate Limiting
	RateLimitPerMinute int
	RateLimitBurst     int
	GlobalRateLimit    int
	EnableRateLimiting bool

	// Request limits
	MaxRequestSize int64
	MaxConcurrent  int

	// Timeouts
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	IdleTimeout     time.Duration
	ShutdownTimeout time.Duration

	// Blockchain components
	Blockchain *core.Blockchain
	Mempool    *mempool.Mempool
	Miner      *miner.Miner
	Logger     *zap.Logger
}

// ServerMetrics tracks server performance metrics
type ServerMetrics struct {
	TotalRequests       uint64
	SuccessfulRequests  uint64
	FailedRequests      uint64
	RateLimitedRequests uint64
	AuthFailures        uint64
	AverageResponseTime time.Duration
	mu                  sync.RWMutex
}

// DefaultServerConfig returns production-ready default configuration
func DefaultServerConfig() *ServerConfig {
	return &ServerConfig{
		Address:             getEnv("DINARI_RPC_ADDR", "localhost:8545"),
		TLSEnabled:          getEnvBool("DINARI_RPC_TLS_ENABLED", false),
		TLSCertFile:         getEnv("DINARI_RPC_TLS_CERT", ""),
		TLSKeyFile:          getEnv("DINARI_RPC_TLS_KEY", ""),
		AutoTLS:             getEnvBool("DINARI_RPC_AUTO_TLS", false),
		AuthToken:           getEnv("DINARI_RPC_AUTH_TOKEN", ""),
		AuthTokenHeader:     getEnv("DINARI_RPC_AUTH_HEADER", DefaultAuthTokenHeader),
		RequireAuth:         getEnvBool("DINARI_RPC_REQUIRE_AUTH", false),
		AllowedOrigins:      getEnvSlice("DINARI_RPC_ALLOWED_ORIGINS", []string{"*"}),
		TrustedProxies:      getEnvSlice("DINARI_RPC_TRUSTED_PROXIES", []string{}),
		RateLimitPerMinute:  getEnvInt("DINARI_RATE_LIMIT_PER_MINUTE", DefaultRateLimit),
		RateLimitBurst:      getEnvInt("DINARI_RATE_LIMIT_BURST", DefaultRateLimitBurst),
		GlobalRateLimit:     getEnvInt("DINARI_GLOBAL_RATE_LIMIT", DefaultGlobalRateLimit),
		EnableRateLimiting:  getEnvBool("DINARI_ENABLE_RATE_LIMITING", true),
		MaxRequestSize:      int64(getEnvInt("DINARI_MAX_REQUEST_SIZE", int(MaxRequestSize))),
		MaxConcurrent:       getEnvInt("DINARI_MAX_CONCURRENT", MaxConcurrentRequests),
		ReadTimeout:         time.Duration(getEnvInt("DINARI_READ_TIMEOUT_SEC", 15)) * time.Second,
		WriteTimeout:        time.Duration(getEnvInt("DINARI_WRITE_TIMEOUT_SEC", 30)) * time.Second,
		IdleTimeout:         time.Duration(getEnvInt("DINARI_IDLE_TIMEOUT_SEC", 120)) * time.Second,
		ShutdownTimeout:     time.Duration(getEnvInt("DINARI_SHUTDOWN_TIMEOUT_SEC", 30)) * time.Second,
	}
}

// NewRPCServer creates a new production-grade RPC server
func NewRPCServer(config *ServerConfig) (*RPCServer, error) {
	// Validate configuration
	if err := validateConfig(config); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	// Validate auth token if required
	if config.RequireAuth {
		if len(config.AuthToken) < MinAuthTokenLength {
			return nil, fmt.Errorf("auth token must be at least %d characters", MinAuthTokenLength)
		}
	}

	// Build allowed origins map
	allowedOrigins := make(map[string]bool)
	for _, origin := range config.AllowedOrigins {
		allowedOrigins[origin] = true
	}

	// Create TLS config if enabled
	var tlsConfig *tls.Config
	if config.TLSEnabled {
		var err error
		tlsConfig, err = createTLSConfig(config)
		if err != nil {
			return nil, fmt.Errorf("failed to create TLS config: %w", err)
		}
	}

	server := &RPCServer{
		blockchain:       config.Blockchain,
		mempool:          config.Mempool,
		miner:            config.Miner,
		logger:           config.Logger,
		config:           config,
		rateLimiters:     make(map[string]*rate.Limiter),
		globalLimiter:    rate.NewLimiter(rate.Limit(config.GlobalRateLimit)/60.0, config.GlobalRateLimit),
		authToken:        config.AuthToken,
		tlsConfig:        tlsConfig,
		allowedOrigins:   allowedOrigins,
		metrics:          &ServerMetrics{},
		shutdownChan:     make(chan struct{}),
	}

	// Start rate limiter cleanup goroutine
	if config.EnableRateLimiting {
		server.cleanupTicker = time.NewTicker(5 * time.Minute)
		server.wg.Add(1)
		go server.cleanupRateLimiters()
	}

	config.Logger.Info("RPC server initialized",
		zap.String("address", config.Address),
		zap.Bool("tlsEnabled", config.TLSEnabled),
		zap.Bool("authRequired", config.RequireAuth),
		zap.Bool("rateLimiting", config.EnableRateLimiting),
		zap.Int("rateLimit", config.RateLimitPerMinute))

	return server, nil
}

// Start starts the RPC server
func (s *RPCServer) Start() error {
	mux := http.NewServeMux()

	// Apply middleware chain (order matters!)
	handler := s.loggingMiddleware(
		s.recoveryMiddleware(
			s.rateLimitMiddleware(
				s.authMiddleware(
					s.corsMiddleware(
						s.requestSizeLimitMiddleware(
							s.handleRPC))))))

	mux.HandleFunc("/", handler)
	mux.HandleFunc("/health", s.corsMiddleware(s.handleHealth))
	mux.HandleFunc("/metrics", s.corsMiddleware(s.handleMetrics))

	// Create HTTP server with production settings
	s.server = &http.Server{
		Addr:           s.config.Address,
		Handler:        mux,
		ReadTimeout:    s.config.ReadTimeout,
		WriteTimeout:   s.config.WriteTimeout,
		IdleTimeout:    s.config.IdleTimeout,
		MaxHeaderBytes: 1 << 20, // 1MB
		TLSConfig:      s.tlsConfig,
		ErrorLog:       nil, // Disable default error logging (we use zap)
		ConnState: func(conn net.Conn, state http.ConnState) {
			// Track connection states for monitoring
			if state == http.StateNew {
				s.logger.Debug("New connection", zap.String("remote", conn.RemoteAddr().String()))
			}
		},
	}

	s.logger.Info("🚀 RPC server starting",
		zap.String("address", s.config.Address),
		zap.Bool("tls", s.config.TLSEnabled),
		zap.Bool("auth", s.config.RequireAuth))

	// Start server
	var err error
	if s.config.TLSEnabled {
		err = s.server.ListenAndServeTLS(s.config.TLSCertFile, s.config.TLSKeyFile)
	} else {
		err = s.server.ListenAndServe()
	}

	if err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("server error: %w", err)
	}

	return nil
}

// Stop gracefully stops the RPC server
func (s *RPCServer) Stop() error {
	s.logger.Info("🛑 Shutting down RPC server...")

	// Signal shutdown
	close(s.shutdownChan)

	// Stop cleanup ticker
	if s.cleanupTicker != nil {
		s.cleanupTicker.Stop()
	}

	// Wait for background goroutines
	s.wg.Wait()

	// Shutdown HTTP server with timeout
	ctx, cancel := context.WithTimeout(context.Background(), s.config.ShutdownTimeout)
	defer cancel()

	if err := s.server.Shutdown(ctx); err != nil {
		s.logger.Error("Error during server shutdown", zap.Error(err))
		return err
	}

	s.logger.Info("✅ RPC server stopped successfully")
	return nil
}

// Middleware implementations

// loggingMiddleware logs all requests with correlation IDs
func (s *RPCServer) loggingMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		
		// Generate correlation ID
		correlationID := fmt.Sprintf("%d-%s", time.Now().UnixNano(), generateShortID())
		
		// Add to context
		ctx := context.WithValue(r.Context(), "correlationID", correlationID)
		r = r.WithContext(ctx)

		// Add to response headers
		w.Header().Set("X-Correlation-ID", correlationID)

		// Wrap response writer to capture status code
		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		// Process request
		next(wrapped, r)

		// Log request
		duration := time.Since(start)
		s.logger.Info("HTTP request",
			zap.String("correlationID", correlationID),
			zap.String("method", r.Method),
			zap.String("path", r.URL.Path),
			zap.String("remote", getRealIP(r)),
			zap.Int("status", wrapped.statusCode),
			zap.Duration("duration", duration),
			zap.Int64("size", wrapped.bytesWritten))

		// Update metrics
		s.updateMetrics(wrapped.statusCode, duration)
	}
}

// recoveryMiddleware recovers from panics
func (s *RPCServer) recoveryMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				correlationID := getCorrelationID(r.Context())
				
				s.logger.Error("🚨 PANIC recovered",
					zap.String("correlationID", correlationID),
					zap.Any("error", err),
					zap.Stack("stack"))

				s.writeError(w, nil, -32603, "Internal server error")
			}
		}()
		next(w, r)
	}
}

// rateLimitMiddleware implements per-IP and global rate limiting
func (s *RPCServer) rateLimitMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.config.EnableRateLimiting {
			next(w, r)
			return
		}

		ip := getRealIP(r)

		// Check global rate limit first
		if !s.globalLimiter.Allow() {
			s.metrics.mu.Lock()
			s.metrics.RateLimitedRequests++
			s.metrics.mu.Unlock()

			s.logger.Warn("Global rate limit exceeded",
				zap.String("ip", ip),
				zap.String("correlationID", getCorrelationID(r.Context())))

			s.writeError(w, nil, -32005, "Rate limit exceeded")
			return
		}

		// Check per-IP rate limit
		limiter := s.getRateLimiter(ip)
		if !limiter.Allow() {
			s.metrics.mu.Lock()
			s.metrics.RateLimitedRequests++
			s.metrics.mu.Unlock()

			s.logger.Warn("IP rate limit exceeded",
				zap.String("ip", ip),
				zap.String("correlationID", getCorrelationID(r.Context())))

			s.writeError(w, nil, -32005, "Rate limit exceeded")
			return
		}

		next(w, r)
	}
}

// authMiddleware validates authentication tokens
func (s *RPCServer) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Skip auth for health/metrics endpoints
		if r.URL.Path == "/health" || r.URL.Path == "/metrics" {
			next(w, r)
			return
		}

		if !s.config.RequireAuth {
			next(w, r)
			return
		}

		// Extract token from header
		token := r.Header.Get(s.config.AuthTokenHeader)
		if token == "" {
			// Also check Authorization header
			auth := r.Header.Get("Authorization")
			if strings.HasPrefix(auth, "Bearer ") {
				token = strings.TrimPrefix(auth, "Bearer ")
			}
		}

		// Validate token using constant-time comparison (prevents timing attacks)
		if token == "" || subtle.ConstantTimeCompare([]byte(token), []byte(s.authToken)) != 1 {
			s.metrics.mu.Lock()
			s.metrics.AuthFailures++
			s.metrics.mu.Unlock()

			s.logger.Warn("Authentication failed",
				zap.String("ip", getRealIP(r)),
				zap.String("correlationID", getCorrelationID(r.Context())))

			s.writeError(w, nil, -32001, "Unauthorized")
			return
		}

		next(w, r)
	}
}

// corsMiddleware handles CORS headers
func (s *RPCServer) corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		
		// Check if origin is allowed
		if origin != "" && (s.allowedOrigins["*"] || s.allowedOrigins[origin]) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, "+s.config.AuthTokenHeader+", Authorization, X-Correlation-ID")
			w.Header().Set("Access-Control-Expose-Headers", "X-Correlation-ID")
			w.Header().Set("Access-Control-Max-Age", "86400") // 24 hours
		}

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next(w, r)
	}
}

// requestSizeLimitMiddleware limits request body size
func (s *RPCServer) requestSizeLimitMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, s.config.MaxRequestSize)
		next(w, r)
	}
}

// Handler implementations

// handleRPC handles JSON-RPC 2.0 requests
func (s *RPCServer) handleRPC(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, nil, -32600, "Invalid request method")
		return
	}

	// Parse request with size limit already enforced by middleware
	var req RPCRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields() // Strict parsing
	
	if err := decoder.Decode(&req); err != nil {
		s.logger.Warn("Failed to parse request",
			zap.String("correlationID", getCorrelationID(r.Context())),
			zap.Error(err))
		s.writeError(w, nil, -32700, "Parse error")
		return
	}

	s.logger.Debug("RPC request",
		zap.String("correlationID", getCorrelationID(r.Context())),
		zap.String("method", req.Method))

	// Route to handler
	result, rpcErr := s.routeRequest(&req, r.Context())

	// Write response
	if rpcErr != nil {
		s.writeError(w, req.ID, rpcErr.Code, rpcErr.Message)
		return
	}

	s.writeResult(w, req.ID, result)
}

// handleHealth provides comprehensive health check
func (s *RPCServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	health := map[string]interface{}{
		"status":     "ok",
		"timestamp":  time.Now().Unix(),
		"version":    "1.0.0",
		"network":    getEnv("DINARI_NETWORK", "testnet"),
	}

	// Add blockchain info
	if s.blockchain != nil {
		health["blockchain"] = map[string]interface{}{
			"height": s.blockchain.GetHeight(),
			"synced": true, // TODO: Implement sync status
		}
	}

	// Add mempool info
	if s.mempool != nil {
		health["mempool"] = map[string]interface{}{
			"size": s.mempool.Size(),
		}
	}

	// Add miner info
	if s.miner != nil {
		health["mining"] = s.miner.IsRunning()
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	json.NewEncoder(w).Encode(health)
}

// handleMetrics exposes server metrics
func (s *RPCServer) handleMetrics(w http.ResponseWriter, r *http.Request) {
	s.metrics.mu.RLock()
	defer s.metrics.mu.RUnlock()

	metrics := map[string]interface{}{
		"total_requests":        s.metrics.TotalRequests,
		"successful_requests":   s.metrics.SuccessfulRequests,
		"failed_requests":       s.metrics.FailedRequests,
		"rate_limited_requests": s.metrics.RateLimitedRequests,
		"auth_failures":         s.metrics.AuthFailures,
		"avg_response_time_ms":  s.metrics.AverageResponseTime.Milliseconds(),
		"active_rate_limiters":  len(s.rateLimiters),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(metrics)
}

// Helper methods

// getRateLimiter gets or creates a rate limiter for an IP
func (s *RPCServer) getRateLimiter(ip string) *rate.Limiter {
	s.rateLimiterMutex.Lock()
	defer s.rateLimiterMutex.Unlock()

	limiter, exists := s.rateLimiters[ip]
	if !exists {
		limiter = rate.NewLimiter(rate.Limit(s.config.RateLimitPerMinute)/60.0, s.config.RateLimitBurst)
		s.rateLimiters[ip] = limiter
	}

	return limiter
}

// cleanupRateLimiters periodically removes unused rate limiters
func (s *RPCServer) cleanupRateLimiters() {
	defer s.wg.Done()

	for {
		select {
		case <-s.cleanupTicker.C:
			s.rateLimiterMutex.Lock()
			// In production, implement more sophisticated cleanup based on last access time
			if len(s.rateLimiters) > 10000 { // Prevent unbounded growth
				s.rateLimiters = make(map[string]*rate.Limiter)
				s.logger.Info("Rate limiter cache cleared")
			}
			s.rateLimiterMutex.Unlock()

		case <-s.shutdownChan:
			return
		}
	}
}

// updateMetrics updates server metrics
func (s *RPCServer) updateMetrics(statusCode int, duration time.Duration) {
	s.metrics.mu.Lock()
	defer s.metrics.mu.Unlock()

	s.metrics.TotalRequests++
	
	if statusCode >= 200 && statusCode < 300 {
		s.metrics.SuccessfulRequests++
	} else {
		s.metrics.FailedRequests++
	}

	// Update rolling average (simple implementation)
	s.metrics.AverageResponseTime = (s.metrics.AverageResponseTime*time.Duration(s.metrics.TotalRequests-1) + duration) / time.Duration(s.metrics.TotalRequests)
}

// writeResult writes a successful JSON-RPC response
func (s *RPCServer) writeResult(w http.ResponseWriter, id interface{}, result interface{}) {
	response := RPCResponse{
		JSONRPC: "2.0",
		Result:  result,
		ID:      id,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// writeError writes an error JSON-RPC response
func (s *RPCServer) writeError(w http.ResponseWriter, id interface{}, code int, message string) {
	response := RPCResponse{
		JSONRPC: "2.0",
		Error: &RPCError{
			Code:    code,
			Message: message,
		},
		ID: id,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK) // JSON-RPC always returns 200
	json.NewEncoder(w).Encode(response)
}

// Utility types and functions

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode   int
	bytesWritten int64
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	n, err := rw.ResponseWriter.Write(b)
	rw.bytesWritten += int64(n)
	return n, err
}

// getRealIP extracts the real client IP, considering proxies
func getRealIP(r *http.Request) string {
	// Check X-Forwarded-For header (most common)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	return ip
}

// getCorrelationID extracts correlation ID from context
func getCorrelationID(ctx context.Context) string {
	if id, ok := ctx.Value("correlationID").(string); ok {
		return id
	}
	return "unknown"
}

// generateShortID generates a short random ID
func generateShortID() string {
	return fmt.Sprintf("%x", time.Now().UnixNano()%0xFFFF)
}

// Validation and configuration helpers

// validateConfig validates server configuration
func validateConfig(config *ServerConfig) error {
	if config.Blockchain == nil {
		return fmt.Errorf("blockchain is required")
	}
	if config.Mempool == nil {
		return fmt.Errorf("mempool is required")
	}
	if config.Miner == nil {
		return fmt.Errorf("miner is required")
	}
	if config.Logger == nil {
		return fmt.Errorf("logger is required")
	}
	if config.Address == "" {
		return fmt.Errorf("address is required")
	}
	if config.TLSEnabled && !config.AutoTLS && (config.TLSCertFile == "" || config.TLSKeyFile == "") {
		return fmt.Errorf("TLS enabled but cert/key files not provided")
	}
	return nil
}

// createTLSConfig creates TLS configuration
func createTLSConfig(config *ServerConfig) (*tls.Config, error) {
	// TODO: Implement auto-TLS with self-signed cert for development
	if config.AutoTLS {
		return nil, fmt.Errorf("auto-TLS not yet implemented")
	}

	// Production TLS configuration
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		},
		PreferServerCipherSuites: true,
	}, nil
}

// Environment variable helpers

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		return value == "true" || value == "1" || value == "yes"
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		var intValue int
		if _, err := fmt.Sscanf(value, "%d", &intValue); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func getEnvSlice(key string, defaultValue []string) []string {
	if value := os.Getenv(key); value != "" {
		return strings.Split(value, ",")
	}
	return defaultValue
}

// RPCRequest represents a JSON-RPC 2.0 request
type RPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
	ID      interface{}     `json:"id"`
}

// RPCResponse represents a JSON-RPC 2.0 response
type RPCResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	Result  interface{} `json:"result,omitempty"`
	Error   *RPCError   `json:"error,omitempty"`
	ID      interface{} `json:"id"`
}

// RPCError represents a JSON-RPC 2.0 error
type RPCError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}
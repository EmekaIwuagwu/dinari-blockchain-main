package api

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/time/rate"

	"github.com/EmekaIwuagwu/dinari-blockchain/internal/core"
	"github.com/EmekaIwuagwu/dinari-blockchain/internal/mempool"
)

const (
	// MaxRequestSize limits request body size to 1MB
	MaxRequestSize = 1 << 20 // 1MB
	
	// RequestTimeout for processing requests
	RequestTimeout = 30 * time.Second
	
	// ReadTimeout for reading request body
	ReadTimeout = 10 * time.Second
	
	// WriteTimeout for writing response
	WriteTimeout = 10 * time.Second
	
	// IdleTimeout for keep-alive connections
	IdleTimeout = 120 * time.Second
	
	// ShutdownTimeout for graceful shutdown
	ShutdownTimeout = 30 * time.Second
	
	// Default rate limit: 100 requests per minute per IP
	DefaultRateLimit = 100
	DefaultRateBurst = 20
	
	// JSON-RPC version
	JSONRPCVersion = "2.0"
)

// JSON-RPC 2.0 error codes
const (
	ErrCodeParseError     = -32700
	ErrCodeInvalidRequest = -32600
	ErrCodeMethodNotFound = -32601
	ErrCodeInvalidParams  = -32602
	ErrCodeInternalError  = -32603
	ErrCodeUnauthorized   = -32001
	ErrCodeRateLimited    = -32002
	ErrCodeRequestTooLarge = -32003
)

var (
	ErrUnauthorized      = errors.New("unauthorized: invalid or missing API key")
	ErrRateLimited       = errors.New("rate limit exceeded")
	ErrRequestTooLarge   = errors.New("request body too large")
	ErrInvalidMethod     = errors.New("method not found")
	ErrServerShutdown    = errors.New("server is shutting down")
)

// ServerConfig contains server configuration
type ServerConfig struct {
	// Network settings
	ListenAddr string
	
	// TLS settings
	TLSEnabled  bool
	TLSCertFile string
	TLSKeyFile  string
	TLSMinVersion uint16 // Default: tls.VersionTLS13
	
	// Security settings
	AuthEnabled    bool
	JWTSecret      []byte
	APIKeys        []string // List of valid API keys
	
	// CORS settings
	CORSEnabled       bool
	CORSAllowedOrigins []string
	
	// Rate limiting
	RateLimitEnabled bool
	RateLimit        int // requests per minute
	RateBurst        int
	
	// Timeouts
	RequestTimeout time.Duration
	ReadTimeout    time.Duration
	WriteTimeout   time.Duration
	
	// Limits
	MaxRequestSize int64
	
	// Logging
	LogRequests bool
}

// DefaultConfig returns default secure configuration
func DefaultConfig() *ServerConfig {
	return &ServerConfig{
		ListenAddr:         "localhost:8545",
		TLSEnabled:         true,
		TLSMinVersion:      tls.VersionTLS13,
		AuthEnabled:        true,
		CORSEnabled:        true,
		CORSAllowedOrigins: []string{"https://localhost:3000"},
		RateLimitEnabled:   true,
		RateLimit:          DefaultRateLimit,
		RateBurst:          DefaultRateBurst,
		RequestTimeout:     RequestTimeout,
		ReadTimeout:        ReadTimeout,
		WriteTimeout:       WriteTimeout,
		MaxRequestSize:     MaxRequestSize,
		LogRequests:        true,
	}
}

// JSONRPCRequest represents a JSON-RPC 2.0 request
type JSONRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
	ID      interface{}     `json:"id"`
}

// JSONRPCResponse represents a JSON-RPC 2.0 response
type JSONRPCResponse struct {
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

// HandlerFunc is the function signature for RPC method handlers
type HandlerFunc func(ctx context.Context, params json.RawMessage) (interface{}, error)

// Server is the JSON-RPC 2.0 API server
type Server struct {
	config   *ServerConfig
	server   *http.Server
	handlers map[string]HandlerFunc

	// Blockchain dependencies
	blockchain *core.Blockchain
	mempool    *mempool.Mempool
	
	// Rate limiting
	limiters   map[string]*rate.Limiter
	limitersMu sync.RWMutex
	
	// API key validation
	apiKeys map[string]bool
	
	// Shutdown coordination
	shutdown chan struct{}
	wg       sync.WaitGroup
	mu       sync.RWMutex
}

// NewServer creates a new API server
func NewServer(config *ServerConfig) (*Server, error) {
	if config == nil {
		config = DefaultConfig()
	}
	
	// Validate configuration
	if err := validateConfig(config); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	
	// Build API keys map for O(1) lookup
	apiKeys := make(map[string]bool)
	for _, key := range config.APIKeys {
		if key != "" {
			apiKeys[key] = true
		}
	}
	
	s := &Server{
		config:   config,
		handlers: make(map[string]HandlerFunc),
		limiters: make(map[string]*rate.Limiter),
		apiKeys:  apiKeys,
		shutdown: make(chan struct{}),
	}
	
	// Create HTTP server with secure defaults
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleRequest)
	mux.HandleFunc("/health", s.handleHealth)
	
	s.server = &http.Server{
		Addr:         config.ListenAddr,
		Handler:      s.middlewareChain(mux),
		ReadTimeout:  config.ReadTimeout,
		WriteTimeout: config.WriteTimeout,
		IdleTimeout:  IdleTimeout,
		
		// Security: Disable HTTP/2 if not needed, set max header size
		MaxHeaderBytes: 1 << 20, // 1MB
		
		// TLS configuration
		TLSConfig: s.buildTLSConfig(),
	}
	
	return s, nil
}

// RegisterMethod registers an RPC method handler
func (s *Server) RegisterMethod(method string, handler HandlerFunc) {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	if method == "" {
		panic("method name cannot be empty")
	}
	if handler == nil {
		panic("handler cannot be nil")
	}
	
	s.handlers[method] = handler
}

// Start starts the API server
func (s *Server) Start() error {
	s.mu.Lock()
	if s.server == nil {
		s.mu.Unlock()
		return errors.New("server not initialized")
	}
	s.mu.Unlock()
	
	// Create listener
	listener, err := net.Listen("tcp", s.config.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to create listener: %w", err)
	}
	
	fmt.Printf("🚀 Dinari RPC Server starting on %s\n", s.config.ListenAddr)
	fmt.Printf("   TLS Enabled: %v\n", s.config.TLSEnabled)
	fmt.Printf("   Auth Enabled: %v\n", s.config.AuthEnabled)
	fmt.Printf("   Rate Limiting: %v\n", s.config.RateLimitEnabled)
	
	// Start server
	if s.config.TLSEnabled {
		return s.server.ServeTLS(listener, s.config.TLSCertFile, s.config.TLSKeyFile)
	}
	return s.server.Serve(listener)
}

// Stop gracefully shuts down the server
func (s *Server) Stop() error {
	close(s.shutdown)
	
	ctx, cancel := context.WithTimeout(context.Background(), ShutdownTimeout)
	defer cancel()
	
	fmt.Println("🛑 Shutting down API server...")
	
	if err := s.server.Shutdown(ctx); err != nil {
		return fmt.Errorf("server shutdown error: %w", err)
	}
	
	// Wait for all handlers to complete
	s.wg.Wait()
	
	fmt.Println("✅ API server stopped")
	return nil
}

// middlewareChain applies all middleware in order
func (s *Server) middlewareChain(next http.Handler) http.Handler {
	handler := next
	
	// Apply middleware in reverse order (last middleware wraps first)
	handler = s.panicRecovery(handler)
	handler = s.requestLogger(handler)
	handler = s.rateLimiter(handler)
	handler = s.authentication(handler)
	handler = s.cors(handler)
	handler = s.requestSizeLimit(handler)
	
	return handler
}

// requestSizeLimit middleware limits request body size
func (s *Server) requestSizeLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, s.config.MaxRequestSize)
		next.ServeHTTP(w, r)
	})
}

// cors middleware handles CORS
func (s *Server) cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.config.CORSEnabled {
			next.ServeHTTP(w, r)
			return
		}
		
		origin := r.Header.Get("Origin")
		
		// Check if origin is allowed
		allowed := false
		for _, allowedOrigin := range s.config.CORSAllowedOrigins {
			if allowedOrigin == "*" || allowedOrigin == origin {
				allowed = true
				break
			}
		}
		
		if allowed {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			w.Header().Set("Access-Control-Max-Age", "86400")
		}
		
		// Handle preflight
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		
		next.ServeHTTP(w, r)
	})
}

// authentication middleware validates API keys or JWT tokens
func (s *Server) authentication(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip auth for health check
		if r.URL.Path == "/health" {
			next.ServeHTTP(w, r)
			return
		}
		
		if !s.config.AuthEnabled {
			next.ServeHTTP(w, r)
			return
		}
		
		// Check Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			s.writeError(w, nil, ErrCodeUnauthorized, "missing authorization header", nil)
			return
		}
		
		// Support both "Bearer <token>" and "ApiKey <key>"
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 {
			s.writeError(w, nil, ErrCodeUnauthorized, "invalid authorization format", nil)
			return
		}
		
		authType := strings.ToLower(parts[0])
		credential := parts[1]
		
		var authorized bool
		
		switch authType {
		case "apikey":
			// Validate API key
			authorized = s.apiKeys[credential]
			
		case "bearer":
			// Validate JWT token
			authorized = s.validateJWT(credential)
			
		default:
			s.writeError(w, nil, ErrCodeUnauthorized, "unsupported auth type", nil)
			return
		}
		
		if !authorized {
			s.writeError(w, nil, ErrCodeUnauthorized, "invalid credentials", nil)
			return
		}
		
		next.ServeHTTP(w, r)
	})
}

// rateLimiter middleware implements per-IP rate limiting
func (s *Server) rateLimiter(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.config.RateLimitEnabled {
			next.ServeHTTP(w, r)
			return
		}
		
		// Extract IP address
		ip := s.getClientIP(r)
		
		// Get or create limiter for this IP
		limiter := s.getLimiter(ip)
		
		if !limiter.Allow() {
			s.writeError(w, nil, ErrCodeRateLimited, "rate limit exceeded", map[string]interface{}{
				"limit": s.config.RateLimit,
				"window": "1 minute",
			})
			return
		}
		
		next.ServeHTTP(w, r)
	})
}

// requestLogger middleware logs requests
func (s *Server) requestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.config.LogRequests {
			next.ServeHTTP(w, r)
			return
		}
		
		start := time.Now()
		
		// Create response writer wrapper to capture status code
		rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		
		next.ServeHTTP(rw, r)
		
		duration := time.Since(start)
		
		fmt.Printf("[API] %s %s %d %v %s\n",
			r.Method,
			r.URL.Path,
			rw.statusCode,
			duration,
			s.getClientIP(r),
		)
	})
}

// panicRecovery middleware recovers from panics
func (s *Server) panicRecovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				fmt.Printf("🚨 PANIC: %v\n", err)
				s.writeError(w, nil, ErrCodeInternalError, "internal server error", nil)
			}
		}()
		
		next.ServeHTTP(w, r)
	})
}

// handleRequest handles JSON-RPC requests
func (s *Server) handleRequest(w http.ResponseWriter, r *http.Request) {
	// Only accept POST
	if r.Method != http.MethodPost {
		s.writeError(w, nil, ErrCodeInvalidRequest, "method not allowed", nil)
		return
	}
	
	// Set content type
	w.Header().Set("Content-Type", "application/json")
	
	// Read and parse request with timeout
	ctx, cancel := context.WithTimeout(r.Context(), s.config.RequestTimeout)
	defer cancel()
	
	body, err := io.ReadAll(r.Body)
	if err != nil {
		if err.Error() == "http: request body too large" {
			s.writeError(w, nil, ErrCodeRequestTooLarge, "request too large", nil)
			return
		}
		s.writeError(w, nil, ErrCodeParseError, "failed to read request", nil)
		return
	}
	
	var req JSONRPCRequest
	if err := json.Unmarshal(body, &req); err != nil {
		s.writeError(w, nil, ErrCodeParseError, "invalid JSON", nil)
		return
	}
	
	// Validate JSON-RPC version
	if req.JSONRPC != JSONRPCVersion {
		s.writeError(w, req.ID, ErrCodeInvalidRequest, "invalid JSON-RPC version", nil)
		return
	}
	
	// Validate method
	if req.Method == "" {
		s.writeError(w, req.ID, ErrCodeInvalidRequest, "missing method", nil)
		return
	}
	
	// Get handler
	s.mu.RLock()
	handler, exists := s.handlers[req.Method]
	s.mu.RUnlock()
	
	if !exists {
		s.writeError(w, req.ID, ErrCodeMethodNotFound, fmt.Sprintf("method %s not found", req.Method), nil)
		return
	}
	
	// Execute handler
	s.wg.Add(1)
	defer s.wg.Done()
	
	result, err := handler(ctx, req.Params)
	if err != nil {
		s.writeError(w, req.ID, ErrCodeInternalError, err.Error(), nil)
		return
	}
	
	// Write success response
	resp := JSONRPCResponse{
		JSONRPC: JSONRPCVersion,
		Result:  result,
		ID:      req.ID,
	}
	
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		fmt.Printf("Failed to encode response: %v\n", err)
	}
}

// handleHealth handles health check requests
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status": "healthy",
		"time":   time.Now().UTC().Format(time.RFC3339),
	})
}

// writeError writes a JSON-RPC error response
func (s *Server) writeError(w http.ResponseWriter, id interface{}, code int, message string, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK) // JSON-RPC errors use 200 status
	
	resp := JSONRPCResponse{
		JSONRPC: JSONRPCVersion,
		Error: &RPCError{
			Code:    code,
			Message: message,
			Data:    data,
		},
		ID: id,
	}
	
	json.NewEncoder(w).Encode(resp)
}

// getLimiter gets or creates a rate limiter for an IP
func (s *Server) getLimiter(ip string) *rate.Limiter {
	s.limitersMu.Lock()
	defer s.limitersMu.Unlock()
	
	limiter, exists := s.limiters[ip]
	if !exists {
		// Create new limiter: rate per minute
		limiter = rate.NewLimiter(rate.Limit(s.config.RateLimit)/60, s.config.RateBurst)
		s.limiters[ip] = limiter
	}
	
	return limiter
}

// getClientIP extracts the client IP from request
func (s *Server) getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		return strings.TrimSpace(ips[0])
	}
	
	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}
	
	// Use remote address
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	return ip
}

// validateJWT validates a JWT token
func (s *Server) validateJWT(tokenString string) bool {
	if len(s.config.JWTSecret) == 0 {
		return false
	}
	
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.config.JWTSecret, nil
	})
	
	if err != nil {
		return false
	}
	
	return token.Valid
}

// buildTLSConfig creates TLS configuration
func (s *Server) buildTLSConfig() *tls.Config {
	if !s.config.TLSEnabled {
		return nil
	}
	
	return &tls.Config{
		MinVersion:               s.config.TLSMinVersion,
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_CHACHA20_POLY1305_SHA256,
		},
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
		},
	}
}

// validateConfig validates server configuration
func validateConfig(config *ServerConfig) error {
	if config.ListenAddr == "" {
		return errors.New("listen address is required")
	}
	
	if config.TLSEnabled {
		if config.TLSCertFile == "" || config.TLSKeyFile == "" {
			return errors.New("TLS cert and key files required when TLS enabled")
		}
	}
	
	if config.RateLimit <= 0 {
		config.RateLimit = DefaultRateLimit
	}
	
	if config.RateBurst <= 0 {
		config.RateBurst = DefaultRateBurst
	}
	
	return nil
}

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

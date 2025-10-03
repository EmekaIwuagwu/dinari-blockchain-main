package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/EmekaIwuagwu/dinari-blockchain/internal/core"
	"github.com/EmekaIwuagwu/dinari-blockchain/internal/mempool"
	"github.com/EmekaIwuagwu/dinari-blockchain/internal/miner"
	"go.uber.org/zap"
)

// RPCServer implements JSON-RPC 2.0 API
type RPCServer struct {
	blockchain *core.Blockchain
	mempool    *mempool.Mempool
	miner      *miner.Miner
	logger     *zap.Logger
	server     *http.Server
}

// Config contains RPC server configuration
type Config struct {
	Blockchain *core.Blockchain
	Mempool    *mempool.Mempool
	Miner      *miner.Miner
	Logger     *zap.Logger
	Address    string
}

// NewRPCServer creates a new RPC server
func NewRPCServer(config *Config) *RPCServer {
	return &RPCServer{
		blockchain: config.Blockchain,
		mempool:    config.Mempool,
		miner:      config.Miner,
		logger:     config.Logger,
	}
}

// Start starts the RPC server
func (s *RPCServer) Start(addr string) error {
	mux := http.NewServeMux()

	// Main RPC endpoint
	mux.HandleFunc("/", s.corsMiddleware(s.handleRPC))

	// Health endpoint
	mux.HandleFunc("/health", s.handleHealth)

	s.server = &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	s.logger.Info("RPC server starting", zap.String("address", addr))

	if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("server error: %w", err)
	}

	return nil
}

// Stop stops the RPC server
func (s *RPCServer) Stop() error {
	if s.server != nil {
		return s.server.Close()
	}
	return nil
}

// handleRPC handles JSON-RPC 2.0 requests
func (s *RPCServer) handleRPC(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, nil, -32600, "Invalid request method")
		return
	}

	// Parse request
	var req RPCRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, nil, -32700, "Parse error")
		return
	}

	s.logger.Debug("RPC request", zap.String("method", req.Method))

	// Route to handler
	result, rpcErr := s.routeRequest(&req)

	// Write response
	if rpcErr != nil {
		s.writeError(w, req.ID, rpcErr.Code, rpcErr.Message)
		return
	}

	s.writeResult(w, req.ID, result)
}

// routeRequest routes the request to the appropriate handler
func (s *RPCServer) routeRequest(req *RPCRequest) (interface{}, *RPCError) {
	switch req.Method {
	// Wallet methods
	case "wallet_create":
		return s.handleWalletCreate(req.Params)
	case "wallet_balance":
		return s.handleWalletBalance(req.Params)

	// Transaction methods
	case "tx_send":
		return s.handleTxSend(req.Params)
	case "tx_get":
		return s.handleTxGet(req.Params)
	case "tx_listByWallet":
		return s.handleTxListByWallet(req.Params)

	// Chain methods
	case "chain_getBlock":
		return s.handleChainGetBlock(req.Params)
	case "chain_getHeight":
		return s.handleChainGetHeight(req.Params)
	case "chain_getTip":
		return s.handleChainGetTip(req.Params)
	
	case "chain_getBlocks":
		return s.handleChainGetBlocks(req.Params)
	case "chain_getRecentBlocks":
		return s.handleChainGetRecentBlocks(req.Params)
	case "chain_getStats":
		return s.handleChainGetStats(req.Params)
	case "chain_search":
		return s.handleChainSearch(req.Params)

	// Mempool methods
	case "mempool_stats":
		return s.handleMempoolStats(req.Params)

	// Miner methods
	case "miner_start":
		return s.handleMinerStart(req.Params)
	case "miner_stop":
		return s.handleMinerStop(req.Params)
	case "miner_status":
		return s.handleMinerStatus(req.Params)
	case "afc_mint":
		return s.handleMintAFC(req.Params)
	case "tx_list_by_wallet":
		return s.handleTxListByWallet(req.Params)
	default:
		return nil, &RPCError{Code: -32601, Message: "Method not found"}
	}
}

// handleHealth handles health check requests
func (s *RPCServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	health := map[string]interface{}{
		"status":    "ok",
		"height":    s.blockchain.GetHeight(),
		"mempool":   s.mempool.Size(),
		"mining":    s.miner.IsRunning(),
		"timestamp": time.Now().Unix(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(health)
}

// corsMiddleware adds CORS headers
func (s *RPCServer) corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next(w, r)
	}
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

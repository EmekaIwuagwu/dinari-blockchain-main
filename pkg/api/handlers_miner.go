package api

import (
	"encoding/json"
)

// handleMinerStart starts the mining process
func (s *Server) handleMinerStart(params json.RawMessage) (interface{}, *RPCError) {
	return nil, &RPCError{
		Code:    -32601,
		Message: "Mining functionality not available in this node configuration",
	}
}

// handleMinerStop stops the mining process
func (s *Server) handleMinerStop(params json.RawMessage) (interface{}, *RPCError) {
	return nil, &RPCError{
		Code:    -32601,
		Message: "Mining functionality not available in this node configuration",
	}
}

// handleMinerStatus returns the current miner status
func (s *Server) handleMinerStatus(params json.RawMessage) (interface{}, *RPCError) {
	return map[string]interface{}{
		"enabled":     false,
		"running":     false,
		"hashrate":    0,
		"blocksMined": 0,
		"difficulty":  0,
		"workers":     0,
		"lastBlock":   nil,
		"uptime":      0,
	}, nil
}

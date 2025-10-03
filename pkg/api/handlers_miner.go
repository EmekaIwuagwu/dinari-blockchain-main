package api

import (
	"encoding/json"
)

// handleMinerStart starts the mining process
func (s *RPCServer) handleMinerStart(params json.RawMessage) (interface{}, *RPCError) {
	if s.miner.IsRunning() {
		return nil, &RPCError{Code: -32000, Message: "miner already running"}
	}

	if err := s.miner.Start(); err != nil {
		return nil, &RPCError{Code: -32000, Message: "failed to start miner: " + err.Error()}
	}

	return map[string]interface{}{
		"status": "mining started",
	}, nil
}

// handleMinerStop stops the mining process
func (s *RPCServer) handleMinerStop(params json.RawMessage) (interface{}, *RPCError) {
	if !s.miner.IsRunning() {
		return nil, &RPCError{Code: -32000, Message: "miner not running"}
	}

	s.miner.Stop()

	return map[string]interface{}{
		"status": "mining stopped",
	}, nil
}

// handleMinerStatus returns the current miner status
func (s *RPCServer) handleMinerStatus(params json.RawMessage) (interface{}, *RPCError) {
	stats := s.miner.Stats()
	return stats, nil
}

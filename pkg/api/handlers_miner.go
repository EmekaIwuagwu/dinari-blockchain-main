package api

import (
	"encoding/json"
	"time"
)

// handleMinerStart starts the mining process
func (s *Server) handleMinerStart(params json.RawMessage) (interface{}, *RPCError) {
	if s.miner == nil {
		return nil, &RPCError{
			Code:    -32601,
			Message: "Mining functionality not available in this node configuration",
		}
	}

	if s.miner.IsRunning() {
		return map[string]interface{}{
			"success": false,
			"message": "Miner is already running",
		}, nil
	}

	if err := s.miner.Start(); err != nil {
		return nil, &RPCError{
			Code:    -32603,
			Message: "Failed to start miner: " + err.Error(),
		}
	}

	return map[string]interface{}{
		"success": true,
		"message": "Miner started successfully",
		"address": s.miner.GetMinerAddress(),
	}, nil
}

// handleMinerStop stops the mining process
func (s *Server) handleMinerStop(params json.RawMessage) (interface{}, *RPCError) {
	if s.miner == nil {
		return nil, &RPCError{
			Code:    -32601,
			Message: "Mining functionality not available in this node configuration",
		}
	}

	if !s.miner.IsRunning() {
		return map[string]interface{}{
			"success": false,
			"message": "Miner is not running",
		}, nil
	}

	s.miner.Stop()

	return map[string]interface{}{
		"success": true,
		"message": "Miner stopped successfully",
	}, nil
}

// handleMinerStatus returns the current miner status
func (s *Server) handleMinerStatus(params json.RawMessage) (interface{}, *RPCError) {
	if s.miner == nil {
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

	stats := s.miner.GetStats()
	isRunning := s.miner.IsRunning()

	// Get blockchain difficulty
	difficulty := uint32(0)
	if s.blockchain != nil {
		difficulty = s.blockchain.GetDifficulty()
	}

	// Convert stats to map with proper formatting
	statsMap, ok := stats.(map[string]interface{})
	if !ok {
		// If stats is a struct, create the map manually
		return map[string]interface{}{
			"enabled":     true,
			"running":     isRunning,
			"address":     s.miner.GetMinerAddress(),
			"difficulty":  difficulty,
			"stats":       stats,
			"timestamp":   time.Now().Unix(),
		}, nil
	}

	// Add runtime info to stats
	statsMap["enabled"] = true
	statsMap["running"] = isRunning
	statsMap["address"] = s.miner.GetMinerAddress()
	statsMap["difficulty"] = difficulty
	statsMap["timestamp"] = time.Now().Unix()

	return statsMap, nil
}

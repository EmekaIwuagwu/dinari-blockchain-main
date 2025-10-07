// internal/core/circuit_breaker.go
// Emergency stop mechanism for detecting and preventing attacks

package core

import (
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"
)

const (
	DefaultThresholdFailureRate    = 0.5 // 50% failure rate
	DefaultThresholdVolume         = 100
	DefaultThresholdHighValue      = 10 // 10 high-value tx per minute
	DefaultSuspiciousPatternScore  = 80
	DefaultMonitoringWindow        = 1 * time.Minute
	DefaultCooldownPeriod          = 5 * time.Minute
	MaxConsecutiveFailures         = 10
	MaxTransactionsPerSecond       = 1000
)

type CircuitState int

const (
	StateClosed CircuitState = iota
	StateOpen
	StateHalfOpen
)

func (s CircuitState) String() string {
	switch s {
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

var (
	ErrCircuitOpen        = errors.New("circuit breaker is open - system in emergency mode")
	ErrAttackDetected     = errors.New("potential attack detected")
	ErrRateLimitExceeded  = errors.New("rate limit exceeded")
	ErrAnomalyDetected    = errors.New("anomaly detected in transaction pattern")
)

type CircuitBreaker struct {
	state                CircuitState
	consecutiveFailures  int
	successCount         int
	failureCount         int
	lastStateChange      time.Time
	lastFailureTime      time.Time
	anomalyDetector      *AnomalyDetector
	rateLimiter         *RateLimiter
	alertManager         *AlertManager
	config               *CircuitBreakerConfig
	metrics              *CircuitMetrics
	mu                   sync.RWMutex
}

type CircuitBreakerConfig struct {
	FailureRateThreshold      float64
	VolumeThreshold           int
	HighValueTxThreshold      int
	MonitoringWindow          time.Duration
	CooldownPeriod            time.Duration
	HalfOpenMaxRequests       int
	EnableAnomalyDetection    bool
	EnableRateLimiting        bool
	AutoRecovery              bool
}

type CircuitMetrics struct {
	TotalRequests        uint64
	TotalFailures        uint64
	TotalSuccesses       uint64
	CircuitOpenCount     uint64
	LastCircuitOpenTime  time.Time
	AnomaliesDetected    uint64
	AttacksPrevented     uint64
	EmergencyStops       uint64
	mu                   sync.RWMutex
}

type AnomalyDetector struct {
	recentTransactions   []TransactionMetadata
	patternScores        map[string]int
	suspiciousAddresses  map[string]SuspiciousActivity
	mu                   sync.RWMutex
}

type TransactionMetadata struct {
	Timestamp    time.Time
	From         string
	To           string
	Amount       *big.Int
	Success      bool
	RiskScore    int
}

type SuspiciousActivity struct {
	Address        string
	SuspicionScore int
	FirstSeen      time.Time
	LastSeen       time.Time
	IncidentCount  int
	Reasons        []string
}

type RateLimiter struct {
	requestCounts    map[string]*RequestWindow
	globalCount      *RequestWindow
	mu               sync.RWMutex
}

type RequestWindow struct {
	Count      int
	WindowStart time.Time
}

type AlertManager struct {
	alerts       []Alert
	subscribers  []AlertSubscriber
	mu           sync.RWMutex
}

type Alert struct {
	Timestamp   time.Time
	Severity    string
	Type        string
	Message     string
	Details     map[string]interface{}
}

type AlertSubscriber func(Alert)

func NewCircuitBreaker(config *CircuitBreakerConfig) *CircuitBreaker {
	if config == nil {
		config = DefaultCircuitBreakerConfig()
	}

	return &CircuitBreaker{
		state:           StateClosed,
		lastStateChange: time.Now(),
		anomalyDetector: NewAnomalyDetector(),
		rateLimiter:     NewRateLimiter(),
		alertManager:    NewAlertManager(),
		config:          config,
		metrics:         NewCircuitMetrics(),
	}
}

func DefaultCircuitBreakerConfig() *CircuitBreakerConfig {
	return &CircuitBreakerConfig{
		FailureRateThreshold:    DefaultThresholdFailureRate,
		VolumeThreshold:         DefaultThresholdVolume,
		HighValueTxThreshold:    DefaultThresholdHighValue,
		MonitoringWindow:        DefaultMonitoringWindow,
		CooldownPeriod:          DefaultCooldownPeriod,
		HalfOpenMaxRequests:     10,
		EnableAnomalyDetection:  true,
		EnableRateLimiting:      true,
		AutoRecovery:            true,
	}
}

func NewCircuitMetrics() *CircuitMetrics {
	return &CircuitMetrics{}
}

func NewAnomalyDetector() *AnomalyDetector {
	return &AnomalyDetector{
		recentTransactions:  make([]TransactionMetadata, 0, 10000),
		patternScores:       make(map[string]int),
		suspiciousAddresses: make(map[string]SuspiciousActivity),
	}
}

func NewRateLimiter() *RateLimiter {
	return &RateLimiter{
		requestCounts: make(map[string]*RequestWindow),
		globalCount:   &RequestWindow{WindowStart: time.Now()},
	}
}

func NewAlertManager() *AlertManager {
	return &AlertManager{
		alerts:      make([]Alert, 0, 1000),
		subscribers: make([]AlertSubscriber, 0),
	}
}

func (cb *CircuitBreaker) AllowRequest() error {
	cb.mu.RLock()
	state := cb.state
	cb.mu.RUnlock()

	switch state {
	case StateClosed:
		return nil
	case StateOpen:
		if cb.shouldAttemptReset() {
			cb.transitionToHalfOpen()
			return nil
		}
		return ErrCircuitOpen
	case StateHalfOpen:
		if cb.canAcceptRequest() {
			return nil
		}
		return ErrCircuitOpen
	}

	return nil
}

func (cb *CircuitBreaker) RecordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.metrics.TotalSuccesses++
	cb.metrics.TotalRequests++
	cb.successCount++
	cb.consecutiveFailures = 0

	if cb.state == StateHalfOpen {
		if cb.successCount >= cb.config.HalfOpenMaxRequests {
			cb.transitionToClosed()
		}
	}
}

func (cb *CircuitBreaker) RecordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.metrics.TotalFailures++
	cb.metrics.TotalRequests++
	cb.failureCount++
	cb.consecutiveFailures++
	cb.lastFailureTime = time.Now()

	if cb.consecutiveFailures >= MaxConsecutiveFailures {
		cb.alertManager.SendAlert(Alert{
			Timestamp: time.Now(),
			Severity:  "CRITICAL",
			Type:      "CONSECUTIVE_FAILURES",
			Message:   fmt.Sprintf("Circuit breaker detected %d consecutive failures", cb.consecutiveFailures),
			Details: map[string]interface{}{
				"failures": cb.consecutiveFailures,
			},
		})
		cb.transitionToOpen()
		return
	}

	if cb.shouldTrip() {
		cb.transitionToOpen()
	}
}

func (cb *CircuitBreaker) RecordTransaction(txMeta TransactionMetadata) error {
	if cb.config.EnableRateLimiting {
		if err := cb.rateLimiter.CheckLimit(txMeta.From); err != nil {
			cb.RecordFailure()
			return err
		}
	}

	if cb.config.EnableAnomalyDetection {
		anomalyScore := cb.anomalyDetector.AnalyzeTransaction(txMeta)
		if anomalyScore > DefaultSuspiciousPatternScore {
			cb.metrics.AnomaliesDetected++
			cb.alertManager.SendAlert(Alert{
				Timestamp: time.Now(),
				Severity:  "HIGH",
				Type:      "ANOMALY_DETECTED",
				Message:   fmt.Sprintf("Suspicious transaction pattern detected (score: %d)", anomalyScore),
				Details: map[string]interface{}{
					"from":       txMeta.From,
					"to":         txMeta.To,
					"amount":     txMeta.Amount.String(),
					"riskScore":  txMeta.RiskScore,
					"anomalyScore": anomalyScore,
				},
			})
			
			if anomalyScore > 95 {
				cb.metrics.AttacksPrevented++
				cb.transitionToOpen()
				return ErrAttackDetected
			}
		}
	}

	cb.anomalyDetector.AddTransaction(txMeta)

	if txMeta.Success {
		cb.RecordSuccess()
	} else {
		cb.RecordFailure()
	}

	return nil
}

func (cb *CircuitBreaker) shouldTrip() bool {
	totalRequests := cb.successCount + cb.failureCount

	if totalRequests < cb.config.VolumeThreshold {
		return false
	}

	failureRate := float64(cb.failureCount) / float64(totalRequests)

	return failureRate >= cb.config.FailureRateThreshold
}

func (cb *CircuitBreaker) shouldAttemptReset() bool {
	if !cb.config.AutoRecovery {
		return false
	}

	return time.Since(cb.lastStateChange) >= cb.config.CooldownPeriod
}

func (cb *CircuitBreaker) canAcceptRequest() bool {
	return cb.successCount < cb.config.HalfOpenMaxRequests
}

func (cb *CircuitBreaker) transitionToOpen() {
	if cb.state == StateOpen {
		return
	}

	cb.state = StateOpen
	cb.lastStateChange = time.Now()
	cb.metrics.CircuitOpenCount++
	cb.metrics.LastCircuitOpenTime = time.Now()
	cb.metrics.EmergencyStops++

	cb.alertManager.SendAlert(Alert{
		Timestamp: time.Now(),
		Severity:  "CRITICAL",
		Type:      "CIRCUIT_OPENED",
		Message:   "Circuit breaker has been opened - system entering emergency mode",
		Details: map[string]interface{}{
			"failureRate":      float64(cb.failureCount) / float64(cb.successCount + cb.failureCount),
			"consecutiveFailures": cb.consecutiveFailures,
			"totalFailures":    cb.metrics.TotalFailures,
		},
	})
}

func (cb *CircuitBreaker) transitionToHalfOpen() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.state = StateHalfOpen
	cb.lastStateChange = time.Now()
	cb.successCount = 0
	cb.failureCount = 0

	cb.alertManager.SendAlert(Alert{
		Timestamp: time.Now(),
		Severity:  "WARNING",
		Type:      "CIRCUIT_HALF_OPEN",
		Message:   "Circuit breaker transitioning to half-open state - testing recovery",
	})
}

func (cb *CircuitBreaker) transitionToClosed() {
	cb.state = StateClosed
	cb.lastStateChange = time.Now()
	cb.successCount = 0
	cb.failureCount = 0
	cb.consecutiveFailures = 0

	cb.alertManager.SendAlert(Alert{
		Timestamp: time.Now(),
		Severity:  "INFO",
		Type:      "CIRCUIT_CLOSED",
		Message:   "Circuit breaker has recovered - normal operations resumed",
	})
}

func (cb *CircuitBreaker) ManualOpen(reason string) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.transitionToOpen()
	
	cb.alertManager.SendAlert(Alert{
		Timestamp: time.Now(),
		Severity:  "CRITICAL",
		Type:      "MANUAL_CIRCUIT_OPEN",
		Message:   "Circuit breaker manually opened",
		Details: map[string]interface{}{
			"reason": reason,
		},
	})
}

func (cb *CircuitBreaker) ManualClose() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.transitionToClosed()
	
	cb.alertManager.SendAlert(Alert{
		Timestamp: time.Now(),
		Severity:  "INFO",
		Type:      "MANUAL_CIRCUIT_CLOSE",
		Message:   "Circuit breaker manually closed",
	})
}

func (cb *CircuitBreaker) GetState() CircuitState {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.state
}

func (cb *CircuitBreaker) GetMetrics() *CircuitMetrics {
	cb.metrics.mu.RLock()
	defer cb.metrics.mu.RUnlock()

	metricsCopy := &CircuitMetrics{}
	*metricsCopy = *cb.metrics
	return metricsCopy
}

func (ad *AnomalyDetector) AnalyzeTransaction(tx TransactionMetadata) int {
	ad.mu.RLock()
	defer ad.mu.RUnlock()

	score := 0

	if tx.Amount.Cmp(big.NewInt(VeryHighValueThreshold)) > 0 {
		score += 30
	}

	fromActivity := ad.getAddressActivity(tx.From)
	toActivity := ad.getAddressActivity(tx.To)

	if fromActivity == 0 {
		score += 15
	}
	if toActivity == 0 {
		score += 10
	}

	recentHighValue := ad.countRecentHighValueTxFrom(tx.From)
	if recentHighValue > 5 {
		score += 20
	}

	if tx.RiskScore > 70 {
		score += 25
	}

	return score
}

func (ad *AnomalyDetector) AddTransaction(tx TransactionMetadata) {
	ad.mu.Lock()
	defer ad.mu.Unlock()

	ad.recentTransactions = append(ad.recentTransactions, tx)

	if len(ad.recentTransactions) > 10000 {
		ad.recentTransactions = ad.recentTransactions[1000:]
	}

	ad.patternScores[tx.From]++
	ad.patternScores[tx.To]++
}

func (ad *AnomalyDetector) getAddressActivity(address string) int {
	return ad.patternScores[address]
}

func (ad *AnomalyDetector) countRecentHighValueTxFrom(address string) int {
	count := 0
	cutoff := time.Now().Add(-5 * time.Minute)

	for _, tx := range ad.recentTransactions {
		if tx.From == address && tx.Timestamp.After(cutoff) {
			if tx.Amount.Cmp(big.NewInt(HighValueThreshold)) > 0 {
				count++
			}
		}
	}

	return count
}

func (rl *RateLimiter) CheckLimit(address string) error {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()

	if rl.globalCount.WindowStart.Add(1 * time.Second).Before(now) {
		rl.globalCount = &RequestWindow{
			Count:       1,
			WindowStart: now,
		}
	} else {
		rl.globalCount.Count++
		if rl.globalCount.Count > MaxTransactionsPerSecond {
			return ErrRateLimitExceeded
		}
	}

	window, exists := rl.requestCounts[address]
	if !exists || window.WindowStart.Add(1*time.Minute).Before(now) {
		rl.requestCounts[address] = &RequestWindow{
			Count:       1,
			WindowStart: now,
		}
		return nil
	}

	window.Count++
	if window.Count > 100 {
		return ErrRateLimitExceeded
	}

	return nil
}

func (am *AlertManager) SendAlert(alert Alert) {
	am.mu.Lock()
	defer am.mu.Unlock()

	am.alerts = append(am.alerts, alert)

	if len(am.alerts) > 1000 {
		am.alerts = am.alerts[100:]
	}

	for _, subscriber := range am.subscribers {
		go subscriber(alert)
	}
}

func (am *AlertManager) Subscribe(subscriber AlertSubscriber) {
	am.mu.Lock()
	defer am.mu.Unlock()

	am.subscribers = append(am.subscribers, subscriber)
}

func (am *AlertManager) GetRecentAlerts(count int) []Alert {
	am.mu.RLock()
	defer am.mu.RUnlock()

	if count > len(am.alerts) {
		count = len(am.alerts)
	}

	start := len(am.alerts) - count
	alerts := make([]Alert, count)
	copy(alerts, am.alerts[start:])

	return alerts
}

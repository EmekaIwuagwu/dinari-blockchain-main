package monitoring

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// AlertingSystem manages security and operational alerts
type AlertingSystem struct {
	// Alert channels
	channels map[string]AlertChannel
	
	// Alert rules
	rules []AlertRule
	
	// Alert history
	history []Alert
	maxHistorySize int
	
	// Metrics
	metrics *MetricsCollector
	
	// SIEM integration
	siemExporter SIEMExporter
	
	mu sync.RWMutex
}

// Alert represents a system alert
type Alert struct {
	ID          string
	Level       AlertLevel
	Category    AlertCategory
	Title       string
	Message     string
	Source      string
	Metadata    map[string]interface{}
	Timestamp   time.Time
	Resolved    bool
	ResolvedAt  *time.Time
	Actions     []string
}

// AlertLevel defines severity levels
type AlertLevel int

const (
	AlertInfo AlertLevel = iota
	AlertWarning
	AlertError
	AlertCritical
)

// AlertCategory defines alert categories
type AlertCategory int

const (
	CategorySecurity AlertCategory = iota
	CategoryPerformance
	CategoryConsensus
	CategoryNetwork
	CategoryCompliance
	CategorySystem
)

// AlertChannel defines output channels for alerts
type AlertChannel interface {
	Send(alert Alert) error
	Close() error
}

// AlertRule defines conditions for triggering alerts
type AlertRule struct {
	ID          string
	Name        string
	Description string
	Condition   AlertCondition
	Level       AlertLevel
	Category    AlertCategory
	Enabled     bool
	Cooldown    time.Duration
	LastFired   time.Time
}

// AlertCondition evaluates whether to trigger an alert
type AlertCondition func(metrics *MetricsCollector) (bool, string)

// MetricsCollector collects system metrics
type MetricsCollector struct {
	// Blockchain metrics
	BlockHeight          uint64
	TxPoolSize           int
	PeerCount            int
	OrphanBlockCount     int
	ReorgCount           int
	
	// Performance metrics
	AvgBlockTime         time.Duration
	AvgTxProcessingTime  time.Duration
	MempoolWaitTime      time.Duration
	
	// Security metrics
	FailedAuthAttempts   int
	RateLimitViolations  int
	InvalidTxCount       int
	BannedIPCount        int
	
	// Resource metrics
	CPUUsage             float64
	MemoryUsage          float64
	DiskUsage            float64
	NetworkBandwidth     uint64
	
	// Custom metrics
	CustomMetrics        map[string]interface{}
	
	mu                   sync.RWMutex
}

// SIEMExporter exports logs to SIEM systems
type SIEMExporter interface {
	Export(event SIEMEvent) error
	Flush() error
}

// SIEMEvent represents a SIEM event
type SIEMEvent struct {
	Timestamp   time.Time
	EventType   string
	Severity    string
	Source      string
	User        string
	Action      string
	Result      string
	Details     map[string]interface{}
	IPAddress   string
	Tags        []string
}

// LogChannel sends alerts to logging system
type LogChannel struct {
	logger Logger
}

type Logger interface {
	Info(msg string, fields map[string]interface{})
	Warn(msg string, fields map[string]interface{})
	Error(msg string, fields map[string]interface{})
	Critical(msg string, fields map[string]interface{})
}

// WebhookChannel sends alerts via HTTP webhook
type WebhookChannel struct {
	url     string
	client  HTTPClient
	headers map[string]string
}

type HTTPClient interface {
	Post(url string, data []byte) error
}

// NewAlertingSystem creates a new alerting system
func NewAlertingSystem(siemExporter SIEMExporter) *AlertingSystem {
	as := &AlertingSystem{
		channels:       make(map[string]AlertChannel),
		rules:          make([]AlertRule, 0),
		history:        make([]Alert, 0),
		maxHistorySize: 10000,
		metrics:        NewMetricsCollector(),
		siemExporter:   siemExporter,
	}

	// Register default alert rules
	as.registerDefaultRules()

	return as
}

// NewMetricsCollector creates a new metrics collector
func NewMetricsCollector() *MetricsCollector {
	return &MetricsCollector{
		CustomMetrics: make(map[string]interface{}),
	}
}

// registerDefaultRules registers critical default alert rules
func (as *AlertingSystem) registerDefaultRules() {
	// Security: High rate of failed authentication
	as.AddRule(AlertRule{
		ID:          "security_failed_auth",
		Name:        "High Failed Authentication Rate",
		Description: "Detects potential brute force attacks",
		Level:       AlertCritical,
		Category:    CategorySecurity,
		Enabled:     true,
		Cooldown:    5 * time.Minute,
		Condition: func(m *MetricsCollector) (bool, string) {
			m.mu.RLock()
			defer m.mu.RUnlock()
			if m.FailedAuthAttempts > 50 {
				return true, fmt.Sprintf("Failed auth attempts: %d", m.FailedAuthAttempts)
			}
			return false, ""
		},
	})

	// Security: High invalid transaction count
	as.AddRule(AlertRule{
		ID:          "security_invalid_tx",
		Name:        "High Invalid Transaction Rate",
		Description: "Detects potential attack or misconfiguration",
		Level:       AlertError,
		Category:    CategorySecurity,
		Enabled:     true,
		Cooldown:    5 * time.Minute,
		Condition: func(m *MetricsCollector) (bool, string) {
			m.mu.RLock()
			defer m.mu.RUnlock()
			if m.InvalidTxCount > 100 {
				return true, fmt.Sprintf("Invalid transactions: %d", m.InvalidTxCount)
			}
			return false, ""
		},
	})

	// Consensus: Blockchain reorganization detected
	as.AddRule(AlertRule{
		ID:          "consensus_reorg",
		Name:        "Blockchain Reorganization",
		Description: "Detects chain reorgs which may indicate attack",
		Level:       AlertCritical,
		Category:    CategoryConsensus,
		Enabled:     true,
		Cooldown:    1 * time.Minute,
		Condition: func(m *MetricsCollector) (bool, string) {
			m.mu.RLock()
			defer m.mu.RUnlock()
			if m.ReorgCount > 0 {
				return true, fmt.Sprintf("Reorgs detected: %d", m.ReorgCount)
			}
			return false, ""
		},
	})

	// Performance: Mempool overflow
	as.AddRule(AlertRule{
		ID:          "performance_mempool",
		Name:        "Mempool Overflow",
		Description: "Transaction pool is nearly full",
		Level:       AlertWarning,
		Category:    CategoryPerformance,
		Enabled:     true,
		Cooldown:    10 * time.Minute,
		Condition: func(m *MetricsCollector) (bool, string) {
			m.mu.RLock()
			defer m.mu.RUnlock()
			if m.TxPoolSize > 50000 {
				return true, fmt.Sprintf("Mempool size: %d", m.TxPoolSize)
			}
			return false, ""
		},
	})

	// Network: Low peer count
	as.AddRule(AlertRule{
		ID:          "network_peers",
		Name:        "Low Peer Count",
		Description: "Network connectivity issues",
		Level:       AlertWarning,
		Category:    CategoryNetwork,
		Enabled:     true,
		Cooldown:    15 * time.Minute,
		Condition: func(m *MetricsCollector) (bool, string) {
			m.mu.RLock()
			defer m.mu.RUnlock()
			if m.PeerCount < 3 {
				return true, fmt.Sprintf("Peer count: %d", m.PeerCount)
			}
			return false, ""
		},
	})

	// System: High resource usage
	as.AddRule(AlertRule{
		ID:          "system_resources",
		Name:        "High Resource Usage",
		Description: "CPU or memory usage is high",
		Level:       AlertWarning,
		Category:    CategorySystem,
		Enabled:     true,
		Cooldown:    10 * time.Minute,
		Condition: func(m *MetricsCollector) (bool, string) {
			m.mu.RLock()
			defer m.mu.RUnlock()
			if m.CPUUsage > 90.0 || m.MemoryUsage > 90.0 {
				return true, fmt.Sprintf("CPU: %.1f%%, Memory: %.1f%%", m.CPUUsage, m.MemoryUsage)
			}
			return false, ""
		},
	})
}

// AddRule adds a new alert rule
func (as *AlertingSystem) AddRule(rule AlertRule) {
	as.mu.Lock()
	defer as.mu.Unlock()
	as.rules = append(as.rules, rule)
}

// AddChannel adds an alert output channel
func (as *AlertingSystem) AddChannel(name string, channel AlertChannel) {
	as.mu.Lock()
	defer as.mu.Unlock()
	as.channels[name] = channel
}

// CheckRules evaluates all alert rules
func (as *AlertingSystem) CheckRules(ctx context.Context) {
	as.mu.RLock()
	rules := make([]AlertRule, len(as.rules))
	copy(rules, as.rules)
	as.mu.RUnlock()

	now := time.Now()

	for i, rule := range rules {
		if !rule.Enabled {
			continue
		}

		// Check cooldown
		if now.Sub(rule.LastFired) < rule.Cooldown {
			continue
		}

		// Evaluate condition
		triggered, message := rule.Condition(as.metrics)
		if triggered {
			alert := Alert{
				ID:        fmt.Sprintf("%s_%d", rule.ID, time.Now().Unix()),
				Level:     rule.Level,
				Category:  rule.Category,
				Title:     rule.Name,
				Message:   message,
				Source:    "AlertingSystem",
				Metadata:  make(map[string]interface{}),
				Timestamp: now,
			}

			// Send alert
			as.SendAlert(alert)

			// Update last fired time
			as.mu.Lock()
			as.rules[i].LastFired = now
			as.mu.Unlock()

			// Export to SIEM
			as.exportToSIEM(alert)
		}
	}
}

// SendAlert sends an alert through all channels
func (as *AlertingSystem) SendAlert(alert Alert) {
	as.mu.Lock()
	
	// Add to history
	as.history = append(as.history, alert)
	if len(as.history) > as.maxHistorySize {
		as.history = as.history[1:]
	}

	// Get channels
	channels := make(map[string]AlertChannel)
	for name, ch := range as.channels {
		channels[name] = ch
	}
	
	as.mu.Unlock()

	// Send to all channels
	for name, channel := range channels {
		go func(n string, ch AlertChannel, a Alert) {
			if err := ch.Send(a); err != nil {
				fmt.Printf("Failed to send alert via %s: %v\n", n, err)
			}
		}(name, channel, alert)
	}
}

// exportToSIEM exports alert to SIEM system
func (as *AlertingSystem) exportToSIEM(alert Alert) {
	if as.siemExporter == nil {
		return
	}

	event := SIEMEvent{
		Timestamp: alert.Timestamp,
		EventType: fmt.Sprintf("ALERT_%s", alert.Category.String()),
		Severity:  alert.Level.String(),
		Source:    alert.Source,
		Action:    "ALERT_TRIGGERED",
		Result:    "ALERT",
		Details: map[string]interface{}{
			"alert_id":  alert.ID,
			"title":     alert.Title,
			"message":   alert.Message,
			"metadata":  alert.Metadata,
		},
		Tags: []string{"blockchain", "dinari", alert.Category.String()},
	}

	go func() {
		if err := as.siemExporter.Export(event); err != nil {
			fmt.Printf("Failed to export to SIEM: %v\n", err)
		}
	}()
}

// UpdateMetric updates a specific metric
func (mc *MetricsCollector) UpdateMetric(name string, value interface{}) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	switch name {
	case "block_height":
		if v, ok := value.(uint64); ok {
			mc.BlockHeight = v
		}
	case "tx_pool_size":
		if v, ok := value.(int); ok {
			mc.TxPoolSize = v
		}
	case "peer_count":
		if v, ok := value.(int); ok {
			mc.PeerCount = v
		}
	case "failed_auth":
		if v, ok := value.(int); ok {
			mc.FailedAuthAttempts = v
		}
	case "invalid_tx":
		if v, ok := value.(int); ok {
			mc.InvalidTxCount = v
		}
	case "reorg_count":
		if v, ok := value.(int); ok {
			mc.ReorgCount = v
		}
	case "cpu_usage":
		if v, ok := value.(float64); ok {
			mc.CPUUsage = v
		}
	case "memory_usage":
		if v, ok := value.(float64); ok {
			mc.MemoryUsage = v
		}
	default:
		mc.CustomMetrics[name] = value
	}
}

// GetMetrics returns current metrics snapshot
func (mc *MetricsCollector) GetMetrics() map[string]interface{} {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	metrics := map[string]interface{}{
		"block_height":       mc.BlockHeight,
		"tx_pool_size":       mc.TxPoolSize,
		"peer_count":         mc.PeerCount,
		"failed_auth":        mc.FailedAuthAttempts,
		"invalid_tx":         mc.InvalidTxCount,
		"reorg_count":        mc.ReorgCount,
		"cpu_usage":          mc.CPUUsage,
		"memory_usage":       mc.MemoryUsage,
		"disk_usage":         mc.DiskUsage,
		"network_bandwidth":  mc.NetworkBandwidth,
	}

	// Add custom metrics
	for k, v := range mc.CustomMetrics {
		metrics[k] = v
	}

	return metrics
}

// GetAlertHistory returns recent alerts
func (as *AlertingSystem) GetAlertHistory(limit int) []Alert {
	as.mu.RLock()
	defer as.mu.RUnlock()

	if limit <= 0 || limit > len(as.history) {
		limit = len(as.history)
	}

	history := make([]Alert, limit)
	start := len(as.history) - limit
	copy(history, as.history[start:])

	return history
}

// ExportMetrics exports metrics in JSON format
func (mc *MetricsCollector) ExportMetrics() ([]byte, error) {
	metrics := mc.GetMetrics()
	return json.Marshal(metrics)
}

// Helper methods for alert levels and categories
func (al AlertLevel) String() string {
	switch al {
	case AlertInfo:
		return "INFO"
	case AlertWarning:
		return "WARNING"
	case AlertError:
		return "ERROR"
	case AlertCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

func (ac AlertCategory) String() string {
	switch ac {
	case CategorySecurity:
		return "SECURITY"
	case CategoryPerformance:
		return "PERFORMANCE"
	case CategoryConsensus:
		return "CONSENSUS"
	case CategoryNetwork:
		return "NETWORK"
	case CategoryCompliance:
		return "COMPLIANCE"
	case CategorySystem:
		return "SYSTEM"
	default:
		return "UNKNOWN"
	}
}

// Send implements AlertChannel for LogChannel
func (lc *LogChannel) Send(alert Alert) error {
	fields := map[string]interface{}{
		"alert_id":  alert.ID,
		"category":  alert.Category.String(),
		"source":    alert.Source,
		"metadata":  alert.Metadata,
	}

	msg := fmt.Sprintf("[%s] %s: %s", alert.Category.String(), alert.Title, alert.Message)

	switch alert.Level {
	case AlertInfo:
		lc.logger.Info(msg, fields)
	case AlertWarning:
		lc.logger.Warn(msg, fields)
	case AlertError:
		lc.logger.Error(msg, fields)
	case AlertCritical:
		lc.logger.Critical(msg, fields)
	}

	return nil
}

func (lc *LogChannel) Close() error {
	return nil
}

// Send implements AlertChannel for WebhookChannel
func (wc *WebhookChannel) Send(alert Alert) error {
	data, err := json.Marshal(alert)
	if err != nil {
		return fmt.Errorf("failed to marshal alert: %w", err)
	}

	return wc.client.Post(wc.url, data)
}

func (wc *WebhookChannel) Close() error {
	return nil
}
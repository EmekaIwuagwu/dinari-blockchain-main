// pkg/monitoring/monitoring.go
package monitoring

import (
	"context"
	"fmt"
	"net/http"
	"runtime"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
)

// Metrics holds all Prometheus metrics
type Metrics struct {
	// Blockchain metrics
	BlockHeight         prometheus.Gauge
	BlockTime           prometheus.Histogram
	BlockSize           prometheus.Histogram
	BlockTransactions   prometheus.Histogram
	BlockValidationTime prometheus.Histogram
	ChainReorgs         prometheus.Counter
	ForkCount           prometheus.Counter

	// Transaction metrics
	TxProcessed       prometheus.Counter
	TxFailed          prometheus.Counter
	TxPoolSize        prometheus.Gauge
	TxValidationTime  prometheus.Histogram
	TxPropagationTime prometheus.Histogram
	TxFeeRate         prometheus.Histogram

	// Mining metrics
	HashRate         prometheus.Gauge
	MiningDifficulty prometheus.Gauge
	BlocksMined      prometheus.Counter
	MiningRevenue    prometheus.Counter
	InvalidBlocks    prometheus.Counter
	StaleBlocks      prometheus.Counter

	// Network metrics
	PeersConnected   prometheus.Gauge
	PeersInbound     prometheus.Gauge
	PeersOutbound    prometheus.Gauge
	NetworkLatency   prometheus.Histogram
	MessagesSent     *prometheus.CounterVec
	MessagesReceived *prometheus.CounterVec
	BytesSent        prometheus.Counter
	BytesReceived    prometheus.Counter
	BannedPeers      prometheus.Counter

	// Database metrics
	DBReads       prometheus.Counter
	DBWrites      prometheus.Counter
	DBSize        prometheus.Gauge
	DBCompactions prometheus.Counter
	DBCacheHits   prometheus.Counter
	DBCacheMisses prometheus.Counter

	// System metrics
	CPUUsage    prometheus.Gauge
	MemoryUsage prometheus.Gauge
	DiskUsage   prometheus.Gauge
	Goroutines  prometheus.Gauge
	GCPauseTime prometheus.Histogram

	// API metrics
	APIRequests        *prometheus.CounterVec
	APIRequestDuration *prometheus.HistogramVec
	APIErrors          *prometheus.CounterVec
	APIRateLimited     prometheus.Counter

	// Consensus metrics
	ConsensusRounds prometheus.Counter
	ConsensusFaults prometheus.Counter
	ValidatorCount  prometheus.Gauge

	// Economic metrics
	TotalSupplyDNT    prometheus.Gauge
	TotalSupplyAFC    prometheus.Gauge
	CirculatingSupply prometheus.Gauge
	MarketCap         prometheus.Gauge

	// Security metrics
	SecurityAlerts     prometheus.Counter
	FailedAuthAttempts prometheus.Counter
	DDoSAttempts       prometheus.Counter
}

// Monitor handles system monitoring
type Monitor struct {
	metrics *Metrics
	server  *http.Server
	logger  *zap.Logger
	stopCh  chan struct{}
	wg      sync.WaitGroup
}

// NewMonitor creates a new monitoring instance
func NewMonitor(port int, logger *zap.Logger) (*Monitor, error) {
	m := &Monitor{
		metrics: initMetrics(),
		logger:  logger,
		stopCh:  make(chan struct{}),
	}

	// Register all metrics
	if err := m.registerMetrics(); err != nil {
		return nil, fmt.Errorf("failed to register metrics: %w", err)
	}

	// Setup HTTP server for metrics endpoint
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/health", m.healthHandler)
	mux.HandleFunc("/ready", m.readyHandler)

	m.server = &http.Server{
		Addr:         fmt.Sprintf(":%d", port),
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	return m, nil
}

func initMetrics() *Metrics {
	return &Metrics{
		// Blockchain metrics
		BlockHeight: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "dinari_block_height",
			Help: "Current blockchain height",
		}),
		BlockTime: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "dinari_block_time_seconds",
			Help:    "Time between blocks in seconds",
			Buckets: []float64{1, 5, 10, 15, 30, 60},
		}),
		BlockSize: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "dinari_block_size_bytes",
			Help:    "Block size in bytes",
			Buckets: prometheus.ExponentialBuckets(1000, 2, 15),
		}),
		BlockTransactions: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "dinari_block_transactions",
			Help:    "Number of transactions per block",
			Buckets: []float64{0, 1, 10, 50, 100, 500, 1000, 5000},
		}),
		BlockValidationTime: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "dinari_block_validation_seconds",
			Help:    "Time to validate a block",
			Buckets: prometheus.ExponentialBuckets(0.001, 2, 15),
		}),
		ChainReorgs: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "dinari_chain_reorgs_total",
			Help: "Total number of chain reorganizations",
		}),
		ForkCount: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "dinari_fork_count_total",
			Help: "Total number of forks detected",
		}),

		// Transaction metrics
		TxProcessed: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "dinari_tx_processed_total",
			Help: "Total number of transactions processed",
		}),
		TxFailed: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "dinari_tx_failed_total",
			Help: "Total number of failed transactions",
		}),
		TxPoolSize: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "dinari_txpool_size",
			Help: "Current transaction pool size",
		}),
		TxValidationTime: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "dinari_tx_validation_seconds",
			Help:    "Transaction validation time",
			Buckets: prometheus.ExponentialBuckets(0.0001, 2, 15),
		}),
		TxPropagationTime: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "dinari_tx_propagation_seconds",
			Help:    "Transaction propagation time",
			Buckets: prometheus.ExponentialBuckets(0.01, 2, 15),
		}),
		TxFeeRate: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "dinari_tx_fee_rate",
			Help:    "Transaction fee rate in DNT per byte",
			Buckets: prometheus.ExponentialBuckets(1, 2, 10),
		}),

		// Mining metrics
		HashRate: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "dinari_hashrate",
			Help: "Current network hash rate",
		}),
		MiningDifficulty: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "dinari_mining_difficulty",
			Help: "Current mining difficulty",
		}),
		BlocksMined: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "dinari_blocks_mined_total",
			Help: "Total blocks mined by this node",
		}),
		MiningRevenue: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "dinari_mining_revenue_total",
			Help: "Total mining revenue earned",
		}),
		InvalidBlocks: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "dinari_invalid_blocks_total",
			Help: "Total invalid blocks received",
		}),
		StaleBlocks: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "dinari_stale_blocks_total",
			Help: "Total stale blocks",
		}),

		// Network metrics
		PeersConnected: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "dinari_peers_connected",
			Help: "Number of connected peers",
		}),
		PeersInbound: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "dinari_peers_inbound",
			Help: "Number of inbound peer connections",
		}),
		PeersOutbound: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "dinari_peers_outbound",
			Help: "Number of outbound peer connections",
		}),
		NetworkLatency: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "dinari_network_latency_seconds",
			Help:    "Network latency to peers",
			Buckets: prometheus.ExponentialBuckets(0.001, 2, 15),
		}),
		MessagesSent: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "dinari_messages_sent_total",
			Help: "Total messages sent by type",
		}, []string{"type"}),
		MessagesReceived: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "dinari_messages_received_total",
			Help: "Total messages received by type",
		}, []string{"type"}),
		BytesSent: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "dinari_bytes_sent_total",
			Help: "Total bytes sent",
		}),
		BytesReceived: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "dinari_bytes_received_total",
			Help: "Total bytes received",
		}),
		BannedPeers: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "dinari_banned_peers_total",
			Help: "Total number of banned peers",
		}),

		// Database metrics
		DBReads: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "dinari_db_reads_total",
			Help: "Total database reads",
		}),
		DBWrites: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "dinari_db_writes_total",
			Help: "Total database writes",
		}),
		DBSize: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "dinari_db_size_bytes",
			Help: "Database size in bytes",
		}),
		DBCompactions: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "dinari_db_compactions_total",
			Help: "Total database compactions",
		}),
		DBCacheHits: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "dinari_db_cache_hits_total",
			Help: "Database cache hits",
		}),
		DBCacheMisses: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "dinari_db_cache_misses_total",
			Help: "Database cache misses",
		}),

		// System metrics
		CPUUsage: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "dinari_cpu_usage_percent",
			Help: "CPU usage percentage",
		}),
		MemoryUsage: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "dinari_memory_usage_bytes",
			Help: "Memory usage in bytes",
		}),
		DiskUsage: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "dinari_disk_usage_bytes",
			Help: "Disk usage in bytes",
		}),
		Goroutines: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "dinari_goroutines",
			Help: "Number of goroutines",
		}),
		GCPauseTime: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "dinari_gc_pause_seconds",
			Help:    "GC pause time in seconds",
			Buckets: prometheus.ExponentialBuckets(0.00001, 2, 15),
		}),

		// API metrics
		APIRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "dinari_api_requests_total",
			Help: "Total API requests by method",
		}, []string{"method", "status"}),
		APIRequestDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "dinari_api_request_duration_seconds",
			Help:    "API request duration",
			Buckets: prometheus.ExponentialBuckets(0.001, 2, 15),
		}, []string{"method"}),
		APIErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "dinari_api_errors_total",
			Help: "Total API errors by type",
		}, []string{"type"}),
		APIRateLimited: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "dinari_api_rate_limited_total",
			Help: "Total rate limited API requests",
		}),

		// Consensus metrics
		ConsensusRounds: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "dinari_consensus_rounds_total",
			Help: "Total consensus rounds",
		}),
		ConsensusFaults: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "dinari_consensus_faults_total",
			Help: "Total consensus faults detected",
		}),
		ValidatorCount: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "dinari_validator_count",
			Help: "Number of active validators",
		}),

		// Economic metrics
		TotalSupplyDNT: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "dinari_total_supply_dnt",
			Help: "Total supply of DNT tokens",
		}),
		TotalSupplyAFC: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "dinari_total_supply_afc",
			Help: "Total supply of AFC tokens",
		}),
		CirculatingSupply: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "dinari_circulating_supply",
			Help: "Circulating supply of tokens",
		}),
		MarketCap: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "dinari_market_cap",
			Help: "Market capitalization",
		}),

		// Security metrics
		SecurityAlerts: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "dinari_security_alerts_total",
			Help: "Total security alerts",
		}),
		FailedAuthAttempts: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "dinari_failed_auth_attempts_total",
			Help: "Total failed authentication attempts",
		}),
		DDoSAttempts: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "dinari_ddos_attempts_total",
			Help: "Total DDoS attempts detected",
		}),
	}
}

func (m *Monitor) registerMetrics() error {
	collectors := []prometheus.Collector{
		m.metrics.BlockHeight,
		m.metrics.BlockTime,
		m.metrics.BlockSize,
		m.metrics.BlockTransactions,
		m.metrics.BlockValidationTime,
		m.metrics.ChainReorgs,
		m.metrics.ForkCount,
		m.metrics.TxProcessed,
		m.metrics.TxFailed,
		m.metrics.TxPoolSize,
		m.metrics.TxValidationTime,
		m.metrics.TxPropagationTime,
		m.metrics.TxFeeRate,
		m.metrics.HashRate,
		m.metrics.MiningDifficulty,
		m.metrics.BlocksMined,
		m.metrics.MiningRevenue,
		m.metrics.InvalidBlocks,
		m.metrics.StaleBlocks,
		m.metrics.PeersConnected,
		m.metrics.PeersInbound,
		m.metrics.PeersOutbound,
		m.metrics.NetworkLatency,
		m.metrics.MessagesSent,
		m.metrics.MessagesReceived,
		m.metrics.BytesSent,
		m.metrics.BytesReceived,
		m.metrics.BannedPeers,
		m.metrics.DBReads,
		m.metrics.DBWrites,
		m.metrics.DBSize,
		m.metrics.DBCompactions,
		m.metrics.DBCacheHits,
		m.metrics.DBCacheMisses,
		m.metrics.CPUUsage,
		m.metrics.MemoryUsage,
		m.metrics.DiskUsage,
		m.metrics.Goroutines,
		m.metrics.GCPauseTime,
		m.metrics.APIRequests,
		m.metrics.APIRequestDuration,
		m.metrics.APIErrors,
		m.metrics.APIRateLimited,
		m.metrics.ConsensusRounds,
		m.metrics.ConsensusFaults,
		m.metrics.ValidatorCount,
		m.metrics.TotalSupplyDNT,
		m.metrics.TotalSupplyAFC,
		m.metrics.CirculatingSupply,
		m.metrics.MarketCap,
		m.metrics.SecurityAlerts,
		m.metrics.FailedAuthAttempts,
		m.metrics.DDoSAttempts,
	}

	for _, collector := range collectors {
		if err := prometheus.Register(collector); err != nil {
			return fmt.Errorf("failed to register collector: %w", err)
		}
	}

	return nil
}

// Start starts the monitoring server
func (m *Monitor) Start() error {
	m.wg.Add(2)

	// Start metrics collection
	go m.collectSystemMetrics()

	// Start HTTP server
	go func() {
		defer m.wg.Done()
		m.logger.Info("Starting metrics server", zap.String("addr", m.server.Addr))
		if err := m.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			m.logger.Error("Metrics server error", zap.Error(err))
		}
	}()

	return nil
}

// Stop stops the monitoring server
func (m *Monitor) Stop(ctx context.Context) error {
	close(m.stopCh)

	if err := m.server.Shutdown(ctx); err != nil {
		return fmt.Errorf("failed to shutdown metrics server: %w", err)
	}

	m.wg.Wait()
	return nil
}

// collectSystemMetrics collects system-level metrics
func (m *Monitor) collectSystemMetrics() {
	defer m.wg.Done()

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			var memStats runtime.MemStats
			runtime.ReadMemStats(&memStats)

			m.metrics.MemoryUsage.Set(float64(memStats.Alloc))
			m.metrics.Goroutines.Set(float64(runtime.NumGoroutine()))

			// Collect GC pause times
			if len(memStats.PauseNs) > 0 {
				lastPause := memStats.PauseNs[(memStats.NumGC+255)%256]
				m.metrics.GCPauseTime.Observe(float64(lastPause) / 1e9)
			}

		case <-m.stopCh:
			return
		}
	}
}

// GetMetrics returns the metrics instance
func (m *Monitor) GetMetrics() *Metrics {
	return m.metrics
}

// healthHandler handles health check requests
func (m *Monitor) healthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

// readyHandler handles readiness check requests
func (m *Monitor) readyHandler(w http.ResponseWriter, r *http.Request) {
	// Add readiness checks here
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("READY"))
}

// RecordBlockMined records a newly mined block
func (m *Monitor) RecordBlockMined(height uint64, txCount int, size int, miningTime time.Duration) {
	m.metrics.BlockHeight.Set(float64(height))
	m.metrics.BlockTransactions.Observe(float64(txCount))
	m.metrics.BlockSize.Observe(float64(size))
	m.metrics.BlockTime.Observe(miningTime.Seconds())
	m.metrics.BlocksMined.Inc()
}

// RecordTransaction records transaction metrics
func (m *Monitor) RecordTransaction(success bool, validationTime time.Duration, feeRate uint64) {
	if success {
		m.metrics.TxProcessed.Inc()
	} else {
		m.metrics.TxFailed.Inc()
	}
	m.metrics.TxValidationTime.Observe(validationTime.Seconds())
	m.metrics.TxFeeRate.Observe(float64(feeRate))
}

// RecordPeerConnection records peer connection events
func (m *Monitor) RecordPeerConnection(connected bool, inbound bool) {
	if connected {
		m.metrics.PeersConnected.Inc()
		if inbound {
			m.metrics.PeersInbound.Inc()
		} else {
			m.metrics.PeersOutbound.Inc()
		}
	} else {
		m.metrics.PeersConnected.Dec()
		if inbound {
			m.metrics.PeersInbound.Dec()
		} else {
			m.metrics.PeersOutbound.Dec()
		}
	}
}

// RecordAPIRequest records API request metrics
func (m *Monitor) RecordAPIRequest(method string, statusCode int, duration time.Duration) {
	status := fmt.Sprintf("%d", statusCode)
	m.metrics.APIRequests.WithLabelValues(method, status).Inc()
	m.metrics.APIRequestDuration.WithLabelValues(method).Observe(duration.Seconds())

	if statusCode >= 400 {
		m.metrics.APIErrors.WithLabelValues(status).Inc()
	}

	if statusCode == 429 {
		m.metrics.APIRateLimited.Inc()
	}
}

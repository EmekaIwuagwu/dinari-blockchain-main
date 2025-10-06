package metrics

import (
	"fmt"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	// Metric namespaces
	namespaceBlockchain = "dinari_blockchain"
	namespaceMining     = "dinari_mining"
	namespaceP2P        = "dinari_p2p"
	namespaceMempool    = "dinari_mempool"
	namespaceAPI        = "dinari_api"
	namespaceState      = "dinari_state"
)

var (
	// Blockchain metrics
	BlockHeight = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: namespaceBlockchain,
		Name:      "height",
		Help:      "Current blockchain height",
	})
	
	BlocksProcessed = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: namespaceBlockchain,
		Name:      "blocks_processed_total",
		Help:      "Total number of blocks processed",
	})
	
	BlocksRejected = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: namespaceBlockchain,
		Name:      "blocks_rejected_total",
		Help:      "Total number of blocks rejected",
	})
	
	OrphanBlocks = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: namespaceBlockchain,
		Name:      "orphan_blocks",
		Help:      "Current number of orphan blocks",
	})
	
	ChainReorgs = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: namespaceBlockchain,
		Name:      "reorgs_total",
		Help:      "Total number of chain reorganizations",
	})
	
	BlockProcessingTime = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: namespaceBlockchain,
		Name:      "block_processing_seconds",
		Help:      "Time taken to process a block",
		Buckets:   prometheus.DefBuckets,
	})
	
	// Mining metrics
	MiningActive = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: namespaceMining,
		Name:      "active",
		Help:      "Whether mining is active (1) or not (0)",
	})
	
	HashRate = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: namespaceMining,
		Name:      "hashrate",
		Help:      "Current mining hash rate in hashes per second",
	})
	
	BlocksMined = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: namespaceMining,
		Name:      "blocks_mined_total",
		Help:      "Total number of blocks mined",
	})
	
	TotalReward = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: namespaceMining,
		Name:      "reward_total",
		Help:      "Total mining rewards earned (in smallest unit)",
	})
	
	MiningThreads = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: namespaceMining,
		Name:      "threads",
		Help:      "Number of active mining threads",
	})
	
	// P2P metrics
	ConnectedPeers = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: namespaceP2P,
		Name:      "connected_peers",
		Help:      "Number of connected peers",
	})
	
	InboundPeers = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: namespaceP2P,
		Name:      "inbound_peers",
		Help:      "Number of inbound peer connections",
	})
	
	OutboundPeers = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: namespaceP2P,
		Name:      "outbound_peers",
		Help:      "Number of outbound peer connections",
	})
	
	BannedPeers = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: namespaceP2P,
		Name:      "banned_peers",
		Help:      "Number of banned peers",
	})
	
	BlocksReceived = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: namespaceP2P,
		Name:      "blocks_received_total",
		Help:      "Total number of blocks received from peers",
	})
	
	BlocksSent = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: namespaceP2P,
		Name:      "blocks_sent_total",
		Help:      "Total number of blocks sent to peers",
	})
	
	TransactionsReceived = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: namespaceP2P,
		Name:      "transactions_received_total",
		Help:      "Total number of transactions received from peers",
	})
	
	TransactionsSent = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: namespaceP2P,
		Name:      "transactions_sent_total",
		Help:      "Total number of transactions sent to peers",
	})
	
	BytesReceived = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: namespaceP2P,
		Name:      "bytes_received_total",
		Help:      "Total bytes received from peers",
	})
	
	BytesSent = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: namespaceP2P,
		Name:      "bytes_sent_total",
		Help:      "Total bytes sent to peers",
	})
	
	// Mempool metrics
	MempoolSize = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: namespaceMempool,
		Name:      "size",
		Help:      "Current number of transactions in mempool",
	})
	
	MempoolBytes = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: namespaceMempool,
		Name:      "bytes",
		Help:      "Total size of mempool in bytes",
	})
	
	TransactionsAccepted = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: namespaceMempool,
		Name:      "transactions_accepted_total",
		Help:      "Total number of transactions accepted into mempool",
	})
	
	TransactionsRejected = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: namespaceMempool,
		Name:      "transactions_rejected_total",
		Help:      "Total number of transactions rejected",
	})
	
	TransactionsEvicted = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: namespaceMempool,
		Name:      "transactions_evicted_total",
		Help:      "Total number of transactions evicted from mempool",
	})
	
	// API metrics
	APIRequests = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespaceAPI,
			Name:      "requests_total",
			Help:      "Total number of API requests",
		},
		[]string{"method", "endpoint", "status"},
	)
	
	APIRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: namespaceAPI,
			Name:      "request_duration_seconds",
			Help:      "API request duration in seconds",
			Buckets:   []float64{0.001, 0.01, 0.1, 0.5, 1, 2.5, 5, 10},
		},
		[]string{"method", "endpoint"},
	)
	
	APIActiveConnections = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: namespaceAPI,
		Name:      "active_connections",
		Help:      "Number of active API connections",
	})
	
	APIRateLimitHits = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: namespaceAPI,
		Name:      "rate_limit_hits_total",
		Help:      "Total number of rate limit hits",
	})
	
	// State metrics
	StateAccounts = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: namespaceState,
		Name:      "accounts_total",
		Help:      "Total number of accounts in state",
	})
	
	StateTotalDNT = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: namespaceState,
		Name:      "total_dnt",
		Help:      "Total DNT in circulation (in smallest unit)",
	})
	
	StateTotalAFC = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: namespaceState,
		Name:      "total_afc",
		Help:      "Total AFC in circulation (in smallest unit)",
	})
	
	StateCommits = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: namespaceState,
		Name:      "commits_total",
		Help:      "Total number of state commits",
	})
	
	StateRollbacks = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: namespaceState,
		Name:      "rollbacks_total",
		Help:      "Total number of state rollbacks",
	})
	
	// Database metrics
	DatabaseSize = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "dinari_database",
		Name:      "size_bytes",
		Help:      "Total database size in bytes",
	})
	
	DatabaseCacheHits = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "dinari_database",
		Name:      "cache_hits_total",
		Help:      "Total number of cache hits",
	})
	
	DatabaseCacheMisses = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "dinari_database",
		Name:      "cache_misses_total",
		Help:      "Total number of cache misses",
	})
)

// MetricsServer manages the Prometheus metrics HTTP server
type MetricsServer struct {
	server *http.Server
	port   int
}

// NewMetricsServer creates a new metrics server
func NewMetricsServer(port int) *MetricsServer {
	return &MetricsServer{
		port: port,
	}
}

// Start starts the metrics HTTP server
func (s *MetricsServer) Start() error {
	// Register all metrics
	if err := registerMetrics(); err != nil {
		return fmt.Errorf("failed to register metrics: %w", err)
	}
	
	// Create HTTP server
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})
	
	s.server = &http.Server{
		Addr:         fmt.Sprintf(":%d", s.port),
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	
	fmt.Printf("📊 Metrics server starting on :%d\n", s.port)
	fmt.Printf("   Prometheus endpoint: http://localhost:%d/metrics\n", s.port)
	
	return s.server.ListenAndServe()
}

// Stop stops the metrics server
func (s *MetricsServer) Stop() error {
	if s.server != nil {
		return s.server.Close()
	}
	return nil
}

// registerMetrics registers all Prometheus metrics
func registerMetrics() error {
	// Blockchain metrics
	prometheus.MustRegister(BlockHeight)
	prometheus.MustRegister(BlocksProcessed)
	prometheus.MustRegister(BlocksRejected)
	prometheus.MustRegister(OrphanBlocks)
	prometheus.MustRegister(ChainReorgs)
	prometheus.MustRegister(BlockProcessingTime)
	
	// Mining metrics
	prometheus.MustRegister(MiningActive)
	prometheus.MustRegister(HashRate)
	prometheus.MustRegister(BlocksMined)
	prometheus.MustRegister(TotalReward)
	prometheus.MustRegister(MiningThreads)
	
	// P2P metrics
	prometheus.MustRegister(ConnectedPeers)
	prometheus.MustRegister(InboundPeers)
	prometheus.MustRegister(OutboundPeers)
	prometheus.MustRegister(BannedPeers)
	prometheus.MustRegister(BlocksReceived)
	prometheus.MustRegister(BlocksSent)
	prometheus.MustRegister(TransactionsReceived)
	prometheus.MustRegister(TransactionsSent)
	prometheus.MustRegister(BytesReceived)
	prometheus.MustRegister(BytesSent)
	
	// Mempool metrics
	prometheus.MustRegister(MempoolSize)
	prometheus.MustRegister(MempoolBytes)
	prometheus.MustRegister(TransactionsAccepted)
	prometheus.MustRegister(TransactionsRejected)
	prometheus.MustRegister(TransactionsEvicted)
	
	// API metrics
	prometheus.MustRegister(APIRequests)
	prometheus.MustRegister(APIRequestDuration)
	prometheus.MustRegister(APIActiveConnections)
	prometheus.MustRegister(APIRateLimitHits)
	
	// State metrics
	prometheus.MustRegister(StateAccounts)
	prometheus.MustRegister(StateTotalDNT)
	prometheus.MustRegister(StateTotalAFC)
	prometheus.MustRegister(StateCommits)
	prometheus.MustRegister(StateRollbacks)
	
	// Database metrics
	prometheus.MustRegister(DatabaseSize)
	prometheus.MustRegister(DatabaseCacheHits)
	prometheus.MustRegister(DatabaseCacheMisses)
	
	return nil
}

// Helper functions for recording metrics

// RecordBlockAdded records metrics when a block is added
func RecordBlockAdded(height uint64, processingTime time.Duration) {
	BlockHeight.Set(float64(height))
	BlocksProcessed.Inc()
	BlockProcessingTime.Observe(processingTime.Seconds())
}

// RecordBlockRejected records metrics when a block is rejected
func RecordBlockRejected() {
	BlocksRejected.Inc()
}

// RecordBlockMined records metrics when a block is mined
func RecordBlockMined(reward uint64) {
	BlocksMined.Inc()
	TotalReward.Add(float64(reward))
}

// RecordHashRate updates the mining hash rate
func RecordHashRate(hashrate float64) {
	HashRate.Set(hashrate)
}

// RecordPeerConnected records when a peer connects
func RecordPeerConnected(direction string) {
	ConnectedPeers.Inc()
	if direction == "inbound" {
		InboundPeers.Inc()
	} else {
		OutboundPeers.Inc()
	}
}

// RecordPeerDisconnected records when a peer disconnects
func RecordPeerDisconnected(direction string) {
	ConnectedPeers.Dec()
	if direction == "inbound" {
		InboundPeers.Dec()
	} else {
		OutboundPeers.Dec()
	}
}

// RecordTransactionAdded records when a transaction is added to mempool
func RecordTransactionAdded() {
	MempoolSize.Inc()
	TransactionsAccepted.Inc()
}

// RecordTransactionRejected records when a transaction is rejected
func RecordTransactionRejected() {
	TransactionsRejected.Inc()
}

// RecordAPIRequest records an API request
func RecordAPIRequest(method, endpoint, status string, duration time.Duration) {
	APIRequests.WithLabelValues(method, endpoint, status).Inc()
	APIRequestDuration.WithLabelValues(method, endpoint).Observe(duration.Seconds())
}

// UpdateMempoolStats updates mempool statistics
func UpdateMempoolStats(size int, bytes int64) {
	MempoolSize.Set(float64(size))
	MempoolBytes.Set(float64(bytes))
}

// UpdateStateStats updates state statistics
func UpdateStateStats(accounts int, dnt, afc uint64) {
	StateAccounts.Set(float64(accounts))
	StateTotalDNT.Set(float64(dnt))
	StateTotalAFC.Set(float64(afc))
}
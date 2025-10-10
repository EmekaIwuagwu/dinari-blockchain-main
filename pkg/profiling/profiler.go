package profiling

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"runtime/pprof"
	"runtime/trace"
	"sync"
	"time"
)

// PerformanceProfiler provides comprehensive performance monitoring
type PerformanceProfiler struct {
	// Performance metrics
	metrics *PerformanceMetrics
	
	// Bottleneck detection
	bottleneckDetector *BottleneckDetector
	
	// Memory profiler
	memoryProfiler *MemoryProfiler
	
	// CPU profiler
	cpuProfiler *CPUProfiler
	
	// Trace collector
	traceCollector *TraceCollector
	
	// Configuration
	config *ProfilerConfig
	
	mu sync.RWMutex
}

// ProfilerConfig contains profiler configuration
type ProfilerConfig struct {
	EnableCPUProfiling    bool
	EnableMemoryProfiling bool
	EnableTracing         bool
	ProfileOutputDir      string
	SampleRate            time.Duration
	EnableBottleneckDetect bool
}

// PerformanceMetrics tracks system performance
type PerformanceMetrics struct {
	// Throughput metrics
	TPS                  float64
	BlocksPerSecond      float64
	
	// Latency metrics
	AvgBlockTime         time.Duration
	AvgTxProcessingTime  time.Duration
	P50Latency           time.Duration
	P95Latency           time.Duration
	P99Latency           time.Duration
	
	// Resource utilization
	CPUUsagePercent      float64
	MemoryUsageMB        uint64
	GoroutineCount       int
	HeapAllocMB          uint64
	
	// Database performance
	DBReadLatency        time.Duration
	DBWriteLatency       time.Duration
	DBCacheHitRate       float64
	
	// Network performance
	NetworkBandwidthMbps float64
	PeerLatencyMs        map[string]float64
	
	timestamp            time.Time
	mu                   sync.RWMutex
}

// BottleneckDetector identifies performance bottlenecks
type BottleneckDetector struct {
	operations    map[string]*OperationStats
	hotspots      []Hotspot
	slowQueries   []SlowQuery
	mu            sync.RWMutex
}

// OperationStats tracks operation performance
type OperationStats struct {
	Name          string
	Count         uint64
	TotalDuration time.Duration
	AvgDuration   time.Duration
	MaxDuration   time.Duration
	MinDuration   time.Duration
	LastExecution time.Time
	Percentiles   map[int]time.Duration // p50, p95, p99
}

// Hotspot represents a performance hotspot
type Hotspot struct {
	Function      string
	File          string
	Line          int
	CPUPercent    float64
	ExecutionTime time.Duration
	CallCount     uint64
}

// SlowQuery represents a slow database query
type SlowQuery struct {
	Query         string
	Duration      time.Duration
	Timestamp     time.Time
	StackTrace    string
}

// MemoryProfiler monitors memory usage
type MemoryProfiler struct {
	snapshots     []*MemorySnapshot
	maxSnapshots  int
	leakDetector  *LeakDetector
	mu            sync.RWMutex
}

// MemorySnapshot captures memory state
type MemorySnapshot struct {
	Timestamp     time.Time
	HeapAlloc     uint64
	HeapInuse     uint64
	StackInuse    uint64
	NumGC         uint32
	GCPauseNs     uint64
	Goroutines    int
	TopAllocators []Allocator
}

// Allocator represents memory allocation source
type Allocator struct {
	Function string
	File     string
	Line     int
	Bytes    uint64
}

// LeakDetector detects memory leaks
type LeakDetector struct {
	baseline      *MemorySnapshot
	growthRate    float64
	leakSuspected bool
}

// CPUProfiler monitors CPU usage
type CPUProfiler struct {
	profiles     []*CPUProfile
	hotFunctions []string
	mu           sync.RWMutex
}

// CPUProfile represents CPU profile data
type CPUProfile struct {
	Timestamp   time.Time
	Duration    time.Duration
	ProfileData []byte
	TopFunctions []FunctionProfile
}

// FunctionProfile contains function-level CPU data
type FunctionProfile struct {
	Name          string
	CPUPercent    float64
	CPUTime       time.Duration
	Calls         uint64
}

// TraceCollector collects execution traces
type TraceCollector struct {
	traces      []*ExecutionTrace
	traceFile   *os.File
	mu          sync.RWMutex
}

// ExecutionTrace represents an execution trace
type ExecutionTrace struct {
	Timestamp time.Time
	Duration  time.Duration
	Events    []TraceEvent
}

// TraceEvent represents a trace event
type TraceEvent struct {
	Type      string
	Timestamp time.Time
	Goroutine uint64
	Details   map[string]interface{}
}

// NewPerformanceProfiler creates a new performance profiler
func NewPerformanceProfiler(config *ProfilerConfig) *PerformanceProfiler {
	// Create output directory
	os.MkdirAll(config.ProfileOutputDir, 0755)
	
	return &PerformanceProfiler{
		metrics: &PerformanceMetrics{
			PeerLatencyMs: make(map[string]float64),
		},
		bottleneckDetector: &BottleneckDetector{
			operations: make(map[string]*OperationStats),
			hotspots:   make([]Hotspot, 0),
			slowQueries: make([]SlowQuery, 0),
		},
		memoryProfiler: &MemoryProfiler{
			snapshots:    make([]*MemorySnapshot, 0),
			maxSnapshots: 100,
			leakDetector: &LeakDetector{},
		},
		cpuProfiler: &CPUProfiler{
			profiles: make([]*CPUProfile, 0),
		},
		traceCollector: &TraceCollector{
			traces: make([]*ExecutionTrace, 0),
		},
		config: config,
	}
}

// Start begins profiling
func (pp *PerformanceProfiler) Start(ctx context.Context) error {
	// Start CPU profiling
	if pp.config.EnableCPUProfiling {
		go pp.runCPUProfiling(ctx)
	}
	
	// Start memory profiling
	if pp.config.EnableMemoryProfiling {
		go pp.runMemoryProfiling(ctx)
	}
	
	// Start tracing
	if pp.config.EnableTracing {
		go pp.runTracing(ctx)
	}
	
	// Start metrics collection
	go pp.collectMetrics(ctx)
	
	// Start bottleneck detection
	if pp.config.EnableBottleneckDetect {
		go pp.detectBottlenecks(ctx)
	}
	
	return nil
}

// TrackOperation tracks execution time of an operation
func (pp *PerformanceProfiler) TrackOperation(name string, duration time.Duration) {
	pp.bottleneckDetector.mu.Lock()
	defer pp.bottleneckDetector.mu.Unlock()
	
	stats, exists := pp.bottleneckDetector.operations[name]
	if !exists {
		stats = &OperationStats{
			Name:        name,
			MinDuration: duration,
			MaxDuration: duration,
			Percentiles: make(map[int]time.Duration),
		}
		pp.bottleneckDetector.operations[name] = stats
	}
	
	// Update stats
	stats.Count++
	stats.TotalDuration += duration
	stats.AvgDuration = time.Duration(int64(stats.TotalDuration) / int64(stats.Count))
	stats.LastExecution = time.Now()
	
	if duration < stats.MinDuration {
		stats.MinDuration = duration
	}
	if duration > stats.MaxDuration {
		stats.MaxDuration = duration
	}
}

// runCPUProfiling runs CPU profiling
func (pp *PerformanceProfiler) runCPUProfiling(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pp.captureCPUProfile()
		}
	}
}

// captureCPUProfile captures a CPU profile
func (pp *PerformanceProfiler) captureCPUProfile() {
	filename := fmt.Sprintf("%s/cpu_profile_%d.prof", 
		pp.config.ProfileOutputDir, 
		time.Now().Unix())
	
	f, err := os.Create(filename)
	if err != nil {
		fmt.Printf("Failed to create CPU profile: %v\n", err)
		return
	}
	defer f.Close()
	
	// Start profiling
	if err := pprof.StartCPUProfile(f); err != nil {
		fmt.Printf("Failed to start CPU profiling: %v\n", err)
		return
	}
	
	// Profile for 30 seconds
	time.Sleep(30 * time.Second)
	pprof.StopCPUProfile()
	
	fmt.Printf("CPU profile saved to: %s\n", filename)
}

// runMemoryProfiling runs memory profiling
func (pp *PerformanceProfiler) runMemoryProfiling(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pp.captureMemorySnapshot()
			pp.detectMemoryLeaks()
		}
	}
}

// captureMemorySnapshot captures memory state
func (pp *PerformanceProfiler) captureMemorySnapshot() {
	pp.memoryProfiler.mu.Lock()
	defer pp.memoryProfiler.mu.Unlock()
	
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	
	snapshot := &MemorySnapshot{
		Timestamp:  time.Now(),
		HeapAlloc:  m.HeapAlloc,
		HeapInuse:  m.HeapInuse,
		StackInuse: m.StackInuse,
		NumGC:      m.NumGC,
		GCPauseNs:  m.PauseNs[(m.NumGC+255)%256],
		Goroutines: runtime.NumGoroutine(),
	}
	
	pp.memoryProfiler.snapshots = append(pp.memoryProfiler.snapshots, snapshot)
	
	// Rotate old snapshots
	if len(pp.memoryProfiler.snapshots) > pp.memoryProfiler.maxSnapshots {
		pp.memoryProfiler.snapshots = pp.memoryProfiler.snapshots[1:]
	}
	
	// Write heap profile periodically
	if len(pp.memoryProfiler.snapshots)%10 == 0 {
		pp.writeHeapProfile()
	}
}

// writeHeapProfile writes heap profile to disk
func (pp *PerformanceProfiler) writeHeapProfile() {
	filename := fmt.Sprintf("%s/heap_profile_%d.prof", 
		pp.config.ProfileOutputDir, 
		time.Now().Unix())
	
	f, err := os.Create(filename)
	if err != nil {
		return
	}
	defer f.Close()
	
	runtime.GC() // Get up-to-date statistics
	pprof.WriteHeapProfile(f)
	
	fmt.Printf("Heap profile saved to: %s\n", filename)
}

// detectMemoryLeaks detects potential memory leaks
func (pp *PerformanceProfiler) detectMemoryLeaks() {
	pp.memoryProfiler.mu.RLock()
	defer pp.memoryProfiler.mu.RUnlock()
	
	if len(pp.memoryProfiler.snapshots) < 10 {
		return
	}
	
	// Check if memory is consistently growing
	recent := pp.memoryProfiler.snapshots[len(pp.memoryProfiler.snapshots)-10:]
	
	growthCount := 0
	for i := 1; i < len(recent); i++ {
		if recent[i].HeapAlloc > recent[i-1].HeapAlloc {
			growthCount++
		}
	}
	
	// If memory grew in 8 out of 10 samples, suspect leak
	if growthCount >= 8 {
		growth := recent[len(recent)-1].HeapAlloc - recent[0].HeapAlloc
		growthRate := float64(growth) / float64(recent[0].HeapAlloc) * 100
		
		if growthRate > 20 {
			fmt.Printf("⚠️  ALERT: Potential memory leak detected\n")
			fmt.Printf("   Memory growth: %.2f%% over last 10 samples\n", growthRate)
			pp.memoryProfiler.leakDetector.leakSuspected = true
		}
	}
}

// runTracing runs execution tracing
func (pp *PerformanceProfiler) runTracing(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pp.captureTrace()
		}
	}
}

// captureTrace captures execution trace
func (pp *PerformanceProfiler) captureTrace() {
	filename := fmt.Sprintf("%s/trace_%d.out", 
		pp.config.ProfileOutputDir, 
		time.Now().Unix())
	
	f, err := os.Create(filename)
	if err != nil {
		return
	}
	defer f.Close()
	
	// Start tracing
	if err := trace.Start(f); err != nil {
		return
	}
	
	// Trace for 10 seconds
	time.Sleep(10 * time.Second)
	trace.Stop()
	
	fmt.Printf("Trace saved to: %s\n", filename)
}

// collectMetrics collects performance metrics
func (pp *PerformanceProfiler) collectMetrics(ctx context.Context) {
	ticker := time.NewTicker(pp.config.SampleRate)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pp.updateMetrics()
		}
	}
}

// updateMetrics updates current metrics
func (pp *PerformanceProfiler) updateMetrics() {
	pp.metrics.mu.Lock()
	defer pp.metrics.mu.Unlock()
	
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	
	pp.metrics.MemoryUsageMB = m.Alloc / 1024 / 1024
	pp.metrics.HeapAllocMB = m.HeapAlloc / 1024 / 1024
	pp.metrics.GoroutineCount = runtime.NumGoroutine()
	pp.metrics.timestamp = time.Now()
	
	// CPU usage (simplified - use proper CPU monitoring in production)
	pp.metrics.CPUUsagePercent = pp.estimateCPUUsage()
}

// estimateCPUUsage estimates CPU usage
func (pp *PerformanceProfiler) estimateCPUUsage() float64 {
	// Placeholder - implement proper CPU monitoring
	// Use gopsutil or similar library for accurate CPU measurement
	return 0.0
}

// detectBottlenecks identifies performance bottlenecks
func (pp *PerformanceProfiler) detectBottlenecks(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pp.analyzeBottlenecks()
		}
	}
}

// analyzeBottlenecks analyzes operations for bottlenecks
func (pp *PerformanceProfiler) analyzeBottlenecks() {
	pp.bottleneckDetector.mu.RLock()
	defer pp.bottleneckDetector.mu.RUnlock()
	
	// Find slowest operations
	type slowOp struct {
		name string
		avg  time.Duration
	}
	
	slowOps := make([]slowOp, 0)
	
	for name, stats := range pp.bottleneckDetector.operations {
		if stats.AvgDuration > 100*time.Millisecond {
			slowOps = append(slowOps, slowOp{
				name: name,
				avg:  stats.AvgDuration,
			})
		}
	}
	
	// Sort by duration
	for i := 0; i < len(slowOps); i++ {
		for j := i + 1; j < len(slowOps); j++ {
			if slowOps[j].avg > slowOps[i].avg {
				slowOps[i], slowOps[j] = slowOps[j], slowOps[i]
			}
		}
	}
	
	// Report top bottlenecks
	if len(slowOps) > 0 {
		fmt.Println("🐌 Performance Bottlenecks Detected:")
		for i := 0; i < len(slowOps) && i < 5; i++ {
			fmt.Printf("   %d. %s - Avg: %v\n", i+1, slowOps[i].name, slowOps[i].avg)
		}
	}
}

// GetMetrics returns current performance metrics
func (pp *PerformanceProfiler) GetMetrics() *PerformanceMetrics {
	pp.metrics.mu.RLock()
	defer pp.metrics.mu.RUnlock()
	
	// Create copy
	metrics := *pp.metrics
	return &metrics
}

// GenerateReport generates a comprehensive performance report
func (pp *PerformanceProfiler) GenerateReport() (*PerformanceReport, error) {
	report := &PerformanceReport{
		Timestamp:     time.Now(),
		Metrics:       pp.GetMetrics(),
		Operations:    pp.getOperationStats(),
		MemoryHealth:  pp.getMemoryHealth(),
		Bottlenecks:   pp.getBottlenecks(),
	}
	
	return report, nil
}

// getOperationStats returns operation statistics
func (pp *PerformanceProfiler) getOperationStats() []OperationStats {
	pp.bottleneckDetector.mu.RLock()
	defer pp.bottleneckDetector.mu.RUnlock()
	
	stats := make([]OperationStats, 0, len(pp.bottleneckDetector.operations))
	for _, op := range pp.bottleneckDetector.operations {
		stats = append(stats, *op)
	}
	
	return stats
}

// getMemoryHealth returns memory health status
func (pp *PerformanceProfiler) getMemoryHealth() MemoryHealth {
	pp.memoryProfiler.mu.RLock()
	defer pp.memoryProfiler.mu.RUnlock()
	
	if len(pp.memoryProfiler.snapshots) == 0 {
		return MemoryHealth{Status: "UNKNOWN"}
	}
	
	latest := pp.memoryProfiler.snapshots[len(pp.memoryProfiler.snapshots)-1]
	
	health := MemoryHealth{
		Status:        "HEALTHY",
		HeapAllocMB:   latest.HeapAlloc / 1024 / 1024,
		GoroutineCount: latest.Goroutines,
		LeakDetected:  pp.memoryProfiler.leakDetector.leakSuspected,
	}
	
	// Determine status
	if health.LeakDetected {
		health.Status = "LEAK_SUSPECTED"
	} else if health.HeapAllocMB > 1000 {
		health.Status = "HIGH_USAGE"
	}
	
	return health
}

// getBottlenecks returns identified bottlenecks
func (pp *PerformanceProfiler) getBottlenecks() []string {
	pp.bottleneckDetector.mu.RLock()
	defer pp.bottleneckDetector.mu.RUnlock()
	
	bottlenecks := make([]string, 0)
	
	for name, stats := range pp.bottleneckDetector.operations {
		if stats.AvgDuration > 100*time.Millisecond {
			bottlenecks = append(bottlenecks, 
				fmt.Sprintf("%s (avg: %v)", name, stats.AvgDuration))
		}
	}
	
	return bottlenecks
}

// PerformanceReport represents a performance report
type PerformanceReport struct {
	Timestamp    time.Time
	Metrics      *PerformanceMetrics
	Operations   []OperationStats
	MemoryHealth MemoryHealth
	Bottlenecks  []string
}

// MemoryHealth represents memory health status
type MemoryHealth struct {
	Status         string
	HeapAllocMB    uint64
	GoroutineCount int
	LeakDetected   bool
}

// ExportReport exports report as JSON
func (pr *PerformanceReport) ExportJSON() ([]byte, error) {
	return json.MarshalIndent(pr, "", "  ")
}
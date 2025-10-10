package storage

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/dgraph-io/badger/v3"
)

// OptimizedDB provides high-performance database operations
type OptimizedDB struct {
	db               *badger.DB
	cache            *LRUCache
	writeQueue       chan *WriteOp
	checkpointMgr    *CheckpointManager
	backupMgr        *BackupManager
	compactionMgr    *CompactionManager
	config           *DBConfig
	metrics          *DBMetrics
	mu               sync.RWMutex
	shutdownChan     chan struct{}
}

// DBConfig contains database configuration
type DBConfig struct {
	DataDir              string
	MaxTableSize         int64
	NumLevelZeroTables   int
	NumMemtables         int
	ValueLogFileSize     int64
	NumCompactors        int
	EnableCompression    bool
	EnableEncryption     bool
	CacheSize            int64
	BatchWriteSize       int
	CheckpointInterval   time.Duration
	BackupRetention      int
	EnableWAL            bool
}

// WriteOp represents a database write operation
type WriteOp struct {
	Key      []byte
	Value    []byte
	TTL      time.Duration
	Delete   bool
	Callback func(error)
}

// CheckpointManager manages database checkpoints
type CheckpointManager struct {
	db               *badger.DB
	checkpointDir    string
	interval         time.Duration
	maxCheckpoints   int
	lastCheckpoint   time.Time
	mu               sync.Mutex
}

// BackupManager handles automated backups
type BackupManager struct {
	db             *badger.DB
	backupDir      string
	retention      int
	backupSchedule *BackupSchedule
	mu             sync.Mutex
}

// BackupSchedule defines backup timing
type BackupSchedule struct {
	Hourly  bool
	Daily   bool
	Weekly  bool
	Monthly bool
}

// CompactionManager optimizes database storage
type CompactionManager struct {
	db                *badger.DB
	compactionWorkers int
	stopChan          chan struct{}
}

// DBMetrics tracks database performance metrics
type DBMetrics struct {
	ReadCount        uint64
	WriteCount       uint64
	DeleteCount      uint64
	CacheHits        uint64
	CacheMisses      uint64
	AvgReadLatency   time.Duration
	AvgWriteLatency  time.Duration
	DiskUsageBytes   uint64
	NumKeys          uint64
	mu               sync.RWMutex
}

// LRUCache implements a thread-safe LRU cache
type LRUCache struct {
	capacity int
	cache    map[string]*cacheEntry
	order    []string
	mu       sync.RWMutex
}

type cacheEntry struct {
	value      []byte
	lastAccess time.Time
}

// NewOptimizedDB creates a new optimized database instance
func NewOptimizedDB(config *DBConfig) (*OptimizedDB, error) {
	// Configure BadgerDB options for production
	opts := badger.DefaultOptions(config.DataDir)
	opts.Logger = nil // Use custom logger
	
	// Performance optimizations
	opts.MaxTableSize = config.MaxTableSize
	opts.NumLevelZeroTables = config.NumLevelZeroTables
	opts.NumMemtables = config.NumMemtables
	opts.ValueLogFileSize = config.ValueLogFileSize
	opts.NumCompactors = config.NumCompactors
	
	// Compression
	if config.EnableCompression {
		opts.Compression = badger.ZSTD
		opts.ZSTDCompressionLevel = 3
	}
	
	// Encryption (if enabled)
	if config.EnableEncryption {
		// Implement encryption key derivation
		// opts.EncryptionKey = deriveEncryptionKey()
	}

	// Sync writes for durability
	opts.SyncWrites = true

	// Open database
	db, err := badger.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	odb := &OptimizedDB{
		db:           db,
		cache:        NewLRUCache(int(config.CacheSize)),
		writeQueue:   make(chan *WriteOp, 10000),
		config:       config,
		metrics:      &DBMetrics{},
		shutdownChan: make(chan struct{}),
	}

	// Initialize checkpoint manager
	odb.checkpointMgr = &CheckpointManager{
		db:             db,
		checkpointDir:  filepath.Join(config.DataDir, "checkpoints"),
		interval:       config.CheckpointInterval,
		maxCheckpoints: 10,
	}
	os.MkdirAll(odb.checkpointMgr.checkpointDir, 0700)

	// Initialize backup manager
	odb.backupMgr = &BackupManager{
		db:        db,
		backupDir: filepath.Join(config.DataDir, "backups"),
		retention: config.BackupRetention,
		backupSchedule: &BackupSchedule{
			Hourly: true,
			Daily:  true,
		},
	}
	os.MkdirAll(odb.backupMgr.backupDir, 0700)

	// Initialize compaction manager
	odb.compactionMgr = &CompactionManager{
		db:                db,
		compactionWorkers: config.NumCompactors,
		stopChan:          make(chan struct{}),
	}

	// Start background workers
	go odb.writeWorker()
	go odb.checkpointWorker()
	go odb.garbageCollectionWorker()
	go odb.compactionWorker()

	return odb, nil
}

// NewLRUCache creates a new LRU cache
func NewLRUCache(capacity int) *LRUCache {
	return &LRUCache{
		capacity: capacity,
		cache:    make(map[string]*cacheEntry),
		order:    make([]string, 0, capacity),
	}
}

// Get retrieves a value from the database with caching
func (odb *OptimizedDB) Get(key []byte) ([]byte, error) {
	start := time.Now()
	defer func() {
		odb.updateReadLatency(time.Since(start))
	}()

	// Check cache first
	if value, found := odb.cache.Get(string(key)); found {
		odb.metrics.mu.Lock()
		odb.metrics.CacheHits++
		odb.metrics.mu.Unlock()
		return value, nil
	}

	odb.metrics.mu.Lock()
	odb.metrics.CacheMisses++
	odb.metrics.mu.Unlock()

	// Read from database
	var value []byte
	err := odb.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(key)
		if err != nil {
			return err
		}

		value, err = item.ValueCopy(nil)
		return err
	})

	if err != nil {
		if err == badger.ErrKeyNotFound {
			return nil, ErrKeyNotFound
		}
		return nil, err
	}

	// Update cache
	odb.cache.Put(string(key), value)

	odb.metrics.mu.Lock()
	odb.metrics.ReadCount++
	odb.metrics.mu.Unlock()

	return value, nil
}

// Set writes a key-value pair to the database
func (odb *OptimizedDB) Set(key, value []byte) error {
	return odb.SetWithTTL(key, value, 0)
}

// SetWithTTL writes a key-value pair with expiration
func (odb *OptimizedDB) SetWithTTL(key, value []byte, ttl time.Duration) error {
	op := &WriteOp{
		Key:   key,
		Value: value,
		TTL:   ttl,
	}

	// Use write queue for batching
	select {
	case odb.writeQueue <- op:
		return nil
	case <-time.After(5 * time.Second):
		return errors.New("write queue timeout")
	}
}

// Delete removes a key from the database
func (odb *OptimizedDB) Delete(key []byte) error {
	op := &WriteOp{
		Key:    key,
		Delete: true,
	}

	select {
	case odb.writeQueue <- op:
		return nil
	case <-time.After(5 * time.Second):
		return errors.New("write queue timeout")
	}
}

// BatchWrite performs a batch write operation
func (odb *OptimizedDB) BatchWrite(ops []WriteOp) error {
	start := time.Now()
	defer func() {
		odb.updateWriteLatency(time.Since(start))
	}()

	txn := odb.db.NewTransaction(true)
	defer txn.Discard()

	for _, op := range ops {
		if op.Delete {
			if err := txn.Delete(op.Key); err != nil {
				return err
			}
			odb.cache.Delete(string(op.Key))
		} else {
			entry := badger.NewEntry(op.Key, op.Value)
			if op.TTL > 0 {
				entry = entry.WithTTL(op.TTL)
			}
			if err := txn.SetEntry(entry); err != nil {
				return err
			}
			odb.cache.Put(string(op.Key), op.Value)
		}
	}

	if err := txn.Commit(); err != nil {
		return err
	}

	odb.metrics.mu.Lock()
	odb.metrics.WriteCount += uint64(len(ops))
	odb.metrics.mu.Unlock()

	return nil
}

// writeWorker processes write operations in batches
func (odb *OptimizedDB) writeWorker() {
	batch := make([]WriteOp, 0, odb.config.BatchWriteSize)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case op := <-odb.writeQueue:
			batch = append(batch, *op)

			// Flush when batch is full
			if len(batch) >= odb.config.BatchWriteSize {
				odb.flushBatch(batch)
				batch = batch[:0]
			}

		case <-ticker.C:
			// Flush periodically
			if len(batch) > 0 {
				odb.flushBatch(batch)
				batch = batch[:0]
			}

		case <-odb.shutdownChan:
			// Flush remaining
			if len(batch) > 0 {
				odb.flushBatch(batch)
			}
			return
		}
	}
}

// flushBatch writes a batch of operations
func (odb *OptimizedDB) flushBatch(batch []WriteOp) {
	if err := odb.BatchWrite(batch); err != nil {
		// Log error and notify callbacks
		for _, op := range batch {
			if op.Callback != nil {
				op.Callback(err)
			}
		}
	} else {
		for _, op := range batch {
			if op.Callback != nil {
				op.Callback(nil)
			}
		}
	}
}

// checkpointWorker creates periodic checkpoints
func (odb *OptimizedDB) checkpointWorker() {
	ticker := time.NewTicker(odb.config.CheckpointInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := odb.CreateCheckpoint(); err != nil {
				// Log error
				fmt.Printf("Checkpoint failed: %v\n", err)
			}

		case <-odb.shutdownChan:
			// Final checkpoint
			odb.CreateCheckpoint()
			return
		}
	}
}

// CreateCheckpoint creates a database checkpoint
func (odb *OptimizedDB) CreateCheckpoint() error {
	odb.checkpointMgr.mu.Lock()
	defer odb.checkpointMgr.mu.Unlock()

	checkpointName := fmt.Sprintf("checkpoint_%d", time.Now().Unix())
	checkpointPath := filepath.Join(odb.checkpointMgr.checkpointDir, checkpointName)

	// Create checkpoint using backup
	f, err := os.Create(checkpointPath)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = odb.db.Backup(f, 0)
	if err != nil {
		os.Remove(checkpointPath)
		return err
	}

	odb.checkpointMgr.lastCheckpoint = time.Now()

	// Cleanup old checkpoints
	return odb.cleanupOldCheckpoints()
}

// cleanupOldCheckpoints removes old checkpoint files
func (odb *OptimizedDB) cleanupOldCheckpoints() error {
	files, err := os.ReadDir(odb.checkpointMgr.checkpointDir)
	if err != nil {
		return err
	}

	if len(files) <= odb.checkpointMgr.maxCheckpoints {
		return nil
	}

	// Sort by modification time
	type fileInfo struct {
		name    string
		modTime time.Time
	}

	fileInfos := make([]fileInfo, 0, len(files))
	for _, f := range files {
		info, err := f.Info()
		if err != nil {
			continue
		}
		fileInfos = append(fileInfos, fileInfo{
			name:    f.Name(),
			modTime: info.ModTime(),
		})
	}

	// Sort oldest first
	for i := 0; i < len(fileInfos); i++ {
		for j := i + 1; j < len(fileInfos); j++ {
			if fileInfos[i].modTime.After(fileInfos[j].modTime) {
				fileInfos[i], fileInfos[j] = fileInfos[j], fileInfos[i]
			}
		}
	}

	// Remove oldest
	toRemove := len(fileInfos) - odb.checkpointMgr.maxCheckpoints
	for i := 0; i < toRemove; i++ {
		path := filepath.Join(odb.checkpointMgr.checkpointDir, fileInfos[i].name)
		os.Remove(path)
	}

	return nil
}

// garbageCollectionWorker runs periodic garbage collection
func (odb *OptimizedDB) garbageCollectionWorker() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			odb.db.RunValueLogGC(0.5)

		case <-odb.shutdownChan:
			return
		}
	}
}

// compactionWorker manages database compaction
func (odb *OptimizedDB) compactionWorker() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Trigger manual compaction during low usage
			go odb.db.Flatten(2)

		case <-odb.shutdownChan:
			return
		}
	}
}

// Get retrieves value from cache
func (c *LRUCache) Get(key string) ([]byte, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if entry, found := c.cache[key]; found {
		entry.lastAccess = time.Now()
		return entry.value, true
	}

	return nil, false
}

// Put adds value to cache
func (c *LRUCache) Put(key string, value []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if key exists
	if _, found := c.cache[key]; found {
		c.cache[key].value = value
		c.cache[key].lastAccess = time.Now()
		return
	}

	// Evict if at capacity
	if len(c.cache) >= c.capacity {
		c.evictLRU()
	}

	// Add new entry
	c.cache[key] = &cacheEntry{
		value:      value,
		lastAccess: time.Now(),
	}
	c.order = append(c.order, key)
}

// Delete removes key from cache
func (c *LRUCache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.cache, key)
}

// evictLRU removes least recently used entry
func (c *LRUCache) evictLRU() {
	if len(c.order) == 0 {
		return
	}

	// Find LRU
	oldestKey := c.order[0]
	oldestTime := c.cache[oldestKey].lastAccess

	for _, key := range c.order {
		if entry, found := c.cache[key]; found {
			if entry.lastAccess.Before(oldestTime) {
				oldestKey = key
				oldestTime = entry.lastAccess
			}
		}
	}

	delete(c.cache, oldestKey)

	// Remove from order
	newOrder := make([]string, 0, len(c.order)-1)
	for _, k := range c.order {
		if k != oldestKey {
			newOrder = append(newOrder, k)
		}
	}
	c.order = newOrder
}

// updateReadLatency updates average read latency
func (odb *OptimizedDB) updateReadLatency(duration time.Duration) {
	odb.metrics.mu.Lock()
	defer odb.metrics.mu.Unlock()

	// Exponential moving average
	alpha := 0.1
	current := float64(odb.metrics.AvgReadLatency)
	new := float64(duration)
	odb.metrics.AvgReadLatency = time.Duration(alpha*new + (1-alpha)*current)
}

// updateWriteLatency updates average write latency
func (odb *OptimizedDB) updateWriteLatency(duration time.Duration) {
	odb.metrics.mu.Lock()
	defer odb.metrics.mu.Unlock()

	alpha := 0.1
	current := float64(odb.metrics.AvgWriteLatency)
	new := float64(duration)
	odb.metrics.AvgWriteLatency = time.Duration(alpha*new + (1-alpha)*current)
}

// GetMetrics returns current database metrics
func (odb *OptimizedDB) GetMetrics() *DBMetrics {
	odb.metrics.mu.RLock()
	defer odb.metrics.mu.RUnlock()

	// Create copy
	metrics := *odb.metrics
	return &metrics
}

// Close shuts down the database
func (odb *OptimizedDB) Close() error {
	close(odb.shutdownChan)
	time.Sleep(2 * time.Second) // Wait for workers
	return odb.db.Close()
}

var ErrKeyNotFound = errors.New("key not found")
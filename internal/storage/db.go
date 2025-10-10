package storage

import (
	"container/list"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/dgraph-io/badger/v4"
	"go.uber.org/zap" 
)

const (
	// Cache settings
	DefaultCacheSize = 10000       // 10K entries in LRU cache
	DefaultCacheTTL  = 5 * time.Minute
	
	// Batch operation limits
	MaxBatchSize     = 1000        // Max items per batch
	BatchTimeout     = 100 * time.Millisecond
	
	// BadgerDB settings
	DefaultGCInterval       = 10 * time.Minute
	DefaultCompactionInterval = 1 * time.Hour
	ValueLogFileSize        = 256 << 20 // 256MB
	NumCompactors           = 2
	NumMemtables            = 3
	
	// Metrics update interval
	MetricsUpdateInterval = 30 * time.Second
)

var (
	ErrKeyNotFound    = badger.ErrKeyNotFound
	ErrDatabaseClosed = errors.New("database is closed")
	ErrBatchTooLarge  = errors.New("batch size exceeds maximum")
	ErrInvalidKey     = errors.New("invalid key")
)

// DB wraps BadgerDB with caching and optimization
type DB struct {
	db    *badger.DB
	cache *LRUCache

	logger *zap.Logger
	path   string
	
	// Configuration
	config *DBConfig
	
	// Batch write queue
	batchQueue chan *batchItem
	batchWg    sync.WaitGroup
	
	// Metrics
	metrics *DBMetrics
	
	// Lifecycle management
	closed    bool
	closeChan chan struct{}
	closeMu   sync.RWMutex
	
	// Background tasks
	gcTicker         *time.Ticker
	compactionTicker *time.Ticker
	metricsTicker    *time.Ticker
}

// DBConfig contains database configuration
type DBConfig struct {
	Path              string
	CacheSize         int
	CacheTTL          time.Duration
	GCInterval        time.Duration
	CompactionInterval time.Duration
	SyncWrites        bool // Sync to disk on every write (slower but safer)
	ReadOnly          bool
	InMemory          bool // For testing
}

// DefaultConfig returns default database configuration
func DefaultConfig(path string) *DBConfig {
	return &DBConfig{
		Path:               path,
		CacheSize:          DefaultCacheSize,
		CacheTTL:           DefaultCacheTTL,
		GCInterval:         DefaultGCInterval,
		CompactionInterval: DefaultCompactionInterval,
		SyncWrites:         false,
		ReadOnly:           false,
		InMemory:           false,
	}
}

// DBMetrics tracks database performance metrics
type DBMetrics struct {
	// Operation counts
	GetCount       uint64
	SetCount       uint64
	DeleteCount    uint64
	BatchCount     uint64
	
	// Cache statistics
	CacheHits      uint64
	CacheMisses    uint64
	CacheEvictions uint64
	
	// Performance
	TotalReadTime  time.Duration
	TotalWriteTime time.Duration
	
	// BadgerDB metrics
	LSMSize        int64
	VLogSize       int64
	NumTables      int
	NumCompactions uint64
	
	mu sync.RWMutex
}

// batchItem represents a queued batch operation
type batchItem struct {
	key   []byte
	value []byte
	done  chan error
}

// NewDB creates a new database instance
func NewDB(config *DBConfig) (*DB, error) {
	if config == nil {
		return nil, errors.New("config cannot be nil")
	}
	
	// Validate config
	if err := validateConfig(config); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	
	// Create directory if it doesn't exist
	if !config.InMemory && !config.ReadOnly {
		if err := os.MkdirAll(config.Path, 0755); err != nil {
			return nil, fmt.Errorf("failed to create directory: %w", err)
		}
	}
	
	// Configure BadgerDB options
	opts := badger.DefaultOptions(config.Path)
	opts = optimizeBadgerOptions(opts, config)
	
	// Open BadgerDB
	badgerDB, err := badger.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to open badger: %w", err)
	}
	
	// Create DB wrapper
	db := &DB{
		db:         badgerDB,
		cache:      NewLRUCache(config.CacheSize),
		config:     config,
		metrics:    &DBMetrics{},
		batchQueue: make(chan *batchItem, MaxBatchSize),
		closeChan:  make(chan struct{}),
	}
	
	// Start background tasks
	db.startBackgroundTasks()
	
	// Start batch processor
	db.batchWg.Add(1)
	go db.processBatchQueue()
	
	fmt.Printf("✅ Database opened: %s (cache: %d entries)\n", config.Path, config.CacheSize)
	
	return db, nil
}

func (db *DB) GetBadger() *badger.DB {
	return db.db
}

// Get retrieves a value from the database with caching
func (db *DB) Get(key []byte) ([]byte, error) {
	if err := db.checkClosed(); err != nil {
		return nil, err
	}
	
	if len(key) == 0 {
		return nil, ErrInvalidKey
	}
	
	startTime := time.Now()
	defer func() {
		db.metrics.mu.Lock()
		db.metrics.GetCount++
		db.metrics.TotalReadTime += time.Since(startTime)
		db.metrics.mu.Unlock()
	}()
	
	// Check cache first
	if value, found := db.cache.Get(string(key)); found {
		db.metrics.mu.Lock()
		db.metrics.CacheHits++
		db.metrics.mu.Unlock()
		return value.([]byte), nil
	}
	
	// Cache miss - read from disk
	db.metrics.mu.Lock()
	db.metrics.CacheMisses++
	db.metrics.mu.Unlock()
	
	var value []byte
	err := db.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(key)
		if err != nil {
			return err
		}
		
		return item.Value(func(val []byte) error {
			value = append([]byte(nil), val...)
			return nil
		})
	})
	
	if err != nil {
		return nil, err
	}
	
	// Add to cache
	db.cache.Put(string(key), value)
	
	return value, nil
}

// Set stores a key-value pair in the database
func (db *DB) Set(key, value []byte) error {
	if err := db.checkClosed(); err != nil {
		return err
	}
	
	if len(key) == 0 {
		return ErrInvalidKey
	}
	
	startTime := time.Now()
	defer func() {
		db.metrics.mu.Lock()
		db.metrics.SetCount++
		db.metrics.TotalWriteTime += time.Since(startTime)
		db.metrics.mu.Unlock()
	}()
	
	// Update cache
	db.cache.Put(string(key), value)
	
	// Write to disk
	err := db.db.Update(func(txn *badger.Txn) error {
		entry := badger.NewEntry(key, value)
		if db.config.SyncWrites {
			entry = entry.WithMeta(0)
		}
		return txn.SetEntry(entry)
	})
	
	return err
}

// Delete removes a key from the database
func (db *DB) Delete(key []byte) error {
	if err := db.checkClosed(); err != nil {
		return err
	}
	
	if len(key) == 0 {
		return ErrInvalidKey
	}
	
	db.metrics.mu.Lock()
	db.metrics.DeleteCount++
	db.metrics.mu.Unlock()
	
	// Remove from cache
	db.cache.Delete(string(key))
	
	// Delete from disk
	return db.db.Update(func(txn *badger.Txn) error {
		return txn.Delete(key)
	})
}

// BatchGet retrieves multiple values efficiently
func (db *DB) BatchGet(keys [][]byte) ([][]byte, error) {
	if err := db.checkClosed(); err != nil {
		return nil, err
	}
	
	values := make([][]byte, len(keys))
	
	err := db.db.View(func(txn *badger.Txn) error {
		for i, key := range keys {
			// Check cache first
			if value, found := db.cache.Get(string(key)); found {
				values[i] = value.([]byte)
				db.metrics.mu.Lock()
				db.metrics.CacheHits++
				db.metrics.mu.Unlock()
				continue
			}
			
			// Cache miss - read from disk
			item, err := txn.Get(key)
			if err == badger.ErrKeyNotFound {
				values[i] = nil
				continue
			}
			if err != nil {
				return err
			}
			
			err = item.Value(func(val []byte) error {
				values[i] = append([]byte(nil), val...)
				return nil
			})
			
			if err != nil {
				return err
			}
			
			// Add to cache
			db.cache.Put(string(key), values[i])
			
			db.metrics.mu.Lock()
			db.metrics.CacheMisses++
			db.metrics.mu.Unlock()
		}
		return nil
	})
	
	return values, err
}

// BatchSet writes multiple key-value pairs efficiently
func (db *DB) BatchSet(keys [][]byte, values [][]byte) error {
	if err := db.checkClosed(); err != nil {
		return err
	}
	
	if len(keys) != len(values) {
		return errors.New("keys and values length mismatch")
	}
	
	if len(keys) > MaxBatchSize {
		return ErrBatchTooLarge
	}
	
	startTime := time.Now()
	defer func() {
		db.metrics.mu.Lock()
		db.metrics.BatchCount++
		db.metrics.TotalWriteTime += time.Since(startTime)
		db.metrics.mu.Unlock()
	}()
	
	// Update cache
	for i, key := range keys {
		db.cache.Put(string(key), values[i])
	}
	
	// Batch write to disk
	wb := db.db.NewWriteBatch()
	defer wb.Cancel()
	
	for i, key := range keys {
		if err := wb.Set(key, values[i]); err != nil {
			return err
		}
	}
	
	return wb.Flush()
}

// Iterate iterates over keys with a given prefix
func (db *DB) Iterate(prefix []byte, fn func(key, value []byte) error) error {
	if err := db.checkClosed(); err != nil {
		return err
	}
	
	return db.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = prefix
		opts.PrefetchSize = 100 // Prefetch for performance
		
		it := txn.NewIterator(opts)
		defer it.Close()
		
		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()
			key := item.Key()
			
			err := item.Value(func(val []byte) error {
				return fn(key, val)
			})
			
			if err != nil {
				return err
			}
		}
		
		return nil
	})
}

// Count counts keys with a given prefix
func (db *DB) Count(prefix []byte) (int, error) {
	if err := db.checkClosed(); err != nil {
		return 0, err
	}
	
	count := 0
	err := db.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = prefix
		opts.PrefetchValues = false // Only need keys for counting
		
		it := txn.NewIterator(opts)
		defer it.Close()
		
		for it.Rewind(); it.Valid(); it.Next() {
			count++
		}
		
		return nil
	})
	
	return count, err
}

// Backup creates a database backup
func (db *DB) Backup(path string) error {
	if err := db.checkClosed(); err != nil {
		return err
	}
	
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create backup file: %w", err)
	}
	defer file.Close()
	
	_, err = db.db.Backup(file, 0)
	if err != nil {
		return fmt.Errorf("backup failed: %w", err)
	}
	
	fmt.Printf("✅ Database backup created: %s\n", path)
	return nil
}

// GetMetrics returns current database metrics
func (db *DB) GetMetrics() DBMetrics {
	db.metrics.mu.RLock()
	defer db.metrics.mu.RUnlock()
	
	return *db.metrics
}

// GetJSON retrieves and unmarshals a JSON value
func (db *DB) GetJSON(key []byte, v interface{}) error {
	data, err := db.Get(key)
	if err != nil {
		return err
	}
	
	return json.Unmarshal(data, v)
}

// SetJSON marshals and stores a JSON value
func (db *DB) SetJSON(key []byte, v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}
	
	return db.Set(key, data)
}

// Sync forces a sync to disk
func (db *DB) Sync() error {
	if err := db.checkClosed(); err != nil {
		return err
	}
	
	return db.db.Sync()
}

// Close safely closes the database
func (db *DB) Close() error {
	db.closeMu.Lock()
	defer db.closeMu.Unlock()
	
	if db.closed {
		return ErrDatabaseClosed
	}
	
	fmt.Println("🛑 Closing database...")
	
	// Signal shutdown
	close(db.closeChan)
	
	// Stop background tasks
	if db.gcTicker != nil {
		db.gcTicker.Stop()
	}
	if db.compactionTicker != nil {
		db.compactionTicker.Stop()
	}
	if db.metricsTicker != nil {
		db.metricsTicker.Stop()
	}
	
	// Wait for batch processor to finish
	close(db.batchQueue)
	db.batchWg.Wait()
	
	// Final sync
	if err := db.db.Sync(); err != nil {
		fmt.Printf("Warning: final sync failed: %v\n", err)
	}
	
	// Close BadgerDB
	if err := db.db.Close(); err != nil {
		return fmt.Errorf("failed to close badger: %w", err)
	}
	
	db.closed = true
	fmt.Println("✅ Database closed")
	
	return nil
}

// Background tasks

func (db *DB) startBackgroundTasks() {
	// Garbage collection
	db.gcTicker = time.NewTicker(db.config.GCInterval)
	go db.runGarbageCollection()
	
	// Compaction
	db.compactionTicker = time.NewTicker(db.config.CompactionInterval)
	go db.runCompaction()
	
	// Metrics update
	db.metricsTicker = time.NewTicker(MetricsUpdateInterval)
	go db.updateMetrics()
}

func (db *DB) runGarbageCollection() {
	for {
		select {
		case <-db.closeChan:
			return
		case <-db.gcTicker.C:
			db.performGC()
		}
	}
}

func (db *DB) performGC() {
	// Run BadgerDB garbage collection
	err := db.db.RunValueLogGC(0.5) // Discard 50% space
	if err != nil && err != badger.ErrNoRewrite {
		fmt.Printf("GC error: %v\n", err)
	}
}

func (db *DB) runCompaction() {
	for {
		select {
		case <-db.closeChan:
			return
		case <-db.compactionTicker.C:
			db.performCompaction()
		}
	}
}

func (db *DB) performCompaction() {
	// Flatten tables for better performance
	err := db.db.Flatten(NumCompactors)
	if err != nil {
		fmt.Printf("Compaction error: %v\n", err)
	}
}

func (db *DB) updateMetrics() {
	for {
		select {
		case <-db.closeChan:
			return
		case <-db.metricsTicker.C:
			db.refreshBadgerMetrics()
		}
	}
}

func (db *DB) refreshBadgerMetrics() {
	lsm, vlog := db.db.Size()
	
	db.metrics.mu.Lock()
	db.metrics.LSMSize = lsm
	db.metrics.VLogSize = vlog
	db.metrics.mu.Unlock()
}

func (db *DB) processBatchQueue() {
	defer db.batchWg.Done()
	
	ticker := time.NewTicker(BatchTimeout)
	defer ticker.Stop()
	
	batch := make([]*batchItem, 0, MaxBatchSize)
	
	flush := func() {
		if len(batch) == 0 {
			return
		}
		
		// Execute batch
		err := db.executeBatch(batch)
		
		// Notify all items
		for _, item := range batch {
			item.done <- err
			close(item.done)
		}
		
		// Clear batch
		batch = batch[:0]
	}
	
	for {
		select {
		case item, ok := <-db.batchQueue:
			if !ok {
				// Channel closed, flush and exit
				flush()
				return
			}
			
			batch = append(batch, item)
			
			if len(batch) >= MaxBatchSize {
				flush()
			}
			
		case <-ticker.C:
			flush()
		}
	}
}

func (db *DB) executeBatch(batch []*batchItem) error {
	wb := db.db.NewWriteBatch()
	defer wb.Cancel()
	
	for _, item := range batch {
		if err := wb.Set(item.key, item.value); err != nil {
			return err
		}
		
		// Update cache
		db.cache.Put(string(item.key), item.value)
	}
	
	return wb.Flush()
}

// Helper methods

func (db *DB) checkClosed() error {
	db.closeMu.RLock()
	defer db.closeMu.RUnlock()
	
	if db.closed {
		return ErrDatabaseClosed
	}
	return nil
}

func validateConfig(config *DBConfig) error {
	if config.Path == "" && !config.InMemory {
		return errors.New("path cannot be empty for disk-based database")
	}
	
	if config.CacheSize <= 0 {
		config.CacheSize = DefaultCacheSize
	}
	
	if config.GCInterval <= 0 {
		config.GCInterval = DefaultGCInterval
	}
	
	if config.CompactionInterval <= 0 {
		config.CompactionInterval = DefaultCompactionInterval
	}
	
	return nil
}

func optimizeBadgerOptions(opts badger.Options, config *DBConfig) badger.Options {
	if config.InMemory {
		opts = opts.WithInMemory(true)
	}
	
	if config.ReadOnly {
		opts = opts.WithReadOnly(true)
	}
	
	// Performance optimizations
	opts = opts.WithValueLogFileSize(ValueLogFileSize)
	opts = opts.WithNumCompactors(NumCompactors)
	opts = opts.WithNumMemtables(NumMemtables)
	opts = opts.WithNumLevelZeroTables(5)
	opts = opts.WithNumLevelZeroTablesStall(10)
	opts = opts.WithValueThreshold(1024) // Store values > 1KB in value log
	opts = opts.WithBlockCacheSize(100 << 20) // 100MB block cache
	opts = opts.WithIndexCacheSize(100 << 20) // 100MB index cache
	
	// Sync settings
	if config.SyncWrites {
		opts = opts.WithSyncWrites(true)
	}
	
	// Logging
	opts = opts.WithLogger(nil) // Disable BadgerDB logs (use your own)
	
	return opts
}

// LRUCache implements a thread-safe LRU cache
type LRUCache struct {
	capacity int
	items    map[string]*list.Element
	list     *list.List
	mu       sync.RWMutex
}

type cacheEntry struct {
	key   string
	value interface{}
	expiry time.Time
}

func NewLRUCache(capacity int) *LRUCache {
	return &LRUCache{
		capacity: capacity,
		items:    make(map[string]*list.Element),
		list:     list.New(),
	}
}

func (c *LRUCache) Get(key string) (interface{}, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	if elem, found := c.items[key]; found {
		entry := elem.Value.(*cacheEntry)
		
		// Check expiry
		if time.Now().After(entry.expiry) {
			c.removeElement(elem)
			return nil, false
		}
		
		// Move to front (most recently used)
		c.list.MoveToFront(elem)
		return entry.value, true
	}
	
	return nil, false
}

func (c *LRUCache) Put(key string, value interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	// Check if key exists
	if elem, found := c.items[key]; found {
		c.list.MoveToFront(elem)
		entry := elem.Value.(*cacheEntry)
		entry.value = value
		entry.expiry = time.Now().Add(DefaultCacheTTL)
		return
	}
	
	// Add new entry
	entry := &cacheEntry{
		key:    key,
		value:  value,
		expiry: time.Now().Add(DefaultCacheTTL),
	}
	elem := c.list.PushFront(entry)
	c.items[key] = elem
	
	// Evict if over capacity
	if c.list.Len() > c.capacity {
		c.removeOldest()
	}
}

func (c *LRUCache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	if elem, found := c.items[key]; found {
		c.removeElement(elem)
	}
}

func (c *LRUCache) removeOldest() {
	elem := c.list.Back()
	if elem != nil {
		c.removeElement(elem)
	}
}

func (c *LRUCache) removeElement(elem *list.Element) {
	c.list.Remove(elem)
	entry := elem.Value.(*cacheEntry)
	delete(c.items, entry.key)
}

func (c *LRUCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.list.Len()
}
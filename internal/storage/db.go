package storage

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/dgraph-io/badger/v4"
	"go.uber.org/zap"
)

// DB wraps BadgerDB and provides convenience methods
type DB struct {
	badger *badger.DB
	logger *zap.Logger
	path   string
}

// Config contains database configuration
type Config struct {
	Path   string
	Logger *zap.Logger
}

// NewDB creates a new database instance
func NewDB(config *Config) (*DB, error) {
	// Create directory if it doesn't exist
	if err := os.MkdirAll(config.Path, 0755); err != nil {
		return nil, fmt.Errorf("failed to create db directory: %w", err)
	}

	// Configure BadgerDB options
	opts := badger.DefaultOptions(config.Path)
	opts.Logger = nil // Disable BadgerDB's own logging

	// Open database
	badgerDB, err := badger.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	db := &DB{
		badger: badgerDB,
		logger: config.Logger,
		path:   config.Path,
	}

	db.logger.Info("Database opened successfully", zap.String("path", config.Path))
	return db, nil
}

// Close closes the database
func (db *DB) Close() error {
	if db.badger == nil {
		return nil
	}

	db.logger.Info("Closing database")
	if err := db.badger.Close(); err != nil {
		return fmt.Errorf("failed to close database: %w", err)
	}

	return nil
}

// Get retrieves a value by key
func (db *DB) Get(key []byte) ([]byte, error) {
	var value []byte

	err := db.badger.View(func(txn *badger.Txn) error {
		item, err := txn.Get(key)
		if err != nil {
			return err
		}

		value, err = item.ValueCopy(nil)
		return err
	})

	if err == badger.ErrKeyNotFound {
		return nil, fmt.Errorf("key not found: %w", err)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to get key: %w", err)
	}

	return value, nil
}

// Set stores a key-value pair
func (db *DB) Set(key, value []byte) error {
	err := db.badger.Update(func(txn *badger.Txn) error {
		return txn.Set(key, value)
	})

	if err != nil {
		return fmt.Errorf("failed to set key: %w", err)
	}

	return nil
}

// Delete removes a key
func (db *DB) Delete(key []byte) error {
	err := db.badger.Update(func(txn *badger.Txn) error {
		return txn.Delete(key)
	})

	if err != nil {
		return fmt.Errorf("failed to delete key: %w", err)
	}

	return nil
}

// Has checks if a key exists
func (db *DB) Has(key []byte) (bool, error) {
	err := db.badger.View(func(txn *badger.Txn) error {
		_, err := txn.Get(key)
		return err
	})

	if err == badger.ErrKeyNotFound {
		return false, nil
	}

	if err != nil {
		return false, fmt.Errorf("failed to check key: %w", err)
	}

	return true, nil
}

// NewBatch creates a new write batch
func (db *DB) NewBatch() *Batch {
	return &Batch{
		db:    db,
		batch: db.badger.NewWriteBatch(),
	}
}

// Iterate iterates over keys with a given prefix
func (db *DB) Iterate(prefix []byte, fn func(key, value []byte) error) error {
	return db.badger.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = prefix

		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
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

// GC runs garbage collection on the database
func (db *DB) GC() error {
	db.logger.Info("Running database garbage collection")

	err := db.badger.RunValueLogGC(0.5)
	if err != nil && err != badger.ErrNoRewrite {
		return fmt.Errorf("garbage collection failed: %w", err)
	}

	return nil
}

// Size returns the approximate size of the database in bytes
func (db *DB) Size() (int64, error) {
	lsm, vlog := db.badger.Size()
	return lsm + vlog, nil
}

// Path returns the database path
func (db *DB) Path() string {
	return db.path
}

// Backup creates a backup of the database
func (db *DB) Backup(backupPath string) error {
	db.logger.Info("Creating database backup", zap.String("path", backupPath))

	// Create backup directory
	if err := os.MkdirAll(filepath.Dir(backupPath), 0755); err != nil {
		return fmt.Errorf("failed to create backup directory: %w", err)
	}

	// Create backup file
	f, err := os.Create(backupPath)
	if err != nil {
		return fmt.Errorf("failed to create backup file: %w", err)
	}
	defer f.Close()

	// Perform backup
	_, err = db.badger.Backup(f, 0)
	if err != nil {
		return fmt.Errorf("backup failed: %w", err)
	}

	db.logger.Info("Backup completed successfully")
	return nil
}

// Batch represents a write batch
type Batch struct {
	db    *DB
	batch *badger.WriteBatch
}

// Set adds a key-value pair to the batch
func (b *Batch) Set(key, value []byte) error {
	return b.batch.Set(key, value)
}

// Delete adds a delete operation to the batch
func (b *Batch) Delete(key []byte) error {
	return b.batch.Delete(key)
}

// Flush commits the batch
func (b *Batch) Flush() error {
	return b.batch.Flush()
}

// Cancel cancels the batch
func (b *Batch) Cancel() {
	b.batch.Cancel()
}

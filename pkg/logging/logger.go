package logging

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const (
	// Log levels
	DebugLevel = "debug"
	InfoLevel  = "info"
	WarnLevel  = "warn"
	ErrorLevel = "error"
	
	// Log rotation
	MaxLogFileSize = 100 * 1024 * 1024 // 100MB
	MaxBackups     = 10
	MaxAge         = 30 // days
)

var (
	// Global logger instance
	globalLogger *Logger
)

// Logger wraps zap logger with additional functionality
type Logger struct {
	*zap.Logger
	config *LogConfig
	sugar  *zap.SugaredLogger
}

// LogConfig contains logging configuration
type LogConfig struct {
	Level      string // debug, info, warn, error
	OutputPath string // File path or "stdout"
	ErrorPath  string // Error output path
	
	// Rotation settings
	EnableRotation bool
	MaxSize        int // MB
	MaxBackups     int
	MaxAge         int // days
	Compress       bool
	
	// Output settings
	Development    bool // Pretty print for development
	DisableCaller  bool
	DisableStacktrace bool
	
	// Component-specific levels
	ComponentLevels map[string]string
}

// DefaultConfig returns default logging configuration
func DefaultConfig() *LogConfig {
	return &LogConfig{
		Level:          InfoLevel,
		OutputPath:     "stdout",
		ErrorPath:      "stderr",
		EnableRotation: false,
		MaxSize:        100,
		MaxBackups:     10,
		MaxAge:         30,
		Compress:       true,
		Development:    false,
		DisableCaller:  false,
		DisableStacktrace: false,
		ComponentLevels: make(map[string]string),
	}
}

// NewLogger creates a new logger instance
func NewLogger(config *LogConfig) (*Logger, error) {
	if config == nil {
		config = DefaultConfig()
	}
	
	// Parse log level
	level, err := parseLevel(config.Level)
	if err != nil {
		return nil, fmt.Errorf("invalid log level: %w", err)
	}
	
	// Build encoder config
	encoderConfig := zapcore.EncoderConfig{
		TimeKey:        "timestamp",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "caller",
		FunctionKey:    zapcore.OmitKey,
		MessageKey:     "msg",
		StacktraceKey:  "stacktrace",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.SecondsDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}
	
	// Use colored output for development
	if config.Development {
		encoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
		encoderConfig.EncodeTime = zapcore.TimeEncoderOfLayout("15:04:05.000")
	}
	
	// Create encoder
	var encoder zapcore.Encoder
	if config.Development {
		encoder = zapcore.NewConsoleEncoder(encoderConfig)
	} else {
		encoder = zapcore.NewJSONEncoder(encoderConfig)
	}
	
	// Create output writers
	var writeSyncer zapcore.WriteSyncer
	if config.OutputPath == "stdout" {
		writeSyncer = zapcore.AddSync(os.Stdout)
	} else {
		// Ensure directory exists
		dir := filepath.Dir(config.OutputPath)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create log directory: %w", err)
		}
		
		file, err := os.OpenFile(config.OutputPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return nil, fmt.Errorf("failed to open log file: %w", err)
		}
		writeSyncer = zapcore.AddSync(file)
	}
	
	// Create core
	core := zapcore.NewCore(encoder, writeSyncer, level)
	
	// Build logger options
	opts := []zap.Option{
		zap.AddCaller(),
		zap.AddStacktrace(zapcore.ErrorLevel),
	}
	
	if config.DisableCaller {
		opts = []zap.Option{}
	}
	
	if config.DisableStacktrace {
		opts = append(opts, zap.AddStacktrace(zapcore.DPanicLevel))
	}
	
	// Create logger
	zapLogger := zap.New(core, opts...)
	
	logger := &Logger{
		Logger: zapLogger,
		config: config,
		sugar:  zapLogger.Sugar(),
	}
	
	return logger, nil
}

// InitGlobalLogger initializes the global logger
func InitGlobalLogger(config *LogConfig) error {
	logger, err := NewLogger(config)
	if err != nil {
		return err
	}
	
	globalLogger = logger
	
	// Replace zap's global logger
	zap.ReplaceGlobals(logger.Logger)
	
	logger.Info("Logger initialized",
		zap.String("level", config.Level),
		zap.String("output", config.OutputPath),
	)
	
	return nil
}

// GetGlobalLogger returns the global logger instance
func GetGlobalLogger() *Logger {
	if globalLogger == nil {
		// Fallback to default logger
		logger, _ := NewLogger(DefaultConfig())
		return logger
	}
	return globalLogger
}

// Component returns a logger for a specific component
func (l *Logger) Component(name string) *Logger {
	// Check if component has custom level
	if level, exists := l.config.ComponentLevels[name]; exists {
		zapLevel, _ := parseLevel(level)
		return &Logger{
			Logger: l.Logger.WithOptions(zap.IncreaseLevel(zapLevel)).Named(name),
			config: l.config,
			sugar:  l.sugar.Named(name),
		}
	}
	
	return &Logger{
		Logger: l.Logger.Named(name),
		config: l.config,
		sugar:  l.sugar.Named(name),
	}
}

// Sync flushes any buffered log entries
func (l *Logger) Sync() error {
	return l.Logger.Sync()
}

// Sugar returns the sugared logger for easier logging
func (l *Logger) Sugar() *zap.SugaredLogger {
	return l.sugar
}

// Convenience methods with structured fields

// Blockchain logs blockchain events
func (l *Logger) Blockchain() *ComponentLogger {
	return &ComponentLogger{logger: l.Component("blockchain")}
}

// Mining logs mining events
func (l *Logger) Mining() *ComponentLogger {
	return &ComponentLogger{logger: l.Component("mining")}
}

// P2P logs network events
func (l *Logger) P2P() *ComponentLogger {
	return &ComponentLogger{logger: l.Component("p2p")}
}

// API logs API events
func (l *Logger) API() *ComponentLogger {
	return &ComponentLogger{logger: l.Component("api")}
}

// Consensus logs consensus events
func (l *Logger) Consensus() *ComponentLogger {
	return &ComponentLogger{logger: l.Component("consensus")}
}

// State logs state events
func (l *Logger) State() *ComponentLogger {
	return &ComponentLogger{logger: l.Component("state")}
}

// Mempool logs mempool events
func (l *Logger) Mempool() *ComponentLogger {
	return &ComponentLogger{logger: l.Component("mempool")}
}

// ComponentLogger provides component-specific logging
type ComponentLogger struct {
	logger *Logger
}

// BlockAdded logs when a block is added
func (c *ComponentLogger) BlockAdded(height uint64, hash string, txCount int) {
	c.logger.Info("Block added",
		zap.Uint64("height", height),
		zap.String("hash", hash),
		zap.Int("transactions", txCount),
	)
}

// BlockRejected logs when a block is rejected
func (c *ComponentLogger) BlockRejected(height uint64, hash string, reason error) {
	c.logger.Warn("Block rejected",
		zap.Uint64("height", height),
		zap.String("hash", hash),
		zap.Error(reason),
	)
}

// TransactionAdded logs when a transaction is added to mempool
func (c *ComponentLogger) TransactionAdded(hash string, from, to string, amount string) {
	c.logger.Debug("Transaction added to mempool",
		zap.String("hash", hash),
		zap.String("from", from),
		zap.String("to", to),
		zap.String("amount", amount),
	)
}

// TransactionRejected logs when a transaction is rejected
func (c *ComponentLogger) TransactionRejected(hash string, reason error) {
	c.logger.Debug("Transaction rejected",
		zap.String("hash", hash),
		zap.Error(reason),
	)
}

// PeerConnected logs when a peer connects
func (c *ComponentLogger) PeerConnected(peerID string, addr string) {
	c.logger.Info("Peer connected",
		zap.String("peer", peerID),
		zap.String("addr", addr),
	)
}

// PeerDisconnected logs when a peer disconnects
func (c *ComponentLogger) PeerDisconnected(peerID string, reason string) {
	c.logger.Info("Peer disconnected",
		zap.String("peer", peerID),
		zap.String("reason", reason),
	)
}

// PeerBanned logs when a peer is banned
func (c *ComponentLogger) PeerBanned(peerID string, reason string) {
	c.logger.Warn("Peer banned",
		zap.String("peer", peerID),
		zap.String("reason", reason),
	)
}

// BlockMined logs when a block is successfully mined
func (c *ComponentLogger) BlockMined(height uint64, nonce uint64, reward string) {
	c.logger.Info("Block mined",
		zap.Uint64("height", height),
		zap.Uint64("nonce", nonce),
		zap.String("reward", reward),
	)
}

// MiningStarted logs when mining starts
func (c *ComponentLogger) MiningStarted(threads int, address string) {
	c.logger.Info("Mining started",
		zap.Int("threads", threads),
		zap.String("address", address),
	)
}

// MiningStopped logs when mining stops
func (c *ComponentLogger) MiningStopped() {
	c.logger.Info("Mining stopped")
}

// StateCommitted logs when state is committed
func (c *ComponentLogger) StateCommitted(height uint64, stateRoot string) {
	c.logger.Debug("State committed",
		zap.Uint64("height", height),
		zap.String("stateRoot", stateRoot),
	)
}

// Reorganization logs when chain reorganization occurs
func (c *ComponentLogger) Reorganization(oldHeight, newHeight uint64, blocksReverted, blocksApplied int) {
	c.logger.Warn("Chain reorganization",
		zap.Uint64("oldHeight", oldHeight),
		zap.Uint64("newHeight", newHeight),
		zap.Int("blocksReverted", blocksReverted),
		zap.Int("blocksApplied", blocksApplied),
	)
}

// APIRequest logs API requests
func (c *ComponentLogger) APIRequest(method, endpoint string, duration time.Duration, statusCode int) {
	c.logger.Info("API request",
		zap.String("method", method),
		zap.String("endpoint", endpoint),
		zap.Duration("duration", duration),
		zap.Int("status", statusCode),
	)
}

// Critical logs critical errors that require immediate attention
func (c *ComponentLogger) Critical(msg string, err error, fields ...zap.Field) {
	fields = append(fields, zap.Error(err))
	c.logger.Error(msg, fields...)
}

// Helper functions

func parseLevel(level string) (zapcore.Level, error) {
	switch level {
	case DebugLevel:
		return zapcore.DebugLevel, nil
	case InfoLevel:
		return zapcore.InfoLevel, nil
	case WarnLevel:
		return zapcore.WarnLevel, nil
	case ErrorLevel:
		return zapcore.ErrorLevel, nil
	default:
		return zapcore.InfoLevel, fmt.Errorf("invalid log level: %s", level)
	}
}

// Global convenience functions

// Debug logs a debug message
func Debug(msg string, fields ...zap.Field) {
	GetGlobalLogger().Debug(msg, fields...)
}

// Info logs an info message
func Info(msg string, fields ...zap.Field) {
	GetGlobalLogger().Info(msg, fields...)
}

// Warn logs a warning message
func Warn(msg string, fields ...zap.Field) {
	GetGlobalLogger().Warn(msg, fields...)
}

// Error logs an error message
func Error(msg string, fields ...zap.Field) {
	GetGlobalLogger().Error(msg, fields...)
}

// Fatal logs a fatal message and exits
func Fatal(msg string, fields ...zap.Field) {
	GetGlobalLogger().Fatal(msg, fields...)
}

// Sync flushes any buffered log entries
func Sync() error {
	return GetGlobalLogger().Sync()
}
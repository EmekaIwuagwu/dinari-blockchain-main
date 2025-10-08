// config/config.go
package config

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/kelseyhightower/envconfig"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

// ChainConfig represents blockchain-specific parameters
type ChainConfig struct {
	NetworkID          uint64        `json:"network_id" envconfig:"NETWORK_ID" default:"1"`
	ChainID            uint64        `json:"chain_id" envconfig:"CHAIN_ID" default:"1"`
	GenesisFile        string        `json:"genesis_file" envconfig:"GENESIS_FILE"`
	BlockTime          time.Duration `json:"block_time" envconfig:"BLOCK_TIME" default:"15s"`
	MaxBlockSize       uint64        `json:"max_block_size" envconfig:"MAX_BLOCK_SIZE" default:"2097152"`
	MaxTxPerBlock      uint32        `json:"max_tx_per_block" envconfig:"MAX_TX_PER_BLOCK" default:"5000"`
	DifficultyTarget   uint32        `json:"difficulty_target" envconfig:"DIFFICULTY_TARGET"`
	HalvingInterval    uint64        `json:"halving_interval" envconfig:"HALVING_INTERVAL" default:"210000"`
	InitialReward      uint64        `json:"initial_reward" envconfig:"INITIAL_REWARD" default:"5000000000"`
	MinimumFee         uint64        `json:"minimum_fee" envconfig:"MINIMUM_FEE" default:"1000"`
	ForkHeight         uint64        `json:"fork_height" envconfig:"FORK_HEIGHT"`
	CheckpointInterval uint64        `json:"checkpoint_interval" envconfig:"CHECKPOINT_INTERVAL" default:"1000"`
}

// NodeConfig represents node-specific settings
type NodeConfig struct {
	DataDir          string   `json:"data_dir" envconfig:"DATA_DIR" default:"./data"`
	LogLevel         string   `json:"log_level" envconfig:"LOG_LEVEL" default:"info"`
	LogFile          string   `json:"log_file" envconfig:"LOG_FILE"`
	LogMaxSize       int      `json:"log_max_size" envconfig:"LOG_MAX_SIZE" default:"100"`
	LogMaxBackups    int      `json:"log_max_backups" envconfig:"LOG_MAX_BACKUPS" default:"10"`
	LogCompress      bool     `json:"log_compress" envconfig:"LOG_COMPRESS" default:"true"`
	CPUProfile       string   `json:"cpu_profile" envconfig:"CPU_PROFILE"`
	MemProfile       string   `json:"mem_profile" envconfig:"MEM_PROFILE"`
	ProfilePort      int      `json:"profile_port" envconfig:"PROFILE_PORT" default:"6060"`
	MetricsEnabled   bool     `json:"metrics_enabled" envconfig:"METRICS_ENABLED" default:"true"`
	MetricsPort      int      `json:"metrics_port" envconfig:"METRICS_PORT" default:"9090"`
	BootstrapNodes   []string `json:"bootstrap_nodes" envconfig:"BOOTSTRAP_NODES"`
	TrustedPeers     []string `json:"trusted_peers" envconfig:"TRUSTED_PEERS"`
	MaxPeers         int      `json:"max_peers" envconfig:"MAX_PEERS" default:"125"`
	PruneBlocksAfter uint64   `json:"prune_blocks_after" envconfig:"PRUNE_BLOCKS_AFTER" default:"100000"`
	ArchiveMode      bool     `json:"archive_mode" envconfig:"ARCHIVE_MODE" default:"false"`
}

// P2PConfig represents P2P network settings
type P2PConfig struct {
	ListenAddr         string        `json:"listen_addr" envconfig:"P2P_LISTEN_ADDR" default:"/ip4/0.0.0.0/tcp/9000"`
	ExternalAddr       string        `json:"external_addr" envconfig:"P2P_EXTERNAL_ADDR"`
	EnableNATTraversal bool          `json:"enable_nat_traversal" envconfig:"P2P_NAT_TRAVERSAL" default:"true"`
	EnableRelay        bool          `json:"enable_relay" envconfig:"P2P_ENABLE_RELAY" default:"true"`
	EnableDHT          bool          `json:"enable_dht" envconfig:"P2P_ENABLE_DHT" default:"true"`
	DHTMode            string        `json:"dht_mode" envconfig:"P2P_DHT_MODE" default:"auto"`
	PeerExchange       bool          `json:"peer_exchange" envconfig:"P2P_PEER_EXCHANGE" default:"true"`
	ConnectionTimeout  time.Duration `json:"connection_timeout" envconfig:"P2P_CONN_TIMEOUT" default:"30s"`
	HandshakeTimeout   time.Duration `json:"handshake_timeout" envconfig:"P2P_HANDSHAKE_TIMEOUT" default:"20s"`
	MaxMessageSize     int           `json:"max_message_size" envconfig:"P2P_MAX_MSG_SIZE" default:"10485760"`
	SendQueueSize      int           `json:"send_queue_size" envconfig:"P2P_SEND_QUEUE" default:"100"`
	RecvQueueSize      int           `json:"recv_queue_size" envconfig:"P2P_RECV_QUEUE" default:"100"`
}

// RPCConfig represents RPC server settings
type RPCConfig struct {
	Enabled          bool          `json:"enabled" envconfig:"RPC_ENABLED" default:"true"`
	ListenAddr       string        `json:"listen_addr" envconfig:"RPC_LISTEN_ADDR" default:"localhost:8545"`
	TLSEnabled       bool          `json:"tls_enabled" envconfig:"RPC_TLS_ENABLED" default:"false"`
	TLSCertFile      string        `json:"tls_cert_file" envconfig:"RPC_TLS_CERT"`
	TLSKeyFile       string        `json:"tls_key_file" envconfig:"RPC_TLS_KEY"`
	MaxConnections   int           `json:"max_connections" envconfig:"RPC_MAX_CONN" default:"100"`
	ReadTimeout      time.Duration `json:"read_timeout" envconfig:"RPC_READ_TIMEOUT" default:"30s"`
	WriteTimeout     time.Duration `json:"write_timeout" envconfig:"RPC_WRITE_TIMEOUT" default:"30s"`
	IdleTimeout      time.Duration `json:"idle_timeout" envconfig:"RPC_IDLE_TIMEOUT" default:"120s"`
	MaxRequestSize   int64         `json:"max_request_size" envconfig:"RPC_MAX_REQ_SIZE" default:"10485760"`
	RateLimitEnabled bool          `json:"rate_limit_enabled" envconfig:"RPC_RATE_LIMIT" default:"true"`
	RateLimitPerMin  int           `json:"rate_limit_per_min" envconfig:"RPC_RATE_LIMIT_MIN" default:"100"`
	AllowedOrigins   []string      `json:"allowed_origins" envconfig:"RPC_CORS_ORIGINS"`
	AllowedMethods   []string      `json:"allowed_methods" envconfig:"RPC_CORS_METHODS"`
	AuthEnabled      bool          `json:"auth_enabled" envconfig:"RPC_AUTH_ENABLED" default:"false"`
	APIKeys          []string      `json:"api_keys" envconfig:"RPC_API_KEYS"`
}

// MinerConfig represents mining settings
type MinerConfig struct {
	Enabled      bool   `json:"enabled" envconfig:"MINER_ENABLED" default:"false"`
	MinerAddress string `json:"miner_address" envconfig:"MINER_ADDRESS"`
	NumWorkers   int    `json:"num_workers" envconfig:"MINER_WORKERS" default:"4"`
	ExtraData    string `json:"extra_data" envconfig:"MINER_EXTRA_DATA"`
	GasFloor     uint64 `json:"gas_floor" envconfig:"MINER_GAS_FLOOR" default:"30000000"`
	GasCeil      uint64 `json:"gas_ceil" envconfig:"MINER_GAS_CEIL" default:"60000000"`
	GasPrice     uint64 `json:"gas_price" envconfig:"MINER_GAS_PRICE" default:"1000000000"`
	AutoDAG      bool   `json:"auto_dag" envconfig:"MINER_AUTO_DAG" default:"true"`
}

// MempoolConfig represents transaction pool settings
type MempoolConfig struct {
	MaxSize             int           `json:"max_size" envconfig:"MEMPOOL_MAX_SIZE" default:"10000"`
	MaxTxSize           int           `json:"max_tx_size" envconfig:"MEMPOOL_MAX_TX_SIZE" default:"32768"`
	MinFeeRate          uint64        `json:"min_fee_rate" envconfig:"MEMPOOL_MIN_FEE_RATE" default:"1"`
	MaxOrphans          int           `json:"max_orphans" envconfig:"MEMPOOL_MAX_ORPHANS" default:"1000"`
	OrphanTTL           time.Duration `json:"orphan_ttl" envconfig:"MEMPOOL_ORPHAN_TTL" default:"15m"`
	RebroadcastInterval time.Duration `json:"rebroadcast_interval" envconfig:"MEMPOOL_REBROADCAST" default:"10m"`
	ExpireTime          time.Duration `json:"expire_time" envconfig:"MEMPOOL_EXPIRE" default:"72h"`
	ReplaceByFee        bool          `json:"replace_by_fee" envconfig:"MEMPOOL_RBF" default:"true"`
}

// DatabaseConfig represents database settings
type DatabaseConfig struct {
	Type                string `json:"type" envconfig:"DB_TYPE" default:"badger"`
	Path                string `json:"path" envconfig:"DB_PATH" default:"./data/blockchain"`
	InMemory            bool   `json:"in_memory" envconfig:"DB_IN_MEMORY" default:"false"`
	MaxOpenFiles        int    `json:"max_open_files" envconfig:"DB_MAX_OPEN_FILES" default:"10000"`
	ValueLogFileSize    int64  `json:"value_log_file_size" envconfig:"DB_VALUE_LOG_SIZE" default:"1073741824"`
	ValueLogMaxEntries  uint32 `json:"value_log_max_entries" envconfig:"DB_VALUE_LOG_ENTRIES" default:"1000000"`
	NumCompactors       int    `json:"num_compactors" envconfig:"DB_NUM_COMPACTORS" default:"4"`
	CompactL0OnClose    bool   `json:"compact_l0_on_close" envconfig:"DB_COMPACT_ON_CLOSE" default:"true"`
	KeepL0InMemory      bool   `json:"keep_l0_in_memory" envconfig:"DB_KEEP_L0_MEM" default:"true"`
	VerifyValueChecksum bool   `json:"verify_value_checksum" envconfig:"DB_VERIFY_CHECKSUM" default:"true"`
	Compression         string `json:"compression" envconfig:"DB_COMPRESSION" default:"snappy"`
	EncryptionKey       string `json:"encryption_key" envconfig:"DB_ENCRYPTION_KEY"`
	BackupInterval      string `json:"backup_interval" envconfig:"DB_BACKUP_INTERVAL" default:"24h"`
	BackupPath          string `json:"backup_path" envconfig:"DB_BACKUP_PATH" default:"./backups"`
	MaxBackups          int    `json:"max_backups" envconfig:"DB_MAX_BACKUPS" default:"7"`
}

// SecurityConfig represents security settings
type SecurityConfig struct {
	EnableTLS            bool          `json:"enable_tls" envconfig:"SEC_TLS_ENABLED" default:"false"`
	TLSMinVersion        string        `json:"tls_min_version" envconfig:"SEC_TLS_MIN_VERSION" default:"TLS1.3"`
	TLSCipherSuites      []string      `json:"tls_cipher_suites" envconfig:"SEC_TLS_CIPHERS"`
	EnableFirewall       bool          `json:"enable_firewall" envconfig:"SEC_FIREWALL" default:"true"`
	BlacklistIPs         []string      `json:"blacklist_ips" envconfig:"SEC_BLACKLIST_IPS"`
	WhitelistIPs         []string      `json:"whitelist_ips" envconfig:"SEC_WHITELIST_IPS"`
	MaxRequestsPerIP     int           `json:"max_requests_per_ip" envconfig:"SEC_MAX_REQ_PER_IP" default:"1000"`
	BanDuration          time.Duration `json:"ban_duration" envconfig:"SEC_BAN_DURATION" default:"24h"`
	EnableDDoSProtection bool          `json:"enable_ddos_protection" envconfig:"SEC_DDOS_PROTECT" default:"true"`
	JWTSecret            string        `json:"jwt_secret" envconfig:"SEC_JWT_SECRET"`
	APIRateLimit         int           `json:"api_rate_limit" envconfig:"SEC_API_RATE_LIMIT" default:"100"`
}

// Config represents the complete configuration
type Config struct {
	Chain    ChainConfig    `json:"chain"`
	Node     NodeConfig     `json:"node"`
	P2P      P2PConfig      `json:"p2p"`
	RPC      RPCConfig      `json:"rpc"`
	Miner    MinerConfig    `json:"miner"`
	Mempool  MempoolConfig  `json:"mempool"`
	Database DatabaseConfig `json:"database"`
	Security SecurityConfig `json:"security"`
}

// LoadConfig loads configuration from files and environment variables
func LoadConfig(configPath string) (*Config, error) {
	cfg := &Config{}

	// Load from config file if exists
	if configPath != "" {
		viper.SetConfigFile(configPath)
		viper.SetConfigType("json")

		if err := viper.ReadInConfig(); err != nil {
			if !os.IsNotExist(err) {
				return nil, fmt.Errorf("failed to read config file: %w", err)
			}
		} else {
			if err := viper.Unmarshal(cfg); err != nil {
				return nil, fmt.Errorf("failed to unmarshal config: %w", err)
			}
		}
	}

	// Override with environment variables
	if err := envconfig.Process("DINARI", cfg); err != nil {
		return nil, fmt.Errorf("failed to process env vars: %w", err)
	}

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	// Setup directories
	if err := cfg.setupDirectories(); err != nil {
		return nil, fmt.Errorf("failed to setup directories: %w", err)
	}

	return cfg, nil
}

// Validate validates the configuration
func (c *Config) Validate() error {
	// Chain validation
	if c.Chain.NetworkID == 0 {
		return fmt.Errorf("network_id must be non-zero")
	}
	if c.Chain.BlockTime < time.Second {
		return fmt.Errorf("block_time must be at least 1 second")
	}
	if c.Chain.MaxBlockSize == 0 {
		return fmt.Errorf("max_block_size must be non-zero")
	}

	// Node validation
	if c.Node.MaxPeers < 1 {
		return fmt.Errorf("max_peers must be at least 1")
	}

	// Miner validation
	if c.Miner.Enabled && c.Miner.MinerAddress == "" {
		return fmt.Errorf("miner_address required when mining enabled")
	}

	// Database validation
	if c.Database.Type != "badger" && c.Database.Type != "leveldb" {
		return fmt.Errorf("unsupported database type: %s", c.Database.Type)
	}

	// Security validation
	if c.Security.EnableTLS {
		if c.RPC.TLSCertFile == "" || c.RPC.TLSKeyFile == "" {
			return fmt.Errorf("TLS cert and key files required when TLS enabled")
		}
	}

	return nil
}

// setupDirectories creates necessary directories
func (c *Config) setupDirectories() error {
	dirs := []string{
		c.Node.DataDir,
		c.Database.Path,
		c.Database.BackupPath,
		filepath.Dir(c.Node.LogFile),
	}

	for _, dir := range dirs {
		if dir != "" {
			if err := os.MkdirAll(dir, 0755); err != nil {
				return fmt.Errorf("failed to create directory %s: %w", dir, err)
			}
		}
	}

	return nil
}

// GetTLSConfig returns the TLS configuration
func (c *Config) GetTLSConfig() (*tls.Config, error) {
	if !c.Security.EnableTLS {
		return nil, nil
	}

	cert, err := tls.LoadX509KeyPair(c.RPC.TLSCertFile, c.RPC.TLSKeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load TLS certificates: %w", err)
	}

	minVersion := tls.VersionTLS12
	switch c.Security.TLSMinVersion {
	case "TLS1.3":
		minVersion = tls.VersionTLS13
	case "TLS1.2":
		minVersion = tls.VersionTLS12
	default:
		return nil, fmt.Errorf("unsupported TLS version: %s", c.Security.TLSMinVersion)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   uint16(minVersion),
		CipherSuites: getCipherSuites(c.Security.TLSCipherSuites),
	}, nil
}

func getCipherSuites(suites []string) []uint16 {
	if len(suites) == 0 {
		return nil
	}

	var cipherSuites []uint16
	for _, suite := range suites {
		switch suite {
		case "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":
			cipherSuites = append(cipherSuites, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
		case "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":
			cipherSuites = append(cipherSuites, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384)
		case "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256":
			cipherSuites = append(cipherSuites, tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)
		case "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384":
			cipherSuites = append(cipherSuites, tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384)
		}
	}

	return cipherSuites
}

// SaveConfig saves the configuration to a file
func (c *Config) SaveConfig(path string) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// GetLogger returns a configured logger
func (c *Config) GetLogger() (*zap.Logger, error) {
	cfg := zap.NewProductionConfig()

	// Set log level
	switch c.Node.LogLevel {
	case "debug":
		cfg.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	case "info":
		cfg.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
	case "warn":
		cfg.Level = zap.NewAtomicLevelAt(zap.WarnLevel)
	case "error":
		cfg.Level = zap.NewAtomicLevelAt(zap.ErrorLevel)
	}

	// Set output paths
	if c.Node.LogFile != "" {
		cfg.OutputPaths = []string{c.Node.LogFile}
	}

	return cfg.Build()
}

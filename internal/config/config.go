// Package config handles configuration loading for the AS4 server.
//
// Configuration is loaded from a YAML file with support for environment
// variable expansion (${VAR} or $VAR syntax). This allows sensitive values
// like database credentials and API keys to be injected at runtime.
//
// # Configuration Sections
//
//   - server: HTTP server settings (port, TLS, base path)
//   - storage: Database connection (MongoDB URI, database name)
//   - signing: Key management mode (file, pkcs11, or prf)
//   - oauth2: JWT authentication (issuer, audience, JWKS URL)
//   - observability: Metrics and tracing endpoints
//
// # Example Configuration
//
//	server:
//	  port: 8080
//	  basePath: "/"
//	  tls:
//	    enabled: true
//	    certFile: /etc/ssl/server.crt
//	    keyFile: /etc/ssl/server.key
//
//	storage:
//	  type: mongodb
//	  uri: ${MONGODB_URI}
//	  database: as4
//
//	oauth2:
//	  issuer: https://auth.example.com
//	  audience: https://as4.example.com
//
// See [Load] for loading configuration from a file.
package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the root configuration structure
type Config struct {
	Server  ServerConfig  `yaml:"server"`
	Storage StorageConfig `yaml:"storage"`
	Signing SigningConfig `yaml:"signing"`
	OAuth2  OAuth2Config  `yaml:"oauth2"`
	Metrics MetricsConfig `yaml:"observability"`
}

// ServerConfig holds HTTP server settings
type ServerConfig struct {
	Port     int    `yaml:"port"`
	BasePath string `yaml:"basePath"`
	AdminKey string `yaml:"adminKey"` // API key for admin endpoints
	TLS      struct {
		Enabled  bool   `yaml:"enabled"`
		CertFile string `yaml:"certFile"`
		KeyFile  string `yaml:"keyFile"`
	} `yaml:"tls"`
}

// StorageConfig holds database settings
type StorageConfig struct {
	MongoDB MongoDBConfig `yaml:"mongodb"`
}

// MongoDBConfig holds MongoDB connection settings
type MongoDBConfig struct {
	URI      string `yaml:"uri"`
	Database string `yaml:"database"`
	GridFS   struct {
		BucketName     string `yaml:"bucketName"`
		ChunkSizeBytes int    `yaml:"chunkSizeBytes"`
	} `yaml:"gridfs"`
}

// SigningConfig holds signing key management settings
type SigningConfig struct {
	// Mode determines how signing keys are managed
	// - "prf": Keys encrypted with FIDO2/PRF-derived keys (client authenticates with FIDO2)
	// - "pkcs11": Keys stored in PKCS#11 token (HSM/smart card)
	// - "file": Keys loaded from PEM files (development only)
	Mode string `yaml:"mode"`

	// PRF mode settings
	PRF PRFConfig `yaml:"prf"`

	// PKCS11 mode settings
	PKCS11 PKCS11Config `yaml:"pkcs11"`

	// File mode settings (development only)
	File FileKeyConfig `yaml:"file"`

	// Session settings (for PRF mode)
	Session SessionConfig `yaml:"session"`
}

// PRFConfig holds PRF-based key encryption settings
type PRFConfig struct {
	// Redis settings for session key caching
	Redis RedisConfig `yaml:"redis"`
}

// RedisConfig holds Redis connection settings
type RedisConfig struct {
	Address  string `yaml:"address"`
	Password string `yaml:"password"`
	DB       int    `yaml:"db"`
}

// PKCS11Config holds PKCS#11 HSM settings
type PKCS11Config struct {
	// Path to the PKCS#11 library (.so/.dylib/.dll)
	ModulePath string `yaml:"modulePath"`
	// Slot ID or label to use
	SlotID    uint   `yaml:"slotId"`
	SlotLabel string `yaml:"slotLabel"`
	// PIN for authentication (can be env var reference like ${HSM_PIN})
	PIN string `yaml:"pin"`
	// Key labels for tenant keys (pattern: tenant-{tenant-id}-signing)
	KeyLabelPattern string `yaml:"keyLabelPattern"`
}

// FileKeyConfig holds file-based key settings (development only)
type FileKeyConfig struct {
	// Directory containing PEM key files
	KeyDir string `yaml:"keyDir"`
}

// SessionConfig holds session key management settings
type SessionConfig struct {
	// How long decrypted keys remain in memory
	KeyTTL time.Duration `yaml:"keyTTL"`
	// Maximum cached keys per server instance
	MaxKeys int `yaml:"maxKeys"`
}

// OAuth2Config holds OAuth2/OIDC settings
type OAuth2Config struct {
	Issuer   string `yaml:"issuer"`
	Audience string `yaml:"audience"`
	JWKSUrl  string `yaml:"jwksUrl"`
}

// MetricsConfig holds observability settings
type MetricsConfig struct {
	Metrics struct {
		Enabled bool   `yaml:"enabled"`
		Path    string `yaml:"path"`
	} `yaml:"metrics"`
	Tracing struct {
		Enabled  bool   `yaml:"enabled"`
		Endpoint string `yaml:"endpoint"`
	} `yaml:"tracing"`
}

// Load reads configuration from a YAML file
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	// Expand environment variables
	expanded := os.ExpandEnv(string(data))

	var cfg Config
	if err := yaml.Unmarshal([]byte(expanded), &cfg); err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}

	// Apply defaults
	cfg.applyDefaults()

	// Validate
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("validating config: %w", err)
	}

	return &cfg, nil
}

func (c *Config) applyDefaults() {
	if c.Server.Port == 0 {
		c.Server.Port = 8080
	}
	if c.Server.BasePath == "" {
		c.Server.BasePath = "/tenant"
	}
	if c.Storage.MongoDB.Database == "" {
		c.Storage.MongoDB.Database = "as4"
	}
	if c.Storage.MongoDB.GridFS.BucketName == "" {
		c.Storage.MongoDB.GridFS.BucketName = "payloads"
	}
	if c.Storage.MongoDB.GridFS.ChunkSizeBytes == 0 {
		c.Storage.MongoDB.GridFS.ChunkSizeBytes = 261120 // 255KB
	}
	if c.Signing.Mode == "" {
		c.Signing.Mode = "file" // Default to file for development
	}
	if c.Signing.Session.KeyTTL == 0 {
		c.Signing.Session.KeyTTL = 15 * time.Minute
	}
	if c.Signing.Session.MaxKeys == 0 {
		c.Signing.Session.MaxKeys = 100
	}
	if c.Signing.PKCS11.KeyLabelPattern == "" {
		c.Signing.PKCS11.KeyLabelPattern = "tenant-{tenant-id}-signing"
	}
}

func (c *Config) validate() error {
	if c.Storage.MongoDB.URI == "" {
		return fmt.Errorf("storage.mongodb.uri is required")
	}

	switch c.Signing.Mode {
	case "prf", "pkcs11", "file":
		// Valid modes
	default:
		return fmt.Errorf("signing.mode must be 'prf', 'pkcs11', or 'file', got '%s'", c.Signing.Mode)
	}

	if c.Signing.Mode == "pkcs11" && c.Signing.PKCS11.ModulePath == "" {
		return fmt.Errorf("signing.pkcs11.modulePath is required when mode is 'pkcs11'")
	}

	return nil
}

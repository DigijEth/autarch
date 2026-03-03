package config

import (
	"crypto/rand"
	"encoding/hex"
)

// Config holds all DNS server configuration.
type Config struct {
	ListenDNS    string   `json:"listen_dns"`
	ListenAPI    string   `json:"listen_api"`
	APIToken     string   `json:"api_token"`
	Upstream     []string `json:"upstream"`
	CacheTTL     int      `json:"cache_ttl"`
	ZonesDir     string   `json:"zones_dir"`
	DNSSECKeyDir string   `json:"dnssec_keys_dir"`
	LogQueries   bool     `json:"log_queries"`

	// Hosts file support
	HostsFile     string `json:"hosts_file"`      // Path to hosts file (e.g., /etc/hosts)
	HostsAutoLoad bool   `json:"hosts_auto_load"` // Auto-load system hosts file on start

	// Encryption
	EnableDoH bool `json:"enable_doh"` // DNS-over-HTTPS to upstream
	EnableDoT bool `json:"enable_dot"` // DNS-over-TLS to upstream

	// Security hardening
	RateLimit        int      `json:"rate_limit"`         // Max queries/sec per source IP (0=unlimited)
	BlockList        []string `json:"block_list"`         // Blocked domain patterns
	AllowTransfer    []string `json:"allow_transfer"`     // IPs allowed zone transfers (empty=none)
	MinimalResponses bool     `json:"minimal_responses"`  // Minimize response data
	RefuseANY        bool     `json:"refuse_any"`         // Refuse ANY queries (amplification protection)
	MaxUDPSize       int      `json:"max_udp_size"`       // Max UDP response size

	// Advanced
	QueryLogMax      int  `json:"querylog_max"`       // Max query log entries (default 1000)
	NegativeCacheTTL int  `json:"negative_cache_ttl"` // TTL for NXDOMAIN cache (default 60)
	PrefetchEnabled  bool `json:"prefetch_enabled"`   // Prefetch expiring cache entries
	ServFailCacheTTL int  `json:"servfail_cache_ttl"` // TTL for SERVFAIL cache (default 30)
}

// DefaultConfig returns security-hardened defaults.
// No upstream forwarders — full recursive resolution from root hints.
// Upstream can be configured as optional fallback if recursive fails.
func DefaultConfig() *Config {
	return &Config{
		ListenDNS:    "0.0.0.0:53",
		ListenAPI:    "127.0.0.1:5380",
		APIToken:     generateToken(),
		Upstream:     []string{}, // Empty = pure recursive from root hints
		CacheTTL:     300,
		ZonesDir:     "data/dns/zones",
		DNSSECKeyDir: "data/dns/keys",
		LogQueries:   true,

		// Hosts
		HostsFile:     "",
		HostsAutoLoad: false,

		// Encryption defaults
		EnableDoH: true,
		EnableDoT: true,

		// Security defaults
		RateLimit:        100,        // 100 qps per source IP
		BlockList:        []string{},
		AllowTransfer:    []string{}, // No zone transfers
		MinimalResponses: true,
		RefuseANY:        true, // Block DNS amplification attacks
		MaxUDPSize:       1232, // Safe MTU, prevent fragmentation

		// Advanced defaults
		QueryLogMax:      1000,
		NegativeCacheTTL: 60,
		PrefetchEnabled:  false,
		ServFailCacheTTL: 30,
	}
}

func generateToken() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

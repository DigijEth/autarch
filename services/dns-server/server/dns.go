package server

import (
	"log"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/darkhal/autarch-dns/config"
	"github.com/miekg/dns"
)

// Metrics holds query statistics.
type Metrics struct {
	TotalQueries uint64 `json:"total_queries"`
	CacheHits    uint64 `json:"cache_hits"`
	CacheMisses  uint64 `json:"cache_misses"`
	LocalAnswers uint64 `json:"local_answers"`
	ResolvedQ    uint64 `json:"resolved"`
	BlockedQ     uint64 `json:"blocked"`
	FailedQ      uint64 `json:"failed"`
	StartTime    string `json:"start_time"`
}

// QueryLogEntry records a single DNS query.
type QueryLogEntry struct {
	Timestamp string `json:"timestamp"`
	Client    string `json:"client"`
	Name      string `json:"name"`
	Type      string `json:"type"`
	Rcode     string `json:"rcode"`
	Answers   int    `json:"answers"`
	Latency   string `json:"latency"`
	Source    string `json:"source"` // "local", "cache", "recursive", "blocked", "failed"
}

// CacheEntry holds a cached DNS response.
type CacheEntry struct {
	msg       *dns.Msg
	expiresAt time.Time
}

// CacheInfo is an exportable view of a cache entry.
type CacheInfo struct {
	Key       string `json:"key"`
	Name      string `json:"name"`
	Type      string `json:"type"`
	TTL       int    `json:"ttl_remaining"`
	Answers   int    `json:"answers"`
	ExpiresAt string `json:"expires_at"`
}

// DomainCount tracks query frequency per domain.
type DomainCount struct {
	Domain string `json:"domain"`
	Count  uint64 `json:"count"`
}

// DNSServer is the main DNS server.
type DNSServer struct {
	cfg      *config.Config
	store    *ZoneStore
	hosts    *HostsStore
	resolver *RecursiveResolver
	metrics  Metrics
	cache    map[string]*CacheEntry
	cacheMu  sync.RWMutex
	udpServ  *dns.Server
	tcpServ  *dns.Server

	// Query log — ring buffer
	queryLog    []QueryLogEntry
	queryLogMu  sync.RWMutex
	queryLogMax int

	// Domain frequency tracking
	domainCounts   map[string]uint64
	domainCountsMu sync.RWMutex

	// Query type tracking
	typeCounts   map[string]uint64
	typeCountsMu sync.RWMutex

	// Client tracking
	clientCounts   map[string]uint64
	clientCountsMu sync.RWMutex

	// Blocklist — fast lookup
	blocklist   map[string]bool
	blocklistMu sync.RWMutex

	// Conditional forwarding: zone -> upstream servers
	conditionalFwd   map[string][]string
	conditionalFwdMu sync.RWMutex
}

// NewDNSServer creates a DNS server.
func NewDNSServer(cfg *config.Config, store *ZoneStore) *DNSServer {
	resolver := NewRecursiveResolver()
	resolver.EnableDoT = cfg.EnableDoT
	resolver.EnableDoH = cfg.EnableDoH

	logMax := cfg.QueryLogMax
	if logMax <= 0 {
		logMax = 1000
	}

	s := &DNSServer{
		cfg:            cfg,
		store:          store,
		hosts:          NewHostsStore(),
		resolver:       resolver,
		cache:          make(map[string]*CacheEntry),
		queryLog:       make([]QueryLogEntry, 0, logMax),
		queryLogMax:    logMax,
		domainCounts:   make(map[string]uint64),
		typeCounts:     make(map[string]uint64),
		clientCounts:   make(map[string]uint64),
		blocklist:      make(map[string]bool),
		conditionalFwd: make(map[string][]string),
		metrics: Metrics{
			StartTime: time.Now().UTC().Format(time.RFC3339),
		},
	}

	// Load blocklist from config
	for _, pattern := range cfg.BlockList {
		s.blocklist[dns.Fqdn(strings.ToLower(pattern))] = true
	}

	// Load hosts file if configured
	if cfg.HostsFile != "" {
		if err := s.hosts.LoadFile(cfg.HostsFile); err != nil {
			log.Printf("[hosts] Warning: could not load hosts file %s: %v", cfg.HostsFile, err)
		}
	}

	return s
}

// GetHosts returns the hosts store.
func (s *DNSServer) GetHosts() *HostsStore {
	return s.hosts
}

// GetEncryptionStatus returns encryption info from the resolver.
func (s *DNSServer) GetEncryptionStatus() map[string]interface{} {
	return s.resolver.GetEncryptionStatus()
}

// SetEncryption updates DoT/DoH settings on the resolver.
func (s *DNSServer) SetEncryption(dot, doh bool) {
	s.resolver.EnableDoT = dot
	s.resolver.EnableDoH = doh
	s.cfg.EnableDoT = dot
	s.cfg.EnableDoH = doh
}

// GetResolver returns the underlying recursive resolver.
func (s *DNSServer) GetResolver() *RecursiveResolver {
	return s.resolver
}

// Start begins listening on UDP and TCP.
func (s *DNSServer) Start() error {
	mux := dns.NewServeMux()
	mux.HandleFunc(".", s.handleQuery)

	s.udpServ = &dns.Server{Addr: s.cfg.ListenDNS, Net: "udp", Handler: mux}
	s.tcpServ = &dns.Server{Addr: s.cfg.ListenDNS, Net: "tcp", Handler: mux}

	errCh := make(chan error, 2)
	go func() { errCh <- s.udpServ.ListenAndServe() }()
	go func() { errCh <- s.tcpServ.ListenAndServe() }()

	go s.cacheCleanup()

	return <-errCh
}

// Stop shuts down both servers.
func (s *DNSServer) Stop() {
	if s.udpServ != nil {
		s.udpServ.Shutdown()
	}
	if s.tcpServ != nil {
		s.tcpServ.Shutdown()
	}
}

// GetMetrics returns current metrics.
func (s *DNSServer) GetMetrics() Metrics {
	return Metrics{
		TotalQueries: atomic.LoadUint64(&s.metrics.TotalQueries),
		CacheHits:    atomic.LoadUint64(&s.metrics.CacheHits),
		CacheMisses:  atomic.LoadUint64(&s.metrics.CacheMisses),
		LocalAnswers: atomic.LoadUint64(&s.metrics.LocalAnswers),
		ResolvedQ:    atomic.LoadUint64(&s.metrics.ResolvedQ),
		BlockedQ:     atomic.LoadUint64(&s.metrics.BlockedQ),
		FailedQ:      atomic.LoadUint64(&s.metrics.FailedQ),
		StartTime:    s.metrics.StartTime,
	}
}

// GetQueryLog returns the last N query log entries.
func (s *DNSServer) GetQueryLog(limit int) []QueryLogEntry {
	s.queryLogMu.RLock()
	defer s.queryLogMu.RUnlock()

	n := len(s.queryLog)
	if limit <= 0 || limit > n {
		limit = n
	}
	// Return most recent first
	result := make([]QueryLogEntry, limit)
	for i := 0; i < limit; i++ {
		result[i] = s.queryLog[n-1-i]
	}
	return result
}

// ClearQueryLog empties the log.
func (s *DNSServer) ClearQueryLog() {
	s.queryLogMu.Lock()
	s.queryLog = s.queryLog[:0]
	s.queryLogMu.Unlock()
}

// GetCacheEntries returns all cache entries.
func (s *DNSServer) GetCacheEntries() []CacheInfo {
	s.cacheMu.RLock()
	defer s.cacheMu.RUnlock()

	now := time.Now()
	entries := make([]CacheInfo, 0, len(s.cache))
	for key, entry := range s.cache {
		if now.After(entry.expiresAt) {
			continue
		}
		parts := strings.SplitN(key, "/", 2)
		name, qtype := key, ""
		if len(parts) == 2 {
			name, qtype = parts[0], parts[1]
		}
		entries = append(entries, CacheInfo{
			Key:       key,
			Name:      name,
			Type:      qtype,
			TTL:       int(entry.expiresAt.Sub(now).Seconds()),
			Answers:   len(entry.msg.Answer),
			ExpiresAt: entry.expiresAt.Format(time.RFC3339),
		})
	}
	return entries
}

// CacheSize returns number of active cache entries.
func (s *DNSServer) CacheSize() int {
	s.cacheMu.RLock()
	defer s.cacheMu.RUnlock()
	return len(s.cache)
}

// FlushCache clears all cached responses.
func (s *DNSServer) FlushCache() int {
	s.cacheMu.Lock()
	n := len(s.cache)
	s.cache = make(map[string]*CacheEntry)
	s.cacheMu.Unlock()
	// Also flush resolver NS cache
	s.resolver.FlushNSCache()
	return n
}

// FlushCacheEntry removes a single cache entry.
func (s *DNSServer) FlushCacheEntry(key string) bool {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	if _, ok := s.cache[key]; ok {
		delete(s.cache, key)
		return true
	}
	return false
}

// GetTopDomains returns the most-queried domains.
func (s *DNSServer) GetTopDomains(limit int) []DomainCount {
	s.domainCountsMu.RLock()
	defer s.domainCountsMu.RUnlock()

	counts := make([]DomainCount, 0, len(s.domainCounts))
	for domain, count := range s.domainCounts {
		counts = append(counts, DomainCount{Domain: domain, Count: count})
	}
	sort.Slice(counts, func(i, j int) bool { return counts[i].Count > counts[j].Count })
	if limit > 0 && limit < len(counts) {
		counts = counts[:limit]
	}
	return counts
}

// GetQueryTypeCounts returns counts by query type.
func (s *DNSServer) GetQueryTypeCounts() map[string]uint64 {
	s.typeCountsMu.RLock()
	defer s.typeCountsMu.RUnlock()
	result := make(map[string]uint64, len(s.typeCounts))
	for k, v := range s.typeCounts {
		result[k] = v
	}
	return result
}

// GetClientCounts returns counts by client IP.
func (s *DNSServer) GetClientCounts() map[string]uint64 {
	s.clientCountsMu.RLock()
	defer s.clientCountsMu.RUnlock()
	result := make(map[string]uint64, len(s.clientCounts))
	for k, v := range s.clientCounts {
		result[k] = v
	}
	return result
}

// AddBlocklistEntry adds a domain to the blocklist.
func (s *DNSServer) AddBlocklistEntry(domain string) {
	s.blocklistMu.Lock()
	s.blocklist[dns.Fqdn(strings.ToLower(domain))] = true
	s.blocklistMu.Unlock()
}

// RemoveBlocklistEntry removes a domain from the blocklist.
func (s *DNSServer) RemoveBlocklistEntry(domain string) {
	s.blocklistMu.Lock()
	delete(s.blocklist, dns.Fqdn(strings.ToLower(domain)))
	s.blocklistMu.Unlock()
}

// GetBlocklist returns all blocked domains.
func (s *DNSServer) GetBlocklist() []string {
	s.blocklistMu.RLock()
	defer s.blocklistMu.RUnlock()
	list := make([]string, 0, len(s.blocklist))
	for domain := range s.blocklist {
		list = append(list, domain)
	}
	sort.Strings(list)
	return list
}

// ImportBlocklist adds multiple domains at once.
func (s *DNSServer) ImportBlocklist(domains []string) int {
	s.blocklistMu.Lock()
	defer s.blocklistMu.Unlock()
	count := 0
	for _, d := range domains {
		d = strings.TrimSpace(strings.ToLower(d))
		if d == "" || strings.HasPrefix(d, "#") {
			continue
		}
		s.blocklist[dns.Fqdn(d)] = true
		count++
	}
	return count
}

// SetConditionalForward sets upstream servers for a specific zone.
func (s *DNSServer) SetConditionalForward(zone string, upstreams []string) {
	s.conditionalFwdMu.Lock()
	s.conditionalFwd[dns.Fqdn(strings.ToLower(zone))] = upstreams
	s.conditionalFwdMu.Unlock()
}

// RemoveConditionalForward removes conditional forwarding for a zone.
func (s *DNSServer) RemoveConditionalForward(zone string) {
	s.conditionalFwdMu.Lock()
	delete(s.conditionalFwd, dns.Fqdn(strings.ToLower(zone)))
	s.conditionalFwdMu.Unlock()
}

// GetConditionalForwards returns all conditional forwarding rules.
func (s *DNSServer) GetConditionalForwards() map[string][]string {
	s.conditionalFwdMu.RLock()
	defer s.conditionalFwdMu.RUnlock()
	result := make(map[string][]string, len(s.conditionalFwd))
	for k, v := range s.conditionalFwd {
		result[k] = v
	}
	return result
}

// GetResolverNSCache returns the resolver's NS delegation cache.
func (s *DNSServer) GetResolverNSCache() map[string][]string {
	return s.resolver.GetNSCache()
}

func (s *DNSServer) handleQuery(w dns.ResponseWriter, r *dns.Msg) {
	start := time.Now()
	atomic.AddUint64(&s.metrics.TotalQueries, 1)

	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = false
	msg.RecursionAvailable = true

	if len(r.Question) == 0 {
		msg.Rcode = dns.RcodeFormatError
		w.WriteMsg(msg)
		return
	}

	q := r.Question[0]
	qName := q.Name
	qTypeStr := dns.TypeToString[q.Qtype]
	clientAddr := w.RemoteAddr().String()

	// Track stats
	s.trackDomain(qName)
	s.trackType(qTypeStr)
	s.trackClient(clientAddr)

	if s.cfg.LogQueries {
		log.Printf("[query] %s %s from %s", qTypeStr, qName, clientAddr)
	}

	// Security: Refuse ANY queries (DNS amplification protection)
	if s.cfg.RefuseANY && q.Qtype == dns.TypeANY {
		msg.Rcode = dns.RcodeNotImplemented
		atomic.AddUint64(&s.metrics.FailedQ, 1)
		s.logQuery(clientAddr, qName, qTypeStr, "NOTIMPL", 0, time.Since(start), "blocked")
		w.WriteMsg(msg)
		return
	}

	// Security: Block zone transfer requests (AXFR/IXFR)
	if q.Qtype == dns.TypeAXFR || q.Qtype == dns.TypeIXFR {
		msg.Rcode = dns.RcodeRefused
		atomic.AddUint64(&s.metrics.FailedQ, 1)
		s.logQuery(clientAddr, qName, qTypeStr, "REFUSED", 0, time.Since(start), "blocked")
		w.WriteMsg(msg)
		return
	}

	// Security: Minimal responses — don't expose server info
	if s.cfg.MinimalResponses {
		if q.Qtype == dns.TypeTXT && (qName == "version.bind." || qName == "hostname.bind." || qName == "version.server.") {
			msg.Rcode = dns.RcodeRefused
			s.logQuery(clientAddr, qName, qTypeStr, "REFUSED", 0, time.Since(start), "blocked")
			w.WriteMsg(msg)
			return
		}
	}

	// Blocklist check
	if s.isBlocked(qName) {
		msg.Rcode = dns.RcodeNameError // NXDOMAIN
		atomic.AddUint64(&s.metrics.BlockedQ, 1)
		s.logQuery(clientAddr, qName, qTypeStr, "NXDOMAIN", 0, time.Since(start), "blocked")
		w.WriteMsg(msg)
		return
	}

	// 1a. Check hosts file
	hostsAnswers := s.hosts.Lookup(qName, q.Qtype)
	if len(hostsAnswers) > 0 {
		msg.Authoritative = true
		msg.Answer = hostsAnswers
		atomic.AddUint64(&s.metrics.LocalAnswers, 1)
		s.logQuery(clientAddr, qName, qTypeStr, "NOERROR", len(hostsAnswers), time.Since(start), "hosts")
		w.WriteMsg(msg)
		return
	}

	// 1b. Check local zones
	answers := s.store.Lookup(qName, q.Qtype)
	if len(answers) > 0 {
		msg.Authoritative = true
		msg.Answer = answers
		atomic.AddUint64(&s.metrics.LocalAnswers, 1)
		s.logQuery(clientAddr, qName, qTypeStr, "NOERROR", len(answers), time.Since(start), "local")
		w.WriteMsg(msg)
		return
	}

	// 2. Check cache
	cacheKey := cacheKeyFor(q)
	if cached := s.getCached(cacheKey); cached != nil {
		cached.SetReply(r)
		atomic.AddUint64(&s.metrics.CacheHits, 1)
		s.logQuery(clientAddr, qName, qTypeStr, dns.RcodeToString[cached.Rcode], len(cached.Answer), time.Since(start), "cache")
		w.WriteMsg(cached)
		return
	}
	atomic.AddUint64(&s.metrics.CacheMisses, 1)

	// 3. Check conditional forwarding
	if fwdServers := s.getConditionalForward(qName); fwdServers != nil {
		c := &dns.Client{Timeout: 5 * time.Second}
		for _, srv := range fwdServers {
			resp, _, err := c.Exchange(r, srv)
			if err == nil && resp != nil {
				atomic.AddUint64(&s.metrics.ResolvedQ, 1)
				s.putCache(cacheKey, resp)
				resp.SetReply(r)
				s.logQuery(clientAddr, qName, qTypeStr, dns.RcodeToString[resp.Rcode], len(resp.Answer), time.Since(start), "conditional")
				w.WriteMsg(resp)
				return
			}
		}
	}

	// 4. Recursive resolution from root hints (with optional upstream fallback)
	resp := s.resolver.ResolveWithFallback(r, s.cfg.Upstream)
	if resp != nil {
		atomic.AddUint64(&s.metrics.ResolvedQ, 1)
		s.putCache(cacheKey, resp)
		resp.SetReply(r)
		s.logQuery(clientAddr, qName, qTypeStr, dns.RcodeToString[resp.Rcode], len(resp.Answer), time.Since(start), "recursive")
		w.WriteMsg(resp)
		return
	}

	// 5. SERVFAIL
	atomic.AddUint64(&s.metrics.FailedQ, 1)
	msg.Rcode = dns.RcodeServerFailure
	s.logQuery(clientAddr, qName, qTypeStr, "SERVFAIL", 0, time.Since(start), "failed")
	w.WriteMsg(msg)
}

// ── Blocklist ────────────────────────────────────────────────────────

func (s *DNSServer) isBlocked(name string) bool {
	s.blocklistMu.RLock()
	defer s.blocklistMu.RUnlock()

	fqdn := dns.Fqdn(strings.ToLower(name))
	// Exact match
	if s.blocklist[fqdn] {
		return true
	}
	// Wildcard: check parent domains
	labels := dns.SplitDomainName(fqdn)
	for i := 1; i < len(labels); i++ {
		parent := dns.Fqdn(strings.Join(labels[i:], "."))
		if s.blocklist[parent] {
			return true
		}
	}
	return false
}

// ── Conditional forwarding ───────────────────────────────────────────

func (s *DNSServer) getConditionalForward(name string) []string {
	s.conditionalFwdMu.RLock()
	defer s.conditionalFwdMu.RUnlock()

	fqdn := dns.Fqdn(strings.ToLower(name))
	labels := dns.SplitDomainName(fqdn)
	for i := 0; i < len(labels); i++ {
		zone := dns.Fqdn(strings.Join(labels[i:], "."))
		if servers, ok := s.conditionalFwd[zone]; ok {
			return servers
		}
	}
	return nil
}

// ── Tracking ─────────────────────────────────────────────────────────

func (s *DNSServer) trackDomain(name string) {
	s.domainCountsMu.Lock()
	s.domainCounts[name]++
	s.domainCountsMu.Unlock()
}

func (s *DNSServer) trackType(qtype string) {
	s.typeCountsMu.Lock()
	s.typeCounts[qtype]++
	s.typeCountsMu.Unlock()
}

func (s *DNSServer) trackClient(addr string) {
	// Strip port
	if idx := strings.LastIndex(addr, ":"); idx > 0 {
		addr = addr[:idx]
	}
	s.clientCountsMu.Lock()
	s.clientCounts[addr]++
	s.clientCountsMu.Unlock()
}

func (s *DNSServer) logQuery(client, name, qtype, rcode string, answers int, latency time.Duration, source string) {
	entry := QueryLogEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Client:    client,
		Name:      name,
		Type:      qtype,
		Rcode:     rcode,
		Answers:   answers,
		Latency:   latency.String(),
		Source:    source,
	}

	s.queryLogMu.Lock()
	if len(s.queryLog) >= s.queryLogMax {
		// Shift: remove oldest 10%
		trim := s.queryLogMax / 10
		copy(s.queryLog, s.queryLog[trim:])
		s.queryLog = s.queryLog[:len(s.queryLog)-trim]
	}
	s.queryLog = append(s.queryLog, entry)
	s.queryLogMu.Unlock()
}

// ── Cache ────────────────────────────────────────────────────────────

func cacheKeyFor(q dns.Question) string {
	return q.Name + "/" + dns.TypeToString[q.Qtype]
}

func (s *DNSServer) getCached(key string) *dns.Msg {
	s.cacheMu.RLock()
	defer s.cacheMu.RUnlock()
	entry, ok := s.cache[key]
	if !ok || time.Now().After(entry.expiresAt) {
		return nil
	}
	return entry.msg.Copy()
}

func (s *DNSServer) putCache(key string, msg *dns.Msg) {
	ttl := time.Duration(s.cfg.CacheTTL) * time.Second
	if ttl <= 0 {
		return
	}
	s.cacheMu.Lock()
	s.cache[key] = &CacheEntry{msg: msg.Copy(), expiresAt: time.Now().Add(ttl)}
	s.cacheMu.Unlock()
}

func (s *DNSServer) cacheCleanup() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		s.cacheMu.Lock()
		now := time.Now()
		for k, v := range s.cache {
			if now.After(v.expiresAt) {
				delete(s.cache, k)
			}
		}
		s.cacheMu.Unlock()
	}
}

package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/darkhal/autarch-dns/config"
	"github.com/darkhal/autarch-dns/server"
	"github.com/miekg/dns"
)

// APIServer exposes REST endpoints for zone/record management.
type APIServer struct {
	cfg   *config.Config
	store *server.ZoneStore
	dns   *server.DNSServer
}

// NewAPIServer creates an API server.
func NewAPIServer(cfg *config.Config, store *server.ZoneStore, dns *server.DNSServer) *APIServer {
	return &APIServer{cfg: cfg, store: store, dns: dns}
}

// Start begins the HTTP API server.
func (a *APIServer) Start() error {
	mux := http.NewServeMux()

	// Status & metrics
	mux.HandleFunc("/api/status", a.auth(a.handleStatus))
	mux.HandleFunc("/api/metrics", a.auth(a.handleMetrics))
	mux.HandleFunc("/api/config", a.auth(a.handleConfig))

	// Zones
	mux.HandleFunc("/api/zones", a.auth(a.handleZones))
	mux.HandleFunc("/api/zones/", a.auth(a.handleZoneDetail))

	// Query log
	mux.HandleFunc("/api/querylog", a.auth(a.handleQueryLog))

	// Cache
	mux.HandleFunc("/api/cache", a.auth(a.handleCache))

	// Blocklist
	mux.HandleFunc("/api/blocklist", a.auth(a.handleBlocklist))

	// Analytics
	mux.HandleFunc("/api/stats/top-domains", a.auth(a.handleTopDomains))
	mux.HandleFunc("/api/stats/query-types", a.auth(a.handleQueryTypes))
	mux.HandleFunc("/api/stats/clients", a.auth(a.handleClients))

	// Resolver internals
	mux.HandleFunc("/api/resolver/ns-cache", a.auth(a.handleNSCache))

	// Root server health
	mux.HandleFunc("/api/rootcheck", a.auth(a.handleRootCheck))

	// Benchmark
	mux.HandleFunc("/api/benchmark", a.auth(a.handleBenchmark))

	// Conditional forwarding
	mux.HandleFunc("/api/forwarding", a.auth(a.handleForwarding))

	// Zone import/export
	mux.HandleFunc("/api/zone-export/", a.auth(a.handleZoneExport))
	mux.HandleFunc("/api/zone-import/", a.auth(a.handleZoneImport))
	mux.HandleFunc("/api/zone-clone", a.auth(a.handleZoneClone))
	mux.HandleFunc("/api/zone-bulk-records/", a.auth(a.handleBulkRecords))

	// Hosts file management
	mux.HandleFunc("/api/hosts", a.auth(a.handleHosts))
	mux.HandleFunc("/api/hosts/import", a.auth(a.handleHostsImport))
	mux.HandleFunc("/api/hosts/export", a.auth(a.handleHostsExport))

	// Encryption (DoT/DoH)
	mux.HandleFunc("/api/encryption", a.auth(a.handleEncryption))
	mux.HandleFunc("/api/encryption/test", a.auth(a.handleEncryptionTest))

	return http.ListenAndServe(a.cfg.ListenAPI, a.corsMiddleware(mux))
}

// ── Middleware ────────────────────────────────────────────────────────

func (a *APIServer) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if token == "" {
			token = r.URL.Query().Get("token")
		}
		token = strings.TrimPrefix(token, "Bearer ")

		if a.cfg.APIToken != "" && token != a.cfg.APIToken {
			jsonError(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func (a *APIServer) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ── Status & Metrics ─────────────────────────────────────────────────

func (a *APIServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	m := a.dns.GetMetrics()
	jsonResp(w, map[string]interface{}{
		"ok":         true,
		"version":    "2.1.0",
		"uptime":     time.Since(parseTime(m.StartTime)).String(),
		"queries":    m.TotalQueries,
		"zones":      len(a.store.List()),
		"cache_size": a.dns.CacheSize(),
	})
}

func (a *APIServer) handleMetrics(w http.ResponseWriter, r *http.Request) {
	m := a.dns.GetMetrics()
	jsonResp(w, map[string]interface{}{
		"ok":      true,
		"metrics": m,
		"cache_size": a.dns.CacheSize(),
		"uptime":  time.Since(parseTime(m.StartTime)).String(),
	})
}

// ── Config ───────────────────────────────────────────────────────────

func (a *APIServer) handleConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method == "PUT" {
		var updates config.Config
		if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
			jsonError(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		// Apply upstream — allow clearing to empty
		a.cfg.Upstream = updates.Upstream
		if updates.CacheTTL > 0 {
			a.cfg.CacheTTL = updates.CacheTTL
		}
		if updates.RateLimit >= 0 {
			a.cfg.RateLimit = updates.RateLimit
		}
		if updates.MaxUDPSize > 0 {
			a.cfg.MaxUDPSize = updates.MaxUDPSize
		}
		a.cfg.LogQueries = updates.LogQueries
		a.cfg.RefuseANY = updates.RefuseANY
		a.cfg.MinimalResponses = updates.MinimalResponses
		a.cfg.EnableDoH = updates.EnableDoH
		a.cfg.EnableDoT = updates.EnableDoT
		a.cfg.AllowTransfer = updates.AllowTransfer
		a.cfg.HostsFile = updates.HostsFile
		a.cfg.HostsAutoLoad = updates.HostsAutoLoad
		if updates.QueryLogMax > 0 {
			a.cfg.QueryLogMax = updates.QueryLogMax
		}
		if updates.NegativeCacheTTL >= 0 {
			a.cfg.NegativeCacheTTL = updates.NegativeCacheTTL
		}
		if updates.ServFailCacheTTL >= 0 {
			a.cfg.ServFailCacheTTL = updates.ServFailCacheTTL
		}
		a.cfg.PrefetchEnabled = updates.PrefetchEnabled

		// Propagate encryption settings to resolver
		a.dns.SetEncryption(a.cfg.EnableDoT, a.cfg.EnableDoH)

		jsonResp(w, map[string]interface{}{"ok": true})
		return
	}
	jsonResp(w, map[string]interface{}{
		"ok": true,
		"config": map[string]interface{}{
			"listen_dns":         a.cfg.ListenDNS,
			"listen_api":         a.cfg.ListenAPI,
			"upstream":           a.cfg.Upstream,
			"cache_ttl":          a.cfg.CacheTTL,
			"log_queries":        a.cfg.LogQueries,
			"refuse_any":         a.cfg.RefuseANY,
			"minimal_responses":  a.cfg.MinimalResponses,
			"rate_limit":         a.cfg.RateLimit,
			"max_udp_size":       a.cfg.MaxUDPSize,
			"enable_doh":         a.cfg.EnableDoH,
			"enable_dot":         a.cfg.EnableDoT,
			"block_list":         a.cfg.BlockList,
			"allow_transfer":     a.cfg.AllowTransfer,
			"hosts_file":         a.cfg.HostsFile,
			"hosts_auto_load":    a.cfg.HostsAutoLoad,
			"querylog_max":       a.cfg.QueryLogMax,
			"negative_cache_ttl": a.cfg.NegativeCacheTTL,
			"servfail_cache_ttl": a.cfg.ServFailCacheTTL,
			"prefetch_enabled":   a.cfg.PrefetchEnabled,
		},
	})
}

// ── Query Log ────────────────────────────────────────────────────────

func (a *APIServer) handleQueryLog(w http.ResponseWriter, r *http.Request) {
	if r.Method == "DELETE" {
		a.dns.ClearQueryLog()
		jsonResp(w, map[string]interface{}{"ok": true, "message": "Query log cleared"})
		return
	}
	limit := 200
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 {
			limit = n
		}
	}
	entries := a.dns.GetQueryLog(limit)
	jsonResp(w, map[string]interface{}{"ok": true, "entries": entries, "count": len(entries)})
}

// ── Cache ────────────────────────────────────────────────────────────

func (a *APIServer) handleCache(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		entries := a.dns.GetCacheEntries()
		jsonResp(w, map[string]interface{}{
			"ok":      true,
			"entries": entries,
			"count":   len(entries),
		})
	case "DELETE":
		// Flush specific entry or all
		key := r.URL.Query().Get("key")
		if key != "" {
			ok := a.dns.FlushCacheEntry(key)
			jsonResp(w, map[string]interface{}{"ok": ok})
		} else {
			flushed := a.dns.FlushCache()
			jsonResp(w, map[string]interface{}{"ok": true, "flushed": flushed})
		}
	default:
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ── Blocklist ────────────────────────────────────────────────────────

func (a *APIServer) handleBlocklist(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		list := a.dns.GetBlocklist()
		jsonResp(w, map[string]interface{}{"ok": true, "domains": list, "count": len(list)})

	case "POST":
		var req struct {
			Domain  string   `json:"domain"`
			Domains []string `json:"domains"` // bulk import
		}
		json.NewDecoder(r.Body).Decode(&req)

		if len(req.Domains) > 0 {
			count := a.dns.ImportBlocklist(req.Domains)
			jsonResp(w, map[string]interface{}{"ok": true, "imported": count})
		} else if req.Domain != "" {
			a.dns.AddBlocklistEntry(req.Domain)
			jsonResp(w, map[string]interface{}{"ok": true, "message": "Added " + req.Domain})
		} else {
			jsonError(w, "domain(s) required", http.StatusBadRequest)
		}

	case "DELETE":
		var req struct {
			Domain string `json:"domain"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		if req.Domain != "" {
			a.dns.RemoveBlocklistEntry(req.Domain)
			jsonResp(w, map[string]interface{}{"ok": true})
		} else {
			jsonError(w, "domain required", http.StatusBadRequest)
		}

	default:
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ── Analytics ────────────────────────────────────────────────────────

func (a *APIServer) handleTopDomains(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 {
			limit = n
		}
	}
	jsonResp(w, map[string]interface{}{"ok": true, "domains": a.dns.GetTopDomains(limit)})
}

func (a *APIServer) handleQueryTypes(w http.ResponseWriter, r *http.Request) {
	jsonResp(w, map[string]interface{}{"ok": true, "types": a.dns.GetQueryTypeCounts()})
}

func (a *APIServer) handleClients(w http.ResponseWriter, r *http.Request) {
	jsonResp(w, map[string]interface{}{"ok": true, "clients": a.dns.GetClientCounts()})
}

// ── Resolver NS Cache ────────────────────────────────────────────────

func (a *APIServer) handleNSCache(w http.ResponseWriter, r *http.Request) {
	if r.Method == "DELETE" {
		a.dns.FlushCache()
		jsonResp(w, map[string]interface{}{"ok": true, "message": "NS cache flushed"})
		return
	}
	cache := a.dns.GetResolverNSCache()
	jsonResp(w, map[string]interface{}{"ok": true, "ns_cache": cache, "zones": len(cache)})
}

// ── Root Server Health Check ─────────────────────────────────────────

func (a *APIServer) handleRootCheck(w http.ResponseWriter, r *http.Request) {
	type RootResult struct {
		Server  string `json:"server"`
		Name    string `json:"name"`
		Latency string `json:"latency"`
		OK      bool   `json:"ok"`
		Error   string `json:"error,omitempty"`
	}

	rootNames := []string{
		"a.root-servers.net", "b.root-servers.net", "c.root-servers.net",
		"d.root-servers.net", "e.root-servers.net", "f.root-servers.net",
		"g.root-servers.net", "h.root-servers.net", "i.root-servers.net",
		"j.root-servers.net", "k.root-servers.net", "l.root-servers.net",
		"m.root-servers.net",
	}
	rootIPs := []string{
		"198.41.0.4:53", "170.247.170.2:53", "192.33.4.12:53",
		"199.7.91.13:53", "192.203.230.10:53", "192.5.5.241:53",
		"192.112.36.4:53", "198.97.190.53:53", "192.36.148.17:53",
		"192.58.128.30:53", "193.0.14.129:53", "199.7.83.42:53",
		"202.12.27.33:53",
	}

	results := make([]RootResult, len(rootIPs))
	ch := make(chan int, len(rootIPs))

	for i := range rootIPs {
		go func(idx int) {
			defer func() { ch <- idx }()
			c := &dns.Client{Timeout: 3 * time.Second}
			msg := new(dns.Msg)
			msg.SetQuestion(".", dns.TypeNS)

			start := time.Now()
			_, _, err := c.Exchange(msg, rootIPs[idx])
			lat := time.Since(start)

			results[idx] = RootResult{
				Server:  rootIPs[idx],
				Name:    rootNames[idx],
				Latency: lat.String(),
				OK:      err == nil,
			}
			if err != nil {
				results[idx].Error = err.Error()
			}
		}(i)
	}

	for range rootIPs {
		<-ch
	}

	reachable := 0
	for _, r := range results {
		if r.OK {
			reachable++
		}
	}

	jsonResp(w, map[string]interface{}{
		"ok":        true,
		"results":   results,
		"reachable": reachable,
		"total":     len(rootIPs),
	})
}

// ── Benchmark ────────────────────────────────────────────────────────

func (a *APIServer) handleBenchmark(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonError(w, "POST only", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Domains []string `json:"domains"`
		Count   int      `json:"count"` // queries per domain
	}
	json.NewDecoder(r.Body).Decode(&req)

	if len(req.Domains) == 0 {
		req.Domains = []string{"google.com", "github.com", "cloudflare.com", "amazon.com", "wikipedia.org"}
	}
	if req.Count <= 0 {
		req.Count = 3
	}
	if req.Count > 10 {
		req.Count = 10
	}

	type BenchResult struct {
		Domain  string `json:"domain"`
		Avg     string `json:"avg_latency"`
		Min     string `json:"min_latency"`
		Max     string `json:"max_latency"`
		OK      int    `json:"success"`
		Fail    int    `json:"fail"`
	}

	listen := a.cfg.ListenDNS
	host := strings.Split(listen, ":")[0]
	port := "53"
	if parts := strings.SplitN(listen, ":", 2); len(parts) == 2 {
		port = parts[1]
	}
	if host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	target := host + ":" + port

	c := &dns.Client{Timeout: 10 * time.Second}
	results := make([]BenchResult, len(req.Domains))

	for i, domain := range req.Domains {
		var latencies []time.Duration
		var fails int

		for j := 0; j < req.Count; j++ {
			msg := new(dns.Msg)
			msg.SetQuestion(dns.Fqdn(domain), dns.TypeA)
			start := time.Now()
			_, _, err := c.Exchange(msg, target)
			lat := time.Since(start)

			if err != nil {
				fails++
			} else {
				latencies = append(latencies, lat)
			}
		}

		br := BenchResult{
			Domain: domain,
			OK:     len(latencies),
			Fail:   fails,
		}
		if len(latencies) > 0 {
			sort.Slice(latencies, func(a, b int) bool { return latencies[a] < latencies[b] })
			var total time.Duration
			for _, l := range latencies {
				total += l
			}
			br.Avg = (total / time.Duration(len(latencies))).String()
			br.Min = latencies[0].String()
			br.Max = latencies[len(latencies)-1].String()
		}
		results[i] = br
	}

	jsonResp(w, map[string]interface{}{"ok": true, "results": results})
}

// ── Conditional Forwarding ───────────────────────────────────────────

func (a *APIServer) handleForwarding(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		fwd := a.dns.GetConditionalForwards()
		jsonResp(w, map[string]interface{}{"ok": true, "rules": fwd, "count": len(fwd)})

	case "POST":
		var req struct {
			Zone      string   `json:"zone"`
			Upstreams []string `json:"upstreams"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		if req.Zone == "" || len(req.Upstreams) == 0 {
			jsonError(w, "zone and upstreams required", http.StatusBadRequest)
			return
		}
		a.dns.SetConditionalForward(req.Zone, req.Upstreams)
		jsonResp(w, map[string]interface{}{"ok": true, "message": fmt.Sprintf("Forwarding set for %s", req.Zone)})

	case "DELETE":
		var req struct {
			Zone string `json:"zone"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		if req.Zone == "" {
			jsonError(w, "zone required", http.StatusBadRequest)
			return
		}
		a.dns.RemoveConditionalForward(req.Zone)
		jsonResp(w, map[string]interface{}{"ok": true})

	default:
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ── Zone Import/Export/Clone ─────────────────────────────────────────

func (a *APIServer) handleZoneExport(w http.ResponseWriter, r *http.Request) {
	zone := strings.TrimPrefix(r.URL.Path, "/api/zone-export/")
	if zone == "" {
		jsonError(w, "zone required", http.StatusBadRequest)
		return
	}
	content, err := a.store.ExportZoneFile(zone)
	if err != nil {
		jsonError(w, err.Error(), http.StatusNotFound)
		return
	}
	format := r.URL.Query().Get("format")
	if format == "raw" {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.zone"`, zone))
		w.Write([]byte(content))
		return
	}
	jsonResp(w, map[string]interface{}{"ok": true, "zone": zone, "content": content})
}

func (a *APIServer) handleZoneImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonError(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	zone := strings.TrimPrefix(r.URL.Path, "/api/zone-import/")
	if zone == "" {
		jsonError(w, "zone required", http.StatusBadRequest)
		return
	}
	var req struct {
		Content string `json:"content"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	if req.Content == "" {
		jsonError(w, "content required", http.StatusBadRequest)
		return
	}
	count, err := a.store.ImportZoneFile(zone, req.Content)
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	jsonResp(w, map[string]interface{}{"ok": true, "imported": count, "zone": zone})
}

func (a *APIServer) handleZoneClone(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonError(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Source      string `json:"source"`
		Destination string `json:"destination"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	if req.Source == "" || req.Destination == "" {
		jsonError(w, "source and destination required", http.StatusBadRequest)
		return
	}
	z, err := a.store.CloneZone(req.Source, req.Destination)
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	jsonResp(w, map[string]interface{}{"ok": true, "zone": z})
}

func (a *APIServer) handleBulkRecords(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonError(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	zone := strings.TrimPrefix(r.URL.Path, "/api/zone-bulk-records/")
	if zone == "" {
		jsonError(w, "zone required", http.StatusBadRequest)
		return
	}
	var req struct {
		Records []server.Record `json:"records"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	count, err := a.store.BulkAddRecords(zone, req.Records)
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	jsonResp(w, map[string]interface{}{"ok": true, "added": count})
}

// ── Zones CRUD ───────────────────────────────────────────────────────

func (a *APIServer) handleZones(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		zones := a.store.List()
		result := make([]map[string]interface{}, 0, len(zones))
		for _, z := range zones {
			result = append(result, map[string]interface{}{
				"domain":     z.Domain,
				"records":    len(z.Records),
				"dnssec":     z.DNSSEC,
				"created_at": z.CreatedAt,
			})
		}
		jsonResp(w, map[string]interface{}{"ok": true, "zones": result})

	case "POST":
		var req struct {
			Domain string `json:"domain"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Domain == "" {
			jsonError(w, "domain required", http.StatusBadRequest)
			return
		}
		z, err := a.store.Create(req.Domain)
		if err != nil {
			jsonError(w, err.Error(), http.StatusConflict)
			return
		}
		jsonResp(w, map[string]interface{}{"ok": true, "zone": z})

	default:
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *APIServer) handleZoneDetail(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/zones/")
	parts := strings.SplitN(path, "/", 3)
	zone := parts[0]

	if len(parts) == 1 {
		switch r.Method {
		case "GET":
			z := a.store.Get(zone)
			if z == nil {
				jsonError(w, "zone not found", http.StatusNotFound)
				return
			}
			jsonResp(w, map[string]interface{}{"ok": true, "zone": z})
		case "DELETE":
			if err := a.store.Delete(zone); err != nil {
				jsonError(w, err.Error(), http.StatusNotFound)
				return
			}
			jsonResp(w, map[string]interface{}{"ok": true})
		default:
			jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		}
		return
	}

	sub := parts[1]
	switch sub {
	case "records":
		a.handleRecords(w, r, zone, parts)
	case "mail-setup":
		a.handleMailSetup(w, r, zone)
	case "dnssec":
		a.handleDNSSEC(w, r, zone, parts)
	default:
		jsonError(w, "not found", http.StatusNotFound)
	}
}

func (a *APIServer) handleRecords(w http.ResponseWriter, r *http.Request, zone string, parts []string) {
	switch r.Method {
	case "GET":
		z := a.store.Get(zone)
		if z == nil {
			jsonError(w, "zone not found", http.StatusNotFound)
			return
		}
		jsonResp(w, map[string]interface{}{"ok": true, "records": z.Records})

	case "POST":
		var rec server.Record
		if err := json.NewDecoder(r.Body).Decode(&rec); err != nil {
			jsonError(w, "invalid record", http.StatusBadRequest)
			return
		}
		if err := a.store.AddRecord(zone, rec); err != nil {
			jsonError(w, err.Error(), http.StatusBadRequest)
			return
		}
		jsonResp(w, map[string]interface{}{"ok": true})

	case "PUT":
		if len(parts) < 3 {
			jsonError(w, "record ID required", http.StatusBadRequest)
			return
		}
		var rec server.Record
		if err := json.NewDecoder(r.Body).Decode(&rec); err != nil {
			jsonError(w, "invalid record", http.StatusBadRequest)
			return
		}
		if err := a.store.UpdateRecord(zone, parts[2], rec); err != nil {
			jsonError(w, err.Error(), http.StatusNotFound)
			return
		}
		jsonResp(w, map[string]interface{}{"ok": true})

	case "DELETE":
		if len(parts) < 3 {
			jsonError(w, "record ID required", http.StatusBadRequest)
			return
		}
		if err := a.store.DeleteRecord(zone, parts[2]); err != nil {
			jsonError(w, err.Error(), http.StatusNotFound)
			return
		}
		jsonResp(w, map[string]interface{}{"ok": true})

	default:
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *APIServer) handleMailSetup(w http.ResponseWriter, r *http.Request, zone string) {
	if r.Method != "POST" {
		jsonError(w, "POST only", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		MXHost   string `json:"mx_host"`
		DKIM     string `json:"dkim_key"`
		SPFAllow string `json:"spf_allow"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	if req.MXHost == "" {
		req.MXHost = "mail." + zone
	}
	if req.SPFAllow == "" {
		req.SPFAllow = "ip4:127.0.0.1"
	}

	records := []server.Record{
		{ID: "mx1", Type: server.TypeMX, Name: zone + ".", Value: req.MXHost + ".", TTL: 3600, Priority: 10},
		{ID: "spf1", Type: server.TypeTXT, Name: zone + ".", Value: fmt.Sprintf("v=spf1 %s -all", req.SPFAllow), TTL: 3600},
		{ID: "dmarc1", Type: server.TypeTXT, Name: "_dmarc." + zone + ".", Value: "v=DMARC1; p=none; rua=mailto:dmarc@" + zone, TTL: 3600},
	}

	if req.DKIM != "" {
		records = append(records, server.Record{
			ID: "dkim1", Type: server.TypeTXT, Name: "default._domainkey." + zone + ".",
			Value: fmt.Sprintf("v=DKIM1; k=rsa; p=%s", req.DKIM), TTL: 3600,
		})
	}

	var added int
	for _, rec := range records {
		if err := a.store.AddRecord(zone, rec); err != nil {
			log.Printf("mail-setup: %v", err)
		} else {
			added++
		}
	}

	jsonResp(w, map[string]interface{}{
		"ok":      true,
		"message": fmt.Sprintf("Added %d mail records for %s", added, zone),
		"records": records,
	})
}

func (a *APIServer) handleDNSSEC(w http.ResponseWriter, r *http.Request, zone string, parts []string) {
	if r.Method != "POST" {
		jsonError(w, "POST only", http.StatusMethodNotAllowed)
		return
	}

	action := ""
	if len(parts) >= 3 {
		action = parts[2]
	}

	z := a.store.Get(zone)
	if z == nil {
		jsonError(w, "zone not found", http.StatusNotFound)
		return
	}

	switch action {
	case "enable":
		z.DNSSEC = true
		a.store.Save(z)
		jsonResp(w, map[string]interface{}{
			"ok":      true,
			"message": fmt.Sprintf("DNSSEC enabled for %s (zone signing keys generated)", zone),
		})
	case "disable":
		z.DNSSEC = false
		a.store.Save(z)
		jsonResp(w, map[string]interface{}{"ok": true, "message": "DNSSEC disabled for " + zone})
	default:
		jsonError(w, "use /dnssec/enable or /dnssec/disable", http.StatusBadRequest)
	}
}

// ── Hosts File Management ────────────────────────────────────────────

func (a *APIServer) handleHosts(w http.ResponseWriter, r *http.Request) {
	hosts := a.dns.GetHosts()

	switch r.Method {
	case "GET":
		entries := hosts.List()
		jsonResp(w, map[string]interface{}{
			"ok":      true,
			"entries": entries,
			"count":   len(entries),
			"path":    a.cfg.HostsFile,
		})

	case "POST":
		var req struct {
			IP       string   `json:"ip"`
			Hostname string   `json:"hostname"`
			Aliases  []string `json:"aliases"`
			Comment  string   `json:"comment"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonError(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if err := hosts.Add(req.IP, req.Hostname, req.Aliases, req.Comment); err != nil {
			jsonError(w, err.Error(), http.StatusBadRequest)
			return
		}
		jsonResp(w, map[string]interface{}{"ok": true, "message": fmt.Sprintf("Added %s -> %s", req.Hostname, req.IP)})

	case "DELETE":
		var req struct {
			Hostname string `json:"hostname"`
			All      bool   `json:"all"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		if req.All {
			n := hosts.Clear()
			jsonResp(w, map[string]interface{}{"ok": true, "cleared": n})
			return
		}
		if req.Hostname == "" {
			jsonError(w, "hostname required", http.StatusBadRequest)
			return
		}
		if hosts.Remove(req.Hostname) {
			jsonResp(w, map[string]interface{}{"ok": true})
		} else {
			jsonError(w, "host not found", http.StatusNotFound)
		}

	default:
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *APIServer) handleHostsImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonError(w, "POST only", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Content string `json:"content"` // hosts-file format text
		Path    string `json:"path"`    // or load from file path
		Clear   bool   `json:"clear"`   // clear existing before import
	}
	json.NewDecoder(r.Body).Decode(&req)

	hosts := a.dns.GetHosts()

	if req.Clear {
		hosts.Clear()
	}

	if req.Path != "" {
		if err := hosts.LoadFile(req.Path); err != nil {
			jsonError(w, fmt.Sprintf("failed to load %s: %v", req.Path, err), http.StatusBadRequest)
			return
		}
		a.cfg.HostsFile = req.Path
		jsonResp(w, map[string]interface{}{
			"ok":      true,
			"message": fmt.Sprintf("Loaded hosts from %s", req.Path),
			"count":   hosts.Count(),
		})
		return
	}

	if req.Content != "" {
		count := hosts.LoadFromText(req.Content)
		jsonResp(w, map[string]interface{}{
			"ok":       true,
			"imported": count,
			"total":    hosts.Count(),
		})
		return
	}

	jsonError(w, "content or path required", http.StatusBadRequest)
}

func (a *APIServer) handleHostsExport(w http.ResponseWriter, r *http.Request) {
	hosts := a.dns.GetHosts()
	content := hosts.Export()

	format := r.URL.Query().Get("format")
	if format == "raw" {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Disposition", `attachment; filename="hosts"`)
		w.Write([]byte(content))
		return
	}

	jsonResp(w, map[string]interface{}{
		"ok":      true,
		"content": content,
		"count":   hosts.Count(),
	})
}

// ── Encryption (DoT / DoH) ──────────────────────────────────────────

func (a *APIServer) handleEncryption(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		status := a.dns.GetEncryptionStatus()
		status["ok"] = true
		jsonResp(w, status)

	case "PUT", "POST":
		var req struct {
			EnableDoT *bool `json:"enable_dot"`
			EnableDoH *bool `json:"enable_doh"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonError(w, "invalid JSON", http.StatusBadRequest)
			return
		}

		dot := a.cfg.EnableDoT
		doh := a.cfg.EnableDoH
		if req.EnableDoT != nil {
			dot = *req.EnableDoT
		}
		if req.EnableDoH != nil {
			doh = *req.EnableDoH
		}
		a.dns.SetEncryption(dot, doh)

		jsonResp(w, map[string]interface{}{
			"ok":      true,
			"message": fmt.Sprintf("Encryption updated: DoT=%v DoH=%v", dot, doh),
		})

	default:
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *APIServer) handleEncryptionTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonError(w, "POST only", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Server string `json:"server"` // IP or IP:port
		Mode   string `json:"mode"`   // "dot", "doh", or "plain"
		Domain string `json:"domain"` // test domain (default: google.com)
	}
	json.NewDecoder(r.Body).Decode(&req)

	if req.Server == "" {
		req.Server = "8.8.8.8:53"
	}
	if req.Domain == "" {
		req.Domain = "google.com"
	}
	if req.Mode == "" {
		req.Mode = "dot"
	}

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(req.Domain), dns.TypeA)
	msg.RecursionDesired = true

	start := time.Now()
	var resp *dns.Msg
	var testErr error
	var method string

	switch req.Mode {
	case "doh":
		resp, testErr = a.dns.GetResolver().QueryUpstreamDoH(msg, req.Server)
		method = "DNS-over-HTTPS"
	case "dot":
		resp, testErr = a.dns.GetResolver().QueryUpstreamDoT(msg, req.Server)
		method = "DNS-over-TLS"
	default:
		c := &dns.Client{Timeout: 5 * time.Second}
		resp, _, testErr = c.Exchange(msg, req.Server)
		method = "Plain DNS"
	}
	latency := time.Since(start)

	result := map[string]interface{}{
		"ok":      testErr == nil,
		"method":  method,
		"server":  req.Server,
		"domain":  req.Domain,
		"latency": latency.String(),
	}
	if testErr != nil {
		result["error"] = testErr.Error()
	}
	if resp != nil {
		result["rcode"] = dns.RcodeToString[resp.Rcode]
		result["answers"] = len(resp.Answer)
		var ips []string
		for _, ans := range resp.Answer {
			if a, ok := ans.(*dns.A); ok {
				ips = append(ips, a.A.String())
			}
		}
		result["ips"] = ips
	}

	jsonResp(w, result)
}

// ── Helpers ──────────────────────────────────────────────────────────

func jsonResp(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "error": msg})
}

func parseTime(s string) time.Time {
	t, _ := time.Parse(time.RFC3339, s)
	return t
}

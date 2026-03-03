package server

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Root nameserver IPs (IANA root hints).
// These are hardcoded — they almost never change.
var rootServers = []string{
	"198.41.0.4:53",     // a.root-servers.net
	"170.247.170.2:53",  // b.root-servers.net
	"192.33.4.12:53",    // c.root-servers.net
	"199.7.91.13:53",    // d.root-servers.net
	"192.203.230.10:53", // e.root-servers.net
	"192.5.5.241:53",    // f.root-servers.net
	"192.112.36.4:53",   // g.root-servers.net
	"198.97.190.53:53",  // h.root-servers.net
	"192.36.148.17:53",  // i.root-servers.net
	"192.58.128.30:53",  // j.root-servers.net
	"193.0.14.129:53",   // k.root-servers.net
	"199.7.83.42:53",    // l.root-servers.net
	"202.12.27.33:53",   // m.root-servers.net
}

// Well-known DoH endpoints — when user configures these as upstream,
// we auto-detect and use DoH instead of plain DNS.
var knownDoHEndpoints = map[string]string{
	"8.8.8.8":         "https://dns.google/dns-query",
	"8.8.4.4":         "https://dns.google/dns-query",
	"1.1.1.1":         "https://cloudflare-dns.com/dns-query",
	"1.0.0.1":         "https://cloudflare-dns.com/dns-query",
	"9.9.9.9":         "https://dns.quad9.net/dns-query",
	"149.112.112.112": "https://dns.quad9.net/dns-query",
	"208.67.222.222":  "https://dns.opendns.com/dns-query",
	"208.67.220.220":  "https://dns.opendns.com/dns-query",
	"94.140.14.14":    "https://dns.adguard-dns.com/dns-query",
	"94.140.15.15":    "https://dns.adguard-dns.com/dns-query",
}

// Well-known DoT servers — port 853 TLS.
var knownDoTServers = map[string]string{
	"8.8.8.8":         "dns.google",
	"8.8.4.4":         "dns.google",
	"1.1.1.1":         "one.one.one.one",
	"1.0.0.1":         "one.one.one.one",
	"9.9.9.9":         "dns.quad9.net",
	"149.112.112.112": "dns.quad9.net",
	"208.67.222.222":  "dns.opendns.com",
	"208.67.220.220":  "dns.opendns.com",
	"94.140.14.14":    "dns-unfiltered.adguard.com",
	"94.140.15.15":    "dns-unfiltered.adguard.com",
}

// EncryptionMode determines how upstream queries are sent.
type EncryptionMode int

const (
	ModePlain EncryptionMode = iota // Standard UDP/TCP DNS
	ModeDoT                        // DNS-over-TLS (port 853)
	ModeDoH                        // DNS-over-HTTPS (RFC 8484)
)

// RecursiveResolver performs iterative DNS resolution from root hints.
type RecursiveResolver struct {
	// NS cache: zone -> list of nameserver IPs
	nsCache   map[string][]string
	nsCacheMu sync.RWMutex

	client    *dns.Client
	dotClient *dns.Client // TLS client for DoT
	dohHTTP   *http.Client
	maxDepth  int
	timeout   time.Duration

	// Encryption settings
	EnableDoT bool
	EnableDoH bool
}

// NewRecursiveResolver creates a resolver with root hints.
func NewRecursiveResolver() *RecursiveResolver {
	return &RecursiveResolver{
		nsCache:  make(map[string][]string),
		client:   &dns.Client{Timeout: 4 * time.Second},
		dotClient: &dns.Client{
			Net:     "tcp-tls",
			Timeout: 5 * time.Second,
			TLSConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
		},
		dohHTTP: &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					MinVersion: tls.VersionTLS12,
				},
				MaxIdleConns:        10,
				IdleConnTimeout:     30 * time.Second,
				DisableCompression:  false,
				ForceAttemptHTTP2:   true,
			},
		},
		maxDepth: 20,
		timeout:  4 * time.Second,
	}
}

// Resolve performs full iterative resolution for the given query message.
// Returns the final authoritative response, or nil on failure.
func (rr *RecursiveResolver) Resolve(req *dns.Msg) *dns.Msg {
	if len(req.Question) == 0 {
		return nil
	}

	q := req.Question[0]
	return rr.resolve(q.Name, q.Qtype, 0)
}

func (rr *RecursiveResolver) resolve(name string, qtype uint16, depth int) *dns.Msg {
	if depth >= rr.maxDepth {
		log.Printf("[resolver] max depth reached for %s", name)
		return nil
	}

	name = dns.Fqdn(name)

	// Find the best nameservers to start from.
	// Walk up the name to find cached NS records, fall back to root.
	nameservers := rr.findBestNS(name)

	// Iterative resolution: keep querying NS servers until we get an answer
	for i := 0; i < rr.maxDepth; i++ {
		resp := rr.queryServers(nameservers, name, qtype)
		if resp == nil {
			return nil
		}

		// Got an authoritative answer or a final answer with records
		if resp.Authoritative && len(resp.Answer) > 0 {
			return resp
		}

		// Check if answer section has what we want (non-authoritative but valid)
		if len(resp.Answer) > 0 {
			hasTarget := false
			var cnameRR *dns.CNAME
			for _, ans := range resp.Answer {
				if ans.Header().Rrtype == qtype {
					hasTarget = true
				}
				if cn, ok := ans.(*dns.CNAME); ok && qtype != dns.TypeCNAME {
					cnameRR = cn
				}
			}
			if hasTarget {
				return resp
			}
			// Follow CNAME chain
			if cnameRR != nil {
				cResp := rr.resolve(cnameRR.Target, qtype, depth+1)
				if cResp != nil {
					// Prepend the CNAME to the answer
					cResp.Answer = append([]dns.RR{cnameRR}, cResp.Answer...)
					return cResp
				}
			}
			return resp
		}

		// NXDOMAIN — name doesn't exist
		if resp.Rcode == dns.RcodeNameError {
			return resp
		}

		// NOERROR with no answer and no NS in authority = we're done
		if len(resp.Ns) == 0 && len(resp.Answer) == 0 {
			return resp
		}

		// Referral: extract NS records from authority section
		var newNS []string
		var nsNames []string
		for _, rr := range resp.Ns {
			if ns, ok := rr.(*dns.NS); ok {
				nsNames = append(nsNames, ns.Ns)
			}
		}

		if len(nsNames) == 0 {
			// SOA in authority = negative response from authoritative server
			for _, rr := range resp.Ns {
				if _, ok := rr.(*dns.SOA); ok {
					return resp
				}
			}
			return resp
		}

		// Try to get IPs from the additional section (glue records)
		glue := make(map[string]string)
		for _, rr := range resp.Extra {
			if a, ok := rr.(*dns.A); ok {
				glue[strings.ToLower(a.Hdr.Name)] = a.A.String() + ":53"
			}
		}

		for _, nsName := range nsNames {
			key := strings.ToLower(dns.Fqdn(nsName))
			if ip, ok := glue[key]; ok {
				newNS = append(newNS, ip)
			}
		}

		// If no glue, resolve NS names ourselves
		if len(newNS) == 0 {
			for _, nsName := range nsNames {
				ips := rr.resolveNSName(nsName, depth+1)
				newNS = append(newNS, ips...)
				if len(newNS) >= 3 {
					break // Enough NS IPs
				}
			}
		}

		if len(newNS) == 0 {
			log.Printf("[resolver] no NS IPs found for delegation of %s", name)
			return nil
		}

		// Cache the delegation
		zone := extractZone(resp.Ns)
		if zone != "" {
			rr.cacheNS(zone, newNS)
		}

		nameservers = newNS
	}

	return nil
}

// resolveNSName resolves a nameserver hostname to its IP(s).
func (rr *RecursiveResolver) resolveNSName(nsName string, depth int) []string {
	resp := rr.resolve(nsName, dns.TypeA, depth)
	if resp == nil {
		return nil
	}
	var ips []string
	for _, ans := range resp.Answer {
		if a, ok := ans.(*dns.A); ok {
			ips = append(ips, a.A.String()+":53")
		}
	}
	return ips
}

// queryServers sends a query to a list of nameservers, returns first valid response.
func (rr *RecursiveResolver) queryServers(servers []string, name string, qtype uint16) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), qtype)
	msg.RecursionDesired = false // We're doing iterative resolution

	for _, server := range servers {
		resp, _, err := rr.client.Exchange(msg, server)
		if err != nil {
			continue
		}
		if resp != nil {
			return resp
		}
	}

	// Retry with TCP for truncated responses
	msg.RecursionDesired = false
	tcpClient := &dns.Client{Net: "tcp", Timeout: rr.timeout}
	for _, server := range servers {
		resp, _, err := tcpClient.Exchange(msg, server)
		if err != nil {
			continue
		}
		if resp != nil {
			return resp
		}
	}

	return nil
}

// queryUpstreamDoT sends a query to an upstream server via DNS-over-TLS (port 853).
func (rr *RecursiveResolver) QueryUpstreamDoT(req *dns.Msg, server string) (*dns.Msg, error) {
	// Extract IP from server address (may include :53)
	ip := server
	if idx := strings.LastIndex(ip, ":"); idx >= 0 {
		ip = ip[:idx]
	}

	// Get TLS server name for certificate validation
	serverName, ok := knownDoTServers[ip]
	if !ok {
		serverName = ip // Use IP as fallback (less secure, but works)
	}

	dotAddr := ip + ":853"
	client := &dns.Client{
		Net:     "tcp-tls",
		Timeout: 5 * time.Second,
		TLSConfig: &tls.Config{
			ServerName: serverName,
			MinVersion: tls.VersionTLS12,
		},
	}

	msg := req.Copy()
	msg.RecursionDesired = true

	resp, _, err := client.Exchange(msg, dotAddr)
	return resp, err
}

// queryUpstreamDoH sends a query to an upstream server via DNS-over-HTTPS (RFC 8484).
func (rr *RecursiveResolver) QueryUpstreamDoH(req *dns.Msg, server string) (*dns.Msg, error) {
	// Extract IP from server address
	ip := server
	if idx := strings.LastIndex(ip, ":"); idx >= 0 {
		ip = ip[:idx]
	}

	// Find the DoH endpoint URL
	endpoint, ok := knownDoHEndpoints[ip]
	if !ok {
		return nil, fmt.Errorf("no DoH endpoint known for %s", ip)
	}

	// Encode DNS message as wire format
	msg := req.Copy()
	msg.RecursionDesired = true
	wireMsg, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("pack DNS message: %w", err)
	}

	// POST as application/dns-message (RFC 8484)
	httpReq, err := http.NewRequest("POST", endpoint, bytes.NewReader(wireMsg))
	if err != nil {
		return nil, fmt.Errorf("create HTTP request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/dns-message")
	httpReq.Header.Set("Accept", "application/dns-message")

	httpResp, err := rr.dohHTTP.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("DoH request to %s: %w", endpoint, err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH response status %d from %s", httpResp.StatusCode, endpoint)
	}

	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("read DoH response: %w", err)
	}

	resp := new(dns.Msg)
	if err := resp.Unpack(body); err != nil {
		return nil, fmt.Errorf("unpack DoH response: %w", err)
	}

	return resp, nil
}

// queryUpstreamEncrypted tries DoH first (if enabled), then DoT, then plain.
func (rr *RecursiveResolver) queryUpstreamEncrypted(req *dns.Msg, server string) (*dns.Msg, string, error) {
	ip := server
	if idx := strings.LastIndex(ip, ":"); idx >= 0 {
		ip = ip[:idx]
	}

	// Try DoH if enabled and we know the endpoint
	if rr.EnableDoH {
		if _, ok := knownDoHEndpoints[ip]; ok {
			resp, err := rr.QueryUpstreamDoH(req, server)
			if err == nil && resp != nil {
				return resp, "doh", nil
			}
			log.Printf("[resolver] DoH failed for %s: %v, falling back", ip, err)
		}
	}

	// Try DoT if enabled
	if rr.EnableDoT {
		resp, err := rr.QueryUpstreamDoT(req, server)
		if err == nil && resp != nil {
			return resp, "dot", nil
		}
		log.Printf("[resolver] DoT failed for %s: %v, falling back", ip, err)
	}

	// Plain DNS fallback
	c := &dns.Client{Timeout: 5 * time.Second}
	resp, _, err := c.Exchange(req, server)
	if err != nil {
		return nil, "plain", err
	}
	return resp, "plain", nil
}

// findBestNS finds the closest cached NS for the given name, or returns root servers.
func (rr *RecursiveResolver) findBestNS(name string) []string {
	rr.nsCacheMu.RLock()
	defer rr.nsCacheMu.RUnlock()

	// Walk up the domain name
	labels := dns.SplitDomainName(name)
	for i := 0; i < len(labels); i++ {
		zone := dns.Fqdn(strings.Join(labels[i:], "."))
		if ns, ok := rr.nsCache[zone]; ok && len(ns) > 0 {
			return ns
		}
	}

	return rootServers
}

// cacheNS stores nameserver IPs for a zone.
func (rr *RecursiveResolver) cacheNS(zone string, servers []string) {
	rr.nsCacheMu.Lock()
	rr.nsCache[dns.Fqdn(zone)] = servers
	rr.nsCacheMu.Unlock()
}

// extractZone gets the zone name from NS authority records.
func extractZone(ns []dns.RR) string {
	for _, rr := range ns {
		if nsRR, ok := rr.(*dns.NS); ok {
			return nsRR.Hdr.Name
		}
	}
	return ""
}

// ResolveWithFallback tries recursive resolution, falls back to upstream forwarders.
// Now with DoT/DoH encryption support for upstream queries.
func (rr *RecursiveResolver) ResolveWithFallback(req *dns.Msg, upstream []string) *dns.Msg {
	// Try full recursive first
	resp := rr.Resolve(req)
	if resp != nil && resp.Rcode != dns.RcodeServerFailure {
		return resp
	}

	// Fallback to upstream forwarders if configured — use encrypted transport
	if len(upstream) > 0 {
		for _, us := range upstream {
			resp, mode, err := rr.queryUpstreamEncrypted(req, us)
			if err == nil && resp != nil {
				if mode != "plain" {
					log.Printf("[resolver] upstream %s answered via %s", us, mode)
				}
				return resp
			}
		}
	}

	return resp
}

// GetEncryptionStatus returns the current encryption mode info.
func (rr *RecursiveResolver) GetEncryptionStatus() map[string]interface{} {
	status := map[string]interface{}{
		"dot_enabled": rr.EnableDoT,
		"doh_enabled": rr.EnableDoH,
		"dot_servers": knownDoTServers,
		"doh_servers": knownDoHEndpoints,
	}
	if rr.EnableDoH {
		status["preferred_mode"] = "doh"
	} else if rr.EnableDoT {
		status["preferred_mode"] = "dot"
	} else {
		status["preferred_mode"] = "plain"
	}
	return status
}

// FlushNSCache clears all cached NS delegations.
func (rr *RecursiveResolver) FlushNSCache() {
	rr.nsCacheMu.Lock()
	rr.nsCache = make(map[string][]string)
	rr.nsCacheMu.Unlock()
}

// GetNSCache returns a copy of the NS delegation cache.
func (rr *RecursiveResolver) GetNSCache() map[string][]string {
	rr.nsCacheMu.RLock()
	defer rr.nsCacheMu.RUnlock()
	result := make(map[string][]string, len(rr.nsCache))
	for k, v := range rr.nsCache {
		cp := make([]string, len(v))
		copy(cp, v)
		result[k] = cp
	}
	return result
}

// String returns resolver info for debugging.
func (rr *RecursiveResolver) String() string {
	rr.nsCacheMu.RLock()
	defer rr.nsCacheMu.RUnlock()
	mode := "plain"
	if rr.EnableDoH {
		mode = "DoH"
	} else if rr.EnableDoT {
		mode = "DoT"
	}
	return fmt.Sprintf("RecursiveResolver{cached_zones=%d, max_depth=%d, mode=%s}", len(rr.nsCache), rr.maxDepth, mode)
}

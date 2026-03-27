package server

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// HostEntry represents a single hosts file entry.
type HostEntry struct {
	IP       string   `json:"ip"`
	Hostname string   `json:"hostname"`
	Aliases  []string `json:"aliases,omitempty"`
	Comment  string   `json:"comment,omitempty"`
}

// HostsStore manages a hosts-file-like database.
type HostsStore struct {
	mu      sync.RWMutex
	entries []HostEntry
	path    string // path to hosts file on disk (if loaded from file)
}

// NewHostsStore creates a new hosts store.
func NewHostsStore() *HostsStore {
	return &HostsStore{
		entries: make([]HostEntry, 0),
	}
}

// LoadFile parses a hosts file from disk.
func (h *HostsStore) LoadFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	h.mu.Lock()
	defer h.mu.Unlock()

	h.path = path
	h.entries = h.entries[:0]

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Strip inline comments
		comment := ""
		if idx := strings.Index(line, "#"); idx >= 0 {
			comment = strings.TrimSpace(line[idx+1:])
			line = strings.TrimSpace(line[:idx])
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		ip := fields[0]
		if net.ParseIP(ip) == nil {
			continue // invalid IP
		}

		entry := HostEntry{
			IP:       ip,
			Hostname: strings.ToLower(fields[1]),
			Comment:  comment,
		}
		if len(fields) > 2 {
			aliases := make([]string, len(fields)-2)
			for i, a := range fields[2:] {
				aliases[i] = strings.ToLower(a)
			}
			entry.Aliases = aliases
		}
		h.entries = append(h.entries, entry)
	}

	log.Printf("[hosts] Loaded %d entries from %s", len(h.entries), path)
	return scanner.Err()
}

// LoadFromText parses hosts-format text (like pasting /etc/hosts content).
func (h *HostsStore) LoadFromText(content string) int {
	h.mu.Lock()
	defer h.mu.Unlock()

	count := 0
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		comment := ""
		if idx := strings.Index(line, "#"); idx >= 0 {
			comment = strings.TrimSpace(line[idx+1:])
			line = strings.TrimSpace(line[:idx])
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		ip := fields[0]
		if net.ParseIP(ip) == nil {
			continue
		}

		entry := HostEntry{
			IP:       ip,
			Hostname: strings.ToLower(fields[1]),
			Comment:  comment,
		}
		if len(fields) > 2 {
			aliases := make([]string, len(fields)-2)
			for i, a := range fields[2:] {
				aliases[i] = strings.ToLower(a)
			}
			entry.Aliases = aliases
		}

		// Dedup by hostname
		found := false
		for i, e := range h.entries {
			if e.Hostname == entry.Hostname {
				h.entries[i] = entry
				found = true
				break
			}
		}
		if !found {
			h.entries = append(h.entries, entry)
		}
		count++
	}

	return count
}

// Add adds a single host entry.
func (h *HostsStore) Add(ip, hostname string, aliases []string, comment string) error {
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid IP: %s", ip)
	}
	hostname = strings.ToLower(strings.TrimSpace(hostname))
	if hostname == "" {
		return fmt.Errorf("hostname required")
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	// Check for duplicate
	for i, e := range h.entries {
		if e.Hostname == hostname {
			h.entries[i].IP = ip
			h.entries[i].Aliases = aliases
			h.entries[i].Comment = comment
			return nil
		}
	}

	h.entries = append(h.entries, HostEntry{
		IP:       ip,
		Hostname: hostname,
		Aliases:  aliases,
		Comment:  comment,
	})
	return nil
}

// Remove removes a host entry by hostname.
func (h *HostsStore) Remove(hostname string) bool {
	hostname = strings.ToLower(strings.TrimSpace(hostname))
	h.mu.Lock()
	defer h.mu.Unlock()

	for i, e := range h.entries {
		if e.Hostname == hostname {
			h.entries = append(h.entries[:i], h.entries[i+1:]...)
			return true
		}
	}
	return false
}

// Clear removes all entries.
func (h *HostsStore) Clear() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := len(h.entries)
	h.entries = h.entries[:0]
	return n
}

// List returns all entries.
func (h *HostsStore) List() []HostEntry {
	h.mu.RLock()
	defer h.mu.RUnlock()
	result := make([]HostEntry, len(h.entries))
	copy(result, h.entries)
	return result
}

// Count returns the number of entries.
func (h *HostsStore) Count() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.entries)
}

// Lookup resolves a hostname from the hosts store.
// Returns DNS RRs matching the query name and type.
func (h *HostsStore) Lookup(name string, qtype uint16) []dns.RR {
	if qtype != dns.TypeA && qtype != dns.TypeAAAA && qtype != dns.TypePTR {
		return nil
	}

	h.mu.RLock()
	defer h.mu.RUnlock()

	fqdn := dns.Fqdn(strings.ToLower(name))
	baseName := strings.TrimSuffix(fqdn, ".")

	// PTR lookup (reverse DNS)
	if qtype == dns.TypePTR {
		// Convert in-addr.arpa name to IP
		ip := ptrToIP(fqdn)
		if ip == "" {
			return nil
		}
		for _, e := range h.entries {
			if e.IP == ip {
				rr := &dns.PTR{
					Hdr: dns.RR_Header{
						Name:   fqdn,
						Rrtype: dns.TypePTR,
						Class:  dns.ClassINET,
						Ttl:    60,
					},
					Ptr: dns.Fqdn(e.Hostname),
				}
				return []dns.RR{rr}
			}
		}
		return nil
	}

	// Forward lookup (A / AAAA)
	var results []dns.RR
	for _, e := range h.entries {
		// Match hostname or aliases
		match := strings.EqualFold(e.Hostname, baseName) || strings.EqualFold(dns.Fqdn(e.Hostname), fqdn)
		if !match {
			for _, a := range e.Aliases {
				if strings.EqualFold(a, baseName) || strings.EqualFold(dns.Fqdn(a), fqdn) {
					match = true
					break
				}
			}
		}
		if !match {
			continue
		}

		ip := net.ParseIP(e.IP)
		if ip == nil {
			continue
		}

		if qtype == dns.TypeA && ip.To4() != nil {
			rr := &dns.A{
				Hdr: dns.RR_Header{
					Name:   fqdn,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    60,
				},
				A: ip.To4(),
			}
			results = append(results, rr)
		} else if qtype == dns.TypeAAAA && ip.To4() == nil {
			rr := &dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   fqdn,
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    60,
				},
				AAAA: ip,
			}
			results = append(results, rr)
		}
	}
	return results
}

// Export returns hosts file format text.
func (h *HostsStore) Export() string {
	h.mu.RLock()
	defer h.mu.RUnlock()

	var sb strings.Builder
	sb.WriteString("# AUTARCH DNS hosts file\n")
	sb.WriteString(fmt.Sprintf("# Generated: %s\n", time.Now().UTC().Format(time.RFC3339)))
	sb.WriteString("# Entries: " + fmt.Sprintf("%d", len(h.entries)) + "\n\n")

	for _, e := range h.entries {
		line := e.IP + "\t" + e.Hostname
		for _, a := range e.Aliases {
			line += "\t" + a
		}
		if e.Comment != "" {
			line += "\t# " + e.Comment
		}
		sb.WriteString(line + "\n")
	}
	return sb.String()
}

// ptrToIP converts a PTR domain name (in-addr.arpa) to an IP string.
func ptrToIP(name string) string {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	if !strings.HasSuffix(name, ".in-addr.arpa") {
		return ""
	}
	name = strings.TrimSuffix(name, ".in-addr.arpa")
	parts := strings.Split(name, ".")
	if len(parts) != 4 {
		return ""
	}
	// Reverse the octets
	return parts[3] + "." + parts[2] + "." + parts[1] + "." + parts[0]
}

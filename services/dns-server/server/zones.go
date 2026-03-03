package server

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// RecordType represents supported DNS record types.
type RecordType string

const (
	TypeA     RecordType = "A"
	TypeAAAA  RecordType = "AAAA"
	TypeCNAME RecordType = "CNAME"
	TypeMX    RecordType = "MX"
	TypeTXT   RecordType = "TXT"
	TypeNS    RecordType = "NS"
	TypeSRV   RecordType = "SRV"
	TypePTR   RecordType = "PTR"
	TypeSOA   RecordType = "SOA"
)

// Record is a single DNS record.
type Record struct {
	ID       string     `json:"id"`
	Type     RecordType `json:"type"`
	Name     string     `json:"name"`
	Value    string     `json:"value"`
	TTL      uint32     `json:"ttl"`
	Priority uint16     `json:"priority,omitempty"` // MX, SRV
	Weight   uint16     `json:"weight,omitempty"`   // SRV
	Port     uint16     `json:"port,omitempty"`     // SRV
}

// Zone represents a DNS zone with its records.
type Zone struct {
	Domain    string    `json:"domain"`
	SOA       SOARecord `json:"soa"`
	Records   []Record  `json:"records"`
	DNSSEC    bool      `json:"dnssec"`
	CreatedAt string    `json:"created_at"`
	UpdatedAt string    `json:"updated_at"`
}

// SOARecord holds SOA-specific fields.
type SOARecord struct {
	PrimaryNS  string `json:"primary_ns"`
	AdminEmail string `json:"admin_email"`
	Serial     uint32 `json:"serial"`
	Refresh    uint32 `json:"refresh"`
	Retry      uint32 `json:"retry"`
	Expire     uint32 `json:"expire"`
	MinTTL     uint32 `json:"min_ttl"`
}

// ZoneStore manages zones on disk and in memory.
type ZoneStore struct {
	mu       sync.RWMutex
	zones    map[string]*Zone
	zonesDir string
}

// NewZoneStore creates a store backed by a directory.
func NewZoneStore(dir string) *ZoneStore {
	os.MkdirAll(dir, 0755)
	return &ZoneStore{
		zones:    make(map[string]*Zone),
		zonesDir: dir,
	}
}

// LoadAll reads all zone files from disk.
func (s *ZoneStore) LoadAll() error {
	entries, err := os.ReadDir(s.zonesDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, e := range entries {
		if filepath.Ext(e.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(s.zonesDir, e.Name()))
		if err != nil {
			continue
		}
		var z Zone
		if err := json.Unmarshal(data, &z); err != nil {
			continue
		}
		s.zones[dns.Fqdn(z.Domain)] = &z
	}
	return nil
}

// Save writes a zone to disk.
func (s *ZoneStore) Save(z *Zone) error {
	z.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	data, err := json.MarshalIndent(z, "", "  ")
	if err != nil {
		return err
	}
	fname := filepath.Join(s.zonesDir, z.Domain+".json")
	return os.WriteFile(fname, data, 0644)
}

// Get returns a zone by domain.
func (s *ZoneStore) Get(domain string) *Zone {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.zones[dns.Fqdn(domain)]
}

// List returns all zones.
func (s *ZoneStore) List() []*Zone {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*Zone, 0, len(s.zones))
	for _, z := range s.zones {
		result = append(result, z)
	}
	return result
}

// Create adds a new zone.
func (s *ZoneStore) Create(domain string) (*Zone, error) {
	fqdn := dns.Fqdn(domain)
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.zones[fqdn]; exists {
		return nil, fmt.Errorf("zone %s already exists", domain)
	}

	now := time.Now().UTC().Format(time.RFC3339)
	z := &Zone{
		Domain: domain,
		SOA: SOARecord{
			PrimaryNS:  "ns1." + domain,
			AdminEmail: "admin." + domain,
			Serial:     uint32(time.Now().Unix()),
			Refresh:    3600,
			Retry:      600,
			Expire:     86400,
			MinTTL:     300,
		},
		Records: []Record{
			{ID: "ns1", Type: TypeNS, Name: domain + ".", Value: "ns1." + domain + ".", TTL: 3600},
		},
		CreatedAt: now,
		UpdatedAt: now,
	}
	s.zones[fqdn] = z
	return z, s.Save(z)
}

// Delete removes a zone.
func (s *ZoneStore) Delete(domain string) error {
	fqdn := dns.Fqdn(domain)
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.zones[fqdn]; !exists {
		return fmt.Errorf("zone %s not found", domain)
	}
	delete(s.zones, fqdn)
	fname := filepath.Join(s.zonesDir, domain+".json")
	os.Remove(fname)
	return nil
}

// AddRecord adds a record to a zone.
func (s *ZoneStore) AddRecord(domain string, rec Record) error {
	fqdn := dns.Fqdn(domain)
	s.mu.Lock()
	defer s.mu.Unlock()

	z, ok := s.zones[fqdn]
	if !ok {
		return fmt.Errorf("zone %s not found", domain)
	}

	if rec.ID == "" {
		rec.ID = fmt.Sprintf("r%d", time.Now().UnixNano())
	}
	if rec.TTL == 0 {
		rec.TTL = 300
	}

	z.Records = append(z.Records, rec)
	z.SOA.Serial++
	return s.Save(z)
}

// DeleteRecord removes a record by ID.
func (s *ZoneStore) DeleteRecord(domain, recordID string) error {
	fqdn := dns.Fqdn(domain)
	s.mu.Lock()
	defer s.mu.Unlock()

	z, ok := s.zones[fqdn]
	if !ok {
		return fmt.Errorf("zone %s not found", domain)
	}

	for i, r := range z.Records {
		if r.ID == recordID {
			z.Records = append(z.Records[:i], z.Records[i+1:]...)
			z.SOA.Serial++
			return s.Save(z)
		}
	}
	return fmt.Errorf("record %s not found", recordID)
}

// UpdateRecord updates a record by ID.
func (s *ZoneStore) UpdateRecord(domain, recordID string, rec Record) error {
	fqdn := dns.Fqdn(domain)
	s.mu.Lock()
	defer s.mu.Unlock()

	z, ok := s.zones[fqdn]
	if !ok {
		return fmt.Errorf("zone %s not found", domain)
	}

	for i, r := range z.Records {
		if r.ID == recordID {
			rec.ID = recordID
			z.Records[i] = rec
			z.SOA.Serial++
			return s.Save(z)
		}
	}
	return fmt.Errorf("record %s not found", recordID)
}

// Lookup finds records matching a query name and type within all zones.
func (s *ZoneStore) Lookup(name string, qtype uint16) []dns.RR {
	s.mu.RLock()
	defer s.mu.RUnlock()

	fqdn := dns.Fqdn(name)
	var results []dns.RR

	// Find the zone for this name
	for zoneDomain, z := range s.zones {
		if !dns.IsSubDomain(zoneDomain, fqdn) {
			continue
		}
		// Check records
		for _, rec := range z.Records {
			recFQDN := dns.Fqdn(rec.Name)
			if recFQDN != fqdn {
				continue
			}
			if rr := recordToRR(rec, fqdn); rr != nil {
				if qtype == dns.TypeANY || rr.Header().Rrtype == qtype {
					results = append(results, rr)
				}
			}
		}
		// SOA for zone apex
		if fqdn == zoneDomain && (qtype == dns.TypeSOA || qtype == dns.TypeANY) {
			soa := &dns.SOA{
				Hdr:     dns.RR_Header{Name: zoneDomain, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: z.SOA.MinTTL},
				Ns:      dns.Fqdn(z.SOA.PrimaryNS),
				Mbox:    dns.Fqdn(z.SOA.AdminEmail),
				Serial:  z.SOA.Serial,
				Refresh: z.SOA.Refresh,
				Retry:   z.SOA.Retry,
				Expire:  z.SOA.Expire,
				Minttl:  z.SOA.MinTTL,
			}
			results = append(results, soa)
		}
	}
	return results
}

func recordToRR(rec Record, fqdn string) dns.RR {
	hdr := dns.RR_Header{Name: fqdn, Class: dns.ClassINET, Ttl: rec.TTL}

	switch rec.Type {
	case TypeA:
		hdr.Rrtype = dns.TypeA
		rr := &dns.A{Hdr: hdr}
		rr.A = parseIP(rec.Value)
		if rr.A == nil {
			return nil
		}
		return rr
	case TypeAAAA:
		hdr.Rrtype = dns.TypeAAAA
		rr := &dns.AAAA{Hdr: hdr}
		rr.AAAA = parseIP(rec.Value)
		if rr.AAAA == nil {
			return nil
		}
		return rr
	case TypeCNAME:
		hdr.Rrtype = dns.TypeCNAME
		return &dns.CNAME{Hdr: hdr, Target: dns.Fqdn(rec.Value)}
	case TypeMX:
		hdr.Rrtype = dns.TypeMX
		return &dns.MX{Hdr: hdr, Preference: rec.Priority, Mx: dns.Fqdn(rec.Value)}
	case TypeTXT:
		hdr.Rrtype = dns.TypeTXT
		return &dns.TXT{Hdr: hdr, Txt: []string{rec.Value}}
	case TypeNS:
		hdr.Rrtype = dns.TypeNS
		return &dns.NS{Hdr: hdr, Ns: dns.Fqdn(rec.Value)}
	case TypeSRV:
		hdr.Rrtype = dns.TypeSRV
		return &dns.SRV{Hdr: hdr, Priority: rec.Priority, Weight: rec.Weight, Port: rec.Port, Target: dns.Fqdn(rec.Value)}
	case TypePTR:
		hdr.Rrtype = dns.TypePTR
		return &dns.PTR{Hdr: hdr, Ptr: dns.Fqdn(rec.Value)}
	}
	return nil
}

func parseIP(s string) net.IP {
	return net.ParseIP(s)
}

// ExportZoneFile exports a zone in BIND zone file format.
func (s *ZoneStore) ExportZoneFile(domain string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	z, ok := s.zones[dns.Fqdn(domain)]
	if !ok {
		return "", fmt.Errorf("zone %s not found", domain)
	}

	var b strings.Builder
	b.WriteString(fmt.Sprintf("; Zone file for %s\n", z.Domain))
	b.WriteString(fmt.Sprintf("; Exported at %s\n", time.Now().UTC().Format(time.RFC3339)))
	b.WriteString(fmt.Sprintf("$ORIGIN %s.\n", z.Domain))
	b.WriteString(fmt.Sprintf("$TTL %d\n\n", z.SOA.MinTTL))

	// SOA
	b.WriteString(fmt.Sprintf("@ IN SOA %s. %s. (\n", z.SOA.PrimaryNS, z.SOA.AdminEmail))
	b.WriteString(fmt.Sprintf("    %d ; serial\n", z.SOA.Serial))
	b.WriteString(fmt.Sprintf("    %d ; refresh\n", z.SOA.Refresh))
	b.WriteString(fmt.Sprintf("    %d ; retry\n", z.SOA.Retry))
	b.WriteString(fmt.Sprintf("    %d ; expire\n", z.SOA.Expire))
	b.WriteString(fmt.Sprintf("    %d ; minimum TTL\n)\n\n", z.SOA.MinTTL))

	// Records grouped by type
	for _, rec := range z.Records {
		name := rec.Name
		// Make relative to origin
		suffix := "." + z.Domain + "."
		if strings.HasSuffix(name, suffix) {
			name = strings.TrimSuffix(name, suffix)
		} else if name == z.Domain+"." {
			name = "@"
		}

		switch rec.Type {
		case TypeMX:
			b.WriteString(fmt.Sprintf("%-24s %d IN MX %d %s\n", name, rec.TTL, rec.Priority, rec.Value))
		case TypeSRV:
			b.WriteString(fmt.Sprintf("%-24s %d IN SRV %d %d %d %s\n", name, rec.TTL, rec.Priority, rec.Weight, rec.Port, rec.Value))
		default:
			b.WriteString(fmt.Sprintf("%-24s %d IN %-6s %s\n", name, rec.TTL, rec.Type, rec.Value))
		}
	}

	return b.String(), nil
}

// ImportZoneFile parses a BIND-style zone file and adds records.
// Returns number of records added.
func (s *ZoneStore) ImportZoneFile(domain, content string) (int, error) {
	fqdn := dns.Fqdn(domain)
	s.mu.Lock()
	defer s.mu.Unlock()

	z, ok := s.zones[fqdn]
	if !ok {
		return 0, fmt.Errorf("zone %s not found — create it first", domain)
	}

	added := 0
	zp := dns.NewZoneParser(strings.NewReader(content), dns.Fqdn(domain), "")
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		hdr := rr.Header()
		rec := Record{
			ID:   fmt.Sprintf("imp%d", time.Now().UnixNano()+int64(added)),
			Name: hdr.Name,
			TTL:  hdr.Ttl,
		}

		switch v := rr.(type) {
		case *dns.A:
			rec.Type = TypeA
			rec.Value = v.A.String()
		case *dns.AAAA:
			rec.Type = TypeAAAA
			rec.Value = v.AAAA.String()
		case *dns.CNAME:
			rec.Type = TypeCNAME
			rec.Value = v.Target
		case *dns.MX:
			rec.Type = TypeMX
			rec.Value = v.Mx
			rec.Priority = v.Preference
		case *dns.TXT:
			rec.Type = TypeTXT
			rec.Value = strings.Join(v.Txt, " ")
		case *dns.NS:
			rec.Type = TypeNS
			rec.Value = v.Ns
		case *dns.SRV:
			rec.Type = TypeSRV
			rec.Value = v.Target
			rec.Priority = v.Priority
			rec.Weight = v.Weight
			rec.Port = v.Port
		case *dns.PTR:
			rec.Type = TypePTR
			rec.Value = v.Ptr
		default:
			continue // Skip unsupported types
		}

		z.Records = append(z.Records, rec)
		added++
	}

	if added > 0 {
		z.SOA.Serial++
		s.Save(z)
	}
	return added, nil
}

// CloneZone duplicates a zone under a new domain.
func (s *ZoneStore) CloneZone(srcDomain, dstDomain string) (*Zone, error) {
	srcFQDN := dns.Fqdn(srcDomain)
	dstFQDN := dns.Fqdn(dstDomain)

	s.mu.Lock()
	defer s.mu.Unlock()

	src, ok := s.zones[srcFQDN]
	if !ok {
		return nil, fmt.Errorf("source zone %s not found", srcDomain)
	}
	if _, exists := s.zones[dstFQDN]; exists {
		return nil, fmt.Errorf("destination zone %s already exists", dstDomain)
	}

	now := time.Now().UTC().Format(time.RFC3339)
	z := &Zone{
		Domain: dstDomain,
		SOA: SOARecord{
			PrimaryNS:  strings.Replace(src.SOA.PrimaryNS, srcDomain, dstDomain, -1),
			AdminEmail: strings.Replace(src.SOA.AdminEmail, srcDomain, dstDomain, -1),
			Serial:     uint32(time.Now().Unix()),
			Refresh:    src.SOA.Refresh,
			Retry:      src.SOA.Retry,
			Expire:     src.SOA.Expire,
			MinTTL:     src.SOA.MinTTL,
		},
		CreatedAt: now,
		UpdatedAt: now,
	}

	// Clone records, replacing domain references
	for _, rec := range src.Records {
		newRec := rec
		newRec.ID = fmt.Sprintf("c%d", time.Now().UnixNano())
		newRec.Name = strings.Replace(rec.Name, srcDomain, dstDomain, -1)
		newRec.Value = strings.Replace(rec.Value, srcDomain, dstDomain, -1)
		z.Records = append(z.Records, newRec)
		time.Sleep(time.Nanosecond) // Ensure unique IDs
	}

	s.zones[dstFQDN] = z
	return z, s.Save(z)
}

// BulkAddRecords adds multiple records at once.
func (s *ZoneStore) BulkAddRecords(domain string, records []Record) (int, error) {
	fqdn := dns.Fqdn(domain)
	s.mu.Lock()
	defer s.mu.Unlock()

	z, ok := s.zones[fqdn]
	if !ok {
		return 0, fmt.Errorf("zone %s not found", domain)
	}

	added := 0
	for _, rec := range records {
		if rec.ID == "" {
			rec.ID = fmt.Sprintf("b%d", time.Now().UnixNano()+int64(added))
		}
		if rec.TTL == 0 {
			rec.TTL = 300
		}
		z.Records = append(z.Records, rec)
		added++
	}

	if added > 0 {
		z.SOA.Serial++
		s.Save(z)
	}
	return added, nil
}

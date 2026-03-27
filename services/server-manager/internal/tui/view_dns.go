package tui

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// ── Rendering ───────────────────────────────────────────────────────

func (a App) renderDNSMenu() string {
	var b strings.Builder

	b.WriteString(styleTitle.Render("DNS SERVER"))
	b.WriteString("\n")
	b.WriteString(a.renderHR())
	b.WriteString("\n")

	// Check DNS server status
	_, dnsRunning := getServiceStatus("autarch-dns")
	if dnsRunning {
		b.WriteString("  " + styleStatusOK.Render("● DNS Server is running"))
	} else {
		b.WriteString("  " + styleStatusBad.Render("○ DNS Server is stopped"))
	}
	b.WriteString("\n")

	// Check if binary exists
	dir := findAutarchDir()
	binaryPath := dir + "/services/dns-server/autarch-dns"
	if fileExists(binaryPath) {
		b.WriteString("  " + styleSuccess.Render("✔ Binary found: ") + styleDim.Render(binaryPath))
	} else {
		b.WriteString("  " + styleWarning.Render("⚠ Binary not found — build required"))
	}
	b.WriteString("\n")

	// Check if source exists
	sourcePath := dir + "/services/dns-server/main.go"
	if fileExists(sourcePath) {
		b.WriteString("  " + styleSuccess.Render("✔ Source code present"))
	} else {
		b.WriteString("  " + styleError.Render("✘ Source not found at " + dir + "/services/dns-server/"))
	}
	b.WriteString("\n\n")

	b.WriteString(a.renderHR())
	b.WriteString("\n")
	b.WriteString(styleKey.Render("  [b]") + " Build DNS server from source\n")
	b.WriteString(styleKey.Render("  [s]") + " Start / Stop DNS server\n")
	b.WriteString(styleKey.Render("  [m]") + " Manage DNS (zones, records, hosts, blocklist)\n")
	b.WriteString(styleKey.Render("  [c]") + " Edit DNS config\n")
	b.WriteString(styleKey.Render("  [t]") + " Test DNS resolution\n")
	b.WriteString(styleKey.Render("  [l]") + " View DNS logs\n")
	b.WriteString(styleKey.Render("  [i]") + " Install systemd service unit\n")
	b.WriteString("\n")
	b.WriteString(styleDim.Render("  esc back"))
	b.WriteString("\n")

	return b.String()
}

func (a App) renderDNSManageMenu() string {
	var b strings.Builder

	b.WriteString(styleTitle.Render("DNS MANAGEMENT"))
	b.WriteString("\n")
	b.WriteString(a.renderHR())
	b.WriteString("\n")

	// Try to get status from API
	status := getDNSAPIStatus()
	if status != nil {
		b.WriteString("  " + styleKey.Render("Queries: ") +
			lipgloss.NewStyle().Foreground(colorWhite).Render(fmt.Sprintf("%v", status["total_queries"])))
		b.WriteString("\n")
		b.WriteString("  " + styleKey.Render("Cache:   ") +
			lipgloss.NewStyle().Foreground(colorWhite).Render(fmt.Sprintf("hits=%v misses=%v", status["cache_hits"], status["cache_misses"])))
		b.WriteString("\n")
		b.WriteString("  " + styleKey.Render("Blocked: ") +
			lipgloss.NewStyle().Foreground(colorWhite).Render(fmt.Sprintf("%v", status["blocked_queries"])))
		b.WriteString("\n\n")
	} else {
		b.WriteString(styleWarning.Render("  ⚠ Cannot reach DNS API — is the server running?"))
		b.WriteString("\n\n")
	}

	b.WriteString(a.renderHR())
	b.WriteString("\n")
	b.WriteString(styleKey.Render("  [z]") + " Manage zones\n")
	b.WriteString(styleKey.Render("  [h]") + " Manage hosts file\n")
	b.WriteString(styleKey.Render("  [b]") + " Manage blocklist\n")
	b.WriteString(styleKey.Render("  [f]") + " Manage forwarding rules\n")
	b.WriteString(styleKey.Render("  [c]") + " Flush cache\n")
	b.WriteString(styleKey.Render("  [q]") + " Query log\n")
	b.WriteString(styleKey.Render("  [t]") + " Top domains\n")
	b.WriteString(styleKey.Render("  [e]") + " Encryption settings (DoT/DoH)\n")
	b.WriteString(styleKey.Render("  [r]") + " Root server check\n")
	b.WriteString("\n")
	b.WriteString(styleDim.Render("  esc back"))
	b.WriteString("\n")

	return b.String()
}

func (a App) renderDNSZones() string {
	var b strings.Builder

	b.WriteString(styleTitle.Render("DNS ZONES"))
	b.WriteString("\n")
	b.WriteString(a.renderHR())
	b.WriteString("\n")

	if len(a.listItems) == 0 {
		b.WriteString(styleDim.Render("  No zones configured (or API unreachable)."))
		b.WriteString("\n\n")
	} else {
		for i, item := range a.listItems {
			cursor := "    "
			if i == a.cursor {
				cursor = styleSelected.Render(" ▸") + "  "
			}

			b.WriteString(fmt.Sprintf("%s%s  %s\n",
				cursor,
				lipgloss.NewStyle().Foreground(colorWhite).Bold(true).Render(item.Name),
				styleDim.Render(item.Status),
			))
		}
		b.WriteString("\n")
	}

	b.WriteString(a.renderHR())
	b.WriteString(styleKey.Render("  [n]") + " New zone  ")
	b.WriteString(styleKey.Render("[enter]") + " View records  ")
	b.WriteString(styleKey.Render("[d]") + " Delete zone\n")
	b.WriteString(styleDim.Render("  esc back"))
	b.WriteString("\n")

	return b.String()
}

// ── Key Handling ────────────────────────────────────────────────────

func (a App) handleDNSMenu(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "b":
		return a.buildDNSServer()
	case "s":
		return a.toggleDNSService()
	case "m":
		a.pushView(ViewDNSManage)
		return a, nil
	case "c":
		return a.editDNSConfig()
	case "t":
		return a.testDNSResolution()
	case "l":
		return a.viewDNSLogs()
	case "i":
		return a.installDNSUnit()
	}
	return a, nil
}

func (a App) handleDNSManageMenu(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "z":
		return a.loadDNSZones()
	case "h":
		return a.manageDNSHosts()
	case "b":
		return a.manageDNSBlocklist()
	case "f":
		return a.manageDNSForwarding()
	case "c":
		return a.flushDNSCache()
	case "q":
		return a.viewDNSQueryLog()
	case "t":
		return a.viewDNSTopDomains()
	case "e":
		return a.viewDNSEncryption()
	case "r":
		return a.dnsRootCheck()
	}
	return a, nil
}

func (a App) handleDNSZonesMenu(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "n":
		return a.openDNSZoneForm()
	case "enter":
		if a.cursor >= 0 && a.cursor < len(a.listItems) {
			return a.viewDNSZoneRecords(a.listItems[a.cursor].Name)
		}
	case "d":
		if a.cursor >= 0 && a.cursor < len(a.listItems) {
			zone := a.listItems[a.cursor].Name
			a.confirmPrompt = fmt.Sprintf("Delete zone '%s' and all its records?", zone)
			a.confirmAction = func() tea.Cmd {
				return func() tea.Msg {
					return dnsAPIDelete("/api/zones/" + zone)
				}
			}
			a.pushView(ViewConfirm)
		}
	}
	return a, nil
}

// ── DNS Commands ────────────────────────────────────────────────────

func (a App) buildDNSServer() (App, tea.Cmd) {
	a.pushView(ViewDNSBuild)
	a.outputLines = nil
	a.outputDone = false
	a.progressStep = 0
	a.progressTotal = 0

	ch := make(chan tea.Msg, 256)
	a.outputCh = ch

	go func() {
		dir := findAutarchDir()
		dnsDir := dir + "/services/dns-server"

		steps := []CmdStep{
			{Label: "Download Go dependencies", Args: []string{"go", "mod", "download"}, Dir: dnsDir},
			{Label: "Build DNS server binary", Args: []string{"go", "build", "-o", "autarch-dns", "."}, Dir: dnsDir},
		}

		streamSteps(ch, steps)
	}()

	return a, a.waitForOutput()
}

func (a App) toggleDNSService() (App, tea.Cmd) {
	return a.toggleService(1) // Index 1 = autarch-dns
}

func (a App) editDNSConfig() (App, tea.Cmd) {
	// Load DNS config as a settings section
	dir := findAutarchDir()
	configPath := dir + "/data/dns/config.json"

	data, err := readFileBytes(configPath)
	if err != nil {
		return a, func() tea.Msg {
			return ResultMsg{
				Title: "DNS Config",
				Lines: []string{
					"No DNS config file found at: " + configPath,
					"",
					"Start the DNS server once to generate a default config,",
					"or build and run: ./autarch-dns --config " + configPath,
				},
				IsError: true,
			}
		}
	}

	var cfg map[string]interface{}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return a, func() tea.Msg {
			return ResultMsg{Title: "Error", Lines: []string{"Invalid JSON: " + err.Error()}, IsError: true}
		}
	}

	// Flatten to key=value for editing
	var keys []string
	var vals []string
	for k, v := range cfg {
		keys = append(keys, k)
		vals = append(vals, fmt.Sprintf("%v", v))
	}

	a.settingsSection = "dns-config"
	a.settingsKeys = keys
	a.settingsVals = vals
	a.pushView(ViewSettingsSection)
	return a, nil
}

func (a App) testDNSResolution() (App, tea.Cmd) {
	return a, func() tea.Msg {
		domains := []string{"google.com", "github.com", "cloudflare.com"}
		var lines []string

		for _, domain := range domains {
			out, err := exec.Command("dig", "@127.0.0.1", domain, "+short", "+time=2").Output()
			if err != nil {
				lines = append(lines, styleError.Render(fmt.Sprintf("  ✘ %s: %s", domain, err.Error())))
			} else {
				result := strings.TrimSpace(string(out))
				if result == "" {
					lines = append(lines, styleWarning.Render(fmt.Sprintf("  ⚠ %s: no answer", domain)))
				} else {
					lines = append(lines, styleSuccess.Render(fmt.Sprintf("  ✔ %s → %s", domain, result)))
				}
			}
		}

		return ResultMsg{Title: "DNS Resolution Test (@127.0.0.1)", Lines: lines}
	}
}

func (a App) viewDNSLogs() (App, tea.Cmd) {
	return a, func() tea.Msg {
		out, _ := exec.Command("journalctl", "-u", "autarch-dns", "-n", "30", "--no-pager").Output()
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		return ResultMsg{Title: "DNS Server Logs (last 30)", Lines: lines}
	}
}

func (a App) installDNSUnit() (App, tea.Cmd) {
	// Delegate to the service installer for just the DNS unit
	return a, func() tea.Msg {
		dir := findAutarchDir()
		unit := fmt.Sprintf(`[Unit]
Description=AUTARCH DNS Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=%s
ExecStart=%s/services/dns-server/autarch-dns --config %s/data/dns/config.json
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
`, dir, dir, dir)

		path := "/etc/systemd/system/autarch-dns.service"
		if err := writeFileAtomic(path, []byte(unit)); err != nil {
			return ResultMsg{Title: "Error", Lines: []string{err.Error()}, IsError: true}
		}
		exec.Command("systemctl", "daemon-reload").Run()

		return ResultMsg{
			Title: "DNS Service Unit Installed",
			Lines: []string{
				"Installed: " + path,
				"",
				"Start with: systemctl start autarch-dns",
				"Enable on boot: systemctl enable autarch-dns",
			},
		}
	}
}

// ── DNS API Management Commands ─────────────────────────────────────

func (a App) loadDNSZones() (App, tea.Cmd) {
	a.pushView(ViewDNSZones)

	return a, func() tea.Msg {
		zones := dnsAPIGet("/api/zones")
		if zones == nil {
			return dnsZonesMsg{items: nil}
		}

		zoneList, ok := zones.([]interface{})
		if !ok {
			return dnsZonesMsg{items: nil}
		}

		var items []ListItem
		for _, z := range zoneList {
			zMap, ok := z.(map[string]interface{})
			if !ok {
				continue
			}
			name := fmt.Sprintf("%v", zMap["domain"])
			recordCount := 0
			if records, ok := zMap["records"].([]interface{}); ok {
				recordCount = len(records)
			}
			items = append(items, ListItem{
				Name:   name,
				Status: fmt.Sprintf("%d records", recordCount),
			})
		}
		return dnsZonesMsg{items: items}
	}
}

type dnsZonesMsg struct{ items []ListItem }

func (a App) openDNSZoneForm() (App, tea.Cmd) {
	a.labels = []string{"Domain", "Primary NS", "Admin Email", "Default TTL"}
	a.inputs = make([]textinput.Model, 4)

	defaults := []string{"", "ns1.example.com", "admin.example.com", "3600"}
	for i := range a.inputs {
		ti := textinput.New()
		ti.CharLimit = 256
		ti.Width = 40
		ti.SetValue(defaults[i])
		if i == 0 {
			ti.Focus()
			ti.SetValue("")
		}
		a.inputs[i] = ti
	}
	a.focusIdx = 0
	a.pushView(ViewDNSZoneEdit)
	return a, nil
}

func (a App) submitDNSZone() (App, tea.Cmd) {
	domain := a.inputs[0].Value()
	ns := a.inputs[1].Value()
	admin := a.inputs[2].Value()
	ttl := a.inputs[3].Value()

	if domain == "" {
		return a, func() tea.Msg {
			return ResultMsg{Title: "Error", Lines: []string{"Domain cannot be empty."}, IsError: true}
		}
	}

	a.popView()

	return a, func() tea.Msg {
		body := fmt.Sprintf(`{"domain":"%s","soa":{"primary_ns":"%s","admin_email":"%s","ttl":%s}}`,
			domain, ns, admin, ttl)
		return dnsAPIPost("/api/zones", body)
	}
}

func (a App) viewDNSZoneRecords(zone string) (App, tea.Cmd) {
	return a, func() tea.Msg {
		data := dnsAPIGet("/api/zones/" + zone + "/records")
		if data == nil {
			return ResultMsg{Title: "Zone: " + zone, Lines: []string{"No records or API unreachable."}, IsError: true}
		}

		records, ok := data.([]interface{})
		if !ok {
			return ResultMsg{Title: "Zone: " + zone, Lines: []string{"Unexpected response format."}, IsError: true}
		}

		var lines []string
		lines = append(lines, fmt.Sprintf("Zone: %s — %d records", zone, len(records)))
		lines = append(lines, "")
		lines = append(lines, styleDim.Render(fmt.Sprintf("  %-8s %-30s %-6s %s", "TYPE", "NAME", "TTL", "VALUE")))
		lines = append(lines, styleDim.Render("  "+strings.Repeat("─", 70)))

		for _, r := range records {
			rec, ok := r.(map[string]interface{})
			if !ok {
				continue
			}
			lines = append(lines, fmt.Sprintf("  %-8v %-30v %-6v %v",
				rec["type"], rec["name"], rec["ttl"], rec["value"]))
		}

		return ResultMsg{Title: "Zone: " + zone, Lines: lines}
	}
}

func (a App) manageDNSHosts() (App, tea.Cmd) {
	return a, func() tea.Msg {
		data := dnsAPIGet("/api/hosts")
		if data == nil {
			return ResultMsg{Title: "DNS Hosts", Lines: []string{"API unreachable."}, IsError: true}
		}

		hosts, ok := data.([]interface{})
		if !ok {
			return ResultMsg{Title: "DNS Hosts", Lines: []string{"No hosts entries."}}
		}

		var lines []string
		lines = append(lines, fmt.Sprintf("%d host entries", len(hosts)))
		lines = append(lines, "")
		for _, h := range hosts {
			hMap, _ := h.(map[string]interface{})
			lines = append(lines, fmt.Sprintf("  %-16v  %v", hMap["ip"], hMap["hostname"]))
		}
		return ResultMsg{Title: "DNS Hosts", Lines: lines}
	}
}

func (a App) manageDNSBlocklist() (App, tea.Cmd) {
	return a, func() tea.Msg {
		data := dnsAPIGet("/api/blocklist")
		if data == nil {
			return ResultMsg{Title: "DNS Blocklist", Lines: []string{"API unreachable."}, IsError: true}
		}

		bl, ok := data.(map[string]interface{})
		if !ok {
			return ResultMsg{Title: "DNS Blocklist", Lines: []string{"Unexpected format."}}
		}

		var lines []string
		if domains, ok := bl["domains"].([]interface{}); ok {
			lines = append(lines, fmt.Sprintf("%d blocked domains", len(domains)))
			lines = append(lines, "")
			max := 30
			if len(domains) < max {
				max = len(domains)
			}
			for _, d := range domains[:max] {
				lines = append(lines, "  "+fmt.Sprintf("%v", d))
			}
			if len(domains) > 30 {
				lines = append(lines, styleDim.Render(fmt.Sprintf("  ... and %d more", len(domains)-30)))
			}
		} else {
			lines = append(lines, "Blocklist is empty.")
		}

		return ResultMsg{Title: "DNS Blocklist", Lines: lines}
	}
}

func (a App) manageDNSForwarding() (App, tea.Cmd) {
	return a, func() tea.Msg {
		data := dnsAPIGet("/api/forwarding")
		if data == nil {
			return ResultMsg{Title: "DNS Forwarding", Lines: []string{"API unreachable."}, IsError: true}
		}

		rules, ok := data.([]interface{})
		if !ok {
			return ResultMsg{Title: "DNS Forwarding", Lines: []string{"No forwarding rules configured."}}
		}

		var lines []string
		lines = append(lines, fmt.Sprintf("%d forwarding rules", len(rules)))
		lines = append(lines, "")
		for _, r := range rules {
			rMap, _ := r.(map[string]interface{})
			lines = append(lines, fmt.Sprintf("  %v → %v", rMap["zone"], rMap["upstream"]))
		}
		return ResultMsg{Title: "DNS Forwarding Rules", Lines: lines}
	}
}

func (a App) flushDNSCache() (App, tea.Cmd) {
	return a, func() tea.Msg {
		return dnsAPIDelete("/api/cache")
	}
}

func (a App) viewDNSQueryLog() (App, tea.Cmd) {
	return a, func() tea.Msg {
		data := dnsAPIGet("/api/querylog?limit=30")
		if data == nil {
			return ResultMsg{Title: "DNS Query Log", Lines: []string{"API unreachable."}, IsError: true}
		}

		entries, ok := data.([]interface{})
		if !ok {
			return ResultMsg{Title: "DNS Query Log", Lines: []string{"No entries."}}
		}

		var lines []string
		for _, e := range entries {
			eMap, _ := e.(map[string]interface{})
			lines = append(lines, fmt.Sprintf("  %-20v %-6v %-30v %v",
				eMap["time"], eMap["type"], eMap["name"], eMap["client"]))
		}
		return ResultMsg{Title: "DNS Query Log (last 30)", Lines: lines}
	}
}

func (a App) viewDNSTopDomains() (App, tea.Cmd) {
	return a, func() tea.Msg {
		data := dnsAPIGet("/api/stats/top-domains?limit=20")
		if data == nil {
			return ResultMsg{Title: "Top Domains", Lines: []string{"API unreachable."}, IsError: true}
		}

		domains, ok := data.([]interface{})
		if !ok {
			return ResultMsg{Title: "Top Domains", Lines: []string{"No data."}}
		}

		var lines []string
		for i, d := range domains {
			dMap, _ := d.(map[string]interface{})
			lines = append(lines, fmt.Sprintf("  %2d. %-40v %v queries", i+1, dMap["domain"], dMap["count"]))
		}
		return ResultMsg{Title: "Top 20 Queried Domains", Lines: lines}
	}
}

func (a App) viewDNSEncryption() (App, tea.Cmd) {
	return a, func() tea.Msg {
		data := dnsAPIGet("/api/encryption")
		if data == nil {
			return ResultMsg{Title: "DNS Encryption", Lines: []string{"API unreachable."}, IsError: true}
		}

		enc, _ := data.(map[string]interface{})
		var lines []string
		for k, v := range enc {
			status := styleStatusBad.Render("disabled")
			if v == true {
				status = styleStatusOK.Render("enabled")
			}
			lines = append(lines, fmt.Sprintf("  %-20s %s", k, status))
		}
		return ResultMsg{Title: "DNS Encryption Status", Lines: lines}
	}
}

func (a App) dnsRootCheck() (App, tea.Cmd) {
	return a, func() tea.Msg {
		body := dnsAPIPostRaw("/api/rootcheck", "")
		if body == nil {
			return ResultMsg{Title: "Root Check", Lines: []string{"API unreachable."}, IsError: true}
		}

		results, ok := body.([]interface{})
		if !ok {
			return ResultMsg{Title: "Root Check", Lines: []string{"Unexpected format."}}
		}

		var lines []string
		for _, r := range results {
			rMap, _ := r.(map[string]interface{})
			latency := fmt.Sprintf("%v", rMap["latency"])
			status := styleSuccess.Render("✔")
			if rMap["error"] != nil && rMap["error"] != "" {
				status = styleError.Render("✘")
				latency = fmt.Sprintf("%v", rMap["error"])
			}
			lines = append(lines, fmt.Sprintf("  %s %-20v %s", status, rMap["server"], latency))
		}
		return ResultMsg{Title: "Root Server Latency Check", Lines: lines}
	}
}

// ── DNS API Helpers ─────────────────────────────────────────────────

func getDNSAPIBase() string {
	return "http://127.0.0.1:5380"
}

func getDNSAPIToken() string {
	dir := findAutarchDir()
	configPath := dir + "/data/dns/config.json"
	data, err := readFileBytes(configPath)
	if err != nil {
		return ""
	}
	var cfg map[string]interface{}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return ""
	}
	if token, ok := cfg["api_token"].(string); ok {
		return token
	}
	return ""
}

func getDNSAPIStatus() map[string]interface{} {
	data := dnsAPIGet("/api/metrics")
	if data == nil {
		return nil
	}
	m, ok := data.(map[string]interface{})
	if !ok {
		return nil
	}
	return m
}

func dnsAPIGet(path string) interface{} {
	url := getDNSAPIBase() + path
	token := getDNSAPIToken()

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	var result interface{}
	json.NewDecoder(resp.Body).Decode(&result)
	return result
}

func dnsAPIPost(path, body string) tea.Msg {
	result := dnsAPIPostRaw(path, body)
	if result == nil {
		return ResultMsg{Title: "Error", Lines: []string{"API request failed."}, IsError: true}
	}
	return ResultMsg{Title: "Success", Lines: []string{"Operation completed."}}
}

func dnsAPIPostRaw(path, body string) interface{} {
	url := getDNSAPIBase() + path
	token := getDNSAPIToken()

	req, err := http.NewRequest("POST", url, strings.NewReader(body))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	var result interface{}
	json.NewDecoder(resp.Body).Decode(&result)
	return result
}

func dnsAPIDelete(path string) tea.Msg {
	url := getDNSAPIBase() + path
	token := getDNSAPIToken()

	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		return ResultMsg{Title: "Error", Lines: []string{err.Error()}, IsError: true}
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return ResultMsg{Title: "Error", Lines: []string{err.Error()}, IsError: true}
	}
	defer resp.Body.Close()

	return ResultMsg{Title: "Success", Lines: []string{"Deleted."}}
}

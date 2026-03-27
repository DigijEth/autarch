package tui

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// ── Module Categories ───────────────────────────────────────────────

var moduleCategories = map[string]string{
	"defender.py":         "Defense",
	"defender_monitor.py": "Defense",
	"defender_windows.py": "Defense",
	"container_sec.py":    "Defense",
	"msf.py":              "Offense",
	"exploit_dev.py":      "Offense",
	"loadtest.py":         "Offense",
	"phishmail.py":        "Offense",
	"deauth.py":           "Offense",
	"mitm_proxy.py":       "Offense",
	"c2_framework.py":     "Offense",
	"api_fuzzer.py":       "Offense",
	"webapp_scanner.py":   "Offense",
	"cloud_scan.py":       "Offense",
	"starlink_hack.py":    "Offense",
	"rcs_tools.py":        "Offense",
	"sms_forge.py":        "Offense",
	"pineapple.py":        "Offense",
	"password_toolkit.py": "Offense",
	"counter.py":          "Counter",
	"anti_forensics.py":   "Counter",
	"analyze.py":          "Analysis",
	"forensics.py":        "Analysis",
	"llm_trainer.py":      "Analysis",
	"report_engine.py":    "Analysis",
	"threat_intel.py":     "Analysis",
	"ble_scanner.py":      "Analysis",
	"rfid_tools.py":       "Analysis",
	"reverse_eng.py":      "Analysis",
	"steganography.py":    "Analysis",
	"incident_resp.py":    "Analysis",
	"net_mapper.py":       "Analysis",
	"log_correlator.py":   "Analysis",
	"malware_sandbox.py":  "Analysis",
	"email_sec.py":        "Analysis",
	"vulnerab_scanner.py": "Analysis",
	"recon.py":            "OSINT",
	"dossier.py":          "OSINT",
	"geoip.py":            "OSINT",
	"adultscan.py":        "OSINT",
	"yandex_osint.py":     "OSINT",
	"social_eng.py":       "OSINT",
	"ipcapture.py":        "OSINT",
	"snoop_decoder.py":    "OSINT",
	"simulate.py":         "Simulate",
	"android_apps.py":     "Android",
	"android_advanced.py": "Android",
	"android_boot.py":     "Android",
	"android_payload.py":  "Android",
	"android_protect.py":  "Android",
	"android_recon.py":    "Android",
	"android_root.py":     "Android",
	"android_screen.py":   "Android",
	"android_sms.py":      "Android",
	"hardware_local.py":   "Hardware",
	"hardware_remote.py":  "Hardware",
	"iphone_local.py":     "Hardware",
	"wireshark.py":        "Hardware",
	"sdr_tools.py":        "Hardware",
	"upnp_manager.py":     "System",
	"wireguard_manager.py": "System",
	"revshell.py":         "System",
	"hack_hijack.py":      "System",
	"chat.py":             "Core",
	"agent.py":            "Core",
	"agent_hal.py":        "Core",
	"mysystem.py":         "Core",
	"setup.py":            "Core",
	"workflow.py":         "Core",
	"nettest.py":          "Core",
	"rsf.py":              "Core",
	"ad_audit.py":         "Offense",
	"router_sploit.py":    "Offense",
	"wifi_audit.py":       "Offense",
}

// ── Rendering ───────────────────────────────────────────────────────

func (a App) renderModulesList() string {
	var b strings.Builder

	b.WriteString(styleTitle.Render("MODULES"))
	b.WriteString("\n")
	b.WriteString(a.renderHR())
	b.WriteString("\n")

	if len(a.listItems) == 0 {
		b.WriteString(styleDim.Render("  Loading..."))
		b.WriteString("\n")
		return b.String()
	}

	// Group by category
	groups := make(map[string][]int)
	for i, item := range a.listItems {
		groups[item.Extra] = append(groups[item.Extra], i)
	}

	// Sort category names
	var cats []string
	for c := range groups {
		cats = append(cats, c)
	}
	sort.Strings(cats)

	for _, cat := range cats {
		b.WriteString(styleKey.Render(fmt.Sprintf("  ── %s ", cat)))
		b.WriteString(styleDim.Render(fmt.Sprintf("(%d)", len(groups[cat]))))
		b.WriteString("\n")

		for _, idx := range groups[cat] {
			item := a.listItems[idx]

			cursor := "    "
			if idx == a.cursor {
				cursor = styleSelected.Render(" ▸") + "  "
			}

			status := styleStatusOK.Render("●")
			if !item.Enabled {
				status = styleStatusBad.Render("○")
			}

			name := item.Name
			if idx == a.cursor {
				name = lipgloss.NewStyle().Foreground(colorWhite).Bold(true).Render(name)
			}

			b.WriteString(fmt.Sprintf("%s%s %s\n", cursor, status, name))
		}
		b.WriteString("\n")
	}

	b.WriteString(a.renderHR())
	b.WriteString(styleKey.Render("  [enter]") + " Toggle enabled/disabled  ")
	b.WriteString(styleKey.Render("[r]") + " Refresh\n")
	b.WriteString(styleDim.Render("  esc back"))
	b.WriteString("\n")

	return b.String()
}

// ── Key Handling ────────────────────────────────────────────────────

func (a App) handleModulesMenu(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "enter":
		if a.cursor >= 0 && a.cursor < len(a.listItems) {
			return a.toggleModule(a.cursor)
		}
	case "r":
		return a, a.loadModules()
	}
	return a, nil
}

func (a App) handleModuleToggle(key string) (tea.Model, tea.Cmd) {
	return a.handleModulesMenu(key)
}

// ── Commands ────────────────────────────────────────────────────────

func (a App) loadModules() tea.Cmd {
	return func() tea.Msg {
		dir := findAutarchDir()
		modulesDir := filepath.Join(dir, "modules")

		entries, err := os.ReadDir(modulesDir)
		if err != nil {
			return ResultMsg{
				Title:   "Error",
				Lines:   []string{"Cannot read modules directory: " + err.Error()},
				IsError: true,
			}
		}

		var items []ListItem
		for _, e := range entries {
			name := e.Name()
			if !strings.HasSuffix(name, ".py") || name == "__init__.py" {
				continue
			}

			cat := "Other"
			if c, ok := moduleCategories[name]; ok {
				cat = c
			}

			// Check if module has a run() function (basic check)
			content, _ := os.ReadFile(filepath.Join(modulesDir, name))
			hasRun := strings.Contains(string(content), "def run(")

			items = append(items, ListItem{
				Name:    strings.TrimSuffix(name, ".py"),
				Enabled: hasRun,
				Extra:   cat,
				Status:  name,
			})
		}

		// Sort by category then name
		sort.Slice(items, func(i, j int) bool {
			if items[i].Extra != items[j].Extra {
				return items[i].Extra < items[j].Extra
			}
			return items[i].Name < items[j].Name
		})

		return modulesLoadedMsg{items: items}
	}
}

type modulesLoadedMsg struct{ items []ListItem }

func (a App) toggleModule(idx int) (App, tea.Cmd) {
	if idx < 0 || idx >= len(a.listItems) {
		return a, nil
	}

	item := a.listItems[idx]
	dir := findAutarchDir()
	modulesDir := filepath.Join(dir, "modules")
	disabledDir := filepath.Join(modulesDir, "disabled")

	srcFile := filepath.Join(modulesDir, item.Status)
	dstFile := filepath.Join(disabledDir, item.Status)

	if item.Enabled {
		// Disable: move to disabled/
		os.MkdirAll(disabledDir, 0755)
		if err := os.Rename(srcFile, dstFile); err != nil {
			return a, func() tea.Msg {
				return ResultMsg{
					Title:   "Error",
					Lines:   []string{"Cannot disable module: " + err.Error()},
					IsError: true,
				}
			}
		}
		a.listItems[idx].Enabled = false
	} else {
		// Enable: move from disabled/ back
		if err := os.Rename(dstFile, srcFile); err != nil {
			// It might just be a module without run()
			return a, func() tea.Msg {
				return ResultMsg{
					Title:   "Note",
					Lines:   []string{"Module " + item.Name + " is present but has no run() entry point."},
					IsError: false,
				}
			}
		}
		a.listItems[idx].Enabled = true
	}

	return a, nil
}

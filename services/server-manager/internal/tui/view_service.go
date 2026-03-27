package tui

import (
	"fmt"
	"os/exec"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// ── Service Definitions ─────────────────────────────────────────────

type serviceInfo struct {
	Name    string
	Unit    string // systemd unit name
	Desc    string
	Binary  string // path to check
}

var managedServices = []serviceInfo{
	{"AUTARCH Web", "autarch-web", "Web dashboard (Flask)", "autarch_web.py"},
	{"AUTARCH DNS", "autarch-dns", "DNS server (Go)", "autarch-dns"},
	{"AUTARCH Autonomy", "autarch-autonomy", "Autonomous AI daemon", ""},
}

// ── Rendering ───────────────────────────────────────────────────────

func (a App) renderServiceMenu() string {
	var b strings.Builder

	b.WriteString(styleTitle.Render("SERVICE MANAGEMENT"))
	b.WriteString("\n")
	b.WriteString(a.renderHR())
	b.WriteString("\n")

	// Show service statuses — checks both systemd and raw processes
	svcChecks := []struct {
		Info    serviceInfo
		Process string // process name to pgrep for
	}{
		{managedServices[0], "autarch_web.py"},
		{managedServices[1], "autarch-dns"},
		{managedServices[2], "autonomy"},
	}

	for _, sc := range svcChecks {
		status, running := getProcessStatus(sc.Info.Unit, sc.Process)

		indicator := styleStatusOK.Render("● running")
		if !running {
			indicator = styleStatusBad.Render("○ stopped")
		}

		b.WriteString(fmt.Sprintf("  %s  %s\n",
			indicator,
			lipgloss.NewStyle().Foreground(colorWhite).Bold(true).Render(sc.Info.Name),
		))
		b.WriteString(fmt.Sprintf("         %s  %s\n",
			styleDim.Render(sc.Info.Desc),
			styleDim.Render("("+status+")"),
		))
		b.WriteString("\n")
	}

	b.WriteString(a.renderHR())
	b.WriteString("\n")
	b.WriteString(styleKey.Render("  [1]") + " Start/Stop AUTARCH Web\n")
	b.WriteString(styleKey.Render("  [2]") + " Start/Stop AUTARCH DNS\n")
	b.WriteString(styleKey.Render("  [3]") + " Start/Stop Autonomy Daemon\n")
	b.WriteString("\n")
	b.WriteString(styleKey.Render("  [r]") + " Restart all running services\n")
	b.WriteString(styleKey.Render("  [e]") + " Enable all services on boot\n")
	b.WriteString(styleKey.Render("  [i]") + " Install/update systemd unit files\n")
	b.WriteString(styleKey.Render("  [l]") + " View service logs (journalctl)\n")
	b.WriteString("\n")
	b.WriteString(styleDim.Render("  esc back"))
	b.WriteString("\n")

	return b.String()
}

// ── Key Handling ────────────────────────────────────────────────────

func (a App) handleServiceMenu(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "1":
		return a.toggleService(0)
	case "2":
		return a.toggleService(1)
	case "3":
		return a.toggleService(2)
	case "r":
		return a.restartAllServices()
	case "e":
		return a.enableAllServices()
	case "i":
		return a.installServiceUnits()
	case "l":
		return a.viewServiceLogs()
	}
	return a, nil
}

// ── Commands ────────────────────────────────────────────────────────

func (a App) loadServiceStatus() tea.Cmd {
	return nil // Services are checked live in render
}

func getServiceStatus(unit string) (string, bool) {
	out, err := exec.Command("systemctl", "is-active", unit).Output()
	status := strings.TrimSpace(string(out))
	if err != nil || status != "active" {
		// Check if unit exists
		_, existErr := exec.Command("systemctl", "cat", unit).Output()
		if existErr != nil {
			return "not installed", false
		}
		return status, false
	}
	return status, true
}

// getProcessStatus checks both systemd and direct process for a service.
// Returns (status description, isRunning).
func getProcessStatus(unitName, processName string) (string, bool) {
	// First try systemd
	status, running := getServiceStatus(unitName)
	if running {
		return "systemd: " + status, true
	}

	// Fall back to process detection (pgrep)
	out, err := exec.Command("pgrep", "-f", processName).Output()
	if err == nil && strings.TrimSpace(string(out)) != "" {
		pids := strings.Fields(strings.TrimSpace(string(out)))
		return fmt.Sprintf("running (PID %s)", pids[0]), true
	}

	return status, false
}

func (a App) toggleService(idx int) (App, tea.Cmd) {
	if idx < 0 || idx >= len(managedServices) {
		return a, nil
	}

	svc := managedServices[idx]
	processNames := []string{"autarch_web.py", "autarch-dns", "autonomy"}
	procName := processNames[idx]

	_, sysRunning := getServiceStatus(svc.Unit)
	_, procRunning := getProcessStatus(svc.Unit, procName)
	isRunning := sysRunning || procRunning

	return a, func() tea.Msg {
		dir := findAutarchDir()

		if isRunning {
			// Stop — try systemd first, then kill process
			if sysRunning {
				cmd := exec.Command("systemctl", "stop", svc.Unit)
				cmd.CombinedOutput()
			}
			// Also kill any direct processes
			exec.Command("pkill", "-f", procName).Run()
			return ResultMsg{
				Title: "Service " + svc.Name,
				Lines: []string{svc.Name + " stopped."},
			}
		}

		// Start — try systemd first, fall back to direct launch
		if _, err := exec.Command("systemctl", "cat", svc.Unit).Output(); err == nil {
			cmd := exec.Command("systemctl", "start", svc.Unit)
			out, err := cmd.CombinedOutput()
			if err != nil {
				return ResultMsg{
					Title:   "Service Error",
					Lines:   []string{"systemctl start failed:", string(out), err.Error(), "", "Trying direct launch..."},
					IsError: true,
				}
			}
			return ResultMsg{
				Title: "Service " + svc.Name,
				Lines: []string{svc.Name + " started via systemd."},
			}
		}

		// Direct launch (no systemd unit installed)
		var startCmd *exec.Cmd
		switch idx {
		case 0: // Web
			venvPy := dir + "/venv/bin/python3"
			startCmd = exec.Command(venvPy, dir+"/autarch_web.py")
		case 1: // DNS
			binary := dir + "/services/dns-server/autarch-dns"
			configFile := dir + "/data/dns/config.json"
			startCmd = exec.Command(binary, "--config", configFile)
		case 2: // Autonomy
			venvPy := dir + "/venv/bin/python3"
			startCmd = exec.Command(venvPy, "-c",
				"import sys; sys.path.insert(0,'"+dir+"'); from core.autonomy import AutonomyDaemon; AutonomyDaemon().run()")
		}

		if startCmd != nil {
			startCmd.Dir = dir
			// Detach process so it survives manager exit
			startCmd.Stdout = nil
			startCmd.Stderr = nil
			if err := startCmd.Start(); err != nil {
				return ResultMsg{
					Title:   "Service Error",
					Lines:   []string{"Failed to start " + svc.Name + ":", err.Error()},
					IsError: true,
				}
			}
			// Release so it runs independently
			go startCmd.Wait()

			return ResultMsg{
				Title: "Service " + svc.Name,
				Lines: []string{
					svc.Name + " started directly (PID " + fmt.Sprintf("%d", startCmd.Process.Pid) + ").",
					"",
					styleDim.Render("Tip: Install systemd units with [i] for persistent service management."),
				},
			}
		}

		return ResultMsg{
			Title:   "Error",
			Lines:   []string{"No start method available for " + svc.Name},
			IsError: true,
		}
	}
}

func (a App) restartAllServices() (App, tea.Cmd) {
	return a, func() tea.Msg {
		var lines []string
		for _, svc := range managedServices {
			_, running := getServiceStatus(svc.Unit)
			if running {
				cmd := exec.Command("systemctl", "restart", svc.Unit)
				out, err := cmd.CombinedOutput()
				if err != nil {
					lines = append(lines, styleError.Render("✘ "+svc.Name+": "+strings.TrimSpace(string(out))))
				} else {
					lines = append(lines, styleSuccess.Render("✔ "+svc.Name+": restarted"))
				}
			} else {
				lines = append(lines, styleDim.Render("- "+svc.Name+": not running, skipped"))
			}
		}
		return ResultMsg{Title: "Restart Services", Lines: lines}
	}
}

func (a App) enableAllServices() (App, tea.Cmd) {
	return a, func() tea.Msg {
		var lines []string
		for _, svc := range managedServices {
			cmd := exec.Command("systemctl", "enable", svc.Unit)
			_, err := cmd.CombinedOutput()
			if err != nil {
				lines = append(lines, styleWarning.Render("⚠ "+svc.Name+": could not enable (unit may not exist)"))
			} else {
				lines = append(lines, styleSuccess.Render("✔ "+svc.Name+": enabled on boot"))
			}
		}
		return ResultMsg{Title: "Enable Services", Lines: lines}
	}
}

func (a App) installServiceUnits() (App, tea.Cmd) {
	return a, func() tea.Msg {
		dir := findAutarchDir()
		var lines []string

		// Web service unit
		webUnit := fmt.Sprintf(`[Unit]
Description=AUTARCH Web Dashboard
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=%s
ExecStart=%s/venv/bin/python3 %s/autarch_web.py
Restart=on-failure
RestartSec=5
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
`, dir, dir, dir)

		// DNS service unit
		dnsUnit := fmt.Sprintf(`[Unit]
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

		// Autonomy daemon unit
		autoUnit := fmt.Sprintf(`[Unit]
Description=AUTARCH Autonomy Daemon
After=network.target autarch-web.service

[Service]
Type=simple
User=root
WorkingDirectory=%s
ExecStart=%s/venv/bin/python3 -c "from core.autonomy import AutonomyDaemon; AutonomyDaemon().run()"
Restart=on-failure
RestartSec=10
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
`, dir, dir)

		units := map[string]string{
			"autarch-web.service":      webUnit,
			"autarch-dns.service":      dnsUnit,
			"autarch-autonomy.service": autoUnit,
		}

		for name, content := range units {
			path := "/etc/systemd/system/" + name
			if err := writeFileAtomic(path, []byte(content)); err != nil {
				lines = append(lines, styleError.Render("✘ "+name+": "+err.Error()))
			} else {
				lines = append(lines, styleSuccess.Render("✔ "+name+": installed"))
			}
		}

		// Reload systemd
		exec.Command("systemctl", "daemon-reload").Run()
		lines = append(lines, "", styleSuccess.Render("✔ systemctl daemon-reload"))

		return ResultMsg{Title: "Service Units Installed", Lines: lines}
	}
}

func (a App) viewServiceLogs() (App, tea.Cmd) {
	return a, func() tea.Msg {
		var lines []string
		for _, svc := range managedServices {
			out, _ := exec.Command("journalctl", "-u", svc.Unit, "-n", "10", "--no-pager").Output()
			lines = append(lines, styleKey.Render("── "+svc.Name+" ──"))
			logLines := strings.Split(strings.TrimSpace(string(out)), "\n")
			for _, l := range logLines {
				lines = append(lines, "  "+l)
			}
			lines = append(lines, "")
		}
		return ResultMsg{Title: "Service Logs (last 10 entries)", Lines: lines}
	}
}

func writeFileAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := writeFile(tmp, data, 0644); err != nil {
		return err
	}
	return renameFile(tmp, path)
}

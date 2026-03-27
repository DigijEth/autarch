package tui

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

const (
	autarchGitRepo = "https://github.com/DigijEth/autarch.git"
	autarchBranch  = "main"
	defaultInstDir = "/opt/autarch"
)

// ── Rendering ───────────────────────────────────────────────────────

func (a App) renderDeployMenu() string {
	var b strings.Builder

	b.WriteString(styleTitle.Render("DEPLOY AUTARCH"))
	b.WriteString("\n")
	b.WriteString(a.renderHR())
	b.WriteString("\n")

	installDir := defaultInstDir
	if a.autarchDir != "" && a.autarchDir != defaultInstDir {
		installDir = a.autarchDir
	}

	// Check current state
	confExists := fileExists(filepath.Join(installDir, "autarch_settings.conf"))
	gitExists := fileExists(filepath.Join(installDir, ".git"))
	venvExists := fileExists(filepath.Join(installDir, "venv", "bin", "python3"))

	b.WriteString(styleKey.Render("  Install directory: ") +
		lipgloss.NewStyle().Foreground(colorWhite).Bold(true).Render(installDir))
	b.WriteString("\n")
	b.WriteString(styleKey.Render("  Git repository:    ") +
		styleDim.Render(autarchGitRepo))
	b.WriteString("\n\n")

	// Status checks
	if gitExists {
		// Get current commit
		out, _ := exec.Command("git", "-C", installDir, "log", "--oneline", "-1").Output()
		commit := strings.TrimSpace(string(out))
		b.WriteString("  " + styleStatusOK.Render("✔ Git repo present") + "  " + styleDim.Render(commit))
	} else {
		b.WriteString("  " + styleStatusBad.Render("✘ Not cloned"))
	}
	b.WriteString("\n")

	if confExists {
		b.WriteString("  " + styleStatusOK.Render("✔ Config file present"))
	} else {
		b.WriteString("  " + styleStatusBad.Render("✘ No config file"))
	}
	b.WriteString("\n")

	if venvExists {
		// Count pip packages
		out, _ := exec.Command(filepath.Join(installDir, "venv", "bin", "pip3"), "list", "--format=columns").Output()
		count := strings.Count(string(out), "\n") - 2
		if count < 0 {
			count = 0
		}
		b.WriteString("  " + styleStatusOK.Render(fmt.Sprintf("✔ Python venv (%d packages)", count)))
	} else {
		b.WriteString("  " + styleStatusBad.Render("✘ No Python venv"))
	}
	b.WriteString("\n")

	// Check node_modules
	nodeExists := fileExists(filepath.Join(installDir, "node_modules"))
	if nodeExists {
		b.WriteString("  " + styleStatusOK.Render("✔ Node modules installed"))
	} else {
		b.WriteString("  " + styleStatusBad.Render("✘ No node_modules"))
	}
	b.WriteString("\n")

	// Check services
	_, webUp := getProcessStatus("autarch-web", "autarch_web.py")
	_, dnsUp := getProcessStatus("autarch-dns", "autarch-dns")
	if webUp {
		b.WriteString("  " + styleStatusOK.Render("✔ Web service running"))
	} else {
		b.WriteString("  " + styleStatusBad.Render("○ Web service stopped"))
	}
	b.WriteString("\n")
	if dnsUp {
		b.WriteString("  " + styleStatusOK.Render("✔ DNS service running"))
	} else {
		b.WriteString("  " + styleStatusBad.Render("○ DNS service stopped"))
	}
	b.WriteString("\n\n")

	b.WriteString(a.renderHR())
	b.WriteString("\n")

	if !gitExists {
		b.WriteString(styleKey.Render("  [c]") + " Clone AUTARCH from GitHub " + styleDim.Render("(full install)") + "\n")
	} else {
		b.WriteString(styleKey.Render("  [u]") + " Update (git pull + reinstall deps)\n")
	}
	b.WriteString(styleKey.Render("  [f]") + " Full setup " + styleDim.Render("(clone/pull + venv + pip + npm + build + systemd + permissions)") + "\n")
	b.WriteString(styleKey.Render("  [v]") + " Setup venv + pip install only\n")
	b.WriteString(styleKey.Render("  [n]") + " Setup npm + build hardware JS only\n")
	b.WriteString(styleKey.Render("  [p]") + " Fix permissions " + styleDim.Render("(chown/chmod)") + "\n")
	b.WriteString(styleKey.Render("  [s]") + " Install systemd service units\n")
	b.WriteString(styleKey.Render("  [d]") + " Build DNS server from source\n")
	b.WriteString(styleKey.Render("  [g]") + " Generate self-signed TLS cert\n")
	b.WriteString("\n")
	b.WriteString(styleDim.Render("  esc back"))
	b.WriteString("\n")

	return b.String()
}

// ── Key Handling ────────────────────────────────────────────────────

func (a App) handleDeployMenu(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "c":
		return a.deployClone()
	case "u":
		return a.deployUpdate()
	case "f":
		return a.deployFull()
	case "v":
		return a.deployVenv()
	case "n":
		return a.deployNpm()
	case "p":
		return a.deployPermissions()
	case "s":
		return a.deploySystemd()
	case "d":
		return a.deployDNSBuild()
	case "g":
		return a.deployTLSCert()
	}
	return a, nil
}

// ── Deploy Commands ─────────────────────────────────────────────────

func (a App) deployClone() (App, tea.Cmd) {
	dir := defaultInstDir

	// Quick check — if already cloned, show result without streaming
	if fileExists(filepath.Join(dir, ".git")) {
		return a, func() tea.Msg {
			return ResultMsg{
				Title:   "Already Cloned",
				Lines:   []string{"AUTARCH is already cloned at " + dir, "", "Use [u] to update or [f] for full setup."},
				IsError: false,
			}
		}
	}

	a.pushView(ViewDepsInstall)
	a.outputLines = nil
	a.outputDone = false
	a.progressStep = 0
	a.progressTotal = 0

	ch := make(chan tea.Msg, 256)
	a.outputCh = ch

	go func() {
		os.MkdirAll(filepath.Dir(dir), 0755)
		steps := []CmdStep{
			{Label: "Clone AUTARCH from GitHub", Args: []string{"git", "clone", "--branch", autarchBranch, "--progress", autarchGitRepo, dir}},
		}
		streamSteps(ch, steps)
	}()

	return a, a.waitForOutput()
}

func (a App) deployUpdate() (App, tea.Cmd) {
	return a, func() tea.Msg {
		dir := defaultInstDir
		if a.autarchDir != "" {
			dir = a.autarchDir
		}
		var lines []string

		// Git pull
		lines = append(lines, styleKey.Render("$ git -C "+dir+" pull"))
		cmd := exec.Command("git", "-C", dir, "pull", "--ff-only")
		out, err := cmd.CombinedOutput()
		for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			lines = append(lines, "  "+l)
		}
		if err != nil {
			lines = append(lines, styleError.Render("  ✘ Pull failed: "+err.Error()))
			return ResultMsg{Title: "Update Failed", Lines: lines, IsError: true}
		}
		lines = append(lines, styleSuccess.Render("  ✔ Updated"))

		return ResultMsg{Title: "AUTARCH Updated", Lines: lines}
	}
}

func (a App) deployFull() (App, tea.Cmd) {
	a.pushView(ViewDepsInstall)
	a.outputLines = nil
	a.outputDone = false
	a.progressStep = 0
	a.progressTotal = 0

	ch := make(chan tea.Msg, 256)
	a.outputCh = ch

	go func() {
		dir := defaultInstDir

		var steps []CmdStep

		// Step 1: Clone or pull
		if !fileExists(filepath.Join(dir, ".git")) {
			os.MkdirAll(filepath.Dir(dir), 0755)
			steps = append(steps, CmdStep{
				Label: "Clone AUTARCH from GitHub",
				Args:  []string{"git", "clone", "--branch", autarchBranch, "--progress", autarchGitRepo, dir},
			})
		} else {
			steps = append(steps, CmdStep{
				Label: "Update from GitHub",
				Args:  []string{"git", "-C", dir, "pull", "--ff-only"},
			})
		}

		// Step 2: System deps
		steps = append(steps, CmdStep{
			Label: "Update package lists",
			Args:  []string{"apt-get", "update", "-qq"},
		})
		aptPkgs := []string{
			"python3", "python3-pip", "python3-venv", "python3-dev",
			"build-essential", "cmake", "pkg-config",
			"git", "curl", "wget", "openssl",
			"libffi-dev", "libssl-dev", "libpcap-dev", "libxml2-dev", "libxslt1-dev",
			"nmap", "tshark", "whois", "dnsutils",
			"adb", "fastboot",
			"wireguard-tools", "miniupnpc", "net-tools",
			"nodejs", "npm", "ffmpeg",
		}
		steps = append(steps, CmdStep{
			Label: "Install system dependencies",
			Args:  append([]string{"apt-get", "install", "-y"}, aptPkgs...),
		})

		// Step 3: System user
		steps = append(steps, CmdStep{
			Label: "Create autarch system user",
			Args:  []string{"useradd", "--system", "--no-create-home", "--shell", "/usr/sbin/nologin", "autarch"},
		})

		// Step 4-5: Python venv + pip
		venv := filepath.Join(dir, "venv")
		pip := filepath.Join(venv, "bin", "pip3")
		steps = append(steps,
			CmdStep{Label: "Create Python virtual environment", Args: []string{"python3", "-m", "venv", venv}},
			CmdStep{Label: "Upgrade pip, setuptools, wheel", Args: []string{pip, "install", "--upgrade", "pip", "setuptools", "wheel"}},
			CmdStep{Label: "Install Python packages", Args: []string{pip, "install", "-r", filepath.Join(dir, "requirements.txt")}},
		)

		// Step 6: npm
		steps = append(steps,
			CmdStep{Label: "Install npm packages", Args: []string{"npm", "install"}, Dir: dir},
		)
		if fileExists(filepath.Join(dir, "scripts", "build-hw-libs.sh")) {
			steps = append(steps, CmdStep{
				Label: "Build hardware JS bundles",
				Args:  []string{"bash", "scripts/build-hw-libs.sh"},
				Dir:   dir,
			})
		}

		// Step 7: Permissions
		steps = append(steps,
			CmdStep{Label: "Set ownership", Args: []string{"chown", "-R", "root:root", dir}},
			CmdStep{Label: "Set permissions", Args: []string{"chmod", "-R", "755", dir}},
		)

		// Step 8: Data directories (quick inline, not a CmdStep)
		dataDirs := []string{"data", "data/certs", "data/dns", "results", "dossiers", "models"}
		for _, d := range dataDirs {
			os.MkdirAll(filepath.Join(dir, d), 0755)
		}

		// Step 9: Sensitive file permissions
		steps = append(steps,
			CmdStep{Label: "Secure config file", Args: []string{"chmod", "600", filepath.Join(dir, "autarch_settings.conf")}},
		)

		// Step 10: TLS cert
		certDir := filepath.Join(dir, "data", "certs")
		certPath := filepath.Join(certDir, "autarch.crt")
		keyPath := filepath.Join(certDir, "autarch.key")
		if !fileExists(certPath) || !fileExists(keyPath) {
			steps = append(steps, CmdStep{
				Label: "Generate self-signed TLS certificate",
				Args: []string{"openssl", "req", "-x509", "-newkey", "rsa:2048",
					"-keyout", keyPath, "-out", certPath,
					"-days", "3650", "-nodes",
					"-subj", "/CN=AUTARCH/O=darkHal"},
			})
		}

		// Step 11: Systemd units — write files inline then reload
		writeSystemdUnits(dir)
		steps = append(steps, CmdStep{
			Label: "Reload systemd daemon",
			Args:  []string{"systemctl", "daemon-reload"},
		})

		streamSteps(ch, steps)
	}()

	return a, a.waitForOutput()
}

func (a App) deployVenv() (App, tea.Cmd) {
	a.pushView(ViewDepsInstall)
	a.outputLines = nil
	a.outputDone = false
	a.progressStep = 0
	a.progressTotal = 0

	ch := make(chan tea.Msg, 256)
	a.outputCh = ch

	dir := resolveDir(a.autarchDir)
	go func() {
		streamSteps(ch, buildVenvSteps(dir))
	}()

	return a, a.waitForOutput()
}

func (a App) deployNpm() (App, tea.Cmd) {
	a.pushView(ViewDepsInstall)
	a.outputLines = nil
	a.outputDone = false
	a.progressStep = 0
	a.progressTotal = 0

	ch := make(chan tea.Msg, 256)
	a.outputCh = ch

	dir := resolveDir(a.autarchDir)
	go func() {
		streamSteps(ch, buildNpmSteps(dir))
	}()

	return a, a.waitForOutput()
}

func (a App) deployPermissions() (App, tea.Cmd) {
	return a, func() tea.Msg {
		dir := resolveDir(a.autarchDir)
		var lines []string

		exec.Command("chown", "-R", "root:root", dir).Run()
		lines = append(lines, styleSuccess.Render("✔ chown -R root:root "+dir))

		exec.Command("chmod", "-R", "755", dir).Run()
		lines = append(lines, styleSuccess.Render("✔ chmod -R 755 "+dir))

		// Sensitive files
		confPath := filepath.Join(dir, "autarch_settings.conf")
		if fileExists(confPath) {
			exec.Command("chmod", "600", confPath).Run()
			lines = append(lines, styleSuccess.Render("✔ chmod 600 autarch_settings.conf"))
		}

		credPath := filepath.Join(dir, "data", "web_credentials.json")
		if fileExists(credPath) {
			exec.Command("chmod", "600", credPath).Run()
			lines = append(lines, styleSuccess.Render("✔ chmod 600 web_credentials.json"))
		}

		// Ensure data dirs exist
		for _, d := range []string{"data", "data/certs", "data/dns", "results", "dossiers", "models"} {
			os.MkdirAll(filepath.Join(dir, d), 0755)
		}
		lines = append(lines, styleSuccess.Render("✔ Data directories created"))

		return ResultMsg{Title: "Permissions Fixed", Lines: lines}
	}
}

func (a App) deploySystemd() (App, tea.Cmd) {
	// Reuse the existing installServiceUnits
	return a.installServiceUnits()
}

func (a App) deployDNSBuild() (App, tea.Cmd) {
	return a.buildDNSServer()
}

func (a App) deployTLSCert() (App, tea.Cmd) {
	return a, func() tea.Msg {
		dir := resolveDir(a.autarchDir)
		certDir := filepath.Join(dir, "data", "certs")
		os.MkdirAll(certDir, 0755)

		certPath := filepath.Join(certDir, "autarch.crt")
		keyPath := filepath.Join(certDir, "autarch.key")

		cmd := exec.Command("openssl", "req", "-x509", "-newkey", "rsa:2048",
			"-keyout", keyPath, "-out", certPath,
			"-days", "3650", "-nodes",
			"-subj", "/CN=AUTARCH/O=darkHal Security Group")
		out, err := cmd.CombinedOutput()
		if err != nil {
			return ResultMsg{
				Title:   "Error",
				Lines:   []string{string(out), err.Error()},
				IsError: true,
			}
		}

		return ResultMsg{
			Title: "TLS Certificate Generated",
			Lines: []string{
				styleSuccess.Render("✔ Certificate: ") + certPath,
				styleSuccess.Render("✔ Private key: ") + keyPath,
				"",
				styleDim.Render("Valid for 10 years. Self-signed."),
				styleDim.Render("For production, use Let's Encrypt via Setec Manager."),
			},
		}
	}
}

// ── Helpers ─────────────────────────────────────────────────────────

func resolveDir(autarchDir string) string {
	if autarchDir != "" {
		return autarchDir
	}
	return defaultInstDir
}

func writeSystemdUnits(dir string) {
	units := map[string]string{
		"autarch-web.service": fmt.Sprintf(`[Unit]
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
`, dir, dir, dir),
		"autarch-dns.service": fmt.Sprintf(`[Unit]
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
`, dir, dir, dir),
	}
	for name, content := range units {
		path := "/etc/systemd/system/" + name
		os.WriteFile(path, []byte(content), 0644)
	}
}

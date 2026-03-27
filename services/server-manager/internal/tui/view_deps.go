package tui

import (
	"fmt"
	"os/exec"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

// ── Dependency Categories ───────────────────────────────────────────

type depCheck struct {
	Name string
	Cmd  string // command to check existence
	Pkg  string // apt package name
	Kind string // "system", "python", "npm"
	Desc string
}

var systemDeps = []depCheck{
	// Core runtime
	{"python3", "python3", "python3", "system", "Python 3.10+ interpreter"},
	{"pip", "pip3", "python3-pip", "system", "Python package manager"},
	{"python3-venv", "python3 -m venv --help", "python3-venv", "system", "Python virtual environments"},
	{"python3-dev", "python3-config --includes", "python3-dev", "system", "Python C headers (for native extensions)"},

	// Build tools
	{"gcc", "gcc", "build-essential", "system", "C/C++ compiler toolchain"},
	{"cmake", "cmake", "cmake", "system", "CMake build system (for llama-cpp)"},
	{"pkg-config", "pkg-config", "pkg-config", "system", "Package config helper"},

	// Core system utilities
	{"git", "git", "git", "system", "Version control"},
	{"curl", "curl", "curl", "system", "HTTP client"},
	{"wget", "wget", "wget", "system", "File downloader"},
	{"openssl", "openssl", "openssl", "system", "TLS/crypto toolkit"},

	// C libraries for Python packages
	{"libffi-dev", "pkg-config --exists libffi", "libffi-dev", "system", "FFI library (for cffi/cryptography)"},
	{"libssl-dev", "pkg-config --exists openssl", "libssl-dev", "system", "OpenSSL headers (for cryptography)"},
	{"libpcap-dev", "pkg-config --exists libpcap", "libpcap-dev", "system", "Packet capture headers (for scapy)"},
	{"libxml2-dev", "pkg-config --exists libxml-2.0", "libxml2-dev", "system", "XML parser headers (for lxml)"},
	{"libxslt1-dev", "pkg-config --exists libxslt", "libxslt1-dev", "system", "XSLT headers (for lxml)"},

	// Security tools
	{"nmap", "nmap", "nmap", "system", "Network scanner"},
	{"tshark", "tshark", "tshark", "system", "Packet analysis (Wireshark CLI)"},
	{"whois", "whois", "whois", "system", "WHOIS lookup"},
	{"dnsutils", "dig", "dnsutils", "system", "DNS utilities (dig, nslookup)"},

	// Android tools
	{"adb", "adb", "adb", "system", "Android Debug Bridge"},
	{"fastboot", "fastboot", "fastboot", "system", "Android Fastboot"},

	// Network tools
	{"wg", "wg", "wireguard-tools", "system", "WireGuard VPN tools"},
	{"upnpc", "upnpc", "miniupnpc", "system", "UPnP port mapping client"},
	{"net-tools", "ifconfig", "net-tools", "system", "Network utilities (ifconfig)"},

	// Node.js
	{"node", "node", "nodejs", "system", "Node.js (for hardware WebUSB libs)"},
	{"npm", "npm", "npm", "system", "Node package manager"},

	// Go
	{"go", "go", "golang", "system", "Go compiler (for DNS server build)"},

	// Media / misc
	{"ffmpeg", "ffmpeg", "ffmpeg", "system", "Media processing"},
}

// ── Rendering ───────────────────────────────────────────────────────

func (a App) renderDepsMenu() string {
	var b strings.Builder

	b.WriteString(styleTitle.Render("DEPENDENCIES"))
	b.WriteString("\n")
	b.WriteString(a.renderHR())
	b.WriteString("\n")

	if len(a.listItems) == 0 {
		b.WriteString(styleDim.Render("  Loading..."))
		b.WriteString("\n")
		return b.String()
	}

	// Count installed vs total
	installed, total := 0, 0
	for _, item := range a.listItems {
		if item.Extra == "system" {
			total++
			if item.Enabled {
				installed++
			}
		}
	}

	// System packages
	b.WriteString(styleKey.Render(fmt.Sprintf("  System Packages (%d/%d installed)", installed, total)))
	b.WriteString("\n\n")

	for _, item := range a.listItems {
		if item.Extra != "system" {
			continue
		}
		status := styleStatusOK.Render("✔ installed")
		if !item.Enabled {
			status = styleStatusBad.Render("✘ missing  ")
		}
		b.WriteString(fmt.Sprintf("    %s  %-14s %s\n", status, item.Name, styleDim.Render(item.Status)))
	}

	// Python venv
	b.WriteString("\n")
	b.WriteString(styleKey.Render("  Python Virtual Environment"))
	b.WriteString("\n\n")
	for _, item := range a.listItems {
		if item.Extra != "venv" {
			continue
		}
		status := styleStatusOK.Render("✔ ready ")
		if !item.Enabled {
			status = styleStatusBad.Render("✘ missing")
		}
		b.WriteString(fmt.Sprintf("    %s  %s\n", status, item.Name))
	}

	// Actions
	b.WriteString("\n")
	b.WriteString(a.renderHR())
	b.WriteString("\n")
	b.WriteString(styleKey.Render("  [a]") + " Install all missing system packages\n")
	b.WriteString(styleKey.Render("  [v]") + " Create/recreate Python venv + install pip packages\n")
	b.WriteString(styleKey.Render("  [n]") + " Install npm packages + build hardware JS bundles\n")
	b.WriteString(styleKey.Render("  [f]") + " Full install (system + venv + pip + npm)\n")
	b.WriteString(styleKey.Render("  [g]") + " Install Go compiler (for DNS server)\n")
	b.WriteString(styleKey.Render("  [r]") + " Refresh status\n")
	b.WriteString("\n")
	b.WriteString(styleDim.Render("  esc back"))
	b.WriteString("\n")

	return b.String()
}

// ── Key Handling ────────────────────────────────────────────────────

func (a App) handleDepsMenu(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "a":
		return a.startDepsInstall("system")
	case "v":
		return a.startDepsInstall("venv")
	case "n":
		return a.startDepsInstall("npm")
	case "f":
		return a.startDepsInstall("full")
	case "g":
		return a.startDepsInstall("go")
	case "r":
		return a, a.loadDepsStatus()
	}
	return a, nil
}

// ── Commands ────────────────────────────────────────────────────────

func (a App) loadDepsStatus() tea.Cmd {
	return func() tea.Msg {
		var items []ListItem

		// Check system deps
		for _, d := range systemDeps {
			installed := false
			parts := strings.Fields(d.Cmd)
			if len(parts) == 1 {
				_, err := exec.LookPath(d.Cmd)
				installed = err == nil
			} else {
				cmd := exec.Command(parts[0], parts[1:]...)
				installed = cmd.Run() == nil
			}
			items = append(items, ListItem{
				Name:    d.Name,
				Status:  d.Desc,
				Enabled: installed,
				Extra:   "system",
			})
		}

		// Check venv
		venvPath := fmt.Sprintf("%s/venv", findAutarchDir())
		_, err := exec.LookPath(venvPath + "/bin/python3")
		items = append(items, ListItem{
			Name:    "venv (" + venvPath + ")",
			Enabled: err == nil,
			Extra:   "venv",
		})

		// Check pip packages in venv
		venvPip := venvPath + "/bin/pip3"
		if _, err := exec.LookPath(venvPip); err == nil {
			out, _ := exec.Command(venvPip, "list", "--format=columns").Output()
			count := strings.Count(string(out), "\n") - 2
			if count < 0 {
				count = 0
			}
			items = append(items, ListItem{
				Name:    fmt.Sprintf("pip packages (%d installed)", count),
				Enabled: count > 5,
				Extra:   "venv",
			})
		} else {
			items = append(items, ListItem{
				Name:    "pip packages (venv not found)",
				Enabled: false,
				Extra:   "venv",
			})
		}

		return depsLoadedMsg{items: items}
	}
}

type depsLoadedMsg struct{ items []ListItem }

func (a App) startDepsInstall(mode string) (App, tea.Cmd) {
	a.pushView(ViewDepsInstall)
	a.outputLines = nil
	a.outputDone = false
	a.progressStep = 0
	a.progressTotal = 0
	a.progressLabel = ""

	ch := make(chan tea.Msg, 256)
	a.outputCh = ch

	autarchDir := findAutarchDir()

	go func() {
		var steps []CmdStep

		switch mode {
		case "system":
			steps = buildSystemInstallSteps()

		case "venv":
			steps = buildVenvSteps(autarchDir)

		case "npm":
			steps = buildNpmSteps(autarchDir)

		case "go":
			steps = []CmdStep{
				{Label: "Update package lists", Args: []string{"apt-get", "update", "-qq"}},
				{Label: "Install Go compiler", Args: []string{"apt-get", "install", "-y", "golang"}},
			}

		case "full":
			steps = buildSystemInstallSteps()
			steps = append(steps, buildVenvSteps(autarchDir)...)
			steps = append(steps, buildNpmSteps(autarchDir)...)
		}

		if len(steps) == 0 {
			ch <- OutputLineMsg(styleSuccess.Render("Nothing to install — all dependencies are present."))
			close(ch)
			return
		}

		streamSteps(ch, steps)
	}()

	return a, a.waitForOutput()
}

// ── Step Builders ───────────────────────────────────────────────────

func buildSystemInstallSteps() []CmdStep {
	// Collect missing packages
	var pkgs []string
	for _, d := range systemDeps {
		parts := strings.Fields(d.Cmd)
		if len(parts) == 1 {
			if _, err := exec.LookPath(d.Cmd); err != nil {
				pkgs = append(pkgs, d.Pkg)
			}
		} else {
			cmd := exec.Command(parts[0], parts[1:]...)
			if cmd.Run() != nil {
				pkgs = append(pkgs, d.Pkg)
			}
		}
	}

	// Deduplicate packages (some deps share packages like build-essential)
	seen := make(map[string]bool)
	var uniquePkgs []string
	for _, p := range pkgs {
		if !seen[p] {
			seen[p] = true
			uniquePkgs = append(uniquePkgs, p)
		}
	}

	if len(uniquePkgs) == 0 {
		return nil
	}

	steps := []CmdStep{
		{Label: "Update package lists", Args: []string{"apt-get", "update", "-qq"}},
	}

	// Install in batches to show progress per category
	// Group: core runtime
	corePackages := filterPackages(uniquePkgs, []string{
		"python3", "python3-pip", "python3-venv", "python3-dev",
		"build-essential", "cmake", "pkg-config",
		"git", "curl", "wget", "openssl",
	})
	if len(corePackages) > 0 {
		steps = append(steps, CmdStep{
			Label: fmt.Sprintf("Install core packages (%s)", strings.Join(corePackages, ", ")),
			Args:  append([]string{"apt-get", "install", "-y"}, corePackages...),
		})
	}

	// Group: C library headers
	libPackages := filterPackages(uniquePkgs, []string{
		"libffi-dev", "libssl-dev", "libpcap-dev", "libxml2-dev", "libxslt1-dev",
	})
	if len(libPackages) > 0 {
		steps = append(steps, CmdStep{
			Label: fmt.Sprintf("Install C library headers (%s)", strings.Join(libPackages, ", ")),
			Args:  append([]string{"apt-get", "install", "-y"}, libPackages...),
		})
	}

	// Group: security & network tools
	toolPackages := filterPackages(uniquePkgs, []string{
		"nmap", "tshark", "whois", "dnsutils",
		"adb", "fastboot",
		"wireguard-tools", "miniupnpc", "net-tools",
		"ffmpeg",
	})
	if len(toolPackages) > 0 {
		steps = append(steps, CmdStep{
			Label: fmt.Sprintf("Install security/network tools (%s)", strings.Join(toolPackages, ", ")),
			Args:  append([]string{"apt-get", "install", "-y"}, toolPackages...),
		})
	}

	// Group: node + go
	devPackages := filterPackages(uniquePkgs, []string{
		"nodejs", "npm", "golang",
	})
	if len(devPackages) > 0 {
		steps = append(steps, CmdStep{
			Label: fmt.Sprintf("Install dev tools (%s)", strings.Join(devPackages, ", ")),
			Args:  append([]string{"apt-get", "install", "-y"}, devPackages...),
		})
	}

	return steps
}

func buildVenvSteps(autarchDir string) []CmdStep {
	venv := autarchDir + "/venv"
	pip := venv + "/bin/pip3"
	reqFile := autarchDir + "/requirements.txt"

	steps := []CmdStep{
		{Label: "Create Python virtual environment", Args: []string{"python3", "-m", "venv", venv}},
		{Label: "Upgrade pip, setuptools, wheel", Args: []string{pip, "install", "--upgrade", "pip", "setuptools", "wheel"}},
	}

	if fileExists(reqFile) {
		steps = append(steps, CmdStep{
			Label: "Install Python packages from requirements.txt",
			Args:  []string{pip, "install", "-r", reqFile},
		})
	}

	return steps
}

func buildNpmSteps(autarchDir string) []CmdStep {
	steps := []CmdStep{
		{Label: "Install npm packages", Args: []string{"npm", "install"}, Dir: autarchDir},
	}

	if fileExists(autarchDir + "/scripts/build-hw-libs.sh") {
		steps = append(steps, CmdStep{
			Label: "Build hardware JS bundles",
			Args:  []string{"bash", "scripts/build-hw-libs.sh"},
			Dir:   autarchDir,
		})
	}

	return steps
}

// filterPackages returns only packages from wanted that exist in available.
func filterPackages(available, wanted []string) []string {
	avail := make(map[string]bool)
	for _, p := range available {
		avail[p] = true
	}
	var result []string
	for _, p := range wanted {
		if avail[p] {
			result = append(result, p)
		}
	}
	return result
}

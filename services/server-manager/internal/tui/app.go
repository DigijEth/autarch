package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// ── View IDs ────────────────────────────────────────────────────────

type ViewID int

const (
	ViewMain ViewID = iota
	ViewDeps
	ViewDepsInstall
	ViewModules
	ViewModuleToggle
	ViewSettings
	ViewSettingsSection
	ViewSettingsEdit
	ViewUsers
	ViewUsersCreate
	ViewUsersReset
	ViewService
	ViewDNS
	ViewDNSBuild
	ViewDNSManage
	ViewDNSZones
	ViewDNSZoneEdit
	ViewDeploy
	ViewConfirm
	ViewResult
)

// ── Styles ──────────────────────────────────────────────────────────

var (
	colorRed     = lipgloss.Color("#ef4444")
	colorGreen   = lipgloss.Color("#22c55e")
	colorYellow  = lipgloss.Color("#eab308")
	colorBlue    = lipgloss.Color("#6366f1")
	colorCyan    = lipgloss.Color("#06b6d4")
	colorMagenta = lipgloss.Color("#a855f7")
	colorDim     = lipgloss.Color("#6b7280")
	colorWhite   = lipgloss.Color("#f9fafb")
	colorSurface = lipgloss.Color("#1e1e2e")
	colorBorder  = lipgloss.Color("#3b3b5c")

	styleBanner = lipgloss.NewStyle().
			Foreground(colorRed).
			Bold(true)

	styleTitle = lipgloss.NewStyle().
			Foreground(colorCyan).
			Bold(true).
			PaddingLeft(2)

	styleSubtitle = lipgloss.NewStyle().
			Foreground(colorDim).
			PaddingLeft(2)

	styleMenuItem = lipgloss.NewStyle().
			PaddingLeft(4)

	styleSelected = lipgloss.NewStyle().
			Foreground(colorBlue).
			Bold(true).
			PaddingLeft(2)

	styleNormal = lipgloss.NewStyle().
			Foreground(colorWhite).
			PaddingLeft(4)

	styleKey = lipgloss.NewStyle().
			Foreground(colorCyan).
			Bold(true)

	styleSuccess = lipgloss.NewStyle().
			Foreground(colorGreen)

	styleError = lipgloss.NewStyle().
			Foreground(colorRed)

	styleWarning = lipgloss.NewStyle().
			Foreground(colorYellow)

	styleDim = lipgloss.NewStyle().
			Foreground(colorDim)

	styleStatusOK = lipgloss.NewStyle().
			Foreground(colorGreen).
			Bold(true)

	styleStatusBad = lipgloss.NewStyle().
			Foreground(colorRed).
			Bold(true)

	styleBox = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(colorBorder).
			Padding(1, 2)

	styleHR = lipgloss.NewStyle().
			Foreground(colorDim)
)

// ── Menu Item ───────────────────────────────────────────────────────

type MenuItem struct {
	Key   string
	Label string
	Desc  string
	View  ViewID
}

// ── Messages ────────────────────────────────────────────────────────

type ResultMsg struct {
	Title   string
	Lines   []string
	IsError bool
}

type ConfirmMsg struct {
	Prompt    string
	OnConfirm func() tea.Cmd
}

type OutputLineMsg string
type DoneMsg struct{ Err error }

// ── App Model ───────────────────────────────────────────────────────

type App struct {
	width, height int

	// Navigation
	view      ViewID
	viewStack []ViewID
	cursor    int

	// Main menu
	mainMenu []MenuItem

	// Dynamic content
	listItems   []ListItem
	listTitle   string
	sectionKeys []string

	// Settings
	settingsSections []string
	settingsSection  string
	settingsKeys     []string
	settingsVals     []string

	// Text input
	textInput  textinput.Model
	inputLabel string
	inputField string
	inputs     []textinput.Model
	labels     []string
	focusIdx   int

	// Result / output
	resultTitle string
	resultLines []string
	resultIsErr bool
	outputLines   []string
	outputDone    bool
	outputCh      chan tea.Msg
	progressStep  int
	progressTotal int
	progressLabel string

	// Confirm
	confirmPrompt string
	confirmAction func() tea.Cmd

	// Config path
	autarchDir string
}

type ListItem struct {
	Name    string
	Status  string
	Enabled bool
	Extra   string
}

func NewApp() App {
	ti := textinput.New()
	ti.CharLimit = 256

	app := App{
		view:       ViewMain,
		autarchDir: findAutarchDir(),
		textInput:  ti,
		mainMenu: []MenuItem{
			{Key: "1", Label: "Deploy AUTARCH", Desc: "Clone from GitHub, setup dirs, venv, deps, permissions, systemd", View: ViewDeploy},
			{Key: "2", Label: "Dependencies", Desc: "Install & manage system packages, Python venv, pip, npm", View: ViewDeps},
			{Key: "3", Label: "Modules", Desc: "List, enable, or disable AUTARCH Python modules", View: ViewModules},
			{Key: "4", Label: "Settings", Desc: "Edit autarch_settings.conf (all 14+ sections)", View: ViewSettings},
			{Key: "5", Label: "Users", Desc: "Create users, reset passwords, manage web credentials", View: ViewUsers},
			{Key: "6", Label: "Services", Desc: "Start, stop, restart AUTARCH web & background daemons", View: ViewService},
			{Key: "7", Label: "DNS Server", Desc: "Build, configure, and manage the AUTARCH DNS server", View: ViewDNS},
			{Key: "q", Label: "Quit", Desc: "Exit the server manager", View: ViewMain},
		},
	}
	return app
}

func (a App) Init() tea.Cmd {
	return nil
}

// waitForOutput returns a Cmd that reads the next message from the output channel.
// This creates the streaming chain: OutputLineMsg → waitForOutput → OutputLineMsg → ...
func (a App) waitForOutput() tea.Cmd {
	ch := a.outputCh
	if ch == nil {
		return nil
	}
	return func() tea.Msg {
		msg, ok := <-ch
		if !ok {
			return DoneMsg{}
		}
		return msg
	}
}

// ── Update ──────────────────────────────────────────────────────────

func (a App) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case tea.WindowSizeMsg:
		a.width = msg.Width
		a.height = msg.Height
		return a, nil

	case ResultMsg:
		a.pushView(ViewResult)
		a.resultTitle = msg.Title
		a.resultLines = msg.Lines
		a.resultIsErr = msg.IsError
		return a, nil

	case OutputLineMsg:
		a.outputLines = append(a.outputLines, string(msg))
		return a, a.waitForOutput()

	case ProgressMsg:
		a.progressStep = msg.Step
		a.progressTotal = msg.Total
		a.progressLabel = msg.Label
		return a, a.waitForOutput()

	case DoneMsg:
		a.outputDone = true
		a.outputCh = nil
		if msg.Err != nil {
			a.outputLines = append(a.outputLines, "", styleError.Render("Error: "+msg.Err.Error()))
		}
		a.outputLines = append(a.outputLines, "", styleDim.Render("Press any key to continue..."))
		return a, nil

	case depsLoadedMsg:
		a.listItems = msg.items
		return a, nil
	case modulesLoadedMsg:
		a.listItems = msg.items
		return a, nil
	case settingsLoadedMsg:
		a.settingsSections = msg.sections
		return a, nil
	case dnsZonesMsg:
		a.listItems = msg.items
		return a, nil

	case tea.KeyMsg:
		return a.handleKey(msg)
	}

	// Update text inputs if active
	if a.isInputView() {
		return a.updateInputs(msg)
	}

	return a, nil
}

func (a App) isInputView() bool {
	return a.view == ViewUsersCreate || a.view == ViewUsersReset ||
		a.view == ViewSettingsEdit || a.view == ViewDNSZoneEdit
}

func (a App) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := msg.String()

	// Global keys
	switch key {
	case "ctrl+c":
		return a, tea.Quit
	}

	// Input views get special handling
	if a.isInputView() {
		return a.handleInputKey(msg)
	}

	// Output view (streaming)
	if a.view == ViewDepsInstall || a.view == ViewDNSBuild {
		if a.outputDone {
			a.popView()
			a.progressStep = 0
			a.progressTotal = 0
			a.progressLabel = ""
			// Reload the parent view's data
			switch a.view {
			case ViewDeps:
				return a, a.loadDepsStatus()
			case ViewDNS:
				return a, nil
			case ViewDeploy:
				return a, nil
			}
		}
		return a, nil
	}

	// Result view
	if a.view == ViewResult {
		a.popView()
		return a, nil
	}

	// Confirm view
	if a.view == ViewConfirm {
		switch key {
		case "y", "Y":
			if a.confirmAction != nil {
				cmd := a.confirmAction()
				a.popView()
				return a, cmd
			}
			a.popView()
		case "n", "N", "esc":
			a.popView()
		}
		return a, nil
	}

	// List navigation
	switch key {
	case "up", "k":
		if a.cursor > 0 {
			a.cursor--
		}
		return a, nil
	case "down", "j":
		max := a.maxCursor()
		if a.cursor < max {
			a.cursor++
		}
		return a, nil
	case "esc":
		if len(a.viewStack) > 0 {
			a.popView()
		}
		return a, nil
	case "q":
		if a.view == ViewMain {
			return a, tea.Quit
		}
		if len(a.viewStack) > 0 {
			a.popView()
			return a, nil
		}
		return a, tea.Quit
	}

	// View-specific handling
	switch a.view {
	case ViewMain:
		return a.handleMainMenu(key)
	case ViewDeps:
		return a.handleDepsMenu(key)
	case ViewModules:
		return a.handleModulesMenu(key)
	case ViewModuleToggle:
		return a.handleModuleToggle(key)
	case ViewSettings:
		return a.handleSettingsMenu(key)
	case ViewSettingsSection:
		return a.handleSettingsSection(key)
	case ViewUsers:
		return a.handleUsersMenu(key)
	case ViewService:
		return a.handleServiceMenu(key)
	case ViewDeploy:
		return a.handleDeployMenu(key)
	case ViewDNS:
		return a.handleDNSMenu(key)
	case ViewDNSManage:
		return a.handleDNSManageMenu(key)
	case ViewDNSZones:
		return a.handleDNSZonesMenu(key)
	}

	return a, nil
}

func (a App) maxCursor() int {
	switch a.view {
	case ViewMain:
		return len(a.mainMenu) - 1
	case ViewModules, ViewModuleToggle:
		return len(a.listItems) - 1
	case ViewSettings:
		return len(a.settingsSections) - 1
	case ViewSettingsSection:
		return len(a.settingsKeys) - 1
	case ViewDNSZones:
		return len(a.listItems) - 1
	}
	return 0
}

// ── Navigation ──────────────────────────────────────────────────────

func (a *App) pushView(v ViewID) {
	a.viewStack = append(a.viewStack, a.view)
	a.view = v
	a.cursor = 0
}

func (a *App) popView() {
	if len(a.viewStack) > 0 {
		a.view = a.viewStack[len(a.viewStack)-1]
		a.viewStack = a.viewStack[:len(a.viewStack)-1]
		a.cursor = 0
	}
}

// ── View Rendering ──────────────────────────────────────────────────

func (a App) View() string {
	var b strings.Builder

	b.WriteString(a.renderBanner())
	b.WriteString("\n")

	switch a.view {
	case ViewMain:
		b.WriteString(a.renderMainMenu())
	case ViewDeploy:
		b.WriteString(a.renderDeployMenu())
	case ViewDeps:
		b.WriteString(a.renderDepsMenu())
	case ViewDepsInstall:
		b.WriteString(a.renderOutput("Installing Dependencies"))
	case ViewModules:
		b.WriteString(a.renderModulesList())
	case ViewModuleToggle:
		b.WriteString(a.renderModulesList())
	case ViewSettings:
		b.WriteString(a.renderSettingsSections())
	case ViewSettingsSection:
		b.WriteString(a.renderSettingsKeys())
	case ViewSettingsEdit:
		b.WriteString(a.renderSettingsEditForm())
	case ViewUsers:
		b.WriteString(a.renderUsersMenu())
	case ViewUsersCreate:
		b.WriteString(a.renderUserForm("Create New User"))
	case ViewUsersReset:
		b.WriteString(a.renderUserForm("Reset Password"))
	case ViewService:
		b.WriteString(a.renderServiceMenu())
	case ViewDNS:
		b.WriteString(a.renderDNSMenu())
	case ViewDNSBuild:
		b.WriteString(a.renderOutput("Building DNS Server"))
	case ViewDNSManage:
		b.WriteString(a.renderDNSManageMenu())
	case ViewDNSZones:
		b.WriteString(a.renderDNSZones())
	case ViewDNSZoneEdit:
		b.WriteString(a.renderDNSZoneForm())
	case ViewConfirm:
		b.WriteString(a.renderConfirm())
	case ViewResult:
		b.WriteString(a.renderResult())
	}

	b.WriteString("\n")
	b.WriteString(a.renderStatusBar())

	return b.String()
}

// ── Banner ──────────────────────────────────────────────────────────

func (a App) renderBanner() string {
	banner := `
    ▄▄▄       █    ██ ▄▄▄█████▓ ▄▄▄       ██▀███   ▄████▄   ██░ ██
   ▒████▄     ██  ▓██▒▓  ██▒ ▓▒▒████▄    ▓██ ▒ ██▒▒██▀ ▀█  ▓██░ ██▒
   ▒██  ▀█▄  ▓██  ▒██░▒ ▓██░ ▒░▒██  ▀█▄  ▓██ ░▄█ ▒▒▓█    ▄ ▒██▀▀██░
   ░██▄▄▄▄██ ▓▓█  ░██░░ ▓██▓ ░ ░██▄▄▄▄██ ▒██▀▀█▄  ▒▓▓▄ ▄██▒░▓█ ░██
    ▓█   ▓██▒▒▒█████▓   ▒██▒ ░  ▓█   ▓██▒░██▓ ▒██▒▒ ▓███▀ ░░▓█▒░██▓
    ▒▒   ▓▒█░░▒▓▒ ▒ ▒   ▒ ░░    ▒▒   ▓▒█░░ ▒▓ ░▒▓░░ ░▒ ▒  ░ ▒ ░░▒░▒
     ▒   ▒▒ ░░░▒░ ░ ░     ░      ▒   ▒▒ ░  ░▒ ░ ▒░  ░  ▒    ▒ ░▒░ ░
     ░   ▒    ░░░ ░ ░   ░        ░   ▒     ░░   ░ ░         ░  ░░ ░
         ░  ░   ░                    ░  ░   ░     ░ ░       ░  ░  ░`

	title := lipgloss.NewStyle().
		Foreground(colorCyan).
		Bold(true).
		Align(lipgloss.Center).
		Render("S E R V E R   M A N A G E R   v1.0")

	sub := styleDim.Render("          darkHal Security Group & Setec Security Labs")

	// Live service status bar
	statusLine := a.renderServiceStatusBar()

	return styleBanner.Render(banner) + "\n" + title + "\n" + sub + "\n" + statusLine + "\n"
}

func (a App) renderServiceStatusBar() string {
	webStatus, webUp := getProcessStatus("autarch-web", "autarch_web.py")
	dnsStatus, dnsUp := getProcessStatus("autarch-dns", "autarch-dns")

	webInd := styleStatusBad.Render("○")
	if webUp {
		webInd = styleStatusOK.Render("●")
	}
	dnsInd := styleStatusBad.Render("○")
	if dnsUp {
		dnsInd = styleStatusOK.Render("●")
	}

	_ = webStatus
	_ = dnsStatus

	return styleDim.Render("  ") +
		webInd + styleDim.Render(" Web ") +
		dnsInd + styleDim.Render(" DNS")
}

func (a App) renderHR() string {
	w := a.width
	if w < 10 {
		w = 66
	}
	if w > 80 {
		w = 80
	}
	return styleHR.Render(strings.Repeat("─", w-4)) + "\n"
}

// ── Main Menu ───────────────────────────────────────────────────────

func (a App) renderMainMenu() string {
	var b strings.Builder

	b.WriteString(styleTitle.Render("MAIN MENU"))
	b.WriteString("\n")
	b.WriteString(a.renderHR())
	b.WriteString("\n")

	for i, item := range a.mainMenu {
		cursor := "  "
		if i == a.cursor {
			cursor = styleSelected.Render("▸ ")
			label := styleKey.Render("["+item.Key+"]") + " " +
				lipgloss.NewStyle().Foreground(colorWhite).Bold(true).Render(item.Label)
			desc := styleDim.Render("  " + item.Desc)
			b.WriteString(cursor + label + "\n")
			b.WriteString("      " + desc + "\n")
		} else {
			label := styleDim.Render("["+item.Key+"]") + " " +
				lipgloss.NewStyle().Foreground(colorWhite).Render(item.Label)
			b.WriteString(cursor + "  " + label + "\n")
		}
	}

	return b.String()
}

// ── Confirm ─────────────────────────────────────────────────────────

func (a App) renderConfirm() string {
	var b strings.Builder
	b.WriteString(styleTitle.Render("CONFIRM"))
	b.WriteString("\n")
	b.WriteString(a.renderHR())
	b.WriteString("\n")
	b.WriteString(styleWarning.Render("  " + a.confirmPrompt))
	b.WriteString("\n\n")
	b.WriteString(styleDim.Render("  [Y] Yes   [N] No"))
	b.WriteString("\n")
	return b.String()
}

// ── Result ──────────────────────────────────────────────────────────

func (a App) renderResult() string {
	var b strings.Builder

	title := a.resultTitle
	if a.resultIsErr {
		b.WriteString(styleError.Render("  " + title))
	} else {
		b.WriteString(styleSuccess.Render("  " + title))
	}
	b.WriteString("\n")
	b.WriteString(a.renderHR())
	b.WriteString("\n")

	for _, line := range a.resultLines {
		b.WriteString("  " + line + "\n")
	}
	b.WriteString("\n")
	b.WriteString(styleDim.Render("  Press any key to continue..."))
	b.WriteString("\n")
	return b.String()
}

// ── Streaming Output ────────────────────────────────────────────────

func (a App) renderOutput(title string) string {
	var b strings.Builder

	b.WriteString(styleTitle.Render(title))
	b.WriteString("\n")
	b.WriteString(a.renderHR())

	// Progress bar
	if a.progressTotal > 0 && !a.outputDone {
		pct := float64(a.progressStep) / float64(a.progressTotal)
		barWidth := 40
		filled := int(pct * float64(barWidth))
		if filled > barWidth {
			filled = barWidth
		}
		bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)
		pctStr := fmt.Sprintf("%3.0f%%", pct*100)

		b.WriteString("  " + styleKey.Render("["+bar+"]") + " " +
			styleWarning.Render(pctStr) + " " +
			styleDim.Render(fmt.Sprintf("Step %d/%d: %s", a.progressStep, a.progressTotal, a.progressLabel)))
		b.WriteString("\n")
		b.WriteString(a.renderHR())
	}
	b.WriteString("\n")

	// Show last N lines that fit the screen
	maxLines := a.height - 22
	if maxLines < 10 {
		maxLines = 20
	}
	start := 0
	if len(a.outputLines) > maxLines {
		start = len(a.outputLines) - maxLines
	}
	for _, line := range a.outputLines[start:] {
		b.WriteString("  " + line + "\n")
	}

	if !a.outputDone {
		b.WriteString("\n")
		b.WriteString(styleDim.Render("  Working..."))
	}

	return b.String()
}

// ── Status Bar ──────────────────────────────────────────────────────

func (a App) renderStatusBar() string {
	nav := styleDim.Render("  ↑↓ navigate")
	esc := styleDim.Render("  esc back")
	quit := styleDim.Render("  q quit")

	path := ""
	for _, v := range a.viewStack {
		path += viewName(v) + " > "
	}
	path += viewName(a.view)

	left := styleDim.Render("  " + path)
	right := nav + esc + quit

	gap := a.width - lipgloss.Width(left) - lipgloss.Width(right)
	if gap < 1 {
		gap = 1
	}

	return "\n" + styleHR.Render(strings.Repeat("─", clamp(a.width-4, 20, 80))) + "\n" +
		left + strings.Repeat(" ", gap) + right + "\n"
}

func viewName(v ViewID) string {
	names := map[ViewID]string{
		ViewMain:            "Main",
		ViewDeps:            "Dependencies",
		ViewDepsInstall:     "Install",
		ViewModules:         "Modules",
		ViewModuleToggle:    "Toggle",
		ViewSettings:        "Settings",
		ViewSettingsSection: "Section",
		ViewSettingsEdit:    "Edit",
		ViewUsers:           "Users",
		ViewUsersCreate:     "Create",
		ViewUsersReset:      "Reset",
		ViewService:         "Services",
		ViewDNS:             "DNS",
		ViewDNSBuild:        "Build",
		ViewDNSManage:       "Manage",
		ViewDNSZones:        "Zones",
		ViewDeploy:          "Deploy",
		ViewDNSZoneEdit:     "Edit Zone",
		ViewConfirm:         "Confirm",
		ViewResult:          "Result",
	}
	if n, ok := names[v]; ok {
		return n
	}
	return "?"
}

// ── User Form Rendering ─────────────────────────────────────────────

func (a App) renderUserForm(title string) string {
	var b strings.Builder

	b.WriteString(styleTitle.Render(title))
	b.WriteString("\n")
	b.WriteString(a.renderHR())
	b.WriteString("\n")

	for i, label := range a.labels {
		prefix := "  "
		if i == a.focusIdx {
			prefix = styleSelected.Render("▸ ")
		}
		b.WriteString(prefix + styleDim.Render(label+": "))
		b.WriteString(a.inputs[i].View())
		b.WriteString("\n\n")
	}

	b.WriteString("\n")
	b.WriteString(styleDim.Render("  tab next field  |  enter submit  |  esc cancel"))
	b.WriteString("\n")
	return b.String()
}

// ── Settings Edit Form ──────────────────────────────────────────────

func (a App) renderSettingsEditForm() string {
	var b strings.Builder

	b.WriteString(styleTitle.Render(fmt.Sprintf("Edit [%s]", a.settingsSection)))
	b.WriteString("\n")
	b.WriteString(a.renderHR())
	b.WriteString("\n")

	for i, label := range a.labels {
		prefix := "  "
		if i == a.focusIdx {
			prefix = styleSelected.Render("▸ ")
		}
		b.WriteString(prefix + styleKey.Render(label) + " = ")
		b.WriteString(a.inputs[i].View())
		b.WriteString("\n")
	}

	b.WriteString("\n")
	b.WriteString(styleDim.Render("  tab next  |  enter save all  |  esc cancel"))
	b.WriteString("\n")
	return b.String()
}

// ── DNS Zone Form ───────────────────────────────────────────────────

func (a App) renderDNSZoneForm() string {
	var b strings.Builder

	b.WriteString(styleTitle.Render("Create DNS Zone"))
	b.WriteString("\n")
	b.WriteString(a.renderHR())
	b.WriteString("\n")

	for i, label := range a.labels {
		prefix := "  "
		if i == a.focusIdx {
			prefix = styleSelected.Render("▸ ")
		}
		b.WriteString(prefix + styleDim.Render(label+": "))
		b.WriteString(a.inputs[i].View())
		b.WriteString("\n\n")
	}

	b.WriteString("\n")
	b.WriteString(styleDim.Render("  tab next field  |  enter submit  |  esc cancel"))
	b.WriteString("\n")
	return b.String()
}

// ── Helpers ─────────────────────────────────────────────────────────

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

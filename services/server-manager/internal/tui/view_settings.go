package tui

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/darkhal/autarch-server-manager/internal/config"
)

// ── Rendering ───────────────────────────────────────────────────────

func (a App) renderSettingsSections() string {
	var b strings.Builder

	b.WriteString(styleTitle.Render("SETTINGS — autarch_settings.conf"))
	b.WriteString("\n")
	b.WriteString(a.renderHR())
	b.WriteString("\n")

	if len(a.settingsSections) == 0 {
		b.WriteString(styleDim.Render("  Loading..."))
		b.WriteString("\n")
		return b.String()
	}

	for i, sec := range a.settingsSections {
		cursor := "    "
		if i == a.cursor {
			cursor = styleSelected.Render(" ▸") + "  "
			b.WriteString(cursor + styleKey.Render("["+sec+"]") + "\n")
		} else {
			b.WriteString(cursor + styleDim.Render("["+sec+"]") + "\n")
		}
	}

	b.WriteString("\n")
	b.WriteString(a.renderHR())
	b.WriteString(styleKey.Render("  [enter]") + " Edit section  ")
	b.WriteString(styleDim.Render("  esc back"))
	b.WriteString("\n")

	return b.String()
}

func (a App) renderSettingsKeys() string {
	var b strings.Builder

	b.WriteString(styleTitle.Render(fmt.Sprintf("SETTINGS — [%s]", a.settingsSection)))
	b.WriteString("\n")
	b.WriteString(a.renderHR())
	b.WriteString("\n")

	for i, key := range a.settingsKeys {
		val := ""
		if i < len(a.settingsVals) {
			val = a.settingsVals[i]
		}

		cursor := "    "
		if i == a.cursor {
			cursor = styleSelected.Render(" ▸") + "  "
		}

		// Mask sensitive values
		displayVal := val
		if isSensitiveKey(key) && len(val) > 4 {
			displayVal = val[:4] + strings.Repeat("•", len(val)-4)
		}

		b.WriteString(fmt.Sprintf("%s%s = %s\n",
			cursor,
			styleKey.Render(key),
			lipgloss.NewStyle().Foreground(colorWhite).Render(displayVal),
		))
	}

	b.WriteString("\n")
	b.WriteString(a.renderHR())
	b.WriteString(styleKey.Render("  [enter]") + " Edit all values  ")
	b.WriteString(styleKey.Render("[d]") + " Edit selected  ")
	b.WriteString(styleDim.Render("  esc back"))
	b.WriteString("\n")

	return b.String()
}

func isSensitiveKey(key string) bool {
	k := strings.ToLower(key)
	return strings.Contains(k, "password") || strings.Contains(k, "secret") ||
		strings.Contains(k, "api_key") || strings.Contains(k, "token")
}

// ── Key Handling ────────────────────────────────────────────────────

func (a App) handleSettingsMenu(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "enter":
		if a.cursor >= 0 && a.cursor < len(a.settingsSections) {
			a.settingsSection = a.settingsSections[a.cursor]
			return a.loadSettingsSection()
		}
	}
	return a, nil
}

func (a App) handleSettingsSection(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "enter":
		// Edit all values in this section
		return a.openSettingsEdit()
	case "d":
		// Edit single selected value
		if a.cursor >= 0 && a.cursor < len(a.settingsKeys) {
			return a.openSingleSettingEdit(a.cursor)
		}
	}
	return a, nil
}

// ── Commands ────────────────────────────────────────────────────────

func (a App) loadSettings() tea.Cmd {
	return func() tea.Msg {
		confPath := findAutarchDir() + "/autarch_settings.conf"
		sections, err := config.ListSections(confPath)
		if err != nil {
			return ResultMsg{
				Title:   "Error",
				Lines:   []string{"Cannot read config: " + err.Error()},
				IsError: true,
			}
		}
		sort.Strings(sections)
		return settingsLoadedMsg{sections: sections}
	}
}

type settingsLoadedMsg struct{ sections []string }

func (a App) loadSettingsSection() (App, tea.Cmd) {
	confPath := findAutarchDir() + "/autarch_settings.conf"
	keys, vals, err := config.GetSection(confPath, a.settingsSection)
	if err != nil {
		return a, func() tea.Msg {
			return ResultMsg{
				Title:   "Error",
				Lines:   []string{err.Error()},
				IsError: true,
			}
		}
	}

	a.settingsKeys = keys
	a.settingsVals = vals
	a.pushView(ViewSettingsSection)
	return a, nil
}

func (a App) openSettingsEdit() (App, tea.Cmd) {
	a.labels = make([]string, len(a.settingsKeys))
	a.inputs = make([]textinput.Model, len(a.settingsKeys))
	copy(a.labels, a.settingsKeys)

	for i, val := range a.settingsVals {
		ti := textinput.New()
		ti.CharLimit = 512
		ti.Width = 50
		ti.SetValue(val)
		if isSensitiveKey(a.settingsKeys[i]) {
			ti.EchoMode = textinput.EchoPassword
		}
		if i == 0 {
			ti.Focus()
		}
		a.inputs[i] = ti
	}

	a.focusIdx = 0
	a.pushView(ViewSettingsEdit)
	return a, nil
}

func (a App) openSingleSettingEdit(idx int) (App, tea.Cmd) {
	a.labels = []string{a.settingsKeys[idx]}
	a.inputs = make([]textinput.Model, 1)

	ti := textinput.New()
	ti.CharLimit = 512
	ti.Width = 50
	ti.SetValue(a.settingsVals[idx])
	if isSensitiveKey(a.settingsKeys[idx]) {
		ti.EchoMode = textinput.EchoPassword
	}
	ti.Focus()
	a.inputs[0] = ti
	a.focusIdx = 0
	a.pushView(ViewSettingsEdit)
	return a, nil
}

func (a App) saveSettings() (App, tea.Cmd) {
	confPath := findAutarchDir() + "/autarch_settings.conf"

	// Read the full config file
	data, err := os.ReadFile(confPath)
	if err != nil {
		return a, func() tea.Msg {
			return ResultMsg{Title: "Error", Lines: []string{err.Error()}, IsError: true}
		}
	}

	content := string(data)

	// Apply changes
	for i, label := range a.labels {
		newVal := a.inputs[i].Value()
		content = config.SetValue(content, a.settingsSection, label, newVal)
	}

	if err := os.WriteFile(confPath, []byte(content), 0644); err != nil {
		return a, func() tea.Msg {
			return ResultMsg{Title: "Error", Lines: []string{err.Error()}, IsError: true}
		}
	}

	a.popView()

	// Reload the section
	keys, vals, _ := config.GetSection(confPath, a.settingsSection)
	a.settingsKeys = keys
	a.settingsVals = vals

	return a, func() tea.Msg {
		return ResultMsg{
			Title: "Settings Saved",
			Lines: []string{
				fmt.Sprintf("Updated [%s] section with %d values.", a.settingsSection, len(a.labels)),
				"",
				"Restart AUTARCH services for changes to take effect.",
			},
		}
	}
}

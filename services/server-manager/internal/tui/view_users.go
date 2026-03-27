package tui

import (
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/darkhal/autarch-server-manager/internal/users"
)

// ── Rendering ───────────────────────────────────────────────────────

func (a App) renderUsersMenu() string {
	var b strings.Builder

	b.WriteString(styleTitle.Render("USER MANAGEMENT"))
	b.WriteString("\n")
	b.WriteString(a.renderHR())
	b.WriteString("\n")

	// Show current credentials info
	dir := findAutarchDir()
	creds, err := users.LoadCredentials(dir)
	if err != nil {
		b.WriteString(styleWarning.Render("  No credentials file found — using defaults (admin/admin)"))
		b.WriteString("\n\n")
	} else {
		b.WriteString("  " + styleKey.Render("Current user: ") +
			lipgloss.NewStyle().Foreground(colorWhite).Bold(true).Render(creds.Username))
		b.WriteString("\n")
		if creds.ForceChange {
			b.WriteString("  " + styleWarning.Render("⚠ Password change required on next login"))
		} else {
			b.WriteString("  " + styleSuccess.Render("✔ Password is set"))
		}
		b.WriteString("\n\n")
	}

	b.WriteString(a.renderHR())
	b.WriteString("\n")
	b.WriteString(styleKey.Render("  [c]") + " Create new user / change username\n")
	b.WriteString(styleKey.Render("  [r]") + " Reset password\n")
	b.WriteString(styleKey.Render("  [f]") + " Force password change on next login\n")
	b.WriteString(styleKey.Render("  [d]") + " Reset to defaults (admin/admin)\n")
	b.WriteString("\n")
	b.WriteString(styleDim.Render("  esc back"))
	b.WriteString("\n")

	return b.String()
}

// ── Key Handling ────────────────────────────────────────────────────

func (a App) handleUsersMenu(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "c":
		return a.openUserCreateForm()
	case "r":
		return a.openUserResetForm()
	case "f":
		return a.forcePasswordChange()
	case "d":
		a.confirmPrompt = "Reset credentials to admin/admin? This cannot be undone."
		a.confirmAction = func() tea.Cmd {
			return func() tea.Msg {
				dir := findAutarchDir()
				err := users.ResetToDefaults(dir)
				if err != nil {
					return ResultMsg{Title: "Error", Lines: []string{err.Error()}, IsError: true}
				}
				return ResultMsg{
					Title: "Credentials Reset",
					Lines: []string{
						"Username: admin",
						"Password: admin",
						"",
						"Force change on next login: YES",
					},
				}
			}
		}
		a.pushView(ViewConfirm)
		return a, nil
	}
	return a, nil
}

// ── Forms ───────────────────────────────────────────────────────────

func (a App) openUserCreateForm() (App, tea.Cmd) {
	a.labels = []string{"Username", "Password", "Confirm Password"}
	a.inputs = make([]textinput.Model, 3)

	for i := range a.inputs {
		ti := textinput.New()
		ti.CharLimit = 128
		ti.Width = 40
		if i > 0 {
			ti.EchoMode = textinput.EchoPassword
		}
		if i == 0 {
			ti.Focus()
		}
		a.inputs[i] = ti
	}

	a.focusIdx = 0
	a.pushView(ViewUsersCreate)
	return a, nil
}

func (a App) openUserResetForm() (App, tea.Cmd) {
	a.labels = []string{"New Password", "Confirm Password"}
	a.inputs = make([]textinput.Model, 2)

	for i := range a.inputs {
		ti := textinput.New()
		ti.CharLimit = 128
		ti.Width = 40
		ti.EchoMode = textinput.EchoPassword
		if i == 0 {
			ti.Focus()
		}
		a.inputs[i] = ti
	}

	a.focusIdx = 0
	a.pushView(ViewUsersReset)
	return a, nil
}

func (a App) submitUserCreate() (App, tea.Cmd) {
	username := a.inputs[0].Value()
	password := a.inputs[1].Value()
	confirm := a.inputs[2].Value()

	if username == "" {
		return a, func() tea.Msg {
			return ResultMsg{Title: "Error", Lines: []string{"Username cannot be empty."}, IsError: true}
		}
	}
	if len(password) < 4 {
		return a, func() tea.Msg {
			return ResultMsg{Title: "Error", Lines: []string{"Password must be at least 4 characters."}, IsError: true}
		}
	}
	if password != confirm {
		return a, func() tea.Msg {
			return ResultMsg{Title: "Error", Lines: []string{"Passwords do not match."}, IsError: true}
		}
	}

	dir := findAutarchDir()
	err := users.CreateUser(dir, username, password)
	a.popView()

	if err != nil {
		return a, func() tea.Msg {
			return ResultMsg{Title: "Error", Lines: []string{err.Error()}, IsError: true}
		}
	}

	return a, func() tea.Msg {
		return ResultMsg{
			Title: "User Created",
			Lines: []string{
				"Username: " + username,
				"Password: (set)",
				"",
				"Restart the web dashboard for changes to take effect.",
			},
		}
	}
}

func (a App) submitUserReset() (App, tea.Cmd) {
	password := a.inputs[0].Value()
	confirm := a.inputs[1].Value()

	if len(password) < 4 {
		return a, func() tea.Msg {
			return ResultMsg{Title: "Error", Lines: []string{"Password must be at least 4 characters."}, IsError: true}
		}
	}
	if password != confirm {
		return a, func() tea.Msg {
			return ResultMsg{Title: "Error", Lines: []string{"Passwords do not match."}, IsError: true}
		}
	}

	dir := findAutarchDir()
	err := users.ResetPassword(dir, password)
	a.popView()

	if err != nil {
		return a, func() tea.Msg {
			return ResultMsg{Title: "Error", Lines: []string{err.Error()}, IsError: true}
		}
	}

	return a, func() tea.Msg {
		return ResultMsg{
			Title: "Password Reset",
			Lines: []string{"Password has been updated.", "", "Force change on next login: NO"},
		}
	}
}

func (a App) forcePasswordChange() (App, tea.Cmd) {
	dir := findAutarchDir()
	err := users.SetForceChange(dir, true)
	if err != nil {
		return a, func() tea.Msg {
			return ResultMsg{Title: "Error", Lines: []string{err.Error()}, IsError: true}
		}
	}
	return a, func() tea.Msg {
		return ResultMsg{
			Title: "Force Change Enabled",
			Lines: []string{"User will be required to change password on next login."},
		}
	}
}
